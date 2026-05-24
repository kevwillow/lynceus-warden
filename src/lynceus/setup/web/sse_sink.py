"""SSE-bridging ``ProgressSink`` for the lynceus-setup web wizard.

``apply_config`` calls ``sink.record(step)`` synchronously inside a
worker thread (we offload via ``asyncio.to_thread`` so the event loop
stays responsive for the SSE channel). The sink serializes each step
to a JSON-safe dict and hands it to the event loop via
``loop.call_soon_threadsafe(queue.put_nowait, ...)`` — that is the
ONLY thread-safe way to push onto an ``asyncio.Queue`` from outside
the loop. The SSE generator reads the queue with native ``await``.

The sink also keeps a local ``records`` list so the apply task can
reconstruct a partial ``ApplyReport`` if ``apply_config`` raises
mid-chain (the exception path otherwise loses the steps that
streamed before the crash). Single-producer (worker thread) /
single-consumer (event loop on the failure path) — Python's GIL
covers the simple append/iterate.
"""

from __future__ import annotations

import asyncio
import dataclasses
from pathlib import Path
from typing import Any

from lynceus.setup.models import ApplyStep


def serialize_step(step: ApplyStep) -> dict[str, Any]:
    """Turn an ``ApplyStep`` into a JSON-safe dict.

    ``detail`` may carry ``Path`` objects (write_config emits
    ``{"path": Path(...)}``) which ``json.dumps`` can't handle. We
    convert recursively; anything not natively JSON-safe falls
    through to ``str()`` rather than crashing the stream.
    """
    return {
        "name": step.name,
        "status": step.status,
        "message": step.message,
        "detail": _json_safe(step.detail) if step.detail is not None else None,
    }


def _json_safe(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    # dataclass values (rare in detail dicts today, but cheap to
    # support) → asdict so we get a plain dict, then recurse.
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return _json_safe(dataclasses.asdict(value))
    return str(value)


class SSEProgressSink:
    """``ProgressSink`` implementation that bridges worker-thread
    ``record(step)`` calls to an event-loop-side ``asyncio.Queue``.

    Construction binds the sink to a specific queue and loop. The
    sink is intentionally lightweight: it does no I/O of its own;
    every step is enqueued and the SSE generator handles the wire
    format.
    """

    def __init__(self, queue: asyncio.Queue, loop: asyncio.AbstractEventLoop) -> None:
        self._queue = queue
        self._loop = loop
        self.records: list[ApplyStep] = []

    def record(self, step: ApplyStep) -> None:
        # Stash the original ApplyStep for partial-report
        # reconstruction on the exception path.
        self.records.append(step)
        # Push serialized form to the SSE queue. call_soon_threadsafe
        # schedules the put on the event loop; this is the documented
        # cross-thread pattern for asyncio.Queue.
        self._loop.call_soon_threadsafe(self._queue.put_nowait, serialize_step(step))
