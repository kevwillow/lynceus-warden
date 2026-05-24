"""In-flight wizard session state.

One operator per wizard run, but request handlers run concurrently
inside the ASGI server, so the store is lock-guarded. Sessions are
keyed by the per-run setup token (the same token that gates auth) so
there is no separate session-id ceremony — the operator pasting the
token-bearing URL into their browser is the session.

State is in-memory only; nothing persists across server restarts. By
design: the wizard is run-once-on-demand, the operator either
completes it or starts over.

The ``answers`` dict mirrors the shape the CLI wizard builds up in
``cli/setup.py:run_wizard`` (kismet_url, kismet_api_key,
kismet_sources, probe_ssids, ble_friendly_names, ntfy_url,
ntfy_topic, min_rssi, etc.). Phase 2a's form handlers populate it
key-by-key; the Phase 2a review page reads it to construct the
final ``Config``.

Phase 2b adds the apply-pipeline state: ``apply_state`` is the
simple state machine ``idle → running → completed | failed``
(re-runnable from terminal states). ``apply_report`` carries the
returned (or synthesized partial) ``ApplyReport``. ``apply_queue``
holds the per-run SSE queue the worker thread pushes to and the
SSE generator drains. ``apply_task`` is the background asyncio
task running the apply; tests await it for determinism. All four
are mutated from BOTH the event loop and a worker thread —
mutations are single-field assignments only (GIL-atomic).
``apply_grace_task`` is the Touch-3 walked-away timer (cancellable
if Done fires first).
"""

from __future__ import annotations

import asyncio
import threading
from dataclasses import dataclass, field
from typing import Any, Literal

from lynceus.setup.models import ApplyReport

ApplyState = Literal["idle", "running", "completed", "failed"]


@dataclass
class WizardSession:
    """One operator's in-flight answers + apply state for a wizard run."""

    token: str
    answers: dict[str, Any] = field(default_factory=dict)
    apply_state: ApplyState = "idle"
    apply_report: ApplyReport | None = None
    apply_queue: asyncio.Queue | None = None
    apply_task: asyncio.Task | None = None
    apply_grace_task: asyncio.Task | None = None
    # Stored ref to /done's fire-and-forget shutdown task. Python's
    # event loop only weakly references tasks; without this strong
    # ref the task can be GC'd between create and fire, silently
    # dropping the shutdown signal. See Finding 3.4.
    shutdown_task: asyncio.Task | None = None
    # Set by the SSE generator's cleanup once it has drained the
    # queue to the sentinel. Lets /apply-stream distinguish "post-
    # apply reconnect against an empty drained queue" (410) from
    # "terminal state but queue still has events for the operator's
    # first/only consumer to tail" (200). See Findings 2.3, 5.1.
    apply_stream_consumed: bool = False


class SessionStore:
    """Thread-safe ``{token: WizardSession}`` map."""

    def __init__(self) -> None:
        self._sessions: dict[str, WizardSession] = {}
        self._lock = threading.Lock()

    def get_or_create(self, token: str) -> WizardSession:
        with self._lock:
            session = self._sessions.get(token)
            if session is None:
                session = WizardSession(token=token)
                self._sessions[token] = session
            return session

    def get(self, token: str) -> WizardSession | None:
        with self._lock:
            return self._sessions.get(token)

    def clear(self) -> None:
        with self._lock:
            self._sessions.clear()
