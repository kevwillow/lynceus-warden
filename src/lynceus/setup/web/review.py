"""Review page + real apply pipeline + SSE progress (F6 Phase 2a/2b).

The review page is the wizard's final ceremony before the apply.
Phase 2a captured the operator's intent as a validated ``Config``
and showed a noop apply placeholder; Phase 2b replaces that
placeholder with the real ``apply_config`` invocation, streamed
back to the operator's browser via SSE while it runs.

Surfaces:
* ``GET /review`` — human-readable HTML, secrets redacted, with
  "Edit step X" links per section so the operator can jump back
  to fix anything. The Apply button is disabled when the Config
  fails validation.
* ``GET /apply-preview.json`` — the validated ``Config`` as JSON,
  same redactions, kept post-Phase-2b for operators / scripts
  that want to diff the wizard's output against an existing
  lynceus.yaml.
* ``POST /apply`` — kicks off the real apply pipeline.
  ``apply_config`` runs in a worker thread via
  ``asyncio.to_thread``; each step is streamed to the operator's
  browser via an ``SSEProgressSink`` that bridges to an
  ``asyncio.Queue``. Returns 303 to ``/apply-progress`` so the
  browser loads the progress page; 409 if a prior apply is still
  running; 303 to ``/review`` if the Config can't be built.
* ``GET /apply-progress`` — renders ``apply_progress.html`` which
  opens an ``EventSource("/apply-stream")`` and updates the DOM
  per record. On stream-end, navigates to ``/apply-complete``.
  State-aware: bounces idle sessions back to ``/review`` and
  terminal sessions forward to ``/apply-complete``.
* ``GET /apply-stream`` — SSE endpoint. Drains
  ``session.apply_queue`` and yields ``data: <json>`` events,
  with a final ``event: end`` before close.

The Config built here uses the daemon's own ``Config(...)``
constructor — there is no parallel validation surface.
"""

from __future__ import annotations

import asyncio
import json
import logging
import traceback
from pathlib import Path
from typing import TYPE_CHECKING, Any

from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from pydantic import ValidationError

from lynceus import paths
from lynceus.cli.setup import _redact_kismet_api_key
from lynceus.config import CaptureConfig, Config
from lynceus.redact import redact_ntfy_topic
from lynceus.setup.core import apply_config
from lynceus.setup.models import ApplyReport, ApplyStep
from lynceus.setup.web.session import WizardSession
from lynceus.setup.web.sse_sink import SSEProgressSink, serialize_step

if TYPE_CHECKING:
    from fastapi import FastAPI

logger = logging.getLogger(__name__)

# Touch 3 teardown constants. APPLY_GRACE_SECONDS is the
# "operator walked away" safety net per the dynamic choice (Done +
# Ctrl-C + 10-min auto-exit): if the apply finishes and Done never
# fires, the server self-exits after this many seconds so the
# wizard doesn't leak as an orphan process. DONE_SHUTDOWN_DELAY_SECONDS
# gives the "Server shutting down" response time to flush before the
# socket closes. Tests monkeypatch both to short values so the test
# suite doesn't stall.
APPLY_GRACE_SECONDS: float = 600.0
DONE_SHUTDOWN_DELAY_SECONDS: float = 0.5

# Map of Config field path (Pydantic loc tuple joined with ".") to
# the wizard step ordinal that owns it. Drives the "Edit step X"
# links the review page surfaces when validation fails on a
# specific field. Keys cover the fields the wizard captures; fields
# Config defaults silently aren't expected to fail and aren't
# represented here (a failure on one of those is surfaced generically
# with a link back to the review page itself).
FIELD_STEP_INDEX: dict[str, int] = {
    "kismet_url": 1,
    "kismet_api_key": 2,
    "kismet_sources": 4,
    "capture.probe_ssids": 5,
    "capture.ble_friendly_names": 6,
    "ntfy_url": 7,
    "ntfy_topic": 8,
    "min_rssi": 10,
    "severity_overrides_path": 11,
}


def _session(request: Request) -> WizardSession:
    state = request.app.state
    return state.session_store.get_or_create(state.setup_token)


def _redirect(request: Request, path: str) -> RedirectResponse:
    token = request.app.state.setup_token
    return RedirectResponse(f"{path}?token={token}", status_code=303)


def _render(request: Request, name: str, **context) -> HTMLResponse:
    from lynceus import __version__
    from lynceus.setup.web.app import STEP_TITLES, TOTAL_STEPS

    base = {
        "version": __version__,
        "step_titles": STEP_TITLES,
        "total_steps": TOTAL_STEPS,
        "step_index": 0,  # Review/apply pages sit outside the numbered flow.
    }
    base.update(context)
    return request.app.state.templates.TemplateResponse(
        request=request,
        name=name,
        context=base,
    )


def _build_config_from_session(answers: dict[str, Any]) -> Config:
    """Construct a ``Config`` from the wizard's per-step answers.

    Empty strings for optional secrets (ntfy_url, ntfy_topic) map
    to ``None`` so the daemon treats them as "ntfy disabled" rather
    than "empty topic" (which would 404 the publish). ``min_rssi``
    is preserved as-typed; missing means default.

    Raises ``ValidationError`` on any Config-level validation
    failure (URL scheme, range, etc.).
    """
    return Config(
        kismet_url=answers.get("kismet_url") or "",
        kismet_api_key=answers.get("kismet_api_key") or None,
        kismet_sources=answers.get("kismet_sources") or None,
        capture=CaptureConfig(
            probe_ssids=bool(answers.get("probe_ssids", False)),
            ble_friendly_names=bool(answers.get("ble_friendly_names", True)),
        ),
        ntfy_url=answers.get("ntfy_url") or None,
        ntfy_topic=answers.get("ntfy_topic") or None,
        min_rssi=answers.get("min_rssi"),
    )


def _resolve_apply_args(
    session: WizardSession,
    scope: str,
) -> tuple[Config, Path, set[str] | None]:
    """Build the apply_config arg tuple from session.answers.

    Returns ``(config_with_rules_path, severity_path, enabled_rule_types)``.
    The Config is mutated to carry ``rules_path`` when alerting is on
    + at least one rule type is selected; that single-render path
    mirrors ``apply_config``'s built-in rules-step contract (see the
    "Single-render path" branch in core.py).
    """
    answers = session.answers
    config = _build_config_from_session(answers)
    severity_str = answers.get("severity_overrides_path")
    if severity_str:
        severity_path = Path(severity_str)
    else:
        # Match the CLI default: target_path.parent / "severity_overrides.yaml".
        # We don't have target_path here, so reconstruct from paths module.
        severity_path = paths.default_config_dir(scope) / "severity_overrides.yaml"
    enabled_list = answers.get("enabled_rule_types") or []
    enable_alerting = bool(answers.get("enable_alerting", False))
    if enable_alerting and enabled_list:
        enabled_rule_types: set[str] | None = set(enabled_list)
        # Set Config.rules_path so apply_config's single-render path
        # writes the comment block inline. apply_config's write_rules
        # step gates on Config.rules_path AND enabled_rule_types non-
        # empty.
        config = config.model_copy(
            update={"rules_path": str(paths.default_config_dir(scope) / "rules.yaml")}
        )
    else:
        enabled_rule_types = None
    return config, severity_path, enabled_rule_types


def _format_validation_errors(exc: ValidationError) -> list[dict[str, Any]]:
    """Turn a Pydantic ValidationError into review-page rows."""
    rows = []
    for err in exc.errors():
        loc = ".".join(str(x) for x in err.get("loc", ()))
        rows.append({
            "field": loc,
            "message": err.get("msg", "invalid"),
            "step_index": FIELD_STEP_INDEX.get(loc),
        })
    return rows


def _redact_config_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Apply per-field redactions to a dumped Config dict.

    Mutates ``data`` and returns it. Redacts the two shared-secret
    fields the wizard collects: ``kismet_api_key`` (head/tail
    preview) and ``ntfy_topic`` (head + bullets + tail).
    """
    if data.get("kismet_api_key"):
        data["kismet_api_key"] = _redact_kismet_api_key(data["kismet_api_key"])
    if data.get("ntfy_topic"):
        data["ntfy_topic"] = redact_ntfy_topic(data["ntfy_topic"])
    if data.get("ntfy_auth_token"):
        data["ntfy_auth_token"] = "•••"
    return data


def _summarize(answers: dict[str, Any], config: Config | None) -> dict[str, Any]:
    """Build the section-by-section summary the HTML template renders."""
    return {
        "kismet_url": answers.get("kismet_url", "") or "(not set)",
        "kismet_api_key_preview": (
            _redact_kismet_api_key(answers.get("kismet_api_key", ""))
            if answers.get("kismet_api_key") else "(not set)"
        ),
        "kismet_sources": answers.get("kismet_sources") or [],
        "probe_ssids": bool(answers.get("probe_ssids", False)),
        "ble_friendly_names": bool(answers.get("ble_friendly_names", True)),
        "ntfy_url": answers.get("ntfy_url", "") or "(ntfy skipped)",
        "ntfy_topic_preview": (
            redact_ntfy_topic(answers.get("ntfy_topic", ""))
            if answers.get("ntfy_topic") else "(ntfy skipped)"
        ),
        "min_rssi": answers.get("min_rssi", "(default)"),
        "severity_overrides_path": (
            answers.get("severity_overrides_path") or "(default)"
        ),
        "enable_alerting": bool(answers.get("enable_alerting", False)),
        "enabled_rule_types": answers.get("enabled_rule_types") or [],
    }


# ---- review + preview ------------------------------------------------------


async def review_get(request: Request) -> HTMLResponse:
    state = request.app.state
    session = _session(request)
    config: Config | None = None
    errors: list[dict[str, Any]] = []
    try:
        config = _build_config_from_session(session.answers)
    except ValidationError as exc:
        errors = _format_validation_errors(exc)
    return _render(
        request,
        "review.html",
        config=config,
        errors=errors,
        summary=_summarize(session.answers, config),
        scope=state.scope,
        target_path=str(state.target_path),
    )


async def apply_preview_json(request: Request) -> JSONResponse:
    """Validated Config as JSON, secrets redacted. Kept post-Phase-2b
    for scripts that want to diff the wizard's output against an
    existing lynceus.yaml; the real apply at ``POST /apply`` is the
    primary path."""
    state = request.app.state
    session = _session(request)
    try:
        config = _build_config_from_session(session.answers)
    except ValidationError as exc:
        return JSONResponse(
            {"valid": False, "errors": _format_validation_errors(exc)},
            status_code=400,
        )
    data = config.model_dump(mode="json")
    _redact_config_dict(data)
    return JSONResponse({
        "valid": True,
        "config": data,
        "extras": {
            "severity_overrides_path": session.answers.get("severity_overrides_path"),
            "enable_alerting": bool(session.answers.get("enable_alerting", False)),
            "enabled_rule_types": session.answers.get("enabled_rule_types") or [],
            "scope": state.scope,
            "target_path": str(state.target_path),
            "reconfigure": bool(state.reconfigure),
            "skip_probes": bool(state.skip_probes),
        },
    })


# ---- apply pipeline -------------------------------------------------------


async def _run_apply_task(
    *,
    app_state,
    session: WizardSession,
    config: Config,
    severity_path: Path,
    enabled_rule_types: set[str] | None,
    queue: asyncio.Queue,
    loop: asyncio.AbstractEventLoop,
) -> None:
    """Background task that runs ``apply_config`` in a worker thread.

    On completion: stores the ``ApplyReport`` on ``session.apply_report``
    and transitions ``session.apply_state`` to ``completed`` / ``failed``
    based on the report's overall_status.

    On exception (``SetupError`` mid-chain): synthesizes a failed
    ``ApplyStep`` capturing the exception, pushes it to the SSE
    queue so the live stream sees the failure, builds a partial
    ``ApplyReport`` from whatever the sink had captured pre-exception
    plus the synthetic step, and transitions to ``failed``.

    Always pushes ``None`` (the sentinel) to the queue at the end so
    the SSE generator can terminate the stream cleanly.

    Touch 3 grace window: schedules a 10-minute timer to auto-exit
    the server if Done never fires. The timer is stashed on the
    session so /done can cancel it.
    """
    sink = SSEProgressSink(queue, loop)
    # Capture the new terminal state separately from session.apply_state
    # so the finally block can arm the grace timer BEFORE flipping state
    # (Finding 4.1). The default "running" means CancelledError mid-
    # to_thread leaves state at "running" — same behavior as pre-fix
    # (Finding 7.2 covers cancellation in batch 2).
    new_state: str = "running"
    try:
        report = await asyncio.to_thread(
            apply_config,
            config,
            scope=app_state.scope,
            target_path=app_state.target_path,
            severity_overrides_path=severity_path,
            enabled_rule_types=enabled_rule_types,
            run_bundled_import=True,
            progress=sink,
        )
        session.apply_report = report
        new_state = "completed" if report.overall_status == "ok" else "failed"
    except Exception as exc:
        logger.exception("apply_config raised in wizard background task")
        tb = traceback.format_exc()
        synthetic = ApplyStep(
            name="apply_config",
            status="failed",
            message=f"{type(exc).__name__}: {exc}",
            detail={"traceback": tb},
        )
        # Push to the queue so the live stream surfaces the failure
        # before the operator hits the completion page.
        await queue.put(serialize_step(synthetic))
        partial_steps = (*sink.records, synthetic)
        session.apply_report = ApplyReport(steps=partial_steps)
        new_state = "failed"
    finally:
        # Sentinel: SSE generator breaks on None and closes the stream.
        await queue.put(None)
        # Schedule the walked-away grace timer (Touch 3). If Done
        # POSTs first, it cancels this task. The scheduling lives in
        # a module-local helper so Touch 3 can import + override it
        # in tests without weaving fixtures through every apply path.
        # Arm BEFORE the terminal state flip so a re-apply POST's
        # cancel-prior-grace block sees the task and can cancel it
        # cleanly — otherwise the new POST runs while the prior
        # task is mid-finally with apply_grace_task still None, and
        # the grace timer ends up armed against the NEW apply run
        # (Finding 4.1).
        _schedule_apply_grace_shutdown(app_state, session)
        session.apply_state = new_state  # type: ignore[assignment]


def _schedule_apply_grace_shutdown(app_state, session: WizardSession) -> None:
    """Schedule the post-apply 10-minute walked-away timer.

    Per the dynamic teardown decision (Done click + Ctrl-C + 10-min
    grace window): apply completion arms a timer that triggers a
    clean ``server.should_exit = True`` after
    ``APPLY_GRACE_SECONDS``. The /done handler cancels this timer
    when the operator clicks Done — Done is the primary signal, the
    timer is just the safety net for an operator who walks away.

    Stored on ``session.apply_grace_task`` so /done can cancel it.
    No-op (with a debug log) if no server instance is exposed on
    app.state (test-only path where uvicorn was mocked away).
    """
    server = getattr(app_state, "server", None)
    if server is None:
        logger.debug("grace shutdown skipped: no app.state.server (test path?)")
        return
    session.apply_grace_task = asyncio.create_task(
        _grace_shutdown(server, APPLY_GRACE_SECONDS)
    )


async def _grace_shutdown(server, delay: float) -> None:
    """Sleep then signal shutdown. CancelledError means /done took
    over and we should stand down silently."""
    try:
        await asyncio.sleep(delay)
    except asyncio.CancelledError:
        # /done cancelled us — this is the normal path, not an error.
        raise
    logger.info(
        "apply grace window (%.0fs) elapsed without /done click; signaling shutdown",
        delay,
    )
    server.should_exit = True


async def _shutdown_after_delay(server, delay: float) -> None:
    """Wait briefly so the calling response can flush, then signal
    shutdown. Used by the /done handler."""
    await asyncio.sleep(delay)
    if server is not None:
        server.should_exit = True


async def done_post(request: Request) -> Response:
    """Operator clicked Done on the completion page.

    Refuses with 409 if an apply is still mid-pipeline (Finding 3.1):
    /done schedules ``server.should_exit = True`` and uvicorn tears
    the loop down — but the worker thread running apply_config
    continues against a closing executor with brittle results
    (partial file writes mitigated only by _atomic_write, abandoned
    bundled-import subprocess). The completion page redirects
    "running" sessions back to /apply-progress, so a careful operator
    won't hit this — but an operator with a stale /apply-complete
    tab from a prior failed run can race the buttons.

    On non-running states: cancels any pending grace-window timer
    (Done is the explicit signal that supersedes it), schedules a
    brief-delay shutdown via ``server.should_exit = True``, and
    returns a "Setup complete — server shutting down" page so the
    operator's browser sees a confirmation before the socket closes.

    The shutdown task is stored on ``session.shutdown_task`` to
    prevent the asyncio loop from weakly GC'ing it before it fires
    (Finding 3.4).

    No-op on the shutdown if ``app.state.server`` isn't exposed
    (test-only path where uvicorn was mocked). The page still
    renders so behavioral tests can assert it without booting
    uvicorn.
    """
    state = request.app.state
    session = _session(request)

    # Finding 3.1: refuse Done mid-apply.
    if session.apply_state == "running":
        return Response(
            "apply still in progress; wait for the completion page "
            "or for the post-apply grace timer to expire",
            status_code=409,
        )

    # Cancel the grace timer. CancelledError on the awaiting
    # _grace_shutdown is the documented "Done won the race" path.
    if session.apply_grace_task is not None and not session.apply_grace_task.done():
        session.apply_grace_task.cancel()
        session.apply_grace_task = None

    server = getattr(state, "server", None)
    if server is not None:
        # Schedule the shutdown; don't await it here or we'd block
        # the response. The brief delay gives the HTML below time to
        # land in the operator's browser before uvicorn tears the
        # socket down. Hold a strong ref on the session so the loop
        # doesn't GC the task before it fires (Finding 3.4).
        session.shutdown_task = asyncio.create_task(
            _shutdown_after_delay(server, DONE_SHUTDOWN_DELAY_SECONDS)
        )

    return _render(
        request,
        "done.html",
        scope=state.scope,
        target_path=str(state.target_path),
    )


async def apply_post(request: Request) -> Response:
    """Kick off the real apply pipeline.

    State machine:
      * idle → running (start apply, redirect to /apply-progress)
      * running → 409 (already in flight; defense in depth — the
        review-page Apply button is also disabled on click)
      * completed | failed → running (re-run, start fresh apply)

    Returns 303 → /review on ValidationError so the operator can
    fix the offending field. Returns 409 on double-Apply.
    """
    state = request.app.state
    session = _session(request)

    if session.apply_state == "running":
        return Response("apply already in progress", status_code=409)

    try:
        config, severity_path, enabled_rule_types = _resolve_apply_args(
            session, scope=state.scope
        )
    except ValidationError:
        # Validation re-renders the review page; we don't surface
        # the errors via a flash message — /review reads
        # session.answers + rebuilds Config + shows the errors
        # inline, so the redirect is idempotent.
        return _redirect(request, "/review")

    # Fresh queue per apply. Re-runs land here and overwrite the
    # prior queue; the old SSE generator will have already drained
    # to its sentinel and closed.
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue()
    # Cancel any prior grace timer from a previous apply.
    if session.apply_grace_task is not None and not session.apply_grace_task.done():
        session.apply_grace_task.cancel()
        session.apply_grace_task = None
    # Finding 7.1: create the task BEFORE flipping state to "running"
    # so a create_task failure (closed loop, system resource limits)
    # cannot strand the session at "running" with no task to advance
    # it through the state machine — which would also wedge the 409
    # guard on a subsequent /apply attempt. asyncio.create_task only
    # schedules; the task body runs after this handler returns and
    # yields control, so the state-flip below still lands before the
    # task can observe it.
    try:
        task = asyncio.create_task(
            _run_apply_task(
                app_state=state,
                session=session,
                config=config,
                severity_path=severity_path,
                enabled_rule_types=enabled_rule_types,
                queue=queue,
                loop=loop,
            )
        )
    except RuntimeError:
        logger.exception("could not schedule apply task")
        return Response(
            "apply could not be scheduled (event loop unavailable)",
            status_code=503,
        )
    session.apply_queue = queue
    session.apply_state = "running"
    session.apply_report = None
    # Reset the consumed flag so /apply-stream serves the new run's
    # events rather than 410-ing on the prior run's drained state.
    session.apply_stream_consumed = False
    session.apply_task = task
    return _redirect(request, "/apply-progress")


async def apply_progress_get(request: Request) -> Response:
    """Render the progress page that opens the SSE connection.

    State-aware so the operator can refresh, deep-link, or
    bookmark without breaking:
      * idle → /review (no apply ever started)
      * running → render progress page
      * completed | failed → /apply-complete (already done)
    """
    session = _session(request)
    if session.apply_state == "idle":
        return _redirect(request, "/review")
    if session.apply_state in ("completed", "failed"):
        return _redirect(request, "/apply-complete")
    # Render with target/scope so the page can show what's being
    # written without re-loading session.answers in JS.
    state = request.app.state
    return _render(
        request,
        "apply_progress.html",
        scope=state.scope,
        target_path=str(state.target_path),
    )


async def apply_complete_get(request: Request) -> Response:
    """Render the completion summary from session.apply_report.

    State-aware: idle → /review (no apply ran), running →
    /apply-progress (browser may have raced ahead of the SSE end
    event), terminal (completed/failed) → render the template.

    The completion summary shows one row per ApplyStep with status
    icon + message + collapsible detail. On the failed path,
    surfaces the first failed step prominently and offers a Re-run
    button (which POSTs to /apply); the Done button POSTs to /done
    on every path (Touch 3 wires the actual shutdown).
    """
    state = request.app.state
    session = _session(request)
    if session.apply_state == "idle":
        return _redirect(request, "/review")
    if session.apply_state == "running":
        return _redirect(request, "/apply-progress")
    # Terminal state.
    report = session.apply_report
    failed_step = None
    if report is not None:
        for s in report.steps:
            if s.status == "failed":
                failed_step = s
                break
    overall_ok = session.apply_state == "completed"
    return _render(
        request,
        "apply_complete.html",
        report=report,
        failed_step=failed_step,
        overall_ok=overall_ok,
        scope=state.scope,
        target_path=str(state.target_path),
    )


async def apply_stream_get(request: Request) -> Response:
    """SSE endpoint. Drains session.apply_queue.

    Yields one ``data: <json>`` event per ``ApplyStep`` record;
    ends with ``event: end`` so the client can navigate without
    relying on connection-error handling.

    State-aware so an EventSource reconnect after the apply finished
    doesn't hang forever on the empty drained queue (Findings 2.3, 5.1):

      * idle              → 404 (no apply ever started on this session)
      * running           → stream the queue as today
      * terminal + drained → 410 (a prior generator already consumed
                              the queue to its sentinel; nothing more
                              will be enqueued)
      * terminal + queue  → stream the tail (operator's first connection
        not yet drained     after a fast apply; they still see the
                            transcript and the closing event: end)
    """
    session = _session(request)
    queue = session.apply_queue
    if session.apply_state == "idle" or queue is None:
        # No apply ever started on this session. JSON close so the
        # client's EventSource sees a definitive failure.
        return JSONResponse(
            {"error": "no apply in progress"},
            status_code=404,
        )
    if (
        session.apply_state in ("completed", "failed")
        and session.apply_stream_consumed
    ):
        # The apply finished AND a prior generator already drained
        # the queue to its sentinel. A new EventSource reconnect
        # here would block forever on queue.get() because nothing
        # else will be enqueued. 410 Gone tells the client the
        # stream is permanently unavailable; the operator can
        # navigate to /apply-complete to see the transcript.
        return JSONResponse(
            {"error": "apply stream already drained"},
            status_code=410,
        )
    if session.apply_stream_active:
        # Finding 1.4: a generator is already draining the queue.
        # Two concurrent consumers would steal each other's records
        # via queue.get() (each item goes to exactly one consumer),
        # leaving one tab with a corrupt transcript and the other
        # possibly hung on the sentinel side of the split. Reject
        # the second connection rather than fan-out.
        return JSONResponse(
            {"error": "apply stream already has an active consumer"},
            status_code=409,
        )
    # Set the active flag synchronously here, BEFORE returning the
    # StreamingResponse. The generator body only runs when Starlette
    # starts iterating it, so a check-set inside the generator would
    # leave a TOCTOU window between two near-simultaneous GETs.
    # Single-process uvicorn with no await between check (above) and
    # this set keeps the pair event-loop-atomic.
    session.apply_stream_active = True

    async def event_stream():
        try:
            while True:
                item = await queue.get()
                if item is None:
                    # Sentinel — emit a closing event so JS can navigate
                    # cleanly rather than relying on onerror.
                    yield "event: end\ndata: {}\n\n"
                    break
                yield f"data: {json.dumps(item)}\n\n"
        finally:
            # Mark drained so a subsequent reconnect 410s rather
            # than hanging on the now-empty queue. Cleanup runs on
            # both the normal sentinel exit and the GeneratorExit
            # path (client disconnect mid-stream).
            session.apply_stream_consumed = True
            session.apply_stream_active = False

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            # Defensive: some reverse proxies (nginx) buffer
            # text/event-stream by default and break SSE. The
            # wizard runs on loopback in practice, but the header
            # is cheap insurance for an operator who tunnels via
            # an unusual setup.
            "X-Accel-Buffering": "no",
        },
    )


# ---- registration ---------------------------------------------------------


def register_review_routes(app: "FastAPI") -> None:
    app.add_api_route("/review", review_get, methods=["GET"], response_class=HTMLResponse)
    app.add_api_route("/apply", apply_post, methods=["POST"])
    app.add_api_route(
        "/apply-preview.json",
        apply_preview_json,
        methods=["GET"],
        response_class=JSONResponse,
    )
    app.add_api_route(
        "/apply-progress",
        apply_progress_get,
        methods=["GET"],
    )
    app.add_api_route(
        "/apply-complete",
        apply_complete_get,
        methods=["GET"],
    )
    app.add_api_route(
        "/apply-stream",
        apply_stream_get,
        methods=["GET"],
    )
    app.add_api_route(
        "/done",
        done_post,
        methods=["POST"],
        response_class=HTMLResponse,
    )
