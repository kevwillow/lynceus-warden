"""Tests for the real apply pipeline + SSE streaming
(F6 Phase 2b, Touch 1).

Pins:
* ``SSEProgressSink.record(step)`` serializes via ``serialize_step``
  and pushes onto an ``asyncio.Queue`` from the worker thread using
  ``loop.call_soon_threadsafe`` — a direct ``put_nowait`` from the
  wrong thread is the failure mode this protects against.
* The ``/apply`` POST state machine: idle → running → completed |
  failed, with 409 returned on double-Apply and 303 → /review on
  ValidationError.
* The apply task uses ``asyncio.to_thread`` so the SSE channel
  stays responsive during ``apply_config``.
* SSE stream emits one ``data:`` event per step record and a
  closing ``event: end`` before the connection closes.
* On exception, a synthesized ``apply_config`` failed step lands
  in the stream AND in ``session.apply_report.steps`` alongside
  whatever streamed before the crash.
* CLI parity: the wizard's apply produces identical filesystem
  state to the CLI's ``apply_config`` call with the same args.
* Re-apply after a terminal state works (no stale-queue contamination).
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from lynceus.setup.core import apply_config
from lynceus.setup.models import ApplyReport, ApplyStep
from lynceus.setup.web import review as review_mod
from lynceus.setup.web.app import create_wizard_app
from lynceus.setup.web.session import WizardSession
from lynceus.setup.web.sse_sink import SSEProgressSink, serialize_step

TOKEN = "test-setup-token-fixed-for-unit-tests-1234567890"


def _valid_answers():
    return {
        "kismet_url": "http://localhost:2501",
        "kismet_api_key": "ABCDEF0123456789XYZ",
        "kismet_sources": ["external_wifi"],
        "probe_ssids": False,
        "ble_friendly_names": True,
        "ntfy_url": "https://ntfy.sh",
        "ntfy_topic": "lynceus-prod-alerts",
        "min_rssi": -70,
        "severity_overrides_path": "",  # → default
        "enable_alerting": False,
        "enabled_rule_types": [],
    }


def _make_app(tmp_path: Path | None = None, **overrides):
    target = (tmp_path / "lynceus.yaml") if tmp_path else Path("/tmp/wizard-test.yaml")
    kwargs = dict(setup_token=TOKEN, scope="user", target_path=target)
    kwargs.update(overrides)
    return create_wizard_app(**kwargs)


def _client(app):
    return TestClient(app, follow_redirects=False)


def _csrf_get(client, path):
    client.get(f"{path}?token={TOKEN}")
    return client.cookies.get("lynceus_csrf")


def _wait_for_state(session, target_states, timeout: float = 3.0):
    """Poll until the apply task transitions to one of target_states.

    The apply task runs on Starlette's portal event loop (alive
    across TestClient requests). Polling with a small sleep gives
    the worker thread + the asyncio task time to complete.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if session.apply_state in target_states:
            return
        time.sleep(0.02)
    raise AssertionError(
        f"apply_state did not reach {target_states} within {timeout}s; "
        f"state={session.apply_state!r}"
    )


@pytest.fixture
def fake_apply_ok(monkeypatch):
    """Replace apply_config with a fake that emits two ok steps and
    returns a clean report. Returns the spy list for assertions."""
    calls: list[dict] = []

    def fake(config, **kwargs):
        calls.append({"config": config, **kwargs})
        sink = kwargs.get("progress")
        steps = (
            ApplyStep(name="write_config", status="ok", message="wrote",
                      detail={"path": kwargs["target_path"]}),
            ApplyStep(name="create_data_dir", status="ok", message="dir ok",
                      detail=None),
        )
        if sink is not None:
            for s in steps:
                sink.record(s)
        return ApplyReport(steps=steps)

    monkeypatch.setattr(review_mod, "apply_config", fake)
    return calls


@pytest.fixture
def fake_apply_fail(monkeypatch):
    """Replace apply_config with a fake that emits one ok step,
    then raises. Tests the partial-report / synthesized-failure
    branch of _run_apply_task."""
    def fake(config, **kwargs):
        sink = kwargs.get("progress")
        if sink is not None:
            sink.record(ApplyStep(
                name="write_config", status="ok", message="wrote first",
                detail=None,
            ))
        raise RuntimeError("simulated mid-chain failure")

    monkeypatch.setattr(review_mod, "apply_config", fake)


# ---- SSEProgressSink unit ------------------------------------------------


def test_serialize_step_converts_path_in_detail():
    # Path str() is platform-dependent (POSIX vs Windows separators);
    # compare against the concrete str() so the test is portable.
    p = Path("/etc/lynceus/lynceus.yaml")
    step = ApplyStep(
        name="write_config",
        status="ok",
        message="ok",
        detail={"path": p, "size": 1234},
    )
    out = serialize_step(step)
    assert out == {
        "name": "write_config",
        "status": "ok",
        "message": "ok",
        "detail": {"path": str(p), "size": 1234},
    }


def test_serialize_step_none_detail():
    step = ApplyStep(name="x", status="skipped", message="m")
    assert serialize_step(step)["detail"] is None


def test_serialize_step_handles_nested_lists():
    a, b = Path("/a"), Path("/b")
    step = ApplyStep(
        name="chown_db_files",
        status="ok",
        message="x",
        detail={"files": [a, b]},
    )
    out = serialize_step(step)
    assert out["detail"] == {"files": [str(a), str(b)]}


def test_sse_sink_uses_call_soon_threadsafe():
    """Pin the thread-safe bridge. A bare put_nowait from the wrong
    thread is the failure mode this guards against."""

    async def run():
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue = asyncio.Queue()
        spy = MagicMock(wraps=loop.call_soon_threadsafe)
        loop.call_soon_threadsafe = spy  # type: ignore[method-assign]
        sink = SSEProgressSink(queue, loop)
        step = ApplyStep(name="t", status="ok", message="m")
        # record() runs synchronously like apply_config calls it.
        sink.record(step)
        # Let the loop tick so the scheduled callback fires.
        await asyncio.sleep(0)
        spy.assert_called_once()
        item = queue.get_nowait()
        assert item["name"] == "t"

    asyncio.run(run())


def test_sse_sink_stashes_records_for_partial_report():
    """The sink keeps its own ApplyStep list so the apply task can
    rebuild a partial ApplyReport when apply_config raises."""

    async def run():
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue = asyncio.Queue()
        sink = SSEProgressSink(queue, loop)
        s1 = ApplyStep(name="a", status="ok", message="m1")
        s2 = ApplyStep(name="b", status="ok", message="m2")
        sink.record(s1)
        sink.record(s2)
        assert sink.records == [s1, s2]

    asyncio.run(run())


# ---- /apply state machine ------------------------------------------------


@pytest.mark.webui
def test_apply_post_idle_to_running_to_completed(fake_apply_ok):
    app = _make_app()
    session = app.state.session_store.get_or_create(TOKEN)
    session.answers.update(_valid_answers())
    assert session.apply_state == "idle"
    with _client(app) as c:
        csrf = _csrf_get(c, "/review")
        resp = c.post(f"/apply?token={TOKEN}", data={"_csrf": csrf})
        assert resp.status_code == 303
        # State transitions: at minimum it's no longer "idle". The
        # worker thread may already have completed; the poll handles
        # either case.
        _wait_for_state(session, ("completed", "failed"))
    assert session.apply_state == "completed"
    assert session.apply_report is not None
    assert len(session.apply_report.steps) == 2


@pytest.mark.webui
def test_apply_post_double_apply_returns_409():
    """While an apply is in flight, a second POST returns 409. We
    keep the apply hanging via a stub apply_config that blocks on
    an Event the test controls."""
    blocker = __import__("threading").Event()

    def hang(config, **kwargs):
        blocker.wait(timeout=3.0)
        return ApplyReport(steps=())

    import lynceus.setup.web.review as review_local
    real = review_local.apply_config
    review_local.apply_config = hang
    try:
        app = _make_app()
        session = app.state.session_store.get_or_create(TOKEN)
        session.answers.update(_valid_answers())
        with _client(app) as c:
            csrf = _csrf_get(c, "/review")
            r1 = c.post(f"/apply?token={TOKEN}", data={"_csrf": csrf})
            assert r1.status_code == 303
            # Briefly yield so the task starts and state flips to running.
            time.sleep(0.05)
            r2 = c.post(f"/apply?token={TOKEN}", data={"_csrf": csrf})
            assert r2.status_code == 409
            assert "in progress" in r2.text.lower()
            blocker.set()
            _wait_for_state(session, ("completed", "failed"))
    finally:
        review_local.apply_config = real


@pytest.mark.webui
def test_apply_post_terminal_state_allows_rerun(fake_apply_ok):
    """After completed/failed, /apply starts a fresh run."""
    app = _make_app()
    session = app.state.session_store.get_or_create(TOKEN)
    session.answers.update(_valid_answers())
    # Simulate a prior terminal state.
    session.apply_state = "completed"
    session.apply_report = ApplyReport(steps=())
    with _client(app) as c:
        csrf = _csrf_get(c, "/review")
        resp = c.post(f"/apply?token={TOKEN}", data={"_csrf": csrf})
        assert resp.status_code == 303
        _wait_for_state(session, ("completed", "failed"))
    # New apply ran (fresh report with the fake's 2 steps).
    assert session.apply_state == "completed"
    assert len(session.apply_report.steps) == 2


@pytest.mark.webui
def test_apply_post_exception_records_synthesized_failed_step(fake_apply_fail):
    app = _make_app()
    session = app.state.session_store.get_or_create(TOKEN)
    session.answers.update(_valid_answers())
    with _client(app) as c:
        csrf = _csrf_get(c, "/review")
        c.post(f"/apply?token={TOKEN}", data={"_csrf": csrf})
        _wait_for_state(session, ("failed",))
    assert session.apply_state == "failed"
    # Partial report: the one ok step that landed + the synthesized
    # failed step capturing the exception.
    steps = session.apply_report.steps
    assert len(steps) == 2
    assert steps[0].status == "ok"
    assert steps[1].status == "failed"
    assert steps[1].name == "apply_config"
    assert "simulated mid-chain failure" in steps[1].message
    assert steps[1].detail and "traceback" in steps[1].detail


# ---- /apply-progress page ------------------------------------------------


@pytest.mark.webui
def test_apply_progress_idle_redirects_to_review():
    app = _make_app()
    with _client(app) as c:
        resp = c.get(f"/apply-progress?token={TOKEN}")
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/review")


@pytest.mark.webui
def test_apply_progress_terminal_redirects_to_complete():
    app = _make_app()
    session = app.state.session_store.get_or_create(TOKEN)
    session.apply_state = "completed"
    with _client(app) as c:
        resp = c.get(f"/apply-progress?token={TOKEN}")
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/apply-complete")


@pytest.mark.webui
def test_apply_progress_running_renders_page():
    app = _make_app()
    session = app.state.session_store.get_or_create(TOKEN)
    session.apply_state = "running"
    with _client(app) as c:
        resp = c.get(f"/apply-progress?token={TOKEN}")
    assert resp.status_code == 200
    body = resp.text
    assert "Applying configuration" in body
    assert "EventSource" in body
    assert "/apply-stream" in body


@pytest.mark.webui
def test_apply_progress_script_renders_warning_icon_branch():
    """Arc B Touch 2: the in-browser SSE consumer must distinguish
    warning steps from failure (❌) and skip (⏭) so the operator can
    tell at a glance that a non-blocking cross-check fired. The
    progress page is server-rendered JS; we assert the warning branch
    is present in the script body the browser will execute."""
    app = _make_app()
    session = app.state.session_store.get_or_create(TOKEN)
    session.apply_state = "running"
    with _client(app) as c:
        resp = c.get(f"/apply-progress?token={TOKEN}")
    body = resp.text
    assert resp.status_code == 200
    # The icon ternary has a "warning" branch wired to ⚠️, distinct
    # from "ok" (✅), "skipped" (⏭), and the default fallback (❌).
    assert '"warning"' in body
    assert "⚠️" in body


# ---- /apply-stream SSE ---------------------------------------------------


@pytest.mark.webui
def test_apply_stream_no_apply_returns_404():
    """Idle session (no apply ever started) → 404. Pre-Touch-4 this
    returned 409 from the queue-is-None branch; the state-aware
    rewrite consolidates that into the idle gate. The behavioral
    contract is the same: client sees a JSON close, not an SSE
    stream that hangs."""
    app = _make_app()
    with _client(app) as c:
        resp = c.get(f"/apply-stream?token={TOKEN}")
    assert resp.status_code == 404


@pytest.mark.webui
def test_apply_stream_emits_records_then_end_event(fake_apply_ok):
    """End-to-end: trigger apply, stream events, assert order +
    end-marker. Uses TestClient's streaming context."""
    app = _make_app()
    session = app.state.session_store.get_or_create(TOKEN)
    session.answers.update(_valid_answers())
    with _client(app) as c:
        csrf = _csrf_get(c, "/review")
        c.post(f"/apply?token={TOKEN}", data={"_csrf": csrf})
        # Wait for the task to finish so all records + sentinel are
        # in the queue before we start the stream. (For Phase 2a tests
        # we don't try to interleave; a separate test covers the
        # live-streaming case below.)
        _wait_for_state(session, ("completed", "failed"))
        with c.stream("GET", f"/apply-stream?token={TOKEN}") as resp:
            assert resp.status_code == 200
            assert resp.headers["content-type"].startswith("text/event-stream")
            assert resp.headers["cache-control"] == "no-cache"
            chunks = list(resp.iter_text())
    payload = "".join(chunks)
    # Two ok steps + one closing end event.
    assert payload.count("data:") >= 2
    assert "event: end" in payload
    # First record is write_config.
    assert "write_config" in payload


@pytest.mark.webui
def test_apply_stream_emits_synthesized_failed_step(fake_apply_fail):
    app = _make_app()
    session = app.state.session_store.get_or_create(TOKEN)
    session.answers.update(_valid_answers())
    with _client(app) as c:
        csrf = _csrf_get(c, "/review")
        c.post(f"/apply?token={TOKEN}", data={"_csrf": csrf})
        _wait_for_state(session, ("failed",))
        with c.stream("GET", f"/apply-stream?token={TOKEN}") as resp:
            payload = "".join(resp.iter_text())
    assert "simulated mid-chain failure" in payload
    assert "event: end" in payload


# ---- SSE terminal-state reconnect (Findings 5.1 + 2.3) -------------------


@pytest.mark.webui
def test_apply_stream_post_drain_reconnect_returns_410(fake_apply_ok):
    """Findings 5.1 + 2.3: a second /apply-stream connection after
    the first has drained the queue must NOT block on an empty
    queue.get() — it returns 410 Gone so the client's EventSource
    sees a definitive close and the operator can navigate to
    /apply-complete."""
    app = _make_app()
    session = app.state.session_store.get_or_create(TOKEN)
    session.answers.update(_valid_answers())
    with _client(app) as c:
        csrf = _csrf_get(c, "/review")
        c.post(f"/apply?token={TOKEN}", data={"_csrf": csrf})
        _wait_for_state(session, ("completed", "failed"))
        # First consumer drains the queue to the sentinel.
        with c.stream("GET", f"/apply-stream?token={TOKEN}") as r1:
            assert r1.status_code == 200
            list(r1.iter_text())
        assert session.apply_stream_consumed is True
        # Second consumer (e.g., EventSource auto-reconnect) sees 410.
        r2 = c.get(f"/apply-stream?token={TOKEN}")
    assert r2.status_code == 410
    assert "drained" in r2.text.lower() or "gone" in r2.text.lower()


@pytest.mark.webui
def test_apply_stream_terminal_first_consumer_still_streams(fake_apply_ok):
    """Terminal state but no generator has drained the queue yet
    (fast apply, operator's only EventSource opens after state has
    flipped to completed): the first consumer must still see the
    transcript + the closing event: end. The 410 only fires on the
    SECOND consumer."""
    app = _make_app()
    session = app.state.session_store.get_or_create(TOKEN)
    session.answers.update(_valid_answers())
    with _client(app) as c:
        csrf = _csrf_get(c, "/review")
        c.post(f"/apply?token={TOKEN}", data={"_csrf": csrf})
        _wait_for_state(session, ("completed", "failed"))
        # No prior stream — apply_stream_consumed still False.
        assert session.apply_stream_consumed is False
        with c.stream("GET", f"/apply-stream?token={TOKEN}") as resp:
            assert resp.status_code == 200
            payload = "".join(resp.iter_text())
    assert "write_config" in payload
    assert "event: end" in payload


@pytest.mark.webui
def test_apply_stream_running_unchanged(fake_apply_ok):
    """The state-aware gate must not regress the running path: an
    operator's first /apply-stream against an in-flight apply
    streams as today (200 + event-stream content-type)."""
    app = _make_app()
    session = app.state.session_store.get_or_create(TOKEN)
    session.answers.update(_valid_answers())
    with _client(app) as c:
        csrf = _csrf_get(c, "/review")
        c.post(f"/apply?token={TOKEN}", data={"_csrf": csrf})
        # Don't wait for terminal — start the stream while running.
        # The fake_apply_ok fixture runs synchronously so the apply
        # may already be terminal; pin only the status + headers.
        with c.stream("GET", f"/apply-stream?token={TOKEN}") as resp:
            assert resp.status_code == 200
            assert resp.headers["content-type"].startswith("text/event-stream")
            # Drain so the context closes cleanly.
            list(resp.iter_text())


# ---- Concurrent SSE rejection (Finding 1.4) ------------------------------


@pytest.mark.webui
def test_apply_stream_rejects_concurrent_consumer():
    """Finding 1.4: a second /apply-stream connection while a prior
    generator is still draining the queue must NOT race for the same
    queue.get() items — that's the multi-tab event-stealing bug.

    We simulate the race by directly toggling the apply_stream_active
    flag (which is what an in-flight generator would do) rather than
    juggling two concurrent TestClient streams. This pins the gate
    behavior without timing dependence on the worker thread."""
    app = _make_app()
    session = app.state.session_store.get_or_create(TOKEN)
    # Plausible mid-apply state: queue exists, apply running, the
    # "first" generator is already active.
    session.apply_state = "running"
    session.apply_queue = asyncio.Queue()
    session.apply_stream_active = True
    with _client(app) as c:
        resp = c.get(f"/apply-stream?token={TOKEN}")
    assert resp.status_code == 409
    assert "active" in resp.text.lower() or "consumer" in resp.text.lower()


@pytest.mark.webui
def test_apply_stream_active_flag_cleared_on_completion(fake_apply_ok):
    """After a /apply-stream generator finishes (sentinel reached
    OR client disconnects), the active flag must be cleared so a
    re-apply on the session can serve a new consumer. Pin the
    cleanup path."""
    app = _make_app()
    session = app.state.session_store.get_or_create(TOKEN)
    session.answers.update(_valid_answers())
    with _client(app) as c:
        csrf = _csrf_get(c, "/review")
        c.post(f"/apply?token={TOKEN}", data={"_csrf": csrf})
        _wait_for_state(session, ("completed", "failed"))
        with c.stream("GET", f"/apply-stream?token={TOKEN}") as resp:
            list(resp.iter_text())  # drain
    # Generator finally ran; active flag cleared.
    assert session.apply_stream_active is False


@pytest.mark.webui
def test_apply_stream_active_flag_set_synchronously_in_handler():
    """The active flag must be set in the handler BEFORE the
    StreamingResponse is returned, not inside the generator body.
    Otherwise two near-simultaneous GETs would both pass the gate
    (the generator body only runs when Starlette iterates it).

    Pin by calling the handler directly and asserting the flag is
    True even before the returned response's body is iterated."""

    async def _scenario():
        from starlette.requests import Request

        app = _make_app()
        session = app.state.session_store.get_or_create(TOKEN)
        session.apply_state = "running"
        session.apply_queue = asyncio.Queue()
        assert session.apply_stream_active is False

        # Build a minimal ASGI scope; the handler reads only
        # request.app.state.
        scope = {
            "type": "http",
            "method": "GET",
            "headers": [],
            "path": "/apply-stream",
            "query_string": b"",
            "app": app,
        }
        request = Request(scope, receive=lambda: None)
        resp = await review_mod.apply_stream_get(request)
        # Returned a StreamingResponse, flag flipped before body iter.
        assert session.apply_stream_active is True
        # Don't iterate the body — it would block on queue.get().
        del resp

    asyncio.run(_scenario())


@pytest.mark.webui
def test_apply_post_resets_stream_consumed_flag(fake_apply_ok):
    """Re-apply path: the consumed flag from the prior run must be
    reset so /apply-stream serves the new run's events rather than
    410-ing on the stale drained state."""
    app = _make_app()
    session = app.state.session_store.get_or_create(TOKEN)
    session.answers.update(_valid_answers())
    # Simulate a prior run that drained.
    session.apply_stream_consumed = True
    with _client(app) as c:
        csrf = _csrf_get(c, "/review")
        c.post(f"/apply?token={TOKEN}", data={"_csrf": csrf})
        # Immediately after apply_post returns, the flag is False.
        # (apply_state may still be "running" if the worker hasn't
        # finished; what matters is the reset happened.)
        assert session.apply_stream_consumed is False
        _wait_for_state(session, ("completed", "failed"))


@pytest.mark.webui
def test_apply_post_resets_stream_active_flag_on_reapply(fake_apply_ok):
    """Finding 1.1 (PRESHIP): re-apply must also reset
    apply_stream_active, not just apply_stream_consumed. The narrow
    failure mode is a prior /apply-stream generator that was
    garbage-collected unstarted (client disconnect between handler
    return and Starlette's first send). The generator's finally
    never ran so the active flag stayed True; without this reset
    every future /apply-stream consumer would 409 and the operator
    would be wedged.

    Simulate by directly setting the flag (mimicking the post-
    stranded-generator state) and confirm apply_post clears it AND
    that a subsequent /apply-stream connection is accepted (not
    409'd by the stale flag).
    """
    app = _make_app()
    session = app.state.session_store.get_or_create(TOKEN)
    session.answers.update(_valid_answers())
    # Simulate the post-stranded-generator state from the failure
    # mode in the finding: prior generator never started, finally
    # never fired, flag stuck True.
    session.apply_stream_active = True
    with _client(app) as c:
        csrf = _csrf_get(c, "/review")
        c.post(f"/apply?token={TOKEN}", data={"_csrf": csrf})
        # Reset happened in the re-apply branch of apply_post.
        assert session.apply_stream_active is False
        _wait_for_state(session, ("completed", "failed"))
        # And — load-bearing — a subsequent /apply-stream connection
        # is NOT rejected by the stale-flag 409 guard. (The terminal
        # + not-yet-consumed branch streams the tail.)
        with c.stream("GET", f"/apply-stream?token={TOKEN}") as resp:
            assert resp.status_code == 200
            list(resp.iter_text())  # drain


# ---- Re-apply after failure leaves no stale queue ------------------------


@pytest.mark.webui
def test_reapply_after_failure_uses_fresh_queue(fake_apply_ok):
    app = _make_app()
    session = app.state.session_store.get_or_create(TOKEN)
    session.answers.update(_valid_answers())
    # Simulate a prior failed run with a queue full of stale items.
    session.apply_state = "failed"
    session.apply_report = ApplyReport(steps=())
    stale_q: asyncio.Queue = asyncio.Queue()
    stale_q.put_nowait({"name": "stale", "status": "ok", "message": "stale"})
    session.apply_queue = stale_q
    with _client(app) as c:
        csrf = _csrf_get(c, "/review")
        c.post(f"/apply?token={TOKEN}", data={"_csrf": csrf})
        _wait_for_state(session, ("completed", "failed"))
    # New queue (different object), and it has only the fresh steps
    # + the sentinel — no "stale" carryover.
    assert session.apply_queue is not stale_q


# ---- CLI parity integration ---------------------------------------------


@pytest.mark.webui
def test_wizard_apply_matches_cli_apply_filesystem_state(tmp_path, monkeypatch):
    """The wizard's apply must produce the same lynceus.yaml that a
    direct CLI apply_config call with the same args would. We skip
    the bundled-import step (off in this test) so neither path hits
    the network or the watchlist DB; the comparison is YAML-shape only.

    No fakes here — we call the REAL apply_config in both paths.
    """
    # Direct CLI-style apply.
    cli_target = tmp_path / "cli" / "lynceus.yaml"
    cli_target.parent.mkdir(parents=True)
    # Both paths point at the same severity_overrides.yaml location so
    # the wizard-side persistence of severity_overrides_path doesn't
    # introduce a spurious diff in this parity check. The earlier shape
    # of this test happened to use distinct cli/ vs wiz/ severity
    # paths, which the pre-touchup wizard silently ignored — that
    # masked the very bug the touchup fixes. Pin them now.
    severity_path = tmp_path / "shared" / "severity_overrides.yaml"
    severity_path.parent.mkdir(parents=True)
    # Same parity argument applies to allowlist_path: both paths must
    # point at the same scaffolded allowlist file so the rendered
    # allowlist_path: lines in lynceus.yaml match byte-for-byte.
    allowlist_path = tmp_path / "shared" / "allowlist.yaml"
    from lynceus.config import CaptureConfig, Config
    cli_config = Config(
        kismet_url="http://localhost:2501",
        kismet_api_key="ABCDEF0123456789XYZ",
        kismet_sources=["external_wifi"],
        capture=CaptureConfig(probe_ssids=False, ble_friendly_names=True),
        ntfy_url="https://ntfy.sh",
        ntfy_topic="lynceus-prod-alerts",
        min_rssi=-70,
    )
    apply_config(
        cli_config,
        scope="user",
        target_path=cli_target,
        severity_overrides_path=severity_path,
        allowlist_path=allowlist_path,
        enabled_rule_types=None,
        run_bundled_import=False,
    )

    # Wizard apply, same Config + same scope, different target dir.
    wiz_target = tmp_path / "wiz" / "lynceus.yaml"
    wiz_target.parent.mkdir(parents=True)
    monkeypatch.setattr(
        "lynceus.paths.default_config_dir",
        lambda scope: tmp_path / "wiz",
    )
    # Wizard derives allowlist_path from paths.default_allowlist_path
    # (which calls default_config_dir); override to the shared path.
    monkeypatch.setattr(
        "lynceus.paths.default_allowlist_path",
        lambda scope: allowlist_path,
    )
    # Suppress the bundled-import in the wizard path too.
    real_apply = apply_config

    def apply_no_import(config, **kwargs):
        kwargs["run_bundled_import"] = False
        return real_apply(config, **kwargs)

    monkeypatch.setattr(review_mod, "apply_config", apply_no_import)
    app = _make_app(target_path=wiz_target)
    session = app.state.session_store.get_or_create(TOKEN)
    session.answers.update(_valid_answers())
    session.answers["severity_overrides_path"] = str(severity_path)
    with _client(app) as c:
        csrf = _csrf_get(c, "/review")
        c.post(f"/apply?token={TOKEN}", data={"_csrf": csrf})
        _wait_for_state(session, ("completed", "failed"), timeout=5.0)
    assert session.apply_state == "completed"

    # The two lynceus.yaml files should be byte-identical after
    # apply (same Config in, deterministic render out).
    assert cli_target.read_text(encoding="utf-8") == wiz_target.read_text(encoding="utf-8")


# ---- SSE generator robustness bundle (Findings 1.5, 2.2, 2.5) ------------


@pytest.mark.webui
def test_run_apply_task_sentinel_posted_on_cancellation(tmp_path):
    """Finding 1.5: even under task cancellation, the sentinel (None)
    must land on the queue so any in-flight SSE consumer's
    queue.get() unblocks rather than waiting forever. Post-fix the
    sentinel is posted via queue.put_nowait (synchronous, no await
    point), so a CancelledError landing at the sentinel-push moment
    cannot skip it."""

    import threading

    from lynceus.config import CaptureConfig, Config

    blocker = threading.Event()

    def hang(config, **kwargs):
        blocker.wait(timeout=3.0)
        return ApplyReport(steps=())

    async def scenario():
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue = asyncio.Queue()
        session = WizardSession(token=TOKEN)
        session.apply_state = "running"

        class FakeState:
            scope = "user"
            target_path = tmp_path / "lynceus.yaml"
            server = None

        config = Config(
            kismet_url="http://localhost:2501",
            capture=CaptureConfig(),
        )

        review_local = review_mod
        real = review_local.apply_config
        review_local.apply_config = hang
        try:
            task = asyncio.create_task(
                review_local._run_apply_task(
                    app_state=FakeState(),
                    session=session,
                    config=config,
                    severity_path=tmp_path / "severity_overrides.yaml",
                    allowlist_path=tmp_path / "allowlist.yaml",
                    enabled_rule_types=None,
                    queue=queue,
                    loop=loop,
                )
            )
            await asyncio.sleep(0.05)
            task.cancel()
            blocker.set()
            with pytest.raises((asyncio.CancelledError, Exception)):
                await task
        finally:
            review_local.apply_config = real
            blocker.set()

        # Drain the queue and confirm the sentinel landed. Other
        # items may or may not have been pushed depending on timing;
        # the load-bearing assertion is None being present.
        items = []
        while not queue.empty():
            items.append(queue.get_nowait())
        assert None in items, f"sentinel missing from queue items: {items!r}"

    asyncio.run(scenario())


@pytest.mark.webui
def test_run_apply_task_handles_sink_construction_failure(tmp_path):
    """Finding 2.2: if SSEProgressSink(...) construction raises, the
    apply task must still transition to a terminal state and post
    the sentinel — otherwise any in-flight consumer hangs and
    /apply-complete bounces forever to /apply-progress. Pre-fix,
    sink construction sat ABOVE the try; a raising __init__ would
    skip the finally entirely."""

    from lynceus.config import CaptureConfig, Config

    class BoomSink:
        def __init__(self, *args, **kwargs):
            raise RuntimeError("simulated sink init failure")

    async def scenario():
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue = asyncio.Queue()
        session = WizardSession(token=TOKEN)
        session.apply_state = "running"

        class FakeState:
            scope = "user"
            target_path = tmp_path / "lynceus.yaml"
            server = None

        config = Config(
            kismet_url="http://localhost:2501",
            capture=CaptureConfig(),
        )

        review_local = review_mod
        real_sink = review_local.SSEProgressSink
        review_local.SSEProgressSink = BoomSink
        try:
            await review_local._run_apply_task(
                app_state=FakeState(),
                session=session,
                config=config,
                severity_path=tmp_path / "severity_overrides.yaml",
                allowlist_path=tmp_path / "allowlist.yaml",
                enabled_rule_types=None,
                queue=queue,
                loop=loop,
            )
        finally:
            review_local.SSEProgressSink = real_sink

        # Terminal state reached; report has the synthetic failed step.
        assert session.apply_state == "failed"
        assert session.apply_report is not None
        last = session.apply_report.steps[-1]
        assert last.status == "failed"
        assert "simulated sink init failure" in last.message
        # Sentinel posted — consumers will not hang.
        items = []
        while not queue.empty():
            items.append(queue.get_nowait())
        assert None in items

    asyncio.run(scenario())


@pytest.mark.webui
def test_run_apply_task_handles_broken_exc_str(tmp_path):
    """Finding 2.2: if the underlying exception's __str__ raises, the
    synthetic step's f-string must NOT propagate — that would skip
    the partial-report write and strand apply_state at "running".
    Post-fix the f-string is guarded with try/except around str(exc)."""

    from lynceus.config import CaptureConfig, Config

    class BadStr(Exception):
        def __str__(self):  # type: ignore[override]
            raise RuntimeError("can't str me")

    def boom(config, **kwargs):
        raise BadStr()

    async def scenario():
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue = asyncio.Queue()
        session = WizardSession(token=TOKEN)
        session.apply_state = "running"

        class FakeState:
            scope = "user"
            target_path = tmp_path / "lynceus.yaml"
            server = None

        config = Config(
            kismet_url="http://localhost:2501",
            capture=CaptureConfig(),
        )

        review_local = review_mod
        real = review_local.apply_config
        review_local.apply_config = boom
        try:
            await review_local._run_apply_task(
                app_state=FakeState(),
                session=session,
                config=config,
                severity_path=tmp_path / "severity_overrides.yaml",
                allowlist_path=tmp_path / "allowlist.yaml",
                enabled_rule_types=None,
                queue=queue,
                loop=loop,
            )
        finally:
            review_local.apply_config = real

        assert session.apply_state == "failed"
        assert session.apply_report is not None
        last = session.apply_report.steps[-1]
        assert last.status == "failed"
        # Synthetic step still got created — message carries the type
        # name even when str(exc) raised.
        assert "BadStr" in last.message
        # Fallback marker for the unprintable str.
        assert "unprintable" in last.message

    asyncio.run(scenario())


@pytest.mark.webui
def test_apply_stream_emits_error_on_non_json_serializable_record():
    """Finding 2.5: if an item bypasses _json_safe (a future caller
    enqueues a raw object), json.dumps in the SSE generator must
    NOT silently kill the stream — the generator emits event: error
    + event: end so the client sees a definitive close and the
    `end` JS handler navigates to /apply-complete instead of the
    `onerror` "lost the progress stream" path firing without a
    reason.

    Pre-populate the queue with a non-serializable item followed by
    the sentinel; the SSE generator's first queue.get() returns the
    bad item and json.dumps raises. Pre-populating directly avoids
    the timing race a sink-based approach would introduce between
    the worker-thread call_soon_threadsafe schedule and the finally-
    block put_nowait(None)."""
    app = _make_app()
    session = app.state.session_store.get_or_create(TOKEN)

    # Simulate an in-flight apply with a non-JSON-serializable item
    # already in the queue, followed by the sentinel. asyncio.Queue
    # in Python 3.10+ does not bind to a loop in __init__; put_nowait
    # without waiters is loop-free. The generator's queue.get() in
    # the test client's loop binds the queue on first await.
    q: asyncio.Queue = asyncio.Queue()
    q.put_nowait(object())  # no JSON representation
    q.put_nowait(None)  # sentinel
    session.apply_queue = q
    session.apply_state = "running"

    with _client(app) as c:
        with c.stream("GET", f"/apply-stream?token={TOKEN}") as resp:
            assert resp.status_code == 200
            payload = "".join(resp.iter_text())

    # Generator did not die silently — emitted error + end so the
    # client's JS sees a definitive close rather than a hung stream.
    assert "event: error" in payload
    assert "event: end" in payload


# ---- Concurrent /apply rejected under lock (Finding 1.1) -----------------


@pytest.mark.webui
def test_apply_post_concurrent_rejection_under_lock(tmp_path):
    """Finding 1.1: two concurrent /apply POSTs must result in exactly
    one apply task being scheduled; the second sees state == "running"
    inside the apply_lock and returns 409.

    NOTE on what this test does and does not prove. Today this test
    passes EVEN WITHOUT session.apply_lock because there are no
    awaits between the apply_state check and the apply_state set, so
    the pair is event-loop-atomic on single-process uvicorn. The
    lock exists as future-proof defense: any await inserted in that
    block in a future change (audit logging, async probes, etc.)
    would silently open a TOCTOU window where two concurrent POSTs
    both see idle and both spawn an apply task. Pinning the
    concurrent-rejection behavior now means a future await insertion
    that breaks the invariant will turn a green test red.

    Drives apply_post directly via asyncio.gather so two requests
    race on the same loop — TestClient is sync and serializes
    requests, so it cannot reproduce the concurrent dispatch path.
    """
    import threading


    blocker = threading.Event()
    call_count = [0]

    def hang(config, **kwargs):
        call_count[0] += 1
        blocker.wait(timeout=3.0)
        return ApplyReport(steps=())

    async def scenario():
        from starlette.requests import Request

        app = _make_app(target_path=tmp_path / "lynceus.yaml")
        session = app.state.session_store.get_or_create(TOKEN)
        session.answers.update(_valid_answers())
        session.answers["severity_overrides_path"] = str(
            tmp_path / "severity_overrides.yaml"
        )

        def make_req():
            scope = {
                "type": "http",
                "method": "POST",
                "headers": [],
                "path": "/apply",
                "query_string": b"",
                "app": app,
            }
            return Request(scope, receive=lambda: None)

        review_local = review_mod
        real = review_local.apply_config
        review_local.apply_config = hang
        try:
            results = await asyncio.gather(
                review_local.apply_post(make_req()),
                review_local.apply_post(make_req()),
            )
            # Exactly one 303 (apply scheduled) + one 409 (lock saw
            # state already running). Order is non-deterministic;
            # sort by status to assert.
            statuses = sorted(r.status_code for r in results)
            assert statuses == [303, 409]
            assert session.apply_state == "running"
            assert session.apply_task is not None

            # Release the worker thread so the apply finishes.
            blocker.set()
            try:
                await asyncio.wait_for(session.apply_task, timeout=3.0)
            except Exception:
                pass

            # Only ONE fake apply_config invocation — the 409'd POST
            # never spawned a task.
            assert call_count[0] == 1
            assert session.apply_state in ("completed", "failed")
        finally:
            review_local.apply_config = real
            blocker.set()

    asyncio.run(scenario())


# ---- Cancellation finalizes to terminal state (Finding 7.2) --------------


@pytest.mark.webui
def test_run_apply_task_cancellation_flips_state_to_failed(tmp_path):
    """Finding 7.2: asyncio.CancelledError is a BaseException, not an
    Exception, so the `except Exception` clause in _run_apply_task
    does not catch it. Pre-fix, cancelling the apply task mid-
    to_thread left session.apply_state stuck at "running" and
    /apply-complete would bounce to /apply-progress which would hang
    forever on the empty SSE queue. Post-fix the finally synthesizes
    a failed step and flips state to "failed" so the operator's
    completion page renders cleanly.

    Drive _run_apply_task directly inside asyncio.run so we can
    cancel the task from inside the same loop where it runs —
    avoids the TestClient-portal-thread plumbing required to safely
    cancel a task running on starlette's background loop."""

    import threading

    from lynceus.config import CaptureConfig, Config

    blocker = threading.Event()

    def hang(config, **kwargs):
        # Block in the worker thread until the test releases us.
        # asyncio cancellation of the to_thread future does NOT abort
        # the worker — the test releases the blocker after cancel so
        # the executor thread doesn't leak.
        blocker.wait(timeout=3.0)
        return ApplyReport(steps=())

    async def scenario():
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue = asyncio.Queue()
        session = WizardSession(token=TOKEN)
        # Set apply_state to "running" so the test mirrors the real
        # apply_post flow (which flips state before creating the task).
        session.apply_state = "running"

        class FakeState:
            scope = "user"
            target_path = tmp_path / "lynceus.yaml"
            server = None

        config = Config(
            kismet_url="http://localhost:2501",
            capture=CaptureConfig(),
        )

        review_local = review_mod
        real = review_local.apply_config
        review_local.apply_config = hang
        try:
            task = asyncio.create_task(
                review_local._run_apply_task(
                    app_state=FakeState(),
                    session=session,
                    config=config,
                    severity_path=tmp_path / "severity_overrides.yaml",
                    allowlist_path=tmp_path / "allowlist.yaml",
                    enabled_rule_types=None,
                    queue=queue,
                    loop=loop,
                )
            )
            # Give the task one loop tick to enter asyncio.to_thread.
            await asyncio.sleep(0.05)
            assert session.apply_state == "running"
            task.cancel()
            # Release the worker thread so the executor doesn't leak.
            blocker.set()
            # The task finalizes through finally; await its completion.
            with pytest.raises((asyncio.CancelledError, Exception)):
                await task
        finally:
            review_local.apply_config = real
            blocker.set()

        # The fix: cancellation finalized to a terminal state, not
        # left stranded at "running".
        assert session.apply_state == "failed"
        # The synthetic cancellation step is in the report so the
        # completion page can surface it.
        assert session.apply_report is not None
        last = session.apply_report.steps[-1]
        assert last.status == "failed"
        assert "cancel" in last.message.lower()

    asyncio.run(scenario())


# ---- Task-creation failure rolls back state (Finding 7.1) ----------------


@pytest.mark.webui
def test_apply_post_create_task_failure_rolls_back_state():
    """Finding 7.1: if asyncio.create_task raises (closed loop, system
    resource pressure — rare), session.apply_state must NOT be left
    at "running" with no task to advance it through the state machine.
    Pre-fix order set state to running BEFORE create_task, so a
    failure would wedge the 409 guard for the wizard's life. Post-fix
    the handler returns 503 and the session stays at its pre-call
    state so the operator's retry is unblocked.

    Drive apply_post directly so the test can monkeypatch
    asyncio.create_task without breaking starlette's own task
    scheduling on the TestClient path."""

    async def scenario():
        from starlette.requests import Request

        app = _make_app()
        session = app.state.session_store.get_or_create(TOKEN)
        session.answers.update(_valid_answers())
        assert session.apply_state == "idle"

        scope = {
            "type": "http",
            "method": "POST",
            "headers": [],
            "path": "/apply",
            "query_string": b"",
            "app": app,
        }
        request = Request(scope, receive=lambda: None)

        real_create_task = asyncio.create_task

        def boom(coro, *args, **kwargs):
            # Close the coro so we don't get a "coroutine was never
            # awaited" warning when the test exits.
            if asyncio.iscoroutine(coro):
                coro.close()
            raise RuntimeError("simulated event loop closed")

        asyncio.create_task = boom  # type: ignore[assignment]
        try:
            resp = await review_mod.apply_post(request)
        finally:
            asyncio.create_task = real_create_task  # type: ignore[assignment]

        assert resp.status_code == 503
        # Pin the rollback: state is unchanged, no task stashed, no
        # queue assigned, no consumed-flag flip — operator can retry.
        assert session.apply_state == "idle"
        assert session.apply_task is None
        assert session.apply_queue is None

    asyncio.run(scenario())


# ---- Token enforcement on new endpoints ---------------------------------


@pytest.mark.webui
@pytest.mark.parametrize("path,method", [
    ("/apply-progress", "GET"),
    ("/apply-stream", "GET"),
])
def test_new_apply_routes_require_token(path, method):
    app = _make_app()
    with _client(app) as c:
        if method == "GET":
            assert c.get(path).status_code == 403
        else:
            assert c.post(path).status_code == 403


@pytest.mark.webui
def test_apply_stream_reports_a_cancelled_apply_instead_of_going_silent():
    """A CANCELLED apply must still say so on the stream, not just in the report.

    ⛔ The regression this pins is a disagreement between two surfaces
    describing the same apply. `_run_apply_task`'s `finally` synthesized a
    failed step for the cancellation path and wrote it to
    ``session.apply_report`` -- so ``/apply-complete`` rendered correctly --
    but never put it on ``session.apply_queue``. The SSE stream therefore
    opened, emitted its closing ``event: end`` and shut, and the operator
    watching the live progress page was told nothing at all.

    Measured before the fix, the entire payload was::

        'event: end\\ndata: {}\\n\\n'

    which is one ``data:`` (the end event's own empty object) and zero step
    records. ⭐ That is also the exact shape the weekly `latest-deps (3.13)`
    job failed with -- ``assert 1 >= 2`` against that literal payload --
    which is how this path was found.

    ⚠️ Keyed on the stream CONTENT rather than on a queue length, so a future
    refactor that changes how the step is enqueued still has to keep the
    operator-visible promise: a terminal apply says which way it ended.
    """
    app = _make_app()
    session = app.state.session_store.get_or_create(TOKEN)
    session.answers.update(_valid_answers())
    with _client(app) as c:
        csrf = _csrf_get(c, "/review")
        c.post(f"/apply?token={TOKEN}", data={"_csrf": csrf})
        task = session.apply_task
        assert task is not None, "precondition: the apply task must exist to be cancelled"
        task.get_loop().call_soon_threadsafe(task.cancel)
        _wait_for_state(session, ("completed", "failed"), timeout=5.0)
        with c.stream("GET", f"/apply-stream?token={TOKEN}") as resp:
            assert resp.status_code == 200
            chunks = list(resp.iter_text())
    payload = "".join(chunks)

    assert session.apply_state == "failed", (
        f"a cancelled apply must land terminal-failed, got {session.apply_state!r}"
    )
    assert "event: end" in payload, "the stream must still close cleanly"
    assert "cancelled" in payload, (
        "the cancellation never reached the stream, so the operator watching "
        f"/apply-progress saw nothing explain it. payload={payload!r}"
    )
    assert payload.count("data:") >= 2, (
        "only the end event's own `data: {}` was present, i.e. zero step "
        f"records. payload={payload!r}"
    )
