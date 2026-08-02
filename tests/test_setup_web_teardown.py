"""Tests for the /done teardown handler + 10-min grace window
(F6 Phase 2b, Touch 3).

Pins:
* POST /done renders the shutting-down page AND schedules
  ``server.should_exit = True`` after a brief delay (so the
  response flushes before the socket closes).
* POST /done cancels any pending grace-window timer (Done is the
  explicit operator signal; the grace timer is just the
  walked-away safety net).
* /done requires the setup token AND a CSRF cookie+token (the
  shutdown route is state-changing).
* The 10-min grace window auto-shuts-down the server when Done
  never fires; tests use a short override of
  ``APPLY_GRACE_SECONDS`` so the suite doesn't stall.
* The grace timer survives the running → completed transition
  (timer is armed in _run_apply_task's finally block).
* ``run_wizard_server`` exposes the uvicorn Server on
  ``app.state.server`` so the handler can reach it.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from lynceus.setup.web import review as review_mod
from lynceus.setup.web.app import create_wizard_app

TOKEN = "test-setup-token-fixed-for-unit-tests-1234567890"


class FakeServer:
    """Minimal uvicorn.Server stand-in for testing the shutdown signal."""

    def __init__(self):
        self.should_exit = False


def _make_app_with_fake_server(**overrides):
    kwargs = dict(setup_token=TOKEN, scope="user", target_path=Path("/tmp/x.yaml"))
    kwargs.update(overrides)
    app = create_wizard_app(**kwargs)
    app.state.server = FakeServer()
    return app


def _client(app):
    return TestClient(app, follow_redirects=False)


def _csrf_get(client, path):
    client.get(f"{path}?token={TOKEN}")
    return client.cookies.get("lynceus_csrf")


# ---- /done handler -------------------------------------------------------


@pytest.mark.webui
def test_done_post_returns_shutting_down_page(monkeypatch):
    # Tighten the delay so the test doesn't actually wait 500ms for
    # the background task to fire.
    monkeypatch.setattr(review_mod, "DONE_SHUTDOWN_DELAY_SECONDS", 0.02)
    app = _make_app_with_fake_server()
    with _client(app) as c:
        csrf = _csrf_get(c, "/apply-complete")
        resp = c.post(f"/done?token={TOKEN}", data={"_csrf": csrf})
    assert resp.status_code == 200
    body = resp.text
    assert "shutting down" in body.lower()
    # The page tells the operator what to do next.
    assert "lynceus-quickstart" in body or "systemctl" in body


@pytest.mark.webui
def test_done_post_schedules_server_shutdown(monkeypatch):
    monkeypatch.setattr(review_mod, "DONE_SHUTDOWN_DELAY_SECONDS", 0.02)
    app = _make_app_with_fake_server()
    server: FakeServer = app.state.server
    assert server.should_exit is False
    with _client(app) as c:
        csrf = _csrf_get(c, "/apply-complete")
        c.post(f"/done?token={TOKEN}", data={"_csrf": csrf})
        # Wait a bit longer than the delay so the scheduled task
        # has fired on the portal loop.
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline and not server.should_exit:
            time.sleep(0.01)
    assert server.should_exit is True


@pytest.mark.webui
def test_done_post_without_server_state_still_renders(monkeypatch):
    """If app.state.server isn't set (test path or unusual launch),
    /done must still render the page rather than crash. The
    shutdown signal is a no-op in that case."""
    monkeypatch.setattr(review_mod, "DONE_SHUTDOWN_DELAY_SECONDS", 0.02)
    app = create_wizard_app(
        setup_token=TOKEN, scope="user", target_path=Path("/tmp/x.yaml")
    )
    # Note: no app.state.server here.
    with _client(app) as c:
        csrf = _csrf_get(c, "/apply-complete")
        resp = c.post(f"/done?token={TOKEN}", data={"_csrf": csrf})
    assert resp.status_code == 200
    assert "shutting down" in resp.text.lower()


@pytest.mark.webui
def test_done_post_cancels_grace_timer():
    """Done is the explicit signal; the grace timer must back off."""

    async def _scenario():
        app = _make_app_with_fake_server()
        session = app.state.session_store.get_or_create(TOKEN)
        # Arm a grace timer that would otherwise fire in 30s.
        session.apply_grace_task = asyncio.create_task(
            review_mod._grace_shutdown(app.state.server, 30.0)
        )
        # Use TestClient inside the scenario only to fire the POST;
        # the actual cancel logic runs in the same event loop.
        # Easier: call the handler directly.
        # Build a minimal Request scope manually is fiddly; use TestClient.
        with _client(app) as c:
            csrf = _csrf_get(c, "/apply-complete")
            c.post(f"/done?token={TOKEN}", data={"_csrf": csrf})
        # Give the cancel time to propagate.
        await asyncio.sleep(0.05)
        # The session's grace_task should be cancelled and cleared.
        assert session.apply_grace_task is None

    asyncio.run(_scenario())


# ---- /done gate on apply_state (Finding 3.1) ------------------------------


@pytest.mark.webui
def test_done_post_refuses_mid_apply_with_409(monkeypatch):
    """Finding 3.1: /done during a running apply must NOT schedule
    shutdown — the worker thread is mid-pipeline and uvicorn tearing
    down would leave the apply in a partial state. The handler
    returns 409 and the FakeServer's should_exit stays False."""
    monkeypatch.setattr(review_mod, "DONE_SHUTDOWN_DELAY_SECONDS", 0.02)
    app = _make_app_with_fake_server()
    session = app.state.session_store.get_or_create(TOKEN)
    session.apply_state = "running"
    server: FakeServer = app.state.server
    with _client(app) as c:
        csrf = _csrf_get(c, "/apply-complete")
        resp = c.post(f"/done?token={TOKEN}", data={"_csrf": csrf})
        # Wait beyond the (non-existent) shutdown delay to be sure
        # no task fired.
        time.sleep(0.1)
    assert resp.status_code == 409
    assert "in progress" in resp.text.lower()
    assert server.should_exit is False


@pytest.mark.webui
def test_done_post_409_renders_styled_html_with_progress_link(monkeypatch):
    """Finding 1.3 (PRESHIP): the 409 response on /done during a
    running apply must render the styled done_busy.html template
    rather than a bare text/plain Response. The operator who hits
    this (the two-tabs race with a stale /apply-complete tab) gets
    a page that names the cause and links to the live progress
    page, rather than an unstyled "apply still in progress..."
    line that the rest of the wizard's surfaces wouldn't produce."""
    monkeypatch.setattr(review_mod, "DONE_SHUTDOWN_DELAY_SECONDS", 0.02)
    app = _make_app_with_fake_server()
    session = app.state.session_store.get_or_create(TOKEN)
    session.apply_state = "running"
    with _client(app) as c:
        csrf = _csrf_get(c, "/apply-complete")
        resp = c.post(f"/done?token={TOKEN}", data={"_csrf": csrf})
    assert resp.status_code == 409
    # HTML, not text/plain.
    assert resp.headers["content-type"].startswith("text/html")
    body = resp.text
    # Renders the actual template (extends _base.html so the
    # <!doctype html> root is present).
    assert "<!doctype html>" in body.lower() or "<html" in body.lower()
    # Operator-facing copy explains why and surfaces the live
    # progress page as the action.
    assert "Apply still in progress" in body
    assert "/apply-progress" in body


@pytest.mark.webui
@pytest.mark.parametrize("state", ["idle", "completed", "failed"])
def test_done_post_allowed_from_non_running_states(monkeypatch, state):
    """The 409 gate fires only on "running"; idle/completed/failed
    must still schedule shutdown as today."""
    monkeypatch.setattr(review_mod, "DONE_SHUTDOWN_DELAY_SECONDS", 0.02)
    app = _make_app_with_fake_server()
    session = app.state.session_store.get_or_create(TOKEN)
    session.apply_state = state
    server: FakeServer = app.state.server
    with _client(app) as c:
        csrf = _csrf_get(c, "/apply-complete")
        resp = c.post(f"/done?token={TOKEN}", data={"_csrf": csrf})
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline and not server.should_exit:
            time.sleep(0.01)
    assert resp.status_code == 200
    assert server.should_exit is True


# ---- Shutdown task ref retention (Finding 3.4) ----------------------------


@pytest.mark.webui
def test_done_post_holds_shutdown_task_reference(monkeypatch):
    """Finding 3.4: the fire-and-forget shutdown task must be held
    on the session so the asyncio loop doesn't weakly GC it before
    it fires. Pin by asserting session.shutdown_task is populated
    after /done returns."""
    # Lengthen the delay enough that the task is still pending
    # when we inspect the session — otherwise we'd race the test
    # window and might catch a Done task that already finished.
    monkeypatch.setattr(review_mod, "DONE_SHUTDOWN_DELAY_SECONDS", 5.0)
    app = _make_app_with_fake_server()
    session = app.state.session_store.get_or_create(TOKEN)
    assert session.shutdown_task is None
    with _client(app) as c:
        csrf = _csrf_get(c, "/apply-complete")
        c.post(f"/done?token={TOKEN}", data={"_csrf": csrf})
        # Inspect while the TestClient context (and its event loop)
        # is still alive — teardown cancels in-flight tasks, so a
        # post-context check would see done()=True regardless of
        # whether the strong ref was held.
        assert session.shutdown_task is not None
        assert not session.shutdown_task.done()


# ---- Grace timer ---------------------------------------------------------


@pytest.mark.webui
def test_grace_shutdown_signals_after_delay():
    async def _scenario():
        server = FakeServer()
        await review_mod._grace_shutdown(server, 0.05)
        assert server.should_exit is True

    asyncio.run(_scenario())


@pytest.mark.webui
def test_grace_shutdown_cancellation_does_not_signal():
    """If the grace task is cancelled (Done took over), should_exit
    must stay False — we don't want a Done click to also fire the
    timer's shutdown via some race."""
    async def _scenario():
        server = FakeServer()
        task = asyncio.create_task(review_mod._grace_shutdown(server, 5.0))
        await asyncio.sleep(0.02)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        # Even after a small wait, no signal.
        await asyncio.sleep(0.05)
        assert server.should_exit is False

    asyncio.run(_scenario())


# ---- Grace timer arm precedes terminal flip (Finding 4.1) ----------------


@pytest.mark.webui
def test_grace_timer_arms_before_apply_state_terminal_flip(monkeypatch):
    """Finding 4.1: the grace timer must be armed BEFORE apply_state
    transitions to "completed" or "failed", so a re-apply POST that
    observes the terminal state also observes a non-None grace task
    and can cancel it cleanly.

    Records the sequence of (event, value) tuples for grace-arm
    calls and apply_state writes. Asserts grace-arm appears before
    the first terminal state write.
    """
    from lynceus.setup.models import ApplyReport, ApplyStep
    from lynceus.setup.web import session as session_mod

    monkeypatch.setattr(
        review_mod, "apply_config",
        lambda config, **kwargs: ApplyReport(steps=(
            ApplyStep(name="write_config", status="ok", message="ok"),
        )),
    )
    monkeypatch.setattr(review_mod, "APPLY_GRACE_SECONDS", 60.0)

    events: list[tuple[str, str | None]] = []

    # Spy on _schedule_apply_grace_shutdown.
    real_schedule = review_mod._schedule_apply_grace_shutdown

    def spy_schedule(app_state, session):
        events.append(("grace_armed", None))
        return real_schedule(app_state, session)

    monkeypatch.setattr(review_mod, "_schedule_apply_grace_shutdown", spy_schedule)

    # Intercept apply_state writes via __setattr__ on a subclass.
    class TracedSession(session_mod.WizardSession):
        def __setattr__(self, name, value):
            if name == "apply_state":
                events.append(("apply_state", value))
            super().__setattr__(name, value)

    # Swap the session class for the duration of the test.
    monkeypatch.setattr(session_mod, "WizardSession", TracedSession)

    app = _make_app_with_fake_server()
    session = app.state.session_store.get_or_create(TOKEN)
    assert isinstance(session, TracedSession)
    session.answers.update({
        "kismet_url": "http://localhost:2501",
        "kismet_api_key": "ABCDEF0123456789XYZ",
        "kismet_sources": ["external_wifi"],
        "probe_ssids": False,
        "ble_friendly_names": True,
        "ntfy_url": "https://ntfy.sh",
        "ntfy_topic": "lynceus-prod-alerts",
        "min_rssi": -70,
        "severity_overrides_path": "",
        "enable_alerting": False,
        "enabled_rule_types": [],
    })
    with _client(app) as c:
        csrf = _csrf_get(c, "/review")
        c.post(f"/apply?token={TOKEN}", data={"_csrf": csrf})
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline and session.apply_state not in ("completed", "failed"):
            time.sleep(0.02)

    # Filter to grace_armed and terminal-flip writes; ignore the
    # initial "running" set in apply_post (pre-fix order had grace
    # armed in finally too — the contract under test is the order
    # *inside* _run_apply_task's finally).
    relevant = [
        ev for ev in events
        if ev[0] == "grace_armed" or (ev[0] == "apply_state" and ev[1] in ("completed", "failed"))
    ]
    # Grace must be armed BEFORE the terminal state write.
    assert relevant, f"no relevant events captured; got {events}"
    assert relevant[0] == ("grace_armed", None), (
        f"expected grace-armed first; got {relevant}"
    )
    assert any(ev[0] == "apply_state" for ev in relevant), (
        f"never saw terminal apply_state flip; got {relevant}"
    )


@pytest.mark.webui
def test_apply_completion_arms_grace_timer(monkeypatch):
    """End-to-end: after apply_config returns, _run_apply_task fires
    _schedule_apply_grace_shutdown which arms the timer on the
    session."""
    from lynceus.setup.models import ApplyReport, ApplyStep

    # Make the grace window short enough for the test to observe
    # without waiting 10 minutes.
    monkeypatch.setattr(review_mod, "APPLY_GRACE_SECONDS", 5.0)
    monkeypatch.setattr(
        review_mod, "apply_config",
        lambda config, **kwargs: ApplyReport(steps=(
            ApplyStep(name="write_config", status="ok", message="ok"),
        )),
    )
    app = _make_app_with_fake_server()
    session = app.state.session_store.get_or_create(TOKEN)
    session.answers.update({
        "kismet_url": "http://localhost:2501",
        "kismet_api_key": "ABCDEF0123456789XYZ",
        "kismet_sources": ["external_wifi"],
        "probe_ssids": False,
        "ble_friendly_names": True,
        "ntfy_url": "https://ntfy.sh",
        "ntfy_topic": "lynceus-prod-alerts",
        "min_rssi": -70,
        "severity_overrides_path": "",
        "enable_alerting": False,
        "enabled_rule_types": [],
    })
    with _client(app) as c:
        csrf = _csrf_get(c, "/review")
        c.post(f"/apply?token={TOKEN}", data={"_csrf": csrf})
        # Wait for the apply to land in terminal state.
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline and session.apply_state not in ("completed", "failed"):
            time.sleep(0.02)
    assert session.apply_state == "completed"
    # The grace timer should be armed (task object present, not
    # cancelled, not yet done because we set it to 5s).
    assert session.apply_grace_task is not None


# ---- Token + CSRF ------------------------------------------------------


@pytest.mark.webui
def test_done_requires_token():
    app = _make_app_with_fake_server()
    with _client(app) as c:
        assert c.post("/done").status_code == 403


@pytest.mark.webui
def test_done_requires_csrf():
    """The /done route is state-changing (it kills the server). The
    CSRF middleware refuses a POST without a matching cookie+token
    pair — bare POST gets 403."""
    app = _make_app_with_fake_server()
    with _client(app) as c:
        # No GET first, so no CSRF cookie set; POST should 403 from
        # the CSRF middleware, not the token middleware.
        resp = c.post(f"/done?token={TOKEN}")
    assert resp.status_code == 403
    assert "csrf" in resp.text.lower()
