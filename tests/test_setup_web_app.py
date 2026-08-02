"""Tests for the lynceus-setup web wizard scaffold (Touch 1).

Pins the token gate (query + header + 403 paths), confirms
``compare_digest`` is on the validation path, asserts CSRF wiring,
checks that ``/healthz`` is exempt, and verifies that
``run_wizard_server`` honors the host/port it is given (so the CLI
caller in Touch 2 controls the bind, not the wizard module).

Phase 2a invariants under test:
- No route mounts ``apply_config``.
- The token middleware short-circuits before CSRF for unauthorized
  requests.
- The session store is per-app (two app instances do not share
  in-flight ``answers``).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from lynceus.setup.web import auth as wizard_auth
from lynceus.setup.web import server as wizard_server_mod
from lynceus.setup.web.app import TOKEN_EXEMPT_PATHS, create_wizard_app
from lynceus.setup.web.server import (
    _browser_url,
    _open_browser_when_ready,
    generate_setup_token,
    run_wizard_server,
)
from lynceus.setup.web.session import SessionStore, WizardSession
from lynceus.webui.csrf import CSRFMiddleware

TOKEN = "test-setup-token-fixed-for-unit-tests-1234567890"


def _make_app(**overrides):
    kwargs = dict(
        setup_token=TOKEN,
        scope="user",
        target_path=Path("/tmp/wizard-test-lynceus.yaml"),
    )
    kwargs.update(overrides)
    return create_wizard_app(**kwargs)


# ---- token-gate behavior --------------------------------------------------


@pytest.mark.webui
def test_root_without_token_returns_403():
    app = _make_app()
    with TestClient(app) as client:
        resp = client.get("/")
    assert resp.status_code == 403
    assert "setup token" in resp.text.lower()


@pytest.mark.webui
def test_root_with_query_token_returns_200():
    app = _make_app()
    with TestClient(app) as client:
        resp = client.get(f"/?token={TOKEN}")
    assert resp.status_code == 200
    assert "lynceus-setup" in resp.text.lower()


@pytest.mark.webui
def test_root_with_header_token_returns_200():
    app = _make_app()
    with TestClient(app) as client:
        resp = client.get("/", headers={"X-Setup-Token": TOKEN})
    assert resp.status_code == 200


@pytest.mark.webui
def test_root_with_wrong_token_returns_403():
    app = _make_app()
    with TestClient(app) as client:
        resp = client.get("/?token=not-the-right-token-just-some-garbage-1234")
    assert resp.status_code == 403


@pytest.mark.webui
def test_root_with_empty_token_returns_403():
    app = _make_app()
    with TestClient(app) as client:
        resp = client.get("/?token=")
    assert resp.status_code == 403


@pytest.mark.webui
def test_token_validated_via_compare_digest(monkeypatch):
    """The token check must go through ``secrets.compare_digest``, not
    bare ``==``. We spy on the imported name in the auth module."""
    calls: list[tuple[str, str]] = []

    def spy(a, b):
        calls.append((a, b))
        # Return True only when the args are equal lengths and contents
        # so the request still proceeds normally on a valid token.
        return a == b

    monkeypatch.setattr(wizard_auth, "compare_digest", spy)
    app = _make_app()
    with TestClient(app) as client:
        resp = client.get(f"/?token={TOKEN}")
    assert resp.status_code == 200
    assert calls, "compare_digest was not invoked on a valid token"
    # Both arguments must equal the configured token.
    assert all(provided == TOKEN and stored == TOKEN for provided, stored in calls)


@pytest.mark.webui
def test_token_length_mismatch_skips_compare_digest(monkeypatch):
    """Length mismatch should fast-path to 403 without invoking
    ``compare_digest`` (which would raise on unequal-length inputs in
    older Python versions and at minimum wastes a syscall)."""
    calls: list[tuple[str, str]] = []

    def spy(a, b):
        calls.append((a, b))
        return False

    monkeypatch.setattr(wizard_auth, "compare_digest", spy)
    app = _make_app()
    with TestClient(app) as client:
        resp = client.get("/?token=short")
    assert resp.status_code == 403
    assert calls == []


# ---- exempt paths ---------------------------------------------------------


@pytest.mark.webui
def test_healthz_unauthenticated_returns_200():
    app = _make_app()
    with TestClient(app) as client:
        resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "service": "lynceus-setup-web"}


@pytest.mark.webui
def test_healthz_in_exempt_paths():
    # Pinned literal so a future refactor that drops /healthz from the
    # exempt tuple breaks loudly here instead of in a smoke test.
    assert "/healthz" in TOKEN_EXEMPT_PATHS


# ---- CSRF wiring ----------------------------------------------------------


@pytest.mark.webui
def test_csrf_middleware_is_wired():
    app = _make_app()
    classes = [m.cls for m in app.user_middleware]
    assert CSRFMiddleware in classes
    assert wizard_auth.SetupTokenMiddleware in classes


@pytest.mark.webui
def test_csrf_runs_inside_token_gate():
    """A POST with a valid token but no CSRF cookie must reach the CSRF
    middleware (403 from CSRF, not 403 from the token gate). We can't
    distinguish the two 403s by status alone, so we check the response
    body — token-gate 403 says "setup token", CSRF 403 says "CSRF"."""
    app = _make_app()
    with TestClient(app) as client:
        # Clear any cookies the GET would have set.
        client.cookies.clear()
        resp = client.post(f"/?token={TOKEN}", data={"x": "1"})
    assert resp.status_code == 403
    assert "csrf" in resp.text.lower()


# ---- /cancel gate (Finding 1.6) -------------------------------------------


@pytest.mark.webui
def test_cancel_redirects_to_progress_when_apply_running():
    """Finding 1.6: /cancel during a running apply must NOT clear
    the session store — clearing would orphan the in-flight apply
    task and let the operator re-walk the wizard with a fresh
    session that bypasses the /apply 409 guard, spawning a second
    concurrent apply against the same target paths.

    Pin: 303 redirect to /apply-progress, AND the running session
    survives in the store."""
    app = _make_app()
    session = app.state.session_store.get_or_create(TOKEN)
    session.apply_state = "running"
    # Touch a piece of session state so we can prove it survived.
    session.answers["kismet_url"] = "http://localhost:2501"
    with TestClient(app, follow_redirects=False) as client:
        resp = client.get(f"/cancel?token={TOKEN}")
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/apply-progress")
    assert f"token={TOKEN}" in resp.headers["location"]
    # Session not cleared.
    surviving = app.state.session_store.get(TOKEN)
    assert surviving is not None
    assert surviving.apply_state == "running"
    assert surviving.answers.get("kismet_url") == "http://localhost:2501"


@pytest.mark.webui
@pytest.mark.parametrize("state", ["idle", "completed", "failed"])
def test_cancel_clears_session_from_non_running_states(state):
    """/cancel from any non-running state renders the cancelled
    page and clears the session store (today's behavior preserved).
    Parametrized so a future regression that over-gates one of these
    states fails loudly."""
    app = _make_app()
    session = app.state.session_store.get_or_create(TOKEN)
    session.apply_state = state
    session.answers["kismet_url"] = "http://localhost:2501"
    with TestClient(app, follow_redirects=False) as client:
        resp = client.get(f"/cancel?token={TOKEN}")
    assert resp.status_code == 200
    assert "cancelled" in resp.text.lower() or "cancel" in resp.text.lower()
    # Session cleared: a fresh get_or_create yields an empty session.
    fresh = app.state.session_store.get_or_create(TOKEN)
    assert fresh.answers == {}
    assert fresh.apply_state == "idle"


# ---- session store --------------------------------------------------------


def test_session_store_get_or_create_idempotent():
    store = SessionStore()
    s1 = store.get_or_create("token-a")
    s2 = store.get_or_create("token-a")
    assert s1 is s2
    assert isinstance(s1, WizardSession)
    assert s1.token == "token-a"
    assert s1.answers == {}


def test_session_store_isolates_by_token():
    store = SessionStore()
    a = store.get_or_create("token-a")
    b = store.get_or_create("token-b")
    a.answers["kismet_url"] = "http://kismet.example/"
    assert b.answers == {}


def test_session_store_is_per_app_instance():
    app1 = _make_app()
    app2 = _make_app()
    assert app1.state.session_store is not app2.state.session_store


# ---- server entry ---------------------------------------------------------


def test_generate_setup_token_is_url_safe_and_fresh():
    t1 = generate_setup_token()
    t2 = generate_setup_token()
    assert t1 != t2
    # secrets.token_urlsafe(32) → 43 chars URL-safe, no padding.
    assert len(t1) == 43
    safe = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
    assert all(c in safe for c in t1)


def _patch_uvicorn_server(monkeypatch):
    """Replace uvicorn.Server with a FakeServer that captures the
    Config it was constructed with. Returns the instances list so
    tests can inspect.

    Phase 2b uses uvicorn.Server explicitly (rather than
    ``uvicorn.run``) so the /done handler can flip
    ``server.should_exit = True``. The tests follow."""
    instances: list = []

    class FakeServer:
        def __init__(self, config):
            self.config = config
            self.should_exit = False
            instances.append(self)

        def run(self):
            self.ran = True

    import uvicorn
    monkeypatch.setattr(uvicorn, "Server", FakeServer)
    return instances


def test_run_wizard_server_passes_host_port_to_uvicorn(monkeypatch, tmp_path):
    instances = _patch_uvicorn_server(monkeypatch)
    target = tmp_path / "lynceus.yaml"
    rc = run_wizard_server(
        host="127.0.0.1",
        port=8766,
        scope="user",
        target_path=target,
        no_browser=True,
    )
    assert rc == 0
    assert len(instances) == 1
    server = instances[0]
    assert server.config.host == "127.0.0.1"
    assert server.config.port == 8766
    assert server.ran is True
    # The app passed to uvicorn carries scope + target_path on state,
    # AND the server is exposed back on app.state.server for the
    # /done handler to reach.
    app = server.config.app
    assert app.state.scope == "user"
    assert app.state.target_path == target
    assert app.state.server is server


def test_run_wizard_server_honors_remote_bind(monkeypatch, tmp_path):
    instances = _patch_uvicorn_server(monkeypatch)
    run_wizard_server(
        host="0.0.0.0",
        port=8766,
        scope="user",
        target_path=tmp_path / "lynceus.yaml",
        no_browser=True,
    )
    assert instances[0].config.host == "0.0.0.0"


def test_run_wizard_server_prints_url_with_token(monkeypatch, tmp_path, capsys):
    """The operator needs the URL+token on stdout so they can paste it
    into a browser. Pin both the URL shape and that the token printed
    matches the one the app actually accepts."""
    _patch_uvicorn_server(monkeypatch)

    # Capture the token created by the server.
    created_tokens: list[str] = []
    real_generate = generate_setup_token

    def spy_generate():
        t = real_generate()
        created_tokens.append(t)
        return t

    monkeypatch.setattr("lynceus.setup.web.server.generate_setup_token", spy_generate)

    run_wizard_server(
        host="127.0.0.1",
        port=8766,
        scope="user",
        target_path=tmp_path / "lynceus.yaml",
        no_browser=True,
    )
    out = capsys.readouterr().out
    assert "127.0.0.1:8766" in out
    assert created_tokens, "no token was generated"
    assert created_tokens[0] in out


# ---------------------------------------------------------------------------
# Browser auto-open (UX-polish arc Touch 1)
# ---------------------------------------------------------------------------


def test_browser_url_is_tokenized_and_loopback_normalized():
    """The auto-open target carries the per-run token and rewrites an
    all-interfaces bind to loopback (0.0.0.0 isn't browsable; the local
    box reaches the wizard over loopback regardless)."""
    assert _browser_url("127.0.0.1", 8766, "tok") == "http://127.0.0.1:8766/?token=tok"
    assert _browser_url("0.0.0.0", 8766, "tok") == "http://127.0.0.1:8766/?token=tok"
    assert _browser_url("::", 8766, "tok") == "http://127.0.0.1:8766/?token=tok"
    # A concrete LAN bind is preserved verbatim.
    assert _browser_url("192.168.1.5", 8766, "tok") == "http://192.168.1.5:8766/?token=tok"


class _ReadyServer:
    started = True


class _NeverReadyServer:
    started = False


def test_open_browser_when_ready_opens_tokenized_url(monkeypatch):
    """Once the server reports started, the tokenized URL is opened."""
    opened: list[str] = []
    monkeypatch.setattr(
        wizard_server_mod.webbrowser, "open", lambda u: opened.append(u) or True
    )
    _open_browser_when_ready(_ReadyServer(), "http://127.0.0.1:8766/?token=tok", "127.0.0.1", 8766)
    assert opened == ["http://127.0.0.1:8766/?token=tok"]


def test_open_browser_when_ready_prints_guidance_when_open_fails(monkeypatch, capsys):
    """No usable browser (headless/sudo/no DISPLAY): webbrowser.open
    returns False — we print prominent manual-access guidance (the
    tokenized URL plus how to reach a localhost-bound wizard over SSH)
    rather than fail."""
    monkeypatch.setattr(wizard_server_mod.webbrowser, "open", lambda u: False)
    _open_browser_when_ready(_ReadyServer(), "http://127.0.0.1:8766/?token=tok", "127.0.0.1", 8766)
    out = capsys.readouterr().out
    assert "http://127.0.0.1:8766/?token=tok" in out
    assert "ssh -L 8766:127.0.0.1:8766" in out
    assert "localhost" in out.lower()


def test_open_browser_when_ready_swallows_open_exception(monkeypatch, capsys):
    """webbrowser.open can raise under odd platform configs; degrade to
    the printed guidance instead of crashing the wizard thread."""
    def _boom(_u):
        raise RuntimeError("no display")

    monkeypatch.setattr(wizard_server_mod.webbrowser, "open", _boom)
    _open_browser_when_ready(_ReadyServer(), "http://127.0.0.1:8766/?token=tok", "127.0.0.1", 8766)
    out = capsys.readouterr().out
    assert "http://127.0.0.1:8766/?token=tok" in out
    assert "ssh -L 8766:127.0.0.1:8766" in out


def test_open_browser_guidance_non_loopback_bind_omits_tunnel(monkeypatch, capsys):
    """A non-loopback bind (e.g. --bind 0.0.0.0) is reachable directly, so
    the guidance must name the bind host and NOT claim localhost-only or
    hand the operator an SSH tunnel they don't need."""
    monkeypatch.setattr(wizard_server_mod.webbrowser, "open", lambda u: False)
    _open_browser_when_ready(_ReadyServer(), "http://127.0.0.1:8766/?token=tok", "0.0.0.0", 8766)
    out = capsys.readouterr().out
    assert "0.0.0.0" in out
    assert "ssh -L" not in out


def test_open_browser_when_ready_times_out_without_opening(monkeypatch, capsys):
    """If the server never reports ready, the helper returns without
    opening anything and prints no guidance (the printed URL+token is the
    standing fallback)."""
    opened: list[str] = []
    monkeypatch.setattr(
        wizard_server_mod.webbrowser, "open", lambda u: opened.append(u) or True
    )
    _open_browser_when_ready(
        _NeverReadyServer(), "http://127.0.0.1:8766/?token=tok", "127.0.0.1", 8766,
        timeout=0.05, poll=0.01,
    )
    assert opened == []
    assert "ssh -L" not in capsys.readouterr().out


def test_run_wizard_server_no_browser_skips_open(monkeypatch, tmp_path):
    """--no-browser must not open a browser even though the server runs."""
    _patch_uvicorn_server(monkeypatch)
    opened: list[str] = []
    monkeypatch.setattr(
        wizard_server_mod.webbrowser, "open", lambda u: opened.append(u) or True
    )
    run_wizard_server(
        host="127.0.0.1",
        port=8766,
        scope="user",
        target_path=tmp_path / "lynceus.yaml",
        no_browser=True,
    )
    assert opened == []


def test_run_wizard_server_auto_opens_by_default(monkeypatch, tmp_path):
    """By default the wizard auto-opens the tokenized URL once the server
    is serving. Uses a server whose ``started`` is already True so the
    daemon thread opens promptly; an Event makes the assertion
    non-racy."""
    import threading as _threading

    instances: list = []

    class StartedServer:
        started = True

        def __init__(self, config):
            self.config = config
            self.should_exit = False
            instances.append(self)

        def run(self):
            self.ran = True

    import uvicorn
    monkeypatch.setattr(uvicorn, "Server", StartedServer)

    opened: list[str] = []
    fired = _threading.Event()

    def _spy_open(u):
        opened.append(u)
        fired.set()
        return True

    monkeypatch.setattr(wizard_server_mod.webbrowser, "open", _spy_open)

    run_wizard_server(
        host="127.0.0.1",
        port=8766,
        scope="user",
        target_path=tmp_path / "lynceus.yaml",
    )
    assert fired.wait(timeout=3.0), "browser auto-open never fired"
    assert len(opened) == 1
    assert opened[0].startswith("http://127.0.0.1:8766/?token=")
