"""Web UI authentication: the password, the session, and the middleware.

⭐ The structural guard in this file is
``test_every_route_is_behind_auth_or_deliberately_exempt``. It derives the route
table from the LIVE app and requires every path to be either refused without a
session or named in ``EXEMPT_PATHS``. That is what makes a route added next
month protected by default — the failure this repo has already paid for twice is
a hand-maintained list that the code outran (``DOWNLOAD_SUFFIXES`` in the browser
gate; the hardcoded 23-route POST list that four merges outran).
"""

from __future__ import annotations

import json
import re
import tempfile
import time
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import create_app
from lynceus.webui.auth import (
    EXEMPT_PATHS,
    MIN_PASSWORD_LENGTH,
    SESSION_COOKIE_NAME,
    LoginRateLimiter,
    PasswordError,
    SessionStore,
    hash_password,
    safe_next_path,
    verify_against_configured,
    verify_password,
)
from lynceus.webui.credentials import (
    CREDENTIALS_VERSION,
    CredentialsError,
    load_credentials,
    write_credentials,
)
from lynceus.webui.csrf import CSRF_COOKIE_NAME, CSRF_FORM_FIELD

REPO_ROOT = Path(__file__).resolve().parents[1]

PASSWORD = "correct-horse-battery-staple"

#: Hashed once. scrypt is ~15 ms by design and this file builds a lot of apps.
_HASH = hash_password(PASSWORD)


# --- Fixtures -----------------------------------------------------------------


def _make_config(td: str) -> Config:
    allowlist = Path(td) / "allowlist.yaml"
    allowlist.write_text("entries: []\n", encoding="utf-8")
    return Config(
        db_path=td + "/s.db",
        rules_path=str(REPO_ROOT / "config" / "rules.yaml"),
        allowlist_path=str(allowlist),
    )


@pytest.fixture()
def authed_app():
    """An app WITH a credentials file, plus its db."""
    td = tempfile.mkdtemp()
    cfg = _make_config(td)
    write_credentials(cfg.resolved_ui_auth_path(), _HASH)
    db = Database(cfg.db_path)
    db.ensure_location("default", "Default")
    try:
        yield create_app(cfg, db), db, cfg
    finally:
        db.close()


@pytest.fixture()
def open_app():
    """An app with NO credentials file — the default loopback install."""
    td = tempfile.mkdtemp()
    cfg = _make_config(td)
    db = Database(cfg.db_path)
    db.ensure_location("default", "Default")
    try:
        yield create_app(cfg, db), db, cfg
    finally:
        db.close()


def _login(client, password: str = PASSWORD):
    """Perform a real form login and return the response."""
    client.get("/login")
    token = client.cookies.get(CSRF_COOKIE_NAME)
    assert token, "no CSRF cookie after GET /login; the login form cannot be submitted"
    return client.post(
        "/login",
        data={"password": password, CSRF_FORM_FIELD: token, "next": "/"},
    )


# --- Password hashing ---------------------------------------------------------


def test_a_password_verifies_against_its_own_hash():
    assert verify_password(PASSWORD, _HASH)


def test_a_wrong_password_does_not_verify():
    assert not verify_password(PASSWORD + "x", _HASH)
    assert not verify_password("", _HASH)


def test_two_hashes_of_one_password_differ():
    """Salted. Identical hashes would mean a shared salt, which makes a
    precomputed table worth building."""
    assert hash_password(PASSWORD) != hash_password(PASSWORD)


def test_a_short_password_is_refused_before_it_is_hashed():
    with pytest.raises(PasswordError):
        hash_password("x" * (MIN_PASSWORD_LENGTH - 1))


def test_an_absurdly_long_password_is_refused():
    """A multi-megabyte POST body must not become multi-megabyte scrypt work on
    an unauthenticated route."""
    with pytest.raises(PasswordError):
        hash_password("x" * 5000)
    # And the verify side refuses it too, rather than doing the work.
    assert not verify_password("x" * 5000, _HASH)


@pytest.mark.parametrize(
    "broken",
    [
        "",
        "not-a-hash",
        "scrypt$16384$8$1$onlyfourfields",
        "bcrypt$16384$8$1$c2FsdA==$aGFzaA==",
        "scrypt$notanumber$8$1$c2FsdA==$aGFzaA==",
        "scrypt$16384$8$1$!!!notbase64!!!$aGFzaA==",
        # ⛔ A hostile credentials file naming a cost parameter that would
        # allocate gigabytes. Must be refused, not attempted.
        "scrypt$1073741824$8$1$c2FsdA==$aGFzaA==",
        # Not a power of two: hashlib raises, and a raise here is a 500 on an
        # unauthenticated route.
        "scrypt$16383$8$1$c2FsdA==$aGFzaA==",
    ],
)
def test_a_malformed_hash_returns_false_rather_than_raising(broken):
    assert verify_password(PASSWORD, broken) is False


def test_verifying_against_no_credential_still_burns_the_work():
    """Timing. "No password is set here" must not be readable from the clock.

    ⚠️ Asserts a RATIO against a measured baseline, not a wall-clock constant.
    A fixed threshold is a flake on a loaded box, and this repo runs its suites
    under a load average of 9 to 15.
    """
    baseline = _time_call(lambda: verify_password(PASSWORD + "x", _HASH))
    unconfigured = _time_call(lambda: verify_against_configured(PASSWORD, None))
    assert verify_against_configured(PASSWORD, None) is False
    # The unconfigured path must not be an order of magnitude cheaper. It is
    # doing the same scrypt, so anything under 10x is comfortably passing and
    # a short-circuit return would be ~1000x.
    assert unconfigured > baseline / 10, (
        f"verifying against no credential took {unconfigured:.4f}s against a "
        f"{baseline:.4f}s baseline — the no-password case is short-circuiting, "
        f"which tells an unauthenticated caller that no password is set"
    )


def test_verifying_against_a_real_credential_still_works():
    assert verify_against_configured(PASSWORD, _HASH) is True
    assert verify_against_configured("wrong", _HASH) is False


def _time_call(fn) -> float:
    start = time.perf_counter()
    fn()
    return time.perf_counter() - start


def test_a_verification_is_not_absurdly_slow():
    """A ceiling, not a value.

    ⚠️ The Pi is the deployment target and this has NOT been measured there.
    This asserts only that the chosen cost parameters have not been raised into
    a range where a login blocks the event loop for a visible second.
    """
    assert _time_call(lambda: verify_password(PASSWORD, _HASH)) < 2.0


# --- Sessions -----------------------------------------------------------------


def test_a_created_session_validates_and_a_random_token_does_not():
    store = SessionStore()
    token = store.create()
    assert store.validate(token)
    assert not store.validate("something-else")
    assert not store.validate(None)
    assert not store.validate("")


def test_revoke_ends_a_session():
    store = SessionStore()
    token = store.create()
    store.revoke(token)
    assert not store.validate(token)


def test_a_session_expires_on_idle():
    clock = _FakeClock(1000.0)
    store = SessionStore(idle_seconds=100, absolute_seconds=10_000, now=clock)
    token = store.create()
    clock.advance(99)
    assert store.validate(token), "expired one second early"
    clock.advance(101)
    assert not store.validate(token)


def test_using_a_session_refreshes_its_idle_clock_but_not_its_absolute_one():
    """The distinction is the point: idle is refreshable, absolute is not.

    Without the absolute ceiling a session used every 7 hours forever is still
    a session that was authenticated once, months ago.
    """
    clock = _FakeClock(1000.0)
    store = SessionStore(idle_seconds=100, absolute_seconds=250, now=clock)
    token = store.create()
    clock.advance(90)
    assert store.validate(token)  # refreshes last_seen
    clock.advance(90)
    assert store.validate(token)  # would have died on idle without the refresh
    clock.advance(90)  # now 270s since creation, past the absolute ceiling
    assert not store.validate(token), "the absolute ceiling was refreshable"


def test_purge_expired_bounds_the_table():
    clock = _FakeClock(1000.0)
    store = SessionStore(idle_seconds=100, absolute_seconds=10_000, now=clock)
    for _ in range(5):
        store.create()
    assert len(store) == 5
    clock.advance(200)
    live = store.create()
    assert store.purge_expired() == 5
    assert len(store) == 1
    assert store.validate(live)


class _FakeClock:
    def __init__(self, start: float) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


# --- Rate limiting ------------------------------------------------------------


def test_the_limiter_locks_out_after_the_configured_failures():
    clock = _FakeClock(0.0)
    limiter = LoginRateLimiter(max_failures=3, window_seconds=60, lockout_seconds=60, now=clock)
    assert not limiter.is_locked("10.0.0.1")
    assert limiter.record_failure("10.0.0.1") is False
    assert limiter.record_failure("10.0.0.1") is False
    assert limiter.record_failure("10.0.0.1") is True
    assert limiter.is_locked("10.0.0.1")


def test_a_lockout_expires():
    clock = _FakeClock(0.0)
    limiter = LoginRateLimiter(max_failures=2, window_seconds=60, lockout_seconds=60, now=clock)
    limiter.record_failure("10.0.0.1")
    limiter.record_failure("10.0.0.1")
    assert limiter.is_locked("10.0.0.1")
    clock.advance(61)
    assert not limiter.is_locked("10.0.0.1")


def test_one_clients_failures_do_not_lock_out_another():
    limiter = LoginRateLimiter(max_failures=2)
    limiter.record_failure("10.0.0.1")
    limiter.record_failure("10.0.0.1")
    assert limiter.is_locked("10.0.0.1")
    assert not limiter.is_locked("10.0.0.2")


def test_a_success_clears_the_failure_count():
    limiter = LoginRateLimiter(max_failures=3)
    limiter.record_failure("10.0.0.1")
    limiter.record_failure("10.0.0.1")
    limiter.record_success("10.0.0.1")
    # Two more must not now trip a limit that counts to three.
    assert limiter.record_failure("10.0.0.1") is False
    assert limiter.record_failure("10.0.0.1") is False
    assert not limiter.is_locked("10.0.0.1")


def test_an_unidentifiable_client_is_still_limited():
    """⛔ Fails CLOSED. A request with no client address must not be unlimited."""
    limiter = LoginRateLimiter(max_failures=2)
    limiter.record_failure(None)
    limiter.record_failure(None)
    assert limiter.is_locked(None)


def test_a_flood_cannot_evict_an_active_lockout():
    """⛔ Found by writing this test, and it was a real hole.

    Plain least-recently-used eviction let an attacker clear their OWN lockout:
    get locked out, then stop failing and make requests from enough other
    addresses, and the now-cold lockout bucket is pushed out of the table. The
    lockout is the state worth protecting, so it is the one thing eviction
    refuses to touch.

    ⚠️ This deliberately does NOT claim a partial failure count survives a
    flood. It does not, the implementation does not pretend it does, and
    asserting it would be asserting a property nothing provides.
    """
    from lynceus.webui.auth import MAX_TRACKED_CLIENTS

    clock = _FakeClock(0.0)
    limiter = LoginRateLimiter(
        max_failures=3, window_seconds=10_000, lockout_seconds=10_000, now=clock
    )
    for _ in range(3):
        limiter.record_failure("attacker")
    assert limiter.is_locked("attacker"), "fixture did not achieve a lockout"

    # The attacker goes quiet and floods the table from other addresses, each
    # newer than the last, so their own bucket is the coldest thing in it.
    for i in range(MAX_TRACKED_CLIENTS + 100):
        clock.advance(1)
        limiter.record_failure(f"flood-{i}")

    assert limiter.is_locked("attacker"), (
        "the attacker cleared their own lockout by flooding the client table"
    )


def test_a_client_arriving_at_a_saturated_table_is_still_limited():
    """⛔ Fails closed at capacity. When every tracked bucket is an active
    lockout there is nothing safe to evict, and the alternative to sharing a
    bucket is letting a new caller through unlimited."""
    from lynceus.webui.auth import MAX_TRACKED_CLIENTS

    clock = _FakeClock(0.0)
    limiter = LoginRateLimiter(
        max_failures=1, window_seconds=10_000, lockout_seconds=10_000, now=clock
    )
    # One failure each, at max_failures=1, locks every one of them.
    for i in range(MAX_TRACKED_CLIENTS):
        limiter.record_failure(f"locked-{i}")

    limiter.record_failure("late-arrival")
    assert limiter.is_locked("late-arrival"), (
        "a client arriving at a saturated table was not rate limited at all"
    )


# --- Redirect safety ----------------------------------------------------------


@pytest.mark.parametrize(
    "hostile",
    [
        "//evil.test/",
        "/\\evil.test",
        "https://evil.test/",
        "http://evil.test",
        "evil.test",
        "javascript:alert(1)",
        "/ok\r\nSet-Cookie: x=1",
        "/ok\nX: y",
        None,
        "",
    ],
)
def test_a_hostile_next_target_is_reduced_to_the_default(hostile):
    assert safe_next_path(hostile) == "/"


@pytest.mark.parametrize(
    "ok", ["/", "/alerts", "/devices/aa:bb:cc:dd:ee:ff", "/alerts?severity=high"]
)
def test_a_same_site_path_survives(ok):
    assert safe_next_path(ok) == ok


@pytest.mark.parametrize("stripped", ["\t", "\n", "\r"], ids=["tab", "lf", "cr"])
def test_a_character_browsers_strip_cannot_smuggle_a_network_relative_target(stripped):
    """The three characters the WHATWG URL parser removes *before* parsing.

    ⛔ Each turns ``/X/evil.test`` into ``//evil.test`` in the browser's hands,
    which is the single shape this function exists to refuse. The check that
    caught ``\\r`` and ``\\n`` was a literal list and let ``\\t`` straight through
    — CodeQL flagged the redirect, and the sanitizer really was short. So this
    asserts the *reason*: what a browser strips must not leave a network-relative
    target behind.
    """
    hostile = f"/{stripped}/evil.test"
    result = safe_next_path(hostile)
    assert result == "/", f"{hostile!r} survived as {result!r}"
    # Spelling out why the assertion above matters: this is what the browser
    # would have resolved the survivor to.
    assert hostile.replace(stripped, "") == "//evil.test"


def test_no_c0_control_character_survives_in_a_next_target():
    """Derive the range, do not transcribe three of it.

    A hand-written tuple of ``("\\r", "\\n", "\\x00")`` is how tab got through in
    the first place. Iterating the whole C0 range plus DEL means the next
    control character nobody thought of is covered without anyone editing a list.
    """
    survivors = [
        hex(c)
        for c in list(range(0x20)) + [0x7F]
        if safe_next_path(f"/{chr(c)}/evil.test") != "/"
    ]
    assert not survivors, f"control characters survived a next target: {survivors}"


# --- The credentials file -----------------------------------------------------


def test_a_written_credentials_file_is_0600(tmp_path):
    path = tmp_path / "ui_auth.json"
    write_credentials(path, _HASH)
    assert (path.stat().st_mode & 0o777) == 0o600


def test_rewriting_over_a_world_readable_file_tightens_it(tmp_path):
    """⛔ The measured half. ``os.open``'s creation mode is ignored when the
    path already exists, so a pre-existing 0644 file would be refilled with the
    hash and left at 0644. The fchmod is what makes the mode true."""
    path = tmp_path / "ui_auth.json"
    path.write_text("{}", encoding="utf-8")
    path.chmod(0o644)
    write_credentials(path, _HASH)
    assert (path.stat().st_mode & 0o777) == 0o600


def test_a_missing_credentials_file_is_none_not_an_error(tmp_path):
    assert load_credentials(tmp_path / "nope.json") is None


@pytest.mark.parametrize(
    "content",
    [
        "not json at all",
        "[]",
        '{"version": 99, "password_hash": "x"}',
        '{"version": 1}',
        '{"version": 1, "password_hash": ""}',
        '{"version": 1, "password_hash": 12345}',
    ],
)
def test_a_corrupt_credentials_file_raises_rather_than_disabling_auth(tmp_path, content):
    """⛔ The fail-open this must never become.

    Returning None for a corrupt file would mean a truncated write — a disk
    full, a power cut mid-save — silently turns authentication OFF on the next
    restart, and the UI comes up wide open with nothing said.
    """
    path = tmp_path / "ui_auth.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(CredentialsError):
        load_credentials(path)


def test_an_over_broad_mode_is_reported_not_enforced(tmp_path):
    path = tmp_path / "ui_auth.json"
    write_credentials(path, _HASH)
    path.chmod(0o644)
    creds = load_credentials(path)
    assert creds is not None, "an over-broad mode must not make the file unusable"
    assert creds.over_broad_mode == 0o644


def test_a_correctly_moded_file_reports_no_complaint(tmp_path):
    """The control. Without it the assertion above passes for a function that
    always reports a complaint."""
    path = tmp_path / "ui_auth.json"
    write_credentials(path, _HASH)
    creds = load_credentials(path)
    assert creds is not None
    assert creds.over_broad_mode is None


def test_the_written_file_is_the_declared_version(tmp_path):
    path = tmp_path / "ui_auth.json"
    write_credentials(path, _HASH)
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["version"] == CREDENTIALS_VERSION
    assert payload["password_hash"] == _HASH


def test_the_credentials_path_is_derived_from_the_database(tmp_path):
    """One resolver. Two callers disagreeing means lynceus-ui-passwd writes a
    password where lynceus-ui does not look for one."""
    cfg = Config(db_path=str(tmp_path / "state" / "s.db"))
    assert cfg.resolved_ui_auth_path() == tmp_path / "state" / "ui_auth.json"


def test_an_explicit_ui_auth_path_wins(tmp_path):
    cfg = Config(db_path=str(tmp_path / "s.db"), ui_auth_path=str(tmp_path / "elsewhere.json"))
    assert cfg.resolved_ui_auth_path() == tmp_path / "elsewhere.json"


# --- The middleware, end to end -----------------------------------------------


def test_an_unauthenticated_browser_is_redirected_to_login(authed_app):
    app, _db, _cfg = authed_app
    client = TestClient(app, follow_redirects=False)
    resp = client.get("/", headers={"accept": "text/html"})
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/login?next=")


def test_an_unauthenticated_post_gets_401_and_not_a_redirect(authed_app):
    """⛔ The distinction that a cold read already caught once in this repo: a
    login redirect is a 303, and a script that follows redirects reads the
    resulting 200 + HTML login form as success. A programmatic caller must be
    told no in a way it cannot mistake."""
    app, db = authed_app[0], authed_app[1]
    client = TestClient(app, follow_redirects=False)
    before = db._conn.execute("SELECT COUNT(*) FROM rule_type_snoozes").fetchone()[0]
    resp = client.post("/rules/watchlist_mac/snooze", data={"duration_seconds": "86400"})
    assert resp.status_code == 401, f"got {resp.status_code}, not 401"
    after = db._conn.execute("SELECT COUNT(*) FROM rule_type_snoozes").fetchone()[0]
    assert after == before, "an unauthenticated POST changed persistent state"


def test_an_unauthenticated_curl_style_get_gets_401(authed_app):
    """No Accept: text/html — so no redirect, because there is no browser to
    send anywhere."""
    app = authed_app[0]
    client = TestClient(app, follow_redirects=False)
    resp = client.get("/alerts.csv", headers={"accept": "*/*"})
    assert resp.status_code == 401


def test_the_case_file_download_is_not_reachable_without_a_session(authed_app):
    """⭐ Named specifically because it is the richest single export the system
    has — a device's complete location history, co-observation record and
    captured evidence, in one unauthenticated GET before this change."""
    app = authed_app[0]
    client = TestClient(app, follow_redirects=False)
    resp = client.get("/devices/aa:bb:cc:dd:ee:ff/case-file.zip", headers={"accept": "*/*"})
    assert resp.status_code == 401
    assert b"PK" not in resp.content[:8], "a zip was served to an unauthenticated caller"


def test_login_then_the_dashboard_is_reachable(authed_app):
    app = authed_app[0]
    client = TestClient(app, follow_redirects=False)
    resp = _login(client)
    assert resp.status_code == 303, resp.text[:400]
    assert client.cookies.get(SESSION_COOKIE_NAME)
    page = client.get("/", headers={"accept": "text/html"})
    assert page.status_code == 200


def test_a_wrong_password_does_not_start_a_session(authed_app):
    app = authed_app[0]
    client = TestClient(app, follow_redirects=False)
    resp = _login(client, "definitely-not-the-password")
    assert resp.status_code == 401
    assert not client.cookies.get(SESSION_COOKIE_NAME)


def test_logout_ends_the_session(authed_app):
    app = authed_app[0]
    client = TestClient(app, follow_redirects=False)
    _login(client)
    assert client.get("/", headers={"accept": "text/html"}).status_code == 200
    token = client.cookies.get(CSRF_COOKIE_NAME)
    out = client.post("/logout", data={CSRF_FORM_FIELD: token})
    assert out.status_code == 303
    # The cookie is cleared, and — the half that matters — the token is dead
    # server-side even if a caller keeps presenting it.
    assert client.get("/", headers={"accept": "text/html"}).status_code == 303


def test_a_revoked_session_token_replayed_by_hand_is_refused(authed_app):
    """The control for the test above: proves logout revokes server-side rather
    than merely asking the browser to forget."""
    app = authed_app[0]
    client = TestClient(app, follow_redirects=False)
    _login(client)
    stolen = client.cookies.get(SESSION_COOKIE_NAME)
    client.post("/logout", data={CSRF_FORM_FIELD: client.cookies.get(CSRF_COOKIE_NAME)})
    replay = TestClient(app, follow_redirects=False)
    replay.cookies.set(SESSION_COOKIE_NAME, stolen)
    assert replay.get("/", headers={"accept": "text/html"}).status_code == 303


def test_the_session_cookie_is_httponly_and_samesite_and_not_secure_over_http(authed_app):
    """⛔ ``Secure`` over plain HTTP is the bug this repo already shipped once:
    the browser stores the cookie and then withholds it from every subsequent
    request, so turning on remote access broke every form on the site."""
    app = authed_app[0]
    client = TestClient(app, follow_redirects=False)
    resp = _login(client)
    # ⚠️ get_list, NOT headers.items(). httpx comma-joins repeated headers into
    # one value, so a login response — which sets the session cookie AND the
    # rotated CSRF cookie — arrives as a single string beginning with the
    # session cookie. A startswith() check against that passes for the session
    # assertions and silently reports "no CSRF cookie was reissued". Measured;
    # the first draft of this file did exactly that and blamed the code.
    setcookies = resp.headers.get_list("set-cookie")
    session_cookie = next(c for c in setcookies if c.startswith(SESSION_COOKIE_NAME + "="))
    assert "HttpOnly" in session_cookie
    assert "SameSite=Strict" in session_cookie
    assert "Secure" not in session_cookie, "Secure on a plain-HTTP cookie is never returned"


def test_the_session_cookie_outlives_the_idle_window(authed_app):
    """⛔ Max-Age is the ABSOLUTE lifetime, not the idle one.

    A cookie's Max-Age is fixed when it is set, while the server refreshes a
    session's idle clock on every request. Setting Max-Age to the 8-hour idle
    window therefore logs out an operator who has been using the dashboard
    continuously for 8 hours — an expiry that reads as a session bug. Both
    timeouts are enforced server-side; the cookie is only a bearer token.
    """
    from lynceus.webui.auth import SESSION_ABSOLUTE_SECONDS, SESSION_IDLE_SECONDS

    app = authed_app[0]
    client = TestClient(app, follow_redirects=False)
    resp = _login(client)
    cookie = next(
        c for c in resp.headers.get_list("set-cookie")
        if c.startswith(SESSION_COOKIE_NAME + "=")
    )
    assert f"Max-Age={SESSION_ABSOLUTE_SECONDS}" in cookie, cookie
    assert f"Max-Age={SESSION_IDLE_SECONDS}" not in cookie, (
        "the cookie expires at the idle window, so continuous use is logged out"
    )


def test_the_csrf_token_is_rotated_on_login(authed_app):
    """A double-submit token is self-issued to anyone who can GET a page, so
    one collected before sign-in must not survive it."""
    app = authed_app[0]
    client = TestClient(app, follow_redirects=False)
    client.get("/login")
    before = client.cookies.get(CSRF_COOKIE_NAME)
    assert before
    resp = client.post(
        "/login", data={"password": PASSWORD, CSRF_FORM_FIELD: before, "next": "/"}
    )
    assert resp.status_code == 303
    setcookies = resp.headers.get_list("set-cookie")  # see the note above on get_list
    rotated = [c for c in setcookies if c.startswith(CSRF_COOKIE_NAME + "=")]
    assert rotated, "no CSRF cookie was reissued on login"
    assert f"{CSRF_COOKIE_NAME}={before}" not in rotated[0], "the pre-login CSRF token survived"


def test_the_login_form_is_itself_csrf_protected(authed_app):
    """It is not special-cased out of the CSRF middleware."""
    app = authed_app[0]
    client = TestClient(app, follow_redirects=False)
    client.get("/login")
    resp = client.post("/login", data={"password": PASSWORD})  # no token
    assert resp.status_code == 403


def test_repeated_wrong_passwords_lock_the_caller_out(authed_app):
    from lynceus.webui.auth import LOGIN_MAX_FAILURES

    app = authed_app[0]
    client = TestClient(app, follow_redirects=False)
    last = None
    for _ in range(LOGIN_MAX_FAILURES):
        last = _login(client, "wrong-password-here")
    assert last is not None and last.status_code == 401
    # The next attempt is refused before the password is even considered — and
    # the RIGHT password is refused too, which is what a lockout means.
    locked = _login(client, PASSWORD)
    assert locked.status_code == 429
    assert not client.cookies.get(SESSION_COOKIE_NAME)


def test_a_csp_header_is_present_on_an_auth_rejection(authed_app):
    """Middleware ordering. CSP is registered last so it runs outermost and
    wraps the 401 as well as the 403 CSRF returns."""
    app = authed_app[0]
    client = TestClient(app, follow_redirects=False)
    resp = client.get("/alerts.csv", headers={"accept": "*/*"})
    assert resp.status_code == 401
    assert "content-security-policy" in {k.lower() for k in resp.headers}


def test_the_login_page_renders_before_authentication(authed_app):
    app = authed_app[0]
    client = TestClient(app, follow_redirects=False)
    resp = client.get("/login", headers={"accept": "text/html"})
    assert resp.status_code == 200
    assert "password" in resp.text.lower()
    # It must not leak whether a password is set, or who set it.
    assert PASSWORD not in resp.text


def test_a_logged_in_operator_visiting_login_is_sent_on(authed_app):
    app = authed_app[0]
    client = TestClient(app, follow_redirects=False)
    _login(client)
    resp = client.get("/login", headers={"accept": "text/html"})
    assert resp.status_code == 303


def test_the_login_page_does_not_echo_a_hostile_next_into_the_form(authed_app):
    app = authed_app[0]
    client = TestClient(app, follow_redirects=False)
    resp = client.get("/login?next=https://evil.test/", headers={"accept": "text/html"})
    assert resp.status_code == 200
    assert "evil.test" not in resp.text


# --- The structural guard -----------------------------------------------------


def test_every_route_is_behind_auth_or_deliberately_exempt(authed_app):
    """⭐ The guard that makes this fail-closed by construction.

    Derived from the LIVE app: every registered path is either refused without
    a session or named in ``EXEMPT_PATHS``. A route added next month is behind
    authentication without anyone remembering to put it there, and a route
    added to the exempt list has to be argued for here.

    ⚠️ Path PARAMETERS are filled with a placeholder rather than skipped. A
    version of this that skipped parameterised routes would have exempted
    ``/devices/{mac}/case-file.zip`` — the single richest export in the system —
    from the only test that checks it is protected.
    """
    app = authed_app[0]
    client = TestClient(app, follow_redirects=False)

    paths = _concrete_paths(app)
    assert len(paths) >= 40, (
        f"only {len(paths)} routes derived; the app did not build its routing "
        f"table and this guard is measuring nothing"
    )

    unprotected = []
    for path, methods in sorted(paths.items()):
        if any(path == e or path.startswith(e + "/") for e in EXEMPT_PATHS):
            continue
        method = "GET" if "GET" in methods else sorted(methods)[0]
        resp = client.request(method, path, headers={"accept": "*/*"})
        if resp.status_code != 401:
            unprotected.append(f"{method} {path} -> {resp.status_code}")

    assert not unprotected, (
        "these routes answered an unauthenticated caller with something other "
        f"than 401: {unprotected}. Either put them behind the middleware or "
        "add them to EXEMPT_PATHS with a written reason."
    )


def _concrete_paths(app) -> dict[str, set[str]]:
    """Live route table with path params filled in."""
    out: dict[str, set[str]] = {}
    for route in app.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)
        if not path or not methods:
            continue
        concrete = re.sub(r"\{[^}]+\}", "aa:bb:cc:dd:ee:ff", path)
        out.setdefault(concrete, set()).update(methods)
    return out


def test_the_exempt_set_is_exactly_what_was_argued_for():
    """⛔ Pinned as a SET, not a size.

    A cap on the length lets an entry be SWAPPED — drop ``/healthz``, add
    ``/probes``, and a length check still passes while the probe-SSID history of
    every device in range becomes reachable without a session. Changing this set
    should require editing this list, which is where the reasons are.

    Each entry's justification lives on ``auth.EXEMPT_PATHS``. In short:
    ``/login`` is the credential surface (circular otherwise); ``/static`` is the
    site's own CSS/JS and holds no operator data; the two health surfaces are
    the documented monitoring contract and were MEASURED to name no device —
    see ``test_the_exempt_health_surfaces_name_no_device``, which greps the
    bytes rather than trusting that sentence.
    """
    assert set(EXEMPT_PATHS) == {"/login", "/static", "/healthz", "/healthz.json"}, (
        f"the exempt set changed to {sorted(EXEMPT_PATHS)}. Every entry is a "
        f"route an unauthenticated caller can reach. Add the reason to "
        f"auth.EXEMPT_PATHS and to this test, deliberately."
    )


def test_the_exempt_list_is_short_and_every_entry_is_reachable(authed_app):
    """An exemption is a claim. A list that grew silently is how a hole gets in.

    ⚠️ Also asserts each exempt path actually ANSWERS. An entry naming a route
    that no longer exists is dead weight that makes the list look more
    considered than it is.
    """
    app = authed_app[0]
    client = TestClient(app, follow_redirects=False)
    assert len(EXEMPT_PATHS) <= 5, (
        f"the exempt list has grown to {len(EXEMPT_PATHS)}: {EXEMPT_PATHS}. "
        f"Every entry is a route an unauthenticated caller can reach."
    )
    for entry in EXEMPT_PATHS:
        probe = "/static/app.css" if entry == "/static" else entry
        resp = client.get(probe, headers={"accept": "*/*"})
        assert resp.status_code < 400, f"exempt path {probe} answered {resp.status_code}"


def test_the_exempt_health_surfaces_name_no_device(authed_app):
    """⭐ Enforced on the BYTES, not on a reading of the handler.

    ``/healthz`` and ``/healthz.json`` are exempt because they are the
    documented monitoring contract and disclose aggregates only. That claim was
    measured 2026-08-25 with a watchlist row, a device row and an alert all
    present — and a claim about output that is checked by reading the code is
    the claim this repo has already been wrong about three times. So this seeds
    the data and greps the response.
    """
    app, db, _cfg = authed_app
    mac = "AA:BB:CC:DD:EE:FF"
    vendor = "VendorNameThatMustNotLeak"
    db.add_watchlist(
        pattern=mac, pattern_type="mac", severity="high", description="TargetLabel"
    )
    db.upsert_device(
        mac=mac, device_type="wifi", oui_vendor=vendor, is_randomized=0, now_ts=int(time.time())
    )
    db.add_alert(
        ts=int(time.time()),
        rule_name="watchlist_mac",
        mac=mac,
        message=f"{mac} seen",
        severity="high",
        rule_type="watchlist_mac",
    )

    client = TestClient(app, follow_redirects=False)
    for path in ("/healthz", "/healthz.json"):
        resp = client.get(path, headers={"accept": "*/*"})
        assert resp.status_code == 200, f"{path} is exempt but answered {resp.status_code}"
        body = resp.text
        assert not re.search(r"(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b", body), (
            f"{path} is reachable without a session and disclosed a MAC address"
        )
        assert vendor not in body, f"{path} disclosed a device vendor"
        assert "TargetLabel" not in body, f"{path} disclosed a watchlist description"


# --- The default install is unchanged -----------------------------------------


def test_with_no_credentials_file_nothing_requires_a_login(open_app):
    """The other direction. A loopback single-operator install must behave
    exactly as it did before this feature existed."""
    app = open_app[0]
    client = TestClient(app, follow_redirects=False)
    assert client.get("/", headers={"accept": "text/html"}).status_code == 200


def test_with_no_credentials_file_there_is_no_login_route(open_app):
    app = open_app[0]
    paths = {getattr(r, "path", None) for r in app.routes}
    assert "/login" not in paths
    assert "/logout" not in paths


def test_with_credentials_the_login_routes_exist(authed_app):
    """The control for the test above."""
    app = authed_app[0]
    paths = {getattr(r, "path", None) for r in app.routes}
    assert "/login" in paths
    assert "/logout" in paths


def test_the_signout_control_appears_only_when_auth_is_configured(authed_app, open_app):
    authed_client = TestClient(authed_app[0], follow_redirects=False)
    _login(authed_client)
    assert "sign out" in authed_client.get("/", headers={"accept": "text/html"}).text

    open_client = TestClient(open_app[0], follow_redirects=False)
    assert "sign out" not in open_client.get("/", headers={"accept": "text/html"}).text


# --- Paths a real client can send that a test client cannot -------------------
#
# ⚠️ These drive the ASGI app with a HAND-BUILT scope. That is not ceremony:
# httpx normalises `..` out of a URL before sending, so the first version of
# this probe reported "no bypass" while testing nothing at all — the client had
# rewritten every hostile path into its harmless form. Uvicorn does no such
# normalisation, so `scope["path"]` for a raw `GET /healthz/../devices` is that
# string verbatim, and only a hand-built scope reproduces it.


async def _fire(app, path: str, *, cookie: str | None = None) -> dict:
    headers = [(b"host", b"127.0.0.1"), (b"accept", b"*/*")]
    if cookie:
        headers.append((b"cookie", cookie.encode("latin-1")))
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("latin-1"),
        "query_string": b"",
        "root_path": "",
        "headers": headers,
        "client": ("127.0.0.1", 5555),
        "server": ("127.0.0.1", 8765),
    }
    captured = {"status": None, "body": b""}

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        if message["type"] == "http.response.start":
            captured["status"] = message["status"]
        elif message["type"] == "http.response.body":
            captured["body"] += message.get("body", b"")

    await app(scope, receive, send)
    return captured


#: Every one of these starts with an exempt prefix, or is a near-miss of one.
HOSTILE_PATHS = [
    "/static/../devices",
    "/static/../../probes",
    "/healthz/../devices",
    "/healthz/../probes",
    "/healthz.json/../devices",
    "/login/../devices",
    "/login/../../devices",
    "/healthz/./../devices",
    "/static/..",
    "/healthz/.",
]


@pytest.mark.parametrize("path", HOSTILE_PATHS)
def test_an_exempt_prefix_cannot_be_used_to_reach_a_protected_route(authed_app, path):
    """⛔ A dot segment must void the exemption, whatever the path starts with.

    `/healthz/../devices` begins with `/healthz/`, so a plain prefix match
    exempts it. Today Starlette's router would then 404 it — but that is a
    property of a DEPENDENCY declining to match, not of our access control, and
    relying on it means a routine upgrade could open a bypass with no diff of
    ours to review.
    """
    import asyncio

    app = authed_app[0]
    result = asyncio.run(_fire(app, path))
    assert b"<table" not in result["body"], f"{path} returned dashboard content"
    # ⛔ 401, specifically — NOT merely "something other than 200".
    #
    # The weaker assertion is what the first draft of this test made, and it
    # could not fail for the defect it names: with a plain prefix match these
    # paths ARE exempted, sail past the session check, reach the router and come
    # back 404. "Not 200" is satisfied by that, so the test would have passed
    # against exactly the code it exists to reject. 401 is the only answer that
    # says the MIDDLEWARE refused, rather than the router happening not to
    # match. Verified by planting the prefix-only matcher: this fails, the
    # weaker form did not.
    assert result["status"] == 401, (
        f"{path} answered {result['status']}, not 401. Anything else means the "
        f"exempt check let it through and something downstream declined to "
        f"serve it — which is luck, not access control."
    )


def test_the_exempt_surfaces_still_answer_when_the_path_is_clean(authed_app):
    """⛔ The control. The test above is satisfied by a middleware that exempts
    NOTHING, which would break monitoring and the login page itself."""
    import asyncio

    app = authed_app[0]
    for path in ("/healthz", "/healthz.json", "/login"):
        result = asyncio.run(_fire(app, path))
        assert result["status"] == 200, (
            f"exempt path {path} answered {result['status']}; the dot-segment "
            f"rule has over-reached and locked out the monitoring contract"
        )


def test_a_filename_that_merely_starts_with_dots_is_not_a_dot_segment():
    """A substring search for "/../" gets this wrong in both directions.

    `..hidden.css` is an ordinary filename, not a traversal, and refusing it
    would be an over-reach that only shows up when someone ships such a file.
    """
    from lynceus.webui.auth import _has_dot_segment

    assert not _has_dot_segment("/static/..hidden.css")
    assert not _has_dot_segment("/static/file..name.css")
    assert _has_dot_segment("/static/../devices")
    assert _has_dot_segment("/static/..")
    assert _has_dot_segment("/healthz/.")


def test_the_app_registers_no_websocket_routes(authed_app):
    """⛔ AuthMiddleware passes every non-HTTP scope straight through.

    That is correct for `lifespan`, and it would be a hole for a WebSocket:
    the socket would be established without a session, and
    `test_every_route_is_behind_auth_or_deliberately_exempt` would not notice,
    because a WebSocketRoute carries no `methods` and is skipped there.

    There are none today. This fails the day someone adds one, which is the
    moment to decide how it authenticates rather than a year later.
    """
    app = authed_app[0]
    websockets = [
        getattr(r, "path", repr(r))
        for r in app.routes
        if type(r).__name__ in ("WebSocketRoute", "APIWebSocketRoute")
    ]
    assert not websockets, (
        f"WebSocket route(s) registered: {websockets}. AuthMiddleware passes "
        f"non-HTTP scopes through unchecked, so these are reachable without a "
        f"session. Handle the websocket scope in AuthMiddleware.__call__ before "
        f"shipping this."
    )


def test_the_session_idle_window_does_not_outlive_the_csrf_cookie():
    """⛔ Asserted, not transcribed.

    A session that outlives its CSRF cookie leaves the operator on a page that
    looks signed in and answers 403 "CSRF token mismatch" to every button —
    which reads as a bug, not an expiry. The constant in `auth.py` carries a
    comment saying the two are "deliberately equal"; this is what stops that
    comment going on saying so after somebody changes one of them.
    """
    from lynceus.webui.auth import SESSION_IDLE_SECONDS
    from lynceus.webui.csrf import CSRF_COOKIE_MAX_AGE

    assert SESSION_IDLE_SECONDS <= CSRF_COOKIE_MAX_AGE, (
        f"the session idle window ({SESSION_IDLE_SECONDS}s) outlives the CSRF "
        f"cookie ({CSRF_COOKIE_MAX_AGE}s), so a still-valid session will hit "
        f"403 CSRF errors on every form after {CSRF_COOKIE_MAX_AGE}s"
    )


# --- One reader for the session cookie ----------------------------------------


def _scope_with_cookie(header: str) -> dict:
    return {
        "type": "http",
        "method": "GET",
        "path": "/",
        "query_string": b"",
        "headers": [(b"cookie", header.encode("latin-1"))],
    }


@pytest.mark.parametrize(
    "header,expected",
    [
        (f"{SESSION_COOKIE_NAME}=abc123", "abc123"),
        (f"{SESSION_COOKIE_NAME}=abc123; other=1", "abc123"),
        (f"other=1; {SESSION_COOKIE_NAME}=abc123", "abc123"),
        # Quoted: stripped, for parity with Starlette's parser.
        (f'{SESSION_COOKIE_NAME}="abc123"', "abc123"),
        # Empty is absent, not a token.
        (f"{SESSION_COOKIE_NAME}=", None),
        ("other=1", None),
        # ⛔ Ambiguous: two DIFFERENT values. Fail closed.
        (f"{SESSION_COOKIE_NAME}=abc123; {SESSION_COOKIE_NAME}=xyz789", None),
        # The same value twice is a duplicate, not an ambiguity.
        (f"{SESSION_COOKIE_NAME}=abc123; {SESSION_COOKIE_NAME}=abc123", "abc123"),
    ],
)
def test_the_session_cookie_reader_is_explicit_about_every_shape(header, expected):
    from lynceus.webui.auth import session_token_from_scope

    assert session_token_from_scope(_scope_with_cookie(header)) == expected


def test_the_two_cookie_readers_agree_on_every_shape_that_reaches_them():
    """⛔ Measured, and it is why there is only one reader now.

    ``Request.cookies`` and ``session_token_from_scope`` disagreed on three
    inputs — a quoted value, and duplicate cookies (Starlette takes the last,
    this took the first). Neither disagreement admits an attacker; both refuse
    rather than allow. But the middleware and the login page would reach
    DIFFERENT answers about whether a caller is signed in, and the symptom is an
    infinite redirect loop between /login and /.

    ⚠️ The duplicate row is deliberately EXCLUDED from the agreement check,
    because the two no longer agree there and that is the fix: Starlette picks
    the last value, and this refuses outright. Cookie shadowing is how someone
    who can write a cookie on a sibling origin gets to choose which parser wins,
    and refusing is the only answer that does not depend on parser order.
    """
    from starlette.requests import Request

    from lynceus.webui.auth import session_token_from_scope

    agreeing_shapes = [
        f"{SESSION_COOKIE_NAME}=abc123",
        f"{SESSION_COOKIE_NAME}=abc123; other=1",
        f"other=1; {SESSION_COOKIE_NAME}=abc123",
        f'{SESSION_COOKIE_NAME}="abc123"',
        f"{SESSION_COOKIE_NAME}=a%3Db",
        f"OTHER=x; {SESSION_COOKIE_NAME}=tok; trailing=y",
        "other=1",
    ]
    for header in agreeing_shapes:
        scope = _scope_with_cookie(header)
        starlette_says = Request(scope).cookies.get(SESSION_COOKIE_NAME) or None
        ours_says = session_token_from_scope(scope)
        assert starlette_says == ours_says, (
            f"the two cookie readers disagree on {header!r}: "
            f"Request.cookies={starlette_says!r}, ours={ours_says!r}"
        )


def test_a_shadowed_session_cookie_does_not_authenticate(authed_app):
    """End to end: a second, different session cookie refuses the request.

    ⛔ Asserts the REFUSAL, not merely that the attacker's token loses. Picking
    a winner by parser order is the thing being removed.
    """
    import asyncio

    app, _db, _cfg = authed_app
    client = TestClient(app, follow_redirects=False)
    _login(client)
    real = client.cookies.get(SESSION_COOKIE_NAME)
    assert real

    # The genuine cookie alone works ...
    ok = asyncio.run(_fire(app, "/", cookie=f"{SESSION_COOKIE_NAME}={real}"))
    assert ok["status"] == 200, f"the control failed: a valid session got {ok['status']}"

    # ... and the same cookie shadowed by a planted one does not, in either order.
    for header in (
        f"{SESSION_COOKIE_NAME}={real}; {SESSION_COOKIE_NAME}=planted-token",
        f"{SESSION_COOKIE_NAME}=planted-token; {SESSION_COOKIE_NAME}={real}",
    ):
        result = asyncio.run(_fire(app, "/", cookie=header))
        assert result["status"] != 200, (
            f"an ambiguous pair of session cookies authenticated the request "
            f"({header[:60]}...); the answer depended on parser order"
        )
