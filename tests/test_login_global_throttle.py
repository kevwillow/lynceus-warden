"""The five-attempt lockout does not bound an attacker who rotates address.

⛔ Measured 2026-09-01 against the unmodified `LoginRateLimiter`: **30,000
login attempts, not one refused.** A single address locks at 5, as advertised;
an attacker presenting a fresh source address per request never reaches 5 in
any bucket. `MAX_TRACKED_CLIENTS` does not save it, because `_evict` protects
only ACTIVE lockouts and the attacker's own never-locked buckets are recycled
forever.

Every one of those attempts ran a full scrypt: ~16 MB and ~29 ms measured on a
12-core x86, on hardware whose deployment target is a Raspberry Pi. The login
body size was already capped (`MAX_PASSWORD_BYTES`) against precisely this
shape of denial of service; the request COUNT was not.

🪤 **Why the obvious fix is wrong.** A global FAILURE counter would bound the
attacker and hand them a lever to lock the operator out with five wrong
guesses — which is exactly what keying on the peer address was chosen to
avoid (`LoginRateLimiter`'s own docstring). The fix therefore had to bound
*work* without introducing any penalty window. It is a token bucket: no
lockout, continuous refill, so the operator is served again seconds after an
attack stops.

⚠️ Rotation is a LAN-adjacent attack and remains outside the documented
deployment (loopback plus an SSH tunnel). This bounds the damage; it is not a
perimeter.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import create_app
from lynceus.webui.auth import (
    GLOBAL_VERIFY_BURST,
    LOGIN_MAX_FAILURES,
    LoginRateLimiter,
    hash_password,
)
from lynceus.webui.credentials import write_credentials
from lynceus.webui.csrf import CSRF_COOKIE_NAME, CSRF_FORM_FIELD

REPO_ROOT = Path(__file__).resolve().parents[1]
PASSWORD = "correct-horse-battery-staple"
_HASH = hash_password(PASSWORD)


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
    td = tempfile.mkdtemp()
    cfg = _make_config(td)
    write_credentials(cfg.resolved_ui_auth_path(), _HASH)
    db = Database(cfg.db_path)
    db.ensure_location("default", "Default")
    try:
        yield create_app(cfg, db), db, cfg
    finally:
        db.close()


# --- The limiter itself -------------------------------------------------------


def test_rotating_source_address_no_longer_buys_unlimited_scrypt():
    """⭐ THE REGRESSION. Without the global budget this allows 30,000."""
    clock = {"t": 1000.0}
    lim = LoginRateLimiter(now=lambda: clock["t"])

    allowed = 0
    for n in range(30_000):
        addr = f"2001:db8::{n:x}"
        if lim.is_locked(addr):
            continue
        if not lim.try_spend_verification():
            continue
        lim.record_failure(addr)
        allowed += 1

    assert allowed == GLOBAL_VERIFY_BURST, (
        f"a rotating attacker got {allowed} scrypt verifications from a "
        f"{GLOBAL_VERIFY_BURST}-token budget with no time passing; the global "
        f"throttle is not bounding the work"
    )


def test_a_single_address_still_locks_out_as_advertised():
    """The per-client control must survive the new one. Five means five."""
    clock = {"t": 1000.0}
    lim = LoginRateLimiter(now=lambda: clock["t"])
    for _ in range(LOGIN_MAX_FAILURES):
        assert not lim.is_locked("10.0.0.9")
        lim.record_failure("10.0.0.9")
    assert lim.is_locked("10.0.0.9")


def test_an_attacker_cannot_lock_the_operator_out():
    """⛔ The property the per-client keying was CHOSEN to protect.

    A global failure counter would break this, which is why the fix is a token
    bucket with no penalty window. An attacker drains the budget; the operator
    is refused only for as long as the attack lasts, then served.
    """
    clock = {"t": 1000.0}
    lim = LoginRateLimiter(now=lambda: clock["t"])

    for _n in range(GLOBAL_VERIFY_BURST * 10):  # attacker drains it
        lim.try_spend_verification()
    assert not lim.try_spend_verification(), "budget should be empty"

    clock["t"] += 5.0  # the attack stops; five seconds pass
    assert lim.try_spend_verification(), (
        "the operator is still refused five seconds after the attack stopped; "
        "this has become a lockout, which is the thing it must not be"
    )
    assert not lim.is_locked("10.0.0.250"), (
        "an attacker's traffic locked out an unrelated client address"
    )


def test_the_budget_refills_and_does_not_exceed_its_burst():
    clock = {"t": 1000.0}
    lim = LoginRateLimiter(now=lambda: clock["t"])
    for _ in range(GLOBAL_VERIFY_BURST):
        assert lim.try_spend_verification()
    assert not lim.try_spend_verification()

    clock["t"] += 10_000.0  # a long quiet period must not create a bigger burst
    spent = 0
    while lim.try_spend_verification():
        spent += 1
        if spent > GLOBAL_VERIFY_BURST * 2:
            break
    assert spent == GLOBAL_VERIFY_BURST, (
        f"the bucket refilled to {spent}, above its {GLOBAL_VERIFY_BURST} ceiling"
    )


def test_an_ordinary_operator_burst_is_never_refused():
    """Five bad guesses then the right one must not hit the global gate.

    If this fails the throttle is too tight and it is a usability defect.
    """
    clock = {"t": 1000.0}
    lim = LoginRateLimiter(now=lambda: clock["t"])
    for _ in range(LOGIN_MAX_FAILURES + 1):
        assert lim.try_spend_verification(), "a normal login burst was throttled"


# --- Wired into the real login route ------------------------------------------


def _login(client, password=PASSWORD):
    client.get("/login")
    token = client.cookies.get(CSRF_COOKIE_NAME)
    assert token
    return client.post("/login", data={"password": password, CSRF_FORM_FIELD: token, "next": "/"})


def test_the_route_refuses_with_429_when_the_budget_is_gone(authed_app):
    app = authed_app[0]
    app.state.login_limiter._global_tokens = 0.0
    client = TestClient(app, follow_redirects=False)
    resp = _login(client, "whatever")
    assert resp.status_code == 429, f"got {resp.status_code}, expected 429"


def test_the_throttle_runs_BEFORE_scrypt(authed_app, monkeypatch):
    """⛔ The ordering IS the fix.

    Spending the hash and then refusing would bound nothing at all: the cost
    this control exists to cap is the scrypt itself. Asserted by spying on the
    verification and requiring it never runs.
    """
    import lynceus.webui.app as app_mod

    app = authed_app[0]
    app.state.login_limiter._global_tokens = 0.0

    calls = []
    real = app_mod.verify_against_configured
    monkeypatch.setattr(
        app_mod,
        "verify_against_configured",
        lambda *a, **k: (calls.append(1), real(*a, **k))[1],
    )

    client = TestClient(app, follow_redirects=False)
    resp = _login(client, "whatever")

    assert resp.status_code == 429
    assert calls == [], (
        "scrypt ran even though the request was throttled; the throttle is "
        "placed after the hash and bounds nothing"
    )


def test_a_correct_password_still_logs_in(authed_app):
    """The control must not have broken the thing it protects."""
    app = authed_app[0]
    client = TestClient(app, follow_redirects=False)
    resp = _login(client)
    assert resp.status_code in (302, 303), f"login broke: {resp.status_code}"
