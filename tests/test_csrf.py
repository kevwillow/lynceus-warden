"""Tests for the CSRF middleware (double-submit cookie pattern)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import create_app
from lynceus.webui.csrf import (
    CSRF_COOKIE_NAME,
    CSRF_FORM_FIELD,
    CSRF_HEADER_NAME,
    constant_time_compare,
    generate_token,
)


def _make_app(tmp_path, *, allow_remote: bool = False):
    kwargs = {"db_path": str(tmp_path / "csrf.db")}
    if allow_remote:
        kwargs["ui_bind_host"] = "0.0.0.0"
        kwargs["ui_allow_remote"] = True
    config = Config(**kwargs)
    db = Database(config.db_path)
    app = create_app(config, db)
    return app, db


def test_generate_token_returns_url_safe_43_chars():
    t1 = generate_token()
    t2 = generate_token()
    assert isinstance(t1, str)
    # secrets.token_urlsafe(32) → 43 chars URL-safe (no padding).
    assert len(t1) == 43
    assert t1 != t2
    safe = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    assert all(c in safe for c in t1)


def test_constant_time_compare_matches_equal_strings():
    assert constant_time_compare("abc", "abc") is True
    long = "a" * 80
    assert constant_time_compare(long, long) is True


def test_constant_time_compare_returns_false_for_unequal_lengths():
    assert constant_time_compare("abc", "abcd") is False
    assert constant_time_compare("", "x") is False


def test_constant_time_compare_returns_false_for_none_input():
    assert constant_time_compare(None, "x") is False
    assert constant_time_compare("x", None) is False
    assert constant_time_compare(None, None) is False
    assert constant_time_compare(123, "abc") is False


@pytest.mark.webui
def test_get_request_sets_cookie_when_missing(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/alerts")
        assert r.status_code == 200
        assert CSRF_COOKIE_NAME in r.cookies
        assert len(r.cookies[CSRF_COOKIE_NAME]) >= 20
    finally:
        db.close()


@pytest.mark.webui
def test_get_request_preserves_existing_cookie(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            client.cookies.set(CSRF_COOKIE_NAME, "existing-token-value")
            r = client.get("/alerts")
        assert r.status_code == 200
        # Either no Set-Cookie was sent for lynceus_csrf (preferred), OR if
        # one was sent, it must equal the existing value.
        set_cookie_headers = [v for k, v in r.headers.raw if k.lower() == b"set-cookie"]
        for raw in set_cookie_headers:
            text = raw.decode("latin-1")
            if text.startswith(f"{CSRF_COOKIE_NAME}="):
                value = text.split("=", 1)[1].split(";", 1)[0]
                assert value == "existing-token-value"
    finally:
        db.close()


@pytest.mark.webui
def test_post_without_cookie_returns_403(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
        with TestClient(app) as client:
            client.cookies.clear()
            r = client.post(f"/alerts/{aid}/ack", data={"_csrf": "anything"})
        assert r.status_code == 403
        assert "CSRF" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_post_with_cookie_but_no_token_returns_403(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
        with TestClient(app) as client:
            client.cookies.set(CSRF_COOKIE_NAME, "token-value-zzz")
            r = client.post(f"/alerts/{aid}/ack", data={})
        assert r.status_code == 403
    finally:
        db.close()


@pytest.mark.webui
def test_post_with_cookie_and_matching_header_passes(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
        with TestClient(app, follow_redirects=False) as client:
            r_get = client.get("/alerts")
            token = r_get.cookies[CSRF_COOKIE_NAME]
            r = client.post(
                f"/alerts/{aid}/ack",
                headers={CSRF_HEADER_NAME: token},
            )
        assert r.status_code == 303
        assert db.get_alert(aid)["acknowledged"] == 1
    finally:
        db.close()


@pytest.mark.webui
def test_post_with_cookie_and_matching_form_field_passes(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
        with TestClient(app, follow_redirects=False) as client:
            r_get = client.get("/alerts")
            token = r_get.cookies[CSRF_COOKIE_NAME]
            r = client.post(
                f"/alerts/{aid}/ack",
                data={CSRF_FORM_FIELD: token},
            )
        assert r.status_code == 303
        assert db.get_alert(aid)["acknowledged"] == 1
    finally:
        db.close()


@pytest.mark.webui
def test_post_with_cookie_but_mismatched_token_returns_403(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
        with TestClient(app) as client:
            client.get("/alerts")
            r = client.post(
                f"/alerts/{aid}/ack",
                data={CSRF_FORM_FIELD: "this-is-the-wrong-token"},
            )
        assert r.status_code == 403
        assert db.get_alert(aid)["acknowledged"] == 0
    finally:
        db.close()


def _csrf_set_cookie_headers(response) -> list[str]:
    raw = [v.decode("latin-1") for k, v in response.headers.raw if k.lower() == b"set-cookie"]
    return [text for text in raw if text.startswith(f"{CSRF_COOKIE_NAME}=")]


@pytest.mark.webui
def test_forms_still_work_over_plain_http_when_remote_is_allowed(tmp_path):
    """The regression guard for the whole defect, stated as BEHAVIOUR.

    This asserts what the operator experiences, not how the header is spelled.
    ``ui_allow_remote: true`` used to attach ``Secure`` to the CSRF cookie
    while the server only ever speaks HTTP, so the cookie jar accepted the
    cookie and then withheld it from every later request. The POST arrived
    carrying no cookie at all and the middleware answered ``403 CSRF token
    mismatch`` -- naming a mismatch when there was nothing to compare.

    The cookie jar here applies the same rule a browser does, which is what
    makes this a real reproduction rather than a restatement of the fix.
    """
    app, db = _make_app(tmp_path, allow_remote=True)
    try:
        aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
        with TestClient(app, base_url="http://testserver") as client:
            client.cookies.clear()
            client.get("/alerts")
            token = client.cookies.get(CSRF_COOKIE_NAME)
            assert token, "no CSRF cookie survived the GET, so the form cannot be submitted"
            posted = client.post(f"/alerts/{aid}/ack", data={CSRF_FORM_FIELD: token})
        assert posted.status_code == 200
        assert db.get_alert(aid)["acknowledged"] == 1
    finally:
        db.close()


@pytest.mark.webui
def test_csrf_cookie_has_no_secure_flag_over_plain_http_when_remote_allowed(tmp_path):
    """``ui_allow_remote`` describes the bind address, never the transport."""
    app, db = _make_app(tmp_path, allow_remote=True)
    try:
        with TestClient(app, base_url="http://testserver") as client:
            client.cookies.clear()
            r = client.get("/alerts")
        csrf_headers = _csrf_set_cookie_headers(r)
        assert len(csrf_headers) >= 1
        for h in csrf_headers:
            assert "Secure" not in h
    finally:
        db.close()


@pytest.mark.webui
def test_csrf_cookie_keeps_secure_flag_when_the_request_arrived_over_https(tmp_path):
    """The permit half. Dropping ``Secure`` everywhere would also pass the two
    tests above, so prove the flag is still set where it is genuinely earned:
    a request whose scheme is https, which is what uvicorn reports when it
    terminates TLS or when a trusted local proxy forwarded the scheme."""
    app, db = _make_app(tmp_path, allow_remote=True)
    try:
        with TestClient(app, base_url="https://testserver") as client:
            client.cookies.clear()
            r = client.get("/alerts")
        csrf_headers = _csrf_set_cookie_headers(r)
        assert len(csrf_headers) >= 1
        assert all("Secure" in h for h in csrf_headers)
    finally:
        db.close()


@pytest.mark.webui
def test_csrf_cookie_no_secure_flag_when_loopback(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            client.cookies.clear()
            r = client.get("/alerts")
        set_cookies = [v.decode("latin-1") for k, v in r.headers.raw if k.lower() == b"set-cookie"]
        csrf_headers = [text for text in set_cookies if text.startswith(f"{CSRF_COOKIE_NAME}=")]
        assert len(csrf_headers) >= 1
        for h in csrf_headers:
            assert "Secure" not in h
    finally:
        db.close()


def test_a_shadowed_csrf_cookie_cannot_satisfy_the_double_submit():
    """Sibling-origin cookie shadowing must not let one caller supply both halves.

    ⛔ The session reader refuses conflicting duplicate cookies and names this
    exact attacker: someone who can write a cookie on a sibling origin under the
    same registrable domain. `SameSite=Strict` does not withhold such a cookie,
    because sibling origins are cross-origin but SAME-site. The CSRF parser was
    last-one-wins, so the attacker's `KNOWN` value overwrote the genuine
    `SECRET`, matched their own form field, and the double-submit check passed.

    Dropping the ambiguous name makes the POST answer 403 instead.
    """
    from lynceus.webui.csrf import _parse_cookie_header

    genuine = "lynceus_csrf=SECRET; lynceus_csrf=KNOWN"
    assert _parse_cookie_header(genuine).get("lynceus_csrf") is None, (
        "a conflicting duplicate CSRF cookie resolved to a value; last-one-wins "
        "lets a sibling origin choose which half of the double-submit wins"
    )


def test_an_identical_duplicate_cookie_is_not_treated_as_ambiguous():
    """Same value twice is a duplicate, not an ambiguity — the session reader
    draws the same distinction, and refusing it would break ordinary clients
    that repeat a cookie."""
    from lynceus.webui.csrf import _parse_cookie_header

    assert _parse_cookie_header("lynceus_csrf=A; lynceus_csrf=A")["lynceus_csrf"] == "A"


def test_unrelated_cookies_are_unaffected_by_a_conflict():
    """A conflict must drop ONLY the conflicting name."""
    from lynceus.webui.csrf import _parse_cookie_header

    out = _parse_cookie_header("a=1; lynceus_csrf=X; lynceus_csrf=Y; b=2")
    assert out["a"] == "1" and out["b"] == "2"
    assert "lynceus_csrf" not in out
