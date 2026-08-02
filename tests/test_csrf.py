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


@pytest.mark.webui
def test_csrf_cookie_secure_flag_when_remote_allowed(tmp_path):
    app, db = _make_app(tmp_path, allow_remote=True)
    try:
        with TestClient(app) as client:
            client.cookies.clear()
            r = client.get("/alerts")
        set_cookies = [v.decode("latin-1") for k, v in r.headers.raw if k.lower() == b"set-cookie"]
        csrf_headers = [text for text in set_cookies if text.startswith(f"{CSRF_COOKIE_NAME}=")]
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
