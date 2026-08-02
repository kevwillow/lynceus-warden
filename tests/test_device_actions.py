"""Tests for the device-detail operator action panel (0.9.0 feature arc).

Covers the three confirmed actions wired on /devices/{mac}:
  - add to watchlist (with severity)   -> db.add_watchlist
  - watch this device (from most-recent alert) -> create_watchful_from_alert
  - silence (suppress future alerts)    -> _write_ui_allowlist / add_ui_entry

Plus the cross-cutting contracts the panel must honor:
  - HX-Request returns the panel partial; non-HX returns the 303 fallback
  - CSRF is enforced on every new POST (blank/missing token -> 403)
  - severity dropdown uses the real model values (low/med/high, NOT medium)

add-to-rules is intentionally NOT built (deferred to its own arc), so it
has no route and no test here.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from lynceus import allowlist as allowlist_mod
from lynceus.allowlist import derive_ui_path
from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import create_app
from lynceus.webui.csrf import CSRF_COOKIE_NAME, CSRF_FORM_FIELD

MAC = "aa:bb:cc:dd:ee:01"


def _make_app(tmp_path, *, with_allowlist=True):
    kwargs = dict(
        db_path=str(tmp_path / "dev.db"),
        kismet_health_check_on_startup=False,
        evidence_capture_enabled=False,
    )
    if with_allowlist:
        kwargs["allowlist_path"] = str(tmp_path / "allowlist.yaml")
    config = Config(**kwargs)
    db = Database(config.db_path)
    app = create_app(config, db)
    return app, db, config


def _csrf_token(client) -> str:
    resp = client.get("/")
    return resp.cookies[CSRF_COOKIE_NAME]


def _seed_device(db, mac=MAC, *, now_ts=100):
    db.upsert_device(mac, "wifi", "Acme", 0, now_ts)


def _seed_alert(db, mac=MAC, *, ts=200, rule_name="rule_a", severity="high"):
    return db.add_alert(
        ts=ts, rule_name=rule_name, mac=mac, message="boom", severity=severity
    )


def _ui_entries(config):
    return allowlist_mod._load_ui_entries(derive_ui_path(Path(config.allowlist_path)))


# --------------------------------------------------------------------------
# Add to watchlist
# --------------------------------------------------------------------------
@pytest.mark.webui
def test_add_watchlist_creates_mac_row_with_severity(tmp_path):
    app, db, _ = _make_app(tmp_path)
    try:
        _seed_device(db)
        with TestClient(app, follow_redirects=False) as client:
            token = _csrf_token(client)
            r = client.post(
                f"/devices/{MAC}/watchlist",
                data={CSRF_FORM_FIELD: token, "severity": "high"},
            )
        assert r.status_code == 303
        row = db.get_watchlist_entry_by_pattern(MAC, "mac")
        assert row is not None
        assert row["pattern"] == MAC
        assert row["pattern_type"] == "mac"
        assert row["severity"] == "high"
    finally:
        db.close()


@pytest.mark.webui
def test_add_watchlist_is_idempotent_and_never_downgrades(tmp_path):
    app, db, _ = _make_app(tmp_path)
    try:
        _seed_device(db)
        with TestClient(app, follow_redirects=False) as client:
            token = _csrf_token(client)
            client.post(
                f"/devices/{MAC}/watchlist",
                data={CSRF_FORM_FIELD: token, "severity": "high"},
            )
            # Re-add at a lower severity: must NOT overwrite the existing row.
            client.post(
                f"/devices/{MAC}/watchlist",
                data={CSRF_FORM_FIELD: token, "severity": "low"},
            )
        rows = [
            r
            for r in db.list_watchlist()
            if r["pattern"] == MAC and r["pattern_type"] == "mac"
        ]
        assert len(rows) == 1
        assert rows[0]["severity"] == "high"
    finally:
        db.close()


@pytest.mark.webui
def test_add_watchlist_invalid_severity_rejected(tmp_path):
    app, db, _ = _make_app(tmp_path)
    try:
        _seed_device(db)
        with TestClient(app, follow_redirects=False) as client:
            token = _csrf_token(client)
            r = client.post(
                f"/devices/{MAC}/watchlist",
                data={CSRF_FORM_FIELD: token, "severity": "medium"},
            )
        assert r.status_code == 400
        assert db.get_watchlist_entry_by_pattern(MAC, "mac") is None
    finally:
        db.close()


# --------------------------------------------------------------------------
# Watch (watchful)
# --------------------------------------------------------------------------
@pytest.mark.webui
def test_watch_creates_watchful_from_most_recent_alert(tmp_path):
    app, db, _ = _make_app(tmp_path)
    try:
        _seed_device(db)
        _seed_alert(db, ts=200, rule_name="rule_old")
        newest = _seed_alert(db, ts=300, rule_name="rule_new")
        with TestClient(app, follow_redirects=False) as client:
            token = _csrf_token(client)
            r = client.post(
                f"/devices/{MAC}/watch",
                data={CSRF_FORM_FIELD: token, "snooze_duration": "30d"},
            )
        assert r.status_code == 303
        entry = db.get_active_watchful_recurrence_by_mac(MAC)
        assert entry is not None
        assert entry.mac == MAC
        # Source must be the NEWEST alert, not the older one.
        assert entry.source_alert_id == newest
    finally:
        db.close()


@pytest.mark.webui
def test_watch_without_any_alert_rejected(tmp_path):
    app, db, _ = _make_app(tmp_path)
    try:
        _seed_device(db)  # device but no alerts
        with TestClient(app, follow_redirects=False) as client:
            token = _csrf_token(client)
            r = client.post(
                f"/devices/{MAC}/watch",
                data={CSRF_FORM_FIELD: token, "snooze_duration": "30d"},
            )
        assert r.status_code == 400
        assert db.get_active_watchful_recurrence_by_mac(MAC) is None
    finally:
        db.close()


@pytest.mark.webui
def test_watch_invalid_duration_rejected(tmp_path):
    app, db, _ = _make_app(tmp_path)
    try:
        _seed_device(db)
        _seed_alert(db)
        with TestClient(app, follow_redirects=False) as client:
            token = _csrf_token(client)
            r = client.post(
                f"/devices/{MAC}/watch",
                data={CSRF_FORM_FIELD: token, "snooze_duration": "99y"},
            )
        assert r.status_code == 400
    finally:
        db.close()


# --------------------------------------------------------------------------
# Silence (suppress future alerts via the UI allowlist)
# --------------------------------------------------------------------------
@pytest.mark.webui
def test_silence_permanent_writes_mac_allowlist_entry(tmp_path):
    app, db, config = _make_app(tmp_path)
    try:
        _seed_device(db)
        with TestClient(app, follow_redirects=False) as client:
            token = _csrf_token(client)
            r = client.post(
                f"/devices/{MAC}/allowlist", data={CSRF_FORM_FIELD: token}
            )
        assert r.status_code == 303
        entries = _ui_entries(config)
        macs = [(e.pattern, e.pattern_type, e.expires_at) for e in entries]
        assert (MAC, "mac", None) in macs
    finally:
        db.close()


@pytest.mark.webui
def test_silence_temporary_sets_expiry(tmp_path):
    app, db, config = _make_app(tmp_path)
    try:
        _seed_device(db)
        with TestClient(app, follow_redirects=False) as client:
            token = _csrf_token(client)
            r = client.post(
                f"/devices/{MAC}/snooze",
                data={CSRF_FORM_FIELD: token, "snooze_duration": "24h"},
            )
        assert r.status_code == 303
        entries = [e for e in _ui_entries(config) if e.pattern == MAC]
        assert len(entries) == 1
        assert entries[0].expires_at is not None  # 24h -> a real future expiry
    finally:
        db.close()


@pytest.mark.webui
def test_silence_remove_clears_entry(tmp_path):
    app, db, config = _make_app(tmp_path)
    try:
        _seed_device(db)
        with TestClient(app, follow_redirects=False) as client:
            token = _csrf_token(client)
            client.post(f"/devices/{MAC}/allowlist", data={CSRF_FORM_FIELD: token})
            assert any(e.pattern == MAC for e in _ui_entries(config))
            r = client.post(
                f"/devices/{MAC}/allowlist/remove", data={CSRF_FORM_FIELD: token}
            )
        assert r.status_code == 303
        assert not any(e.pattern == MAC for e in _ui_entries(config))
    finally:
        db.close()


@pytest.mark.webui
def test_silence_hidden_when_allowlist_not_configured(tmp_path):
    app, db, _ = _make_app(tmp_path, with_allowlist=False)
    try:
        _seed_device(db)
        with TestClient(app) as client:
            html = client.get(f"/devices/{MAC}").text
        # Panel renders, but the silence section is gated off.
        assert 'id="device-actions"' in html
        assert "<h4>silence</h4>" not in html
        assert f'action="/devices/{MAC}/allowlist"' not in html
    finally:
        db.close()


# --------------------------------------------------------------------------
# htmx partial vs 303 fallback
# --------------------------------------------------------------------------
@pytest.mark.webui
def test_hx_request_returns_panel_partial(tmp_path):
    app, db, _ = _make_app(tmp_path)
    try:
        _seed_device(db)
        with TestClient(app, follow_redirects=False) as client:
            token = _csrf_token(client)
            r = client.post(
                f"/devices/{MAC}/watchlist",
                data={CSRF_FORM_FIELD: token, "severity": "med"},
                headers={"HX-Request": "true"},
            )
        assert r.status_code == 200
        assert 'id="device-actions"' in r.text
        # A partial, not a full document.
        assert "<!DOCTYPE html>" not in r.text
        assert "<html" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_non_hx_redirects_to_device_page(tmp_path):
    app, db, _ = _make_app(tmp_path)
    try:
        _seed_device(db)
        with TestClient(app, follow_redirects=False) as client:
            token = _csrf_token(client)
            r = client.post(
                f"/devices/{MAC}/watchlist",
                data={CSRF_FORM_FIELD: token, "severity": "med"},
            )
        assert r.status_code == 303
        assert r.headers["location"] == f"/devices/{MAC}"
    finally:
        db.close()


# --------------------------------------------------------------------------
# CSRF enforcement on every new POST
# --------------------------------------------------------------------------
@pytest.mark.webui
@pytest.mark.parametrize(
    "path, data",
    [
        ("/devices/" + MAC + "/watchlist", {"severity": "high"}),
        ("/devices/" + MAC + "/watch", {"snooze_duration": "30d"}),
        ("/devices/" + MAC + "/allowlist", {}),
        ("/devices/" + MAC + "/snooze", {"snooze_duration": "24h"}),
        ("/devices/" + MAC + "/allowlist/remove", {}),
    ],
)
def test_csrf_blank_or_missing_token_rejected(tmp_path, path, data):
    app, db, _ = _make_app(tmp_path)
    try:
        _seed_device(db)
        _seed_alert(db)
        with TestClient(app, follow_redirects=False) as client:
            _csrf_token(client)  # establish the cookie
            # Missing token entirely.
            r_missing = client.post(path, data=data)
            # Blank token.
            r_blank = client.post(path, data={**data, CSRF_FORM_FIELD: ""})
        assert r_missing.status_code == 403
        assert r_blank.status_code == 403
        # Nothing mutated.
        assert db.get_watchlist_entry_by_pattern(MAC, "mac") is None
        assert db.get_active_watchful_recurrence_by_mac(MAC) is None
    finally:
        db.close()


# --------------------------------------------------------------------------
# Panel renders the real severity vocabulary on the device page
# --------------------------------------------------------------------------
@pytest.mark.webui
def test_panel_severity_dropdown_uses_real_values(tmp_path):
    app, db, _ = _make_app(tmp_path)
    try:
        _seed_device(db)
        with TestClient(app) as client:
            html = client.get(f"/devices/{MAC}").text
        assert 'id="device-actions"' in html
        assert '<option value="low"' in html
        assert '<option value="med"' in html
        assert '<option value="high"' in html
        # The classic silent-disable trap: must NOT offer "medium".
        assert '<option value="medium"' not in html
    finally:
        db.close()
