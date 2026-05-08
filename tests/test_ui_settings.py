"""Tests for the read-only /settings page.

The /settings page surfaces current configuration with prominent visual
treatment for privacy-relevant settings (probe SSID capture in particular).
It's strictly read-only — no mutation endpoints — and never displays
sensitive values (Kismet API token, full ntfy topic) at full fidelity.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from lynceus import __version__
from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import create_app
from lynceus.webui.csrf import CSRF_HEADER_NAME

KISMET_TOKEN_SENTINEL = "kismet-secret-token-DO-NOT-LEAK-12345"
NTFY_TOPIC_SENTINEL = "lynceus-private-topic-abcdef-XYZ"


def _make_app(tmp_path, **config_overrides):
    kwargs = {"db_path": str(tmp_path / "settings.db")}
    kwargs.update(config_overrides)
    config = Config(**kwargs)
    db = Database(config.db_path)
    app = create_app(config, db)
    return app, db


def _add_watchlist(
    db: Database,
    pattern: str,
    pattern_type: str = "mac",
    severity: str = "med",
    description: str | None = None,
) -> int:
    with db._conn:
        cur = db._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
            "VALUES (?, ?, ?, ?)",
            (pattern, pattern_type, severity, description),
        )
        return int(cur.lastrowid)


def _stub_kismet_reachable(monkeypatch):
    monkeypatch.setattr(
        "lynceus.kismet.KismetClient.health_check",
        lambda self: {"reachable": True, "version": "Kismet-2024-08", "error": None},
    )


def _stub_kismet_unreachable(monkeypatch, error: str = "connection refused"):
    monkeypatch.setattr(
        "lynceus.kismet.KismetClient.health_check",
        lambda self: {"reachable": False, "version": None, "error": error},
    )


# ---------------------------------------------------------------------------
# Smoke + nav.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_settings_returns_200(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
    finally:
        db.close()


@pytest.mark.webui
def test_settings_link_present_on_settings_page(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        assert 'href="/settings"' in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_settings_link_present_on_alerts_page(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/alerts")
        assert r.status_code == 200
        assert 'href="/settings"' in r.text
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Capture configuration section.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_capture_section_renders_both_toggles(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        # Both names visible on the page.
        assert "probe_ssids" in r.text
        assert "ble_friendly_names" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_probe_ssids_off_shows_privacy_mode_not_recording(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path, capture={"probe_ssids": False})
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        assert "privacy mode" in r.text
        assert "recording probe SSIDs" not in r.text
        assert "is not recorded" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_probe_ssids_on_shows_recording_not_privacy_mode(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path, capture={"probe_ssids": True})
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        assert "recording probe SSIDs" in r.text
        assert "privacy mode" not in r.text
        assert "Lynceus is recording WiFi network names" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_capture_section_includes_reconfigure_guidance(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        assert "lynceus-setup --reconfigure" in r.text
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Kismet section.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_kismet_section_renders_url(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path, kismet_url="http://kismet.test:2501")
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        assert "http://kismet.test:2501" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_kismet_token_never_in_html(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path, kismet_api_key=KISMET_TOKEN_SENTINEL)
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        assert KISMET_TOKEN_SENTINEL not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_kismet_token_configured_placeholder(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path, kismet_api_key=KISMET_TOKEN_SENTINEL)
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        assert "(configured)" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_kismet_token_not_configured_placeholder(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path, kismet_api_key=None)
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        assert "(not configured)" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_kismet_health_check_success_renders_reachable(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        assert "reachable" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_kismet_health_check_failure_renders_unreachable_with_reason(tmp_path, monkeypatch):
    error_reason = "kismet-down-test-reason"
    _stub_kismet_unreachable(monkeypatch, error=error_reason)
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        assert "unreachable" in r.text
        assert error_reason in r.text
    finally:
        db.close()


# ---------------------------------------------------------------------------
# ntfy section.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_ntfy_topic_full_value_never_in_html(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(
        tmp_path,
        ntfy_url="https://ntfy.example.com",
        ntfy_topic=NTFY_TOPIC_SENTINEL,
    )
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        assert NTFY_TOPIC_SENTINEL not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_ntfy_topic_redacted_form_present(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(
        tmp_path,
        ntfy_url="https://ntfy.example.com",
        ntfy_topic=NTFY_TOPIC_SENTINEL,
    )
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        # First 4 + bullets + last 2.
        expected = NTFY_TOPIC_SENTINEL[:4] + "•••" + NTFY_TOPIC_SENTINEL[-2:]
        assert expected in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_ntfy_section_renders_broker_url(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(
        tmp_path,
        ntfy_url="https://ntfy.example.com",
        ntfy_topic=NTFY_TOPIC_SENTINEL,
    )
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        assert "https://ntfy.example.com" in r.text
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Watchlist data section.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_watchlist_section_shows_total_count(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        _add_watchlist(db, "aa:bb:cc:dd:ee:01")
        _add_watchlist(db, "aa:bb:cc:dd:ee:02")
        _add_watchlist(db, "aa:bb:cc:dd:ee:03")
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        # Total count shown somewhere.
        assert "3" in r.text
        assert "watchlist" in r.text.lower()
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_section_shows_origin_breakdown(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        # Argus-imported (3 entries with non-yaml argus_record_id)
        for i in range(3):
            wid = _add_watchlist(db, f"argus-{i:02d}:11:22:33:44:55", description=f"argus-{i}")
            db.upsert_metadata(
                wid, {"argus_record_id": f"argus-rec-{i}", "device_category": "test"}
            )
        # Yaml-seeded (2 entries with yaml- prefixed argus_record_id)
        for i in range(2):
            wid = _add_watchlist(db, f"yaml-{i:02d}:11:22:33:44:55", description=f"yaml-{i}")
            db.upsert_metadata(
                wid, {"argus_record_id": f"yaml-{i:016d}", "device_category": "test"}
            )
        # Bundled-or-other (1 entry with no metadata)
        _add_watchlist(db, "bundled-aa:bb:cc:dd:ee:99", description="bundled")
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        text = r.text
        # Find the watchlist section and check the three counts appear.
        # Descriptive labels for each origin.
        assert "argus-imported" in text
        assert "yaml-seeded" in text
        assert "bundled" in text
        # Look for "3" near argus, "2" near yaml, "1" near bundled.
        argus_idx = text.find("argus-imported")
        assert argus_idx != -1
        assert "3" in text[argus_idx : argus_idx + 200]
        yaml_idx = text.find("yaml-seeded")
        assert yaml_idx != -1
        assert "2" in text[yaml_idx : yaml_idx + 200]
        bundled_idx = text.find("bundled")
        assert bundled_idx != -1
        assert "1" in text[bundled_idx : bundled_idx + 200]
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_section_includes_import_guidance(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        assert "lynceus-import-argus" in r.text
        assert "lynceus-seed-watchlist" in r.text
    finally:
        db.close()


# ---------------------------------------------------------------------------
# System info section.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_system_info_shows_lynceus_version(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        assert __version__ in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_system_info_shows_db_path(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    db_path = str(tmp_path / "settings.db")
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        assert db_path in r.text
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Severity overrides + system info: guidance text.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_severity_overrides_section_includes_guidance(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        assert "severity_overrides.yaml" in r.text
        assert "Edit the file directly" in r.text
    finally:
        db.close()


# ---------------------------------------------------------------------------
# No-mutation guarantees.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_settings_post_returns_405(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r_get = client.get("/settings")
            token = r_get.cookies.get("lynceus_csrf", "")
            r = client.post("/settings", headers={CSRF_HEADER_NAME: token})
        assert r.status_code == 405
    finally:
        db.close()


@pytest.mark.webui
def test_settings_put_returns_405(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r_get = client.get("/settings")
            token = r_get.cookies.get("lynceus_csrf", "")
            r = client.put("/settings", headers={CSRF_HEADER_NAME: token})
        assert r.status_code == 405
    finally:
        db.close()


@pytest.mark.webui
def test_settings_patch_returns_405(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r_get = client.get("/settings")
            token = r_get.cookies.get("lynceus_csrf", "")
            r = client.patch("/settings", headers={CSRF_HEADER_NAME: token})
        assert r.status_code == 405
    finally:
        db.close()


@pytest.mark.webui
def test_settings_delete_returns_405(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r_get = client.get("/settings")
            token = r_get.cookies.get("lynceus_csrf", "")
            r = client.delete("/settings", headers={CSRF_HEADER_NAME: token})
        assert r.status_code == 405
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Misc safety / regression.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_xss_in_kismet_error_is_escaped(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "lynceus.kismet.KismetClient.health_check",
        lambda self: {
            "reachable": False,
            "version": None,
            "error": "<script>alert('xss')</script>",
        },
    )
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        assert "<script>alert('xss')</script>" not in r.text
        assert "&lt;script&gt;" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_importlib_metadata_used_for_version(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        with patch("importlib.metadata.version", return_value="9.9.9-test"):
            with TestClient(app) as client:
                r = client.get("/settings")
        assert r.status_code == 200
        assert "9.9.9-test" in r.text
    finally:
        db.close()
