"""Tests for the read-only web UI skeleton."""

from __future__ import annotations

import io
from contextlib import redirect_stdout

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from talos.config import Config
from talos.db import Database
from talos.webui.app import create_app


def _make_app(tmp_path):
    config = Config(db_path=str(tmp_path / "ui.db"))
    db = Database(config.db_path)
    app = create_app(config, db)
    return app, db


@pytest.mark.webui
def test_healthz_returns_200_and_renders(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/healthz")
        assert r.status_code == 200
        assert "schema version" in r.text
        assert "devices tracked" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_healthz_reflects_db_state(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        db.upsert_device("aa:bb:cc:dd:ee:01", "wifi", "Acme", 0, 100)
        db.upsert_device("aa:bb:cc:dd:ee:02", "wifi", "Acme", 0, 100)
        db.add_alert(ts=200, rule_name="rule_a", mac=None, message="boom", severity="high")

        with TestClient(app) as client:
            r = client.get("/healthz")
        assert r.status_code == 200
        text = r.text
        # Loose assertions — tighten when real views land in prompt 15.
        idx_devices = text.find("devices tracked")
        assert idx_devices != -1
        assert "2" in text[idx_devices : idx_devices + 200]
        idx_alerts_total = text.find("alerts (total)")
        assert idx_alerts_total != -1
        assert "1" in text[idx_alerts_total : idx_alerts_total + 200]
    finally:
        db.close()


@pytest.mark.webui
def test_root_renders_index_landing_page(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r_root = client.get("/")
            r_health = client.get("/healthz")
        assert r_root.status_code == 200
        assert r_health.status_code == 200
        # The new landing page is the index, not the healthz template.
        assert "<h2>home</h2>" in r_root.text
        assert "recent unacknowledged alerts" in r_root.text
    finally:
        db.close()


@pytest.mark.webui
def test_static_pico_css_served(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/static/pico.min.css")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/css")
    finally:
        db.close()


@pytest.mark.webui
def test_static_htmx_js_served(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/static/htmx.min.js")
        assert r.status_code == 200
        assert "javascript" in r.headers["content-type"]
    finally:
        db.close()


@pytest.mark.webui
def test_openapi_disabled(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            assert client.get("/openapi.json").status_code == 404
            assert client.get("/docs").status_code == 404
            assert client.get("/redoc").status_code == 404
    finally:
        db.close()


@pytest.mark.webui
def test_app_factory_returns_distinct_apps(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    app1, db1 = _make_app(tmp_path / "a")
    app2, db2 = _make_app(tmp_path / "b")
    try:
        assert app1 is not app2
        assert app1.state.db is not app2.state.db
    finally:
        db1.close()
        db2.close()


@pytest.mark.webui
def test_main_version_flag_exits_zero():
    from talos import __version__
    from talos.webui.server import main

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["--version"])
    assert rc == 0
    assert __version__ in buf.getvalue()


@pytest.mark.webui
def test_main_missing_config_returns_one(tmp_path):
    from talos.webui.server import main

    rc = main(["--config", str(tmp_path / "nonexistent.yaml")])
    assert rc == 1


@pytest.mark.webui
def test_config_default_ui_bind_host_loopback():
    cfg = Config()
    assert cfg.ui_bind_host == "127.0.0.1"
    assert cfg.ui_bind_port == 8765
    assert cfg.ui_allow_remote is False


@pytest.mark.webui
def test_config_non_loopback_without_remote_flag_rejected():
    with pytest.raises(ValidationError) as exc_info:
        Config(ui_bind_host="0.0.0.0")
    assert "ui_allow_remote" in str(exc_info.value)


@pytest.mark.webui
def test_config_non_loopback_with_remote_flag_accepted():
    cfg = Config(ui_bind_host="0.0.0.0", ui_allow_remote=True)
    assert cfg.ui_bind_host == "0.0.0.0"
    assert cfg.ui_allow_remote is True


@pytest.mark.webui
def test_config_localhost_string_accepted():
    cfg = Config(ui_bind_host="localhost")
    assert cfg.ui_bind_host == "localhost"
    assert cfg.ui_allow_remote is False


@pytest.mark.webui
def test_config_invalid_port_rejected():
    with pytest.raises(ValidationError):
        Config(ui_bind_port=0)
    with pytest.raises(ValidationError):
        Config(ui_bind_port=70000)


# ---------------------------------------------------------------------------
# Read-only views: alerts, devices, rules, allowlist.
# ---------------------------------------------------------------------------

MAC_A = "aa:bb:cc:dd:ee:01"
MAC_B = "aa:bb:cc:dd:ee:02"
LOC = "lab"


def _ack(db, alert_id):
    with db._conn:
        db._conn.execute("UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,))


@pytest.mark.webui
def test_index_renders_with_recent_alerts(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        a1 = db.add_alert(ts=100, rule_name="r", mac=None, message="acked-msg", severity="low")
        db.add_alert(ts=200, rule_name="r", mac=None, message="unacked-one", severity="med")
        db.add_alert(ts=300, rule_name="r", mac=None, message="unacked-two", severity="high")
        _ack(db, a1)
        with TestClient(app) as client:
            r = client.get("/")
        assert r.status_code == 200
        assert "unacked-one" in r.text
        assert "unacked-two" in r.text
        assert "acked-msg" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_index_renders_with_no_alerts_shows_empty_message(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/")
        assert r.status_code == 200
        assert "No unacknowledged alerts" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_renders(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        for i in range(5):
            db.add_alert(ts=100 + i, rule_name="r", mac=None, message=f"alert-{i}", severity="low")
        with TestClient(app) as client:
            r = client.get("/alerts")
        assert r.status_code == 200
        for i in range(5):
            assert f"alert-{i}" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_filter_severity(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        db.add_alert(ts=100, rule_name="r", mac=None, message="low-msg", severity="low")
        db.add_alert(ts=101, rule_name="r", mac=None, message="med-msg", severity="med")
        db.add_alert(ts=102, rule_name="r", mac=None, message="high-msg", severity="high")
        with TestClient(app) as client:
            r = client.get("/alerts?severity=high")
        assert r.status_code == 200
        assert "high-msg" in r.text
        assert "low-msg" not in r.text
        assert "med-msg" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_filter_acknowledged_true_false(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        a1 = db.add_alert(ts=100, rule_name="r", mac=None, message="ackmsg-yes", severity="low")
        db.add_alert(ts=200, rule_name="r", mac=None, message="pendmsg-no", severity="low")
        _ack(db, a1)
        with TestClient(app) as client:
            r_acked = client.get("/alerts?acknowledged=true")
            r_unacked = client.get("/alerts?acknowledged=false")
        assert "ackmsg-yes" in r_acked.text
        assert "pendmsg-no" not in r_acked.text
        assert "pendmsg-no" in r_unacked.text
        assert "ackmsg-yes" not in r_unacked.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_invalid_severity_returns_400(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/alerts?severity=critical")
        assert r.status_code == 400
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_invalid_acknowledged_returns_400(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/alerts?acknowledged=maybe")
        assert r.status_code == 400
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_pagination_links_preserve_filters(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        for i in range(60):
            db.add_alert(ts=100 + i, rule_name="r", mac=None, message=f"m{i}", severity="high")
        with TestClient(app) as client:
            r = client.get("/alerts?severity=high&page=1&page_size=25")
        assert r.status_code == 200
        assert "severity=high" in r.text
        assert "page=2" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alert_detail_renders(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        db.upsert_device(MAC_A, "wifi", "Acme", 0, 100)
        aid = db.add_alert(
            ts=500, rule_name="my_rule", mac=MAC_A, message="boom-msg", severity="high"
        )
        with TestClient(app) as client:
            r = client.get(f"/alerts/{aid}")
        assert r.status_code == 200
        assert "boom-msg" in r.text
        assert "my_rule" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alert_detail_404(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/alerts/9999")
        assert r.status_code == 404
        assert "not found" in r.text.lower()
    finally:
        db.close()


@pytest.mark.webui
def test_alert_detail_with_null_mac_no_device_section(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        aid = db.add_alert(ts=500, rule_name="r", mac=None, message="systemic", severity="med")
        with TestClient(app) as client:
            r = client.get(f"/alerts/{aid}")
        assert r.status_code == 200
        assert "systemic" in r.text
        # No device card should be present.
        assert "<header><strong>device</strong></header>" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_devices_list_renders(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        db.upsert_device(MAC_A, "wifi", "Acme", 0, 100)
        db.upsert_device(MAC_B, "ble", "Beta", 1, 200)
        with TestClient(app) as client:
            r = client.get("/devices")
        assert r.status_code == 200
        assert MAC_A in r.text
        assert MAC_B in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_devices_list_filter_by_type(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        db.upsert_device(MAC_A, "wifi", "Acme", 0, 100)
        db.upsert_device(MAC_B, "ble", "Beta", 0, 100)
        with TestClient(app) as client:
            r = client.get("/devices?device_type=ble")
        assert r.status_code == 200
        assert MAC_B in r.text
        assert MAC_A not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_devices_list_filter_randomized_true_false(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        db.upsert_device(MAC_A, "wifi", "Acme", 0, 100)
        db.upsert_device(MAC_B, "wifi", "Acme", 1, 100)
        with TestClient(app) as client:
            r_rand = client.get("/devices?randomized=true")
            r_not = client.get("/devices?randomized=false")
        assert MAC_B in r_rand.text and MAC_A not in r_rand.text
        assert MAC_A in r_not.text and MAC_B not in r_not.text
    finally:
        db.close()


@pytest.mark.webui
def test_devices_list_invalid_type_returns_400(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/devices?device_type=cellular")
        assert r.status_code == 400
    finally:
        db.close()


@pytest.mark.webui
def test_device_detail_renders_with_sightings(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        db.ensure_location(LOC, "Lab")
        db.upsert_device(MAC_A, "wifi", "Acme", 0, 100)
        for ts in (1234567001, 1234567002, 1234567003):
            db.insert_sighting(MAC_A, ts, -55, "TestSSID", LOC)
        with TestClient(app) as client:
            r = client.get(f"/devices/{MAC_A}")
        assert r.status_code == 200
        assert "1234567001" in r.text
        assert "1234567002" in r.text
        assert "1234567003" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_device_detail_404_for_unknown_mac(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/devices/aa:bb:cc:dd:ee:99")
        assert r.status_code == 404
        assert "not found" in r.text.lower()
    finally:
        db.close()


@pytest.mark.webui
def test_device_detail_400_for_malformed_mac(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/devices/not-a-mac")
        assert r.status_code == 400
    finally:
        db.close()


@pytest.mark.webui
def test_device_detail_mac_with_colons_routes_correctly(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        db.upsert_device("aa:bb:cc:dd:ee:ff", "wifi", "Acme", 0, 100)
        with TestClient(app) as client:
            r = client.get("/devices/aa:bb:cc:dd:ee:ff")
        assert r.status_code == 200
        assert "aa:bb:cc:dd:ee:ff" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_rules_list_renders_from_file(tmp_path):
    rules_yaml = tmp_path / "rules.yaml"
    rules_yaml.write_text(
        "rules:\n"
        "  - name: known_bad_mac\n"
        "    rule_type: watchlist_mac\n"
        "    severity: high\n"
        "    patterns: ['de:ad:be:ef:00:01']\n"
        "  - name: rogue_ssids\n"
        "    rule_type: watchlist_ssid\n"
        "    severity: med\n"
        "    patterns: ['FreeAirportWiFi']\n",
        encoding="utf-8",
    )
    config = Config(db_path=str(tmp_path / "ui.db"), rules_path=str(rules_yaml))
    db = Database(config.db_path)
    app = create_app(config, db)
    try:
        with TestClient(app) as client:
            r = client.get("/rules")
        assert r.status_code == 200
        assert "known_bad_mac" in r.text
        assert "rogue_ssids" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_rules_list_with_no_path_shows_empty_notice(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/rules")
        assert r.status_code == 200
        assert "rules_path" in r.text or "No rules" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_rules_list_with_missing_file_shows_empty_notice(tmp_path):
    config = Config(
        db_path=str(tmp_path / "ui.db"),
        rules_path=str(tmp_path / "nope.yaml"),
    )
    db = Database(config.db_path)
    app = create_app(config, db)
    try:
        with TestClient(app) as client:
            r = client.get("/rules")
        assert r.status_code == 200
        assert "not found" in r.text.lower()
    finally:
        db.close()


@pytest.mark.webui
def test_rules_list_disabled_rules_dimmed(tmp_path):
    rules_yaml = tmp_path / "rules.yaml"
    rules_yaml.write_text(
        "rules:\n"
        "  - name: enabled_rule\n"
        "    rule_type: watchlist_mac\n"
        "    severity: high\n"
        "    patterns: ['aa:bb:cc:dd:ee:ff']\n"
        "  - name: disabled_rule\n"
        "    rule_type: watchlist_mac\n"
        "    severity: low\n"
        "    patterns: ['11:22:33:44:55:66']\n"
        "    enabled: false\n",
        encoding="utf-8",
    )
    config = Config(db_path=str(tmp_path / "ui.db"), rules_path=str(rules_yaml))
    db = Database(config.db_path)
    app = create_app(config, db)
    try:
        with TestClient(app) as client:
            r = client.get("/rules")
        assert r.status_code == 200
        assert "enabled_rule" in r.text
        assert "disabled_rule" in r.text
        # Disabled rule must be visually dimmed.
        idx_disabled = r.text.find("disabled_rule")
        # Walk back to the enclosing <article ...> tag.
        article_start = r.text.rfind("<article", 0, idx_disabled)
        assert article_start != -1
        article_open = r.text[article_start:idx_disabled]
        assert "dim" in article_open or "opacity" in article_open
    finally:
        db.close()


@pytest.mark.webui
def test_allowlist_renders_from_file(tmp_path):
    allowlist_yaml = tmp_path / "allowlist.yaml"
    allowlist_yaml.write_text(
        "entries:\n"
        "  - pattern: 'a4:83:e7:11:22:33'\n"
        "    pattern_type: mac\n"
        "    note: My laptop\n"
        "  - pattern: 'HomeNet'\n"
        "    pattern_type: ssid\n",
        encoding="utf-8",
    )
    config = Config(db_path=str(tmp_path / "ui.db"), allowlist_path=str(allowlist_yaml))
    db = Database(config.db_path)
    app = create_app(config, db)
    try:
        with TestClient(app) as client:
            r = client.get("/allowlist")
        assert r.status_code == 200
        assert "a4:83:e7:11:22:33" in r.text
        assert "HomeNet" in r.text
        assert "My laptop" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_allowlist_with_no_path_shows_empty_notice(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/allowlist")
        assert r.status_code == 200
        assert "allowlist_path" in r.text or "No allowlist" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_topnav_active_link(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/alerts")
        assert r.status_code == 200
        # The alerts link is marked active.
        assert 'href="/alerts" class="active"' in r.text
        # The devices link is not.
        assert 'href="/devices" class="active"' not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_static_talos_css_served_with_view_classes(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/static/talos.css")
        assert r.status_code == 200
        assert "badge-high" in r.text
    finally:
        db.close()
