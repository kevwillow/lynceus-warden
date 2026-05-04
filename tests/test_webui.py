"""Tests for the read-only web UI skeleton."""

from __future__ import annotations

import io
from contextlib import redirect_stdout
from pathlib import Path

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


# ---------------------------------------------------------------------------
# Prompt 003: ack/unack mutations, bulk ack, filter polish, stats, CSRF.
# ---------------------------------------------------------------------------

from talos.webui.csrf import CSRF_COOKIE_NAME, CSRF_FORM_FIELD  # noqa: E402


def _csrf_setup(client) -> tuple[str, dict]:
    resp = client.get("/alerts")
    cookie = resp.cookies[CSRF_COOKIE_NAME]
    return cookie, {CSRF_COOKIE_NAME: cookie}


@pytest.mark.webui
def test_index_renders_severity_grid_with_three_windows(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/")
        assert r.status_code == 200
        assert "stat-grid" in r.text
        assert "24h" in r.text
        assert "7d" in r.text
        assert "30d" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_index_renders_sparkline_with_30_bars(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/")
        assert r.status_code == 200
        assert 'class="sparkline"' in r.text
        assert r.text.count("sparkline-bar") == 30
    finally:
        db.close()


@pytest.mark.webui
def test_index_sparkline_handles_zero_max_without_div_by_zero(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/")
        assert r.status_code == 200
        # Page renders successfully even with no alerts (max_count=0).
        assert "sparkline-bar" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_index_inline_ack_button_present_on_unacked_alerts(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        aid = db.add_alert(ts=100, rule_name="r", mac=None, message="x", severity="low")
        with TestClient(app) as client:
            r = client.get("/")
        assert r.status_code == 200
        assert f"/alerts/{aid}/ack" in r.text
        assert "ack-button-inline" in r.text
        assert CSRF_FORM_FIELD in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_filter_since_until(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        # 2026-04-01 ~ 1775347200, 2026-04-15, 2026-05-01.
        ts_apr1 = 1775347200
        ts_apr15 = ts_apr1 + 14 * 86400
        ts_may1 = ts_apr1 + 30 * 86400
        db.add_alert(ts=ts_apr1, rule_name="r", mac=None, message="apr1-msg", severity="low")
        db.add_alert(ts=ts_apr15, rule_name="r", mac=None, message="apr15-msg", severity="low")
        db.add_alert(ts=ts_may1, rule_name="r", mac=None, message="may1-msg", severity="low")
        with TestClient(app) as client:
            r = client.get("/alerts?since=2026-04-10&until=2026-04-20")
        assert r.status_code == 200
        assert "apr15-msg" in r.text
        assert "apr1-msg" not in r.text
        assert "may1-msg" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_filter_search_message(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        db.add_alert(ts=100, rule_name="r1", mac=None, message="rogue beacon found", severity="low")
        db.add_alert(ts=101, rule_name="r2", mac=None, message="ordinary boring", severity="low")
        with TestClient(app) as client:
            r = client.get("/alerts?search=rogue")
        assert r.status_code == 200
        assert "rogue beacon found" in r.text
        assert "ordinary boring" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_filter_search_rule_name(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        db.add_alert(ts=100, rule_name="watchlist_mac", mac=None, message="msg-a", severity="low")
        db.add_alert(ts=101, rule_name="rogue_ap", mac=None, message="msg-b", severity="low")
        with TestClient(app) as client:
            r = client.get("/alerts?search=watch")
        assert r.status_code == 200
        assert "msg-a" in r.text
        assert "msg-b" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_filter_search_too_long_returns_400(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/alerts?search=" + "a" * 101)
        assert r.status_code == 400
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_filter_invalid_date_returns_400(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r1 = client.get("/alerts?since=not-a-date")
            r2 = client.get("/alerts?until=2026-13-99")
        assert r1.status_code == 400
        assert r2.status_code == 400
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_pagination_preserves_search_and_dates(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        for i in range(60):
            db.add_alert(
                ts=1775347200 + i,
                rule_name="r",
                mac=None,
                message=f"world {i}",
                severity="low",
            )
        with TestClient(app) as client:
            r = client.get(
                "/alerts?search=world&since=2026-04-01&until=2026-05-01&page=1&page_size=25"
            )
        assert r.status_code == 200
        assert "search=world" in r.text
        assert "since=2026-04-01" in r.text
        assert "until=2026-05-01" in r.text
        assert "page=2" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_bulk_ack_form_has_csrf_field(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
        with TestClient(app) as client:
            r = client.get("/alerts")
        assert r.status_code == 200
        assert 'action="/alerts/bulk-ack"' in r.text
        assert f'name="{CSRF_FORM_FIELD}"' in r.text
        assert 'name="alert_ids"' in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_ack_post_without_csrf_returns_403(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
        with TestClient(app) as client:
            client.cookies.clear()
            r = client.post(f"/alerts/{aid}/ack")
        assert r.status_code == 403
        assert db.get_alert(aid)["acknowledged"] == 0
    finally:
        db.close()


@pytest.mark.webui
def test_ack_post_with_valid_csrf_succeeds(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                f"/alerts/{aid}/ack",
                data={CSRF_FORM_FIELD: token, "note": "looked at it"},
            )
        assert r.status_code == 303
        alert = db.get_alert(aid)
        assert alert["acknowledged"] == 1
        actions = db.list_alert_actions(aid)
        assert len(actions) == 1
        assert actions[0]["note"] == "looked at it"
    finally:
        db.close()


@pytest.mark.webui
def test_ack_post_for_missing_alert_returns_404(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                "/alerts/9999/ack",
                data={CSRF_FORM_FIELD: token},
            )
        assert r.status_code == 404
    finally:
        db.close()


@pytest.mark.webui
def test_ack_post_with_too_long_note_returns_400(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                f"/alerts/{aid}/ack",
                data={CSRF_FORM_FIELD: token, "note": "x" * 501},
            )
        assert r.status_code == 400
        assert db.get_alert(aid)["acknowledged"] == 0
    finally:
        db.close()


@pytest.mark.webui
def test_unack_post_with_valid_csrf_succeeds(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
        db.acknowledge_alert(aid, actor="seed", ts=200)
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                f"/alerts/{aid}/unack",
                data={CSRF_FORM_FIELD: token},
            )
        assert r.status_code == 303
        assert db.get_alert(aid)["acknowledged"] == 0
        actions = db.list_alert_actions(aid)
        assert actions[0]["action"] == "unack"
    finally:
        db.close()


@pytest.mark.webui
def test_bulk_ack_post_renders_result_page(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        a1 = db.add_alert(ts=100, rule_name="r", mac=None, message="a", severity="low")
        a2 = db.add_alert(ts=101, rule_name="r", mac=None, message="b", severity="low")
        a3 = db.add_alert(ts=102, rule_name="r", mac=None, message="c", severity="low")
        db.acknowledge_alert(a3, actor="seed", ts=150)
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                "/alerts/bulk-ack",
                data={
                    CSRF_FORM_FIELD: token,
                    "alert_ids": [str(a1), str(a2), str(a3)],
                },
            )
        assert r.status_code == 200
        assert "bulk acknowledge result" in r.text.lower()
        # The result page surfaces the counts.
        assert "acknowledged" in r.text.lower()
        # Action rows: one per existing alert (3).
        cnt = db._conn.execute("SELECT COUNT(*) FROM alert_actions").fetchone()[0]
        assert cnt == 4  # 1 from seed + 3 from bulk
    finally:
        db.close()


@pytest.mark.webui
def test_bulk_ack_post_without_alert_ids_returns_400(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                "/alerts/bulk-ack",
                data={CSRF_FORM_FIELD: token},
            )
        assert r.status_code == 400
    finally:
        db.close()


@pytest.mark.webui
def test_bulk_ack_post_with_too_many_ids_returns_400(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                "/alerts/bulk-ack",
                data={
                    CSRF_FORM_FIELD: token,
                    "alert_ids": [str(i) for i in range(1, 1002)],
                },
            )
        assert r.status_code == 400
    finally:
        db.close()


@pytest.mark.webui
def test_alert_detail_renders_action_history(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
        db.acknowledge_alert(aid, actor="ip-1", ts=200)
        db.acknowledge_alert(aid, actor="ip-2", ts=300)
        with TestClient(app) as client:
            r = client.get(f"/alerts/{aid}")
        assert r.status_code == 200
        assert "action history" in r.text.lower()
        # Both action rows show.
        assert "ip-1" in r.text
        assert "ip-2" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alert_detail_unack_form_shown_when_acked(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
        with TestClient(app) as client:
            r_unacked = client.get(f"/alerts/{aid}")
            db.acknowledge_alert(aid, actor="ip", ts=200)
            r_acked = client.get(f"/alerts/{aid}")
        assert f'action="/alerts/{aid}/ack"' in r_unacked.text
        assert f'action="/alerts/{aid}/unack"' not in r_unacked.text
        assert f'action="/alerts/{aid}/unack"' in r_acked.text
    finally:
        db.close()


@pytest.mark.webui
def test_csrf_token_in_template_matches_cookie(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        # Add an alert so an inline ack form (with CSRF field) is rendered.
        db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
        with TestClient(app) as client:
            client.cookies.clear()
            r = client.get("/")
        assert r.status_code == 200
        cookie_val = r.cookies[CSRF_COOKIE_NAME]
        assert f'value="{cookie_val}"' in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_redirect_to_referer_only_when_same_origin(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r_safe = client.post(
                f"/alerts/{aid}/ack",
                data={CSRF_FORM_FIELD: token},
                headers={"Referer": "/alerts"},
            )
        assert r_safe.status_code == 303
        assert r_safe.headers["location"] == "/alerts"
        # Re-unack to test the evil-referer case.
        db.unacknowledge_alert(aid, actor="reset", ts=400)
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r_evil = client.post(
                f"/alerts/{aid}/ack",
                data={CSRF_FORM_FIELD: token},
                headers={"Referer": "http://evil.com/alerts"},
            )
        assert r_evil.status_code == 303
        assert r_evil.headers["location"] == "/alerts"
    finally:
        db.close()


# ---------------------------------------------------------------------------
# UX polish: device-seen tiles, last-poll, ack-all-visible, unix_to_iso filter,
# severity row classes, inline ack note, reset-filters link, talos.js.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_index_renders_device_seen_tiles(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        import time as _time

        now = int(_time.time())
        db.ensure_location(LOC, "Lab")
        db.upsert_device(MAC_A, "wifi", "Acme", 0, now)
        db.upsert_device(MAC_B, "ble", "Acme", 0, now)
        db.insert_sighting(MAC_A, now - 60, None, None, LOC)
        db.insert_sighting(MAC_B, now - 5 * 86400, None, None, LOC)
        with TestClient(app) as client:
            r = client.get("/")
        assert r.status_code == 200
        assert "tile-row" in r.text
        assert "last 24h" in r.text
        assert "last 7d" in r.text
        assert "last 30d" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_index_renders_last_poll_when_set(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        db.set_state("last_poll_ts", "1700000000")
        with TestClient(app) as client:
            r = client.get("/")
        assert r.status_code == 200
        assert "Last polled" in r.text
        assert 'datetime="' in r.text
        assert "<time" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_index_renders_never_polled_when_unset(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/")
        assert r.status_code == 200
        assert "Never polled yet" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_reset_link_present_when_filters_active(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/alerts?severity=high")
        assert r.status_code == 200
        assert "reset-filters" in r.text
        assert 'href="/alerts"' in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_reset_link_absent_when_no_filters(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/alerts")
        assert r.status_code == 200
        assert "reset-filters" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_ack_all_visible_form_carries_filter_state(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="high")
        with TestClient(app) as client:
            r = client.get("/alerts?severity=high&acknowledged=false")
        assert r.status_code == 200
        assert 'action="/alerts/ack-all-visible"' in r.text
        assert 'name="severity" value="high"' in r.text
        assert 'name="acknowledged" value="false"' in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_ack_all_visible_acks_filtered_subset(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        high_ids = [
            db.add_alert(ts=100 + i, rule_name="r", mac=None, message=f"h{i}", severity="high")
            for i in range(3)
        ]
        low_ids = [
            db.add_alert(ts=200 + i, rule_name="r", mac=None, message=f"l{i}", severity="low")
            for i in range(2)
        ]
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                "/alerts/ack-all-visible",
                data={CSRF_FORM_FIELD: token, "severity": "high"},
            )
        assert r.status_code == 200
        assert "bulk acknowledge result" in r.text.lower()
        for aid in high_ids:
            assert db.get_alert(aid)["acknowledged"] == 1
        for aid in low_ids:
            assert db.get_alert(aid)["acknowledged"] == 0
    finally:
        db.close()


@pytest.mark.webui
def test_ack_all_visible_respects_acknowledged_filter(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        a1 = db.add_alert(ts=100, rule_name="r", mac=None, message="a", severity="low")
        a2 = db.add_alert(ts=101, rule_name="r", mac=None, message="b", severity="low")
        a3 = db.add_alert(ts=102, rule_name="r", mac=None, message="c", severity="low")
        db.acknowledge_alert(a3, actor="seed", ts=150)
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                "/alerts/ack-all-visible",
                data={CSRF_FORM_FIELD: token, "acknowledged": "false"},
            )
        assert r.status_code == 200
        assert db.get_alert(a1)["acknowledged"] == 1
        assert db.get_alert(a2)["acknowledged"] == 1
        # a3 was already acked; the "acknowledged=false" filter excluded it
        # from the candidate set, so no NEW action row was written for it
        # (only the original seed acknowledgement remains).
        assert db.get_alert(a3)["acknowledged"] == 1
        actions_a3 = db.list_alert_actions(a3)
        assert len(actions_a3) == 1
        assert actions_a3[0]["actor"] == "seed"
    finally:
        db.close()


@pytest.mark.webui
def test_ack_all_visible_invalid_severity_returns_400(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                "/alerts/ack-all-visible",
                data={CSRF_FORM_FIELD: token, "severity": "critical"},
            )
        assert r.status_code == 400
    finally:
        db.close()


@pytest.mark.webui
def test_ack_all_visible_invalid_date_returns_400(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                "/alerts/ack-all-visible",
                data={CSRF_FORM_FIELD: token, "since": "not-a-date"},
            )
        assert r.status_code == 400
    finally:
        db.close()


@pytest.mark.webui
def test_ack_all_visible_overflow_returns_400(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        for i in range(1001):
            db.add_alert(ts=100 + i, rule_name="r", mac=None, message=f"m{i}", severity="low")
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                "/alerts/ack-all-visible",
                data={CSRF_FORM_FIELD: token},
            )
        assert r.status_code == 400
        assert "1000" in r.text
        # Nothing should have been written.
        assert db._conn.execute("SELECT COUNT(*) FROM alert_actions").fetchone()[0] == 0
        assert (
            db._conn.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged = 1").fetchone()[0]
            == 0
        )
    finally:
        db.close()


@pytest.mark.webui
def test_ack_all_visible_no_match_returns_zero_counts(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                "/alerts/ack-all-visible",
                data={CSRF_FORM_FIELD: token, "severity": "high"},
            )
        assert r.status_code == 200
        assert "bulk acknowledge result" in r.text.lower()
    finally:
        db.close()


@pytest.mark.webui
def test_ack_all_visible_without_csrf_returns_403(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
        with TestClient(app, follow_redirects=False) as client:
            client.cookies.clear()
            r = client.post("/alerts/ack-all-visible")
        assert r.status_code == 403
    finally:
        db.close()


@pytest.mark.webui
def test_unix_to_iso_filter_renders_z_suffix(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        aid = db.add_alert(ts=1700000000, rule_name="r", mac=None, message="m", severity="low")
        with TestClient(app) as client:
            r = client.get(f"/alerts/{aid}")
        assert r.status_code == 200
        assert 'datetime="2023-11-14T22:13:20Z"' in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_unix_to_iso_filter_handles_none():
    from talos.webui.app import unix_to_iso

    assert unix_to_iso(None) == ""
    assert unix_to_iso("") == ""
    assert unix_to_iso(0) == "1970-01-01T00:00:00Z"


@pytest.mark.webui
def test_static_talos_js_served(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/static/talos.js")
        assert r.status_code == 200
        assert "javascript" in r.headers["content-type"]
    finally:
        db.close()


@pytest.mark.webui
def test_base_html_includes_talos_js_script(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/")
        assert r.status_code == 200
        assert 'src="/static/talos.js"' in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_inline_ack_note_input_present_per_row(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        for i in range(3):
            db.add_alert(ts=100 + i, rule_name="r", mac=None, message=f"m{i}", severity="low")
        with TestClient(app) as client:
            r = client.get("/alerts")
        assert r.status_code == 200
        # Each unacked row carries a note input. Bulk-ack form has its own
        # textarea; the row inputs use class ack-row-note to disambiguate.
        assert r.text.count("ack-row-note") >= 3
    finally:
        db.close()


@pytest.mark.webui
def test_inline_ack_note_submitted(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                f"/alerts/{aid}/ack",
                data={CSRF_FORM_FIELD: token, "note": "manual"},
            )
        assert r.status_code == 303
        actions = db.list_alert_actions(aid)
        assert len(actions) == 1
        assert actions[0]["note"] == "manual"
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_row_class_reflects_severity(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        db.add_alert(ts=100, rule_name="r", mac=None, message="low-x", severity="low")
        db.add_alert(ts=101, rule_name="r", mac=None, message="med-x", severity="med")
        db.add_alert(ts=102, rule_name="r", mac=None, message="high-x", severity="high")
        with TestClient(app) as client:
            r = client.get("/alerts")
        assert r.status_code == 200
        assert "row-sev-low" in r.text
        assert "row-sev-med" in r.text
        assert "row-sev-high" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_row_class_acked(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
        _ack(db, aid)
        with TestClient(app) as client:
            r = client.get("/alerts")
        assert r.status_code == 200
        assert "row-acked" in r.text
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Kismet status indicator on the index page (cached for 30s).
# ---------------------------------------------------------------------------


class _FakeStatusClient:
    def __init__(self, status: dict):
        self._status = status
        self.calls = 0

    def health_check(self):
        self.calls += 1
        return dict(self._status)


@pytest.mark.webui
def test_index_renders_kismet_status_reachable(tmp_path):
    app, db = _make_app(tmp_path)
    fake = _FakeStatusClient({"reachable": True, "version": "fake-fixture", "error": None})
    app.state.kismet_client = fake
    try:
        with TestClient(app) as client:
            r = client.get("/")
        assert r.status_code == 200
        assert "Kismet status" in r.text
        assert "reachable" in r.text
        assert "fake-fixture" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_index_renders_kismet_status_unreachable(tmp_path):
    app, db = _make_app(tmp_path)
    fake = _FakeStatusClient({"reachable": False, "version": None, "error": "connection refused"})
    app.state.kismet_client = fake
    try:
        with TestClient(app) as client:
            r = client.get("/")
        assert r.status_code == 200
        assert "unreachable" in r.text
        assert "connection refused" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_index_kismet_status_caches_for_30_seconds(tmp_path, monkeypatch):
    app, db = _make_app(tmp_path)
    fake = _FakeStatusClient({"reachable": True, "version": "fake-fixture", "error": None})
    app.state.kismet_client = fake

    fake_now = {"t": 1_700_000_000.0}

    def fake_time():
        return fake_now["t"]

    monkeypatch.setattr("talos.webui.app.time.time", fake_time)
    try:
        with TestClient(app) as client:
            client.get("/")
            fake_now["t"] += 25
            client.get("/")
        assert fake.calls == 1
    finally:
        db.close()


@pytest.mark.webui
def test_index_kismet_status_recheck_after_cache_expiry(tmp_path, monkeypatch):
    app, db = _make_app(tmp_path)
    fake = _FakeStatusClient({"reachable": True, "version": "fake-fixture", "error": None})
    app.state.kismet_client = fake

    fake_now = {"t": 1_700_000_000.0}

    def fake_time():
        return fake_now["t"]

    monkeypatch.setattr("talos.webui.app.time.time", fake_time)
    try:
        with TestClient(app) as client:
            client.get("/")
            fake_now["t"] += 31
            client.get("/")
        assert fake.calls == 2
    finally:
        db.close()


@pytest.mark.webui
def test_index_kismet_status_health_check_exception_degrades(tmp_path):
    app, db = _make_app(tmp_path)

    class _RaisingClient:
        def health_check(self):
            raise RuntimeError("kaboom")

    app.state.kismet_client = _RaisingClient()
    try:
        with TestClient(app) as client:
            r = client.get("/")
        assert r.status_code == 200
        assert "unreachable" in r.text
        assert "kaboom" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_topnav_present_on_every_page(tmp_path):
    """Every page that renders the base template must include the top nav.

    This test exists because /healthz shipped without _topnav.html for
    several prompts and was only caught by manual browser testing. Tests
    that asserted page-specific content didn't notice the missing nav.

    Approach: hit every GET route that renders an HTML page, assert each
    response contains the topnav's distinctive markers (the link to /alerts
    AND the link to /devices). If a future page is added without the
    partial, this test fails for that page.
    """
    app, db = _make_app(tmp_path)

    # Seed minimal data so detail pages have something to render.
    now = 1700000000
    db.ensure_location("default", "Default")
    db.upsert_device(
        mac="aa:bb:cc:dd:ee:ff",
        device_type="wifi",
        oui_vendor="TestVendor",
        is_randomized=0,
        now_ts=now,
    )
    db.insert_sighting(
        mac="aa:bb:cc:dd:ee:ff",
        ts=now,
        rssi=-50,
        ssid="test",
        location_id="default",
    )
    alert_id = db.add_alert(
        ts=now,
        rule_name="test_rule",
        mac="aa:bb:cc:dd:ee:ff",
        message="test alert",
        severity="low",
    )

    from fastapi.testclient import TestClient

    client = TestClient(app)

    pages = [
        "/",
        "/healthz",
        "/alerts",
        f"/alerts/{alert_id}",
        "/devices",
        "/devices/aa:bb:cc:dd:ee:ff",
        "/rules",
        "/allowlist",
    ]

    for path in pages:
        resp = client.get(path)
        assert resp.status_code == 200, f"{path} returned {resp.status_code}"
        # Topnav distinctive markers — these come from _topnav.html only.
        # Use markers that are unlikely to appear in any page's content
        # by accident. All four must be present, anchored as href targets,
        # so a page that incidentally mentioned the word "alerts" in
        # body content wouldn't pass while missing the nav.
        assert 'href="/alerts"' in resp.text, f"{path} missing /alerts nav link"
        assert 'href="/devices"' in resp.text, f"{path} missing /devices nav link"
        assert 'href="/rules"' in resp.text, f"{path} missing /rules nav link"
        assert 'href="/allowlist"' in resp.text, f"{path} missing /allowlist nav link"

    db.close()


# ---------------------------------------------------------------------------
# v0.2 UI tweaks: header rename, sparkline section, JS time-format change.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_kismet_status_header_renamed(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/")
        assert r.status_code == 200
        assert "Kismet status" in r.text
        assert "Kismet sources" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_index_renders_alerts_per_day_section(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/")
        assert r.status_code == 200
        assert "alerts per day" in r.text
        assert 'class="sparkline"' in r.text
    finally:
        db.close()


def test_talos_js_contains_new_format_logic():
    js_path = (
        Path(__file__).resolve().parent.parent / "src" / "talos" / "webui" / "static" / "talos.js"
    )
    content = js_path.read_text(encoding="utf-8")
    for needle in ("weeks ago", "months ago", "years ago", "just now"):
        assert needle in content, f"talos.js missing expected phrase: {needle!r}"
    for gone in ("minutes ago", "hours ago"):
        assert gone not in content, f"talos.js still contains old relative-format phrase: {gone!r}"
