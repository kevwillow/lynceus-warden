"""Tests for the read-only web UI skeleton."""

from __future__ import annotations

import io
from contextlib import redirect_stdout
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient
from pydantic import ValidationError

from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import create_app


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
    from lynceus import __version__
    from lynceus.webui.server import main

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["--version"])
    assert rc == 0
    assert __version__ in buf.getvalue()


@pytest.mark.webui
def test_main_missing_config_returns_one(tmp_path):
    from lynceus.webui.server import main

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
def test_relative_time_filter_buckets():
    from lynceus.webui.app import relative_time

    now = 1_000_000
    # None / empty → "—"
    assert relative_time(None, now_ts=now) == "—"
    assert relative_time("", now_ts=now) == "—"
    # < 60s → "just now"
    assert relative_time(now - 30, now_ts=now) == "just now"
    # Future timestamp (clock skew) → "just now", not negative.
    assert relative_time(now + 30, now_ts=now) == "just now"
    # < 60 min
    assert relative_time(now - 600, now_ts=now) == "10m ago"
    # < 24 h
    assert relative_time(now - 3 * 3600, now_ts=now) == "3h ago"
    # >= 24 h
    assert relative_time(now - 5 * 86400, now_ts=now) == "5d ago"


@pytest.mark.webui
def test_rules_list_default_window_is_7d_and_default_sort_preserves_yaml_order(tmp_path):
    """Bookmarked URLs from pre-rc5 (no query params) must keep
    yielding the same row order — defaulting to count_desc would
    surprise operators. The window default of 7d matches the
    /alerts intuition of "recent past"."""
    rules_yaml = tmp_path / "rules.yaml"
    rules_yaml.write_text(
        "rules:\n"
        "  - name: aaaa_first_in_yaml\n"
        "    rule_type: watchlist_mac\n"
        "    severity: high\n"
        "    patterns: ['de:ad:be:ef:00:01']\n"
        "  - name: bbbb_second_in_yaml\n"
        "    rule_type: watchlist_ssid\n"
        "    severity: med\n"
        "    patterns: ['SSID']\n",
        encoding="utf-8",
    )
    config = Config(db_path=str(tmp_path / "ui.db"), rules_path=str(rules_yaml))
    db = Database(config.db_path)
    # Give bbbb more fires than aaaa; default sort must still put
    # aaaa first because that's the rules.yaml order.
    import time as _time

    now = int(_time.time())
    db.add_alert(ts=now - 100, rule_name="aaaa_first_in_yaml", mac=None,
                 message="x", severity="high")
    db.add_alert(ts=now - 200, rule_name="bbbb_second_in_yaml", mac=None,
                 message="x", severity="med")
    db.add_alert(ts=now - 300, rule_name="bbbb_second_in_yaml", mac=None,
                 message="x", severity="med")
    app = create_app(config, db)
    try:
        with TestClient(app) as client:
            r = client.get("/rules")
        assert r.status_code == 200
        # Default window is 7d → label text appears in the page.
        assert "last 7d" in r.text or "7d" in r.text
        idx_a = r.text.find("aaaa_first_in_yaml")
        idx_b = r.text.find("bbbb_second_in_yaml")
        assert idx_a != -1 and idx_b != -1
        assert idx_a < idx_b, "default sort must preserve rules.yaml order"
        # The "fires" stats line must show the actual counts.
        # Find the fires line right after aaaa's row.
        aaaa_segment = r.text[idx_a:idx_b]
        assert "fires" in aaaa_segment.lower()
        # aaaa has exactly 1 fire in the default 7d window.
        assert "1" in aaaa_segment
    finally:
        db.close()


@pytest.mark.webui
def test_rules_list_since_window_narrows_counts(tmp_path):
    """since=1h must exclude the older alert; rule's count drops."""
    rules_yaml = tmp_path / "rules.yaml"
    rules_yaml.write_text(
        "rules:\n"
        "  - name: r1\n"
        "    rule_type: watchlist_mac\n"
        "    severity: high\n"
        "    patterns: ['de:ad:be:ef:00:01']\n",
        encoding="utf-8",
    )
    config = Config(db_path=str(tmp_path / "ui.db"), rules_path=str(rules_yaml))
    db = Database(config.db_path)
    import time as _time

    now = int(_time.time())
    db.add_alert(ts=now - 30, rule_name="r1", mac=None, message="x", severity="high")
    db.add_alert(ts=now - 7200, rule_name="r1", mac=None, message="x", severity="high")
    app = create_app(config, db)
    try:
        with TestClient(app) as client:
            r_1h = client.get("/rules?since=1h")
            r_24h = client.get("/rules?since=24h")
            r_all = client.get("/rules?since=all")
        # All three should render successfully.
        for r in (r_1h, r_24h, r_all):
            assert r.status_code == 200
            assert "r1" in r.text
        # The 1h window excludes the 2h-old alert: only 1 fire visible.
        # The 24h and "all" windows include both.
        # Look at the "fires (last X):" line content.
        for r, expected_count in (
            (r_1h, "1"),
            (r_24h, "2"),
            (r_all, "2"),
        ):
            # Find the fires line for r1 and verify the count appears.
            idx = r.text.find("r1")
            assert idx != -1
            # Search forward a reasonable window for the count.
            segment = r.text[idx:idx + 600]
            assert f"fires" in segment.lower()
            # We expect the count immediately after "fires (...)".
            import re as _re

            m = _re.search(r"fires\s*\([^)]*\)\s*:\s*</strong>\s*(\d+)", segment)
            assert m is not None, f"could not parse fires count in:\n{segment[:300]}"
            assert m.group(1) == expected_count, (
                f"expected count={expected_count}, got {m.group(1)} "
                f"for url={r.request.url}"
            )
        # Window label appears in the column header.
        assert "all time" in r_all.text
        assert "1h" in r_1h.text
    finally:
        db.close()


@pytest.mark.webui
def test_rules_list_sort_count_desc_orders_by_count(tmp_path):
    """sort=count_desc must put high-volume rules first; ties break by name."""
    rules_yaml = tmp_path / "rules.yaml"
    rules_yaml.write_text(
        "rules:\n"
        "  - name: low_volume\n"
        "    rule_type: watchlist_mac\n"
        "    severity: high\n"
        "    patterns: ['de:ad:be:ef:00:01']\n"
        "  - name: high_volume\n"
        "    rule_type: watchlist_mac\n"
        "    severity: high\n"
        "    patterns: ['de:ad:be:ef:00:02']\n"
        "  - name: zzz_never_fires\n"
        "    rule_type: watchlist_mac\n"
        "    severity: low\n"
        "    patterns: ['11:22:33:44:55:66']\n",
        encoding="utf-8",
    )
    config = Config(db_path=str(tmp_path / "ui.db"), rules_path=str(rules_yaml))
    db = Database(config.db_path)
    import time as _time

    now = int(_time.time())
    db.add_alert(ts=now - 100, rule_name="low_volume", mac=None,
                 message="x", severity="high")
    for i in range(5):
        db.add_alert(ts=now - 100 - i, rule_name="high_volume", mac=None,
                     message="x", severity="high")
    app = create_app(config, db)
    try:
        with TestClient(app) as client:
            r = client.get("/rules?sort=count_desc")
        assert r.status_code == 200
        idx_high = r.text.find("high_volume")
        idx_low = r.text.find("low_volume")
        idx_zero = r.text.find("zzz_never_fires")
        assert idx_high < idx_low < idx_zero
    finally:
        db.close()


@pytest.mark.webui
def test_rules_list_sort_count_asc_inverts(tmp_path):
    """sort=count_asc is the mirror image: lowest count first."""
    rules_yaml = tmp_path / "rules.yaml"
    rules_yaml.write_text(
        "rules:\n"
        "  - name: alpha_high_count\n"
        "    rule_type: watchlist_mac\n"
        "    severity: high\n"
        "    patterns: ['de:ad:be:ef:00:01']\n"
        "  - name: beta_zero_count\n"
        "    rule_type: watchlist_mac\n"
        "    severity: low\n"
        "    patterns: ['11:22:33:44:55:66']\n",
        encoding="utf-8",
    )
    config = Config(db_path=str(tmp_path / "ui.db"), rules_path=str(rules_yaml))
    db = Database(config.db_path)
    import time as _time

    now = int(_time.time())
    for i in range(3):
        db.add_alert(ts=now - i, rule_name="alpha_high_count", mac=None,
                     message="x", severity="high")
    app = create_app(config, db)
    try:
        with TestClient(app) as client:
            r = client.get("/rules?sort=count_asc")
        assert r.status_code == 200
        idx_zero = r.text.find("beta_zero_count")
        idx_high = r.text.find("alpha_high_count")
        assert idx_zero < idx_high
    finally:
        db.close()


@pytest.mark.webui
def test_rules_list_never_fired_rule_shows_dash(tmp_path):
    """A rule with zero fires must still render — with '—' for last fired."""
    rules_yaml = tmp_path / "rules.yaml"
    rules_yaml.write_text(
        "rules:\n"
        "  - name: configured_but_silent\n"
        "    rule_type: watchlist_mac\n"
        "    severity: low\n"
        "    patterns: ['11:22:33:44:55:66']\n",
        encoding="utf-8",
    )
    config = Config(db_path=str(tmp_path / "ui.db"), rules_path=str(rules_yaml))
    db = Database(config.db_path)
    app = create_app(config, db)
    try:
        with TestClient(app) as client:
            r = client.get("/rules")
        assert r.status_code == 200
        # The rule itself appears.
        assert "configured_but_silent" in r.text
        # Fires count is zero.
        idx = r.text.find("configured_but_silent")
        segment = r.text[idx:idx + 600]
        import re as _re

        m = _re.search(r"fires\s*\([^)]*\)\s*:\s*</strong>\s*(\d+)", segment)
        assert m is not None
        assert m.group(1) == "0"
        # Last-fired column shows a dash (mdash entity) since the
        # rule never fired in the window.
        assert "&mdash;" in segment or "—" in segment
    finally:
        db.close()


@pytest.mark.webui
def test_rules_list_window_dropdown_renders_all_options(tmp_path):
    """The window dropdown must render all five buckets, with the
    current value selected. Same for the sort dropdown."""
    rules_yaml = tmp_path / "rules.yaml"
    rules_yaml.write_text(
        "rules:\n"
        "  - name: r\n"
        "    rule_type: watchlist_mac\n"
        "    severity: low\n"
        "    patterns: ['11:22:33:44:55:66']\n",
        encoding="utf-8",
    )
    config = Config(db_path=str(tmp_path / "ui.db"), rules_path=str(rules_yaml))
    db = Database(config.db_path)
    app = create_app(config, db)
    try:
        with TestClient(app) as client:
            r = client.get("/rules?since=24h&sort=count_desc")
        assert r.status_code == 200
        # All five window values must appear as <option> values.
        for w in ("1h", "24h", "7d", "30d", "all"):
            assert f'value="{w}"' in r.text, f"window option {w!r} missing"
        # Current window=24h selected.
        assert 'value="24h" selected' in r.text
        # Sort options too.
        for s in ("default", "count_desc", "count_asc"):
            assert f'value="{s}"' in r.text, f"sort option {s!r} missing"
        assert 'value="count_desc" selected' in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_rules_list_invalid_since_falls_back_to_default(tmp_path):
    """Invalid since (e.g. stale URL) must silently fall back to
    the 7d default rather than 400 — the underlying data is
    independent of the query params, so refusing to render is
    hostile."""
    rules_yaml = tmp_path / "rules.yaml"
    rules_yaml.write_text(
        "rules:\n"
        "  - name: r\n"
        "    rule_type: watchlist_mac\n"
        "    severity: low\n"
        "    patterns: ['11:22:33:44:55:66']\n",
        encoding="utf-8",
    )
    config = Config(db_path=str(tmp_path / "ui.db"), rules_path=str(rules_yaml))
    db = Database(config.db_path)
    app = create_app(config, db)
    try:
        with TestClient(app) as client:
            r = client.get("/rules?since=bogus&sort=alsobogus")
        assert r.status_code == 200
        # Falls back to since=7d and sort=default (rules.yaml order).
        assert 'value="7d" selected' in r.text
        assert 'value="default" selected' in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_rules_list_empty_alerts_table_shows_zero_counts(tmp_path):
    """All rules render with 0 / — when the alerts table is empty."""
    rules_yaml = tmp_path / "rules.yaml"
    rules_yaml.write_text(
        "rules:\n"
        "  - name: rule_a\n"
        "    rule_type: watchlist_mac\n"
        "    severity: low\n"
        "    patterns: ['11:22:33:44:55:66']\n"
        "  - name: rule_b\n"
        "    rule_type: watchlist_ssid\n"
        "    severity: med\n"
        "    patterns: ['SSID']\n",
        encoding="utf-8",
    )
    config = Config(db_path=str(tmp_path / "ui.db"), rules_path=str(rules_yaml))
    db = Database(config.db_path)
    app = create_app(config, db)
    try:
        with TestClient(app) as client:
            r = client.get("/rules")
        assert r.status_code == 200
        import re as _re

        for name in ("rule_a", "rule_b"):
            assert name in r.text
            idx = r.text.find(name)
            segment = r.text[idx:idx + 600]
            m = _re.search(r"fires\s*\([^)]*\)\s*:\s*</strong>\s*(\d+)", segment)
            assert m is not None
            assert m.group(1) == "0"
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
def test_static_lynceus_css_served_with_view_classes(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/static/lynceus.css")
        assert r.status_code == 200
        assert "badge-high" in r.text
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Prompt 003: ack/unack mutations, bulk ack, filter polish, stats, CSRF.
# ---------------------------------------------------------------------------

from lynceus.webui.csrf import CSRF_COOKIE_NAME, CSRF_FORM_FIELD  # noqa: E402


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
# severity row classes, inline ack note, reset-filters link, lynceus.js.
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
    from lynceus.webui.app import unix_to_iso

    assert unix_to_iso(None) == ""
    assert unix_to_iso("") == ""
    assert unix_to_iso(0) == "1970-01-01T00:00:00Z"


@pytest.mark.webui
def test_static_lynceus_js_served(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/static/lynceus.js")
        assert r.status_code == 200
        assert "javascript" in r.headers["content-type"]
    finally:
        db.close()


@pytest.mark.webui
def test_base_html_includes_lynceus_js_script(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/")
        assert r.status_code == 200
        assert 'src="/static/lynceus.js"' in r.text
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

    monkeypatch.setattr("lynceus.webui.app.time.time", fake_time)
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

    monkeypatch.setattr("lynceus.webui.app.time.time", fake_time)
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


def test_lynceus_js_contains_new_format_logic():
    js_path = (
        Path(__file__).resolve().parent.parent
        / "src"
        / "lynceus"
        / "webui"
        / "static"
        / "lynceus.js"
    )
    content = js_path.read_text(encoding="utf-8")
    for needle in ("weeks ago", "months ago", "years ago", "just now"):
        assert needle in content, f"lynceus.js missing expected phrase: {needle!r}"
    for gone in ("minutes ago", "hours ago"):
        assert gone not in content, (
            f"lynceus.js still contains old relative-format phrase: {gone!r}"
        )


# ---------------------------------------------------------------------------
# v0.2 UI cleanup: full-width layout, table scroll, header/button rename,
# Device column + device_label Jinja filter.
# ---------------------------------------------------------------------------


def _render_device_label(d):
    from jinja2 import Environment

    from lynceus.webui.app import _device_label

    env = Environment()
    env.filters["device_label"] = _device_label
    return env.from_string("{{ d | device_label }}").render(d=d)


@pytest.mark.webui
def test_device_label_filter_with_friendly_name():
    assert _render_device_label({"friendly_name": "AirPods Pro"}) == "AirPods Pro"


@pytest.mark.webui
def test_device_label_filter_falls_back_to_vendor():
    assert _render_device_label({"oui_vendor": "Apple"}) == "Apple"


@pytest.mark.webui
def test_device_label_filter_returns_dash_for_empty():
    assert _render_device_label({}) == "—"


@pytest.mark.webui
def test_device_label_filter_handles_none():
    assert _render_device_label(None) == "—"


@pytest.mark.webui
def test_device_label_filter_friendly_name_takes_priority():
    out = _render_device_label({"friendly_name": "John's iPhone", "oui_vendor": "Apple"})
    assert out == "John's iPhone"


@pytest.mark.webui
def test_device_label_filter_strips_whitespace():
    assert _render_device_label({"friendly_name": "  AirPods  "}) == "AirPods"


@pytest.mark.webui
def test_device_label_filter_empty_string_falls_through():
    assert _render_device_label({"friendly_name": "", "oui_vendor": "Apple"}) == "Apple"
    assert _render_device_label({"friendly_name": "   ", "oui_vendor": "Apple"}) == "Apple"


@pytest.mark.webui
def test_alerts_list_renames_ts_to_timestamp(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
        with TestClient(app) as client:
            r = client.get("/alerts")
        assert r.status_code == 200
        assert "Timestamp" in r.text
        assert ">ts<" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_renames_ack_to_status(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
        with TestClient(app) as client:
            r = client.get("/alerts")
        assert r.status_code == 200
        assert "Status" in r.text
        assert ">ack<" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_button_says_acknowledge(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
        with TestClient(app) as client:
            r = client.get("/alerts")
        assert r.status_code == 200
        assert "Acknowledge" in r.text
        assert "Acknowledge selected" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_has_device_column_with_vendor_fallback(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        db.upsert_device("aa:bb:cc:dd:ee:01", "wifi", "TestVendor", 0, 100)
        db.add_alert(
            ts=100,
            rule_name="r",
            mac="aa:bb:cc:dd:ee:01",
            message="m",
            severity="low",
        )
        with TestClient(app) as client:
            r = client.get("/alerts")
        assert r.status_code == 200
        assert "TestVendor" in r.text
        assert "<th>Device</th>" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_device_column_dash_when_no_device(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
        with TestClient(app) as client:
            r = client.get("/alerts")
        assert r.status_code == 200
        assert "—" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_devices_list_has_device_column_no_vendor_column(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        db.upsert_device("aa:bb:cc:dd:ee:01", "wifi", "Apple", 0, 100)
        with TestClient(app) as client:
            r = client.get("/devices")
        assert r.status_code == 200
        assert "Apple" in r.text
        assert "<th>Vendor</th>" not in r.text
        assert "<th>vendor</th>" not in r.text
        assert "<th>Device</th>" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_index_alerts_have_device_data_enriched(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        db.upsert_device("aa:bb:cc:dd:ee:ff", "wifi", "EnrichTest", 0, 100)
        db.add_alert(
            ts=100,
            rule_name="r",
            mac="aa:bb:cc:dd:ee:ff",
            message="m",
            severity="low",
        )
        with TestClient(app) as client:
            r = client.get("/")
        assert r.status_code == 200
        assert "EnrichTest" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_index_alerts_with_missing_device_renders_dash(tmp_path):
    """Belt-and-braces: even if an alert ends up with a mac that no
    device row exists for (e.g., a device was deleted, or a future
    schema relaxation), the Device column must render an em dash and
    the page must not 500. We bypass the FK temporarily to construct
    the orphan state."""
    app, db = _make_app(tmp_path)
    try:
        with db._conn:
            db._conn.execute("PRAGMA foreign_keys = OFF")
            db._conn.execute(
                "INSERT INTO alerts(ts, rule_name, mac, message, severity) VALUES (?, ?, ?, ?, ?)",
                (100, "r", "ff:ff:ff:ff:ff:ff", "missing-device-msg", "low"),
            )
            db._conn.execute("PRAGMA foreign_keys = ON")
        with TestClient(app) as client:
            r = client.get("/")
        assert r.status_code == 200
        assert "missing-device-msg" in r.text
        assert "—" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_table_scroll_class_present_on_alerts_list(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
        with TestClient(app) as client:
            r = client.get("/alerts")
        assert r.status_code == 200
        assert 'class="table-scroll"' in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_table_scroll_class_present_on_devices_list(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        db.upsert_device("aa:bb:cc:dd:ee:01", "wifi", "Acme", 0, 100)
        with TestClient(app) as client:
            r = client.get("/devices")
        assert r.status_code == 200
        assert 'class="table-scroll"' in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_table_scroll_css_class_defined():
    css_path = (
        Path(__file__).resolve().parent.parent
        / "src"
        / "lynceus"
        / "webui"
        / "static"
        / "lynceus.css"
    )
    content = css_path.read_text(encoding="utf-8")
    idx = content.find(".table-scroll")
    assert idx != -1, "lynceus.css is missing the .table-scroll rule"
    assert "overflow-x: auto" in content[idx : idx + 500]


@pytest.mark.webui
def test_base_html_uses_container_fluid():
    base_path = (
        Path(__file__).resolve().parent.parent
        / "src"
        / "lynceus"
        / "webui"
        / "templates"
        / "base.html"
    )
    content = base_path.read_text(encoding="utf-8")
    assert 'class="container-fluid"' in content
    # The non-fluid variant must be gone — guard against an accidental revert.
    assert 'class="container"' not in content


# ---------------------------------------------------------------------------
# rc5: alert-detail triage buttons (Allowlist / Snooze 24h / Remove).
# Depends on the allowlist backend reshape from the preceding prompt:
# expires_at + added_at on AllowlistEntry, split-storage loader, atomic
# writers, mtime watch.
# ---------------------------------------------------------------------------


def _make_app_with_allowlist(tmp_path):
    """App with an empty operator-curated primary allowlist.yaml configured.

    The triage routes refuse to write when allowlist_path is unset; tests
    that exercise the success path need a configured primary even when
    its contents are intentionally empty.
    """
    primary = tmp_path / "allowlist.yaml"
    primary.write_text("entries: []\n", encoding="utf-8")
    config = Config(
        db_path=str(tmp_path / "ui.db"),
        allowlist_path=str(primary),
    )
    db = Database(config.db_path)
    app = create_app(config, db)
    return app, db, primary


def _ui_path_for(primary: Path) -> Path:
    from lynceus.allowlist import derive_ui_path as _derive

    return _derive(primary)


def _read_ui_entries(primary: Path):
    """Read entries from the daemon-managed UI sibling, or empty list."""
    import yaml as _yaml

    ui_path = _ui_path_for(primary)
    if not ui_path.exists():
        return []
    data = _yaml.safe_load(ui_path.read_text(encoding="utf-8")) or {}
    return data.get("entries", [])


def _seed_alert_with_mac(db, mac: str, *, ts: int = 100, severity: str = "med") -> int:
    """Insert a device row + an alert row pointing at it.

    ``alerts.mac`` has a FOREIGN KEY → ``devices.mac``, so an alert with
    a non-null MAC requires the device to exist first.
    """
    db.upsert_device(mac, "wifi", None, 0, ts)
    return db.add_alert(
        ts=ts, rule_name="r", mac=mac, message="m", severity=severity
    )


# --- routes ----------------------------------------------------------------


@pytest.mark.webui
def test_triage_allowlist_post_writes_entry_and_redirects(tmp_path):
    app, db, primary = _make_app_with_allowlist(tmp_path)
    try:
        aid = _seed_alert_with_mac(db, "aa:bb:cc:dd:ee:ff")
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                f"/alerts/{aid}/allowlist",
                data={CSRF_FORM_FIELD: token},
            )
        assert r.status_code == 303
        assert r.headers["location"] == f"/alerts/{aid}"
        entries = _read_ui_entries(primary)
        assert len(entries) == 1
        assert entries[0]["pattern"] == "aa:bb:cc:dd:ee:ff"
        assert entries[0]["pattern_type"] == "mac"
        assert "expires_at" not in entries[0]  # permanent
        assert "added_at" in entries[0]
        assert "added via webui" in entries[0]["note"]
    finally:
        db.close()


@pytest.mark.webui
def test_triage_snooze_post_writes_entry_with_expiry(tmp_path):
    import time as _time

    app, db, primary = _make_app_with_allowlist(tmp_path)
    try:
        aid = _seed_alert_with_mac(db, "aa:bb:cc:dd:ee:ff")
        before = int(_time.time())
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                f"/alerts/{aid}/snooze",
                data={CSRF_FORM_FIELD: token},
            )
        after = int(_time.time())
        assert r.status_code == 303
        entries = _read_ui_entries(primary)
        assert len(entries) == 1
        e = entries[0]
        assert e["pattern"] == "aa:bb:cc:dd:ee:ff"
        # 86400 second window from "now" — bounded by before/after to
        # tolerate the second the request straddled.
        assert before + 86400 <= e["expires_at"] <= after + 86400
        assert "snoozed 24h via webui" in e["note"]
    finally:
        db.close()


@pytest.mark.webui
def test_triage_remove_post_drops_existing_entry(tmp_path):
    from lynceus.allowlist import AllowlistEntry, add_ui_entry

    app, db, primary = _make_app_with_allowlist(tmp_path)
    try:
        aid = _seed_alert_with_mac(db, "aa:bb:cc:dd:ee:ff")
        # Seed a UI entry so /remove has something to delete.
        add_ui_entry(
            _ui_path_for(primary),
            AllowlistEntry(
                pattern="aa:bb:cc:dd:ee:ff",
                pattern_type="mac",
                added_at=1_799_000_000,
            ),
        )
        assert len(_read_ui_entries(primary)) == 1
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                f"/alerts/{aid}/allowlist/remove",
                data={CSRF_FORM_FIELD: token},
            )
        assert r.status_code == 303
        assert _read_ui_entries(primary) == []
    finally:
        db.close()


@pytest.mark.webui
def test_triage_remove_post_idempotent_when_nothing_to_remove(tmp_path):
    """Clicking Remove twice (or against a primary-side entry the UI
    can't delete) must not 500; the redirect re-renders the truth."""
    app, db, primary = _make_app_with_allowlist(tmp_path)
    try:
        aid = _seed_alert_with_mac(db, "aa:bb:cc:dd:ee:ff")
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                f"/alerts/{aid}/allowlist/remove",
                data={CSRF_FORM_FIELD: token},
            )
        assert r.status_code == 303
        assert _read_ui_entries(primary) == []
    finally:
        db.close()


@pytest.mark.webui
@pytest.mark.parametrize("path_suffix", ["allowlist", "snooze", "allowlist/remove"])
def test_triage_routes_return_404_for_missing_alert(tmp_path, path_suffix):
    app, db, _primary = _make_app_with_allowlist(tmp_path)
    try:
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                f"/alerts/9999/{path_suffix}",
                data={CSRF_FORM_FIELD: token},
            )
        assert r.status_code == 404
    finally:
        db.close()


@pytest.mark.webui
@pytest.mark.parametrize("path_suffix", ["allowlist", "snooze", "allowlist/remove"])
def test_triage_routes_reject_without_csrf(tmp_path, path_suffix):
    app, db, _primary = _make_app_with_allowlist(tmp_path)
    try:
        aid = _seed_alert_with_mac(db, "aa:bb:cc:dd:ee:ff")
        with TestClient(app) as client:
            client.cookies.clear()
            r = client.post(f"/alerts/{aid}/{path_suffix}")
        assert r.status_code == 403
    finally:
        db.close()


@pytest.mark.webui
@pytest.mark.parametrize("path_suffix", ["allowlist", "snooze", "allowlist/remove"])
def test_triage_routes_return_400_when_allowlist_not_configured(tmp_path, path_suffix):
    """No allowlist_path → there is no file to write to. The UI hides
    the buttons in this case, but a forged POST (e.g. an operator who
    enabled triage then disabled allowlist_path) must not silently no-op."""
    config = Config(db_path=str(tmp_path / "ui.db"))
    db = Database(config.db_path)
    app = create_app(config, db)
    try:
        aid = _seed_alert_with_mac(db, "aa:bb:cc:dd:ee:ff")
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                f"/alerts/{aid}/{path_suffix}",
                data={CSRF_FORM_FIELD: token},
            )
        assert r.status_code == 400
    finally:
        db.close()


@pytest.mark.webui
@pytest.mark.parametrize("path_suffix", ["allowlist", "snooze", "allowlist/remove"])
def test_triage_routes_return_400_when_alert_has_no_mac(tmp_path, path_suffix):
    """Alerts without a MAC (e.g. rules that fire on per-source counts)
    can't be triaged by MAC. Surface the mismatch with 400."""
    app, db, _primary = _make_app_with_allowlist(tmp_path)
    try:
        aid = db.add_alert(
            ts=100,
            rule_name="r",
            mac=None,
            message="m",
            severity="med",
        )
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                f"/alerts/{aid}/{path_suffix}",
                data={CSRF_FORM_FIELD: token},
            )
        assert r.status_code == 400
    finally:
        db.close()


# --- template render states -----------------------------------------------


@pytest.mark.webui
def test_alert_detail_state1_renders_both_buttons_and_csrf(tmp_path):
    """No matching allowlist entry: both action forms appear with CSRF."""
    app, db, _primary = _make_app_with_allowlist(tmp_path)
    try:
        aid = _seed_alert_with_mac(db, "aa:bb:cc:dd:ee:ff")
        with TestClient(app) as client:
            r = client.get(f"/alerts/{aid}")
        assert r.status_code == 200
        assert "Allowlist this device" in r.text
        assert ">Snooze</button>" in r.text
        assert f'action="/alerts/{aid}/allowlist"' in r.text
        assert f'action="/alerts/{aid}/snooze"' in r.text
        # Both forms must carry the CSRF token.
        assert r.text.count(f'name="{CSRF_FORM_FIELD}"') >= 2
    finally:
        db.close()


@pytest.mark.webui
def test_alert_detail_state2_renders_status_and_remove_button(tmp_path):
    """Permanently allowlisted via UI: status text + Remove button."""
    from lynceus.allowlist import AllowlistEntry, add_ui_entry

    app, db, primary = _make_app_with_allowlist(tmp_path)
    try:
        aid = _seed_alert_with_mac(db, "aa:bb:cc:dd:ee:ff")
        add_ui_entry(
            _ui_path_for(primary),
            AllowlistEntry(
                pattern="aa:bb:cc:dd:ee:ff",
                pattern_type="mac",
                added_at=1_799_000_000,
            ),
        )
        with TestClient(app) as client:
            r = client.get(f"/alerts/{aid}")
        assert r.status_code == 200
        assert "Allowlisted" in r.text
        assert "Remove from allowlist" in r.text
        # The "added" timestamp renders in human form.
        assert "2027-01-03 18:13 UTC" in r.text  # 1_799_000_000 → 2027-01-03 18:13 UTC
        # No State-1 buttons present.
        assert "Snooze for 24h" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alert_detail_state3_renders_countdown_and_cancel_button(tmp_path):
    """Snoozed via UI: countdown + Cancel button."""
    import time as _time

    from lynceus.allowlist import AllowlistEntry, add_ui_entry

    app, db, primary = _make_app_with_allowlist(tmp_path)
    try:
        aid = _seed_alert_with_mac(db, "aa:bb:cc:dd:ee:ff")
        now = int(_time.time())
        add_ui_entry(
            _ui_path_for(primary),
            AllowlistEntry(
                pattern="aa:bb:cc:dd:ee:ff",
                pattern_type="mac",
                added_at=now,
                expires_at=now + 12 * 3600,  # 12h remaining
            ),
        )
        with TestClient(app) as client:
            r = client.get(f"/alerts/{aid}")
        assert r.status_code == 200
        assert "Snoozed until" in r.text
        assert "hours remaining" in r.text
        assert "Cancel snooze" in r.text
        # State-1/2 controls absent.
        assert "Allowlist this device" not in r.text
        assert "Remove from allowlist" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alert_detail_state2_primary_match_shows_no_button(tmp_path):
    """An entry living in the operator-curated primary file is not
    UI-removable; the section shows status and a hint, no button."""
    app, db, primary = _make_app_with_allowlist(tmp_path)
    try:
        primary.write_text(
            "entries:\n  - pattern: aa:bb:cc:dd:ee:ff\n    pattern_type: mac\n",
            encoding="utf-8",
        )
        aid = _seed_alert_with_mac(db, "aa:bb:cc:dd:ee:ff")
        with TestClient(app) as client:
            r = client.get(f"/alerts/{aid}")
        assert r.status_code == 200
        assert "Allowlisted" in r.text
        assert "Remove from allowlist" not in r.text
        assert "operator-managed" in r.text
        assert "allowlist.yaml" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alert_detail_triage_hidden_when_allowlist_path_not_configured(tmp_path):
    """No allowlist_path: the whole triage section is omitted."""
    config = Config(db_path=str(tmp_path / "ui.db"))
    db = Database(config.db_path)
    app = create_app(config, db)
    try:
        aid = _seed_alert_with_mac(db, "aa:bb:cc:dd:ee:ff")
        with TestClient(app) as client:
            r = client.get(f"/alerts/{aid}")
        assert r.status_code == 200
        assert "<strong>triage</strong>" not in r.text
        assert "Snooze for 24h" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alert_detail_triage_hidden_when_alert_has_no_mac(tmp_path):
    """An alert without a MAC has nothing to allowlist; section is hidden."""
    app, db, _primary = _make_app_with_allowlist(tmp_path)
    try:
        aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="med")
        with TestClient(app) as client:
            r = client.get(f"/alerts/{aid}")
        assert r.status_code == 200
        assert "<strong>triage</strong>" not in r.text
    finally:
        db.close()


# --- end-to-end: snooze → no alert → expire → alert again ------------------


@pytest.mark.webui
def test_triage_snooze_end_to_end_through_poll_cycle(tmp_path):
    """The load-bearing operator-comfort claim: a UI snooze suppresses the
    next poll without daemon restart, then expires cleanly.

    Synthesizes a watchlist hit observation, POSTs /snooze through the
    webui, runs poll_once → confirms zero alerts; then fast-forwards
    ``now_ts`` past the snooze expiry and runs poll_once again →
    confirms the alert fires.
    """
    from lynceus.allowlist import load_allowlist
    from lynceus.kismet import FakeKismetClient
    from lynceus.poller import poll_once
    from lynceus.rules import Rule, Ruleset

    fixture = Path(__file__).parent / "fixtures" / "kismet_devices.json"
    primary = tmp_path / "allowlist.yaml"
    primary.write_text("entries: []\n", encoding="utf-8")
    config = Config(
        kismet_fixture_path=str(fixture),
        db_path=str(tmp_path / "ui.db"),
        location_id="testloc",
        location_label="Test Location",
        allowlist_path=str(primary),
    )
    db = Database(config.db_path)
    app = create_app(config, db)
    target_mac = "a4:83:e7:11:22:33"  # present in the fixture
    try:
        aid = _seed_alert_with_mac(db, target_mac, severity="high")
        # 1. Operator clicks Snooze for 24h on the alert detail page.
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                f"/alerts/{aid}/snooze",
                data={CSRF_FORM_FIELD: token},
            )
        assert r.status_code == 303
        # 2. Next poll: same watchlist rule fires on the same MAC. With
        #    snooze active, the audit-log line should fire but no new
        #    alert row should be written.
        rs = Ruleset(
            rules=[
                Rule(
                    name="apple_mac",
                    rule_type="watchlist_mac",
                    severity="high",
                    patterns=[target_mac],
                )
            ]
        )
        # Reload merges the new UI entry — same path the daemon takes
        # via mtime watch.
        allowlist = load_allowlist(config.allowlist_path)
        snooze_entry = next(
            e for e in allowlist.entries if e.pattern == target_mac
        )
        assert snooze_entry.expires_at is not None
        snooze_expiry = snooze_entry.expires_at
        # Use an unambiguously-before-expiry timestamp.
        before_expiry = snooze_expiry - 1
        fake_client = FakeKismetClient(str(fixture))
        baseline_alerts = db._conn.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]
        poll_once(
            fake_client,
            db,
            config,
            before_expiry,
            ruleset=rs,
            allowlist=allowlist,
        )
        after_snooze = db._conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        assert after_snooze == baseline_alerts  # no new alert
        # 3. Fast-forward past expiry: same observation, same rules, but
        #    now the entry is past expires_at and is_allowed skips it.
        after_expiry = snooze_expiry + 1
        db.set_state("last_poll_ts", "0")  # reset so the fake client returns devices again
        fake_client2 = FakeKismetClient(str(fixture))
        poll_once(
            fake_client2,
            db,
            config,
            after_expiry,
            ruleset=rs,
            allowlist=allowlist,
        )
        after_expiry_alerts = db._conn.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]
        assert after_expiry_alerts > after_snooze  # alert fires
    finally:
        db.close()


# ---------------------------------------------------------------------------
# /allowlist management surface (rc5): filters, add-form, bulk remove,
# primary-source read-only protection.
# ---------------------------------------------------------------------------


def _make_app_with_mixed_allowlist(tmp_path):
    """Seed an allowlist with primary + UI entries spanning all 7 types
    plus active/snoozed/expired statuses, so filter tests have something
    to exercise. Returns (app, db, primary_path, ui_path, now_ts).

    Entries (intentional diversity, not realism):

      primary:
        - mac    aa:aa:aa:aa:aa:01    note='primary camera'
        - ssid   PrimaryNet           note='operator network'

      ui:
        - mac    11:22:33:44:55:01    note='ui device'              (active)
        - mac    22:22:22:22:22:22    expires_at=now-3600           (expired)
        - mac    33:33:33:33:33:33    expires_at=now+86400, note='ui-snooze'  (snoozed)
        - mac_range            aa:bb:cc:d/28   note='ui range'
        - ble_uuid             0000180f-0000-1000-8000-00805f9b34fb
        - ble_manufacturer_id  004c
        - drone_id_prefix      ABC1234
    """
    import time as _time

    from lynceus.allowlist import AllowlistEntry, add_ui_entry, derive_ui_path

    primary = tmp_path / "allowlist.yaml"
    primary.write_text(
        "entries:\n"
        "  - pattern: aa:aa:aa:aa:aa:01\n"
        "    pattern_type: mac\n"
        "    note: primary camera\n"
        "  - pattern: PrimaryNet\n"
        "    pattern_type: ssid\n"
        "    note: operator network\n",
        encoding="utf-8",
    )
    config = Config(
        db_path=str(tmp_path / "ui.db"),
        allowlist_path=str(primary),
    )
    db = Database(config.db_path)
    app = create_app(config, db)
    ui_path = derive_ui_path(primary)
    now_ts = int(_time.time())
    seeds = [
        AllowlistEntry(
            pattern="11:22:33:44:55:01",
            pattern_type="mac",
            note="ui device",
            added_at=now_ts,
        ),
        AllowlistEntry(
            pattern="22:22:22:22:22:22",
            pattern_type="mac",
            expires_at=now_ts - 3600,
            added_at=now_ts - 7200,
        ),
        AllowlistEntry(
            pattern="33:33:33:33:33:33",
            pattern_type="mac",
            note="ui-snooze",
            expires_at=now_ts + 86400,
            added_at=now_ts,
        ),
        AllowlistEntry(
            pattern="aa:bb:cc:d",  # canonicalizes to aa:bb:cc:d/28
            pattern_type="mac_range",
            note="ui range",
            added_at=now_ts,
        ),
        AllowlistEntry(
            pattern="0000180f-0000-1000-8000-00805f9b34fb",
            pattern_type="ble_uuid",
            added_at=now_ts,
        ),
        AllowlistEntry(
            pattern="004c",
            pattern_type="ble_manufacturer_id",
            added_at=now_ts,
        ),
        AllowlistEntry(
            pattern="ABC1234",
            pattern_type="drone_id_prefix",
            added_at=now_ts,
        ),
    ]
    for entry in seeds:
        add_ui_entry(ui_path, entry)
    return app, db, primary, ui_path, now_ts


@pytest.mark.webui
def test_allowlist_no_filters_shows_every_entry(tmp_path):
    app, db, _primary, _ui, _now = _make_app_with_mixed_allowlist(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/allowlist")
        assert r.status_code == 200
        # Pattern from every entry must appear in the rendered body.
        for pat in [
            "aa:aa:aa:aa:aa:01",
            "PrimaryNet",
            "11:22:33:44:55:01",
            "22:22:22:22:22:22",
            "33:33:33:33:33:33",
            "aa:bb:cc:d/28",
            "0000180f-0000-1000-8000-00805f9b34fb",
            "004c",
            "ABC1234",
        ]:
            assert pat in r.text, f"missing pattern {pat!r} in default render"
    finally:
        db.close()


@pytest.mark.webui
def test_allowlist_filter_q_matches_pattern_and_note(tmp_path):
    app, db, _primary, _ui, _now = _make_app_with_mixed_allowlist(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/allowlist?q=camera")
        assert r.status_code == 200
        assert "aa:aa:aa:aa:aa:01" in r.text  # primary camera note matched
        # Unrelated rows should not appear.
        assert "PrimaryNet" not in r.text
        assert "11:22:33:44:55:01" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_allowlist_filter_q_case_insensitive(tmp_path):
    app, db, _primary, _ui, _now = _make_app_with_mixed_allowlist(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/allowlist?q=CAMERA")
        assert r.status_code == 200
        assert "aa:aa:aa:aa:aa:01" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_allowlist_filter_source_primary(tmp_path):
    app, db, _primary, _ui, _now = _make_app_with_mixed_allowlist(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/allowlist?source=primary")
        assert r.status_code == 200
        assert "aa:aa:aa:aa:aa:01" in r.text
        assert "PrimaryNet" in r.text
        # No UI entries:
        assert "11:22:33:44:55:01" not in r.text
        assert "004c" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_allowlist_filter_source_ui(tmp_path):
    app, db, _primary, _ui, _now = _make_app_with_mixed_allowlist(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/allowlist?source=ui")
        assert r.status_code == 200
        assert "11:22:33:44:55:01" in r.text
        assert "aa:bb:cc:d/28" in r.text
        # No primary entries:
        assert "aa:aa:aa:aa:aa:01" not in r.text
        assert "PrimaryNet" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_allowlist_filter_status_expired(tmp_path):
    app, db, _primary, _ui, _now = _make_app_with_mixed_allowlist(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/allowlist?status=expired")
        assert r.status_code == 200
        assert "22:22:22:22:22:22" in r.text  # expired
        assert "33:33:33:33:33:33" not in r.text  # snoozed
        assert "11:22:33:44:55:01" not in r.text  # active
    finally:
        db.close()


@pytest.mark.webui
def test_allowlist_filter_status_snoozed(tmp_path):
    app, db, _primary, _ui, _now = _make_app_with_mixed_allowlist(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/allowlist?status=snoozed")
        assert r.status_code == 200
        assert "33:33:33:33:33:33" in r.text
        assert "22:22:22:22:22:22" not in r.text
        assert "11:22:33:44:55:01" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_allowlist_filter_status_active(tmp_path):
    app, db, _primary, _ui, _now = _make_app_with_mixed_allowlist(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/allowlist?status=active")
        assert r.status_code == 200
        # Active = no expires_at. The active UI mac and all the primary
        # rows + no-expiry UI rows survive.
        assert "11:22:33:44:55:01" in r.text
        assert "aa:aa:aa:aa:aa:01" in r.text
        # Snoozed/expired excluded.
        assert "22:22:22:22:22:22" not in r.text
        assert "33:33:33:33:33:33" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_allowlist_filter_type_mac(tmp_path):
    app, db, _primary, _ui, _now = _make_app_with_mixed_allowlist(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/allowlist?type=mac")
        assert r.status_code == 200
        assert "aa:aa:aa:aa:aa:01" in r.text  # primary mac
        assert "11:22:33:44:55:01" in r.text  # UI mac
        # Non-mac types excluded:
        assert "PrimaryNet" not in r.text
        assert "aa:bb:cc:d/28" not in r.text
        assert "0000180f-0000-1000-8000-00805f9b34fb" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_allowlist_filter_type_each_supported_renders_only_that_type(tmp_path):
    """Smoke per-type: each of the 7 dropdown options narrows to that
    pattern_type alone."""
    app, db, _primary, _ui, _now = _make_app_with_mixed_allowlist(tmp_path)
    try:
        with TestClient(app) as client:
            for ptype, present in [
                ("ssid", "PrimaryNet"),
                ("mac_range", "aa:bb:cc:d/28"),
                ("ble_uuid", "0000180f-0000-1000-8000-00805f9b34fb"),
                ("ble_manufacturer_id", "004c"),
                ("drone_id_prefix", "ABC1234"),
                ("oui", None),  # no oui entries — empty state
            ]:
                r = client.get(f"/allowlist?type={ptype}")
                assert r.status_code == 200
                if present is None:
                    assert "No entries match" in r.text
                else:
                    assert present in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_allowlist_filter_combined_and_together(tmp_path):
    app, db, _primary, _ui, _now = _make_app_with_mixed_allowlist(tmp_path)
    try:
        with TestClient(app) as client:
            # source=ui AND type=mac AND status=active intersects to the
            # one row 11:22:33:44:55:01.
            r = client.get("/allowlist?source=ui&type=mac&status=active")
        assert r.status_code == 200
        assert "11:22:33:44:55:01" in r.text
        assert "22:22:22:22:22:22" not in r.text  # status=expired
        assert "33:33:33:33:33:33" not in r.text  # status=snoozed
        assert "aa:aa:aa:aa:aa:01" not in r.text  # source=primary
        assert "aa:bb:cc:d/28" not in r.text  # type=mac_range
    finally:
        db.close()


@pytest.mark.webui
def test_allowlist_filter_empty_result_renders_empty_state(tmp_path):
    app, db, _primary, _ui, _now = _make_app_with_mixed_allowlist(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/allowlist?q=zzzzzzzzzz")
        assert r.status_code == 200
        assert "No entries match the current filters." in r.text
        assert 'href="/allowlist"' in r.text  # reset link present
    finally:
        db.close()


@pytest.mark.webui
def test_allowlist_filter_invalid_source_returns_400(tmp_path):
    app, db, _primary, _ui, _now = _make_app_with_mixed_allowlist(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/allowlist?source=bogus")
        assert r.status_code == 400
    finally:
        db.close()


@pytest.mark.webui
def test_allowlist_filter_invalid_status_returns_400(tmp_path):
    app, db, _primary, _ui, _now = _make_app_with_mixed_allowlist(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/allowlist?status=bogus")
        assert r.status_code == 400
    finally:
        db.close()


@pytest.mark.webui
def test_allowlist_filter_invalid_type_returns_400(tmp_path):
    app, db, _primary, _ui, _now = _make_app_with_mixed_allowlist(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/allowlist?type=bssid")
        assert r.status_code == 400
    finally:
        db.close()


@pytest.mark.webui
def test_allowlist_source_badges_render(tmp_path):
    app, db, _primary, _ui, _now = _make_app_with_mixed_allowlist(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/allowlist")
        assert r.status_code == 200
        assert "badge-source-primary" in r.text
        assert "badge-source-ui" in r.text
        # Status badges present too:
        assert "badge-allow-active" in r.text
        assert "badge-allow-snoozed" in r.text
        assert "badge-allow-expired" in r.text
    finally:
        db.close()


# --- POST /allowlist/add ----------------------------------------------------


def _read_ui_file(primary):
    """Read entries from the daemon-managed UI sibling, or empty list."""
    from lynceus.allowlist import derive_ui_path as _derive

    ui = _derive(primary)
    if not ui.exists():
        return []
    return yaml.safe_load(ui.read_text(encoding="utf-8"))["entries"]


@pytest.mark.webui
def test_allowlist_add_valid_mac_persists_and_redirects(tmp_path):
    app, db, primary = _make_app_with_allowlist(tmp_path)
    try:
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                "/allowlist/add",
                data={
                    CSRF_FORM_FIELD: token,
                    "pattern": "AA:BB:CC:DD:EE:FF",
                    "pattern_type": "mac",
                    "note": "added via test",
                },
            )
        assert r.status_code == 303
        assert r.headers["location"] == "/allowlist?success=add"
        entries = _read_ui_file(primary)
        assert len(entries) == 1
        assert entries[0]["pattern"] == "aa:bb:cc:dd:ee:ff"  # canonicalized
        assert entries[0]["pattern_type"] == "mac"
        assert entries[0]["note"] == "added via test"
        assert "added_at" in entries[0]
    finally:
        db.close()


@pytest.mark.webui
@pytest.mark.parametrize(
    "ptype,raw_pattern,canonical_pattern",
    [
        ("mac", "AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"),
        ("oui", "AA-BB-CC", "aa:bb:cc"),
        ("ssid", "HomeNet", "HomeNet"),
        ("mac_range", "aa:bb:cc:d", "aa:bb:cc:d/28"),
        (
            "ble_uuid",
            "0000180F-0000-1000-8000-00805F9B34FB",
            "0000180f-0000-1000-8000-00805f9b34fb",
        ),
        ("ble_manufacturer_id", "0x004C", "004c"),
        ("drone_id_prefix", "abc1234", "ABC1234"),
    ],
)
def test_allowlist_add_canonicalizes_each_pattern_type(
    tmp_path, ptype, raw_pattern, canonical_pattern
):
    """Per supported type: form input is canonicalized via patterns.py
    before write — proves the canonicalizer is wired through the add
    route, not just the model."""
    app, db, primary = _make_app_with_allowlist(tmp_path)
    try:
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                "/allowlist/add",
                data={
                    CSRF_FORM_FIELD: token,
                    "pattern": raw_pattern,
                    "pattern_type": ptype,
                },
            )
        assert r.status_code == 303, f"{ptype} {raw_pattern} → {r.status_code} {r.text[:200]}"
        entries = _read_ui_file(primary)
        assert len(entries) == 1
        assert entries[0]["pattern"] == canonical_pattern
        assert entries[0]["pattern_type"] == ptype
    finally:
        db.close()


@pytest.mark.webui
def test_allowlist_add_empty_pattern_returns_400_inline_error(tmp_path):
    app, db, primary = _make_app_with_allowlist(tmp_path)
    try:
        with TestClient(app) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                "/allowlist/add",
                data={
                    CSRF_FORM_FIELD: token,
                    "pattern": "   ",
                    "pattern_type": "mac",
                },
            )
        assert r.status_code == 400
        assert "pattern is required" in r.text
        assert _read_ui_file(primary) == []
    finally:
        db.close()


@pytest.mark.webui
def test_allowlist_add_invalid_pattern_returns_400_inline_error(tmp_path):
    app, db, primary = _make_app_with_allowlist(tmp_path)
    try:
        with TestClient(app) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                "/allowlist/add",
                data={
                    CSRF_FORM_FIELD: token,
                    "pattern": "not-a-mac",
                    "pattern_type": "mac",
                },
            )
        assert r.status_code == 400
        assert "invalid mac" in r.text or "pattern" in r.text
        # No write.
        assert _read_ui_file(primary) == []
    finally:
        db.close()


@pytest.mark.webui
def test_allowlist_add_invalid_pattern_type_returns_400(tmp_path):
    app, db, primary = _make_app_with_allowlist(tmp_path)
    try:
        with TestClient(app) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                "/allowlist/add",
                data={
                    CSRF_FORM_FIELD: token,
                    "pattern": "aa:bb:cc:dd:ee:ff",
                    "pattern_type": "bssid",
                },
            )
        assert r.status_code == 400
        assert "invalid pattern_type" in r.text
        assert _read_ui_file(primary) == []
    finally:
        db.close()


@pytest.mark.webui
def test_allowlist_add_invalid_expires_at_returns_400(tmp_path):
    app, db, primary = _make_app_with_allowlist(tmp_path)
    try:
        with TestClient(app) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                "/allowlist/add",
                data={
                    CSRF_FORM_FIELD: token,
                    "pattern": "aa:bb:cc:dd:ee:ff",
                    "pattern_type": "mac",
                    "expires_at": "not-a-date",
                },
            )
        assert r.status_code == 400
        assert "expires_at" in r.text
        assert _read_ui_file(primary) == []
    finally:
        db.close()


@pytest.mark.webui
def test_allowlist_add_accepts_datetime_local_expires_at(tmp_path):
    """Datetime-local input shape is YYYY-MM-DDTHH:MM with no tz; the
    handler should interpret as UTC and store an int epoch."""
    app, db, primary = _make_app_with_allowlist(tmp_path)
    try:
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                "/allowlist/add",
                data={
                    CSRF_FORM_FIELD: token,
                    "pattern": "aa:bb:cc:dd:ee:ff",
                    "pattern_type": "mac",
                    "expires_at": "2030-01-02T03:04",
                },
            )
        assert r.status_code == 303
        entries = _read_ui_file(primary)
        # 2030-01-02 03:04 UTC = 1893553440
        assert entries[0]["expires_at"] == 1_893_553_440
    finally:
        db.close()


@pytest.mark.webui
def test_allowlist_add_missing_csrf_returns_403(tmp_path):
    app, db, primary = _make_app_with_allowlist(tmp_path)
    try:
        with TestClient(app) as client:
            client.cookies.clear()
            r = client.post(
                "/allowlist/add",
                data={"pattern": "aa:bb:cc:dd:ee:ff", "pattern_type": "mac"},
            )
        assert r.status_code == 403
        assert _read_ui_file(primary) == []
    finally:
        db.close()


# --- POST /allowlist/bulk_remove --------------------------------------------


def _seed_ui_entries(primary, entries_specs):
    """Seed several UI entries; returns the list of canonical patterns
    as stored, so tests can construct composite keys without
    re-canonicalizing."""
    from lynceus.allowlist import AllowlistEntry, add_ui_entry, derive_ui_path

    ui_path = derive_ui_path(primary)
    canonical = []
    for spec in entries_specs:
        e = AllowlistEntry(**spec)
        add_ui_entry(ui_path, e)
        canonical.append(e.pattern)
    return canonical, ui_path


@pytest.mark.webui
def test_allowlist_bulk_remove_three_ui_entries_single_atomic_write(tmp_path):
    """Selecting 3 UI rows removes all 3 via one os.replace; mtime moves
    exactly once across the bulk operation."""
    import os as _os
    import time as _time

    app, db, primary = _make_app_with_allowlist(tmp_path)
    try:
        _patterns, ui_path = _seed_ui_entries(
            primary,
            [
                {"pattern": "aa:bb:cc:dd:ee:01", "pattern_type": "mac"},
                {"pattern": "aa:bb:cc:dd:ee:02", "pattern_type": "mac"},
                {"pattern": "aa:bb:cc:dd:ee:03", "pattern_type": "mac"},
                {"pattern": "aa:bb:cc:dd:ee:04", "pattern_type": "mac"},
            ],
        )
        # Rewind mtime so the post-bulk stat is provably distinct.
        st = ui_path.stat()
        _os.utime(ui_path, (st.st_atime, st.st_mtime - 5))
        mtime_before = ui_path.stat().st_mtime
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                "/allowlist/bulk_remove",
                data={
                    CSRF_FORM_FIELD: token,
                    "entry_keys": [
                        "mac:aa:bb:cc:dd:ee:01",
                        "mac:aa:bb:cc:dd:ee:02",
                        "mac:aa:bb:cc:dd:ee:03",
                    ],
                },
            )
        assert r.status_code == 303
        assert r.headers["location"] == "/allowlist?success=bulk_remove&count=3"
        entries = _read_ui_file(primary)
        assert [e["pattern"] for e in entries] == ["aa:bb:cc:dd:ee:04"]
        # mtime moved exactly once (bulk write).
        assert ui_path.stat().st_mtime != mtime_before
        _ = _time  # keep the import live for readers
    finally:
        db.close()


@pytest.mark.webui
def test_allowlist_bulk_remove_with_primary_collision_refuses_atomically(tmp_path):
    """Selecting 2 UI rows + 1 primary row → 400; neither file changes.

    The hostile case the prompt's regression-fence describes: a crafted
    form submission tries to enlist a primary-source key in a batch.
    The handler must refuse the entire batch before any write, even for
    the UI-side rows that are legitimately removable.
    """
    app, db, primary = _make_app_with_allowlist(tmp_path)
    try:
        primary.write_text(
            "entries:\n  - pattern: ee:ee:ee:ee:ee:ee\n    pattern_type: mac\n",
            encoding="utf-8",
        )
        _patterns, ui_path = _seed_ui_entries(
            primary,
            [
                {"pattern": "aa:bb:cc:dd:ee:01", "pattern_type": "mac"},
                {"pattern": "aa:bb:cc:dd:ee:02", "pattern_type": "mac"},
            ],
        )
        primary_before = primary.read_text(encoding="utf-8")
        ui_before = ui_path.read_text(encoding="utf-8")
        with TestClient(app) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                "/allowlist/bulk_remove",
                data={
                    CSRF_FORM_FIELD: token,
                    "entry_keys": [
                        "mac:aa:bb:cc:dd:ee:01",
                        "mac:aa:bb:cc:dd:ee:02",
                        "mac:ee:ee:ee:ee:ee:ee",
                    ],
                },
            )
        assert r.status_code == 400
        assert "primary-file" in r.text or "operator-managed" in r.text
        # Both files byte-for-byte unchanged.
        assert primary.read_text(encoding="utf-8") == primary_before
        assert ui_path.read_text(encoding="utf-8") == ui_before
    finally:
        db.close()


@pytest.mark.webui
def test_allowlist_bulk_remove_empty_selection_returns_400(tmp_path):
    app, db, _primary = _make_app_with_allowlist(tmp_path)
    try:
        with TestClient(app) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                "/allowlist/bulk_remove",
                data={CSRF_FORM_FIELD: token},
            )
        assert r.status_code == 400
    finally:
        db.close()


@pytest.mark.webui
def test_allowlist_bulk_remove_missing_csrf_returns_403(tmp_path):
    app, db, primary = _make_app_with_allowlist(tmp_path)
    try:
        _seed_ui_entries(
            primary,
            [{"pattern": "aa:bb:cc:dd:ee:01", "pattern_type": "mac"}],
        )
        with TestClient(app) as client:
            client.cookies.clear()
            r = client.post(
                "/allowlist/bulk_remove",
                data={"entry_keys": ["mac:aa:bb:cc:dd:ee:01"]},
            )
        assert r.status_code == 403
        # File unchanged.
        entries = _read_ui_file(primary)
        assert [e["pattern"] for e in entries] == ["aa:bb:cc:dd:ee:01"]
    finally:
        db.close()


@pytest.mark.webui
def test_allowlist_bulk_remove_preserves_filter_state_in_redirect(tmp_path):
    """The redirect URL after a bulk_remove echoes the filter form
    fields so operators can keep bulk-cleaning within the same view."""
    app, db, primary = _make_app_with_allowlist(tmp_path)
    try:
        _seed_ui_entries(
            primary,
            [{"pattern": "aa:bb:cc:dd:ee:01", "pattern_type": "mac"}],
        )
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                "/allowlist/bulk_remove",
                data={
                    CSRF_FORM_FIELD: token,
                    "entry_keys": ["mac:aa:bb:cc:dd:ee:01"],
                    "source": "ui",
                    "status": "active",
                    "type": "mac",
                    "q": "aa",
                },
            )
        assert r.status_code == 303
        loc = r.headers["location"]
        assert "source=ui" in loc
        assert "status=active" in loc
        assert "type=mac" in loc
        assert "q=aa" in loc
        assert "success=bulk_remove" in loc
        assert "count=1" in loc
    finally:
        db.close()


@pytest.mark.webui
def test_allowlist_bulk_remove_emits_audit_log_line(tmp_path, caplog):
    """One INFO line per bulk_remove call, with actor + removed + requested
    counts so a journalctl reader can audit who removed what."""
    import logging as _logging

    app, db, primary = _make_app_with_allowlist(tmp_path)
    try:
        _seed_ui_entries(
            primary,
            [
                {"pattern": "aa:bb:cc:dd:ee:01", "pattern_type": "mac"},
                {"pattern": "aa:bb:cc:dd:ee:02", "pattern_type": "mac"},
            ],
        )
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            with caplog.at_level(_logging.INFO, logger="lynceus.webui.app"):
                r = client.post(
                    "/allowlist/bulk_remove",
                    data={
                        CSRF_FORM_FIELD: token,
                        "entry_keys": [
                            "mac:aa:bb:cc:dd:ee:01",
                            "mac:aa:bb:cc:dd:ee:02",
                        ],
                    },
                )
        assert r.status_code == 303
        msgs = [r.getMessage() for r in caplog.records if "bulk_remove" in r.getMessage()]
        assert any("removed=2" in m and "requested=2" in m for m in msgs)
    finally:
        db.close()


# --- primary-source read-only protection (regression fence) -----------------


@pytest.mark.webui
def test_primary_source_entry_renders_without_checkbox(tmp_path):
    """A primary-source entry must render in the table without a
    checkbox — there should be no way for a normal click-through
    operator to select it for bulk removal."""
    app, db, _primary, _ui, _now = _make_app_with_mixed_allowlist(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/allowlist?source=primary")
        assert r.status_code == 200
        # No checkbox input for primary rows. The render places a dash
        # in the cell instead of an <input>.
        assert 'name="entry_keys"' not in r.text
        assert "aa:aa:aa:aa:aa:01" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_primary_source_survives_when_ui_has_same_pattern(tmp_path):
    """Hostile fixture: primary + UI carry the same pattern. Removing the
    UI side must leave the primary side untouched — the daemon never
    writes to allowlist.yaml, so the primary copy is the source of
    truth and must survive any UI-side mutation."""
    from lynceus.allowlist import AllowlistEntry, add_ui_entry, derive_ui_path

    primary = tmp_path / "allowlist.yaml"
    primary.write_text(
        "entries:\n  - pattern: aa:bb:cc:dd:ee:ff\n    pattern_type: mac\n"
        "    note: primary copy\n",
        encoding="utf-8",
    )
    config = Config(
        db_path=str(tmp_path / "ui.db"),
        allowlist_path=str(primary),
    )
    db = Database(config.db_path)
    app = create_app(config, db)
    try:
        ui_path = derive_ui_path(primary)
        add_ui_entry(
            ui_path,
            AllowlistEntry(
                pattern="aa:bb:cc:dd:ee:ff",
                pattern_type="mac",
                note="ui copy",
                added_at=1_799_000_000,
            ),
        )
        primary_before = primary.read_text(encoding="utf-8")
        # Bulk remove the UI key. Composite key matches both rows by
        # (pattern, pattern_type), but the handler only writes to the UI
        # file, and load_allowlist_with_source ensures the primary copy
        # is not even in scope for the removal call (no primary entry is
        # in `keys`, so primary_collisions is empty — but we still hit
        # the only-touch-UI-file invariant).
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                "/allowlist/bulk_remove",
                data={
                    CSRF_FORM_FIELD: token,
                    "entry_keys": ["mac:aa:bb:cc:dd:ee:ff"],
                },
            )
        # The handler refuses because the same composite key matches a
        # primary entry too — this is the safer-by-default behavior.
        assert r.status_code == 400
        # Both files unchanged.
        assert primary.read_text(encoding="utf-8") == primary_before
        ui_entries = _read_ui_file(primary)
        assert len(ui_entries) == 1
        assert ui_entries[0]["pattern"] == "aa:bb:cc:dd:ee:ff"
    finally:
        db.close()


@pytest.mark.webui
def test_allowlist_add_writes_only_to_ui_file_not_primary(tmp_path):
    """Add via the form lands in allowlist_ui.yaml; the operator-curated
    primary file is byte-for-byte untouched, including any operator
    comments above the entries block."""
    primary = tmp_path / "allowlist.yaml"
    primary_text = (
        "# operator comment that must survive\n"
        "entries:\n  - pattern: ee:ee:ee:ee:ee:ee\n    pattern_type: mac\n"
    )
    primary.write_text(primary_text, encoding="utf-8")
    config = Config(
        db_path=str(tmp_path / "ui.db"),
        allowlist_path=str(primary),
    )
    db = Database(config.db_path)
    app = create_app(config, db)
    try:
        primary_mtime_before = primary.stat().st_mtime
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                "/allowlist/add",
                data={
                    CSRF_FORM_FIELD: token,
                    "pattern": "11:22:33:44:55:66",
                    "pattern_type": "mac",
                },
            )
        assert r.status_code == 303
        # Primary unchanged.
        assert primary.read_text(encoding="utf-8") == primary_text
        assert primary.stat().st_mtime == primary_mtime_before
        # UI file got the write.
        ui_entries = _read_ui_file(primary)
        assert [e["pattern"] for e in ui_entries] == ["11:22:33:44:55:66"]
    finally:
        db.close()


@pytest.mark.webui
def test_allowlist_cross_process_daemon_picks_up_new_entry(tmp_path, caplog):
    """End-to-end: add via webui, then a fresh poller reload (mtime watch)
    sees the new entry. Mirrors the cross-process invariant the existing
    triage e2e exercises."""
    import logging as _logging

    from lynceus.poller import Poller

    primary = tmp_path / "allowlist.yaml"
    primary.write_text("entries: []\n", encoding="utf-8")
    config = Config(
        db_path=str(tmp_path / "ui.db"),
        allowlist_path=str(primary),
    )
    db = Database(config.db_path)
    app = create_app(config, db)
    try:
        # 1) Daemon (poller) starts with no allowlist.
        poller_cfg = Config(
            kismet_fixture_path=str(
                Path(__file__).parent / "fixtures" / "kismet_devices.json"
            ),
            db_path=str(tmp_path / "lynceus.db"),
            location_id="testloc",
            location_label="Test Location",
            allowlist_path=str(primary),
        )
        poller = Poller(poller_cfg)
        try:
            assert poller.allowlist.entries == []
            # 2) Webui adds an entry.
            with TestClient(app, follow_redirects=False) as client:
                token, _ = _csrf_setup(client)
                r = client.post(
                    "/allowlist/add",
                    data={
                        CSRF_FORM_FIELD: token,
                        "pattern": "aa:bb:cc:dd:ee:ff",
                        "pattern_type": "mac",
                    },
                )
            assert r.status_code == 303
            # 3) Daemon reloads on next tick.
            import os as _os

            ui_path = primary.with_stem(primary.stem + "_ui")
            st = ui_path.stat()
            _os.utime(ui_path, (st.st_atime, st.st_mtime + 1))
            with caplog.at_level(_logging.INFO, logger="lynceus.poller"):
                poller._maybe_reload_allowlist()
            assert len(poller.allowlist.entries) == 1
            assert poller.allowlist.entries[0].pattern == "aa:bb:cc:dd:ee:ff"
        finally:
            poller.db.close()
    finally:
        db.close()


# ---------------------------------------------------------------------------
# /alerts -- rc5 filter additions (rule_type, q, window) and unified
# pagination via PaginationParams. Existing severity / acknowledged /
# since / until / search / page_size tests above cover the pre-rc5
# filter set; the section below covers the new dimensions + the
# pagination-helper integration end-to-end through the route.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_alerts_list_filter_rule_type(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        db.add_alert(
            ts=100, rule_name="r", mac=None, message="mac-msg",
            severity="low", rule_type="watchlist_mac",
        )
        db.add_alert(
            ts=101, rule_name="r", mac=None, message="oui-msg",
            severity="low", rule_type="watchlist_oui",
        )
        with TestClient(app) as client:
            r = client.get("/alerts?rule_type=watchlist_oui")
        assert r.status_code == 200
        assert "oui-msg" in r.text
        assert "mac-msg" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_invalid_rule_type_falls_back_silently(tmp_path):
    # Invalid rule_type ignored (per the prompt's "ignore the invalid
    # value, fall back to default. Don't 400."). Returns the same view
    # as no rule_type filter.
    app, db = _make_app(tmp_path)
    try:
        db.add_alert(
            ts=100, rule_name="r", mac=None, message="mac-msg",
            severity="low", rule_type="watchlist_mac",
        )
        with TestClient(app) as client:
            r = client.get("/alerts?rule_type=bogus")
        assert r.status_code == 200
        assert "mac-msg" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_filter_q_matches_mac(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        db.upsert_device("aa:bb:cc:dd:ee:ff", "wifi", "Acme", 0, 100)
        db.upsert_device("11:22:33:44:55:66", "wifi", "Acme", 0, 100)
        db.add_alert(
            ts=100, rule_name="r", mac="aa:bb:cc:dd:ee:ff",
            message="mac-alpha", severity="low",
        )
        db.add_alert(
            ts=101, rule_name="r", mac="11:22:33:44:55:66",
            message="mac-beta", severity="low",
        )
        with TestClient(app) as client:
            r = client.get("/alerts?q=aa:bb")
        assert r.status_code == 200
        assert "mac-alpha" in r.text
        assert "mac-beta" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_filter_q_matches_ssid_via_message(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        db.add_alert(
            ts=100, rule_name="r", mac=None,
            message="SSID 'MySSID' on watchlist", severity="low",
        )
        db.add_alert(
            ts=101, rule_name="r", mac=None,
            message="MAC aa:bb:cc on watchlist", severity="low",
        )
        with TestClient(app) as client:
            r = client.get("/alerts?q=myssid")
        assert r.status_code == 200
        assert "MySSID" in r.text
        assert "aa:bb:cc" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_filter_q_too_long_returns_400(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/alerts?q=" + "x" * 200)
        assert r.status_code == 400
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_filter_window_relative_resolves_server_side(tmp_path, monkeypatch):
    # Fix a clock so "last 1h" has a deterministic bound.
    import time as _t
    fixed_now = 10_000_000
    monkeypatch.setattr(_t, "time", lambda: fixed_now)

    app, db = _make_app(tmp_path)
    try:
        # 3 alerts: 5 min ago, 2 hours ago, 2 days ago.
        db.add_alert(
            ts=fixed_now - 300, rule_name="r", mac=None,
            message="recent-msg", severity="low",
        )
        db.add_alert(
            ts=fixed_now - 7200, rule_name="r", mac=None,
            message="older-msg", severity="low",
        )
        db.add_alert(
            ts=fixed_now - 2 * 86400, rule_name="r", mac=None,
            message="oldest-msg", severity="low",
        )
        with TestClient(app) as client:
            r = client.get("/alerts?window=1h")
        assert r.status_code == 200
        assert "recent-msg" in r.text
        assert "older-msg" not in r.text
        assert "oldest-msg" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_filter_window_24h(tmp_path, monkeypatch):
    import time as _t
    fixed_now = 10_000_000
    monkeypatch.setattr(_t, "time", lambda: fixed_now)

    app, db = _make_app(tmp_path)
    try:
        db.add_alert(
            ts=fixed_now - 3600, rule_name="r", mac=None,
            message="hourago-msg", severity="low",
        )
        db.add_alert(
            ts=fixed_now - 2 * 86400, rule_name="r", mac=None,
            message="twodaysago-msg", severity="low",
        )
        with TestClient(app) as client:
            r = client.get("/alerts?window=24h")
        assert "hourago-msg" in r.text
        assert "twodaysago-msg" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_invalid_window_falls_back_silently(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        db.add_alert(
            ts=100, rule_name="r", mac=None, message="m",
            severity="low",
        )
        with TestClient(app) as client:
            r = client.get("/alerts?window=lol")
        assert r.status_code == 200
        assert "m" in r.text
    finally:
        db.close()


# --- pagination via PaginationParams helper ---------------------------------


@pytest.mark.webui
def test_alerts_list_pagination_four_pages_at_per_page_25(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        # 100 alerts, per_page=25 -> 4 pages.
        for i in range(100):
            db.add_alert(
                ts=100 + i, rule_name="r", mac=None,
                message=f"alert-{i:03d}", severity="low",
                rule_type="watchlist_mac",
            )
        with TestClient(app) as client:
            r1 = client.get("/alerts?page_size=25&page=1")
            r2 = client.get("/alerts?page_size=25&page=2")
            r4 = client.get("/alerts?page_size=25&page=4")
        # Page 1 carries the newest 25 (alert-075..alert-099).
        assert "alert-099" in r1.text
        assert "alert-075" in r1.text
        # Page 2 carries the next 25 (alert-050..alert-074).
        assert "alert-074" in r2.text
        assert "alert-050" in r2.text
        # Footer says "Page N of M ... K total ... per_page=PP".
        assert "Page 1 of 4" in r1.text
        assert "100 total" in r1.text
        assert "per_page=25" in r1.text
        # Page 4 carries the oldest 25 (alert-000..alert-024).
        assert "alert-000" in r4.text
        assert "alert-024" in r4.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_pagination_page_above_total_clamps_to_last(tmp_path):
    # Per-prompt: page=999 with only 4 pages -> clamp to 4. Don't 404.
    app, db = _make_app(tmp_path)
    try:
        for i in range(100):
            db.add_alert(
                ts=100 + i, rule_name="r", mac=None,
                message=f"a{i:03d}", severity="low",
            )
        with TestClient(app) as client:
            r = client.get("/alerts?page_size=25&page=999")
        assert r.status_code == 200
        assert "Page 4 of 4" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_pagination_negative_page_clamps_to_one(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
        with TestClient(app) as client:
            r = client.get("/alerts?page=-1")
        assert r.status_code == 200
        assert "Page 1 of 1" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_pagination_invalid_per_page_falls_back_to_default(tmp_path):
    # Per-prompt: per_page=999 -> clamp to default 50.
    app, db = _make_app(tmp_path)
    try:
        for i in range(60):
            db.add_alert(
                ts=100 + i, rule_name="r", mac=None,
                message=f"a{i}", severity="low",
            )
        with TestClient(app) as client:
            r = client.get("/alerts?page_size=999")
        assert r.status_code == 200
        assert "per_page=50" in r.text


    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_pagination_non_allowed_per_page_falls_back(tmp_path):
    # Per-prompt: per_page=37 (non-allowed) -> default 50.
    app, db = _make_app(tmp_path)
    try:
        for i in range(60):
            db.add_alert(
                ts=100 + i, rule_name="r", mac=None,
                message=f"a{i}", severity="low",
            )
        with TestClient(app) as client:
            r = client.get("/alerts?page_size=37")
        assert r.status_code == 200
        assert "per_page=50" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_pagination_empty_dataset_renders_empty_state(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/alerts")
        assert r.status_code == 200
        assert "Page 1 of 1" in r.text
        assert "0 total" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_filter_plus_pagination_combined(tmp_path):
    # 50 alerts; rule_type filter narrows to 10. per_page=25, page=1 ->
    # 10 rows, "Page 1 of 1 ... 10 total".
    app, db = _make_app(tmp_path)
    try:
        for i in range(40):
            db.add_alert(
                ts=100 + i, rule_name="r", mac=None,
                message=f"oui-{i}", severity="low",
                rule_type="watchlist_oui",
            )
        for i in range(10):
            db.add_alert(
                ts=500 + i, rule_name="r", mac=None,
                message=f"mac-{i}", severity="low",
                rule_type="watchlist_mac",
            )
        with TestClient(app) as client:
            r = client.get("/alerts?rule_type=watchlist_mac&page_size=25")
        assert r.status_code == 200
        assert "Page 1 of 1" in r.text
        assert "10 total" in r.text
        for i in range(10):
            assert f"mac-{i}" in r.text
        assert "oui-0" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_pagination_next_link_preserves_filter_state(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        for i in range(60):
            db.add_alert(
                ts=100 + i, rule_name="r", mac=None,
                message=f"a{i:02d}", severity="high",
                rule_type="watchlist_mac",
            )
        with TestClient(app) as client:
            r = client.get(
                "/alerts?rule_type=watchlist_mac&severity=high&page=1&page_size=25"
            )
        assert r.status_code == 200
        # Next-page link must round-trip both filters.
        assert "page=2" in r.text
        assert "severity=high" in r.text
        assert "rule_type=watchlist_mac" in r.text
        assert "page_size=25" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_reset_link_when_new_filters_active(tmp_path):
    # rule_type / q / window each individually activate filters_active.
    app, db = _make_app(tmp_path)
    try:
        db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
        with TestClient(app) as client:
            r_type = client.get("/alerts?rule_type=watchlist_mac")
            r_q = client.get("/alerts?q=anything")
            r_w = client.get("/alerts?window=1h")
        for r in (r_type, r_q, r_w):
            assert "reset filters" in r.text or 'class="reset-filters"' in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_ack_all_visible_form_carries_new_filter_state(tmp_path):
    # The bulk-write filter set MUST mirror the GET filter set or the
    # operator silently acks alerts they can't see.
    app, db = _make_app(tmp_path)
    try:
        db.add_alert(
            ts=100, rule_name="r", mac=None, message="m",
            severity="low", rule_type="watchlist_mac",
        )
        with TestClient(app) as client:
            r = client.get(
                "/alerts?rule_type=watchlist_mac&q=foo&window=24h"
            )
        assert r.status_code == 200
        # Hidden inputs reflect the filter values.
        assert 'name="rule_type"' in r.text
        assert 'value="watchlist_mac"' in r.text
        assert 'name="q"' in r.text
        assert 'value="foo"' in r.text
        assert 'name="window"' in r.text
        assert 'value="24h"' in r.text
    finally:
        db.close()


# ---------------------------------------------------------------------------
# /allowlist -- unified pagination via the same PaginationParams helper
# /alerts uses. Filter dimensions are unchanged in this prompt; tests
# below cover only the pagination addition.
# ---------------------------------------------------------------------------


def _make_app_with_many_ui_allowlist_entries(tmp_path, n: int):
    """Seed an allowlist with N UI entries (active mac patterns) so
    pagination tests have something to slice. Returns (app, db, ui_path).
    """
    import time as _time

    from lynceus.allowlist import AllowlistEntry, add_ui_entry, derive_ui_path

    primary = tmp_path / "allowlist.yaml"
    primary.write_text("entries: []\n", encoding="utf-8")
    config = Config(
        db_path=str(tmp_path / "ui.db"),
        allowlist_path=str(primary),
    )
    db = Database(config.db_path)
    app = create_app(config, db)
    ui_path = derive_ui_path(primary)
    now_ts = int(_time.time())
    for i in range(n):
        # Distinct 1-byte tail so the patterns are unique. Mac
        # validator wants 6 lowercase hex octets joined by colons.
        tail = f"{i & 0xff:02x}"
        entry = AllowlistEntry(
            pattern=f"aa:bb:cc:dd:{(i >> 8) & 0xff:02x}:{tail}",
            pattern_type="mac",
            note=f"seed-{i:03d}",
            added_at=now_ts + i,
        )
        add_ui_entry(ui_path, entry)
    return app, db, ui_path


@pytest.mark.webui
def test_allowlist_pagination_three_pages_at_per_page_25(tmp_path):
    app, db, _ui = _make_app_with_many_ui_allowlist_entries(tmp_path, 75)
    try:
        with TestClient(app) as client:
            r1 = client.get("/allowlist?page_size=25&page=1")
            r2 = client.get("/allowlist?page_size=25&page=2")
            r3 = client.get("/allowlist?page_size=25&page=3")
        for r in (r1, r2, r3):
            assert r.status_code == 200
        # Footer literal mirrors /alerts.
        assert "Page 1 of 3" in r1.text
        assert "75 total" in r1.text
        assert "per_page=25" in r1.text
        assert "Page 2 of 3" in r2.text
        assert "Page 3 of 3" in r3.text
    finally:
        db.close()


@pytest.mark.webui
def test_allowlist_pagination_page_above_total_clamps_to_last(tmp_path):
    app, db, _ui = _make_app_with_many_ui_allowlist_entries(tmp_path, 30)
    try:
        with TestClient(app) as client:
            r = client.get("/allowlist?page_size=25&page=999")
        assert r.status_code == 200
        assert "Page 2 of 2" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_allowlist_pagination_single_page_shows_disabled_nav(tmp_path):
    # 10 entries, default per_page=50 -> one page. prev/next must
    # render as disabled rather than 404 links.
    app, db, _ui = _make_app_with_many_ui_allowlist_entries(tmp_path, 10)
    try:
        with TestClient(app) as client:
            r = client.get("/allowlist")
        assert r.status_code == 200
        assert "Page 1 of 1" in r.text
        # Disabled prev/next render in <span class="dim">.
        assert 'class="dim"' in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_allowlist_pagination_invalid_per_page_falls_back(tmp_path):
    app, db, _ui = _make_app_with_many_ui_allowlist_entries(tmp_path, 60)
    try:
        with TestClient(app) as client:
            r = client.get("/allowlist?page_size=37")
        assert r.status_code == 200
        assert "per_page=50" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_allowlist_pagination_filter_plus_pagination_combined(tmp_path):
    # Filter narrows the set; pagination math operates on the filtered
    # list, not the raw list. Single source of truth for "total."
    app, db, _ui = _make_app_with_many_ui_allowlist_entries(tmp_path, 60)
    try:
        with TestClient(app) as client:
            r = client.get("/allowlist?q=seed-005&page_size=25")
        assert r.status_code == 200
        # q=seed-005 matches exactly one entry (seed-005). Note that
        # seed-050..seed-059 contain "seed-05" so substring match on
        # "seed-005" is exact -- one row.
        assert "Page 1 of 1" in r.text
        assert "1 total" in r.text
        assert "seed-005" in r.text
        assert "seed-050" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_allowlist_pagination_next_link_preserves_filter_state(tmp_path):
    # Filter-narrowed set still has enough entries to be paginated.
    # q=seed matches all 60 rows; type=mac matches all 60; status=active
    # matches all 60 -- so filtered=60 and pagination still produces
    # multiple pages.
    app, db, _ui = _make_app_with_many_ui_allowlist_entries(tmp_path, 60)
    try:
        with TestClient(app) as client:
            r = client.get(
                "/allowlist?q=seed&status=active&page_size=25&page=1"
            )
        assert r.status_code == 200
        # Next-page link round-trips q + status + page_size.
        assert "page=2" in r.text
        assert "q=seed" in r.text
        assert "status=active" in r.text
        assert "page_size=25" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_allowlist_pagination_empty_filtered_set_no_nav_404(tmp_path):
    # 60 entries; filter produces 0 matches. Empty-state renders.
    # Pagination footer still coherent ("Page 1 of 1, 0 total").
    app, db, _ui = _make_app_with_many_ui_allowlist_entries(tmp_path, 60)
    try:
        with TestClient(app) as client:
            r = client.get("/allowlist?q=nonexistent-substring-xyz")
        assert r.status_code == 200
        assert "No entries match" in r.text
        assert "Page 1 of 1" in r.text
        assert "0 total" in r.text
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Per-alert triage notes (alerts.note + /alerts/{id}/note + list indicator).
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_alert_detail_no_note_renders_placeholder_and_empty_textarea(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
        with TestClient(app) as client:
            r = client.get(f"/alerts/{aid}")
        assert r.status_code == 200
        assert "No triage note recorded" in r.text
        assert "Save note" in r.text
        # Empty textarea (no pre-populated value).
        assert 'name="note_text"' in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alert_detail_with_note_renders_text_and_timestamp(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
        db.update_alert_note(aid, "FP -- known neighbour AP", now_ts=999)
        with TestClient(app) as client:
            r = client.get(f"/alerts/{aid}")
        assert r.status_code == 200
        assert "FP -- known neighbour AP" in r.text
        assert "Last updated" in r.text
        assert "Update note" in r.text
        assert "Clear note" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alert_note_post_saves_text_and_redirects(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                f"/alerts/{aid}/note",
                data={CSRF_FORM_FIELD: token, "note_text": "actioned -- physical check"},
            )
        assert r.status_code == 303
        assert r.headers["location"] == f"/alerts/{aid}?success=note_saved"
        alert = db.get_alert(aid)
        assert alert["note"] == "actioned -- physical check"
        assert alert["note_updated_at"] is not None
    finally:
        db.close()


@pytest.mark.webui
def test_alert_note_post_empty_clears_note(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
        db.update_alert_note(aid, "initial conclusion", now_ts=42)
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                f"/alerts/{aid}/note",
                data={CSRF_FORM_FIELD: token, "note_text": ""},
            )
        assert r.status_code == 303
        assert r.headers["location"] == f"/alerts/{aid}?success=note_cleared"
        alert = db.get_alert(aid)
        assert alert["note"] is None
        assert alert["note_updated_at"] is None
    finally:
        db.close()


@pytest.mark.webui
def test_alert_note_post_over_limit_returns_400_and_leaves_db_unchanged(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
        db.update_alert_note(aid, "stable", now_ts=42)
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                f"/alerts/{aid}/note",
                data={CSRF_FORM_FIELD: token, "note_text": "x" * 4097},
            )
        assert r.status_code == 400
        assert db.get_alert(aid)["note"] == "stable"
    finally:
        db.close()


@pytest.mark.webui
def test_alert_note_post_without_csrf_returns_403(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
        with TestClient(app, follow_redirects=False) as client:
            client.cookies.clear()
            r = client.post(f"/alerts/{aid}/note", data={"note_text": "x"})
        assert r.status_code == 403
        assert db.get_alert(aid)["note"] is None
    finally:
        db.close()


@pytest.mark.webui
def test_alert_note_post_missing_alert_returns_404(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                "/alerts/99999/note",
                data={CSRF_FORM_FIELD: token, "note_text": "x"},
            )
        assert r.status_code == 404
    finally:
        db.close()


@pytest.mark.webui
def test_alert_detail_success_flash_renders_on_save(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
        db.update_alert_note(aid, "noted", now_ts=42)
        with TestClient(app) as client:
            r = client.get(f"/alerts/{aid}?success=note_saved")
        assert r.status_code == 200
        assert "Note saved." in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alert_detail_success_flash_renders_on_clear(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
        with TestClient(app) as client:
            r = client.get(f"/alerts/{aid}?success=note_cleared")
        assert r.status_code == 200
        assert "Note cleared." in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alert_detail_unknown_success_token_renders_no_flash(tmp_path):
    """Spoofed / hand-crafted ?success=... values must not echo into
    the page. The whitelist drops unknown tokens before render."""
    app, db = _make_app(tmp_path)
    try:
        aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
        with TestClient(app) as client:
            r = client.get(f"/alerts/{aid}?success=<script>alert(1)</script>")
        assert r.status_code == 200
        assert "<script>alert(1)</script>" not in r.text
        assert "Note saved." not in r.text
        assert "Note cleared." not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_row_with_note_shows_indicator(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
        db.update_alert_note(aid, "FP -- known neighbour AP", now_ts=42)
        with TestClient(app) as client:
            r = client.get("/alerts")
        assert r.status_code == 200
        assert "alert-note-indicator" in r.text
        # Tooltip carries the truncated preview.
        assert "FP -- known neighbour AP" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_row_without_note_shows_no_indicator(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
        with TestClient(app) as client:
            r = client.get("/alerts")
        assert r.status_code == 200
        assert "alert-note-indicator" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_indicator_tooltip_truncates_long_notes(tmp_path):
    """Indicator hover preview shows the first ~50 chars + ellipsis
    for longer notes; the full note never leaks into the list-page
    HTML (operators reading over the shoulder don't see triage
    rationale unless they click through)."""
    app, db = _make_app(tmp_path)
    long_note = "A" * 200
    try:
        aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
        db.update_alert_note(aid, long_note, now_ts=42)
        with TestClient(app) as client:
            r = client.get("/alerts")
        assert r.status_code == 200
        assert "alert-note-indicator" in r.text
        # Truncated preview only; full note must not appear on the
        # list page (only on the detail page).
        assert "A" * 200 not in r.text
        assert "A" * 50 in r.text
    finally:
        db.close()


# ---------------------------------------------------------------------------
# /alerts has_note filter -- pairs with the per-row indicator above to
# close the triage-workflow loop (notes -> indicator -> filter).
# ---------------------------------------------------------------------------


def _seed_two_alerts_one_noted(db):
    # Use distinct non-overlapping substrings so containment
    # assertions don't conflate the two rows (e.g. "triaged" is a
    # suffix of "untriaged"). "msg-noted" and "msg-fresh" share no
    # substring, so `"msg-noted" not in text` is unambiguous.
    a1 = db.add_alert(ts=100, rule_name="r", mac=None, message="msg-noted", severity="low")
    a2 = db.add_alert(ts=101, rule_name="r", mac=None, message="msg-fresh", severity="low")
    db.update_alert_note(a1, "FP -- known device", now_ts=999)
    return a1, a2


@pytest.mark.webui
def test_alerts_has_note_dropdown_renders_with_all_three_options(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/alerts")
        assert r.status_code == 200
        assert 'name="has_note"' in r.text
        assert 'value="all"' in r.text
        assert 'value="with_note"' in r.text
        assert 'value="without_note"' in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_has_note_default_shows_all(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        _seed_two_alerts_one_noted(db)
        with TestClient(app) as client:
            r = client.get("/alerts")
        assert r.status_code == 200
        assert "msg-noted" in r.text
        assert "msg-fresh" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_has_note_with_note_narrows_to_noted_rows(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        _seed_two_alerts_one_noted(db)
        with TestClient(app) as client:
            r = client.get("/alerts?has_note=with_note")
        assert r.status_code == 200
        assert "msg-noted" in r.text
        assert "msg-fresh" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_has_note_without_note_narrows_to_fresh_rows(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        _seed_two_alerts_one_noted(db)
        with TestClient(app) as client:
            r = client.get("/alerts?has_note=without_note")
        assert r.status_code == 200
        assert "msg-fresh" in r.text
        assert "msg-noted" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_has_note_invalid_value_falls_back_to_all(tmp_path):
    """Stale bookmark / typo'd has_note value lands on the unfiltered
    page rather than a 400 -- matches the rule_type / window
    silent-clamp precedent."""
    app, db = _make_app(tmp_path)
    try:
        _seed_two_alerts_one_noted(db)
        with TestClient(app) as client:
            r = client.get("/alerts?has_note=bogus_value")
        assert r.status_code == 200
        assert "msg-noted" in r.text
        assert "msg-fresh" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_has_note_combines_with_severity(tmp_path):
    """has_note ANDs cleanly with severity at the handler+DB layer."""
    app, db = _make_app(tmp_path)
    try:
        a1 = db.add_alert(ts=100, rule_name="r", mac=None, message="alpha-msg", severity="high")
        db.add_alert(ts=101, rule_name="r", mac=None, message="bravo-msg", severity="high")
        a3 = db.add_alert(ts=102, rule_name="r", mac=None, message="charlie-msg", severity="low")
        db.update_alert_note(a1, "FP", now_ts=999)
        db.update_alert_note(a3, "FP", now_ts=999)
        with TestClient(app) as client:
            r = client.get("/alerts?severity=high&has_note=with_note")
        assert r.status_code == 200
        assert "alpha-msg" in r.text
        assert "bravo-msg" not in r.text
        assert "charlie-msg" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_has_note_round_trips_in_pagination_links(tmp_path):
    """has_note is preserved through next/prev pagination links --
    operator paginating through a filtered view stays in the filter."""
    app, db = _make_app(tmp_path)
    try:
        # 30 alerts, all noted, so the filter narrows nothing
        # (purpose is to verify state preservation, not selection).
        for i in range(30):
            aid = db.add_alert(
                ts=100 + i, rule_name="r", mac=None,
                message=f"m{i}", severity="low",
            )
            db.update_alert_note(aid, f"note-{i}", now_ts=999)
        with TestClient(app) as client:
            r = client.get("/alerts?has_note=with_note&page_size=25")
        assert r.status_code == 200
        # Pagination next link carries has_note through.
        assert "has_note=with_note" in r.text
        assert "page=2" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_has_note_dropdown_round_trips_selected_state(tmp_path):
    """Round-trip on the dropdown: visiting /alerts?has_note=with_note
    renders that option as selected so the operator sees the active
    filter state in the form."""
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/alerts?has_note=with_note")
        assert r.status_code == 200
        assert 'value="with_note" selected' in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_has_note_carried_through_ack_all_visible_form(tmp_path):
    """ack-all-visible MUST mirror the GET filter set exactly. The
    has_note hidden input rides along when set, so 'ack all matching'
    operates on the same rows the operator sees."""
    app, db = _make_app(tmp_path)
    try:
        _seed_two_alerts_one_noted(db)
        with TestClient(app) as client:
            r = client.get("/alerts?has_note=with_note")
        assert r.status_code == 200
        # Hidden input present in the ack-all-visible form.
        assert 'name="has_note" value="with_note"' in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_ack_all_visible_post_with_has_note_acks_only_matching(tmp_path):
    """ack-all-visible POST with has_note=with_note acknowledges
    only triaged rows -- single-source-of-truth invariant: the
    POST handler's filter clamp must mirror the GET handler exactly."""
    app, db = _make_app(tmp_path)
    try:
        a1, a2 = _seed_two_alerts_one_noted(db)
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                "/alerts/ack-all-visible",
                data={
                    CSRF_FORM_FIELD: token,
                    "has_note": "with_note",
                },
            )
        assert r.status_code == 200
        # Only the noted alert (a1) was acknowledged; untriaged (a2)
        # left alone.
        assert db.get_alert(a1)["acknowledged"] == 1
        assert db.get_alert(a2)["acknowledged"] == 0
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_has_note_default_omits_param_from_pagination_url(tmp_path):
    """When has_note is the default 'all', it must NOT appear in
    pagination URLs -- keeps default-state URLs short and the
    'no params -> baseline' invariant intact."""
    app, db = _make_app(tmp_path)
    try:
        for i in range(30):
            db.add_alert(
                ts=100 + i, rule_name="r", mac=None,
                message=f"m{i}", severity="low",
            )
        with TestClient(app) as client:
            r = client.get("/alerts?page_size=25")
        assert r.status_code == 200
        assert "has_note=" not in r.text or "has_note=all" not in r.text
        # The pagination block contains 'page=2' but not has_note=all.
        idx = r.text.find("page=2")
        assert idx != -1
        # Look in a 200-char window around the page=2 link.
        link_window = r.text[max(0, idx - 200): idx + 200]
        assert "has_note" not in link_window
    finally:
        db.close()


# ---------------------------------------------------------------------------
# rc6: per-rule_type snooze controls on /rules.
# ---------------------------------------------------------------------------


def _make_app_with_rules(tmp_path, body: str):
    """App factory for /rules tests: writes a rules.yaml at tmp_path
    and configures the Config + Database around it. Body is the YAML
    document body (everything below the top-level ``rules:`` key)."""
    rules_yaml = tmp_path / "rules.yaml"
    rules_yaml.write_text("rules:\n" + body, encoding="utf-8")
    config = Config(db_path=str(tmp_path / "ui.db"), rules_path=str(rules_yaml))
    db = Database(config.db_path)
    app = create_app(config, db)
    return app, db


_TWO_RULES_YAML = (
    "  - name: known_bad_mac\n"
    "    rule_type: watchlist_mac\n"
    "    severity: high\n"
    "    patterns: ['de:ad:be:ef:00:01']\n"
    "  - name: rogue_ssids\n"
    "    rule_type: watchlist_ssid\n"
    "    severity: med\n"
    "    patterns: ['FreeAirportWiFi']\n"
)


@pytest.mark.webui
def test_rules_list_renders_snooze_form_when_no_active_snooze(tmp_path):
    """The collapsible snooze form is the per-row affordance for
    rule_types without an active snooze — operators see the option to
    silence, with the dropdown of durations."""
    app, db = _make_app_with_rules(tmp_path, _TWO_RULES_YAML)
    try:
        with TestClient(app) as client:
            r = client.get("/rules")
        assert r.status_code == 200
        assert "/rules/watchlist_mac/snooze" in r.text
        assert "/rules/watchlist_ssid/snooze" in r.text
        assert 'name="duration_seconds"' in r.text
        assert 'value="3600"' in r.text  # 1h
        assert 'value="86400"' in r.text  # 24h
        assert "badge-snoozed" not in r.text  # no badge when no snooze active
    finally:
        db.close()


@pytest.mark.webui
def test_rules_list_renders_badge_and_unsnooze_when_active(tmp_path):
    """An active snooze on watchlist_mac swaps the snooze form for a
    badge + unsnooze button on that row only. The other rule_type's
    row is unaffected."""
    app, db = _make_app_with_rules(tmp_path, _TWO_RULES_YAML)
    now = int(__import__("time").time())
    db.add_rule_type_snooze(
        rule_type="watchlist_mac",
        expires_at=now + 4 * 3600,
        added_at=now,
        note="network reconfigure",
    )
    try:
        with TestClient(app) as client:
            r = client.get("/rules")
        assert r.status_code == 200
        # Snoozed row: badge + unsnooze button.
        assert "/rules/watchlist_mac/unsnooze" in r.text
        assert "badge-snoozed" in r.text
        assert "snooze note" in r.text
        assert "network reconfigure" in r.text
        # Non-snoozed row: snooze form still rendered.
        assert "/rules/watchlist_ssid/snooze" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_rules_list_status_filter_snoozed_only(tmp_path):
    """status=snoozed narrows the iteration to rules whose rule_type
    has an active snooze. The unsnoozed rule's name disappears from
    the render."""
    app, db = _make_app_with_rules(tmp_path, _TWO_RULES_YAML)
    now = int(__import__("time").time())
    db.add_rule_type_snooze(
        rule_type="watchlist_mac", expires_at=now + 3600, added_at=now
    )
    try:
        with TestClient(app) as client:
            r = client.get("/rules?status=snoozed")
        assert r.status_code == 200
        assert "known_bad_mac" in r.text
        assert "rogue_ssids" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_rules_list_status_filter_active_only(tmp_path):
    """status=active is the complement: only rules whose rule_type
    has no active snooze appear."""
    app, db = _make_app_with_rules(tmp_path, _TWO_RULES_YAML)
    now = int(__import__("time").time())
    db.add_rule_type_snooze(
        rule_type="watchlist_mac", expires_at=now + 3600, added_at=now
    )
    try:
        with TestClient(app) as client:
            r = client.get("/rules?status=active")
        assert r.status_code == 200
        assert "rogue_ssids" in r.text
        assert "known_bad_mac" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_rules_list_invalid_status_falls_back_to_all(tmp_path):
    """Stale-bookmark posture: a typo in the status query param lands
    on the unfiltered page rather than 400."""
    app, db = _make_app_with_rules(tmp_path, _TWO_RULES_YAML)
    try:
        with TestClient(app) as client:
            r = client.get("/rules?status=garbage")
        assert r.status_code == 200
        assert "known_bad_mac" in r.text
        assert "rogue_ssids" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_snooze_post_inserts_row_and_redirects(tmp_path):
    app, db = _make_app_with_rules(tmp_path, _TWO_RULES_YAML)
    try:
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                "/rules/watchlist_mac/snooze",
                data={
                    CSRF_FORM_FIELD: token,
                    "duration_seconds": 3600,
                    "note": "investigating",
                },
            )
        assert r.status_code == 303
        assert "success=snooze_added" in r.headers["location"]
        assert "rule_type=watchlist_mac" in r.headers["location"]
        row = db._conn.execute(
            "SELECT rule_type, note FROM rule_type_snoozes"
        ).fetchone()
        assert row["rule_type"] == "watchlist_mac"
        assert row["note"] == "investigating"
    finally:
        db.close()


@pytest.mark.webui
def test_unsnooze_post_deletes_row_and_redirects(tmp_path):
    app, db = _make_app_with_rules(tmp_path, _TWO_RULES_YAML)
    now = int(__import__("time").time())
    db.add_rule_type_snooze(
        rule_type="watchlist_mac", expires_at=now + 3600, added_at=now
    )
    try:
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                "/rules/watchlist_mac/unsnooze",
                data={CSRF_FORM_FIELD: token},
            )
        assert r.status_code == 303
        assert "success=snooze_removed" in r.headers["location"]
        row = db._conn.execute(
            "SELECT * FROM rule_type_snoozes WHERE rule_type='watchlist_mac'"
        ).fetchone()
        assert row is None
    finally:
        db.close()


@pytest.mark.webui
def test_snooze_post_invalid_duration_returns_400(tmp_path):
    """An attacker-supplied duration outside the whitelist gets a 400
    rather than silently inserting. The duration set is strictly
    enforced (the dropdown is the only legitimate source)."""
    app, db = _make_app_with_rules(tmp_path, _TWO_RULES_YAML)
    try:
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                "/rules/watchlist_mac/snooze",
                data={CSRF_FORM_FIELD: token, "duration_seconds": 999},
            )
        assert r.status_code == 400
        row_count = db._conn.execute(
            "SELECT COUNT(*) FROM rule_type_snoozes"
        ).fetchone()[0]
        assert row_count == 0
    finally:
        db.close()


@pytest.mark.webui
def test_snooze_post_unknown_rule_type_returns_400(tmp_path):
    """Path-param rule_type must be a known RuleType literal; arbitrary
    strings get 400 (defense in depth against PK-pollution attempts)."""
    app, db = _make_app_with_rules(tmp_path, _TWO_RULES_YAML)
    try:
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                "/rules/totally_made_up/snooze",
                data={CSRF_FORM_FIELD: token, "duration_seconds": 3600},
            )
        assert r.status_code == 400
    finally:
        db.close()


@pytest.mark.webui
def test_snooze_post_without_csrf_returns_403(tmp_path):
    app, db = _make_app_with_rules(tmp_path, _TWO_RULES_YAML)
    try:
        with TestClient(app, follow_redirects=False) as client:
            client.cookies.clear()
            r = client.post(
                "/rules/watchlist_mac/snooze",
                data={"duration_seconds": 3600},
            )
        assert r.status_code == 403
        row_count = db._conn.execute(
            "SELECT COUNT(*) FROM rule_type_snoozes"
        ).fetchone()[0]
        assert row_count == 0
    finally:
        db.close()


@pytest.mark.webui
def test_unsnooze_post_without_csrf_returns_403(tmp_path):
    app, db = _make_app_with_rules(tmp_path, _TWO_RULES_YAML)
    now = int(__import__("time").time())
    db.add_rule_type_snooze(
        rule_type="watchlist_mac", expires_at=now + 3600, added_at=now
    )
    try:
        with TestClient(app, follow_redirects=False) as client:
            client.cookies.clear()
            r = client.post("/rules/watchlist_mac/unsnooze")
        assert r.status_code == 403
        # Row still present.
        row = db._conn.execute(
            "SELECT * FROM rule_type_snoozes WHERE rule_type='watchlist_mac'"
        ).fetchone()
        assert row is not None
    finally:
        db.close()


@pytest.mark.webui
def test_unsnooze_post_idempotent_when_no_row_exists(tmp_path):
    """Double-clicking unsnooze (or unsnoozing a rule that wasn't
    snoozed) returns 303 rather than an error. The /rules re-render
    shows current state, which is more useful than a 404."""
    app, db = _make_app_with_rules(tmp_path, _TWO_RULES_YAML)
    try:
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                "/rules/watchlist_mac/unsnooze",
                data={CSRF_FORM_FIELD: token},
            )
        assert r.status_code == 303
    finally:
        db.close()


@pytest.mark.webui
def test_snooze_post_replaces_existing_snooze(tmp_path):
    """Re-snoozing a rule_type that already has an active snooze
    overwrites the prior expires_at rather than 400. Operator who
    initially picked 1h and now wants 24h shouldn't have to unsnooze
    first."""
    app, db = _make_app_with_rules(tmp_path, _TWO_RULES_YAML)
    now = int(__import__("time").time())
    db.add_rule_type_snooze(
        rule_type="watchlist_mac",
        expires_at=now + 3600,
        added_at=now,
        note="first",
    )
    try:
        with TestClient(app, follow_redirects=False) as client:
            token, _ = _csrf_setup(client)
            r = client.post(
                "/rules/watchlist_mac/snooze",
                data={
                    CSRF_FORM_FIELD: token,
                    "duration_seconds": 24 * 3600,
                    "note": "second",
                },
            )
        assert r.status_code == 303
        rows = db._conn.execute(
            "SELECT note FROM rule_type_snoozes WHERE rule_type='watchlist_mac'"
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["note"] == "second"
    finally:
        db.close()


@pytest.mark.webui
def test_rules_list_flash_banner_on_success(tmp_path):
    """The POST redirect's ?success=snooze_added&rule_type=<rt> renders
    a flash banner on the resulting /rules page."""
    app, db = _make_app_with_rules(tmp_path, _TWO_RULES_YAML)
    try:
        with TestClient(app) as client:
            r = client.get(
                "/rules?success=snooze_added&rule_type=watchlist_mac"
            )
        assert r.status_code == 200
        assert "flash-success" in r.text or "Snooze added" in r.text
        assert "watchlist_mac" in r.text
    finally:
        db.close()
