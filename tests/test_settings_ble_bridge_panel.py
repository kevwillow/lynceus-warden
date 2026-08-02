"""Read-only /settings panel for the passive BLE bridge.

tests/ is gitignored — these are NEVER committed (see project memory).

The panel answers two questions the operator otherwise cannot: "is this on,
and is it actually producing anything", and "what would stop it working if I
turned it on". Readiness is therefore evaluated whether or not it is enabled.
"""

from __future__ import annotations

import pytest

from lynceus import ble_bridge_checks
from lynceus.ble_bridge_checks import CHECK_BLEAK_MISSING
from lynceus.config import BleBridgeConfig, Config
from lynceus.db import Database
from lynceus.webui.app import _build_settings_context


@pytest.fixture(autouse=True)
def _bleak_present(monkeypatch):
    """Pin the environment gate to "installed" so these stay config tests.

    The panel composes the config-derived gates with a probe for bleak, which
    is an optional extra. Unpinned, every assertion in this file would depend
    on whether the machine running the suite happens to have it -- green on
    the rig, red on a dev box, for no code reason. Tests that care about the
    absent case re-patch it themselves.
    """
    monkeypatch.setattr(
        ble_bridge_checks.importlib.util, "find_spec", lambda name: object()
    )


def _ctx(config: Config, db: Database) -> dict:
    return _build_settings_context(config, db, {"state": "unknown"})


def _config(**overrides) -> Config:
    base = {"kismet_url": "http://localhost:2501"}
    base.update(overrides)
    return Config(**base)


def test_panel_reports_disabled_by_default(tmp_path):
    db = Database(str(tmp_path / "t.db"))
    try:
        panel = _ctx(_config(), db)["ble_bridge"]
        assert panel["enabled"] is False
        assert panel["adapter"] == BleBridgeConfig().adapter
    finally:
        db.close()


def test_panel_reports_enabled_and_adapter(tmp_path):
    db = Database(str(tmp_path / "t.db"))
    try:
        config = _config(ble_bridge=BleBridgeConfig(enabled=True, adapter="hci0"))
        panel = _ctx(config, db)["ble_bridge"]
        assert panel["enabled"] is True
        assert panel["adapter"] == "hci0"
        assert panel["source_name"] == "ble:hci0"
    finally:
        db.close()


def test_warnings_are_evaluated_even_when_disabled(tmp_path):
    """'What would happen if I turned this on' is the point of the panel."""
    db = Database(str(tmp_path / "t.db"))
    try:
        config = _config(kismet_sources=["hci1"])
        panel = _ctx(config, db)["ble_bridge"]
        assert panel["enabled"] is False
        assert panel["warnings"]
    finally:
        db.close()


def test_clean_config_has_no_warnings(tmp_path):
    db = Database(str(tmp_path / "t.db"))
    try:
        config = _config(kismet_sources=["wlan0", "ble:hci1"])
        assert _ctx(config, db)["ble_bridge"]["warnings"] == ()
    finally:
        db.close()


def test_missing_bleak_surfaces_in_the_panel(tmp_path, monkeypatch):
    """The panel must name the one failure a default install always has.

    Regression for 03a8b1f: with bleak absent and the config otherwise
    clean, the panel used to report nothing wrong and then explain the
    silence as "no Apple device in range, or the adapter being unavailable"
    -- pointing the operator at hardware for a packaging problem.
    """
    monkeypatch.setattr(
        ble_bridge_checks.importlib.util, "find_spec", lambda name: None
    )
    db = Database(str(tmp_path / "t.db"))
    try:
        config = _config(kismet_sources=["wlan0", "ble:hci1"])
        warnings = _ctx(config, db)["ble_bridge"]["warnings"]
        assert {w.code for w in warnings} == {CHECK_BLEAK_MISSING}
        # The remedy has to be actionable on its own -- this panel is the
        # only place many operators will ever read it.
        assert "lynceus[ble]" in warnings[0].remedy
    finally:
        db.close()


def test_bleak_warning_leads_the_list(tmp_path, monkeypatch):
    """Ordering is load-bearing: nothing else matters without a scan library."""
    monkeypatch.setattr(
        ble_bridge_checks.importlib.util, "find_spec", lambda name: None
    )
    db = Database(str(tmp_path / "t.db"))
    try:
        # Deliberately also trips the adapter-contention gate.
        config = _config(kismet_sources=["hci1"])
        warnings = _ctx(config, db)["ble_bridge"]["warnings"]
        assert len(warnings) > 1
        assert warnings[0].code == CHECK_BLEAK_MISSING
    finally:
        db.close()


def test_decoded_total_is_zero_on_an_empty_db(tmp_path):
    db = Database(str(tmp_path / "t.db"))
    try:
        panel = _ctx(_config(), db)["ble_bridge"]
        assert panel["decoded_total"] == 0
        assert panel["class_counts"] == {}
    finally:
        db.close()


def test_decoded_counts_come_from_persisted_device_classes(tmp_path):
    """Only the bridge populates ble_device_class, so this is its evidence."""
    db = Database(str(tmp_path / "t.db"))
    try:
        for mac, cls in (
            ("aa:bb:cc:dd:ee:01", "find_my_separated"),
            ("aa:bb:cc:dd:ee:02", "find_my_separated"),
            ("aa:bb:cc:dd:ee:03", "airpods"),
        ):
            db.upsert_device(
                mac=mac,
                device_type="ble",
                oui_vendor=None,
                is_randomized=0,
                now_ts=2,
                ble_device_class=cls,
            )
        panel = _ctx(_config(), db)["ble_bridge"]
        assert panel["class_counts"]["find_my_separated"] == 2
        assert panel["class_counts"]["airpods"] == 1
        assert panel["decoded_total"] == 3
    finally:
        db.close()


def test_null_class_devices_are_not_counted(tmp_path):
    """Kismet-sourced rows keep NULL permanently — they are not evidence."""
    db = Database(str(tmp_path / "t.db"))
    try:
        db.upsert_device(
            mac="aa:bb:cc:dd:ee:04",
            device_type="ble",
            oui_vendor=None,
            is_randomized=0,
            now_ts=2,
        )
        assert _ctx(_config(), db)["ble_bridge"]["decoded_total"] == 0
    finally:
        db.close()


# ---- rendered HTML (the context tests above never touch the template) ------


def _client(tmp_path, **overrides):
    from fastapi.testclient import TestClient

    from lynceus.webui.app import create_app

    kwargs = {"db_path": str(tmp_path / "panel.db"), "kismet_url": "http://localhost:2501"}
    kwargs.update(overrides)
    config = Config(**kwargs)
    db = Database(config.db_path)
    return TestClient(create_app(config, db)), db


def test_panel_renders_on_settings(tmp_path):
    client, db = _client(tmp_path)
    try:
        html = client.get("/settings").text
        assert "passive BLE bridge" in html
        assert "ble:hci1" in html
    finally:
        db.close()


def test_panel_renders_warnings(tmp_path):
    client, db = _client(tmp_path, kismet_sources=["hci1"])
    try:
        html = client.get("/settings").text
        assert "would stop this working" in html
        assert "Fix:" in html
    finally:
        db.close()


def test_panel_states_it_is_not_a_kismet_decoder(tmp_path):
    """The correction that matters most, pinned where an operator reads it."""
    client, db = _client(tmp_path)
    try:
        assert "not a decoder over Kismet" in client.get("/settings").text
    finally:
        db.close()


def test_unreadable_rules_file_is_reported_not_swallowed(tmp_path):
    """A skipped check must not render as a clean one."""
    bad = tmp_path / "rules.yaml"
    bad.write_text("rules: [ this: is: not: valid\n", encoding="utf-8")
    client, db = _client(tmp_path, rules_path=str(bad))
    try:
        html = client.get("/settings").text
        assert "alert-storm check was not" in html
        assert "incomplete, not clean" in html
    finally:
        db.close()


def test_readable_rules_file_does_not_report_incomplete(tmp_path):
    good = tmp_path / "rules.yaml"
    good.write_text("rules: []\n", encoding="utf-8")
    client, db = _client(tmp_path, rules_path=str(good))
    try:
        assert "incomplete, not clean" not in client.get("/settings").text
    finally:
        db.close()


def test_storm_rule_is_flagged_when_rules_load(tmp_path):
    """The gate the wizard cannot check, checked here."""
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "rules:\n"
        "  - name: raw_vendor\n"
        "    rule_type: watchlist_ble_manufacturer_id\n"
        "    severity: med\n",
        encoding="utf-8",
    )
    client, db = _client(tmp_path, rules_path=str(rules), kismet_sources=["ble:hci1"])
    try:
        assert "entire vendor" in client.get("/settings").text
    finally:
        db.close()
