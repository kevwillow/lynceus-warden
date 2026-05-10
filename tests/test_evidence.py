"""Tests for evidence snapshot capture and retention."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest
from pydantic import ValidationError

from lynceus.config import CaptureConfig, Config
from lynceus.db import Database
from lynceus.evidence import (
    STATE_KEY_LAST_EVIDENCE_PRUNE,
    capture_evidence,
    prune_old_evidence,
)
from lynceus.kismet import FakeKismetClient
from lynceus.poller import STATE_KEY_LAST_POLL, poll_once
from lynceus.rules import Rule, Ruleset

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "kismet_devices.json"

MAC = "aa:bb:cc:dd:ee:ff"
LOC = "lab"


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "lynceus.db")


@pytest.fixture
def db(db_path):
    d = Database(db_path)
    d.ensure_location(LOC, "Lab")
    d.upsert_device(MAC, "wifi", "TestVendor", 0, 1700000000)
    yield d
    d.close()


@pytest.fixture
def alert_id(db):
    return db.add_alert(
        ts=1700000000,
        rule_name="test_rule",
        mac=MAC,
        message="boom",
        severity="high",
    )


def _kismet_record(
    *,
    with_signal_rrd: bool = True,
    with_location: bool = True,
    minute_vec: list[int] | None = None,
    last_signal: int = -50,
    rrd_last_time: int = 1700000100,
) -> dict:
    """Build a minimal-but-realistic Kismet device record."""
    record: dict = {
        "kismet.device.base.macaddr": MAC,
        "kismet.device.base.type": "Wi-Fi AP",
        "kismet.device.base.first_time": 1699999100,
        "kismet.device.base.last_time": 1700000100,
        "kismet.device.base.manuf": "TestVendor",
    }
    if with_signal_rrd:
        if minute_vec is None:
            minute_vec = [-50 - i for i in range(60)]
        record["kismet.device.base.signal"] = {
            "kismet.common.signal.last_signal": last_signal,
            "kismet.common.signal.signal_rrd": {
                "kismet.common.rrd.last_time": rrd_last_time,
                "kismet.common.rrd.minute_vec": minute_vec,
            },
        }
    if with_location:
        record["kismet.device.base.location"] = {
            "kismet.common.location.last": {
                "kismet.common.location.geopoint": [-122.4194, 37.7749],
                "kismet.common.location.alt": 52.0,
                "kismet.common.location.time_sec": 1700000095,
            }
        }
    return record


# ---------------------------- migration / schema ----------------------------


def test_migration_creates_evidence_table(db):
    rows = db._conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='evidence_snapshots'"
    ).fetchall()
    assert len(rows) == 1


def test_migration_creates_indexes(db):
    names = {
        r[0]
        for r in db._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='evidence_snapshots'"
        ).fetchall()
    }
    assert "evidence_alert_id_idx" in names
    assert "evidence_mac_captured_idx" in names


def test_migration_idempotent(db_path):
    Database(db_path).close()
    Database(db_path).close()
    db = Database(db_path)
    rows = db._conn.execute("SELECT COUNT(*) FROM evidence_snapshots").fetchone()[0]
    db.close()
    assert rows == 0


# ------------------------------- capture path -------------------------------


def test_capture_inserts_row_with_full_record(db, alert_id):
    rid = capture_evidence(db, alert_id, MAC, _kismet_record(), now_ts=1700000200)
    assert isinstance(rid, int) and rid > 0
    row = db._conn.execute("SELECT * FROM evidence_snapshots WHERE id = ?", (rid,)).fetchone()
    assert row["alert_id"] == alert_id
    assert row["mac"] == MAC
    assert row["captured_at"] == 1700000200
    decoded = json.loads(row["kismet_record_json"])
    assert decoded["kismet.device.base.macaddr"] == MAC
    assert decoded["kismet.device.base.manuf"] == "TestVendor"


def test_capture_extracts_rssi_history_60_samples(db, alert_id):
    minute_vec = list(range(-50, -110, -1))  # 60 entries
    rid = capture_evidence(
        db, alert_id, MAC, _kismet_record(minute_vec=minute_vec, rrd_last_time=2000)
    )
    row = db._conn.execute(
        "SELECT rssi_history_json FROM evidence_snapshots WHERE id = ?", (rid,)
    ).fetchone()
    history = json.loads(row["rssi_history_json"])
    assert len(history) == 60
    for entry in history:
        assert set(entry.keys()) == {"ts", "rssi"}
    # The most-recent sample (last in reversed iteration order) should carry
    # the rrd_last_time stamp.
    timestamps = [e["ts"] for e in history]
    assert max(timestamps) == 2000
    assert min(timestamps) == 2000 - 59


def test_capture_rssi_history_null_when_signal_rrd_absent(db, alert_id):
    rid = capture_evidence(db, alert_id, MAC, _kismet_record(with_signal_rrd=False))
    row = db._conn.execute(
        "SELECT rssi_history_json FROM evidence_snapshots WHERE id = ?", (rid,)
    ).fetchone()
    assert row["rssi_history_json"] is None


def test_capture_rssi_history_null_when_minute_vec_malformed(db, alert_id):
    record = _kismet_record()
    # Strip out the minute_vec to simulate a malformed signal_rrd block.
    record["kismet.device.base.signal"]["kismet.common.signal.signal_rrd"] = {
        "kismet.common.rrd.last_time": 1700000100
        # minute_vec missing
    }
    rid = capture_evidence(db, alert_id, MAC, record)
    assert rid is not None
    row = db._conn.execute(
        "SELECT rssi_history_json FROM evidence_snapshots WHERE id = ?", (rid,)
    ).fetchone()
    assert row["rssi_history_json"] is None


def test_capture_extracts_gps_when_present(db, alert_id):
    rid = capture_evidence(db, alert_id, MAC, _kismet_record(), store_gps=True)
    row = db._conn.execute(
        "SELECT gps_lat, gps_lon, gps_alt, gps_captured_at FROM evidence_snapshots WHERE id = ?",
        (rid,),
    ).fetchone()
    assert row["gps_lat"] == pytest.approx(37.7749)
    assert row["gps_lon"] == pytest.approx(-122.4194)
    assert row["gps_alt"] == pytest.approx(52.0)
    assert row["gps_captured_at"] == 1700000095


def test_capture_gps_null_when_location_absent(db, alert_id):
    rid = capture_evidence(db, alert_id, MAC, _kismet_record(with_location=False), store_gps=True)
    row = db._conn.execute(
        "SELECT gps_lat, gps_lon, gps_alt, gps_captured_at FROM evidence_snapshots WHERE id = ?",
        (rid,),
    ).fetchone()
    assert row["gps_lat"] is None
    assert row["gps_lon"] is None
    assert row["gps_alt"] is None
    assert row["gps_captured_at"] is None


def test_capture_handles_string_record(db, alert_id, caplog):
    """Malformed kismet_record (string instead of dict): warn, return None."""
    with caplog.at_level(logging.WARNING):
        result = capture_evidence(db, alert_id, MAC, "not a dict")
    assert result is None
    rows = db._conn.execute("SELECT COUNT(*) FROM evidence_snapshots").fetchone()[0]
    assert rows == 0
    assert any(
        r.levelname == "WARNING" and "evidence" in r.getMessage().lower() for r in caplog.records
    )


def test_capture_handles_missing_keys(db, alert_id):
    # Pass a dict without any of the expected fields. capture should still
    # write a row (json.dumps of an empty dict round-trips fine; signal/gps
    # gracefully degrade to NULL).
    rid = capture_evidence(db, alert_id, MAC, {"some_other_key": "value"})
    assert rid is not None
    row = db._conn.execute(
        "SELECT rssi_history_json, gps_lat FROM evidence_snapshots WHERE id = ?",
        (rid,),
    ).fetchone()
    assert row["rssi_history_json"] is None
    assert row["gps_lat"] is None


def test_capture_serializes_non_json_native_with_default_str(db, alert_id):
    """default=str must convert datetime-like values without raising."""
    import datetime as _dt

    record = _kismet_record()
    record["captured_at_external"] = _dt.datetime(2026, 5, 10, 12, 0, 0)
    rid = capture_evidence(db, alert_id, MAC, record)
    assert rid is not None
    row = db._conn.execute(
        "SELECT kismet_record_json FROM evidence_snapshots WHERE id = ?", (rid,)
    ).fetchone()
    decoded = json.loads(row["kismet_record_json"])
    # The datetime was stringified, not raised on.
    assert "captured_at_external" in decoded
    assert isinstance(decoded["captured_at_external"], str)


# -------------------------- foreign-key cascade -----------------------------


def test_foreign_key_cascade_deletes_evidence(db, alert_id):
    rid = capture_evidence(db, alert_id, MAC, _kismet_record())
    assert rid is not None
    with db._conn:
        db._conn.execute("DELETE FROM alerts WHERE id = ?", (alert_id,))
    rows = db._conn.execute(
        "SELECT COUNT(*) FROM evidence_snapshots WHERE alert_id = ?",
        (alert_id,),
    ).fetchone()[0]
    assert rows == 0


# --------------------------- poll-path integration --------------------------


def _ruleset_for_fixture_mac() -> Ruleset:
    return Ruleset(
        rules=[
            Rule(
                name="watch_apple",
                rule_type="watchlist_mac",
                severity="high",
                patterns=["a4:83:e7:11:22:33"],
            )
        ]
    )


def test_poll_path_captures_evidence_on_alert(db_path):
    cfg = Config(
        kismet_fixture_path=str(FIXTURE_PATH),
        db_path=db_path,
        location_id="testloc",
        location_label="Test",
    )
    db = Database(db_path)
    client = FakeKismetClient(str(FIXTURE_PATH))
    poll_once(client, db, cfg, 1700001000, ruleset=_ruleset_for_fixture_mac())
    alerts = db._conn.execute("SELECT id FROM alerts WHERE rule_name = 'watch_apple'").fetchall()
    snapshots = db._conn.execute("SELECT alert_id, mac FROM evidence_snapshots").fetchall()
    db.close()
    assert len(alerts) == 1
    assert len(snapshots) == 1
    assert snapshots[0]["alert_id"] == alerts[0]["id"]
    assert snapshots[0]["mac"] == "a4:83:e7:11:22:33"


def test_one_snapshot_per_alert_via_dedup(db_path):
    """A re-fired alert (within the dedup window) does not yield a 2nd snapshot."""
    cfg = Config(
        kismet_fixture_path=str(FIXTURE_PATH),
        db_path=db_path,
        location_id="testloc",
        location_label="Test",
    )
    db = Database(db_path)
    client = FakeKismetClient(str(FIXTURE_PATH))

    poll_once(client, db, cfg, 1700001000, ruleset=_ruleset_for_fixture_mac())
    # Reset the poll state so the same fixture devices are re-emitted on the
    # next call. Without this, get_devices_since(1700001000) returns nothing
    # and the dedup path is never exercised.
    db.set_state(STATE_KEY_LAST_POLL, "0")
    poll_once(client, db, cfg, 1700001100, ruleset=_ruleset_for_fixture_mac())

    alerts = db._conn.execute("SELECT id FROM alerts WHERE rule_name = 'watch_apple'").fetchall()
    snapshots = db._conn.execute("SELECT id FROM evidence_snapshots").fetchall()
    db.close()
    assert len(alerts) == 1
    assert len(snapshots) == 1


def test_capture_disabled_in_poll_path_writes_no_snapshots(db_path):
    cfg = Config(
        kismet_fixture_path=str(FIXTURE_PATH),
        db_path=db_path,
        location_id="testloc",
        location_label="Test",
        evidence_capture_enabled=False,
    )
    db = Database(db_path)
    client = FakeKismetClient(str(FIXTURE_PATH))
    poll_once(client, db, cfg, 1700001000, ruleset=_ruleset_for_fixture_mac())
    alerts = db._conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    snapshots = db._conn.execute("SELECT COUNT(*) FROM evidence_snapshots").fetchone()[0]
    db.close()
    assert alerts >= 1
    assert snapshots == 0


# ------------------------------ retention prune -----------------------------


def test_prune_deletes_only_old_rows(db, alert_id):
    new_id = capture_evidence(db, alert_id, MAC, _kismet_record(), now_ts=1700000000)
    old_id = capture_evidence(db, alert_id, MAC, _kismet_record(), now_ts=1700000000)
    # Backdate the second row to 100 days ago.
    with db._conn:
        db._conn.execute(
            "UPDATE evidence_snapshots SET captured_at = ? WHERE id = ?",
            (1700000000 - 100 * 86400, old_id),
        )
    deleted, oldest = prune_old_evidence(db, retention_days=90, now_ts=1700000000)
    assert deleted == 1
    assert oldest == 1700000000
    remaining = db._conn.execute("SELECT id FROM evidence_snapshots ORDER BY id").fetchall()
    assert [r["id"] for r in remaining] == [new_id]


def test_prune_returns_zero_when_nothing_to_delete(db, alert_id):
    capture_evidence(db, alert_id, MAC, _kismet_record(), now_ts=1700000000)
    deleted, oldest = prune_old_evidence(db, retention_days=90, now_ts=1700000000)
    assert deleted == 0
    assert oldest == 1700000000


def test_prune_returns_none_oldest_when_table_empty(db):
    deleted, oldest = prune_old_evidence(db, retention_days=90, now_ts=1700000000)
    assert deleted == 0
    assert oldest is None


def test_prune_logs_at_info_when_runs(db, alert_id, caplog):
    capture_evidence(db, alert_id, MAC, _kismet_record(), now_ts=1700000000)
    with caplog.at_level(logging.INFO, logger="lynceus.evidence"):
        prune_old_evidence(db, retention_days=90, now_ts=1700000000)
    msgs = [r.getMessage() for r in caplog.records]
    assert any("Pruned" in m and "evidence" in m for m in msgs)


def test_poll_path_runs_prune_after_24h(db_path, monkeypatch):
    cfg = Config(
        kismet_fixture_path=str(FIXTURE_PATH),
        db_path=db_path,
        location_id="testloc",
        location_label="Test",
    )
    db = Database(db_path)
    client = FakeKismetClient(str(FIXTURE_PATH))
    poll_once(client, db, cfg, 1700001000, ruleset=_ruleset_for_fixture_mac())
    # First poll initialises the prune-state.
    assert db.get_state(STATE_KEY_LAST_EVIDENCE_PRUNE) == "1700001000"
    # Second poll inside the 24h window: state should not advance.
    db.set_state(STATE_KEY_LAST_POLL, "0")
    poll_once(client, db, cfg, 1700001500, ruleset=_ruleset_for_fixture_mac())
    assert db.get_state(STATE_KEY_LAST_EVIDENCE_PRUNE) == "1700001000"
    # After 24h+: state advances.
    db.set_state(STATE_KEY_LAST_POLL, "0")
    poll_once(client, db, cfg, 1700001000 + 86401, ruleset=_ruleset_for_fixture_mac())
    assert db.get_state(STATE_KEY_LAST_EVIDENCE_PRUNE) == str(1700001000 + 86401)
    db.close()


# --------------------------------- config -----------------------------------


def test_config_defaults():
    cfg = Config()
    assert cfg.evidence_capture_enabled is True
    assert cfg.evidence_retention_days == 90


def test_config_rejects_zero_retention():
    with pytest.raises(ValidationError):
        Config(evidence_retention_days=0)


def test_config_rejects_negative_retention():
    with pytest.raises(ValidationError):
        Config(evidence_retention_days=-1)


def test_config_rejects_too_large_retention():
    with pytest.raises(ValidationError):
        Config(evidence_retention_days=3651)


def test_config_accepts_boundary_values():
    assert Config(evidence_retention_days=1).evidence_retention_days == 1
    assert Config(evidence_retention_days=3650).evidence_retention_days == 3650


# ---------------------------- regression (rc3) ------------------------------


def test_capture_circular_record_does_not_raise(db, alert_id, caplog):
    """REGRESSION: capture_evidence with a circular dict must NOT raise.

    json.dumps on a circular reference raises ``ValueError`` (CPython encodes
    it as "Circular reference detected"). Without the try/except guard around
    the capture body, that exception would escape the function — which in the
    poll loop means the *next* hit in the same observation never gets its
    add_alert attempted, and the evidence write itself is silently lost.

    The guarantee here is: capture_evidence catches its own failures so the
    alert path can never be derailed by malformed Kismet input. Returning
    None (rather than raising) is part of the contract.
    """
    bad: dict = {"foo": "bar"}
    bad["self"] = bad  # circular

    with caplog.at_level(logging.WARNING):
        result = capture_evidence(db, alert_id, MAC, bad)

    assert result is None
    # The pre-existing alert is still in the DB (capture must not roll it back):
    assert (
        db._conn.execute("SELECT COUNT(*) FROM alerts WHERE id = ?", (alert_id,)).fetchone()[0] == 1
    )
    # No evidence row was written for that alert:
    assert (
        db._conn.execute(
            "SELECT COUNT(*) FROM evidence_snapshots WHERE alert_id = ?",
            (alert_id,),
        ).fetchone()[0]
        == 0
    )
    # A WARNING (not ERROR) was logged.
    assert any(r.levelname == "WARNING" for r in caplog.records)
    assert not any(r.levelname == "ERROR" for r in caplog.records)


# ----------------------- redaction per capture toggle -----------------------


def _wifi_record_with_probes() -> dict:
    """Wi-Fi AP record carrying the probed-SSID nest the toggle gates."""
    record = _kismet_record()
    record["dot11.device"] = {
        "dot11.device.last_probed_ssid_csum_map": {
            "0xdeadbeef": {"dot11.probedssid.ssid": "HomeNet-5G"},
            "0xcafef00d": {"dot11.probedssid.ssid": "AirportFreeWiFi"},
        }
    }
    return record


def _ble_record_with_friendly_names() -> dict:
    """BLE record carrying the friendly-name fields the toggle gates."""
    return {
        "kismet.device.base.macaddr": "06:aa:bb:cc:dd:ee",
        "kismet.device.base.type": "BTLE",
        "kismet.device.base.first_time": 1699999300,
        "kismet.device.base.last_time": 1700000300,
        "kismet.device.base.name": "John's iPhone",
        "btle": {
            "btle.device.name": "John's iPhone",
            "btle.advertised.name": "John's iPhone (BLE adv)",
        },
    }


def test_capture_redacts_probe_ssids_when_toggle_disabled(db, alert_id):
    record = _wifi_record_with_probes()
    rid = capture_evidence(db, alert_id, MAC, record, capture=CaptureConfig(probe_ssids=False))
    assert rid is not None
    row = db._conn.execute(
        "SELECT kismet_record_json FROM evidence_snapshots WHERE id = ?", (rid,)
    ).fetchone()
    blob = row["kismet_record_json"]
    # The csum-map key and the nested per-record SSID key must both be gone.
    assert "dot11.device.last_probed_ssid_csum_map" not in blob
    assert "dot11.probedssid.ssid" not in blob
    assert "HomeNet-5G" not in blob
    assert "AirportFreeWiFi" not in blob


def test_capture_redacts_ble_friendly_names_when_toggle_disabled(db, alert_id):
    record = _ble_record_with_friendly_names()
    rid = capture_evidence(
        db,
        alert_id,
        MAC,
        record,
        capture=CaptureConfig(probe_ssids=False, ble_friendly_names=False),
    )
    assert rid is not None
    row = db._conn.execute(
        "SELECT kismet_record_json FROM evidence_snapshots WHERE id = ?", (rid,)
    ).fetchone()
    blob = row["kismet_record_json"]
    decoded = json.loads(blob)
    assert "kismet.device.base.name" not in decoded
    assert "btle.device.name" not in blob
    assert "btle.advertised.name" not in blob
    assert "John's iPhone" not in blob


def test_capture_does_not_mutate_upstream_record(db, alert_id):
    record = _wifi_record_with_probes()
    record_before = json.dumps(record, sort_keys=True)
    capture_evidence(db, alert_id, MAC, record, capture=CaptureConfig(probe_ssids=False))
    record_after = json.dumps(record, sort_keys=True)
    assert record_before == record_after


def test_capture_with_both_toggles_on_keeps_all_fields(db, alert_id):
    record = _wifi_record_with_probes()
    rid = capture_evidence(
        db,
        alert_id,
        MAC,
        record,
        capture=CaptureConfig(probe_ssids=True, ble_friendly_names=True),
    )
    assert rid is not None
    row = db._conn.execute(
        "SELECT kismet_record_json FROM evidence_snapshots WHERE id = ?", (rid,)
    ).fetchone()
    decoded = json.loads(row["kismet_record_json"])
    assert "dot11.device" in decoded
    assert "dot11.device.last_probed_ssid_csum_map" in decoded["dot11.device"]
    assert (
        decoded["dot11.device"]["dot11.device.last_probed_ssid_csum_map"]["0xdeadbeef"][
            "dot11.probedssid.ssid"
        ]
        == "HomeNet-5G"
    )


def test_capture_keeps_wifi_ssid_even_when_ble_names_disabled(db, alert_id):
    """kismet.device.base.name is the SSID for Wi-Fi devices; BLE-name
    redaction must not strip it for non-BLE device types."""
    record = _kismet_record()
    record["kismet.device.base.name"] = "HomeNet"
    rid = capture_evidence(
        db,
        alert_id,
        MAC,
        record,
        capture=CaptureConfig(probe_ssids=False, ble_friendly_names=False),
    )
    assert rid is not None
    row = db._conn.execute(
        "SELECT kismet_record_json FROM evidence_snapshots WHERE id = ?", (rid,)
    ).fetchone()
    decoded = json.loads(row["kismet_record_json"])
    assert decoded.get("kismet.device.base.name") == "HomeNet"


# --------------------------- evidence_store_gps -----------------------------


def test_capture_omits_gps_when_evidence_store_gps_false(db, alert_id):
    """Default behaviour: GPS columns stay NULL even when the record has
    a location block. The geopoint Kismet emits is the OPERATOR's GPS
    fix; storing it by default would be a privacy regression."""
    rid = capture_evidence(db, alert_id, MAC, _kismet_record(), store_gps=False)
    assert rid is not None
    row = db._conn.execute(
        "SELECT gps_lat, gps_lon, gps_alt, gps_captured_at FROM evidence_snapshots WHERE id = ?",
        (rid,),
    ).fetchone()
    assert row["gps_lat"] is None
    assert row["gps_lon"] is None
    assert row["gps_alt"] is None
    assert row["gps_captured_at"] is None


def test_capture_includes_gps_when_evidence_store_gps_true(db, alert_id):
    rid = capture_evidence(db, alert_id, MAC, _kismet_record(), store_gps=True)
    assert rid is not None
    row = db._conn.execute(
        "SELECT gps_lat, gps_lon, gps_alt, gps_captured_at FROM evidence_snapshots WHERE id = ?",
        (rid,),
    ).fetchone()
    assert row["gps_lat"] == pytest.approx(37.7749)
    assert row["gps_lon"] == pytest.approx(-122.4194)
    assert row["gps_alt"] == pytest.approx(52.0)
    assert row["gps_captured_at"] == 1700000095


def test_config_evidence_store_gps_defaults_false():
    assert Config().evidence_store_gps is False


def test_poll_path_omits_gps_by_default(db_path):
    """Integration: even with a fixture that has location data, the
    poll path must not populate GPS columns when evidence_store_gps is
    at its default (False)."""
    cfg = Config(
        kismet_fixture_path=str(FIXTURE_PATH),
        db_path=db_path,
        location_id="testloc",
        location_label="Test",
    )
    db = Database(db_path)
    client = FakeKismetClient(str(FIXTURE_PATH))
    poll_once(client, db, cfg, 1700001000, ruleset=_ruleset_for_fixture_mac())
    rows = db._conn.execute(
        "SELECT gps_lat, gps_lon, gps_alt, gps_captured_at FROM evidence_snapshots"
    ).fetchall()
    db.close()
    assert len(rows) >= 1
    for row in rows:
        assert row["gps_lat"] is None
        assert row["gps_lon"] is None
        assert row["gps_alt"] is None
        assert row["gps_captured_at"] is None


# ----------------------- bytes-safe JSON serialization ---------------------


def test_capture_handles_bytes_in_record(db, alert_id):
    """REGRESSION: a raw bytes field anywhere in a Kismet record must
    not lose the entire snapshot. json.dumps' default=str path is *not*
    consulted for bytes — the encoder rejects them outright with
    TypeError before falling through. The custom default hex-encodes
    bytes so the snapshot survives."""
    record = _kismet_record()
    record["dot11.device.bssid_bytes"] = b"\xff\xfe\x12\x34"
    rid = capture_evidence(db, alert_id, MAC, record)
    assert rid is not None
    row = db._conn.execute(
        "SELECT kismet_record_json FROM evidence_snapshots WHERE id = ?", (rid,)
    ).fetchone()
    decoded = json.loads(row["kismet_record_json"])
    assert decoded["dot11.device.bssid_bytes"] == "fffe1234"


def test_capture_handles_bytearray_in_record(db, alert_id):
    record = _kismet_record()
    record["dot11.ssid.raw"] = bytearray(b"\x00\x01\x02\xff")
    rid = capture_evidence(db, alert_id, MAC, record)
    assert rid is not None
    row = db._conn.execute(
        "SELECT kismet_record_json FROM evidence_snapshots WHERE id = ?", (rid,)
    ).fetchone()
    decoded = json.loads(row["kismet_record_json"])
    assert decoded["dot11.ssid.raw"] == "000102ff"


# ----------------------- non-finite float sanitization ---------------------


def _reject_constant(c):
    raise ValueError(f"non-finite token in JSON: {c}")


def _strict_loads(blob: str):
    """json.loads that rejects Infinity / NaN tokens.

    Default json.loads accepts non-standard "Infinity"/"NaN" tokens and
    decodes them into Python floats — which is exactly what FOIA-export
    or journalist-tool consumers using strict JSON parsers will choke
    on. parse_constant is invoked for those tokens; raising here turns
    them into a hard test failure if they ever leak through."""
    return json.loads(blob, parse_constant=_reject_constant)


def test_capture_handles_inf_in_rrd(db, alert_id):
    """REGRESSION: inf in a signal RRD slot must serialize as null,
    not the non-standard "Infinity" token. The captured row must
    round-trip through a strict JSON parser."""
    record = _kismet_record(minute_vec=[float("inf"), -50, -55] + [-60] * 57)
    rid = capture_evidence(db, alert_id, MAC, record)
    assert rid is not None
    row = db._conn.execute(
        "SELECT kismet_record_json, rssi_history_json FROM evidence_snapshots WHERE id = ?",
        (rid,),
    ).fetchone()
    # Strict round-trip — Infinity / NaN tokens would raise here.
    decoded = _strict_loads(row["kismet_record_json"])
    history = _strict_loads(row["rssi_history_json"])
    # The inf value is now null in both encodings.
    minute_vec = decoded["kismet.device.base.signal"]["kismet.common.signal.signal_rrd"][
        "kismet.common.rrd.minute_vec"
    ]
    assert None in minute_vec
    assert any(entry["rssi"] is None for entry in history)


def test_capture_handles_nan_in_signal(db, alert_id):
    record = _kismet_record()
    record["kismet.device.base.signal"]["kismet.common.signal.last_signal"] = float("nan")
    rid = capture_evidence(db, alert_id, MAC, record)
    assert rid is not None
    row = db._conn.execute(
        "SELECT kismet_record_json FROM evidence_snapshots WHERE id = ?", (rid,)
    ).fetchone()
    decoded = _strict_loads(row["kismet_record_json"])
    assert decoded["kismet.device.base.signal"]["kismet.common.signal.last_signal"] is None
