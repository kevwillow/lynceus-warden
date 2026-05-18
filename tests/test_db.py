"""Tests for the SQLite persistence layer."""

import logging
import os
import sqlite3
import stat
import sys

import pytest

from lynceus.db import Database

MAC = "aa:bb:cc:dd:ee:ff"
LOC = "lab"


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "lynceus.db")


@pytest.fixture
def db(db_path):
    d = Database(db_path)
    yield d
    d.close()


def _seed(db: Database) -> None:
    db.ensure_location(LOC, "Lab")
    db.upsert_device(MAC, "wifi", "Acme", 0, 100)


def test_migration_idempotent(db_path):
    first = Database(db_path)
    count_first = first._conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0]
    first.close()
    second = Database(db_path)
    count_second = second._conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0]
    second.close()
    assert count_first >= 1
    assert count_first == count_second


def test_migration_007_sql_idempotent_at_statement_level(db_path):
    """Replay 007's SQL DIRECTLY via executescript, bypassing the
    runner's version-tracking short-circuit. Guards the recovery path
    on a DB where 007's objects were created but the corresponding
    schema_migrations row was never written (interrupted runner, crash
    mid-script). Without IF NOT EXISTS the second apply raises
    sqlite3.OperationalError 'table evidence_snapshots already exists'
    on the first CREATE TABLE, or analogous errors on the CREATE INDEX
    statements that follow.

    Narrow M-series hardening — the broader migration-runner atomicity
    work (L-MIG-1/7) stays deferred to v0.4.1."""
    db = Database(db_path)
    try:
        sql_path = db._migrations_dir / "007_evidence_snapshots.sql"
        sql = sql_path.read_text(encoding="utf-8")
        # First apply already happened on Database.__init__; the replay
        # below is the second-apply that must be a no-op.
        db._conn.executescript(sql)
    finally:
        db.close()


def test_foreign_keys_enforced(db):
    db.ensure_location(LOC, "Lab")
    with pytest.raises(sqlite3.IntegrityError):
        db.insert_sighting("11:22:33:44:55:66", 100, -50, "TestSSID", LOC)


def test_invalid_device_type_rejected(db):
    with pytest.raises(sqlite3.IntegrityError):
        db.upsert_device(MAC, "cellular", None, 0, 100)


def test_invalid_severity_rejected(db):
    with pytest.raises(sqlite3.IntegrityError):
        db.add_alert(100, "rule_x", None, "boom", "critical")


def test_upsert_creates_then_updates(db):
    db.upsert_device(MAC, "wifi", "Acme", 0, 100)
    db.upsert_device(MAC, "wifi", "Acme", 0, 250)
    dev = db.get_device(MAC)
    assert dev is not None
    assert dev["sighting_count"] == 2
    assert dev["first_seen"] == 100
    assert dev["last_seen"] == 250


def test_sighting_ids_monotonic(db):
    _seed(db)
    ids = [db.insert_sighting(MAC, 100 + i, None, None, LOC) for i in range(5)]
    assert len(ids) == 5
    assert all(b > a for a, b in zip(ids, ids[1:], strict=False))


def test_list_recent_sightings_boundary(db):
    _seed(db)
    for ts in (100, 200, 300):
        db.insert_sighting(MAC, ts, None, None, LOC)
    rows = db.list_recent_sightings(200)
    assert [r["ts"] for r in rows] == [200, 300]


def test_timestamps_exact(db):
    _seed(db)
    db.insert_sighting(MAC, 1234567890, None, None, LOC)
    rows = db.list_recent_sightings(0)
    ts_values = [r["ts"] for r in rows]
    assert 1234567890 in ts_values
    for ts in ts_values:
        assert isinstance(ts, int)
        assert not isinstance(ts, bool)


def test_wal_mode_active(db):
    mode = db._conn.execute("PRAGMA journal_mode").fetchone()[0]
    assert mode.lower() == "wal"


def test_context_manager_closes(db_path):
    with Database(db_path) as d:
        d.ensure_location(LOC, "Lab")
    with pytest.raises(sqlite3.ProgrammingError):
        d.get_device(MAC)


def test_get_recent_alert_no_match_returns_none(db):
    _seed(db)
    db.add_alert(ts=500, rule_name="rule_a", mac=MAC, message="boom", severity="high")
    assert db.get_recent_alert_for_rule_and_mac("rule_b", MAC, 0) is None


def test_get_recent_alert_match_within_window(db):
    _seed(db)
    db.add_alert(ts=500, rule_name="rule_a", mac=MAC, message="boom", severity="high")
    row = db.get_recent_alert_for_rule_and_mac("rule_a", MAC, since_ts=400)
    assert row is not None
    assert row["rule_name"] == "rule_a"
    assert row["mac"] == MAC
    assert row["message"] == "boom"
    assert row["severity"] == "high"


def test_get_recent_alert_outside_window_returns_none(db):
    _seed(db)
    db.add_alert(ts=500, rule_name="rule_a", mac=MAC, message="boom", severity="high")
    assert db.get_recent_alert_for_rule_and_mac("rule_a", MAC, since_ts=600) is None


def test_get_recent_alert_null_mac(db):
    db.add_alert(ts=500, rule_name="rule_a", mac=None, message="systemic", severity="med")
    row = db.get_recent_alert_for_rule_and_mac("rule_a", None, since_ts=0)
    assert row is not None
    assert row["mac"] is None
    assert row["rule_name"] == "rule_a"


def test_migrations_dir_found_via_package_resources(db):
    assert db._migrations_dir.is_dir()
    assert (db._migrations_dir / "001_initial.sql").exists()
    assert any("lynceus" in part for part in db._migrations_dir.parts)


def test_migrations_dir_lists_both_files(db):
    names = sorted(p.name for p in db._migrations_dir.glob("*.sql"))
    assert names == [
        "001_initial.sql",
        "002_poller_state.sql",
        "003_alert_actions.sql",
        "004_watchlist_metadata.sql",
        "005_alert_watchlist_link.sql",
        "006_tier1_capture.sql",
        "007_evidence_snapshots.sql",
        "008_evidence_captured_at_index.sql",
        "009_evidence_do_not_publish.sql",
        "010_normalize_watchlist_patterns.sql",
        "011_watchlist_mac_range.sql",
        "012_import_runs.sql",
        "013_pattern_type_extension.sql",
        "014_devices_remote_id.sql",
        "015_alerts_rule_type.sql",
        "016_alerts_note.sql",
    ]


def test_healthcheck_returns_expected_keys_and_types(db):
    health = db.healthcheck()
    assert set(health.keys()) == {
        "schema_version",
        "device_count",
        "alert_count",
        "unacked_alert_count",
    }
    for value in health.values():
        assert isinstance(value, int)
    assert health["schema_version"] > 0


def test_healthcheck_counts_reflect_writes(db):
    db.ensure_location(LOC, "Lab")
    db.upsert_device("aa:bb:cc:dd:ee:01", "wifi", "Acme", 0, 100)
    db.upsert_device("aa:bb:cc:dd:ee:02", "wifi", "Acme", 0, 100)
    db.insert_sighting("aa:bb:cc:dd:ee:01", 100, -50, "TestSSID", LOC)
    acked_id = db.add_alert(ts=200, rule_name="rule_a", mac=None, message="acked", severity="high")
    db.add_alert(ts=201, rule_name="rule_b", mac=None, message="unacked", severity="high")
    with db._conn:
        db._conn.execute("UPDATE alerts SET acknowledged = 1 WHERE id = ?", (acked_id,))

    health = db.healthcheck()
    assert health["device_count"] == 2
    assert health["alert_count"] == 2
    assert health["unacked_alert_count"] == 1


# ---------------------------------------------------------------------------
# Read-only query methods used by the web UI.
# ---------------------------------------------------------------------------


def _ack(db: Database, alert_id: int) -> None:
    with db._conn:
        db._conn.execute("UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,))


def test_list_alerts_empty(db):
    assert db.list_alerts() == []


def test_list_alerts_orders_by_ts_desc(db):
    db.add_alert(ts=100, rule_name="r1", mac=None, message="oldest", severity="low")
    db.add_alert(ts=300, rule_name="r2", mac=None, message="newest", severity="low")
    db.add_alert(ts=200, rule_name="r3", mac=None, message="middle", severity="low")
    rows = db.list_alerts()
    assert [r["message"] for r in rows] == ["newest", "middle", "oldest"]


def test_list_alerts_filter_by_severity_validates(db):
    with pytest.raises(ValueError):
        db.list_alerts(severity="critical")


def test_list_alerts_filter_by_acknowledged(db):
    a1 = db.add_alert(ts=100, rule_name="r", mac=None, message="acked", severity="low")
    db.add_alert(ts=200, rule_name="r", mac=None, message="unacked", severity="low")
    _ack(db, a1)
    acked = db.list_alerts(acknowledged=True)
    assert [r["message"] for r in acked] == ["acked"]
    unacked = db.list_alerts(acknowledged=False)
    assert [r["message"] for r in unacked] == ["unacked"]


def test_list_alerts_pagination_offset(db):
    for i in range(5):
        db.add_alert(ts=100 + i, rule_name="r", mac=None, message=f"m{i}", severity="low")
    page1 = db.list_alerts(limit=2, offset=0)
    page2 = db.list_alerts(limit=2, offset=2)
    page3 = db.list_alerts(limit=2, offset=4)
    assert [r["message"] for r in page1] == ["m4", "m3"]
    assert [r["message"] for r in page2] == ["m2", "m1"]
    assert [r["message"] for r in page3] == ["m0"]


def test_list_alerts_limit_out_of_bounds_raises(db):
    with pytest.raises(ValueError):
        db.list_alerts(limit=0)
    with pytest.raises(ValueError):
        db.list_alerts(limit=1001)
    with pytest.raises(ValueError):
        db.list_alerts(offset=-1)


def test_count_alerts_matches_list(db):
    for i in range(7):
        db.add_alert(ts=100 + i, rule_name="r", mac=None, message=f"m{i}", severity="high")
    db.add_alert(ts=200, rule_name="r", mac=None, message="low", severity="low")
    assert db.count_alerts() == 8
    assert db.count_alerts(severity="high") == 7
    assert db.count_alerts(severity="low") == 1
    with pytest.raises(ValueError):
        db.count_alerts(severity="critical")


def test_get_alert_returns_none_for_missing(db):
    assert db.get_alert(99999) is None


def test_get_alert_includes_device_sub_dict(db):
    db.upsert_device(MAC, "wifi", "Acme", 0, 100)
    aid = db.add_alert(ts=500, rule_name="r", mac=MAC, message="m", severity="med")
    alert = db.get_alert(aid)
    assert alert is not None
    assert alert["mac"] == MAC
    assert alert["device"] is not None
    assert alert["device"]["mac"] == MAC
    assert alert["device"]["oui_vendor"] == "Acme"


def test_get_alert_with_null_mac_has_no_device(db):
    aid = db.add_alert(ts=500, rule_name="r", mac=None, message="m", severity="med")
    alert = db.get_alert(aid)
    assert alert is not None
    assert alert["mac"] is None
    assert alert["device"] is None


def test_add_alert_persists_rule_type(db):
    db.upsert_device(MAC, "wifi", "Acme", 0, 100)
    aid = db.add_alert(
        ts=500,
        rule_name="r",
        mac=MAC,
        message="m",
        severity="med",
        rule_type="watchlist_mac",
    )
    alert = db.get_alert(aid)
    assert alert is not None
    assert alert["rule_type"] == "watchlist_mac"


def test_add_alert_rule_type_defaults_to_null(db):
    # Backward-compat: callers that don't pass rule_type (e.g. legacy
    # tests, or any code path that pre-dates migration 015) still
    # work. The column stays NULL, which the /alerts filter treats
    # as "unknown type" and excludes from any type=<specific> filter.
    db.upsert_device(MAC, "wifi", "Acme", 0, 100)
    aid = db.add_alert(ts=500, rule_name="r", mac=MAC, message="m", severity="med")
    alert = db.get_alert(aid)
    assert alert is not None
    assert alert["rule_type"] is None


def test_add_alert_rule_type_round_trips_all_literals(db):
    # Every RuleType literal currently emitted by the daemon round-
    # trips byte-identical through the column. New literals added to
    # rules.RuleType in the future are expected to land in this list
    # so any drift surfaces here.
    expected_types = [
        "watchlist_mac",
        "watchlist_oui",
        "watchlist_ssid",
        "watchlist_mac_range",
        "ble_uuid",
        "watchlist_ble_manufacturer_id",
        "watchlist_drone_id_prefix",
        "new_non_randomized_device",
    ]
    db.upsert_device(MAC, "wifi", "Acme", 0, 100)
    ids = {}
    for i, rt in enumerate(expected_types):
        ids[rt] = db.add_alert(
            ts=500 + i,
            rule_name=f"r_{rt}",
            mac=MAC,
            message=f"m_{rt}",
            severity="low",
            rule_type=rt,
        )
    for rt, aid in ids.items():
        alert = db.get_alert(aid)
        assert alert is not None
        assert alert["rule_type"] == rt


def test_list_devices_orders_by_last_seen_desc(db):
    db.upsert_device("aa:bb:cc:dd:ee:01", "wifi", "Acme", 0, 100)
    db.upsert_device("aa:bb:cc:dd:ee:02", "wifi", "Acme", 0, 300)
    db.upsert_device("aa:bb:cc:dd:ee:03", "wifi", "Acme", 0, 200)
    rows = db.list_devices()
    assert [r["mac"] for r in rows] == [
        "aa:bb:cc:dd:ee:02",
        "aa:bb:cc:dd:ee:03",
        "aa:bb:cc:dd:ee:01",
    ]


def test_list_devices_filter_by_type_validates(db):
    with pytest.raises(ValueError):
        db.list_devices(device_type="cellular")


def test_list_devices_filter_by_randomized(db):
    db.upsert_device("aa:bb:cc:dd:ee:01", "wifi", "Acme", 0, 100)
    db.upsert_device("aa:bb:cc:dd:ee:02", "wifi", "Acme", 1, 100)
    rand = db.list_devices(randomized=True)
    not_rand = db.list_devices(randomized=False)
    assert [r["mac"] for r in rand] == ["aa:bb:cc:dd:ee:02"]
    assert [r["mac"] for r in not_rand] == ["aa:bb:cc:dd:ee:01"]


def test_count_devices_matches_list(db):
    db.upsert_device("aa:bb:cc:dd:ee:01", "wifi", "Acme", 0, 100)
    db.upsert_device("aa:bb:cc:dd:ee:02", "ble", "Acme", 0, 100)
    assert db.count_devices() == 2
    assert db.count_devices(device_type="wifi") == 1
    assert db.count_devices(device_type="ble") == 1
    with pytest.raises(ValueError):
        db.count_devices(device_type="cellular")


def test_get_device_with_sightings_returns_none_for_missing(db):
    assert db.get_device_with_sightings("aa:bb:cc:dd:ee:99") is None


def test_get_device_with_sightings_orders_desc(db):
    _seed(db)
    for ts in (100, 300, 200):
        db.insert_sighting(MAC, ts, None, None, LOC)
    result = db.get_device_with_sightings(MAC)
    assert result is not None
    assert [s["ts"] for s in result["sightings"]] == [300, 200, 100]
    assert result["device"]["mac"] == MAC


def test_get_device_with_sightings_respects_limit(db):
    _seed(db)
    for i in range(10):
        db.insert_sighting(MAC, 100 + i, None, None, LOC)
    result = db.get_device_with_sightings(MAC, sighting_limit=3)
    assert result is not None
    assert len(result["sightings"]) == 3
    with pytest.raises(ValueError):
        db.get_device_with_sightings(MAC, sighting_limit=0)
    with pytest.raises(ValueError):
        db.get_device_with_sightings(MAC, sighting_limit=1001)


def test_list_watchlist_orders_by_type_then_pattern(db):
    with db._conn:
        db._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
            "VALUES (?, ?, ?, ?)",
            ("HomeNet", "ssid", "low", "trusted ssid"),
        )
        db._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
            "VALUES (?, ?, ?, ?)",
            ("aa:bb:cc:dd:ee:ff", "mac", "high", None),
        )
        db._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
            "VALUES (?, ?, ?, ?)",
            ("00:13:37", "oui", "high", "hak5"),
        )
        db._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
            "VALUES (?, ?, ?, ?)",
            ("11:22:33:44:55:66", "mac", "med", None),
        )
    rows = db.list_watchlist()
    assert [(r["pattern_type"], r["pattern"]) for r in rows] == [
        ("mac", "11:22:33:44:55:66"),
        ("mac", "aa:bb:cc:dd:ee:ff"),
        ("oui", "00:13:37"),
        ("ssid", "HomeNet"),
    ]


# ---------------------------------------------------------------------------
# Migration 003: alert_actions, ack/unack mutations, stats, alert filters.
# ---------------------------------------------------------------------------


def test_migration_003_creates_alert_actions(db):
    cols = db._conn.execute("PRAGMA table_info(alert_actions)").fetchall()
    by_name = {row[1]: row for row in cols}
    assert set(by_name) == {"id", "alert_id", "action", "ts", "actor", "note"}
    assert by_name["alert_id"][3] == 1
    assert by_name["action"][3] == 1
    assert by_name["ts"][3] == 1
    assert by_name["actor"][3] == 1
    assert by_name["note"][3] == 0
    with pytest.raises(sqlite3.IntegrityError):
        with db._conn:
            db._conn.execute(
                "INSERT INTO alert_actions(alert_id, action, ts, actor) VALUES (?, ?, ?, ?)",
                (1, "delete", 100, "tester"),
            )


def test_acknowledge_alert_flips_flag_and_logs_action(db):
    aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
    ok = db.acknowledge_alert(aid, actor="1.2.3.4", note="checked", ts=200)
    assert ok is True
    alert = db.get_alert(aid)
    assert alert["acknowledged"] == 1
    actions = db.list_alert_actions(aid)
    assert len(actions) == 1
    assert actions[0]["action"] == "ack"
    assert actions[0]["actor"] == "1.2.3.4"
    assert actions[0]["note"] == "checked"
    assert actions[0]["ts"] == 200


def test_acknowledge_alert_idempotent_writes_second_action(db):
    aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
    assert db.acknowledge_alert(aid, actor="ip", ts=200) is True
    assert db.acknowledge_alert(aid, actor="ip", ts=300) is True
    actions = db.list_alert_actions(aid)
    assert len(actions) == 2
    assert all(a["action"] == "ack" for a in actions)
    assert db.get_alert(aid)["acknowledged"] == 1


def test_acknowledge_alert_returns_false_for_missing_id(db):
    assert db.acknowledge_alert(99999, actor="ip", ts=100) is False
    rows = db._conn.execute("SELECT COUNT(*) FROM alert_actions").fetchone()[0]
    assert rows == 0


def test_acknowledge_alert_validates_actor_nonempty(db):
    aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
    with pytest.raises(ValueError):
        db.acknowledge_alert(aid, actor="   ", ts=200)
    with pytest.raises(ValueError):
        db.acknowledge_alert(aid, actor="", ts=200)


def test_acknowledge_alert_validates_note_length(db):
    aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
    with pytest.raises(ValueError):
        db.acknowledge_alert(aid, actor="ip", note="x" * 501, ts=200)
    assert db.acknowledge_alert(aid, actor="ip", note="x" * 500, ts=200) is True


def test_acknowledge_alert_validates_alert_id(db):
    with pytest.raises(ValueError):
        db.acknowledge_alert(0, actor="ip", ts=100)
    with pytest.raises(ValueError):
        db.acknowledge_alert(-5, actor="ip", ts=100)


def test_unacknowledge_alert_inverse_behavior(db):
    aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
    db.acknowledge_alert(aid, actor="ip", ts=200)
    assert db.get_alert(aid)["acknowledged"] == 1
    ok = db.unacknowledge_alert(aid, actor="ip", note="reopen", ts=300)
    assert ok is True
    assert db.get_alert(aid)["acknowledged"] == 0
    actions = db.list_alert_actions(aid)
    assert [a["action"] for a in actions] == ["unack", "ack"]
    with pytest.raises(ValueError):
        db.unacknowledge_alert(aid, actor="", ts=400)
    with pytest.raises(ValueError):
        db.unacknowledge_alert(aid, actor="ip", note="x" * 501, ts=400)
    assert db.unacknowledge_alert(99999, actor="ip", ts=400) is False


def test_update_alert_note_sets_note_and_timestamp(db):
    aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
    ok = db.update_alert_note(aid, "FP -- known neighbour AP", now_ts=12345)
    assert ok is True
    alert = db.get_alert(aid)
    assert alert["note"] == "FP -- known neighbour AP"
    assert alert["note_updated_at"] == 12345


def test_update_alert_note_empty_text_clears(db):
    aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
    db.update_alert_note(aid, "first conclusion", now_ts=12345)
    assert db.update_alert_note(aid, "", now_ts=99999) is True
    alert = db.get_alert(aid)
    assert alert["note"] is None
    assert alert["note_updated_at"] is None


def test_update_alert_note_whitespace_only_clears(db):
    aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
    db.update_alert_note(aid, "first conclusion", now_ts=12345)
    assert db.update_alert_note(aid, "   \n  \t  ", now_ts=99999) is True
    alert = db.get_alert(aid)
    assert alert["note"] is None
    assert alert["note_updated_at"] is None


def test_update_alert_note_strips_surrounding_whitespace(db):
    aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
    db.update_alert_note(aid, "  spaced note  \n", now_ts=12345)
    assert db.get_alert(aid)["note"] == "spaced note"


def test_update_alert_note_returns_false_for_missing_id(db):
    assert db.update_alert_note(99999, "note", now_ts=12345) is False


def test_update_alert_note_validates_alert_id(db):
    with pytest.raises(ValueError):
        db.update_alert_note(0, "x", now_ts=1)
    with pytest.raises(ValueError):
        db.update_alert_note(-5, "x", now_ts=1)


def test_update_alert_note_validates_type(db):
    aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
    with pytest.raises(ValueError):
        db.update_alert_note(aid, None, now_ts=1)  # type: ignore[arg-type]


def test_update_alert_note_length_boundary(db):
    aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
    # exactly 4096 chars accepted
    assert db.update_alert_note(aid, "x" * 4096, now_ts=1) is True
    assert db.get_alert(aid)["note"] == "x" * 4096
    # 4097 rejected; pre-existing row unchanged
    with pytest.raises(ValueError, match="4096"):
        db.update_alert_note(aid, "x" * 4097, now_ts=2)
    assert db.get_alert(aid)["note"] == "x" * 4096


def test_update_alert_note_uses_default_now_when_omitted(db, monkeypatch):
    aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
    monkeypatch.setattr("lynceus.db.time.time", lambda: 7777.0)
    assert db.update_alert_note(aid, "default-now") is True
    assert db.get_alert(aid)["note_updated_at"] == 7777


def test_update_alert_note_replace_on_update(db):
    """Single note per alert -- updating replaces, no history accrued."""
    aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
    db.update_alert_note(aid, "v1", now_ts=10)
    db.update_alert_note(aid, "v2 supersedes v1", now_ts=20)
    alert = db.get_alert(aid)
    assert alert["note"] == "v2 supersedes v1"
    assert alert["note_updated_at"] == 20


def test_get_alert_with_match_exposes_note_fields(db):
    """get_alert_with_match (used by the alert detail page) surfaces
    the new note + note_updated_at fields alongside the watchlist
    join. Regression: pre-rc5 the SELECT did not project these."""
    aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
    db.update_alert_note(aid, "triage-context", now_ts=999)
    alert = db.get_alert_with_match(aid)
    assert alert["note"] == "triage-context"
    assert alert["note_updated_at"] == 999


def test_list_alerts_with_match_exposes_note_fields(db):
    """list_alerts_with_match (powers the /alerts list page) projects
    the note field so the per-row indicator can render without a
    separate query."""
    aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
    db.update_alert_note(aid, "list-indicator probe", now_ts=42)
    rows = db.list_alerts_with_match()
    assert len(rows) == 1
    assert rows[0]["note"] == "list-indicator probe"
    assert rows[0]["note_updated_at"] == 42


def test_migration_016_columns_present_and_nullable(db):
    """Existing pre-migration alerts must read NULL for the new
    columns rather than erroring on the SELECT. Re-applying the
    migration must be a no-op (covered by the idempotent suite
    already, but this asserts the specific column shape)."""
    cols = {
        row[1] for row in db._conn.execute("PRAGMA table_info(alerts)").fetchall()
    }
    assert "note" in cols
    assert "note_updated_at" in cols
    # NULL default observed via a fresh insert that does not set
    # the note (the daemon path -- add_alert -- never writes note).
    aid = db.add_alert(ts=1, rule_name="r", mac=None, message="m", severity="low")
    alert = db.get_alert(aid)
    assert alert["note"] is None
    assert alert["note_updated_at"] is None


def test_bulk_acknowledge_returns_correct_counts(db):
    a1 = db.add_alert(ts=100, rule_name="r", mac=None, message="a", severity="low")
    a2 = db.add_alert(ts=101, rule_name="r", mac=None, message="b", severity="low")
    a3 = db.add_alert(ts=102, rule_name="r", mac=None, message="c", severity="low")
    db.acknowledge_alert(a3, actor="ip", ts=150)
    ids = [a1, a2, a3, 9001, 9002]
    result = db.bulk_acknowledge_alerts(ids, actor="ip", ts=200)
    assert result == {
        "requested": 5,
        "acknowledged": 2,
        "already_acked": 1,
        "missing": 2,
        "action_rows_written": 3,
    }
    cnt = db._conn.execute("SELECT COUNT(*) FROM alert_actions WHERE ts = 200").fetchone()[0]
    assert cnt == 3


def test_bulk_acknowledge_atomic(db):
    a1 = db.add_alert(ts=100, rule_name="r", mac=None, message="a", severity="low")
    a2 = db.add_alert(ts=101, rule_name="r", mac=None, message="b", severity="low")
    real_conn = db._conn
    call_counter = {"n": 0}

    class BoomProxy:
        def __init__(self, inner):
            self._inner = inner

        def execute(self, sql, *args, **kwargs):
            if "INSERT INTO alert_actions" in sql:
                call_counter["n"] += 1
                if call_counter["n"] == 2:
                    raise sqlite3.OperationalError("simulated failure")
            return self._inner.execute(sql, *args, **kwargs)

        def __enter__(self):
            return self._inner.__enter__()

        def __exit__(self, *exc):
            return self._inner.__exit__(*exc)

        def __getattr__(self, name):
            return getattr(self._inner, name)

    db._conn = BoomProxy(real_conn)
    try:
        with pytest.raises(sqlite3.OperationalError):
            db.bulk_acknowledge_alerts([a1, a2], actor="ip", ts=300)
    finally:
        db._conn = real_conn
    assert db.get_alert(a1)["acknowledged"] == 0
    assert db.get_alert(a2)["acknowledged"] == 0
    rows = db._conn.execute("SELECT COUNT(*) FROM alert_actions").fetchone()[0]
    assert rows == 0


def test_bulk_acknowledge_validates_size(db):
    with pytest.raises(ValueError):
        db.bulk_acknowledge_alerts([], actor="ip", ts=100)
    with pytest.raises(ValueError):
        db.bulk_acknowledge_alerts(list(range(1, 1002)), actor="ip", ts=100)
    with pytest.raises(ValueError):
        db.bulk_acknowledge_alerts([1, 0, 2], actor="ip", ts=100)
    with pytest.raises(ValueError):
        db.bulk_acknowledge_alerts([1, 2], actor=" ", ts=100)


def test_list_alert_actions_orders_desc(db):
    aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
    db.acknowledge_alert(aid, actor="ip", ts=200)
    db.unacknowledge_alert(aid, actor="ip", ts=300)
    db.acknowledge_alert(aid, actor="ip", ts=400)
    actions = db.list_alert_actions(aid)
    assert [a["ts"] for a in actions] == [400, 300, 200]
    with pytest.raises(ValueError):
        db.list_alert_actions(aid, limit=0)
    with pytest.raises(ValueError):
        db.list_alert_actions(aid, limit=1001)


def test_alert_severity_counts_all_time(db):
    db.add_alert(ts=100, rule_name="r", mac=None, message="x", severity="low")
    db.add_alert(ts=101, rule_name="r", mac=None, message="x", severity="med")
    db.add_alert(ts=102, rule_name="r", mac=None, message="x", severity="med")
    db.add_alert(ts=103, rule_name="r", mac=None, message="x", severity="high")
    counts = db.alert_severity_counts()
    assert counts == {"low": 1, "med": 2, "high": 1}


def test_alert_severity_counts_with_since_ts(db):
    db.add_alert(ts=100, rule_name="r", mac=None, message="x", severity="low")
    db.add_alert(ts=200, rule_name="r", mac=None, message="x", severity="med")
    db.add_alert(ts=300, rule_name="r", mac=None, message="x", severity="high")
    counts = db.alert_severity_counts(since_ts=200)
    assert counts == {"low": 0, "med": 1, "high": 1}
    aid = db.add_alert(ts=400, rule_name="r", mac=None, message="x", severity="low")
    db.acknowledge_alert(aid, actor="ip", ts=500)
    counts = db.alert_severity_counts(since_ts=200)
    assert counts["low"] == 1


def test_count_alerts_grouped_by_rule_name_all_time(db):
    db.add_alert(ts=100, rule_name="rule_a", mac=None, message="x", severity="low")
    db.add_alert(ts=150, rule_name="rule_a", mac=None, message="x", severity="med")
    db.add_alert(ts=200, rule_name="rule_b", mac=None, message="x", severity="high")
    stats = db.count_alerts_grouped_by_rule_name()
    assert set(stats.keys()) == {"rule_a", "rule_b"}
    assert stats["rule_a"].count == 2
    assert stats["rule_a"].last_fired_ts == 150
    assert stats["rule_b"].count == 1
    assert stats["rule_b"].last_fired_ts == 200


def test_count_alerts_grouped_by_rule_name_with_since_ts(db):
    db.add_alert(ts=100, rule_name="rule_a", mac=None, message="x", severity="low")
    db.add_alert(ts=200, rule_name="rule_a", mac=None, message="x", severity="med")
    db.add_alert(ts=300, rule_name="rule_b", mac=None, message="x", severity="high")
    # since_ts excludes the ts=100 alert; rule_a count drops to 1.
    stats = db.count_alerts_grouped_by_rule_name(since_ts=200)
    assert stats["rule_a"].count == 1
    assert stats["rule_a"].last_fired_ts == 200
    assert stats["rule_b"].count == 1
    assert stats["rule_b"].last_fired_ts == 300


def test_count_alerts_grouped_by_rule_name_empty_table(db):
    stats = db.count_alerts_grouped_by_rule_name()
    assert stats == {}
    stats = db.count_alerts_grouped_by_rule_name(since_ts=1_000_000)
    assert stats == {}


def test_count_alerts_grouped_by_rule_name_rule_outside_window_absent(db):
    db.add_alert(ts=100, rule_name="ancient", mac=None, message="x", severity="low")
    db.add_alert(ts=500, rule_name="recent", mac=None, message="x", severity="low")
    stats = db.count_alerts_grouped_by_rule_name(since_ts=400)
    # "ancient" fired before the window and must be absent — caller
    # defaults missing rule_names to RuleStats(0, None).
    assert "ancient" not in stats
    assert stats["recent"].count == 1


def test_count_alerts_grouped_by_rule_name_edge_rule_names(db):
    # rule_name is operator-defined; spaces, quotes, and unicode all
    # must round-trip through the GROUP BY without mangling.
    weird = "rule with spaces & quotes\""
    unicode_name = "règle_éé"
    db.add_alert(ts=100, rule_name=weird, mac=None, message="x", severity="low")
    db.add_alert(ts=110, rule_name=weird, mac=None, message="x", severity="low")
    db.add_alert(ts=120, rule_name=unicode_name, mac=None, message="x", severity="low")
    stats = db.count_alerts_grouped_by_rule_name()
    assert stats[weird].count == 2
    assert stats[weird].last_fired_ts == 110
    assert stats[unicode_name].count == 1


def test_count_alerts_grouped_by_rule_name_returns_rulestats_named_fields(db):
    db.add_alert(ts=100, rule_name="r", mac=None, message="x", severity="low")
    stats = db.count_alerts_grouped_by_rule_name()
    # Confirm named-field access (RuleStats is a NamedTuple, not a
    # plain tuple — callers use .count / .last_fired_ts).
    assert stats["r"].count == 1
    assert stats["r"].last_fired_ts == 100


def test_alerts_per_day_includes_zero_days(db):
    now_ts = 1777809600
    today_ts = now_ts
    three_days_ago = today_ts - 3 * 86400
    db.add_alert(ts=today_ts, rule_name="r", mac=None, message="x", severity="low")
    db.add_alert(ts=three_days_ago, rule_name="r", mac=None, message="x", severity="low")
    rows = db.alerts_per_day(days=5, now_ts=now_ts)
    assert len(rows) == 5
    for r in rows:
        assert "date" in r
        assert "count" in r
        assert isinstance(r["count"], int)
    zero_days = [r for r in rows if r["count"] == 0]
    assert len(zero_days) >= 1
    nonzero = [r for r in rows if r["count"] > 0]
    assert sum(r["count"] for r in nonzero) == 2


def test_alerts_per_day_validates_range(db):
    with pytest.raises(ValueError):
        db.alerts_per_day(days=0, now_ts=1000000)
    with pytest.raises(ValueError):
        db.alerts_per_day(days=366, now_ts=1000000)


def test_list_alerts_with_since_until(db):
    db.add_alert(ts=100, rule_name="r", mac=None, message="m1", severity="low")
    db.add_alert(ts=200, rule_name="r", mac=None, message="m2", severity="low")
    db.add_alert(ts=300, rule_name="r", mac=None, message="m3", severity="low")
    rows = db.list_alerts(since_ts=200, until_ts=200)
    assert [r["message"] for r in rows] == ["m2"]
    rows = db.list_alerts(since_ts=200)
    assert sorted(r["message"] for r in rows) == ["m2", "m3"]
    rows = db.list_alerts(until_ts=200)
    assert sorted(r["message"] for r in rows) == ["m1", "m2"]


def test_list_alerts_search_matches_message_case_insensitive(db):
    db.add_alert(
        ts=100,
        rule_name="rule1",
        mac=None,
        message="Beacon FROM rogue AP",
        severity="low",
    )
    db.add_alert(ts=101, rule_name="rule2", mac=None, message="boring stuff", severity="low")
    rows = db.list_alerts(search="rogue")
    assert [r["message"] for r in rows] == ["Beacon FROM rogue AP"]
    rows = db.list_alerts(search="ROGUE")
    assert [r["message"] for r in rows] == ["Beacon FROM rogue AP"]


def test_list_alerts_search_matches_rule_name(db):
    db.add_alert(ts=100, rule_name="watchlist_mac", mac=None, message="boom", severity="low")
    db.add_alert(ts=101, rule_name="rogue_ap", mac=None, message="boom", severity="low")
    rows = db.list_alerts(search="watch")
    assert [r["rule_name"] for r in rows] == ["watchlist_mac"]


def test_count_alerts_search_matches_list(db):
    db.add_alert(ts=100, rule_name="r", mac=None, message="hello world", severity="low")
    db.add_alert(ts=101, rule_name="r", mac=None, message="goodbye world", severity="low")
    db.add_alert(ts=102, rule_name="r", mac=None, message="boom", severity="low")
    assert db.count_alerts(search="world") == 2
    assert db.count_alerts(search="hello") == 1
    assert db.count_alerts(search="WORLD") == 2
    assert db.count_alerts(since_ts=101, search="world") == 1


def test_list_alerts_filter_by_rule_type(db):
    db.add_alert(
        ts=100, rule_name="r", mac=None, message="m",
        severity="low", rule_type="watchlist_mac",
    )
    db.add_alert(
        ts=101, rule_name="r", mac=None, message="m",
        severity="low", rule_type="watchlist_oui",
    )
    db.add_alert(
        ts=102, rule_name="r", mac=None, message="m",
        severity="low", rule_type="watchlist_ssid",
    )
    rows = db.list_alerts(rule_type="watchlist_oui")
    assert [r["rule_type"] for r in rows] == ["watchlist_oui"]
    assert db.count_alerts(rule_type="watchlist_oui") == 1


def test_list_alerts_filter_by_rule_type_excludes_null_rule_type(db):
    # Honest exclusion of legacy NULL-rule_type rows from any
    # specific type filter. rule_type=None is the "any" default and
    # includes them.
    db.add_alert(
        ts=100, rule_name="r", mac=None, message="m",
        severity="low", rule_type=None,
    )
    db.add_alert(
        ts=101, rule_name="r", mac=None, message="m",
        severity="low", rule_type="watchlist_mac",
    )
    rows = db.list_alerts(rule_type="watchlist_mac")
    assert len(rows) == 1
    rows_all = db.list_alerts()
    assert len(rows_all) == 2


def test_list_alerts_filter_by_q_matches_mac(db):
    db.upsert_device("aa:bb:cc:dd:ee:ff", "wifi", "Acme", 0, 100)
    db.upsert_device("11:22:33:44:55:66", "wifi", "Acme", 0, 100)
    db.add_alert(
        ts=100, rule_name="r", mac="aa:bb:cc:dd:ee:ff",
        message="m", severity="low",
    )
    db.add_alert(
        ts=101, rule_name="r", mac="11:22:33:44:55:66",
        message="m", severity="low",
    )
    rows = db.list_alerts(q="aa:bb")
    assert [r["mac"] for r in rows] == ["aa:bb:cc:dd:ee:ff"]
    # Case-insensitive.
    rows = db.list_alerts(q="AA:BB")
    assert [r["mac"] for r in rows] == ["aa:bb:cc:dd:ee:ff"]


def test_list_alerts_filter_by_q_matches_message_substring(db):
    db.add_alert(
        ts=100, rule_name="r", mac=None,
        message="SSID 'MySSID' on watchlist", severity="low",
    )
    db.add_alert(
        ts=101, rule_name="r", mac=None,
        message="MAC aa:bb:cc on watchlist", severity="low",
    )
    rows = db.list_alerts(q="myssid")
    assert len(rows) == 1
    assert "MySSID" in rows[0]["message"]


def test_list_alerts_filter_by_q_matches_manufacturer_via_join(db):
    # q substring matches against watchlist_metadata.vendor. Forces
    # both the LEFT JOIN and the COALESCE NULL-safety in the
    # filter clause to be exercised.
    db.upsert_device("aa:bb:cc:dd:ee:ff", "wifi", "Acme", 0, 100)
    wl_id = db._conn.execute(
        "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
        "VALUES (?, ?, ?, ?)",
        ("aa:bb:cc:dd:ee:ff", "mac", "high", "Apple device"),
    ).lastrowid
    db._conn.execute(
        "INSERT INTO watchlist_metadata("
        "watchlist_id, argus_record_id, device_category, vendor) "
        "VALUES (?, ?, ?, ?)",
        (wl_id, "argus-1", "phone", "Apple Inc."),
    )
    db._conn.commit()
    db.add_alert(
        ts=100, rule_name="r", mac="aa:bb:cc:dd:ee:ff",
        message="generic", severity="low",
        matched_watchlist_id=wl_id,
    )
    db.add_alert(
        ts=101, rule_name="r", mac=None,
        message="generic", severity="low",
    )
    rows = db.list_alerts(q="apple")
    assert len(rows) == 1
    assert rows[0]["mac"] == "aa:bb:cc:dd:ee:ff"
    assert db.count_alerts(q="apple") == 1


def test_list_alerts_filter_by_has_note_with_note(db):
    """has_note='with_note' returns only alerts where note IS NOT NULL.
    Pairs with the per-row 📝 indicator on /alerts -- closes the
    triage-workflow loop (notes -> indicator -> filter)."""
    a1 = db.add_alert(ts=100, rule_name="r", mac=None, message="triaged", severity="low")
    db.add_alert(ts=101, rule_name="r", mac=None, message="untriaged-1", severity="low")
    db.add_alert(ts=102, rule_name="r", mac=None, message="untriaged-2", severity="low")
    db.update_alert_note(a1, "FP -- known device", now_ts=999)
    rows = db.list_alerts(has_note="with_note")
    assert [r["message"] for r in rows] == ["triaged"]
    assert db.count_alerts(has_note="with_note") == 1


def test_list_alerts_filter_by_has_note_without_note(db):
    a1 = db.add_alert(ts=100, rule_name="r", mac=None, message="triaged", severity="low")
    db.add_alert(ts=101, rule_name="r", mac=None, message="untriaged-1", severity="low")
    db.add_alert(ts=102, rule_name="r", mac=None, message="untriaged-2", severity="low")
    db.update_alert_note(a1, "FP", now_ts=999)
    rows = db.list_alerts(has_note="without_note")
    # ts DESC -- newest first.
    assert [r["message"] for r in rows] == ["untriaged-2", "untriaged-1"]
    assert db.count_alerts(has_note="without_note") == 2


def test_list_alerts_has_note_all_is_noop(db):
    """has_note='all', None, and unrecognized values all degrade to
    'no clause' -- same silent-fallback semantic as rule_type / window."""
    a1 = db.add_alert(ts=100, rule_name="r", mac=None, message="triaged", severity="low")
    db.add_alert(ts=101, rule_name="r", mac=None, message="untriaged", severity="low")
    db.update_alert_note(a1, "FP", now_ts=999)
    # None, "all", "" all return the full set.
    assert db.count_alerts(has_note=None) == 2
    assert db.count_alerts(has_note="all") == 2
    assert db.count_alerts(has_note="") == 2
    # Unrecognized value silently falls back to 'all' (no error).
    assert db.count_alerts(has_note="bogus") == 2


def test_list_alerts_has_note_combines_with_other_filters(db):
    """has_note ANDs cleanly with severity / acknowledged."""
    a1 = db.add_alert(ts=100, rule_name="r", mac=None, message="high-triaged", severity="high")
    a2 = db.add_alert(ts=101, rule_name="r", mac=None, message="low-triaged", severity="low")
    db.add_alert(ts=102, rule_name="r", mac=None, message="high-untriaged", severity="high")
    db.add_alert(ts=103, rule_name="r", mac=None, message="low-untriaged", severity="low")
    db.update_alert_note(a1, "FP", now_ts=999)
    db.update_alert_note(a2, "FP", now_ts=999)
    rows = db.list_alerts(severity="high", has_note="with_note")
    assert [r["message"] for r in rows] == ["high-triaged"]
    assert db.count_alerts(severity="high", has_note="with_note") == 1
    assert db.count_alerts(severity="high", has_note="without_note") == 1
    assert db.count_alerts(severity="low", has_note="with_note") == 1


def test_list_alerts_with_match_has_note_filter(db):
    """list_alerts_with_match (the page query) honors has_note --
    matching the count_alerts behavior so pagination math stays
    correct."""
    a1 = db.add_alert(ts=100, rule_name="r", mac=None, message="triaged", severity="low")
    db.add_alert(ts=101, rule_name="r", mac=None, message="untriaged", severity="low")
    db.update_alert_note(a1, "FP", now_ts=999)
    rows = db.list_alerts_with_match({"has_note": "with_note"})
    assert [r["message"] for r in rows] == ["triaged"]


def test_list_alerts_with_match_rejects_unknown_filter(db):
    """The filter-key whitelist gates unknown filters (regression
    against future typos like 'has_notes' or 'note_filter')."""
    with pytest.raises(ValueError, match="unknown filter keys"):
        db.list_alerts_with_match({"has_notes": "with_note"})


def test_count_alerts_and_list_alerts_apply_same_filter(db):
    # Single-source-of-truth invariant: count and page query must
    # report the same set under identical filters. Drift here is the
    # pagination-math-is-a-lie bug class.
    for i, sev in enumerate(["low", "med", "high", "low", "high"]):
        db.add_alert(
            ts=100 + i, rule_name=f"r{i}", mac=None, message=f"m{i}",
            severity=sev, rule_type="watchlist_mac" if i < 3 else "watchlist_oui",
        )
    filters = {
        "severity": "low",
        "rule_type": "watchlist_mac",
    }
    page = db.list_alerts(limit=100, offset=0, **filters)
    total = db.count_alerts(**filters)
    assert len(page) == total


def test_list_alerts_with_match_accepts_rule_type_and_q(db):
    # Confirms _ALERT_WITH_MATCH_FILTER_KEYS admits the new keys.
    db.add_alert(
        ts=100, rule_name="r", mac=None, message="m",
        severity="low", rule_type="watchlist_mac",
    )
    rows = db.list_alerts_with_match({"rule_type": "watchlist_mac"})
    assert len(rows) == 1
    assert rows[0]["rule_type"] == "watchlist_mac"
    rows = db.list_alerts_with_match({"q": "m"})
    assert len(rows) == 1


# ---------------------------------------------------------------------------
# device_seen_counts and latest_poll_ts (UI dashboard helpers).
# ---------------------------------------------------------------------------


def test_device_seen_counts_validates_now_ts(db):
    with pytest.raises(ValueError):
        db.device_seen_counts(now_ts=0)
    with pytest.raises(ValueError):
        db.device_seen_counts(now_ts=-5)


def test_device_seen_counts_zero_devices(db):
    assert db.device_seen_counts(now_ts=2_000_000_000) == {"day": 0, "week": 0, "month": 0}


def test_device_seen_counts_dedups_per_window(db):
    _seed(db)
    now_ts = 2_000_000_000
    for offset in range(5):
        db.insert_sighting(MAC, now_ts - offset, None, None, LOC)
    counts = db.device_seen_counts(now_ts=now_ts)
    assert counts["day"] == 1
    assert counts["week"] == 1
    assert counts["month"] == 1


def test_device_seen_counts_window_boundaries(db):
    """Boundary semantics: ts >= now_ts - window_seconds counts (inclusive)."""
    _seed(db)
    db.upsert_device("aa:bb:cc:dd:ee:11", "wifi", "Acme", 0, 100)
    db.upsert_device("aa:bb:cc:dd:ee:22", "wifi", "Acme", 0, 100)
    now_ts = 2_000_000_000
    db.insert_sighting(MAC, now_ts - 86400, None, None, LOC)
    db.insert_sighting("aa:bb:cc:dd:ee:11", now_ts - 7 * 86400, None, None, LOC)
    db.insert_sighting("aa:bb:cc:dd:ee:22", now_ts - 30 * 86400, None, None, LOC)
    counts = db.device_seen_counts(now_ts=now_ts)
    # Each device sits exactly on a boundary; inclusive means each is counted.
    assert counts["day"] == 1
    assert counts["week"] == 2
    assert counts["month"] == 3


def test_device_seen_counts_separates_devices(db):
    _seed(db)
    db.upsert_device("aa:bb:cc:dd:ee:11", "wifi", "Acme", 0, 100)
    db.upsert_device("aa:bb:cc:dd:ee:22", "wifi", "Acme", 0, 100)
    now_ts = 2_000_000_000
    db.insert_sighting(MAC, now_ts - 3600, None, None, LOC)
    db.insert_sighting("aa:bb:cc:dd:ee:11", now_ts - 3 * 86400, None, None, LOC)
    db.insert_sighting("aa:bb:cc:dd:ee:22", now_ts - 20 * 86400, None, None, LOC)
    counts = db.device_seen_counts(now_ts=now_ts)
    assert counts == {"day": 1, "week": 2, "month": 3}


def test_latest_poll_ts_returns_none_when_unset(db):
    assert db.latest_poll_ts() is None


def test_latest_poll_ts_returns_int_when_set(db):
    db.set_state("last_poll_ts", "1700000000")
    assert db.latest_poll_ts() == 1700000000


def test_latest_poll_ts_invalid_value_raises(db):
    db.set_state("last_poll_ts", "not-an-int")
    with pytest.raises(ValueError):
        db.latest_poll_ts()


# ------------------- G2 regression: parent dir mkdir -----------------------
#
# rc1.30c patched ``data_dir.mkdir`` inside the wizard, but anything
# constructing ``Database()`` directly with a path whose parent does not
# yet exist still hit the opaque sqlite "unable to open database file"
# error. Pre-existing tests passed because they always used
# ``tmp_path / "lynceus.db"`` — ``tmp_path`` exists. This regression
# uses a deeply-nested path the test creates only once, so the
# constructor itself must do the mkdir.


def test_database_creates_missing_parent_dirs(tmp_path):
    nested = tmp_path / "deep" / "nested" / "subdir" / "lynceus.db"
    assert not nested.parent.exists()  # precondition

    d = Database(str(nested))
    try:
        assert nested.parent.is_dir()
        assert nested.exists()
        # Sanity: usable connection.
        d.ensure_location("loc", "Lab")
    finally:
        d.close()


def test_database_in_memory_path_does_not_create_dirs(tmp_path, monkeypatch):
    """``:memory:`` is the sqlite sentinel for an in-memory database; it has
    no real path, so the mkdir must be skipped. Otherwise we would create
    a literally-named ``./:memory:`` directory on platforms that allow it."""
    cwd_before = list(tmp_path.iterdir())
    monkeypatch.chdir(tmp_path)
    d = Database(":memory:")
    try:
        assert list(tmp_path.iterdir()) == cwd_before
    finally:
        d.close()


# ---------------- mac_range matcher (resolve_matched_mac_range) -------------


def _add_mac_range(
    db: Database,
    pattern: str,
    prefix: str,
    length: int,
    severity: str = "low",
) -> int:
    with db._conn:
        cur = db._conn.execute(
            "INSERT INTO watchlist("
            "pattern, pattern_type, severity, description, "
            "mac_range_prefix, mac_range_prefix_length) "
            "VALUES (?, 'mac_range', ?, NULL, ?, ?)",
            (pattern, severity, prefix, length),
        )
        return int(cur.lastrowid)


def test_resolve_matched_mac_range_28_hit(db):
    wid = _add_mac_range(db, "aa:bb:cc:d/28", "aabbccd", 28, severity="high")
    match = db.resolve_matched_mac_range("aa:bb:cc:d1:23:45")
    assert match is not None
    assert match.watchlist_id == wid
    assert match.severity == "high"
    assert match.prefix_length == 28
    # No metadata row attached → device_category is None.
    assert match.device_category is None


def test_resolve_matched_mac_range_populates_device_category(db):
    """LEFT JOIN onto watchlist_metadata surfaces device_category for
    mac_range matches the same way it does for the simple matchers."""
    wid = _add_mac_range(db, "aa:bb:cc:d/28", "aabbccd", 28, severity="high")
    with db._conn:
        db._conn.execute(
            "INSERT INTO watchlist_metadata("
            "watchlist_id, argus_record_id, device_category) "
            "VALUES (?, ?, ?)",
            (wid, f"argus-{wid}", "alpr"),
        )
    match = db.resolve_matched_mac_range("aa:bb:cc:d1:23:45")
    assert match is not None
    assert match.device_category == "alpr"


def test_resolve_matched_mac_range_populates_manufacturer(db):
    """LEFT JOIN onto watchlist_metadata surfaces ``vendor`` projected
    as ``manufacturer`` (Argus CSV column → DB ``vendor`` column →
    Python field ``manufacturer``). Powers the runtime
    ``suppress_vendors`` check."""
    wid = _add_mac_range(db, "aa:bb:cc:d/28", "aabbccd", 28, severity="high")
    with db._conn:
        db._conn.execute(
            "INSERT INTO watchlist_metadata("
            "watchlist_id, argus_record_id, device_category, vendor) "
            "VALUES (?, ?, ?, ?)",
            (wid, f"argus-{wid}", "alpr", "Mitsubishi Electric US, Inc."),
        )
    match = db.resolve_matched_mac_range("aa:bb:cc:d1:23:45")
    assert match is not None
    assert match.manufacturer == "Mitsubishi Electric US, Inc."


def test_resolve_matched_mac_range_manufacturer_null_when_no_metadata(db):
    """No metadata row → manufacturer is None. Mirrors the
    device_category-NULL pass-through used for the 63 bundled
    default_watchlist rows."""
    _add_mac_range(db, "aa:bb:cc:d/28", "aabbccd", 28)
    match = db.resolve_matched_mac_range("aa:bb:cc:d1:23:45")
    assert match is not None
    assert match.manufacturer is None


def test_resolve_matched_mac_range_manufacturer_null_when_vendor_unset(db):
    """A metadata row that omits ``vendor`` (NULL) → manufacturer
    surfaces as None, not the empty string. The runtime suppress_vendors
    check skips entirely when manufacturer is None — vendor-NULL is a
    valid state for any non-Argus metadata row."""
    wid = _add_mac_range(db, "aa:bb:cc:d/28", "aabbccd", 28)
    with db._conn:
        db._conn.execute(
            "INSERT INTO watchlist_metadata("
            "watchlist_id, argus_record_id, device_category) "
            "VALUES (?, ?, ?)",
            (wid, f"argus-{wid}", "alpr"),
        )
    match = db.resolve_matched_mac_range("aa:bb:cc:d1:23:45")
    assert match is not None
    assert match.manufacturer is None


def test_resolve_matched_mac_range_populates_argus_record_id(db):
    """LEFT JOIN onto watchlist_metadata surfaces ``argus_record_id``
    on the match. Powers the runtime ``pattern_overrides`` row-level
    severity remap — operators key on the canonical Argus identifier
    (16-hex SHA-256 prefix in production, but the column is plain
    TEXT so the test uses an opaque sentinel)."""
    wid = _add_mac_range(db, "aa:bb:cc:d/28", "aabbccd", 28, severity="high")
    with db._conn:
        db._conn.execute(
            "INSERT INTO watchlist_metadata("
            "watchlist_id, argus_record_id, device_category) "
            "VALUES (?, ?, ?)",
            (wid, "a1b2c3d4e5f60001", "alpr"),
        )
    match = db.resolve_matched_mac_range("aa:bb:cc:d1:23:45")
    assert match is not None
    assert match.argus_record_id == "a1b2c3d4e5f60001"


def test_resolve_matched_mac_range_argus_record_id_null_when_no_metadata(db):
    """No metadata row → argus_record_id is None. The runtime
    pattern_overrides check skips entirely on None — these rows fall
    through to the category layer."""
    _add_mac_range(db, "aa:bb:cc:d/28", "aabbccd", 28)
    match = db.resolve_matched_mac_range("aa:bb:cc:d1:23:45")
    assert match is not None
    assert match.argus_record_id is None


def test_resolve_matched_mac_range_36_hit(db):
    wid = _add_mac_range(db, "aa:bb:cc:dd:e/36", "aabbccdde", 36, severity="med")
    match = db.resolve_matched_mac_range("aa:bb:cc:dd:e7:89")
    assert match is not None
    assert match.watchlist_id == wid
    assert match.severity == "med"
    assert match.prefix_length == 36


def test_resolve_matched_mac_range_miss(db):
    _add_mac_range(db, "aa:bb:cc:d/28", "aabbccd", 28)
    assert db.resolve_matched_mac_range("11:22:33:44:55:66") is None


def test_resolve_matched_mac_range_none_and_empty_mac(db):
    _add_mac_range(db, "aa:bb:cc:d/28", "aabbccd", 28)
    assert db.resolve_matched_mac_range(None) is None
    assert db.resolve_matched_mac_range("") is None


def test_resolve_matched_mac_range_is_case_insensitive(db):
    """The watchlist mac_range_prefix is stored lowercase-hex per
    Part 1's canonicalization (importer + parse_mac_range_pattern).
    Observation MACs from Kismet are also lowercased by the poller
    before reaching this layer, but the matcher hardens against
    callers passing uppercase by lowering at the boundary —
    a row-stored-as-lowercase / observation-as-uppercase mismatch
    used to be the L-RULES-1 silent-no-match class of bug."""
    wid = _add_mac_range(db, "aa:bb:cc:d/28", "aabbccd", 28)
    match = db.resolve_matched_mac_range("AA:BB:CC:D1:23:45")
    assert match is not None
    assert match.watchlist_id == wid


def test_resolve_matched_mac_range_36_wins_over_overlapping_28(db, caplog):
    """/28 and /36 ranges covering the same MAC should never coexist
    by IEEE design — this scenario is an Argus contract violation.
    When it surfaces defensively, the more-specific /36 wins and a
    WARNING is logged carrying both watchlist_ids so operators can
    raise upstream."""
    id_28 = _add_mac_range(db, "aa:bb:cc:d/28", "aabbccd", 28, severity="low")
    id_36 = _add_mac_range(db, "aa:bb:cc:dd:e/36", "aabbccdde", 36, severity="high")
    with caplog.at_level(logging.WARNING, logger="lynceus.db"):
        match = db.resolve_matched_mac_range("aa:bb:cc:dd:e7:89")
    assert match is not None
    assert match.watchlist_id == id_36
    assert match.severity == "high"
    assert match.prefix_length == 36
    overlap_warnings = [
        r for r in caplog.records
        if r.levelno == logging.WARNING
        and "mac_range overlap" in r.getMessage()
    ]
    assert len(overlap_warnings) == 1
    msg = overlap_warnings[0].getMessage()
    assert str(id_28) in msg and str(id_36) in msg


def test_resolve_matched_mac_range_no_match_emits_no_warning(db, caplog):
    """The overlap WARNING must fire only when two ranges actually
    match — a no-match observation must not produce spurious noise
    in the daemon log. Polling sees thousands of non-watchlisted
    MACs per cycle; one log line per miss would flood journalctl."""
    _add_mac_range(db, "aa:bb:cc:d/28", "aabbccd", 28)
    with caplog.at_level(logging.WARNING, logger="lynceus.db"):
        db.resolve_matched_mac_range("11:22:33:44:55:66")
    overlap_warnings = [
        r for r in caplog.records
        if r.levelno == logging.WARNING
        and "mac_range overlap" in r.getMessage()
    ]
    assert overlap_warnings == []


# ---- resolve_matched_watchlist_id mac_range annotation branch -----


def test_resolve_matched_watchlist_id_mac_range_annotates(db):
    """Annotation path: a MAC inside a watchlisted mac_range with no
    overlapping mac/oui row returns the mac_range row id, so
    matched_watchlist_id is correctly stamped on the alert."""
    wid = _add_mac_range(db, "aa:bb:cc:d/28", "aabbccd", 28)
    rid = db.resolve_matched_watchlist_id(mac="aa:bb:cc:d1:23:45")
    assert rid == wid


def test_resolve_matched_watchlist_id_mac_precedence_over_mac_range(db):
    """Tiebreaker: an exact-MAC watchlist row outranks a mac_range
    covering the same MAC. Operator-curated exact rules beat bulk
    imports."""
    _add_mac_range(db, "aa:bb:cc:d/28", "aabbccd", 28)
    with db._conn:
        cur = db._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
            "VALUES (?, 'mac', 'high', NULL)",
            ("aa:bb:cc:d1:23:45",),
        )
        exact_id = int(cur.lastrowid)
    rid = db.resolve_matched_watchlist_id(mac="aa:bb:cc:d1:23:45")
    assert rid == exact_id


def test_resolve_matched_watchlist_id_oui_precedence_over_mac_range(db):
    """oui beats mac_range — IEEE design says they're disjoint for a
    real MAC, but the tiebreaker is conservative so an operator-
    curated oui rule isn't silently overridden by a bulk Argus
    mac_range covering the same OUI."""
    _add_mac_range(db, "aa:bb:cc:d/28", "aabbccd", 28)
    with db._conn:
        cur = db._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
            "VALUES (?, 'oui', 'high', NULL)",
            ("aa:bb:cc",),
        )
        oui_id = int(cur.lastrowid)
    rid = db.resolve_matched_watchlist_id(mac="aa:bb:cc:d1:23:45")
    assert rid == oui_id


def test_resolve_matched_watchlist_id_mac_range_does_not_double_warn(db, caplog):
    """The annotation path uses the private _lookup_mac_range_matches
    helper directly so the WARNING-on-overlap is not emitted twice
    when the rules engine has already logged it for the same
    observation. Without this contract every overlap would log
    twice per poll cycle, defeating the signal."""
    _add_mac_range(db, "aa:bb:cc:d/28", "aabbccd", 28)
    _add_mac_range(db, "aa:bb:cc:dd:e/36", "aabbccdde", 36)
    with caplog.at_level(logging.WARNING, logger="lynceus.db"):
        db.resolve_matched_watchlist_id(mac="aa:bb:cc:dd:e7:89")
    overlap_warnings = [
        r for r in caplog.records
        if r.levelno == logging.WARNING
        and "mac_range overlap" in r.getMessage()
    ]
    assert overlap_warnings == []


# --- delegation eval matchers (resolve_matched_*_for_eval) ----------------
#
# Backs the empty-patterns delegation semantic for watchlist_mac,
# watchlist_oui, watchlist_ssid, and ble_uuid in rules.evaluate. Each
# matcher returns a ResolvedWatchlistMatch (watchlist_id + severity)
# so the consuming branch can stamp the emitted RuleHit with the
# matched DB row's severity rather than the rule's severity. The
# matchers share the _lookup_simple_watchlist_match helper with
# resolve_matched_watchlist_id (the annotation path), so SQL changes
# flow to both at once.


def _add_simple(
    db: Database,
    pattern: str,
    pattern_type: str,
    severity: str = "low",
) -> int:
    with db._conn:
        cur = db._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
            "VALUES (?, ?, ?, NULL)",
            (pattern, pattern_type, severity),
        )
        return int(cur.lastrowid)


# ---- resolve_matched_mac_for_eval ----


def _attach_metadata(db: Database, watchlist_id: int, *, device_category: str, **extra) -> None:
    """Attach a watchlist_metadata row to an existing watchlist row.

    The runtime severity-overrides layer keys on
    ``watchlist_metadata.device_category`` for per-category remap and
    suppression. The LEFT JOIN in the lookup helpers surfaces this
    field on ResolvedWatchlistMatch / ResolvedMacRangeMatch; the
    helper below seeds it for tests.
    """
    payload = {"argus_record_id": f"argus-{watchlist_id}", "device_category": device_category}
    payload.update(extra)
    db.upsert_metadata(watchlist_id, payload)


def test_resolve_matched_mac_for_eval_hit(db):
    wid = _add_simple(db, "aa:bb:cc:dd:ee:ff", "mac", severity="high")
    match = db.resolve_matched_mac_for_eval("aa:bb:cc:dd:ee:ff")
    assert match is not None
    assert match.watchlist_id == wid
    assert match.severity == "high"
    # No metadata row attached → device_category is None.
    assert match.device_category is None


def test_resolve_matched_mac_for_eval_populates_device_category(db):
    """LEFT JOIN onto watchlist_metadata surfaces device_category on
    the match. The runtime severity-overrides layer keys on this
    field to look up per-category remap / suppression entries."""
    wid = _add_simple(db, "aa:bb:cc:dd:ee:ff", "mac", severity="high")
    _attach_metadata(db, wid, device_category="alpr")
    match = db.resolve_matched_mac_for_eval("aa:bb:cc:dd:ee:ff")
    assert match is not None
    assert match.device_category == "alpr"


def test_resolve_matched_mac_for_eval_populates_manufacturer(db):
    """LEFT JOIN projects ``watchlist_metadata.vendor`` as
    ``manufacturer`` on the match. Powers ``suppress_vendors``."""
    wid = _add_simple(db, "aa:bb:cc:dd:ee:ff", "mac", severity="high")
    _attach_metadata(db, wid, device_category="alpr", vendor="Acme Surveillance Corp")
    match = db.resolve_matched_mac_for_eval("aa:bb:cc:dd:ee:ff")
    assert match is not None
    assert match.manufacturer == "Acme Surveillance Corp"


def test_resolve_matched_mac_for_eval_manufacturer_null_when_no_metadata(db):
    """The 63 bundled default_watchlist rows ship without metadata
    rows. Their manufacturer surfaces as None — runtime
    suppress_vendors check skips entirely (pass-through)."""
    _add_simple(db, "aa:bb:cc:dd:ee:ff", "mac")
    match = db.resolve_matched_mac_for_eval("aa:bb:cc:dd:ee:ff")
    assert match is not None
    assert match.manufacturer is None


def test_resolve_matched_mac_for_eval_populates_argus_record_id(db):
    """LEFT JOIN surfaces ``argus_record_id`` on the match. Powers
    the runtime ``pattern_overrides`` row-level remap."""
    wid = _add_simple(db, "aa:bb:cc:dd:ee:ff", "mac", severity="high")
    _attach_metadata(
        db, wid, device_category="alpr", argus_record_id="0123456789abcdef"
    )
    match = db.resolve_matched_mac_for_eval("aa:bb:cc:dd:ee:ff")
    assert match is not None
    assert match.argus_record_id == "0123456789abcdef"


def test_resolve_matched_mac_for_eval_argus_record_id_null_when_no_metadata(db):
    """Rows without a metadata row (e.g. the 63 bundled defaults)
    surface argus_record_id=None. The runtime pattern_overrides
    check skips entirely on None — these rows are untargetable from
    pattern_overrides and fall through to the category layer."""
    _add_simple(db, "aa:bb:cc:dd:ee:ff", "mac")
    match = db.resolve_matched_mac_for_eval("aa:bb:cc:dd:ee:ff")
    assert match is not None
    assert match.argus_record_id is None


def test_resolve_matched_mac_for_eval_device_category_null_when_no_metadata(db):
    """The 63 bundled default_watchlist rows ship without metadata
    rows. Their device_category surfaces as None, which the runtime
    layer treats as pass-through (no remap, no suppress applies)."""
    _add_simple(db, "aa:bb:cc:dd:ee:ff", "mac")
    match = db.resolve_matched_mac_for_eval("aa:bb:cc:dd:ee:ff")
    assert match is not None
    assert match.device_category is None


def test_resolve_matched_mac_for_eval_miss(db):
    _add_simple(db, "aa:bb:cc:dd:ee:ff", "mac")
    assert db.resolve_matched_mac_for_eval("11:22:33:44:55:66") is None


def test_resolve_matched_mac_for_eval_none_and_empty(db):
    """Falsy mac short-circuits — same boundary check as
    resolve_matched_mac_range, kept consistent across the matchers."""
    _add_simple(db, "aa:bb:cc:dd:ee:ff", "mac")
    assert db.resolve_matched_mac_for_eval(None) is None
    assert db.resolve_matched_mac_for_eval("") is None


def test_resolve_matched_mac_for_eval_only_matches_mac_pattern_type(db):
    """A row with the same string but pattern_type != 'mac' must not
    match. Tightens the SELECT against accidental cross-type leakage
    (e.g. a row with pattern='aa:bb:cc' and pattern_type='oui' must
    NOT show up for a literal-MAC lookup)."""
    _add_simple(db, "aa:bb:cc", "oui")
    assert db.resolve_matched_mac_for_eval("aa:bb:cc") is None


# ---- resolve_matched_oui_for_eval ----


def test_resolve_matched_oui_for_eval_hit(db):
    wid = _add_simple(db, "aa:bb:cc", "oui", severity="med")
    match = db.resolve_matched_oui_for_eval("aa:bb:cc:dd:ee:ff")
    assert match is not None
    assert match.watchlist_id == wid
    assert match.severity == "med"
    assert match.device_category is None


def test_resolve_matched_oui_for_eval_populates_device_category(db):
    wid = _add_simple(db, "00:13:37", "oui", severity="high")
    _attach_metadata(db, wid, device_category="hacking_tool")
    match = db.resolve_matched_oui_for_eval("00:13:37:aa:bb:cc")
    assert match is not None
    assert match.device_category == "hacking_tool"


def test_resolve_matched_oui_for_eval_populates_manufacturer(db):
    wid = _add_simple(db, "00:13:37", "oui", severity="high")
    _attach_metadata(db, wid, device_category="hacking_tool", vendor="Hak5 LLC")
    match = db.resolve_matched_oui_for_eval("00:13:37:aa:bb:cc")
    assert match is not None
    assert match.manufacturer == "Hak5 LLC"


def test_resolve_matched_oui_for_eval_populates_argus_record_id(db):
    wid = _add_simple(db, "00:13:37", "oui", severity="high")
    _attach_metadata(
        db, wid, device_category="hacking_tool", argus_record_id="fedcba9876543210"
    )
    match = db.resolve_matched_oui_for_eval("00:13:37:aa:bb:cc")
    assert match is not None
    assert match.argus_record_id == "fedcba9876543210"


def test_resolve_matched_oui_for_eval_miss(db):
    _add_simple(db, "aa:bb:cc", "oui")
    assert db.resolve_matched_oui_for_eval("11:22:33:44:55:66") is None


def test_resolve_matched_oui_for_eval_none_and_empty(db):
    _add_simple(db, "aa:bb:cc", "oui")
    assert db.resolve_matched_oui_for_eval(None) is None
    assert db.resolve_matched_oui_for_eval("") is None


def test_resolve_matched_oui_for_eval_extracts_first_8_chars(db):
    """OUI is the first 8 chars of the MAC (the MAC[:8] slice). A
    different MAC sharing the same OUI must match the same row."""
    wid = _add_simple(db, "00:13:37", "oui")
    assert db.resolve_matched_oui_for_eval("00:13:37:aa:bb:cc").watchlist_id == wid
    assert db.resolve_matched_oui_for_eval("00:13:37:99:88:77").watchlist_id == wid


# ---- resolve_matched_ssid_for_eval ----


def test_resolve_matched_ssid_for_eval_hit(db):
    wid = _add_simple(db, "FreeAirportWiFi", "ssid", severity="high")
    match = db.resolve_matched_ssid_for_eval("FreeAirportWiFi")
    assert match is not None
    assert match.watchlist_id == wid
    assert match.severity == "high"
    assert match.device_category is None


def test_resolve_matched_ssid_for_eval_populates_device_category(db):
    wid = _add_simple(db, "FreeAirportWiFi", "ssid", severity="med")
    _attach_metadata(db, wid, device_category="drone")
    match = db.resolve_matched_ssid_for_eval("FreeAirportWiFi")
    assert match is not None
    assert match.device_category == "drone"


def test_resolve_matched_ssid_for_eval_populates_manufacturer(db):
    wid = _add_simple(db, "FreeAirportWiFi", "ssid", severity="med")
    _attach_metadata(db, wid, device_category="drone", vendor="DJI Inc.")
    match = db.resolve_matched_ssid_for_eval("FreeAirportWiFi")
    assert match is not None
    assert match.manufacturer == "DJI Inc."


def test_resolve_matched_ssid_for_eval_populates_argus_record_id(db):
    wid = _add_simple(db, "FreeAirportWiFi", "ssid", severity="med")
    _attach_metadata(
        db, wid, device_category="drone", argus_record_id="1111222233334444"
    )
    match = db.resolve_matched_ssid_for_eval("FreeAirportWiFi")
    assert match is not None
    assert match.argus_record_id == "1111222233334444"


def test_resolve_matched_ssid_for_eval_miss(db):
    _add_simple(db, "FreeAirportWiFi", "ssid")
    assert db.resolve_matched_ssid_for_eval("HomeNet") is None


def test_resolve_matched_ssid_for_eval_none_and_empty(db):
    """Falsy ssid (None or "") short-circuits to None — observations
    without a captured SSID can't match a watchlist_ssid row."""
    _add_simple(db, "FreeAirportWiFi", "ssid")
    assert db.resolve_matched_ssid_for_eval(None) is None
    assert db.resolve_matched_ssid_for_eval("") is None


def test_resolve_matched_ssid_for_eval_case_sensitive(db):
    """SSIDs are case-sensitive per IEEE 802.11. The DB stores the
    pattern verbatim; the matcher does an equality lookup. A
    case-mismatched SSID must NOT match. Documented as intentional —
    operators wanting case-insensitive matching curate per-case rows."""
    _add_simple(db, "FreeAirportWiFi", "ssid")
    assert db.resolve_matched_ssid_for_eval("freeairportwifi") is None


# ---- resolve_matched_ble_uuid_for_eval ----


_AIRTAG_UUID = "0000fd5a-0000-1000-8000-00805f9b34fb"
_TILE_UUID = "0000feed-0000-1000-8000-00805f9b34fb"


def test_resolve_matched_ble_uuid_for_eval_hit(db):
    wid = _add_simple(db, _AIRTAG_UUID, "ble_uuid", severity="high")
    match = db.resolve_matched_ble_uuid_for_eval([_AIRTAG_UUID])
    assert match is not None
    assert match.watchlist_id == wid
    assert match.severity == "high"
    assert match.device_category is None


def test_resolve_matched_ble_uuid_for_eval_populates_device_category(db):
    wid = _add_simple(db, _AIRTAG_UUID, "ble_uuid", severity="high")
    _attach_metadata(db, wid, device_category="alpr")
    match = db.resolve_matched_ble_uuid_for_eval([_AIRTAG_UUID])
    assert match is not None
    assert match.device_category == "alpr"


def test_resolve_matched_ble_uuid_for_eval_populates_manufacturer(db):
    wid = _add_simple(db, _AIRTAG_UUID, "ble_uuid", severity="high")
    _attach_metadata(db, wid, device_category="alpr", vendor="Apple Inc.")
    match = db.resolve_matched_ble_uuid_for_eval([_AIRTAG_UUID])
    assert match is not None
    assert match.manufacturer == "Apple Inc."


def test_resolve_matched_ble_uuid_for_eval_populates_argus_record_id(db):
    wid = _add_simple(db, _AIRTAG_UUID, "ble_uuid", severity="high")
    _attach_metadata(
        db, wid, device_category="alpr", argus_record_id="abcdef0123456789"
    )
    match = db.resolve_matched_ble_uuid_for_eval([_AIRTAG_UUID])
    assert match is not None
    assert match.argus_record_id == "abcdef0123456789"


def test_resolve_matched_ble_uuid_for_eval_miss(db):
    _add_simple(db, _AIRTAG_UUID, "ble_uuid")
    assert db.resolve_matched_ble_uuid_for_eval([_TILE_UUID]) is None


def test_resolve_matched_ble_uuid_for_eval_empty_uuids(db):
    _add_simple(db, _AIRTAG_UUID, "ble_uuid")
    assert db.resolve_matched_ble_uuid_for_eval([]) is None
    assert db.resolve_matched_ble_uuid_for_eval(()) is None


def test_resolve_matched_ble_uuid_for_eval_returns_first_match(db):
    """Iterates ``uuids`` in order and returns the first watchlisted
    UUID — same first-match shape as the existing in-memory
    ble_uuid eval branch (which loops rule.patterns and breaks on
    first hit). Determinism matters because operators build alert
    expectations on rule order."""
    airtag_id = _add_simple(db, _AIRTAG_UUID, "ble_uuid", severity="high")
    tile_id = _add_simple(db, _TILE_UUID, "ble_uuid", severity="med")
    # Tile listed first → tile wins.
    match = db.resolve_matched_ble_uuid_for_eval([_TILE_UUID, _AIRTAG_UUID])
    assert match.watchlist_id == tile_id
    # Airtag listed first → airtag wins.
    match = db.resolve_matched_ble_uuid_for_eval([_AIRTAG_UUID, _TILE_UUID])
    assert match.watchlist_id == airtag_id


def test_resolve_matched_ble_uuid_for_eval_skips_non_matching_uuids(db):
    """A UUID list with a non-matching prefix and a matching one
    later returns the matching one rather than short-circuiting on
    the first miss."""
    wid = _add_simple(db, _AIRTAG_UUID, "ble_uuid")
    match = db.resolve_matched_ble_uuid_for_eval(
        ["0000beef-0000-1000-8000-00805f9b34fb", _AIRTAG_UUID]
    )
    assert match is not None
    assert match.watchlist_id == wid


# ---- shared lookup contract ----


def test_resolve_matched_eval_matchers_share_lookup_with_annotation_path(db):
    """The four eval matchers use _lookup_simple_watchlist_match,
    which also backs resolve_matched_watchlist_id. A row that one
    sees, the other must see — drift between the eval path and the
    annotation path used to mean alerts fired with the right severity
    but landed without a matched_watchlist_id stamp (or vice versa).
    Single SELECT shared across both paths makes the drift class of
    bug structurally impossible."""
    mac_id = _add_simple(db, "aa:bb:cc:dd:ee:ff", "mac")
    oui_id = _add_simple(db, "00:13:37", "oui")
    ssid_id = _add_simple(db, "HomeNet", "ssid")
    ble_id = _add_simple(db, _AIRTAG_UUID, "ble_uuid")

    assert db.resolve_matched_mac_for_eval("aa:bb:cc:dd:ee:ff").watchlist_id == mac_id
    assert (
        db.resolve_matched_watchlist_id(mac="aa:bb:cc:dd:ee:ff") == mac_id
    )

    assert db.resolve_matched_oui_for_eval("00:13:37:11:22:33").watchlist_id == oui_id
    # Annotation path returns mac_id absent the mac row, oui_id otherwise.
    assert db.resolve_matched_watchlist_id(mac="00:13:37:11:22:33") == oui_id

    assert db.resolve_matched_ssid_for_eval("HomeNet").watchlist_id == ssid_id
    assert (
        db.resolve_matched_watchlist_id(mac=None, ssid="HomeNet") == ssid_id
    )

    assert db.resolve_matched_ble_uuid_for_eval([_AIRTAG_UUID]).watchlist_id == ble_id
    assert (
        db.resolve_matched_watchlist_id(
            mac=None, ble_service_uuids=(_AIRTAG_UUID,)
        )
        == ble_id
    )


# ---- resolve_matched_ble_manufacturer_id_for_eval ----


def test_resolve_matched_ble_manufacturer_id_for_eval_hit(db):
    wid = _add_simple(db, "004c", "ble_manufacturer_id", severity="med")
    match = db.resolve_matched_ble_manufacturer_id_for_eval("004c")
    assert match is not None
    assert match.watchlist_id == wid
    assert match.severity == "med"
    assert match.device_category is None


def test_resolve_matched_ble_manufacturer_id_for_eval_populates_metadata(db):
    wid = _add_simple(db, "004c", "ble_manufacturer_id", severity="high")
    _attach_metadata(
        db, wid, device_category="hacking_tool", vendor="Apple, Inc."
    )
    match = db.resolve_matched_ble_manufacturer_id_for_eval("004c")
    assert match is not None
    assert match.device_category == "hacking_tool"
    assert match.manufacturer == "Apple, Inc."
    assert match.argus_record_id == f"argus-{wid}"


def test_resolve_matched_ble_manufacturer_id_for_eval_null_metadata_fields(db):
    """A row without a metadata side carries None for device_category /
    manufacturer / argus_record_id — the runtime overrides layer
    pass-throughs cleanly on each None."""
    _add_simple(db, "09c8", "ble_manufacturer_id")
    match = db.resolve_matched_ble_manufacturer_id_for_eval("09c8")
    assert match is not None
    assert match.device_category is None
    assert match.manufacturer is None
    assert match.argus_record_id is None


def test_resolve_matched_ble_manufacturer_id_for_eval_miss(db):
    _add_simple(db, "004c", "ble_manufacturer_id")
    assert db.resolve_matched_ble_manufacturer_id_for_eval("ffff") is None


def test_resolve_matched_ble_manufacturer_id_for_eval_none_and_empty(db):
    _add_simple(db, "004c", "ble_manufacturer_id")
    assert db.resolve_matched_ble_manufacturer_id_for_eval(None) is None
    assert db.resolve_matched_ble_manufacturer_id_for_eval("") is None


def test_resolve_matched_ble_manufacturer_id_for_eval_only_matches_own_pattern_type(db):
    """A '004c' MAC-typed row must not be returned by the
    ble_manufacturer_id matcher — pattern_type is part of the natural key."""
    _add_simple(db, "004c", "mac", severity="high")
    assert db.resolve_matched_ble_manufacturer_id_for_eval("004c") is None


# ---- resolve_matched_drone_id_prefix_for_eval ----


def test_resolve_matched_drone_id_prefix_for_eval_hit(db):
    wid = _add_simple(db, "21239ESA2", "drone_id_prefix", severity="med")
    match = db.resolve_matched_drone_id_prefix_for_eval("21239ESA2")
    assert match is not None
    assert match.watchlist_id == wid
    assert match.severity == "med"
    assert match.device_category is None


def test_resolve_matched_drone_id_prefix_for_eval_populates_metadata(db):
    wid = _add_simple(db, "178852", "drone_id_prefix", severity="med")
    _attach_metadata(db, wid, device_category="drone", vendor="Vision Aerial")
    match = db.resolve_matched_drone_id_prefix_for_eval("178852")
    assert match is not None
    assert match.device_category == "drone"
    assert match.manufacturer == "Vision Aerial"
    assert match.argus_record_id == f"argus-{wid}"


def test_resolve_matched_drone_id_prefix_for_eval_null_metadata_fields(db):
    _add_simple(db, "2137FDE1", "drone_id_prefix")
    match = db.resolve_matched_drone_id_prefix_for_eval("2137FDE1")
    assert match is not None
    assert match.device_category is None
    assert match.manufacturer is None
    assert match.argus_record_id is None


def test_resolve_matched_drone_id_prefix_for_eval_miss(db):
    _add_simple(db, "21239ESA2", "drone_id_prefix")
    assert db.resolve_matched_drone_id_prefix_for_eval("OTHER123") is None


def test_resolve_matched_drone_id_prefix_for_eval_none_and_empty(db):
    _add_simple(db, "21239ESA2", "drone_id_prefix")
    assert db.resolve_matched_drone_id_prefix_for_eval(None) is None
    assert db.resolve_matched_drone_id_prefix_for_eval("") is None


def test_resolve_matched_drone_id_prefix_for_eval_case_sensitive():
    """Both pattern_type matchers are exact-equality SQL — the canonical
    is uppercase so lowercase observations must be normalized at the
    boundary by callers (kismet._coerce_drone_id_prefix). This guards
    against a regression where someone adds LOWER() to the SQL."""


def test_resolve_matched_drone_id_prefix_for_eval_case_sensitive_in_sql(db):
    _add_simple(db, "21239ESA2", "drone_id_prefix")
    # Uppercase canonical hits.
    assert db.resolve_matched_drone_id_prefix_for_eval("21239ESA2") is not None
    # Lowercase does not hit — caller is responsible for canonicalizing.
    assert db.resolve_matched_drone_id_prefix_for_eval("21239esa2") is None


def test_resolve_matched_drone_id_prefix_for_eval_only_matches_own_pattern_type(db):
    """An 'ABCD1234' ssid-typed row must not be returned by the
    drone_id_prefix matcher."""
    _add_simple(db, "ABCD1234", "ssid", severity="high")
    assert db.resolve_matched_drone_id_prefix_for_eval("ABCD1234") is None


# ---------------------------- file mode (POSIX) ----------------------------


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes only")
def test_fresh_database_is_chmod_0600(tmp_path):
    """REGRESSION: user-mode installs left lynceus.db at the process
    umask (typically 0644 — world-readable). Evidence rows can carry
    operator GPS and probe SSIDs; system-mode already chmods to 0640
    via setup, but user-mode had no equivalent. Database.__init__ now
    forces 0600 on first creation."""
    db_path = str(tmp_path / "fresh.db")
    d = Database(db_path)
    try:
        mode = stat.S_IMODE(os.stat(db_path).st_mode)
        assert mode == 0o600, f"expected 0o600, got {oct(mode)}"
    finally:
        d.close()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes only")
def test_reopening_database_preserves_existing_mode(tmp_path):
    """Operator-set modes (e.g. the 0640 root:lynceus that the
    system-mode installer applies) must survive a daemon restart.
    Database.__init__ only chmods on first creation, not on reopen."""
    db_path = str(tmp_path / "preexisting.db")
    Database(db_path).close()
    # Operator chmods to a non-default mode.
    os.chmod(db_path, 0o640)
    d = Database(db_path)
    try:
        mode = stat.S_IMODE(os.stat(db_path).st_mode)
        assert mode == 0o640, f"expected 0o640 preserved, got {oct(mode)}"
    finally:
        d.close()


# ---- import_runs (migration 012) ------------------------------------------
#
# Per-import metadata table. Powers the staleness signal at /settings
# and the poller's startup log line. record_import_run writes one row
# per successful import; get_latest_import_run reads the most recent
# by imported_at (NOT exported_at — see method docstring).


def test_get_latest_import_run_empty_returns_none(db):
    """Fresh DB has no import runs recorded → None. Backward-compat
    invariant: an empty DB / no imports yet must not crash the
    staleness signal, just say so cleanly."""
    assert db.get_latest_import_run() is None


def test_record_and_get_latest_import_run_roundtrip(db):
    """The basic write/read shape. Every column populates."""
    rid = db.record_import_run(
        imported_at=1700001000,
        exported_at=1699900000,
        source="/var/lib/lynceus/argus-cache/v1.2.3__argus_export.csv",
        record_count=17786,
    )
    assert rid > 0
    latest = db.get_latest_import_run()
    assert latest is not None
    assert latest["imported_at"] == 1700001000
    assert latest["exported_at"] == 1699900000
    assert latest["source"] == "/var/lib/lynceus/argus-cache/v1.2.3__argus_export.csv"
    assert latest["record_count"] == 17786


def test_record_import_run_accepts_null_exported_at_and_source(db):
    """exported_at is nullable: legacy CSVs without a parseable
    `# meta:` line land here as None. source / record_count are
    similarly nullable for the same defensive reason."""
    db.record_import_run(
        imported_at=1700001000,
        exported_at=None,
        source=None,
        record_count=None,
    )
    latest = db.get_latest_import_run()
    assert latest is not None
    assert latest["exported_at"] is None
    assert latest["source"] is None
    assert latest["record_count"] is None


def test_get_latest_import_run_returns_most_recent_by_imported_at(db):
    """Tiebreaker is descending imported_at, NOT exported_at — an
    operator re-importing an older CSV on top of a newer one is
    deliberately reverting and the freshness card must show the
    active import."""
    # Earlier import with a NEWER export.
    db.record_import_run(
        imported_at=1700001000,
        exported_at=1799999999,  # far future export
        source="newer-export.csv",
        record_count=100,
    )
    # Later import with an OLDER export.
    db.record_import_run(
        imported_at=1700002000,
        exported_at=1699000000,
        source="older-export.csv",
        record_count=50,
    )
    latest = db.get_latest_import_run()
    assert latest is not None
    # The later-imported row wins, even though its export is older.
    assert latest["source"] == "older-export.csv"
    assert latest["imported_at"] == 1700002000


def test_watchlist_pattern_type_counts_empty_returns_zero_for_each_type(db):
    """Empty watchlist returns zero for every pattern_type the schema
    admits — stable shape lets the /settings template render without
    branching on per-type presence."""
    counts = db.watchlist_pattern_type_counts()
    assert counts == {
        "mac": 0,
        "oui": 0,
        "ssid": 0,
        "ble_uuid": 0,
        "mac_range": 0,
        "ble_manufacturer_id": 0,
        "drone_id_prefix": 0,
    }


def test_watchlist_pattern_type_counts_groups_by_type(db):
    """Counts are per-pattern_type, not total — the operator-facing
    breakdown."""
    with db._conn:
        for pattern in ("aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"):
            db._conn.execute(
                "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
                "VALUES (?, 'mac', 'low', NULL)",
                (pattern,),
            )
        db._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
            "VALUES ('00:13:37', 'oui', 'low', NULL)"
        )
    counts = db.watchlist_pattern_type_counts()
    assert counts["mac"] == 2
    assert counts["oui"] == 1
    assert counts["ssid"] == 0


# ---------------------------------------------------------------------------
# Migration 014: devices.device_type CHECK extended to admit 'remote_id'.
# ---------------------------------------------------------------------------


def test_migration_014_file_present(db):
    names = sorted(p.name for p in db._migrations_dir.glob("*.sql"))
    assert "014_devices_remote_id.sql" in names


def test_migration_014_applied_on_fresh_db(db):
    rows = db._conn.execute(
        "SELECT version FROM schema_migrations ORDER BY version"
    ).fetchall()
    assert 14 in [r[0] for r in rows]


def test_migration_014_idempotent_second_open(db_path):
    Database(db_path).close()
    second = Database(db_path)
    rows = second._conn.execute(
        "SELECT COUNT(*) FROM schema_migrations WHERE version = 14"
    ).fetchone()
    assert rows[0] == 1
    second.close()


def test_migration_014_devices_check_admits_remote_id(db):
    """The whole point of the migration: a row with device_type='remote_id'
    inserts cleanly. Pre-rc5 the CHECK constraint rejected this."""
    db.upsert_device("aa:bb:cc:dd:ee:01", "remote_id", "DroneCorp", 0, 1000)
    row = db.get_device("aa:bb:cc:dd:ee:01")
    assert row is not None
    assert row["device_type"] == "remote_id"


def test_migration_014_devices_check_still_rejects_unknown(db):
    """CHECK enforcement intact — additive admission of 'remote_id'
    must not relax the constraint for arbitrary unknown values.
    Mirrors the existing test_invalid_device_type_rejected test that
    pins 'cellular' as still-rejected."""
    with pytest.raises(sqlite3.IntegrityError):
        db.upsert_device("aa:bb:cc:dd:ee:02", "zigbee", None, 0, 1000)


def test_migration_014_preserves_existing_columns(db):
    """The migration rebuilds the devices table — every column from
    migration 001 plus the additive columns from migration 006
    (probe_ssids, ble_name) must survive. A missed column in the
    INSERT staging step would silently drop data."""
    cols = {
        row[1]
        for row in db._conn.execute("PRAGMA table_info(devices)").fetchall()
    }
    assert cols == {
        "mac",
        "device_type",
        "first_seen",
        "last_seen",
        "sighting_count",
        "oui_vendor",
        "is_randomized",
        "notes",
        "probe_ssids",
        "ble_name",
    }


def test_migration_014_preserves_existing_rows_through_rebuild(tmp_path):
    """Stand up a v0.4.0-rc4-shaped DB (migrations 001-013 applied,
    014 not yet) carrying a representative spread of device rows
    plus a probe_ssids / ble_name payload, then open with the
    rc5 codepath (014 applies on the second open) and confirm
    every row survives the rebuild verbatim — including the
    additive migration-006 columns and the sighting_count counter
    that the upsert path would otherwise reset."""
    db_path = str(tmp_path / "rc4_shaped.db")

    # First open: apply all migrations through 014. We'll then
    # manually rewind by deleting the 014 schema_migrations row and
    # restoring the pre-014 devices table shape, so we can prove
    # the migration runner picks 014 up cleanly on the second open
    # with pre-existing rows in place.
    first = Database(db_path)
    first.ensure_location("loc", "Lab")
    first.upsert_device("aa:bb:cc:dd:ee:01", "wifi", "Acme", 0, 1000)
    first.upsert_device("aa:bb:cc:dd:ee:02", "ble", "BleVendor", 1, 1100)
    first.upsert_device("aa:bb:cc:dd:ee:03", "bt_classic", "BTVendor", 0, 1200)
    # Touch each device twice so sighting_count > 1 — proves the
    # counter is carried verbatim, not reset by the rebuild.
    first.upsert_device("aa:bb:cc:dd:ee:01", "wifi", "Acme", 0, 1010)
    first.upsert_device("aa:bb:cc:dd:ee:02", "ble", "BleVendor", 1, 1110)
    # Plant a probe_ssids JSON + ble_name so the migration-006
    # columns are non-trivially exercised through the rebuild.
    first._conn.execute(
        "UPDATE devices SET probe_ssids = ?, ble_name = ? WHERE mac = ?",
        ('["CafeWifi","HomeNet"]', "PixelBuds", "aa:bb:cc:dd:ee:02"),
    )
    first._conn.commit()
    first.close()

    # Rewind: remove the 014 row from schema_migrations AND swap
    # the devices table back to the pre-014 shape (without
    # 'remote_id' in the CHECK). This simulates a DB on disk that
    # was last opened by a pre-rc5 build.
    raw = sqlite3.connect(db_path)
    try:
        raw.execute("PRAGMA foreign_keys = OFF")
        raw.execute("DELETE FROM schema_migrations WHERE version = 14")
        raw.executescript(
            """
            CREATE TABLE devices_pre014(
              mac TEXT PRIMARY KEY,
              device_type TEXT NOT NULL CHECK(device_type IN ('wifi','ble','bt_classic')),
              first_seen INTEGER NOT NULL,
              last_seen INTEGER NOT NULL,
              sighting_count INTEGER NOT NULL DEFAULT 0,
              oui_vendor TEXT,
              is_randomized INTEGER NOT NULL CHECK(is_randomized IN (0,1)),
              notes TEXT,
              probe_ssids TEXT,
              ble_name TEXT
            );
            INSERT INTO devices_pre014 SELECT
              mac, device_type, first_seen, last_seen, sighting_count,
              oui_vendor, is_randomized, notes, probe_ssids, ble_name
            FROM devices;
            DROP TABLE devices;
            ALTER TABLE devices_pre014 RENAME TO devices;
            """
        )
        raw.commit()
    finally:
        raw.close()

    # Second open: 014 must apply cleanly, rebuilding the table
    # in place. Every row survives.
    second = Database(db_path)
    try:
        rows = {
            r["mac"]: dict(r)
            for r in second._conn.execute(
                "SELECT mac, device_type, first_seen, last_seen, "
                "sighting_count, oui_vendor, is_randomized, notes, "
                "probe_ssids, ble_name FROM devices ORDER BY mac"
            ).fetchall()
        }
        assert set(rows) == {
            "aa:bb:cc:dd:ee:01",
            "aa:bb:cc:dd:ee:02",
            "aa:bb:cc:dd:ee:03",
        }
        # device_type / vendor / randomized survive
        assert rows["aa:bb:cc:dd:ee:01"]["device_type"] == "wifi"
        assert rows["aa:bb:cc:dd:ee:01"]["oui_vendor"] == "Acme"
        assert rows["aa:bb:cc:dd:ee:01"]["is_randomized"] == 0
        assert rows["aa:bb:cc:dd:ee:02"]["device_type"] == "ble"
        assert rows["aa:bb:cc:dd:ee:02"]["is_randomized"] == 1
        assert rows["aa:bb:cc:dd:ee:03"]["device_type"] == "bt_classic"
        # Sighting counters survive (>1 proves the rebuild kept the
        # counter, not just the row).
        assert rows["aa:bb:cc:dd:ee:01"]["sighting_count"] == 2
        assert rows["aa:bb:cc:dd:ee:02"]["sighting_count"] == 2
        # First-seen / last-seen survive verbatim.
        assert rows["aa:bb:cc:dd:ee:01"]["first_seen"] == 1000
        assert rows["aa:bb:cc:dd:ee:01"]["last_seen"] == 1010
        # Migration-006 columns survive.
        assert rows["aa:bb:cc:dd:ee:02"]["probe_ssids"] == '["CafeWifi","HomeNet"]'
        assert rows["aa:bb:cc:dd:ee:02"]["ble_name"] == "PixelBuds"
        # And the new device_type is now insertable.
        second.upsert_device("aa:bb:cc:dd:ee:04", "remote_id", "DroneCorp", 0, 2000)
        new_row = second.get_device("aa:bb:cc:dd:ee:04")
        assert new_row is not None
        assert new_row["device_type"] == "remote_id"
    finally:
        second.close()


def test_migration_014_preserves_fk_from_sightings_to_devices(db):
    """sightings.mac REFERENCES devices(mac) — must survive the
    rebuild. Insert a remote_id device, attach a sighting, confirm
    the FK fires when the parent row is missing."""
    db.ensure_location("loc", "Lab")
    db.upsert_device("aa:bb:cc:dd:ee:01", "remote_id", "DroneCorp", 0, 1000)
    # FK target present → insert succeeds.
    db.insert_sighting("aa:bb:cc:dd:ee:01", 1000, -55, None, "loc")
    # FK target absent → insert raises.
    with pytest.raises(sqlite3.IntegrityError):
        db.insert_sighting("aa:bb:cc:dd:ee:99", 1001, -55, None, "loc")


def test_migration_014_preserves_fk_from_alerts_to_devices(db):
    """alerts.mac REFERENCES devices(mac) — must survive the rebuild.
    Same shape as the sightings FK check but exercises the second
    inbound FK."""
    db.ensure_location("loc", "Lab")
    db.upsert_device("aa:bb:cc:dd:ee:01", "remote_id", "DroneCorp", 0, 1000)
    # FK target present → insert succeeds.
    db.add_alert(
        ts=1000, rule_name="r", mac="aa:bb:cc:dd:ee:01", message="m", severity="low"
    )
    # FK target absent → insert raises.
    with pytest.raises(sqlite3.IntegrityError):
        db.add_alert(
            ts=1001,
            rule_name="r",
            mac="aa:bb:cc:dd:ee:99",
            message="m",
            severity="low",
        )


def test_migration_014_sql_replay_is_safe_rebuild(db_path):
    """Replaying 014's SQL directly via executescript (bypassing the
    runner's version-tracking short-circuit) is a safe full rebuild:
    every row carried in the staging-table INSERT survives, no
    column projection drops data, the CHECK constraint is the
    extended one. This guards the narrow recovery path for a DB
    where 014's row in schema_migrations is missing but the table
    has already been rebuilt (interrupted runner, crash mid-script).
    The broader migration-runner atomicity work (L-MIG-1/7) stays
    deferred."""
    db = Database(db_path)
    try:
        db.upsert_device("aa:bb:cc:dd:ee:01", "wifi", "Acme", 0, 1000)
        db.upsert_device("aa:bb:cc:dd:ee:02", "remote_id", "DroneCorp", 0, 1100)
        sql_path = db._migrations_dir / "014_devices_remote_id.sql"
        sql = sql_path.read_text(encoding="utf-8")
        db._conn.executescript(sql)
        # Both rows present after the replay rebuild.
        rows = {
            r["mac"]: dict(r)
            for r in db._conn.execute(
                "SELECT mac, device_type FROM devices ORDER BY mac"
            ).fetchall()
        }
        assert rows["aa:bb:cc:dd:ee:01"]["device_type"] == "wifi"
        assert rows["aa:bb:cc:dd:ee:02"]["device_type"] == "remote_id"
        # And the table still rejects unknown device_types — the
        # extended CHECK is intact after the replay.
        with pytest.raises(sqlite3.IntegrityError):
            db.upsert_device("aa:bb:cc:dd:ee:03", "zigbee", None, 0, 1200)
    finally:
        db.close()


def test_db_device_types_tuple_admits_remote_id(db):
    """db._DEVICE_TYPES is the validator the read-only web UI
    queries (list_devices, count_devices) use to reject bogus filter
    params. Extending it to admit 'remote_id' lets operators filter
    the /devices page by Remote-ID broadcaster type. Backward-compat:
    the existing four types still validate."""
    assert "remote_id" in Database._DEVICE_TYPES
    # The pre-rc5 set is still admitted.
    for existing in ("wifi", "ble", "bt_classic"):
        assert existing in Database._DEVICE_TYPES
    # And the validator accepts a remote_id filter without raising.
    assert db.list_devices(device_type="remote_id") == []
    assert db.count_devices(device_type="remote_id") == 0
    # Unknown types still rejected.
    with pytest.raises(ValueError):
        db.list_devices(device_type="zigbee")
