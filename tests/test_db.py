"""Tests for the SQLite persistence layer."""

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
