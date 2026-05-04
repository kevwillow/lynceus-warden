"""Tests for the SQLite persistence layer."""

import sqlite3

import pytest

from talos.db import Database

MAC = "aa:bb:cc:dd:ee:ff"
LOC = "lab"


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "talos.db")


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
    assert any("talos" in part for part in db._migrations_dir.parts)


def test_migrations_dir_lists_both_files(db):
    names = sorted(p.name for p in db._migrations_dir.glob("*.sql"))
    assert names == ["001_initial.sql", "002_poller_state.sql"]


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
