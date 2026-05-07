"""Tests for the v0.3 watchlist_metadata table and DB layer methods."""

import sqlite3

import pytest

from lynceus.db import Database


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "lynceus.db")


@pytest.fixture
def db(db_path):
    d = Database(db_path)
    yield d
    d.close()


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


# ---------------------------------------------------------------------------
# Migration: file presence and clean apply on a fresh DB.
# ---------------------------------------------------------------------------


def test_migration_file_present(db):
    names = sorted(p.name for p in db._migrations_dir.glob("*.sql"))
    assert "004_watchlist_metadata.sql" in names


def test_migration_004_applied_on_fresh_db(db):
    rows = db._conn.execute("SELECT version FROM schema_migrations ORDER BY version").fetchall()
    versions = [r[0] for r in rows]
    assert 4 in versions


def test_migration_004_creates_table(db):
    row = db._conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='watchlist_metadata'"
    ).fetchone()
    assert row is not None


def test_migration_004_idempotent_second_open(db_path):
    Database(db_path).close()
    second = Database(db_path)
    rows = second._conn.execute(
        "SELECT COUNT(*) FROM schema_migrations WHERE version = 4"
    ).fetchone()
    assert rows[0] == 1
    second.close()


def test_migration_004_applies_to_v02_shaped_db(tmp_path):
    """Build a v0.2-shaped DB (only migrations 001-003), seed watchlist rows,
    then re-open and confirm 004 applies cleanly without losing data."""
    db_path = str(tmp_path / "v02.db")
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE schema_migrations(version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);
        CREATE TABLE devices(
          mac TEXT PRIMARY KEY,
          device_type TEXT NOT NULL CHECK(device_type IN ('wifi','ble','bt_classic')),
          first_seen INTEGER NOT NULL,
          last_seen INTEGER NOT NULL,
          sighting_count INTEGER NOT NULL DEFAULT 0,
          oui_vendor TEXT,
          is_randomized INTEGER NOT NULL CHECK(is_randomized IN (0,1)),
          notes TEXT
        );
        CREATE TABLE locations(id TEXT PRIMARY KEY, label TEXT NOT NULL);
        CREATE TABLE sightings(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          mac TEXT NOT NULL REFERENCES devices(mac),
          ts INTEGER NOT NULL,
          rssi INTEGER,
          ssid TEXT,
          location_id TEXT NOT NULL REFERENCES locations(id)
        );
        CREATE TABLE watchlist(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          pattern TEXT NOT NULL,
          pattern_type TEXT NOT NULL CHECK(pattern_type IN ('mac','oui','ssid','ble_uuid')),
          severity TEXT NOT NULL CHECK(severity IN ('low','med','high')),
          description TEXT
        );
        CREATE TABLE alerts(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts INTEGER NOT NULL,
          rule_name TEXT NOT NULL,
          mac TEXT REFERENCES devices(mac),
          message TEXT NOT NULL,
          severity TEXT NOT NULL CHECK(severity IN ('low','med','high')),
          acknowledged INTEGER NOT NULL DEFAULT 0 CHECK(acknowledged IN (0,1))
        );
        CREATE TABLE poller_state(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE alert_actions(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          alert_id INTEGER NOT NULL REFERENCES alerts(id),
          action TEXT NOT NULL CHECK(action IN ('ack','unack')),
          ts INTEGER NOT NULL,
          actor TEXT NOT NULL,
          note TEXT
        );
        INSERT INTO schema_migrations(version, applied_at) VALUES (1, 1), (2, 2), (3, 3);
        INSERT INTO watchlist(pattern, pattern_type, severity, description)
          VALUES ('aa:bb:cc:dd:ee:ff', 'mac', 'high', 'preseeded');
        INSERT INTO watchlist(pattern, pattern_type, severity, description)
          VALUES ('00:13:37', 'oui', 'med', NULL);
        """
    )
    conn.commit()
    conn.close()

    db = Database(db_path)
    try:
        rows = db._conn.execute(
            "SELECT pattern, pattern_type, severity, description FROM watchlist ORDER BY id"
        ).fetchall()
        assert [tuple(r) for r in rows] == [
            ("aa:bb:cc:dd:ee:ff", "mac", "high", "preseeded"),
            ("00:13:37", "oui", "med", None),
        ]
        assert (
            db._conn.execute("SELECT COUNT(*) FROM schema_migrations WHERE version = 4").fetchone()[
                0
            ]
            == 1
        )
        assert (
            db._conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='watchlist_metadata'"
            ).fetchone()
            is not None
        )
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Schema introspection.
# ---------------------------------------------------------------------------


def test_schema_columns_present_with_correct_types(db):
    cols = db._conn.execute("PRAGMA table_info(watchlist_metadata)").fetchall()
    by_name = {row[1]: row for row in cols}
    expected = {
        "id": "INTEGER",
        "watchlist_id": "INTEGER",
        "argus_record_id": "TEXT",
        "device_category": "TEXT",
        "confidence": "INTEGER",
        "vendor": "TEXT",
        "source": "TEXT",
        "source_url": "TEXT",
        "source_excerpt": "TEXT",
        "fcc_id": "TEXT",
        "geographic_scope": "TEXT",
        "first_seen": "INTEGER",
        "last_verified": "INTEGER",
        "notes": "TEXT",
        "created_at": "INTEGER",
        "updated_at": "INTEGER",
    }
    assert set(by_name) == set(expected)
    for name, expected_type in expected.items():
        assert by_name[name][2].upper() == expected_type, name


def test_schema_id_is_primary_key(db):
    cols = db._conn.execute("PRAGMA table_info(watchlist_metadata)").fetchall()
    by_name = {row[1]: row for row in cols}
    assert by_name["id"][5] == 1


def test_schema_not_null_constraints(db):
    cols = db._conn.execute("PRAGMA table_info(watchlist_metadata)").fetchall()
    by_name = {row[1]: row for row in cols}
    assert by_name["watchlist_id"][3] == 1
    assert by_name["argus_record_id"][3] == 1
    assert by_name["device_category"][3] == 1
    assert by_name["created_at"][3] == 1
    assert by_name["updated_at"][3] == 1
    assert by_name["confidence"][3] == 0
    assert by_name["vendor"][3] == 0
    assert by_name["notes"][3] == 0


def test_schema_foreign_key_to_watchlist(db):
    fks = db._conn.execute("PRAGMA foreign_key_list(watchlist_metadata)").fetchall()
    assert len(fks) == 1
    fk = fks[0]
    # (id, seq, table, from, to, on_update, on_delete, match)
    assert fk[2] == "watchlist"
    assert fk[3] == "watchlist_id"
    assert fk[4] == "id"
    assert fk[6] == "CASCADE"


def test_schema_unique_on_watchlist_id(db):
    wl = _add_watchlist(db, "aa:bb:cc:dd:ee:ff")
    db.upsert_metadata(wl, {"argus_record_id": "argus-1", "device_category": "lpr"})
    with pytest.raises(sqlite3.IntegrityError):
        with db._conn:
            db._conn.execute(
                "INSERT INTO watchlist_metadata"
                "(watchlist_id, argus_record_id, device_category) VALUES (?, ?, ?)",
                (wl, "argus-2", "lpr"),
            )


def test_schema_unique_on_argus_record_id(db):
    wl1 = _add_watchlist(db, "aa:bb:cc:dd:ee:01")
    wl2 = _add_watchlist(db, "aa:bb:cc:dd:ee:02")
    db.upsert_metadata(wl1, {"argus_record_id": "argus-shared", "device_category": "lpr"})
    with pytest.raises(sqlite3.IntegrityError):
        with db._conn:
            db._conn.execute(
                "INSERT INTO watchlist_metadata"
                "(watchlist_id, argus_record_id, device_category) VALUES (?, ?, ?)",
                (wl2, "argus-shared", "dashcam"),
            )


def test_schema_check_on_confidence_enforced_low(db):
    wl = _add_watchlist(db, "aa:bb:cc:dd:ee:ff")
    with pytest.raises(sqlite3.IntegrityError):
        with db._conn:
            db._conn.execute(
                "INSERT INTO watchlist_metadata"
                "(watchlist_id, argus_record_id, device_category, confidence) "
                "VALUES (?, ?, ?, ?)",
                (wl, "argus-1", "lpr", -1),
            )


def test_schema_check_on_confidence_enforced_high(db):
    wl = _add_watchlist(db, "aa:bb:cc:dd:ee:ff")
    with pytest.raises(sqlite3.IntegrityError):
        with db._conn:
            db._conn.execute(
                "INSERT INTO watchlist_metadata"
                "(watchlist_id, argus_record_id, device_category, confidence) "
                "VALUES (?, ?, ?, ?)",
                (wl, "argus-1", "lpr", 101),
            )


def test_schema_default_timestamps_populated(db):
    wl = _add_watchlist(db, "aa:bb:cc:dd:ee:ff")
    with db._conn:
        db._conn.execute(
            "INSERT INTO watchlist_metadata"
            "(watchlist_id, argus_record_id, device_category) VALUES (?, ?, ?)",
            (wl, "argus-1", "lpr"),
        )
    row = db._conn.execute(
        "SELECT created_at, updated_at FROM watchlist_metadata WHERE watchlist_id = ?",
        (wl,),
    ).fetchone()
    assert isinstance(row["created_at"], int)
    assert isinstance(row["updated_at"], int)
    assert row["created_at"] > 0
    assert row["updated_at"] > 0


# ---------------------------------------------------------------------------
# upsert_metadata.
# ---------------------------------------------------------------------------


def test_upsert_metadata_insert_path(db):
    wl = _add_watchlist(db, "aa:bb:cc:dd:ee:ff")
    new_id = db.upsert_metadata(
        wl,
        {
            "argus_record_id": "argus-001",
            "device_category": "lpr",
            "confidence": 80,
            "vendor": "Flock",
            "source": "fcc",
            "source_url": "https://example.test/argus/1",
            "source_excerpt": "FCC ID lookup excerpt",
            "fcc_id": "ABC123",
            "geographic_scope": "US",
            "first_seen": 1700000000,
            "last_verified": 1700000100,
            "notes": "high-confidence",
        },
    )
    assert isinstance(new_id, int)
    assert new_id > 0
    row = db.get_metadata_by_watchlist_id(wl)
    assert row["argus_record_id"] == "argus-001"
    assert row["device_category"] == "lpr"
    assert row["confidence"] == 80
    assert row["vendor"] == "Flock"
    assert row["source"] == "fcc"
    assert row["source_url"] == "https://example.test/argus/1"
    assert row["source_excerpt"] == "FCC ID lookup excerpt"
    assert row["fcc_id"] == "ABC123"
    assert row["geographic_scope"] == "US"
    assert row["first_seen"] == 1700000000
    assert row["last_verified"] == 1700000100
    assert row["notes"] == "high-confidence"


def test_upsert_metadata_minimal_fields(db):
    wl = _add_watchlist(db, "aa:bb:cc:dd:ee:ff")
    new_id = db.upsert_metadata(
        wl,
        {"argus_record_id": "argus-001", "device_category": "lpr"},
    )
    row = db.get_metadata_by_watchlist_id(wl)
    assert row["id"] == new_id
    assert row["confidence"] is None
    assert row["vendor"] is None
    assert row["notes"] is None


def test_upsert_metadata_update_path_matched_by_argus_record_id(db):
    wl = _add_watchlist(db, "aa:bb:cc:dd:ee:ff")
    first_id = db.upsert_metadata(
        wl,
        {"argus_record_id": "argus-001", "device_category": "lpr", "confidence": 50},
    )
    second_id = db.upsert_metadata(
        wl,
        {
            "argus_record_id": "argus-001",
            "device_category": "lpr",
            "confidence": 90,
            "notes": "promoted",
        },
    )
    assert second_id == first_id
    by_argus = db.get_metadata_by_argus_record_id("argus-001")
    assert by_argus is not None
    assert by_argus["id"] == first_id
    assert by_argus["confidence"] == 90
    assert by_argus["notes"] == "promoted"
    count = db._conn.execute(
        "SELECT COUNT(*) FROM watchlist_metadata WHERE watchlist_id = ?",
        (wl,),
    ).fetchone()[0]
    assert count == 1


def test_upsert_metadata_rejects_missing_argus_record_id(db):
    wl = _add_watchlist(db, "aa:bb:cc:dd:ee:ff")
    with pytest.raises(ValueError):
        db.upsert_metadata(wl, {"device_category": "lpr"})


def test_upsert_metadata_rejects_missing_device_category(db):
    wl = _add_watchlist(db, "aa:bb:cc:dd:ee:ff")
    with pytest.raises(ValueError):
        db.upsert_metadata(wl, {"argus_record_id": "argus-001"})


def test_upsert_metadata_rejects_unknown_field(db):
    wl = _add_watchlist(db, "aa:bb:cc:dd:ee:ff")
    with pytest.raises(ValueError):
        db.upsert_metadata(
            wl,
            {
                "argus_record_id": "argus-001",
                "device_category": "lpr",
                "not_a_real_field": "x",
            },
        )


def test_upsert_metadata_rejects_non_int_watchlist_id(db):
    with pytest.raises(ValueError):
        db.upsert_metadata(
            "not-an-int",
            {"argus_record_id": "argus-001", "device_category": "lpr"},
        )


def test_upsert_metadata_rejects_non_dict_fields(db):
    wl = _add_watchlist(db, "aa:bb:cc:dd:ee:ff")
    with pytest.raises(ValueError):
        db.upsert_metadata(wl, "not-a-dict")


def test_upsert_metadata_confidence_zero_accepted(db):
    wl = _add_watchlist(db, "aa:bb:cc:dd:ee:ff")
    db.upsert_metadata(
        wl,
        {"argus_record_id": "argus-001", "device_category": "lpr", "confidence": 0},
    )
    assert db.get_metadata_by_watchlist_id(wl)["confidence"] == 0


def test_upsert_metadata_confidence_hundred_accepted(db):
    wl = _add_watchlist(db, "aa:bb:cc:dd:ee:ff")
    db.upsert_metadata(
        wl,
        {"argus_record_id": "argus-001", "device_category": "lpr", "confidence": 100},
    )
    assert db.get_metadata_by_watchlist_id(wl)["confidence"] == 100


def test_upsert_metadata_confidence_negative_rejected(db):
    wl = _add_watchlist(db, "aa:bb:cc:dd:ee:ff")
    with pytest.raises(sqlite3.IntegrityError):
        db.upsert_metadata(
            wl,
            {
                "argus_record_id": "argus-001",
                "device_category": "lpr",
                "confidence": -1,
            },
        )


def test_upsert_metadata_confidence_over_hundred_rejected(db):
    wl = _add_watchlist(db, "aa:bb:cc:dd:ee:ff")
    with pytest.raises(sqlite3.IntegrityError):
        db.upsert_metadata(
            wl,
            {
                "argus_record_id": "argus-001",
                "device_category": "lpr",
                "confidence": 101,
            },
        )


def test_upsert_metadata_confidence_none_accepted(db):
    wl = _add_watchlist(db, "aa:bb:cc:dd:ee:ff")
    db.upsert_metadata(
        wl,
        {"argus_record_id": "argus-001", "device_category": "lpr", "confidence": None},
    )
    assert db.get_metadata_by_watchlist_id(wl)["confidence"] is None


def test_upsert_metadata_updated_at_refreshes_created_at_preserved(db, monkeypatch):
    wl = _add_watchlist(db, "aa:bb:cc:dd:ee:ff")
    times = iter([1_700_000_000, 1_700_000_500])

    def fake_time():
        return next(times)

    monkeypatch.setattr("lynceus.db.time.time", fake_time)
    db.upsert_metadata(wl, {"argus_record_id": "argus-001", "device_category": "lpr"})
    first = db.get_metadata_by_watchlist_id(wl)
    db.upsert_metadata(wl, {"argus_record_id": "argus-001", "device_category": "lpr", "notes": "n"})
    second = db.get_metadata_by_watchlist_id(wl)
    assert first["created_at"] == 1_700_000_000
    assert second["created_at"] == 1_700_000_000
    assert second["updated_at"] == 1_700_000_500
    assert second["updated_at"] > first["updated_at"]


# ---------------------------------------------------------------------------
# get_metadata_by_watchlist_id / get_metadata_by_argus_record_id.
# ---------------------------------------------------------------------------


def test_get_metadata_by_watchlist_id_hit(db):
    wl = _add_watchlist(db, "aa:bb:cc:dd:ee:ff")
    db.upsert_metadata(wl, {"argus_record_id": "argus-001", "device_category": "lpr"})
    row = db.get_metadata_by_watchlist_id(wl)
    assert row is not None
    assert row["watchlist_id"] == wl
    assert row["argus_record_id"] == "argus-001"


def test_get_metadata_by_watchlist_id_miss(db):
    assert db.get_metadata_by_watchlist_id(99999) is None


def test_get_metadata_by_argus_record_id_hit(db):
    wl = _add_watchlist(db, "aa:bb:cc:dd:ee:ff")
    db.upsert_metadata(wl, {"argus_record_id": "argus-007", "device_category": "lpr"})
    row = db.get_metadata_by_argus_record_id("argus-007")
    assert row is not None
    assert row["watchlist_id"] == wl
    assert row["device_category"] == "lpr"


def test_get_metadata_by_argus_record_id_miss(db):
    assert db.get_metadata_by_argus_record_id("does-not-exist") is None


# ---------------------------------------------------------------------------
# list_watchlist_with_metadata.
# ---------------------------------------------------------------------------


def test_list_watchlist_with_metadata_empty_db_returns_empty(db):
    assert db.list_watchlist_with_metadata() == []


def test_list_watchlist_with_metadata_left_join_includes_unjoined_rows(db):
    wl1 = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "high")
    wl2 = _add_watchlist(db, "aa:bb:cc:dd:ee:02", "mac", "med")
    db.upsert_metadata(
        wl1,
        {"argus_record_id": "argus-001", "device_category": "lpr", "confidence": 90},
    )
    rows = db.list_watchlist_with_metadata()
    assert len(rows) == 2
    by_id = {r["id"]: r for r in rows}
    assert by_id[wl1]["argus_record_id"] == "argus-001"
    assert by_id[wl1]["device_category"] == "lpr"
    assert by_id[wl1]["confidence"] == 90
    assert by_id[wl2]["argus_record_id"] is None
    assert by_id[wl2]["device_category"] is None
    assert by_id[wl2]["confidence"] is None
    assert by_id[wl2]["metadata_id"] is None


def test_list_watchlist_with_metadata_filter_pattern_type(db):
    wl_mac = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "high")
    wl_oui = _add_watchlist(db, "00:13:37", "oui", "high")
    _add_watchlist(db, "EvilSSID", "ssid", "high")
    db.upsert_metadata(wl_mac, {"argus_record_id": "argus-mac", "device_category": "lpr"})
    db.upsert_metadata(wl_oui, {"argus_record_id": "argus-oui", "device_category": "dashcam"})
    rows = db.list_watchlist_with_metadata({"pattern_type": "mac"})
    assert [r["pattern"] for r in rows] == ["aa:bb:cc:dd:ee:01"]
    rows = db.list_watchlist_with_metadata({"pattern_type": "oui"})
    assert [r["pattern"] for r in rows] == ["00:13:37"]


def test_list_watchlist_with_metadata_filter_severity(db):
    wl_high = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "high")
    wl_med = _add_watchlist(db, "aa:bb:cc:dd:ee:02", "mac", "med")
    _add_watchlist(db, "aa:bb:cc:dd:ee:03", "mac", "low")
    db.upsert_metadata(wl_high, {"argus_record_id": "argus-h", "device_category": "lpr"})
    db.upsert_metadata(wl_med, {"argus_record_id": "argus-m", "device_category": "lpr"})
    rows = db.list_watchlist_with_metadata({"severity": "high"})
    assert [r["pattern"] for r in rows] == ["aa:bb:cc:dd:ee:01"]
    rows = db.list_watchlist_with_metadata({"severity": "low"})
    assert [r["pattern"] for r in rows] == ["aa:bb:cc:dd:ee:03"]
    assert rows[0]["argus_record_id"] is None


def test_list_watchlist_with_metadata_filter_device_category(db):
    wl_lpr = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "high")
    wl_dash = _add_watchlist(db, "aa:bb:cc:dd:ee:02", "mac", "high")
    _add_watchlist(db, "aa:bb:cc:dd:ee:03", "mac", "high")
    db.upsert_metadata(wl_lpr, {"argus_record_id": "argus-lpr", "device_category": "lpr"})
    db.upsert_metadata(wl_dash, {"argus_record_id": "argus-dash", "device_category": "dashcam"})
    rows = db.list_watchlist_with_metadata({"device_category": "lpr"})
    assert [r["pattern"] for r in rows] == ["aa:bb:cc:dd:ee:01"]
    rows = db.list_watchlist_with_metadata({"device_category": "dashcam"})
    assert [r["pattern"] for r in rows] == ["aa:bb:cc:dd:ee:02"]
    rows = db.list_watchlist_with_metadata({"device_category": "absent"})
    assert rows == []


def test_list_watchlist_with_metadata_combined_filters(db):
    wl_a = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "high")
    wl_b = _add_watchlist(db, "aa:bb:cc:dd:ee:02", "mac", "med")
    wl_c = _add_watchlist(db, "00:13:37", "oui", "high")
    db.upsert_metadata(wl_a, {"argus_record_id": "argus-a", "device_category": "lpr"})
    db.upsert_metadata(wl_b, {"argus_record_id": "argus-b", "device_category": "lpr"})
    db.upsert_metadata(wl_c, {"argus_record_id": "argus-c", "device_category": "lpr"})
    rows = db.list_watchlist_with_metadata(
        {"pattern_type": "mac", "severity": "high", "device_category": "lpr"}
    )
    assert [r["pattern"] for r in rows] == ["aa:bb:cc:dd:ee:01"]


def test_list_watchlist_with_metadata_orders_by_pattern_type_then_pattern(db):
    _add_watchlist(db, "EvilSSID", "ssid", "high")
    _add_watchlist(db, "11:22:33:44:55:66", "mac", "med")
    _add_watchlist(db, "aa:bb:cc:dd:ee:ff", "mac", "high")
    _add_watchlist(db, "00:13:37", "oui", "high")
    rows = db.list_watchlist_with_metadata()
    assert [(r["pattern_type"], r["pattern"]) for r in rows] == [
        ("mac", "11:22:33:44:55:66"),
        ("mac", "aa:bb:cc:dd:ee:ff"),
        ("oui", "00:13:37"),
        ("ssid", "EvilSSID"),
    ]


def test_list_watchlist_with_metadata_validates_pattern_type(db):
    with pytest.raises(ValueError):
        db.list_watchlist_with_metadata({"pattern_type": "cellular"})


def test_list_watchlist_with_metadata_validates_severity(db):
    with pytest.raises(ValueError):
        db.list_watchlist_with_metadata({"severity": "critical"})


def test_list_watchlist_with_metadata_rejects_unknown_filter(db):
    with pytest.raises(ValueError):
        db.list_watchlist_with_metadata({"bogus": "x"})


# ---------------------------------------------------------------------------
# Foreign-key cascade and backward compatibility.
# ---------------------------------------------------------------------------


def test_fk_cascade_delete_watchlist_removes_metadata(db):
    wl = _add_watchlist(db, "aa:bb:cc:dd:ee:ff")
    db.upsert_metadata(wl, {"argus_record_id": "argus-001", "device_category": "lpr"})
    assert db.get_metadata_by_watchlist_id(wl) is not None
    with db._conn:
        db._conn.execute("DELETE FROM watchlist WHERE id = ?", (wl,))
    assert db.get_metadata_by_watchlist_id(wl) is None
    count = db._conn.execute("SELECT COUNT(*) FROM watchlist_metadata").fetchone()[0]
    assert count == 0


def test_v02_watchlist_queries_unchanged_when_metadata_empty(db):
    _add_watchlist(db, "HomeNet", "ssid", "low", "trusted ssid")
    _add_watchlist(db, "aa:bb:cc:dd:ee:ff", "mac", "high", None)
    _add_watchlist(db, "00:13:37", "oui", "high", "hak5")
    _add_watchlist(db, "11:22:33:44:55:66", "mac", "med", None)
    rows = db.list_watchlist()
    assert [(r["pattern_type"], r["pattern"]) for r in rows] == [
        ("mac", "11:22:33:44:55:66"),
        ("mac", "aa:bb:cc:dd:ee:ff"),
        ("oui", "00:13:37"),
        ("ssid", "HomeNet"),
    ]
    assert db._conn.execute("SELECT COUNT(*) FROM watchlist_metadata").fetchone()[0] == 0
