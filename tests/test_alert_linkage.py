"""Tests for migration 005: matched_watchlist_id linkage on alerts.

Plumbs the watchlist row that triggered an alert through the rules engine into
the alerts table, so v0.3 alert/ntfy surfaces can render watchlist_metadata for
the specific row that fired the alert. UI rendering is deferred; this layer
only captures the link.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from lynceus.config import Config
from lynceus.db import Database
from lynceus.kismet import FakeKismetClient
from lynceus.poller import poll_once
from lynceus.rules import Rule, Ruleset

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "kismet_devices.json"


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "lynceus.db")


@pytest.fixture
def db(db_path):
    d = Database(db_path)
    yield d
    d.close()


@pytest.fixture
def config(db_path):
    return Config(
        kismet_fixture_path=str(FIXTURE_PATH),
        db_path=db_path,
        location_id="testloc",
        location_label="Test Location",
        alert_dedup_window_seconds=0,
    )


@pytest.fixture
def fake_client():
    return FakeKismetClient(str(FIXTURE_PATH))


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


def test_migration_005_file_present(db):
    names = sorted(p.name for p in db._migrations_dir.glob("*.sql"))
    assert "005_alert_watchlist_link.sql" in names


def test_migration_005_applied_on_fresh_db(db):
    rows = db._conn.execute("SELECT version FROM schema_migrations ORDER BY version").fetchall()
    assert 5 in [r[0] for r in rows]


def test_migration_005_idempotent_second_open(db_path):
    Database(db_path).close()
    second = Database(db_path)
    rows = second._conn.execute(
        "SELECT COUNT(*) FROM schema_migrations WHERE version = 5"
    ).fetchone()
    assert rows[0] == 1
    second.close()


def test_migration_005_applies_to_v02_shaped_db_preserves_alerts(tmp_path):
    """v0.2 DB (only migrations 1-3) with pre-existing alert rows; 004 + 005
    apply cleanly, alerts survive, and matched_watchlist_id is NULL on each."""
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
        INSERT INTO alerts(ts, rule_name, mac, message, severity)
          VALUES (1700000000, 'rule_a', NULL, 'preexisting alert', 'high');
        INSERT INTO alerts(ts, rule_name, mac, message, severity)
          VALUES (1700000100, 'rule_b', NULL, 'second alert', 'low');
        """
    )
    conn.commit()
    conn.close()

    db = Database(db_path)
    try:
        rows = db._conn.execute(
            "SELECT id, message, matched_watchlist_id FROM alerts ORDER BY id"
        ).fetchall()
        assert len(rows) == 2
        assert [r["message"] for r in rows] == ["preexisting alert", "second alert"]
        assert all(r["matched_watchlist_id"] is None for r in rows)
        applied = {
            r[0] for r in db._conn.execute("SELECT version FROM schema_migrations").fetchall()
        }
        assert {4, 5}.issubset(applied)
    finally:
        db.close()


def test_migration_005_applies_to_v03_shaped_db(tmp_path):
    """v0.3 DB (migrations 1-4 applied, alerts has no matched_watchlist_id);
    migration 005 lights up cleanly on re-open."""
    db_path = str(tmp_path / "v03.db")
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
        CREATE TABLE watchlist_metadata(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          watchlist_id INTEGER NOT NULL UNIQUE REFERENCES watchlist(id) ON DELETE CASCADE,
          argus_record_id TEXT NOT NULL UNIQUE,
          device_category TEXT NOT NULL,
          confidence INTEGER CHECK (confidence IS NULL OR confidence BETWEEN 0 AND 100),
          vendor TEXT,
          source TEXT,
          source_url TEXT,
          source_excerpt TEXT,
          fcc_id TEXT,
          geographic_scope TEXT,
          first_seen INTEGER,
          last_verified INTEGER,
          notes TEXT,
          created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
          updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
        );
        INSERT INTO schema_migrations(version, applied_at)
          VALUES (1, 1), (2, 2), (3, 3), (4, 4);
        INSERT INTO watchlist(pattern, pattern_type, severity, description)
          VALUES ('aa:bb:cc:dd:ee:ff', 'mac', 'high', NULL);
        """
    )
    conn.commit()
    conn.close()

    db = Database(db_path)
    try:
        applied = {
            r[0] for r in db._conn.execute("SELECT version FROM schema_migrations").fetchall()
        }
        assert 5 in applied
        cols = {row[1] for row in db._conn.execute("PRAGMA table_info(alerts)").fetchall()}
        assert "matched_watchlist_id" in cols
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Schema introspection.
# ---------------------------------------------------------------------------


def test_matched_watchlist_id_column_present(db):
    cols = db._conn.execute("PRAGMA table_info(alerts)").fetchall()
    by_name = {row[1]: row for row in cols}
    assert "matched_watchlist_id" in by_name
    assert by_name["matched_watchlist_id"][2].upper() == "INTEGER"


def test_matched_watchlist_id_is_nullable(db):
    cols = db._conn.execute("PRAGMA table_info(alerts)").fetchall()
    by_name = {row[1]: row for row in cols}
    # PRAGMA table_info notnull column: 0 means NULL allowed.
    assert by_name["matched_watchlist_id"][3] == 0


def test_matched_watchlist_id_has_fk_to_watchlist(db):
    fks = db._conn.execute("PRAGMA foreign_key_list(alerts)").fetchall()
    matches = [fk for fk in fks if fk[3] == "matched_watchlist_id"]
    assert len(matches) == 1
    fk = matches[0]
    # (id, seq, table, from, to, on_update, on_delete, match)
    assert fk[2] == "watchlist"
    assert fk[4] == "id"
    assert fk[6] == "SET NULL"


def test_matched_watchlist_id_has_no_check_constraint(db):
    sql = db._conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='alerts'"
    ).fetchone()[0]
    # Only the pre-existing severity/acknowledged CHECKs should be present.
    assert sql.count("CHECK") == 2


# ---------------------------------------------------------------------------
# add_alert: explicit matched_watchlist_id parameter.
# ---------------------------------------------------------------------------


def test_add_alert_default_matched_id_is_null(db):
    aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
    row = db._conn.execute(
        "SELECT matched_watchlist_id FROM alerts WHERE id = ?", (aid,)
    ).fetchone()
    assert row["matched_watchlist_id"] is None


def test_add_alert_explicit_matched_id_persists(db):
    wl = _add_watchlist(db, "aa:bb:cc:dd:ee:ff")
    db.upsert_device("aa:bb:cc:dd:ee:ff", "wifi", "Acme", 0, 100)
    aid = db.add_alert(
        ts=100,
        rule_name="r",
        mac="aa:bb:cc:dd:ee:ff",
        message="m",
        severity="low",
        matched_watchlist_id=wl,
    )
    row = db._conn.execute(
        "SELECT matched_watchlist_id FROM alerts WHERE id = ?", (aid,)
    ).fetchone()
    assert row["matched_watchlist_id"] == wl


# ---------------------------------------------------------------------------
# resolve_matched_watchlist_id: tiebreaker logic.
# ---------------------------------------------------------------------------


def test_resolve_returns_none_when_no_match(db):
    _add_watchlist(db, "11:22:33:44:55:66", "mac")
    assert db.resolve_matched_watchlist_id(mac="aa:bb:cc:dd:ee:ff") is None


def test_resolve_mac_wins_over_oui(db):
    mac_id = _add_watchlist(db, "aa:bb:cc:dd:ee:ff", "mac", "high")
    _add_watchlist(db, "aa:bb:cc", "oui", "med")
    assert db.resolve_matched_watchlist_id(mac="aa:bb:cc:dd:ee:ff") == mac_id


def test_resolve_oui_when_no_mac_row(db):
    oui_id = _add_watchlist(db, "aa:bb:cc", "oui", "med")
    assert db.resolve_matched_watchlist_id(mac="aa:bb:cc:dd:ee:ff") == oui_id


def test_resolve_ssid_when_no_mac_or_oui(db):
    ssid_id = _add_watchlist(db, "EvilSSID", "ssid", "med")
    assert db.resolve_matched_watchlist_id(mac="aa:bb:cc:dd:ee:ff", ssid="EvilSSID") == ssid_id


def test_resolve_ble_uuid_when_no_other_match(db):
    uuid = "0000fd5a-0000-1000-8000-00805f9b34fb"
    ble_id = _add_watchlist(db, uuid, "ble_uuid", "high")
    assert (
        db.resolve_matched_watchlist_id(
            mac="aa:bb:cc:dd:ee:ff",
            ble_service_uuids=(uuid,),
        )
        == ble_id
    )


# ---------------------------------------------------------------------------
# Rules engine integration via poll_once: matched_watchlist_id population.
# ---------------------------------------------------------------------------


def _alerts(db: Database) -> list[dict]:
    rows = db._conn.execute(
        "SELECT id, rule_name, mac, severity, matched_watchlist_id FROM alerts ORDER BY id"
    ).fetchall()
    return [dict(r) for r in rows]


def test_rule_fires_from_mac_watchlist_match_links_mac_row(db, config, fake_client):
    mac_id = _add_watchlist(db, "a4:83:e7:11:22:33", "mac", "high")
    rs = Ruleset(
        rules=[
            Rule(
                name="apple_mac",
                rule_type="watchlist_mac",
                severity="high",
                patterns=["a4:83:e7:11:22:33"],
            )
        ]
    )
    poll_once(fake_client, db, config, 1700001000, ruleset=rs)
    alerts = _alerts(db)
    assert len(alerts) == 1
    assert alerts[0]["matched_watchlist_id"] == mac_id


def test_rule_fires_from_oui_watchlist_match_links_oui_row(db, config, fake_client):
    oui_id = _add_watchlist(db, "a4:83:e7", "oui", "high")
    rs = Ruleset(
        rules=[
            Rule(
                name="apple_oui",
                rule_type="watchlist_oui",
                severity="high",
                patterns=["a4:83:e7"],
            )
        ]
    )
    poll_once(fake_client, db, config, 1700001000, ruleset=rs)
    alerts = _alerts(db)
    assert len(alerts) == 1
    assert alerts[0]["matched_watchlist_id"] == oui_id


def test_rule_fires_from_ssid_watchlist_match_links_ssid_row(db, config, fake_client):
    ssid_id = _add_watchlist(db, "HomeNet", "ssid", "med")
    rs = Ruleset(
        rules=[
            Rule(
                name="rogue_ssid",
                rule_type="watchlist_ssid",
                severity="med",
                patterns=["HomeNet"],
            )
        ]
    )
    poll_once(fake_client, db, config, 1700001000, ruleset=rs)
    alerts = _alerts(db)
    assert len(alerts) == 1
    assert alerts[0]["matched_watchlist_id"] == ssid_id


def test_rule_fires_from_ble_uuid_watchlist_match_links_ble_row(db, config, fake_client):
    uuid = "0000fd5a-0000-1000-8000-00805f9b34fb"
    ble_id = _add_watchlist(db, uuid, "ble_uuid", "high")
    rs = Ruleset(
        rules=[
            Rule(
                name="airtag",
                rule_type="ble_uuid",
                severity="high",
                patterns=[uuid],
            )
        ]
    )
    poll_once(fake_client, db, config, 1700001000, ruleset=rs)
    alerts = _alerts(db)
    assert len(alerts) == 1
    assert alerts[0]["matched_watchlist_id"] == ble_id


def test_tiebreaker_mac_pattern_wins_over_oui(db, config, fake_client):
    mac_id = _add_watchlist(db, "a4:83:e7:11:22:33", "mac", "high")
    _add_watchlist(db, "a4:83:e7", "oui", "med")
    rs = Ruleset(
        rules=[
            Rule(
                name="apple_oui",
                rule_type="watchlist_oui",
                severity="med",
                patterns=["a4:83:e7"],
            )
        ]
    )
    poll_once(fake_client, db, config, 1700001000, ruleset=rs)
    alerts = _alerts(db)
    assert len(alerts) == 1
    assert alerts[0]["matched_watchlist_id"] == mac_id


def test_new_non_randomized_device_alert_has_null_matched_id(db, config, fake_client):
    # Watchlist contains a row that *would* match the obs MAC if rules were
    # watchlist-based, but the new_non_randomized_device rule is not — so
    # matched_watchlist_id stays NULL.
    _add_watchlist(db, "a4:83:e7:11:22:33", "mac", "high")
    rs = Ruleset(
        rules=[Rule(name="new_dev", rule_type="new_non_randomized_device", severity="low")]
    )
    poll_once(fake_client, db, config, 1700001000, ruleset=rs)
    alerts = [a for a in _alerts(db) if a["mac"] == "a4:83:e7:11:22:33"]
    assert alerts, "expected at least one new_non_randomized_device alert for the apple mac"
    for a in alerts:
        assert a["matched_watchlist_id"] is None


def test_watchlist_rule_with_no_matching_db_row_yields_null(db, config, fake_client):
    # Rule matches the obs by pattern, but no watchlist DB row exists for it.
    rs = Ruleset(
        rules=[
            Rule(
                name="apple_mac",
                rule_type="watchlist_mac",
                severity="high",
                patterns=["a4:83:e7:11:22:33"],
            )
        ]
    )
    poll_once(fake_client, db, config, 1700001000, ruleset=rs)
    alerts = _alerts(db)
    assert len(alerts) == 1
    assert alerts[0]["matched_watchlist_id"] is None


def test_alert_matched_watchlist_id_works_with_mixed_case_pattern(db, config, fake_client):
    """L-RULES-1: an entry seeded with an uppercase MAC must still link
    to the alert that fires for the lowercase observation MAC.

    Pre-fix, ``seed_from_yaml`` stored the YAML pattern verbatim, so the
    poller's lowercase-normalized observation MAC missed the equality
    lookup in ``db.resolve_matched_watchlist_id`` and the alert landed
    with ``matched_watchlist_id = NULL`` — silently dropping the entire
    Argus metadata enrichment chain (vendor, severity hint, source URL)
    that v0.4.0 promises. THIS MUST FAIL PRE-FIX.
    """
    import yaml

    from lynceus.cli.seed_watchlist import seed_from_yaml

    yaml_path = config.db_path + ".wl.yaml"
    with open(yaml_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(
            {
                "entries": [
                    {
                        "pattern": "A4:83:E7:11:22:33",
                        "pattern_type": "mac",
                        "severity": "high",
                        "description": "uppercase apple mac",
                        "metadata": {
                            "device_category": "alpr",
                            "vendor": "Flock",
                            "confidence": 92,
                        },
                    }
                ]
            },
            f,
        )
    seed_from_yaml(db, yaml_path)

    rs = Ruleset(
        rules=[
            Rule(
                name="apple_mac",
                rule_type="watchlist_mac",
                severity="high",
                patterns=["a4:83:e7:11:22:33"],
            )
        ]
    )
    poll_once(fake_client, db, config, 1700001000, ruleset=rs)
    alerts = _alerts(db)
    assert len(alerts) == 1
    assert alerts[0]["matched_watchlist_id"] is not None
    enriched = db.get_alert_with_match(alerts[0]["id"])
    assert enriched is not None
    assert enriched["watchlist"] is not None
    assert enriched["watchlist"]["pattern"] == "a4:83:e7:11:22:33"
    md = enriched["watchlist_metadata"]
    assert md is not None
    assert md["vendor"] == "Flock"
    assert md["device_category"] == "alpr"
    assert md["confidence"] == 92


# ---------------------------------------------------------------------------
# FK ON DELETE SET NULL.
# ---------------------------------------------------------------------------


def test_fk_on_delete_set_null_clears_alert_link(db):
    wl = _add_watchlist(db, "aa:bb:cc:dd:ee:ff")
    db.upsert_device("aa:bb:cc:dd:ee:ff", "wifi", "Acme", 0, 100)
    aid = db.add_alert(
        ts=100,
        rule_name="r",
        mac="aa:bb:cc:dd:ee:ff",
        message="m",
        severity="low",
        matched_watchlist_id=wl,
    )
    with db._conn:
        db._conn.execute("DELETE FROM watchlist WHERE id = ?", (wl,))
    # Alert row must survive.
    row = db._conn.execute(
        "SELECT id, matched_watchlist_id FROM alerts WHERE id = ?", (aid,)
    ).fetchone()
    assert row is not None
    assert row["matched_watchlist_id"] is None


def test_fk_does_not_cascade_delete_alerts(db):
    wl = _add_watchlist(db, "aa:bb:cc:dd:ee:ff")
    db.upsert_device("aa:bb:cc:dd:ee:ff", "wifi", "Acme", 0, 100)
    db.add_alert(
        ts=100,
        rule_name="r",
        mac="aa:bb:cc:dd:ee:ff",
        message="m",
        severity="low",
        matched_watchlist_id=wl,
    )
    with db._conn:
        db._conn.execute("DELETE FROM watchlist WHERE id = ?", (wl,))
    count = db._conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    assert count == 1


# ---------------------------------------------------------------------------
# watchlist_mac_range — DB-delegated rule_type end-to-end.
# ---------------------------------------------------------------------------


def _add_mac_range_watchlist(
    db: Database,
    pattern: str,
    prefix: str,
    length: int,
    severity: str = "low",
    description: str | None = None,
) -> int:
    with db._conn:
        cur = db._conn.execute(
            "INSERT INTO watchlist("
            "pattern, pattern_type, severity, description, "
            "mac_range_prefix, mac_range_prefix_length) "
            "VALUES (?, 'mac_range', ?, ?, ?, ?)",
            (pattern, severity, description, prefix, length),
        )
        return int(cur.lastrowid)


def test_watchlist_mac_range_rule_fires_e2e_severity_from_db(db, config, fake_client):
    """End-to-end: a single empty-patterns watchlist_mac_range rule
    enables alert-firing for a MAC inside a watchlisted /28. The
    alert severity must match the matched DB row's severity (NOT
    the rule's severity, which is 'low' below — proving the
    DB-sourced-severity contract). matched_watchlist_id stamps the
    correct row id."""
    # a4:83:e7:11:22:33 is present in the kismet fixture; first 7 hex
    # chars are a483e71, so a /28 row with that prefix covers it.
    mac_range_id = _add_mac_range_watchlist(
        db,
        pattern="a4:83:e7:1/28",
        prefix="a483e71",
        length=28,
        severity="high",
        description="Argus mac_range corpus (synthetic)",
    )
    rs = Ruleset(
        rules=[
            Rule(
                name="argus_mac_range",
                rule_type="watchlist_mac_range",
                severity="low",  # ignored for this rule_type
                patterns=[],
            )
        ]
    )
    poll_once(fake_client, db, config, 1700001000, ruleset=rs)
    alerts = [a for a in _alerts(db) if a["mac"] == "a4:83:e7:11:22:33"]
    assert len(alerts) == 1
    assert alerts[0]["matched_watchlist_id"] == mac_range_id
    # Severity sourced from the matched DB row, not from rule.severity.
    assert alerts[0]["severity"] == "high"


def test_watchlist_mac_range_rule_e2e_miss_no_alert(db, config, fake_client):
    """If no watchlist mac_range row covers any observed MAC, the
    rule fires zero alerts even though it's enabled."""
    # Plant a /28 row that does NOT cover any fixture MAC.
    _add_mac_range_watchlist(
        db,
        pattern="de:ad:be:e/28",
        prefix="deadbee",
        length=28,
        severity="high",
    )
    rs = Ruleset(
        rules=[
            Rule(
                name="argus_mac_range",
                rule_type="watchlist_mac_range",
                severity="low",
                patterns=[],
            )
        ]
    )
    poll_once(fake_client, db, config, 1700001000, ruleset=rs)
    assert _alerts(db) == []


def test_watchlist_mac_range_rule_e2e_allowlist_audit_logs(db, config, fake_client, caplog):
    """A MAC inside a watchlisted mac_range that is ALSO in the
    allowlist must not fire an alert, but MUST emit the allowlist
    audit INFO line. The audit pass exists to surface operator
    misconfigurations where a watchlist hit is silently disabled
    by allowlist coverage; mac_range hits get the same treatment
    as every other watchlist_* type."""
    import logging as _logging

    from lynceus.allowlist import Allowlist, AllowlistEntry

    _add_mac_range_watchlist(
        db,
        pattern="a4:83:e7:1/28",
        prefix="a483e71",
        length=28,
        severity="high",
    )
    rs = Ruleset(
        rules=[
            Rule(
                name="argus_mac_range",
                rule_type="watchlist_mac_range",
                severity="low",
                patterns=[],
            )
        ]
    )
    allowlist = Allowlist(
        entries=[AllowlistEntry(pattern="a4:83:e7:11:22:33", pattern_type="mac")]
    )
    with caplog.at_level(_logging.INFO, logger="lynceus.poller"):
        poll_once(
            fake_client,
            db,
            config,
            1700001000,
            ruleset=rs,
            allowlist=allowlist,
        )
    # No alert fired — allowlist suppressed.
    apple_alerts = [a for a in _alerts(db) if a["mac"] == "a4:83:e7:11:22:33"]
    assert apple_alerts == []
    # But the audit pass logged the suppressed watchlist hit.
    audit = [
        r for r in caplog.records
        if "Allowlist suppressed watchlist hit" in r.getMessage()
        and "argus_mac_range" in r.getMessage()
    ]
    assert len(audit) == 1


# ---------------------------------------------------------------------------
# Delegation extension end-to-end: watchlist_mac, watchlist_oui,
# watchlist_ssid, ble_uuid with empty patterns each fire alerts whose
# severity is sourced from the matched DB row and whose
# matched_watchlist_id stamps the matched row id. Mirror of the
# watchlist_mac_range e2e block above; same fixture and same
# alert-shape assertions, one block per rule_type.
# ---------------------------------------------------------------------------

# The kismet fixture (tests/fixtures/kismet_devices.json) carries:
#   - a4:83:e7:11:22:33 wifi AP with SSID "HomeNet", vendor "Apple"
#   - 5a:11:22:33:44:55 BTLE with service_uuid 0000FD5A-... (airtag)
# These exact identifiers back the four delegation hits below.
_FIXTURE_MAC = "a4:83:e7:11:22:33"
_FIXTURE_OUI = "a4:83:e7"
_FIXTURE_SSID = "HomeNet"
_FIXTURE_BLE_UUID = "0000fd5a-0000-1000-8000-00805f9b34fb"


def test_watchlist_mac_delegation_rule_fires_e2e_severity_from_db(db, config, fake_client):
    """End-to-end: a single empty-patterns watchlist_mac rule enables
    alert-firing for every mac watchlist row. Severity from the DB
    row (NOT from rule.severity, which is 'low' here — proving the
    delegation contract). matched_watchlist_id stamps the row."""
    mac_id = _add_watchlist(db, _FIXTURE_MAC, "mac", "high")
    rs = Ruleset(
        rules=[
            Rule(
                name="argus_mac",
                rule_type="watchlist_mac",
                severity="low",  # ignored — DB severity wins
                patterns=[],
            )
        ]
    )
    poll_once(fake_client, db, config, 1700001000, ruleset=rs)
    alerts = [a for a in _alerts(db) if a["mac"] == _FIXTURE_MAC]
    assert len(alerts) == 1
    assert alerts[0]["matched_watchlist_id"] == mac_id
    assert alerts[0]["severity"] == "high"


def test_watchlist_mac_delegation_e2e_no_db_row_no_alert(db, config, fake_client):
    """Empty patterns + no matching DB row → no alert. Confirms that
    the empty-patterns idiom does NOT fire on every observation
    (which would be a catastrophic delegation contract bug)."""
    rs = Ruleset(
        rules=[
            Rule(
                name="argus_mac",
                rule_type="watchlist_mac",
                severity="low",
                patterns=[],
            )
        ]
    )
    poll_once(fake_client, db, config, 1700001000, ruleset=rs)
    assert _alerts(db) == []


def test_watchlist_oui_delegation_rule_fires_e2e_severity_from_db(db, config, fake_client):
    oui_id = _add_watchlist(db, _FIXTURE_OUI, "oui", "high")
    rs = Ruleset(
        rules=[
            Rule(
                name="argus_oui",
                rule_type="watchlist_oui",
                severity="low",  # ignored
                patterns=[],
            )
        ]
    )
    poll_once(fake_client, db, config, 1700001000, ruleset=rs)
    apple_alerts = [a for a in _alerts(db) if a["mac"].startswith(_FIXTURE_OUI + ":")]
    assert len(apple_alerts) == 1
    assert apple_alerts[0]["matched_watchlist_id"] == oui_id
    assert apple_alerts[0]["severity"] == "high"


def test_watchlist_oui_delegation_e2e_no_db_row_no_alert(db, config, fake_client):
    rs = Ruleset(
        rules=[
            Rule(
                name="argus_oui",
                rule_type="watchlist_oui",
                severity="low",
                patterns=[],
            )
        ]
    )
    poll_once(fake_client, db, config, 1700001000, ruleset=rs)
    assert _alerts(db) == []


def test_watchlist_ssid_delegation_rule_fires_e2e_severity_from_db(db, config, fake_client):
    ssid_id = _add_watchlist(db, _FIXTURE_SSID, "ssid", "med")
    rs = Ruleset(
        rules=[
            Rule(
                name="argus_ssid",
                rule_type="watchlist_ssid",
                severity="low",  # ignored
                patterns=[],
            )
        ]
    )
    poll_once(fake_client, db, config, 1700001000, ruleset=rs)
    # The kismet fixture row with HomeNet SSID is at _FIXTURE_MAC.
    homenet_alerts = [a for a in _alerts(db) if a["mac"] == _FIXTURE_MAC]
    assert len(homenet_alerts) == 1
    assert homenet_alerts[0]["matched_watchlist_id"] == ssid_id
    assert homenet_alerts[0]["severity"] == "med"


def test_watchlist_ssid_delegation_e2e_no_db_row_no_alert(db, config, fake_client):
    rs = Ruleset(
        rules=[
            Rule(
                name="argus_ssid",
                rule_type="watchlist_ssid",
                severity="low",
                patterns=[],
            )
        ]
    )
    poll_once(fake_client, db, config, 1700001000, ruleset=rs)
    assert _alerts(db) == []


def test_ble_uuid_delegation_rule_fires_e2e_severity_from_db(db, config, fake_client):
    ble_id = _add_watchlist(db, _FIXTURE_BLE_UUID, "ble_uuid", "high")
    rs = Ruleset(
        rules=[
            Rule(
                name="argus_ble_uuid",
                rule_type="ble_uuid",
                severity="low",  # ignored
                patterns=[],
            )
        ]
    )
    poll_once(fake_client, db, config, 1700001000, ruleset=rs)
    # Fixture's BTLE device with the airtag UUID is mac 5a:11:22:33:44:55.
    ble_alerts = [a for a in _alerts(db) if a["mac"] == "5a:11:22:33:44:55"]
    assert len(ble_alerts) == 1
    assert ble_alerts[0]["matched_watchlist_id"] == ble_id
    assert ble_alerts[0]["severity"] == "high"


def test_ble_uuid_delegation_e2e_no_db_row_no_alert(db, config, fake_client):
    rs = Ruleset(
        rules=[
            Rule(
                name="argus_ble_uuid",
                rule_type="ble_uuid",
                severity="low",
                patterns=[],
            )
        ]
    )
    poll_once(fake_client, db, config, 1700001000, ruleset=rs)
    assert _alerts(db) == []


# ---------------------------------------------------------------------------
# get_alert_with_match.
# ---------------------------------------------------------------------------


def test_get_alert_with_match_includes_alert_columns(db):
    aid = db.add_alert(ts=500, rule_name="r", mac=None, message="boom", severity="med")
    alert = db.get_alert_with_match(aid)
    assert alert is not None
    assert alert["id"] == aid
    assert alert["ts"] == 500
    assert alert["rule_name"] == "r"
    assert alert["mac"] is None
    assert alert["message"] == "boom"
    assert alert["severity"] == "med"
    assert alert["acknowledged"] == 0
    assert alert["matched_watchlist_id"] is None


def test_get_alert_with_match_returns_none_for_missing(db):
    assert db.get_alert_with_match(99999) is None


def test_get_alert_with_match_null_match_means_null_watchlist(db):
    aid = db.add_alert(ts=100, rule_name="r", mac=None, message="m", severity="low")
    alert = db.get_alert_with_match(aid)
    assert alert is not None
    assert alert["matched_watchlist_id"] is None
    assert alert["watchlist"] is None
    assert alert["watchlist_metadata"] is None


def test_get_alert_with_match_includes_watchlist_when_linked(db):
    wl = _add_watchlist(db, "aa:bb:cc:dd:ee:ff", "mac", "high", "stolen laptop")
    db.upsert_device("aa:bb:cc:dd:ee:ff", "wifi", "Acme", 0, 100)
    aid = db.add_alert(
        ts=100,
        rule_name="r",
        mac="aa:bb:cc:dd:ee:ff",
        message="m",
        severity="high",
        matched_watchlist_id=wl,
    )
    alert = db.get_alert_with_match(aid)
    assert alert is not None
    assert alert["matched_watchlist_id"] == wl
    assert alert["watchlist"] is not None
    assert alert["watchlist"]["id"] == wl
    assert alert["watchlist"]["pattern"] == "aa:bb:cc:dd:ee:ff"
    assert alert["watchlist"]["pattern_type"] == "mac"
    assert alert["watchlist"]["severity"] == "high"
    assert alert["watchlist"]["description"] == "stolen laptop"
    assert alert["watchlist_metadata"] is None


def test_get_alert_with_match_includes_watchlist_and_metadata(db):
    wl = _add_watchlist(db, "aa:bb:cc:dd:ee:ff", "mac", "high")
    db.upsert_metadata(
        wl,
        {
            "argus_record_id": "argus-001",
            "device_category": "lpr",
            "confidence": 80,
            "vendor": "Flock",
        },
    )
    db.upsert_device("aa:bb:cc:dd:ee:ff", "wifi", "Acme", 0, 100)
    aid = db.add_alert(
        ts=100,
        rule_name="r",
        mac="aa:bb:cc:dd:ee:ff",
        message="m",
        severity="high",
        matched_watchlist_id=wl,
    )
    alert = db.get_alert_with_match(aid)
    assert alert is not None
    assert alert["watchlist"]["id"] == wl
    md = alert["watchlist_metadata"]
    assert md is not None
    assert md["argus_record_id"] == "argus-001"
    assert md["device_category"] == "lpr"
    assert md["confidence"] == 80
    assert md["vendor"] == "Flock"


def test_get_alert_with_match_validates_alert_id(db):
    with pytest.raises(ValueError):
        db.get_alert_with_match(0)
    with pytest.raises(ValueError):
        db.get_alert_with_match(-1)


# ---------------------------------------------------------------------------
# list_alerts_with_match.
# ---------------------------------------------------------------------------


def test_list_alerts_with_match_empty(db):
    assert db.list_alerts_with_match() == []


def test_list_alerts_with_match_returns_join_shape(db):
    wl = _add_watchlist(db, "aa:bb:cc:dd:ee:ff", "mac", "high", "linked")
    db.upsert_metadata(wl, {"argus_record_id": "argus-1", "device_category": "lpr"})
    db.upsert_device("aa:bb:cc:dd:ee:ff", "wifi", "Acme", 0, 100)
    db.add_alert(
        ts=200,
        rule_name="r",
        mac="aa:bb:cc:dd:ee:ff",
        message="linked",
        severity="high",
        matched_watchlist_id=wl,
    )
    db.add_alert(ts=100, rule_name="r", mac=None, message="unlinked", severity="low")
    rows = db.list_alerts_with_match()
    assert len(rows) == 2
    by_msg = {r["message"]: r for r in rows}
    assert by_msg["linked"]["watchlist"]["id"] == wl
    assert by_msg["linked"]["watchlist_metadata"]["argus_record_id"] == "argus-1"
    assert by_msg["unlinked"]["watchlist"] is None
    assert by_msg["unlinked"]["watchlist_metadata"] is None


def test_list_alerts_with_match_orders_by_ts_desc(db):
    db.add_alert(ts=100, rule_name="r", mac=None, message="oldest", severity="low")
    db.add_alert(ts=300, rule_name="r", mac=None, message="newest", severity="low")
    db.add_alert(ts=200, rule_name="r", mac=None, message="middle", severity="low")
    rows = db.list_alerts_with_match()
    assert [r["message"] for r in rows] == ["newest", "middle", "oldest"]


def test_list_alerts_with_match_supports_filter_dict(db):
    a1 = db.add_alert(ts=100, rule_name="r", mac=None, message="acked", severity="low")
    db.add_alert(ts=200, rule_name="r", mac=None, message="unacked", severity="low")
    db.add_alert(ts=300, rule_name="r2", mac=None, message="hi", severity="high")
    with db._conn:
        db._conn.execute("UPDATE alerts SET acknowledged = 1 WHERE id = ?", (a1,))
    assert [r["message"] for r in db.list_alerts_with_match({"acknowledged": True})] == ["acked"]
    assert [r["message"] for r in db.list_alerts_with_match({"severity": "high"})] == ["hi"]
    assert [r["message"] for r in db.list_alerts_with_match({"since_ts": 200})] == ["hi", "unacked"]


def test_list_alerts_with_match_pagination(db):
    for i in range(5):
        db.add_alert(ts=100 + i, rule_name="r", mac=None, message=f"m{i}", severity="low")
    page1 = db.list_alerts_with_match({"limit": 2, "offset": 0})
    page2 = db.list_alerts_with_match({"limit": 2, "offset": 2})
    page3 = db.list_alerts_with_match({"limit": 2, "offset": 4})
    assert [r["message"] for r in page1] == ["m4", "m3"]
    assert [r["message"] for r in page2] == ["m2", "m1"]
    assert [r["message"] for r in page3] == ["m0"]


def test_list_alerts_with_match_search_finds_message_and_rule_name(db):
    db.add_alert(ts=100, rule_name="apple_mac", mac=None, message="boom", severity="low")
    db.add_alert(ts=200, rule_name="r", mac=None, message="something apple", severity="low")
    db.add_alert(ts=300, rule_name="r", mac=None, message="unrelated", severity="low")
    rows = db.list_alerts_with_match({"search": "apple"})
    assert {r["message"] for r in rows} == {"boom", "something apple"}


def test_list_alerts_with_match_rejects_unknown_filter(db):
    with pytest.raises(ValueError):
        db.list_alerts_with_match({"bogus": "x"})


def test_list_alerts_with_match_validates_severity(db):
    with pytest.raises(ValueError):
        db.list_alerts_with_match({"severity": "critical"})


def test_list_alerts_with_match_validates_pagination(db):
    with pytest.raises(ValueError):
        db.list_alerts_with_match({"limit": 0})
    with pytest.raises(ValueError):
        db.list_alerts_with_match({"limit": 1001})
    with pytest.raises(ValueError):
        db.list_alerts_with_match({"offset": -1})


# ---------------------------------------------------------------------------
# Backward compat: existing list_alerts and get_alert results unchanged.
# ---------------------------------------------------------------------------


def test_list_alerts_shape_unchanged_by_migration_005(db):
    wl = _add_watchlist(db, "aa:bb:cc:dd:ee:ff")
    db.upsert_device("aa:bb:cc:dd:ee:ff", "wifi", "Acme", 0, 100)
    db.add_alert(
        ts=100,
        rule_name="r",
        mac="aa:bb:cc:dd:ee:ff",
        message="m",
        severity="low",
        matched_watchlist_id=wl,
    )
    rows = db.list_alerts()
    assert len(rows) == 1
    assert set(rows[0].keys()) == {
        "id",
        "ts",
        "rule_name",
        "mac",
        "message",
        "severity",
        "acknowledged",
    }


def test_get_alert_shape_unchanged_by_migration_005(db):
    wl = _add_watchlist(db, "aa:bb:cc:dd:ee:ff")
    db.upsert_device("aa:bb:cc:dd:ee:ff", "wifi", "Acme", 0, 100)
    aid = db.add_alert(
        ts=100,
        rule_name="r",
        mac="aa:bb:cc:dd:ee:ff",
        message="m",
        severity="low",
        matched_watchlist_id=wl,
    )
    alert = db.get_alert(aid)
    assert alert is not None
    # Existing keys: id, ts, rule_name, mac, message, severity, acknowledged, device.
    # No watchlist or matched_watchlist_id keys leak into the v0.2 shape.
    assert set(alert.keys()) == {
        "id",
        "ts",
        "rule_name",
        "mac",
        "message",
        "severity",
        "acknowledged",
        "device",
    }
