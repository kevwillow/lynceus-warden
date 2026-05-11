"""Tests for the lynceus-seed-watchlist CLI."""

from __future__ import annotations

import logging

import yaml

from lynceus.cli.seed_watchlist import (
    main,
    seed_ble_uuids,
    seed_from_yaml,
    seed_threat_ouis,
)
from lynceus.db import Database
from lynceus.seeds.ble_uuids import TRACKER_UUIDS
from lynceus.seeds.threat_ouis import THREAT_OUIS


def _watchlist_rows(db: Database) -> list[dict]:
    return [dict(r) for r in db._conn.execute("SELECT * FROM watchlist").fetchall()]


def test_seed_threat_ouis_first_run_inserts_all(tmp_path):
    db = Database(str(tmp_path / "t.db"))
    try:
        inserted, skipped = seed_threat_ouis(db)
        assert inserted == len(THREAT_OUIS)
        assert skipped == 0
        rows = _watchlist_rows(db)
        assert len(rows) == len(THREAT_OUIS)
        assert {r["pattern"] for r in rows} == {e["pattern"] for e in THREAT_OUIS}
        assert all(r["pattern_type"] == "oui" for r in rows)
    finally:
        db.close()


def test_seed_threat_ouis_idempotent(tmp_path):
    db = Database(str(tmp_path / "t.db"))
    try:
        seed_threat_ouis(db)
        inserted, skipped = seed_threat_ouis(db)
        assert inserted == 0
        assert skipped == len(THREAT_OUIS)
        assert len(_watchlist_rows(db)) == len(THREAT_OUIS)
    finally:
        db.close()


def test_seed_from_yaml_valid_entries(tmp_path):
    yaml_path = tmp_path / "wl.yaml"
    yaml_path.write_text(
        yaml.safe_dump(
            {
                "entries": [
                    {
                        "pattern": "aa:bb:cc:dd:ee:ff",
                        "pattern_type": "mac",
                        "severity": "high",
                        "description": "test mac",
                    },
                    {
                        "pattern": "11:22:33",
                        "pattern_type": "oui",
                        "severity": "med",
                        "description": "test oui",
                    },
                    {
                        "pattern": "EvilSSID",
                        "pattern_type": "ssid",
                        "severity": "low",
                        "description": "test ssid",
                    },
                ]
            }
        )
    )
    db = Database(str(tmp_path / "t.db"))
    try:
        inserted, skipped = seed_from_yaml(db, str(yaml_path))
        assert inserted == 3
        assert skipped == 0
        assert len(_watchlist_rows(db)) == 3
    finally:
        db.close()


def test_seed_from_yaml_invalid_pattern_type_skipped(tmp_path):
    yaml_path = tmp_path / "wl.yaml"
    yaml_path.write_text(
        yaml.safe_dump(
            {
                "entries": [
                    {
                        "pattern": "aa:bb:cc",
                        "pattern_type": "cellular",
                        "severity": "high",
                        "description": "bad type",
                    },
                    {
                        "pattern": "11:22:33",
                        "pattern_type": "oui",
                        "severity": "low",
                        "description": "good",
                    },
                ]
            }
        )
    )
    db = Database(str(tmp_path / "t.db"))
    try:
        inserted, skipped = seed_from_yaml(db, str(yaml_path))
        assert inserted == 1
        assert skipped == 1
        rows = _watchlist_rows(db)
        assert len(rows) == 1
        assert rows[0]["pattern_type"] == "oui"
    finally:
        db.close()


def test_seed_from_yaml_invalid_severity_skipped(tmp_path):
    yaml_path = tmp_path / "wl.yaml"
    yaml_path.write_text(
        yaml.safe_dump(
            {
                "entries": [
                    {
                        "pattern": "aa:bb:cc",
                        "pattern_type": "oui",
                        "severity": "critical",
                        "description": "bad sev",
                    },
                    {
                        "pattern": "11:22:33",
                        "pattern_type": "oui",
                        "severity": "low",
                        "description": "good",
                    },
                ]
            }
        )
    )
    db = Database(str(tmp_path / "t.db"))
    try:
        inserted, skipped = seed_from_yaml(db, str(yaml_path))
        assert inserted == 1
        assert skipped == 1
    finally:
        db.close()


def test_seed_from_yaml_empty_pattern_skipped(tmp_path):
    yaml_path = tmp_path / "wl.yaml"
    yaml_path.write_text(
        yaml.safe_dump(
            {
                "entries": [
                    {
                        "pattern": "",
                        "pattern_type": "oui",
                        "severity": "low",
                        "description": "empty",
                    },
                    {
                        "pattern": "   ",
                        "pattern_type": "oui",
                        "severity": "low",
                        "description": "whitespace",
                    },
                    {
                        "pattern": "11:22:33",
                        "pattern_type": "oui",
                        "severity": "low",
                        "description": "good",
                    },
                ]
            }
        )
    )
    db = Database(str(tmp_path / "t.db"))
    try:
        inserted, skipped = seed_from_yaml(db, str(yaml_path))
        assert inserted == 1
        assert skipped == 2
    finally:
        db.close()


def test_main_neither_flag_returns_2(tmp_path):
    rc = main(["--db", str(tmp_path / "x.db")])
    assert rc == 2


def test_main_threat_ouis_returns_0(tmp_path):
    db_path = tmp_path / "x.db"
    rc = main(["--db", str(db_path), "--threat-ouis"])
    assert rc == 0
    db = Database(str(db_path))
    try:
        rows = _watchlist_rows(db)
        assert len(rows) == len(THREAT_OUIS)
    finally:
        db.close()


def test_seed_ble_uuids_first_run_inserts_all(tmp_path):
    db = Database(str(tmp_path / "t.db"))
    try:
        inserted, skipped = seed_ble_uuids(db)
        assert inserted == len(TRACKER_UUIDS)
        assert skipped == 0
        rows = _watchlist_rows(db)
        assert len(rows) == len(TRACKER_UUIDS)
        assert {r["pattern"] for r in rows} == {e["pattern"] for e in TRACKER_UUIDS}
        assert all(r["pattern_type"] == "ble_uuid" for r in rows)
    finally:
        db.close()


def test_main_ble_uuids_flag_returns_0(tmp_path):
    db_path = tmp_path / "x.db"
    rc = main(["--db", str(db_path), "--ble-uuids"])
    assert rc == 0
    db = Database(str(db_path))
    try:
        rows = _watchlist_rows(db)
        assert len(rows) == len(TRACKER_UUIDS)
        assert all(r["pattern_type"] == "ble_uuid" for r in rows)
    finally:
        db.close()


# ---------------------------------------------------------------------------
# L-RULES-1: write-time pattern normalization.
# ---------------------------------------------------------------------------


def test_seed_watchlist_normalizes_uppercase_mac_at_write(tmp_path):
    """YAML-authored uppercase MACs must land lowercase in the DB so the
    poller's lowercase-normalized observation MAC matches at lookup time.
    THIS MUST FAIL PRE-FIX (the seeder wrote the YAML pattern verbatim)."""
    yaml_path = tmp_path / "wl.yaml"
    yaml_path.write_text(
        yaml.safe_dump(
            {
                "entries": [
                    {
                        "pattern": "AA:BB:CC:DD:EE:FF",
                        "pattern_type": "mac",
                        "severity": "high",
                        "description": "uppercase mac",
                    }
                ]
            }
        )
    )
    db = Database(str(tmp_path / "t.db"))
    try:
        seed_from_yaml(db, str(yaml_path))
        rows = _watchlist_rows(db)
        assert len(rows) == 1
        assert rows[0]["pattern"] == "aa:bb:cc:dd:ee:ff"
    finally:
        db.close()


def test_seed_watchlist_normalizes_hyphen_mac_at_write(tmp_path):
    """Hyphen-separated MACs (Linux convention from /sys/class/net) coerce
    to canonical colon form."""
    yaml_path = tmp_path / "wl.yaml"
    yaml_path.write_text(
        yaml.safe_dump(
            {
                "entries": [
                    {
                        "pattern": "aa-bb-cc-dd-ee-ff",
                        "pattern_type": "mac",
                        "severity": "high",
                        "description": "hyphen mac",
                    }
                ]
            }
        )
    )
    db = Database(str(tmp_path / "t.db"))
    try:
        seed_from_yaml(db, str(yaml_path))
        rows = _watchlist_rows(db)
        assert len(rows) == 1
        assert rows[0]["pattern"] == "aa:bb:cc:dd:ee:ff"
    finally:
        db.close()


def test_seed_watchlist_rejects_malformed_mac(tmp_path, caplog):
    """A YAML entry whose pattern can't be normalized (here: 3-octet
    string declared as a full MAC) is skipped with a WARNING; the
    counter surfaces in a summary log line so silent drops are
    visible. Other valid entries in the same file still land."""
    yaml_path = tmp_path / "wl.yaml"
    yaml_path.write_text(
        yaml.safe_dump(
            {
                "entries": [
                    {
                        "pattern": "AA:BB:CC",
                        "pattern_type": "mac",
                        "severity": "high",
                        "description": "too short for mac",
                    },
                    {
                        "pattern": "11:22:33:44:55:66",
                        "pattern_type": "mac",
                        "severity": "low",
                        "description": "valid",
                    },
                ]
            }
        )
    )
    db = Database(str(tmp_path / "t.db"))
    try:
        with caplog.at_level(logging.WARNING, logger="lynceus.cli.seed_watchlist"):
            inserted, skipped = seed_from_yaml(db, str(yaml_path))
        assert inserted == 1
        assert skipped == 1
        rows = _watchlist_rows(db)
        assert [r["pattern"] for r in rows] == ["11:22:33:44:55:66"]
        assert "rejected for normalization" in caplog.text
        assert "1 rejected for normalization" in caplog.text
    finally:
        db.close()
