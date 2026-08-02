"""Tests for the v0.3 metadata block in lynceus-seed-watchlist YAML."""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

import pytest
import yaml

from lynceus.cli.seed_watchlist import (
    _synthetic_argus_record_id,
    main,
    seed_ble_uuids,
    seed_from_yaml,
    seed_threat_ouis,
)
from lynceus.db import Database


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "lynceus.db")


@pytest.fixture
def db(db_path):
    d = Database(db_path)
    yield d
    d.close()


def _write_yaml(tmp_path: Path, name: str, data: dict) -> str:
    p = tmp_path / name
    p.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return str(p)


def _watchlist_count(db: Database) -> int:
    return int(db._conn.execute("SELECT COUNT(*) FROM watchlist").fetchone()[0])


def _metadata_count(db: Database) -> int:
    return int(db._conn.execute("SELECT COUNT(*) FROM watchlist_metadata").fetchone()[0])


# ---------------------------------------------------------------------------
# Backward compatibility — v0.2-shaped YAML and bundled lists.
# ---------------------------------------------------------------------------


def test_v02_yaml_no_metadata_loads_cleanly(tmp_path, db):
    path = _write_yaml(
        tmp_path,
        "wl.yaml",
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
            ]
        },
    )
    inserted, skipped = seed_from_yaml(db, path)
    assert inserted == 2
    assert skipped == 0
    assert _watchlist_count(db) == 2
    assert _metadata_count(db) == 0


def test_bundled_threat_ouis_creates_no_metadata_rows(db):
    seed_threat_ouis(db)
    assert _watchlist_count(db) > 0
    assert _metadata_count(db) == 0


def test_bundled_ble_uuids_creates_no_metadata_rows(db):
    seed_ble_uuids(db)
    assert _watchlist_count(db) > 0
    assert _metadata_count(db) == 0


# ---------------------------------------------------------------------------
# Full and partial metadata blocks.
# ---------------------------------------------------------------------------


def test_full_metadata_block_creates_complete_row(tmp_path, db):
    path = _write_yaml(
        tmp_path,
        "wl.yaml",
        {
            "entries": [
                {
                    "pattern": "0000fd5a-0000-1000-8000-00805f9b34fb",
                    "pattern_type": "ble_uuid",
                    "severity": "high",
                    "description": "AirTag",
                    "metadata": {
                        "argus_record_id": "argus-bleuuid-airtag",
                        "device_category": "tracker",
                        "confidence": 95,
                        "vendor": "Apple",
                        "source": "manufacturer_doc",
                        "source_url": "https://developer.apple.com/find-my/",
                        "source_excerpt": "Find My service excerpt",
                        "fcc_id": "BCG-A2187",
                        "geographic_scope": "global",
                        "first_seen": 1714820000,
                        "last_verified": 1714909700,
                        "notes": "AirTag service UUID",
                    },
                }
            ]
        },
    )
    inserted, skipped = seed_from_yaml(db, path)
    assert inserted == 1
    assert skipped == 0
    md = db.get_metadata_by_argus_record_id("argus-bleuuid-airtag")
    assert md is not None
    assert md["device_category"] == "tracker"
    assert md["confidence"] == 95
    assert md["vendor"] == "Apple"
    assert md["source"] == "manufacturer_doc"
    assert md["source_url"] == "https://developer.apple.com/find-my/"
    assert md["source_excerpt"] == "Find My service excerpt"
    assert md["fcc_id"] == "BCG-A2187"
    assert md["geographic_scope"] == "global"
    assert md["first_seen"] == 1714820000
    assert md["last_verified"] == 1714909700
    assert md["notes"] == "AirTag service UUID"


def test_partial_metadata_only_device_category_leaves_other_fields_null(tmp_path, db):
    path = _write_yaml(
        tmp_path,
        "wl.yaml",
        {
            "entries": [
                {
                    "pattern": "aa:bb:cc:dd:ee:ff",
                    "pattern_type": "mac",
                    "severity": "high",
                    "description": None,
                    "metadata": {"device_category": "tracker"},
                }
            ]
        },
    )
    inserted, _ = seed_from_yaml(db, path)
    assert inserted == 1
    assert _metadata_count(db) == 1
    md = db._conn.execute("SELECT * FROM watchlist_metadata").fetchone()
    assert md["device_category"] == "tracker"
    for col in (
        "confidence",
        "vendor",
        "source",
        "source_url",
        "source_excerpt",
        "fcc_id",
        "geographic_scope",
        "first_seen",
        "last_verified",
        "notes",
    ):
        assert md[col] is None
    assert md["argus_record_id"].startswith("yaml-")


# ---------------------------------------------------------------------------
# Validation errors — entries skipped, no DB write.
# ---------------------------------------------------------------------------


def test_missing_device_category_skips_entry(tmp_path, db, caplog):
    path = _write_yaml(
        tmp_path,
        "wl.yaml",
        {
            "entries": [
                {
                    "pattern": "aa:bb:cc:dd:ee:ff",
                    "pattern_type": "mac",
                    "severity": "high",
                    "metadata": {"vendor": "Apple"},
                }
            ]
        },
    )
    with caplog.at_level(logging.WARNING):
        inserted, skipped = seed_from_yaml(db, path)
    assert inserted == 0
    assert skipped == 1
    assert _watchlist_count(db) == 0
    assert _metadata_count(db) == 0
    assert "device_category" in caplog.text


def test_empty_metadata_block_treated_as_missing_device_category(tmp_path, db, caplog):
    path = _write_yaml(
        tmp_path,
        "wl.yaml",
        {
            "entries": [
                {
                    "pattern": "aa:bb:cc:dd:ee:ff",
                    "pattern_type": "mac",
                    "severity": "high",
                    "metadata": {},
                }
            ]
        },
    )
    with caplog.at_level(logging.WARNING):
        inserted, skipped = seed_from_yaml(db, path)
    assert inserted == 0
    assert skipped == 1
    assert "device_category" in caplog.text


def test_unknown_metadata_key_rejects_entry_to_catch_typos(tmp_path, db, caplog):
    path = _write_yaml(
        tmp_path,
        "wl.yaml",
        {
            "entries": [
                {
                    "pattern": "aa:bb:cc:dd:ee:ff",
                    "pattern_type": "mac",
                    "severity": "high",
                    "metadata": {
                        "device_category": "tracker",
                        "sourse_url": "https://typo.example/",
                    },
                }
            ]
        },
    )
    with caplog.at_level(logging.WARNING):
        inserted, skipped = seed_from_yaml(db, path)
    assert inserted == 0
    assert skipped == 1
    assert _watchlist_count(db) == 0
    assert _metadata_count(db) == 0
    assert "sourse_url" in caplog.text


@pytest.mark.parametrize("bad_value", [-1, 101, 150])
def test_invalid_int_confidence_skips_entry_before_db_write(tmp_path, db, caplog, bad_value):
    path = _write_yaml(
        tmp_path,
        "wl.yaml",
        {
            "entries": [
                {
                    "pattern": "aa:bb:cc:dd:ee:ff",
                    "pattern_type": "mac",
                    "severity": "high",
                    "metadata": {
                        "device_category": "tracker",
                        "confidence": bad_value,
                    },
                }
            ]
        },
    )
    with caplog.at_level(logging.WARNING):
        inserted, skipped = seed_from_yaml(db, path)
    assert inserted == 0
    assert skipped == 1
    assert _watchlist_count(db) == 0
    assert _metadata_count(db) == 0
    assert "confidence" in caplog.text


def test_non_int_confidence_skips_entry(tmp_path, db, caplog):
    path = _write_yaml(
        tmp_path,
        "wl.yaml",
        {
            "entries": [
                {
                    "pattern": "aa:bb:cc:dd:ee:ff",
                    "pattern_type": "mac",
                    "severity": "high",
                    "metadata": {"device_category": "tracker", "confidence": "high"},
                }
            ]
        },
    )
    with caplog.at_level(logging.WARNING):
        inserted, skipped = seed_from_yaml(db, path)
    assert inserted == 0
    assert skipped == 1
    assert _metadata_count(db) == 0
    assert "confidence" in caplog.text


# ---------------------------------------------------------------------------
# Synthetic argus_record_id helper.
# ---------------------------------------------------------------------------


def test_no_argus_record_id_generates_synthetic_yaml_prefix(tmp_path, db):
    path = _write_yaml(
        tmp_path,
        "wl.yaml",
        {
            "entries": [
                {
                    "pattern": "aa:bb:cc:dd:ee:ff",
                    "pattern_type": "mac",
                    "severity": "high",
                    "metadata": {"device_category": "tracker"},
                }
            ]
        },
    )
    seed_from_yaml(db, path)
    rows = db._conn.execute("SELECT argus_record_id FROM watchlist_metadata").fetchall()
    assert len(rows) == 1
    rec_id = rows[0]["argus_record_id"]
    assert rec_id.startswith("yaml-")
    assert len(rec_id) == len("yaml-") + 16


def test_synthetic_id_is_stable_for_same_pattern_and_type():
    a = _synthetic_argus_record_id("aa:bb:cc:dd:ee:ff", "mac")
    b = _synthetic_argus_record_id("aa:bb:cc:dd:ee:ff", "mac")
    assert a == b
    assert a.startswith("yaml-")


def test_synthetic_id_differs_for_different_pattern():
    a = _synthetic_argus_record_id("aa:bb:cc:dd:ee:ff", "mac")
    b = _synthetic_argus_record_id("11:22:33:44:55:66", "mac")
    assert a != b


def test_synthetic_id_differs_for_different_pattern_type():
    a = _synthetic_argus_record_id("0000fd5a", "ble_uuid")
    b = _synthetic_argus_record_id("0000fd5a", "ssid")
    assert a != b


def test_synthetic_id_matches_documented_construction():
    pattern = "aa:bb:cc:dd:ee:ff"
    ptype = "mac"
    expected = "yaml-" + hashlib.sha256(f"{pattern}:{ptype}".encode()).hexdigest()[:16]
    assert _synthetic_argus_record_id(pattern, ptype) == expected


def test_explicit_argus_record_id_used_verbatim_no_synthetic_generation(tmp_path, db):
    path = _write_yaml(
        tmp_path,
        "wl.yaml",
        {
            "entries": [
                {
                    "pattern": "aa:bb:cc:dd:ee:ff",
                    "pattern_type": "mac",
                    "severity": "high",
                    "metadata": {
                        "argus_record_id": "argus-explicit-123",
                        "device_category": "tracker",
                    },
                }
            ]
        },
    )
    seed_from_yaml(db, path)
    md = db.get_metadata_by_argus_record_id("argus-explicit-123")
    assert md is not None
    assert md["argus_record_id"] == "argus-explicit-123"


# ---------------------------------------------------------------------------
# Idempotency — same YAML re-seeded.
# ---------------------------------------------------------------------------


def test_reseed_same_yaml_idempotent_no_duplicate_metadata(tmp_path, db):
    path = _write_yaml(
        tmp_path,
        "wl.yaml",
        {
            "entries": [
                {
                    "pattern": "aa:bb:cc:dd:ee:ff",
                    "pattern_type": "mac",
                    "severity": "high",
                    "metadata": {
                        "device_category": "tracker",
                        "confidence": 80,
                    },
                }
            ]
        },
    )
    seed_from_yaml(db, path)
    seed_from_yaml(db, path)
    assert _watchlist_count(db) == 1
    assert _metadata_count(db) == 1


def test_reseed_yaml_with_synthetic_id_idempotent(tmp_path, db):
    entry = {
        "pattern": "aa:bb:cc:dd:ee:ff",
        "pattern_type": "mac",
        "severity": "high",
        "metadata": {"device_category": "tracker"},
    }
    path = _write_yaml(tmp_path, "wl.yaml", {"entries": [entry]})
    seed_from_yaml(db, path)
    md1 = db._conn.execute("SELECT id, argus_record_id FROM watchlist_metadata").fetchone()
    seed_from_yaml(db, path)
    md2 = db._conn.execute("SELECT id, argus_record_id FROM watchlist_metadata").fetchone()
    assert md1["id"] == md2["id"]
    assert md1["argus_record_id"] == md2["argus_record_id"]
    assert _metadata_count(db) == 1


def test_reseed_with_changed_metadata_updates_in_place(tmp_path, db):
    entry = {
        "pattern": "aa:bb:cc:dd:ee:ff",
        "pattern_type": "mac",
        "severity": "high",
        "metadata": {
            "argus_record_id": "argus-x",
            "device_category": "tracker",
            "confidence": 95,
        },
    }
    path = _write_yaml(tmp_path, "wl.yaml", {"entries": [entry]})
    seed_from_yaml(db, path)
    md1 = db.get_metadata_by_argus_record_id("argus-x")
    assert md1["confidence"] == 95

    entry["metadata"]["confidence"] = 80
    _write_yaml(tmp_path, "wl.yaml", {"entries": [entry]})
    seed_from_yaml(db, path)
    md2 = db.get_metadata_by_argus_record_id("argus-x")
    assert md2["confidence"] == 80
    assert _metadata_count(db) == 1


def test_reseed_changed_metadata_refreshes_updated_at_preserves_created_at(
    tmp_path, db, monkeypatch
):
    entry = {
        "pattern": "aa:bb:cc:dd:ee:ff",
        "pattern_type": "mac",
        "severity": "high",
        "metadata": {
            "argus_record_id": "argus-x",
            "device_category": "tracker",
            "confidence": 95,
        },
    }
    path = _write_yaml(tmp_path, "wl.yaml", {"entries": [entry]})
    times = iter([1_700_000_000, 1_700_000_500])
    monkeypatch.setattr("lynceus.db.time.time", lambda: next(times))

    seed_from_yaml(db, path)
    first = db.get_metadata_by_argus_record_id("argus-x")

    entry["metadata"]["confidence"] = 80
    _write_yaml(tmp_path, "wl.yaml", {"entries": [entry]})
    seed_from_yaml(db, path)
    second = db.get_metadata_by_argus_record_id("argus-x")

    assert second["created_at"] == first["created_at"]
    assert second["updated_at"] > first["updated_at"]


# ---------------------------------------------------------------------------
# Mixed entries.
# ---------------------------------------------------------------------------


def test_mixed_entries_some_with_metadata_some_without(tmp_path, db):
    path = _write_yaml(
        tmp_path,
        "wl.yaml",
        {
            "entries": [
                {
                    "pattern": "aa:bb:cc:dd:ee:01",
                    "pattern_type": "mac",
                    "severity": "high",
                    "description": "no metadata",
                },
                {
                    "pattern": "aa:bb:cc:dd:ee:02",
                    "pattern_type": "mac",
                    "severity": "high",
                    "metadata": {"device_category": "tracker"},
                },
                {
                    "pattern": "00:13:37",
                    "pattern_type": "oui",
                    "severity": "med",
                },
            ]
        },
    )
    inserted, skipped = seed_from_yaml(db, path)
    assert inserted == 3
    assert skipped == 0
    assert _watchlist_count(db) == 3
    assert _metadata_count(db) == 1


def test_mixed_valid_and_invalid_metadata_entries_continues(tmp_path, db, caplog):
    path = _write_yaml(
        tmp_path,
        "wl.yaml",
        {
            "entries": [
                {
                    "pattern": "aa:bb:cc:dd:ee:01",
                    "pattern_type": "mac",
                    "severity": "high",
                    "metadata": {"device_category": "tracker"},
                },
                {
                    "pattern": "aa:bb:cc:dd:ee:02",
                    "pattern_type": "mac",
                    "severity": "high",
                    "metadata": {"vendor": "Apple"},
                },
                {
                    "pattern": "aa:bb:cc:dd:ee:03",
                    "pattern_type": "mac",
                    "severity": "high",
                },
            ]
        },
    )
    with caplog.at_level(logging.WARNING):
        inserted, skipped = seed_from_yaml(db, path)
    assert inserted == 2
    assert skipped == 1
    assert _watchlist_count(db) == 2
    assert _metadata_count(db) == 1


# ---------------------------------------------------------------------------
# main() entrypoint and pre-existing rows.
# ---------------------------------------------------------------------------


def test_main_yaml_with_metadata_returns_zero(tmp_path):
    db_path = tmp_path / "x.db"
    yaml_path = tmp_path / "wl.yaml"
    yaml_path.write_text(
        yaml.safe_dump(
            {
                "entries": [
                    {
                        "pattern": "aa:bb:cc:dd:ee:ff",
                        "pattern_type": "mac",
                        "severity": "high",
                        "metadata": {"device_category": "tracker"},
                    }
                ]
            }
        )
    )
    rc = main(["--db", str(db_path), "--yaml", str(yaml_path)])
    assert rc == 0
    db = Database(str(db_path))
    try:
        assert _watchlist_count(db) == 1
        assert _metadata_count(db) == 1
    finally:
        db.close()


def test_preexisting_v02_row_attaches_metadata_on_reseed_with_block(tmp_path, db):
    path1 = _write_yaml(
        tmp_path,
        "wl1.yaml",
        {
            "entries": [
                {
                    "pattern": "aa:bb:cc:dd:ee:ff",
                    "pattern_type": "mac",
                    "severity": "high",
                    "description": "stage1",
                }
            ]
        },
    )
    seed_from_yaml(db, path1)
    assert _metadata_count(db) == 0

    path2 = _write_yaml(
        tmp_path,
        "wl2.yaml",
        {
            "entries": [
                {
                    "pattern": "aa:bb:cc:dd:ee:ff",
                    "pattern_type": "mac",
                    "severity": "high",
                    "description": "stage1",
                    "metadata": {"device_category": "tracker"},
                }
            ]
        },
    )
    inserted, skipped = seed_from_yaml(db, path2)
    assert inserted == 0
    assert skipped == 1
    assert _watchlist_count(db) == 1
    assert _metadata_count(db) == 1
