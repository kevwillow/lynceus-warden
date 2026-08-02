"""Diagnostic + guard: C2min(a) — ensure_location is deduped to once per
distinct location per tick.

Originally a reproduction dump (a stale snapshot showed two call sites:
poller.py pre-loop once/tick + once/observation inside the loop, the
latter re-committing the identical 'default' row N times a tick). The fix
keeps a per-tick set of already-ensured location ids so the per-obs call
fires only for a genuinely-new source_locations-remapped location. These
tests now HARD-ASSERT that behaviour:

  1. K obs, all default              -> ensure_location called ONCE
                                        (the pre-loop call); 1 location row.
  2. mix of default + a remapped loc -> EACH distinct location ensured
                                        exactly once (correctness guard:
                                        remapped ensuring must NOT break).
  3. same remapped loc across N obs  -> that location ensured exactly once.

ensure_location (db.py:668) opens a write transaction
(INSERT ... ON CONFLICT(id) DO UPDATE) on every call, so each avoided call
is a real avoided commit.
"""

from __future__ import annotations

import json

import pytest

import lynceus.poller as poller_mod
from lynceus.config import Config
from lynceus.db import Database
from lynceus.poller import poll_once

pytestmark = pytest.mark.diagnostic


def _wifi_record(i: int, sources: tuple[str, ...] = ()) -> dict:
    """A well-formed wifi record; ``sources`` populates kismet seenby so the
    observation carries source attribution for source_locations remapping."""
    rec: dict = {
        "kismet.device.base.macaddr": f"aa:bb:cc:00:00:{i:02x}",
        "kismet.device.base.type": "Wi-Fi AP",
        "kismet.device.base.first_time": 1_700_000_000,
        "kismet.device.base.last_time": 1_700_000_100,
        "kismet.device.base.manuf": "DiagVendor",
        "kismet.device.base.signal": {"kismet.common.signal.last_signal": -42},
    }
    if sources:
        rec["kismet.device.base.seenby"] = [
            {"kismet.common.seenby.source": {"kismet.datasource.name": s}}
            for s in sources
        ]
    return rec


def _run(tmp_path, records: list[dict], source_locations: dict[str, str] | None):
    """Run one poll tick over ``records``; return (db, config, ensure_calls,
    processed). ``ensure_calls`` is the ordered list of location_ids passed
    to ensure_location this tick (via a counting wrapper)."""
    fixture = tmp_path / "obs.json"
    fixture.write_text(json.dumps(records), encoding="utf-8")
    config = Config(
        kismet_fixture_path=str(fixture),
        db_path=str(tmp_path / "c2.db"),
        kismet_health_check_on_startup=False,
        evidence_capture_enabled=False,
    )
    db = Database(config.db_path)
    client = poller_mod.build_kismet_client(config)

    calls: list[str] = []
    real_ensure = db.ensure_location

    def _counting_ensure(location_id: str, label: str) -> None:
        calls.append(location_id)
        real_ensure(location_id, label)

    db.ensure_location = _counting_ensure  # type: ignore[method-assign]

    processed = poll_once(
        client, db, config, now_ts=1_700_001_000, source_locations=source_locations
    )
    return db, config, calls, processed


def _row_count(db: Database) -> int:
    return db._conn.execute("SELECT COUNT(*) FROM locations").fetchone()[0]


def test_diag_c2min_all_default_ensures_once(diag, tmp_path):
    records = [_wifi_record(i) for i in range(5)]
    db, config, calls, processed = _run(tmp_path, records, source_locations=None)

    diag.fixture("5 wifi obs, all at config.location_id, no source_locations")
    diag.observed(f"observations admitted (processed): {processed}")
    diag.observed(f"ensure_location() calls this tick: {calls}")
    diag.observed(f"locations table row count: {_row_count(db)}")
    diag.notes(
        "Common single-location case: the 5 per-observation calls collapse "
        "to nothing; only the pre-loop ensure of the default location fires "
        "(was 1 + 5 = 6 calls / 5 redundant commits before the dedup)."
    )

    # The dedup collapses the per-obs calls; only the pre-loop ensure fires.
    assert processed == 5
    assert calls == [config.location_id]            # exactly ONE call
    assert len(calls) == len(set(calls))            # no redundant re-ensure
    assert _row_count(db) == 1
    db.close()


def test_diag_c2min_mixed_default_and_remap_each_once(diag, tmp_path):
    # obs 0,2,4 default (no source); obs 1,3 seen by 'wlan1' -> remapped.
    records = [
        _wifi_record(0),
        _wifi_record(1, sources=("wlan1",)),
        _wifi_record(2),
        _wifi_record(3, sources=("wlan1",)),
        _wifi_record(4),
    ]
    db, config, calls, processed = _run(
        tmp_path, records, source_locations={"wlan1": "loc-wlan1"}
    )

    diag.fixture(
        "5 obs: 3 default + 2 seen-by wlan1; source_locations wlan1->loc-wlan1"
    )
    diag.observed(f"observations admitted (processed): {processed}")
    diag.observed(f"ensure_location() calls this tick: {calls}")
    diag.observed(f"locations table row count: {_row_count(db)}")
    diag.notes(
        "Correctness guard: the dedup must NOT swallow a genuinely-new "
        "remapped location. Default ensured once (pre-loop), loc-wlan1 "
        "ensured once on its first observation, second wlan1 obs skipped."
    )

    # Each distinct location ensured exactly once; remapped ensuring intact.
    assert processed == 5
    assert len(calls) == len(set(calls))
    assert set(calls) == {config.location_id, "loc-wlan1"}
    assert calls.count(config.location_id) == 1
    assert calls.count("loc-wlan1") == 1
    assert _row_count(db) == 2
    db.close()


def test_diag_c2min_same_remap_repeated_ensures_once(diag, tmp_path):
    # All 5 obs seen by 'wlan1' -> all remap to the SAME loc-wlan1.
    records = [_wifi_record(i, sources=("wlan1",)) for i in range(5)]
    db, config, calls, processed = _run(
        tmp_path, records, source_locations={"wlan1": "loc-wlan1"}
    )

    diag.fixture("5 obs all seen-by wlan1; source_locations wlan1->loc-wlan1")
    diag.observed(f"observations admitted (processed): {processed}")
    diag.observed(f"ensure_location() calls this tick: {calls}")
    diag.observed(f"locations table row count: {_row_count(db)}")
    diag.notes(
        "Same remapped location across all 5 obs collapses to a single "
        "ensure of loc-wlan1 (plus the pre-loop default). 5 obs -> 1 "
        "loc-wlan1 ensure, not 5."
    )

    # The repeated remapped location is ensured exactly once.
    assert processed == 5
    assert calls.count("loc-wlan1") == 1
    assert set(calls) == {config.location_id, "loc-wlan1"}
    assert len(calls) == len(set(calls))
    assert _row_count(db) == 2
    db.close()
