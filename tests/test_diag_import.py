"""Diagnostic dumps for ``lynceus-import-argus`` accounting.

The pre-smoke dry-exercise quantified the counter lies: re-importing
the bundled CSV produced 31 false-new + 21 false-updated counters
and 25 ``watchlist_metadata`` rows where ``updated_at`` was bumped
despite no content change. These tests reproduce the surface at a
unit-test scale with deterministic synthetic CSVs so the reviewer
can verify behavior against intent without needing live timing of
the bundled 22k-row import.
"""

from __future__ import annotations

import csv
import time

import pytest

from lynceus.cli.import_argus import (
    EXPECTED_HEADER,
    OverrideConfig,
    import_csv,
)
from lynceus.db import Database

pytestmark = pytest.mark.diagnostic


META_LINE = "# meta: schema_version=21, exported_at=2026-05-17T15:53:27Z, record_count=4, confidence_threshold=0\n"


def _row(**overrides) -> dict[str, str]:
    base = {
        "argus_record_id": "diag-rec-1",
        "id": "1",
        "identifier": "aa:bb:cc:11:22:33",
        "identifier_type": "mac",
        "device_category": "alpr",
        "manufacturer": "DiagVendor",
        "model": "DiagModel",
        "confidence": "85",
        "source_type": "manufacturer_doc",
        "source_url": "https://example.com/diag",
        "source_excerpt": "diag excerpt",
        "geographic_scope": "US",
        "description": "diag record",
        "first_seen": "2026-05-06T00:30:28Z",
        "last_verified": "2026-05-06T00:30:28Z",
        "notes": "",
    }
    base.update(overrides)
    return base


def _write_csv(path, rows, *, header=None):
    header = header if header is not None else EXPECTED_HEADER
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(META_LINE)
        w = csv.writer(f)
        w.writerow(header)
        for r in rows:
            w.writerow([r.get(c, "") for c in header])
    return str(path)


def _metadata_snapshot(db: Database) -> list[dict]:
    rows = db._conn.execute(
        "SELECT id, argus_record_id, watchlist_id, updated_at, created_at, vendor "
        "FROM watchlist_metadata ORDER BY id"
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Test 1 — SQL trace of a no-op re-import
# ---------------------------------------------------------------------------


def test_diag_import_argus_no_op_sql_trace(diag, tmp_path):
    csv_path = _write_csv(
        tmp_path / "diag.csv",
        [
            _row(argus_record_id="rec-mac-1", identifier="aa:bb:cc:11:22:33"),
            _row(argus_record_id="rec-mac-2", identifier="aa:bb:cc:11:22:44"),
            _row(argus_record_id="rec-oui-1", identifier_type="oui",
                 identifier="de:ad:be", manufacturer="OUIVendor"),
            _row(argus_record_id="rec-ssid-1", identifier_type="ssid_exact",
                 identifier="DiagSSID", manufacturer="SSIDVendor"),
        ],
    )

    db = Database(str(tmp_path / "diag.db"))

    diag.fixture("4-row CSV: 2 mac, 1 oui, 1 ssid_exact")

    diag.exercise("import_csv() first run -- populates DB")
    r1 = import_csv(db, csv_path, OverrideConfig())
    diag.observed(f"first run report: new={r1.imported_new} "
                  f"updated={r1.updated} unchanged={r1.unchanged} "
                  f"dropped={r1.dropped_severity_drop + r1.dropped_unknown_type + r1.dropped_geographic_filter + r1.dropped_mac_range + r1.dropped_low_confidence}")

    # Install SQL trace BEFORE the second run; capture only mutating
    # statements so noisy SELECT chatter doesn't dilute the dump.
    mutations: list[str] = []
    selects = {"count": 0}

    def capture(sql: str) -> None:
        upper = sql.upper().lstrip()
        if upper.startswith(("INSERT", "UPDATE", "DELETE", "REPLACE")):
            mutations.append(sql.strip())
        elif upper.startswith("SELECT"):
            selects["count"] += 1

    db._conn.set_trace_callback(capture)

    diag.exercise("import_csv() second run -- SAME CSV, no field changes")
    r2 = import_csv(db, csv_path, OverrideConfig())
    diag.observed(f"second run report: new={r2.imported_new} "
                  f"updated={r2.updated} unchanged={r2.unchanged}")
    diag.observed(f"second-run SELECT count (read-side traffic): "
                  f"{selects['count']}")
    diag.observed(f"second-run mutating-statement count: {len(mutations)}")
    diag.observed("--- second-run mutating statements (target table + verb) ---")
    for stmt in mutations:
        verb = stmt.split(None, 1)[0].upper()
        head = " ".join(stmt.split()[:6])
        diag.observed(f"  {verb}: {head}")

    diag.notes("Expected on an honest no-op: new=0, updated=0, "
               "unchanged=<total_rows>, mutating-statement count=1 "
               "(just the import_runs row that records the import "
               "happened). Any additional UPDATEs against "
               "watchlist_metadata or watchlist are the import "
               "thrashing the row needlessly.")
    db.close()


# ---------------------------------------------------------------------------
# Test 2 — argus_metadata row updated_at diff after no-op re-import
# ---------------------------------------------------------------------------


def test_diag_import_argus_metadata_thrash(diag, tmp_path):
    csv_path = _write_csv(
        tmp_path / "diag.csv",
        [
            _row(argus_record_id="rec-1"),
            _row(argus_record_id="rec-2", identifier="aa:bb:cc:dd:ee:01"),
            _row(argus_record_id="rec-3", identifier="aa:bb:cc:dd:ee:02"),
            _row(argus_record_id="rec-4", identifier_type="oui",
                 identifier="de:ad:be"),
        ],
    )
    db = Database(str(tmp_path / "diag.db"))

    diag.exercise("import_csv() first run")
    import_csv(db, csv_path, OverrideConfig())
    pre = _metadata_snapshot(db)
    diag.fixture(f"first-run watchlist_metadata snapshot ({len(pre)} rows):")
    for row in pre:
        diag.fixture(f"  {row}")

    # Sleep 1s so the upsert_metadata wall-clock now_ts differs if it
    # writes -- the diff is then unambiguous.
    time.sleep(1.1)

    diag.exercise("import_csv() second run -- identical CSV")
    import_csv(db, csv_path, OverrideConfig())
    post = _metadata_snapshot(db)
    diag.observed(f"second-run watchlist_metadata snapshot ({len(post)} rows):")
    for row in post:
        diag.observed(f"  {row}")

    diag.observed("--- per-row updated_at delta ---")
    pre_map = {r["id"]: r for r in pre}
    bumped = 0
    for row in post:
        pre_row = pre_map.get(row["id"], {})
        delta = row["updated_at"] - (pre_row.get("updated_at") or 0)
        marker = " <-- THRASHED" if delta > 0 else ""
        diag.observed(
            f"  id={row['id']} argus_record_id={row['argus_record_id']} "
            f"updated_at_delta={delta}{marker}"
        )
        if delta > 0:
            bumped += 1
    diag.observed(f"rows with updated_at bumped despite no content change: {bumped}")

    diag.notes("Per upsert_metadata (db.py:1842): when md_changed is True "
               "in import_argus the function calls into upsert_metadata, "
               "which UPDATEs updated_at unconditionally. The dry-exercise "
               "logged 25 such rows on the bundled CSV's no-op re-import. "
               "Any non-zero bumped count here corroborates that path is "
               "still active at the unit level.")
    db.close()


# ---------------------------------------------------------------------------
# Test 3 — per-type admit-vs-drop accounting
# ---------------------------------------------------------------------------


def test_diag_import_argus_admit_vs_drop(diag, tmp_path):
    rows = [
        # Supported identifier_types per IDENTIFIER_TYPE_MAP (import_argus.py:61):
        _row(argus_record_id="ok-mac", identifier_type="mac",
             identifier="aa:bb:cc:11:22:33"),
        _row(argus_record_id="ok-oui", identifier_type="oui",
             identifier="de:ad:be"),
        _row(argus_record_id="ok-ssid", identifier_type="ssid_exact",
             identifier="ExactSSID"),
        _row(argus_record_id="ok-ssidpat", identifier_type="ssid_pattern",
             identifier="*-pattern"),
        _row(argus_record_id="ok-ble", identifier_type="ble_uuid",
             identifier="0000180a-0000-1000-8000-00805f9b34fb"),
        _row(argus_record_id="ok-bleservice", identifier_type="ble_service",
             identifier="0000180f-0000-1000-8000-00805f9b34fb"),
        _row(argus_record_id="ok-blemfg", identifier_type="ble_manufacturer_id",
             identifier="0x004c"),
        _row(argus_record_id="ok-blecompany", identifier_type="ble_company_id",
             identifier="0x09c8"),
        _row(argus_record_id="ok-drone", identifier_type="drone_id_prefix",
             identifier="DIAG-DRONE-PREFIX"),
        _row(argus_record_id="ok-macrange", identifier_type="mac_range",
             identifier="aa:bb:cc:1/28"),
        # Unsupported types (should be dropped as unknown):
        _row(argus_record_id="bad-typo", identifier_type="ssid",
             identifier="LegacyTypeSSID"),
        _row(argus_record_id="bad-empty", identifier_type="",
             identifier="EmptyType"),
        _row(argus_record_id="bad-unknown", identifier_type="not_a_type",
             identifier="UnknownTypeIdent"),
        # Severity drop (severity_overrides config could downgrade to 'drop',
        # but default config admits all -- so this is here as a baseline).
        _row(argus_record_id="lowconf", identifier_type="mac",
             identifier="aa:bb:cc:99:99:99", confidence="10"),
        # Empty identifier:
        _row(argus_record_id="bad-empty-ident", identifier_type="mac",
             identifier=""),
    ]
    csv_path = _write_csv(tmp_path / "diag.csv", rows)
    db = Database(str(tmp_path / "diag.db"))

    diag.fixture(f"CSV total rows: {len(rows)} "
                 f"(10 supported types + 3 unsupported + 1 low-confidence "
                 f"baseline + 1 empty-identifier error)")
    diag.exercise("import_csv() with default OverrideConfig "
                  "(no geographic filter, no severity downgrade)")
    report = import_csv(db, csv_path, OverrideConfig(), min_confidence=70)
    diag.observed(f"report: total_rows={report.total_rows} "
                  f"imported_new={report.imported_new} "
                  f"updated={report.updated} unchanged={report.unchanged}")
    diag.observed(f"  dropped_unknown_type={report.dropped_unknown_type}")
    diag.observed(f"  dropped_severity_drop={report.dropped_severity_drop}")
    diag.observed(f"  dropped_geographic_filter={report.dropped_geographic_filter}")
    diag.observed(f"  dropped_mac_range={report.dropped_mac_range}")
    diag.observed(f"  dropped_low_confidence={report.dropped_low_confidence}")
    diag.observed(f"  normalization_failed={report.normalization_failed}")
    diag.observed(f"  errors={report.errors}")
    diag.observed(f"  error_log: {report.error_log}")

    # Cross-check by reading the DB directly.
    wl_rows = db._conn.execute(
        "SELECT pattern_type, COUNT(*) FROM watchlist GROUP BY pattern_type"
    ).fetchall()
    diag.observed(f"watchlist rows by pattern_type: "
                  f"{[(r[0], r[1]) for r in wl_rows]}")
    md_count = db._conn.execute(
        "SELECT COUNT(*) FROM watchlist_metadata"
    ).fetchone()[0]
    diag.observed(f"watchlist_metadata row count: {md_count}")

    diag.notes("Reviewer cross-check: imported_new + sum(dropped_*) + "
               "normalization_failed + errors SHOULD equal total_rows. Any "
               "shortfall indicates rows silently disappearing. The "
               "ssid_exact vs ssid_pattern split lands in watchlist as "
               "pattern_type 'ssid' (for ssid_exact) and 'ssid_pattern'.")
    db.close()
