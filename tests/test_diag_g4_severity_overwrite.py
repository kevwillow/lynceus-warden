"""Regression: G4 — operator-seeded watchlist rows OVERRIDE Argus on a
natural-key (pattern, pattern_type) collision; the conflict is surfaced,
not silently overwritten.

Was a diagnostic dump of the silent-overwrite bug; now hard-asserts the
fix. Operator decision is DECIDED POLICY: on collision the operator's
severity AND description are preserved, NO Argus metadata is attached
(signal integrity — attaching it would flip the row out of the
operator-seeded branch and re-enable the overwrite next import), the row
is counted in a distinct ``operator_preserved`` bucket (NOT
imported_new), and a per-row WARNING names the kept vs declined severity.

Path under fix (import_argus.py, import_csv Pass 3):
  - existing_md = get_metadata_by_argus_record_id(c.argus_id) -> None
    (operator row has no Argus metadata).
  - operator_wl = _watchlist_row_by_natural_key(...) -> finds the row.
  - operator_wl is not None  ->  preserve completely, no UPDATE, no
    upsert_metadata; report.operator_preserved += 1; WARN.

The second-import-still-preserves assertion proves no signal poisoning:
because no metadata was attached, the row re-reads operator-seeded and is
preserved again rather than adopted-then-overwritten.
"""

from __future__ import annotations

import csv
import logging

import pytest

from lynceus.cli.import_argus import EXPECTED_HEADER, OverrideConfig, import_csv
from lynceus.db import Database

pytestmark = pytest.mark.diagnostic

META_LINE = (
    "# meta: schema_version=21, exported_at=2026-05-17T15:53:27Z, "
    "record_count=1, confidence_threshold=0\n"
)

OPERATOR_MAC = "aa:bb:cc:11:22:33"


def _row(**overrides) -> dict[str, str]:
    base = {
        "argus_record_id": "argus-collide-1",
        "id": "1",
        "identifier": OPERATOR_MAC,
        "identifier_type": "mac",
        # device_category "unknown" resolves to severity "low" via
        # DEFAULT_CATEGORY_SEVERITIES -- deliberately LOWER than the
        # operator's "high" so the overwrite is unmistakable (a silent
        # downgrade of an operator escalation).
        "device_category": "unknown",
        "manufacturer": "ArgusVendor",
        "model": "ArgusModel",
        "confidence": "85",
        "source_type": "manufacturer_doc",
        "source_url": "https://example.com/argus",
        "source_excerpt": "argus excerpt",
        "geographic_scope": "US",
        "description": "argus-imported description",
        "first_seen": "2026-05-06T00:30:28Z",
        "last_verified": "2026-05-06T00:30:28Z",
        "notes": "",
    }
    base.update(overrides)
    return base


def _write_csv(path, rows) -> str:
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(META_LINE)
        w = csv.writer(f)
        w.writerow(EXPECTED_HEADER)
        for r in rows:
            w.writerow([r.get(c, "") for c in EXPECTED_HEADER])
    return str(path)


def _wl_row(db: Database, mac: str) -> dict | None:
    row = db._conn.execute(
        "SELECT id, pattern, pattern_type, severity, description FROM watchlist "
        "WHERE pattern = ? AND pattern_type = 'mac'",
        (mac,),
    ).fetchone()
    return dict(row) if row else None


def test_diag_g4_severity_overwrite(diag, tmp_path, caplog):
    db = Database(str(tmp_path / "g4.db"))

    # Operator seeds a watchlist row with severity HIGH, no Argus metadata.
    with db._conn:
        db._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
            "VALUES (?, 'mac', 'high', 'operator-seeded: escalated by hand')",
            (OPERATOR_MAC,),
        )
    before = _wl_row(db, OPERATOR_MAC)
    diag.fixture(f"operator-seeded watchlist row BEFORE import: {before}")
    diag.fixture(
        "Argus CSV: same natural key (aa:bb:cc:11:22:33, mac), "
        "device_category='unknown' -> resolved severity 'low'"
    )

    csv_path = _write_csv(tmp_path / "argus.csv", [_row()])
    with caplog.at_level(logging.WARNING, logger="lynceus.cli.import_argus"):
        report = import_csv(db, csv_path, OverrideConfig())

    after = _wl_row(db, OPERATOR_MAC)
    diag.observed(f"watchlist row AFTER import: {after}")
    diag.observed(
        f"severity transition: {before['severity']!r} -> {after['severity']!r}"
    )
    diag.observed(
        f"description transition: {before['description']!r} -> "
        f"{after['description']!r}"
    )
    diag.observed(
        f"report buckets: imported_new={report.imported_new} "
        f"updated={report.updated} unchanged={report.unchanged} "
        f"operator_preserved={report.operator_preserved} "
        f"errors={report.errors}"
    )
    md = db.get_metadata_by_argus_record_id("argus-collide-1")
    diag.observed(
        f"watchlist_metadata attached to operator row: "
        f"{md['watchlist_id'] if md else None} (expect None — not adopted)"
    )

    # --- Hard asserts: operator preserved, Argus declined.
    assert after["severity"] == "high", (
        f"operator severity must be PRESERVED; got {after['severity']!r}"
    )
    assert after["description"] == "operator-seeded: escalated by hand", (
        f"operator description must be PRESERVED; got {after['description']!r}"
    )
    assert report.operator_preserved == 1, (
        f"collision must count in operator_preserved, got "
        f"{report.operator_preserved}"
    )
    assert report.imported_new == 0, (
        f"operator collision must NOT count as imported_new, got "
        f"{report.imported_new}"
    )
    # Signal integrity: NO Argus metadata attached to the operator row.
    assert md is None, (
        "no Argus metadata may be attached to a preserved operator row "
        "(attaching it poisons the operator-seeded signal)"
    )
    # Per-row WARNING names the kept + declined severity.
    warns = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert any(
        "operator-seeded" in m and "'high'" in m and "'low'" in m for m in warns
    ), f"expected an operator-seeded kept/declined WARNING, got {warns!r}"

    # --- Second import: still preserved (proves no signal poisoning).
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="lynceus.cli.import_argus"):
        report2 = import_csv(db, csv_path, OverrideConfig())
    after2 = _wl_row(db, OPERATOR_MAC)
    md2 = db.get_metadata_by_argus_record_id("argus-collide-1")
    diag.observed(
        f"SECOND import: severity={after2['severity']!r} "
        f"operator_preserved={report2.operator_preserved} "
        f"imported_new={report2.imported_new} "
        f"metadata_attached={md2 is not None}"
    )
    assert after2["severity"] == "high", "second import must STILL preserve"
    assert md2 is None, "second import must STILL not attach metadata"
    assert report2.operator_preserved == 1, (
        "second import must re-report the same conflict (operator_preserved=1)"
    )
    assert report2.imported_new == 0

    diag.notes(
        "G4 FIXED: operator 'high' stays 'high', Argus 'low' declined; "
        "counted operator_preserved (not imported_new); WARNING emitted; "
        "no metadata attached. The second import re-reads the row as "
        "operator-seeded and preserves it again — proving the fix does not "
        "poison the signal by adopting the row on first contact."
    )
    db.close()
