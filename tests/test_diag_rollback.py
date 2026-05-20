"""Diagnostic dumps for the migration rollback chain (H1).

``Database.rollback_to(target_version)`` reverses every applied
migration whose version is strictly greater than ``target_version``,
applying paired ``_down.sql`` files in descending order. Special
cases:

- Irreversible migrations (marker ``IRREVERSIBLE:`` in down file):
  schema_migrations row removed, SQL skipped, WARNING logged.
- Conditional-reverse migrations (011, 013, 014, 019): down asserts
  no rows of the now-disallowed type exist; raises
  ``sqlite3.IntegrityError`` otherwise.

These tests dump: which versions actually rolled back, the WARNING
output for irreversibles, the resulting ``schema_migrations`` row
set, and the table/column shape after rollback.
"""

from __future__ import annotations

import logging

import pytest

from lynceus.db import Database

pytestmark = pytest.mark.diagnostic


def _schema_snapshot(db: Database) -> dict:
    """Compact structural snapshot suitable for diff in a .log file."""
    tables_rows = db._conn.execute(
        "SELECT name, type FROM sqlite_master WHERE type IN ('table','index') "
        "AND name NOT LIKE 'sqlite_%' ORDER BY type, name"
    ).fetchall()
    tables = sorted({r["name"] for r in tables_rows if r["type"] == "table"})
    indexes = sorted({r["name"] for r in tables_rows if r["type"] == "index"})
    columns: dict[str, list[str]] = {}
    for t in tables:
        cols = db._conn.execute(f"PRAGMA table_info({t})").fetchall()
        columns[t] = [c["name"] for c in cols]
    return {"tables": tables, "indexes": indexes, "columns": columns}


def _format_snapshot(snap: dict) -> str:
    lines = []
    lines.append(f"  tables ({len(snap['tables'])}): {snap['tables']}")
    lines.append(f"  indexes ({len(snap['indexes'])}): {snap['indexes']}")
    for t in snap["tables"]:
        lines.append(f"  {t}: {snap['columns'][t]}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Test 1 — fully-applied forward chain rolled back to v15
# ---------------------------------------------------------------------------


def test_diag_rollback_to_v15(diag, tmp_path, caplog):
    db = Database(str(tmp_path / "diag.db"))
    before_versions = db.applied_versions()
    diag.fixture(f"forward-applied versions: {before_versions}")
    before_snap = _schema_snapshot(db)
    diag.fixture(f"pre-rollback schema:\n{_format_snapshot(before_snap)}")

    caplog.set_level(logging.INFO, logger="lynceus.db")
    diag.exercise("db.rollback_to(15) -- reverses 19, 18, 17, 16")
    rolled = db.rollback_to(15)
    diag.observed(f"rolled back (reverse order): {rolled}")
    diag.observed(f"applied_versions after: {db.applied_versions()}")

    after_snap = _schema_snapshot(db)
    diag.observed(f"post-rollback schema:\n{_format_snapshot(after_snap)}")

    removed_tables = sorted(set(before_snap["tables"]) - set(after_snap["tables"]))
    new_tables = sorted(set(after_snap["tables"]) - set(before_snap["tables"]))
    diag.observed(f"tables removed by rollback: {removed_tables}")
    diag.observed(f"tables added by rollback (should be empty): {new_tables}")

    diag.observed("--- log records emitted during rollback ---")
    for rec in caplog.records:
        if rec.name.startswith("lynceus"):
            diag.observed(f"  {rec.levelname} {rec.name}: {rec.getMessage()}")

    diag.notes("Each reversed migration is logged at INFO or higher by the "
               "runner. Reviewer: confirm reversed-versions list matches "
               "intent (every applied version > 15) and that no spurious "
               "'no _down.sql found' WARNINGs appear (those indicate a "
               "packaging bug, not an operator concern).")
    db.close()


# ---------------------------------------------------------------------------
# Test 2 — rollback crosses the irreversible-migration boundary (v10)
# ---------------------------------------------------------------------------


def test_diag_rollback_to_v10_irreversible(diag, tmp_path, caplog):
    db = Database(str(tmp_path / "diag.db"))
    before_versions = db.applied_versions()
    diag.fixture(f"forward-applied versions: {before_versions}")
    diag.fixture("migration 010 is IRREVERSIBLE; rollback to v9 would force "
                 "the runner to cross it. Rolling to v10 stops just above.")

    caplog.set_level(logging.INFO, logger="lynceus.db")
    diag.exercise("db.rollback_to(9) -- crosses the v10 irreversible boundary")
    try:
        rolled = db.rollback_to(9)
        diag.observed(f"rolled back: {rolled}")
        diag.observed(f"applied_versions after: {db.applied_versions()}")
    except Exception as exc:  # noqa: BLE001 -- diagnostic, surface + dump
        diag.observed(f"rollback_to raised: {type(exc).__name__}: {exc}")

    diag.observed("--- log records (WARNING level expected for v010) ---")
    for rec in caplog.records:
        if rec.name.startswith("lynceus") and rec.levelno >= logging.WARNING:
            diag.observed(f"  {rec.levelname} {rec.name}: {rec.getMessage()}")

    snap = _schema_snapshot(db)
    diag.observed(f"post-rollback schema:\n{_format_snapshot(snap)}")
    diag.notes("Per Database.rollback_to docstring + db.py:488-505: "
               "irreversible migrations skip the SQL layer but still remove "
               "the schema_migrations row so the chain continues. The data "
               "state changed by 010 (case-folding of watchlist.pattern) is "
               "NOT restored. Reviewer: confirm the WARNING explicitly names "
               "migration 010 and explains the data-state implication.")
    db.close()


# ---------------------------------------------------------------------------
# Test 3 — rollback target already met (no-op)
# ---------------------------------------------------------------------------


def test_diag_rollback_already_rolled_back(diag, tmp_path, caplog):
    db = Database(str(tmp_path / "diag.db"))

    diag.fixture(f"forward-applied versions: {db.applied_versions()}")
    diag.exercise("db.rollback_to(10) twice in succession")

    caplog.set_level(logging.INFO, logger="lynceus.db")
    first = db.rollback_to(10)
    after_first = db.applied_versions()
    diag.observed(f"first call rolled back: {first}")
    diag.observed(f"applied_versions after first call: {after_first}")

    caplog.clear()
    second = db.rollback_to(10)
    after_second = db.applied_versions()
    diag.observed(f"second call rolled back (should be empty): {second}")
    diag.observed(f"applied_versions after second call: {after_second}")
    diag.observed("--- log records for the no-op second call ---")
    for rec in caplog.records:
        if rec.name.startswith("lynceus"):
            diag.observed(f"  {rec.levelname} {rec.name}: {rec.getMessage()}")

    diag.notes("A no-op rollback returns an empty list. The runner should "
               "neither log a WARNING nor mutate schema_migrations. "
               "Reviewer: confirm the second call is silent and idempotent.")
    db.close()
