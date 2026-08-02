"""G5 regression: a wholly-failed import must NOT exit 0 and must NOT
record a false freshness row. Partial / clean / conflict-only behave per
the decided contract.

Originally a VERIFY-ONLY observation dump that proved the bug; promoted to
hard asserts when the fix landed (`fix(import): exit non-zero and skip
freshness when an import wholly fails`). Still `diagnostic`-marked so it
runs pre-push via `pytest -m diagnostic`, mirroring the G4 diagnostic.

The bug (current-main, pre-fix):
  - Per-row write failures were swallowed: the write loop caught
    Exception, did `report.errors += 1`, and continued — no re-raise.
  - `record_import_run` was UNCONDITIONAL under `if not dry_run:` — it
    never inspected `report.errors` or whether any write landed.
  - `main()` returned 1 ONLY when `import_csv` raised; per-row failures
    never raise, so `main()` reached `return 0` regardless of errors.
  Net: a fully-failed import was indistinguishable from a clean one to
  both the shell exit code and the staleness signal.

The contract (post-fix), keyed on `report.errors` (write failures) ONLY,
never on `operator_preserved` (G4 intentional declines):
  - TOTAL FAILURE (0 written, errors > 0): main() != 0, NO import_runs
    row (freshness stays at the last GOOD import).
  - CLEAN (all written, 0 errors): exit 0, freshness recorded.
  - PARTIAL (some written, some errors): exit non-zero (errors are real
    problems, not routine — every routine drop has its own dropped_*
    counter), freshness IS recorded (data changed).
  - CONFLICT-ONLY (operator_preserved > 0, errors == 0): exit 0,
    freshness recorded — NOT a failure.
"""

from __future__ import annotations

import csv

import pytest

from lynceus.cli import import_argus
from lynceus.cli.import_argus import EXPECTED_HEADER, OverrideConfig, import_csv
from lynceus.db import Database

pytestmark = pytest.mark.diagnostic

META_LINE = (
    "# meta: schema_version=21, exported_at=2026-05-17T15:53:27Z, "
    "record_count=3, confidence_threshold=0\n"
)

OPERATOR_MAC = "aa:bb:cc:99:88:77"


def _row(**overrides) -> dict[str, str]:
    base = {
        "argus_record_id": "rec-1",
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


def _write_csv(path, rows) -> str:
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(META_LINE)
        w = csv.writer(f)
        w.writerow(EXPECTED_HEADER)
        for r in rows:
            w.writerow([r.get(c, "") for c in EXPECTED_HEADER])
    return str(path)


def _wl_count(db: Database) -> int:
    return db._conn.execute("SELECT COUNT(*) FROM watchlist").fetchone()[0]


def _import_runs_count(db: Database) -> int:
    return db._conn.execute("SELECT COUNT(*) FROM import_runs").fetchone()[0]


VALID_ROWS = [
    _row(argus_record_id="rec-1", identifier="aa:bb:cc:11:22:33"),
    _row(argus_record_id="rec-2", identifier="aa:bb:cc:11:22:44"),
    _row(argus_record_id="rec-3", identifier="aa:bb:cc:11:22:55"),
]


def _boom(*_a, **_k):
    raise RuntimeError("forced write failure (simulated DB error)")


# ---------------------------------------------------------------------------
# TOTAL FAILURE — every row fails to write.
# ---------------------------------------------------------------------------
def test_g5_total_failure_import_csv_skips_freshness(diag, tmp_path, monkeypatch):
    """import_csv over a CSV whose every row fails to write returns
    normally (errors swallowed per row) but records NO import_runs row and
    reports is_total_failure()."""
    diag.section("TOTAL FAILURE: import_csv — every row's write fails")
    csv_path = _write_csv(tmp_path / "argus.csv", VALID_ROWS)
    db = Database(str(tmp_path / "g5a.db"))
    # First DB call inside the per-row try is get_metadata_by_argus_record_id;
    # forcing it to raise makes every survivor row hit the write-loop except.
    monkeypatch.setattr(db, "get_metadata_by_argus_record_id", _boom)

    assert db.get_latest_import_run() is None, "precondition: empty import_runs"
    report = import_csv(db, csv_path, OverrideConfig())

    diag.observed(
        f"report: imported_new={report.imported_new} updated={report.updated} "
        f"unchanged={report.unchanged} operator_preserved="
        f"{report.operator_preserved} errors={report.errors} "
        f"wrote_any={report.wrote_any()} is_total_failure={report.is_total_failure()}"
    )
    diag.observed(f"watchlist rows: {_wl_count(db)}; import_runs rows: "
                  f"{_import_runs_count(db)}")

    assert report.errors == 3, f"every row must error; got {report.errors}"
    assert report.imported_new == 0
    assert report.updated == 0
    assert report.unchanged == 0
    assert report.wrote_any() is False
    assert report.is_total_failure() is True
    assert _wl_count(db) == 0, "no watchlist rows may land on total failure"
    # The G5 fix: NO false freshness row.
    assert db.get_latest_import_run() is None, (
        "a wholly-failed import must NOT record an import_runs freshness row"
    )
    db.close()


def test_g5_total_failure_preserves_last_good_freshness(
    diag, tmp_path, monkeypatch
):
    """A total failure must not OVERWRITE the freshness of a prior good
    import — the staleness signal stays at the last GOOD import."""
    diag.section("TOTAL FAILURE: prior good freshness is preserved")
    csv_path = _write_csv(tmp_path / "argus.csv", VALID_ROWS)
    db = Database(str(tmp_path / "g5pre.db"))

    # 1) Clean import lands a good freshness row.
    good = import_csv(db, csv_path, OverrideConfig())
    assert good.imported_new == 3 and good.errors == 0
    run_a = db.get_latest_import_run()
    assert run_a is not None
    diag.observed(f"good import freshness row: {run_a}")

    # 2) A subsequent import where every row fails to write.
    monkeypatch.setattr(db, "get_metadata_by_argus_record_id", _boom)
    bad = import_csv(db, csv_path, OverrideConfig())
    assert bad.is_total_failure() is True
    run_after = db.get_latest_import_run()
    diag.observed(f"freshness row AFTER failed import: {run_after}")

    assert run_after == run_a, (
        "total failure must leave the last good freshness row untouched"
    )
    assert _import_runs_count(db) == 1, (
        "total failure must add NO import_runs row (count stays at 1)"
    )
    db.close()


def test_g5_total_failure_main_exits_nonzero(diag, tmp_path, monkeypatch):
    """The real main() entrypoint must return NON-ZERO on a total write
    failure (pre-fix it returned 0)."""
    diag.section("TOTAL FAILURE: main() exit code")
    csv_path = _write_csv(tmp_path / "argus.csv", VALID_ROWS)
    monkeypatch.setattr(
        import_argus.Database, "get_metadata_by_argus_record_id", _boom
    )
    db_path = tmp_path / "g5b.db"
    rc = import_argus.main([
        "--input", csv_path,
        "--db", str(db_path),
        "--override-file", str(tmp_path / "no_such_overrides.yaml"),
        "--scope", "user",
        "--log-level", "ERROR",
    ])
    diag.observed(f"main() rc={rc}")

    verify = Database(str(db_path))
    diag.observed(f"watchlist rows: {_wl_count(verify)}; import_runs rows: "
                  f"{_import_runs_count(verify)}")
    assert rc != 0, "main() must exit non-zero when every row fails to write"
    assert _wl_count(verify) == 0
    assert verify.get_latest_import_run() is None, (
        "main() total failure must record NO freshness row"
    )
    verify.close()


# ---------------------------------------------------------------------------
# CLEAN — all rows write, 0 errors. Unchanged behavior.
# ---------------------------------------------------------------------------
def test_g5_clean_import_exits_zero_and_records_freshness(diag, tmp_path):
    diag.section("CLEAN: main() exit 0 + freshness recorded")
    csv_path = _write_csv(tmp_path / "argus.csv", VALID_ROWS)
    db_path = tmp_path / "g5clean.db"
    rc = import_argus.main([
        "--input", csv_path,
        "--db", str(db_path),
        "--override-file", str(tmp_path / "no_such_overrides.yaml"),
        "--scope", "user",
        "--log-level", "ERROR",
    ])
    diag.observed(f"main() rc={rc}")

    verify = Database(str(db_path))
    latest = verify.get_latest_import_run()
    diag.observed(f"watchlist rows: {_wl_count(verify)}; freshness: {latest}")
    assert rc == 0, "a clean import must exit 0"
    assert _wl_count(verify) == 3
    assert latest is not None, "a clean import must record a freshness row"
    verify.close()


# ---------------------------------------------------------------------------
# PARTIAL — some rows write, some error. Exit non-zero, freshness recorded.
# ---------------------------------------------------------------------------
def test_g5_partial_failure_records_freshness(diag, tmp_path, monkeypatch):
    """import_csv: one row of three fails to write. Real writes land; the
    error is real (not routine), so it is NOT a total failure and freshness
    IS recorded (data changed)."""
    diag.section("PARTIAL: import_csv — 1 of 3 rows fails")
    csv_path = _write_csv(tmp_path / "argus.csv", VALID_ROWS)
    db = Database(str(tmp_path / "g5part.db"))
    real = db.get_metadata_by_argus_record_id

    def _selective(argus_id):
        if argus_id == "rec-2":
            raise RuntimeError("forced write failure for rec-2")
        return real(argus_id)

    monkeypatch.setattr(db, "get_metadata_by_argus_record_id", _selective)
    report = import_csv(db, csv_path, OverrideConfig())
    diag.observed(
        f"report: imported_new={report.imported_new} errors={report.errors} "
        f"wrote_any={report.wrote_any()} is_total_failure={report.is_total_failure()}"
    )
    diag.observed(f"watchlist rows: {_wl_count(db)}; freshness: "
                  f"{db.get_latest_import_run()}")

    assert report.imported_new == 2, "the two good rows must write"
    assert report.errors == 1, "the one bad row must error"
    assert report.wrote_any() is True
    assert report.is_total_failure() is False, "partial is NOT a total failure"
    assert _wl_count(db) == 2
    assert db.get_latest_import_run() is not None, (
        "partial import changed data → freshness IS recorded"
    )
    db.close()


def test_g5_partial_failure_main_exits_nonzero(diag, tmp_path, monkeypatch):
    """main(): a partial failure must surface to cron via a non-zero exit
    (errors are real problems), while still recording freshness."""
    diag.section("PARTIAL: main() exit code")
    csv_path = _write_csv(tmp_path / "argus.csv", VALID_ROWS)
    real_method = import_argus.Database.get_metadata_by_argus_record_id

    def _selective(self, argus_id):
        if argus_id == "rec-2":
            raise RuntimeError("forced write failure for rec-2")
        return real_method(self, argus_id)

    monkeypatch.setattr(
        import_argus.Database, "get_metadata_by_argus_record_id", _selective
    )
    db_path = tmp_path / "g5partmain.db"
    rc = import_argus.main([
        "--input", csv_path,
        "--db", str(db_path),
        "--override-file", str(tmp_path / "no_such_overrides.yaml"),
        "--scope", "user",
        "--log-level", "ERROR",
    ])
    diag.observed(f"main() rc={rc}")

    verify = Database(str(db_path))
    latest = verify.get_latest_import_run()
    diag.observed(f"watchlist rows: {_wl_count(verify)}; freshness: {latest}")
    assert rc != 0, "a partial failure must exit non-zero so cron sees it"
    assert _wl_count(verify) == 2, "the two good rows must have landed"
    assert latest is not None, "partial import records freshness (data changed)"
    verify.close()


# ---------------------------------------------------------------------------
# CONFLICT-ONLY — operator_preserved > 0, errors == 0. NOT a failure (G4).
# ---------------------------------------------------------------------------
def test_g5_conflict_only_is_not_a_failure(diag, tmp_path):
    """A G4 operator-seeded collision (no real errors) must NOT trip the
    failure path: import_csv reports operator_preserved with errors == 0,
    is_total_failure() is False, and main() exits 0 + records freshness."""
    diag.section("CONFLICT-ONLY: operator_preserved with 0 errors → exit 0")
    db_path = tmp_path / "g5conflict.db"

    # Operator seeds a watchlist row (no Argus metadata) at the natural key.
    seed = Database(str(db_path))
    with seed._conn:
        seed._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
            "VALUES (?, 'mac', 'high', 'operator-seeded: escalated by hand')",
            (OPERATOR_MAC,),
        )
    seed.close()

    # Argus CSV collides on that exact natural key.
    csv_path = _write_csv(
        tmp_path / "argus.csv",
        [_row(argus_record_id="argus-collide-1", identifier=OPERATOR_MAC)],
    )

    # 1) import_csv level: operator_preserved, 0 errors, NOT total failure.
    db = Database(str(db_path))
    report = import_csv(db, csv_path, OverrideConfig())
    diag.observed(
        f"report: operator_preserved={report.operator_preserved} "
        f"errors={report.errors} imported_new={report.imported_new} "
        f"is_total_failure={report.is_total_failure()}"
    )
    assert report.operator_preserved == 1, "the collision is a G4 decline"
    assert report.errors == 0, "an operator decline is NOT an error"
    assert report.is_total_failure() is False, (
        "operator_preserved must NOT trip the total-failure path"
    )
    assert db.get_latest_import_run() is not None, (
        "conflict-only import records freshness (it is not a failure)"
    )
    db.close()

    # 2) main() level: exit 0 despite zero writes (all operator-preserved).
    db_path2 = tmp_path / "g5conflict_main.db"
    seed2 = Database(str(db_path2))
    with seed2._conn:
        seed2._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
            "VALUES (?, 'mac', 'high', 'operator-seeded')",
            (OPERATOR_MAC,),
        )
    seed2.close()
    rc = import_argus.main([
        "--input", csv_path,
        "--db", str(db_path2),
        "--override-file", str(tmp_path / "no_such_overrides.yaml"),
        "--scope", "user",
        "--log-level", "ERROR",
    ])
    diag.observed(f"main() rc={rc}")
    verify = Database(str(db_path2))
    assert rc == 0, "conflict-only (0 errors) must exit 0, not be flagged failed"
    assert verify.get_latest_import_run() is not None
    verify.close()
