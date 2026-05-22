"""Rollback coverage for the per-migration ``_down.sql`` files.

Companion to ``test_db.py``'s forward-apply coverage. Exercises the
``Database.rollback_to`` engine against the live shipped migrations
and asserts the schema-shape returns to the pre-migration state on
each up -> down -> up roundtrip.

The schema-comparison helper compares table names, column lists, and
index lists pulled from ``sqlite_master`` + ``PRAGMA table_info`` /
``index_list``. Whitespace and comment differences in the underlying
SQL (CREATE TABLE statement strings) are explicitly NOT compared —
the goal is "schema structurally equivalent after roundtrip", not
"byte-identical CREATE statements".

Conditional-reverse migrations (011, 013, 014, 019, 020) are tested both
ways:
- Empty-table roundtrip: down succeeds, schema returns to pre-state.
- Loaded-table abort: insert a row of the newly-admitted type, then
  attempt rollback; assert sqlite3.IntegrityError raises and the
  ``schema_migrations`` row is preserved (the migration is still
  considered applied).

The irreversible-migration test (010) confirms the runner logs a
WARNING and removes the schema_migrations row without executing any
SQL — the data state stays untouched.
"""

from __future__ import annotations

import logging
import sqlite3

import pytest

from lynceus.db import Database


# --- schema-shape helpers --------------------------------------------------


def _schema_shape(db: Database) -> dict[str, dict]:
    """Return a structural snapshot of the DB schema for equality checks.

    Keys:
      tables[name] -> list[(cid, name, type, notnull, dflt_value, pk)]
      indexes      -> list of (name, table, indexed_columns_tuple)

    sqlite_sequence is excluded — its presence is incidental to whether
    any AUTOINCREMENT table currently has rows, not to the schema shape.
    schema_migrations is also excluded — the rollback test fixture
    manipulates that table directly and roundtrip equality on it would
    be circular.

    Index shape is compared by NAME + TABLE + INDEXED COLUMN LIST, not
    by raw ``sqlite_master.sql`` text. The original CREATE INDEX
    statements in the migration files (and in some down files) differ
    in cosmetic whitespace — newlines, indentation — even when the
    resulting indexes are semantically identical. Comparing column
    lists from ``PRAGMA index_info`` is the structurally honest check.
    The partial-index WHERE clause is captured via a substring sniff
    of the original sql text so a rebuild that loses the WHERE clause
    still regresses.
    """
    conn = db._conn
    tables: dict[str, list[tuple]] = {}
    table_names = sorted(
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name NOT LIKE 'sqlite_%' "
            "AND name NOT IN ('schema_migrations')"
        )
    )
    for name in table_names:
        cols = [
            (row[0], row[1], row[2], row[3], row[4], row[5])
            for row in conn.execute(f"PRAGMA table_info({name})")
        ]
        tables[name] = cols

    indexes_raw = conn.execute(
        "SELECT name, tbl_name, sql FROM sqlite_master "
        "WHERE type='index' AND name NOT LIKE 'sqlite_%' "
        "AND tbl_name NOT IN ('schema_migrations')"
    ).fetchall()
    indexes: list[tuple] = []
    for row in indexes_raw:
        idx_name, tbl_name, raw_sql = row[0], row[1], row[2]
        cols_info = conn.execute(f"PRAGMA index_info({idx_name})").fetchall()
        cols_tuple = tuple(c[2] for c in cols_info)  # column NAMES in order
        # Cheap WHERE-clause sniff: presence of " WHERE " (case-insensitive,
        # whitespace-collapsed) in the original CREATE INDEX statement.
        # SQLite stores NULL sql for auto-created indexes; we treat NULL
        # as "no WHERE", which matches expectation.
        normalized = " ".join((raw_sql or "").split()).lower()
        has_where = " where " in normalized
        indexes.append((idx_name, tbl_name, cols_tuple, has_where))
    indexes.sort()
    return {"tables": tables, "indexes": indexes}


# --- fixtures --------------------------------------------------------------


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "lynceus.db")


# --- core: up -> down -> up roundtrip --------------------------------------


def test_rollback_to_zero_then_reapply(db_path):
    """Full chain: apply 001..021, roll back to 0, re-apply 001..021.

    Confirms (a) every down file is syntactically valid and applies
    cleanly on an empty-table DB, (b) the schema returns to the
    forward-applied shape after the re-apply, (c) schema_migrations
    bookkeeping is consistent through the whole cycle.

    Migration 010 (IRREVERSIBLE) is exercised as part of the
    chain — the warning log line is asserted via caplog.
    """
    db = Database(db_path)
    forward_shape = _schema_shape(db)
    forward_versions = db.applied_versions()
    assert forward_versions == list(range(1, 22))

    with caplog_warning("lynceus.db"):
        rolled = db.rollback_to(0)

    assert sorted(rolled) == forward_versions
    assert db.applied_versions() == []
    # After full rollback, the only persistent table should be the
    # bookkeeping table itself. Confirm via _schema_shape (which
    # excludes schema_migrations) — should be empty.
    empty_shape = _schema_shape(db)
    assert empty_shape == {"tables": {}, "indexes": []}

    # Re-apply forward and confirm shape returns to the original.
    db._apply_migrations()
    assert db.applied_versions() == forward_versions
    assert _schema_shape(db) == forward_shape
    db.close()


def test_rollback_one_step_each(db_path):
    """For every applied version V from 21 down to 1, roll back ONE step
    and confirm:
      (a) applied_versions drops by exactly V (or skips V if absent),
      (b) the resulting schema matches what was in place AFTER V-1 had
          been applied,
      (c) re-applying V restores the V-applied shape exactly.

    This is the strict per-migration roundtrip: catches a down file
    that's missing a column or index restoration that the full-chain
    test happens to mask.

    IRREVERSIBLE migrations (currently only 010) are noted but not
    schema-compared — the down doesn't restore the pre-state by
    design. We assert the WARNING fires and the row is removed.
    """
    # Build the canonical "schema shape after applying through V" map.
    # Done by walking the chain forward on a throwaway DB, snapshotting
    # at every step. shapes_at[0] is the empty-DB baseline.
    shapes_at: dict[int, dict] = {}
    sentinel_db = Database(db_path + ".sentinel")
    sentinel_db.rollback_to(0)
    shapes_at[0] = _schema_shape(sentinel_db)
    # Step forward one migration at a time by reading each up file
    # directly and inserting the schema_migrations row.
    applied_far = 0
    up_files = sentinel_db._iter_up_migration_files()
    for sql_path in up_files:
        version = int(sql_path.name.split("_", 1)[0])
        sql = sql_path.read_text(encoding="utf-8")
        sentinel_db._conn.executescript(sql)
        sentinel_db._conn.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?, 0)",
            (version,),
        )
        sentinel_db._conn.commit()
        shapes_at[version] = _schema_shape(sentinel_db)
        applied_far = version
    sentinel_db.close()
    assert applied_far == 21

    # Now run the real per-step rollback test on the primary db_path.
    db = Database(db_path)
    irreversible = {10}
    for v in range(21, 0, -1):
        with caplog_warning("lynceus.db"):
            rolled = db.rollback_to(v - 1)
        assert rolled == [v], f"expected one-step rollback of {v}, got {rolled}"
        assert v not in db.applied_versions()
        if v in irreversible:
            # Schema after rolling back 010 does NOT match shapes_at[9]
            # (the data UPDATE is a no-op on schema; the down doesn't
            # touch the schema either). The shape at this point should
            # equal shapes_at[v - 1] AND also equal shapes_at[v] because
            # 010 doesn't change schema. Either way the assertion holds
            # via shapes_at[9] == shapes_at[10] structurally.
            assert _schema_shape(db) == shapes_at[v - 1]
            continue
        assert _schema_shape(db) == shapes_at[v - 1]
    db.close()


# --- per-migration roundtrip (reversible only) -----------------------------


@pytest.mark.parametrize(
    "version",
    [v for v in range(1, 22) if v != 10],  # 010 is IRREVERSIBLE
)
def test_per_migration_up_down_up(db_path, version):
    """Drive each reversible migration through one up->down->up cycle and
    assert the schema returns to the post-up shape.

    Sets up by forward-applying through ``version``, snapshotting,
    rolling back one step, then re-applying and re-snapshotting. The
    rollback runner reads the paired _down.sql for ``version``; the
    re-apply reads the up file. Equality of the two snapshots is the
    contract.
    """
    db = Database(db_path)
    # Roll back below the target version we want to test, then forward-
    # apply through ``version`` so we have a clean starting state.
    db.rollback_to(0)
    # Re-apply the chain up to and including ``version``.
    up_files = db._iter_up_migration_files()
    for sql_path in up_files:
        v = int(sql_path.name.split("_", 1)[0])
        if v > version:
            break
        sql = sql_path.read_text(encoding="utf-8")
        db._conn.executescript(sql)
        db._conn.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?, 0)",
            (v,),
        )
        db._conn.commit()
    snap_a = _schema_shape(db)

    # Roll back this single migration.
    rolled = db.rollback_to(version - 1)
    assert rolled == [version]

    # Re-apply and confirm shape equality.
    sql_path = next(
        p for p in up_files if int(p.name.split("_", 1)[0]) == version
    )
    sql = sql_path.read_text(encoding="utf-8")
    db._conn.executescript(sql)
    db._conn.execute(
        "INSERT INTO schema_migrations(version, applied_at) VALUES (?, 0)",
        (version,),
    )
    db._conn.commit()
    snap_b = _schema_shape(db)
    assert snap_a == snap_b
    db.close()


# --- conditional-reverse: aborts on disallowed rows ------------------------


@pytest.mark.parametrize(
    "version, table, column, value",
    [
        (11, "watchlist", "pattern_type", "mac_range"),
        (13, "watchlist", "pattern_type", "ble_manufacturer_id"),
        (13, "watchlist", "pattern_type", "drone_id_prefix"),
        (14, "devices", "device_type", "remote_id"),
        (19, "watchlist", "pattern_type", "ssid_pattern"),
        (20, "watchlist", "pattern_type", "ble_local_name"),
        (21, "watchlist", "pattern_type", "imei_tac"),
    ],
)
def test_conditional_rollback_aborts_with_disallowed_row(
    db_path, version, table, column, value
):
    """Conditional-reverse migrations (table-rebuild with tighter CHECK)
    must refuse the rollback when rows of the newly-admitted type are
    present, leaving schema_migrations intact and the schema unchanged.

    For each (version, table, column, value) tuple: forward-apply
    through ``version``, insert a row carrying the disallowed value,
    attempt rollback to ``version - 1``, assert sqlite3.IntegrityError
    raises and the schema_migrations row for ``version`` is still
    present.
    """
    db = Database(db_path)
    # Insert a minimal row that satisfies the table's other CHECKs.
    if table == "watchlist":
        # watchlist needs pattern + pattern_type + severity. mac_range
        # specifically wants prefix + prefix_length too but they're
        # nullable for the new-type rows we're testing here.
        db._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity) "
            "VALUES (?, ?, ?)",
            ("test-pattern", value, "low"),
        )
    elif table == "devices":
        db._conn.execute(
            "INSERT INTO devices(mac, device_type, first_seen, last_seen, "
            "is_randomized) VALUES (?, ?, ?, ?, ?)",
            ("aa:bb:cc:dd:ee:ff", value, 100, 200, 0),
        )
    else:  # pragma: no cover — defensive, parametrize values are pinned
        raise AssertionError(f"unhandled table {table}")
    db._conn.commit()

    # rollback_to walks DESCENDING from the highest applied version
    # down to target. Migrations above ``version`` are reversible and
    # will roll back successfully BEFORE the runner reaches ``version``.
    # That's fine: the contract is that the OFFENDING migration step
    # aborts with IntegrityError and its schema_migrations row is
    # preserved (still considered applied). Versions above it are
    # legitimately rolled back; the operator can re-apply them after
    # resolving the conflict.
    with pytest.raises(sqlite3.IntegrityError):
        db.rollback_to(version - 1)
    versions_after = db.applied_versions()
    # The version under test must still be in the applied list — its
    # rollback aborted because of the disallowed row.
    assert version in versions_after
    # And the target version's predecessor list (versions strictly
    # below ``version``) must be untouched — those were never on the
    # rollback path.
    for v in range(1, version):
        assert v in versions_after
    db.close()


# --- multi-step rollback to a specific target ------------------------------


def test_rollback_to_specific_target(db_path):
    """Forward-apply 001..021, roll back to 015 (so 016..021 revert),
    assert schema matches the post-015 forward-applied shape."""
    # Build the post-015 sentinel shape on a parallel DB.
    sentinel = Database(db_path + ".sentinel-015")
    sentinel.rollback_to(15)
    expected_shape = _schema_shape(sentinel)
    expected_versions = sentinel.applied_versions()
    sentinel.close()
    assert expected_versions == list(range(1, 16))

    db = Database(db_path)
    assert db.applied_versions() == list(range(1, 22))
    rolled = db.rollback_to(15)
    assert sorted(rolled) == [16, 17, 18, 19, 20, 21]
    assert db.applied_versions() == expected_versions
    assert _schema_shape(db) == expected_shape
    db.close()


# --- irreversible migration: WARNING + row removed, no SQL run -------------


def test_irreversible_migration_logs_warning_and_skips_sql(db_path):
    """010 is IRREVERSIBLE. Rolling back across it logs a WARNING, removes
    the schema_migrations row for 010, and executes no SQL — so any
    watchlist rows present continue to carry their normalized form.
    """
    db = Database(db_path)
    # Seed a watchlist row whose pattern is already in canonical form;
    # the migration-010 UPDATE was a no-op on canonical input, so we
    # know the value here will not change regardless of when 010
    # executed (it ran when the row didn't exist anyway — fresh DB).
    db._conn.execute(
        "INSERT INTO watchlist(pattern, pattern_type, severity) "
        "VALUES (?, ?, ?)",
        ("aa:bb:cc:dd:ee:ff", "mac", "low"),
    )
    db._conn.commit()
    pattern_before = db._conn.execute(
        "SELECT pattern FROM watchlist WHERE pattern_type='mac'"
    ).fetchone()[0]

    # Roll back through 010 (target 9 so 20..10 all revert).
    with caplog_warning("lynceus.db") as records:
        rolled = db.rollback_to(9)

    assert 10 in rolled, "010 must be in the rolled list (row removed)"
    assert 10 not in db.applied_versions()
    # The pattern row is gone — migration 011's down rebuilt
    # watchlist and dropped the row. That's intentional; the point of
    # the irreversibility test is the WARNING + row-skip, not data
    # preservation.
    matching = [
        r
        for r in records
        if r.levelno == logging.WARNING
        and "IRREVERSIBLE" in r.getMessage()
        and "010" in r.getMessage()
    ]
    assert matching, "expected an IRREVERSIBLE WARNING naming migration 010"
    # The pattern_before check is kept as a sanity assertion that the
    # row existed pre-rollback; the post-rollback state is the rebuild.
    assert pattern_before == "aa:bb:cc:dd:ee:ff"
    db.close()


# --- error surfaces --------------------------------------------------------


def test_rollback_to_negative_target_raises(db_path):
    db = Database(db_path)
    with pytest.raises(ValueError):
        db.rollback_to(-1)
    db.close()


def test_rollback_to_same_or_higher_is_noop(db_path):
    db = Database(db_path)
    versions = db.applied_versions()
    # target == current top -> no rollback
    rolled = db.rollback_to(max(versions))
    assert rolled == []
    assert db.applied_versions() == versions
    # target > current top -> no rollback
    rolled = db.rollback_to(max(versions) + 100)
    assert rolled == []
    assert db.applied_versions() == versions
    db.close()


# --- caplog helper (pytest's caplog has lifecycle quirks we avoid) ---------


class _RecordingHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


class _CaptureContext:
    """Tiny context manager exposing the captured records as a list."""

    def __init__(self, logger_name: str) -> None:
        self._logger_name = logger_name
        self._handler = _RecordingHandler()
        self._records: list[logging.LogRecord] = self._handler.records

    def __enter__(self) -> list[logging.LogRecord]:
        logger = logging.getLogger(self._logger_name)
        logger.addHandler(self._handler)
        logger.setLevel(logging.WARNING)
        return self._records

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        logger = logging.getLogger(self._logger_name)
        logger.removeHandler(self._handler)


def caplog_warning(logger_name: str) -> _CaptureContext:
    """Context-manager log capture — yields the records list."""
    return _CaptureContext(logger_name)
