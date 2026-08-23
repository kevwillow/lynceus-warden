"""Migration replay: what happens when a migration's DDL outlives its version
stamp, and — separately — which routes can actually put the database there.

WHY THIS FILE EXISTS
--------------------
``Database._apply_migrations`` applies each pending migration in two steps that
are NOT one transaction::

    self._conn.executescript(sql)                          # step 1
    self._conn.execute("INSERT INTO schema_migrations...")  # step 2
    self._conn.commit()                                    # step 3

``sqlite3.Connection.executescript`` commits any pending transaction and then
runs the script in autocommit, so step 1 is **durable the instant it returns**.
Step 2 opens a fresh implicit transaction that only step 3 commits. Anything
that kills the process in between — SIGKILL, OOM, power loss, a yanked battery
on a mobile deployment — leaves that migration's schema changed and its version
row missing.

⚠️ **THE CRASH WINDOW IS ONE MIGRATION WIDE, AND THAT BOUNDS WHAT IT CAN DO.**
``commit()`` is *inside* the per-migration loop (``db.py:479``), so a crash
during migration N leaves the database stamped through N-1 with **N+1..HEAD not
yet run at all**. The replay therefore happens against an N-1-era schema, not
against a head one. An earlier draft of this file asserted otherwise, and three
of its four conclusions followed from that error.

So the two states must be kept apart:

* **Crash state** — schema at N, stamps at N-1, nothing later applied.
* **Schema-ahead-of-stamp at HEAD** — a fully migrated database with one
  version row missing. A crash *cannot* produce this. ``rollback_to`` can:
  two branches delete the ``schema_migrations`` row **without applying any
  down migration** (``db.py`` ~525-545) — one when no ``_down.sql`` exists
  ("so the rollback chain can continue"), one on an ``IRREVERSIBLE:`` marker.
  Branch 2 is live today via ``010_normalize_watchlist_patterns_down.sql``;
  branch 1 is currently unreachable but is one packaging slip away, and the
  code's own comment calls that "a packaging bug".

The tests below deliberately construct the second state by deleting a stamp
row, because that is the state whose consequences are unknown. **Only category
1 is reachable by a crash today.** Categories 2 and 3 are latent: real, and
waiting for anything that unstamps a migration without reverting it.

Of the 24 migrations, 5 replay cleanly. The rest fail in three distinct ways,
pinned separately because they need different responses from an operator:

1. ``sqlite3.OperationalError`` (14 migrations) — "duplicate column name" or
   "table ... already exists". ``Database.__init__`` raises, so the daemon
   does not start. Loud, unmissable, and unrecoverable without hand-editing
   ``schema_migrations``.
2. ``sqlite3.IntegrityError`` (011, 013, 019, 020) — the ``watchlist``
   table-rebuild migrations re-create the table with the ``pattern_type``
   CHECK constraint as it stood at THEIR version, which rejects rows of any
   type a later migration introduced. This one is DATA-DEPENDENT: on an empty
   or simple watchlist the replay succeeds silently, so a test that did not
   seed a late ``pattern_type`` would call these migrations safe.
3. Silent loss (014) — no exception at all. 014 rebuilds ``devices`` from a
   hard-coded column list frozen at its own version, so replaying it on a
   head database DROPS ``devices.ble_device_class`` and every BLE Continuity
   classification stored in it. The daemon then starts happily against a
   schema that is quietly one column short. This is the worst of the three
   and the only one nothing else in the suite would notice.

Migration 009 documents the opposite belief in its own header:

    "IF NOT EXISTS not used: SQLite's ALTER TABLE ADD COLUMN doesn't
     support it. The migration runner gates re-application via
     schema_migrations, so this only runs once per DB."

The gate it trusts is exactly the row the crash window loses.

WHAT WOULD SILENTLY BREAK WITHOUT THIS FILE
-------------------------------------------
* Someone reorders ``_apply_migrations`` to stamp the version first and trades
  an unstartable daemon for a silently-skipped schema change — strictly worse,
  and no existing test notices.
* Someone drops the ``if version in applied: continue`` short-circuit and every
  ordinary restart begins replaying migration 001.
* A new table-rebuild migration copies 014's hard-coded column list and adds a
  second silent-truncation path.
* The project's belief about which migrations tolerate a replay drifts from the
  code. The census below is an exact partition, so it fails in both directions:
  when a migration stops being safe, and when one becomes safe.

``tests/test_db.py`` covers 007's statement-level idempotence and
``tests/test_migration_rollback.py`` covers the ``_down.sql`` chain. Neither
drives the crash window in the forward runner, and neither knows what a replay
does to a database that has operator data in it.
"""

from __future__ import annotations

import shutil
import sqlite3
import time as time_module
from pathlib import Path

import pytest

from lynceus import db as db_module
from lynceus.db import Database

# --------------------------------------------------------------------------
# Measured ground truth.
#
# Each up-migration was applied to a fresh DB which was then seeded with
# operator rows, its schema_migrations row was removed (the exact on-disk state
# a crash in the window leaves behind), and the DB was reopened. The four sets
# below record what actually happened and are asserted as an exact partition of
# the migrations on disk.
# --------------------------------------------------------------------------

# Replay raises sqlite3.OperationalError out of Database.__init__ regardless of
# what is in the database. Value is the distinctive error-message fragment.
REPLAY_RAISES_OPERATIONAL = {
    1: "table devices already exists",
    2: "table poller_state already exists",
    3: "table alert_actions already exists",
    4: "table watchlist_metadata already exists",
    5: "duplicate column name: matched_watchlist_id",
    6: "duplicate column name: probe_ssids",
    9: "duplicate column name: do_not_publish",
    12: "table import_runs already exists",
    15: "duplicate column name: rule_type",
    16: "duplicate column name: note",
    17: "table rule_type_snoozes already exists",
    18: "table watchful_recurrence already exists",
    23: "duplicate column name: ble_device_class",
    24: "duplicate column name: notified_at",
    25: "table heartbeats already exists",
    26: "table watchful_escalations already exists",
    27: "duplicate column name: notify_abandoned_at",
}

# watchlist table-rebuild migrations. Replay is silent on an empty watchlist and
# raises sqlite3.IntegrityError once the table holds a pattern_type introduced
# after that migration's version.
REPLAY_RAISES_INTEGRITY_WITH_DATA = {11, 13, 19, 20}

# No exception, but the devices table-rebuild is frozen at 014's column list, so
# the replay drops every column a later migration added to devices.
# ⭐ EMPTIED by the runner-level column-loss guard. 14 WAS the sole member:
# replaying it against a head schema silently dropped devices.ble_device_class.
# `Database._assert_no_columns_lost` now refuses to stamp any forward
# migration that removes a column from a surviving table, so 14 raises
# RuntimeError instead of quietly succeeding. Kept as an empty set rather
# than deleted: the census below asserts an exact partition of HEAD, and an
# empty category is the honest way to say "this failure mode is closed"
# rather than "this failure mode never existed".
REPLAY_SILENTLY_LOSSY: set[int] = set()
#: Refused by the runner guard rather than by SQLite. Same loud outcome as
#: REPLAY_RAISES_OPERATIONAL, different mechanism, so it gets its own row.
REPLAY_REFUSED_BY_COLUMN_GUARD = {14}
LOSSY_VICTIM_COLUMN = "ble_device_class"  # added by 023, destroyed by a 014 replay

# Genuinely idempotent: IF NOT EXISTS guards (007, 008, 022), a pure UPDATE
# normalisation (010), or the newest watchlist rebuild, whose CHECK constraint
# still matches head (021).
# 028 joins them: its UPDATE selects the rows that violate the invariant, and
# after the first run there are none, so a replay updates 0 rows; the index is
# CREATE UNIQUE INDEX IF NOT EXISTS. Verified by this census rather than
# asserted from reading the SQL.
REPLAY_CLEAN = {7, 8, 10, 21, 22, 28}

# Crash-injection targets: one additive (ADD COLUMN) migration and one that
# creates a table, so both defect shapes are pinned end to end.
ADDITIVE_VICTIM = 23
ADDITIVE_VICTIM_TABLE = "devices"
ADDITIVE_VICTIM_COLUMN = "ble_device_class"
CREATE_TABLE_VICTIM = 17
CREATE_TABLE_VICTIM_TABLE = "rule_type_snoozes"

# A watchlist pattern_type introduced by 021, i.e. after every migration in
# REPLAY_RAISES_INTEGRITY_WITH_DATA. Seeding one row of this type is what turns
# those replays from silent no-ops into IntegrityError.
LATE_PATTERN_TYPE = "imei_tac"

SEED_MAC = "aa:bb:cc:dd:ee:ff"
SEED_BLE_CLASS = "airpods"


class SimulatedCrash(RuntimeError):
    """Stands in for SIGKILL/OOM/power-loss inside the commit window."""


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _up_migration_files() -> list[Path]:
    """Every forward migration on disk, sorted, discovered independently.

    Deliberately does NOT call ``Database._iter_up_migration_files``: the
    control test compares the runner's result against this list, and a test that
    asked the runner what it intended to do could not catch the runner doing the
    wrong thing.
    """
    migrations_dir = db_module._find_migrations_dir()
    return sorted(p for p in migrations_dir.glob("*.sql") if not p.name.endswith("_down.sql"))


def _version_of(path: Path) -> int:
    return int(path.name.split("_", 1)[0])


HEAD_VERSIONS = [_version_of(p) for p in _up_migration_files()]


def _table_names(conn: sqlite3.Connection) -> set[str]:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}


def _column_names(conn: sqlite3.Connection, table: str) -> set[str]:
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}


def _stamped_versions(path: Path) -> set[int]:
    """Read schema_migrations straight from the file, no Database involved."""
    conn = sqlite3.connect(str(path))
    try:
        return {r[0] for r in conn.execute("SELECT version FROM schema_migrations")}
    finally:
        conn.close()


@pytest.fixture(scope="session")
def golden_db(tmp_path_factory) -> Path:
    """A fully migrated database, built once by the real runner."""
    path = tmp_path_factory.mktemp("golden") / "golden.db"
    Database(str(path)).close()
    return path


@pytest.fixture
def fresh_copy(golden_db, tmp_path):
    """Hand out private copies of the golden DB, optionally seeded.

    ``seed=True`` adds one device carrying a value in the column 014's replay
    destroys, and one watchlist row of a pattern_type older migrations reject.
    Those two rows are what separate the three replay failure modes.
    """
    counter = {"n": 0}

    def _copy(seed: bool = True) -> Path:
        counter["n"] += 1
        dest = tmp_path / f"copy{counter['n']}.db"
        shutil.copy(golden_db, dest)
        for suffix in ("-wal", "-shm"):
            side = Path(str(golden_db) + suffix)
            if side.exists():
                shutil.copy(side, str(dest) + suffix)
        if seed:
            conn = sqlite3.connect(str(dest))
            try:
                conn.execute(
                    "INSERT INTO devices(mac, device_type, first_seen, last_seen, "
                    "sighting_count, is_randomized, ble_device_class) "
                    "VALUES (?, 'ble', 1, 2, 1, 0, ?)",
                    (SEED_MAC, SEED_BLE_CLASS),
                )
                conn.execute(
                    "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
                    "VALUES ('35391807', ?, 'high', 'late pattern type')",
                    (LATE_PATTERN_TYPE,),
                )
                conn.commit()
            finally:
                conn.close()
        return dest

    return _copy


def _unstamp(path: Path, version: int) -> None:
    """Reproduce the post-crash on-disk state for ``version``.

    The migration's DDL is already committed (executescript did that); only the
    schema_migrations row is missing. Deleting the row produces a database that
    is equivalent, for the next start's purposes, to one the process died on
    mid-window. ``test_ddl_is_durable_before_its_version_row_is_committed``
    proves that equivalence against the real runner.
    """
    conn = sqlite3.connect(str(path))
    try:
        conn.execute("DELETE FROM schema_migrations WHERE version = ?", (version,))
        conn.commit()
    finally:
        conn.close()


def _crash_during_migration(path: Path, landed, monkeypatch) -> None:
    """Run the REAL runner against ``path`` and kill it inside the window.

    ``_apply_migrations`` evaluates ``int(time.time())`` to build the
    schema_migrations INSERT — after ``executescript`` has returned and before
    the row is written or committed. Raising from ``time.time`` therefore lands
    the crash precisely in the untested gap, using the shipping code path rather
    than a reimplementation of it.

    ``landed(conn)`` is polled through a SEPARATE connection and returns True
    once the target migration's schema change is visible to another reader —
    which is itself the proof that executescript committed. Keying on observed
    schema state rather than a call count keeps the crash on the intended
    migration no matter who else calls ``time.time``.
    """
    real_time = time_module.time

    def crashing_time() -> float:
        probe = sqlite3.connect(str(path))
        try:
            if landed(probe):
                raise SimulatedCrash("process died before the version row was committed")
        finally:
            probe.close()
        return real_time()

    monkeypatch.setattr(db_module.time, "time", crashing_time)
    with pytest.raises(SimulatedCrash):
        Database(str(path))


def _column_landed(table: str, column: str):
    def landed(conn: sqlite3.Connection) -> bool:
        return column in {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}

    return landed


def _table_landed(table: str):
    def landed(conn: sqlite3.Connection) -> bool:
        return (
            conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
            ).fetchone()
            is not None
        )

    return landed


# --------------------------------------------------------------------------
# Controls: the full fresh-database path must really work.
# --------------------------------------------------------------------------


def test_fresh_database_migrates_to_head(tmp_path):
    """Control. Without this the whole file could pass by migrating nothing."""
    path = tmp_path / "fresh.db"
    db = Database(str(path))
    try:
        applied = db.applied_versions()

        assert HEAD_VERSIONS, "no forward migrations discovered on disk"
        assert applied == HEAD_VERSIONS
        assert applied == list(range(1, len(applied) + 1)), "version numbering is not contiguous"
        assert max(applied) >= 24, "expected at least 24 migrations; suite constants are stale"

        # The stamps are not the point — the schema is. Assert objects created
        # across the whole range, early and late.
        tables = _table_names(db._conn)
        for table in (
            "devices",
            "sightings",
            "alerts",
            "watchlist",
            "poller_state",
            "alert_actions",
            "watchlist_metadata",
            "evidence_snapshots",
            "import_runs",
            "rule_type_snoozes",
            "watchful_recurrence",
        ):
            assert table in tables, f"migration head is missing table {table}"

        # Scratch tables from the rebuild migrations must NOT survive.
        assert "watchlist_new" not in tables
        assert "devices_new" not in tables

        assert LOSSY_VICTIM_COLUMN in _column_names(db._conn, "devices")
        assert "probe_ssids" in _column_names(db._conn, "devices")
        assert "notified_at" in _column_names(db._conn, "alerts")
        assert "rule_type" in _column_names(db._conn, "alerts")
        assert "do_not_publish" in _column_names(db._conn, "evidence_snapshots")

        # The newest watchlist pattern_type is accepted, so the CHECK
        # constraint really is at head and not at some earlier rebuild.
        db._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity) VALUES ('35391807', ?, 'high')",
            (LATE_PATTERN_TYPE,),
        )

        # And the result is a usable database, not just a shape.
        db.ensure_location("lab", "Lab")
        db.upsert_device(SEED_MAC, "wifi", "Acme", 0, 100)
        device = db.get_device(SEED_MAC)
        assert device is not None
        assert device["oui_vendor"] == "Acme"
    finally:
        db.close()


def test_reopening_a_migrated_database_replays_nothing(fresh_copy):
    """The version-row gate is what makes an ordinary restart safe.

    Presence side: every version is still stamped and the schema is intact.
    Absence side: no version was stamped twice and no ``applied_at`` moved, so
    nothing was re-applied.
    """
    path = fresh_copy()
    before = sqlite3.connect(str(path))
    try:
        stamps_before = sorted(
            tuple(r) for r in before.execute("SELECT version, applied_at FROM schema_migrations")
        )
    finally:
        before.close()

    db = Database(str(path))
    try:
        stamps_after = sorted(
            tuple(r) for r in db._conn.execute("SELECT version, applied_at FROM schema_migrations")
        )
        assert db.applied_versions() == HEAD_VERSIONS
        assert LOSSY_VICTIM_COLUMN in _column_names(db._conn, "devices")
    finally:
        db.close()

    assert stamps_before == stamps_after, "reopening re-stamped or re-applied a migration"
    assert len(stamps_after) == len(HEAD_VERSIONS)


# --------------------------------------------------------------------------
# The crash window itself, driven through the real runner.
# --------------------------------------------------------------------------


def test_ddl_is_durable_before_its_version_row_is_committed(tmp_path, monkeypatch):
    """The two steps are not atomic, and this is the proof.

    Kills the real runner between ``executescript`` and the commit of the
    version row, then reads the file with a fresh connection. The migration's
    column survives (presence) while its stamp does not (absence, paired with
    the previous version's stamp still being there).
    """
    path = tmp_path / "crash.db"
    _crash_during_migration(
        path, _column_landed(ADDITIVE_VICTIM_TABLE, ADDITIVE_VICTIM_COLUMN), monkeypatch
    )

    stamped = _stamped_versions(path)
    assert ADDITIVE_VICTIM not in stamped, "version row survived; there would be no replay bug"
    assert ADDITIVE_VICTIM - 1 in stamped, "crash landed on the wrong migration"
    assert stamped == set(range(1, ADDITIVE_VICTIM))

    check = sqlite3.connect(str(path))
    try:
        assert ADDITIVE_VICTIM_COLUMN in _column_names(check, ADDITIVE_VICTIM_TABLE), (
            "executescript's DDL was rolled back, so the atomicity gap this "
            "file pins would not exist"
        )
    finally:
        check.close()


def test_replayed_additive_migration_stops_the_daemon_starting(tmp_path, monkeypatch):
    """Pin the consequence: ``Database.__init__`` raises, so nothing starts."""
    path = tmp_path / "crash.db"
    _crash_during_migration(
        path, _column_landed(ADDITIVE_VICTIM_TABLE, ADDITIVE_VICTIM_COLUMN), monkeypatch
    )

    with pytest.raises(sqlite3.OperationalError) as first:
        Database(str(path))
    assert f"duplicate column name: {ADDITIVE_VICTIM_COLUMN}" in str(first.value)

    # No self-healing: the next start fails identically. The operator is stuck
    # until someone hand-edits schema_migrations or restores a backup.
    with pytest.raises(sqlite3.OperationalError) as second:
        Database(str(path))
    assert str(second.value) == str(first.value)
    assert ADDITIVE_VICTIM not in _stamped_versions(path)


def test_replayed_create_table_migration_stops_the_daemon_starting(tmp_path, monkeypatch):
    """Same window, non-additive shape — ADD COLUMN is not the only victim."""
    path = tmp_path / "crash.db"
    _crash_during_migration(path, _table_landed(CREATE_TABLE_VICTIM_TABLE), monkeypatch)

    assert CREATE_TABLE_VICTIM not in _stamped_versions(path)
    check = sqlite3.connect(str(path))
    try:
        assert CREATE_TABLE_VICTIM_TABLE in _table_names(check)
    finally:
        check.close()

    with pytest.raises(sqlite3.OperationalError) as exc:
        Database(str(path))
    assert f"table {CREATE_TABLE_VICTIM_TABLE} already exists" in str(exc.value)


# --------------------------------------------------------------------------
# The census: exactly what a replay of each migration does.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("version", sorted(REPLAY_RAISES_OPERATIONAL))
def test_replay_raises_operational_error(version, fresh_copy):
    """These 14 fail loudly and unconditionally: the daemon will not start."""
    path = fresh_copy()
    _unstamp(path, version)
    assert version not in _stamped_versions(path)

    with pytest.raises(sqlite3.OperationalError) as exc:
        Database(str(path))
    assert REPLAY_RAISES_OPERATIONAL[version] in str(exc.value), (
        f"migration {version:03d} replay failed differently than recorded: {exc.value}"
    )
    assert version not in _stamped_versions(path), "a failed replay stamped itself anyway"


@pytest.mark.parametrize("version", sorted(REPLAY_RAISES_INTEGRITY_WITH_DATA))
def test_watchlist_rebuild_replay_is_a_data_dependent_landmine(version, fresh_copy):
    """011/013/019/020 rebuild ``watchlist`` with THEIR OWN pattern_type CHECK.

    Both halves matter. On an empty watchlist the replay is silent, which is
    exactly why a test seeded with nothing would wrongly call these safe. Put
    one row of a pattern_type a later migration introduced in the table and the
    same replay aborts the daemon with IntegrityError.
    """
    # Half one: no late-type rows -> replay succeeds and re-stamps.
    empty = fresh_copy(seed=False)
    empty_conn = sqlite3.connect(str(empty))
    try:
        late_rows = empty_conn.execute(
            "SELECT COUNT(*) FROM watchlist WHERE pattern_type = ?", (LATE_PATTERN_TYPE,)
        ).fetchone()[0]
    finally:
        empty_conn.close()
    assert late_rows == 0, "fixture is not actually free of late pattern types"

    _unstamp(empty, version)
    db = Database(str(empty))
    try:
        assert db.applied_versions() == HEAD_VERSIONS
    finally:
        db.close()

    # Half two: one late-type row -> the same replay refuses to start.
    seeded = fresh_copy(seed=True)
    _unstamp(seeded, version)
    with pytest.raises(sqlite3.IntegrityError) as exc:
        Database(str(seeded))
    assert "CHECK constraint failed" in str(exc.value)
    assert "pattern_type" in str(exc.value)
    assert version not in _stamped_versions(seeded)


def test_replaying_014_is_refused_instead_of_silently_dropping_a_column(fresh_copy):
    """Was the worst case; is now the loud one.

    014 rebuilds ``devices`` from a column list frozen at its own version, and
    023 later added ``ble_device_class``. Replaying 014 against a head database
    copied only 014's columns and dropped the rest — every stored BLE Continuity
    classification, gone, with nothing raised and nothing logged.

    ⛔ It could not be fixed in 014's SQL, and that was verified rather than
    assumed: adding the column to 014's list breaks a fresh migrate-to-head with
    ``no such column: ble_device_class``, because 023 has not run when 014
    executes. A historical migration cannot reference a later migration's
    schema.

    So the fix lives in the runner. ``Database._assert_no_columns_lost``
    compares each table's columns before and after every forward migration and
    refuses to stamp one that lost any. Measured safe to apply
    unconditionally: stepping 001..HEAD over an empty database produces zero
    column losses.

    Presence and absence together — the column and its value must be verified
    present BEFORE the replay, or "it refused" proves nothing about what was at
    stake.
    """
    path = fresh_copy(seed=True)

    before = sqlite3.connect(str(path))
    try:
        assert LOSSY_VICTIM_COLUMN in _column_names(before, "devices")
        stored = before.execute(
            f"SELECT {LOSSY_VICTIM_COLUMN} FROM devices WHERE mac = ?", (SEED_MAC,)
        ).fetchone()
        assert stored is not None and stored[0] == SEED_BLE_CLASS
    finally:
        before.close()

    _unstamp(path, 14)

    with pytest.raises(RuntimeError) as exc:
        Database(str(path))

    message = str(exc.value)
    assert LOSSY_VICTIM_COLUMN in message, f"the lost column is not named: {message}"
    assert "14" in message, f"the migration is not named: {message}"

@pytest.mark.parametrize("version", sorted(REPLAY_CLEAN))
def test_replay_is_genuinely_idempotent(version, fresh_copy):
    """The five that survive: no error, re-stamped, and nothing lost."""
    path = fresh_copy(seed=True)
    _unstamp(path, version)
    assert version not in _stamped_versions(path)

    db = Database(str(path))
    try:
        assert db.applied_versions() == HEAD_VERSIONS
        assert LOSSY_VICTIM_COLUMN in _column_names(db._conn, "devices")
        assert "watchlist_new" not in _table_names(db._conn)
        assert "devices_new" not in _table_names(db._conn)

        device = db._conn.execute(
            f"SELECT {LOSSY_VICTIM_COLUMN} FROM devices WHERE mac = ?", (SEED_MAC,)
        ).fetchone()
        assert device is not None, "replay lost the device row"
        assert device[0] == SEED_BLE_CLASS, "replay lost the device's BLE class"

        late = db._conn.execute(
            "SELECT severity, description FROM watchlist WHERE pattern_type = ?",
            (LATE_PATTERN_TYPE,),
        ).fetchall()
        assert len(late) == 1, "replay lost or duplicated the late-pattern watchlist row"
        assert late[0][0] == "high"
    finally:
        db.close()


def test_replay_census_is_an_exact_partition_of_head():
    """Every migration is classified, and no class may quietly empty out.

    A new migration lands unclassified -> this fails and forces a decision
    about what its replay does.
    """
    classes = {
        "REPLAY_RAISES_OPERATIONAL": set(REPLAY_RAISES_OPERATIONAL),
        "REPLAY_RAISES_INTEGRITY_WITH_DATA": REPLAY_RAISES_INTEGRITY_WITH_DATA,
        "REPLAY_REFUSED_BY_COLUMN_GUARD": REPLAY_REFUSED_BY_COLUMN_GUARD,
        "REPLAY_SILENTLY_LOSSY": REPLAY_SILENTLY_LOSSY,
        "REPLAY_CLEAN": REPLAY_CLEAN,
    }
    # ⭐ REPLAY_SILENTLY_LOSSY is deliberately allowed to be EMPTY, and it is
    # the only one. It held exactly {14} until the runner-level column-loss
    # guard turned that silent drop into a refusal. "No migration replays
    # silently lossily" is a real, checkable property of the current tree —
    # emptying the set is the finding, not a gap in the census. Every OTHER
    # class must stay non-empty, because an empty one there means a failure
    # mode stopped being observed rather than stopped existing.
    for name, members in classes.items():
        if name == "REPLAY_SILENTLY_LOSSY":
            continue
        assert members, f"{name} is empty; the census has lost a failure mode"

    seen: set[int] = set()
    for name, members in classes.items():
        overlap = seen & members
        assert not overlap, f"{name} overlaps an earlier class on {overlap}"
        seen |= members

    assert seen == set(HEAD_VERSIONS), (
        f"migrations on disk are not classified: {set(HEAD_VERSIONS) - seen}"
    )
    # The reason this file exists: most of the chain cannot survive a replay.
    assert len(REPLAY_CLEAN) < len(REPLAY_RAISES_OPERATIONAL)


def test_migration_009_comment_promises_a_guarantee_the_runner_cannot_keep():
    """Prose/code disagreement, pinned so it cannot be forgotten.

    009's header tells the next reader that ``schema_migrations`` makes its
    unguarded ADD COLUMN safe. The census shows 009 is one of the migrations
    that cannot survive a replay. If the runner is ever made atomic, 009 leaves
    REPLAY_RAISES_OPERATIONAL and this test fails — which is the moment to
    delete the comment's caveat rather than leave a stale promise standing.
    """
    sql_path = next(p for p in _up_migration_files() if _version_of(p) == 9)
    text = sql_path.read_text(encoding="utf-8")
    assert "only runs once per DB" in text, (
        "009's claim was reworded; re-check whether the new wording is true "
        "before editing this assertion"
    )
    assert 9 in REPLAY_RAISES_OPERATIONAL, (
        "009 now survives replay, so its header comment is finally accurate — "
        "update the comment and this test together"
    )
