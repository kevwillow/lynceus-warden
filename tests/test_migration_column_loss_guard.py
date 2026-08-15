"""A forward migration must never drop a column from a surviving table.

⭐ Why this file exists — audit item **B4**, and why the fix is here rather
than in the migration.

Six migrations rebuild a table because SQLite cannot `ALTER` a `CHECK`
constraint (011, 013, 014, 019, 020, 021), and each one's `INSERT ... SELECT`
enumerates the columns **as of its own version**. Migration 014 lists ten;
migration 023 later adds `devices.ble_device_class`. Replaying 014 against a
head database rebuilds `devices` from the 014-era list and **silently drops
that column**, taking every stored Apple Continuity classification with it — no
exception, no warning, and the daemon starts happily one column short.

⛔ **B4 was filed as "make 014's rebuild list dynamic". That is impossible, and
it was verified rather than assumed.** Adding `ble_device_class` to 014's list
breaks a fresh migrate-to-head:

    OperationalError: no such column: ble_device_class

because 023 has not run when 014 executes. **A historical migration cannot
reference a later migration's schema.** The SQL must stay frozen, so the check
has to live in the runner, where both the before and after schemas are
observable.

⚠️ The guard is safe to apply unconditionally, and that was measured rather
than reasoned: stepping migrations 001..HEAD in order over an empty database
produces **zero** column losses. No forward migration legitimately removes a
column, so this can only fire on the defect.

⇒ Silent data loss becomes a loud refusal to stamp, naming the column and the
migration.
"""

from __future__ import annotations

import sqlite3

import pytest

from lynceus.db import Database

SEED_MAC = "aa:bb:cc:dd:ee:ff"
SEED_CLASS = "Audio/Video::Headphones"
LOST_COLUMN = "ble_device_class"
REBUILD_MIGRATION = 14


def _seeded_db(tmp_path) -> str:
    path = str(tmp_path / "guard.db")
    db = Database(path)
    db._conn.execute(
        "INSERT INTO devices(mac, device_type, first_seen, last_seen, "
        "is_randomized, sighting_count, ble_device_class) "
        "VALUES (?, 'ble', 1, 2, 0, 1, ?)",
        (SEED_MAC, SEED_CLASS),
    )
    db._conn.commit()
    # Presence assertion: the thing we are about to protect must exist first,
    # or "it was not lost" would be trivially true.
    stored = db._conn.execute(
        f"SELECT {LOST_COLUMN} FROM devices WHERE mac = ?", (SEED_MAC,)
    ).fetchone()
    assert stored is not None and stored[0] == SEED_CLASS
    db.close()
    return path


def _unstamp(path: str, version: int) -> None:
    """Produce schema-ahead-of-stamp, the state a replay needs.

    ⚠️ A crash cannot produce this — `commit()` is inside the per-migration
    loop, so a crash at N leaves N+1..HEAD unrun. `rollback_to` can, via its
    branches that delete the version row without applying a down migration.
    Constructed by hand here because the *consequence* is what matters.
    """
    conn = sqlite3.connect(path)
    conn.execute("DELETE FROM schema_migrations WHERE version = ?", (version,))
    conn.commit()
    conn.close()


# --- the control: normal operation must be untouched ------------------------


def test_a_fresh_database_migrates_to_head(tmp_path):
    """The arm that fails if the guard is too strict.

    A guard that raised on legitimate migrations would also make the test
    below pass, so this is what stops "fix it by rejecting everything".
    """
    db = Database(str(tmp_path / "fresh.db"))
    try:
        versions = db.applied_versions()
        assert len(versions) >= 25, f"fresh migrate stopped early: {versions}"
        columns = {row[1] for row in db._conn.execute("PRAGMA table_info(devices)")}
        assert LOST_COLUMN in columns
    finally:
        db.close()


def test_reopening_a_migrated_database_is_silent(tmp_path):
    """No pending migrations means the guard never runs — no cost, no noise."""
    path = _seeded_db(tmp_path)
    db = Database(path)
    try:
        assert db._conn.execute(
            f"SELECT {LOST_COLUMN} FROM devices WHERE mac = ?", (SEED_MAC,)
        ).fetchone()[0] == SEED_CLASS
    finally:
        db.close()


# --- the defect: a rebuild migration replaying against a newer schema -------


def test_replaying_a_rebuild_migration_refuses_instead_of_dropping_a_column(tmp_path):
    """The measured defect, now loud.

    Before the guard, this started cleanly and `devices.ble_device_class` was
    gone — along with the Continuity classification of every device row.
    """
    path = _seeded_db(tmp_path)
    _unstamp(path, REBUILD_MIGRATION)

    with pytest.raises(RuntimeError) as exc:
        Database(path)

    message = str(exc.value)
    # The operator must be told WHICH column and WHICH migration, or the
    # refusal is just a different kind of unhelpful.
    assert LOST_COLUMN in message, f"the lost column is not named: {message}"
    assert "14" in message, f"the migration is not named: {message}"
    assert "devices" in message


def test_the_data_is_still_there_after_the_refusal(tmp_path):
    """Refusing must not itself destroy anything.

    The rebuild runs inside `executescript`, which commits — so the guard
    fires *after* the damage would have been done to the table. This pins what
    actually survives, rather than assuming the raise rolled anything back.
    """
    path = _seeded_db(tmp_path)
    _unstamp(path, REBUILD_MIGRATION)
    with pytest.raises(RuntimeError):
        Database(path)

    conn = sqlite3.connect(path)
    try:
        row = conn.execute(
            "SELECT mac FROM devices WHERE mac = ?", (SEED_MAC,)
        ).fetchone()
        assert row is not None, "the device row itself was destroyed"
        # ⚠️ Deliberately NOT asserting the column survived. It does not — the
        # rebuild already committed. The guard's job is to stop the daemon
        # STAMPING that state and carrying on, not to undo it. Recorded here
        # so nobody reads the refusal as a rollback it is not.
        columns = {r[1] for r in conn.execute("PRAGMA table_info(devices)")}
        assert LOST_COLUMN not in columns
    finally:
        conn.close()


def test_every_rebuild_migration_is_covered_by_the_guard(tmp_path):
    """Sweep with a floor, so a new rebuild migration cannot slip in unguarded.

    ⚠️ `assert seen >= N` before judging: a pattern that matched nothing would
    otherwise make this pass by finding no rebuild migrations at all.
    """
    import pathlib
    import re

    import lynceus.db as db_mod

    migrations = pathlib.Path(db_mod.__file__).parent / "migrations"
    rebuilds = []
    for sql in sorted(migrations.glob("*.sql")):
        if sql.name.endswith("_down.sql"):
            continue
        text = sql.read_text(encoding="utf-8")
        if re.search(r"DROP TABLE", text, re.I) and re.search(r"RENAME TO", text, re.I):
            rebuilds.append(sql.name)

    assert len(rebuilds) >= 6, (
        f"expected at least the six known table-rebuild migrations, found "
        f"{rebuilds} — the detection pattern has drifted"
    )
    # The guard is unconditional in _apply_migrations, so covering "every
    # rebuild" means covering every migration. This asserts the guard is
    # actually wired into the loop rather than defined and unused.
    import inspect

    body = inspect.getsource(db_mod.Database._apply_migrations)
    assert "_assert_no_columns_lost" in body, (
        "the column-loss guard is no longer called from _apply_migrations"
    )
