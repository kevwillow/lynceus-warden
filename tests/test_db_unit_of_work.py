"""The `Database.unit()` contract, from SPEC_unit_of_work.md §3.

⭐ The headline is `test_transaction_loses_a_concurrent_write_and_unit_does_not`.
Everything else here is the contract; that one is the reason the contract is
worth having.

⛔ `unit()` is added ALONGSIDE `transaction()` (spec §6 step 2). Nothing is
migrated onto it in this change, so both must keep working, and a test here
asserts the OLD behaviour deliberately -- not because it is correct, but
because it is what callers still get until they are moved. When a caller
migrates, the assertion about `transaction()` in that path is what should
change.
"""

from __future__ import annotations

import sqlite3

import pytest

from lynceus.db import Database

MAC = "aa:bb:cc:00:00:01"


def _db(tmp_path, name="u.db"):
    db = Database(str(tmp_path / name))
    db.ensure_location("home", "Home")
    db.upsert_device(
        mac=MAC, device_type="wifi", oui_vendor="Axon", is_randomized=0, now_ts=1000
    )
    return db


def _read_last_seen(db):
    return db._conn.execute(
        "SELECT last_seen FROM devices WHERE mac = ?", (MAC,)
    ).fetchone()[0]


# ---------------------------------------------------------------------------
# The defect the unit exists to close
# ---------------------------------------------------------------------------


def _read_decide_write(db, opener, other):
    """One read-then-write, with a competing writer committing in between.

    Returns (the competing writer was blocked, the final stored value).
    """
    blocked = None
    with opener() as conn:
        before = conn.execute(
            "SELECT last_seen FROM devices WHERE mac = ?", (MAC,)
        ).fetchone()[0]
        try:
            other.execute("UPDATE devices SET last_seen = 9999 WHERE mac = ?", (MAC,))
            other.commit()
            blocked = False
        except sqlite3.OperationalError:
            blocked = True
        conn.execute(
            "UPDATE devices SET last_seen = ? WHERE mac = ?", (before + 1, MAC)
        )
    return blocked, _read_last_seen(db)


def test_transaction_loses_a_concurrent_write_and_unit_does_not(tmp_path):
    """🪤 A read inside `transaction()` is NOT inside the transaction.

    `Database` sets no `isolation_level`, so sqlite3 opens a DEFERRED
    transaction lazily, on the first statement that writes. Every SELECT before
    that runs in autocommit. Read-decide-write is the shape every rule in this
    product uses, so the window between the read and the write is open to any
    other writer, and the loser's commit is overwritten with no error anywhere.

    `unit()` issues BEGIN IMMEDIATE, taking the write lock up front, so the
    competing writer waits out `busy_timeout` and is refused instead of
    silently interleaving.
    """
    db = _db(tmp_path, "old.db")
    other = sqlite3.connect(str(tmp_path / "old.db"), timeout=0.3)
    try:
        blocked, final = _read_decide_write(db, db.transaction, other)
    finally:
        other.close()
        db.close()
    assert blocked is False, "the competing writer was blocked; the premise has changed"
    assert final == 1001, (
        "expected the classic lost update: our read saw 1000, the other writer "
        "committed 9999, and our write put 1001 over the top of it"
    )

    db = _db(tmp_path, "new.db")
    other = sqlite3.connect(str(tmp_path / "new.db"), timeout=0.3)
    try:
        blocked, final = _read_decide_write(db, db.unit, other)
    finally:
        other.close()
        db.close()
    assert blocked is True, (
        "the competing writer was NOT blocked inside a unit, so BEGIN IMMEDIATE "
        "did not take the write lock and the lost-update window is still open"
    )
    assert final == 1001


def test_a_read_inside_a_unit_is_actually_inside_the_transaction(tmp_path):
    """The mechanism behind the test above, asserted directly."""
    db = _db(tmp_path)
    try:
        with db.unit() as conn:
            conn.execute("SELECT last_seen FROM devices WHERE mac = ?", (MAC,)).fetchone()
            assert conn.in_transaction, (
                "the SELECT ran in autocommit, so the unit is not isolating reads"
            )
        with db.transaction() as conn:
            conn.execute("SELECT last_seen FROM devices WHERE mac = ?", (MAC,)).fetchone()
            assert not conn.in_transaction, (
                "transaction() now isolates reads too. That is an improvement, "
                "but it means the comparison above no longer measures anything "
                "-- rewrite these two tests rather than deleting this line."
            )
    finally:
        db.close()


# ---------------------------------------------------------------------------
# §3, row by row
# ---------------------------------------------------------------------------


def test_the_unit_commits_on_clean_exit(tmp_path):
    db = _db(tmp_path)
    try:
        with db.unit() as conn:
            conn.execute("UPDATE devices SET last_seen = 4242 WHERE mac = ?", (MAC,))
        assert _read_last_seen(db) == 4242
    finally:
        db.close()


def test_an_exception_rolls_back_and_propagates(tmp_path):
    db = _db(tmp_path)
    try:
        with pytest.raises(ValueError, match="boom"):
            with db.unit() as conn:
                conn.execute("UPDATE devices SET last_seen = 7777 WHERE mac = ?", (MAC,))
                raise ValueError("boom")
        assert _read_last_seen(db) == 1000, "the unit committed work it should have rolled back"
    finally:
        db.close()


def test_a_keyboardinterrupt_also_rolls_back(tmp_path):
    """⛔ Caught as BaseException, not Exception.

    A unit interrupted mid-body must release the write lock. Leaving the
    transaction open would hold it until the connection died, blocking the
    poller and the web UI in other processes for as long as the process lived.
    """
    db = _db(tmp_path)
    try:
        with pytest.raises(KeyboardInterrupt):
            with db.unit() as conn:
                conn.execute("UPDATE devices SET last_seen = 5555 WHERE mac = ?", (MAC,))
                raise KeyboardInterrupt
        assert _read_last_seen(db) == 1000
        assert not db._conn.in_transaction, "the write lock is still held after the interrupt"
    finally:
        db.close()


@pytest.mark.parametrize(
    "outer,inner",
    [("unit", "unit"), ("unit", "transaction"), ("transaction", "unit")],
    ids=["unit-in-unit", "transaction-in-unit", "unit-in-transaction"],
)
def test_nesting_is_refused_in_every_direction(tmp_path, outer, inner):
    """⛔ All three interleavings, because the two share one depth counter.

    An inner block's exit COMMITS the connection, so nesting turns an outer
    rollback into a partial commit. Refusing `unit()` inside `unit()` but
    allowing it inside `transaction()` would leave that hole open through the
    whole migration, which is when both APIs are live at once.
    """
    db = _db(tmp_path)
    try:
        with pytest.raises(RuntimeError, match="nest|already open"):
            with getattr(db, outer)():
                with getattr(db, inner)():
                    pass
    finally:
        db.close()


def test_a_readonly_unit_does_not_block_a_writer(tmp_path):
    """`readonly=True` issues a plain BEGIN, so it takes no write lock."""
    db = _db(tmp_path)
    other = sqlite3.connect(str(tmp_path / "u.db"), timeout=0.3)
    try:
        with db.unit(readonly=True) as conn:
            conn.execute("SELECT count(*) FROM devices").fetchone()
            other.execute("UPDATE devices SET last_seen = 3333 WHERE mac = ?", (MAC,))
            other.commit()
    except sqlite3.OperationalError as exc:  # pragma: no cover - the failure we guard
        pytest.fail(f"a read-only unit blocked a writer: {exc}")
    finally:
        other.close()
        db.close()


def test_the_isolation_level_is_restored_after_a_unit(tmp_path):
    """🪤 The unit switches the shared connection to manual transaction mode.

    If that leaked, every later `transaction()` and every implicit `with
    self._conn:` in this class would stop committing, silently, everywhere.
    """
    db = _db(tmp_path)
    try:
        before = db._conn.isolation_level
        with db.unit() as conn:
            conn.execute("UPDATE devices SET last_seen = 11 WHERE mac = ?", (MAC,))
        assert db._conn.isolation_level == before
        # And it is restored on the failing path too.
        with pytest.raises(ValueError):
            with db.unit() as conn:
                raise ValueError
        assert db._conn.isolation_level == before
        # The old API still commits afterwards.
        with db.transaction() as conn:
            conn.execute("UPDATE devices SET last_seen = 22 WHERE mac = ?", (MAC,))
        assert _read_last_seen(db) == 22
    finally:
        db.close()


def test_a_lock_timeout_raises_rather_than_returning(tmp_path):
    """⛔ Failure classes are never converted into a result.

    Spec §3: "Nothing in this design ever converts an infrastructure failure
    into a 'someone else won' result." A caller that could not write has to
    find out.
    """
    path = str(tmp_path / "u.db")
    db = _db(tmp_path)
    holder = sqlite3.connect(path, timeout=0.1, isolation_level=None)
    try:
        holder.execute("BEGIN IMMEDIATE")
        db._conn.execute("PRAGMA busy_timeout = 100")
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            with db.unit():
                pass
        assert not db._conn.in_transaction, "a failed BEGIN left the connection in a transaction"
    finally:
        holder.rollback()
        holder.close()
        db.close()
