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

import contextlib
import sqlite3

import pytest

from lynceus.db import Database

MAC = "aa:bb:cc:00:00:01"


@contextlib.contextmanager
def _db(tmp_path, name="u.db"):
    """A seeded database, closed on exit.

    `Database` is a context manager, and holding one in a `with` rather than a
    `try/finally` is what the rest of `tests/` does.
    """
    with Database(str(tmp_path / name)) as db:
        db.ensure_location("home", "Home")
        db.upsert_device(
            mac=MAC, device_type="wifi", oui_vendor="Axon", is_randomized=0, now_ts=1000
        )
        yield db


def _raise(exc: BaseException) -> None:
    """Raise `exc` from inside a `with pytest.raises(...)` body.

    ⚠️ A CALL rather than a bare `raise` statement, and that is not cosmetic.
    A literal `raise` inside the block makes static analysis mark every
    statement after the enclosing `pytest.raises` as unreachable -- CodeQL
    reported exactly that, three times, on the assertions that check what the
    unit did with the failure. Those assertions are the point of the tests.
    """
    raise exc


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
    with _db(tmp_path, "old.db") as db, \
            contextlib.closing(sqlite3.connect(str(tmp_path / "old.db"), timeout=0.3)) as other:
        blocked, final = _read_decide_write(db, db.transaction, other)
    assert blocked is False, "the competing writer was blocked; the premise has changed"
    assert final == 1001, (
        "expected the classic lost update: our read saw 1000, the other writer "
        "committed 9999, and our write put 1001 over the top of it"
    )

    with _db(tmp_path, "new.db") as db, \
            contextlib.closing(sqlite3.connect(str(tmp_path / "new.db"), timeout=0.3)) as other:
        blocked, final = _read_decide_write(db, db.unit, other)
    assert blocked is True, (
        "the competing writer was NOT blocked inside a unit, so BEGIN IMMEDIATE "
        "did not take the write lock and the lost-update window is still open"
    )
    assert final == 1001


def test_a_read_inside_a_unit_is_actually_inside_the_transaction(tmp_path):
    """The mechanism behind the test above, asserted directly."""
    with _db(tmp_path) as db:
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


# ---------------------------------------------------------------------------
# §3, row by row
# ---------------------------------------------------------------------------


def test_the_unit_commits_on_clean_exit(tmp_path):
    with _db(tmp_path) as db:
        with db.unit() as conn:
            conn.execute("UPDATE devices SET last_seen = 4242 WHERE mac = ?", (MAC,))
        assert _read_last_seen(db) == 4242


def test_an_exception_rolls_back_and_propagates(tmp_path):
    with _db(tmp_path) as db:
        with pytest.raises(ValueError, match="boom"):
            with db.unit() as conn:
                conn.execute("UPDATE devices SET last_seen = 7777 WHERE mac = ?", (MAC,))
                _raise(ValueError("boom"))
        assert _read_last_seen(db) == 1000, "the unit committed work it should have rolled back"


def test_a_keyboardinterrupt_also_rolls_back(tmp_path):
    """⛔ Caught as BaseException, not Exception.

    A unit interrupted mid-body must release the write lock. Leaving the
    transaction open would hold it until the connection died, blocking the
    poller and the web UI in other processes for as long as the process lived.
    """
    with _db(tmp_path) as db:
        with pytest.raises(KeyboardInterrupt):
            with db.unit() as conn:
                conn.execute("UPDATE devices SET last_seen = 5555 WHERE mac = ?", (MAC,))
                _raise(KeyboardInterrupt())
        assert _read_last_seen(db) == 1000
        assert not db._conn.in_transaction, "the write lock is still held after the interrupt"


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
    with _db(tmp_path) as db:
        with pytest.raises(RuntimeError, match="nest|already open"):
            with getattr(db, outer)():
                with getattr(db, inner)():
                    pass


def test_a_readonly_unit_does_not_block_a_writer(tmp_path):
    """`readonly=True` issues a plain BEGIN, so it takes no write lock."""
    with _db(tmp_path) as db, \
            contextlib.closing(sqlite3.connect(str(tmp_path / "u.db"), timeout=0.3)) as other:
        try:
            with db.unit(readonly=True) as conn:
                conn.execute("SELECT count(*) FROM devices").fetchone()
                other.execute("UPDATE devices SET last_seen = 3333 WHERE mac = ?", (MAC,))
                other.commit()
        except sqlite3.OperationalError as exc:  # pragma: no cover - the guarded failure
            pytest.fail(f"a read-only unit blocked a writer: {exc}")


def test_the_isolation_level_is_restored_after_a_unit(tmp_path):
    """🪤 The unit switches the shared connection to manual transaction mode.

    If that leaked, every later `transaction()` and every implicit `with
    self._conn:` in this class would stop committing, silently, everywhere.
    """
    with _db(tmp_path) as db:
        before = db._conn.isolation_level
        with db.unit() as conn:
            conn.execute("UPDATE devices SET last_seen = 11 WHERE mac = ?", (MAC,))
        assert db._conn.isolation_level == before
        # And it is restored on the failing path too.
        with pytest.raises(ValueError):
            with db.unit() as conn:
                _raise(ValueError())
        assert db._conn.isolation_level == before
        # The old API still commits afterwards.
        with db.transaction() as conn:
            conn.execute("UPDATE devices SET last_seen = 22 WHERE mac = ?", (MAC,))
        assert _read_last_seen(db) == 22


def test_a_lock_timeout_raises_rather_than_returning(tmp_path):
    """⛔ Failure classes are never converted into a result.

    Spec §3: "Nothing in this design ever converts an infrastructure failure
    into a 'someone else won' result." A caller that could not write has to
    find out.
    """
    path = str(tmp_path / "u.db")
    with _db(tmp_path) as db, \
            contextlib.closing(sqlite3.connect(path, timeout=0.1, isolation_level=None)) as holder:
        holder.execute("BEGIN IMMEDIATE")
        try:
            db._conn.execute("PRAGMA busy_timeout = 100")
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                with db.unit():
                    pass
            assert not db._conn.in_transaction, (
                "a failed BEGIN left the connection in a transaction"
            )
        finally:
            holder.rollback()


# ---------------------------------------------------------------------------
# A failed ENTRY must not wedge the Database.
#
# ⛔ The defect these cover: the depth counter was incremented BEFORE the
# `try`, and two statements sat in the gap -- reading and then clearing
# `isolation_level` on the shared connection. Either can raise (a closed
# `sqlite3.Connection` raises `ProgrammingError` on both; a stand-in without
# the attribute raises `AttributeError` on the read). The `finally` that
# decrements never ran, so the depth stayed at 1 FOREVER and every later
# `transaction()` and `unit()` on that Database was refused -- each with a
# message naming a cause that was not the cause.
#
# A third leak lived INSIDE the `finally`: the isolation restore ran BEFORE the
# decrement, so a raise in the restore leaked the depth too.
#
# ⚠️ These tests assert the RECOVERY, not the counter. `_txn_depth == 0` is a
# private detail; "the next caller can still write" is the property.


class _ConnProxy:
    """Delegates everything to a real `sqlite3.Connection`, both ways.

    ⚠️ `__setattr__` forwards on purpose. Six existing `_conn` stand-ins in
    `tests/` define only `__getattr__`, so `self._conn.isolation_level = None`
    inside `unit()` lands on the PROXY and shadows the delegated read -- the
    real connection never leaves `isolation_level = ''` and the unit's core
    mechanism silently becomes a no-op. A proxy used to test `unit()` must not
    have that hole, or the test is vacuous.
    """

    def __init__(self, inner):
        object.__setattr__(self, "_inner", inner)

    def __getattr__(self, name):
        return getattr(object.__getattribute__(self, "_inner"), name)

    def __setattr__(self, name, value):
        setattr(object.__getattribute__(self, "_inner"), name, value)


class _ReadOfIsolationRaises(_ConnProxy):
    """Fails where the entry sequence READS `isolation_level`."""

    def __getattr__(self, name):
        if name == "isolation_level":
            raise sqlite3.ProgrammingError("Cannot operate on a closed database.")
        return super().__getattr__(name)


class _WriteOfIsolationRaises(_ConnProxy):
    """Fails where the entry sequence CLEARS `isolation_level`."""

    def __setattr__(self, name, value):
        if name == "isolation_level":
            raise sqlite3.ProgrammingError("Cannot operate on a closed database.")
        super().__setattr__(name, value)


class _RestoreOfIsolationRaises(_ConnProxy):
    """Lets the unit run, then fails in the `finally` that restores isolation."""

    def __setattr__(self, name, value):
        if name == "isolation_level" and value is not None:
            raise sqlite3.ProgrammingError("Cannot operate on a closed database.")
        super().__setattr__(name, value)


def _assert_the_database_still_works(db, marker):
    """The load-bearing half: a later caller can still open and commit.

    Checks BOTH primitives, because the leaked depth is shared: it refused
    `transaction()` with "already open on this thread" and `unit()` with
    "cannot nest", and neither message was true.
    """
    assert db._txn_depth == 0, f"the depth counter leaked: {db._txn_depth}"
    with db.transaction() as conn:
        conn.execute("UPDATE devices SET last_seen = ? WHERE mac = ?", (marker, MAC))
    assert _read_last_seen(db) == marker
    with db.unit() as conn:
        conn.execute("UPDATE devices SET last_seen = ? WHERE mac = ?", (marker + 1, MAC))
    assert _read_last_seen(db) == marker + 1
    # ⛔ OPPOSITE DIRECTION. The fail-CLOSED mirror of this fix is a counter
    # that no longer counts, which would silently re-open the nesting bug the
    # counter exists to prevent. Nesting must STILL be refused.
    with pytest.raises(RuntimeError, match="cannot nest"):
        with db.unit():
            with db.unit():
                pass  # pragma: no cover - the nested body must never run
    assert db._txn_depth == 0, "the refused nesting leaked the depth"


@pytest.mark.parametrize(
    "trap",
    [_ReadOfIsolationRaises, _WriteOfIsolationRaises],
    ids=["reading_isolation_level", "clearing_isolation_level"],
)
def test_a_unit_whose_ENTRY_raises_does_not_wedge_the_database(tmp_path, trap):
    """🪤 The entry failure must cost that ONE call, not the Database."""
    with _db(tmp_path) as db:
        real = db._conn
        db._conn = trap(real)
        try:
            # (i) the ORIGINAL failure reaches the caller, not a RuntimeError
            #     about nesting that names a cause which is not the cause.
            with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
                with db.unit():
                    pass  # pragma: no cover - entry never completes
        finally:
            db._conn = real
        # (ii) and the Database is still usable afterwards.
        _assert_the_database_still_works(db, 4001)


def test_a_unit_whose_isolation_RESTORE_raises_does_not_wedge_the_database(tmp_path):
    """🪤 The third leak, inside the `finally` itself.

    The restore ran before the decrement in the same `finally`, so a raise in
    the restore skipped the decrement. Same permanent wedge, reached from the
    exit path instead of the entry path.
    """
    with _db(tmp_path) as db:
        real = db._conn
        db._conn = _RestoreOfIsolationRaises(real)
        try:
            with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
                with db.unit() as conn:
                    conn.execute(
                        "UPDATE devices SET last_seen = 5000 WHERE mac = ?", (MAC,)
                    )
        finally:
            db._conn = real
            real.isolation_level = ""
        _assert_the_database_still_works(db, 5001)


def test_the_entry_fix_did_not_stop_the_counter_counting(tmp_path):
    """⛔ Control for the fail-CLOSED direction, on the clean path.

    Moving the increment or the `try` is one edit away from a counter that is
    decremented while it should still be held. If that happened, nesting would
    stop being refused and `unit()` inside `unit()` would silently commit the
    outer block's partial work -- the exact bug the counter exists to prevent.
    """
    with _db(tmp_path) as db:
        assert db._txn_depth == 0
        with db.unit():
            assert db._txn_depth == 1, "the depth is not held for the unit's body"
            with pytest.raises(RuntimeError, match="cannot nest"):
                with db.unit():
                    pass  # pragma: no cover - the nested body must never run
            with pytest.raises(RuntimeError, match="already open on this thread"):
                with db.transaction():
                    pass  # pragma: no cover - the nested body must never run
        assert db._txn_depth == 0
