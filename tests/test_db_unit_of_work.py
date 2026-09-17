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

from lynceus.db import Database, _UnitConnection

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


def test_run_inside_an_open_unit_is_refused_and_does_not_deadlock(tmp_path):
    """⚠️ CONTROL, and it passes both before and after `run()` became a unit.

    `unit()` holds an RLock for its whole body, and `run()` now opens a unit per
    attempt, so a `run()` reached from inside an open unit on the same thread
    re-enters the lock rather than blocking on it. The depth counter is what
    refuses it, immediately -- measured at 0.000s -- and the refusal is a
    `RuntimeError`, which `run()` does not classify as contention and therefore
    does not retry. If the counter ever stopped counting, this would deadlock or
    silently commit the outer unit's partial work instead.
    """
    with _db(tmp_path) as db:
        with db.unit():
            with pytest.raises(RuntimeError, match="nest|already open"):
                db.run(lambda conn: conn.execute("SELECT 1"), deadline_seconds=5)
        assert db._txn_depth == 0


def test_a_readonly_run_does_not_take_the_write_lock(tmp_path):
    """⛔ ``run()`` without a read-only form turns a working read into a 500.

    Measured before this existed, against an 8s cross-process write hold:

        main    RETURNED 0 in 0.00s,  fn invoked 1x
        run()   RAISED database is locked after 5.00s, fn invoked 0x

    Pure loss: nothing is written, so no atomicity is bought — the caller pays
    the deadline plus a full ``busy_timeout`` and gets an exception where it
    used to get data. ``SPEC_unit_of_work.md`` §8 already says read-only web
    routes get ``unit(readonly=True)``; ``run()`` is the retryable form of the
    same primitive and needs the same door.
    """
    import sqlite3 as _sq

    path = str(tmp_path / "ro.db")
    db = Database(path)
    db._conn.execute("CREATE TABLE k(id INTEGER PRIMARY KEY, v INT)")
    db._conn.execute("INSERT INTO k VALUES (1, 10)")
    db._conn.commit()

    other = _sq.connect(path, timeout=0.5)
    seen = {}

    def body(conn):
        # ⚠️ Read FIRST. A plain `BEGIN` is DEFERRED, so the read snapshot is
        # taken by the first statement that reads, not by the BEGIN itself.
        # Writing this the other way round measures nothing.
        first = conn.execute("SELECT v FROM k WHERE id = 1").fetchone()[0]
        # A writer on a SEPARATE connection must get through while this
        # read-only unit is open. Under BEGIN IMMEDIATE it would be blocked.
        try:
            other.execute("BEGIN IMMEDIATE")
            other.execute("UPDATE k SET v = 99 WHERE id = 1")
            other.commit()
            seen["other"] = "WROTE"
        except _sq.OperationalError as exc:
            seen["other"] = f"BLOCKED: {exc}"
        return first, conn.execute("SELECT v FROM k WHERE id = 1").fetchone()[0]

    first, second = db.run(body, deadline_seconds=5, readonly=True)

    assert seen["other"] == "WROTE", (
        "a read-only run() took the write lock, so a concurrent writer was "
        f"blocked: {seen['other']}"
    )
    assert (first, second) == (10, 10), (
        "the read-only unit is not a consistent snapshot: it saw the other "
        f"writer's commit mid-body ({first} then {second})"
    )
    other.close()


def test_a_WRITING_run_still_takes_the_write_lock(tmp_path):
    """⛔ The opposite direction: adding ``readonly`` must not weaken the default.

    If ``run()`` stopped taking the write lock by default, every caller would
    silently go back to the read-decide-write window this primitive exists to
    close — a regression that no test asserting "it returned a value" would
    catch.
    """
    import sqlite3 as _sq

    path = str(tmp_path / "rw.db")
    db = Database(path)
    db._conn.execute("CREATE TABLE k(id INTEGER PRIMARY KEY, v INT)")
    db._conn.execute("INSERT INTO k VALUES (1, 10)")
    db._conn.commit()

    other = _sq.connect(path, timeout=0.5)
    seen = {}

    def body(conn):
        try:
            other.execute("BEGIN IMMEDIATE")
            other.execute("UPDATE k SET v = 99 WHERE id = 1")
            other.commit()
            seen["other"] = "WROTE"
        except _sq.OperationalError as exc:
            seen["other"] = f"BLOCKED: {exc}"
        conn.execute("UPDATE k SET v = 11 WHERE id = 1")

    db.run(body, deadline_seconds=5)  # default: writing

    assert seen["other"].startswith("BLOCKED"), (
        "a writing run() did NOT hold the write lock across its body; the "
        f"lost-update window is open again: {seen['other']}"
    )
    other.close()


def _a_database_method(db, label):
    """The shape 39 methods in db.py use verbatim."""
    with db._lock, db._conn:
        db._conn.execute("INSERT INTO t VALUES (?)", (label,))


def _seeded(tmp_path, name):
    db = Database(str(tmp_path / name))
    db._conn.execute("CREATE TABLE t(v TEXT)")
    db._conn.commit()
    return db


def test_a_database_method_called_inside_a_unit_is_REFUSED(tmp_path):
    """⛔ Finding 68. A nested ``with conn:`` COMMITS the unit's transaction.

    ``unit()`` sets ``isolation_level = None`` to own its own BEGIN/COMMIT, so
    ``with self._lock, self._conn:`` -- the shape 39 ``db.py`` methods use --
    commits on exit. Everything after it then runs in autocommit, and the
    rollback at the end has nothing left to undo. Measured before this refusal:

        rows surviving a FAILED unit: ['a', 'b', 'c']
        the contract says:            []

    ⛔ No static guard can catch it: ``run()``'s callable is not lexically
    inside a ``with``. SPEC_unit_of_work.md §3 says "Nesting? Refused. No
    implicit joining, no savepoint games" -- so it is refused at RUNTIME, at
    the call site, rather than silently joined.
    """
    db = _seeded(tmp_path, "f68.db")

    with pytest.raises(RuntimeError, match="pass the connection"):
        with db.unit() as conn:
            conn.execute("INSERT INTO t VALUES ('a')")
            _a_database_method(db, "b")

    rows = [r[0] for r in db._conn.execute("SELECT v FROM t")]
    assert rows == [], f"a failed unit left rows behind: {rows}"


def test_the_refusal_does_not_wedge_the_database(tmp_path):
    """⛔ The fix installs a proxy as ``self._conn``. A raise between installing
    and restoring it would leave the Database holding a proxy forever — which
    is Defect A (#279) reintroduced through a different door."""
    db = _seeded(tmp_path, "wedge.db")

    with pytest.raises(RuntimeError):
        with db.unit() as conn:
            conn.execute("INSERT INTO t VALUES ('x')")
            _a_database_method(db, "y")

    assert db._txn_depth == 0, "the depth counter leaked"
    assert not isinstance(db._conn, _UnitConnection), "the proxy was never removed"
    # ⭐ The load-bearing half: the Database still WORKS.
    _a_database_method(db, "after")
    with db.unit() as conn:
        conn.execute("INSERT INTO t VALUES ('later')")
    assert [r[0] for r in db._conn.execute("SELECT v FROM t")] == ["after", "later"]


def test_a_database_method_OUTSIDE_a_unit_still_commits(tmp_path):
    """⛔ The opposite direction. The fail-closed mirror of this change is a
    refusal that escapes the unit and breaks all 39 ordinary call sites."""
    db = _seeded(tmp_path, "outside.db")
    _a_database_method(db, "ordinary")
    assert [r[0] for r in db._conn.execute("SELECT v FROM t")] == ["ordinary"]


def test_a_unit_body_cannot_commit_or_rollback_the_unit(tmp_path):
    """SPEC §3: "Who commits? The unit, on clean exit. Callers never commit." """
    db = _seeded(tmp_path, "nocommit.db")
    for op in ("commit", "rollback"):
        with pytest.raises(RuntimeError, match="the unit"):
            with db.unit() as conn:
                getattr(conn, op)()
        assert db._txn_depth == 0


def test_a_readonly_unit_refuses_nesting_too(tmp_path):
    """A read-only unit takes no write lock, but a nested block would still end
    its transaction — the refusal is about the transaction, not the lock."""
    db = _seeded(tmp_path, "ro.db")
    with pytest.raises(RuntimeError, match="pass the connection"):
        with db.unit(readonly=True) as conn:
            conn.execute("SELECT 1")
            _a_database_method(db, "z")
    assert db._txn_depth == 0


def test_an_attribute_set_through_the_unit_reaches_the_REAL_connection(tmp_path):
    """⛔ The proxy forwards writes. A ``__getattr__``-only proxy swallows
    attribute WRITES into its own ``__dict__`` while reads still pass through —
    nothing errors, and the real connection never changes. That exact shape was
    measured in this repo's test proxies, where ``isolation_level = None``
    landed on the proxy and the connection stayed in legacy mode, passing."""
    db = _seeded(tmp_path, "setattr.db")
    real = db._conn
    with db.unit() as conn:
        conn.row_factory = sqlite3.Row
        assert real.row_factory is sqlite3.Row, (
            "the write landed on the proxy, not the connection"
        )
    real.row_factory = None
