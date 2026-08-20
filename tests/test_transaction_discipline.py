"""Finding 52 — transaction discipline across the WHOLE application.

``tests/test_db.py::test_every_transaction_block_takes_the_lock`` holds
``db.py``'s own blocks to ``with self._lock, self._conn:``. ⛔ Its universe is
**one file**, and Finding 52's acceptance criterion said so in as many words:
*"the first alone passes the moment someone adds an unguarded block somewhere
else."*

Someone already had. At ``cca7c5c`` there were **five** bare ``with db._conn:``
transaction blocks outside ``db.py`` — ``retention.py``, ``evidence.py`` ×2 and
``cli/import_argus.py`` ×2 — none of them taking ``db._lock``, and none of them
visible to that guard, which matches only the receiver ``self`` in one file.

⚠️ They were **unreachable rather than safe**: all three poller-side sites are
single-threaded only because ``bridges/ble.py`` happens to own its own
``Database``. One added thread, or one web route that captures evidence, makes
Finding 52's corruption live again — and nothing would have gone red.

So this guard's unit is *the application*, and the rule outside ``db.py`` is:

* write through :meth:`lynceus.db.Database.transaction`;
* never open a ``with`` block on ``._conn`` directly;
* never execute DML on ``._conn`` at all — that is an autocommit write holding
  no lock, the same hole with the ``with`` removed.
"""

from __future__ import annotations

import ast
import re
import threading
from pathlib import Path

import pytest

from lynceus.db import Database

SRC = Path(__file__).resolve().parents[1] / "src" / "lynceus"

# ⛔ Provably read-only, and NOTHING else. Anything this cannot prove is a read
# is treated as a write: a guard that assumes the unprovable case is a SELECT
# lets the one dynamic query through.
#
# ⚠️ This list started as a prefix tuple `("select", "pragma", "with", ...)`
# and a cross-model read killed it three ways, all reproduced:
#   * `WITH x AS (SELECT 1) DELETE FROM sightings`  really deletes (3 -> 0 rows)
#   * `PRAGMA user_version = 123`                   really writes (0 -> 123)
#   * `withering_heights_is_not_a_cte`              scored read-only, because a
#     bare `str.startswith` has no token boundary.
# `WITH` is now a WRITE unless nothing at all follows it that could write, which
# is not worth proving — no read site in `src/` uses a CTE — so it simply reads
# as a write. `PRAGMA` counts only in its argument-less QUERY form.
_READ_ONLY_SQL = re.compile(
    r"""^\s*(?:
          (?:select|explain)\b        # ordinary reads
        | pragma\s+\w+\s*;?\s*$     # `PRAGMA foo` -- the query form ONLY,
        )""",                        # never `PRAGMA foo = bar`, which writes
    re.IGNORECASE | re.VERBOSE,
)

# Methods that end or alter a transaction without executing any SQL at all. ⛔
# `db._conn.commit()` is the single most direct way to commit another thread's
# pending work, and a rule that only inspects `execute()` cannot see it.
_TXN_CONTROL = {"commit", "rollback"}

# ⛔ The universe as a CONTRACT, not a floor. `len(files) >= N` proves the walk
# ran, not that it looked at the right things: a broken glob, a renamed package
# or an AST parse that silently yielded nothing all score green against a count.
#
# ⚠️ These are modules the walk must PARSE — deliberately not "modules that
# reference `._conn`". The first version keyed on the latter and went red the
# moment `evidence.py` was cleaned up and legitimately stopped touching it: a
# contract that a *fix* can break is a contract that will be edited away rather
# than believed. Parsing is the property that only breaks when the walk does.
_MUST_BE_PARSED = {
    "db.py",
    "retention.py",
    "evidence.py",
    "poller.py",
    "webui/app.py",
    "cli/import_argus.py",
    "cli/seed_watchlist.py",
}


def _is_conn_attr(node: ast.AST) -> bool:
    """True for ``<anything>._conn`` — any receiver, not just ``self``."""
    return isinstance(node, ast.Attribute) and node.attr == "_conn"


def _alias_names(tree: ast.AST) -> set[str]:
    """Locals bound to the raw connection: ``conn = db._conn``.

    ⛔ Without this the guard matches a SPELLING rather than the connection. One
    assignment defeats it, and `webui/app.py` already contains that exact line —
    so the escape is not hypothetical, it is a line of shipped code away.
    """
    names: set[str] = set()

    def _binds_conn(value: ast.AST) -> bool:
        # ⛔ `cur = db._conn.cursor()` writes on the same connection and the
        # same transaction. A rule that follows only the connection OBJECT
        # lets every cursor write through — measured, both the chained and the
        # assigned form scored zero violations before this.
        if _is_conn_attr(value):
            return True
        return (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Attribute)
            and value.func.attr == "cursor"
            and _is_conn_attr(value.func.value)
        )

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and _binds_conn(node.value):
            names |= {t.id for t in node.targets if isinstance(t, ast.Name)}
        elif (
            isinstance(node, ast.AnnAssign)
            and node.value is not None
            and _binds_conn(node.value)
            and isinstance(node.target, ast.Name)
        ):
            names.add(node.target.id)
        elif isinstance(node, ast.withitem) and _binds_conn(node.context_expr):
            if isinstance(node.optional_vars, ast.Name):
                names.add(node.optional_vars.id)
    return names


def _is_conn_ref(node: ast.AST, aliases: set[str]) -> bool:
    """The connection itself, however it is spelled at this point.

    Covers the attribute, a name bound to it, and a cursor taken from it —
    including the chained ``db._conn.cursor().execute(...)`` form, where the
    receiver is a Call rather than a Name.
    """
    if _is_conn_attr(node):
        return True
    if isinstance(node, ast.Name) and node.id in aliases:
        return True
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "cursor"
        and _is_conn_ref(node.func.value, aliases)
    )


def _sql_is_read_only(arg: ast.AST, method: str = "execute") -> bool:
    """⛔ ``executescript`` is NEVER provably a read, whatever it starts with.

    ``execute()`` rejects a second statement; ``executescript()`` exists to
    accept one. So ``executescript("SELECT 1; DELETE FROM alerts;")`` reads as
    a SELECT and deletes the table — measured: 1 row -> 0.
    """
    if method == "executescript":
        return False
    if not (isinstance(arg, ast.Constant) and isinstance(arg.value, str)):
        return False  # not provably a read
    return _READ_ONLY_SQL.match(arg.value) is not None


def _scan() -> tuple[list[str], list[str], list[str]]:
    """Return (relative paths PARSED, `with ._conn` violations, DML violations)."""
    parsed: list[str] = []
    with_blocks: list[str] = []
    dml: list[str] = []

    for path in sorted(SRC.rglob("*.py")):
        rel = path.relative_to(SRC).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"))
        parsed.append(rel)
        if rel == "db.py":
            continue  # its own, stricter, in-file rule lives in test_db.py
        aliases = _alias_names(tree)

        for node in ast.walk(tree):
            if isinstance(node, ast.With) and any(
                _is_conn_ref(item.context_expr, aliases) for item in node.items
            ):
                with_blocks.append(f"{rel}:{node.lineno}")
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            if not _is_conn_ref(node.func.value, aliases):
                continue
            if node.func.attr in _TXN_CONTROL:
                dml.append(f"{rel}:{node.lineno} ({node.func.attr}())")
            elif node.func.attr in {"execute", "executemany", "executescript"} and not (
                node.args and _sql_is_read_only(node.args[0], node.func.attr)
            ):
                dml.append(f"{rel}:{node.lineno}")

    return parsed, with_blocks, dml


def test_the_guard_can_see_the_modules_it_is_supposed_to_police():
    """⛔ Run FIRST: a guard whose universe collapsed reports zero violations.

    This is the assertion that makes the two below mean something. Without it
    a typo in ``SRC``, a package rename or a parse that yielded nothing would
    turn this whole file into a test that cannot fail.
    """
    parsed, _, _ = _scan()
    missing = sorted(_MUST_BE_PARSED - set(parsed))
    assert not missing, (
        f"the guard no longer parses {missing} — either the walk is broken or "
        f"they were renamed. It parsed {len(parsed)} files: {sorted(parsed)[:12]}…"
    )
    assert len(parsed) > 40, (
        f"only {len(parsed)} modules parsed; the package has far more, so the "
        f"walk is not reaching them"
    )


def test_no_module_outside_db_opens_a_transaction_on_the_raw_connection():
    """Finding 52: ``with db._conn:`` outside ``db.py`` takes NO lock."""
    _, with_blocks, _ = _scan()
    assert not with_blocks, (
        f"{len(with_blocks)} transaction block(s) bypass `db._lock` entirely, at "
        f"{with_blocks}. Use `with db.transaction() as conn:` — it holds the lock "
        f"and the transaction together. See Database.transaction's docstring."
    )


def test_no_module_outside_db_writes_through_the_raw_connection():
    """The same hole with the ``with`` removed: an autocommit DML write.

    ⚠️ Closing only the ``with`` form would be a guard on a *spelling*.
    ``db._conn.execute("DELETE ...")`` with no block at all is the identical
    unlocked write, and it would sail past a with-only check.
    """
    _, _, dml = _scan()
    assert not dml, (
        f"{len(dml)} statement(s) execute on the raw connection outside `db.py` "
        f"and are not provably read-only, at {dml}. Route writes through "
        f"`db.transaction()`; keep `db._conn` for SELECT/PRAGMA only."
    )


def test_nothing_calls_a_database_method_from_inside_a_transaction_block():
    """⛔ ``transaction()`` refuses to nest ITSELF. It cannot refuse this.

    ``db.py``'s own methods open ``with self._lock, self._conn:`` directly and
    never consult the depth counter, and the ``RLock`` lets the same thread
    straight back in. So this still commits the outer block's partial work —
    measured on the shipped code:

        with db.transaction() as conn:
            conn.execute("INSERT ... 'outer'")
            db.add_alert(...)            # <- inner block EXITS -> COMMIT
            raise RuntimeError
        -> rows afterwards: ['outer', 'inner']

    Making every ``db.py`` method check the counter would be a 36-site change
    to a proven pattern for a caller that does not exist. Refusing the shape
    statically costs one test and cannot decay. ⚠️ If a real caller ever needs
    it, the fix is to pass ``conn`` down — not to relax this.
    """
    offenders: list[str] = []
    for path in sorted(SRC.rglob("*.py")):
        rel = path.relative_to(SRC).as_posix()
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.With):
                continue
            receivers = {
                item.context_expr.func.value.id
                for item in node.items
                if isinstance(item.context_expr, ast.Call)
                and isinstance(item.context_expr.func, ast.Attribute)
                and item.context_expr.func.attr == "transaction"
                and isinstance(item.context_expr.func.value, ast.Name)
            }
            if not receivers:
                continue
            for inner in ast.walk(node):
                if (
                    isinstance(inner, ast.Call)
                    and isinstance(inner.func, ast.Attribute)
                    and isinstance(inner.func.value, ast.Name)
                    and inner.func.value.id in receivers
                    and inner.func.attr != "transaction"
                ):
                    offenders.append(
                        f"{rel}:{inner.lineno} calls "
                        f"{inner.func.value.id}.{inner.func.attr}()"
                    )
    assert not offenders, (
        f"a Database method is called from inside a transaction block, which "
        f"COMMITS that block's partial work when the inner one exits: {offenders}. "
        f"Pass the yielded connection down instead."
    )


@pytest.mark.parametrize(
    "snippet, expect_with, expect_dml",
    [
        ("with db._conn:\n    db._conn.execute('DELETE FROM t')", 1, 1),
        ("db._conn.execute('DELETE FROM t')", 0, 1),
        ("db._conn.execute('SELECT 1')", 0, 0),
        ("db._conn.execute(sql)", 0, 1),  # not provably a read
        ("with db.transaction() as c:\n    c.execute('DELETE FROM t')", 0, 0),
        # ⭐ every row below is a real escape a cross-model read found in the
        # first version of this guard, and each was reproduced before being
        # fixed. They are the reason the matcher is not a prefix tuple.
        ("conn = db._conn\nwith conn:\n    conn.execute('DELETE FROM t')", 1, 1),
        ("db._conn.execute('WITH x AS (SELECT 1) DELETE FROM t')", 0, 1),
        ("db._conn.execute('PRAGMA user_version = 123')", 0, 1),
        ("db._conn.execute('PRAGMA user_version')", 0, 0),
        ("db._conn.execute('withering_heights_is_not_a_cte')", 0, 1),
        ("db._conn.commit()", 0, 1),
        ("conn = db._conn\nconn.rollback()", 0, 1),
        ("conn = db._conn\nconn.execute('SELECT 1')", 0, 0),
        # ⭐ round 2 of the cross-model read, against the FIXES above. Each of
        # these scored zero violations until the row beside it was added.
        ("db._conn.executescript('SELECT 1; DELETE FROM t;')", 0, 1),
        ("db._conn.cursor().execute('DELETE FROM t')", 0, 1),
        ("cur = db._conn.cursor()\ncur.execute('DELETE FROM t')", 0, 1),
        ("cur = db._conn.cursor()\ncur.execute('SELECT 1')", 0, 0),
        ("with db._conn.cursor() as c:\n    c.execute('DELETE FROM t')", 1, 1),
    ],
    ids=[
        "with-block", "autocommit-dml", "select", "dynamic-sql", "the-blessed-form",
        "aliased-with-block", "cte-that-deletes", "pragma-assignment",
        "pragma-query", "no-token-boundary", "bare-commit", "aliased-rollback",
        "aliased-select-is-fine",
        "executescript-select-prefix", "chained-cursor", "assigned-cursor",
        "cursor-select-is-fine", "cursor-as-context",
    ],
)
def test_the_detector_actually_discriminates(snippet, expect_with, expect_dml, tmp_path):
    """⭐ The detector, tested against known-bad and known-good source.

    A guard that reports "no violations" because its matcher is broken is
    indistinguishable from a clean tree. This pins the matcher itself — and the
    ``the-blessed-form`` row pins the other direction, so the rule cannot be
    satisfied by a detector that simply never fires.
    """
    tree = ast.parse(snippet)
    aliases = _alias_names(tree)
    found_with = sum(
        1
        for n in ast.walk(tree)
        if isinstance(n, ast.With)
        and any(_is_conn_ref(i.context_expr, aliases) for i in n.items)
    )
    found_dml = 0
    for n in ast.walk(tree):
        if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)):
            continue
        if not _is_conn_ref(n.func.value, aliases):
            continue
        if n.func.attr in _TXN_CONTROL:
            found_dml += 1
        elif n.func.attr in {"execute", "executemany", "executescript"} and not (
            n.args and _sql_is_read_only(n.args[0], n.func.attr)
        ):
            found_dml += 1
    assert (found_with, found_dml) == (expect_with, expect_dml)


# ---------------------------------------------------------------------------
# The primitive's own runtime contract. The guard above says "use
# db.transaction()"; these say what it is that you are being sent to.
# ---------------------------------------------------------------------------


def test_a_failed_transaction_rolls_its_own_write_back(tmp_path):
    """The baseline the two below are only interesting against."""
    db = Database(str(tmp_path / "t.db"))
    with pytest.raises(RuntimeError):
        with db.transaction() as conn:
            conn.execute(
                "INSERT INTO alerts (ts,rule_name,message,severity) VALUES (1,'a','m','low')"
            )
            raise RuntimeError("boom")
    assert db._conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0
    db.close()


def test_transaction_refuses_to_nest_because_nesting_would_commit_the_outer_block(
    tmp_path,
):
    """⛔ ``sqlite3``'s connection manager is not a savepoint.

    Measured on this exact code before the refusal was added: the inner block's
    exit COMMITTED, so the outer block's ``raise`` rolled back nothing and the
    rows afterwards were ``['outer', 'inner']``. A rollback that silently
    becomes a partial commit is the worst shape this class has — so re-entry is
    now a loud ``RuntimeError`` instead.
    """
    db = Database(str(tmp_path / "n.db"))
    with pytest.raises(RuntimeError, match="already open on this thread"):
        with db.transaction() as conn:
            conn.execute(
                "INSERT INTO alerts (ts,rule_name,message,severity) VALUES (1,'o','m','low')"
            )
            with db.transaction():
                pass

    # ...and the refusal did not leave the outer write committed either.
    assert db._conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0
    assert db._txn_depth == 0, "the depth counter leaked"
    db.close()


def test_a_DIFFERENT_thread_is_never_refused_it_simply_waits_its_turn(tmp_path):
    """⭐ THE FAIL-CLOSED CONTROL, and it is the reason the check sits inside
    the lock.

    A plain instance flag tested *before* acquiring would see "a transaction is
    open" for a second thread that is merely queued behind the first, and refuse
    a completely legitimate caller. This repo has already shipped one fix in
    this class that turned a duplicate-alert bug into an *undeliverable* alert,
    so the opposite direction gets its own test rather than an assumption.

    Both threads must COMMIT, and the refusal must never fire.
    """
    db = Database(str(tmp_path / "p.db"))
    start = threading.Barrier(2)
    errors: list[BaseException] = []

    def writer(name: str) -> None:
        try:
            start.wait(timeout=10)
            for i in range(20):  # plenty of overlap; the RLock must serialise
                with db.transaction() as conn:
                    conn.execute(
                        "INSERT INTO alerts (ts,rule_name,message,severity) "
                        "VALUES (?,?,?,?)",
                        (i, name, "m", "low"),
                    )
        except BaseException as exc:  # noqa: BLE001 - recorded, then asserted on
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(n,)) for n in ("A", "B")]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert not errors, f"a queued thread was refused: {errors!r}"
    counts = dict(
        db._conn.execute("SELECT rule_name, COUNT(*) FROM alerts GROUP BY rule_name")
    )
    assert counts == {"A": 20, "B": 20}, counts
    db.close()
