"""`REPLACE` / `INSERT OR REPLACE` must not appear in this codebase's SQL.

⛔ This is the ONE lexical rule in the unit-of-work work, and it exists because
a runtime gate provably cannot cover this case.

`internal/specs/SPEC_unit_of_work.md` §7 records the measurement:
`sqlite3.Connection.set_authorizer` is column-precise for `UPDATE`, catches
`INSERT ... ON CONFLICT DO UPDATE` through the same gate, and reports `DELETE`
per table. But `REPLACE` reports `SQLITE_INSERT` on the table with **no column
and no delete** -- byte-for-byte indistinguishable from a legitimate insert. So
denying it at runtime would mean denying every insert. Gating `SQLITE_DELETE`
does not help either: `REPLACE` never reports a delete. Verified both ways.

⇒ The keyword is closed at the source instead. This is deliberately NOT the
rule an earlier red-team destroyed: that one required proving a SQL literal
lived inside a particular function, which is undecidable in a real codebase.
"Does any SQL statement in `src/` begin a REPLACE?" is decidable, and it
composes WITH the runtime gate rather than substituting for it.

⚠️ Why `REPLACE` is worth banning at all: it is a DELETE plus an INSERT wearing
an INSERT's clothes. It silently destroys the row it replaces, taking every
column the caller did not mention with it, and it fires ON DELETE CASCADE on
children. An upsert (`INSERT ... ON CONFLICT DO UPDATE`) touches only the
columns it names, which is what this schema's concurrent writers need.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"

# ⛔ The statement forms only. SQLite also has a scalar function `replace(X,Y,Z)`
# for string substitution, which is entirely legitimate and must not be caught:
# a rule that banned the bare word would fire on `replace(mac, ':', '')` and be
# switched off within a week.
BANNED = re.compile(r"\b(?:INSERT\s+OR\s+REPLACE|REPLACE\s+INTO)\b", re.IGNORECASE)

# 🪤 A string is SQL only if it opens with a statement keyword AND that keyword
# is followed by the structure the statement requires. The first version of this
# rule matched on the keyword alone, and immediately fired on a docstring
# beginning "Insert (or replace) the rule_type snooze row." -- English prose that
# happens to start with a verb SQLite also uses. A guard that reports correct
# code as a defect is a guard somebody switches off.
LOOKS_LIKE_SQL = re.compile(
    r"^\s*(?:--[^\n]*\n|\s)*"
    r"(?:"
    r"SELECT\b[\s\S]*?\bFROM\b"
    r"|INSERT\s+(?:OR\s+\w+\s+)?INTO\b"
    r"|REPLACE\s+INTO\b"
    r"|UPDATE\b[\s\S]*?\bSET\b"
    r"|DELETE\s+FROM\b"
    r"|CREATE\s+(?:UNIQUE\s+)?(?:TABLE|INDEX|VIEW|TRIGGER)\b"
    r"|DROP\s+(?:TABLE|INDEX|VIEW|TRIGGER)\b"
    r"|ALTER\s+TABLE\b"
    r"|WITH\b[\s\S]*?\bAS\s*\("
    r"|PRAGMA\s+\w+"
    r"|BEGIN\s+(?:IMMEDIATE|DEFERRED|EXCLUSIVE|TRANSACTION)\b"
    r")",
    re.IGNORECASE,
)


def _sql_literals(py: Path):
    """Every string constant in a module that reads as SQL, with its line."""
    try:
        tree = ast.parse(py.read_text(encoding="utf-8"), filename=str(py))
    except SyntaxError as exc:  # pragma: no cover - a broken file is its own failure
        # ⚠️ `raise ... from` rather than `pytest.fail`. `fail()` does not
        # return, but a static analyser cannot know that, and CodeQL flagged
        # `tree` as possibly-unbound below because of it. Raising here says the
        # same thing to both a reader and an analyser.
        raise AssertionError(f"{py} does not parse: {exc}") from exc
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if LOOKS_LIKE_SQL.match(node.value):
                yield node.lineno, node.value


def test_the_scan_has_something_to_scan():
    """⛔ An empty universe scores as green.

    If this repo stopped putting SQL in string literals -- moved it to files, or
    to a query builder -- the scan below would pass while checking nothing. Fail
    loudly instead, so the rule gets rewritten rather than silently retired.
    """
    py_files = sorted(SRC.rglob("*.py"))
    assert py_files, f"no Python under {SRC}"
    total = sum(1 for f in py_files for _ in _sql_literals(f))
    assert total > 50, (
        f"only {total} SQL literals found under {SRC}. This scan is keyed on "
        f"string constants that open with a SQL statement keyword; if the SQL "
        f"moved somewhere else, this rule now covers nothing and needs "
        f"rewriting rather than deleting."
    )


def test_no_python_sql_literal_uses_replace():
    offenders = []
    for py in sorted(SRC.rglob("*.py")):
        for lineno, sql in _sql_literals(py):
            match = BANNED.search(sql)
            if match:
                offenders.append(
                    f"{py.relative_to(SRC)}:{lineno} uses {match.group(0)!r}"
                )
    assert not offenders, (
        "REPLACE cannot be gated at runtime -- SQLite reports it as a plain "
        "INSERT with no column and no delete, so the authorizer cannot tell it "
        "from a legitimate insert. It is also a DELETE in disguise: it destroys "
        "the existing row, losing every column you did not name, and fires "
        "ON DELETE CASCADE on children. Use INSERT ... ON CONFLICT DO UPDATE, "
        "which touches only the columns it names.\n  " + "\n  ".join(offenders)
    )


def test_no_migration_uses_replace():
    """Migrations are the deliberate exception to the connection rule, not to
    this one. A `REPLACE` here would rewrite operator rows during an upgrade."""
    migrations = sorted((SRC / "lynceus" / "migrations").glob("*.sql"))
    assert migrations, "no migrations found; this test would prove nothing"
    offenders = []
    for sql_file in migrations:
        text = sql_file.read_text(encoding="utf-8")
        for i, line in enumerate(text.splitlines(), 1):
            stripped = line.split("--", 1)[0]
            match = BANNED.search(stripped)
            if match:
                offenders.append(f"{sql_file.name}:{i} uses {match.group(0)!r}")
    assert not offenders, (
        "a migration uses REPLACE, which destroys the row it replaces rather "
        "than updating it:\n  " + "\n  ".join(offenders)
    )


def test_the_rule_does_not_fire_on_sqlites_replace_function():
    """⛔ The guard must stay narrow enough to survive.

    SQLite's scalar `replace(X, Y, Z)` does string substitution and is fine. A
    rule that banned the bare word would fire on it, be judged wrong, and be
    switched off -- taking the statement ban with it.
    """
    assert not BANNED.search("SELECT replace(mac, ':', '') FROM devices")
    assert not BANNED.search("UPDATE devices SET mac = REPLACE(mac, '-', ':')")
    # And it must still catch both statement spellings, in either case.
    assert BANNED.search("INSERT OR REPLACE INTO devices(mac) VALUES (?)")
    assert BANNED.search("insert or replace into devices(mac) values (?)")
    assert BANNED.search("REPLACE INTO devices(mac) VALUES (?)")
    assert BANNED.search("replace into devices(mac) values (?)")
    # Whitespace between the keywords is not fixed width.
    assert BANNED.search("INSERT  OR\n  REPLACE INTO devices(mac) VALUES (?)")


def test_prose_that_starts_like_sql_is_not_treated_as_sql():
    """🪤 The exact false positive the first version of this rule produced.

    `db.py`'s `add_rule_type_snooze` docstring opens "Insert (or replace) the
    rule_type snooze row." and goes on to name the INSERT OR REPLACE semantic.
    Matching on the opening keyword alone flagged that docstring as SQL using a
    banned statement -- a correct comment reported as a defect.
    """
    docstring = (
        "Insert (or replace) the rule_type snooze row.\n\n"
        "INSERT OR REPLACE semantic: re-snoozing a rule_type that already has "
        "an active snooze overwrites expires_at rather than failing."
    )
    assert not LOOKS_LIKE_SQL.match(docstring), (
        "a docstring is being scanned as if it were SQL"
    )
    # And a real statement still reads as SQL.
    assert LOOKS_LIKE_SQL.match("INSERT INTO devices(mac) VALUES (?)")
    assert LOOKS_LIKE_SQL.match("SELECT mac FROM devices")
    assert LOOKS_LIKE_SQL.match("UPDATE devices SET last_seen = ?")
