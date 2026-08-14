"""Every forward migration must ship a paired ``_down.sql``.

`Database.rollback_to` already anticipates the alternative and calls it what it
is -- *"that case is a packaging bug, not an operator-facing situation"* -- but
nothing stopped it happening. This closes that at CI time, where a missing file
costs one red run, instead of at rollback time on an operator's machine.

⛔ Why it is worth a test of its own, rather than being left as a comment.

When no down file is found, `rollback_to` logs a WARNING and then
**`DELETE FROM schema_migrations` anyway**, "so the rollback chain can
continue". That leaves the database **schema ahead of its stamp**: the
migration's DDL is still applied, but nothing records that it was.

On the next daemon start the runner sees an unapplied version and replays it.
For most migrations that is loud and harmless (`duplicate column name: ...`).
But **six forward migrations rebuild a table** -- 011, 013, 014, 019, 020, 021
-- because SQLite cannot ALTER a CHECK constraint, and each one's
`INSERT ... SELECT` enumerates the columns **as of its own version**. A replay
of one of those against a later schema rebuilds the table from the older column
list and silently drops everything added since.

⚠️ That combination is NOT reachable today, and this test is what keeps it that
way. Every forward migration currently has a down file, so the branch above
cannot be taken. The test makes that a checked property rather than a lucky
one -- the packaging slip and the destructive replay are the same bug, one
migration apart.

🪤 An `IRREVERSIBLE:` down file is still a down file and still passes. That
branch also removes the stamp without reverting, but it is a documented,
deliberate path the operator opts into after being told to restore from backup
-- a different question from a file simply being absent, and not one a test
should quietly re-decide.
"""

from __future__ import annotations

from lynceus import db as db_module


def _migrations_dir():
    return db_module._find_migrations_dir()


def _forward_migrations():
    """Discovered by globbing the directory, not by asking the runner.

    The runner's own enumeration is what a missing file would break, so using
    it as the source of truth here would be circular.
    """
    return sorted(
        p for p in _migrations_dir().glob("*.sql") if not p.name.endswith("_down.sql")
    )


def test_the_fixture_finds_migrations_at_all():
    """⭐ A completeness test that silently enumerated nothing would pass
    forever while checking nothing. Assert the corpus is non-empty before
    judging anything about it."""
    found = _forward_migrations()
    assert len(found) >= 20, f"only {len(found)} forward migrations discovered"


def test_every_forward_migration_has_a_paired_down_file():
    missing = [
        p.name
        for p in _forward_migrations()
        if not p.with_name(f"{p.stem}_down.sql").exists()
    ]
    assert missing == [], (
        "these forward migrations ship no _down.sql: "
        f"{missing}. rollback_to would log a WARNING and delete the "
        "schema_migrations row anyway, leaving the schema ahead of its stamp. "
        "The next start replays the migration -- and for a table-rebuild "
        "migration (011, 013, 014, 019, 020, 021) that silently drops every "
        "column added after it."
    )


def test_every_down_file_pairs_with_a_forward_migration():
    """The other direction: an orphaned down file is a rename that went half
    done, and would be applied by nothing while looking like coverage."""
    forward_stems = {p.stem for p in _forward_migrations()}
    orphans = [
        p.name
        for p in sorted(_migrations_dir().glob("*_down.sql"))
        if p.name[: -len("_down.sql")] not in forward_stems
    ]
    assert orphans == [], f"down files with no forward migration: {orphans}"


def test_down_files_are_not_empty():
    """A zero-byte down file satisfies "a paired file exists" while reverting
    nothing -- the same schema-ahead-of-stamp state by a different route, and
    one this suite's headline test could not see."""
    empty = [
        p.name for p in sorted(_migrations_dir().glob("*_down.sql")) if not p.read_text(
            encoding="utf-8"
        ).strip()
    ]
    assert empty == [], f"empty down files: {empty}"
