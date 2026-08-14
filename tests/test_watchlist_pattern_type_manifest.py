"""The watchlist pattern-type manifest must match the schema that admits them.

⭐ Why this file exists. `Database._WATCHLIST_PATTERN_TYPES` is a hand-maintained
tuple that has to agree with the `pattern_type` CHECK constraint on the
`watchlist` table. Nothing enforced that, and it drifted twice: migration 019
added `ssid_pattern`, migration 021 added `imei_tac`, and the tuple stayed at
eight.

**The drift is silent in the direction that matters.**
`Database.watchlist_pattern_type_counts` seeds its dict from the manifest's keys
and then fills only keys it already holds, so a row whose type is missing from
the manifest is not an error and not a warning — it is counted as **zero**.
Measured before the fix, on three seeded rows of three types:

    rows actually in watchlist : 3
    sum of reported counts     : 1
    UNDER-REPORTED BY          : 2 rows

`/healthz.json` reports that sum as the watchlist total and `/settings` renders
the per-type breakdown from it, so the operator is told their watchlist holds
one entry when it holds three. In a tool whose entire job is knowing what it is
watching, that is the worst available lie: it under-states coverage, and it does
so most for the newest pattern types, which are exactly the ones an operator has
just added.

⚠️ There were **three** independently-drifted copies of this list — `db.py`,
`webui/app.py` and `cli/seed_watchlist.py`, the last still frozen at migration
001 with four entries. That is why the fix is a single definition rather than
three corrected ones: correcting three copies leaves three things to drift.

🪤 The schema is read from `sqlite_master` at runtime rather than from a second
hardcoded list, for the same reason `test_migration_replay.py` globs its
migration files instead of asking the runner: **a manifest cannot be graded
against a copy of itself.** If migration 026 adds a pattern type, this file
fails loudly and names it, instead of the count silently going wrong.
"""

from __future__ import annotations

import re

import pytest

from lynceus.cli.seed_watchlist import VALID_PATTERN_TYPES
from lynceus.db import Database
from lynceus.webui.app import _WATCHLIST_PATTERN_TYPES as WEBUI_PATTERN_TYPES

_CHECK_RE = re.compile(r"CHECK\s*\(\s*pattern_type\s+IN\s*\((.*?)\)\s*\)", re.S | re.I)


def _schema_pattern_types(db: Database) -> set[str]:
    """The pattern types the live `watchlist` CHECK constraint actually admits.

    Parsed from `sqlite_master`, not from any Python list — the whole point is
    to compare the manifest against something that is not the manifest.
    """
    row = db._conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='watchlist'"
    ).fetchone()
    assert row is not None, "no watchlist table — the schema did not migrate"
    match = _CHECK_RE.search(row[0])
    assert match is not None, (
        "could not find the pattern_type CHECK constraint in the watchlist DDL; "
        "if the constraint was restructured, fix this parser rather than "
        "deleting the test"
    )
    types = set(re.findall(r"'(\w+)'", match.group(1)))
    # Presence assertion beside the comparison: a parser that silently matched
    # nothing would make every assertion below trivially true.
    assert len(types) >= 8, f"parsed implausibly few pattern types: {sorted(types)}"
    return types


@pytest.fixture
def db(tmp_path):
    database = Database(str(tmp_path / "manifest.db"))
    try:
        yield database
    finally:
        database.close()


def test_manifest_matches_the_live_check_constraint(db):
    """The one that fails when a migration adds a type and nothing else does."""
    schema = _schema_pattern_types(db)
    manifest = set(Database._WATCHLIST_PATTERN_TYPES)

    assert manifest == schema, (
        f"Database._WATCHLIST_PATTERN_TYPES is out of sync with the watchlist "
        f"CHECK constraint.\n"
        f"  missing from the manifest: {sorted(schema - manifest)}\n"
        f"  in the manifest but not admitted by the schema: {sorted(manifest - schema)}\n"
        f"A type missing here is counted as ZERO by "
        f"watchlist_pattern_type_counts, so /healthz.json and /settings will "
        f"under-report the operator's watchlist rather than fail."
    )


def test_the_manifest_has_no_duplicates(db):
    manifest = Database._WATCHLIST_PATTERN_TYPES
    assert len(manifest) == len(set(manifest)), f"duplicate entries: {manifest}"


def test_there_is_only_one_manifest(db):
    """`webui` and the seeder must not carry their own copies.

    Both did, and both drifted — the webui copy to migration 020, the seeder's
    all the way back to 001. Comparing them to the source of truth here is what
    stops a fourth copy appearing.
    """
    assert set(WEBUI_PATTERN_TYPES) == set(Database._WATCHLIST_PATTERN_TYPES), (
        "webui/app.py is carrying its own pattern-type list again; import "
        "Database._WATCHLIST_PATTERN_TYPES instead of re-declaring it"
    )
    assert VALID_PATTERN_TYPES == set(Database._WATCHLIST_PATTERN_TYPES), (
        "cli/seed_watchlist.py is carrying its own pattern-type list again"
    )


# --- the behaviour the manifest actually drives -----------------------------


def test_every_admitted_pattern_type_is_counted(db):
    """The measured defect: a row of an unlisted type is reported as zero.

    Absence-and-presence together: the total must match, AND each type must
    appear with the right count, so a counter that returned an empty dict
    cannot satisfy this.
    """
    schema = sorted(_schema_pattern_types(db))
    for i, pattern_type in enumerate(schema):
        db._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity) VALUES (?, ?, 'high')",
            (f"seed-{i}", pattern_type),
        )
    db._conn.commit()

    real_total = db._conn.execute("SELECT COUNT(*) FROM watchlist").fetchone()[0]
    counts = db.watchlist_pattern_type_counts()

    assert real_total == len(schema)
    assert sum(counts.values()) == real_total, (
        f"watchlist holds {real_total} rows but the counts sum to "
        f"{sum(counts.values())} — rows of these types are invisible: "
        f"{sorted(set(schema) - set(counts))}"
    )
    for pattern_type in schema:
        assert counts.get(pattern_type) == 1, (
            f"{pattern_type!r} is admitted by the schema but counted as "
            f"{counts.get(pattern_type)!r}"
        )


def test_add_watchlist_accepts_every_admitted_type(db):
    """Four DB methods gate writes/filters on the manifest.

    `add_watchlist` (:2488) raises ValueError for anything not in the tuple, so
    while it was stale the sanctioned "add to watchlist" write surface **refused
    two pattern types the schema admits** — the operator action simply failed
    for `ssid_pattern` and `imei_tac`. `list_watchlist_with_metadata`,
    `list_watchlist_filtered` and `iter_watchlist_filtered` gate their filters
    the same way.
    """
    schema = sorted(_schema_pattern_types(db))
    for i, pattern_type in enumerate(schema):
        db.add_watchlist(
            pattern=f"gated-{i}",
            pattern_type=pattern_type,
            severity="high",
        )
    stored = db._conn.execute(
        "SELECT COUNT(DISTINCT pattern_type) FROM watchlist"
    ).fetchone()[0]
    assert stored == len(schema), (
        f"add_watchlist stored {stored} distinct types out of {len(schema)} admitted"
    )


def test_filter_methods_accept_every_admitted_type(db):
    """The read side: a filter on a live type must not raise."""
    for pattern_type in sorted(_schema_pattern_types(db)):
        db.list_watchlist_filtered(pattern_type=pattern_type)
        db.list_watchlist_with_metadata(filters={"pattern_type": pattern_type})


# --- an unhonoured filter must be reported, not dropped ---------------------


def _app_with_rows(tmp_path):
    from fastapi.testclient import TestClient

    from lynceus.config import Config
    from lynceus.webui.app import create_app

    config = Config(db_path=str(tmp_path / "w.db"))
    database = Database(config.db_path)
    for i, pattern_type in enumerate(sorted(set(Database._WATCHLIST_PATTERN_TYPES))):
        database.add_watchlist(
            pattern=f"row-{i}", pattern_type=pattern_type, severity="high"
        )
    return TestClient(create_app(config, database)), database


def test_an_unrecognised_pattern_type_filter_is_reported_not_dropped(tmp_path):
    """The lie this replaces: filter silently ignored, every row returned.

    Kept lenient on purpose — a 400 would break stale bookmarks and
    hand-edited URLs — so the whole guarantee rests on the page SAYING it
    ignored the filter. Presence and absence asserted together: the notice must
    appear AND the rows must still be there, so neither an empty page nor a
    silent full page can satisfy it.
    """
    client, database = _app_with_rows(tmp_path)
    try:
        r = client.get("/watchlist", params={"pattern_type": "not_a_real_type"})
        assert r.status_code == 200
        body = r.text
        assert "filter ignored" in body, (
            "an unrecognised pattern_type was dropped silently; the page is "
            "showing every row while the operator believes it is filtered"
        )
        assert "not_a_real_type" in body, "the notice must name the filter it ignored"
        # ...and the rows really are all still rendered.
        assert "row-0" in body
    finally:
        database.close()


def test_a_recognised_pattern_type_filter_shows_no_notice(tmp_path):
    """The presence assertion's partner: no false alarm on the happy path."""
    client, database = _app_with_rows(tmp_path)
    try:
        r = client.get("/watchlist", params={"pattern_type": "imei_tac"})
        assert r.status_code == 200
        assert "filter ignored" not in r.text
    finally:
        database.close()
