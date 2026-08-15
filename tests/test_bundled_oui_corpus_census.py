"""The bundled OUI corpus, censused — so Finding 37's numbers cannot rot the way
the ones they replaced did.

⭐ Why this file exists, and it is not arithmetic. `import_argus.py` justified its
placeholder-skip branch with *"~40 rows in the bundled default_watchlist.csv, all
CCTV vendors"*. The corpus was re-exported at some point; that count silently
became **zero**. Nothing failed, so the claim survived long enough to be copied
verbatim into `db.py`'s new write-time refusal on 2026-08-15 — by a reader who
had every reason to trust it.

⛔ A register entry recording "221 of 444 rows are inert" is the NEXT "~40 rows"
unless something fails when the data moves under it. That is what this file is.

Both directions fail, and both are useful:

  * the corpus is re-exported and the census shifts -> re-measure, update
    docs/AUDIT_REGISTER.md Finding 37 and the two code comments that cite it
  * someone FIXES the upstream data or adds an importer filter -> the finding is
    closing, which the register should say rather than discover later

⚠️ This does NOT assert that 221 inert rows are acceptable. That is Kev's
decision (register item 9) — dropping them changes the shipped corpus and the
`/watchlist` count every operator already sees.
"""

from __future__ import annotations

import csv
import sqlite3
from pathlib import Path

import pytest

from lynceus.db import Database
from lynceus.kismet import DeviceObservation
from lynceus.rules import Rule, Ruleset, _is_reserved_oui_mac, evaluate

REPO_ROOT = Path(__file__).resolve().parents[1]
BUNDLED_CSV = REPO_ROOT / "src" / "lynceus" / "data" / "default_watchlist.csv"

# Measured 2026-08-15 on schema_version=31, exported 2026-06-03.
# See docs/AUDIT_REGISTER.md, Finding 37.
EXPECTED_OUI_ROWS = 444
EXPECTED_INERT = 221
EXPECTED_CAN_FIRE = 223
EXPECTED_EXACT_PLACEHOLDER = 0

#: Sanity floor for the whole file. A truncated or missing CSV would otherwise
#: make every count below trivially "match" at zero.
MIN_PLAUSIBLE_ROWS = 40_000


def _rows() -> list[dict[str, str]]:
    """Parse the bundled CSV, locating columns BY NAME.

    🪤 The first line is a ``# meta:`` comment, so ``csv.reader``'s row 0 is NOT
    the header. The 221 figure was nearly published off a guessed column index
    that happened to be right; this is the fix for that class of near-miss.
    """
    with BUNDLED_CSV.open(newline="", encoding="utf-8") as fh:
        raw = list(csv.reader(fh))
    header_idx = next(
        (i for i, row in enumerate(raw[:5]) if "identifier" in row and "identifier_type" in row),
        None,
    )
    assert header_idx is not None, (
        "could not find a header row carrying 'identifier' and 'identifier_type' "
        f"in the first 5 lines of {BUNDLED_CSV}; the export format changed"
    )
    header = raw[header_idx]
    return [
        dict(zip(header, row, strict=True))
        for row in raw[header_idx + 1 :]
        if len(row) == len(header)
    ]


def _oui_identifiers() -> list[str]:
    return [r["identifier"] for r in _rows() if r["identifier_type"] == "oui"]


def test_the_parser_actually_found_the_corpus():
    """The presence floor. Every count below is vacuous without it."""
    rows = _rows()
    assert len(rows) >= MIN_PLAUSIBLE_ROWS, (
        f"only parsed {len(rows)} rows from {BUNDLED_CSV.name}; expected at least "
        f"{MIN_PLAUSIBLE_ROWS}. The file is truncated, missing, or its format changed — "
        "fix the instrument before believing any census."
    )


def test_the_classifier_still_behaves_as_the_census_assumes():
    """Independent anchor for the thing doing the classifying.

    If `_is_reserved_oui_mac` ever answered the same way for everything, the
    census would still produce a number and it would mean nothing.
    """
    assert _is_reserved_oui_mac("de:ad:be:00:00:00")[0] is True, (
        "a known locally-administered prefix stopped being flagged"
    )
    assert _is_reserved_oui_mac("ac:de:48:00:00:00")[0] is False, (
        "a genuine universally-administered OUI is now flagged as reserved"
    )


def test_the_bundled_oui_census_matches_the_register():
    """Finding 37's numbers, derived rather than trusted.

    ⚠️ When this fails it is usually NOT a bug — it means the corpus moved. Go
    re-measure, then update docs/AUDIT_REGISTER.md Finding 37 *and* the comments
    in `db.py` (the oui refusal) and `import_argus.py` (the placeholder skip),
    both of which cite these figures. Updating one and not the others is how the
    number this test exists to protect went wrong in the first place.
    """
    ouis = _oui_identifiers()
    inert = [o for o in ouis if _is_reserved_oui_mac(f"{o.lower()}:00:00:00")[0]]
    can_fire = [o for o in ouis if not _is_reserved_oui_mac(f"{o.lower()}:00:00:00")[0]]

    assert (len(ouis), len(inert), len(can_fire)) == (
        EXPECTED_OUI_ROWS,
        EXPECTED_INERT,
        EXPECTED_CAN_FIRE,
    ), (
        f"bundled OUI census moved: {len(ouis)} rows "
        f"({len(inert)} inert / {len(can_fire)} can fire), register records "
        f"{EXPECTED_OUI_ROWS} ({EXPECTED_INERT} / {EXPECTED_CAN_FIRE})"
    )
    # The two parts must still sum to the whole -- a classifier that returned
    # None for everything would otherwise satisfy both counts independently.
    assert len(inert) + len(can_fire) == len(ouis)


def test_no_exact_placeholder_rows_remain_in_the_bundled_corpus():
    """The claim that was wrong for releases, now pinned.

    `import_argus.py`'s placeholder skip matches `pattern == "00:00:00"` exactly.
    It is justified by rows that are not in this snapshot, so it drops nothing
    from the bundled data and `dropped_placeholder_oui` is always 0 for it.

    ⚠️ Keeping the branch is still correct — an operator-supplied CSV can carry
    placeholder rows. This pins only that the BUNDLED justification is absent.
    """
    placeholders = [r for r in _rows() if r["identifier"].strip() == "00:00:00"]
    assert len(placeholders) == EXPECTED_EXACT_PLACEHOLDER, (
        f"{len(placeholders)} row(s) with identifier == '00:00:00' are now in the "
        f"bundled corpus (register records {EXPECTED_EXACT_PLACEHOLDER}). If the "
        "upstream export brought them back, `import_argus.py`'s placeholder skip "
        "is load-bearing again — say so in Finding 37 rather than leaving it "
        "described as inert."
    )


# --- the behavioural half: are the "inert" rows actually inert? --------------


def _observation(mac: str) -> DeviceObservation:
    return DeviceObservation(
        mac=mac,
        device_type="wifi",
        first_seen=1_700_000_000,
        last_seen=1_700_000_000,
        rssi=-40,
        ssid=None,
        oui_vendor=None,
        is_randomized=False,
    )


def _delegating_oui_ruleset() -> Ruleset:
    """`watchlist_oui` with empty patterns delegates to the DB. Enabled here so
    the ruleset is not the variable — the shipped one has it commented out."""
    return Ruleset(
        rules=[Rule(name="argus_oui", rule_type="watchlist_oui", severity="low", patterns=[])]
    )


def _insert_oui_row_like_the_importer(db_path: str, pattern: str) -> None:
    """The importer writes watchlist rows with DIRECT SQL, bypassing
    `add_watchlist`. Since #86 that is the ONLY path that can still create an
    inert OUI row — the operator-facing one now refuses. Driving the real
    bypass is the point; using `add_watchlist` here would raise and prove
    nothing about the bundled data."""
    conn = sqlite3.connect(db_path)
    try:
        with conn:
            conn.execute(
                "INSERT INTO watchlist (pattern, pattern_type, severity, description) "
                "VALUES (?, ?, 'high', 'bundled-corpus row')",
                (pattern, "oui"),
            )
    finally:
        conn.close()


@pytest.mark.parametrize("inert_prefix", ["02:00:00", "62:60:1f", "0a:2a:33"])
def test_an_inert_bundled_prefix_produces_no_alert(inert_prefix, tmp_path):
    """Behaviour, not arithmetic. These prefixes are real rows in the shipped
    corpus; a device on one of them must produce nothing."""
    assert inert_prefix in _oui_identifiers(), (
        f"{inert_prefix!r} is no longer in the bundled corpus; pick another inert "
        "row from the census or the case is testing nothing"
    )
    db_path = str(tmp_path / f"{inert_prefix.replace(':', '')}.db")
    db = Database(db_path)
    try:
        _insert_oui_row_like_the_importer(db_path, inert_prefix)
        hits = evaluate(
            _delegating_oui_ruleset(),
            _observation(f"{inert_prefix}:11:22:33"),
            False,
            db=db,
        )
    finally:
        db.close()
    assert hits == [], (
        f"a device on bundled OUI {inert_prefix!r} now alerts ({hits}). If the "
        "reserved-OUI guard changed, Finding 37 is closing — re-measure and say so."
    )


def test_a_bundled_prefix_that_CAN_fire_actually_does(tmp_path):
    """⚠️ The control, and the assertion that stops all of this being vacuous.

    Without it, "no alert" above is satisfied by a delegation path that alerts on
    nothing at all — a broken control fabricates a confident finding, which is
    how three invalid results were produced in one morning on this project.
    """
    can_fire = [
        o for o in _oui_identifiers() if not _is_reserved_oui_mac(f"{o.lower()}:00:00:00")[0]
    ]
    assert can_fire, "no can-fire bundled OUI to use as a control"
    prefix = sorted(can_fire)[0].lower()

    db_path = str(tmp_path / "control.db")
    db = Database(db_path)
    try:
        _insert_oui_row_like_the_importer(db_path, prefix)
        hits = evaluate(
            _delegating_oui_ruleset(), _observation(f"{prefix}:11:22:33"), False, db=db
        )
    finally:
        db.close()
    assert [h.rule_name for h in hits] == ["argus_oui"], (
        f"the control bundled OUI {prefix!r} produced no alert either, so the "
        f"absence assertions above are measuring a dead pipeline, not inert data"
    )
