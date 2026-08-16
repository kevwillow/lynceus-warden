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
from collections import Counter
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
    data = raw[header_idx + 1 :]
    kept = [row for row in data if len(row) == len(header)]
    # ⛔ Do not let the instrument silently discard what it is supposed to count.
    # A cold read caught this: the width filter existed to avoid a ragged-row
    # crash, but a malformed re-export would have lost rows QUIETLY, and the
    # 40,000-row floor below only catches wholesale truncation, never selective
    # loss. A census that drops its own inputs reports a clean number about a
    # corpus it did not fully read.
    dropped = len(data) - len(kept)
    assert dropped == 0, (
        f"{dropped} of {len(data)} rows in {BUNDLED_CSV.name} do not have the "
        f"header's {len(header)} columns and were about to be silently skipped. "
        "Re-export or repair the corpus; do not widen this filter."
    )
    return [dict(zip(header, row, strict=True)) for row in kept]


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

    ⛔ The control prefix is NAMED, not selected at runtime. It used to be
    `sorted(can_fire)[0]`, which a cold read flagged: a corpus re-export could
    silently change which prefix this test exercises, so the case would drift
    without anyone reviewing it — and a regression breaking every OUI except the
    alphabetically-first one would still pass.
    """
    prefix = "00:04:7d"  # Motorola Solutions, police_radio — globally administered
    assert prefix in [o.lower() for o in _oui_identifiers()], (
        f"the named control prefix {prefix!r} is no longer in the bundled corpus; "
        "pick another globally-administered row and name it here explicitly"
    )
    assert not _is_reserved_oui_mac(f"{prefix}:00:00:00")[0], (
        f"the control prefix {prefix!r} is now classified reserved, so it can no "
        "longer serve as the can-fire control"
    )

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


# ---------------------------------------------------------------------------
# The other number in import_argus.py that nothing was holding still.
# ---------------------------------------------------------------------------
#
# `NON_RF_IDENTIFIER_TYPES`'s comment states: "The bundled snapshot is ~43% such
# rows (17,952 of 41,508 at schema_version=31)". Re-measured 2026-08-16 against
# the shipped CSV and exact on every figure -- so this is a guard against future
# rot, not a correction.
#
# ⭐ The second test below is the one that matters, and the source comment says
# so itself: "An Argus release that adds a genuinely RF-observable identifier
# type Lynceus has not mapped would otherwise land in the same silent bucket and
# quietly shrink detection coverage with no operator-visible signal."
#
# There IS a runtime WARNING for that case, but it fires during an import an
# operator may never read, and the bundled snapshot ships WITH the product --
# so a re-export carrying a new type would reach every install having produced
# no signal anybody saw. This fails in CI instead.

EXPECTED_TOTAL_ROWS = 41_508
EXPECTED_NON_RF_ROWS = 17_952
EXPECTED_MAPPED_ROWS = 23_556


def _identifier_types() -> Counter[str]:
    return Counter((r["identifier_type"] or "").strip().lower() for r in _rows())


def test_the_non_rf_share_of_the_bundled_corpus_still_matches_the_comment():
    """Pins the "~43% (17,952 of 41,508)" figure in import_argus.py.

    Fails in BOTH directions on a re-export: update the comment and this
    block together, or discover later that a sentence stopped being true.
    """
    from lynceus.cli.import_argus import IDENTIFIER_TYPE_MAP, NON_RF_IDENTIFIER_TYPES

    types = _identifier_types()
    total = sum(types.values())
    non_rf = sum(n for t, n in types.items() if t in NON_RF_IDENTIFIER_TYPES)
    mapped = sum(n for t, n in types.items() if t in IDENTIFIER_TYPE_MAP)

    assert (total, non_rf, mapped) == (
        EXPECTED_TOTAL_ROWS,
        EXPECTED_NON_RF_ROWS,
        EXPECTED_MAPPED_ROWS,
    ), (
        f"bundled corpus census moved: total={total} non_rf={non_rf} "
        f"mapped={mapped}. Re-measure, then update BOTH these constants and "
        f"the '~43% such rows' comment in import_argus.py's "
        f"NON_RF_IDENTIFIER_TYPES block."
    )


def test_every_bundled_identifier_type_is_mapped_or_recorded_as_non_rf():
    """No shipped row may land in the silent bucket.

    A type that is neither in `IDENTIFIER_TYPE_MAP` nor in
    `NON_RF_IDENTIFIER_TYPES` is dropped as `unknown_type`. For a type Argus
    added that IS observable over the air, that is detection coverage lost
    with the only signal a WARNING during an import nobody watches.

    ⚠️ The failure is not "add it to the non-RF set to make this pass". Decide
    which it is: a matcher in `IDENTIFIER_TYPE_MAP` if Lynceus can see it, an
    entry in `NON_RF_IDENTIFIER_TYPES` if it genuinely cannot -- the two are
    held disjoint by `test_non_rf_set_and_identifier_map_are_disjoint`.
    """
    from lynceus.cli.import_argus import IDENTIFIER_TYPE_MAP, NON_RF_IDENTIFIER_TYPES

    types = _identifier_types()
    unclassified = {
        t: n
        for t, n in types.items()
        if t not in IDENTIFIER_TYPE_MAP and t not in NON_RF_IDENTIFIER_TYPES
    }
    assert unclassified == {}, (
        f"identifier types in the bundled corpus that are neither matched nor "
        f"recorded as non-RF, so they import as 'unknown_type' drops: "
        f"{unclassified}"
    )
