"""The bundled substring needles must be literal, and must not be words.

Two failure modes, both of which have already shipped.

## 1. A regex in a column that is matched literally

`ssid_pattern` and `ble_local_name` are matched with
`? LIKE '%' || pattern || '%' COLLATE NOCASE`. A stored needle of
`dji[-_].+` therefore requires an SSID that literally contains the characters
`dji[-_].+`. 32 bundled rows were cut as Python regexes — the entire drone
fleet, the forensic-extraction tools and the in-vehicle routers — and every one
of them was graded LIVE by `/watchlist` and `/healthz.json` while being unable
to match anything. No import warning fired.

⭐ That is a RECURRENCE of Finding 37 ("221 bundled OUI rows land and can never
fire"). The guard added then was keyed to the OUI column, so it reported on the
OUI column. This one is keyed on the PROPERTY — a needle for a literal matcher
must be literal — and derives its universe from
`Database.SUBSTRING_PATTERN_TYPES`, so a third substring-matched column added
tomorrow is covered the day it exists.

## 2. A stem so generic it fires on an ordinary network

The fix for (1) is to re-cut the identifiers as literal stems, and the fix for
(1) done carelessly creates (2). `magnet`, `oxygen`, `inspire`, `parrot` and
`phantom` are all dictionary words; `ibr` is three characters and occurs inside
"Fibre", "Calibri" and "library". As substrings they alert on ordinary consumer
networks — and for the people this product is built for, being told a police
forensic tool is nearby when it is a neighbour's router is not a small error.

So a bare needle must be at least `_MIN_BARE_STEM` characters and must not be a
dictionary word. Anything else is anchored to the separator the vendor actually
uses (`phantom-`), or dropped.

⚠️ EXEMPTIONS ARE CLAIMS. Each one below states the evidence for it, and the
test refuses an exemption that is not in the shipped data — so the list cannot
rot into a set of names nobody has re-checked.
"""

from __future__ import annotations

import csv
import re
from pathlib import Path

import pytest

from lynceus.db import Database

_CSV = Path(__file__).parent.parent / "src" / "lynceus" / "data" / "default_watchlist.csv"
_WORDS = Path("/usr/share/dict/american-english")

#: Characters that mean "this was written as a regex", not "this is a needle".
#: `.` is excluded deliberately: it is legal and common inside a literal
#: hostname or product string, so flagging it would be noise.
_REGEX_METACHARS = re.compile(r"[\[\]\(\)\*\+\?\{\}\|\\^$]")

#: A bare (unanchored) needle shorter than this is a substring of too many
#: ordinary names. Anchored needles are exempt because the separator carries
#: the specificity.
_MIN_BARE_STEM = 5

#: Bare needles that ARE dictionary words or short, kept anyway. Each value is
#: the evidence, not a preference.
_EXEMPT_BARE = {
    "flock": (
        "Flock Safety's own vendor name and the one bundled signature measured "
        "firing end to end through the real matcher (it is the control the "
        "post-merge hunt used to prove the others were dead). An SSID or BLE "
        "name containing 'flock' as an English word is rare enough that the "
        "measured detection is worth it."
    ),
    "mp70": (
        "Sierra Wireless MP70 model number. Four chars, but 'mp70' is not an "
        "English fragment and does not occur inside ordinary network names."
    ),
    "rv50": (
        "Sierra Wireless RV50 model number. Four chars, but 'rv50' is not an "
        "English fragment and does not occur inside ordinary network names — "
        "the same argument as mp70, stated rather than cross-referenced."
    ),
    "msab": (
        "MSAB is the vendor's four-letter name. Not an English fragment."
    ),
    "ufed": (
        "Cellebrite UFED is the product name. Four chars, not an English "
        "fragment."
    ),
}


def _load_rows() -> list[dict]:
    with _CSV.open(encoding="utf-8") as handle:
        handle.readline()  # the `# meta:` provenance line is not CSV
        return list(csv.DictReader(handle))


@pytest.fixture(scope="module")
def substring_rows() -> dict[str, list[str]]:
    rows = _load_rows()
    types = Database.SUBSTRING_PATTERN_TYPES
    out: dict[str, list[str]] = {t: [] for t in types}
    for row in rows:
        if row["identifier_type"] in types:
            out[row["identifier_type"]].append(row["identifier"])
    return out


def test_the_sweep_has_something_to_sweep(substring_rows):
    """A derived universe that quietly became empty passes every case below."""
    assert Database.SUBSTRING_PATTERN_TYPES, "no substring pattern types declared"
    for pattern_type, needles in substring_rows.items():
        assert needles, f"{pattern_type} contributed no bundled rows; sweep is vacuous"


def test_no_bundled_needle_is_regex_shaped(substring_rows):
    """The Finding 37 recurrence. A needle for a literal matcher must be literal."""
    offenders = [
        (pattern_type, needle)
        for pattern_type, needles in substring_rows.items()
        for needle in needles
        if _REGEX_METACHARS.search(needle)
    ]
    assert not offenders, (
        "regex-shaped identifiers in a column matched by LIKE substring — these "
        "rows can never fire, and /watchlist and /healthz.json will grade them "
        "LIVE anyway:\n" + "\n".join(f"  {t}: {n!r}" for t, n in offenders)
    )


@pytest.mark.skipif(not _WORDS.exists(), reason="no system dictionary to check against")
def test_no_bare_needle_is_a_dictionary_word(substring_rows):
    """A bare English word as a substring needle alerts on ordinary networks."""
    words = {w.strip().lower() for w in _WORDS.read_text(errors="ignore").splitlines()}
    offenders = []
    for pattern_type, needles in substring_rows.items():
        for needle in needles:
            bare = needle.lower()
            if bare.endswith(("-", "_")) or " " in bare:
                continue  # anchored, or a multi-word product string
            if bare in _EXEMPT_BARE:
                continue
            if bare in words:
                offenders.append((pattern_type, needle))
    assert not offenders, (
        "bare dictionary words shipped as substring needles — each of these "
        "alerts on an ordinary network name. Anchor it to the separator the "
        "vendor uses, drop it, or add it to _EXEMPT_BARE WITH THE EVIDENCE:\n"
        + "\n".join(f"  {t}: {n!r}" for t, n in offenders)
    )


def test_no_bare_needle_is_too_short(substring_rows):
    offenders = []
    for pattern_type, needles in substring_rows.items():
        for needle in needles:
            bare = needle.lower()
            if bare.endswith(("-", "_")) or " " in bare:
                continue
            if bare in _EXEMPT_BARE:
                continue
            if len(bare) < _MIN_BARE_STEM:
                offenders.append((pattern_type, needle))
    assert not offenders, (
        f"bare needles shorter than {_MIN_BARE_STEM} chars:\n"
        + "\n".join(f"  {t}: {n!r}" for t, n in offenders)
    )


def test_every_exemption_is_still_in_the_shipped_data(substring_rows):
    """⛔ An exemption is a claim about a row. When the row goes, the claim has
    to go with it, or the list rots into names nobody has re-checked and the
    next person reads a stale justification as a reviewed one."""
    shipped = {n.lower() for needles in substring_rows.values() for n in needles}
    stale = sorted(set(_EXEMPT_BARE) - shipped)
    assert not stale, (
        f"exemptions for identifiers that are no longer bundled: {stale}. "
        "Remove them rather than leaving a reason attached to nothing."
    )


def test_every_exemption_states_a_reason(substring_rows):
    for needle, reason in _EXEMPT_BARE.items():
        assert len(reason) > 60, f"{needle!r}'s exemption is not an argument: {reason!r}"


def test_the_guard_can_actually_fail():
    """⭐ The guard applied to a planted corpus, because a data-driven test
    whose data happens to be clean is indistinguishable from one that cannot
    fail. Kept in-process rather than mutating the shipped CSV."""
    words = {"phantom", "magnet"}
    planted = ["dji[-_].+", "phantom", "ibr", "cradlepoint", "dji-"]
    assert [n for n in planted if _REGEX_METACHARS.search(n)] == ["dji[-_].+"]
    bare = [n for n in planted if not n.endswith(("-", "_"))]
    assert [n for n in bare if n in words] == ["phantom"]
    assert [n for n in bare if len(n) < _MIN_BARE_STEM] == ["ibr"]
