"""Which watchlist pattern_types the operator can ALSO allowlist — pinned.

⭐ Why this file exists. `allowlist.py` claimed its pattern types covered "any
shape the watchlist alerts on", and named the consequence of that being untrue
in the very next sentence: *drift between the two surfaces silently allows an
alert to fire that an operator believed they had allowlisted.* The claim was
false when measured — the allowlist rejects `ssid_pattern`, which is one of only
three watchlist types that fire on the shipped ruleset (Finding 32).

⚠️ This does NOT assert the gap is wrong. A substring allowlist silences
everything containing the needle, which is a genuinely different power from
suppressing one SSID; whether to add one is a live decision recorded in
docs/AUDIT_REGISTER.md. What this asserts is that the gap is exactly what we
measured, so it cannot widen silently — and cannot be closed silently either.

Both directions fail:

  * a NEW watchlist pattern_type with no allowlist counterpart -> test_the_gap_...
  * the gap being CLOSED (e.g. ssid_pattern added)             -> test_the_gap_...
  * an allowlist type the watchlist cannot express             -> test_the_allowlist_...
"""

from __future__ import annotations

import re
import sqlite3
import typing

from lynceus.allowlist import AllowlistPatternType
from lynceus.db import Database

STORABLE_ALLOWLIST = frozenset(typing.get_args(AllowlistPatternType))

#: Measured 2026-08-15. Watchlist types with no allowlist counterpart, and why
#: each one is a different kind of gap.
#:
#:   ssid_pattern  LIVE on the watchlist side (the shipped `argus_ssid` rule
#:                 dispatches it) and unsuppressable by the same predicate.
#:                 The gap that actually bites an operator.
#:   imei_tac      Dead on BOTH sides — `DeviceObservation` carries no field for
#:                 it, so there is nothing to match and nothing to suppress.
#:                 Closing it here would be meaningless until capture lands.
KNOWN_GAP = frozenset({"ssid_pattern", "imei_tac"})


def _admitted_watchlist_types(tmp_path) -> set[str]:
    """Parse the live CHECK constraint, so the two sides of the comparison
    below have genuinely independent sources — a Python tuple compared against
    a copy of itself proves nothing."""
    path = str(tmp_path / "schema.db")
    Database(path).close()
    conn = sqlite3.connect(path)
    try:
        sql = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='watchlist'"
        ).fetchone()[0]
    finally:
        conn.close()
    match = re.search(
        r"pattern_type\s+TEXT[^,]*?CHECK\s*\(\s*pattern_type\s+IN\s*\(([^)]*)\)",
        sql,
        re.IGNORECASE | re.DOTALL,
    )
    assert match, f"could not find the pattern_type CHECK constraint in:\n{sql}"
    return set(re.findall(r"'([^']+)'", match.group(1)))


def test_the_gap_between_the_two_surfaces_is_exactly_what_we_measured(tmp_path):
    watchlist = _admitted_watchlist_types(tmp_path)
    # Presence floor: a regex that matched nothing would make the set
    # comparison below vacuously true.
    assert len(watchlist) >= 10, f"parsed too few watchlist types: {sorted(watchlist)}"

    gap = watchlist - STORABLE_ALLOWLIST
    assert gap == KNOWN_GAP, (
        f"the watchlist/allowlist surface gap moved. Now unsuppressable: "
        f"{sorted(gap - KNOWN_GAP)}; no longer in the gap: {sorted(KNOWN_GAP - gap)}. "
        f"A watchlist type an operator cannot allowlist means an alert they "
        f"believe they silenced still fires — measure it, then update KNOWN_GAP "
        f"and docs/AUDIT_REGISTER.md together."
    )


def test_the_allowlist_expresses_nothing_the_watchlist_cannot(tmp_path):
    """The other direction, and the one that would be a genuine bug.

    An allowlist type with no watchlist counterpart would be suppression against
    a predicate nothing can ever alert on — dead configuration the operator can
    still write.
    """
    watchlist = _admitted_watchlist_types(tmp_path)
    orphans = STORABLE_ALLOWLIST - watchlist
    assert not orphans, (
        f"allowlist pattern type(s) the watchlist cannot express: {sorted(orphans)}. "
        f"An operator can store a suppression that no alert could ever match."
    )
    # Presence beside absence: the overlap must be non-trivial, or an empty
    # STORABLE_ALLOWLIST would satisfy the assertion above.
    assert len(STORABLE_ALLOWLIST & watchlist) >= 8, (
        f"implausibly small overlap: {sorted(STORABLE_ALLOWLIST & watchlist)}"
    )


def test_the_live_half_of_the_gap_is_the_one_that_matters(tmp_path):
    """Pins WHY `ssid_pattern` is listed separately from `imei_tac`.

    `imei_tac` is dead on both sides — no `DeviceObservation` field exists, so
    no watchlist row of that type can alert and there is nothing to suppress.
    `ssid_pattern` alerts today. If `imei_tac` ever gains a capture field, this
    fails and the gap has to be re-judged rather than inherited.
    """
    from lynceus.kismet import DeviceObservation

    assert "imei_tac" not in DeviceObservation.model_fields, (
        "DeviceObservation now carries imei_tac — the capture side landed, so "
        "the imei_tac half of KNOWN_GAP is no longer harmless. Re-judge it."
    )
    # Presence beside absence: a field the observation DOES carry, so a rename
    # of model_fields cannot make the assertion above vacuously true.
    assert "ssid" in DeviceObservation.model_fields
