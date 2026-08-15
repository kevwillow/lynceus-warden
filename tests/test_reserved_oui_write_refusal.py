"""A watchlist row that can never fire must be refused, not stored.

`rules.evaluate`'s `watchlist_oui` branch calls `_is_reserved_oui_mac` on the
OBSERVATION and drops the hit before the DB is consulted. So a watchlist row on
a reserved prefix was accepted, listed on /watchlist beside working entries, and
could never fire. Measured: `resolve_matched_oui_for_eval` FOUND the row and the
guard discarded it afterwards — the database was innocent.

⚠️ This does NOT replace that guard. `cli/import_argus.py` writes watchlist rows
with direct SQL, bypassing `add_watchlist`, and the bundled Argus snapshot
carries ~40 rows with `pattern=00:00:00` — the exact rows the guard exists for.
This closes the OPERATOR-facing paths so a person is told at once instead of
being silently ignored later.

⭐ Same principle as #84's mac_range refusal, and the same phrase from
`rules.yaml`: a watchlist that does not watch is the behaviour nobody wants.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lynceus.db import Database  # noqa: E402
from lynceus.kismet import DeviceObservation  # noqa: E402
from lynceus.rules import Rule, Ruleset, evaluate  # noqa: E402

NOW = 1_700_000_000


@pytest.fixture()
def db(tmp_path):
    d = Database(str(tmp_path / "w.db"))
    yield d
    d.close()


@pytest.mark.parametrize(
    "oui,note",
    [
        ("00:00:00", "placeholder"),
        ("ff:ff:ff", "broadcast"),
        ("01:00:5e", "IPv4 multicast"),
        ("de:ad:be", "locally administered"),
        ("aa:bb:cc", "locally administered — 0xAA has the LA bit set"),
    ],
)
def test_a_reserved_oui_is_refused_at_write(db, oui, note):
    """Every class `_is_reserved_oui_mac` drops at eval must be refused here.

    ⚠️ `aa:bb:cc` and `de:ad:be` are in this list deliberately: both LOOK like
    ordinary vendor prefixes and both have the locally-administered bit set.
    Two sessions independently picked one of them as an "ordinary" control and
    got a confident wrong answer from it.
    """
    with pytest.raises(ValueError, match="could never fire"):
        db.add_watchlist(
            pattern=oui, pattern_type="oui", severity="high", description=note
        )


@pytest.mark.parametrize("oui", ["ac:de:48", "00:13:37", "b8:27:eb"])
def test_a_globally_administered_oui_is_still_accepted(db, oui):
    """⚠️ The twin, and the one that matters most here.

    A refusal that rejected everything would pass every test above. These three
    are real, universally-administered prefixes — `00:13:37` and `b8:27:eb` are
    bundled in `THREAT_OUIS`, so rejecting them would break seeding outright.
    """
    row_id, inserted = db.add_watchlist(
        pattern=oui, pattern_type="oui", severity="high", description="x"
    )
    assert inserted and row_id > 0


def test_an_accepted_oui_actually_fires(db):
    """⭐ The point of the whole change: what we DO store must work.

    Refusing the dead rows is only half. This asserts the surviving class still
    produces an alert end to end, so "refuse everything" cannot pass.
    """
    rs = Ruleset(
        rules=[
            Rule(
                name="oui_deleg",
                rule_type="watchlist_oui",
                severity="low",
                patterns=[],
                description="d",
            )
        ]
    )
    db.add_watchlist(
        pattern="ac:de:48", pattern_type="oui", severity="high", description="x"
    )
    obs = DeviceObservation(
        mac="ac:de:48:11:22:33",
        device_type="wifi",
        first_seen=NOW,
        last_seen=NOW,
        rssi=-40,
        ssid=None,
        oui_vendor=None,
        is_randomized=False,
    )
    assert evaluate(rs, obs, is_new_device=False, db=db), (
        "a globally-administered OUI entry did not alert; the refusal has "
        "taken the working case with it"
    )


def test_the_seeder_goes_through_the_single_write_path(tmp_path):
    """⛔ `seed_watchlist._insert_entry` had its OWN 4-column INSERT.

    #84 removed the first copy of that SQL from this file after it had drifted;
    this one survived because `oui`/`ble_uuid` need no derived columns. But it
    also bypassed every validation `add_watchlist` performs — so a refusal added
    there would have been silently skipped by exactly the OUI path it targets.

    ⇒ A second writer that skips validation is the same defect as a second
    writer that skips a column.
    """
    import inspect

    from lynceus.cli import seed_watchlist

    src = inspect.getsource(seed_watchlist._insert_entry)
    assert "INSERT INTO watchlist" not in src, (
        "the seeder has its own INSERT again; it bypasses add_watchlist's "
        "validation, including the reserved-OUI refusal"
    )
    assert "add_watchlist" in src


def test_the_bundled_threat_ouis_all_seed(tmp_path):
    """The curated constants must survive the new refusal.

    ⚠️ Checked before the refusal was written, not after: a bundled constant
    that trips your own new validation is something to discover now rather than
    in CI.
    """
    from lynceus.cli.seed_watchlist import THREAT_OUIS, seed_threat_ouis

    d = Database(str(tmp_path / "s.db"))
    inserted, skipped = seed_threat_ouis(d)
    assert inserted == len(THREAT_OUIS), (
        f"only {inserted} of {len(THREAT_OUIS)} bundled threat OUIs seeded; "
        "the refusal is rejecting curated data"
    )
    assert skipped == 0
    d.close()


# ---------------------------------------------------------------------------
# The guard asks `_is_reserved_oui_mac` about a SYNTHESISED full MAC
# (`f"{pattern}:00:00:00"`), not about the bare 3-octet pattern. Nothing pinned
# that, and it is load-bearing in exactly one direction.
#
# 🪤 Found by planting it during adoption of this PR: rewriting the call to
# `_is_reserved_oui_mac(pattern)` left the whole suite GREEN. The two forms
# agree on every canonical 3-octet OUI, so the plant looked equivalent — and for
# well-formed input it is. They diverge on a SHORT pattern, because
# `_is_reserved_oui_mac` returns `(False, None)` for anything under 8 characters:
#
#     'de:ad'   bare -> False (stored!)   synthesised -> True (refused)
#
# ⇒ The bare form fails OPEN on malformed input. Since nothing upstream of
# `add_watchlist` enforces the 3-octet OUI shape — these values reach the guard
# as written — that is the difference between refusing junk and storing it.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("malformed", ["de:ad", "de", "aa:bb"])
def test_a_short_oui_pattern_is_refused_rather_than_stored(db, malformed):
    """Fail closed on a pattern too short to be an OUI.

    This is what makes the synthesised-MAC form of the check load-bearing; with
    the bare pattern these are silently accepted as watchlist rows.
    """
    with pytest.raises(ValueError):
        db.add_watchlist(
            pattern=malformed, pattern_type="oui", severity="high", description=None
        )


def test_the_check_is_asked_about_a_full_mac_not_the_bare_prefix():
    """Names the invariant directly, so the reason survives a refactor.

    Presence beside absence: the two forms MUST still agree on a well-formed
    OUI, or this test would pass for a guard that had simply become stricter
    about everything.
    """
    from lynceus.rules import _is_reserved_oui_mac

    # The divergence that makes the synthesised form necessary.
    assert _is_reserved_oui_mac("de:ad")[0] is False
    assert _is_reserved_oui_mac("de:ad:00:00:00")[0] is True

    # ...and the agreement that stops this becoming a claim about strictness.
    for well_formed in ("ac:de:48", "b8:27:eb"):
        assert (
            _is_reserved_oui_mac(well_formed)[0]
            is _is_reserved_oui_mac(f"{well_formed}:00:00:00")[0]
            is False
        )
    for reserved in ("de:ad:be", "00:00:00"):
        assert (
            _is_reserved_oui_mac(reserved)[0]
            is _is_reserved_oui_mac(f"{reserved}:00:00:00")[0]
            is True
        )
