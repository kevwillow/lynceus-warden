"""A watchlisted 16-bit BLE service UUID must actually fire.

⭐ Why this file exists. The watchlist side and the observation side
canonicalized BLE service UUIDs **differently**, and the mismatch was total and
silent.

`patterns._normalize_ble_uuid` expands 16- and 32-bit Bluetooth SIG assigned
UUIDs into the base UUID per Core Spec §3.2.1, so an operator who watchlists
`fd5a` — the form a real advertisement carries — stores
`0000fd5a-0000-1000-8000-00805f9b34fb`. `kismet.normalize_uuid` required the
full dashed 128-bit form and raised for anything shorter, and
`parse_kismet_device` caught that and dropped the UUID with a DEBUG line.

So the two sides could never meet. Measured on `origin/main`:

    watchlist stores: 0000fd5a-0000-1000-8000-00805f9b34fb
    advert ['fd5a']                                 parsed=0  ALERT=no
    advert ['0000FD5A']                             parsed=0  ALERT=no
    advert ['0000fd5a-0000-1000-8000-00805f9b34fb'] parsed=1  ALERT=YES

⚠️ **The operator gets no error and no warning** — a DEBUG line they will never
see, and a watchlist entry that sits there looking armed. For a tool whose job
is noticing trackers, a watchlist row that can never match is the worst
available failure: it reads as coverage.

⚠️ `kismet.normalize_uuid` is the chokepoint for **three** paths —
`parse_kismet_device`, `rules` pattern normalization, and `bridges/ble.py`'s
live radio capture — so the same miss applied to directly captured BLE adverts,
not only Kismet-sourced ones.

The fix is to delegate to the same public function the watchlist side uses,
rather than to reimplement the parsing. **Two sides that must agree can only be
guaranteed to agree by calling one function** — the same reasoning as the
watchlist pattern-type manifest.

🪤 Found by auditing `test_diag_d1_ble_short_uuid_drop.py`, an observation-only
diagnostic that has documented this since 2026-08-02 with no assertion able to
fail. It was right, and nothing acted on it because nothing could go red.
"""

from __future__ import annotations

import pytest

from lynceus.db import Database
from lynceus.kismet import normalize_uuid, parse_kismet_device
from lynceus.patterns import normalize_pattern

# 16-bit assigned UUID, in the shape an advertisement actually carries it.
SHORT_UUID = "fd5a"
CANONICAL = "0000fd5a-0000-1000-8000-00805f9b34fb"


@pytest.fixture
def db(tmp_path):
    database = Database(str(tmp_path / "uuid.db"))
    try:
        yield database
    finally:
        database.close()


def _observe(advertised: list[str]):
    return parse_kismet_device(
        {
            "kismet.device.base.macaddr": "aa:bb:cc:dd:ee:01",
            "kismet.device.base.type": "BTLE",
            "kismet.device.base.first_time": 1000,
            "kismet.device.base.last_time": 1000,
            "kismet.device.base.service_uuids": advertised,
        },
        capture_ble_name=True,
    )


# --- the two sides must canonicalize identically ----------------------------


@pytest.mark.parametrize(
    "advertised",
    ["fd5a", "FD5A", "0000fd5a", "0000FD5A", CANONICAL, CANONICAL.upper()],
)
def test_both_sides_canonicalize_to_the_same_string(advertised):
    """The invariant the whole file rests on, asserted directly.

    If these two ever diverge again the match becomes impossible, so this is
    the cheapest place to catch it.
    """
    assert normalize_uuid(advertised) == normalize_pattern("ble_uuid", advertised)
    assert normalize_uuid(advertised) == CANONICAL


# --- end to end: the operator's entry actually fires ------------------------


@pytest.mark.parametrize(
    "advertised", [["fd5a"], ["FD5A"], ["0000fd5a"], ["0000FD5A"], [CANONICAL]]
)
def test_a_watchlisted_short_uuid_matches_the_advertised_form(db, advertised):
    """Watchlist `fd5a`, advertise any equivalent form, expect a match."""
    db.add_watchlist(
        pattern=normalize_pattern("ble_uuid", SHORT_UUID),
        pattern_type="ble_uuid",
        severity="high",
    )

    obs = _observe(advertised)
    uuids = tuple(obs.ble_service_uuids or ())

    # Presence beside the match assertion: a parser that dropped everything
    # would make "no match" look like correct behaviour rather than the bug.
    assert uuids, f"the advertised UUID {advertised!r} was dropped before matching"
    assert uuids == (CANONICAL,)

    assert db.resolve_matched_ble_uuid_for_eval(uuids) is not None, (
        f"a watchlist entry for {SHORT_UUID!r} did not fire for an advertised "
        f"{advertised!r} — the two sides are canonicalizing differently again"
    )


# --- and genuine garbage is still rejected ----------------------------------


@pytest.mark.parametrize("bad", ["zzzz", "", "fd5", "0000fd5a-0000-1000-8000-00805f9b34"])
def test_malformed_uuids_are_still_rejected(bad):
    """The other direction. Accepting everything would also make the test above
    pass, so this is what stops the fix being 'delete the validation'."""
    with pytest.raises(ValueError):
        normalize_uuid(bad)


def test_a_malformed_uuid_is_dropped_without_killing_the_observation(db):
    """A bad UUID must not take the whole device record with it.

    Presence assertion: the observation still exists and still carries the
    good UUID alongside the dropped one.
    """
    obs = _observe(["zzzz", SHORT_UUID])
    assert obs is not None, "one malformed UUID discarded the entire device"
    assert tuple(obs.ble_service_uuids or ()) == (CANONICAL,)
