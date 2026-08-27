"""The BLE manufacturer-id chain, pinned end to end.

`kismet.py` carries an UNVERIFIED caveat on `_BLE_MANUFACTURER_ID_PATHS`, and
that caveat is true: extracting a company id from a *Kismet* record is not
proven against a live capture. It was then repeated as though it applied to the
rule as a whole, which is wrong, and the difference decides whether an operator
believes the Bluetooth rule can fire at all.

⭐ The BLE BRIDGE does not use those paths. `bleak` hands it manufacturer data
as `{company_id: payload}` directly, and that route is already proven on real
hardware: Apple Continuity *is* manufacturer data under company id 0x004C, and
a genuine `find_my_separated` advert produced an alert on 2026-08-20 (README).

What was never pinned is the join between the two halves: the bridge emits a
canonical 4-hex lower-case company id, while Argus ships the same identifier as
`0x004C`, `0x4C` and `0x09C8`. If the importer did not canonicalise, the rule
would match nothing with a tracker sitting on the desk, and no amount of
waiting would reveal it.

⚠️ Drones are NOT covered by this argument. `ble_odid` decodes Open Drone ID
service data and is tested against the ASTM spec, but no real drone has been
captured, so `drone_id_prefix` stays genuinely unproven end to end. The claim
narrowed here is about manufacturer ids only.
"""

from __future__ import annotations

import pytest

from lynceus.bridges.ble import BleBridge
from lynceus.patterns import normalize_pattern

APPLE = 0x004C


def test_the_bridge_emits_canonical_four_hex_lowercase():
    assert BleBridge._select_manufacturer_id((APPLE,)) == "004c"


@pytest.mark.parametrize(
    ("argus_spelling", "expected"),
    [
        ("0x004C", "004c"),  # the common shipped form
        ("0x4C", "004c"),    # short form, also present in the corpus
        ("0x09C8", "09c8"),
        ("004C", "004c"),    # no 0x prefix
    ],
)
def test_the_importer_canonicalises_every_shipped_spelling(argus_spelling, expected):
    """⛔ The join. The corpus spells one company id at least three ways."""
    assert normalize_pattern("ble_manufacturer_id", argus_spelling) == expected


def test_bridge_output_and_imported_pattern_meet(tmp_path):
    """The whole chain, through the real database lookup.

    bleak company id -> bridge -> stored watchlist pattern -> resolve -> match.
    Each half is exercised elsewhere; nothing pinned that they agree, and a
    mismatch here is invisible in every unit test on either side of the join.
    """
    from lynceus.db import Database

    db = Database(str(tmp_path / "chain.db"))
    db.ensure_location("default", "Default")
    try:
        stored = normalize_pattern("ble_manufacturer_id", "0x004C")
        db.add_watchlist(pattern=stored, pattern_type="ble_manufacturer_id", severity="high")

        emitted = BleBridge._select_manufacturer_id((APPLE,))
        matched = db.resolve_matched_watchlist_id(
            mac="aa:bb:cc:dd:ee:ff", ble_manufacturer_id=emitted
        )
        assert matched is not None, (
            f"the bridge emits {emitted!r} and the importer stores {stored!r}; "
            f"they did not meet. With this broken the Bluetooth rule matches "
            f"nothing even with a tracker in the room, and the failure looks "
            f"exactly like 'no watchlisted device is nearby'."
        )
    finally:
        db.close()


def test_a_raw_uncanonicalised_pattern_does_NOT_match(tmp_path):
    """⚠️ The control, and the reason the test above is not vacuous.

    Writing the Argus spelling straight to the database, bypassing the
    importer, must NOT match. If it did, the canonicalisation would be doing
    nothing and the passing test above would prove nothing about the importer.
    """
    from lynceus.db import Database

    db = Database(str(tmp_path / "control.db"))
    db.ensure_location("default", "Default")
    try:
        db.add_watchlist(pattern="0x004C", pattern_type="ble_manufacturer_id", severity="high")
        matched = db.resolve_matched_watchlist_id(
            mac="aa:bb:cc:dd:ee:ff",
            ble_manufacturer_id=BleBridge._select_manufacturer_id((APPLE,)),
        )
        assert matched is None, (
            "a raw '0x004C' pattern matched the bridge's '004c'. The lookup is "
            "doing its own normalisation somewhere, so this file is not "
            "measuring what it claims to measure."
        )
    finally:
        db.close()
