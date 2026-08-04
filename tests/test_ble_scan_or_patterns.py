"""Regression guard for the BlueZ AdvertisementMonitor pattern set.

⚠️ This file IS tracked. An earlier version of this line claimed "tests/ is
gitignored — these are NEVER committed", which was false: only the eleven files
named in .gitignore are excluded, and this is not one of them. Corrected rather
than left, because a reader who believes it writes rig-identifying detail into a
file that ships.

Guards the 2026-08-01 rig finding: Apple Continuity adverts are
non-connectable and carry NO Flags AD element, so a monitor keyed only on
Flags never fires for them. The bridge ran clean, logged no error, and
reported zero Apple devices forever. Back-to-back A/B on the same adapter:
Flags-only 0 devices / 0 frames over two 20s windows; with the Apple
manufacturer-data pattern 7 devices / 61 frames and 5 devices / 5 frames.

Without the manufacturer pattern the whole ble_continuity decoder is dead
code, so this test fails loudly rather than silently capturing nothing.
"""

from __future__ import annotations

from lynceus.bridges.ble import (
    _APPLE_COMPANY_BYTES,
    _FLAGS_AD_TYPE,
    _MFR_DATA_AD_TYPE,
    _ODID_PATTERN_CONTENT,
    _SERVICE_DATA_AD_TYPE,
    _or_pattern_specs,
)


def test_apple_manufacturer_pattern_is_present():
    """THE regression: without this the bridge sees zero Apple devices."""
    specs = _or_pattern_specs()
    assert (0, _MFR_DATA_AD_TYPE, _APPLE_COMPANY_BYTES) in specs


def test_apple_company_bytes_are_little_endian_004c():
    # 0x004C on the wire is 4c 00 — big-endian here matches nothing.
    assert _APPLE_COMPANY_BYTES == b"\x4c\x00"


def test_flags_patterns_are_retained():
    """Five Flags values remain; 0x00 was traded for the ODID pattern.

    See test_odid_service_data_pattern_is_present for the measurement that
    justified the trade.
    """
    specs = _or_pattern_specs()
    flags = [s for s in specs if s[1] == _FLAGS_AD_TYPE]
    assert len(flags) == 5
    assert {s[2] for s in flags} == {b"\x06", b"\x1a", b"\x02", b"\x04", b"\x05"}


def test_odid_service_data_pattern_is_present():
    """Without this the Remote-ID receiver never sees a single advert.

    An ASTM F3411 legacy advert is ONE service-data element filling all 31
    bytes of the legacy payload (transmitter-linux/bluetooth.c:171 sets
    Advertising_Data_Length = 0x1F), so it carries no Flags element and no
    manufacturer data and matches none of the other patterns. Content is
    0xFFFA little-endian plus the Open Drone ID AD application code 0x0D.
    """
    specs = _or_pattern_specs()
    assert (0, _SERVICE_DATA_AD_TYPE, b"\xfa\xff\x0d") in specs


def test_pattern_count_within_bluez_limit():
    """BlueZ drops the monitor above 7 patterns — MEASURED, not inferred.

    On-rig 2026-08-03, hci1, four arms over matched 20s windows
    (internal/tools/measure_ble_patterns.py), radio verified powered before
    and after every round:

        A shipped                7 patterns, no ODID   14 devices / 81 frames
        B shipped + ODID         8 patterns, ODID       0 devices /  0 frames
        C ODID swapped for 0x00  7 patterns, ODID      15 devices / 80 frames
        D extra Flags 0x07       8 patterns, no ODID    0 devices /  0 frames

    D is the arm that matters: 8 patterns collapse to zero with no ODID
    involved at all, so the ceiling is the COUNT and not the service-data
    pattern. C is the shipped configuration and cost nothing measurable
    against A. ⛔ Raising this number without re-measuring gives you a bridge
    that captures NOTHING and logs no error.
    """
    assert len(_or_pattern_specs()) <= 7


def test_apple_pattern_leads_the_set():
    """If the count ever has to be trimmed, Apple must not be the one cut."""
    assert _or_pattern_specs()[0] == (0, _MFR_DATA_AD_TYPE, _APPLE_COMPANY_BYTES)


def test_specs_are_start_adtype_content_triples():
    # Shape must stay OrPattern(start_position, ad_type, content)-compatible.
    for start, ad_type, content in _or_pattern_specs():
        assert start == 0
        assert isinstance(ad_type, int)
        assert isinstance(content, bytes) and content


def test_odid_pattern_content_is_derived_from_the_decoder_constants():
    """⭐ The pattern and the decoder must not be able to drift apart.

    ``bridges/ble.py`` hardcodes the match bytes ``fa ff 0d`` while
    ``ble_odid`` independently declares ODID_SERVICE_UUID and
    ODID_AD_APPLICATION_CODE. Nothing tied them, so correcting one and not the
    other leaves BlueZ matching adverts the decoder rejects, or the decoder
    waiting on adverts BlueZ never matches. Both are silent: the bridge runs,
    logs nothing, and captures zero, which is indistinguishable from "no drones
    nearby" -- the exact failure that hid 88% of drones in the first place.

    Rebuilds the pattern from the decoder's own constants and requires the
    shipped bytes to equal it.
    """
    from lynceus.ble_odid import ODID_AD_APPLICATION_CODE, ODID_SERVICE_UUID

    # "0000fffa-0000-1000-8000-00805f9b34fb" -> 0xFFFA, the 16-bit assignment.
    uuid16 = int(ODID_SERVICE_UUID[4:8], 16)
    # BLE advertises 16-bit UUIDs little-endian on the wire, then the AD
    # application code within the ASTM space.
    expected = uuid16.to_bytes(2, "little") + bytes([ODID_AD_APPLICATION_CODE])

    assert _ODID_PATTERN_CONTENT == expected, (
        f"pattern {_ODID_PATTERN_CONTENT!r} no longer matches the decoder's "
        f"UUID/AD-code constants (expected {expected!r})"
    )
    assert (0, _SERVICE_DATA_AD_TYPE, expected) in _or_pattern_specs()


def test_odid_pattern_offset_matches_the_flags_patterns_that_are_known_to_work():
    """start_position 0 means the first byte of the AD element's DATA.

    Not asserted from the BlueZ docs but from this rig: the Flags patterns are
    ``(0, 0x01, b"\\x06")`` and they demonstrably match real devices here
    (14 devices / 81 frames, measured 2026-08-03). A Flags element on the wire
    is ``02 01 06`` -- length, type, data -- so if position 0 counted the length
    or the type byte, that pattern could not match anything and the measurement
    would have been zero.

    The ODID pattern therefore expects the service-data element's data to begin
    ``FA FF 0D``, which is exactly the documented layout ``1E 16 | FA FF 0D``.
    All patterns share the offset, so they stand or fall together.
    """
    assert {spec[0] for spec in _or_pattern_specs()} == {0}
