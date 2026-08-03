"""Regression guard for the BlueZ AdvertisementMonitor pattern set.

tests/ is gitignored — these are NEVER committed (see project memory).

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
