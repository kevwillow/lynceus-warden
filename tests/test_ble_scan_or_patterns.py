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
    """The Apple pattern is additive — non-Apple BLE capture must not regress."""
    specs = _or_pattern_specs()
    flags = [s for s in specs if s[1] == _FLAGS_AD_TYPE]
    assert len(flags) == 6
    assert {s[2] for s in flags} == {b"\x06", b"\x1a", b"\x02", b"\x04", b"\x05", b"\x00"}


def test_pattern_count_within_bluez_limit():
    """BlueZ silently drops the monitor above ~7 patterns — we sit exactly at 7."""
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
