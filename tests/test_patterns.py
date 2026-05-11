"""Tests for the watchlist pattern normalizer (L-RULES-1, L-RULES-11).

The normalizer is the single source of truth for what canonical form lands
in ``watchlist.pattern``. The poller normalizes its observation MAC/UUID at
read time, so any write-time non-canonical form silently dead-ends in the
``db.resolve_matched_watchlist_id`` lookup.
"""

from __future__ import annotations

import logging

import pytest

from lynceus.patterns import normalize_pattern

# ------------------------------ mac normalization ----------------------------


def test_normalize_mac_uppercase_lowered():
    assert normalize_pattern("mac", "AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"


def test_normalize_mac_hyphen_separator_to_colons():
    assert normalize_pattern("mac", "aa-bb-cc-dd-ee-ff") == "aa:bb:cc:dd:ee:ff"


def test_normalize_mac_flat_hex_to_colons():
    """L-RULES-11: bare 12-hex (the IEEE distribution form for MACs)
    must coerce to canonical colon-separated form, not be rejected."""
    assert normalize_pattern("mac", "AABBCCDDEEFF") == "aa:bb:cc:dd:ee:ff"


def test_normalize_mac_cisco_dotted_to_colons():
    """Cisco IOS ``aabb.ccdd.eeff`` is a real-world copy-paste source —
    operators dropping a MAC out of an IOS show command shouldn't have
    to hand-rewrite it."""
    assert normalize_pattern("mac", "aabb.ccdd.eeff") == "aa:bb:cc:dd:ee:ff"


def test_normalize_mac_already_canonical_idempotent():
    """Idempotency guard: re-running the helper on already-canonical input
    returns the same string. This matters for the migration 010 path,
    which runs LOWER+REPLACE on every row, including ones already
    canonical."""
    canonical = "aa:bb:cc:dd:ee:ff"
    assert normalize_pattern("mac", canonical) == canonical
    assert normalize_pattern("mac", normalize_pattern("mac", canonical)) == canonical


def test_normalize_mac_mixed_separators_lowercase():
    """Defensive: ``Aa-bb:CC-dd:eE-ff`` (split-personality CSV import)
    coerces cleanly. Not a path we expect to see, but the underlying
    helper strips all separators before validating."""
    assert normalize_pattern("mac", "Aa-bb:CC-dd:eE-ff") == "aa:bb:cc:dd:ee:ff"


def test_normalize_mac_too_few_octets_rejected():
    with pytest.raises(ValueError, match="mac"):
        normalize_pattern("mac", "aa:bb:cc:dd:ee")


def test_normalize_mac_too_many_octets_rejected():
    with pytest.raises(ValueError, match="mac"):
        normalize_pattern("mac", "aa:bb:cc:dd:ee:ff:00")


def test_normalize_mac_non_hex_rejected():
    with pytest.raises(ValueError, match="mac"):
        normalize_pattern("mac", "zz:bb:cc:dd:ee:ff")


def test_normalize_mac_empty_rejected():
    with pytest.raises(ValueError, match="mac"):
        normalize_pattern("mac", "")


# ------------------------------ oui normalization ----------------------------


def test_normalize_oui_uppercase_lowered():
    assert normalize_pattern("oui", "AA:BB:CC") == "aa:bb:cc"


def test_normalize_oui_hyphen_separator_to_colons():
    assert normalize_pattern("oui", "aa-bb-cc") == "aa:bb:cc"


def test_normalize_oui_flat_hex_to_colons():
    """L-RULES-11: IEEE distributes OUIs as bare 6-hex (``001A7D``).
    Operator pasting the IEEE form should not get a ValueError."""
    assert normalize_pattern("oui", "AABBCC") == "aa:bb:cc"


def test_normalize_oui_already_canonical_idempotent():
    canonical = "aa:bb:cc"
    assert normalize_pattern("oui", canonical) == canonical


def test_normalize_oui_too_few_rejected():
    with pytest.raises(ValueError, match="oui"):
        normalize_pattern("oui", "aa:bb")


def test_normalize_oui_too_many_rejected():
    with pytest.raises(ValueError, match="oui"):
        normalize_pattern("oui", "aa:bb:cc:dd")


def test_normalize_oui_non_hex_rejected():
    with pytest.raises(ValueError, match="oui"):
        normalize_pattern("oui", "gg:hh:ii")


# ------------------------------ ble_uuid normalization -----------------------


def test_normalize_ble_uuid_uppercase_lowered():
    assert (
        normalize_pattern("ble_uuid", "0000FD6F-0000-1000-8000-00805F9B34FB")
        == "0000fd6f-0000-1000-8000-00805f9b34fb"
    )


def test_normalize_ble_uuid_no_hyphens_inserts_canonical():
    """The 32-hex dehyphenated form is what some vendor docs ship —
    the helper should reinsert hyphens at the canonical 8-4-4-4-12
    positions, not reject."""
    assert (
        normalize_pattern("ble_uuid", "0000fd6f00001000800000805f9b34fb")
        == "0000fd6f-0000-1000-8000-00805f9b34fb"
    )


def test_normalize_ble_uuid_already_canonical_idempotent():
    canonical = "0000fd6f-0000-1000-8000-00805f9b34fb"
    assert normalize_pattern("ble_uuid", canonical) == canonical


def test_normalize_ble_uuid_short_16bit_rejected():
    """Documents the deliberate non-expansion of 16-bit short UUIDs.
    Expanding ``0xfd6f`` to the full Bluetooth-base 128-bit form is a
    SEPARATE fix (the Kismet short-UUID hardware finding) and merging
    it into this helper would let two unrelated changes ride together
    on one normalization pass."""
    with pytest.raises(ValueError, match="ble_uuid"):
        normalize_pattern("ble_uuid", "0000fd6f")


def test_normalize_ble_uuid_short_32bit_rejected():
    """Same posture as the 16-bit case: 32-bit form is also a short UUID
    that the Bluetooth-base expansion fix will handle separately."""
    with pytest.raises(ValueError, match="ble_uuid"):
        normalize_pattern("ble_uuid", "0000fd6f-0000-1000")


def test_normalize_ble_uuid_non_hex_rejected():
    with pytest.raises(ValueError, match="ble_uuid"):
        normalize_pattern("ble_uuid", "zzzzfd6f-0000-1000-8000-00805f9b34fb")


# ------------------------------ ssid passthrough -----------------------------


def test_normalize_ssid_preserves_case():
    """SSIDs are case-sensitive per IEEE 802.11 — ``HomeNet`` and
    ``homenet`` are different networks. Lowering would silently break
    matching. L-RULES-10 (configurable case-insensitive SSID compare)
    is a deliberate v0.4.x deferral, not a v0.4.0 P0."""
    assert normalize_pattern("ssid", "HomeNet") == "HomeNet"
    assert normalize_pattern("ssid", "homenet") == "homenet"


def test_normalize_ssid_preserves_whitespace():
    """SSIDs can legitimately contain leading/trailing/internal
    whitespace (the spec doesn't forbid it). Stripping would change
    matching semantics."""
    assert normalize_pattern("ssid", " Home Net ") == " Home Net "


def test_normalize_ssid_preserves_unicode():
    """Tier-3 SSIDs in the wild include emoji and non-ASCII; pass-through
    must be byte-perfect."""
    assert normalize_pattern("ssid", "café-2.4") == "café-2.4"


# ------------------------------ unknown pattern_type -------------------------


def test_normalize_unknown_pattern_type_passthrough(caplog):
    """Forward-compat: a future schema addition (e.g. ``fcc_id``) must
    not raise — the helper should pass through unchanged so an older
    Lynceus installation reading a newer seed file degrades gracefully
    rather than crashing."""
    with caplog.at_level(logging.DEBUG, logger="lynceus.patterns"):
        out = normalize_pattern("fcc_id", "ABC-12345")
    assert out == "ABC-12345"
    assert any("unknown pattern_type" in r.getMessage() for r in caplog.records)


def test_normalize_unknown_pattern_type_does_not_raise():
    # No assertion target other than "no exception" — explicit guard
    # against a future refactor that defaults to raising.
    assert normalize_pattern("never_heard_of_this", "anything goes") == "anything goes"
