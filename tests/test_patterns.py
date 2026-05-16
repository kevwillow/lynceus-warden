"""Tests for the watchlist pattern normalizer (L-RULES-1, L-RULES-11).

The normalizer is the single source of truth for what canonical form lands
in ``watchlist.pattern``. The poller normalizes its observation MAC/UUID at
read time, so any write-time non-canonical form silently dead-ends in the
``db.resolve_matched_watchlist_id`` lookup.
"""

from __future__ import annotations

import logging

import pytest

from lynceus.patterns import (
    canonicalize_mac_range_pattern,
    normalize_pattern,
    parse_mac_range_pattern,
)

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


# ------------------------- mac_range parsing ---------------------------------
#
# parse_mac_range_pattern admits the two canonical CIDR shapes Argus emits
# (snapshot exported_at 2026-05-14T22:34:07Z: ~64% /28, ~35% /36) plus the
# 12 legacy bare-prefix rows the Argus engineer flagged as queued for
# upstream canonicalization. Returns (cleaned hex prefix, length in bits)
# for the watchlist columns; rejects every other shape loudly because a
# new length surfacing means an Argus wire-contract change worth raising
# on rather than silently accepting.


def test_parse_mac_range_canonical_28_round_trip():
    """Canonical /28: 'aa:bb:cc:d/28' → ('aabbccd', 28). The cleaned hex
    fits the lowercase-no-separators form stored in watchlist.mac_range_prefix."""
    prefix, length = parse_mac_range_pattern("aa:bb:cc:d/28")
    assert prefix == "aabbccd"
    assert length == 28
    assert canonicalize_mac_range_pattern(prefix, length) == "aa:bb:cc:d/28"


def test_parse_mac_range_canonical_36_round_trip():
    """Canonical /36: 'aa:bb:cc:dd:e/36' → ('aabbccdde', 36)."""
    prefix, length = parse_mac_range_pattern("aa:bb:cc:dd:e/36")
    assert prefix == "aabbccdde"
    assert length == 36
    assert canonicalize_mac_range_pattern(prefix, length) == "aa:bb:cc:dd:e/36"


def test_parse_mac_range_uppercase_input_lowercased():
    """Argus has not historically uppercased mac_range but the parser
    should be defensive — the lowercase invariant of mac_range_prefix
    matters for the future poller's prefix-match SQL."""
    prefix, length = parse_mac_range_pattern("AA:BB:CC:D/28")
    assert prefix == "aabbccd"
    assert length == 28


def test_parse_mac_range_legacy_bare_prefix_28_infers_length():
    """4-group bare-prefix 'aa:bb:cc:d' (no '/28' suffix) → /28, same
    cleaned hex as the canonical equivalent. Accepted per the
    Argus-engineer handoff (12 rows out of 22,532 in the live snapshot
    are this shape, queued for upstream canonicalization)."""
    bare_prefix, bare_length = parse_mac_range_pattern("aa:bb:cc:d")
    canonical_prefix, canonical_length = parse_mac_range_pattern("aa:bb:cc:d/28")
    assert bare_prefix == canonical_prefix == "aabbccd"
    assert bare_length == canonical_length == 28


def test_parse_mac_range_legacy_bare_prefix_36_infers_length():
    """5-group bare-prefix 'aa:bb:cc:dd:e' → /36 with same cleaned hex
    as the canonical equivalent."""
    bare_prefix, bare_length = parse_mac_range_pattern("aa:bb:cc:dd:e")
    canonical_prefix, canonical_length = parse_mac_range_pattern("aa:bb:cc:dd:e/36")
    assert bare_prefix == canonical_prefix == "aabbccdde"
    assert bare_length == canonical_length == 36


@pytest.mark.parametrize("length", [24, 32, 40, 44, 48])
def test_parse_mac_range_rejects_unsupported_length(length):
    """Only /28 and /36 emit in current Argus traffic; /24 is identifier_type
    'oui' by IEEE design (oui ↔ mac_range are disjoint). A new length
    surfacing means an Argus contract change — raise loudly rather than
    silently accept and quietly skew the partial-index population."""
    with pytest.raises(ValueError, match=r"prefix length /\d+ is not supported"):
        parse_mac_range_pattern(f"aa:bb:cc:d/{length}")


def test_parse_mac_range_rejects_non_hex_characters():
    with pytest.raises(ValueError, match="non-hex"):
        parse_mac_range_pattern("zz:bb:cc:d/28")


def test_parse_mac_range_rejects_3_groups():
    """Wrong group count: 3 colon-separated groups cannot encode /28 or /36."""
    with pytest.raises(ValueError, match="4 or 5 colon-separated groups"):
        parse_mac_range_pattern("aa:bb:c")


def test_parse_mac_range_rejects_6_groups():
    """A full 6-octet MAC (e.g. accidentally pasted into the mac_range
    column) must fail loudly, not be silently truncated."""
    with pytest.raises(ValueError, match="4 or 5 colon-separated groups"):
        parse_mac_range_pattern("aa:bb:cc:dd:ee:ff")


def test_parse_mac_range_rejects_2_nibble_last_group_on_bare_prefix():
    """Bare-prefix shape requires the last group to be exactly 1 nibble.
    A 2-nibble last group 'aa:bb:cc:dd' could be ambiguously read as an
    /32 (which Argus doesn't emit anyway) or a malformed /28. Reject."""
    with pytest.raises(ValueError, match="exactly 1 hex"):
        parse_mac_range_pattern("aa:bb:cc:dd")


def test_parse_mac_range_rejects_length_mismatch_28_declared_36_shape():
    """'aa:bb:cc:d/36' declares /36 but the 4-group shape (7 hex chars)
    implies /28 — almost certainly an Argus bug. Reject loudly."""
    with pytest.raises(ValueError, match=r"declared /36 but prefix shape implies /28"):
        parse_mac_range_pattern("aa:bb:cc:d/36")


def test_parse_mac_range_rejects_length_mismatch_36_declared_28_shape():
    """Mirror of the above: 5-group shape declared /28."""
    with pytest.raises(ValueError, match=r"declared /28 but prefix shape implies /36"):
        parse_mac_range_pattern("aa:bb:cc:dd:e/28")


def test_parse_mac_range_rejects_empty_string():
    with pytest.raises(ValueError, match="empty"):
        parse_mac_range_pattern("")


def test_parse_mac_range_rejects_non_integer_cidr_length():
    with pytest.raises(ValueError, match="CIDR length must be an integer"):
        parse_mac_range_pattern("aa:bb:cc:d/twentyeight")
