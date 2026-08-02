"""Byte-vector tests for the Apple Continuity payload decoder."""

from lynceus.ble_continuity import (
    APPLE_COMPANY_ID,
    CLASS_AIRPODS,
    CLASS_APPLE_UNKNOWN,
    CLASS_FIND_MY,
    CLASS_FIND_MY_PAIRED,
    CLASS_FIND_MY_SEPARATED,
    CLASS_NEARBY,
    classify,
    classify_manufacturer_data,
)


def _tlv(msg_type: int, body: bytes) -> bytes:
    return bytes([msg_type, len(body)]) + body


def test_non_apple_company_id_returns_none():
    assert classify(0x0075, _tlv(0x12, b"\x00")) is None


def test_find_my_type_byte_classifies():
    assert classify(APPLE_COMPANY_ID, _tlv(0x12, b"\x00")) == CLASS_FIND_MY


def test_proximity_pairing_is_airpods():
    assert classify(APPLE_COMPANY_ID, _tlv(0x07, b"\x01\x02")) == CLASS_AIRPODS


def test_nearby_is_nearby():
    assert classify(APPLE_COMPANY_ID, _tlv(0x10, b"\x05")) == CLASS_NEARBY


def test_unknown_message_type_is_apple_unknown():
    assert classify(APPLE_COMPANY_ID, _tlv(0x0C, b"\xaa")) == CLASS_APPLE_UNKNOWN


def test_multi_tlv_find_my_outranks_nearby():
    payload = _tlv(0x10, b"\x05") + _tlv(0x12, b"\x00")
    assert classify(APPLE_COMPANY_ID, payload) == CLASS_FIND_MY


def test_empty_payload_returns_none():
    assert classify(APPLE_COMPANY_ID, b"") is None


def test_single_stray_byte_returns_none():
    assert classify(APPLE_COMPANY_ID, b"\x12") is None


def test_truncated_body_stops_without_raising():
    # Declares a 9-byte body but supplies 2 — must not raise, must not
    # invent a class from the partial parse.
    assert classify(APPLE_COMPANY_ID, b"\x12\x09\x00\x01") is None


def test_truncated_tail_keeps_earlier_valid_message():
    payload = _tlv(0x07, b"\x01") + b"\x12\x09\x00"
    assert classify(APPLE_COMPANY_ID, payload) == CLASS_AIRPODS


def test_zero_length_body_is_tolerated():
    assert classify(APPLE_COMPANY_ID, _tlv(0x12, b"")) == CLASS_FIND_MY


def test_classify_manufacturer_data_picks_highest_priority():
    data = {0x0075: b"\xff", APPLE_COMPANY_ID: _tlv(0x12, b"\x00")}
    assert classify_manufacturer_data(data) == CLASS_FIND_MY


def test_classify_manufacturer_data_empty_and_none():
    assert classify_manufacturer_data({}) is None
    assert classify_manufacturer_data(None) is None


def test_classify_manufacturer_data_tolerates_non_mapping():
    # The bridge's existing call sites accept tuples of company ids; a
    # non-mapping must degrade to None rather than raise.
    assert classify_manufacturer_data((0x004C, 0x0075)) is None


# --- separated state: length-based, three-valued (2026-08-01 rig capture) ---
#
# Byte shapes below are the real captured forms from the 2026-08-01 Parrot-rig
# passive capture (490 Apple TLVs, 0 structure failures), NOT payloads authored
# to satisfy this decoder. The prior _FIND_MY_SEPARATED_MASK = 0x04 survived
# precisely because it was only ever tested against self-constructed bytes.

_FIND_MY_STATUS_BYTES_OBSERVED = (0x00, 0x21, 0x23, 0x28, 0x29, 0xA0, 0xA2, 0xAA)


def _find_my_long(status: int = 0x00) -> bytes:
    """0x12 len=0x19 — status + 24 bytes of rotating EC public key material."""
    return _tlv(0x12, bytes([status]) + bytes(24))


def _find_my_short(status: int = 0x00) -> bytes:
    """0x12 len=0x02 — status + hint, no key material."""
    return _tlv(0x12, bytes([status, 0x00]))


def test_long_form_find_my_is_separated():
    assert classify(APPLE_COMPANY_ID, _find_my_long()) == CLASS_FIND_MY_SEPARATED


def test_short_form_find_my_is_paired():
    assert classify(APPLE_COMPANY_ID, _find_my_short()) == CLASS_FIND_MY_PAIRED


def test_unseen_body_length_is_unqualified_not_paired():
    """Unknown separation must never collapse into the benign value."""
    assert classify(APPLE_COMPANY_ID, _tlv(0x12, b"\x00\x00\x00")) == CLASS_FIND_MY


def test_separation_is_length_driven_not_status_driven():
    """THE regression: every observed status byte, both forms.

    The retired 0x04 mask was never set in any of these — a status-bit
    branch reports the same class for both forms and is therefore wrong.
    """
    for status in _FIND_MY_STATUS_BYTES_OBSERVED:
        assert classify(APPLE_COMPANY_ID, _find_my_long(status)) == CLASS_FIND_MY_SEPARATED
        assert classify(APPLE_COMPANY_ID, _find_my_short(status)) == CLASS_FIND_MY_PAIRED


def test_status_bit_0x04_does_not_decide_separation():
    """0x04 was never set across 204 captured frames; it must not be load-bearing."""
    assert classify(APPLE_COMPANY_ID, _find_my_short(0x04)) == CLASS_FIND_MY_PAIRED
    assert classify(APPLE_COMPANY_ID, _find_my_long(0x00)) == CLASS_FIND_MY_SEPARATED


def test_airpods_long_form_is_not_find_my_separated():
    """0x07 is also len=0x19 — length must only discriminate WITHIN type 0x12."""
    body = bytes([0x01, 0x24, 0x20, 0x13, 0xAA, 0xB3, 0x05, 0x00, 0x00]) + bytes(16)
    assert len(body) == 0x19
    assert classify(APPLE_COMPANY_ID, _tlv(0x07, body)) == CLASS_AIRPODS


def test_nearby_observed_shape_still_nearby():
    """0x10 always len=0x05: flags, state, 3-byte auth tag."""
    assert classify(APPLE_COMPANY_ID, _tlv(0x10, b"\x3a\x1c\x11\x22\x33")) == CLASS_NEARBY


def test_separated_outranks_paired_in_multi_message_advert():
    payload = _find_my_short() + _find_my_long()
    assert classify(APPLE_COMPANY_ID, payload) == CLASS_FIND_MY_SEPARATED


def test_unknown_separation_outranks_paired():
    payload = _find_my_short() + _tlv(0x12, b"\x00\x00\x00")
    assert classify(APPLE_COMPANY_ID, payload) == CLASS_FIND_MY


def test_paired_outranks_airpods():
    payload = _tlv(0x07, b"\x01") + _find_my_short()
    assert classify(APPLE_COMPANY_ID, payload) == CLASS_FIND_MY_PAIRED


def test_retired_mask_constant_is_gone():
    """Fails if the unvalidated status-bit mask is ever reintroduced."""
    import lynceus.ble_continuity as mod

    assert not hasattr(mod, "_FIND_MY_SEPARATED_MASK")
