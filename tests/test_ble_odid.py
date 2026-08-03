"""Byte-vector tests for the Open Drone ID (ASTM F3411) BLE payload decoder.

Every fixture here is hand-laid from the wire layout, NOT produced by our own
encoder. A round-trip against our own encoder would prove only that the decoder
is self-consistent with itself.

The layout is verified against two independent sides of the reference
implementation, fetched 2026-08-03:

  opendroneid/transmitter-linux ``bluetooth.c:168-184``
  (``hci_le_set_advertising_data``) builds the BT4 legacy advert as::

      1F  Advertising_Data_Length (31 -- the whole legacy payload)
      1E  length of the service-data AD element (30)
      16  GAP AD type = "Service Data - 16-bit UUID"
      FA FF   0xFFFA little-endian = ASTM International, ASTM Remote ID
      0D  AD Application Code within the ASTM space = Open Drone ID
      xx  8-bit message counter, starts 0x00, wraps at 0xFF
      ..  25 bytes = ODID_MESSAGE_SIZE

  opendroneid/receiver-android ``BluetoothScanner.java:114-134`` filters on the
  same UUID and AD code, and ``OpenDroneIdParser.java:466,493-496`` reads the
  nibbles: ``type = (b & 0xF0) >> 4`` for the message type and again for the ID
  type, low nibble being protocol version / UA type respectively.

  opendroneid/opendroneid-core-c ``libopendroneid/opendroneid.h:423-437``
  gives the Basic ID body: byte 0 [MessageType][ProtoVersion], byte 1
  [IDType][UAType], bytes 2-21 UASID[20], bytes 22-24 Reserved[3]; and
  ``:123-132`` gives ODID_IDTYPE_SERIAL_NUMBER = 1.

BlueZ hands bleak the service-data value with the 16-bit UUID already stripped,
so the bytes this decoder sees start at the AD Application Code.
"""

from lynceus.ble_odid import (
    ODID_AD_APPLICATION_CODE,
    ODID_SERVICE_UUID,
    decode_serial,
    decode_service_data,
)

_MSGTYPE_BASIC_ID = 0x0
_MSGTYPE_LOCATION = 0x1
_MSGTYPE_PACKED = 0xF
_IDTYPE_SERIAL = 1
_IDTYPE_CAA_REGISTRATION = 2


def _basic_id_message(
    serial: bytes,
    *,
    id_type: int = _IDTYPE_SERIAL,
    ua_type: int = 2,
    proto_version: int = 2,
) -> bytes:
    """One 25-byte Basic ID message, laid out from opendroneid.h:423-437."""
    assert len(serial) <= 20, "UASID is ODID_ID_SIZE = 20 bytes"
    return (
        bytes([(_MSGTYPE_BASIC_ID << 4) | proto_version])
        + bytes([(id_type << 4) | ua_type])
        + serial.ljust(20, b"\x00")
        + b"\x00\x00\x00"
    )


def _service_data(message: bytes, *, counter: int = 0x00, ad_code: int = 0x0D) -> bytes:
    """Wrap a 25-byte message the way bluetooth.c:174-181 puts it on the air."""
    return bytes([ad_code, counter]) + message


def _location_message(*, status: int = 1) -> bytes:
    """A 25-byte Location message whose body would decode as a serial.

    Status 1 (Ground) puts a 1 in byte 1's high nibble, the same place the ID
    type sits in a Basic ID — so this fixture cannot be rejected by the
    ID-type check, isolating the message-type check.
    """
    return (
        bytes([(_MSGTYPE_LOCATION << 4) | 2])
        + bytes([(status << 4) | 0x0A])
        + b"51079400024117600"[:20].ljust(23, b"\x00")
    )[:25]


def _message_pack(messages: list[bytes], *, proto_version: int = 2) -> bytes:
    """A type-0xF pack: [type|ver][msg size][msg count][messages...].

    Layout from OpenDroneIdParser.java:615-630, which reads message size and
    count from offset+1 and offset+2 and then that many fixed-size messages.
    """
    return (
        bytes([(_MSGTYPE_PACKED << 4) | proto_version])
        + bytes([25])
        + bytes([len(messages)])
        + b"".join(messages)
    )


# --- the constants themselves ------------------------------------------------


def test_service_uuid_is_the_astm_remote_id_assignment():
    # 0xFFFA = ASTM International, ASTM Remote ID, in the Bluetooth SIG
    # 16-bit UUID space. BluetoothScanner.java:120 spells out the 128-bit form.
    assert ODID_SERVICE_UUID == "0000fffa-0000-1000-8000-00805f9b34fb"


def test_ad_application_code_is_open_drone_id():
    assert ODID_AD_APPLICATION_CODE == 0x0D


# --- the happy path ----------------------------------------------------------


def test_decodes_the_serial_from_a_basic_id_advert():
    payload = _service_data(_basic_id_message(b"1596F3AN4X8Y2Z"))
    assert decode_serial(payload) == "1596F3AN4X8Y2Z"


def test_strips_the_nul_padding_from_a_short_serial():
    # A serial shorter than ODID_ID_SIZE is NUL-padded to 20 on the wire.
    payload = _service_data(_basic_id_message(b"21239ESA2"))
    assert decode_serial(payload) == "21239ESA2"


def test_a_full_twenty_byte_serial_is_not_truncated():
    payload = _service_data(_basic_id_message(b"ABCDEFGHIJKLMNOPQRST"))
    assert decode_serial(payload) == "ABCDEFGHIJKLMNOPQRST"


def test_the_message_counter_does_not_affect_the_result():
    serial = b"21239ESA2"
    first = decode_serial(_service_data(_basic_id_message(serial), counter=0x00))
    wrapped = decode_serial(_service_data(_basic_id_message(serial), counter=0xFF))
    assert first == wrapped == "21239ESA2"


def test_protocol_version_in_the_low_nibble_is_ignored():
    # Versions 0-2 are in the wild; the low nibble must not be read as type.
    for version in (0, 1, 2, 15):
        payload = _service_data(_basic_id_message(b"21239ESA2", proto_version=version))
        assert decode_serial(payload) == "21239ESA2"


# --- what must NOT decode ----------------------------------------------------


def test_a_non_open_drone_id_ad_application_code_is_rejected():
    """0xFFFA is ASTM's whole address space, not Open Drone ID's alone."""
    payload = _service_data(_basic_id_message(b"21239ESA2"), ad_code=0x0E)
    assert decode_serial(payload) is None


def test_a_location_message_yields_no_serial():
    """Type 1 = Location: no UAS ID at all, so bytes 2-21 are position data.

    Byte 1 of a Location message is [Status][flags], and status 1 = Ground —
    so its high nibble is indistinguishable from ODID_IDTYPE_SERIAL_NUMBER.
    The ID-type check therefore cannot reject this; only the message-type
    check can. The body bytes are ASCII-alphanumeric on purpose: with plain
    zero bytes the coercion would reject the result anyway and the test would
    pass whether or not the guard existed. Proven by prove_ble_odid.py M2.
    """
    location = _location_message()
    assert decode_serial(_service_data(location)) is None


def test_a_non_serial_id_type_yields_no_serial():
    """drone_id_prefix is defined as the CTA-2063-A serial, not any UAS ID."""
    payload = _service_data(
        _basic_id_message(b"FIN87astrdge12k8", id_type=_IDTYPE_CAA_REGISTRATION)
    )
    assert decode_serial(payload) is None


def test_a_serial_that_is_not_ascii_alphanumeric_is_dropped():
    payload = _service_data(_basic_id_message(b"\xff\xfe\xfd\xfc"))
    assert decode_serial(payload) is None


def test_a_serial_shorter_than_the_minimum_is_dropped():
    # drone_id_prefix is 3-32 chars; a 2-char serial cannot be one.
    payload = _service_data(_basic_id_message(b"AB"))
    assert decode_serial(payload) is None


def test_an_all_padding_serial_is_dropped():
    payload = _service_data(_basic_id_message(b""))
    assert decode_serial(payload) is None


# --- truncation and garbage --------------------------------------------------


def test_a_truncated_message_is_dropped():
    full = _service_data(_basic_id_message(b"21239ESA2"))
    assert decode_serial(full[:-1]) is None


def test_empty_payload_is_dropped():
    assert decode_serial(b"") is None


def test_the_ad_code_byte_alone_is_dropped():
    assert decode_serial(b"\x0d") is None


def test_arbitrary_garbage_never_raises():
    for payload in (b"\x00" * 27, bytes(range(27)), b"\x0d" * 27, b"\xff" * 64):
        decode_serial(payload)


# --- message packs -----------------------------------------------------------


def test_decodes_a_basic_id_inside_a_message_pack():
    pack = _message_pack([_basic_id_message(b"21239ESA2")])
    assert decode_serial(_service_data(pack)) == "21239ESA2"


def test_finds_the_basic_id_among_other_messages_in_a_pack():
    """A Location message ahead of the Basic ID must not shadow it.

    The Location fixture would itself decode as a serial if the message-type
    check were missing, so this pins the ordering too: the answer must come
    from the Basic ID, not from whatever sits first in the pack.
    """
    location = _location_message()
    pack = _message_pack([location, _basic_id_message(b"21239ESA2"), location])
    assert decode_serial(_service_data(pack)) == "21239ESA2"


def test_a_pack_whose_count_overruns_the_payload_is_dropped():
    pack = _message_pack([_basic_id_message(b"21239ESA2")])
    lying = pack[:2] + bytes([9]) + pack[3:]
    assert decode_serial(_service_data(lying)) is None


def test_a_pack_declaring_the_wrong_message_size_is_dropped():
    """An oversized declared size must be refused, not silently mis-sliced.

    Declaring 26 rather than 25 has to be tested against a pack big enough to
    satisfy the overrun check, or the overrun check rejects it first and this
    says nothing about the size check. With two real messages present, a
    26-byte stride still lands on the first message and would decode a serial.
    Proven by prove_ble_odid.py M5.
    """
    pack = _message_pack([_basic_id_message(b"21239ESA2"), _location_message()])
    lying = pack[:1] + bytes([26]) + bytes([1]) + pack[3:]
    assert decode_serial(_service_data(lying)) is None


def test_a_nested_pack_is_not_recursed_into():
    """A pack inside a pack is malformed; recursion there is a DoS shape."""
    inner = _message_pack([_basic_id_message(b"21239ESA2")])
    pack = _message_pack([inner[:25]])
    assert decode_serial(_service_data(pack)) is None


# --- the bleak-shaped mapping ------------------------------------------------


def test_decodes_from_the_bleak_service_data_mapping():
    payload = _service_data(_basic_id_message(b"21239ESA2"))
    assert decode_service_data({ODID_SERVICE_UUID: payload}) == "21239ESA2"


def test_ignores_service_data_under_another_uuid():
    payload = _service_data(_basic_id_message(b"21239ESA2"))
    other = {"0000fe9f-0000-1000-8000-00805f9b34fb": payload}
    assert decode_service_data(other) is None


def test_the_service_uuid_match_is_case_insensitive():
    payload = _service_data(_basic_id_message(b"21239ESA2"))
    assert decode_service_data({ODID_SERVICE_UUID.upper(): payload}) == "21239ESA2"


def test_a_missing_or_empty_mapping_is_none():
    assert decode_service_data(None) is None
    assert decode_service_data({}) is None


def test_a_non_mapping_does_not_raise():
    # Some call sites pass a bare tuple of UUIDs; mirror ble_continuity's
    # classify_manufacturer_data, which returns None rather than raising.
    assert decode_service_data(("0000fffa-0000-1000-8000-00805f9b34fb",)) is None
