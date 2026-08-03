"""Open Drone ID (ASTM F3411) BLE advertisement decoder.

This is the second module in the project that reads raw BLE advertisement
payload bytes, and it follows ``ble_continuity``'s contract exactly: it returns
one derived label — the Remote-ID serial — and nothing else. The payload bytes
never leave the caller's stack frame, are never buffered, and are never handed
to the database. That is what keeps the bridge's "we never retain advertisement
content" promise literally true while still letting us name a drone.

Why this exists: Kismet's UAV phy decodes DJI's proprietary DroneID, which was
51 of 427 drone rows (12%) in the 2026-08-03 Argus measurement. The other 88%
broadcast ASTM F3411 and Kismet does not decode it.

WIRE LAYOUT — verified 2026-08-03 against two independent sides of the
reference implementation, not written from memory. The BT4 legacy advert is a
single AD element that fills the whole 31-byte legacy payload
(``transmitter-linux/bluetooth.c:168-184``)::

    1F  Advertising_Data_Length -- 31, the entire legacy capacity
    1E  length of the service-data AD element (30)
    16  GAP AD type = "Service Data - 16-bit UUID"
    FA FF   0xFFFA little-endian = ASTM International, ASTM Remote ID
    0D  AD Application Code within the ASTM space = Open Drone ID
    xx  8-bit message counter, starts at 0x00 and wraps at 0xFF
    ..  25 bytes = ODID_MESSAGE_SIZE

``receiver-android/BluetoothScanner.java:114-134`` filters on that same UUID
and AD code; ``OpenDroneIdParser.java:466,493-496`` reads the type nibbles;
``opendroneid-core-c/libopendroneid/opendroneid.h:423-437`` gives the Basic ID
body and ``:123-132`` gives ODID_IDTYPE_SERIAL_NUMBER = 1.

⛔ The AD Application Code is NOT redundant with the service UUID. 0xFFFA is
ASTM International's whole 16-bit assignment; 0x0D is Open Drone ID's code
*within* it. Matching the UUID alone would hand foreign ASTM payloads to this
parser.

BlueZ strips the 16-bit UUID before exposing ``ServiceData``, so the bytes this
decoder receives from bleak begin at the AD Application Code.
"""

from __future__ import annotations

from .kismet import _coerce_drone_id_prefix

# 0xFFFA = ASTM International, ASTM Remote ID, in the Bluetooth SIG 16-bit UUID
# space, expanded to the 128-bit form bleak/BlueZ key ServiceData by.
ODID_SERVICE_UUID = "0000fffa-0000-1000-8000-00805f9b34fb"

# AD Application Code within the ASTM address space = Open Drone ID.
ODID_AD_APPLICATION_CODE = 0x0D

# ODID_MESSAGE_SIZE (opendroneid.h:23). Fixed for every message type, which is
# what lets a pack address its members by index.
_MESSAGE_SIZE = 25

# ODID_ID_SIZE (opendroneid.h:24) -- the UASID field, NUL-padded when short.
_ID_SIZE = 20

_MSGTYPE_BASIC_ID = 0x0
_MSGTYPE_PACKED = 0xF

# ODID_IDTYPE_SERIAL_NUMBER. The other ID types (2 = CAA registration, 3 = UTM
# assigned UUID, 4 = specific session ID) are deliberately NOT mapped to
# drone_id_prefix: that field is documented as the ANSI/CTA-2063-A serial and
# the watchlist patterns operators load into it are serial prefixes. A UUID
# arriving in the same field would match nothing and look like a decode bug.
_IDTYPE_SERIAL_NUMBER = 1

# ODID_PACK_MAX_MESSAGES (opendroneid.h:73).
_PACK_MAX_MESSAGES = 9

# Offsets inside the service-data value.
_OFF_AD_CODE = 0
_OFF_COUNTER = 1
_OFF_MESSAGE = 2


def decode_serial(payload) -> str | None:
    """Canonical ``drone_id_prefix`` from one ODID service-data value.

    ``payload`` is the service-data value as BlueZ hands it over: the AD
    Application Code, the message counter, then one 25-byte message or one
    message pack. Returns the same canonical form the Kismet path produces, or
    None for anything that is not a Basic ID carrying a serial. Never raises.
    """
    try:
        data = bytes(payload or b"")
    except (TypeError, ValueError):
        return None
    if len(data) <= _OFF_MESSAGE:
        return None
    if data[_OFF_AD_CODE] != ODID_AD_APPLICATION_CODE:
        return None
    # data[_OFF_COUNTER] is the message counter. It is read for documentation
    # only: it identifies retransmissions, and we deduplicate by MAC per flush
    # window already, so nothing here needs it.
    return _serial_from_body(data[_OFF_MESSAGE:])


def decode_service_data(service_data) -> str | None:
    """Canonical ``drone_id_prefix`` from a bleak ``service_data`` mapping.

    Accepts the ``{uuid: payload_bytes}`` shape. A non-mapping yields None
    rather than raising, mirroring ``ble_continuity.classify_manufacturer_data``
    — several call sites pass a bare tuple of UUIDs.
    """
    items = getattr(service_data, "items", None)
    if items is None:
        return None
    for uuid, payload in items():
        if not isinstance(uuid, str) or uuid.lower() != ODID_SERVICE_UUID:
            continue
        serial = decode_serial(payload)
        if serial is not None:
            return serial
    return None


def _serial_from_body(body: bytes) -> str | None:
    """Dispatch on the message-type nibble: one message, or a pack of them."""
    if not body:
        return None
    if body[0] >> 4 == _MSGTYPE_PACKED:
        return _serial_from_pack(body)
    if len(body) < _MESSAGE_SIZE:
        return None
    return _serial_from_basic_id(body[:_MESSAGE_SIZE])


def _serial_from_pack(pack: bytes) -> str | None:
    """First serial among a message pack's members.

    Pack layout is [type|version][message size][message count][messages...]
    (OpenDroneIdParser.java:615-630). A pack only fits in a BT5 extended
    advertisement, so this path is unreachable on a controller that can receive
    legacy adverts only.
    """
    if len(pack) < 3:
        return None
    message_size = pack[1]
    count = pack[2]
    # A pack that lies about either field is dropped whole rather than parsed
    # as far as it goes: a partial result from a bad parse is worse than none.
    if message_size != _MESSAGE_SIZE or not 1 <= count <= _PACK_MAX_MESSAGES:
        return None
    if len(pack) < 3 + message_size * count:
        return None
    for i in range(count):
        start = 3 + i * message_size
        # No recursion: a nested pack fails the Basic ID type check below and
        # is simply skipped, so a crafted advert cannot drive this into depth.
        serial = _serial_from_basic_id(pack[start : start + message_size])
        if serial is not None:
            return serial
    return None


def _serial_from_basic_id(message: bytes) -> str | None:
    """The UASID of a Basic ID message, if it is a CTA-2063-A serial.

    Byte 0 is [MessageType][ProtoVersion] and byte 1 is [IDType][UAType], high
    nibble first in both cases. The protocol version is deliberately not
    checked: versions 0 through 2 are all in the wild and the UASID offset has
    not moved across them, so refusing an unknown version would drop future
    transmitters for no gain.
    """
    if len(message) < _MESSAGE_SIZE:
        return None
    if message[0] >> 4 != _MSGTYPE_BASIC_ID:
        return None
    if message[1] >> 4 != _IDTYPE_SERIAL_NUMBER:
        return None
    raw = message[2 : 2 + _ID_SIZE]
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    # ONE canonical form for the whole project: the Kismet path's coercion,
    # which strips NUL padding and separator punctuation, uppercases, and then
    # shape-checks 3-32 ASCII alphanumerics. Reimplementing it here would let
    # the two ingest paths drift into disagreeing about the same serial.
    return _coerce_drone_id_prefix(text)
