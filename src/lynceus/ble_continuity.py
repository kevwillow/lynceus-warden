"""Apple Continuity advertisement-payload decoder — pure, stdlib-only.

This module is the ONLY code in the project that reads raw BLE
advertisement payload bytes. It returns a derived class label and nothing
else; the bytes never leave the caller's stack frame. That is what keeps
the bridge's "we never retain advertisement content" invariant literally
true while still letting us tell an AirTag from a pair of AirPods.

Every Apple device advertises under company id 0x004C, so the company id
alone is useless as a signal. The discriminator is the Continuity
message-type byte inside the payload.
"""

from __future__ import annotations

APPLE_COMPANY_ID = 0x004C

_MSG_PROXIMITY_PAIRING = 0x07
_MSG_NEARBY = 0x10
_MSG_FIND_MY = 0x12

CLASS_FIND_MY_SEPARATED = "find_my_separated"
CLASS_FIND_MY = "find_my"
CLASS_AIRPODS = "airpods"
CLASS_NEARBY = "nearby"
CLASS_APPLE_UNKNOWN = "apple_unknown"

# Most surveillance-relevant first. A device emitting several Continuity
# messages in one advert resolves to the highest-ranked class present, so
# a tracker is never masked by a co-emitted Nearby message.
_PRIORITY = (
    CLASS_FIND_MY_SEPARATED,
    CLASS_FIND_MY,
    CLASS_AIRPODS,
    CLASS_NEARBY,
    CLASS_APPLE_UNKNOWN,
)

# UNVALIDATED — pending a real rig capture. Directly analogous to
# kismet._DRONE_ID_PATHS: the surrounding matcher is built and tested, but
# which bit of the Find My status byte means "separated from owner" has
# NOT been confirmed against hardware. Do not promote
# CLASS_FIND_MY_SEPARATED into an alerting rule until it has been.
_FIND_MY_SEPARATED_MASK = 0x04


def classify(company_id: int, payload: bytes) -> str | None:
    """Highest-priority Continuity class in one manufacturer-data entry.

    Returns None for a non-Apple company id and for any payload that
    yields no parseable message. Never raises.
    """
    if company_id != APPLE_COMPANY_ID:
        return None
    found: set[str] = set()
    i = 0
    n = len(payload)
    # Each message is [type][length][body]; a payload may chain several.
    while i + 1 < n:
        msg_type = payload[i]
        length = payload[i + 1]
        body = payload[i + 2 : i + 2 + length]
        if len(body) != length:
            # Truncated or lying length byte. Stop rather than attempt to
            # resync — a partial result from a bad parse is worse than none.
            break
        found.add(_classify_one(msg_type, body))
        i += 2 + length
    for cls in _PRIORITY:
        if cls in found:
            return cls
    return None


def classify_manufacturer_data(manufacturer_data) -> str | None:
    """Highest-priority class across every company-id entry in an advert.

    Accepts the bleak-shaped ``{company_id: payload_bytes}`` mapping. A
    non-mapping (some call sites pass a bare tuple of company ids) yields
    None rather than raising.
    """
    items = getattr(manufacturer_data, "items", None)
    if items is None:
        return None
    best: str | None = None
    for cid, payload in items():
        try:
            label = classify(int(cid), bytes(payload or b""))
        except (TypeError, ValueError):
            continue
        if label is None:
            continue
        if best is None or _PRIORITY.index(label) < _PRIORITY.index(best):
            best = label
    return best


def _classify_one(msg_type: int, body: bytes) -> str:
    if msg_type == _MSG_FIND_MY:
        if body and (body[0] & _FIND_MY_SEPARATED_MASK):
            return CLASS_FIND_MY_SEPARATED
        return CLASS_FIND_MY
    if msg_type == _MSG_PROXIMITY_PAIRING:
        return CLASS_AIRPODS
    if msg_type == _MSG_NEARBY:
        return CLASS_NEARBY
    return CLASS_APPLE_UNKNOWN
