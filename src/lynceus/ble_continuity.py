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
CLASS_FIND_MY_PAIRED = "find_my_paired"
CLASS_AIRPODS = "airpods"
CLASS_NEARBY = "nearby"
CLASS_APPLE_UNKNOWN = "apple_unknown"

# Most surveillance-relevant first. A device emitting several Continuity
# messages in one advert resolves to the highest-ranked class present, so
# a tracker is never masked by a co-emitted Nearby message. Unknown
# separation outranks known-paired: an unmeasured state must never be
# reported as the benign one.
_PRIORITY = (
    CLASS_FIND_MY_SEPARATED,
    CLASS_FIND_MY,
    CLASS_FIND_MY_PAIRED,
    CLASS_AIRPODS,
    CLASS_NEARBY,
    CLASS_APPLE_UNKNOWN,
)

# Separated state is read from the Find My message's STRUCTURE, not from a
# status-flag bit.
#
# A prior revision guessed a `status & 0x04` mask. The 2026-08-01 rig
# capture retired it: across 204 Find My frames from 5 devices, both length
# forms, iPhone present and absent, 0x04 was never set once (0x10 and 0x40
# were equally dead while every odd bit varied). A mask pointing at a
# permanently-zero bit is indistinguishable from a correct mask that was
# never exercised — it would have reported "not separated" for every device
# on earth, including genuinely separated ones. That is worse than an
# unimplemented field because it looks implemented.
#
# The long form carries the rotating EC public key the finder network needs
# to report a sighting; a device only broadcasts that when it is not near
# its owner. The short form carries status and hint bytes only. This is the
# offline-finding layout documented by OpenHaystack and Heinrich et al.,
# "Who Can Find My Devices?", and it is a structural difference we observed
# directly rather than a bit whose meaning we inferred.
_FIND_MY_SEPARATED_LEN = 0x19  # 25 — status + rotating public key material
_FIND_MY_PAIRED_LEN = 0x02  # status + hint, no key material


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


def _classify_find_my(body: bytes) -> str:
    """Three-valued separation state for one Find My message.

    Separated and paired are the two forms observed on hardware; any other
    body length is a form we have not seen, and resolves to the unqualified
    CLASS_FIND_MY rather than being forced into either. Unknown separation
    is a real state and must never collapse into "not separated".
    """
    if len(body) == _FIND_MY_SEPARATED_LEN:
        return CLASS_FIND_MY_SEPARATED
    if len(body) == _FIND_MY_PAIRED_LEN:
        return CLASS_FIND_MY_PAIRED
    return CLASS_FIND_MY


def _classify_one(msg_type: int, body: bytes) -> str:
    if msg_type == _MSG_FIND_MY:
        return _classify_find_my(body)
    if msg_type == _MSG_PROXIMITY_PAIRING:
        return CLASS_AIRPODS
    if msg_type == _MSG_NEARBY:
        return CLASS_NEARBY
    return CLASS_APPLE_UNKNOWN
