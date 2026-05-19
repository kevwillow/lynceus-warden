"""Canonical normalization for watchlist patterns at write time.

The poller normalizes observation MACs to lowercase colon-separated form via
``kismet.normalize_mac`` before any matching pass; if a watchlist row stores
``"AA:BB:CC:DD:EE:FF"`` instead of ``"aa:bb:cc:dd:ee:ff"``, the SQL equality
lookup in ``db.resolve_matched_watchlist_id`` misses, leaving every alert
that *should* link to that row with ``matched_watchlist_id = NULL`` and
silently dropping the Argus metadata enrichment (vendor, confidence, source,
severity hint) that v0.4.0 promises in the alert detail page.

The fix is to normalize at write time only — read-time normalization would
mask future write-time regressions and add per-lookup cost. The canonical
form is what every persistence path (``cli.seed_watchlist``,
``cli.import_argus``, future bulk loaders) should pass to the DB.

Pattern types (matching the column values stored in ``watchlist.pattern_type``):

* ``mac``        – lowercase, colon-separated, 6 octets. Accepts colon, hyphen,
                   dot (Cisco ``aabb.ccdd.eeff``), and flat-hex (``AABBCCDDEEFF``)
                   inputs. Closes L-RULES-1.
* ``oui``        – lowercase, colon-separated, 3 octets. Accepts colon, hyphen,
                   and flat-hex (``AABBCC`` — IEEE distribution form). The flat
                   form closes L-RULES-11.
* ``ble_uuid``   – lowercase, hyphen-separated 128-bit UUID. Accepts uppercase
                   and the dehyphenated 32-hex form. Also accepts 16-bit
                   (4-hex) and 32-bit (8-hex) Bluetooth SIG short forms,
                   which expand against the canonical Bluetooth base UUID
                   ``00000000-0000-1000-8000-00805f9b34fb`` (Core Spec §3.2.1).
                   Additionally accepts dual-form Argus emissions like
                   ``"fd5a / 0x0075"`` (16-bit UUID plus paired company id);
                   the leading UUID is taken and the trailing commentary
                   dropped. Canonical output form is unchanged — the
                   admitted-input shape widened, the stored 36-char
                   8-4-4-4-12 form did not.
* ``ssid``       – returned unchanged. SSIDs are case-sensitive by IEEE 802.11
                   spec; normalizing would silently change matching behaviour.
                   L-RULES-10 (SSID case/whitespace handling) is a deliberate
                   v0.4.x deferral, not a v0.4.0 P0.

The ``mac_range`` pattern type is intentionally NOT handled by
``normalize_pattern`` because it returns a structured (prefix, length)
pair rather than a single string. See ``parse_mac_range_pattern``
below; the importer calls it directly and stores both the canonical
CIDR string in ``watchlist.pattern`` and the prefix nibble metadata in
the ``mac_range_prefix`` / ``mac_range_prefix_length`` columns.

Unknown ``pattern_type`` values pass through unchanged with a debug log,
so future pattern types added to the schema don't cause this helper to
raise on previously-valid input.
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

_HEX_RE = re.compile(r"^[0-9a-f]+$")


def _to_canonical_hex(pattern: str, expected_hex_count: int, label: str) -> str:
    """Strip separators, lowercase, validate length+alphabet. Returns the
    cleaned hex string (no separators)."""
    # Tolerate every separator we've seen in real-world watchlist input:
    # hyphens (Linux convention), dots (Cisco IOS), spaces (hand-typed),
    # colons (canonical). Empty after stripping is rejected.
    cleaned = pattern.strip().lower()
    for sep in (":", "-", ".", " "):
        cleaned = cleaned.replace(sep, "")
    if len(cleaned) != expected_hex_count or not _HEX_RE.match(cleaned):
        raise ValueError(
            f"invalid {label}: {pattern!r} "
            f"(expected {expected_hex_count} hex digits after stripping separators)"
        )
    return cleaned


def _normalize_mac(pattern: str) -> str:
    hex_str = _to_canonical_hex(pattern, 12, "mac")
    return ":".join(hex_str[i : i + 2] for i in range(0, 12, 2))


def _normalize_oui(pattern: str) -> str:
    hex_str = _to_canonical_hex(pattern, 6, "oui")
    return ":".join(hex_str[i : i + 2] for i in range(0, 6, 2))


# Bluetooth Core Specification §3.2.1 base UUID. 16-bit and 32-bit assigned
# UUIDs are folded into the first 4 / 8 hex chars of this base when expanded
# to the canonical 128-bit form — i.e. 16-bit ``fd5a`` becomes
# ``0000fd5a-0000-1000-8000-00805f9b34fb``. Lowercase here so the canonical
# output form lands lowercase without an extra .lower() pass.
_BLE_BASE_UUID_SUFFIX = "-0000-1000-8000-00805f9b34fb"


def _normalize_ble_uuid(pattern: str) -> str:
    # Argus emits a small number of ble_service_uuid rows in dual-form
    # commentary shape — ``"fd5a / 0x0075"`` is "16-bit assigned UUID
    # fd5a paired with company id 0x0075". For watchlist purposes the
    # ``ble_uuid`` admission is the UUID half; the company id half is
    # admitted separately as ``ble_manufacturer_id`` by Argus when it
    # carries detection value on its own. Take the segment before the
    # first ``/`` and canonicalize that.
    text = pattern.strip()
    if "/" in text:
        text = text.split("/", 1)[0].strip()
    cleaned = text.lower()
    for sep in (":", "-", ".", " "):
        cleaned = cleaned.replace(sep, "")
    if not cleaned or not _HEX_RE.match(cleaned):
        raise ValueError(
            f"invalid ble_uuid: {pattern!r} "
            f"(expected 4, 8, or 32 hex digits after stripping separators)"
        )
    # 16-bit and 32-bit Bluetooth SIG assigned UUIDs fold into the
    # base UUID per Core Spec §3.2.1.
    if len(cleaned) == 4:
        return f"0000{cleaned}{_BLE_BASE_UUID_SUFFIX}"
    if len(cleaned) == 8:
        return f"{cleaned}{_BLE_BASE_UUID_SUFFIX}"
    if len(cleaned) == 32:
        # Canonical UUID hyphen positions: 8-4-4-4-12.
        return (
            f"{cleaned[0:8]}-{cleaned[8:12]}-{cleaned[12:16]}-"
            f"{cleaned[16:20]}-{cleaned[20:32]}"
        )
    raise ValueError(
        f"invalid ble_uuid: {pattern!r} "
        f"(expected 4, 8, or 32 hex digits after stripping separators, "
        f"got {len(cleaned)})"
    )


# mac_range parsing. Argus emits two CIDR shapes (operator-confirmed against
# the 2026-05-14T22:34:07Z live argus_export.csv, 22,532 records):
#
#   /28  (MA-M):       'aa:bb:cc:d/28'      — 7 hex chars (~64.49% of corpus)
#   /36  (MA-S / IAB): 'aa:bb:cc:dd:e/36'   — 9 hex chars (~35.44% of corpus)
#
# Legacy bare-prefix rows (12 in the snapshot, ~0.07%) are accepted dual-shape:
#   'aa:bb:cc:d'       → infer /28
#   'aa:bb:cc:dd:e'    → infer /36
#
# Always nibble-aligned. Only /28 and /36 in current emission — other lengths
# are rejected loudly rather than silently accepted, because a new length
# surfacing means an Argus contract change worth raising on.
_MAC_RANGE_LENGTHS: dict[int, tuple[int, int]] = {
    # length_bits -> (group_count, total_hex_chars)
    28: (4, 7),
    36: (5, 9),
}


def parse_mac_range_pattern(raw: str) -> tuple[str, int]:
    """Parse an Argus mac_range pattern into ``(prefix_hex, prefix_length_bits)``.

    Accepts per the Argus wire contract (snapshot 2026-05-14T22:34:07Z):

    * Canonical CIDR:   ``'aa:bb:cc:d/28'``, ``'aa:bb:cc:dd:e/36'``
    * Legacy bare:      ``'aa:bb:cc:d'`` → /28, ``'aa:bb:cc:dd:e'`` → /36

    Returns the lowercase hex prefix with all colons stripped (the form
    stored in ``watchlist.mac_range_prefix``) plus the prefix length in
    bits (28 or 36, the form stored in ``watchlist.mac_range_prefix_length``).

    Raises ``ValueError`` for any unrecognized shape — wrong group count,
    wrong last-group nibble width, non-hex characters, unsupported CIDR
    length (/24 is identifier_type='oui' by IEEE design and is rejected
    here on purpose; /32 / /40 / /44 / /48 do not currently emit and a
    new length surfacing means an Argus contract change worth raising
    on rather than silently accepting), or a declared length that
    disagrees with the prefix shape (e.g. ``'aa:bb:cc:d/36'`` declares
    /36 but the 7-hex-char prefix implies /28 — likely an Argus bug,
    reject loudly).
    """
    if not isinstance(raw, str):
        raise ValueError(f"mac_range pattern must be a string, got {type(raw).__name__}")
    text = raw.strip().lower()
    if not text:
        raise ValueError("mac_range pattern is empty")

    # Split off CIDR suffix if present. Legacy bare-prefix has no '/'.
    declared_length: int | None
    if "/" in text:
        prefix_part, _, length_part = text.partition("/")
        try:
            declared_length = int(length_part)
        except ValueError as exc:
            raise ValueError(
                f"mac_range pattern {raw!r}: CIDR length must be an integer"
            ) from exc
        if declared_length not in _MAC_RANGE_LENGTHS:
            raise ValueError(
                f"mac_range pattern {raw!r}: prefix length /{declared_length} "
                f"is not supported (Argus currently emits only /28 and /36)"
            )
    else:
        prefix_part = text
        declared_length = None

    groups = prefix_part.split(":")
    if len(groups) == 4:
        inferred_length = 28
    elif len(groups) == 5:
        inferred_length = 36
    else:
        raise ValueError(
            f"mac_range pattern {raw!r}: must have 4 or 5 colon-separated "
            f"groups (got {len(groups)})"
        )

    # Per-group width: first N-1 groups are 2 hex chars, last group is 1
    # hex nibble. This is the nibble-aligned contract Argus codified.
    if len(groups[-1]) != 1:
        raise ValueError(
            f"mac_range pattern {raw!r}: last group must be exactly 1 hex "
            f"nibble (got {groups[-1]!r}, width {len(groups[-1])})"
        )
    for g in groups[:-1]:
        if len(g) != 2:
            raise ValueError(
                f"mac_range pattern {raw!r}: first {len(groups) - 1} groups "
                f"must each be 2 hex chars (got {g!r}, width {len(g)})"
            )

    cleaned = "".join(groups)
    if not _HEX_RE.match(cleaned):
        raise ValueError(
            f"mac_range pattern {raw!r}: non-hex characters in prefix"
        )

    expected_group_count, expected_hex_count = _MAC_RANGE_LENGTHS[inferred_length]
    if len(cleaned) != expected_hex_count:
        # Defensive — group-width checks above already enforce this, but
        # belt-and-suspenders keeps the contract obvious on inspection.
        raise ValueError(
            f"mac_range pattern {raw!r}: prefix has {len(cleaned)} hex "
            f"chars, expected {expected_hex_count} for /{inferred_length}"
        )

    if declared_length is not None and declared_length != inferred_length:
        raise ValueError(
            f"mac_range pattern {raw!r}: declared /{declared_length} but "
            f"prefix shape implies /{inferred_length} "
            f"({expected_hex_count} hex chars across {expected_group_count} groups)"
        )

    return cleaned, inferred_length


def canonicalize_mac_range_pattern(prefix_hex: str, length_bits: int) -> str:
    """Render a cleaned hex prefix + length back into canonical CIDR form.

    ``parse_mac_range_pattern('aa:bb:cc:d')`` returns ``('aabbccd', 28)``;
    feeding that pair to ``canonicalize_mac_range_pattern`` yields
    ``'aa:bb:cc:d/28'``. Used at import time to canonicalize legacy
    bare-prefix Argus rows before they hit the ``watchlist.pattern``
    column, so the watchlist UI (which renders ``pattern`` verbatim)
    shows uniform shape regardless of the input form.
    """
    if length_bits == 28:
        return f"{prefix_hex[0:2]}:{prefix_hex[2:4]}:{prefix_hex[4:6]}:{prefix_hex[6:7]}/28"
    if length_bits == 36:
        return f"{prefix_hex[0:2]}:{prefix_hex[2:4]}:{prefix_hex[4:6]}:{prefix_hex[6:8]}:{prefix_hex[8:9]}/36"
    raise ValueError(f"unsupported mac_range length: {length_bits}")


def mac_in_mac_range(mac: str, range_pattern: str) -> bool:
    """Test whether a canonical observation MAC falls within a mac_range.

    ``mac`` is the colon-separated lowercase form that
    ``kismet.normalize_mac`` produces (e.g. ``'aa:bb:cc:dd:ee:ff'``).
    ``range_pattern`` is any shape ``parse_mac_range_pattern`` accepts
    (canonical CIDR, legacy bare). A malformed pattern returns False
    rather than raising — both the live poll path (allowlist
    ``_entry_matches``) and the SQLite-registered helper used by the
    /alerts has_action filter need a non-crashing soft-fail when an
    operator-curated YAML entry is malformed.
    """
    try:
        prefix_hex, length = parse_mac_range_pattern(range_pattern)
    except ValueError:
        return False
    nibbles = length // 4
    return mac.replace(":", "")[:nibbles] == prefix_hex


# ble_manufacturer_id parsing. Argus emits the Bluetooth SIG 16-bit
# Company Identifier (Assigned Numbers, §2.1) in the canonical
# '0x'-prefixed uppercase 4-hex-char form, e.g. '0x004C' (Apple) or
# '0x09C8' (XUNTONG). Verified against the 2026-05-14T22:34:07Z
# argus_export.csv snapshot: 100% of the 3,969 rows are exactly 6
# characters in that '0x'-prefixed shape.
#
# Canonical persistent form is 4-hex-char lowercase, no prefix —
# 'apple' becomes '004c'. The bare-hex form (no 0x prefix) is the
# shape a Kismet observation will most likely surface in its
# advertisement-decoded fields, so storing in that form keeps the
# runtime equality lookup a direct string compare. Accepts:
#
#   '0x004C' / '0X004C'         → '004c'      (Argus canonical)
#   '004c' / '004C'             → '004c'      (bare hex, both cases)
#   '4c'                        → '004c'      (zero-padded short form)
#   '0x4C' / '4C' / '76'        → '004c'      (defensive — short / mixed)
#
# Rejects: empty after strip, non-hex chars after stripping '0x',
# more than 4 hex chars (the 16-bit constraint is hard).
def _normalize_ble_manufacturer_id(pattern: str) -> str:
    if not isinstance(pattern, str):
        raise ValueError(
            f"ble_manufacturer_id pattern must be a string, "
            f"got {type(pattern).__name__}"
        )
    raw = pattern.strip().lower()
    if not raw:
        raise ValueError("ble_manufacturer_id pattern is empty")
    if raw.startswith("0x"):
        raw = raw[2:]
    if not raw:
        raise ValueError(
            f"ble_manufacturer_id pattern {pattern!r}: empty after stripping '0x'"
        )
    if len(raw) > 4:
        raise ValueError(
            f"ble_manufacturer_id pattern {pattern!r}: too long after stripping "
            f"'0x' ({len(raw)} hex chars, expected at most 4 for 16-bit company id)"
        )
    if not _HEX_RE.match(raw):
        raise ValueError(
            f"ble_manufacturer_id pattern {pattern!r}: non-hex characters "
            f"after stripping '0x'"
        )
    return raw.zfill(4)


# drone_id_prefix parsing. Argus emits ANSI/CTA-2063-A (Remote-ID
# serial number) prefixes — typically 4-char manufacturer code plus
# variable-length serial fragment, uppercase ASCII alphanumeric.
# Verified against the 2026-05-14T22:34:07Z argus_export.csv
# snapshot: all 427 rows are 3-20 chars, 100% alphanumeric, all
# uppercase.
#
# Canonical persistent form is uppercase ASCII alphanumeric. The
# uppercase choice matches the Argus emission verbatim — Remote-ID
# serial numbers are case-sensitive per the standard (lowercasing a
# real serial 'ABCDE' to 'abcde' would silently break equality
# lookups against a Kismet observation that decoded the uppercase
# form from the RID payload). Defensive bounds (3-32 chars) catch
# stray whitespace / one-char fragments without rejecting any of
# the observed Argus shapes.
def _normalize_drone_id_prefix(pattern: str) -> str:
    if not isinstance(pattern, str):
        raise ValueError(
            f"drone_id_prefix pattern must be a string, "
            f"got {type(pattern).__name__}"
        )
    raw = pattern.strip().upper()
    if not raw:
        raise ValueError("drone_id_prefix pattern is empty")
    if len(raw) < 3 or len(raw) > 32:
        raise ValueError(
            f"drone_id_prefix pattern {pattern!r}: length {len(raw)} "
            f"out of range (expected 3-32 chars; Argus emits 3-20 today)"
        )
    if not raw.isascii() or not raw.isalnum():
        raise ValueError(
            f"drone_id_prefix pattern {pattern!r}: must be ASCII "
            f"alphanumeric (A-Z, 0-9)"
        )
    return raw


def normalize_pattern(pattern_type: str, pattern: str) -> str:
    """Return the canonical persistent form of ``pattern`` for ``pattern_type``.

    Raises ``ValueError`` for known types when the input cannot be coerced to
    canonical form (wrong octet count, non-hex characters, malformed UUID).
    Unknown ``pattern_type`` values pass through unchanged so future schema
    additions don't surprise this helper.
    """
    if pattern_type == "mac":
        return _normalize_mac(pattern)
    if pattern_type == "oui":
        return _normalize_oui(pattern)
    if pattern_type == "ble_uuid":
        return _normalize_ble_uuid(pattern)
    if pattern_type == "ble_manufacturer_id":
        return _normalize_ble_manufacturer_id(pattern)
    if pattern_type == "drone_id_prefix":
        return _normalize_drone_id_prefix(pattern)
    if pattern_type == "ssid":
        # SSIDs are case-sensitive per 802.11; do not normalize.
        return pattern
    if pattern_type == "ssid_pattern":
        # Case-insensitive substring needle. Case-folding happens in
        # the matcher (db.resolve_matched_ssid_pattern_for_eval via
        # COLLATE NOCASE), not at write time — the original case is
        # preserved so the stored pattern remains operator-readable.
        return pattern
    logger.debug(
        "normalize_pattern: unknown pattern_type %r — passing through unchanged",
        pattern_type,
    )
    return pattern
