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
                   and the dehyphenated 32-hex form. Does NOT expand short
                   16-bit / 32-bit UUIDs to the Bluetooth base — that's a
                   separate fix tracked under the Kismet short-UUID finding.
* ``ssid``       – returned unchanged. SSIDs are case-sensitive by IEEE 802.11
                   spec; normalizing would silently change matching behaviour.
                   L-RULES-10 (SSID case/whitespace handling) is a deliberate
                   v0.4.x deferral, not a v0.4.0 P0.

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


def _normalize_ble_uuid(pattern: str) -> str:
    hex_str = _to_canonical_hex(pattern, 32, "ble_uuid")
    # Canonical UUID hyphen positions: 8-4-4-4-12.
    return f"{hex_str[0:8]}-{hex_str[8:12]}-{hex_str[12:16]}-{hex_str[16:20]}-{hex_str[20:32]}"


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
    if pattern_type == "ssid":
        # SSIDs are case-sensitive per 802.11; do not normalize.
        return pattern
    logger.debug(
        "normalize_pattern: unknown pattern_type %r — passing through unchanged",
        pattern_type,
    )
    return pattern
