-- Normalize pre-existing watchlist patterns to the canonical lowercase
-- colon-separated form (L-RULES-1).
--
-- Pre-v0.4.0 seed/import paths inserted patterns verbatim from operator
-- input. The poller normalizes its observation MAC to lowercase
-- colon-separated form before any equality lookup against the watchlist
-- table; an "AA:BB:CC:DD:EE:FF" row therefore never linked to the
-- matching alert and silently dropped Argus metadata enrichment.
--
-- This migration applies the conservative normalization that SQLite can
-- express in pure SQL — case-fold and convert hyphens/dots/spaces to
-- colons — for the three pattern types where canonical form is
-- well-defined:
--
--   * mac:      lowercase, colon-separated 6 octets
--   * oui:      lowercase, colon-separated 3 octets
--   * ble_uuid: lowercase, hyphen-separated 128-bit UUID
--
-- For ble_uuid we keep hyphens (not colons), so the REPLACE chain skips
-- hyphens for that type. For mac/oui we collapse hyphens, dots, and
-- spaces to colons.
--
-- Exotic input forms (Cisco-dotted MACs without separators after some
-- transit, flat 12-hex MACs, dehyphenated 32-hex UUIDs) won't be
-- perfectly normalized by this SQL pass — that's acceptable. Those
-- inputs are rare in YAML/CSV and the next seed/import run lands them
-- in canonical form via the new normalize_pattern helper. The cost of
-- a perfect SQL-side normalization (regex extension, custom function
-- registration) is not worth chasing for a corner case.
--
-- Idempotent: LOWER + REPLACE on already-canonical input is a no-op,
-- so re-applying this migration (or running it on a freshly-seeded DB
-- that's already in canonical form) does nothing.
--
-- ssid is intentionally NOT touched. SSIDs are case-sensitive per
-- 802.11 and lowercasing them would silently break matching. The
-- separate L-RULES-10 (SSID case/whitespace handling) is a deliberate
-- v0.4.x deferral.

UPDATE watchlist
SET pattern = LOWER(REPLACE(REPLACE(REPLACE(pattern, '-', ':'), '.', ':'), ' ', ''))
WHERE pattern_type IN ('mac', 'oui');

UPDATE watchlist
SET pattern = LOWER(pattern)
WHERE pattern_type = 'ble_uuid';
