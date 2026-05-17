-- Extend watchlist.pattern_type to admit 'ble_manufacturer_id' and
-- 'drone_id_prefix'.
--
-- Migration 011 (mac_range) relaxed the pattern_type CHECK from the
-- original v0.3 set ('mac','oui','ssid','ble_uuid') to add 'mac_range'.
-- Argus's live argus_export.csv snapshot at
-- exported_at=2026-05-14T22:34:07Z carries two more identifier_type
-- values currently dropped at the IDENTIFIER_TYPE_MAP gate in
-- lynceus-import-argus:
--
--   ble_manufacturer_id  3,969 rows  (Bluetooth SIG 16-bit company IDs,
--                                     e.g. '0x004C' for Apple)
--   drone_id_prefix        427 rows  (ANSI/CTA-2063-A Remote-ID
--                                     identifier prefixes, e.g.
--                                     '178852', '2137FDE1', '21239ESA2')
--
-- This migration mirrors migration 011's shape: it relaxes the CHECK
-- to whitelist the two new pattern_types, leaving every other column
-- unchanged. No new metadata columns are needed (unlike mac_range's
-- prefix_length / prefix); both new types are equality-shaped at the
-- string level and use the existing single SELECT in
-- db._lookup_simple_watchlist_match.
--
-- SQLite does not support modifying a CHECK constraint via ALTER TABLE,
-- so a full table rebuild is required (SQLite docs §7, "Making other
-- kinds of table schema changes"). PRAGMA foreign_keys=OFF during the
-- rebuild so the inbound FKs from alerts.matched_watchlist_id
-- (ON DELETE SET NULL) and watchlist_metadata.watchlist_id
-- (ON DELETE CASCADE) do not fire during the intermediate DROP TABLE.
-- AUTOINCREMENT ROWIDs are preserved by INSERTing with explicit id.
-- The mac_range_prefix and mac_range_prefix_length columns from
-- migration 011 are carried across verbatim; they remain NULL for
-- every non-mac_range row including the new types.
--
-- The partial index idx_watchlist_mac_range_prefix from migration 011
-- is dropped + recreated as part of the rebuild because the SQL
-- rebuild pattern requires it; the recreated index has identical
-- WHERE clause so non-mac_range rows (including the two new types)
-- still stay out of it.
--
-- IF NOT EXISTS on the staging table + new index matches the
-- migration-007 partial-apply hardening pattern.
--
-- Runtime alerting for the two new types depends on the Kismet
-- observation surface carrying ble manufacturer ID + Remote-ID
-- fields. The current src/lynceus/kismet.py adds best-effort
-- population paths with documented field-name uncertainty; rule
-- entries for these types will not fire until the Kismet field
-- paths are confirmed against a live capture. See the CHANGELOG
-- entry for the operator-facing caveat.

PRAGMA foreign_keys = OFF;

BEGIN TRANSACTION;

CREATE TABLE IF NOT EXISTS watchlist_new(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pattern TEXT NOT NULL,
  pattern_type TEXT NOT NULL CHECK(pattern_type IN (
    'mac','oui','ssid','ble_uuid','mac_range',
    'ble_manufacturer_id','drone_id_prefix'
  )),
  severity TEXT NOT NULL CHECK(severity IN ('low','med','high')),
  description TEXT,
  mac_range_prefix TEXT,
  mac_range_prefix_length INTEGER
);

INSERT INTO watchlist_new(
  id, pattern, pattern_type, severity, description,
  mac_range_prefix, mac_range_prefix_length
)
  SELECT id, pattern, pattern_type, severity, description,
         mac_range_prefix, mac_range_prefix_length
  FROM watchlist;

DROP TABLE watchlist;
ALTER TABLE watchlist_new RENAME TO watchlist;

CREATE INDEX IF NOT EXISTS idx_watchlist_mac_range_prefix
  ON watchlist(mac_range_prefix_length, mac_range_prefix)
  WHERE pattern_type = 'mac_range';

COMMIT;

PRAGMA foreign_keys = ON;
