-- mac_range schema support.
--
-- The base v0.3 schema (migration 001) constrained pattern_type to
-- ('mac','oui','ssid','ble_uuid'); mac_range never had a home. The
-- ~17,798 mac_range rows in Argus's live export (snapshot exported_at
-- 2026-05-14T22:34:07Z, ~64.49% /28 + ~35.44% /36) were silently
-- swallowed into the dropped_mac_range counter at the
-- IDENTIFIER_TYPE_MAP gate before they could land in the DB.
--
-- This migration:
--   1. Relaxes the watchlist.pattern_type CHECK to admit 'mac_range'.
--   2. Adds two nibble-precision prefix columns, NULL for every other
--      pattern_type:
--        mac_range_prefix          TEXT     (lowercase hex, no separators)
--        mac_range_prefix_length   INTEGER  (28 or 36 in current emission)
--   3. Creates a partial index on (prefix_length, prefix) WHERE
--      pattern_type = 'mac_range' so the poller's future range-match
--      query (added in the follow-up prompt) hits an index. Partial
--      keeps non-mac_range rows out of the index, saves space, and
--      leaves oui equality lookups completely unaffected.
--
-- SQLite does not support modifying a CHECK constraint via ALTER TABLE,
-- so a full table rebuild is required (SQLite docs §7, "Making other
-- kinds of table schema changes"). PRAGMA foreign_keys=OFF during the
-- rebuild so the inbound FKs from alerts.matched_watchlist_id
-- (ON DELETE SET NULL) and watchlist_metadata.watchlist_id
-- (ON DELETE CASCADE) do not fire during the intermediate DROP TABLE.
-- AUTOINCREMENT ROWIDs are preserved by INSERTing with explicit id.
--
-- IF NOT EXISTS on the staging table + new index matches the
-- migration-007 partial-apply hardening pattern. The broader
-- migration-runner atomicity work (L-MIG-1/7) stays deferred.
--
-- Runtime range-matching (db.resolve_matched_watchlist_id + the poller)
-- intentionally lands in the follow-up prompt — this migration plus the
-- importer extension keep the diff bisect-clean. mac_range rows will
-- appear in the watchlist after this migration but will not yet fire
-- alerts on MACs that fall inside their range.

PRAGMA foreign_keys = OFF;

BEGIN TRANSACTION;

CREATE TABLE IF NOT EXISTS watchlist_new(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pattern TEXT NOT NULL,
  pattern_type TEXT NOT NULL CHECK(pattern_type IN ('mac','oui','ssid','ble_uuid','mac_range')),
  severity TEXT NOT NULL CHECK(severity IN ('low','med','high')),
  description TEXT,
  mac_range_prefix TEXT,
  mac_range_prefix_length INTEGER
);

INSERT INTO watchlist_new(id, pattern, pattern_type, severity, description)
  SELECT id, pattern, pattern_type, severity, description FROM watchlist;

DROP TABLE watchlist;
ALTER TABLE watchlist_new RENAME TO watchlist;

CREATE INDEX IF NOT EXISTS idx_watchlist_mac_range_prefix
  ON watchlist(mac_range_prefix_length, mac_range_prefix)
  WHERE pattern_type = 'mac_range';

COMMIT;

PRAGMA foreign_keys = ON;
