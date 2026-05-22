-- Extend watchlist.pattern_type to admit 'imei_tac'.
--
-- Forward-compat structural slot for Argus v1.5.0's mig-0027 CP33
-- identifier_type addition. IMEI TAC (Type Allocation Code, the first
-- 8 digits of an IMEI identifying device make/model) is populated via
-- regulatory channels — there is no Kismet-observable surface for it.
-- v1.5.0 ships 0 imei_tac rows; this migration lands the DB-level
-- admission ahead of v1.5.x backfills so the importer accepts the
-- rows the moment Argus starts emitting them, rather than failing at
-- INSERT with a CHECK constraint error.
--
-- NO matcher, NO device_category default, NO severity default lands
-- in this cycle. Promotion to runtime alerting is deferred until
-- Argus publishes the first concrete TAC corpus and a clear rule
-- semantic emerges (regulatory metadata only, no RF observation).
-- Same posture as icao_24bit_address on the Argus side.
--
-- SQLite does not support modifying a CHECK constraint via ALTER TABLE,
-- so a full table rebuild is required (SQLite docs §7, "Making other
-- kinds of table schema changes"). Mirrors migration 020 byte-for-byte:
-- PRAGMA foreign_keys=OFF during the rebuild so the inbound FKs from
-- alerts.matched_watchlist_id (ON DELETE SET NULL) and
-- watchlist_metadata.watchlist_id (ON DELETE CASCADE) do not fire
-- during the intermediate DROP TABLE; AUTOINCREMENT ROWIDs preserved
-- by INSERTing with explicit id; mac_range_prefix and
-- mac_range_prefix_length columns from migration 011 carried across
-- verbatim; partial index ``idx_watchlist_mac_range_prefix`` dropped +
-- recreated with identical WHERE clause so non-mac_range rows
-- (including imei_tac) stay out of it.
--
-- IF NOT EXISTS on the staging table + new index matches the
-- migration-007 partial-apply hardening pattern.

PRAGMA foreign_keys = OFF;

BEGIN TRANSACTION;

CREATE TABLE IF NOT EXISTS watchlist_new(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pattern TEXT NOT NULL,
  pattern_type TEXT NOT NULL CHECK(pattern_type IN (
    'mac','oui','ssid','ssid_pattern','ble_uuid','mac_range',
    'ble_manufacturer_id','drone_id_prefix','ble_local_name','imei_tac'
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
