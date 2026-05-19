-- Extend watchlist.pattern_type to admit 'ssid_pattern'.
--
-- Argus's argus_export.csv snapshot at exported_at=2026-05-17T15:53:27Z
-- carries 5 ssid_pattern rows currently dropped at the
-- IDENTIFIER_TYPE_MAP gate in lynceus-import-argus (see
-- docs/ARGUS_RESIDUALS.md, "defer-pending-smoke"). The matcher
-- semantics differ from the existing exact-match 'ssid' pattern_type:
-- case-insensitive substring rather than case-sensitive equality.
--
-- The watchlist_ssid rule's DB-delegation branch is extended in
-- parallel (rules.py, db.py) to dispatch both 'ssid' and 'ssid_pattern'
-- rows under a single rule_type: exact match consulted first, substring
-- fallback if exact misses. Operators see one rule_type; the watchlist
-- DB carries both pattern_types.
--
-- L-RULES-10 (SSID case/whitespace handling for the existing 'ssid'
-- type) remains deferred — case-insensitivity is specifically scoped to
-- the new ssid_pattern matcher, not retroactively applied to ssid.
--
-- This migration mirrors migration 013's shape: it relaxes the CHECK
-- to whitelist the new pattern_type, leaving every other column and
-- the partial index unchanged. No new metadata columns are needed;
-- ssid_pattern stores the substring needle in the existing pattern
-- column.
--
-- SQLite does not support modifying a CHECK constraint via ALTER TABLE,
-- so a full table rebuild is required (SQLite docs §7). PRAGMA
-- foreign_keys=OFF during the rebuild so the inbound FKs from
-- alerts.matched_watchlist_id (ON DELETE SET NULL) and
-- watchlist_metadata.watchlist_id (ON DELETE CASCADE) do not fire
-- during the intermediate DROP TABLE. AUTOINCREMENT ROWIDs are
-- preserved by INSERTing with explicit id. The mac_range_prefix and
-- mac_range_prefix_length columns from migration 011 are carried
-- across verbatim; they remain NULL for ssid_pattern rows.
--
-- The partial index idx_watchlist_mac_range_prefix from migration 011
-- is dropped + recreated as part of the rebuild because the SQL
-- rebuild pattern requires it; the recreated index has identical
-- WHERE clause so ssid_pattern rows stay out of it.
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
