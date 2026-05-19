-- Reverse of 013_pattern_type_extension.sql.
--
-- 013 relaxed watchlist.pattern_type CHECK to admit
-- 'ble_manufacturer_id' and 'drone_id_prefix' (on top of 011's
-- 'mac_range'). The reverse tightens the CHECK back to the
-- post-011 / pre-013 set. Carries the post-011 columns
-- (mac_range_prefix, mac_range_prefix_length) and the partial
-- index across the rebuild verbatim.
--
-- Conditional reverse. If any row with pattern_type IN
-- ('ble_manufacturer_id','drone_id_prefix') exists, the INSERT
-- raises CHECK constraint failed and the rollback aborts at
-- this step. See 011's down preamble for operator guidance.

PRAGMA foreign_keys = OFF;

BEGIN TRANSACTION;

CREATE TABLE watchlist_pre013(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pattern TEXT NOT NULL,
  pattern_type TEXT NOT NULL CHECK(pattern_type IN ('mac','oui','ssid','ble_uuid','mac_range')),
  severity TEXT NOT NULL CHECK(severity IN ('low','med','high')),
  description TEXT,
  mac_range_prefix TEXT,
  mac_range_prefix_length INTEGER
);

INSERT INTO watchlist_pre013(
  id, pattern, pattern_type, severity, description,
  mac_range_prefix, mac_range_prefix_length
)
  SELECT id, pattern, pattern_type, severity, description,
         mac_range_prefix, mac_range_prefix_length
  FROM watchlist;

DROP INDEX IF EXISTS idx_watchlist_mac_range_prefix;
DROP TABLE watchlist;
ALTER TABLE watchlist_pre013 RENAME TO watchlist;

CREATE INDEX idx_watchlist_mac_range_prefix
  ON watchlist(mac_range_prefix_length, mac_range_prefix)
  WHERE pattern_type = 'mac_range';

COMMIT;

PRAGMA foreign_keys = ON;
