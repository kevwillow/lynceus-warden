-- Reverse of 020_pattern_type_ble_local_name.sql.
--
-- 020 relaxed watchlist.pattern_type CHECK to admit 'ble_local_name'.
-- The reverse tightens the CHECK back to the post-019 set. Carries
-- the post-013 columns (mac_range_prefix, mac_range_prefix_length)
-- and the partial index across the rebuild.
--
-- Conditional reverse. If any row with pattern_type='ble_local_name'
-- exists, the INSERT raises CHECK constraint failed and the
-- rollback aborts at this step. See 011's down preamble for
-- operator guidance.

PRAGMA foreign_keys = OFF;

BEGIN TRANSACTION;

CREATE TABLE watchlist_pre020(
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

INSERT INTO watchlist_pre020(
  id, pattern, pattern_type, severity, description,
  mac_range_prefix, mac_range_prefix_length
)
  SELECT id, pattern, pattern_type, severity, description,
         mac_range_prefix, mac_range_prefix_length
  FROM watchlist;

DROP INDEX IF EXISTS idx_watchlist_mac_range_prefix;
DROP TABLE watchlist;
ALTER TABLE watchlist_pre020 RENAME TO watchlist;

CREATE INDEX idx_watchlist_mac_range_prefix
  ON watchlist(mac_range_prefix_length, mac_range_prefix)
  WHERE pattern_type = 'mac_range';

COMMIT;

PRAGMA foreign_keys = ON;
