-- Reverse of 021_pattern_type_imei_tac.sql.
--
-- 021 relaxed watchlist.pattern_type CHECK to admit 'imei_tac'. The
-- reverse tightens the CHECK back to the post-020 set. Carries the
-- post-013 columns (mac_range_prefix, mac_range_prefix_length) and
-- the partial index across the rebuild.
--
-- Conditional reverse. If any row with pattern_type='imei_tac'
-- exists, the INSERT raises CHECK constraint failed and the
-- rollback aborts at this step. See 011's down preamble for
-- operator guidance.

PRAGMA foreign_keys = OFF;

BEGIN TRANSACTION;

CREATE TABLE watchlist_pre021(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pattern TEXT NOT NULL,
  pattern_type TEXT NOT NULL CHECK(pattern_type IN (
    'mac','oui','ssid','ssid_pattern','ble_uuid','mac_range',
    'ble_manufacturer_id','drone_id_prefix','ble_local_name'
  )),
  severity TEXT NOT NULL CHECK(severity IN ('low','med','high')),
  description TEXT,
  mac_range_prefix TEXT,
  mac_range_prefix_length INTEGER
);

INSERT INTO watchlist_pre021(
  id, pattern, pattern_type, severity, description,
  mac_range_prefix, mac_range_prefix_length
)
  SELECT id, pattern, pattern_type, severity, description,
         mac_range_prefix, mac_range_prefix_length
  FROM watchlist;

DROP INDEX IF EXISTS idx_watchlist_mac_range_prefix;
DROP TABLE watchlist;
ALTER TABLE watchlist_pre021 RENAME TO watchlist;

CREATE INDEX idx_watchlist_mac_range_prefix
  ON watchlist(mac_range_prefix_length, mac_range_prefix)
  WHERE pattern_type = 'mac_range';

COMMIT;

PRAGMA foreign_keys = ON;
