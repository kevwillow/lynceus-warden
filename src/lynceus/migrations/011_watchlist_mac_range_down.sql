-- Reverse of 011_watchlist_mac_range.sql.
--
-- 011 (a) relaxed watchlist.pattern_type CHECK to admit 'mac_range',
-- (b) added two columns (mac_range_prefix, mac_range_prefix_length),
-- and (c) created a partial index keyed off pattern_type='mac_range'.
-- The reverse must tighten the CHECK back to the original v0.3 set
-- and remove the columns and the index.
--
-- Conditional reverse. If any row with pattern_type='mac_range'
-- exists, the rebuild's INSERT ... SELECT will violate the tighter
-- CHECK and SQLite raises CHECK constraint failed. That's the
-- intended behaviour: the operator is told (via the runner's error
-- surface) to either delete those rows manually first (DELETE FROM
-- watchlist WHERE pattern_type='mac_range';) or restore from a
-- backup, then re-run rollback. The rollback runner aborts at this
-- step rather than silently dropping the mac_range rows.
--
-- See 005's preamble for the SQLite-3.35 / Debian-stable rebuild
-- rationale. PRAGMA foreign_keys=OFF spans the rebuild so the
-- inbound FKs from alerts.matched_watchlist_id and
-- watchlist_metadata.watchlist_id do not fire during the
-- intermediate DROP TABLE. AUTOINCREMENT ROWIDs are preserved.

PRAGMA foreign_keys = OFF;

BEGIN TRANSACTION;

CREATE TABLE watchlist_pre011(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pattern TEXT NOT NULL,
  pattern_type TEXT NOT NULL CHECK(pattern_type IN ('mac','oui','ssid','ble_uuid')),
  severity TEXT NOT NULL CHECK(severity IN ('low','med','high')),
  description TEXT
);

-- This INSERT raises CHECK constraint failed if any mac_range rows
-- exist. The transaction rolls back; the runner surfaces the error
-- to the operator. Documented behaviour, see preamble.
INSERT INTO watchlist_pre011(id, pattern, pattern_type, severity, description)
  SELECT id, pattern, pattern_type, severity, description FROM watchlist;

DROP INDEX IF EXISTS idx_watchlist_mac_range_prefix;
DROP TABLE watchlist;
ALTER TABLE watchlist_pre011 RENAME TO watchlist;

COMMIT;

PRAGMA foreign_keys = ON;
