-- Reverse of 015_alerts_rule_type.sql.
--
-- 015 added rule_type via ALTER TABLE ADD COLUMN. Portable reverse
-- is a table rebuild (see 005's preamble for the SQLite-3.35 /
-- Debian-stable rationale). Carries the post-005 alerts shape
-- (matched_watchlist_id) across the rebuild.

PRAGMA foreign_keys = OFF;

BEGIN TRANSACTION;

CREATE TABLE alerts_pre015(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  rule_name TEXT NOT NULL,
  mac TEXT REFERENCES devices(mac),
  message TEXT NOT NULL,
  severity TEXT NOT NULL CHECK(severity IN ('low','med','high')),
  acknowledged INTEGER NOT NULL DEFAULT 0 CHECK(acknowledged IN (0,1)),
  matched_watchlist_id INTEGER REFERENCES watchlist(id) ON DELETE SET NULL
);

INSERT INTO alerts_pre015(
  id, ts, rule_name, mac, message, severity, acknowledged,
  matched_watchlist_id
)
  SELECT id, ts, rule_name, mac, message, severity, acknowledged,
         matched_watchlist_id
  FROM alerts;

DROP TABLE alerts;
ALTER TABLE alerts_pre015 RENAME TO alerts;

CREATE INDEX idx_alerts_ts ON alerts(ts);
CREATE INDEX idx_alerts_unack ON alerts(acknowledged) WHERE acknowledged = 0;

COMMIT;

PRAGMA foreign_keys = ON;
