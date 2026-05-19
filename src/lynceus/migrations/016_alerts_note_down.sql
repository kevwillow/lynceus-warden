-- Reverse of 016_alerts_note.sql.
--
-- 016 added note + note_updated_at via two ALTER TABLE ADD COLUMN
-- statements. Portable reverse is a table rebuild (see 005's
-- preamble). Carries the post-015 alerts shape (rule_type +
-- matched_watchlist_id) across the rebuild. Operator triage notes
-- are intentionally dropped — that's the definition of reversing
-- the additive.

PRAGMA foreign_keys = OFF;

BEGIN TRANSACTION;

CREATE TABLE alerts_pre016(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  rule_name TEXT NOT NULL,
  mac TEXT REFERENCES devices(mac),
  message TEXT NOT NULL,
  severity TEXT NOT NULL CHECK(severity IN ('low','med','high')),
  acknowledged INTEGER NOT NULL DEFAULT 0 CHECK(acknowledged IN (0,1)),
  matched_watchlist_id INTEGER REFERENCES watchlist(id) ON DELETE SET NULL,
  rule_type TEXT
);

INSERT INTO alerts_pre016(
  id, ts, rule_name, mac, message, severity, acknowledged,
  matched_watchlist_id, rule_type
)
  SELECT id, ts, rule_name, mac, message, severity, acknowledged,
         matched_watchlist_id, rule_type
  FROM alerts;

DROP TABLE alerts;
ALTER TABLE alerts_pre016 RENAME TO alerts;

CREATE INDEX idx_alerts_ts ON alerts(ts);
CREATE INDEX idx_alerts_unack ON alerts(acknowledged) WHERE acknowledged = 0;

COMMIT;

PRAGMA foreign_keys = ON;
