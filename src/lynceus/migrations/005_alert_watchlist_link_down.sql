-- Reverse of 005_alert_watchlist_link.sql.
--
-- 005 added `matched_watchlist_id` to alerts via ALTER TABLE ADD
-- COLUMN. SQLite's ALTER TABLE DROP COLUMN exists from 3.35.0
-- (March 2021), but Debian stable / Ubuntu LTS / Kali rolling all
-- shipped older SQLite for the operator-relevant install window
-- and the project does not pin a SQLite floor in pyproject.toml.
-- The portable reverse is a table rebuild: recreate the pre-005
-- shape, copy across, swap. FK semantics inbound to alerts are
-- preserved by carrying the FROM-side FKs (alerts.mac -> devices)
-- on the rebuilt table.
--
-- PRAGMA foreign_keys=OFF spans the rebuild so the inbound FK
-- from alert_actions.alert_id (added by migration 003) does not
-- fire SET-NULL / CASCADE during the intermediate DROP TABLE.

PRAGMA foreign_keys = OFF;

BEGIN TRANSACTION;

CREATE TABLE alerts_pre005(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  rule_name TEXT NOT NULL,
  mac TEXT REFERENCES devices(mac),
  message TEXT NOT NULL,
  severity TEXT NOT NULL CHECK(severity IN ('low','med','high')),
  acknowledged INTEGER NOT NULL DEFAULT 0 CHECK(acknowledged IN (0,1))
);

INSERT INTO alerts_pre005(id, ts, rule_name, mac, message, severity, acknowledged)
  SELECT id, ts, rule_name, mac, message, severity, acknowledged FROM alerts;

DROP TABLE alerts;
ALTER TABLE alerts_pre005 RENAME TO alerts;

CREATE INDEX idx_alerts_ts ON alerts(ts);
CREATE INDEX idx_alerts_unack ON alerts(acknowledged) WHERE acknowledged = 0;

COMMIT;

PRAGMA foreign_keys = ON;
