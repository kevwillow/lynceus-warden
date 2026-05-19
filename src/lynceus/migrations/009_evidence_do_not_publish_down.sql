-- Reverse of 009_evidence_do_not_publish.sql.
--
-- 009 added do_not_publish via ALTER TABLE ADD COLUMN with
-- NOT NULL DEFAULT 0. Portable reverse is a table rebuild (see
-- 005's preamble for rationale). Pre-006 there was no
-- evidence_snapshots table at all; we're inside 007's frame
-- here, so the rebuild restores the post-008 / pre-009 shape:
-- evidence_snapshots + both indexes from 007 and 008.

PRAGMA foreign_keys = OFF;

BEGIN TRANSACTION;

CREATE TABLE evidence_snapshots_pre009(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  alert_id INTEGER NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
  mac TEXT NOT NULL,
  captured_at INTEGER NOT NULL,
  kismet_record_json TEXT NOT NULL,
  rssi_history_json TEXT,
  gps_lat REAL,
  gps_lon REAL,
  gps_alt REAL,
  gps_captured_at INTEGER
);

INSERT INTO evidence_snapshots_pre009(
  id, alert_id, mac, captured_at, kismet_record_json,
  rssi_history_json, gps_lat, gps_lon, gps_alt, gps_captured_at
)
  SELECT id, alert_id, mac, captured_at, kismet_record_json,
         rssi_history_json, gps_lat, gps_lon, gps_alt, gps_captured_at
  FROM evidence_snapshots;

DROP TABLE evidence_snapshots;
ALTER TABLE evidence_snapshots_pre009 RENAME TO evidence_snapshots;

CREATE INDEX evidence_alert_id_idx ON evidence_snapshots(alert_id);
CREATE INDEX evidence_mac_captured_idx ON evidence_snapshots(mac, captured_at DESC);
CREATE INDEX evidence_captured_at_idx ON evidence_snapshots(captured_at);

COMMIT;

PRAGMA foreign_keys = ON;
