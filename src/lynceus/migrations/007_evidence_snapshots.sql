-- Evidence snapshots: one row per fired alert, capturing the Kismet device
-- record at the moment of the alert, the recent RSSI history pulled from
-- Kismet's signal RRD, and (when present) the GPS fix.
--
-- Foundational layer for transparency reporting, FOIA requests, journalism
-- use cases, and the v0.4.1 movement-aware alerting that needs recent
-- evidence per device. The kismet_record_json column stores the full
-- device record verbatim (json.dumps with default=str) so downstream
-- consumers do not need to re-query Kismet.
--
-- The (mac, captured_at DESC) index supports "give me the most recent
-- evidence for this device" lookups in v0.4.1 without a full scan.

CREATE TABLE evidence_snapshots(
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

CREATE INDEX evidence_alert_id_idx ON evidence_snapshots(alert_id);
CREATE INDEX evidence_mac_captured_idx ON evidence_snapshots(mac, captured_at DESC);
