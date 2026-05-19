-- Reverse of 007_evidence_snapshots.sql.
--
-- Drops the evidence_snapshots table. Operator evidence data
-- (Kismet record snapshots, RSSI history, GPS) is permanently
-- lost — the operator should back up the DB before rolling past
-- this migration if any evidence rows matter. The runner does
-- NOT prompt; the operator is expected to have read the
-- rollback section of docs/CONFIGURATION.md before invoking the
-- rollback CLI.

DROP INDEX IF EXISTS evidence_mac_captured_idx;
DROP INDEX IF EXISTS evidence_alert_id_idx;
DROP TABLE IF EXISTS evidence_snapshots;
