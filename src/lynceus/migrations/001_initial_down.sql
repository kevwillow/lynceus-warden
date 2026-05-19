-- Reverse of 001_initial.sql.
--
-- Drops the v0.3 base schema in reverse FK-dependency order:
-- alerts and sightings reference devices (and sightings.location_id
-- references locations), watchlist and locations and devices are
-- leaves. Indexes on a dropped table are removed automatically by
-- SQLite, so the explicit DROP INDEX calls are belt-and-suspenders
-- for partially-applied state. PRAGMA foreign_keys=OFF is not
-- strictly required (we drop in dep order), but the runner sets it
-- around every down to keep behaviour uniform with the rebuild
-- migrations.

DROP INDEX IF EXISTS idx_alerts_unack;
DROP INDEX IF EXISTS idx_alerts_ts;
DROP INDEX IF EXISTS idx_sightings_ts;
DROP INDEX IF EXISTS idx_sightings_mac_ts;

DROP TABLE IF EXISTS alerts;
DROP TABLE IF EXISTS watchlist;
DROP TABLE IF EXISTS sightings;
DROP TABLE IF EXISTS locations;
DROP TABLE IF EXISTS devices;
