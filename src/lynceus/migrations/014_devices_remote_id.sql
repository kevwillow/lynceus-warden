-- Extend devices.device_type CHECK to admit 'remote_id'.
--
-- The base v0.3 schema (migration 001) constrained device_type to
-- ('wifi','ble','bt_classic'). Kismet's Remote-ID datasource emits
-- device records with a base type currently rejected by
-- kismet._TYPE_MAP — even once that gate is relaxed, the records
-- cannot land in the DB without this CHECK relaxation. Migration
-- 013 admitted 'drone_id_prefix' as a watchlist pattern_type, but
-- the matching observation-side gate (this CHECK plus the
-- _TYPE_MAP extension landing in the same rc5 touch) was the
-- explicit deferred follow-up flagged in 013's preamble and in the
-- rc5 CHANGELOG caveat.
--
-- Naming: 'remote_id' matches the existing lowercase-with-
-- underscores convention used by 'bt_classic'. The watchlist-side
-- pattern_type (migration 013) is 'drone_id_prefix' — the two
-- naming axes are intentionally distinct because the watchlist
-- type names *what is matched* (a serial prefix) whereas the
-- device_type names *what category of device emitted it* (a
-- Remote-ID broadcaster, which is conceptually a peer of wifi /
-- ble / bt_classic at the radio-source layer).
--
-- SQLite does not support modifying a CHECK constraint via
-- ALTER TABLE, so a full table rebuild is required (SQLite docs
-- §7, "Making other kinds of table schema changes"). PRAGMA
-- foreign_keys=OFF during the rebuild so the inbound FKs from
-- sightings.mac and alerts.mac do not fire during the
-- intermediate DROP TABLE. The intermediate INSERT carries all
-- columns explicitly so the additive migration-006 columns
-- (probe_ssids, ble_name) survive the rebuild.
--
-- IF NOT EXISTS on the staging table matches the migration-007
-- partial-apply hardening pattern. The broader migration-runner
-- atomicity work (L-MIG-1/7) stays deferred.
--
-- Runtime alerting against Remote-ID-typed observations still
-- depends on kismet._TYPE_MAP admitting the live Kismet emission
-- string AND _DRONE_ID_PATHS resolving against the live record
-- shape. Both lists ship in the same rc5 commit as defensive
-- best-effort guesses, verified at operator smoke time. See the
-- rc5 CHANGELOG caveat for the residual probe-path follow-up.

PRAGMA foreign_keys = OFF;

BEGIN TRANSACTION;

CREATE TABLE IF NOT EXISTS devices_new(
  mac TEXT PRIMARY KEY,
  device_type TEXT NOT NULL CHECK(device_type IN (
    'wifi','ble','bt_classic','remote_id'
  )),
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  sighting_count INTEGER NOT NULL DEFAULT 0,
  oui_vendor TEXT,
  is_randomized INTEGER NOT NULL CHECK(is_randomized IN (0,1)),
  notes TEXT,
  probe_ssids TEXT,
  ble_name TEXT
);

INSERT INTO devices_new(
  mac, device_type, first_seen, last_seen, sighting_count,
  oui_vendor, is_randomized, notes, probe_ssids, ble_name
)
  SELECT mac, device_type, first_seen, last_seen, sighting_count,
         oui_vendor, is_randomized, notes, probe_ssids, ble_name
  FROM devices;

DROP TABLE devices;
ALTER TABLE devices_new RENAME TO devices;

COMMIT;

PRAGMA foreign_keys = ON;
