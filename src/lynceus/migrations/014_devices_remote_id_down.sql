-- Reverse of 014_devices_remote_id.sql.
--
-- 014 relaxed devices.device_type CHECK to admit 'remote_id'. The
-- reverse tightens the CHECK back to the post-006 set
-- ('wifi','ble','bt_classic'). Carries the post-006 columns
-- (probe_ssids, ble_name) across the rebuild verbatim.
--
-- Conditional reverse. If any row with device_type='remote_id'
-- exists, the INSERT raises CHECK constraint failed and the
-- rollback aborts at this step. The operator must either delete
-- those rows (and any FK-dependent sightings.mac / alerts.mac
-- rows) or restore from backup. See 011's down preamble for the
-- general guidance.

PRAGMA foreign_keys = OFF;

BEGIN TRANSACTION;

CREATE TABLE devices_pre014(
  mac TEXT PRIMARY KEY,
  device_type TEXT NOT NULL CHECK(device_type IN ('wifi','ble','bt_classic')),
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  sighting_count INTEGER NOT NULL DEFAULT 0,
  oui_vendor TEXT,
  is_randomized INTEGER NOT NULL CHECK(is_randomized IN (0,1)),
  notes TEXT,
  probe_ssids TEXT,
  ble_name TEXT
);

INSERT INTO devices_pre014(
  mac, device_type, first_seen, last_seen, sighting_count,
  oui_vendor, is_randomized, notes, probe_ssids, ble_name
)
  SELECT mac, device_type, first_seen, last_seen, sighting_count,
         oui_vendor, is_randomized, notes, probe_ssids, ble_name
  FROM devices;

DROP TABLE devices;
ALTER TABLE devices_pre014 RENAME TO devices;

COMMIT;

PRAGMA foreign_keys = ON;
