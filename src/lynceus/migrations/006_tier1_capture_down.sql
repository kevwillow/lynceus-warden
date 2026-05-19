-- Reverse of 006_tier1_capture.sql.
--
-- 006 added probe_ssids and ble_name via ALTER TABLE ADD COLUMN.
-- Portable reverse is a table rebuild (see 005's preamble for the
-- SQLite-3.35 / Debian-stable rationale). The rebuild preserves
-- the post-005 alerts column shape and the pre-006 devices shape.
-- Operator data in probe_ssids and ble_name is intentionally
-- dropped — that's the definition of reversing the additive.

PRAGMA foreign_keys = OFF;

BEGIN TRANSACTION;

CREATE TABLE devices_pre006(
  mac TEXT PRIMARY KEY,
  device_type TEXT NOT NULL CHECK(device_type IN ('wifi','ble','bt_classic')),
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  sighting_count INTEGER NOT NULL DEFAULT 0,
  oui_vendor TEXT,
  is_randomized INTEGER NOT NULL CHECK(is_randomized IN (0,1)),
  notes TEXT
);

INSERT INTO devices_pre006(
  mac, device_type, first_seen, last_seen, sighting_count,
  oui_vendor, is_randomized, notes
)
  SELECT mac, device_type, first_seen, last_seen, sighting_count,
         oui_vendor, is_randomized, notes
  FROM devices;

DROP TABLE devices;
ALTER TABLE devices_pre006 RENAME TO devices;

COMMIT;

PRAGMA foreign_keys = ON;
