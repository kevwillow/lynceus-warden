-- Tier 1 passive metadata capture columns on the devices row.
--
-- probe_ssids: JSON array of strings (e.g. '["MyHome","Starbucks"]'). NULL
--   when capture.probe_ssids is off, or when no probe SSIDs have been
--   observed for this device.
-- ble_name:    BLE friendly name from the GAP advertisement. NULL when
--   capture.ble_friendly_names is off, or when none was advertised.

ALTER TABLE devices ADD COLUMN probe_ssids TEXT;
ALTER TABLE devices ADD COLUMN ble_name TEXT;
