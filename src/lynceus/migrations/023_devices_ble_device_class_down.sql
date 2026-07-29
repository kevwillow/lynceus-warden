-- Reverses 023. SQLite has supported DROP COLUMN since 3.35 (2021-03);
-- the project's other reversible column migrations rely on the same.

ALTER TABLE devices DROP COLUMN ble_device_class;
