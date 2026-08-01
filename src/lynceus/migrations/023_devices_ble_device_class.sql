-- Derived Apple Continuity class for BLE devices, populated only by the
-- passive BLE bridge (src/lynceus/ble_continuity.py). One of
-- 'find_my_separated', 'find_my', 'find_my_paired', 'airpods', 'nearby',
-- 'apple_unknown', or NULL when the advert carried no decodable
-- Continuity message. The three find_my_* values are the three-valued
-- separation state (separated / unknown / near owner).
--
-- This stores a DERIVED LABEL, never raw advertisement content. The
-- payload bytes it was computed from are read inside the bleak callback
-- and discarded there; nothing raw reaches the database.
--
-- Nullable with no default and no backfill: existing rows predate the
-- decoder and genuinely have no class. NULL means "unknown", which is
-- distinct from 'apple_unknown' (an Apple advert whose Continuity message
-- type we did not recognize).
--
-- Kismet-sourced devices keep NULL permanently — the classic-HCI capture
-- path surfaces no advertisement payload to decode.

ALTER TABLE devices ADD COLUMN ble_device_class TEXT;
