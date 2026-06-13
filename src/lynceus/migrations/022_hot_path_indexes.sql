-- Two hot-path indexes proven missing by the C1 diagnostic at Argus scale
-- (~30k watchlist + 30k devices). Both add no columns and change no data;
-- they are plainly reversible (see the paired _down).
--
-- 1. watchlist(pattern_type, pattern) — the simple-equality eval lookup
--    (_lookup_simple_watchlist_match, db.py) runs
--        WHERE pattern_type = ? AND pattern = ?
--    for every non-mac_range pattern type probed per observation
--    (mac / oui / ssid / ble_uuid / ble_manufacturer_id / ble_local_name /
--    drone_id_prefix). With no supporting index each lookup SCANs the whole
--    watchlist; a miss — the common case, since most observed devices are
--    NOT on the watchlist — cannot LIMIT-exit early and pays the full scan,
--    multiplied by the number of pattern types probed per observation.
--    NON-UNIQUE: duplicate (pattern_type, pattern) rows may legitimately
--    exist, so a UNIQUE index could reject valid data / fail to apply.
--    This is a DIFFERENT path from the partial idx_watchlist_mac_range_prefix
--    (migration 011/021), which covers only the mac_range eval and is left
--    untouched.
--
-- 2. devices(last_seen) — the default /devices page (list_devices, db.py)
--    sorts ORDER BY last_seen DESC. With no index SQLite SCANs devices and
--    builds a TEMP B-TREE, materializing and sorting the full table before
--    LIMIT is applied. A single-column last_seen index lets the planner walk
--    the index in reverse and drop the TEMP B-TREE.
--
-- IF NOT EXISTS so a partially-applied migration (or an operator with a
-- hand-built index of the same name) cannot wedge the next boot — matches
-- the migration-008 partial-apply hardening pattern.

CREATE INDEX IF NOT EXISTS idx_watchlist_pattern_type_pattern
    ON watchlist(pattern_type, pattern);

CREATE INDEX IF NOT EXISTS idx_devices_last_seen
    ON devices(last_seen);
