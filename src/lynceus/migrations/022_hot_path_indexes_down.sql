-- Reverse of 022_hot_path_indexes.sql. Drop both hot-path indexes; the
-- watchlist and devices tables themselves are owned by earlier migrations
-- and are unaffected.

DROP INDEX IF EXISTS idx_watchlist_pattern_type_pattern;
DROP INDEX IF EXISTS idx_devices_last_seen;
