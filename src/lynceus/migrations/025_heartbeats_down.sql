-- Reverses 025. Additive table creation, so the down is a clean drop: no
-- other table references `heartbeats`, and its rows are an operational log
-- rather than capture data, so nothing irrecoverable is lost.
DROP INDEX IF EXISTS idx_heartbeats_undelivered;
DROP INDEX IF EXISTS idx_heartbeats_ts;
DROP TABLE IF EXISTS heartbeats;
