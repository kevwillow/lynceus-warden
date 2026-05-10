-- Index on captured_at alone for the daily retention prune.
--
-- prune_old_evidence runs DELETE FROM evidence_snapshots WHERE captured_at < ?
-- on every poll tick (gated to once per 24h). The existing
-- (mac, captured_at DESC) index has mac as the leading column and is not
-- usable for an unconstrained range scan, so the prune was a full table
-- scan. Fine at 10K rows; painful at 1M after weeks of operation on a
-- busy site (especially on Pi-class disks).
--
-- IF NOT EXISTS so a partially-applied migration (or operators with a
-- hand-built index of the same name) cannot wedge the next boot.

CREATE INDEX IF NOT EXISTS evidence_captured_at_idx
    ON evidence_snapshots(captured_at);
