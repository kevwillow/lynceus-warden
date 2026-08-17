-- Reverses 026. Additive table creation, so the down is a clean drop: nothing
-- references `watchful_escalations`, and its rows are a dedup ledger rather
-- than capture data -- the escalation alerts themselves live in `alerts` and
-- are untouched.
--
-- ⚠️ What IS lost is the generation bookkeeping, so an entry sitting in the
-- failed-stamp state at the moment of the rollback becomes able to emit one
-- duplicate escalation again. That is the pre-026 behaviour, which is the
-- correct thing for a rollback to restore.
DROP TABLE IF EXISTS watchful_escalations;
