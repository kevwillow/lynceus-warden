-- Reverses 028.
--
-- ⚠️ The index is dropped; the duplicate rows 028 archived are NOT resurrected.
-- Un-archiving them would recreate the exact state the index exists to forbid,
-- so a rollback followed by a re-migration would then fail. The archived rows
-- remain, which is the conservative direction: an entry the operator can
-- re-create is recoverable, a suppression they cannot see is not.
--
-- After this runs, "at most one active watchful entry per MAC" is once again
-- enforced only by the application-layer check in
-- `create_watchful_from_alert`, which is per-process and therefore does not
-- hold across the poller / bridge / web UI.

DROP INDEX IF EXISTS idx_watchful_one_active_per_mac;
