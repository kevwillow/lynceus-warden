-- Generation-keyed record of watchful escalations that were EMITTED.
-- Closes Finding 44.
--
-- The defect this exists for: `_emit_watchful_escalation` writes the alert row
-- and the caller then stamps `watchful_recurrence.escalated_at`. Those are two
-- transactions, so a failure BETWEEN them (sqlite "database is locked" is
-- reachable -- the web UI is a separate process writing this same file) leaves
-- a delivered escalation with no stamp. The next sighting re-takes the
-- first-crossing branch, which is guarded on `escalated_at IS NULL`, and the
-- operator gets a second "this device appears to be following you".
--
-- ⛔ Why the obvious dedup is the UNSAFE direction, and why this needs a table
-- at all. "Skip the write if an escalation alert row already exists for this
-- MAC" would suppress the genuine escalation of a RESET entry:
-- `reset_watchful_recurrence` clears `escalated_at` and the count but leaves
-- the old alert row behind, so a device the operator deliberately restarted
-- watching would never escalate again. Suppression is the direction that hides
-- a follower, which is the one thing this product exists to not do.
--
-- ⭐ The discriminator is the entry GENERATION. `reset_count` is incremented by
-- `reset_watchful_recurrence` and by nothing else, so (entry_id, reset_count)
-- names one watch generation exactly. A reset moves the entry to a generation
-- with no row here, and escalation is available again.
--
-- The UNIQUE constraint is the authority, not an application-layer check: the
-- reservation INSERT and the alert INSERT are one transaction, so
-- "a row exists here for this generation" and "an escalation alert was written
-- for this generation" cannot disagree. That is the whole point -- the previous
-- pair of writes could disagree, and a duplicate is what that disagreement
-- looked like.
--
-- ⚠️ Records EMISSION, not consumption. A crossing suppressed by the
-- `watchful_recurrence` rule_type snooze writes NO alert row and therefore
-- writes NO row here, even though it does stamp `escalated_at`. Reserving there
-- too would make this table claim an alert was emitted when the operator's
-- snooze deliberately stopped it. The two states stay distinguishable, which is
-- the property `test_a_snoozed_escalation_is_consumed_and_never_resurrected`
-- already depends on.
--
-- ⚠️ NOT backfilled, deliberately, and the cost is stated rather than hidden.
-- An install upgrading with an entry ALREADY in the failed-stamp state
-- (`escalated_at IS NULL`, alert row present) has no reservation, so its next
-- crossing still costs the one duplicate this migration exists to prevent --
-- after which the generation is reserved and it cannot recur. Backfilling from
-- `escalated_at IS NOT NULL` would be worse than doing nothing: it cannot
-- distinguish an emitted escalation from a snooze-consumed one, so it would
-- write rows asserting alerts that were never sent, and any future reader of
-- this table would inherit that lie. One bounded duplicate on one upgrade is
-- the cheaper honest option.
--
-- alert_id is nullable and is forensic only -- it links the reservation to the
-- row it reserved. Nothing keys off it; the dedup reads (entry_id, generation).
-- It is set in the same transaction as the alert INSERT, so a NULL here on a
-- committed row would itself be a defect worth seeing.
--
-- No separate index: the UNIQUE constraint creates one on
-- (entry_id, generation), which is exactly the lookup the poller performs.

CREATE TABLE watchful_escalations(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  entry_id INTEGER NOT NULL REFERENCES watchful_recurrence(id),
  generation INTEGER NOT NULL,
  alert_id INTEGER REFERENCES alerts(id),
  created_at INTEGER NOT NULL,
  UNIQUE(entry_id, generation)
);
