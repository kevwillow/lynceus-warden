-- Enforce "at most one ACTIVE watchful entry per MAC" in the schema, where it
-- can actually hold. Closes the S9 duplicate-row race.
--
-- The invariant is not new. Migration 018 documented it and
-- `create_watchful_from_alert` has always checked it:
--
--     existing = self.get_active_watchful_recurrence_by_mac(mac)
--     if existing is not None:
--         raise ValueError(...)
--     ...
--     with self._lock, self._conn:
--         INSERT ...
--
-- The SELECT is outside the transaction, so two callers can both read None and
-- both insert. That much is an ordinary check-then-act.
--
-- ⛔ What makes it a SCHEMA problem rather than a locking one: moving the
-- SELECT inside `self._lock` would not fix it. `self._lock` is a
-- `threading.Lock`. The poller, the passive BLE bridge and the web UI are
-- separate PROCESSES holding separate connections to this file -- the bridge
-- opens its own Database by design ("WAL second writer; the poller's connection
-- is never shared"). A per-process lock is not a lock. The only thing all three
-- share is this database, so the invariant has to be stated here.
--
-- ⭐ And a constraint is retroactive in a way a guard is not: it holds for rows
-- already in the table, whatever wrote them, including any duplicates a
-- pre-028 install already accumulated.
--
-- Why it matters more than "a duplicate row". A watchful entry carries its own
-- `snooze_expires_at`, and the poller's suppression gate resolves BY MAC. A
-- second active row the operator cannot see in the UI can therefore suppress
-- that operator's own HIGH alerts for a device they never snoozed -- and the
-- symptom is silence, which is indistinguishable from a quiet RF environment.
--
-- ⚠️ PARTIAL, on `archived_at IS NULL`. A plain UNIQUE(mac) would forbid ever
-- watching a MAC again after archiving one, which breaks the ordinary
-- watch/dismiss/watch-again cycle and would delete the audit history the table
-- is explicitly retained for. `test_archived_rows_do_not_block_a_new_watch` and
-- `test_many_archived_rows_for_one_mac_are_allowed` pin that direction.

-- Existing duplicates must go before the index can be built, or the migration
-- fails on precisely the installs that hit the race it is closing. Keep the
-- OLDEST active row per MAC -- it is the one the operator created first and the
-- one whose id the UI has been showing -- and archive the rest.
--
-- ⚠️ `strftime('%s','now')` and not the row's own timestamps: this IS being
-- archived now, by this migration, and back-dating it to `created_at` would
-- assert an operator action that never happened. Anything auditing the table
-- can tell these apart by the archived_at clustering at the upgrade moment.
UPDATE watchful_recurrence
   SET archived_at = CAST(strftime('%s','now') AS INTEGER)
 WHERE archived_at IS NULL
   AND id NOT IN (
       SELECT MIN(id) FROM watchful_recurrence
        WHERE archived_at IS NULL
        GROUP BY mac
   );

CREATE UNIQUE INDEX IF NOT EXISTS idx_watchful_one_active_per_mac
    ON watchful_recurrence(mac)
    WHERE archived_at IS NULL;
