-- Watchful recurrence: backend tracking for the recurrence-aware
-- third snooze surface (alongside the per-alert allowlist snooze
-- and the per-rule_type snooze from migration 017). The operator
-- clicks "watchful snooze" on an alert; the daemon silently tracks
-- every subsequent observation of that MAC, counts distinct
-- sightings under a >=24h-gap debounce, and emits a synthetic
-- `watchful_recurrence` rule_type alert at ntfy priority 4 on the
-- 4th sighting.
--
-- Phase 1 (this migration) implements: schema, DB helpers, the
-- tracking gate in poller.py, escalation emission, and the
-- 90-day quiet-stretch auto-archive. Operator-facing UI -- the
-- /watchful page, POST routes, /alerts triage button -- is
-- Phase 2; entries are created via direct INSERT in tests only
-- for now. See docs/WATCHFUL_SNOOZE_DESIGN.md for the full
-- design rationale.
--
-- Lifecycle is timestamp-derived, not stored in a `state` enum:
--
--   escalated_at IS NULL,     archived_at IS NULL  -> tracking
--   escalated_at IS NOT NULL, archived_at IS NULL  -> escalated
--   archived_at IS NOT NULL                        -> archived
--
-- The audit predicate
--   `escalated_at IS NOT NULL AND archived_at IS NOT NULL`
-- distinguishes "escalated then aged out unaddressed" from
-- "never escalated, archived after 90d quiet". Per OQ-7 we do
-- not introduce a sixth `escalated_then_archived` state.
--
-- snooze_expires_at gates ALERTS ONLY (per OQ-3): it has no
-- housekeeping effect on the row's lifecycle. The 90-day
-- no-observation auto-archive is the sole lifecycle clock for
-- unactioned entries. Two clocks would be coupled state that
-- the operator has to reason about; one is honest.
--
-- last_seen_at updates only on counted sightings (>=24h gap),
-- not on intra-debounce observations. This collapses the design
-- doc's `last_observation_at` + `last_counted_sighting_at` into
-- one column. The consequence: a continuously-nearby device
-- accumulates one sighting per ~24h rather than one total. This
-- is the documented v1 recurrence model.
--
-- sighting_count starts at 1 (per OQ-4): the alert that prompted
-- the watch IS the first sighting; the threshold of 4 means
-- 1 initial + 3 counted recurrences.
--
-- Phase 2 dormant columns (confirmed_safe,
-- flagged_for_investigation, operator_note, reset_count) ship now
-- to avoid a migration 019 when the operator UI lands. They
-- default to inert values and are not read or written by Phase 1
-- code paths. Forward-compat with reset-from-escalated (OQ-8)
-- requires no schema change beyond what is already here.
--
-- Indexes:
--   idx_watchful_recurrence_mac      -- gate lookup at every
--     observation; the `archived_at IS NULL` filter is applied
--     in SQL after the mac point lookup.
--   idx_watchful_recurrence_archived -- supports the
--     housekeeping sweep
--     `WHERE archived_at IS NULL AND last_seen_at < cutoff`
--     and the active/archived filter on Phase 2's /watchful UI.
--
-- No partial-unique index on `mac WHERE archived_at IS NULL`.
-- The "at most one active row per MAC" invariant is enforced
-- in the application layer (Phase 1 tests INSERT one row per
-- MAC; Phase 2's operator-create path will double-check). The
-- alternative -- a partial unique index -- would block Phase 2
-- reset-from-escalated re-creates and would force the helper
-- semantics into uniqueness-aware shapes prematurely.

CREATE TABLE watchful_recurrence(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  mac TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  first_seen_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  sighting_count INTEGER NOT NULL DEFAULT 1,
  snooze_expires_at INTEGER,
  escalated_at INTEGER,
  archived_at INTEGER,
  source_alert_id INTEGER REFERENCES alerts(id),
  matched_watchlist_id INTEGER REFERENCES watchlist(id),
  confirmed_safe INTEGER NOT NULL DEFAULT 0,
  flagged_for_investigation INTEGER NOT NULL DEFAULT 0,
  operator_note TEXT,
  reset_count INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_watchful_recurrence_mac
    ON watchful_recurrence(mac);

CREATE INDEX idx_watchful_recurrence_archived
    ON watchful_recurrence(archived_at);
