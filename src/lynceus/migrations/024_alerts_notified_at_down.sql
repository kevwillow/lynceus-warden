-- Reverses 024. SQLite has supported DROP COLUMN since 3.35 (2021-03); the
-- project's other reversible column migrations rely on the same.
--
-- Dropping notified_at returns dedup to keying on row existence, which
-- reinstates Wave 5 Finding 12: a failed notification is silently swallowed
-- for the whole dedup window. Down is for rollback testing, not for running
-- on a deployment you care about.

DROP INDEX IF EXISTS idx_alerts_undelivered;
ALTER TABLE alerts DROP COLUMN notify_attempts;
ALTER TABLE alerts DROP COLUMN notified_at;
