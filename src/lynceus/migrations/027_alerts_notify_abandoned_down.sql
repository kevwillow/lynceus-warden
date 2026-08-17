-- Reverses 027. SQLite has supported DROP COLUMN since 3.35 (2021-03); 024
-- reverses the sibling delivery columns the same way.
--
-- ⚠️ Dropping this column makes every abandoned escalation count as undelivered
-- again, so the permanent "N alert(s) written but never delivered" line that
-- Finding 50 is about comes back for any entry the operator has reset. That is
-- the pre-027 behaviour, which is what a rollback should restore -- but it is
-- worth knowing that the rollback is visible on the operator's health surface
-- rather than silent.

ALTER TABLE alerts DROP COLUMN notify_abandoned_at;
