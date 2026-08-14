-- Delivery state for an alert, closing the defect recorded as Wave 5
-- Finding 12 in docs/AUDIT_REGISTER.md.
--
-- ⛔ THE DEFECT. `poll_once` committed the alert row BEFORE attempting
-- delivery, and the dedup gate keyed on that row's EXISTENCE. A send that
-- failed logged a warning and was never retried: the next poll found the row
-- it had just written and skipped the emit path entirely. At the default
-- alert_dedup_window_seconds of 3600, one transient ntfy failure cost a full
-- hour of alerting for that device and rule. Measured with a notifier failing
-- a single poll while the device stayed in range for five: two send attempts,
-- ZERO delivered, never retried.
--
-- That is the product's reason to exist failing on its most likely error.
-- The deployment is mobile, so a data blip is MOST likely exactly when
-- something worth detecting is nearby.
--
-- notified_at: unix seconds when the notifier reported success; NULL means
-- "written but nobody has been told yet". Dedup consults only DELIVERED
-- alerts, so an undelivered one no longer suppresses its own retry.
--
-- notify_attempts: how many delivery attempts this row has had. Bounds the
-- retry loop against a server that is down for the whole window, and gives
-- /settings something honest to show. 0 for rows written before this
-- migration.
--
-- ⚠️ Existing rows are backfilled notified_at = ts, NOT left NULL. They
-- predate delivery tracking and their true state is unknowable; treating
-- them as delivered keeps historical alerts out of a retry queue and out of
-- the "undelivered" count, which is the honest reading of "we do not know
-- and can no longer find out". The alternative would page the operator about
-- every alert the database has ever held the moment they upgrade.

ALTER TABLE alerts ADD COLUMN notified_at INTEGER;
ALTER TABLE alerts ADD COLUMN notify_attempts INTEGER NOT NULL DEFAULT 0;

UPDATE alerts SET notified_at = ts WHERE notified_at IS NULL;

-- Retry lookup: "undelivered alerts in this window", the hot path added by
-- this change. Partial index so it stays small -- in steady state almost
-- every row is delivered and therefore absent from it.
CREATE INDEX IF NOT EXISTS idx_alerts_undelivered
    ON alerts(ts) WHERE notified_at IS NULL;
