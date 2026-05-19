-- Reverse of 003_alert_actions.sql.

DROP INDEX IF EXISTS idx_alert_actions_ts;
DROP INDEX IF EXISTS idx_alert_actions_alert_id;
DROP TABLE IF EXISTS alert_actions;
