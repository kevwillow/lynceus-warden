-- Per-rule_type snooze: temporary, time-bounded suppression of all
-- alerts from a single rule_type. Distinct from the per-alert snooze
-- the allowlist surface implements:
--
--   * Per-alert snooze (existing) writes to allowlist_ui.yaml with
--     pattern_type='mac' and expires_at, scoped to a specific
--     observation (mac/oui/ssid/...). It gates BEFORE rule evaluation
--     against the observation's attributes.
--
--   * Rule_type snooze (this table) gates AFTER rule evaluation, at
--     the alert-emit boundary. The rule still evaluates, /rules
--     statistics still increment, but alert rows are not written for
--     suppressed emits during the snooze window.
--
-- Storage chosen as a dedicated table rather than extending the
-- allowlist's pattern_type enum because the two semantics differ at
-- the gate-ordering layer (pre-evaluation vs post-evaluation) and
-- mixing them would require reasoning about that ordering at every
-- read site. The table is small at steady-state (a handful of rows
-- at most) and the schema overhead is minimal.
--
-- PRIMARY KEY on rule_type: at most one snooze per rule_type at any
-- time. Re-snoozing the same rule_type while a snooze is active uses
-- INSERT OR REPLACE in the helper, so the new expires_at / added_at
-- overwrite the prior values (operator-extension and operator-
-- shortening both work).
--
-- expires_at is forward-bounded (operator-curated allowlist YAML may
-- carry NULL for "permanent", but this table is always time-bounded;
-- permanent suppression belongs in the allowlist or via disabling the
-- rule outright). Expired rows are filtered at gate-check time and
-- physically deleted on poll cycle (cleanup_expired_rule_type_snoozes).
--
-- The expires_at index supports the cleanup DELETE WHERE expires_at
-- <= ? and the list-active WHERE expires_at > ?. PK already covers
-- the per-rule_type point lookup used at gate time.

CREATE TABLE rule_type_snoozes (
    rule_type TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL,
    added_at INTEGER NOT NULL,
    note TEXT
);

CREATE INDEX idx_rule_type_snoozes_expires
    ON rule_type_snoozes(expires_at);
