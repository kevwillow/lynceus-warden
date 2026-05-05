CREATE TABLE alert_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL REFERENCES alerts(id),
    action TEXT NOT NULL CHECK(action IN ('ack', 'unack')),
    ts INTEGER NOT NULL,
    actor TEXT NOT NULL,
    note TEXT
);

CREATE INDEX idx_alert_actions_alert_id ON alert_actions(alert_id);
CREATE INDEX idx_alert_actions_ts ON alert_actions(ts);
