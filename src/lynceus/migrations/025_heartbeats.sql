-- Heartbeat / dead-man's switch.
--
-- The remaining hole after migration 024: every OTHER failure mode now alerts,
-- so what is left is the daemon dying or delivery breaking -- and there the
-- operator's only symptom is silence, which is indistinguishable from "nothing
-- is out there". This table makes silence falsifiable.
--
-- The delivery columns deliberately mirror `alerts` (024). Building this on the
-- old fire-and-forget path would inherit exactly the defect 024 fixed: a send
-- that failed would be invisible AND would suppress its own retry. A heartbeat
-- with that defect is worse than no heartbeat, because a missing heartbeat is
-- read as "the daemon is dead" and would send an operator looking at hardware
-- when the real fault was one transient ntfy blip.
--
--   notified_at     NULL = composed but nobody was told. Drives both the retry
--                   and the /settings undelivered count.
--   notify_attempts bounded by NOTIFY_MAX_ATTEMPTS, counted BEFORE the send so
--                   a hung notifier still burns one (same reasoning as 024).
--
-- `healthy` is stored, not derived at read time, because it records what was
-- true when the message was composed. A heartbeat is a statement about a moment
-- and must stay auditable as one.
CREATE TABLE heartbeats (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  healthy INTEGER NOT NULL,
  message TEXT NOT NULL,
  notified_at INTEGER,
  notify_attempts INTEGER NOT NULL DEFAULT 0
);

-- Both hot reads are "the most recent row" and "how many are undelivered".
CREATE INDEX idx_heartbeats_ts ON heartbeats(ts DESC);
CREATE INDEX idx_heartbeats_undelivered ON heartbeats(notified_at, ts DESC);
