ALTER TABLE alerts
  ADD COLUMN matched_watchlist_id INTEGER
  REFERENCES watchlist(id) ON DELETE SET NULL;
