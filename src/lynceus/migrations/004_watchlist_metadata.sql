CREATE TABLE watchlist_metadata (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    watchlist_id INTEGER NOT NULL UNIQUE REFERENCES watchlist(id) ON DELETE CASCADE,
    argus_record_id TEXT NOT NULL UNIQUE,
    device_category TEXT NOT NULL,
    confidence INTEGER CHECK (confidence IS NULL OR confidence BETWEEN 0 AND 100),
    vendor TEXT,
    source TEXT,
    source_url TEXT,
    source_excerpt TEXT,
    fcc_id TEXT,
    geographic_scope TEXT,
    first_seen INTEGER,
    last_verified INTEGER,
    notes TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now'))
);
