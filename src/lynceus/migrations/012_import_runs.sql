-- 012_import_runs.sql — per-import metadata for watchlist staleness signal.
--
-- Surfaces the freshness of the imported Argus corpus. The `# meta:`
-- comment line on every Argus CSV carries an `exported_at` Argus-side
-- timestamp; until this migration, lynceus-import-argus read that line
-- only to validate its prefix and dropped the body. Persisting it
-- closes the "running on months-old data with no indication" gap:
-- the poller logs the age at startup (INFO under threshold, WARNING
-- over), and /settings renders a Watchlist freshness card.
--
-- Column shapes:
-- - imported_at: int UTC seconds at the moment lynceus-import-argus
--   wrote the import. The local clock at write time, NOT the
--   Argus-side timestamp — that's exported_at.
-- - exported_at: int UTC seconds parsed from the CSV's `# meta:`
--   line's `exported_at` field. Nullable: legacy CSVs (pre the
--   `# meta:` line landing in the Argus contract) or malformed
--   meta lines that the parser can't extract a timestamp from
--   land here as NULL. The startup-log + settings-card paths
--   both treat NULL exported_at as "no Argus-side freshness
--   signal" and fall back to imported_at as the rendered age.
-- - source: free-form text identifying the import's origin —
--   absolute path for `--input`, `owner/repo@ref` for
--   `--from-github`. Forensic field, surfaced on /settings only.
-- - record_count: total rows in the imported CSV per the
--   `# meta:` line. Distinct from the rows-that-survived-filters
--   counts (which live in the ImportReport on stdout); this is
--   the canonical Argus-side row count for the export.
--
-- No FK out to watchlist/watchlist_metadata — an import run is a
-- standalone event, not bound to any specific row. Deletes cascade
-- nowhere by design.

CREATE TABLE import_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    imported_at INTEGER NOT NULL,
    exported_at INTEGER,
    source TEXT,
    record_count INTEGER
);

CREATE INDEX idx_import_runs_imported_at ON import_runs(imported_at DESC);
