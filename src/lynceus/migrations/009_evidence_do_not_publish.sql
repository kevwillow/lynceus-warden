-- Forward-compat column for v0.5.0's hypothetical public-feed export.
--
-- Default 0 = publishable; 1 = the operator (or a future code path)
-- has marked this row as do-not-publish. v0.4.0 has no producers or
-- consumers of this column — it lands in the schema now so v0.5.0
-- can flip per-row publication without a destructive migration.
-- Adding it later would be cheap-but-not-free; adding it now while
-- the table is small is free.
--
-- IF NOT EXISTS not used: SQLite's ALTER TABLE ADD COLUMN doesn't
-- support it. The migration runner gates re-application via
-- schema_migrations, so this only runs once per DB.

ALTER TABLE evidence_snapshots
    ADD COLUMN do_not_publish INTEGER NOT NULL DEFAULT 0;
