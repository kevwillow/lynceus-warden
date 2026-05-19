-- Reverse of 008_evidence_captured_at_index.sql. Drop the index;
-- the table itself is owned by migration 007 and unaffected.

DROP INDEX IF EXISTS evidence_captured_at_idx;
