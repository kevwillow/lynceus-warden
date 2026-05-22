-- Extend watchlist.pattern_type to admit 'ble_local_name'.
--
-- Coordinated release boundary: Lynceus admits the new pattern_type
-- BEFORE Argus v1.4.2 ships its IDENTIFIER_TYPE_TO_PATTERN_TYPE
-- promotion, so the consumer-side gate (lynceus-import-argus's
-- IDENTIFIER_TYPE_MAP) starts admitting ``ble_local_name`` rows the
-- moment the Argus side starts emitting them in larger volume.
-- v1.4.1 carries 20 ble_local_name rows that currently 100% drop at
-- our gate -- Flock Safety BLE device names: ``'Penguin'``,
-- ``'FS Ext Battery'``, ``'Flock'``, ``'FLOCK'``, ``'Flock-*'`` shape
-- variants per the v1.4.0 audit + v1.4.1 handoff.
--
-- BLE local names are case-sensitive per Bluetooth Core Spec §4.5.2
-- (Complete Local Name) -- no case folding at write time. Mirrors the
-- SSID convention in ``patterns._normalize_ssid`` (the pass-through
-- branch).
--
-- Equality-shape semantic at the string level. Argus emits exact
-- strings; substring / regex semantics are a separate, deferred work
-- item (the ssid_pattern parallel-track, deferred to v1.4.3+). The
-- runtime rule body equality-matches the canonicalizer's stored form
-- against ``obs.ble_local_name`` (the observation field renamed from
-- ``obs.ble_name`` for symmetry with pattern_type, see kismet.py).
--
-- The Kismet observation surface is already wired: kismet.py harvests
-- ``kismet.device.base.name`` via ``_BLE_NAME_FIELD`` when
-- ``capture.ble_friendly_names`` is enabled. No new config gate; the
-- existing flag covers admission of the field through to the
-- observation namedtuple.
--
-- SQLite does not support modifying a CHECK constraint via ALTER TABLE,
-- so a full table rebuild is required (SQLite docs §7, "Making other
-- kinds of table schema changes"). Mirrors the migration 019 idiom
-- byte-for-byte: PRAGMA foreign_keys=OFF during the rebuild so the
-- inbound FKs from alerts.matched_watchlist_id (ON DELETE SET NULL)
-- and watchlist_metadata.watchlist_id (ON DELETE CASCADE) do not fire
-- during the intermediate DROP TABLE; AUTOINCREMENT ROWIDs preserved
-- by INSERTing with explicit id; mac_range_prefix and
-- mac_range_prefix_length columns from migration 011 carried across
-- verbatim; partial index ``idx_watchlist_mac_range_prefix`` dropped +
-- recreated with identical WHERE clause so non-mac_range rows
-- (including ble_local_name) stay out of it.
--
-- IF NOT EXISTS on the staging table + new index matches the
-- migration-007 partial-apply hardening pattern.

PRAGMA foreign_keys = OFF;

BEGIN TRANSACTION;

CREATE TABLE IF NOT EXISTS watchlist_new(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  pattern TEXT NOT NULL,
  pattern_type TEXT NOT NULL CHECK(pattern_type IN (
    'mac','oui','ssid','ssid_pattern','ble_uuid','mac_range',
    'ble_manufacturer_id','drone_id_prefix','ble_local_name'
  )),
  severity TEXT NOT NULL CHECK(severity IN ('low','med','high')),
  description TEXT,
  mac_range_prefix TEXT,
  mac_range_prefix_length INTEGER
);

INSERT INTO watchlist_new(
  id, pattern, pattern_type, severity, description,
  mac_range_prefix, mac_range_prefix_length
)
  SELECT id, pattern, pattern_type, severity, description,
         mac_range_prefix, mac_range_prefix_length
  FROM watchlist;

DROP TABLE watchlist;
ALTER TABLE watchlist_new RENAME TO watchlist;

CREATE INDEX IF NOT EXISTS idx_watchlist_mac_range_prefix
  ON watchlist(mac_range_prefix_length, mac_range_prefix)
  WHERE pattern_type = 'mac_range';

COMMIT;

PRAGMA foreign_keys = ON;
