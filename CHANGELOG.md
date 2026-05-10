# Changelog

All notable changes to this project will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.4.0] - Unreleased

### Added

- **`evidence_snapshots.do_not_publish` column** (migration 009).
  Forward-compat for v0.5.0 public-feed export — no producers or
  consumers in v0.4.0. Defaults to 0; surfaced in
  `db.get_evidence_for_alert` so future consumers can read it
  without a second query. Adding the column now while the table is
  small avoids a destructive migration when v0.5.0 ships.

### Documentation

- **SECURITY.md gains a "Data at rest" section** documenting that
  `lynceus.db` is unencrypted, that `evidence_snapshots` carries the
  most sensitive data Lynceus has shipped (probe SSIDs gated by
  capture toggle, operator GPS gated by `evidence_store_gps`), and
  that the WAL sidecar retains rows after a logical `DELETE`.
  Includes the `PRAGMA wal_checkpoint(TRUNCATE)` recipe for
  operators who need to flush the WAL before a backup or hand-off.
- **CONFIGURATION.md field-reference table now lists the v0.4.0
  evidence knobs** (`evidence_capture_enabled`,
  `evidence_retention_days`, `evidence_store_gps`).

### Performance

- **`captured_at` index for the evidence retention prune.** Migration
  008 adds `evidence_captured_at_idx` so the daily
  `DELETE FROM evidence_snapshots WHERE captured_at < ?` no longer
  falls back to a full table scan. The pre-existing
  `(mac, captured_at DESC)` index leads with `mac` and is not usable
  for an unconstrained range scan; this becomes a real cost on
  Pi-class hardware after weeks of operation on a busy site.

### Fixed

- **Freshly-created user-mode databases are now `chmod 0600` on
  POSIX.** Previously the file landed at the process umask (typically
  `0644` — world-readable on multi-user boxes). System-mode installs
  already get `0640 root:lynceus` from setup; this fix only affects
  user-mode where evidence rows could otherwise be readable by any
  local account. Existing databases keep operator-set modes; the
  chmod runs only on first creation. No-op on Windows.
- **Alert detail page hides the GPS section when stored coordinates
  are non-finite.** Belt-and-suspenders against a pre-H-2 install or
  hand-edited DB row carrying `inf` / `nan`: the OSM URL would
  otherwise render as `mlat=nan&mlon=...&map=18/nan/...` and the
  visible coordinate line would say "nan, 0". The handler now
  zeroes out the GPS context fields and logs a WARNING when it
  detects non-finite values.
- **OpenStreetMap link on the alert detail page now opens in a new
  tab.** Previously had `rel="noopener noreferrer"` but no
  `target="_blank"`, so clicking it navigated the operator off the
  alert page and dropped any pagination/filter context. Now matches
  the watchlist `source_url` link's behaviour.
- **Evidence capture now honors the `capture.probe_ssids` and
  `capture.ble_friendly_names` toggles.** Previously the verbatim
  Kismet record stored in `evidence_snapshots.kismet_record_json`
  bypassed both toggles, so an operator who explicitly disabled probe
  capture still had every probed SSID for every alerting device
  persisted to disk. `capture_evidence` now redacts the record per the
  active `CaptureConfig` before serialization (deep-copy-safe — the
  upstream record is never mutated).
- **`bytes` / `bytearray` fields in Kismet records are now hex-encoded
  in evidence JSON** instead of stringified as a Python repr. Previous
  `default=str` produced ugly tool-hostile blobs like
  `"b'\\xff\\xfe'"`; new custom default emits clean hex (`"fffe"`)
  that round-trips through any JSON consumer.
- **Non-finite floats in Kismet records (`inf`, `nan`) are now
  serialized as `null` in evidence JSON** instead of the non-standard
  `Infinity` / `NaN` tokens. Strict JSON parsers (FOIA-export
  pipelines, journalist tooling) reject those tokens; a single
  Kismet RRD slot carrying a sentinel value used to render the entire
  snapshot non-portable.
- **`raw_record` is no longer attached to `DeviceObservation` when
  evidence capture is disabled.** Each Kismet device record can be
  tens of KB; for poll batches of hundreds of devices that was
  multi-MB of needless retention every tick when the evidence path
  would never consume it. `parse_kismet_device` now takes
  `evidence_capture_enabled`, threaded down from `poll_once` via the
  Kismet client.
- **Capture-failure log line no longer leaks exception body content.**
  `json.dumps` failures can carry offending field values (BLE friendly
  names, SSIDs, vendor strings) in the exception message; logging the
  exception via `%s` echoed those values into journalctl outside
  Lynceus's privacy controls. The WARNING line now includes only the
  exception type name; full traceback is reserved for explicit
  DEBUG-mode operation (`logger.isEnabledFor(logging.DEBUG)` gate).
- **GPS in evidence rows is now opt-in.** The geopoint in a Kismet
  device record is the receiver's GPS fix, not the observed device's,
  so persisting it on every alert was building a high-resolution
  operator-movement log retained for the full
  `evidence_retention_days` window. New config flag
  `evidence_store_gps` (default `false`) gates the GPS columns; when
  off, `gps_lat` / `gps_lon` / `gps_alt` / `gps_captured_at` stay NULL
  even when the Kismet record contains location data.
  - **BREAKING (pre-release):** `evidence_store_gps` defaults to
    `false`. Operators who want GPS in evidence rows must enable it
    explicitly. Existing rows in `evidence_snapshots` from a
    pre-release v0.4.0 still carry whatever GPS values were captured
    at the time; only future captures are gated.

### Added

- **Evidence snapshots table, alert-time capture, retention prune.** When
  an alert fires, lynceus now persists a full evidence snapshot to a new
  `evidence_snapshots` table: the Kismet device record at that moment
  (verbatim JSON), the recent RSSI history pulled from Kismet's signal
  RRD (60-sample minute_vec), and the GPS fix when one is present. This
  is the foundational layer for transparency reporting, FOIA requests,
  journalism use cases, and the v0.4.1 movement-aware alerting that
  needs recent per-device evidence.
  - Schema migration `007_evidence_snapshots.sql` adds the table with
    a foreign key onto `alerts(id) ON DELETE CASCADE` plus
    `(alert_id)` and `(mac, captured_at DESC)` indexes for the
    "recent evidence for this device" lookup pattern.
  - New config knobs `evidence_capture_enabled` (default true; the
    operator off-switch for storage-constrained Pis) and
    `evidence_retention_days` (default 90, validated to [1, 3650]).
  - New `lynceus.evidence` module exports `capture_evidence` and
    `prune_old_evidence`. Capture is wrapped in a broad try/except —
    a malformed Kismet record must never derail the alert path — and
    failures log at WARNING (not ERROR).
  - Daily housekeeping: `maybe_prune_evidence` runs at most once per
    24h from the poll loop, tracked under a new
    `last_evidence_prune_ts` poller-state key.
  - Alert detail page surfaces evidence with RSSI sparkline and GPS link.
    `/alerts/{id}` now renders an Evidence section with the captured
    Kismet record (collapsed `<details>` with pre-formatted JSON), an
    inline SVG sparkline of the 60-sample RSSI history (no external
    chart library — Lynceus stays offline-capable), and an
    OpenStreetMap link for the captured GPS fix when present (not Google
    Maps — privacy posture matters here). Older alerts that predate
    v0.4.0, or alerts where capture was disabled, render a "No evidence
    captured" placeholder.
  - CLI export commands intentionally deferred to a follow-up prompt.

## [0.3.0-rc2] - 2026-05-08

### Fixed

- **Setup wizard crashed on a fresh box during the bundled-watchlist
  import** because the data directory (e.g. `~/.local/share/lynceus`,
  `/var/lib/lynceus`) didn't exist yet, and sqlite refused to open the
  target DB with "unable to open database file". The wizard now creates
  the data and log directories defensively before invoking
  `lynceus-import-argus`.

### Added

- **Bluetooth capture source selection** in `lynceus-setup`. On Linux the
  wizard enumerates `/sys/class/bluetooth/` for `hci*` adapters and, when
  one is present, offers to append it to `kismet_sources` so Tier 1 BLE
  enrichment has a Kismet source to draw on. macOS and Windows print a
  one-line note explaining that BT enumeration is not implemented and
  the operator should configure Kismet's BT source manually.
- **ntfy skip support.** Pressing Enter at the broker URL prompt now
  skips ntfy entirely — empty strings are written for `ntfy_url` and
  `ntfy_topic`, the publish probe is suppressed, and the daemon's
  existing `NullNotifier` fallback handles the empty config gracefully.
  When the URL is set, an empty topic re-prompts (topic is required if
  URL is set).

### Changed

- **Severity-overrides path prompt** now prints an explanation block
  describing what the file does before asking for a path, and validates
  the input with a light heuristic — `na`, `skip`, `none`, and other
  bare alphabetic strings are rejected with "That doesn't look like a
  file path" instead of silently landing in the wrong place.
- **Optional 'additional Argus CSV' prompt has been retired.** It was
  redundant on top of the bundled-watchlist auto-import, and the
  trailing yes/no/path-prompt loop was a frequent source of
  copy-paste-the-wrong-string mistakes. The wizard now closes with a
  one-line hint pointing operators at `lynceus-import-argus --input
  <path>` for later imports.

## [0.3.0-rc1] - 2026-05-08

### Added

- **Argus integration** — first-class support for the Argus surveillance-equipment
  signature dataset:
  - DB schema migration (`004_watchlist_metadata.sql`) adding a
    `watchlist_metadata` table that stores Argus record id, device category,
    confidence, vendor, source attribution, FCC id, geographic scope, and
    verification timestamps alongside each watchlist entry.
  - `lynceus-seed-watchlist` YAML loader extended to accept an optional
    `metadata:` block per entry, persisted into `watchlist_metadata`.
  - New `lynceus-import-argus` CLI for ingesting the Argus dual-artifact CSV
    format (signatures + metadata) into the watchlist + metadata tables.
  - New `/watchlist` web UI with list and detail pages that surface vendor,
    category, confidence, source, and notes.
  - Alert-to-watchlist linkage: alerts now record `matched_watchlist_id`
    (migration `005_alert_watchlist_link.sql`) so triage can carry metadata
    end-to-end from detection through review.
  - Alert UI enriched with the matched watchlist's metadata (vendor, category,
    confidence, source link).
  - ntfy notification body enriched with vendor and confidence so push
    notifications are actionable without opening the UI.
- **Tier 1 passive metadata capture** (migration `006_tier1_capture.sql` adds
  `probe_ssids` and `ble_name` columns on `devices`):
  - WiFi probe-request SSID capture, opt-in via `capture.probe_ssids`,
    **default off** to preserve a privacy-conservative posture out of the box.
  - BLE friendly-name capture from GAP advertisements, default on.
  - Expanded BLE service-UUID enrichment dictionary covering more
    consumer-tracker and accessory profiles.
- **CLI tooling** for getting a fresh install running without hand-editing YAML:
  - `lynceus-quickstart` — dev/demo launcher that brings up the daemon and
    web UI together against a sane default config.
  - `lynceus-setup` — interactive configuration wizard with live Kismet and
    ntfy connection probes, optional Argus dataset import, and a
    first-run auto-import of the bundled default watchlist.
- **Read-only `/settings` page** in the web UI surfacing capture configuration,
  Kismet and ntfy connection status, watchlist origin breakdown, and basic
  system info. Sensitive values (Kismet API token, ntfy topic) are redacted
  server-side. No mutation endpoints — the page is observability only.
- **Release packaging** for first-class Linux deployment:
  - `install.sh` (Linux-only) supporting `--user`, `--system`, `--uninstall`,
    `--purge`, and `--dry-run`.
  - systemd unit files (`lynceus.service`, `lynceus-ui.service`) with a
    hardened sandbox profile (`NoNewPrivileges`, `ProtectSystem`,
    namespace restrictions, and related directives).
- **Bundled default watchlist data**: `src/lynceus/data/default_watchlist.csv`
  ships inside the wheel as package data, and `lynceus-setup` auto-imports
  it on first run so a fresh install boots with a useful baseline.

### Changed

- **DB schema** moved forward three migrations on top of the v0.2 baseline:
  added `watchlist_metadata` (004), added `alerts.matched_watchlist_id`
  with a foreign key to `watchlist` (005), and added the `probe_ssids` and
  `ble_name` capture columns to `devices` (006). Existing v0.2 databases
  upgrade in place.
- **Filesystem paths** — the codebase now follows XDG-aware conventions
  consistently for config, data, and state directories, replacing the
  ad-hoc paths used in v0.2. `--user` installs land under
  `~/.config/lynceus`, `~/.local/share/lynceus`, and `~/.local/state/lynceus`;
  `--system` installs land under `/etc/lynceus`, `/var/lib/lynceus`, and
  `/var/log/lynceus`.
- **Test suite** grew from 437 passing tests at the v0.2 baseline to 888
  passing tests, covering Argus import, tier 1 capture, watchlist metadata
  rendering, the setup wizard, and the install/systemd surface.

## [0.2.0] - 2026-05-04

- Initial tagged release: passive Kismet polling, OUI / SSID / BLE-UUID
  watchlist matching, alerts with allowlist suppression, ntfy push
  notifications, and a read-only FastAPI web UI for alerts, devices, rules,
  and the allowlist. Includes CSRF middleware, bulk-ack, audit trail, the
  `lynceus-seed-watchlist` CLI, and a basic systemd unit.
