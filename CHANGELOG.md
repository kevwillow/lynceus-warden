# Changelog

All notable changes to this project will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.4.0] - Unreleased

### Security

- **Allowlist suppression of watchlist hits is now audit-logged
  (L-RULES-2).** Previously the allowlist-then-evaluate ordering in
  `poll_once` meant an allowlist entry could silently disable any
  watchlist rule whose pattern overlapped with the allowlisted device
  — anyone with write access to the allowlist file got an undocumented
  watchlist kill-switch with zero log signal. The poll loop now
  re-evaluates rules on the allowlisted-suppression path and emits an
  INFO line per suppressed watchlist hit
  (`Allowlist suppressed watchlist hit: rule=<name> mac=<mac> severity=<sev>`),
  so operators can grep journalctl to review whether their allowlist
  is too permissive. The audit pass costs one extra `evaluate()` call
  per allowlisted observation; allowlists are operator-curated and
  typically small, and the visibility win is worth the cost. Docstrings
  on `poll_once` and `Allowlist.is_allowed` now make the precedence
  ordering explicit so future refactors don't drop the audit signal.
  `new_non_randomized_device` hits are intentionally excluded from the
  audit log — the whole point of allowlisting is to silence the "first
  time we've seen this known device" path, and logging it would just
  mean every allowlisted device gets one INFO line per poll cycle.

- **ntfy topic no longer leaks in notifier logs, wizard summary, or
  probe-failure prints.** The topic is a shared-secret URL path
  component on public ntfy brokers — anyone who knows it can both
  subscribe to alerts and publish forged ones. The webui already
  redacted it via a private helper; three other surfaces still rendered
  it verbatim:
  - **`notify.py`** logged the full POST URL on every network failure
    AND embedded the `requests` exception's `__str__()`, which itself
    typically embeds the URL+topic — so the secret landed in journalctl
    twice per failure (L-NTFY-4).
  - **`lynceus-setup` wizard summary** printed the raw topic to stdout
    at the end of a run, where it lingers in terminal scrollback and
    any tee'd install log (L-NTFY-5).
  - **`probe_ntfy` failure path** returned `str(exc)` verbatim, which
    the wizard then printed; same exception-body-embeds-URL leak as
    `notify.py` (L-NTFY-6).

  All three now route through a new `lynceus.redact` module that
  exposes `redact_ntfy_topic` (the existing webui helper, lifted to a
  shared location and made public) and `redact_topic_in_url` (parses
  the URL, redacts only the final path segment, preserves query and
  fragment). The previously-private `_redact_ntfy_topic` in
  `webui/app.py` is gone; the webui now imports the shared version so
  every surface speaks one consistent redaction shape (`prefix•••suffix`).

  The notifier and the wizard probe now log only the exception type
  name plus the topic-redacted URL on failure; full exception detail
  is reserved for explicit DEBUG operation (mirrors the H-7 discipline
  from `b0879e2`). The trade-off is a small loss of debug context in
  default-INFO journalctl in exchange for a guarantee that the topic
  cannot leak via the warning line — operators who need the full
  exception body can enable DEBUG temporarily.

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

- **Watchlist patterns are now normalized at write time (L-RULES-1,
  L-RULES-11).** Pre-fix, `cli.seed_watchlist` and `cli.import_argus`
  inserted operator-supplied patterns verbatim. The poller normalizes
  its observation MAC to lowercase colon-separated form (and BLE UUIDs
  to lowercase hyphen-separated form) before the equality lookup in
  `db.resolve_matched_watchlist_id`, so a watchlist row stored as
  `"AA:BB:CC:DD:EE:FF"` silently never linked to the alert that fired
  for `"aa:bb:cc:dd:ee:ff"`. The alert was still written (the rules
  engine had already matched the pattern via the in-memory rule), but
  `matched_watchlist_id` landed `NULL` — dropping the entire Argus
  metadata enrichment chain (vendor, confidence, source URL, severity
  hint) that v0.4.0 surfaces on the alert detail page. The bug was
  structural: any seed/import path that didn't happen to use canonical
  lowercase silently broke the Argus integration contract.

  A new `lynceus.patterns.normalize_pattern` helper is now the single
  source of truth for canonical persistent form, called by both the
  YAML seeder and the Argus CSV importer before insert. Accepts the
  separator variants found in the wild (Cisco-dotted MACs, hyphen
  MACs, IEEE-distribution flat-hex OUIs — that last form closes
  L-RULES-11) and rejects anything that can't be coerced. SSIDs pass
  through unchanged (case-sensitive per IEEE 802.11 — L-RULES-10 is a
  separate v0.4.x deferral). Short 16-bit / 32-bit BLE UUIDs are
  rejected rather than silently expanded; the Bluetooth-base
  expansion is a separate fix tracked under the Kismet short-UUID
  hardware finding.

  Migration 010 normalizes pre-existing rows in place: `LOWER` +
  collapse `-`/`.`/space to `:` for `mac`/`oui`, `LOWER` only for
  `ble_uuid` (canonical UUID form keeps hyphens). SSID rows are
  intentionally not touched. Idempotent — re-running on
  already-canonical input is a no-op. Exotic input forms (flat 12-hex
  MACs, dehyphenated 32-hex UUIDs) won't be perfectly normalized by
  the SQL pass but the next seed/import run lands them in canonical
  form via the new helper; chasing perfect SQL-side normalization
  isn't worth the regex/UDF complexity for a corner case.

  `cli.import_argus` reports a new `normalization_failed` counter on
  `ImportReport`, surfaced in the operator-facing summary so silent
  drops are visible at the end of an import run. `cli.seed_watchlist`
  emits a per-rejection WARNING and a single rolling-up summary
  WARNING when any rejections occurred. This matters specifically for
  the Wave G + flock-back data the Argus engineer is about to push —
  fixing pre-push is the right ordering since we don't know how their
  export normalizes patterns.

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
