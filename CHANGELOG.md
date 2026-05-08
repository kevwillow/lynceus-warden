# Changelog

All notable changes to this project will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
