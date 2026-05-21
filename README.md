# Lynceus - Warden

Personal-use RF security monitoring: passive WiFi/Bluetooth observation, watchlist matching, alerting.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Status: v0.6.0](https://img.shields.io/badge/Status-v0.6.0-blue.svg)](#project-status)
[![Counter-Surveillance](https://img.shields.io/badge/Counter--Surveillance-passive%20only-1f6feb.svg)](#privacy--threat-model)
[![Watching the Watchers](https://img.shields.io/badge/Watching-the%20Watchers-black.svg)](#what-lynceus-does)

> **Project assertions.** Read these first.
>
> - **Passive only.** Lynceus never transmits, probes, injects, or associates. It only reads what Kismet has already heard.
> - **Read-only UI by design.** The web UI surfaces state and never mutates configuration. Read-only is a security boundary, not a missing feature.
> - **No telemetry.** Lynceus does not phone home. The only outbound connection is to the operator-configured ntfy broker.
> - **Probe SSID capture is OFF by default.** Probe SSIDs reveal device WiFi history. Operators opt in explicitly during `lynceus-setup`.

---

## Project status

**Personal-use RF security monitoring tool. v0.6.0.**

This is not a hardened public product. It is a personal project, feature-complete for v0.6.0, with Kali hardware-smoke validation pending. Use it on hardware you control, in a jurisdiction where passive RF observation is legal, and read the source before trusting it with anything.

Test count: **2475 passing on Windows / 2491 expected on Linux** at v0.6.0 (the 16-test delta is POSIX-only `install.sh` + `chmod`-mode tests that skip on non-POSIX hosts). Up from 2434 at v0.5.0, 1215 at v0.4.0-rc4, and 888 at v0.3.0-rc1. A separate diagnostic suite of **22 behavior-dump tests** (`pytest -m diagnostic`) is run pre-push for pre-flight observation and is excluded from the default suite.

## What Lynceus does

Lynceus is a small daemon plus read-only web UI that watches the WiFi and Bluetooth airspace around the operator and flags hardware of interest. It polls a local [Kismet](https://www.kismetwireless.net/) instance for sightings, persists them to SQLite, and matches each sighting against a curated watchlist (MAC addresses, OUIs, MAC ranges, BLE service UUIDs). Matches generate alerts that surface in the web UI and as push notifications via [ntfy](https://ntfy.sh/).

The threat model is simple: detect surveillance-relevant devices in the operator's environment — license-plate readers, body-worn cameras, drones, gunshot-detection nodes, known-bad hacking-tool hardware, AirTag-class trackers, and other RF-emitting equipment that's worth knowing about when it shows up. Lynceus is not a network attack tool, not a tracking tool, and not a substitute for situational awareness.

## Features

- **Argus integration.** Watchlist metadata schema migration, dual-artifact CSV import via `lynceus-import-argus`, optional metadata extension to `lynceus-seed-watchlist` YAML, alert-to-watchlist linkage in the alerts table, and a `/watchlist` UI page that surfaces vendor/category/confidence. Ntfy notification bodies are enriched with vendor and confidence. Per-Argus-record dedup gating (peer-collide + within-import dup) makes a no-op re-import idempotent (1 mutating SQL statement down from 99 against the bundled snapshot); the three-tier highest-severity-wins tiebreak (severity > confidence > CSV order) prevents a low-severity peer from silently downgrading a high-severity sibling.
- **Tier 1 enrichment.** Probe SSID capture (opt-in, off by default), BLE friendly-name capture (on by default — BLE names are publicly broadcast), and an expanded BLE service UUID enrichment dictionary.
- **Operator triage workflow on `/alerts`.** Filter dropdowns for severity, time window (relative buckets plus an absolute `since` / `until` range that now accepts sub-day `YYYY-MM-DDTHH:MM[:SS]` datetime strings in addition to date-only), acknowledged state, search, rule_type, `has_note`, and `has_action` (any alert covered by an active snooze / permanent allowlist / non-archived watchful tracking). Per-alert snooze with operator-pickable durations (`1h / 24h / 7d / 30d / forever`), per-rule_type snooze on `/rules` alongside a per-rule_type fires breakdown that surfaces type-level totals + last-fired + snooze state above the per-rule_name list (lockstep window dropdown), single + bulk acknowledge, a minimum keyboard shortcut set (`/` focus search, `n`/`p` paginate, `?` toggle a non-modal help overlay, `Esc` close help / reset filters), and streaming CSV export at `/alerts.csv` that mirrors the filtered set with full Argus-metadata join + `action_taken` column. `mac_range` parity across the alert-detail "Allowlisted" badge and the `has_action` filter.
- **Watchful snooze (recurrence-aware tracking).** A third snooze surface for MACs that should not page on every sighting but should escalate if they keep showing up. A `/watchful` page lists tracked entries with status / state / window / MAC filters, a recurrence-digest section grouping escalations by ISO week, and per-entry action buttons: dismiss (archive), promote (allowlist + archive atomically), reset (walk back from escalated), investigate (flag + note, keep counting), confirmed-safe (close as benign, no allowlist write). Triage entry-point is the per-row "Watch" button on `/alerts`. A synthetic `watchful_recurrence` rule_type alert at ntfy priority 4 fires on the 4th sighting (1 initial + 3 counted recurrences on a ≥24h gap debounce); unactioned entries auto-archive after 90 days with no observations.
- **Watchlist exploration.** `/watchlist` list page with search (`q`), filters (`pattern_type`, `severity`, `device_category`), and pagination over the full ~22.5k-row corpus. Per-row detail page at `/watchlist/<id>` cross-links to matched alerts and surfaces full Argus provenance (vendor, source URL, source excerpt, FCC ID, geographic scope, first-seen / last-verified timestamps). Streaming CSV export at `/watchlist.csv` covers the filtered set with the full metadata-join column projection.
- **Migration rollback (operator-facing, opt-in destructive flow).** Every shipped DB migration ships a paired `NNN_<name>_down.sql`. The `lynceus-validate rollback --target-version N` subcommand walks the chain in descending order with interactive confirmation (`--yes` for scripted use), reversing pure-CREATE migrations cleanly, ADD-COLUMN migrations via portable table-rebuild, and CHECK-relaxation migrations with informative abort on now-disallowed rows. Migration 010 (`normalize_watchlist_patterns`) is irreversible by design and skipped with a logged WARNING. **Back up your DB before invoking rollback.**
- **Dark mode (theme toggle).** Persistent operator preference via `localStorage`. Theme bootstrap script in the `<head>` resolves the active theme before first paint so navigating between pages never flashes the wrong palette. Toggle lives in the topnav on every page.
- **Ergonomic CLI tooling.** `lynceus-quickstart` (foreground daemon + UI + browser launch for dev/demo), `lynceus-setup` (interactive wizard with Kismet/ntfy probes and optional Argus import), `lynceus-bootstrap-kismet` (Debian/Ubuntu/Kali helper that adds the Kismet apt repo, installs the package, configures capture interfaces, and adds the operator to the `kismet` group — idempotent, the one CLI that's allowed to touch the network), `lynceus-validate` (config preflight + migration rollback subcommand), `lynceus-export-config` (single-file YAML+rules+allowlist bundle for backup / sharing / diffing).
- **Read-only `/settings` page.** Surfaces current capture state with prominent privacy treatment (recording warning when probe-SSID capture is on, privacy-mode indicator when off), Kismet/ntfy connection status, watchlist origin breakdown (Argus / YAML / bundled), and system info (version, DB path, log path). Sensitive values (Kismet API token, ntfy topic) are redacted server-side. **No mutation endpoints.**
- **Release packaging.** `install.sh` and a thin `uninstall.sh` wrapper (Linux only; `--user` / `--system` / `--uninstall` / `--purge` / `--dry-run`), hardened systemd units (`lynceus.service`, `lynceus-ui.service`, `lynceus-refresh.service` + `lynceus-refresh.timer`) with `NoNewPrivileges`, `ProtectSystem=strict`, restricted namespaces, and friends. Canonical XDG-aware DB-path conventions across the codebase. End-to-end fresh-host deployment runbook at [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) and Kali Linux smoke checklist at [docs/KALI_SMOKE_CHECKLIST.md](docs/KALI_SMOKE_CHECKLIST.md).
- **Bundled threat data.** A curated default watchlist (~22,500 Argus rows, exported 2026-05-17) ships in the wheel as package data and is auto-imported on first `lynceus-setup` run. Coverage includes MAC, OUI, MAC ranges, BLE manufacturer IDs, BLE service UUIDs, drone Remote-ID prefixes, and SSID rows (both exact and case-insensitive-substring matches — the bundled `argus_ssid` rule fires on Flock cameras, Penguin trackers, and the FS Ext Battery family out of the box). Refresh from the latest published export with `lynceus-import-argus --from-github`.

## Installation

**Linux (primary supported target).**

```sh
git clone https://github.com/kevwillow/lynceus-warden
cd lynceus-warden
./install.sh --user
```

For production on a dedicated host, install system-wide:

```sh
sudo ./install.sh --system
```

> **Lynceus uses a dedicated Python venv to comply with PEP 668** (the externally-managed-environment policy on Debian/Ubuntu/Kali). The `lynceus-*` commands are exposed via symlinks to the venv binaries; you don't need to activate the venv manually.

`install.sh --user` creates the venv at `~/.local/share/lynceus/.venv` and symlinks the console scripts into `~/.local/bin/`. `install.sh --system` does the same at `/opt/lynceus/.venv` with symlinks under `/usr/local/bin/`. Operators don't need to manage the venv themselves; the symlinks make the `lynceus-*` commands appear on `PATH` transparently. `install.sh` never adds `--break-system-packages` — the venv is the whole point.

The system mode also creates a `lynceus` system user (which owns `/opt/lynceus`), lays down `/etc/lynceus`, `/var/lib/lynceus`, and `/var/log/lynceus`, copies the systemd units into `/etc/systemd/system`, and runs `daemon-reload`. The units are not auto-enabled — that's an explicit step after `lynceus-setup --system`.

Run `./install.sh --help` for the full flag list (`--user`, `--system`, `--uninstall`, `--purge`, `--dry-run`). `--dry-run` works without root and prints the planned commands so operators can preview the install before committing to it.

To reverse an install, pass the matching scope to `--uninstall`:

```sh
./install.sh --uninstall --user             # reverse a --user install
sudo ./install.sh --uninstall --system      # reverse a --system install
```

`--purge` extends `--uninstall` to also delete config / data / state. With `--user` that's `~/.config/lynceus`, `~/.local/share/lynceus`, and `~/.local/state/lynceus` (the latter two contain `lynceus.db` and logs). With `--system` that's `/etc/lynceus` and `/var/lib/lynceus`. Without `--purge`, the install artifacts (venv, symlinks, systemd units) are removed and operator data is preserved.

For convenience, `./uninstall.sh` is a thin wrapper that auto-detects the install scope by looking for the venv marker (`~/.local/share/lynceus/.venv` for `--user`, `/opt/lynceus/.venv` for `--system`) and execs `install.sh --uninstall` with the right flag. Pass `--user` / `--system` explicitly if both are present, or to override the auto-detection. `--purge` and `--dry-run` pass through.

**Do NOT pipe `install.sh` through `curl | bash`.** Lynceus is a security tool. An install method that doesn't let you read the script before running it directly contradicts the project's threat model. If you want a one-liner, write your own — none is shipped.

**macOS.** `pip install -e .` from a clone (or, on PEP-668-managed installs, inside your own venv). The Python tools (`lynceus`, `lynceus-ui`, `lynceus-setup`, `lynceus-quickstart`, `lynceus-seed-watchlist`, `lynceus-import-argus`) all work. There is no systemd integration; use `launchd` if you need a service.

**Windows.** Same as macOS: `pip install -e .` from a clone. Treated as **works for development; production deployment is not supported.** No installer, no service automation, no documentation for running unattended.

### Troubleshooting

- **`install.sh` fails with `python3 -m venv` errors.** Install the venv module via your distro's package manager and re-run:
  - Debian/Ubuntu/Kali: `sudo apt install python3-venv`
  - Fedora/RHEL: `sudo dnf install python3-virtualenv`
  - Arch: ships with `python` (no separate package needed).
- **`lynceus-*` commands not found after install.** Confirm the install's bin directory is on your `PATH`:
  - `--user` install: `~/.local/bin` must be on `PATH`. `install.sh --user` prints a one-liner hint when it isn't.
  - `--system` install: `/usr/local/bin` is on `PATH` for normal login shells; if it isn't, fix your shell profile rather than working around it.

## Getting started

For a step-by-step end-to-end install from a fresh Kali / Debian /
Ubuntu host through working capture + alerting + web UI, see
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md). The runbook covers
prerequisites, install, Kismet bootstrap, configuration,
validation, systemd enablement, and post-install smoke
verification, with a "common issues" section for the operator-
facing failure modes that surface most often.

## Quick start

1. **Install Lynceus.** `./install.sh --user` from a clone.
2. **Install Kismet (if you don't already have it).** On Debian/Ubuntu/Kali, `sudo lynceus-bootstrap-kismet` adds the official Kismet apt repo, installs the `kismet` package, detects Wi-Fi monitor-capable + Bluetooth interfaces, patches `/etc/kismet/kismet_site.conf` (append-only, preserves your edits), and adds you to the `kismet` group. Idempotent; safe to re-run. `install.sh` itself remains offline by design — this helper is the one CLI that handles the network-using install step. On other distros, install Kismet manually per <https://www.kismetwireless.net/packages/> and skip this step. Then log out and back in (so the `kismet` group takes effect), start Kismet (`sudo systemctl start kismet` or foreground `kismet`), open <http://localhost:2501>, set the admin password, and create an API key under `Settings → API Keys` (name `lynceus`, role `readonly`).
3. **Configure Lynceus.** Run `lynceus-setup`. The wizard probes Kismet and ntfy, generates `lynceus.yaml`, auto-locates the API key from `~/.kismet/session.db` (no copy-paste needed in the common case), and prompts explicitly for probe SSID capture with a privacy explanation (off unless you opt in). It also offers to add a Bluetooth capture source (when an `hci*` adapter is detected) and auto-imports the bundled threat data. Press Enter at the ntfy prompt to skip notifications entirely. To refresh the Argus watchlist later, run `lynceus-import-argus --from-github` (or `--input <path-to-csv>` for an air-gapped host).
4. **Run.** For dev/demo, `lynceus-quickstart` launches the daemon, the UI, and a browser tab in the foreground; Ctrl+C shuts it down. For production, `sudo systemctl enable --now lynceus.service lynceus-ui.service`.
5. **Verify.** Open the UI, watch sightings populate, browse `/watchlist` for the bundled threat data, and visit `/settings` to confirm capture state, Kismet/ntfy connectivity, and the watchlist origin breakdown.

## Configuration

`lynceus-setup` is the primary configuration tool. Re-run it with `--reconfigure` to rewrite an existing config; without that flag it refuses to clobber what's already there.

Configuration files live at XDG-aware paths:

- **`--user` install:** `~/.config/lynceus/lynceus.yaml` (or `$XDG_CONFIG_HOME/lynceus/lynceus.yaml`).
- **`--system` install:** `/etc/lynceus/lynceus.yaml`.

Operator-local severity tuning lives alongside the main config in `severity_overrides.yaml`. Vendor overrides, device-category severity bumps, a confidence-downgrade threshold, and the Argus CSV `# meta: schema_version` accept-list (`argus_schema_version_accept_list`, default `["25", "26"]`) all go there; the file is read by `lynceus-import-argus --override-file` so changes propagate at next import.

To check current configuration without editing files, navigate to `/settings` in the web UI. Capture state, watchlist data status, and system info are visible there. The page is read-only — to change settings, run `lynceus-setup --reconfigure`.

## Bundled threat data

Lynceus ships a default watchlist as package data inside the wheel: `src/lynceus/data/default_watchlist.csv`.

- **Source.** Snapshot from [Argus](https://github.com/kevwillow/argus-db), the companion RF-signature project. Lynceus is **not** redistributing the full Argus corpus — what's bundled is a point-in-time snapshot.
- **Coverage.** ~22,500 records (exported 2026-05-17) across `mac`, `oui`, `mac_range`, `ble_manufacturer_id`, `ble_uuid`, `drone_remote_id_prefix`, `ssid`, and `ssid_pattern` identifier types. Categories include `drone`, `alpr`, `gunshot_detect`, `hacking_tool`, and `unknown`. The bundled `argus_ssid` rule fires on Flock-class cameras, Penguin trackers, and the FS Ext Battery family out of the box.
- **First-run.** `lynceus-setup` auto-imports the bundled CSV on first run, so a fresh install has a working watchlist out of the box.
- **Refresh.** When a newer Argus export is available, refresh in place. The single-command path pulls the latest tagged release straight from GitHub:

  ```sh
  lynceus-import-argus --from-github
  ```

  This fetches `exports/argus_export.csv` from the latest release of [`kevwillow/argus-db`](https://github.com/kevwillow/argus-db) and runs the existing import. The pulled artifact is preserved at `<data-dir>/argus-cache/<ref>__argus_export.csv` so each refresh leaves an audit trail. `--db` defaults to the canonical path for the active scope (`~/.local/share/lynceus/lynceus.db` for `--scope user`, `/var/lib/lynceus/lynceus.db` for `--scope system`); pass `--db` to override. Pin a specific ref with `--ref v1.2.3` (tag, branch, or commit), and override the source repo with `--repo OWNER/NAME` if you maintain a fork.

  Air-gapped operators still pass a local file:

  ```sh
  lynceus-import-argus --input <path-to-fresh-argus-export.csv>
  ```

  `--from-github` and `--input` are mutually exclusive; pass exactly one. The importer is idempotent and metadata-aware in both modes — re-running against the same input is safe. `lynceus-import-argus` is the only Lynceus CLI that touches the network; `install.sh` and the daemon stay offline.

- **Auto-refresh (system installs, opt-in).** `install.sh --system` ships `lynceus-refresh.timer` + `lynceus-refresh.service` to `/etc/systemd/system/` but does **not** enable them — the timer is the only Lynceus surface that opts the host into a recurring outbound call, so it stays an explicit operator decision (keeps the `install.sh` offline invariant intact). Once enabled, the timer re-runs `lynceus-import-argus --scope system --from-github` weekly, comfortably faster than the default 30-day staleness threshold so the `/settings` "watchlist stale" badge stays cold:

  ```sh
  # Enable (weekly, default off):
  sudo systemctl enable --now lynceus-refresh.timer

  # Customize cadence — opens a drop-in override:
  sudo systemctl edit lynceus-refresh.timer

  # Disable:
  sudo systemctl disable --now lynceus-refresh.timer
  ```

  Failures (network outage, transient GitHub error) are logged via `journalctl -u lynceus-refresh.service`; the next scheduled fire retries. The oneshot does not `Restart=` — tight retry loops on a sustained outage are worse than a missed window.

## Running Lynceus

**Production (Linux + systemd).** Two services:

- `lynceus.service` — the poller daemon.
- `lynceus-ui.service` — the read-only web UI.

Both units are hardened (`NoNewPrivileges=yes`, `ProtectSystem=strict`, restricted namespaces, etc.) and run as the `lynceus` system user. Logs land under `/var/log/lynceus/`. Database under `/var/lib/lynceus/`.

**Development / demo.** `lynceus-quickstart`. Foreground process group, browser auto-launch, Ctrl+C to shut everything down cleanly. Suitable for hacking on Lynceus or showing somebody what it does. Not suitable for unattended operation.

**CLI surface.**

| Command | Purpose |
| --- | --- |
| `lynceus` | Poller daemon (entry point of `lynceus.service`). |
| `lynceus-ui` | Web UI (entry point of `lynceus-ui.service`). |
| `lynceus-quickstart` | Foreground dev/demo launcher (daemon + UI + browser). |
| `lynceus-setup` | Interactive configuration wizard. |
| `lynceus-seed-watchlist` | Add watchlist entries from a YAML file. |
| `lynceus-import-argus` | Import an Argus CSV export. `--from-github` pulls the latest release from `kevwillow/argus-db`; `--input <path>` reads a local file. `--db` defaults to the canonical scope path. |
| `lynceus-validate` | Config preflight + DB migration rollback. The legacy no-subcommand form runs the read-only config validator; `lynceus-validate rollback --target-version N` reverses applied migrations with an opt-in confirmation flow. |
| `lynceus-bootstrap-kismet` | Debian/Ubuntu/Kali installer for the Kismet apt repo + package + capture-interface configuration. The one CLI that touches the network during install. |
| `lynceus-export-config` | Bundle current config + rules + allowlist into a single YAML for backup / sharing / diffing. |

For at-a-glance configuration and connectivity verification while running, navigate to `/settings` in the web UI. It surfaces capture state, Kismet/ntfy reachability, watchlist origin breakdown, and system info — read-only.

## Privacy / threat model

- **Read-only UI is a security boundary.** All configuration mutations happen out-of-band — `lynceus-setup`, or by editing the YAML directly. Visibility (the `/settings` page) supports operator awareness; mutability would erode the boundary, so it isn't there.
- **Probe SSID capture is OFF by default.** A device's probe SSIDs are the SSIDs it has previously associated with — effectively a partial WiFi history. Capturing them by default would turn Lynceus into a passive surveillance tool aimed at bystanders. The setup wizard prompts explicitly, and `/settings` makes the current state prominent: a "recording" warning when capture is on, a "privacy mode" indicator when it is off.
- **BLE friendly-name capture is ON by default.** BLE friendly names are broadcast publicly with intent; capturing them does not breach any reasonable privacy expectation.
- **GPS in evidence rows is OFF by default and records the OPERATOR's location.** When alert-time evidence capture is enabled, the GPS fix Kismet provides is the **receiver's** location at alert time, not the observed device's. Persisting it would build a high-resolution movement log of the operator. The `evidence_store_gps` config flag is opt-in (default `false`) and is independent of `evidence_capture_enabled`. When enabled, GPS values are retained per `evidence_retention_days` (default 90) along with the rest of the snapshot.
- **Sensitive values are redacted server-side.** The Kismet API token and ntfy topic never appear in `/settings`-rendered HTML. Reduces shoulder-surfing risk and keeps secrets out of the response stream.
- **No outbound telemetry.** Lynceus does not phone home, ship analytics, or report to any external service. The only outbound connection is to the operator-configured ntfy broker.
- **Operator responsibility.** Passive WiFi/Bluetooth observation is legal in most US jurisdictions but rules vary. It is the operator's job to verify what is allowed where they live. Lynceus is not, and will not become, an active-attack tool.

## Architecture

Two-process production deployment, single SQLite database between them.

```
+----------------+   poll    +----------+   write   +-----------+
|   Kismet API   |<----------|  poller  |---------->|  SQLite   |
+----------------+           +----+-----+           +-----+-----+
                                  |                       ^
                                  | rules engine          | read
                                  v                       |
                              +---+----+              +---+-----+
                              |  ntfy  |<-- alerts    |  webui  |
                              +--------+    rendered  | (FastAPI|
                                                      |  Jinja2)|
                                                      +---------+
```

- **Poller** (`lynceus`) — polls the Kismet REST API on a configurable interval, runs the rules engine over each sighting, persists sightings + alerts.
- **Rules engine** — watchlist match (mac / oui / mac_range / ble service uuid / ble manufacturer id / ssid exact / ssid substring / drone remote-id prefix), allowlist suppression, AirTag-class tracker recognition, first-sighting heuristics, watchful recurrence tracking, per-rule_type and per-alert snooze gates.
- **Database** — SQLite, with versioned migrations and a canonical XDG-aware path resolution.
- **Web UI** (`lynceus-ui`) — FastAPI + Jinja2 templates, read-only. Served by uvicorn.
- **Notifier** — ntfy push for matched alerts. Null/recording backends exist for testing.

## License & credits

License: MIT. See [LICENSE](LICENSE).

Built on [Kismet](https://www.kismetwireless.net/) for radio capture and [ntfy](https://ntfy.sh/) for push delivery.


## How I built this

Lynceus-Warden && Argus-db is the result of many long days and longer nights of iterative work across multiple machines — Windows dev boxes for some scraping and analysis work, Linux dev machines and a Linux server for the database, orchestration, and most agent work. The build process spans research, scraping, validation, schema design, license posture, discipline framework, building the web UI and the audit trail that backs every promotion. The substantive growth from a 514-row baseline to over 22,000 active identifiers happened across roughly two weeks of compressed work; the architectural framework that makes those promotions trustworthy took longer.

### Operator-led orchestration

I plan and orchestrate this project myself, using Claude chat as a strategic-planning collaborator, paperclipai as the company orchestration layer, and Claude Code as the execution agent across multiple specialist roles (extraction worker, source worker, validator, database architect, orchestrator). I have final decision authority on everything that lands in this repo. Strategic direction, architectural decisions, source-admission disputes, license posture, schema changes, and discipline-framework evolution are all operator-ratified before they commit.

The AI agents are highly capable executors with substantial scoping autonomy inside the constraints I set. They surface findings, propose decompositions, escalate when something needs ratification, and run extensive verification work I couldn't do at scale manually. But they don't decide canonical contract. I do.

This was not vibe-coded. Argus has 21 documented amendments to its canonical contract and 14 sub-agent rules governing how the build process itself operates. Every active identifier traces back to a verifiable public source via the audit trail. The discipline framework exists precisely because building a surveillance-equipment identification database is the kind of work where "looks roughly right" isn't good enough — provenance, confidence, and false-positive resistance all need to be load-bearing, not afterthoughts.

### Notable technical work

Two areas surfaced data that wasn't otherwise aggregated anywhere queryable:

**Vendor app decompilation.** I downloaded Android APKs of setup and admin apps published by surveillance-equipment vendors (Flock Safety being one substantive example) and analyzed the binaries for embedded identifier patterns — BLE service UUIDs, MAC address prefixes, vendor-specific protocol fields, default device names. Vendor setup apps need to recognize and connect to their own equipment, so they ship with the identifiers needed to do that. Decompiling public app-store binaries surfaced this information directly. This is legal reverse-engineering of publicly-distributed software, but it required actually doing the work rather than waiting for vendors to publish identifier schemas (they don't).

**GitHub researcher-repo aggregation.** Surveillance equipment has been studied by independent researchers for years — drone RID protocol work (alphafox02/DragonSync), cellular intercept detection (EFForg/rayhunter), BLE stalking-tracker research (seemoo-lab/AirGuard), FAA Remote ID database mirrors (jlrjr's wrapper), and more. The data exists across these projects but had never been pulled into a single queryable database with provenance discipline. Argus aggregates it: every identifier traces back to the specific researcher repo, the specific commit, the specific file path, with proper attribution under the original licenses. This is meta-research synthesis rather than primary discovery, but it makes a large amount of distributed researcher work actually usable.

### The discipline framework

The most substantive thing I built isn't the database. It's the framework that makes the database verifiable.

Every active identifier carries source attribution, confidence scoring, source-type classification, and a chain of corroboration. The framework includes hard rules that prevent fabrication (every identifier must trace to a concrete public source), PII discipline (individual-attributed registrations stay held, not promoted), and downstream-consumer protection (downstream scanners receive only high-confidence canonical data). The framework evolved with the work — each substantive amendment is documented with case studies showing what went wrong (or could have gone wrong) and why the rule exists.

Building this with AI tools is what made it possible at the scale and velocity it happened. Building it deliberately, with operator-final-say discipline and a binding correctness framework, is what makes the output trustworthy.

---

## Support the Project

This project was built as a hobby by one person, a couple computers, and a couple of LLMs. It burned through quite a bit of token cost and mass amounts of personal time — but it was worth it. If Lynceus saves you some time or you just think it's cool, consider tossing a few sats my way. No pressure, but coffee and compute aren't free.

- **Star this repo** — it's free and it helps others find the project
- **Submit an issue or PR** — bug reports and feature ideas welcome
- **Crypto donations** — if you're feeling generous:
  - **BTC** — `bc1qmtzjlc2cw2y45nea2jqf4deh946j8mq502zvsw`
  - **BTC (Unstoppable Domain)** — `gurutech.blockchain`
  - **LTC** — `ltc1qf32n038a90ulajlq6zz67r3n2myewpjlj2ej6w`
  - **ETH** — `0x9bf3311c4721fe37f58913dc57c2bf1722dc8a0f`
  - **BCH** — `bitcoincash:qr2l294kuve9cw48u7xek9nklhed066ycvjtj4ymq9`
  - **SOL** — `CuraE8usMpSrAhpY2QiWaQGoBjyJzkSaUNP6kRgAzscU`

- **Contact** — kev@gurutechnology.services
