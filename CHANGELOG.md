# Changelog

All notable changes to this project will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- **Browser-based `lynceus-setup --web` wizard.** A second frontend
  for the first-run configuration ceremony, fully functional end to
  end. Invoke `lynceus-setup --web` and the command prints a loopback
  URL with a single-use setup token; opening that URL in a browser
  starts a 12-step form that mirrors the interactive CLI flow
  question-for-question (Kismet URL / API key auto-locate + paste /
  probe / source selection / capture privacy / ntfy URL / topic /
  probe / RSSI / severity overrides / alerting + per-rule-type
  enables). Every page validates input through the same `Config`
  constructor the daemon loads from disk, so the wizard can never
  produce a configuration the daemon will refuse. The `/review` page
  renders the validated config with secrets redacted (Kismet API key
  head/tail; ntfy topic head + bullets + tail), and clicking Apply
  runs the same `apply_config` side-effect chain the CLI flow
  executes (write `lynceus.yaml`, scaffold severity overrides,
  create data + log dirs with system-mode permissions, import the
  bundled watchlist, write `rules.yaml` when alerting was enabled).
  Live per-step progress streams to the browser via Server-Sent
  Events while the apply runs; the completion page renders the
  per-step transcript with status icons and offers a Re-run button
  on failure (the chain is idempotent — atomic writes, idempotent
  chowns, per-record-dedup'd bundled import). Clicking Done at the
  end cleanly shuts down the wizard's HTTP server; Ctrl-C in the
  launching terminal is the manual fallback, and a 10-minute
  post-apply grace window auto-exits if the operator walks away
  without clicking Done. Loopback-bound by default on port 8766
  (one above the `lynceus-ui` default 8765 to avoid collision with
  a running dashboard); `--bind 0.0.0.0` is the explicit remote
  opt-out, and `--port` overrides the default. Every route is gated
  on a per-run setup token validated with `secrets.compare_digest`,
  and POST routes reuse the existing CSRF middleware unchanged.
  Probes (Kismet, ntfy) run synchronously in the request and respect
  the existing `--skip-probes` flag, so a flaky network won't hang
  the browser longer than the existing 5-second probe timeout. The
  CLI flow (`lynceus-setup` without `--web`) is unchanged when this
  flag is absent.

### Changed

- **Internal refactor: `lynceus-setup` now drives its file-write chain
  through a new `lynceus.setup` package.** No operator-visible
  behavior change — the wizard's prompts, output lines, exit codes,
  and the `--system` permissions sequence are byte-for-byte identical
  to v0.6.3. The deterministic write+import+chown chain
  (`write_config`, `scaffold_severity_overrides`, `import_bundled_
  watchlist`, the post-import sqlite chown loop) moved out of
  `lynceus.cli.setup` into `lynceus.setup.core.apply_config(...)`,
  which returns an `ApplyReport` (one structured `ApplyStep` per
  phase). The interactive prompt helpers moved alongside into
  `lynceus.setup.prompts`. `lynceus.cli.setup` becomes a thinner CLI
  frontend that builds a validated `Config` from the prompted
  answers and hands it to `apply_config`. Foundation for the
  forthcoming run-once web wizard (Phase 2 of the install-flow webui
  arc) which will plug a different progress sink + a different
  prompt layer into the same core. Known parity gap carried forward:
  the wizard scaffolds `severity_overrides.yaml` but does NOT
  persist `severity_overrides_path` into `lynceus.yaml` — a quirk
  that pre-dates this refactor; flagged here to be revisited when
  Phase 3's persistent admin pages land.

## [0.6.3] - 2026-05-23

### Added

- **Startup banner when running the daemon foreground in a terminal.**
  Direct invocation (`lynceus --config foo.yaml` from a terminal) now
  shows an ASCII-art "LYNCEUS" banner with a dynamic subtitle
  (version, active rule count, interface count, ctrl-c-to-stop hint)
  before the poll loop begins. TTY-gated: under `lynceus-quickstart`
  (which pipes stdout) and under systemd (which captures stdout to
  journalctl) the banner is suppressed and a single
  `Lynceus daemon started, N rules active, watching M interfaces`
  INFO log line goes out instead, so operators grepping
  `journalctl -u lynceus.service` see a clear start marker without
  box-drawing garbage.

### Fixed

- **`lynceus-setup --system` no longer hangs silently after completing.**
  Operators running `sudo lynceus-setup --system` would see the
  wizard's last hint line ("UI will be available at...") and then a
  shell prompt that appeared mixed with that line, with no clear
  "the wizard is done" signal — indistinguishable from a hang. The
  wizard now prints an explicit `Setup complete — exiting.` boundary
  (with a flushed stdout) as its final visible line so the
  end-of-flow handoff is unambiguous. As defensive insurance against
  a separate failure mode, the bundled-watchlist auto-import
  subprocess now has a 120s timeout — if `lynceus-import-argus`
  itself ever hangs (stuck sqlite lock, malformed DB), the wizard
  kills it and surfaces a clear "exceeded timeout (process killed)"
  error instead of waiting forever.

- **`lynceus-bootstrap-kismet --reset-config` clears stale adapter
  entries.** Previously, re-running bootstrap after physically removing
  an adapter left the old `source=<iface>` line in `kismet_site.conf`
  forever — the patcher was append-only by design (to preserve
  operator hand-edits like `:channel_list=...`), and had no way to
  drop a line. The new flag backs up the existing
  `kismet_site.conf` to `kismet_site.conf.bak-<unix-ts>` (so any
  non-source hand-edits like `httpd_*`, `server_name`, `log_prefix`
  survive in the backup, recoverable by `mv` back), then writes a
  fresh file from the current interface detection. Default behaviour
  unchanged — re-runs without the flag still preserve everything.
  The bootstrap script's closing "Next steps" block now ends with a
  one-line tip pointing at `--reset-config` for future re-runs after
  adapter removal, so the flag is discoverable without reading
  `--help` or the changelog. The tip is suppressed when the operator
  has just used `--reset-config` (the existing "previous
  kismet_site.conf was backed up to ..." note already covers it).

## [0.6.2] - 2026-05-22

### Added

- **Argus `schema_version=27` now accepted silently.** Argus v1.5.0
  bumps the schema version to 27. The importer's accept-list (added
  in v0.6.1) grows to cover `25 / 26 / 27`, so v1.5.0 exports import
  without tripping the "unknown schema version" warning. Other values
  still warn; the warn-don't-abort posture is unchanged.

- **Forward-compat slot for `imei_tac` identifier_type.** Argus v1.5.0
  adds `imei_tac` (IMEI Type Allocation Code — the first 8 digits of
  an IMEI, populated via regulatory channels) as a new
  identifier_type. It ships at 0 rows initially, with backfills
  arriving in v1.5.x. Migration 021 admits `imei_tac` in the
  watchlist `pattern_type` CHECK and the importer's identifier-type
  map gains the matching entry. Without the migration, the first
  v1.5.x backfill would fail the SQLite CHECK on INSERT. Runtime
  alerting on `imei_tac` is deferred — there is no Kismet-observable
  surface for IMEI TAC values, so no matcher, no `device_category`
  default, and no severity default land in this release. Once Argus
  publishes a concrete TAC corpus, runtime alerting can be wired up;
  same posture as `icao_24bit_address`.

## [0.6.1] - 2026-05-22

### Fixed

- **`lynceus-bootstrap-kismet --skip-install` now works on every Linux
  distro.** Previously the flag only worked on Debian, Ubuntu, and Kali.
  Operators on Mint, Parrot, Devuan, etc. saw an "unsupported distro"
  message and the script exited without doing anything — even though
  `--skip-install` was meant to say "I'll install Kismet myself, just do
  the rest." The flag now does what it says: configure the interface,
  patch `kismet_site.conf`, and add you to the `kismet` group, on any
  Linux host.

- **Bootstrap finds Kismet's config no matter how it was installed.**
  Apt installs put the config at `/etc/kismet/`; from-source builds use
  `/usr/local/etc/kismet/`. The script now checks both locations. If
  neither exists (Kismet not installed yet), it prints a clear message
  instead of writing to a guessed path.

- **Bootstrap's closing hints match what actually ran.** The "what to
  do next" message used to be identical regardless of whether Kismet
  got installed, was skipped, or hit a snag. It now adapts to the
  outcome.

- **Raspberry Pi OS regression guard.** Pi is the main deployment
  target but had no test pinning its OS detection. Added one. Pi OS
  Bookworm continues to work (it identifies as Debian Bookworm); the
  test catches any future change that would silently break Pi
  deployments.

- **`install.sh` now walks you through the next steps.** The old
  two-line hint left fresh operators wondering what to do. Install now
  ends with a numbered Next Steps block: install Kismet (three paths
  depending on your distro and whether you already have it), log out
  and back in, start Kismet, set the admin password, create an API
  key, configure Lynceus, run. Adapts to `--user` vs `--system`. Points
  to `docs/DEPLOYMENT.md` for the full runbook and `docs/SMOKE.md` for
  post-install verification.

### Added

- **Detect Flock Safety devices by their Bluetooth name.** Lynceus can
  now watch for specific BLE device names (the "Complete Local Name"
  from the Bluetooth spec) — useful for Flock devices that broadcast
  names like `Penguin`, `FS Ext Battery`, `Flock`, `FLOCK`, and
  `Flock-*` variants. This bumps Flock detection from 3 watchlist rows
  to 20 — a 6.7× yield jump for the most operationally relevant
  target. Names match case-sensitively and exactly (wildcards are
  planned for a later release). Surfaces in the watchlist filter
  dropdown, the `/allowlist` add-form, the setup wizard (now 8
  delegation rules), and a commented-out template in
  `config/rules.yaml` (off by default for privacy). Requires
  `capture.ble_friendly_names: true` in `lynceus.yaml` to fire —
  without it, BLE names aren't captured at all.

- **Placeholder severity setting for automotive telematics.** Argus
  v1.4.1 added an `automotive_telematics` device category but hasn't
  shipped any rows in it yet (coming in v1.4.2). The setup wizard now
  seeds a commented example so the category shows up in your config
  when the data arrives. No runtime change.

- **Warning if an Argus export's schema version is unexpected.** The
  importer now checks the `schema_version` in incoming Argus CSV
  exports against an accept-list (default: versions 25 and 26).
  Unknown versions print a warning but the import still proceeds —
  preserves backward compat for old exports. Tunable in
  `severity_overrides.yaml`; set to `null` or `[]` to disable. Old
  exports that don't carry a `schema_version` field pass silently.

## [0.6.0] - 2026-05-21

Release status: This release has not yet been validated against real
Kismet + ntfy + systemd on Linux hardware. The test suite covers 2475
tests on Windows / 2491 on Linux at this commit, plus 22 diagnostic
tests. Functional correctness is asserted by tests; deployment
behavior is documented in `docs/DEPLOYMENT.md` and
`docs/KALI_SMOKE_CHECKLIST.md` but unsmoked at this tag. If you hit
issues, file via the project tracker with browser + Python version +
relevant journalctl excerpt. The most likely class of bugs is
UI-related — the new `/alerts` keyboard-shortcut JS in particular has
lighter coverage by its nature.

### Added

- **Keyboard shortcuts on `/alerts`.** Triage the alert queue without
  reaching for the mouse:

  - `/` — focus the search bar
  - `n` — next page
  - `p` — previous page
  - `?` — toggle a help panel listing all shortcuts
  - `Esc` — close the help panel, or reset filters if the panel is
    already closed

  Shortcuts don't fire while you're typing in a text field (so `/` and
  `?` land as characters in the search box) or when you're holding
  Ctrl / Cmd / Alt (so OS and browser shortcuts still win). The page
  remains fully usable with JavaScript disabled — every shortcut has a
  mouse equivalent. A small "Press `?` for keyboard shortcuts" hint
  sits near the page counter for discoverability. Scope is `/alerts`
  only for now; other pages to follow. Row-selection shortcuts
  (`j` / `k` / `a` / `Enter`) are deferred — they need a selected-row
  UI primitive that doesn't exist yet.

- **Hour-and-minute precision on `/alerts` date filters.** You can now
  filter by something like "Tuesday 14:00 to Wednesday 09:00" directly
  in the filter bar. Previously only whole days worked, which
  overstated any sub-day window. Date pickers swap from date-only to
  datetime-local; times are interpreted as UTC (no timezone config —
  single-operator deployment, you do the mental math, same as
  everywhere else in the UI). Old date-only bookmarks still work:
  `since=YYYY-MM-DD` becomes midnight UTC, `until=YYYY-MM-DD` becomes
  23:59:59 UTC, exactly as before. Malformed input is silently
  ignored (lands you on the unfiltered page) rather than throwing an
  error. No schema changes, no migration.

- **Per-rule-type fire counts on `/rules`.** The page already showed
  fire counts per rule name, but you had to add them up by hand to get
  type-level totals like "all `watchlist_mac` fires in the last 24h."
  A new summary section shows this directly, with inline snooze
  controls so you can snooze an entire rule type from the type-level
  view. The same time window controls both summary and detail list.
  Sorted by fire count, highest first; types with zero fires in the
  window still appear so their snooze controls stay reachable.

### Fixed

- **Re-importing the same Argus CSV no longer fakes "new" or
  "updated" entries.** Before this fix, re-importing the bundled
  Argus CSV against an already-populated database falsely reported
  31 "new" + 21 "updated" rows (out of 22,533 input rows) and ran 99
  unnecessary SQL writes — even though nothing in the source had
  actually changed. Two distinct duplicate shapes in the upstream
  Argus data caused this; both are now caught at import time. A
  no-op re-import now produces exactly 1 SQL write (the import-run
  log entry).

  As a side benefit, when duplicates do exist in the source CSV, the
  importer now picks the highest-severity entry instead of whichever
  appeared first in the file. The motivating case was a Flock Safety
  row pair where the first-in-file entry would have been flagged
  `low` and the second `med` — previously the `low` entry silently
  won; now the `med` one does. Counter math now balances cleanly:
  `imported_new + dropped_peer_collision + dropped_in_import_dup +
  dropped_unknown_type = total_input_rows`.

  Two new counters (`dropped_peer_collision` and
  `dropped_in_import_dup`) appear in import reports. No schema
  changes, no migration — existing databases with thrashed timestamps
  need nothing; the next import is idempotent against them.

## [0.5.0] - 2026-05-20

Release status: This release has not yet been validated against real Kismet + ntfy + systemd on Linux hardware. The test suite covers 2434 tests on Windows / 2450 on Linux at this commit, plus 21 diagnostic tests. Functional correctness is asserted by tests; deployment behavior is documented in `docs/DEPLOYMENT.md` and `docs/KALI_SMOKE_CHECKLIST.md` but unsmoked at this tag. If you hit issues, file via the project tracker with browser + Python version + relevant journalctl excerpt. The most likely class of bugs is UI-related — the keyboard-shortcut JS and the operator-facing templates have lighter coverage by their nature.

### Added

- **Clearer filtered indicator on `/alerts`, plus `Esc` to reset.** The bare "reset filters" link is replaced with a single summary that names which filters are active and their values, e.g. `Filtered by: severity=high, since=2026-05-01, q=apple -- reset filters (or press Esc)`. No more scanning the form to figure out why a result count is narrow. Pressing `Esc` resets filters, with an input-focus guard so typing into the search box is unaffected. First keyboard shortcut on the webui; scoped to `/alerts` only. The watchful / watchlist / allowlist pages keep their existing bare-link rendering.

- **`docs/DEPLOYMENT.md` — end-to-end install runbook.** Walks a fresh Kali / Debian / Ubuntu host through prerequisites, clone + install, Kismet bootstrap, API key creation, `lynceus-setup`, optional Argus refresh, `lynceus-validate` preflight, systemd enable (system install) or `lynceus-quickstart` foreground (dev/demo), and smoke verification. Each step carries action + expected output + brief explanation, so you can paste and tell whether it worked. A "Common issues" section covers the five failure modes that surface most often: Kismet API key auto-detect, PATH not picking up `lynceus-*`, adapter not in monitor mode, ntfy topic mismatch, and systemd unit permission-denied. README gains a "Getting started" link to the new runbook.

- **Migration rollback via `lynceus-validate rollback --target-version N`.** Every shipped DB migration (001..019) now ships a paired down-file, and the new subcommand walks the applied chain in descending order to undo them. Defaults to the canonical DB path for `--scope user|system`; `--db PATH` overrides for off-canonical installs or copies. Interactive runs prompt for an explicit `yes`; scripted use requires `--yes`. The legacy `lynceus-validate --scope user` invocation is preserved verbatim for existing scripts. Most migrations reverse cleanly. CHECK-relaxation migrations (011, 013, 014, 019) abort with `CHECK constraint failed` if rows of the now-disallowed type exist — delete them or restore from backup, then re-run. Migration 010 (watchlist-pattern normalization) is IRREVERSIBLE; the runner logs a WARNING, marks it un-applied so the chain can continue, and runs no SQL. **BACK UP YOUR DB BEFORE INVOKING ROLLBACK.** See [`docs/CONFIGURATION.md` §Database migration rollback](docs/CONFIGURATION.md#database-migration-rollback) for the full flow.

- **`/watchlist.csv` — streaming CSV export of the filtered watchlist.** Sibling of `/alerts.csv`. "Export CSV" link sits next to the pagination summary on `/watchlist`; the href carries the current filter query string (pattern_type, severity, device_category, q). Pagination is bypassed — the export covers every matching row, up to the full ~22k-row Argus corpus. Filename: `watchlist-YYYYMMDDTHHMMSSZ.csv` (ISO UTC, sorts lexicographically). Column projection is wider than the list page: surfaces the full Argus provenance you'd otherwise click through to per-row (`argus_record_id`, `device_category`, `confidence`, `vendor`, `source`, `source_url`, `source_excerpt`, `fcc_id`, `geographic_scope`, `first_seen`, `last_verified`, `notes`) plus the row itself. YAML-seeded rows without Argus metadata export with empty cells in the metadata columns. Streamed; no row cap. Invalid filter values silently fall back to "all" (matches the list route); `q` capped at 100 chars.

- **`/alerts.csv` — streaming CSV export of the filtered alerts.** "Export CSV" link next to the pagination summary on `/alerts`. The href carries the current query string, so the download mirrors the visible filter state exactly (severity, acknowledged, since/until, search, rule_type, q, window, has_note, has_action). Pagination is bypassed. Filename: `alerts-YYYYMMDDTHHMMSSZ.csv`. Column order is stable and parser-friendly, with both watchlist and Argus-provenance join fields surfaced so you get vendor / confidence / category offline without clicking through. Streamed; no row cap. Invalid severity still 400s; other invalid filter values silent-fall-back to "all". No CSRF (GET-only).

- **`/alerts` `has_action` filter: triage-state-aware dropdown.** `any / with action taken / without action taken`, default `any`, alongside the existing `has_note`. An alert counts as "actioned" if any of three signals applies: a per-alert snooze (active entry in `allowlist_ui.yaml`), a permanent allowlist match (active entry in `allowlist.yaml`), or watchful tracking (the alert's MAC has a non-archived watchful row). The watchful signal is mac-scoped — every alert from a MAC under an active watchful entry inherits the actioned status, matching the actual suppression effect. Expired snoozes are skipped. Rule-type snoozes are intentionally NOT in scope (that surface is system-wide, not per-alert). Notes are also out of scope — combine with `has_note` for workflows like `?has_action=with_action&has_note=without_note` ("actioned but unannotated"). Composes with every existing filter; pagination counts honor it; bulk-ack via `/alerts/ack-all-visible` mirrors it cleanly. Allowlist YAML loads are lazy — only when `has_action` is engaged — so the default `/alerts` page stays YAML-cost-free. Pattern types other than `mac` and `oui` are out of scope here (see the `mac_range` parity bullet below for the follow-up).

- **Per-alert snooze: operator-pickable duration.** The snooze form on the alert detail page grows a duration selector: `1h / 24h / 7d / 30d / forever`, replacing the bare "Snooze for 24h" button. Default stays `24h`, and a form submission without a duration produces the same `expires_at` and provenance note as before, so existing links / scripts behave identically. `1h` is new and lives on per-alert snooze only ("shut up about this for an hour while I look into it"); the watchful triage selector stays at four options since 1h doesn't fit recurrence-tracking semantics. The `forever` option writes a NULL `expires_at` but records distinct provenance (`"snoozed forever via webui"`) so you can tell from `allowlist_ui.yaml` which surface produced the entry. Unknown duration values return 400 with no YAML side-effect. CSRF and the `confirm()` safety prompt are unchanged.

- **Per-rule_type snooze.** New `rule_type_snoozes` table (migration 017) lets you silence all alerts from a specific rule_type for a bounded window (`1h / 4h / 24h / 7d / 30d`). Controls live on `/rules` per row: rule_types without an active snooze get a collapsible "snooze..." form with a duration dropdown and optional note; snoozed ones get a badge (expiry rendered relative and absolute in the tooltip), the note, and an "unsnooze" button. A new `status=all|snoozed|active` filter on the page lets you narrow to "what's currently silenced?". Distinct from per-alert snooze: rule-type snooze mutes the whole rule class at the alert-emit boundary — the rule still evaluates, but DB write, evidence capture, and ntfy emit are all gated during the window (the operator's whole point in snoozing is "don't page me"). Expired snoozes are filtered at gate-check time and physically deleted on the poller cycle. A periodic INFO line in the daemon — `rule_type snooze suppressed N alert(s) in last ~Ts: <breakdown>` — surfaces suppression counts to `journalctl` so you can confirm it's doing its job beyond the badge. Re-snoozing an active rule_type overwrites the prior expiry (no need to unsnooze first).

- **Watchful snooze — backend.** Recurrence-aware third snooze surface; the daemon-side machinery lands first, UI follows in the next bullets. New `watchful_recurrence` table (migration 018) tracks per-MAC observations under watchful snooze, counts sightings on a >=24h gap debounce, and emits a synthetic `watchful_recurrence` rule_type alert at ntfy priority 4 on the 4th sighting (1 initial + 3 counted recurrences). A 90-day no-observation auto-archive runs on the poller cycle (alongside rule_type snooze and evidence-prune housekeeping). Gate ordering is allowlist -> watchful -> rule eval -> rule_type snooze -> per-alert snooze -> emit, so allowlist precedence wins: an allowlisted MAC under watchful snooze sees no sighting count increment and no escalation alert. Severity stays `high` for `/alerts` and `/rules` rendering; only the ntfy priority drops to 4 for the scare-factor mitigation. With no entries in the table, poll cycles are byte-identical to pre-feature behavior.

- **Watchful snooze — operator actions.** HTTP-and-DB plumbing for the five operator actions on watchful entries, plus the triage entry-point from `/alerts`. CSRF-protected throughout. Routes: `/alerts/{id}/watch` to start watching from the alert list, and `/watchful/{id}/{dismiss,promote,reset,investigate,confirm-safe}` for the action surface. All return 303 redirects, validate snooze duration against `{forever, 24h, 7d, 30d}`, cap operator notes at 4096 chars, and return 400 for stateful preconditions. The auto-archive sweep coexists cleanly with operator-driven archives. `promote` writes to `allowlist.yaml` and archives atomically (YAML first, DB second, best-effort YAML rollback on race). `confirm-safe` archives but does NOT create an allowlist entry — the operator's signal is "this entry is benign", not "never alert me on this MAC again". No schema change.

- **Watchful snooze — UI.** Closes the loop. New `/watchful` page lists tracked devices with filter (status / state / window / MAC substring), pagination (25 / 50 / 100 / 200; default 50), per-entry action buttons, and a recurrence-digest section. A new `/watchful/<id>` detail page mirrors `/alerts/<id>` with full state, cross-links to source alert / matched watchlist row / device record, and the same action panel. Topnav gains `/watchful` between `/alerts` and `/devices`. `/alerts` grows a per-row "Watch" button (`24h / 7d / 30d / forever`, default `30d`) that posts to the triage route. All five action POSTs redirect to `/watchful?success=<token>` so you stay in context and see a banner per the `/rules` flash convention. Action visibility honors the state guard: reset only on escalated entries; archived entries are read-only. Promote (red, "never alert me on this MAC again") and confirmed-safe (green, "close as benign") are visually distinct — conflating them would silently break the threat-model intuition. The recurrence digest is a section on `/watchful` (not a separately-emitted notification): groups escalations from the last 8 ISO weeks, most recent first. Copy stays non-alarmist: "watchful", "recurrence", "sighting", "tracked device" rather than "threat" / "intrusion" / "danger".

- **SSID dimension activated end-to-end.** Three changes land together. The `watchlist_ssid` rule type is unchanged on the operator-facing surface, but its DB-delegation mode now dispatches both exact-match and substring patterns from one rule, the bundled `argus_ssid` rule is enabled by default, and the bundled `default_watchlist.csv` is refreshed from the 2026-05-17 Argus snapshot so fresh installs alert on Flock-class equipment out of the box.

  Migration 019 admits `ssid_pattern` in the watchlist `pattern_type` CHECK. A new substring matcher (case-insensitive) joins the existing exact-match path: exact is consulted first, substring falls back on miss; severity flows from whichever DB row fires.

  `lynceus-import-argus` learns the `ssid_pattern` identifier. The 5 ssid_pattern rows from the Argus snapshot (`flock`, `Flock`, `FLOCK`, `FS Ext Battery`, `Penguin`) flow into the watchlist at the `device_category`-derived severity. Rows whose `ssid_exact` value contains a literal `*` (e.g. Argus's `Flock-*` row) log a WARNING and are imported anyway — the `*` never matches a real WiFi observation, so the row sits dormant until Argus fixes the typing upstream.

  `default_watchlist.csv` refresh: 22533 records exported 2026-05-17, replacing the prior 63-row / zero-SSID-coverage snapshot. `config/rules.yaml`'s `argus_ssid` template is uncommented and enabled. `docs/ARGUS_RESIDUALS.md` updated to reflect `ssid_pattern` moving from deferred to admitted (deferred drops from 2 types / 21 rows to 1 type / 16 rows).

  Operationally: a Kismet observation of `Flock-230503` (exact ssid) or `My-Penguin-AP` (substring) now alerts at the matched row's severity on a fresh install with the bundled config.

- **`mac_range` parity in `/alerts` `has_action` filter and the alert-detail "Allowlisted" badge.** Operators allowlisting a vendor block via a `mac_range` entry (e.g. `aa:bb:cc:d/28`) now see affected alerts flagged as actioned on the list filter AND get the Allowlisted status on each alert's detail page. Both surfaces previously covered only `mac` and `oui` — `mac_range` was the deliberate omission tracked in `BACKLOG.md`. The same bit-level matcher drives the live poll path, the detail page, the CSV export's `action_taken` column, and the list-page filter — no per-surface re-implementation that could drift. `/28` and `/36` are the only prefix lengths admitted (both nibble-aligned), so no operator-visible caveat about prefix alignment.

### Performance

- **`/watchlist/<id>` detail page: single-row read instead of full-table scan.** The route used to load every watchlist row (up to ~22k after a full Argus import) and pick the matching one in Python on every detail-page request. It now reads one row per request. Same template, same fields, same 404 path for missing ids — just no longer the scaling footgun the docstring already called out for the list page.

### Fixed

- **`/alerts?has_action=with_action` no longer 500s when NULL-mac alerts coexist with a `mac_range` allowlist entry.** The `with_action` SQL clause invoked the mac-range matcher (a Python UDF) without a NULL guard, so any NULL-mac alert in the table caused the query to raise and the page to 500. NULL-mac alerts are legitimate (pre-migration-015 historical rows; certain `new_non_randomized_device` early failures). Each predicate now carries an inner `mac IS NOT NULL AND ...` guard. `with_action` returns 200 and excludes NULL-mac alerts (they can't carry a mac-keyed action signal); `without_action` behavior is unchanged.

### Documentation

- **Multi-rule emit policy made explicit.** A single observation that matches N enabled rules emits N alerts — one per matching rule, each carrying its own severity from its own DB row (for `watchlist_*` and `ble_uuid` delegation rules) or from `rule.severity` (for in-memory pattern rules). There is no "highest-severity wins", "first-match wins", or "merge into one alert" step: every matching rule is its own alert. A device on the watchlist by mac, oui, AND ssid produces three alert rows at three potentially-different severities for the same observation. This is intentional — the audit-first design treats each rule as an independent reason to surface the observation, and the dedup window (configurable, default N minutes) collapses near-duplicates downstream so ntfy doesn't drown in repeats. Behavior is locked; `BACKLOG.md` carries a future-consideration entry for an opt-in single-emit-with-resolved-severity mode if operators ask for it.

## [0.4.0-rc6] - 2026-05-17

Mostly cleanup. rc5 shipped the big feature push — `/watchlist` search, filter, and pagination; `/rules` statistics; `lynceus-export-config`; the Argus residuals audit. rc6 closes two normalization gaps the audit surfaced, corrects one audit verdict that was wrong on inspection, and adds per-alert triage notes (plus a matching `/alerts` filter) that operators were working around with external trackers.

### Fixed

- **Importer now admits 17 Argus rows that previously dropped as `unknown_type`.** The rc5 residuals audit (`docs/ARGUS_RESIDUALS.md`) flagged `ble_company_id` (7 rows) and `ble_service_uuid` (10 rows) as semantic duplicates of the already-admitted `ble_manufacturer_id` and `ble_uuid` types — separated only by the Argus label and a couple of input-shape variants (16-bit and 32-bit Bluetooth SIG short forms, plus Argus's dual-form rendering like `"fd5a / 0x0075"` for Samsung SmartTag / Tile rows). The importer now accepts both. Admit count moves 22,294 → 22,311; dropped 239 → 222. No schema change, no migration.

- **Corrected one audit verdict from "needs smoke" to "drop entirely".** The rc5 audit deferred 49 `device_class_id` rows on plausibility. Going row-by-row, all 49 are DJI drone model-class enum codes (e.g. `'1'='Inspire 1'`) — labels for decoding the DroneID device-type byte, not per-device identifiers. Admitting them would alert on every DJI drone of that model class in range. Per-device Remote-ID coverage is already handled by the admitted `drone_id_prefix`. The audit report is regenerated; total dropped row count is unchanged at 222 — only the reason changed.

### Added

- **Per-alert triage notes.** Closes the "what did I conclude about this alert?" gap operators were working around with external trackers. The alert detail page gains a notes section: an editable textarea (4096-char cap), Save and Clear buttons (Clear behind a confirm prompt), and a relative "Last updated N ago" stamp. Notes are plain text, one per alert, replace-on-update — markdown, history, and multi-operator audit trail are deferred. Empty or whitespace-only text clears the note. Migration 016 adds nullable `note` and `note_updated_at` columns to `alerts`. The `/alerts` list shows a small indicator on rows that carry a note, with a 50-character tooltip preview — the full rationale stays on the detail page so it isn't visible over the shoulder.

- **`has_note` filter on `/alerts`.** Pairs with the list-page note indicator so the triage loop closes: notes → indicator → filter. Three values: `any` (default, unchanged behaviour), `with_note`, and `without_note`. Invalid values fall back to `any`, matching the existing `rule_type` / `window` convention. Bulk-ack via `/alerts/ack-all-visible` honours the filter exactly, so it always operates on the set the operator can see. Pagination links carry the filter through; the default `any` is omitted from URLs so the no-params baseline stays clean.

## [0.4.0-rc5] - 2026-05-17

Release status: alerting for `ble_manufacturer_id` and `drone_id_prefix` rule types needs Kismet probe-path verification on real hardware before it fires on live observations — the import, DB, rules engine, wizard, and `/watchlist` UI all work, but until the Kismet field paths are confirmed against a real capture, the observation fields read `None` and the delegation rules fire zero alerts. See the bullet below for the workaround.

### Added

- **`/watchlist` gets search, filter, and pagination.** A full Argus import lands ~22k rows, and the pre-rc5 page rendered every one in a single pass — genuinely unbrowsable. The page now has a filter bar (substring `q` across pattern / manufacturer / argus_record_id / device_category, plus dropdowns for `pattern_type`, `severity`, and `device_category`) and offset pagination matching `/alerts` (`page` + `page_size` in {25, 50, 100, 200}, default 50). The "where did I just import that row to?" pain finally has an answer: type the `argus_record_id` substring into `q` and the row surfaces. Filter state round-trips through the URL so a filtered view is bookmarkable. Invalid filter values silently fall back to "all"; out-of-range pages clamp to the last valid page (no 404 on a typo'd `?page=999`). The `device_category` dropdown is populated live from the DB, with `(uncategorized)` as a dedicated option for YAML-seeded rows that lack a category. No schema change, no new indexes — 22k-row scans complete well under the 500ms perf budget.

- **`/rules` shows per-rule fire count and "last fired" stamp.** Answers "is this rule worth keeping?" at a glance. Each rule row carries its fire count over a configurable window plus a relative "last fired" stamp ("3h ago" / "5d ago" / "—" if never). A `since` dropdown matches the `/alerts` convention (`1h` / `24h` / `7d` / `30d` / `all`) with `7d` as the default, so a fresh visit reads "what fired this week." Sort defaults to `rules.yaml` order; opt into `count_desc` / `count_asc` via the sort dropdown for "high-volume rules first." URL params round-trip — `/rules?since=24h&sort=count_desc` bookmarks exactly that view. No schema change, no caching; stats aggregate live from the `alerts` table on every render.

- **`lynceus-export-config` — bundle config (and optionally state) into a portable `tar.gz`.** Closes the missing "save / share / back up my config" surface alongside `lynceus-validate`, `lynceus-bootstrap-kismet`, and `lynceus-setup`. Four use cases: backup before an upgrade, machine-to-machine migration, sanitized snapshot for support, template-sharing with another operator.

  **Safe by default.** A bare invocation produces a config-only archive with credentials redacted — `kismet_api_key`, `ntfy_auth_token`, `ntfy_topic`, and `user:pass@` userinfo in `ntfy_url`. Paste-into-chat-safe. Redaction is line-based and preserves your comments, key ordering, and whitespace.

  **Opt-outs are explicit.** `--include-secrets` disables redaction (for personal backups you're keeping on your own host). `--include-state` adds the SQLite database (and any `.db-shm` / `.db-wal` sidecars) under `state/` in the archive — off by default because the DB can be large and carries observed MACs. State files are never redacted; an anonymized state export is deferred.

  **Self-describing archive.** Layout is `lynceus-export-<scope>-<UTC-timestamp>/` with `README.txt` (restore guide), `manifest.json` (version, scope, timestamp, redaction policy, per-file sha256), `config/<name>.yaml`, and (when included) `state/`. Re-hashing on restore catches transport damage.

  **Other flags.** `--scope {user,system,auto}` defaults to `auto`. `--output` refuses to overwrite (unless `--force`), refuses a directory, refuses an unwritable parent. `--dry-run` prints the inventory and produces no archive. Cross-platform (pure `tarfile` + `pathlib`, no shell calls), read-only, no network, no daemon dependency. Registered in both `pyproject.toml` and `install.sh`.

- **Auto-refresh timer for the Argus watchlist (`lynceus-refresh.service` + `lynceus-refresh.timer`).** Closes the loop with the rc4 staleness indicator — the indicator detects stale data, the timer prevents it. Default cadence is `OnCalendar=weekly` with `RandomizedDelaySec=30min` (spreads load across deployments) and `Persistent=true` (catches missed runs after reboots), comfortably faster than the default 30-day `watchlist_staleness_warn_days`. The oneshot service re-runs `lynceus-import-argus --scope system --from-github` under `User=lynceus` with the same hardening posture as `lynceus.service`.

  **Default-off — operator opt-in.** `install.sh --system` copies both unit files and runs `daemon-reload` but does NOT enable the timer. Enabling it is the only Lynceus surface that opts a host into recurring outbound network calls, so it stays an explicit decision. The `install.sh` offline invariant still holds. Enable with:

  ```sh
  sudo systemctl enable --now lynceus-refresh.timer
  ```

  Want a different cadence? `sudo systemctl edit lynceus-refresh.timer` and write a drop-in. A transient GitHub outage fails the oneshot run and journals under `journalctl -u lynceus-refresh.service`; the next scheduled fire retries. No `Restart=` directive — tight retry loops on a sustained outage burn through the GitHub API budget. `uninstall.sh` removes the unit files; `--purge` also wipes `/var/lib/lynceus/`. User-scope installs don't ship the timer.

- **`/alerts` filter bar grows `rule_type` / `q` / `window`, and `/alerts` + `/allowlist` share pagination.** Both pages now route through a single helper with the same `per_page` set (`{25, 50, 100, 200}`, default `50`), the same footer copy, and the same clamp-silently semantics for out-of-range inputs. New `/alerts` filters:

  - `rule_type=<literal>` — narrow by the rule's `rule_type`. Invalid values fall back to "any" rather than 400.
  - `q=<substring>` — case-insensitive substring against MAC, message, and manufacturer. Distinct from the pre-existing `search` (which matches `rule_name` + `message`); both apply alongside if both are set.
  - `window=1h|24h|7d|30d` — relative time window resolved server-side at request time. A shared link means the same recency to any operator. Combines with absolute `since` / `until` by taking the tighter lower bound.

  Pre-rc5 query params keep byte-identical semantics — bookmarked URLs resolve unchanged. `page_size=10` is dropped (move to `25`); other invalid values silently fall back to `50` rather than 400.

  **Schema change: `alerts.rule_type TEXT`** (migration 015). The value was carried in-memory since day one but never persisted; the new filter forced it. Historical rows pre-rc5 carry `NULL`; "any" includes them, a specific `rule_type=...` excludes them.

  Out-of-range behaviour is "clamp silently" rather than 4xx — `?page=999` lands on the last valid page, `?per_page=37` falls back to default, `?rule_type=bogus` ignores the filter. Stale bookmarks survive ruleset extensions. The `/alerts/ack-all-visible` POST mirrors the GET filter set byte-identical, so bulk-ack can never act on alerts the operator can't see.

- **`/allowlist` management surface — search, filter, add, bulk remove.** Closes the "edit `allowlist_ui.yaml` by hand" gap that's existed since the per-alert mutation routes landed. You can now do the full lifecycle from the browser.

  **Filter bar.** Four query params, all AND together, all round-trip through the URL:

  - `q=<substring>` — case-insensitive against pattern + note.
  - `source=primary|ui|all` — primary = your `allowlist.yaml`, UI = daemon-managed `allowlist_ui.yaml`.
  - `status=active|snoozed|expired|all` — expired entries are no longer suppressing but stay rendered so you can bulk-clean them.
  - `type=mac|oui|ssid|mac_range|ble_uuid|ble_manufacturer_id|drone_id_prefix|all`.

  **Add-entry form.** Collapsible `<details>` above the table; expands on validation error so the rejected input survives the round-trip. Inputs pass through the same canonicalization the importer uses, so a pasted uppercase MAC or `0x004C`-shaped manufacturer id ends up in canonical form. Successful add redirects with a one-shot flash.

  **Bulk remove.** Checkboxes on UI-source rows only. The handler reads the file once, filters in memory, and emits a single atomic write covering all N selections — one mtime tick for the poller's reload watcher rather than N.

  **Primary file is hard read-only.** The daemon never writes to `allowlist.yaml`. The UI enforces this by construction: primary rows render with a `[primary]` badge and no checkbox; a hostile submission enlisting a primary key alongside legitimate UI keys fails atomically (HTTP 400, no partial removes). `POST /allowlist/add` writes only to `allowlist_ui.yaml`.

  Allowlist entries now accept all seven pattern types (the four added since `mac`/`oui`/`ssid` — `mac_range`, `ble_uuid`, `ble_manufacturer_id`, `drone_id_prefix`), so an alert keyed off any watchlist type has an allowlist counterpart.

- **`lynceus-bootstrap-kismet` — new helper that takes a fresh Debian / Ubuntu / Kali host from "no Kismet installed" to "ready for `lynceus-setup`."** Closes the "what do I do before running lynceus-setup?" gap.

  Scope is bounded by Kismet's apt-repo coverage: Debian (`bookworm`, `trixie`), Ubuntu (`focal`, `jammy`, `noble`, `plucky`), Kali. On any other distro it prints a pointer to <https://www.kismetwireless.net/packages/> and exits 0.

  What it does, in order: refuses to run if not root (exit 2), reads `/etc/os-release` for the distro gate, installs Kismet via apt if not already on PATH (with `DEBIAN_FRONTEND=noninteractive` to bypass the suid-root prompt), auto-detects Wi-Fi monitor-mode-capable interfaces and Bluetooth controllers (Y/n per interface with default Y), patches `/etc/kismet/kismet_site.conf` append-only with `source=<iface>:type=linuxwifi` or `:type=linuxbluetooth` lines (atomic write, idempotent — your `name=` / `channel_list=` customizations are preserved), adds `$SUDO_USER` to the `kismet` group, then prints next steps (log out + back in, start Kismet, set password, create the API key, run `sudo lynceus-setup`).

  **`install.sh` stays offline.** This script is the one that uses the network for apt; the threat-model invariant that `install.sh` curls no third parties is unchanged.

  **Idempotent on every step** — re-running on a partially-set-up host skips work already done. Flags: `--skip-install` (Kismet already present), `--interface <name>` (repeatable, with `--interface-type {wifi,bt}`), `--no-network` (refuse apt — for air-gapped hosts, implies `--skip-install`), `--dry-run` (preview only), `--yes` (accept all defaults — for scripted bootstrap). Exit codes: 0 success / unsupported-distro, 1 recoverable failure, 2 tool-level failure.

  Wired into `install.sh`'s `CONSOLE_SCRIPTS` symlink layer and `pyproject.toml`; the post-install hint and the `lynceus-setup` "if Kismet isn't installed" block both point at it. End-to-end testing is manual-smoke against a fresh Debian/Ubuntu/Kali VM.

- **`lynceus-setup` auto-locates an existing Kismet API key.** The wizard reads Kismet's per-user `~/.kismet/session.db` (under `--system` also checks `$SUDO_USER`'s home and `/root/.kismet/`) and picks the best match: a key named `lynceus`, else `readonly`, else `admin`, else the first non-empty token. On hit, it shows the source path, a redacted preview (`abcd…wxyz`), and asks `Use this key? [Y/n]`. Y skips the manual copy-paste flow.

  Purely additive: every failure mode (missing file, malformed JSON, no usable entry, Windows host) silently falls through to the existing manual walkthrough. The located key is never echoed in full — only the head/tail preview. No new dependencies, no new config fields, no network calls, read-only against Kismet's files.

- **`GET /healthz.json` — machine-readable health endpoint for monitoring integration.** Returns JSON with overall status plus per-check details (DB reachability, daemon liveness, watchlist freshness, ruleset count, alert counts). Read-only, no auth, derived from existing DB + filesystem state — no new tables, no heartbeat infrastructure, no daemon-side changes.

  HTTP semantics follow the standard monitoring convention: 200 when status is `ok`, 503 when `error`. Currently only the DB-reachable check flips the top-level status; the rest return `ok` with values your monitoring tool can threshold against.

  Response shape:

      {
        "status": "ok" | "error",
        "version": "0.4.0rc5",
        "checks": {
          "db":        {"status": ..., "detail": ... | null},
          "poller":    {"status": ..., "last_poll_at": ...,
                        "seconds_since_poll": ...,
                        "last_observation_at": ...,
                        "seconds_since_observation": ...},
          "watchlist": {"status": ..., "total_rows": ...,
                        "by_pattern_type": {...},
                        "last_imported_at": ...,
                        "days_since_import": ..., "stale": ...},
          "ruleset":   {"status": ..., "active_rules": ...,
                        "rules_path_configured": ...},
          "alerts":    {"status": ..., "total": ...,
                        "last_hour": ...}
        }
      }

  The `poller` check carries `last_poll_at` (daemon-alive proxy) and `last_observation_at` (Kismet-returning-data proxy). The `watchlist.stale` boolean uses the same `watchlist_staleness_warn_days` threshold the startup log and `/settings` card already use.

  **Shape-stability commitment:** existing keys never disappear; future releases only add keys. Pin against this shape without expecting churn. The existing HTML `/healthz` (topnav, `docs/SMOKE.md`, `lynceus-quickstart` readiness probe) is unchanged.

  Example:

      curl -sS http://127.0.0.1:8765/healthz.json | jq .

  Polling at 30s adds no measurable load. Out of scope for v1: auth, Prometheus `/metrics`, response caching, configurable thresholds.

- **`lynceus-validate` CLI — read-only configuration validator.** Catches typos, schema errors, malformed values, and missing referenced paths at edit time instead of at the next daemon restart. Wraps the existing loaders so the diagnoses match what the daemon would hit.

  Covers the five files you may maintain:

  - `lynceus.yaml` — Pydantic schema check; missing-file ERROR for each populated `*_path` reference.
  - `rules.yaml` — surfaces ruleset loader errors (duplicate names, invalid `rule_type`, malformed patterns); empty ruleset is a WARNING.
  - `severity_overrides.yaml` — louder at edit time than the daemon. Unknown top-level keys get a Levenshtein hint (`'supress_categories' -- did you mean 'suppress_categories'?`); unknown Argus categories WARN; `pattern_overrides` keys not matching the 16-hex `argus_record_id` shape ERROR.
  - `allowlist.yaml` — Pydantic validation; entries with `expires_at` in the past WARN.
  - `allowlist_ui.yaml` — same shape; missing file is normal.

  Exit-code contract (stable for CI / pre-commit use): `0` no errors, `1` errors found, `2` tool-level failure. Scope handling matches `lynceus-import-argus` (`--scope user` default or `--scope system`). Output is plain ASCII (no ANSI, no emoji) so you can grep / awk it. `--quiet` suppresses OK + WARNING for CI use.

  Example:

      sudo lynceus-validate --scope system

      Validating Lynceus configuration (scope: system)

      /etc/lynceus/lynceus.yaml
        OK (schema valid; all referenced paths exist)

      /etc/lynceus/severity_overrides.yaml
        ERROR (line 8): invalid severity 'medium' for category
                        'unknown' -- must be one of: low, med, high
        ERROR (line 14): unknown key 'supress_categories' -- did
                         you mean 'suppress_categories'?

      Summary: 2 errors, 0 warnings across 2 files

  The validator never opens the DB; cross-file checks against live DB state are out of scope for v1.

- **Alert detail page gains triage buttons: Allowlist, Snooze 24h, Remove.** Triaging a false positive no longer means editing `allowlist.yaml` and restarting — one click on `/alerts/<id>` writes a MAC-keyed entry to `allowlist_ui.yaml`, the poller picks it up on the next tick via the mtime watch, and future alerts for that device are suppressed immediately.

  Three POST routes under `/alerts/{id}`:

  - `/allowlist` — permanent entry (no `expires_at`), note prefix `added via webui at <ISO>`.
  - `/snooze` — entry with `expires_at = now + 86400`. The fixed 24h window is the only UI cadence; custom durations stay YAML-only.
  - `/allowlist/remove` — idempotent removal by MAC. Returns 303 whether the entry existed or not.

  All three share the same validation: alert exists (404 otherwise), alert carries a MAC (400 otherwise — alerts without one can't be triaged this way), `allowlist_path` is configured (400 otherwise). CSRF protection is the standard `_csrf` form field + `lynceus_csrf` cookie.

  The detail page renders one of three triage states: **not allowlisted** (Allowlist + Snooze 24h buttons), **permanently allowlisted** (status line + Remove button if the match came from the UI sibling; explanatory hint pointing at `allowlist.yaml` if it came from the primary — the daemon cannot edit that file), **snoozed** ("Snoozed until <ISO> (N hours remaining)" with Cancel snooze button on UI-sibling matches). The triage section is omitted entirely when `allowlist_path` is unset or the alert has no MAC.

- **Allowlist supports temporary entries via `expires_at`, and the daemon picks up edits without a restart.** Three operator-facing changes land together:

  - `AllowlistEntry` gains optional `expires_at` (Unix epoch seconds; `None` = permanent) and `added_at`. Both default to `None` so existing `allowlist.yaml` files parse unchanged. Entries past their `expires_at` are silently skipped at poll time — the "snooze expired" path.

  - The poller stat()s the allowlist file(s) before every tick and reloads when mtime moves. Daemon restart is no longer required for allowlist edits. A deleted primary triggers a WARNING and the daemon retains its last-known-good entries rather than dropping every suppression at once (defends against mid-rename and fat-fingered-rm). Each reload emits a single INFO line: `allowlist reloaded: N operator entries + M UI entries`.

  - Storage splits into two files. `allowlist.yaml` (operator-curated primary, path from `Config.allowlist_path`) is read-only from the daemon's perspective — your hand-formatting, comments, and key ordering are preserved indefinitely. A sibling `allowlist_ui.yaml` (path derived by inserting `_ui` before the suffix, e.g. `/etc/lynceus/allowlist.yaml` → `/etc/lynceus/allowlist_ui.yaml`) is daemon-managed: created on first write, merged into the in-memory allowlist at load. Absent is normal pre-first-write; a malformed UI file logs WARNING and is treated as empty so a corrupt sibling can't cripple suppression; a malformed primary logs ERROR and is treated as empty (pre-rc5 would have crashed the poller init).

  The existing audit INFO line at the suppression site keeps its `Allowlist suppressed watchlist hit: rule=… mac=… severity=…` prefix verbatim — `journalctl` greps are unaffected — and appends ` (expires <ISO>)` only when the matched entry has an `expires_at`.

- **`ble_manufacturer_id` and `drone_id_prefix` rows from Argus now land in the watchlist.** Pre-rc5, every row of these two types hit the importer's identifier-type gate and dropped to `dropped_unknown_type` without reaching the DB. Against the live `argus_export.csv` snapshot at `exported_at=2026-05-14T22:34:07Z`:

  - `ble_manufacturer_id`: 3,969 rows (Bluetooth SIG 16-bit Company Identifiers, e.g. `0x004C` for Apple).
  - `drone_id_prefix`: 427 rows (ANSI/CTA-2063-A Remote-ID serial prefixes, e.g. `21239ESA2`).

  `dropped_unknown_type` for that snapshot moves from 4,635 → 239 — exactly the sum of the two new types.

  Migration 013 rebuilds the `watchlist` table to relax the `pattern_type` CHECK (mirroring migration 011's mac_range pattern; SQLite cannot modify a CHECK via `ALTER TABLE`). No new metadata columns: both new types are equality-shaped at the string level. Canonical forms: `ble_manufacturer_id` lowercases and strips the `0x` prefix (`'0x004C'` → `'004c'`) so the runtime equality against Kismet's bare-hex emission is direct; `drone_id_prefix` preserves case (`'21239ESA2'` → `'21239ESA2'`) because ANSI/CTA-2063-A serials are case-sensitive per the standard.

- **`watchlist_ble_manufacturer_id` and `watchlist_drone_id_prefix` rule types.** Same empty-patterns-delegates-to-DB shape established by `watchlist_mac` / `watchlist_oui` / `watchlist_ssid` / `ble_uuid` in rc4: a single empty-patterns rule of the new type enables alert-firing for every matching watchlist row of that type; severity comes from the matched DB row; the runtime override layer (`suppress_vendors`, `suppress_categories`, `pattern_overrides`, `device_category_severity`) applies transparently. Non-empty patterns also accepted and normalized at load time (so `0x004C` in `rules.yaml` matches the bare-hex `004c` on the observation). The setup wizard grows two per-type prompts, each gated by a row-count check so operators with an empty pattern_type don't see them. Re-run `lynceus-setup --reconfigure` to add the new types to an existing install.

  **CAVEAT — runtime alerting needs Kismet probe-path verification.** The Kismet device parser gained two new optional observation fields (`ble_manufacturer_id`, `drone_id_prefix`) populated via best-effort extractors that walk a small table of likely Kismet field paths. These paths come from public Kismet schema docs, NOT a live capture — the codebase had no prior consumer of either surface. Until the paths are confirmed and corrected against a real Kismet emission, both fields read `None` on real hardware and the delegation rules fire zero alerts. The import + DB + rules-engine + wizard pipeline is load-bearing in the meantime: rows land in the watchlist DB, appear in the `/watchlist` UI, and show on the `/settings` count card; only the alert-time match against a live observation is gated on probe-path verification. Promoting a confirmed path to the front of the probe table is a one-line edit.

  **Drone Remote-ID structural gates closed.** The initial rc5 cut shipped with two gates that blocked Remote-ID observations independent of probe-path uncertainty: the Kismet type map admitted only Wi-Fi / BTLE / Bluetooth, and the `devices.device_type` CHECK constraint from migration 001 would have rejected the Remote-ID category. Both are now closed: migration 014 rebuilds `devices` to add `'remote_id'` to the CHECK; the type map maps `'Remote ID'` and `'Remote ID Drone'` to the new category; the drone-ID probe table is re-anchored on the canonical `kismet.device.base.*` paths (`kismet.device.base.remote_id.serial_number` / `.uas_id`) with the older `remoteid.device.basic_id.*` paths retained as fallbacks; the `/devices?device_type=...` query handler admits the new value (the dropdown still lists three types — pass the query param directly for a Remote-ID-only view, dropdown polish tracked separately).

- **Annotation walk now covers all 7 pattern_types.** Alerts fired by the two new delegation rule types were landing with `matched_watchlist_id=NULL` because the rc4 annotation walk only knew the original five types — `rule_name` and severity were right, but the alert → watchlist-row click-through, ntfy enrichment, and audit trail all keyed off `matched_watchlist_id` and went cold. The walk now covers all seven in tiebreaker order: `mac > oui > ble_manufacturer_id > mac_range > drone_id_prefix > ssid > ble_uuid`. The poller passes the new observation fields through to the annotation call. No DB schema change.

  **Operator UX note for BT- and Remote-ID-capable deployments.** Operators running Kismet with the BT scanner enabled gain 3,969 BLE manufacturer signatures on re-import; Remote-ID-enabled deployments gain 427 drone serial-prefix signatures. Both fire alerts as soon as the Kismet probe-path verification lands.

### Documentation

- **Argus residuals audit.** New `docs/ARGUS_RESIDUALS.md` characterizes the ~239 Argus rows still dropped as `unknown_type`, plus a re-runnable diagnostic at `scripts/audit_residuals.py` that regenerates the report against any Argus snapshot. Each of the 31 distinct residual types is classified by Kismet observation surface (`verified-lynceus`, `verified-kismet-docs`, `plausible-needs-smoke`, `no-observation-surface`, `normalization-variant`) with a mechanical per-type recommendation. Surfaces two normalization gaps (`ble_company_id`, `ble_service_uuid`) that overlap admitted pattern_types and would be fixed in the importer's normalization layer rather than via new Kismet surfaces. The script lives in `scripts/` and is deliberately not a `[project.scripts]` entry — operator surface stays unchanged.

- **Doc-rot sweep.** `SECURITY.md` version refreshed from `0.3.0-rc1` to `0.4.0-rc5`. `PROJECT_STATUS.md` reworded for 0.4 reality. `SMOKE.md` header drops its stale `(v0.2)` pin. `WINDOWS_DEV.md` drops the "live reload is on the v0.3 backlog" promise and points `git clone` at `lynceus-warden`. `docs/CONFIGURATION.md` webui-routes tables grow `/watchlist`, `/settings`, `/healthz.json`, the rc5 `/alerts` filter additions, the `/allowlist` management routes (`/allowlist/add`, `/allowlist/bulk_remove`), and the per-alert allowlist + snooze mutations. Confirmed rot only — no stylistic rewrites.

### Changed

- **`lynceus-setup` Kismet + ntfy sections ship with inline context for first-time operators.** Pre-rc5, the wizard asked `Kismet API token (input hidden):` with no preceding explanation — a fresh operator had to go elsewhere to figure out where API keys live, what role to pick, and what the ntfy topic was for. Each section now opens with a `═══`-underlined header, a short explanation of what the value is and why Lynceus needs it, and (for the Kismet API key) a step-by-step walkthrough of where to generate one in the Kismet web UI. The ntfy section calls out the topic-as-shared-secret property up front so you pick something unguessable rather than reading the warning after the fact in the generated `lynceus.yaml`.

  No prompts were added, removed, or reordered. Defaults are unchanged. Existing operators tab through at the same pace. Plain ASCII + box-drawing only (no emoji, no ANSI), so it still looks right tee'd into an install log.

- **`vendor_severity` — runtime vendor-level severity remap on `severity_overrides.yaml`.** Closes the runtime override matrix at vendor × remap. "All devices from this vendor should be `high`" is now a single line instead of N entries under `pattern_overrides` or a manual sweep across `device_category_severity`. The matrix closes to **remap × {category, vendor, row} + suppress × {category, vendor}**.

  **Schema.** `vendor_severity: dict[str, severity]`. Keys are manufacturer strings (matched against `watchlist_metadata.vendor`); values are `"low"` / `"med"` / `"high"`. Keys normalized at load time (lowercase + strip) and matched case-insensitive exact — `"  Axon Enterprise, Inc.  "`, `"axon enterprise, inc."`, and `"AXON ENTERPRISE, INC."` all match the same row. Substring / regex deliberately not supported (`"Apple"` would otherwise match `"Pineapple Computing"`).

  **Precedence (most-specific wins):**

  1. `suppress_vendors` — vendor suppress.
  2. `suppress_categories` — category suppress.
  3. `pattern_overrides` — row-level remap.
  4. `vendor_severity` (new) — vendor-level remap.
  5. `device_category_severity` — category-level remap.

  Suppression at either layer always wins over any remap — per-row UNSUPPRESS is explicitly not a feature. NULL manufacturer falls through to the category remap.

  **Why not extend `vendor_overrides` at runtime.** `vendor_overrides`' `"drop"` sentinel means skip-at-import; a runtime interpretation would silently overload the meaning and produce a footgun. `vendor_overrides` stays import-time-only by design.

  **Tolerant parsing.** Non-string keys, empty-after-strip keys, and invalid severity values each drop with a WARNING; the rest of the dict parses normally. One malformed entry never disables the whole layer.

  The wizard's `severity_overrides.yaml` starter template gains a `vendor_severity:` block adjacent to `vendor_overrides` with a `# LAYER: RUNTIME` tag and a worked example targeting surveillance-camera vendors. The `/settings` runtime-keys card lists it alongside the four existing runtime keys. In-memory pattern rules (rules with non-empty `patterns`) are unaffected — runtime overrides apply only to DB-delegation matches. No DB schema change.

### Fixed

- **Poller now logs a grep-able INFO line on every ruleset load.** Pre-rc5 the loader was called silently at init, leaving no startup signal that `rules.yaml` had actually been read. Symmetric with the watchlist-staleness and runtime-severity-overrides lines:

      loaded ruleset from <path>: N active rules
      loaded ruleset from <path>: N active rules (M disabled)
      no rules_path configured; ruleset is empty — no alerts will fire

  The empty-state line catches the failure mode where the wizard wrote `rules.yaml` but `rules_path` was never wired in `lynceus.yaml` — pre-fix the daemon ran with no alerting and no log line explaining why.

- **`/settings` watchlist-freshness card now lists all 7 pattern_types.** rc5 landed `ble_manufacturer_id` and `drone_id_prefix` in the DB and importer, but the Jinja template on the freshness card was never extended past the five rc4 types. Operators saw the new rows in `lynceus-import-argus` stdout and could `SELECT` them out of SQLite, but the card silently rendered zero for both. The backing helper was already returning all 7 keys; only the template was stale. Caught pre-smoke during runbook verification.

## [0.4.0-rc4] - 2026-05-15

### Added

- **Argus `mac_range` rows now land in the watchlist.** Pre-rc4, every `mac_range` row from Argus hit the importer's identifier-type gate and was silently dropped — about 17,798 of 22,532 rows in the current Argus export, none of which could contribute to detections. Migration 011 relaxes the watchlist `pattern_type` check to admit `mac_range`, adds nibble-precision prefix columns, and a partial index over them. The importer accepts both canonical CIDR shapes (`aa:bb:cc:d/28`, `aa:bb:cc:dd:e/36`) and legacy bare-prefix rows (canonicalized on disk with one INFO log line per row so you can watch the legacy count drop to zero). Unrecognized shapes go to the existing `normalization_failed` counter rather than being silently accepted.

  This rc lands the schema + import path only — `mac_range` rows appear in the watchlist UI but the poller cannot yet match a sighted MAC against them. Runtime matching arrives in the next bullet.

- **`watchlist_mac_range` rule type — first DB-delegated rule in Lynceus.** Closes the runtime-matching gap above. A single empty-patterns `watchlist_mac_range` entry in `rules.yaml` enables alert-firing for every matching `mac_range` row in the watchlist DB — no need to duplicate patterns across the DB and `rules.yaml`. `/36` matches sort ahead of `/28` (more specific wins); `/watchlist` detail renders the prefix length plus a block-class annotation (MA-M `/28` = 1,048,576 addresses; MA-S/IAB `/36` = 4,096).

  **Severity comes from the matched DB row, NOT `rule.severity`.** The importer wrote per-row severity from `device_category` at import time; reading it back at alert time is the only path that respects that data. The bundled `config/rules.yaml` template calls this out where the example sits.

  **Alert volume after enabling.** Shipped commented-out; default is OFF. Uncommenting enables alert-firing for any MAC inside any of the 17,786 IEEE-registry rows imported by `lynceus-import-argus`. All of those rows carry `device_category = 'unknown'`, which maps to `low` — so enabling fires `low` alerts at whatever rate observed MACs fall inside the IEEE allocations Argus catalogued (predominantly enterprise / embedded / medical / industrial vendors). If `low` is the wrong tier for this volume, tune via `severity_overrides.yaml` (see runtime layer below) or use the allowlist to scope by geography.

- **DB delegation extended to `watchlist_mac`, `watchlist_oui`, `watchlist_ssid`, and `ble_uuid`.** Before this change, only `watchlist_mac_range` fired via DB delegation; the 63 bundled `default_watchlist.csv` rows plus every Argus-imported mac/oui/ssid/ble_uuid row stayed inert unless you manually copied their patterns into `rules.yaml`. Now a single empty-patterns rule per type fires alerts for every matching DB row of that type — same idiom as `watchlist_mac_range`. Rules with non-empty patterns see byte-identical behaviour.

  All four ship commented-out in `config/rules.yaml`; default OFF. The matched row's severity flows into the alert (rule severity is ignored for empty-patterns delegation). Per-row severity is populated by `lynceus-import-argus` from `device_category`:

  - `imsi_catcher`, `alpr`, `hacking_tool` → `high`
  - `body_cam`, `drone`, `gunshot_detect`, `in_vehicle_router` → `med`
  - `unknown` and anything unlisted → `low`

  Before enabling a delegation entry, run `lynceus-list-watchlist --pattern-type mac` (and the other three types) to see the severity distribution in your DB. If a category's default is wrong for your environment, tune via `--override-file severity_overrides.yaml` at import time, or via the runtime layer below.

- **Runtime severity layer — `severity_overrides.yaml` now applies at alert time, not just at import time.** Pre-rc4, the wizard scaffolded the file and `lynceus-import-argus --override-file` consumed it, but the daemon never read it. Retuning severities meant re-importing the full ~22,500-row Argus corpus. Now the poller reads the file at startup and transforms DB-delegation matches at alert construction.

  Two keys take effect at runtime:

  - **`device_category_severity`** (existing key, now both layers). Import bakes per-category remap into `watchlist.severity` at write time (unchanged); runtime re-applies the same map at alert time. Set `unknown: med` in the file, restart the daemon, and the 17,786 IEEE-registry `mac_range` rows fire at `med` on the next poll. No re-import.
  - **`suppress_categories`** (new, runtime only). A delegation match whose `device_category` is in the list emits no alert (no row in `alerts`, no ntfy push). The watchlist row stays; only alert emission is silenced. An INFO log line per suppression names the rule, category, and watchlist row for forensics.

  Opt-in: set `severity_overrides_path` in `lynceus.yaml` to your file. Unset means runtime layer disabled; malformed YAML logs a WARNING and falls back to pass-through (the poller never crashes on this file). In-memory pattern rules (non-empty `patterns`) are unaffected — runtime overrides apply only to DB-delegation matches. The import-time consumer is byte-identical pre/post.

  The wizard's starter file gains inline `# LAYER:` tags on each section (`IMPORT-TIME` / `RUNTIME` / `BOTH`) so you can see at a glance whether a change needs a re-import or just a daemon restart. The `/settings` severity-overrides card mirrors the same wording.

- **`lynceus-setup` enable-alerting flow — wizard now wires up alerts end-to-end.** Pre-rc4, running the wizard left you with a configured daemon and imported watchlist but no alerts: you had to copy `config/rules.yaml`, uncomment the right delegation entries by hand, and add `rules_path` to `lynceus.yaml`. The wizard now drives all three.

  Between bundled-watchlist import and "Setup complete", a single gate fires: `Enable Argus-backed alerting? [y/N]`. Default is NO — an operator who hits Enter completes the wizard in the exact pre-rc4 state (no alerts). Saying yes prompts per-rule-type with the current DB row count (`Enable watchlist_mac_range (17,786 MAC ranges)? [y/N]`); types with zero rows are skipped silently. Selected entries land as active in a fresh `rules.yaml` at the scope-appropriate path (`/etc/lynceus/rules.yaml` under `--system`, `~/.config/lynceus/rules.yaml` under `--user`); the rest ship as commented templates. `rules_path` then gets appended to the already-written `lynceus.yaml`.

  Re-runs treat hand-edits as sacred: if `rules.yaml` already exists, a separate `Overwrite? [y/N]` prompt fires (default NO). Declining leaves the file untouched but still wires `rules_path` when previously unset — recovers the "I copied the file but never wired it up" case. All defaults are NO, matching Lynceus's privacy-conservative posture: a wizard run with all defaults gets a Lynceus that observes but does not alert. `new_non_randomized_device` and any custom pattern-bearing rules still require manual edits.

- **`suppress_vendors` — runtime manufacturer-level alert suppression.** Sits adjacent to `suppress_categories` on the same runtime layer: a delegation alert whose matched watchlist row carries a manufacturer in the list emits no alert. The watchlist row stays in the DB; only alert emission is silenced. Edit the file, restart the daemon, no re-import.

  Comparison is case-insensitive exact match — entries are normalized (lowercase + strip) at load and at eval. So `"  Mitsubishi Electric US, Inc.  "`, `"mitsubishi electric us, inc."`, and `"MITSUBISHI ELECTRIC US, INC."` all match. Substring / regex was rejected: `"Apple"` would otherwise match `"Pineapple Computing"`. Configure with the canonical vendor string from the watchlist row — the same value Argus emits in its `manufacturer` column.

  Precedence: `suppress_vendors` checks first (most specific), then `suppress_categories`, then `device_category_severity`. Vendor wins because manufacturer is the more specific axis. NULL manufacturer rows skip the check entirely and fall through. `vendor_overrides` is unchanged — its import-time `"drop"` sentinel keeps its skip-at-import semantic; `suppress_vendors` is strictly additive at runtime.

- **`pattern_overrides` — runtime row-level severity remap by `argus_record_id`.** Closes the runtime severity-tuning matrix at the row axis. Use case: "the specific Flock camera at my workplace → high; everything else in `alpr` → low." Without this knob you could only set `alpr → low` (and lose the workplace signal) or `alpr → high` (and over-alert on every camera).

  Schema: `pattern_overrides: dict[str, severity]`. Keys are the 16-hex `argus_record_id` Argus emits (case-normalized at load time so copy-paste case doesn't matter); values are `low` / `med` / `high`. Precedence sits between suppression and category remap: `suppress_vendors` → `suppress_categories` → `pattern_overrides` → `device_category_severity`. Suppression at either layer always wins over a row-level remap — per-row UNSUPPRESS is explicitly not a feature; use the allowlist for per-row alert suppression instead.

  Argus-imported rows only. The 63 bundled `default_watchlist.csv` rows and any rows added via `lynceus-seed-watchlist` without metadata have no stable identifier and skip the check. For non-Argus row-level tuning, use `device_category_severity` (category granularity) or the allowlist (per-row suppression). Load-time validation is per-entry tolerant: bad keys or values get a WARNING and drop, the rest of the dict parses. The wizard's starter template gains a `pattern_overrides:` block with an inline SQL query you can paste to find an `argus_record_id` for a row of interest.

- **Watchlist staleness indicator — startup WARNING + `/settings` freshness card.** Pre-rc4 the daemon ran silently against whatever was last imported; boot a system that had been off for two months and you had no way to tell threat data was 60+ days behind. The settings page's "last imported" field made it worse by surfacing a per-row local-clock proxy that flipped to "now" on every re-import of a stale CSV.

  Migration 012 adds an `import_runs` table that persists one row per successful `lynceus-import-argus`: local-clock `imported_at`, Argus-side `exported_at` parsed from the CSV's `# meta:` line, the canonical Argus-side `record_count`, and a free-form `source` (absolute path for `--input`, `owner/repo@ref` for `--from-github`). The poller reads the most-recent row at startup; the `/settings` freshness card reads it on every render. Both surfaces agree by construction.

  Startup log shapes:

  - Within threshold: `INFO watchlist: N rows total, most recent Argus import D days ago (exported YYYY-MM-DD)`.
  - Over threshold: `WARNING watchlist: N rows total, most recent Argus import D days ago (exported YYYY-MM-DD); consider 'lynceus-import-argus --from-github' to refresh`.
  - No imports recorded (fresh install): `INFO watchlist: N rows total, no Argus import metadata recorded`. Deliberately INFO, not WARNING — a fresh install where you haven't run the importer yet is the expected state right after `lynceus-setup`.

  New `watchlist_staleness_warn_days: int = 30` config field (matches Argus's nominal release cadence; tune via `lynceus.yaml` for slower cadences). Validated `>= 1`. The `/settings` 'Watchlist freshness' card renders status badge, Argus exported date, locally imported date, age in days, source string, record count, and a pattern-type breakdown. Refresh hint shows the exact command, only in the stale branch. Read-only — no "Force refresh" button. The misleading `last_imported_ts = MAX(updated_at)` field on the existing watchlist data card is removed. Imports from before migration 012 don't appear on the card; the next refresh starts the signal cleanly.

### Fixed

- **Runtime severity-overrides loader now logs INFO at every load outcome, not just on missing-file.** The Kali live-validation runbook promised "an INFO line confirming the runtime severity-overrides file was loaded" but the initial implementation logged INFO only on the missing-file path; successful-load and disabled-via-None returned silently. Three new INFO lines now cover the three non-failure outcomes — active-keys (names the path and the count of active remaps and suppressions), empty-keys (parses cleanly but no runtime keys uncommented; layer is effectively pass-through), and `severity_overrides_path` unset (names the field and points at the canonical paths under `--system` and `--user`). All three are greppable via the literal `runtime severity overrides`. The four failure modes (missing file, unreadable file, malformed YAML, validation error) still log at WARNING and are unchanged.

- **`lynceus-import-argus --from-github` default `--repo` was pointing at a non-existent repository.** rc3 hard-coded `kevlattice/argus` as the default; the actual Argus repo is `kevwillow/argus-db`. The headline rc3 feature 404'd on the `/releases/latest` API call and operators saw an opaque `HTTPError` instead of a successful refresh. Passing `--repo OWNER/NAME` for a fork still works the same way.

- **`lynceus-import-argus --from-github` no longer crashes when the Argus repo has no published GitHub Releases.** rc4 still required `/repos/{repo}/releases/latest` to return a tag, but `kevwillow/argus-db` ships its CSV on every commit and does not cut formal Releases. The API returned 404, `raise_for_status()` raised `HTTPError`, and `--from-github` was unusable. The resolver now treats a 404 on `/releases/latest` as "no published releases" and falls back to the `main` branch with a WARNING (`No published releases for {repo}; falling back to 'main'. Pin a tag with --ref for reproducibility.`). Other non-200 statuses (500, 403) still propagate — a transient GitHub outage must not silently degrade to importing whatever `main` happens to be.

- **`lynceus-import-argus --override-file` is now scope-strict.** Pre-fix, the argparse default was hard-coded to `/etc/lynceus/severity_overrides.yaml` regardless of `--scope`. On a host with a system install (`/etc/lynceus` is `0750 root:lynceus`), an unprivileged user running the importer with `--scope user` hit the system path via the default and crashed with `PermissionError`. The flag now defaults to `None`; resolution is scope-aware — user-scope only probes the user-scope path, system-scope only the system path, no cross-scope fallback. Explicit `--override-file <path>` is used verbatim. `PermissionError` on the probe is now converted into an actionable message that names the offending path.

- **`lynceus-setup` refuses sudo-without-`--system` to prevent silent scope misplacement.** Reproduced in the rc4 live smoke: `sudo lynceus-setup --reconfigure` (no `--system`) silently regenerated `/root/.config/lynceus/lynceus.yaml` while the system daemon kept reading `/etc/lynceus/lynceus.yaml` — operator believed they'd reconfigured the daemon, but it was still running the stale config. The wizard now refuses early when `euid=0` and `--system` is not passed, prints both correct invocations side-by-side, and exits 2. Three legitimate combinations are unchanged: root + `--system`, non-root alone, non-root + `--system` (still hits the existing "use sudo" preflight). Windows is a no-op. After upgrading, operators who hit this in rc4 should re-run `sudo lynceus-setup --system --reconfigure` to bring `/etc/lynceus/lynceus.yaml` back into sync.

### Changed

- **All `kevlattice/lynceus` GitHub URLs replaced with `kevwillow/lynceus-warden`** to reflect the upstream account + repo rename. Touches `pyproject.toml` (Homepage / Repository / Issues, which flow into PyPI metadata), `SECURITY.md`, the `git clone` URL in the README, and the `Documentation=` line in both systemd unit files (visible in `systemctl status` and journalctl context). The GitHub-side redirect from `kevwillow/lynceus.git` to `kevwillow/lynceus-warden.git` is still active, so older clones continue to push and pull — but new clones should use the canonical URL.

## [0.4.0-rc3] - 2026-05-15

> **⚠️ Broken release — superseded by [0.4.0-rc4](#040-rc4---2026-05-15). Do not install.**
>
> The headline `lynceus-import-argus --from-github` feature shipped
> with a non-existent default `--repo` (`kevlattice/argus`); the API
> release lookup 404s before the fetch can start, and operators see
> an opaque `HTTPError` instead of a successful refresh. Fixed in
> rc4 (`kevwillow/argus-db`). The `v0.4.0-rc3` tag has been deleted
> from the GitHub remote to prevent accidental installs from the
> tag; the commit history remains for reference.

### Added

- **`lynceus-import-argus --from-github` for one-command watchlist refresh.** Fetches `exports/argus_export.csv` from [`kevwillow/argus-db`](https://github.com/kevwillow/argus-db) over HTTPS and runs the existing idempotent import — replacing the old three-step scp + find-the-db + import flow. Defaults to the latest tagged release (not `main`) so one bad upstream push can't poison every operator. `--ref` overrides (tag, branch, or commit; `--ref main` allowed for bleeding-edge), and `--repo OWNER/NAME` swaps the source for forks. Fetched CSVs land in `<data-dir>/argus-cache/<ref>__argus_export.csv` for a forensic trail. No GitHub token required. TLS verify on, 15s/30s timeouts. `install.sh` stays OFFLINE; only this one CLI talks to the network. `--input` remains for air-gapped operators — the two flags are mutually exclusive, exactly one required.

- **`lynceus-import-argus --db` now defaults to the canonical scope path.** Previously `--db` was required, so every invocation hand-rolled `/var/lib/lynceus/lynceus.db` or `~/.local/share/lynceus/lynceus.db`. Now the same XDG-aware resolver the setup wizard and daemon use picks the right path when `--db` is omitted. New `--scope user|system` selects the default scope (defaults to `user`); pass `--db` explicitly to override. Existing scripts passing `--db` are unaffected.

- **Scope-aware uninstall in `install.sh --uninstall`.** Now accepts both `--user` and `--system`, closing the gap where only system installs had a clean reversal path. Flag order is now free: `--uninstall --user` and `--user --uninstall` both work. `--purge` now errors unless `--uninstall` is also passed. `--user --purge` deletes `~/.config/lynceus`, `~/.local/share/lynceus`, and `~/.local/state/lynceus` (the latter two hold `lynceus.db` and logs). Without `--purge`, only the venv at `~/.local/share/lynceus/.venv` is removed — your database survives. If no `--user` install artifact is found, the script prints where it looked and suggests `sudo install.sh --uninstall --system` in case you picked the wrong scope, then exits 0 rather than running no-op `rm`s.

- **Top-level `uninstall.sh` wrapper.** Operators look for an `uninstall.sh` next to `install.sh`; we now ship one. Thin shell wrapper — auto-detects scope by venv marker (`~/.local/share/lynceus/.venv` for `--user`, `/opt/lynceus/.venv` for `--system`), refuses to guess if both exist (lists them, asks you to be explicit), prints where it looked if neither is present, and otherwise execs `install.sh --uninstall --user|--system` with `--purge` and `--dry-run` passed through. Like `install.sh`, it is OFFLINE — no network access of any kind.

## [0.4.0-rc2] - 2026-05-15

### Security

- **Allowlist suppression of watchlist hits is now audit-logged.** Previously the allowlist-then-evaluate ordering meant an allowlist entry could silently disable any watchlist rule whose pattern overlapped — anyone with write access to the allowlist file got an undocumented watchlist kill-switch with zero log signal. The poll loop now re-evaluates rules on the allowlisted-suppression path and emits an INFO line per suppressed hit: `Allowlist suppressed watchlist hit: rule=<name> mac=<mac> severity=<sev>`. Grep `journalctl` to review whether your allowlist is too permissive. `new_non_randomized_device` hits are intentionally excluded — the whole point of allowlisting is to silence those, and logging would mean one INFO line per allowlisted device per poll cycle.

- **ntfy topic no longer leaks in notifier logs, wizard summary, or probe-failure output.** The topic is a shared-secret URL path component on public ntfy brokers — anyone who knows it can both subscribe and publish forged alerts. The web UI already redacted it; three other surfaces did not:

  - The notifier logged the full POST URL on every network failure plus the `requests` exception string (which itself embeds the URL) — leaking the topic twice per failure into `journalctl`.
  - `lynceus-setup` wizard printed the raw topic to stdout at the end of a run, lingering in scrollback and any tee'd install log.
  - The wizard's ntfy probe printed `str(exc)` verbatim on failure — same exception-embeds-URL leak.

  All three now redact the topic to `prefix•••suffix` form. The notifier and wizard probe log only the exception type name plus the topic-redacted URL on failure; full exception detail is reserved for DEBUG operation.

### Added

- **Dark mode for the web UI.** Auto-follows the OS via `prefers-color-scheme: dark`, with a `theme: auto / light / dark` toggle in the topnav. Cycles auto → light → dark → auto and persists to `localStorage` (`lynceus-theme` key) across reloads. Pico CSS handles standard elements; `lynceus.css` adds matching dark variants for severity / confidence / status badges, topnav border, sparkline bar fill, severity-tinted alert rows, and the table-scroll fade gradient. Light-mode rendering is byte-identical to pre-change — operators who keep their OS in light and never touch the toggle see no visual change. A small synchronous `<head>` bootstrap reads the stored choice before the stylesheet loads, so there is no flash of `prefers-color-scheme` on a forced theme.

- **`lynceus-import-argus --min-confidence N` row-skip flag.** Hard-skips rows where `confidence < N` before any DB write; skipped rows land in a new `dropped_low_confidence` counter shown in both per-bucket and trailing-summary report lines, plus a per-row INFO log so the count is debuggable. Distinct from the YAML-configured `confidence_downgrade_threshold` (which downgrades severity tier — `high` → `med` → `low` — but still imports the row): `--min-confidence` is a hard pre-DB filter, the threshold is a severity nudge. Both can be active simultaneously. Intended workflow: `--min-confidence=80 --dry-run` against an incoming push to confirm the high-conf subset lands cleanly, then re-run without the flag for the full export. Default unset (no filtering), so existing scripts are unaffected.

- **`evidence_snapshots.do_not_publish` column** (migration 009). Forward-compat for v0.5.0 public-feed export — no producers or consumers in v0.4.0. Defaults to 0. Adding the column now while the table is small avoids a destructive migration when v0.5.0 ships.

### Documentation

- **`SECURITY.md` gains a "Data at rest" section.** Documents that `lynceus.db` is unencrypted, that `evidence_snapshots` carries the most sensitive data Lynceus has shipped (probe SSIDs gated by `capture.probe_ssids`, operator GPS gated by `evidence_store_gps`), and that the WAL sidecar retains rows after a logical `DELETE`. Includes the `PRAGMA wal_checkpoint(TRUNCATE)` recipe for operators who need to flush WAL before a backup or hand-off.

- **`CONFIGURATION.md` field-reference table now lists the v0.4.0 evidence knobs** (`evidence_capture_enabled`, `evidence_retention_days`, `evidence_store_gps`).

### Performance

- **`captured_at` index for the evidence retention prune** (migration 008). The daily `DELETE FROM evidence_snapshots WHERE captured_at < ?` no longer falls back to a full table scan. The pre-existing `(mac, captured_at DESC)` index leads with `mac` and is not usable for an unconstrained range scan; this becomes a real cost on Pi-class hardware after weeks of operation on a busy site.

### Changed

- **`lynceus-import-argus` now emits a per-row INFO log line on every `identifier_type` drop.** Pre-change, `mac_range` rows and rows carrying an unknown `identifier_type` were silently swallowed into the `dropped_mac_range` / `dropped_unknown_type` counters — visible in the final report but with no row-level trail. The new lines carry `argus_record_id`, the raw identifier_type value, and a stable reason token (`mac_range_unsupported` / `unknown_identifier_type`), so the forensic question is answered by `journalctl | grep "argus import: skipping"`. INFO not WARNING because these are expected drops per the Argus contract, not anomalies — they must surface for debuggability but must not upgrade the ntfy threshold or screen-flood on large imports.

### Fixed

- **Importer now tolerates four timestamp shapes in the Argus CSV's `first_seen` / `last_verified` columns.** Pre-fix, the parser only accepted the space-separated `"%Y-%m-%d %H:%M:%S"` shape — but Argus codified its canonical emission as ISO-8601 UTC with `Z` suffix (e.g. `"2026-05-14T06:13:42Z"`), and older write-paths had emitted at least four distinct shapes. The strict parser rejected every Z-form value and silently dropped the matching watchlist rows. Smoke against the live 22,532-row export showed **50 imported / 53 errors** pre-fix; post-fix the same dry-run reports **103 imported / 0 errors**. The parser now accepts: canonical Z form, ISO with explicit UTC offset, space-separated treated as UTC (backward compat with archived exports), and date-only midnight UTC. Non-zero offsets are coerced to UTC. Unparseable shapes still raise so a future fifth shape surfaces immediately rather than landing silently.

- **Migration 007 (`evidence_snapshots`) now uses `IF NOT EXISTS` guards on its CREATE statements.** Re-running on a DB where 007's objects exist but the `schema_migrations` row was never written (interrupted runner, crash mid-script) is now a no-op rather than raising `sqlite3.OperationalError: table evidence_snapshots already exists`. Narrow partial-apply hardening — the broader migration-runner atomicity work stays deferred to v0.4.1. A follow-up sweep will apply the same guards to the other migrations.

- **Watchlist patterns are now normalized at write time.** Pre-fix, `lynceus-seed-watchlist` and `lynceus-import-argus` inserted operator-supplied patterns verbatim. The poller normalizes its observation MAC to lowercase colon-separated form before lookup, so a watchlist row stored as `"AA:BB:CC:DD:EE:FF"` silently never linked to the alert that fired for `"aa:bb:cc:dd:ee:ff"`. The alert was still written, but `matched_watchlist_id` landed `NULL` — dropping the entire Argus metadata enrichment (vendor, confidence, source URL, severity hint) from the alert detail page. Both the YAML seeder and the Argus CSV importer now canonicalize before insert: lowercase, colon-separated MACs, lowercase BLE UUIDs (hyphens preserved), case-sensitive SSIDs pass through. Migration 010 normalizes pre-existing rows in place; idempotent. `lynceus-import-argus` adds a `normalization_failed` counter to its report; `lynceus-seed-watchlist` emits a WARNING per rejection plus a rolled-up summary.

- **`lynceus-import-argus` now case-normalizes `identifier_type` before the allowlist check.** Pre-fix, a row from Argus with `identifier_type="BLE_SERVICE"` (uppercase) missed the lowercase keys in the importer's type map and silently dropped into `dropped_unknown_type` with no per-row log line. The importer now lowercases and strips whitespace before lookup, so high-confidence `ble_service` rows that happen to ship as `BLE_SERVICE` are no longer lost without warning.

- **Freshly-created user-mode databases are now `chmod 0600` on POSIX.** Previously the file landed at the process umask (typically `0644` — world-readable on multi-user boxes). System-mode installs already get `0640 root:lynceus` from setup; this fix only affects user-mode where evidence rows could otherwise be readable by any local account. Existing databases keep operator-set modes; the chmod runs only on first creation. No-op on Windows.

- **Alert detail page hides the GPS section when stored coordinates are non-finite.** Belt-and-suspenders against a pre-`evidence_store_gps` install or hand-edited DB row carrying `inf` / `nan`: the OSM URL would otherwise render as `mlat=nan&mlon=...` and the visible coordinate line would say "nan, 0". The handler now zeroes out the GPS fields and logs a WARNING when it detects non-finite values.

- **OpenStreetMap link on the alert detail page now opens in a new tab.** Previously had `rel="noopener noreferrer"` but no `target="_blank"`, so clicking it navigated off the alert page and dropped pagination/filter context. Now matches the watchlist `source_url` link's behaviour.

- **Evidence capture now honors the `capture.probe_ssids` and `capture.ble_friendly_names` toggles.** Previously the verbatim Kismet record stored in `evidence_snapshots.kismet_record_json` bypassed both toggles, so an operator who explicitly disabled probe capture still had every probed SSID for every alerting device persisted to disk. Evidence capture now redacts the record per the active capture config before serialization (the upstream record is never mutated).

- **`bytes` / `bytearray` fields in Kismet records are now hex-encoded in evidence JSON** instead of stringified as a Python repr. Old output was tool-hostile blobs like `"b'\\xff\\xfe'"`; new output is clean hex (`"fffe"`) that round-trips through any JSON consumer.

- **Non-finite floats in Kismet records (`inf`, `nan`) are now serialized as `null` in evidence JSON** instead of the non-standard `Infinity` / `NaN` tokens. Strict JSON parsers (FOIA-export pipelines, journalist tooling) reject those tokens; a single Kismet RRD slot carrying a sentinel value used to render the entire snapshot non-portable.

- **`raw_record` is no longer attached to in-memory device observations when evidence capture is disabled.** Each Kismet device record can be tens of KB; for poll batches of hundreds of devices that was multi-MB of needless retention every tick when the evidence path would never consume it.

- **Capture-failure log line no longer leaks exception body content.** `json.dumps` failures can carry offending field values (BLE friendly names, SSIDs, vendor strings) in the exception message; logging via `%s` echoed those values into `journalctl` outside Lynceus's privacy controls. The WARNING line now includes only the exception type name; full traceback is reserved for DEBUG operation.

- **GPS in evidence rows is now opt-in.** The geopoint in a Kismet device record is the receiver's GPS fix, not the observed device's, so persisting it on every alert was building a high-resolution operator-movement log retained for the full `evidence_retention_days` window. New config flag `evidence_store_gps` (default `false`) gates the GPS columns; when off, `gps_lat` / `gps_lon` / `gps_alt` / `gps_captured_at` stay NULL even when the Kismet record contains location data.

  - **BREAKING (pre-release):** `evidence_store_gps` defaults to `false`. Operators who want GPS in evidence rows must enable it explicitly. Existing rows in `evidence_snapshots` from a pre-release v0.4.0 still carry whatever GPS values were captured at the time; only future captures are gated.

### Added

- **Evidence snapshots: alert-time capture and daily retention prune.** When an alert fires, Lynceus now persists a full evidence snapshot to a new `evidence_snapshots` table: the Kismet device record at that moment (verbatim JSON), the recent RSSI history from Kismet's signal RRD (60-sample minute_vec), and the GPS fix when one is present and `evidence_store_gps` is enabled. Foundational layer for transparency reporting, FOIA requests, journalism use cases, and the v0.4.1 movement-aware alerting that needs recent per-device evidence.

  - Migration `007_evidence_snapshots.sql` adds the table with `ON DELETE CASCADE` from `alerts(id)` plus `(alert_id)` and `(mac, captured_at DESC)` indexes.
  - New config knobs: `evidence_capture_enabled` (default `true`; off-switch for storage-constrained Pis) and `evidence_retention_days` (default 90, validated to [1, 3650]).
  - Capture is wrapped in a broad try/except — a malformed Kismet record must never derail the alert path — and failures log at WARNING, not ERROR.
  - Daily housekeeping runs at most once per 24h from the poll loop.
  - Alert detail page `/alerts/{id}` surfaces evidence: the captured Kismet record in a collapsed `<details>` block, an inline SVG sparkline of the 60-sample RSSI history (no external chart library — Lynceus stays offline-capable), and an OpenStreetMap link for the captured GPS fix when present (not Google Maps — privacy posture matters here). Older alerts that predate v0.4.0, or alerts where capture was disabled, render a "No evidence captured" placeholder.
  - CLI export commands intentionally deferred to a follow-up.

## [0.3.0-rc2] - 2026-05-08

### Fixed

- **Setup wizard no longer crashes on a fresh box during the bundled-watchlist import.** On a clean install the data directory (`~/.local/share/lynceus`, `/var/lib/lynceus`) didn't exist yet, and sqlite refused to open the DB with "unable to open database file". The wizard now creates the data and log directories before invoking `lynceus-import-argus`.

### Added

- **Bluetooth source selection in `lynceus-setup`.** On Linux the wizard enumerates `hci*` adapters and, when one is present, offers to append it to `kismet_sources` so Tier 1 BLE enrichment has a source to draw on. macOS and Windows print a one-line note saying BT enumeration isn't implemented — configure Kismet's BT source manually.
- **ntfy is now skippable in the wizard.** Pressing Enter at the broker URL prompt skips ntfy entirely — `ntfy_url` and `ntfy_topic` are written empty, the publish probe is suppressed, and the daemon's null-notifier fallback handles it. If you do set a URL, an empty topic re-prompts (topic is required when URL is set).

### Changed

- **Severity-overrides prompt explains itself and rejects obvious non-paths.** The prompt now prints what `severity_overrides.yaml` is for before asking for a path, and inputs like `na`, `skip`, or `none` are rejected with "That doesn't look like a file path" instead of silently landing in the wrong place.
- **Retired the optional "additional Argus CSV" prompt.** It was redundant on top of the bundled-watchlist auto-import, and its yes/no/path loop was a frequent source of copy-paste mistakes. The wizard now closes with a one-line hint pointing at `lynceus-import-argus --input <path>` for later imports.

## [0.3.0-rc1] - 2026-05-08

### Added

- **Argus integration.** First-class support for the Argus surveillance-equipment signature dataset. Migration `004_watchlist_metadata` adds a metadata table storing Argus record id, device category, confidence, vendor, source attribution, FCC id, geographic scope, and verification timestamps alongside each watchlist entry. `lynceus-seed-watchlist` accepts an optional `metadata:` block per entry. New `lynceus-import-argus` CLI ingests the Argus dual-artifact CSV (signatures + metadata) into the watchlist. A new `/watchlist` page lists entries and per-device detail surfaces vendor, category, confidence, source, and notes. Alerts now record `matched_watchlist_id` (migration `005_alert_watchlist_link`) so triage carries metadata end-to-end, and the `/alerts` view plus the ntfy notification body include vendor and confidence so push notifications are actionable without opening the UI.

- **Tier 1 passive metadata capture.** Migration `006_tier1_capture` adds `probe_ssids` and `ble_name` columns to devices. WiFi probe-request SSID capture is opt-in via `capture.probe_ssids` (default off, privacy-conservative). BLE friendly-name capture from GAP advertisements is on by default. The BLE service-UUID enrichment dictionary now covers more consumer-tracker and accessory profiles.

- **CLI tooling for getting a fresh install running without hand-editing YAML.** `lynceus-quickstart` brings up the daemon and web UI together against a sane default config for dev/demo use. `lynceus-setup` is the interactive wizard — live Kismet and ntfy connection probes, optional Argus dataset import, and a first-run auto-import of the bundled default watchlist.

- **Read-only `/settings` page** in the web UI surfacing capture configuration, Kismet and ntfy connection status, watchlist origin breakdown, and basic system info. Sensitive values (Kismet API token, ntfy topic) are redacted server-side. Observability only — no mutation endpoints.

- **Release packaging for first-class Linux deployment.** `install.sh` (Linux-only) supports `--user`, `--system`, `--uninstall`, `--purge`, and `--dry-run`. Ships `lynceus.service` and `lynceus-ui.service` systemd units with a hardened sandbox profile (`NoNewPrivileges`, `ProtectSystem`, namespace restrictions).

- **Bundled default watchlist.** A baseline Argus-derived watchlist ships inside the wheel, and `lynceus-setup` auto-imports it on first run so a fresh install boots with something useful.

### Changed

- **DB schema** moves forward three migrations on top of v0.2: `004_watchlist_metadata`, `005_alert_watchlist_link`, and `006_tier1_capture`. Existing v0.2 databases upgrade in place.
- **Filesystem paths now follow XDG conventions.** `--user` installs land under `~/.config/lynceus/`, `~/.local/share/lynceus/`, and `~/.local/state/lynceus/`; `--system` installs land under `/etc/lynceus/`, `/var/lib/lynceus/`, and `/var/log/lynceus/`. Replaces the ad-hoc paths used in v0.2.

## [0.2.0] - 2026-05-04

- Initial tagged release: passive Kismet polling, OUI / SSID /
  BLE-UUID watchlist matching, alerts with allowlist suppression,
  ntfy push notifications, and a read-only FastAPI web UI for
  alerts, devices, rules, and the allowlist. Includes CSRF
  middleware, bulk-ack, audit trail, the `lynceus-seed-watchlist`
  CLI, and a basic systemd unit.
