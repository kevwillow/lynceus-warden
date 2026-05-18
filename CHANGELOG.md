# Changelog

All notable changes to this project will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.4.0-rc6] - 2026-05-17

Mostly cleanup. rc5 shipped the big feature push — `/watchlist` search,
filter, and pagination; `/rules` statistics; `lynceus-export-config`;
the Argus residuals audit. rc6 closes the two normalization gaps that
audit surfaced, corrects one audit verdict that turned out to be wrong
on inspection, and adds the per-alert triage-note surface (plus a
matching `/alerts` filter) that operators were quietly working around
with external trackers.

### Fixed

- **Importer admits 17 Argus rows that previously dropped as
  `unknown_type`.** The rc5 residuals audit (`docs/ARGUS_RESIDUALS.md`)
  flagged that `ble_company_id` (7 rows) and `ble_service_uuid`
  (10 rows) were semantic duplicates of the already-admitted
  `ble_manufacturer_id` and `ble_uuid` pattern types — separated only
  by the Argus type label and a couple of input-shape variants (16-bit
  and 32-bit Bluetooth SIG short forms, plus Argus's dual-form
  rendering like `"fd5a / 0x0075"` for the Samsung SmartTag / Tile Tag
  rows). The importer now aliases the two Argus types one-way onto the
  existing pattern types, and the `ble_uuid` canonicalizer accepts the
  4-hex and 8-hex short forms (expanded against the Bluetooth Core
  Spec §3.2.1 base UUID `00000000-0000-1000-8000-00805f9b34fb`) plus
  the dual-form shape (UUID half taken, paired company-id commentary
  dropped). Canonical output forms unchanged; pattern_type set
  unchanged; no schema migration. The admit count moves
  22,294 → 22,311; dropped 239 → 222; the audit's
  `admit-via-normalization` bucket is now empty.

- **`device_class_id` audit verdict corrected from
  `plausible-needs-smoke` to `drop-entirely`.** The rc5 audit deferred
  49 `device_class_id` rows — the largest deferred category — on the
  basis of plausibility rather than evidence. Going row-by-row showed
  all 49 are DJI drone model-class enum codes pulled from the
  `RUB-SysSec/DroneSecurity` decoder's `DRONEID_DRONE_TYPES` table
  (e.g. `'1'='Inspire 1'`). Those are labels for decoding the DroneID
  device-type byte, not per-device identifiers — admitting them would
  alert on every DJI drone of a given model class in range, the same
  unbounded-fanout posture the audit already records for
  `rf_channel`. Per-device Remote-ID coverage is already handled by
  the admitted `drone_id_prefix` (ANSI/CTA-2063-A serial-number
  prefix). The audit's source table is updated with the evidence; the
  regenerated report shifts `defer-pending-smoke` from 3 / 70 to
  2 / 21 and `drop-entirely` from 26 / 152 to 27 / 201. Total dropped
  row count is unchanged at 222 — the row was always dropped; only
  the reason changed.

### Added

- **Per-alert triage notes.** Closes the "what did I conclude about
  this alert?" gap operators were working around with external
  trackers. Migration 016 adds a nullable `note TEXT` column plus a
  `note_updated_at INTEGER` column to `alerts`. Notes are written
  only from the alert detail page (the daemon's add-alert path never
  touches the column); the server stores stripped text plus an
  epoch-seconds timestamp, enforces a 4096-character cap, and treats
  empty / whitespace-only text as "clear" (both columns return to
  NULL). The alert detail page gains a triage-notes section with the
  current note rendered in a `<pre>` (preserves line breaks), a
  relative-time "Last updated N ago" stamp, an editable textarea
  (4096-char `maxlength`), and Save / Clear buttons (Clear behind a
  `confirm()` prompt). The `/alerts` list page shows a 📝 indicator on
  rows that carry a note, with a 50-character tooltip preview — the
  full rationale stays on the detail page so it isn't visible over the
  shoulder. Plain text only, one note per alert (replace-on-update);
  markdown rendering, multi-operator history, and a note-history
  table are all explicitly deferred. CSRF is enforced via the
  existing global middleware.

- **`/alerts` `has_note` filter dropdown.** Pairs the list-page 📝
  indicator with a narrow-by-state filter so the triage workflow loop
  closes: notes → indicator → filter. Three values: `any` (default;
  renders byte-identical to pre-filter behaviour), `with_note`
  (filters to alerts where `note IS NOT NULL`), and `without_note`
  (the inverse). Invalid values silently fall back to `any`, matching
  the `rule_type` / `window` convention. Both the COUNT query and the
  page query consume the same internal filter helper, so the totals
  and rows stay aligned under combined filters;
  `/alerts/ack-all-visible` POSTs mirror the GET clamp exactly so
  bulk-ack always operates on the same set the operator can see. The
  template carries `has_note` through the ack-all-visible hidden
  inputs and the prev/next pagination links; the default `any` is
  omitted from URLs so the no-params baseline stays clean. No new
  indexes — `note IS [NOT] NULL` full-scans cheaply at current scale;
  a partial index is a follow-up if filter latency surfaces.

## [0.4.0-rc5] - 2026-05-17

### Added

- **`/watchlist` search, filter, and pagination.** A full Argus import
  lands ~22k rows in the watchlist, and the pre-rc5 page rendered every
  row in a single template pass — genuinely unbrowsable past a few
  thousand rows. The rc5 surface adds a filter bar (substring `q`
  across pattern / manufacturer / argus_record_id / device_category,
  plus dropdowns for `pattern_type`, `severity`, and `device_category`)
  and offset pagination matching the `/alerts` convention (`page` +
  `page_size` in {25, 50, 100, 200}, default 50). The "I know I
  imported a specific Argus row — where is it?" pain point finally has
  a real answer: type the row's `argus_record_id` substring (or its
  manufacturer, or its pattern) into `q` and the row surfaces. Filter
  state round-trips through the URL so a filtered view is bookmarkable
  and shareable. With this landing, the three list pages (`/alerts`,
  `/allowlist`, `/watchlist`) all share the same filter+pagination
  idiom — consistent operator muscle memory and a single source of
  truth for the math.

  The default render (no query params) is byte-equivalent to pre-rc5:
  severity-by-importance, then pattern alphabetical, with `id` as the
  deterministic tiebreaker so pagination doesn't flicker. Invalid
  filter values silently fall back to "all" (a stale bookmark with
  `severity=foo` lands on the unfiltered page rather than returning
  400), and an out-of-range page clamps silently to the last valid
  page (no 404 on a typo'd `?page=999`). The `device_category`
  dropdown is populated live from a `SELECT DISTINCT` against
  `watchlist_metadata`; NULL category surfaces as a dedicated
  `(uncategorized)` option backed by a `__none__` sentinel, so the
  YAML-seeded and bundled rows can be triaged separately from
  Argus-imported rows.

  No schema change, no new indexes — the 22k-row scans against
  `watchlist` complete well under the 500ms perf budget on SQLite,
  and indexing ahead of demonstrated need would trade insert/import
  cost for read cost that isn't there yet.

- **`/rules` per-rule fire count and last-fired statistics.** Answers
  the "is this rule worth keeping?" question at a glance: each rule
  row now carries its fire count over a configurable time window plus
  a relative-time "last fired" stamp ("3h ago" / "5d ago" / "—" if
  never). A `since` dropdown matches the `/alerts` convention
  (`1h` / `24h` / `7d` / `30d` / `all`) with `7d` as the default
  recency anchor, so a fresh visit reads "what fired this week" rather
  than diluting against the lifetime of the deployment. The default
  `sort=default` preserves the rules.yaml ordering, so an operator
  with a pre-rc5 `/rules` bookmark sees byte-equivalent row order on
  first visit; the `count_desc` and `count_asc` sort options are
  opt-in via the sort dropdown for "show me the high-volume rules
  first" reads. Stats are aggregated live from the `alerts` table on
  every render — a single grouped count query backed by the existing
  `idx_alerts_ts` index — so there's no schema change, no caching, and
  no invalidation surface to maintain. URL params round-trip for
  shareability: `/rules?since=24h&sort=count_desc` bookmarks exactly
  that view.

- **`lynceus-export-config` — operator-facing CLI that bundles config
  (and optionally state) into a portable `tar.gz` archive.** Closes
  the missing "save / share / back up my config" surface in the CLI
  suite, complementing `lynceus-validate` (verify a config),
  `lynceus-bootstrap-kismet` (initial Kismet install), and
  `lynceus-setup` (interactive wizard). Four operator use cases are
  in scope:

  - Backup before an upgrade.
  - Machine-to-machine migration.
  - Sharing a sanitized snapshot with the maintainer for support.
  - Template-sharing with another operator.

  **Safe by default.** A bare invocation produces a config-only
  archive with credentials redacted — `kismet_api_key`,
  `ntfy_auth_token`, `ntfy_topic`, and `user:pass@` userinfo in
  `ntfy_url` — so an operator who copy-pastes the bundle into a chat
  or a support ticket does not leak secrets. The redactor lives in
  `src/lynceus/redact.py` alongside the existing ntfy-topic shape
  helpers; redaction is line-based and preserves operator comments,
  key ordering, and whitespace. Block-scalar (`|`) and folded (`>`)
  forms of credential fields are not produced by the wizard and are
  not specially recognized.

  **Opt-outs are explicit, never default.**

  - `--include-secrets` disables redaction. For personal backups where
    the operator intends a full restore and is keeping the archive on
    their own host. Never appropriate for an archive being shared.
  - `--include-state` adds the SQLite database (and any
    `lynceus.db-shm` / `lynceus.db-wal` sidecars present) under
    `state/` in the archive. Off by default because the DB can be
    large and carries observed MAC addresses. State files are NEVER
    redacted — they're observational data, not config, and scrubbing
    them would defeat the purpose of `--include-state`. An anonymized
    state export (`--include-state-anonymized`) is deferred, not
    promised.

  **Self-describing archive.** The internal layout is:

  ```
  lynceus-export-<scope>-<UTC-timestamp>/
    README.txt           # restore guide + redaction notes
    manifest.json        # machine-readable inventory
    config/<name>.yaml   # five config files (redacted by default)
    state/               # only with --include-state
      lynceus.db
      lynceus.db-shm     # only when present on the source
      lynceus.db-wal     # only when present on the source
  ```

  `manifest.json` records the Lynceus version, the UTC export
  timestamp (ISO-8601), the resolved scope (`user` or `system`), the
  originating exporter command, the redaction policy
  (`redaction_applied: true|false`) and the full list of redacted
  fields, plus one entry per bundled file with its `size_bytes`,
  `sha256`, and `redacted` flag. Missing-on-source files are
  enumerated under `missing`; unreadable files (permission denied,
  etc.) under `errored`. Re-hashing a file on restore and comparing
  to the manifest catches transport damage. `README.txt` spells out
  the canonical restore paths for user and system scope and tells the
  receiver to replace `<REDACTED>` placeholders before the next
  daemon restart.

  **Path resolution.** `--scope {user,system,auto}` defaults to
  `auto`, which probes the existing config resolver and falls back to
  `user` if neither scope has a `lynceus.yaml`. Config files are read
  from the scope's canonical directory, except that `rules_path` /
  `allowlist_path` / `severity_overrides_path` settings inside
  `lynceus.yaml` are honoured when present (the same fields the
  daemon already follows). `allowlist_ui.yaml` is derived alongside
  the operator-curated primary so daemon-managed UI entries are
  bundled too.

  **Output safety.**

  - Refuses to overwrite an existing `--output` path; `--force` is the
    explicit opt-in. The failure mode this prevents is operators
    accidentally clobbering a prior export.
  - Refuses an `--output` that resolves to a directory.
  - Refuses an `--output` whose parent directory does not exist or
    isn't writable.
  - The default output filename is
    `lynceus-export-<scope>-<UTC-timestamp>.tar.gz` in the current
    working directory. The compact `YYYYMMDDTHHMMSSZ` form sorts
    cleanly and matches the archive's internal root directory name.

  **Dry-run.** `--dry-run` prints the inventory (per-file path + size,
  total count + bytes, scope, redaction state, included fields) and
  produces no archive. Useful for confirming that the redaction set
  covers what the operator expects.

  **Cross-platform.** Implementation uses `tarfile` and `pathlib` only
  — no shell calls — so it runs on both Linux (primary target) and
  Windows (dev box).

  **No network, no daemon dependency, read-only.** The CLI never
  writes outside `--output`, never mutates a source file, and does
  not require the daemon to be running. Operators who want to verify
  an archive before sharing can extract it on a fresh host and run
  `lynceus-validate` against the restored configs.

  Registered as a console script in both `pyproject.toml`
  `[project.scripts]` and `install.sh`'s `CONSOLE_SCRIPTS` block,
  matching the pattern set by `lynceus-validate` and
  `lynceus-bootstrap-kismet`.

- **Auto-refresh systemd timer for the Argus watchlist
  (`lynceus-refresh.service` + `lynceus-refresh.timer`).** Closes the
  loop with the rc4 staleness indicator: the indicator detects stale
  data; the timer prevents it from going stale in the first place.
  Default cadence is `OnCalendar=weekly` with
  `RandomizedDelaySec=30min` (spreads load across deployments) and
  `Persistent=true` (catches up missed runs after reboots),
  comfortably faster than the default 30-day
  `watchlist_staleness_warn_days` threshold so the `/settings` "stale"
  badge stays cold once the timer is enabled. The oneshot service
  re-runs `lynceus-import-argus --scope system --from-github` and runs
  as the same `User=lynceus` with the same hardening posture as
  `lynceus.service` (`NoNewPrivileges`, `ProtectSystem=strict`,
  restricted address families).

  **Default-off — operator opt-in only.** `install.sh --system` copies
  both unit files to `/etc/systemd/system/` and runs `daemon-reload`,
  but does NOT enable the timer. Enabling the timer is the only
  Lynceus surface that opts a host into a recurring outbound network
  call, so it stays an explicit operator decision —
  `install.sh`'s offline-invariant header comment still holds. The
  post-install summary, `lynceus-setup --system`'s closing pointer,
  and the README under "Bundled threat data → Auto-refresh" all
  surface the same one-liner:

  ```sh
  sudo systemctl enable --now lynceus-refresh.timer
  ```

  Operators who want a different cadence (daily, monthly, custom
  `OnCalendar` spec) use a drop-in override via
  `sudo systemctl edit lynceus-refresh.timer`. Timer cadence is kept
  out-of-band from `talos.yaml` on purpose — mixing the two would
  create overlapping config surfaces with no single-source-of-truth
  answer for which wins.

  **Failure semantics.** A transient GitHub outage, network blip, or
  malformed export fails the oneshot run; systemd journals it under
  `journalctl -u lynceus-refresh.service`; the next scheduled fire
  retries. No `Restart=` directive — tight retry loops on a sustained
  outage burn through the GitHub API budget and never resolve. The
  daemon is unaffected: SQLite WAL mode tolerates the concurrent
  reader/writer between the importer's oneshot write and the daemon's
  continuous read/write loop.

  `uninstall.sh` removes both new unit files alongside the daemon and
  UI units; a `--purge` run also wipes `/var/lib/lynceus` (which
  holds the `argus-cache/` subdirectory the refresh populates).
  User-scope installs do not ship the timer (no systemd integration
  on `--user`); the bundled-watchlist + on-demand
  `lynceus-import-argus --from-github` story is unchanged for that
  scope.

- **`/alerts` filter bar grows `rule_type` / `q` / `window`, and
  `/alerts` + `/allowlist` share a unified pagination model.**
  Fulfills the "pagination deferred" promise from the `/allowlist`
  management surface bullet below: rather than two divergent
  paginators, both pages now route through a single pagination helper
  (`src/lynceus/webui/pagination.py`) with the same allowed `per_page`
  set (`{25, 50, 100, 200}`, default `50`), the same footer copy
  (`Page N of M · K total · per_page=PP`), and the same clamp-silently
  semantics for out-of-range inputs. New `/alerts` filter dimensions:

  - `rule_type=<literal>` — narrows by the rule's `rule_type`. The
    full set is derived at module load from
    `typing.get_args(rules.RuleType)`, so a new literal added to that
    type alias automatically appears in the dropdown — no manual list
    to drift. Invalid values fall back to "any" rather than 400, so
    stale URLs survive a `RuleType` extension.
  - `q=<substring>` — case-insensitive substring against MAC, message,
    and manufacturer (via the existing `watchlist_metadata` LEFT JOIN,
    with `COALESCE` NULL-safety for alerts without a MAC or without a
    matched watchlist row). Distinct from the pre-existing `search`
    filter (which matches `rule_name` + `message`); both apply
    alongside if both are set.
  - `window=1h|24h|7d|30d` — relative time window resolved server-side
    at request time. Anchors "what does this URL show" to the
    recipient's open-time clock so a shared link means the same
    recency to any operator. Combines with the pre-existing absolute
    `since` / `until` by taking the tighter (more-recent) lower bound
    on the timestamp axis.

  Pre-rc5 query params on `/alerts` (`severity`, `acknowledged`,
  `since`, `until`, `search`, `page`, `page_size`) keep byte-identical
  semantics — bookmarked URLs from earlier versions resolve unchanged.
  The pre-existing `page_size` validation widens slightly: invalid
  values now silently fall back to the default (`50`) rather than 400;
  the allowed set drops `10` (operators relying on dense renders move
  to `25`).

  **Schema change: `alerts.rule_type TEXT`** (migration 015). The
  rule-type value has been carried in-memory since the project
  started but the alert writer dropped it on the floor; the new
  filter forced persistence. Historical rows pre-rc5 carry `NULL`
  (the `rule_name → rule_type` mapping requires the loaded ruleset
  and isn't recoverable retroactively); the filter default ("any")
  includes them and a specific `rule_type=...` filter excludes them —
  the honest answer for "unknown type." No new index: `rule_type`
  filtering composes with the existing `ts DESC + LIMIT` slice and
  the `ts` index dominates in practice. A `(rule_type, ts)` composite
  is a future optimization gated on combined-filter `COUNT(*)`
  latency.

  **`/alerts/ack-all-visible` filter set mirrors the page GET
  byte-identical.** The bulk-write surface MUST see the same filtered
  set the operator sees on the page; a divergence (e.g. a new filter
  wired to GET but not to the POST) would silently ack alerts the
  operator can't see — worst-class bug class for a non-reversible
  bulk operation. Every new filter is plumbed through both surfaces
  in the same commit.

  **`/allowlist` pagination.** Reuses the same pagination helper with
  the same per_page set, default, and footer copy. Pagination is
  applied in Python on the already-filtered list because the
  allowlist lives in YAML on disk, not a DB table — the math is
  identical to `/alerts`, only the slice substrate differs. Filter
  dimensions are unchanged in this bullet (only pagination added).

  **Out-of-range behaviour is "clamp silently" rather than
  "raise 4xx."** Operator UX wins for an entirely non-mutating GET
  surface: `?page=999` lands on the last valid page; `?per_page=37`
  falls back to default; `?rule_type=bogus` ignores the filter rather
  than 400. Stale bookmarks survive a rule-set extension, a per_page
  set change, or a typo.

  **Single source of truth for filters across COUNT and the page
  query.** The alerts count and the page query share the same
  filter-clause builder, so the "K total" the footer prints can't
  drift from the rows actually rendered — otherwise the pagination
  math becomes a lie. Same shape on `/allowlist` (one filter pass,
  one slice).

- **`/allowlist` management surface — search, filter, add entry, and
  bulk remove.** Closes the "edit `allowlist_ui.yaml` by hand to
  manage allowlists" gap that has existed since the snooze/allowlist
  UI prompt added per-alert mutation routes but left the management
  view read-only. Operators can now do the full lifecycle from the
  browser without dropping to a shell.

  **Filter bar.** GET-form on `/allowlist` accepts four query
  parameters and round-trips them through the URL:

  - `q=<substring>` — case-insensitive substring match against
    `pattern` + `note`.
  - `source=primary|ui|all` — discriminates entries by the file they
    came from. Primary = operator-curated `allowlist.yaml`; UI =
    daemon-managed `allowlist_ui.yaml`.
  - `status=active|snoozed|expired|all` — `active` = no `expires_at`;
    `snoozed` = future `expires_at`; `expired` = past `expires_at`.
    Expired entries are no longer suppressing alerts at poll time,
    but they stay rendered so operators can bulk-clean them.
  - `type=mac|oui|ssid|mac_range|ble_uuid|ble_manufacturer_id|drone_id_prefix|all`
    — narrows by `pattern_type`.

  All four AND together; an empty result renders an inline empty-state
  with a reset link. Filters are server-side over the merged
  primary+UI in-memory list; no DB schema, no new indexes.

  **Add-entry form.** Collapsible `<details>` section above the table;
  expands automatically on a validation error so the rejected input
  survives the round-trip with an inline error message. Inputs pass
  through the same canonicalization helpers (`normalize_pattern`,
  `parse_mac_range_pattern`) the importer uses, so an operator
  pasting an uppercase MAC, a Cisco-dotted MAC, an `0x004C`-shaped
  manufacturer id, or a legacy bare-prefix mac_range gets the same
  canonical row the importer would write — and an invalid one
  surfaces the validator's exception verbatim, never a write to disk.
  Successful add redirects to `/allowlist?success=add` with a
  one-shot flash message.

  **Bulk remove.** Checkboxes on UI-source rows only; the form wraps
  the table and POSTs to `/allowlist/bulk_remove`. The handler reads
  the UI file once, filters in memory, and emits a single atomic
  write covering all N selections — bulk operations land as exactly
  one mtime tick for the poller's reload watcher rather than N. The
  single-entry remove path is left unchanged; bulk uses its own path
  so the atomic-write contract is obvious by name.

  **Primary-source read-only protection (hard invariant).** The
  daemon never writes to `allowlist.yaml`. The /allowlist surface
  enforces this by construction:

  - Primary rows render with a `[primary]` badge and a dash in the
    checkbox cell — there is no DOM input to select them. The
    bulk-remove form can't see them.
  - The `POST /allowlist/bulk_remove` handler load-with-source on
    every request and refuses the entire batch with HTTP 400 if any
    submitted composite key matches a primary entry — no partial
    removes. A hostile form submission that enlists a primary key
    alongside legitimate UI keys fails atomically; the UI rows are
    not silently deleted while the operator is told the primary
    refused.
  - `POST /allowlist/add` writes only to `allowlist_ui.yaml`. The
    primary file's bytes (and mtime) are unchanged across the
    request, verified by a test fixture that snapshots an operator
    comment + entry block round-trip.

  **AllowlistEntry pattern_type extension (backend).** Previously the
  allowlist only suppressed `mac`/`oui`/`ssid` alerts — the four
  pattern types the watchlist gained later (`mac_range`, `ble_uuid`,
  `ble_manufacturer_id`, `drone_id_prefix`) had no allowlist
  counterpart, so an operator who wanted to silence an alert keyed
  off one of them had to fall back to the device's MAC and lose the
  broader-shape suppression. AllowlistEntry now accepts all seven
  types; each is matched against the same observation field the
  watchlist branch matches against, so suppression and alerting see
  the same truth (no drift). The validator routes every type through
  `lynceus.patterns` so the canonical form stored in
  `allowlist_ui.yaml` is byte-identical to the form stored in
  `watchlist.pattern` for the same input — equality lookups stay
  direct.

  **Pagination deferred.** Assumes small-to-medium allowlists (<500
  entries) where every entry fits on one screen. Pagination lands as
  a unified webui-pagination prompt alongside `/alerts` filtering
  later in this rc. Bulk operations are correspondingly bounded by
  what fits in a single render rather than enforced server-side;
  operators with thousands of allowlist entries are out of scope for
  v1.

- **`lynceus-bootstrap-kismet` — new operator-facing helper that takes
  a fresh Debian / Ubuntu / Kali host from "no Kismet installed" to
  "Kismet installed, capture interfaces configured, kismet group set
  up, ready for the operator to open the web UI, set a password, and
  generate the API key `lynceus-setup` will pick up."** Closes the
  "what do I do before running lynceus-setup?" gap for new operators.

  Scope is bounded by Kismet's apt-repo coverage: Debian (`bookworm`,
  `trixie`), Ubuntu (`focal`, `jammy`, `noble`, `plucky`), and Kali.
  On any other distro the script prints a pointer to
  <https://www.kismetwireless.net/packages/> and exits 0 — the
  operator isn't broken, they just need to install Kismet by hand.

  What it does, in order:

  1. Refuses to run if not root; exits 2.
  2. Reads `/etc/os-release` to gate on supported distro.
  3. If `kismet` is not on PATH and `--skip-install` was not passed:
     downloads the Kismet GPG key (via stdlib `urllib`, no `wget`
     dependency), dearmors it through `gpg --dearmor` to
     `/usr/share/keyrings/kismet-archive-keyring.gpg`, writes the
     codename-specific
     `deb [signed-by=…] https://www.kismetwireless.net/repos/apt/release/<codename> <codename> main`
     line to `/etc/apt/sources.list.d/kismet.list`, runs
     `apt-get update`, and runs
     `DEBIAN_FRONTEND=noninteractive apt-get install -y kismet`. The
     noninteractive frontend matters — Kismet's postinst defaults to
     prompting for "Install with suid root?" and would hang an
     unattended run.
  4. Detects Wi-Fi monitor-mode-capable interfaces via `iw dev` +
     `iw phy <phy> info` parsing (looking for the `* monitor` bullet
     in `Supported interface modes:`), and Bluetooth controllers via
     `/sys/class/bluetooth/hci*` (sysfs is the canonical source —
     works regardless of whether `bluetoothctl` is installed). Per
     interface, asks Y/n with default Y so the common case is hitting
     Enter through.
  5. Patches `/etc/kismet/kismet_site.conf` append-only: each selected
     Wi-Fi interface gets a `source=<iface>:type=linuxwifi` line, each
     BT controller gets `source=<iface>:type=linuxbluetooth`.
     Idempotent — an interface that already heads an existing
     `source=` line is skipped regardless of suffix, so operator
     customizations (`name=…`, `channel_list=…`) are preserved.
     Atomic write via `tempfile.mkstemp` + `os.replace` so a Kismet
     daemon reading the file mid-update never sees a partial write.
  6. Adds the invoking operator (`$SUDO_USER`) to the `kismet` group
     if not already a member. If the group does not exist — the
     .deb's postinst should create it — the script does NOT silently
     `groupadd`. It surfaces the missing group as an error pointing
     back to the package install, because a missing group is a signal
     that `apt install kismet` didn't behave as expected and adding
     the operator to a hand-rolled group would not give them capture
     capabilities.
  7. Prints the closing block: log out + back in (group membership
     doesn't propagate to running shells), how to start Kismet
     (`systemctl start kismet` or foreground for first-launch
     password setup), the web-UI URL, the API-key creation walkthrough
     (`Settings → API Keys → Create`, `Name: lynceus, Role: readonly`),
     and `sudo lynceus-setup`.

  **`install.sh` stays offline.** This script is the one that uses
  the network for apt operations; the boundary is preserved
  intentionally. The threat-model invariant that an operator can read
  `install.sh` before running it without that script then curling
  third parties is unchanged.

  **Idempotent on every step.** Re-running on a partially-set-up
  host: already-installed Kismet → "kismet binary already on PATH",
  skip apt install (or re-run if the operator says Y);
  already-configured apt source → skip add-source, just
  `apt-get update`; pre-existing `kismet_site.conf` → diff and append
  missing lines only; operator already in `kismet` group → skip
  `usermod`. Second run is safe to invoke from any
  partially-successful first run.

  Flags:

  - `--skip-install` — Kismet is already present (manual build,
    different package, etc.); skip the apt steps but still do
    interface config + permissions.
  - `--interface <name>` (repeatable) — bypass auto-detection and
    configure these interfaces explicitly. Pairs with
    `--interface-type {wifi,bt}` (default `wifi`).
  - `--no-network` — refuse any apt / network operation. Implies
    `--skip-install`. For operators who installed Kismet from
    air-gapped media.
  - `--dry-run` — print every command + file write, but execute
    nothing. Operator prompts still appear so the preview reflects
    the choices that would actually be made.
  - `--yes` — accept every Y/n prompt with its default (most are Y;
    the "re-install on top of existing Kismet?" prompt defaults to N).
    For scripted bootstrap.

  Exit codes: 0 success or unsupported-distro, 1 recoverable failure
  (operator action: fix + re-run), 2 tool-level failure (not root,
  not Linux).

  Wired into `install.sh`'s `CONSOLE_SCRIPTS` symlink layer (same
  pattern the `lynceus-validate` addition followed) and into
  `pyproject.toml`'s `[project.scripts]`. `install.sh`'s post-install
  hint block now mentions `sudo lynceus-bootstrap-kismet` alongside
  `lynceus-setup`, and the `lynceus-setup` wizard's "If Kismet isn't
  installed or running yet" context block points operators at it as a
  concrete option. End-to-end testing requires a fresh
  Debian/Ubuntu/Kali VM and is manual-smoke territory.

- **`lynceus-setup` Kismet API key prompt now auto-locates an existing
  key from disk before falling through to the manual copy-paste
  flow.** The wizard reads Kismet's per-user `~/.kismet/session.db`
  (under `--system` it also checks the invoking operator's
  `SUDO_USER` home, then `/root/.kismet/`), parses the JSON array of
  `{token, name, role, ...}` objects Kismet has written there since
  the 2022-08 Boost.Beast server rewrite, and picks the best match: a
  key named `lynceus`, else a `readonly` key, else `admin`, else the
  first non-empty token.

  On hit, the wizard shows the source path, a redacted preview
  (first 4 chars + ellipsis + last 4 chars — short keys collapse to a
  `***` placeholder), and asks `Use this key? [Y/n]`. Y stores the
  key and skips the manual prompt + walkthrough. N falls through to
  the existing manual walkthrough unchanged.

  Auto-locate is purely additive — every failure mode (missing file,
  unreadable, malformed JSON, no usable entry, Windows host) results
  in a silent fall-through to the existing manual flow. The operator
  only ever sees `Searching for an existing API key on disk...`
  followed by `Found a key in <path>` or `no existing key found`;
  permission denials, parse errors, and filesystem paths beyond the
  located one are never surfaced.

  **Redaction contract:** the located key is never echoed in full —
  only the head/tail preview. Tests assert the sentinel key value
  never appears in captured stdout or stderr under any flow,
  including the accept-the-key path where the key ends up in the
  generated `lynceus.yaml`.

  Closes the "where do I find this?" friction that the rc5
  walkthrough explained but didn't eliminate. An operator with a
  working Kismet install no longer has to log into the web UI to
  copy-paste a key the wizard could read for them.

  No new dependencies, no new config fields (candidate paths are
  hardcoded per scope), no network calls. Read-only — the wizard
  never writes to Kismet's config files.

- **`GET /healthz.json` — machine-readable health endpoint for
  monitoring integration.** Returns JSON with overall status plus
  per-check details (DB reachability, daemon liveness, watchlist
  freshness, ruleset count, alert counts). Read-only, no auth,
  derived entirely from existing DB + filesystem state — no new
  tables, no heartbeat infrastructure, no daemon-side changes.

  HTTP semantics follow the standard monitoring convention: 200 when
  the top-level status is `ok`, 503 when it is `error`. Currently
  only the DB-reachable check can flip the top-level status; the
  other checks return `status: ok` with values the monitoring tool
  can apply its own thresholds against. When the DB is unreachable
  the response carries only the `db` check (the others can't be
  computed without DB access).

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

  The `poller` check carries two signals — `last_poll_at` (from
  `poller_state.last_poll_ts`, written by the daemon every tick,
  proxies "daemon process alive") and `last_observation_at`
  (`MAX(sightings.ts)`, proxies "Kismet returning data"). Both are
  index-backed single-row lookups; sub-second response on a populated
  DB. The `watchlist.stale` boolean uses the same
  `watchlist_staleness_warn_days` threshold the startup log line and
  `/settings` card already use.

  **Shape-stability commitment:** existing keys never disappear in
  future releases; future releases only add keys. Monitoring tools
  can pin against this shape without expecting churn.

  **Path choice — new sibling, not replacement.** The existing
  `/healthz` HTML page (linked from the topnav, grep'd by
  `docs/SMOKE.md`, polled for HTTP 200 by `lynceus-quickstart`) is
  kept unchanged. The JSON endpoint lives at `/healthz.json` so the
  human-facing nav, the smoke runbook, and the quickstart readiness
  probe all stay untouched. Content-negotiation single-path design
  was considered and rejected: a `curl` without
  `Accept: application/json` would get HTML, which monitoring tools
  then try to parse as JSON — fragile against the shape-stability
  commitment.

  Example invocation:

      curl -sS http://127.0.0.1:8765/healthz.json | jq .

  Polling at the typical 30s cadence adds no measurable load — every
  query is index-backed.

  Out of scope for v1 (future polish): authentication, Prometheus
  text-format exposition at `/metrics`, response caching,
  configurable thresholds, top-level status flips on non-DB failures,
  daemon-side heartbeat infrastructure.

- **`lynceus-validate` CLI — read-only configuration validator.**
  Catches typos, schema errors, malformed values, and missing
  referenced paths at edit time instead of at the next daemon
  restart. Wraps the existing loaders so the diagnoses are exactly
  what the daemon would hit — no separate validation logic to drift.

  Covers the five files an operator may maintain:

  - `lynceus.yaml` — Pydantic schema check; missing-file ERROR for
    each populated `*_path` reference.
  - `rules.yaml` — surfaces the ruleset loader's errors (duplicate
    names, invalid `rule_type`, malformed patterns, delegation-shape
    violations); an empty ruleset is a WARNING.
  - `severity_overrides.yaml` — louder at edit time than the daemon.
    The runtime loader is lenient by design (malformed values land as
    WARNING + pass-through so the poller never crashes); the
    validator promotes those to ERROR. Adds edit-time-only checks:
    unknown top-level keys get a Levenshtein-distance hint
    (`'supress_categories' -- did you mean 'suppress_categories'?`),
    unknown Argus device categories WARN, `pattern_overrides` keys
    not matching the 16-hex `argus_record_id` shape ERROR.
  - `allowlist.yaml` — Pydantic validation; entries with `expires_at`
    in the past WARN ("it will never match — consider removing").
  - `allowlist_ui.yaml` — same shape; missing file is normal (no UI
    writes yet).

  Exit-code contract is stable for CI / pre-commit hook use:

  - `0` — no errors (warnings may exist).
  - `1` — errors found.
  - `2` — tool-level failure (config dir unreachable).

  Scope handling matches `lynceus-import-argus`: `--scope user`
  (default) or `--scope system`. The validator never modifies any
  file — pure read-only. Output is plain ASCII (no ANSI color, no
  emoji) so operators can grep / awk it from scripts. `--quiet`
  suppresses OK and WARNING lines for CI usage where only ERRORs
  matter.

  Example invocation:

      sudo lynceus-validate --scope system

  Example output:

      Validating Lynceus configuration (scope: system)

      /etc/lynceus/lynceus.yaml
        OK (schema valid; all referenced paths exist)

      /etc/lynceus/severity_overrides.yaml
        ERROR (line 8): invalid severity 'medium' for category
                        'unknown' -- must be one of: low, med, high
        ERROR (line 14): unknown key 'supress_categories' -- did
                         you mean 'suppress_categories'?

      Summary: 2 errors, 0 warnings across 2 files

  Cross-file checks against live DB state (e.g. validating that
  `pattern_overrides` keys correspond to real `argus_record_id`
  values in the watchlist) are deliberately out of scope for v1; the
  validator never opens the DB. A future `--check-db` flag could add
  that.

- **Alert detail page gains triage buttons: Allowlist, Snooze 24h,
  Remove.** Operators triaging a false-positive alert no longer need
  to edit `allowlist.yaml` and restart the daemon — one click on
  `/alerts/<id>` writes a MAC-keyed entry to the daemon-managed
  `allowlist_ui.yaml` sibling, the poller picks it up on its next
  tick via the mtime watch, and future alerts for that device are
  suppressed immediately. Builds on the allowlist backend reshape
  (`expires_at` + `added_at`, split storage, runtime reload, atomic
  writers) that landed earlier in this rc.

  Three POST routes under `/alerts/{id}`:

  - `/allowlist` — writes a permanent (no `expires_at`) entry, note
    prefix `added via webui at <ISO>`.
  - `/snooze` — writes an entry with `expires_at = now + 86400`
    seconds, note prefix `snoozed 24h via webui at <ISO>`. The fixed
    24h window is the only operator-comfort cadence available from
    the UI; custom durations are deliberately out of scope (operators
    wanting non-24h windows edit the YAML directly).
  - `/allowlist/remove` — idempotent removal by MAC. Returns 303
    whether the entry existed or not; the redirect re-renders the
    truth, which is more useful than a stale error.

  All three share the same validation set: alert exists (404
  otherwise), alert carries a MAC (400 otherwise — alerts without a
  MAC, e.g. per-source-count rules, can't be triaged this way),
  `allowlist_path` is configured (400 otherwise — there's no file to
  write to). CSRF protection is the standard `_csrf` form field plus
  `lynceus_csrf` cookie that the existing middleware enforces;
  forged POSTs return 403.

  The alert-detail template renders one of three states in a new
  `triage` article, distinct from the existing `actions` (ack/unack)
  article so the two concerns stay visually separate:

  - **State 1 (not allowlisted):** Allowlist + Snooze 24h buttons.
    Vanilla `window.confirm()` on submit — no modal framework, no JS
    dependency.
  - **State 2 (permanently allowlisted):** "Allowlisted (added
    YYYY-MM-DD HH:MM UTC)" status. A Remove button if the match came
    from the daemon-managed UI sibling; an explanatory hint pointing
    at `allowlist.yaml` if the match came from the operator-curated
    primary (the daemon cannot edit that file, so a button there
    would silently no-op).
  - **State 3 (snoozed):** "Snoozed until YYYY-MM-DD HH:MM UTC (N
    hours remaining)" status. Cancel snooze button on UI-sibling
    matches; same primary-file hint otherwise. Hours-remaining is
    computed against the request's `now_ts` and rounded up so a
    partial hour shows as ≥ 1.

  The triage section is omitted entirely when `allowlist_path` is
  unset or when the alert carries no MAC. The existing /alerts/<id>
  render path is otherwise unchanged.

  **Closes the documented limitation in the `pattern_overrides` note**
  that pointed operators at allowlist edits for non-Argus row
  suppression. The allowlist remains the right tool for that case;
  the YAML-edit-and-restart friction is now gone.

- **Allowlist supports temporary entries via `expires_at`, and the
  daemon picks up edits without a restart.** Three operator-facing
  changes land together to set up the operator-comfort UI work
  tracked separately:

  - `AllowlistEntry` gains two optional fields: `expires_at` (Unix
    epoch seconds; `None` means permanent) and `added_at` (Unix epoch
    seconds at which the entry was created). Both default to `None`
    so existing operator-curated `allowlist.yaml` files parse
    unchanged. Entries whose `expires_at` is at or before the
    evaluation clock are silently skipped at poll time — that is the
    "snooze expired" path.

  - The poller stat()s the allowlist file(s) before every poll tick
    and reloads the in-memory `Allowlist` when either mtime has moved.
    Daemon restart is no longer required for allowlist edits. A
    missing file maps to sentinel mtime 0.0, so a file appearing for
    the first time and a file being deleted both register as changes
    — except that a deleted primary triggers a WARNING and the daemon
    retains its last-known-good entries rather than dropping every
    suppression at once (defends against the operator-mid-rename /
    fat-fingered-rm case). Each reload emits a single INFO line of
    the form `allowlist reloaded: N operator entries + M UI entries`.

  - Allowlist storage splits into two YAML files. `allowlist.yaml`
    (the operator-curated primary, path set via
    `Config.allowlist_path`) is read-only from the daemon's
    perspective — Lynceus never writes to it, so hand-formatting,
    comments, and key ordering are preserved indefinitely. A sibling
    `allowlist_ui.yaml` (path derived by inserting `_ui` before the
    suffix, e.g. `/etc/lynceus/allowlist.yaml` →
    `/etc/lynceus/allowlist_ui.yaml`) is daemon-managed: created on
    first write by the UI mutation routes, and merged into the
    in-memory allowlist transparently at load. An absent UI file is
    the normal pre-first-write state and is not an error; a malformed
    UI file logs WARNING and is treated as empty so a corrupt sibling
    cannot cripple suppression. A malformed primary logs ERROR and is
    treated as empty — the startup ERROR line in journalctl is the
    surfacing path for an operator's syntax slip; pre-rc5 behaviour
    would have crashed the poller init.

  Two writer helpers ship in the allowlist module so the UI routes
  have a stable API to call: an append-and-create-atomically writer
  for additions, and a canonical-pattern remover that returns whether
  it actually matched. Concurrent UI writes are last-write-wins by
  file mtime — the cadence is operator-driven (manual button clicks)
  so locking is not warranted at this scale.

  The existing `Allowlist.is_allowed(obs)` signature gains an optional
  `now_ts: int | None = None` parameter (default to wall clock) and
  the return type changes from `bool` to `AllowlistEntry | None` —
  the matched entry's `expires_at` is what lets the poller annotate
  the suppression audit line. Callers that only needed a boolean keep
  working because `None` is falsy and `AllowlistEntry` is truthy; the
  four in-tree tests that asserted strict `is True` / `is False`
  identity were updated to `is not None` / `is None`.

  The existing audit INFO line at the allowlist-suppression site
  keeps its `Allowlist suppressed watchlist hit: rule=… mac=… severity=…`
  prefix verbatim — operators grepping for it across journalctl
  history are unaffected — and appends ` (expires <ISO>)` only when
  the matched entry carries a non-None `expires_at`. Permanent
  suppressions emit the same line they always did.

- **`identifier_type='ble_manufacturer_id'` and
  `identifier_type='drone_id_prefix'` rows from Argus now land in the
  watchlist instead of being silently dropped.** Pre-rc5, every row
  of these two types hit the importer's identifier-type allowlist
  gate, fell to the `dropped_unknown_type` counter, and never reached
  the DB. Against Argus's live `argus_export.csv` snapshot at
  `exported_at=2026-05-14T22:34:07Z`:

  - `ble_manufacturer_id`: 3,969 rows (Bluetooth SIG 16-bit Company
    Identifiers, e.g. `0x004C` for Apple).
  - `drone_id_prefix`: 427 rows (ANSI/CTA-2063-A Remote-ID
    serial-number prefixes, e.g. `21239ESA2`).

  The `dropped_unknown_type` counter for that snapshot moves from
  4,635 → 239 — a 4,396-row drop, exactly the sum of the two new
  types. Residual types (`ble_company_id`, `ble_service_uuid`,
  `chipset_codename`, `firmware_build_*`, etc.) remain deferred to
  future prompts.

  Migration 013 (`013_pattern_type_extension.sql`) rebuilds the
  `watchlist` table to relax the `pattern_type` CHECK constraint,
  mirroring migration 011's mac_range pattern: full table rebuild
  under `PRAGMA foreign_keys=OFF` (SQLite cannot modify a CHECK via
  `ALTER TABLE` per SQLite docs §7), AUTOINCREMENT ROWIDs preserved,
  the `mac_range_prefix` / `mac_range_prefix_length` columns and the
  partial index from 011 carried across unchanged. No new metadata
  columns: both new types are equality-shaped at the string level and
  reuse the existing simple-watchlist match SELECT.

  Two new canonicalizers in `lynceus.patterns`:

  - `ble_manufacturer_id`: `'0x004C'` → `'004c'` (4-hex-char
    lowercase, no `'0x'` prefix, zero-padded). Lowercase chosen so
    the runtime equality lookup against a Kismet
    advertisement-decoded field (most likely delivered as bare hex)
    is a direct string compare. Defensive rejects: empty,
    just-prefix, >4 hex chars (16-bit constraint is hard), non-hex.
  - `drone_id_prefix`: `'21239ESA2'` → `'21239ESA2'` (uppercase ASCII
    alphanumeric, 3-32 chars). Uppercase mirrors Argus's emission
    verbatim — ANSI/CTA-2063-A serials are case-sensitive per the
    standard; lowercasing would silently break equality against real
    serials. Defensive rejects: empty, <3 or >32 chars,
    non-alphanumeric, non-ASCII.

- **`watchlist_ble_manufacturer_id` and `watchlist_drone_id_prefix`
  rule types — extends the rc4 delegation pattern to two more
  identifier types.** Same empty-patterns-delegates-to-DB shape
  established by `watchlist_mac` / `watchlist_oui` /
  `watchlist_ssid` / `ble_uuid` in rc4: a single empty-patterns rule
  of the new type enables alert-firing for every matching row of that
  pattern_type in the watchlist DB; severity is sourced from the
  matched DB row (NOT from `rule.severity`, which is IGNORED for
  delegation, per the rc4 architectural divergence documented under
  `watchlist_mac_range`); the existing runtime override layer
  (`suppress_vendors`, `suppress_categories`, `pattern_overrides`,
  `device_category_severity`) applies transparently with no changes.

  Three additions land together:

  - New matchers for the two new pattern types delegate to the
    existing simple-watchlist lookup so the SQL cannot drift from the
    annotation path that stamps `matched_watchlist_id`.

  - `rules.evaluate` admits the two new rule types and extends the
    validator carve-out: both accept empty AND non-empty patterns
    (the delegation-capable shape; no required-empty constraint like
    `watchlist_mac_range`, since equality match on a single
    canonical-string field is a sensible in-memory shape too).
    Non-empty patterns are normalized at load time through
    `patterns.normalize_pattern` so an inline `0x004C` in rules.yaml
    matches the bare-hex `004c` carried on the observation.

  - The wizard's enable-alerting flow grows two more per-type prompts,
    each gated by a watchlist row-count check — operators with an
    empty pattern_type don't see the prompt. Operators who already
    enabled alerting can re-run `lynceus-setup --reconfigure` to add
    the new types; the existing rules.yaml overwrite-protection
    (default N) stays in force.

  **CAVEAT — runtime alerting depends on Kismet probe-path
  verification at smoke time.** `DeviceObservation` gains two new
  optional fields (`ble_manufacturer_id`, `drone_id_prefix`) and the
  Kismet device parser populates them via two best-effort extractors
  that walk a small table of likely Kismet field paths. These paths
  are derived from public Kismet schema documentation, NOT confirmed
  against a live capture — the Lynceus codebase had no prior consumer
  of either surface. Until the paths are confirmed and corrected
  against a real Kismet emission, both fields read `None` on real
  hardware and the delegation rules fire zero alerts. The import + DB
  + rules-engine + wizard pipeline is load-bearing in the meantime:
  rows land in the watchlist DB, appear in the `/watchlist` UI, and
  contribute to the `/settings` count card; only the alert-time match
  against a live observation is gated on the Kismet half being wired
  up.

  **Drone Remote-ID type-layer gates closed (mid-rc5).** The initial
  rc5 cut shipped with two structural gates that blocked Remote-ID
  observations independently of the probe-path uncertainty: the
  Kismet type map admitted only Wi-Fi / BTLE / Bluetooth device
  types, dropping records typed `'Remote ID'` before they reached the
  drone-id extractor; and the `devices.device_type` CHECK constraint
  from migration 001 would have rejected the corresponding internal
  category even if the type-map gate were lifted. Both are now
  closed:

  - **`migrations/014_devices_remote_id.sql`** rebuilds the `devices`
    table to extend the `device_type` CHECK from
    `('wifi','ble','bt_classic')` to add `'remote_id'`, mirroring
    migration 011 / 013's full-table-rebuild discipline (SQLite
    cannot modify a CHECK via `ALTER TABLE` per SQLite docs §7;
    `PRAGMA foreign_keys=OFF` during the rebuild so the inbound FKs
    from `sightings.mac` and `alerts.mac` don't fire during the
    intermediate `DROP TABLE`; the additive migration-006 columns
    `probe_ssids` and `ble_name` are carried across verbatim). The
    new internal category name matches the existing
    lowercase-with-underscores convention used by `'bt_classic'`.
    The naming axis is intentionally distinct from the watchlist
    `pattern_type` (`'drone_id_prefix'`, admitted by migration 013):
    the watchlist type names *what is matched* (a serial prefix),
    the device_type names *what category of device emitted it* (a
    Remote-ID broadcaster, conceptually a peer of wifi / ble /
    bt_classic at the radio-source layer).

  - **Kismet type-map extension.** Two Remote-ID Kismet device-type
    strings now map to the new `'remote_id'` internal category:
    `'Remote ID'` and `'Remote ID Drone'`. Defensive multi-alias
    coverage — Kismet's exact emission for ASTM F3411 Remote-ID
    devices varies by version + datasource configuration, so
    confirming the specific live string is an operator-smoke step and
    adding it is a one-line edit. The existing four mappings are
    unchanged.

  - **Drone-ID probe-path refinement.** The probe table is re-anchored
    on the canonical `kismet.device.base.*` convention every other
    top-level Kismet field uses. Two new probe paths take the front
    of the table — `kismet.device.base.remote_id.serial_number` and
    `kismet.device.base.remote_id.uas_id` — with the original
    `remoteid.device.basic_id.*` paths retained as fallbacks for
    older / alternate Kismet RID datasources. First match wins;
    promoting the confirmed live path to the front is a one-line
    edit.

  - **Device-type filter API parity.** The DB-level device-types and
    the corresponding hard-coded validator on the
    `/devices?device_type=...` query handler admit the new
    `'remote_id'` value so the DB-level filter API and the UI route
    are in sync. The `/devices` filter dropdown template is unchanged
    and still lists only the original three types; operators who
    want a Remote-ID-only view can pass the query parameter directly.
    Adding the dropdown option is a separate UI polish item, tracked
    outside this caveat.

  The four touches together collapse the rc5 caveat from "two
  structural gates AND probe-path verification" to "probe-path
  verification at smoke time" for both `drone_id_prefix` and
  `ble_manufacturer_id`.

- **Annotation-path closure for `ble_manufacturer_id` and
  `drone_id_prefix` (rc5 in-flight).** Surfaced during the type-layer
  gate work: the rc4 annotation path walked only the original five
  pattern_types (`mac > oui > mac_range > ssid > ble_uuid`), so
  alerts fired by the two new delegation rule types
  (`watchlist_ble_manufacturer_id`, `watchlist_drone_id_prefix`)
  landed with `matched_watchlist_id=NULL`. The right `rule_name` and
  DB-sourced severity flowed through, but the alert → watchlist-row
  click-through, ntfy enrichment, and the audit trail all keyed off
  `matched_watchlist_id` and went cold for these two rule_types.

  The walk now covers all seven pattern_types in tiebreaker order:

      mac > oui > ble_manufacturer_id > mac_range >
      drone_id_prefix > ssid > ble_uuid

  `ble_manufacturer_id` slots between `oui` and `mac_range` (same
  vendor-level specificity tier as `oui`, 16-bit BLE Company
  Identifier instead of the 24-bit IEEE OUI — a direct `mac`/`oui`
  hit on the same observation outranks the vendor-wide BLE company
  id). `drone_id_prefix` slots between `mac_range` and `ssid` (a
  serial-shaped device identifier is stronger evidence than a
  free-form SSID string, weaker than a curated mac_range catching the
  device's MAC). Both new branches are no-op when the observation
  carries `None` for the corresponding field, preserving the existing
  5-type behaviour for every caller that doesn't pass the new kwargs.

  The poller is updated in lockstep to pass `obs.ble_manufacturer_id`
  and `obs.drone_id_prefix` through to the annotation call, so alerts
  for the two new rule_types now stamp `matched_watchlist_id`
  correctly. No DB schema change.

  **Operator UX note for BT- and Remote-ID-capable deployments.**
  Operators running Kismet with the BT scanner enabled gain a
  watchlist of 3,969 BLE manufacturer signatures the moment they
  re-import the Argus CSV. Once the Kismet field-path verification
  lands, those signatures fire alerts on every BLE advertisement
  carrying a watchlisted manufacturer id — defensive coverage
  against manufacturer-specific surveillance hardware that broadcasts
  via BTLE. Equivalently for operators running Kismet with the
  Remote-ID datasource enabled: 427 drone serial-prefix signatures
  land in the watchlist and start firing once the observation-surface
  gates are resolved.

  Builds on the rc4 delegation extension (`watchlist_mac`,
  `watchlist_oui`, `watchlist_ssid`, `ble_uuid` delegation branches)
  and the rc4 mac_range work. Each prompt has extended the same
  pattern to more identifier types; this rc5 takes it to 7 of the 10
  most-populous Argus types.

### Documentation

- **Argus residual types audit.** Added a per-type residual analysis
  at `docs/ARGUS_RESIDUALS.md` characterizing the ~239 Argus rows
  currently dropped by the importer as `unknown_type`, plus a
  re-runnable diagnostic script at `scripts/audit_residuals.py` that
  regenerates the report against any Argus snapshot. The report
  enumerates 31 distinct residual identifier_types in the current
  snapshot, with each row classified by Kismet observation surface —
  `verified-lynceus` (already extracted in the Kismet parser),
  `verified-kismet-docs` (in Kismet's documented schema),
  `plausible-needs-smoke` (likely observable but unconfirmed),
  `no-observation-surface` (static manufacturer / spec metadata
  Kismet does not emit), or `normalization-variant` (same concept as
  an admitted pattern_type, blocked only by case / hex-shape /
  dual-form rendering). Per-type recommendation falls out
  mechanically from surface + yield: `admit` /
  `admit-via-normalization` / `defer-pending-smoke` / `drop-entirely`.
  With the `ble_manufacturer_id` + `drone_id_prefix` admissions
  landed earlier in rc5, the residual count dropped from ~4,635 to
  239; the audit answers the natural follow-up "which of those 239
  are worth a third admission" with concrete data rather than
  guesswork, and surfaces two normalization gaps (`ble_company_id`,
  `ble_service_uuid`) that overlap admitted pattern_types and would
  be fixed in the importer's normalization layer rather than via new
  Kismet surfaces. The script lives in `scripts/` and is intentionally
  not a `[project.scripts]` entry — operator surface stays unchanged.

- **Doc-rot sweep across operator-visible docs.** `SECURITY.md`
  version refreshed from `0.3.0-rc1` to `0.4.0-rc5` (two
  occurrences). `PROJECT_STATUS.md` refreshed for 0.4 reality:
  current-version line, hardware-tested section reworded to describe
  the rc5 shakedown rather than the v0.3 forward look. `SMOKE.md`
  header drops its stale `(v0.2)` pin (the checklist still applies
  through 0.4). `WINDOWS_DEV.md` drops the "live reload is on the
  v0.3 backlog" promise — live reload remains deferred without a
  version target per `BACKLOG.md`, and the example `git clone`
  command targets the current `lynceus-warden` name.
  `CONFIGURATION.md` webui-routes tables grow `/watchlist`,
  `/settings`, `/healthz.json`, the rc5 `/alerts` filter additions
  (`rule_type` / `q` / `window`), the `/allowlist` management
  surface (`/allowlist/add`, `/allowlist/bulk_remove`), and the
  per-alert allowlist + snooze mutations. No prose rewritten for
  stylistic reasons; only confirmed rot fixed.

### Changed

- **`lynceus-setup` Kismet + ntfy sections now ship with inline
  context blocks for first-time operators.** Pre-rc5, the wizard
  asked `Kismet API token (input hidden):` with no preceding
  explanation — an operator who had just installed Kismet had to go
  elsewhere to figure out where API keys live, what role to pick, and
  what the topic in the ntfy prompt was even for. After this change
  each section opens with a `═══`-underlined header, a short
  explanation of what the value is and why Lynceus needs it, and (for
  the Kismet API key) a step-by-step walkthrough of where to generate
  one in the Kismet web UI. The ntfy section also calls out the
  topic-as-shared-secret property up front so the operator picks
  something unguessable rather than reading the warning after the
  fact in the generated `lynceus.yaml`.

  No prompts were added, removed, or reordered. Default values are
  unchanged. Existing operators who already know the answers tab
  through at the same pace as before — the context blocks render
  above each prompt but never block input. The output is plain ASCII
  + box-drawing characters (no emoji, no ANSI color, no new
  dependency), so it still looks right when tee'd into an install
  log.

- **`vendor_severity` — runtime vendor-level severity remap on
  `severity_overrides.yaml`.** Closes the runtime override matrix at
  vendor × remap. The three earlier rc5 bullets shipped category
  remap, vendor suppression, and row-level remap; this bullet adds
  the missing cell — vendor-level severity tuning without enumerating
  individual rows. Operator UX: "all devices from this vendor should
  be high" is now a single line in the override file instead of N
  entries under `pattern_overrides` or a manual sweep across
  `device_category_severity` entries. The override matrix closes to a
  coherent shape: **remap × {category, vendor, row} + suppress ×
  {category, vendor}**.

  **Schema.** `vendor_severity: dict[str, severity]`. Keys are
  manufacturer strings — the same canonical vendor string the
  watchlist row carries on `watchlist_metadata.vendor`, projected as
  `manufacturer` on the resolved match (same naming asymmetry as
  `suppress_vendors`). Values are severity literals (`"low"` /
  `"med"` / `"high"`). Keys normalized at load time (lowercase +
  strip) so casing and accidental whitespace don't matter — same
  normalization shape as `suppress_vendors`, applied to both sides of
  the comparison at eval time.

  **Comparison is case-insensitive exact match.** Mirrors
  `suppress_vendors`. So `"  Axon Enterprise, Inc.  "`,
  `"axon enterprise, inc."`, and `"AXON ENTERPRISE, INC."` all match
  the same row. Substring / regex matching is deliberately NOT
  supported — `"Apple"` would otherwise match `"Pineapple Computing"`
  (use individual entries; for the per-row carve-out case, use
  `pattern_overrides`).

  **Precedence (most-specific wins).** Inserted between
  `pattern_overrides` and `device_category_severity`:

  1. `suppress_vendors` — vendor suppress.
  2. `suppress_categories` — category suppress.
  3. `pattern_overrides` — row-level remap.
  4. `vendor_severity` (NEW) — vendor-level remap.
  5. `device_category_severity` — category-level remap.

  Vendor remap wins over category remap because manufacturer is the
  more specific axis. Row remap wins over vendor remap because a
  specific row is more specific than a vendor. Suppression at either
  layer always wins over any remap — per-row UNSUPPRESS is explicitly
  NOT a feature, and the same holds at the vendor axis. NULL
  manufacturer (no metadata, or metadata with NULL vendor) skips the
  vendor remap check entirely and falls through to the category
  remap — same gating shape as `suppress_vendors`.

  **Why a separate key rather than extending `vendor_overrides` at
  runtime.** `vendor_overrides`' `"drop"` sentinel means
  skip-at-import; a runtime interpretation would silently overload
  the meaning and produce a footgun. `suppress_vendors` (rc5) and
  `vendor_severity` (this bullet) are the cleanly-designed runtime
  cousins. `vendor_overrides` stays import-time-only by design.

  **Per-entry tolerant parsing.** Same posture as `pattern_overrides`:
  non-string keys, empty-after-strip keys, and invalid severity
  values each drop with a WARNING; the rest of the dict parses
  normally. One malformed entry must never disable the whole layer.

  **Other touches.** The wizard's `severity_overrides.yaml` starter
  template gains a `vendor_severity:` block adjacent to
  `vendor_overrides` for logical grouping with other vendor-keyed
  entries, with the `# LAYER: RUNTIME` tag and a worked example
  targeting surveillance-camera vendors. The `/settings` web UI card
  lists `vendor_severity` in the runtime-keys group alongside the
  four existing runtime keys.

  **Deliberate non-scope.**

  - `vendor_overrides` is UNCHANGED — its import-time `"drop"`
    sentinel keeps its skip-at-import semantic.
  - `suppress_vendors` semantics are UNCHANGED — vendor suppression
    stays as the gate it is today.
  - No DB schema changes. The `watchlist_metadata.vendor` column has
    been carried since migration 004 and was already surfaced through
    the eval path by the `suppress_vendors` bullet — this bullet
    plugs the existing field into a new transform.
  - In-memory pattern rules (rules with non-empty `patterns`)
    continue to source severity from the rule and are unaffected by
    `vendor_severity` — runtime overrides apply only to DB-delegation
    matches.
  - No substring or regex matching. Case-insensitive exact match
    only, mirroring `suppress_vendors`.
  - No per-vendor UNSUPPRESS knob. Suppression at either layer is a
    deliberate operator statement that the vendor remap cannot
    override.

  Cross-references the `suppress_vendors` and `pattern_overrides`
  bullets as the prerequisite chain: `suppress_vendors` projected
  `manufacturer` onto the resolved match and established the
  vendor-axis comparison shape; `pattern_overrides` established the
  per-match-metadata-gate pattern this bullet extends to the vendor
  remap. Together with those two bullets and the original runtime
  severity-overrides + `suppress_categories` work, the matrix now
  reads as a tidy 2×3 grid: severity tuning at row, vendor, or
  category × {remap, suppress} — with the suppress-row cell
  deliberately left empty (the allowlist mechanism handles per-row
  suppression for both Argus and non-Argus rows).

### Fixed

- **Poller now logs a grep-able INFO line on every ruleset load.**
  Pre-rc5 the poller silently called the ruleset loader at init,
  leaving operators no startup signal that `rules.yaml` had actually
  been read. Symmetric with the watchlist-staleness line (rc4) and
  the runtime severity-overrides line (rc4 pre-smoke fix), every
  operator-configurable startup load now ships with a deterministic
  literal:

      loaded ruleset from <path>: N active rules
      loaded ruleset from <path>: N active rules (M disabled)
      no rules_path configured; ruleset is empty — no alerts will fire

  `active` mirrors the existing `rule.enabled` gate (a disabled rule
  is loaded into the ruleset but never evaluated). The empty-state
  line catches the failure mode where the wizard wrote `rules.yaml`
  but `rules_path` was never wired in `lynceus.yaml` — pre-fix the
  daemon would run with no alerting and no log line explaining why.

- **`/settings` watchlist-freshness card breakdown extends to all 7
  pattern_types.** rc5 landed `ble_manufacturer_id` and
  `drone_id_prefix` in the DB and in the importer, but the template
  line on the freshness card was never extended past the five rc4
  types. Operators saw the new rows in `lynceus-import-argus` stdout
  and could `SELECT` them out of SQLite, but the /settings card
  silently rendered zero for both. The data was correct in the
  backing dict (the pattern-type-counts helper returns all 7 keys);
  only the Jinja was stale. Caught pre-smoke during runbook
  verification against `settings.html`. The card now lists all 7
  keys; the docstring on the helper also flags the DB/template
  coupling so the next pattern_type addition gets the template
  extension too.

## [0.4.0-rc4] - 2026-05-15

### Added

- **`identifier_type='mac_range'` rows from Argus now land in the
  watchlist instead of being silently dropped.** Pre-rc4, every
  mac_range row hit the importer's identifier-type allowlist gate,
  fell to the `dropped_mac_range` counter, and never reached the DB.
  Argus's live `argus_export.csv` snapshot at
  `exported_at=2026-05-14T22:34:07Z` carried ~17,798 mac_range rows
  out of 22,532 total — ~64.49% as `/28` (MA-M, 7-hex prefix e.g.
  `'aa:bb:cc:d/28'`), ~35.44% as `/36` (MA-S / IAB, 9-hex prefix
  e.g. `'aa:bb:cc:dd:e/36'`), plus 12 legacy bare-prefix rows
  (~0.07%) queued for upstream canonicalization. All of these were
  missing from the Lynceus watchlist and could not contribute to
  detections.

  Migration 011 (`011_watchlist_mac_range.sql`) rebuilds the
  `watchlist` table to relax the `pattern_type` CHECK constraint
  (adding `'mac_range'` to the whitelist) and adds two
  nibble-precision prefix columns — `mac_range_prefix` (lowercase
  hex, no separators) and `mac_range_prefix_length` (28 or 36 in
  current Argus emission) — both NULL for non-mac_range rows. A
  partial index on `(prefix_length, prefix) WHERE pattern_type =
  'mac_range'` keeps non-mac_range rows out of the index and leaves
  OUI equality lookups completely unaffected. SQLite cannot modify a
  CHECK constraint via `ALTER TABLE`, so the migration does a full
  table rebuild under `PRAGMA foreign_keys=OFF` per SQLite docs §7;
  the inbound FKs from `alerts.matched_watchlist_id` and
  `watchlist_metadata.watchlist_id` are preserved by-reference and
  do not fire during the intermediate `DROP TABLE`.

  The importer parses both Argus shapes via a new
  `parse_mac_range_pattern` helper in `lynceus.patterns`. Canonical
  CIDR (`'aa:bb:cc:d/28'`, `'aa:bb:cc:dd:e/36'`) round-trips
  unchanged into `watchlist.pattern`; legacy bare-prefix
  (`'aa:bb:cc:d'`, `'aa:bb:cc:dd:e'`) is accepted dual-shape per the
  Argus-engineer handoff and canonicalized on disk so the watchlist
  UI renders uniform shape regardless of input. Each legacy row
  emits one per-row INFO log line (`argus import: mac_range legacy
  bare-prefix '<raw>' canonicalized to '<canonical>'
  argus_record_id=<id>`) so operators can grep their import logs to
  watch the legacy count drop to zero once Argus canonicalizes
  upstream. Unrecognized shapes (wrong group count, non-hex
  characters, unsupported prefix length like `/24`, mismatched
  declared-vs-shape length) are rejected loudly and routed to the
  existing `normalization_failed` counter rather than silently
  accepted — a new length surfacing means an Argus wire-contract
  change worth raising on.

  **Intermediate state — runtime matching follows in a sibling
  rc.** After this rc, mac_range rows appear in the watchlist table
  and the watchlist UI, but the poller cannot yet match a sighted
  MAC against a watchlisted range. Alerts on MACs inside watchlisted
  mac_range prefixes will start firing once the follow-up rc lands
  runtime prefix-matching against the new partial index. This
  intermediate state is intentional and keeps the diff bisect-clean:
  the schema + import path land first, the runtime match wires up
  second.

- **`watchlist_mac_range` rule type — first DB-delegated rule in
  Lynceus.** Closes the runtime-matching gap from the previous
  bullet. The redrafted design (after archaeological confirmation
  that no existing watchlist DB → rules engine bridge existed in the
  codebase) establishes a new architectural pattern: a rule type
  whose matching is delegated to the watchlist DB at evaluate-time,
  rather than checked against `rule.patterns` in memory. A single
  empty-patterns `watchlist_mac_range` entry in `rules.yaml` enables
  alert-firing for every matching mac_range row in the watchlist DB
  — operators no longer have to duplicate patterns across the DB and
  rules.yaml for mac_range coverage.

  Three changes land together:

  - **`db.resolve_matched_mac_range(mac)`** returns a watchlist match
    (watchlist_id, severity, prefix_length) or `None`. It hits the
    partial index from migration 011 — two indexed lookups per call
    (/36 first, then /28) so the more-specific match sorts ahead of
    the less-specific one. Falsy `mac` short-circuits to `None`;
    uppercase observation MACs are lowercased at the boundary to
    harden against the silent-no-match class of bug. `/28` and
    `/36` ranges covering the same MAC are forbidden by IEEE design;
    if both surface defensively, a single WARNING is logged carrying
    both watchlist_ids and the more-specific `/36` row wins. The
    annotation path (`resolve_matched_watchlist_id`) gains a
    mac_range branch between the oui and ssid checks using the same
    private helper, so alerts fired by mac_range rules get
    `matched_watchlist_id` stamped without re-issuing the WARNING.

  - **`rules.evaluate` admits `watchlist_mac_range`** and gains an
    optional keyword-only `db` parameter. The 18 pre-existing
    rules-evaluate callsites all pass without modification — the
    optional-kwarg signature change is verified non-breaking by an
    explicit regression test. The validator carve-out
    (`rule_type == "watchlist_mac_range"` REQUIRES empty patterns,
    mirror of the `new_non_randomized_device` carve-out) is the
    first such requirement among `watchlist_*` types.

  - **`/watchlist` detail page** renders the prefix length (`/28` or
    `/36`) plus a block-class annotation (MA-M, 1,048,576 addresses
    vs MA-S / IAB, 4,096 addresses) for mac_range entries. The
    annotation is presentational but operationally useful —
    "vendor `/28` owns a million MACs" and "specific device
    identifier" get different responses from a triager. The list
    page needs no template change; the write-time canonicalization
    above makes `pattern` render uniformly.

  **Architectural divergence — severity is sourced from the matched
  DB row, NOT from `rule.severity`.** Every other `watchlist_*` rule
  type populates the alert's severity from `rule.severity`; for
  `watchlist_mac_range` the alert's severity comes from
  `watchlist.severity` of the matched row, which the importer writes
  from `device_category → severity` defaults at import time. The
  divergence is deliberate: the importer wrote per-row severity for
  a reason, and reading it back at alert time is the only path that
  respects that data. `rule.severity` is ignored for this rule type
  — the bundled `config/rules.yaml` template's commented-out example
  calls this out explicitly so operators don't expect the field to
  apply.

  **Operator UX — alert volume after enabling.** A
  `watchlist_mac_range` entry is shipped commented-out in
  `config/rules.yaml`; default is OFF. Uncommenting enables
  alert-firing for any MAC inside any of the 17,786 IEEE-registry
  rows imported by lynceus-import-argus. All of these rows have
  `device_category = 'unknown'`, which maps to severity `"low"` in
  the importer's `DEFAULT_CATEGORY_SEVERITIES`. So enabling the rule
  will produce `low`-severity alerts at whatever rate observed MACs
  fall inside the IEEE allocations Argus catalogued. The 17,786 rows
  cover Mitsubishi Electric, Becton Dickinson, Airgain, and similar
  enterprise / embedded / medical / industrial vendors —
  predominantly enterprise scan surfaces, sparse on residential. If
  `"low"` is the wrong tier for this volume, tune
  `DEFAULT_CATEGORY_SEVERITIES['unknown']` before enabling the rule,
  or use the allowlist to scope the detection geographically. The
  default severity is intentionally not changed in this rc — that's
  an operator-policy conversation, not a code-level decision.

  This pattern is a natural migration target for the other
  `watchlist_*` rule types in a future rc, which would close the
  broader UX gap surfaced by the archaeology: today every watchlist
  DB row is inert unless operators manually duplicate its pattern
  into rules.yaml. That migration is deliberately out of scope here;
  this rc establishes the precedent cleanly.

  Cross-references the schema+importer half of this arc in the
  prior bullet (migration 011, `parse_mac_range_pattern`); the full
  arc reads in order down the page.

- **Watchlist delegation extension — `watchlist_mac`,
  `watchlist_oui`, `watchlist_ssid`, and `ble_uuid` now accept the
  empty-patterns-delegates-to-DB semantic.** Closes the broader
  DB-delegation gap that the prior bullet flagged as a natural
  follow-up. Before this change, only `watchlist_mac_range` fired
  alerts via DB delegation; the 63 rows shipped via the bundled
  `default_watchlist.csv` plus every Argus-imported
  mac/oui/ssid/ble_uuid row remained inert unless operators manually
  duplicated their patterns into `rules.yaml`. After this change, a
  single empty-patterns rule per type enables alert-firing for every
  matching DB row of that type — same one-line idiom that the prior
  bullet established for `watchlist_mac_range`.

  Three changes land together:

  - Four new matchers (`mac`, `oui`, `ssid`, `ble_uuid`) returning a
    watchlist match (`watchlist_id`, `severity`) or `None`. The four
    delegate to a single private helper that also backs the
    annotation path used by `matched_watchlist_id` stamping, so the
    eval path and the annotation path can never drift on what counts
    as a match. The OUI matcher takes a full MAC and slices the
    first 8 chars internally (mirror of the annotation path's
    `mac[:8]` derivation); the ble_uuid matcher takes the obs's UUID
    list and returns the first watchlisted UUID, mirroring the
    existing in-memory ble_uuid eval branch's first-match behaviour.

  - `rules.evaluate` gains delegation paths for the four rule types.
    Each existing in-memory branch wraps in `if rule.patterns:`
    (preserved verbatim) and adds an `else:` delegation branch
    consulting the corresponding DB matcher. Severity is sourced
    from the matched DB row in the delegation case, from
    `rule.severity` in the in-memory case (the prior bullet's
    severity-from-row pattern, now established as the convention for
    every DB-delegated path). Rules with non-empty patterns see
    byte-identical behaviour — the in-memory branch's code is
    untouched, just indented one level under the new `if`.

  - **Validator restructured** — the rule validator no longer relies
    on a generic `startswith("watchlist_")` branch to require
    non-empty patterns. Each rule type's empty/non-empty admission
    is now spelled out explicitly: `watchlist_mac_range` REQUIRES
    empty (prior bullet's carve-out unchanged),
    `new_non_randomized_device` REQUIRES empty (existing carve-out
    unchanged), and the four delegation-capable types accept BOTH
    shapes. Spelling each policy out individually means a future
    hypothetical `watchlist_X` lands in an explicit branch rather
    than silently inheriting whichever default is most recent.

  **Backward compatibility — non-negotiable, verified end-to-end.**
  Operators running pre-existing deployments with non-empty
  `watchlist_mac` / `watchlist_oui` / `watchlist_ssid` / `ble_uuid`
  rules see ZERO behavioural change. Verified by per-type "in-memory
  path severity from rule unchanged" regression tests, and by every
  existing test in the rules and alert-linkage suites continuing to
  pass without modification. The validator change relaxes empty
  patterns from "rejected" to "accepted as delegation idiom" for the
  four affected types, so two pre-existing tests that asserted the
  old "empty rejected" behaviour were updated to assert the new
  semantic — this is the only test modification in scope, and it's
  on the precise behaviour this rc deliberately changes.

  **Operator UX — alert volume after enabling.** All four entries
  ship commented-out in `config/rules.yaml`; default is OFF.
  Uncommenting an entry enables alert-firing for every matching
  watchlist row of that type. The matched DB row's severity flows
  into the alert directly (NOT `rule.severity`, which is ignored for
  the delegation case — the rules.yaml comment is explicit). Per-row
  severity is populated by `lynceus-import-argus` from
  `device_category` via `DEFAULT_CATEGORY_SEVERITIES`:

  - `imsi_catcher` → `high`
  - `alpr` → `high`
  - `hacking_tool` → `high`
  - `body_cam` → `med`
  - `drone` → `med`
  - `gunshot_detect` → `med`
  - `in_vehicle_router` → `med`
  - `unknown` → `low`
  - any category not listed → `low`

  The 63 bundled rows in `default_watchlist.csv` are populated per
  the same map. Operators planning to enable a delegation entry
  should `lynceus-list-watchlist --pattern-type mac` (and the other
  three types) first to see the `severity` distribution of what's
  actually in their DB; the alert volume after enabling scales with
  the count of matching observations and the imported per-category
  severity. If a category's default severity is wrong for an
  operator's environment, tune via
  `--override-file severity_overrides.yaml` at import time (the
  existing `OverrideConfig` path) before enabling the delegation
  entry. Runtime `severity_overrides.yaml` consumption is still
  backlog — operators wanting per-category severity tuning today
  still do it via the import-time `OverrideConfig`, not at evaluate
  time.

  Cross-references the prior bullet as the architectural precedent
  (`watchlist_mac_range` was the first DB-delegated rule type; this
  bullet completes the broader story by extending the same pattern
  to the other four). The prior bullet introduced the empty-patterns
  idiom and the severity-from-row divergence; this bullet
  generalizes both as the convention.

- **Runtime severity-overrides layer — `severity_overrides.yaml` now
  applies at alert time, not just at import time.** Closes the final
  archaeology backlog item. Pre-this-rc, the wizard scaffolded
  `severity_overrides.yaml` and `lynceus-import-argus --override-file`
  consumed it (`vendor_overrides`, `geographic_filter`,
  `confidence_downgrade_threshold`, `device_category_severity`), but
  the daemon never read the file. Operators wanting to retune
  severities after import had to re-import the entire Argus corpus
  (~22,500 rows) to see the new severities applied. Now the poller
  reads the same file at startup and applies a runtime transform on
  DB-delegation matches at alert construction.

  Two new behaviours. Both are runtime-layer-only — the import-time
  consumer in `lynceus-import-argus` is unchanged.

  - **`device_category_severity` (existing key, now BOTH layers).**
    Import bakes the per-category remap into `watchlist.severity` at
    write time (unchanged); runtime re-applies the same map at alert
    time on top of whatever was baked. An operator changing
    `unknown: med` in the file → daemon restart → the 17,786
    IEEE-registry mac_range rows (baked `low`) fire at `med` on the
    next poll cycle. No re-import. The same key flows consistently
    to both layers.

  - **`suppress_categories` (NEW key, runtime only).** A delegation
    match whose `device_category` is in this list emits no alert —
    the alert is suppressed entirely (no row in `alerts`, no ntfy
    push). The watchlist row stays present; only alert emission is
    silenced. Useful when an operator wants to retain enrichment
    metadata for a category without producing alerts on it. An INFO
    log line per suppression names the rule, category, and
    watchlist_id so operators have a forensic trail.

  Three structural changes:

  - The delegation-match objects (mac_range + simple-watchlist
    matches) gain a `device_category: str | None` field. Both
    private lookup helpers LEFT JOIN onto `watchlist_metadata` to
    surface the category. The JOIN is indexed on `watchlist_id`;
    cost is negligible against the primary equality / prefix lookup.
    NULL category (the 63 bundled `default_watchlist.csv` rows that
    ship without metadata) means the runtime layer passes through —
    no remap, no suppression applies.

  - A new runtime-side view of `severity_overrides.yaml` reads only
    the two runtime-relevant keys; pydantic `extra="ignore"` lets
    the parser tolerate the full superset of keys the wizard's
    starter file documents — a file containing only import-time keys
    yields an empty runtime view that fast-paths through. Missing
    file → INFO + None; malformed YAML / OSError / validation error
    → WARNING + None. The poller never crashes because of a
    malformed override file.

  - `rules.evaluate` gains a runtime-overrides kwarg (mirror of the
    prior bullet's `db=` addition). All five DB-delegation eval
    branches (mac_range + the four extension types) call a shared
    transform after the DB match and before the alert is constructed.
    Precedence is documented as suppress > remap > pass-through. The
    pass-through fast-path short-circuits when overrides is None /
    empty / the match has no `device_category` — byte-identical
    alerts to pre-this-rc behaviour.

  **Backward compatibility — verified end-to-end.**

  - In-memory pattern rules (non-empty patterns) are unchanged;
    severity stays rule-sourced. Runtime overrides apply only to
    DB-delegation matches. Explicit regression test in the rules
    test suite.
  - The import-time `OverrideConfig` consumption in the importer is
    byte-identical pre/post (separate code path, separate parser
    instance). `vendor_overrides`, `geographic_filter`, and
    `confidence_downgrade_threshold` remain import-time-only with
    their existing semantics.
  - `DEFAULT_CATEGORY_SEVERITIES` in the importer is unchanged —
    still controls what gets baked at import time. Runtime overrides
    apply on top.
  - The full pre-this-rc test suite passes without modification
    (modulo additive `device_category` assertions on the matchers,
    which surface the new field without changing existing behaviour).

  **Operator UX — what changed in `severity_overrides.yaml`.**

  - The wizard's starter file now carries inline `# LAYER:` tags on
    each section: `IMPORT-TIME` (re-import to apply), `RUNTIME`
    (daemon restart applies live), or `BOTH`
    (`device_category_severity` only). The user-facing explanation
    block enumerates the two layers explicitly. Operators
    reconfiguring see the per-layer effect of each section inline
    rather than having to read source.
  - The webui `/settings` severity-overrides card mirrors the same
    wording — import-time keys vs runtime keys, with the action
    required to apply changes.
  - `Config` gains a `severity_overrides_path: str | None` field.
    Defaults to None (opt-in for the runtime layer); set to the same
    path the wizard scaffolds to activate runtime overrides. The
    wizard does NOT currently auto-persist this path into
    `lynceus.yaml` — operators opt in by adding the line.

  **Deliberate deferral — `vendor_overrides` at runtime.**
  `vendor_overrides` stays import-time-only this rc. Its `"drop"`
  sentinel today means "skip the row at import" — a runtime
  interpretation would silently overload that meaning to mean
  "suppress the alert" instead, which is a footgun worth designing
  deliberately. A future `suppress_vendors` key (named to avoid the
  `vendor_overrides`/`"drop"` semantic clash) is the right shape,
  and that's a dedicated design pass, not a one-line schema
  addition.

  Cross-references the `watchlist_mac_range` and delegation
  extension bullets as the prerequisite chain: the prior bullets
  introduced DB-delegated rule types; this rc adds the runtime
  severity layer that operators can tune without re-importing.

- **`lynceus-setup` enable-alerting flow — operator path from
  `sudo lynceus-setup` to alerts-firing is now wizard-driven.**
  Closes the deployment-UX gap surfaced by the Kali live-smoke
  runbook. Pre-this-bullet, an operator who ran the wizard got a
  configured daemon with the bundled watchlist imported but no
  alerts fired — they had to (1) copy `config/rules.yaml` to the
  scope-appropriate path, (2) uncomment the right delegation entries
  by hand, and (3) edit `lynceus.yaml` to add `rules_path`. The
  runbook called all three out as manual Phase 1 steps because the
  wizard did not. Now the wizard's closing arc, between the
  bundled-watchlist auto-import and the "Setup complete" hint block,
  drives an interactive flow that lands all three artefacts on the
  operator's behalf.

  Three things happen when the operator opts in:

  - **Top-level gate.** `Enable Argus-backed alerting? [y/N]`
    appears once. Default is NO. An operator who answers no — or
    just hits Enter — completes the wizard in the exact behavioural
    state Lynceus has today: no `rules.yaml` created, `rules_path`
    unset, daemon runs with an empty `Ruleset`. The pre-bullet
    behaviour is preserved as the default; the new flow is strictly
    additive.

  - **Per-rule_type prompts.** For each of the five delegation types
    (`watchlist_mac_range`, `watchlist_mac`, `watchlist_oui`,
    `watchlist_ssid`, `ble_uuid`) the wizard prompts once with the
    current DB row count for context — e.g. `Enable
    watchlist_mac_range (17,786 MAC ranges)? [y/N]`. Default is NO.
    Types whose count is zero have their prompt skipped entirely;
    an operator with no data of that type sees no misleading prompt
    and gets no empty rule emitted. Counts come from a single
    `SELECT pattern_type, COUNT(*) FROM watchlist GROUP BY
    pattern_type` against the canonical scope DB path — read-only,
    no migrations run.

  - **`rules.yaml` write + `rules_path` wire.** When at least one
    type is enabled the wizard writes a fresh `rules.yaml` at
    `<config-dir>/rules.yaml` — under `--system` that's
    `/etc/lynceus/rules.yaml` (atomic, 0640 root:lynceus, same
    contract as `lynceus.yaml`); under `--user` it's
    `~/.config/lynceus/rules.yaml` (atomic, 0600). Selected entries
    are active; the others ship as commented-out templates the
    operator can enable later by hand. The file parses cleanly
    through the ruleset loader. The wizard then appends
    `rules_path: "<path>"` to the already-written `lynceus.yaml`
    (append-mode preserves the atomic-write file mode set during
    the original render).

  **Idempotency for re-runs.** `--reconfigure` alone is NOT
  authorization to clobber an existing `rules.yaml` — the wizard
  treats hand-edits as sacred. When the target `rules.yaml` already
  exists, a separate `Overwrite? [y/N]` prompt fires (default NO).
  If the operator declines, the file is left untouched but
  `rules_path` is still wired in `lynceus.yaml` when previously
  unset — this recovers the "I manually copied the file but never
  wired it up" case that the runbook had as a separate hand-edit
  step. If the operator confirms overwrite, the new selections
  replace the file.

  **Defaults are NO at every prompt** — gate, per-type, and
  overwrite. This matches Lynceus's existing privacy-conservative
  posture (probe SSID capture defaults off, severity overrides empty
  by default, ntfy URL blank skips notifications entirely). An
  operator who runs the wizard with all defaults gets a Lynceus that
  observes but does not alert, same as pre-rc4. Alerts are
  explicitly opt-in.

  **Out of scope.** The flow only covers the five delegation rule
  types — `new_non_randomized_device` and any custom pattern-bearing
  rules continue to require manual `rules.yaml` edits. The bundled
  `config/rules.yaml` template stays as-is; the wizard generates a
  derived file at the scope-appropriate path rather than copying the
  template verbatim.

  Cross-references the `watchlist_mac_range`, delegation extension
  (the other four DB-delegated types), and runtime severity-overrides
  bullets as the prerequisite chain: the prior bullets landed the
  rule types the wizard now enables; the runtime severity-overrides
  layer is what makes the resulting alerts tunable without
  re-importing. Together with that prior bullet, this bullet closes
  the operator-deployment loop for the whole Argus integration arc
  — `sudo lynceus-setup` → answer the prompts → alerts fire on the
  next poll, no manual file edits required for the common case.

- **`suppress_vendors` — runtime manufacturer-level alert suppression
  on `severity_overrides.yaml`.** Closes the runtime severity-tuning
  story end-to-end. The runtime severity-overrides bullet above
  explicitly deferred runtime vendor suppression because overloading
  `vendor_overrides`' import-time `"drop"` sentinel would silently
  change its meaning — that bullet named `suppress_vendors` as the
  right path, and this bullet ships it.

  The new key sits adjacent to `suppress_categories` on the same
  RUNTIME layer: a delegation alert whose matched watchlist row
  carries a manufacturer in the list emits no alert (no DB alert
  row, no ntfy push). The matching watchlist row stays in the DB;
  only alert emission is silenced. Operator UX is the same as
  `suppress_categories`: edit the file, restart the daemon, no
  re-import.

  **Comparison is case-insensitive exact match.** Entries are
  normalized at load time (lowercase + strip) and stored in that
  form; the eval-time check normalizes the matched row's
  manufacturer the same way before comparison. So
  `"  Mitsubishi Electric US, Inc.  "`, `"mitsubishi electric us,
  inc."`, and `"MITSUBISHI ELECTRIC US, INC."` all match the same
  row. Substring / regex matching was considered and rejected: an
  entry like `"Apple"` would otherwise match `"Pineapple Computing"`.
  Operators configure with the canonical vendor string from the
  watchlist row — the same string the Argus CSV exports in its
  `manufacturer` column.

  **Manufacturer source.** Sourced from `watchlist_metadata.vendor`
  (named `manufacturer` on the Python side to mirror the Argus CSV
  column the value ultimately comes from — same naming asymmetry as
  the importer's `manufacturer` kwarg → `vendor` DB column mapping).
  NULL manufacturer (rows without a metadata row, or with a metadata
  row whose vendor is NULL) → the `suppress_vendors` check skips
  entirely and the match falls through to the category-driven checks.

  **Precedence (most-specific wins).** Inserted as the FIRST check:

  1. `suppress_vendors` (NEW) — normalized manufacturer match →
     suppress.
  2. `suppress_categories` — `device_category` match → suppress.
  3. `device_category_severity` — `device_category` remap.

  Vendor wins over category because manufacturer is the more
  specific axis. When both keys would suppress the same match, the
  INFO log line names the vendor (forensic precision for operators
  debugging dropped alerts).

  **Per-entry tolerant parsing.** Non-string entries and entries
  that are empty after whitespace-strip get a WARNING and are
  dropped from the loaded set; the rest of the list still parses.
  One malformed entry must never disable the whole runtime layer.
  This matches the loader's existing posture: every failure mode for
  the runtime layer is benign (the importer's separate code path
  stays unaffected; the poller continues with pass-through
  semantics).

  **Other touches.** Both private lookup helpers extend their LEFT
  JOIN to also project `watchlist_metadata.vendor AS manufacturer`
  (single JOIN, no extra round-trip — cost is negligible against
  the primary equality / prefix lookup). The runtime-overrides
  loader gains a `suppress_vendors: frozenset[str]` field and
  includes it in its empty check so a file populated only with
  vendor suppressions does not short-circuit to the pass-through
  fast-path.

  **Deliberate non-scope.**

  - `vendor_overrides` is UNCHANGED — its import-time `"drop"`
    sentinel keeps its skip-at-import semantic. `suppress_vendors`
    is strictly additive at runtime. The wizard's starter template
    now points operators at `suppress_vendors` for runtime
    suppression on already-imported rows; the "future-key"
    disclaimer on `vendor_overrides` is dropped (no longer future).
  - No `suppress_vendors_severity` remap key. Vendor-level severity
    adjustment is a future prompt; designing it properly is a
    separate pass — same reasoning as the original deferral of
    runtime vendor suppression.
  - No substring or regex matching. Exact case-insensitive only.
  - No DB schema changes. The `watchlist_metadata.vendor` column has
    been in place since migration 004; this bullet just surfaces it
    through the eval path.
  - In-memory pattern rules (rules with non-empty `patterns`)
    continue to source severity from the rule and are unaffected by
    `suppress_vendors` — runtime overrides apply only to
    DB-delegation matches.

  Cross-references the delegation extension (the four other
  DB-delegated rule types beyond `watchlist_mac_range`) and the
  runtime severity-overrides bullets as the prerequisite chain: the
  extension landed the rule types whose matches now carry a
  manufacturer; the runtime overrides layer is what
  `suppress_vendors` plugs into. Together with those bullets the
  runtime severity-tuning story closes: an operator can now reassign
  severity by category (`device_category_severity`), silence
  categories (`suppress_categories`), or silence vendors
  (`suppress_vendors`), all at alert time, all with a daemon
  restart, no re-import.

- **`pattern_overrides` — runtime row-level severity remap keyed by
  `argus_record_id` on `severity_overrides.yaml`.** Closes the
  runtime severity-tuning matrix at the row axis. The three
  preceding bullets gave operators category-level remap,
  category-level suppress, and vendor-level suppress. This bullet
  adds the finest-grained knob: target a single specific watchlist
  row by its stable Argus identifier and assign a per-row severity.

  Use case: "the specific Flock camera at my workplace → high;
  everything else in `alpr` → low." Without `pattern_overrides` an
  operator could only set `alpr → low` and lose the workplace
  signal, or set `alpr → high` and over-alert on every camera in the
  corpus. The new key carves the specific row out of the category
  default.

  **Schema.** `pattern_overrides: dict[str, severity]`. Keys are the
  16-hex SHA-256 prefix Argus emits as its consumer-facing identifier
  and Lynceus stores in `watchlist_metadata.argus_record_id` (column
  from migration 004). Values are severity literals (`"low"` /
  `"med"` / `"high"`). Keys are normalized to lowercase at load time
  so case-of-paste doesn't matter — the production shape is
  lowercase but the web UI and DB inspection surfaces render the
  value verbatim, and a copy-paste from either could land in mixed
  case.

  **Precedence (most-specific wins).** Slotted between the
  suppression gates and the category remap:

  1. `suppress_vendors` — manufacturer suppress.
  2. `suppress_categories` — category suppress.
  3. `pattern_overrides` (NEW) — row-level remap.
  4. `device_category_severity` — category-level remap.

  Suppression at either layer always wins over the row-level remap
  — per-row UNSUPPRESS is explicitly NOT a feature, by design. An
  operator who wants a vendor or category alert to fire again on a
  specific row must lift the suppression at the layer it was set.
  (A symmetric per-row suppression knob is also out of scope; the
  existing allowlist mechanism handles per-row alert suppression
  for both Argus and non-Argus rows.)

  **Limitation: Argus-imported rows only.** Only rows that carry an
  `argus_record_id` in `watchlist_metadata` can be targeted via
  `pattern_overrides`. The 63 bundled `default_watchlist.csv` rows
  and any rows operators add via `lynceus-seed-watchlist` without
  metadata have no stable identifier to key on; their
  `pattern_overrides` check skips entirely and they fall through to
  the category layer. For non-Argus row-level severity tuning, use
  `device_category_severity` (category granularity) or the allowlist
  mechanism (per-row suppression).

  **Load-time validation.** Per-entry tolerant parsing: a key that
  isn't exactly 16 hex chars after normalization is dropped with a
  WARNING; a value that isn't a known severity literal (including
  non-string YAML scalars) is dropped with a WARNING; one malformed
  entry never disables the rest of the dict. Whether the
  `argus_record_id` corresponds to a real row in the DB is NOT
  checked at load time — operators may legitimately carry a stale
  entry across a re-import (the row will be re-added and the
  override will start applying again). The eval-time check is a
  simple dict-membership test that pass-throughs on miss.

  **Other touches.** Both private lookup helpers extend their LEFT
  JOIN to project `watchlist_metadata.argus_record_id`. The wizard's
  `severity_overrides.yaml` starter template gains a
  `pattern_overrides:` block adjacent to `device_category_severity`
  (both are remaps) with the `# LAYER: RUNTIME` tag and an inline
  SQL query operators can paste to find an `argus_record_id` for a
  row of interest. The `/settings` web UI card lists
  `pattern_overrides` in the runtime-keys group.

  **Deliberate non-scope.** No DB schema changes. No per-row
  suppression (allowlist handles that). No raw-pattern-keyed
  overrides (pattern + pattern_type tuple). No DB-validity check on
  `argus_record_id` keys at load time. In-memory pattern rules
  (non-empty `patterns`) keep their rule-sourced severity and are
  unaffected — runtime overrides apply only to DB-delegation
  matches.

  Cross-references the delegation extension, the runtime
  severity-overrides bullet, and the `suppress_vendors` bullet as
  the prerequisite chain: the extension landed the rule types whose
  matches now carry an `argus_record_id`; the runtime overrides
  layer is what `pattern_overrides` plugs into; `suppress_vendors`
  established the per-match metadata-gate pattern this bullet
  extends to a third axis. Together the four bullets close the
  severity-tuning matrix at remap × {category, row} + suppress ×
  {category, vendor}.

- **Watchlist staleness indicator — startup WARNING + `/settings`
  freshness card.** Surfaces the age of imported Argus data so an
  operator who hasn't refreshed in months sees a clear signal before
  alerts fire on stale threat intel. Pre-rc4 the daemon ran silently
  against whatever was last imported; an operator who booted a
  system that had been off for two months had no way to tell their
  threat data was 60+ days behind without manually checking. The
  settings page's existing "last imported" field was misleading on
  this front: it surfaced `MAX(updated_at) FROM watchlist_metadata`
  (a per-row local-clock proxy that flipped to "now" whenever an
  operator re-imported a stale CSV) rather than the Argus-side
  `exported_at`.

  **Three surfaces, one source of truth.** A new `import_runs` table
  (migration 012) persists one row per successful
  `lynceus-import-argus` write: the local-clock `imported_at`, the
  Argus-side `exported_at` parsed from the CSV's `# meta:` line, the
  canonical Argus-side `record_count`, and a free-form `source`
  (absolute path for `--input`, `owner/repo@ref` for
  `--from-github`). The poller's startup staleness check reads the
  most-recent row; the /settings freshness card reads it on every
  render. Both surfaces agree by construction — an operator who sees
  a WARNING in journalctl can open /settings and see the same
  numbers without reconciling.

  **Startup log line, three shapes.**

  - Within threshold: `INFO watchlist: N rows total, most recent
    Argus import D days ago (exported YYYY-MM-DD)`.
  - Over threshold: `WARNING watchlist: N rows total, most recent
    Argus import D days ago (exported YYYY-MM-DD); consider
    'lynceus-import-argus --from-github' to refresh`.
  - No imports recorded (fresh install, never ran the importer):
    `INFO watchlist: N rows total, no Argus import metadata
    recorded`. Deliberately NOT a WARNING — a fresh install where
    the operator hasn't run `lynceus-import-argus` yet is the
    expected state right after `lynceus-setup`, and warning would be
    noise.

  **Configurable threshold.** New
  `watchlist_staleness_warn_days: int = 30` config field. 30 days
  matches Argus's nominal release cadence; kiosk / air-gapped
  operators on a slower cadence tune via this field. Validated as
  `>= 1` (a 0-day threshold would WARN at every startup). The wizard
  doesn't prompt for it — operators tune via manual `lynceus.yaml`
  edit, in line with other operability fields like
  `alert_dedup_window_seconds`.

  **/settings 'Watchlist freshness' card.** New card alongside the
  existing watchlist data card. Renders:

  - Status badge — fresh (within N days) / stale (older than N
    days), using the existing card-status visual conventions.
  - Argus exported date, locally imported date, age in days, source
    string, Argus-side record count.
  - Pattern-type breakdown (mac / oui / ssid / ble_uuid / mac_range
    counts) — rendered in both has-import and no-import branches
    because it reflects the LIVE watchlist contents, not the import
    metadata. Same numbers operators see in the importer's stdout
    summary.
  - Refresh hint with the exact command, surfaced only in the stale
    branch. Read-only — no "Force refresh" button; the boundary
    stands.

  **Replaces the misleading proxy.** The
  `last_imported_ts = MAX(updated_at)` field on the existing
  "watchlist data" card is removed — the new card renders both
  Argus-side `exported_at` and local-clock `imported_at` so the
  re-import-of-stale-CSV case is forensically clear instead of
  ambiguous.

  **Importer changes.**

  - A new `parse_argus_meta(path)` helper parses the
    `# meta: key=value, ...` line that prefixes every Argus CSV.
    Per-field tolerant: malformed `exported_at` / `record_count`
    lands as None for just that field; unknown keys (Argus adds new
    pairs over time) are ignored; a free-form meta line (the
    rc2-era shape) parses to all-Nones cleanly. The parser is
    additive — the existing `parse_argus_csv` API is unchanged, so
    call sites continue to receive a plain `list[dict]` without
    modification.
  - The importer's `import_csv` gains a keyword-only
    `source: str | None` parameter and writes one `import_runs` row
    on every successful (non-`--dry-run`) import. Failure to record
    the run downgrades to a WARNING; the watchlist write already
    succeeded and the staleness signal is observability-only.
  - The GitHub-fetch helper now returns `(cached_path, resolved_ref)`
    so the caller can build the `owner/repo@ref` source string
    without a duplicate ref-resolution call (the latter is a
    network round-trip on the default unspecified-ref path).

  **DB layer.**

  - Migration 012 (`012_import_runs.sql`). One table
    `import_runs(id, imported_at INT NOT NULL, exported_at INT,
    source TEXT, record_count INTEGER)` plus an index on
    `imported_at DESC` for the single-row most-recent lookup. No FK
    out to watchlist / watchlist_metadata — an import run is a
    standalone event, not bound to any specific row.

  **Deliberate non-scope.** No ntfy push for staleness (future
  polish; startup WARNING + /settings card is the MVP). No periodic
  re-check at runtime (startup-only). No "Force refresh" button on
  /settings (read-only UI boundary). No retroactive backfill —
  imports from before migration 012 landed don't appear on the card;
  the next refresh starts the signal cleanly.

### Fixed

- **Runtime severity-overrides loader now logs INFO at every load
  outcome, not only on missing-file.** Surfaced during pre-smoke
  review of the Kali live-validation runbook against the as-shipped
  code. The runbook promised "an INFO line confirming the runtime
  severity-overrides file was loaded ... grep for 'severity_override'
  or 'runtime override'" — but the initial implementation logged
  INFO only on the missing-file path. The successful-load path and
  the disabled-via-None path (operator hadn't set
  `severity_overrides_path` in `lynceus.yaml`) both returned
  silently. An operator running the smoke and grepping journalctl at
  startup would have seen nothing and been unable to tell whether
  the runtime layer was active, disabled, or silently pass-through
  because of an unset config field — exactly the diagnostic blind
  spot the runbook step was meant to prevent.

  Three new INFO lines now cover the three load outcomes that
  return non-failure (the four failure modes — missing file,
  unreadable file, malformed YAML, validation error — already
  logged at WARNING and are unchanged):

  - Active-keys path: `runtime severity overrides loaded from
    <path>: N category remap(s), M suppressed category(ies). Edits
    take effect on daemon restart.` Self-describing — an operator
    who expected 3 remaps but sees 1 knows the parser was selective.
    Counts at startup are the runbook's happy-path grep target.
  - Empty-keys path: `runtime severity overrides loaded from <path>
    but contain no active runtime keys (device_category_severity /
    suppress_categories); runtime layer is effectively pass-through.
    Edit the file and restart the daemon to activate.` Distinguishes
    a wizard-default-state file (parses cleanly, no runtime keys
    uncommented) from one where the operator's edits actually took
    effect.
  - None path (`severity_overrides_path` unset):
    `severity_overrides_path not set in lynceus.yaml; runtime
    override layer disabled. Set the field to your
    severity_overrides.yaml path (e.g.
    /etc/lynceus/severity_overrides.yaml under --system, or
    ~/.config/lynceus/severity_overrides.yaml under --user) and
    restart the daemon to enable.` Names the config field by exact
    name + points at the canonical paths so an operator who skipped
    the relevant lynceus.yaml edit sees the actionable hint without
    grepping source.

  All three are greppable via the literal `runtime severity
  overrides`.

- **`lynceus-import-argus --from-github` default `--repo` was
  pointing at a non-existent repository.** rc3 hard-coded
  `kevlattice/argus` as the default; the actual Argus repo is
  `kevwillow/argus-db`. The headline rc3 feature 404'd on the
  `/releases/latest` API call before it could even start the raw
  fetch, and operators saw an opaque `HTTPError` instead of a
  successful refresh. The default repo now resolves correctly;
  passing `--repo OWNER/NAME` for a fork still works the same way.

- **`lynceus-import-argus --from-github` no longer crashes when the
  Argus repo has no published GitHub Releases.** rc4 still required
  `/repos/{repo}/releases/latest` to return a tag, but
  `kevwillow/argus-db` ships its CSV on every commit and does not
  cut formal Release objects (its README is explicit that release
  cadence is discretionary; the GitHub sidebar reads "No releases
  published"). The API returned 404, `raise_for_status()` raised
  `HTTPError`, and `--from-github` was unusable until Argus
  published its first Release — wrong dependency to bake in. The
  ref resolver now treats a 404 on `/releases/latest` as "no
  published releases" and falls back to the `main` branch, logging
  a WARNING (`No published releases for {repo}; falling back to
  'main'. Pin a tag with --ref for reproducibility.`) so operators
  can see at a glance whether they got a release tag or a branch
  HEAD. Other non-200 statuses (500, 403) still propagate — a
  transient GitHub outage must not silently degrade to importing
  whatever `main` happens to be. Surfaced by the rc4 live smoke
  against the real Argus repo.

- **`lynceus-import-argus --override-file` is now scope-strict and
  no longer crashes for unprivileged `--scope user` runs on a host
  that also carries a `--system` install.** Pre-fix, the argparse
  default was hard-coded to `/etc/lynceus/severity_overrides.yaml`
  regardless of `--scope`. On a Linux host with the system-scope
  install (`/etc/lynceus` is `0750 root:lynceus` by design), an
  unprivileged user running the importer hit the system path via
  the default and crashed with `PermissionError` inside
  `Path.is_file()`. The flag now defaults to `None`; resolution
  derives from the scope-aware path helper — user-scope only ever
  probes the user-scope path, system-scope only the system path, no
  cross-scope fallback. Explicit `--override-file <path>` is used
  verbatim and bypasses scope-derived defaults entirely. The
  override loader also converts `PermissionError` on the probe into
  a `RuntimeError` that names the offending path, so operators see
  an actionable message instead of a bare traceback. Surfaced by
  the rc4 live smoke; the bug was latent in every prior
  `lynceus-import-argus` ship but only triggers on mixed user+system
  installs.

- **`lynceus-setup` refuses sudo-without-`--system` to prevent
  silent scope misplacement.** Reproduced in the rc4 live smoke:
  `sudo lynceus-setup --reconfigure` (no `--system`) silently
  regenerated `/root/.config/lynceus/lynceus.yaml` while the system
  daemon kept reading `/etc/lynceus/lynceus.yaml` — the operator
  believed they had reconfigured the daemon, but the daemon was
  still running the stale pre-reconfigure config. The wizard
  followed its scope rules literally (`euid=0`, scope defaults to
  user, `Path.home()` is `/root`) but the operator-facing result was
  divergence between intent and effect. The wizard now refuses
  early when `euid=0` and `--system` is not passed, prints both
  correct invocations side-by-side, and exits 2. Three legitimate
  combinations are unchanged: root + `--system` (system install),
  non-root + no flag (user install), non-root + `--system` (still
  hits the pre-existing "use sudo" preflight). Windows is a no-op
  for the new check — there's no euid to read, so no sudo trap to
  fall into. After upgrading, operators who hit this bug in rc4
  should re-run `sudo lynceus-setup --system --reconfigure` to
  bring `/etc/lynceus/lynceus.yaml` back into sync with their
  intended configuration.

### Changed

- **All `kevlattice/lynceus` GitHub URLs replaced with
  `kevwillow/lynceus-warden`** to reflect the upstream account
  rename + repo rename. Surfaces touched: `pyproject.toml`
  (Homepage / Repository / Issues, which flow into the wheel's
  PKG-INFO and PyPI metadata), `SECURITY.md` (private-advisory and
  public-issues URLs), the `git clone` URL in the README, and the
  `Documentation=` line in both systemd unit files (visible in
  `systemctl status` and journalctl context). The
  `kevwillow/lynceus.git` → `kevwillow/lynceus-warden.git`
  GitHub-side redirect is still active, so older clones continue to
  push and pull, but new clones should use the canonical URL.

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

- **`lynceus-import-argus --from-github`.** Argus-watchlist refresh
  collapses from a three-step manual flow (scp the CSV, find the
  right `--db` path, run the importer) into a single command. The
  new flag fetches `exports/argus_export.csv` from
  [`kevwillow/argus-db`](https://github.com/kevwillow/argus-db) over
  HTTPS and runs the existing idempotent, migration-aware import.
  Default ref is the *latest tagged release* (NOT the tip of
  `main`) — a single bad push must not poison every operator who
  refreshes. Explicit `--ref` overrides the default (tag / branch /
  commit all work; `--ref main` is allowed for operators who
  consciously want the bleeding edge). `--repo OWNER/NAME` swaps the
  source repo for forks. Pulled artifacts land in
  `<data-dir>/argus-cache/<ref>__argus_export.csv` so each refresh
  leaves a forensic trail.

  Network access is confined to this one CLI by design:
  `install.sh` stays offline (its header invariant), the daemon and
  the web UI don't change, and the bundled-watchlist first-run
  import in `lynceus-setup` continues to read from the wheel. The
  `--from-github` path uses `requests` with default `verify=True`
  TLS and bounded timeouts (15s for the API release lookup, 30s for
  the raw fetch). No GitHub API token is required — both
  `/releases/latest` and `raw.githubusercontent.com` work
  unauthenticated. `--input` remains for air-gapped operators; the
  two flags are mutually exclusive, exactly one is required.

- **`--db` now defaults to the canonical scope path** in
  `lynceus-import-argus`. Pre-change the flag was required, so
  every operator had to hand-roll `/var/lib/lynceus/lynceus.db`
  (under `--system`) or `~/.local/share/lynceus/lynceus.db` (under
  `--user`) every time. The flag now resolves to the scope-aware DB
  path helper when omitted — same XDG-aware resolver the setup
  wizard and the daemon already consult — so the common case is a
  no-flag invocation. New `--scope user|system` picks the default
  scope (defaults to `user`); pass `--db` explicitly to override.
  Existing scripts passing `--db` keep working unchanged.

- **Scope-aware uninstall.** `install.sh --uninstall` now accepts
  both `--user` and `--system`, closing the gap where only
  `--system` installs had a clean reversal path. The internal `MODE`
  variable was split into orthogonal `ACTION` (install / uninstall)
  and `SCOPE` (user / system), so `--uninstall --user` and
  `--user --uninstall` are order-independent and the dispatch table
  is `case "$ACTION:$SCOPE"`. Pre-flight is now action-aware:
  `python3` and `python3-venv` are install-only requirements
  (uninstall must work on a host where Python is already gone), and
  `systemctl` is gated on `SCOPE=system` (covers both
  install-system and uninstall-system). `--purge` now errors unless
  `--uninstall` is also passed, making the previously-implicit
  "purge only applies to uninstall" relationship explicit at the
  CLI surface.

  `--user --purge` semantics: deletes `~/.config/lynceus`,
  `~/.local/share/lynceus`, and `~/.local/state/lynceus` (the latter
  two contain `lynceus.db` and logs). Without `--purge`, the venv
  at `~/.local/share/lynceus/.venv` is removed (the install
  artifact) but the surrounding data dir is preserved, so the
  operator's database survives a non-purge uninstall. If no
  `--user` install artifact is found anywhere, the script prints
  the checked paths and suggests `sudo install.sh --uninstall
  --system` in case the operator picked the wrong scope, then
  exits 0 rather than running a chain of no-op `rm`s.

- **Top-level `uninstall.sh` wrapper.** Operators look for an
  `uninstall.sh` next to `install.sh`; we now ship one. Thin shell
  wrapper — not a Python entry point, doesn't touch
  `pyproject.toml` or the `CONSOLE_SCRIPTS` array. Auto-detects
  scope by venv marker (`~/.local/share/lynceus/.venv` for `--user`,
  `/opt/lynceus/.venv` for `--system`), refuses to guess if both
  markers exist (lists them, asks the operator to be explicit),
  prints where it looked if neither is present, and otherwise execs
  `install.sh --uninstall --user|--system` with `--purge` and
  `--dry-run` passed through. Like `install.sh`, it's intentionally
  OFFLINE — no network access of any kind.

## [0.4.0-rc2] - 2026-05-15

### Security

- **Allowlist suppression of watchlist hits is now audit-logged.**
  Previously the allowlist-then-evaluate ordering in the poll loop
  meant an allowlist entry could silently disable any watchlist rule
  whose pattern overlapped with the allowlisted device — anyone with
  write access to the allowlist file got an undocumented watchlist
  kill-switch with zero log signal. The poll loop now re-evaluates
  rules on the allowlisted-suppression path and emits an INFO line
  per suppressed watchlist hit (`Allowlist suppressed watchlist hit:
  rule=<name> mac=<mac> severity=<sev>`), so operators can grep
  journalctl to review whether their allowlist is too permissive.
  The audit pass costs one extra `evaluate()` call per allowlisted
  observation; allowlists are operator-curated and typically small,
  and the visibility win is worth the cost. Docstrings on the
  relevant code paths now make the precedence ordering explicit so
  future refactors don't drop the audit signal.
  `new_non_randomized_device` hits are intentionally excluded from
  the audit log — the whole point of allowlisting is to silence the
  "first time we've seen this known device" path, and logging it
  would just mean every allowlisted device gets one INFO line per
  poll cycle.

- **ntfy topic no longer leaks in notifier logs, wizard summary, or
  probe-failure prints.** The topic is a shared-secret URL path
  component on public ntfy brokers — anyone who knows it can both
  subscribe to alerts and publish forged ones. The webui already
  redacted it via a private helper; three other surfaces still
  rendered it verbatim:

  - **The notifier** logged the full POST URL on every network
    failure AND embedded the `requests` exception's string form,
    which itself typically embeds the URL+topic — so the secret
    landed in journalctl twice per failure.
  - **`lynceus-setup` wizard summary** printed the raw topic to
    stdout at the end of a run, where it lingers in terminal
    scrollback and any tee'd install log.
  - **The wizard's ntfy probe failure path** returned `str(exc)`
    verbatim, which the wizard then printed; same
    exception-body-embeds-URL leak as the notifier.

  All three now route through a new `lynceus.redact` module that
  exposes `redact_ntfy_topic` (the existing webui helper, lifted to
  a shared location and made public) and `redact_topic_in_url`
  (parses the URL, redacts only the final path segment, preserves
  query and fragment). The previously-private redactor in the webui
  is gone; the webui now imports the shared version so every surface
  speaks one consistent redaction shape (`prefix•••suffix`).

  The notifier and the wizard probe now log only the exception type
  name plus the topic-redacted URL on failure; full exception detail
  is reserved for explicit DEBUG operation. The trade-off is a small
  loss of debug context in default-INFO journalctl in exchange for a
  guarantee that the topic cannot leak via the warning line —
  operators who need the full exception body can enable DEBUG
  temporarily.

### Added

- **Dark mode for the web UI.** Auto-follows the OS via
  `prefers-color-scheme: dark`, with a small `theme: auto / light /
  dark` toggle button in the topnav for operators who want to
  override. The toggle cycles auto → light → dark → auto and
  persists the choice to `localStorage` (`lynceus-theme` key), so it
  sticks across page navigations and reloads. Pico CSS v2.1.1
  (already vendored) handles the dark palette for every standard
  semantic element — body, text, links, tables, forms, buttons, nav,
  article, borders — and `lynceus.css` adds matching dark variants
  for the project-custom surface (severity / confidence / status
  badges, the topnav border, the sparkline bar fill, the
  severity-tinted alert rows, and the table-scroll fade gradient).
  The toggle sets `data-theme` on `<html>`, which Pico and
  `lynceus.css` overrides both honor coherently from a single flag.
  Light-mode rendering is byte-identical to pre-change (the `:root`
  defaults preserve the prior color literals exactly), so operators
  who keep their OS in light mode and never touch the toggle see no
  visual change. Known limitation: a brief flash-of-prefers-color-
  scheme on every page load because `lynceus.js` runs `defer`red;
  fixing requires an inline `<head>` script and is deferred to a
  future iteration if anyone reports it as bothersome.

- **`lynceus-import-argus --min-confidence N` row-skip flag.**
  Hard-skips rows where `confidence < N` before any DB write;
  skipped rows land in a new `dropped_low_confidence` counter
  surfaced in both the per-bucket and the trailing-summary lines of
  the operator-facing report, plus a per-row INFO log line
  (`argus_record_id` + actual confidence) so the count is
  debuggable instead of opaque. Deliberately distinct from the
  YAML-configured `confidence_downgrade_threshold` (which downgrades
  severity tier — high→med→low — but still imports the row):
  `--min-confidence` is a hard pre-DB filter, the threshold is a
  severity nudge. Both can be active simultaneously and operate
  independently. The intended workflow is a high-confidence-first
  smoke test — `--min-confidence=80 --dry-run` against the incoming
  push to confirm the high-conf subset lands cleanly before
  re-running without the flag to ingest the full export. Default is
  unset (no filtering), so the flag is opt-in and existing import
  scripts are unaffected.

- **`evidence_snapshots.do_not_publish` column** (migration 009).
  Forward-compat for v0.5.0 public-feed export — no producers or
  consumers in v0.4.0. Defaults to 0; surfaced in the
  evidence-for-alert lookup so future consumers can read it without
  a second query. Adding the column now while the table is small
  avoids a destructive migration when v0.5.0 ships.

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

- **`captured_at` index for the evidence retention prune.**
  Migration 008 adds `evidence_captured_at_idx` so the daily
  `DELETE FROM evidence_snapshots WHERE captured_at < ?` no longer
  falls back to a full table scan. The pre-existing
  `(mac, captured_at DESC)` index leads with `mac` and is not
  usable for an unconstrained range scan; this becomes a real cost
  on Pi-class hardware after weeks of operation on a busy site.

### Changed

- **`lynceus-import-argus` now emits a per-row INFO log line on
  every identifier_type drop.** Pre-change, `mac_range` rows and
  rows carrying an unknown `identifier_type` were silently swallowed
  into the `dropped_mac_range` / `dropped_unknown_type` counters —
  visible in the final report total, but with zero row-level
  forensic trail. An operator who imported an Argus export and saw
  the unknown-type count jump had no way to learn *which*
  identifier_type values Argus had pushed without re-grepping the
  source CSV. The new log lines carry `argus_record_id` and the raw
  (case-preserved) identifier_type value plus a stable reason token
  (`mac_range_unsupported` / `unknown_identifier_type`), so the
  forensic question is answered by
  `journalctl | grep "argus import: skipping"`. INFO not WARNING
  because these are *expected* drops per the Argus §4.4 contract,
  not anomalies — they must surface for debuggability but must not
  upgrade the ntfy notification threshold or screen-flood on large
  imports. The immediate consumer is the next Argus push: any new
  identifier_type Argus emits behind us will now be visible in the
  first operator's import log rather than being lost to the
  unknown-type bucket.

### Fixed

- **Importer now tolerates four timestamp shapes in the Argus CSV's
  `first_seen` / `last_verified` columns.** Pre-fix, the parser
  only accepted the space-separated `"%Y-%m-%d %H:%M:%S"` shape —
  but on 2026-05-14 Argus codified its canonical emission as
  ISO-8601 UTC with `Z` suffix at seconds precision (e.g.
  `"2026-05-14T06:13:42Z"`), and the older write-paths that fed the
  dataset had historically emitted at least four distinct shapes
  anyway. The strict parser rejected every Z-form value with
  `ValueError`, surfacing in the per-row `errors` bucket and
  silently dropping the matching watchlist rows. Smoke against the
  live `argus_export.csv` (22,532 rows) showed **50 imported / 53
  errors** pre-fix, every error of the form `time data '...Z' does
  not match format '%Y-%m-%d %H:%M:%S'`. Post-fix, the same dry-run
  reports **103 imported / 0 errors** with the expected
  reconciliation (103 + 17,794 `mac_range` + 4,635 `unknown_type` =
  22,532); the 50→103 delta is rows that previously failed on a
  Z-form `last_verified` value mid-row, now parsed cleanly. The
  parser now accepts: canonical Z form (`"2026-05-14T06:13:42Z"`),
  ISO with explicit UTC offset
  (`"2026-05-14T06:13:42.204792+00:00"`, the pre-canonicalization
  dominant shape), space-separated treated as UTC
  (`"2026-05-06 00:30:28"`, backward compat with archived exports),
  and date-only midnight UTC (`"2026-05-10"`, preserves the only
  signal a date-only row carries). Non-zero offsets are coerced to
  UTC. Unparseable shapes still raise `ValueError` so a future
  fifth shape surfaces immediately in the existing row-error path
  rather than landing silently. Defense in depth with the
  Argus-side canonicalization: either side could have fixed it
  alone, both is more robust against archived pre-canonicalization
  exports an operator may replay.

- **Migration 007 (`evidence_snapshots`) now uses `IF NOT EXISTS`
  guards on its three CREATE statements** (one table, two indexes).
  Re-running the SQL on a DB where 007's objects exist but the
  `schema_migrations` row was never written (interrupted runner,
  crash mid-script) is now a no-op rather than raising
  `sqlite3.OperationalError: table evidence_snapshots already
  exists`. Narrow partial-apply hardening from the v0.4.0
  diagnostic backlog — the broader migration-runner atomicity work
  (per-migration transactions and a recovery path that reconciles
  the on-disk schema with `schema_migrations`) stays deferred to
  v0.4.1. Other migrations are unchanged in this pass; a follow-up
  sweep will apply the same guards to 001-006 and 008-010 once the
  runner work lands.

- **Watchlist patterns are now normalized at write time.** Pre-fix,
  `lynceus-seed-watchlist` and `lynceus-import-argus` inserted
  operator-supplied patterns verbatim. The poller normalizes its
  observation MAC to lowercase colon-separated form (and BLE UUIDs
  to lowercase hyphen-separated form) before the equality lookup
  in the annotation path, so a watchlist row stored as
  `"AA:BB:CC:DD:EE:FF"` silently never linked to the alert that
  fired for `"aa:bb:cc:dd:ee:ff"`. The alert was still written (the
  rules engine had already matched the pattern via the in-memory
  rule), but `matched_watchlist_id` landed `NULL` — dropping the
  entire Argus metadata enrichment chain (vendor, confidence, source
  URL, severity hint) that v0.4.0 surfaces on the alert detail page.
  The bug was structural: any seed/import path that didn't happen to
  use canonical lowercase silently broke the Argus integration
  contract.

  A new `lynceus.patterns.normalize_pattern` helper is now the
  single source of truth for canonical persistent form, called by
  both the YAML seeder and the Argus CSV importer before insert.
  Accepts the separator variants found in the wild (Cisco-dotted
  MACs, hyphen MACs, IEEE-distribution flat-hex OUIs — that last
  form closes the OUI normalization gap) and rejects anything that
  can't be coerced. SSIDs pass through unchanged (case-sensitive
  per IEEE 802.11 — separate SSID-case deferral remains for v0.4.x).
  Short 16-bit / 32-bit BLE UUIDs are rejected rather than silently
  expanded; the Bluetooth-base expansion is a separate fix tracked
  under the Kismet short-UUID hardware finding.

  Migration 010 normalizes pre-existing rows in place: `LOWER` +
  collapse `-`/`.`/space to `:` for `mac`/`oui`, `LOWER` only for
  `ble_uuid` (canonical UUID form keeps hyphens). SSID rows are
  intentionally not touched. Idempotent — re-running on
  already-canonical input is a no-op. Exotic input forms (flat
  12-hex MACs, dehyphenated 32-hex UUIDs) won't be perfectly
  normalized by the SQL pass but the next seed/import run lands
  them in canonical form via the new helper; chasing perfect
  SQL-side normalization isn't worth the regex/UDF complexity for a
  corner case.

  `lynceus-import-argus` reports a new `normalization_failed`
  counter on its report, surfaced in the operator-facing summary so
  silent drops are visible at the end of an import run.
  `lynceus-seed-watchlist` emits a per-rejection WARNING and a
  single rolling-up summary WARNING when any rejections occurred.
  This matters specifically for the next Argus push — fixing
  pre-push is the right ordering since we don't know how their
  export normalizes patterns.

- **`lynceus-import-argus` now case-normalizes `identifier_type`
  before the allowlist check.** Symmetrical with the pattern-value
  normalization fix above: that one canonicalized the *identifier*
  (the pattern string itself) at write time, this one canonicalizes
  the *identifier_type* column at read time. Pre-fix, a row from
  Argus with `identifier_type="BLE_SERVICE"` (uppercase) missed the
  lowercase keys in the importer's identifier-type map and silently
  dropped into the `dropped_unknown_type` counter — visible in the
  final report total but with no per-row log line, so operators
  reviewing import stdout would see the count drop without learning
  which type variants Argus had pushed. The importer now does
  `(row["identifier_type"] or "").strip().lower()` before the
  allowlist lookup; the whitespace strip also handles BOM /
  trailing-space edge cases for free. This matters specifically for
  the next Argus push: high-confidence `ble_service` rows that
  happen to ship as `BLE_SERVICE` would otherwise be lost without
  warning.

- **Freshly-created user-mode databases are now `chmod 0600` on
  POSIX.** Previously the file landed at the process umask
  (typically `0644` — world-readable on multi-user boxes).
  System-mode installs already get `0640 root:lynceus` from setup;
  this fix only affects user-mode where evidence rows could
  otherwise be readable by any local account. Existing databases
  keep operator-set modes; the chmod runs only on first creation.
  No-op on Windows.

- **Alert detail page hides the GPS section when stored coordinates
  are non-finite.** Belt-and-suspenders against a
  pre-evidence-store-gps install or hand-edited DB row carrying
  `inf` / `nan`: the OSM URL would otherwise render as
  `mlat=nan&mlon=...&map=18/nan/...` and the visible coordinate line
  would say "nan, 0". The handler now zeroes out the GPS context
  fields and logs a WARNING when it detects non-finite values.

- **OpenStreetMap link on the alert detail page now opens in a new
  tab.** Previously had `rel="noopener noreferrer"` but no
  `target="_blank"`, so clicking it navigated the operator off the
  alert page and dropped any pagination/filter context. Now matches
  the watchlist `source_url` link's behaviour.

- **Evidence capture now honors the `capture.probe_ssids` and
  `capture.ble_friendly_names` toggles.** Previously the verbatim
  Kismet record stored in `evidence_snapshots.kismet_record_json`
  bypassed both toggles, so an operator who explicitly disabled
  probe capture still had every probed SSID for every alerting
  device persisted to disk. Evidence capture now redacts the record
  per the active capture config before serialization
  (deep-copy-safe — the upstream record is never mutated).

- **`bytes` / `bytearray` fields in Kismet records are now
  hex-encoded in evidence JSON** instead of stringified as a Python
  repr. Previous `default=str` produced ugly tool-hostile blobs like
  `"b'\\xff\\xfe'"`; the new custom default emits clean hex
  (`"fffe"`) that round-trips through any JSON consumer.

- **Non-finite floats in Kismet records (`inf`, `nan`) are now
  serialized as `null` in evidence JSON** instead of the
  non-standard `Infinity` / `NaN` tokens. Strict JSON parsers
  (FOIA-export pipelines, journalist tooling) reject those tokens;
  a single Kismet RRD slot carrying a sentinel value used to render
  the entire snapshot non-portable.

- **`raw_record` is no longer attached to `DeviceObservation` when
  evidence capture is disabled.** Each Kismet device record can be
  tens of KB; for poll batches of hundreds of devices that was
  multi-MB of needless retention every tick when the evidence path
  would never consume it. The Kismet parser now takes an
  evidence-enabled flag, threaded down from the poll loop via the
  Kismet client.

- **Capture-failure log line no longer leaks exception body
  content.** `json.dumps` failures can carry offending field values
  (BLE friendly names, SSIDs, vendor strings) in the exception
  message; logging the exception via `%s` echoed those values into
  journalctl outside Lynceus's privacy controls. The WARNING line
  now includes only the exception type name; full traceback is
  reserved for explicit DEBUG-mode operation.

- **GPS in evidence rows is now opt-in.** The geopoint in a Kismet
  device record is the receiver's GPS fix, not the observed device's,
  so persisting it on every alert was building a high-resolution
  operator-movement log retained for the full
  `evidence_retention_days` window. New config flag
  `evidence_store_gps` (default `false`) gates the GPS columns; when
  off, `gps_lat` / `gps_lon` / `gps_alt` / `gps_captured_at` stay
  NULL even when the Kismet record contains location data.

  - **BREAKING (pre-release):** `evidence_store_gps` defaults to
    `false`. Operators who want GPS in evidence rows must enable it
    explicitly. Existing rows in `evidence_snapshots` from a
    pre-release v0.4.0 still carry whatever GPS values were captured
    at the time; only future captures are gated.

### Added

- **Evidence snapshots table, alert-time capture, retention prune.**
  When an alert fires, Lynceus now persists a full evidence snapshot
  to a new `evidence_snapshots` table: the Kismet device record at
  that moment (verbatim JSON), the recent RSSI history pulled from
  Kismet's signal RRD (60-sample minute_vec), and the GPS fix when
  one is present. This is the foundational layer for transparency
  reporting, FOIA requests, journalism use cases, and the v0.4.1
  movement-aware alerting that needs recent per-device evidence.

  - Schema migration `007_evidence_snapshots.sql` adds the table
    with a foreign key onto `alerts(id) ON DELETE CASCADE` plus
    `(alert_id)` and `(mac, captured_at DESC)` indexes for the
    "recent evidence for this device" lookup pattern.
  - New config knobs `evidence_capture_enabled` (default true; the
    operator off-switch for storage-constrained Pis) and
    `evidence_retention_days` (default 90, validated to [1, 3650]).
  - New `lynceus.evidence` module exports `capture_evidence` and
    `prune_old_evidence`. Capture is wrapped in a broad try/except —
    a malformed Kismet record must never derail the alert path —
    and failures log at WARNING (not ERROR).
  - Daily housekeeping: `maybe_prune_evidence` runs at most once per
    24h from the poll loop, tracked under a new
    `last_evidence_prune_ts` poller-state key.
  - Alert detail page surfaces evidence with RSSI sparkline and GPS
    link. `/alerts/{id}` now renders an Evidence section with the
    captured Kismet record (collapsed `<details>` with pre-formatted
    JSON), an inline SVG sparkline of the 60-sample RSSI history
    (no external chart library — Lynceus stays offline-capable),
    and an OpenStreetMap link for the captured GPS fix when present
    (not Google Maps — privacy posture matters here). Older alerts
    that predate v0.4.0, or alerts where capture was disabled,
    render a "No evidence captured" placeholder.
  - CLI export commands intentionally deferred to a follow-up
    prompt.

## [0.3.0-rc2] - 2026-05-08

### Fixed

- **Setup wizard crashed on a fresh box during the bundled-watchlist
  import** because the data directory (e.g.
  `~/.local/share/lynceus`, `/var/lib/lynceus`) didn't exist yet,
  and sqlite refused to open the target DB with "unable to open
  database file". The wizard now creates the data and log
  directories defensively before invoking `lynceus-import-argus`.

### Added

- **Bluetooth capture source selection** in `lynceus-setup`. On
  Linux the wizard enumerates `/sys/class/bluetooth/` for `hci*`
  adapters and, when one is present, offers to append it to
  `kismet_sources` so Tier 1 BLE enrichment has a Kismet source to
  draw on. macOS and Windows print a one-line note explaining that
  BT enumeration is not implemented and the operator should
  configure Kismet's BT source manually.
- **ntfy skip support.** Pressing Enter at the broker URL prompt now
  skips ntfy entirely — empty strings are written for `ntfy_url`
  and `ntfy_topic`, the publish probe is suppressed, and the
  daemon's existing `NullNotifier` fallback handles the empty config
  gracefully. When the URL is set, an empty topic re-prompts (topic
  is required if URL is set).

### Changed

- **Severity-overrides path prompt** now prints an explanation block
  describing what the file does before asking for a path, and
  validates the input with a light heuristic — `na`, `skip`, `none`,
  and other bare alphabetic strings are rejected with "That doesn't
  look like a file path" instead of silently landing in the wrong
  place.
- **Optional 'additional Argus CSV' prompt has been retired.** It
  was redundant on top of the bundled-watchlist auto-import, and
  the trailing yes/no/path-prompt loop was a frequent source of
  copy-paste-the-wrong-string mistakes. The wizard now closes with
  a one-line hint pointing operators at `lynceus-import-argus
  --input <path>` for later imports.

## [0.3.0-rc1] - 2026-05-08

### Added

- **Argus integration** — first-class support for the Argus
  surveillance-equipment signature dataset:

  - DB schema migration (`004_watchlist_metadata.sql`) adding a
    `watchlist_metadata` table that stores Argus record id, device
    category, confidence, vendor, source attribution, FCC id,
    geographic scope, and verification timestamps alongside each
    watchlist entry.
  - `lynceus-seed-watchlist` YAML loader extended to accept an
    optional `metadata:` block per entry, persisted into
    `watchlist_metadata`.
  - New `lynceus-import-argus` CLI for ingesting the Argus
    dual-artifact CSV format (signatures + metadata) into the
    watchlist + metadata tables.
  - New `/watchlist` web UI with list and detail pages that surface
    vendor, category, confidence, source, and notes.
  - Alert-to-watchlist linkage: alerts now record
    `matched_watchlist_id` (migration `005_alert_watchlist_link.sql`)
    so triage can carry metadata end-to-end from detection through
    review.
  - Alert UI enriched with the matched watchlist's metadata (vendor,
    category, confidence, source link).
  - ntfy notification body enriched with vendor and confidence so
    push notifications are actionable without opening the UI.

- **Tier 1 passive metadata capture** (migration
  `006_tier1_capture.sql` adds `probe_ssids` and `ble_name` columns
  on `devices`):

  - WiFi probe-request SSID capture, opt-in via
    `capture.probe_ssids`, **default off** to preserve a
    privacy-conservative posture out of the box.
  - BLE friendly-name capture from GAP advertisements, default on.
  - Expanded BLE service-UUID enrichment dictionary covering more
    consumer-tracker and accessory profiles.

- **CLI tooling** for getting a fresh install running without
  hand-editing YAML:

  - `lynceus-quickstart` — dev/demo launcher that brings up the
    daemon and web UI together against a sane default config.
  - `lynceus-setup` — interactive configuration wizard with live
    Kismet and ntfy connection probes, optional Argus dataset
    import, and a first-run auto-import of the bundled default
    watchlist.

- **Read-only `/settings` page** in the web UI surfacing capture
  configuration, Kismet and ntfy connection status, watchlist origin
  breakdown, and basic system info. Sensitive values (Kismet API
  token, ntfy topic) are redacted server-side. No mutation endpoints
  — the page is observability only.

- **Release packaging** for first-class Linux deployment:

  - `install.sh` (Linux-only) supporting `--user`, `--system`,
    `--uninstall`, `--purge`, and `--dry-run`.
  - systemd unit files (`lynceus.service`, `lynceus-ui.service`)
    with a hardened sandbox profile (`NoNewPrivileges`,
    `ProtectSystem`, namespace restrictions, and related
    directives).

- **Bundled default watchlist data**:
  `src/lynceus/data/default_watchlist.csv` ships inside the wheel as
  package data, and `lynceus-setup` auto-imports it on first run so
  a fresh install boots with a useful baseline.

### Changed

- **DB schema** moved forward three migrations on top of the v0.2
  baseline: added `watchlist_metadata` (004), added
  `alerts.matched_watchlist_id` with a foreign key to `watchlist`
  (005), and added the `probe_ssids` and `ble_name` capture columns
  to `devices` (006). Existing v0.2 databases upgrade in place.
- **Filesystem paths** — the codebase now follows XDG-aware
  conventions consistently for config, data, and state directories,
  replacing the ad-hoc paths used in v0.2. `--user` installs land
  under `~/.config/lynceus`, `~/.local/share/lynceus`, and
  `~/.local/state/lynceus`; `--system` installs land under
  `/etc/lynceus`, `/var/lib/lynceus`, and `/var/log/lynceus`.
- **Test suite** grew substantially from the v0.2 baseline, covering
  Argus import, tier 1 capture, watchlist metadata rendering, the
  setup wizard, and the install/systemd surface.

## [0.2.0] - 2026-05-04

- Initial tagged release: passive Kismet polling, OUI / SSID /
  BLE-UUID watchlist matching, alerts with allowlist suppression,
  ntfy push notifications, and a read-only FastAPI web UI for
  alerts, devices, rules, and the allowlist. Includes CSRF
  middleware, bulk-ack, audit trail, the `lynceus-seed-watchlist`
  CLI, and a basic systemd unit.
