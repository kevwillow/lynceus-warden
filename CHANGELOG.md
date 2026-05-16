# Changelog

All notable changes to this project will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.4.0-rc4] - 2026-05-15

### Added

- **`identifier_type='mac_range'` rows from Argus now land in the
  watchlist instead of being silently dropped.** Pre-rc4, every
  mac_range row hit the `IDENTIFIER_TYPE_MAP` allowlist gate in
  `lynceus-import-argus`, fell to the `dropped_mac_range` counter,
  and never reached the DB. Argus's live `argus_export.csv` snapshot
  at `exported_at=2026-05-14T22:34:07Z` carried ~17,798 mac_range
  rows out of 22,532 total — ~64.49% as `/28` (MA-M, 7-hex prefix
  e.g. `'aa:bb:cc:d/28'`), ~35.44% as `/36` (MA-S / IAB, 9-hex
  prefix e.g. `'aa:bb:cc:dd:e/36'`), plus 12 legacy bare-prefix
  rows (~0.07%) queued for upstream canonicalization. All of these
  were missing from the Lynceus watchlist and could not contribute
  to detections.

  The new `migrations/011_watchlist_mac_range.sql` rebuilds the
  `watchlist` table to relax the `pattern_type` CHECK constraint
  (adding `'mac_range'` to the whitelist) and adds two
  nibble-precision prefix columns — `mac_range_prefix` (lowercase
  hex, no separators) and `mac_range_prefix_length` (28 or 36 in
  current Argus emission) — both NULL for non-mac_range rows. A
  partial index on `(prefix_length, prefix) WHERE pattern_type =
  'mac_range'` keeps non-mac_range rows out of the index and leaves
  oui equality lookups completely unaffected. SQLite cannot modify
  a CHECK constraint via `ALTER TABLE`, so the migration does a
  full table rebuild under `PRAGMA foreign_keys=OFF` per SQLite
  docs §7; the inbound FKs from `alerts.matched_watchlist_id` and
  `watchlist_metadata.watchlist_id` are preserved by-reference and
  do not fire during the intermediate `DROP TABLE`.

  The importer parses both Argus shapes via the new
  `parse_mac_range_pattern` helper in `lynceus.patterns`. Canonical
  CIDR (`'aa:bb:cc:d/28'`, `'aa:bb:cc:dd:e/36'`) round-trips
  unchanged into `watchlist.pattern`; legacy bare-prefix
  (`'aa:bb:cc:d'`, `'aa:bb:cc:dd:e'`) is accepted dual-shape per
  the Argus-engineer handoff and canonicalized on disk so the
  watchlist UI renders uniform shape regardless of input. Each
  legacy row emits one per-row INFO log line
  (`argus import: mac_range legacy bare-prefix '<raw>'
  canonicalized to '<canonical>' argus_record_id=<id>`) so
  operators can grep their import logs to watch the legacy count
  drop to zero once Argus canonicalizes upstream. Unrecognized
  shapes (wrong group count, non-hex characters, unsupported
  prefix length like `/24`, mismatched declared-vs-shape length)
  are rejected loudly and routed to the existing
  `normalization_failed` counter rather than silently accepted —
  a new length surfacing means an Argus wire-contract change worth
  raising on.

  **Intermediate state — runtime matching follows in a sibling
  rc.** After this rc, mac_range rows appear in the watchlist
  table and the watchlist UI, but the poller (`db.resolve_matched_
  watchlist_id`) cannot yet match a sighted MAC against a
  watchlisted range. Alerts on MACs inside watchlisted mac_range
  prefixes will start firing once the follow-up rc lands runtime
  prefix-matching against the new partial index. This intermediate
  state is intentional and keeps the diff bisect-clean: the schema
  + import path land first, the runtime match wires up second.

- **`watchlist_mac_range` rule type — first DB-delegated rule in
  Lynceus.** Closes the runtime-matching gap from the previous
  bullet. The redrafted Part 2 design (after archaeological
  confirmation that no existing watchlist DB → rules engine bridge
  exists in the codebase) establishes a new architectural pattern:
  a rule type whose matching is delegated to the watchlist DB at
  evaluate-time, rather than checked against `rule.patterns` in
  memory. A single empty-patterns `watchlist_mac_range` entry in
  `rules.yaml` enables alert-firing for every matching mac_range
  row in the watchlist DB — operators no longer have to duplicate
  patterns across the DB and rules.yaml for mac_range coverage.

  Three changes land together:

  - **`db.resolve_matched_mac_range(mac)`** returns a
    `ResolvedMacRangeMatch` (watchlist_id, severity, prefix_length)
    or `None`. Hits the partial index from migration 011 — two
    indexed lookups per call (/36 first, then /28) so the more-
    specific match sorts ahead of the less-specific one. Falsy
    `mac` short-circuits to `None`; uppercase observation MACs are
    lowercased at the boundary to harden against the L-RULES-1
    silent-no-match class of bug. `/28` and `/36` ranges covering
    the same MAC are forbidden by IEEE design; if both surface
    defensively, a single WARNING is logged carrying both
    watchlist_ids and the more-specific `/36` row wins.
    `resolve_matched_watchlist_id` (the existing annotation path)
    gains a mac_range branch between the oui and ssid checks
    using the same private helper, so alerts fired by mac_range
    rules get `matched_watchlist_id` stamped without re-issuing
    the WARNING.

  - **`rules.evaluate` admits `watchlist_mac_range`** and gains
    an optional keyword-only `db` parameter. The 18 pre-Part-2
    callsites in `test_rules.py` all pass without modification —
    the optional-kwarg signature change is verified non-breaking
    by an explicit regression test. The validator carve-out
    (`rule_type == "watchlist_mac_range"` REQUIRES empty
    patterns, mirror of the `new_non_randomized_device` carve-out)
    is the first such requirement among `watchlist_*` types.

  - **`/watchlist` detail page** renders the prefix length (`/28`
    or `/36`) plus a block-class annotation (MA-M, 1,048,576
    addresses vs MA-S / IAB, 4,096 addresses) for mac_range
    entries. The annotation is presentational but operationally
    useful — `vendor /28 owns a million MACs` and `specific
    device identifier` get different responses from a triager.
    The list page needs no template change; Part 1's write-time
    canonicalization makes `pattern` render uniformly.

  **Architectural divergence — severity is sourced from the
  matched DB row, NOT from `rule.severity`.** Every other
  `watchlist_*` rule type populates `RuleHit.severity` from
  `rule.severity`; for `watchlist_mac_range` the alert's severity
  comes from `watchlist.severity` of the matched row, which the
  importer writes from `device_category → severity` defaults at
  import time. The divergence is deliberate: the importer wrote
  per-row severity for a reason, and reading it back at alert
  time is the only path that respects that data. `rule.severity`
  is ignored for this rule type — the bundled `config/rules.yaml`
  template's commented-out example calls this out explicitly so
  operators don't expect the field to apply.

  **Operator UX — alert volume after enabling.** A
  `watchlist_mac_range` entry is shipped commented-out in
  `config/rules.yaml`; default is OFF. Uncommenting enables
  alert-firing for any MAC inside any of the 17,786 IEEE-registry
  rows imported by lynceus-import-argus. All of these rows have
  `device_category = 'unknown'`, which maps to severity `"low"`
  in `import_argus.py`'s `DEFAULT_CATEGORY_SEVERITIES`. So:
  enabling the rule will produce `low`-severity alerts at
  whatever rate observed MACs fall inside the IEEE allocations
  Argus catalogued. The 17,786 rows cover Mitsubishi Electric,
  Becton Dickinson, Airgain, and similar enterprise / embedded /
  medical / industrial vendors — predominantly enterprise scan
  surfaces, sparse on residential. If `"low"` is the wrong tier
  for this volume, tune `DEFAULT_CATEGORY_SEVERITIES['unknown']`
  before enabling the rule, or use the allowlist to scope the
  detection geographically. The default severity is intentionally
  not changed in this rc — that's an operator-policy
  conversation, not a code-level decision.

  This pattern is a natural migration target for the other
  `watchlist_*` rule types in a future rc, which would close the
  broader UX gap surfaced by the Part 2 archaeology: today every
  watchlist DB row is inert unless operators manually duplicate
  its pattern into rules.yaml. That migration is deliberately out
  of scope here; this rc establishes the precedent cleanly.

  Cross-references the schema+importer half of this arc in the
  prior bullet (migration 011, `parse_mac_range_pattern`); the
  full arc reads in order down the page.

- **Watchlist delegation extension — `watchlist_mac`,
  `watchlist_oui`, `watchlist_ssid`, and `ble_uuid` now accept the
  empty-patterns-delegates-to-DB semantic.** Closes the broader
  DB-delegation gap that the Part 2 bullet above flagged as a
  natural follow-up. Before this change, only `watchlist_mac_range`
  fired alerts via DB delegation; the 63 rows shipped via the
  bundled `default_watchlist.csv` plus every Argus-imported
  mac/oui/ssid/ble_uuid row remained inert unless operators
  manually duplicated their patterns into `rules.yaml`. After this
  change, a single empty-patterns rule per type enables alert-firing
  for every matching DB row of that type — same one-line idiom that
  Part 2 established for `watchlist_mac_range`.

  Three changes land together:

  - **`db.resolve_matched_{mac,oui,ssid,ble_uuid}_for_eval`** —
    four new matchers returning a `ResolvedWatchlistMatch`
    (`watchlist_id`, `severity`) or `None`. The four delegate to a
    single `_lookup_simple_watchlist_match(pattern_type, pattern)`
    helper that also backs `resolve_matched_watchlist_id` (the
    annotation path used by `matched_watchlist_id` stamping), so
    the eval path and the annotation path can never drift on what
    counts as a match. The oui matcher takes a full MAC and slices
    the first 8 chars internally (mirror of the annotation path's
    `mac[:8]` derivation); the ble_uuid matcher takes the obs's
    UUID list and returns the first watchlisted UUID, mirroring
    the existing in-memory ble_uuid eval branch's first-match
    behavior.

  - **`rules.evaluate` gains delegation paths** for the four
    rule types. Each existing in-memory branch wraps in
    `if rule.patterns:` (preserved verbatim) and adds an `else:`
    delegation branch consulting the corresponding DB matcher.
    Severity sourced from the matched DB row in the delegation
    case, from `rule.severity` in the in-memory case (Part 2's
    severity-from-row pattern, now established as the convention
    for every DB-delegated path). Rules with non-empty patterns
    see byte-identical behavior — the in-memory branch's code is
    untouched, just indented one level under the new `if`.

  - **Validator restructured** — `Rule._validate_rule` no longer
    relies on a generic `startswith("watchlist_")` branch to
    require non-empty patterns. Each rule type's empty/non-empty
    admission is now spelled out explicitly: `watchlist_mac_range`
    REQUIRES empty (Part 2 carve-out unchanged),
    `new_non_randomized_device` REQUIRES empty (existing carve-out
    unchanged), and the four delegation-capable types accept BOTH
    shapes. Spelling each policy out individually means a future
    hypothetical `watchlist_X` lands in an explicit branch rather
    than silently inheriting whichever default is most recent.

  **Backward compatibility — non-negotiable, verified end-to-end.**
  Operators running pre-existing deployments with non-empty
  `watchlist_mac` / `watchlist_oui` / `watchlist_ssid` / `ble_uuid`
  rules see ZERO behavioral change. Verified by per-type "in-memory
  path severity from rule unchanged" regression tests in
  `test_rules.py` and by every existing test in `test_rules.py`
  (33 prior callsites) and `test_alert_linkage.py` continuing to
  pass without modification. The validator change relaxes empty
  patterns from "rejected" to "accepted as delegation idiom" for
  the four affected types, so two pre-existing tests that asserted
  the old "empty rejected" behavior were updated to assert the new
  semantic — this is the only test modification in scope, and it's
  on the precise behavior this rc deliberately changes.

  **Operator UX — alert volume after enabling.** All four entries
  ship commented-out in `config/rules.yaml`; default is OFF.
  Uncommenting an entry enables alert-firing for every matching
  watchlist row of that type. The matched DB row's severity flows
  into the alert directly (NOT `rule.severity`, which is ignored
  for the delegation case — the rules.yaml comment is explicit).
  Per-row severity is populated by `lynceus-import-argus` from
  `device_category` via `DEFAULT_CATEGORY_SEVERITIES` in
  `import_argus.py:62-72`:

  - `imsi_catcher` → `high`
  - `alpr` → `high`
  - `hacking_tool` → `high`
  - `body_cam` → `med`
  - `drone` → `med`
  - `gunshot_detect` → `med`
  - `in_vehicle_router` → `med`
  - `unknown` → `low`
  - any category not listed → `low`

  The 63 bundled rows in `default_watchlist.csv` are populated
  per the same map. Operators planning to enable a delegation
  entry should `lynceus-list-watchlist --pattern-type mac` (and
  the other three types) first to see the `severity` distribution
  of what's actually in their DB; the alert volume after enabling
  scales with the count of matching observations and the imported
  per-category severity. If a category's default severity is
  wrong for an operator's environment, tune via
  `--override-file severity_overrides.yaml` at import time
  (the existing OverrideConfig path) before enabling the
  delegation entry. Runtime `severity_overrides.yaml` consumption
  (the half-wired feature noted in the Part 2 archaeology) is
  still in backlog — operators wanting per-category severity
  tuning today still do it via the import-time OverrideConfig,
  not at evaluate time.

  Cross-references Part 2's bullet above as the architectural
  precedent (`watchlist_mac_range` was the first DB-delegated rule
  type; this bullet completes the broader story by extending the
  same pattern to the other four). Part 2 introduced the
  empty-patterns idiom and the severity-from-row divergence; this
  bullet generalizes both as the convention.

- **Runtime severity-overrides layer — `severity_overrides.yaml`
  now applies at alert time, not just at import time.** Closes the
  final Part 2 archaeology backlog item. Pre-this-rc, the wizard
  scaffolded `severity_overrides.yaml` and `lynceus-import-argus
  --override-file` consumed it (vendor_overrides, geographic_filter,
  confidence_downgrade_threshold, device_category_severity), but
  the daemon never read the file. Operators wanting to retune
  severities after import had to re-import the entire Argus corpus
  (~22,500 rows) to see the new severities applied. Now the poller
  reads the same file at startup and applies a runtime transform
  on DB-delegation matches at alert construction.

  Two new behaviors. Both are runtime-layer-only — the import-time
  consumer in `lynceus-import-argus` is unchanged.

  - **`device_category_severity` (existing key, now BOTH layers).**
    Import bakes the per-category remap into `watchlist.severity`
    at write time (unchanged); runtime re-applies the same map at
    alert time on top of whatever was baked. An operator changing
    `unknown: med` in the file → daemon restart → the 17,786
    IEEE-registry mac_range rows (baked `low`) fire at `med` on
    the next poll cycle. No re-import. The same key flows
    consistently to both layers.

  - **`suppress_categories` (NEW key, runtime only).** A
    delegation match whose `device_category` is in this list emits
    no `RuleHit` — the alert is suppressed entirely (no row in
    `alerts`, no ntfy push). The watchlist row stays present;
    only alert emission is silenced. Useful when an operator wants
    to retain enrichment metadata for a category without producing
    alerts on it. An INFO log line per suppression names the rule,
    category, and watchlist_id so operators have a forensic trail.

  Three structural changes:

  - `ResolvedMacRangeMatch` and `ResolvedWatchlistMatch` (the
    delegation-match dataclasses) gain a `device_category: str |
    None` field. Both private lookup helpers
    (`_lookup_simple_watchlist_match`, `_lookup_mac_range_matches`)
    LEFT JOIN onto `watchlist_metadata` to surface the category.
    The JOIN is indexed on `watchlist_id`; cost is negligible
    against the primary equality / prefix lookup. NULL category
    (the 63 bundled `default_watchlist.csv` rows that ship without
    metadata) means the runtime layer passes through — no remap,
    no suppression applies.

  - `rules.RuntimeSeverityOverride` is the runtime-side view of
    `severity_overrides.yaml`. Reads only the two runtime-relevant
    keys; pydantic `extra="ignore"` lets the parser tolerate the
    full superset of keys the wizard's starter file documents — a
    file containing only import-time keys yields an empty runtime
    view that fast-paths through. `rules.load_runtime_severity_
    overrides` is the loader: missing file → INFO + None; malformed
    YAML / OSError / validation error → WARNING + None. The poller
    never crashes because of a malformed override file.

  - `rules.evaluate` gains a `severity_overrides:
    RuntimeSeverityOverride | None = None` kwarg (mirror of the
    Part 2 `db=` addition). All five DB-delegation eval branches
    (mac_range + the four extension types) call a shared
    `_apply_runtime_overrides` helper after the DB match and before
    `RuleHit` construction. Precedence is documented as
    suppress > remap > pass-through. Pass-through fast-path
    short-circuits when overrides is None / `is_empty()` / the
    match has no `device_category` — byte-identical RuleHits to
    pre-this-rc behavior.

  **Backward compatibility — verified end-to-end.**

  - In-memory pattern rules (non-empty patterns) are unchanged;
    severity stays rule-sourced. Runtime overrides apply only to
    DB-delegation matches. Explicit regression test in
    `test_rules.py`.
  - The import-time `OverrideConfig` consumption in
    `import_argus.py` is byte-identical pre/post (separate code
    path, separate parser instance). `vendor_overrides`,
    `geographic_filter`, and `confidence_downgrade_threshold`
    remain import-time-only with their existing semantics.
  - `DEFAULT_CATEGORY_SEVERITIES` at `import_argus.py:62-72` is
    unchanged — still controls what gets baked at import time.
    Runtime overrides apply on top.
  - The full pre-this-rc test suite passes without modification
    (modulo additive device_category assertions on the matchers,
    which surface the new field without changing existing
    behavior).

  **Operator UX — what changed in `severity_overrides.yaml`.**

  - The wizard's starter file now carries inline `# LAYER:` tags
    on each section: `IMPORT-TIME` (re-import to apply),
    `RUNTIME` (daemon restart applies live), or `BOTH`
    (`device_category_severity` only). The user-facing explanation
    block enumerates the two layers explicitly. Operators
    reconfiguring see the per-layer effect of each section
    inline rather than having to read source.
  - The webui `/settings` severity-overrides card mirrors the
    same wording — import-time keys vs runtime keys, with the
    action required to apply changes.
  - `Config` gains a `severity_overrides_path: str | None`
    field. Defaults to None (opt-in for the runtime layer); set
    to `paths.default_overrides_path(<scope>)` (the same path the
    wizard scaffolds) to activate runtime overrides. The wizard
    does NOT currently auto-persist this path into `lynceus.yaml`
    — operators opt in by adding the line.

  **Deliberate deferral — `vendor_overrides` at runtime.**
  `vendor_overrides` stays import-time-only this rc. Its `"drop"`
  sentinel today means "skip the row at import" — a runtime
  interpretation would silently overload that meaning to mean
  "suppress the alert" instead, which is a footgun worth
  designing deliberately. A future `suppress_vendors` key (named
  to avoid the `vendor_overrides`/`"drop"` semantic clash) is the
  right shape, and that's a dedicated design pass, not a one-line
  schema addition.

  Cross-references Part 2 (`watchlist_mac_range`) and the
  delegation extension bullet above as the prerequisite chain:
  Part 2 introduced DB-delegated rule types; the delegation
  extension generalized that to mac/oui/ssid/ble_uuid; this rc
  adds the runtime severity layer that operators can tune
  without re-importing. The Part 2 archaeology surfaced
  `severity_overrides.yaml` as half-wired (created by the wizard,
  read only at import time); this bullet makes the wizard's
  framing accurate.

### Fixed

- **`load_runtime_severity_overrides` now logs INFO at every load
  outcome, not only on missing-file.** Surfaced during pre-smoke
  review of the Kali live-validation runbook against the as-shipped
  code. The runbook's Phase 3 step 8 promised "an INFO line
  confirming the runtime severity-overrides file was loaded ...
  grep for 'severity_override' or 'runtime override'" — but the
  initial implementation logged INFO only on the missing-file
  path. The successful-load path and the disabled-via-None path
  (operator hadn't set `severity_overrides_path` in lynceus.yaml)
  both returned silently. An operator running the smoke and
  grepping journalctl at startup would have seen nothing and been
  unable to tell whether the runtime layer was active, disabled,
  or silently pass-through because of an unset config field —
  exactly the diagnostic blind spot the runbook step was meant to
  prevent.

  Three new INFO lines now cover the three load outcomes that
  return non-failure (the four failure modes — missing file,
  unreadable file, malformed YAML, validation error — already
  logged at WARNING and are unchanged):

  - Active-keys path: `runtime severity overrides loaded from
    <path>: N category remap(s), M suppressed category(ies). Edits
    take effect on daemon restart.` Self-describing — an operator
    who expected 3 remaps but sees 1 knows the parser was
    selective. Counts at startup are the runbook's happy-path
    grep target.
  - Empty-keys path: `runtime severity overrides loaded from
    <path> but contain no active runtime keys
    (device_category_severity / suppress_categories); runtime
    layer is effectively pass-through. Edit the file and restart
    the daemon to activate.` Distinguishes a wizard-default-state
    file (parses cleanly, no runtime keys uncommented) from one
    where the operator's edits actually took effect.
  - None path (severity_overrides_path unset): `severity_overrides
    _path not set in lynceus.yaml; runtime override layer
    disabled. Set the field to your severity_overrides.yaml path
    (e.g. /etc/lynceus/severity_overrides.yaml under --system, or
    ~/.config/lynceus/severity_overrides.yaml under --user) and
    restart the daemon to enable.` Names the config field by
    exact name + points at the canonical paths so an operator
    who skipped the relevant lynceus.yaml edit sees the
    actionable hint without grepping source.

  All three are greppable via the literal `runtime severity
  overrides` (the originally-promised `severity_override` /
  `runtime override` shapes both match). One new test +
  reframing of two existing parser tests cover the three new
  paths. Backward compat: the four WARNING-level failure-mode
  log lines are unchanged in content; only the previously-silent
  success / disabled paths gained log entries. The new entries
  are additive and have no functional impact on the runtime
  override transform itself.

- **`lynceus-import-argus --from-github` default `--repo` was
  pointing at a non-existent repository.** rc3 hard-coded
  `kevlattice/argus` as the default; the actual Argus repo is
  `kevwillow/argus-db`. The headline rc3 feature 404'd on the
  `/releases/latest` API call before it could even start the raw
  fetch, and operators saw an opaque `HTTPError` instead of a
  successful refresh. `DEFAULT_GITHUB_REPO` now resolves
  correctly; passing `--repo OWNER/NAME` for a fork still works
  the same way.

- **`lynceus-import-argus --from-github` no longer crashes when
  the Argus repo has no published GitHub Releases.** rc4 still
  required `/repos/{repo}/releases/latest` to return a tag, but
  `kevwillow/argus-db` ships its CSV on every commit and does not
  cut formal Release objects (its README is explicit that release
  cadence is discretionary; the GitHub sidebar reads "No releases
  published"). The API returned 404, `raise_for_status()` raised
  `HTTPError`, and `--from-github` was unusable until Argus
  published its first Release — wrong dependency to bake in.
  `_resolve_ref` now treats a 404 on `/releases/latest` as "no
  published releases" and falls back to the `main` branch, logging
  a WARNING (`No published releases for {repo}; falling back to
  'main'. Pin a tag with --ref for reproducibility.`) so operators
  can see at a glance whether they got a release tag or a branch
  HEAD. Other non-200 statuses (500, 403) still propagate — a
  transient GitHub outage must not silently degrade to importing
  whatever `main` happens to be. Surfaced by the rc4 live smoke
  against the real Argus repo.

- **`lynceus-import-argus --override-file` is now scope-strict and
  no longer crashes for unprivileged `--scope user` runs on a
  host that also carries a `--system` install.** Pre-fix, the
  argparse default was hard-coded to
  `/etc/lynceus/severity_overrides.yaml` regardless of `--scope`.
  On a Linux host with the system-scope install (`/etc/lynceus`
  is `0750 root:lynceus` by design), an unprivileged user running
  the importer hit the system path via the default and crashed
  with `PermissionError` inside `Path.is_file()`. The flag now
  defaults to `None`; resolution derives from
  `paths.default_overrides_path(--scope)` — user-scope only ever
  probes the user-scope path, system-scope only the system path,
  no cross-scope fallback. Explicit `--override-file <path>` is
  used verbatim and bypasses scope-derived defaults entirely.
  `load_override_config` also converts `PermissionError` on the
  probe into a `RuntimeError` that names the offending path, so
  operators see an actionable message instead of a bare traceback.
  Surfaced by the rc4 live smoke; the bug was latent in every
  prior `lynceus-import-argus` ship but only triggers on mixed
  user+system installs.

- **`lynceus-setup` refuses sudo-without-`--system` to prevent
  silent scope misplacement.** Reproduced in the rc4 live smoke:
  `sudo lynceus-setup --reconfigure` (no `--system`) silently
  regenerated `/root/.config/lynceus/lynceus.yaml` while the
  system daemon kept reading `/etc/lynceus/lynceus.yaml` — the
  operator believed they had reconfigured the daemon, but the
  daemon was still running the stale pre-reconfigure config. The
  wizard followed its scope rules literally (`euid=0`, scope
  defaults to user, `Path.home()` is `/root`) but the
  operator-facing result was divergence between intent and effect.
  The wizard now refuses early in `main()` when `euid=0` and
  `--system` is not passed, prints both correct invocations
  side-by-side, and exits 2. Three legitimate combinations are
  unchanged: root + `--system` (system install), non-root + no
  flag (user install), non-root + `--system` (still hits the
  pre-existing "use sudo" preflight). Windows is a no-op for the
  new check — `_euid()` returns `None`, no sudo trap to fall into.
  After upgrading, operators who hit this bug in rc4 should re-run
  `sudo lynceus-setup --system --reconfigure` to bring
  `/etc/lynceus/lynceus.yaml` back into sync with their intended
  configuration.

### Changed

- **All `kevlattice/lynceus` GitHub URLs replaced with
  `kevwillow/lynceus-warden`** to reflect the upstream account
  rename + repo rename. Surfaces touched: `pyproject.toml`
  (Homepage / Repository / Issues, which flow into the wheel's
  PKG-INFO and PyPI metadata), `SECURITY.md` (private-advisory
  and public-issues URLs), the `git clone` URL in the README, and
  the `Documentation=` line in both systemd unit files (visible
  in `systemctl status` and journalctl context). The
  `kevwillow/lynceus.git` → `kevwillow/lynceus-warden.git`
  GitHub-side redirect is still active, so older clones continue
  to push and pull, but new clones should use the canonical URL.

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
  consciously want the bleeding edge). `--repo OWNER/NAME` swaps
  the source repo for forks. Pulled artifacts land in
  `<data-dir>/argus-cache/<ref>__argus_export.csv` so each refresh
  leaves a forensic trail.

  Network access is confined to this one CLI by design:
  `install.sh` stays offline (its header invariant), the daemon
  and the web UI don't change, and the bundled-watchlist first-run
  import in `lynceus-setup` continues to read from the wheel. The
  `--from-github` path uses `requests` with default `verify=True`
  TLS and bounded timeouts (15s for the API release lookup, 30s
  for the raw fetch). No GitHub API token is required — both
  `/releases/latest` and `raw.githubusercontent.com` work
  unauthenticated. `--input` remains for air-gapped operators;
  the two flags are mutually exclusive, exactly one is required.

- **`--db` now defaults to the canonical scope path** in
  `lynceus-import-argus`. Pre-change the flag was required, so
  every operator had to hand-roll `/var/lib/lynceus/lynceus.db`
  (under `--system`) or `~/.local/share/lynceus/lynceus.db`
  (under `--user`) every time. The flag now resolves to
  `paths.default_db_path(--scope)` when omitted — same XDG-aware
  helper the setup wizard and the daemon already consult — so the
  common case is a no-flag invocation. New `--scope user|system`
  picks the default scope (defaults to `user`); pass `--db`
  explicitly to override. Existing scripts passing `--db` keep
  working unchanged.

- **Scope-aware uninstall.** `install.sh --uninstall` now accepts
  both `--user` and `--system`, closing the gap where only
  `--system` installs had a clean reversal path. The internal
  `MODE` variable was split into orthogonal `ACTION` (install /
  uninstall) and `SCOPE` (user / system), so `--uninstall --user`
  and `--user --uninstall` are order-independent and the dispatch
  table is `case "$ACTION:$SCOPE"`. Pre-flight is now
  action-aware: `python3` and `python3-venv` are install-only
  requirements (uninstall must work on a host where Python is
  already gone), and `systemctl` is gated on `SCOPE=system` (covers
  both install-system and uninstall-system). `--purge` now errors
  unless `--uninstall` is also passed, making the previously-implicit
  "purge only applies to uninstall" relationship explicit at the
  CLI surface.

  `--user --purge` semantics: deletes `~/.config/lynceus`,
  `~/.local/share/lynceus`, and `~/.local/state/lynceus` (the
  latter two contain `lynceus.db` and logs). Without `--purge`,
  the venv at `~/.local/share/lynceus/.venv` is removed (the
  install artifact) but the surrounding data dir is preserved, so
  the operator's database survives a non-purge uninstall. If no
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
  prints where it looked if neither is present, and otherwise
  execs `install.sh --uninstall --user|--system` with `--purge`
  and `--dry-run` passed through. Like `install.sh`, it's
  intentionally OFFLINE — no network access of any kind.

## [0.4.0-rc2] - 2026-05-15

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

- **Dark mode for the web UI.** Auto-follows the OS via
  `prefers-color-scheme: dark`, with a small `theme: auto / light /
  dark` toggle button in the topnav for operators who want to
  override. The toggle cycles auto → light → dark → auto and
  persists the choice to `localStorage` (`lynceus-theme` key), so it
  sticks across page navigations and reloads. Pico CSS v2.1.1
  (already vendored) handles the dark palette for every standard
  semantic element — body, text, links, tables, forms, buttons,
  nav, article, borders — and `lynceus.css` adds matching dark
  variants for the project-custom surface (severity / confidence /
  status badges, the topnav border, the sparkline bar fill, the
  severity-tinted alert rows, and the table-scroll fade gradient).
  The toggle sets `data-theme` on `<html>`, which Pico and our
  `lynceus.css` overrides both honor coherently from a single flag.
  Light-mode rendering is byte-identical to pre-change (the
  `:root` defaults preserve the prior color literals exactly), so
  operators who keep their OS in light mode and never touch the
  toggle see no visual change. Known limitation: a brief
  flash-of-prefers-color-scheme on every page load because
  `lynceus.js` runs `defer`red; fixing requires an inline `<head>`
  script and is deferred to a future iteration if anyone reports
  it as bothersome.

- **`lynceus-import-argus --min-confidence N` row-skip flag.** Hard-skips
  rows where `confidence < N` before any DB write; skipped rows land in
  a new `ImportReport.dropped_low_confidence` counter surfaced in both
  the per-bucket and the trailing-summary lines of the operator-facing
  report, plus a per-row INFO log line (`argus_record_id` + actual
  confidence) so the count is debuggable instead of opaque. Deliberately
  distinct from the YAML-configured `confidence_downgrade_threshold`
  (which downgrades severity tier — high→med→low — but still imports
  the row): `--min-confidence` is a hard pre-DB filter, the threshold
  is a severity nudge. Both can be active simultaneously and operate
  independently. The intended Wave G workflow is a high-confidence-first
  smoke test — `--min-confidence=80 --dry-run` against the incoming
  push to confirm the high-conf subset lands cleanly before re-running
  without the flag to ingest the full export. Default is unset (no
  filtering), so the flag is opt-in and existing import scripts are
  unaffected.

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

### Changed

- **`cli.import_argus` now emits a per-row INFO log line on every
  identifier_type drop.** Pre-change, `mac_range` rows and rows
  carrying an unknown `identifier_type` were silently swallowed into
  the `dropped_mac_range` / `dropped_unknown_type` counters — visible
  in the final report total, but with zero row-level forensic trail.
  An operator who imported an Argus export and saw the unknown-type
  count jump had no way to learn *which* identifier_type values Argus
  had pushed without re-grepping the source CSV. The new log lines
  carry `argus_record_id` and the raw (case-preserved) identifier_type
  value plus a stable reason token
  (`mac_range_unsupported` / `unknown_identifier_type`), so the
  forensic question is answered by `journalctl | grep "argus import:
  skipping"`. INFO not WARNING because these are *expected* drops per
  the Argus §4.4 contract, not anomalies — they must surface for
  debuggability but must not upgrade the ntfy notification threshold
  or screen-flood on large imports. The immediate consumer is the
  Wave G + flock-back push the Argus engineer is about to ship: any
  new identifier_type Argus emits behind us will now be visible in
  the first operator's import log rather than being lost to the
  unknown-type bucket.

### Fixed

- **`cli.import_argus._parse_date` now tolerates four timestamp shapes
  in the Argus CSV's `first_seen` / `last_verified` columns** (F6).
  Pre-fix, the parser only accepted the space-separated
  `"%Y-%m-%d %H:%M:%S"` shape — but on 2026-05-14 Argus codified its
  canonical emission (CP22) as ISO-8601 UTC with `Z` suffix at seconds
  precision (e.g. `"2026-05-14T06:13:42Z"`), and the older write-paths
  that fed the dataset had historically emitted at least four distinct
  shapes anyway. The strict parser rejected every Z-form value with
  `ValueError`, surfacing in the per-row `errors` bucket and silently
  dropping the matching watchlist rows. Smoke against the live
  `argus_export.csv` (22,532 rows) showed **50 imported / 53 errors**
  pre-fix, every error of the form
  `time data '...Z' does not match format '%Y-%m-%d %H:%M:%S'`. Post-fix,
  the same dry-run reports **103 imported / 0 errors** with the
  expected reconciliation (103 + 17,794 `mac_range` + 4,635
  `unknown_type` = 22,532); the 50→103 delta is rows that previously
  failed on a Z-form `last_verified` value mid-row, now parsed cleanly.
  `_parse_date` accepts: canonical Z form (`"2026-05-14T06:13:42Z"`),
  ISO with explicit UTC offset (`"2026-05-14T06:13:42.204792+00:00"`,
  the pre-CP22 dominant shape), space-separated treated as UTC
  (`"2026-05-06 00:30:28"`, backward compat with archived exports), and
  date-only midnight UTC (`"2026-05-10"`, preserves the only signal a
  date-only row carries). Non-zero offsets are coerced to UTC via
  `astimezone`. Unparseable shapes still raise `ValueError` so a future
  fifth shape surfaces immediately in the existing row-error path
  rather than landing silently. Defense in depth with the Argus-side
  `_normalize_datetime` (which canonicalizes at emission): either side
  could have fixed it alone, both is more robust against archived
  pre-CP22 exports an operator may replay. Five new format-tolerance
  unit tests cover each shape end-to-end through `import_csv`, and one
  opportunistic cross-repo integration smoke
  (`test_cross_repo_live_argus_csv_imports_without_errors`) imports a
  real `argus_export.csv` and asserts zero row errors plus full
  reconciliation — skips when the sibling Argus checkout is absent
  (CI, fresh clone), runs locally when both repos coexist.

- **Migration 007 (`evidence_snapshots`) now uses `IF NOT EXISTS`
  guards on its three CREATE statements** (one table, two indexes).
  Re-running the SQL on a DB where 007's objects exist but the
  `schema_migrations` row was never written (interrupted runner,
  crash mid-script) is now a no-op rather than raising
  `sqlite3.OperationalError: table evidence_snapshots already exists`.
  Narrow M-series partial-apply hardening from the v0.4.0 diagnostic
  backlog — the broader migration-runner atomicity work (L-MIG-1/7,
  per-migration transactions and a recovery path that reconciles the
  on-disk schema with `schema_migrations`) stays deferred to v0.4.1.
  Other migrations are unchanged in this pass; a follow-up sweep
  will apply the same guards to 001-006 and 008-010 once the runner
  work lands.

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

- **`cli.import_argus` now case-normalizes `identifier_type` before the
  allowlist check.** Symmetrical with the 19aabf6 pattern-value
  normalization fix: that one canonicalized the *identifier* (the
  pattern string itself) at write time, this one canonicalizes the
  *identifier_type* column at read time. Pre-fix, a row from Argus
  with `identifier_type="BLE_SERVICE"` (uppercase) missed the
  lowercase keys in `IDENTIFIER_TYPE_MAP` and silently dropped into
  the `dropped_unknown_type` counter — visible in the final report
  total but with no per-row log line, so operators reviewing import
  stdout would see the count drop without learning which type
  variants Argus had pushed. The importer now does
  `(row["identifier_type"] or "").strip().lower()` before the
  allowlist lookup; the whitespace strip also handles
  BOM / trailing-space edge cases for free. This matters specifically
  for the Wave G + flock-back push the Argus engineer is about to
  ship: high-confidence `ble_service` rows that happen to ship as
  `BLE_SERVICE` would otherwise be lost without warning.
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
