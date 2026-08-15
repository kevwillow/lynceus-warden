# lynceus backlog

Deferred features and known followups, captured here so they don't get lost.

## v0.2 release notes

What landed in the v0.2 cycle:

- Project skeleton, packaging, and console scripts (`lynceus`, `lynceus-ui`,
  `lynceus-seed-watchlist`).
- SQLite schema with bundled migrations and a `poller_state` table for
  incremental polling.
- Kismet REST client with multi-source support, startup health check,
  and a fixture-driven fake client for offline development.
- Poll loop with YAML config (pydantic v2 validation), signal handling,
  and a `--once` smoke-test mode.
- Rules engine and allowlist, both YAML-defined, with a configurable
  alert-deduplication window.
- BLE service-UUID extraction and a matching `ble_uuid` rule type for
  AirTag-class trackers.
- ntfy.sh notifier with priority and emoji tags by severity, plus null
  and recording variants for tests.
- Read-only FastAPI web UI: dashboard, alerts list and detail, devices
  list and detail, rules and allowlist views; pagination, filtering,
  single and bulk alert acknowledgement with audit trail; CSRF middleware
  on POST routes; localhost-bound by default.
- Hardened systemd units for the daemon and UI, with env-file template.
- Watchlist seeding CLI with bundled threat OUIs and BLE tracker UUIDs,
  plus user-supplied YAML.
- Documentation: README, configuration reference, rules reference, smoke
  checklist, Windows dev guide, deploy guide, status snapshot.

## Deferred features (revisit when conditions met)

### Argus surveillance-equipment database
A versioned, community-maintainable watchlist of RF signatures for known
surveillance hardware: marked police vehicle WiFi/BT, body-worn cameras,
dashcams, license plate readers, Flock and similar fixed camera systems.
Maintained in a separate project (argus-db) and consumed by lynceus via
the dedicated `lynceus-import-argus` CLI, which lands rows into the
watchlist + watchlist_metadata side table. Continued work here is
data-gathering, not lynceus-side integration -- the importer shipped in
v0.5.0.
- **Trigger**: when a useful baseline of real-world signatures has been
  collected. Data work first; lynceus-side ingest is already in place.
- **Estimated**: data-gathering effort dominates; lynceus-side work is
  bounded to schema or importer changes if the CSV contract evolves.
- **Notes**: maintain in its own repo or sub-tree so the dataset can
  evolve at its own pace and be forked. Permissive licence on the
  dataset so derivatives are allowed. Detection only. Lynceus does not
  jam, spoof, or otherwise interfere with any of the equipment in the
  list, and the project's "passive-only" stance applies to Argus too.

### Stingray hunter bridge
Re-emits hunter alerts to Lynceus ntfy topic. Independent module under
`src/lynceus/bridges/stingray.py`, doesn't touch core.
- **Trigger**: when active SIM is in the hotspot AND hunter is operational.
- **Estimated**: 1 prompt, ~200 LOC + tests.
- **Notes**: ADB workaround NOT recommended. Wait for SIM. Building before
  the hunter is operational means the integration drifts out of sync with
  Rayhunter/Crocodile Hunter releases before it's ever exercised.

### Single-emit-with-resolved-severity mode for multi-rule matches
`rules.evaluate()` emits one RuleHit per matching rule per observation;
a device on the watchlist by both mac AND oui produces two alert rows
at two potentially-different severities for the same poll-cycle
observation. This is intentional (see CHANGELOG `[Unreleased] §
Documentation`, audit-first design, dedup window collapses
near-duplicates downstream). If operators report ntfy/alert-list noise
that the dedup window doesn't smooth out, the alternative is an opt-in
"single-emit with resolved severity" mode: highest-severity-wins
across the matching set, one alert row, configurable via the existing
runtime overrides surface. NOT a default change. The current emit
semantics let operators see which rule chains are catching what
across the same observation, which is information the merged path
would hide.
- **Trigger**: real-world operator report of multi-rule noise that
  the dedup window can't absorb, OR a request to attribute a single
  alert to a single resolved cause for downstream tooling.
- **Estimated**: 1 prompt, ~100 LOC in `rules.evaluate()` + a config
  knob + tests. Architecturally cheap. The loop already collects all
  hits before returning; a post-loop resolve step is small.
- **Notes**: until then, do NOT "fix" the multi-emit behavior. It is
  the locked semantic. Diagnostic test
  `tests/test_diag_rules.py::test_diag_rules_severity_resolution`
  pins the current behavior; future contributors who read it asking
  "shouldn't this resolve?" should be pointed at this entry.

### L-RULES-10: SSID case/whitespace handling for the `ssid` pattern_type
The existing exact-match `ssid` pattern_type (case-sensitive per
IEEE 802.11) deliberately does NOT case-fold or strip whitespace. The
new `ssid_pattern` pattern_type (rc6, migration 019) is case-
insensitive substring; that scope intentionally does not retroactively
change `ssid`. If operators report missed alerts due to case drift on
exact watchlist entries (vs. observed SSIDs from the same vendor), the
fix would be either: (a) normalize at write time (would change stored
data, needs migration), or (b) normalize at match time (preserve
stored data, fold at lookup, symmetric to the ssid_pattern matcher).
- **Trigger**: operator reports of missed exact-ssid alerts traced to
  case mismatch between watchlist entry and Kismet observation.
- **Estimated**: 1 prompt, ~30 LOC + tests + migration if (a) wins.
- **Notes**: ssid_pattern covers the substring-with-case-insensitivity
  use case already, so the remaining gap is narrow. Default to deferral
  until a real miss is observed.

### Per-Argus-record dedup model
Operational symptom (pre-v0.6.0): re-importing the bundled Argus CSV
inflated counters (31 false-new + 21 false-updated) and thrashed
`updated_at` on 25 `watchlist_metadata` rows per re-import (99
mutating SQL statements against unchanged content). The pre-v0.6.0
hypothesis recorded here, "same-pattern Argus rows differing only
in `device_category`", was falsified by scouting in 2026-05-XX:
**0 of 15** peer-collide groups in the bundled CSV differ on
device_category. The actual upstream-emitted shapes are documented
in [docs/ARGUS_DEDUP_SHAPES.md](docs/ARGUS_DEDUP_SHAPES.md).

**Status: operational thrash fix landed in v0.6.0** via two import-
side gates and a layered idempotency short-circuit in
`upsert_metadata`. See the CHANGELOG `Fixed` entry under
`[Unreleased]` for the full landing summary. Second-run mutation
count on the bundled CSV is now 1 (`import_runs` INSERT); counter
math invariant balances; new `dropped_peer_collision` and
`dropped_in_import_dup` counters surface the gated rows in the
operator-facing report. Both gates adjudicate among colliding
members via an explicit highest-severity-wins tiebreak chain
(severity rank → confidence → earliest CSV index) so the policy
is operator-protective rather than dependent on Argus emission
order; see [docs/ARGUS_DEDUP_SHAPES.md](docs/ARGUS_DEDUP_SHAPES.md)
"Tiebreak policy" for the chain rationale and the audit of which
bundled-CSV groups carry severity drift.

**Schema-side rework still possible if operationally useful**
(v0.7.0+ candidate, conditional). The v0.6.0 fix preserves the
1:1 `watchlist_metadata.watchlist_id UNIQUE` constraint and uses
first-occurrence-wins. The collapsed peer-row's
manufacturer/source/category data is dropped at import time,
not persisted. If operators ever need access to per-peer-row
metadata (e.g., severity override edge cases that depend on
which device_category Flock-the-ALPR-vendor canonicalizes to,
currently first-Argus-row-wins), the rework to consider is an
`argus_record_id`-keyed `watchlist_metadata` (drop the
`watchlist_id UNIQUE` constraint, allow 1:N), plus a row-level
dispatch decision in `rules.py` to pick which peer's
severity/category to apply per observation. Non-trivial migration
+ blast radius (LEFT-JOIN consumers across `get_watchlist_with_
metadata`, `list_watchlist_with_metadata`, `/watchlist` UI,
`/watchlist.csv` export, alert payload metadata embed). Defer
until a concrete operator pain-point materializes; the v0.6.0 fix
is the right resting place absent that.

**Upstream-side context**: the Argus emission itself is the actual
root cause of the dup shapes. Bucket A (peer-collide) reflects
Argus emitting both legacy and canonical mac_range forms, and both
short and zero-padded ble_manufacturer_id / ble_uuid forms, as
distinct records. Bucket B (in-import-dup) reflects Argus emitting
the same `argus_record_id` 2-3× with content drift across
primary_registry vs crowdsourced sources. An upstream-side
canonicalization in Argus would eliminate both buckets at source.
See [docs/ARGUS_DEDUP_SHAPES.md](docs/ARGUS_DEDUP_SHAPES.md) for
the inventory and the upstream-tracking pointer.

### Argus data quality observations relayed upstream
The 2026-05-17 Argus export contains a `'Flock-*'` row typed as
`ssid_exact` (almost certainly should be `ssid_pattern`) and duplicate
`'Flock'` + `'Flock-230503'` rows differing only in `device_category`.
The importer warns on wildcards and lets dedup collapse the duplicates,
but the upstream curation is what would fix this cleanly. Forward via
the Argus issue tracker when convenient; the next Argus refresh after
the fix will pick it up naturally and the lynceus-side warning counter
should drop to zero.

### BLE 16-bit short UUID expansion
Extend `normalize_uuid` to accept 16-bit shorts and expand to full 128-bit
form via the standard base UUID (`0000XXXX-0000-1000-8000-00805F9B34FB`).
- **Trigger**: when we observe a real-world miss caused by Kismet emitting
  only the short form for a tracker we care about.
- **Estimated**: 1 prompt, ~50 LOC + tests.
- **Notes**: currently parser drops shorts at DEBUG level. If we observe
  meaningful misses, lift this to a real feature.

### Web UI editing for rules and allowlist
Currently read-only views exist; YAML editing is the only path to change them.
- **Trigger**: when YAML editing becomes annoying enough to justify the
  validation/rollback/audit complexity.
- **Estimated**: 3-4 prompts, includes form validation, optimistic-locking
  via a content hash, undo via the existing audit-trail pattern.

### Stalking heuristics (multi-location detection)
Requires real captured baseline data to design well. Deferred indefinitely;
revisit when a real-world capture corpus is large enough to characterise
"normal" in the deployment environment.
- **Trigger**: enough real-world data to know what "normal" looks like in
  your environment.

### Watchful snooze: possible Phase 3 enhancements
Phase 1 (backend foundation), Phase 2a (operator-action backend), and
Phase 2b (operator-facing UI) all shipped in rc6 -- the feature is
complete and usable. Future work would be reactive to operator
experience rather than planned now. Candidates a few weeks of real
usage might surface:
- ntfy-pushed weekly digest (current digest is render-on-load on
  `/watchful` per locked decision 7d; if operators ask for a pushed
  summary, the existing helper just needs a notifier wire-up)
- per-entry sighting timeline (current detail page shows aggregate
  counts; a per-sighting log would require schema and is deferred
  unless operators ask for it)
- bulk-action surface (e.g. select-all-archived → bulk dismiss);
  unclear whether watchful's expected steady-state size makes this
  worth the UI complexity
- richer audit predicates on `/watchful` (e.g. "escalated then
  archived without action", the schema already supports this via
  `escalated_at IS NOT NULL AND archived_at IS NOT NULL`)
- **Trigger**: real-world operator feedback after a few weeks of
  usage; not worth pre-designing.

### Allowlist auto-learn mode
First N hours after install, everything seen goes into a "candidate
allowlist" you review and accept rather than firing alerts on.
- **Trigger**: confirmed false-positive volume in early deployments.

### /alerts column resize (override CSS)
/alerts is the one list table without resizable columns. It was left as a
bare table because its action column relies on it: the 2-row action-control
flex (commit d7ebbef) and the width:auto inline ack/watch buttons (29ce7be)
are documented to depend on nothing clamping the cell. Putting /alerts on the
data_table macro applies table-layout:fixed + table[data-table-id] td
{overflow:hidden}, which would clip the bulk-ack form's interactive controls.
- **Trigger**: when resize on /alerts is wanted enough to justify dedicated
  override CSS.
- **Estimated**: investigation-first arc. Needs override CSS that exempts the
  action column from the fixed-layout overflow clamp without regressing
  d7ebbef or 29ce7be; resize-only opt-in (the per-feature macro flags from
  4ab16a8 already allow resize without hide/sort). Rig render-check required.
- **Notes**: the bulk-ack <form> wrapper + select-checkbox column + nested
  per-row forms make this the most structurally involved table to convert.

### Filter-aware /alerts ack/watch row swap
/alerts ack/unack/watch currently always keep the row and re-render it in the
new state (htmx, d886a18). This is correct on the default "all alerts" view,
but on a filtered view (e.g. unacked-only) an acked row no longer matches the
active filter and should be REMOVED, like the home page does. Instead it
persists until reload.
- **Trigger**: when filtered /alerts views are used enough that stale-after-
  action rows are a real annoyance.
- **Estimated**: medium. The htmx route handler must know the active filter,
  decide remove-vs-rerender per action (empty-body removal vs _alert_row.html
  partial), and the row forms must convey enough filter context. Regression
  tests on both no-JS (303) and htmx paths, across filtered + unfiltered.
- **Notes**: do NOT bundle with the Pico-specificity styling arc. That table
  is already fragile; adding filter-aware swap logic on top risks tangled
  debugging. Sequence after styling is stable.

## Co-observation red team, 2026-08-06 — unfixed items

Findings from adversarially attacking the co-observation explorer. The four confirmed defects were
fixed in PR #16, and `shared_probe_ssids`'s corpus-linear cost — the one item listed here that was a
defect rather than a judgement — was fixed straight after and is no longer on this list. What
remains is hardening and one product question. Full register with every measurement is in those PRs.

### ~~No `Cache-Control` on the co-observation 404~~ — ✅ FIXED 2026-08-14 (#34)
`_absent()` now sends `Cache-Control: no-store`. It is the shared response for **both** "capability
off" and "no such device", so it is a statement about which MACs the operator has seen — the exact
fact the shared response exists to withhold. The previous protection was incidental (the CSRF
`Set-Cookie`) and would have vanished silently the day those cookies moved or became conditional.

### ~~The audit line is written before the query it describes~~ — ✅ FIXED 2026-08-14 (#34)
⭐ **The fix was NOT "move the line after the query"** — that re-introduces red-team finding 1 (fixed
in #16), where a failed query leaves no trace at all and an attacker who can provoke failures erases
themselves from the one control Decision 6 kept after rejecting rate limiting. The attempt is now
logged *as* an attempt and the outcome recorded separately; the exception is re-raised unchanged, so
a broken feature is not hidden from the operator by a handler meant to fix a log.

### Coverage thresholds are still uncalibrated
`_CO_COVERAGE_MIN_RUNS = 20` and `_CO_COVERAGE_SHARE = 0.25` were reasoned, then validated only
against seeded data. The 2026-08-06 wave fixed the *cliff* those constants created but deliberately
did not tune the numbers themselves. Kev's field capture could settle them.

### "No ranking of suspicion" vs what the layout communicates
The panel promises counts only, no ranking. Verified facts: the default sort is
`shared_anchor_runs DESC` and `LIMIT` is applied **after** it, so position controls not just
prominence but **inclusion** ("Showing 25 of N"); the set-aside groups are a classification; shared
SSIDs are ordered rarest-first; the demoted group has no drill-down affordance. Whether that
amounts to a suspicion ranking expressed through layout is a **product judgement**, not a code
defect — recorded so it is argued once, deliberately, rather than rediscovered.

## Production-readiness pass, 2026-08-13 — unfixed items

Findings from the shippable/shareable audit at `d66d844`. The defects that were fixed are recorded
in `docs/AUDIT_REGISTER.md` (Wave 5, Findings 12–17) with their measurements. What follows is what
was found and deliberately **not** taken on in that remediation.

### Web UI has no authentication — 23 unauthenticated state-changing routes
Measured: nothing in `src/lynceus/webui/` implements auth of any kind; loopback binding is the only
control, and `ui_allow_remote: true` (`config.py:178,368`) removes it. There are 23 `@app.post`
routes, including `/devices/{mac}/allowlist`, `/rules/{rule_type}/snooze` and
`/alerts/{id}/ack`. CSRF does not help against a direct LAN attacker, who simply reads the token.

Concrete attack: someone on the same network allowlists **their own** tracker; the operator is never
alerted and the UI shows nothing wrong. They can also read `/probes`, which is the probe-SSID history
of every device in range — the most sensitive data the system holds, and about bystanders rather than
the operator.

⭐ Partially self-limiting today, **by a bug rather than by design**: `ui_allow_remote` unconditionally
sets a `Secure` CSRF cookie (`webui/app.py:1453`) while the bundled Uvicorn serves plain HTTP
(`webui/server.py:55-63`), so a browser will not return the cookie and state-changing forms 403.
That impairs the operator without impeding a non-browser attacker, who forges the header. Fixing the
cookie bug **without** adding auth would make this strictly worse.

- **Trigger**: any deployment story beyond "loopback, single operator" — a shared house, a second
  device, or the first user who asks for remote access.
- **Interim, and what the docs should say now**: SSH port-forwarding is the supported remote path;
  `ui_allow_remote` should warn loudly at startup rather than reading as a normal toggle.
- **Estimated**: real work. Session auth + a login surface + rate limiting, or delegate it to a
  reverse proxy and document that as the only supported remote mode.

### Silent pipeline death — the daemon stays alive with ingest stopped
A persistent DB lock, disk-full, or a changed Kismet devices-schema is caught per-tick by
`run_forever` and logged, while the runtime-loss state machine deliberately stays quiet because
Kismet's health endpoint is still reachable (`poller.py:1257+`). Process alive, Kismet alive,
ingest and alerting stopped, operator untold. `test_poller_runtime_kismet_loss.py` correctly
prevents a *false* "Kismet down" for DB failures, but nothing requires a truthful
"storage/pipeline degraded" notification in its place.
- ~~**Trigger**: take with the heartbeat work.~~ ✅ **TAKEN 2026-08-14 (#31).** The heartbeat
  reports this case explicitly rather than staying quiet: a watermark held at
  `POLL_WATERMARK_MAX_HOLDS` renders as "observations are failing to persist (capture data is being
  lost)", and the heartbeat is sent at raised priority instead of the low-priority path. ⛔ It never
  claims health it has not verified — forcing `healthy = True` fails five tests.

### Test gaps worth pinning (analysis only — no tests written)
Ranked by consequence. The suite is ~3,260 tests and genuinely strong on rules, UI, import and
evidence; these are gaps *between* well-tested units, on failure paths.

- ~~**Watermark advances past a failed record.**~~ ✅ **FIXED 2026-08-14** — and it was a live
  defect, not just a coverage gap: the device was measured permanently lost, because the watermark
  is set to the tick time while `last_seen` is older. Bounded hold (`POLL_WATERMARK_MAX_HOLDS`),
  which retries transient failures without reintroducing the poison-record livelock the
  unconditional advance was defending against. See audit register Finding 19.
- ~~**BLE flush → alert handoff.**~~ ✅ **COVERED 2026-08-14** — measured: with the handoff broken,
  45 existing BLE tests still passed and the new suite caught it. See Finding 20.
- ~~**Migration replay atomicity.**~~ ✅ **PINNED 2026-08-14 (#29).** ⚠️ And the finding it
  produced had a **real state under a false cause**: a crash cannot reach the lossy replay, because
  `commit()` is inside the per-migration loop (`db.py:479`), so a crash at N leaves N+1..HEAD unrun
  and the column-adding migration has not run yet. The state (*schema ahead of stamp*) is real but
  reachable only via `rollback_to`'s skip-but-unstamp branches. #37 closes the accidental one.
- ~~**The real Kismet HTTP client.**~~ ✅ **PINNED 2026-08-14 (#29).**
- **`cli/bootstrap_kismet.py` (now 1,607 lines) — PARTIALLY covered.** ✅ File modes (#25) and
  ✅ the named case above, `--interface` pointing at a device that is not present, which now warns
  rather than silently configuring a source Kismet cannot open (#36). ⚠️ **Still unpinned:** distro
  detection, source-line generation, backup/atomic patching and dry-run.
- ~~**Clock jumps.**~~ ✅ **FIXED 2026-08-14 (#35)** for the retention half, and it was a live
  defect: measured **29 of 30** in-window sightings deleted on a +30d excursion, with `evidence.py`
  worse because it is on by default. ⛔ **Not fixable inside `retention.py`** — from there, "the
  clock jumped forward" and "the table holds only old rows" are the same observation, and an
  existing test *requires* the second to delete everything. Fixed with a `time.monotonic()` anchor
  in `Poller`, which declines to call the prunes at all while the clock is untrusted, with a bounded
  hold. ⚠️ **Still open:** the `last_poll_ts` cursor half — a forward excursion still makes later
  polls ask Kismet for devices "since the future".

### ~~Heartbeat / dead-man's switch~~ — ✅ SHIPPED 2026-08-14 (#31)
Built on migration 024's delivery-tracked path, as the sequencing below required. `heartbeat_enabled`
(default **false**) and `heartbeat_interval_hours` (default 24); migration 025 adds a `heartbeats`
table mirroring the alert delivery columns, and `/settings` reports whether the switch is armed and
when it last arrived.

⛔ **The invariant it rests on: it never claims health it has not verified.** A cheerful "still
watching" sent while ingest is dead is *worse* than no heartbeat — it converts unease into false
confidence on the one channel the operator trusts. It names a wedged poll loop, failing persists and
undelivered alerts, and raises priority when unhealthy. 🪤 A quiet RF environment is deliberately
**not** unhealthy.

⚠️ **Open, and Kev's call: nothing prompts for it.** It is off by default and the setup wizard does
not offer it, so a safety feature ships unused. Adding a prompt is a UX decision with 200+ wizard
tests behind it.

The original rationale, kept because the sequencing argument is what made it correct:

The one genuinely new feature worth building, deferred until the delivery path is trustworthy
(audit register Finding 12). Every other failure mode now alerts — Kismet loss alerts and recovers,
systemd restarts on failure, the allowlist fails safe. But if the daemon dies, the host loses power,
the SD card wears out, or ntfy delivery itself breaks, the operator's phone simply goes quiet — **and
quiet is indistinguishable from "you are safe"**, which is the worst possible failure for this
product.

A configurable low-priority "still watching, N devices seen, last alert Xh ago" push makes silence
falsifiable, and continuously exercises the delivery path so a broken topic or auth token surfaces
within a day instead of at the moment it matters.
- **Trigger**: after Finding 12's delivery fix lands — building it on the current fire-and-forget
  path would inherit the same defect.
- **Estimated**: ~150 LOC + config knob + tests. Cheap; the value is in the sequencing.

## Followups for technical debt

### CSRF token rotation on session boundaries
v0.2 ships a single token per cookie session (8 hours). Rotation on
auth events comes when auth lands.

### Per-request DB connection pool
v0.2 uses a single shared connection with `check_same_thread=False`.
Safe under WAL + single-writer access pattern. If concurrent UI writes
become real (form-driven rule editing), revisit with a small connection pool.

### Migration packaging revisit on more install paths
Currently tested under editable install + wheel install. If we ever build
a Debian/Arch package, validate migration discovery there too.

### `flake8-bugbear extend-immutable-calls` audit
Currently exempts `fastapi.Form`. Confirm coverage extends to `Query`,
`Depends`, `Path`, `Body`, `Header`, `Cookie` if any are added later.

### Reverse-proxy path prefix support
Currently base.html uses literal /static/ paths. If we ever support
deployment behind a reverse proxy at a non-root path, switch to
url_for('static', path=...) and update tests to assert the resolved
path rather than the literal substring.

### Auto-shift-to-now in FakeKismetClient
The dev fixture (tests/fixtures/dev_kismet.json) currently requires
manual rebumping when its timestamps age out (see scripts/rebump_dev_fixture.py
and docs/WINDOWS_DEV.md). The durable fix:

- Add FakeKismetClient(auto_shift_to_now: bool = False,
  auto_shift_anchor_seconds: float | None = None) constructor params.
- When auto_shift_to_now is True, on first get_devices_since call,
  compute the offset = now - max(last_time across fixture) and apply
  that delta to all timestamps before parsing into observations.
- Surface the flag through Config as kismet_fixture_auto_shift: bool.
- Default to False to preserve current FakeKismetClient behavior for
  integration tests that depend on frozen timestamps.

Trigger: next time someone has to manually rebump the fixture, OR when
v0.3 work touches kismet.py for other reasons (rolling both into one
prompt is cheap).
Estimated: 1 prompt, ~50 LOC + ~15 tests, including a regression test
that proves integration test fixtures are NOT shifted (default off).

### Brittle position-sensitive layout tests
Several gitignored layout tests assert CSS rules via naive first-occurrence
string matching (e.g. content.find(".table-scroll") / find(".watchful-
actions")). These have tripped twice when a CSS *comment* contained the
matched selector literal before the real rule, forcing comment rewordings
that don't reflect a real code problem. Harden the matching to target the
actual rule (e.g. match a selector-plus-brace pattern, or parse the rule
block) rather than first textual occurrence.
- **Trigger**: next time one of these tests trips on a comment, OR any arc
  that already touches these test files.
- **Notes**: tests are gitignored (OPSEC), so this is local-only test
  maintenance, no repo commit for the tests themselves.

### README integrity: ble_uuid-dependent claims vs the current capture path
The README advertises "BLE service UUID" matching and "AirTag-class tracker
recognition", both of which ride the `ble_uuid` surface, which does not fire
on the current Kismet classic-HCI capture path (see "BLE advertisement-payload
capture" under Network capture features). The claims describe built, tested
matchers that are inert in the field.
**Still open after the bridge landed.** Building the capture path was the
first of the two ways to make the README accurate, but it does not by itself
make the claims true: the bridge is OFF by default (BLE-G1 curation), so in a
default deployment the claims remain inert. "BLE service UUID matching" becomes
accurate once the bridge is enabled and curated; **"AirTag-class tracker
recognition" needs more than that**. Distinguishing an AirTag from any other
Apple device is exactly the Find My / Apple Continuity decoder arc, which has
not started. Softening that claim should not wait on it.
- **Trigger**: now actionable. The bridge decision resolved in the "build it"
  direction. Re-check the claims once the bridge is enabled + curated, and
  again after the Find My decoder lands.
- **Notes**: deliberately NOT bundled into the docs commit that closed the
  bridge arc. README wording is its own change with its own review. Options
  unchanged: soften to "implemented, pending a capture path", or gate the
  wording on the feature flag.

### G4 operator-seeded collision: argus_record_id durability signal
The v0.9.2 G4 fix preserves operator-seeded watchlist severities on an Argus
collision using `existing_md is None` as the "operator-seeded" proxy. That
proxy also catches an Argus row whose `argus_record_id` was re-keyed upstream
(it too reads metadata-None) and would be preserved as if operator-seeded. A
harmless WARN + declined update rather than the silent clobber it replaced, but
still a misfire.
- **Trigger**: the operator-override flag work, OR observed Argus record_id
  churn that mislabels real Argus rows as operator-seeded.
- **Notes**: the precise signal is `get_metadata_by_watchlist_id is None`;
  deferred to the operator-override flag arc per the G4 commit.

### A2 startup allowlist-failure ntfy: assert the deferred emit
The v0.9.2 A2 fix raises an operator ntfy when the allowlist fails to load at
startup, but the emit is deferred until `build_notifier` runs and is a no-op
when ntfy is unconfigured (the CRITICAL log is then the sole signal). No test
asserts the deferred ntfy actually fires when ntfy IS configured.
- **Trigger**: next arc touching the allowlist loader or startup notifier
  wiring.
- **Notes**: tests are gitignored (OPSEC); local-only diagnostic to add.

### A2 _load_ui_entries fail-open sibling
The A2 fix hardened the load-bearing suppression loader; the UI sibling loader
`_load_ui_entries` keeps its lenient corrupt → WARNING → empty behavior. It is
daemon-managed and not the suppression surface, so this is a lower-severity
asymmetry, explicitly left unfixed in v0.9.2.
- **Trigger**: if the UI read views ever become suppression-relevant, or any
  arc already in `_load_ui_entries`.

### Stale diagnostic: test_diag_home_ack_flow content assertions
`test_diag_home_ack_flow` asserts page content (hx attributes) that has since
moved into the `_alert_row.html` partial, so it fails pre-existingly under
`pytest -m diagnostic`. Not a regression. The assertions are stale against the
current template split.
- **Trigger**: next time the diagnostic suite is run pre-push, or any arc
  touching the home-page ack flow / alert-row partial.
- **Notes**: tests are gitignored (OPSEC); local-only test maintenance.

## Network capture features

### Per-band filtering (2.4/5/6 GHz)
Currently filtering is per-source (adapter), not per-band. If the same
adapter captures multiple bands and we want to alert differently per band,
we'd need to extract Kismet's frequency field per observation.
Trigger: when one-source-per-band setup proves insufficient.

### Retry policy on Kismet API failures
Currently a single failed poll is silently logged and the next poll
proceeds. If transient failures become noisy, add exponential backoff
with a circuit breaker.

### ~~Kismet-died notification~~ — ✅ SHIPPED in 0.9.1, entry was stale
Verified 2026-08-13: `poller.py:1257-1310` implements exactly this. A runtime
loss alerts once after `RUNTIME_KISMET_LOSS_THRESHOLD = 3` consecutive failed
ticks (~3 min at the default interval), re-probes `health_check()` to avoid
paging on a transient blip, and sends a **recovery** notification when Kismet
comes back. `priority_override=4` keeps it below the 5 reserved for
watchlist hits. Original text kept below for provenance:

> Lynceus can detect Kismet unreachability (via health_check) but doesn't
> currently alert via ntfy when this happens. Add a "lynceus infrastructure
> alert" tier that fires on kismet-down, db-locked, etc.

⚠️ The "db-locked, etc." half is **not** done — see "Silent pipeline death"
under the 2026-08-13 items below.

### Per-channel filtering
Same logic as per-band. Wait until the simpler primitives prove
insufficient.

### BLE advertisement-payload capture (passive bleak bridge)
The `ble_uuid`, `ble_manufacturer_id`, and drone Remote-ID matchers did not fire
on the Kismet capture path: Kismet's classic-HCI Bluetooth datasource surfaces
no advertisement payload, so service UUIDs, 16-bit company ids, and Remote-ID
serials never reached the matcher. Rig-confirmed 2026-06-17 that a BlueZ/bleak
passive scan on the *same* adapter DOES surface company ids and service UUIDs.
The data exists; Kismet's classic path just doesn't expose it.

**Status: the capture bridge landed (unreleased)**. `lynceus.bridges.ble`
plus daemon wiring, flag-gated on `ble_bridge.enabled` and OFF by default;
hardware-validated end to end from inside the daemon. See the CHANGELOG
`[Unreleased]` entry for the landing summary.

**What is NOT done is the half this entry always said was the harder half:
the matching strategy.** Company-id alone is too coarse, one id covers a
whole vendor, so the bridge is built but must not be enabled against a raw
company-id watchlist. The remaining work is split into the numbered
enablement gates below (BLE-G1 … BLE-G8); BLE-G1 and BLE-G2 are blocking.
The payload-format-signature work that makes company ids useful is tracked
separately as the Find My / Apple Continuity decoder arc.
- **Trigger**: gates BLE-G1 and BLE-G2 cleared, then flip `ble_bridge.enabled`.
- **Notes**: passive-only, consistent with the project stance. Observe and
  match, never connect/pair/probe; the shipped scanner is passive-mode with no
  connect path. Pairs with the README-integrity follow-up (the README already
  claims BLE-UUID / AirTag-class recognition that rides this surface) and the
  D2 drone field-path confirmation below. D2 is unaffected by this landing and
  still needs a live drone capture.

### BLE-G1: watchlist curation before enabling the bridge (BLOCKING)
A watchlist matching raw `ble_manufacturer_id` values is an alert storm, not a
detection: company id `004c` is *every* Apple device in range, `0075` every
Samsung, and so on. Enabling the bridge against an uncurated company-id
watchlist would alert on every passer-by's phone and earbuds. The curation
decision, which company ids (or which id + payload-shape pairs) are a
surveillance signal rather than consumer noise, is Argus-side data work, not
lynceus-side code.
**Substantially reduced for Apple by the Continuity decoder (unreleased).**
`lynceus.ble_continuity` now resolves `004c` to `find_my_separated` /
`find_my` / `find_my_paired` / `airpods` / `nearby` / `apple_unknown`, and
the `ble_device_class` rule type alerts on named classes, so the Apple case
is a classification problem rather than a vendor blocklist, and the
alert-storm risk for Apple is gone. The separated-from-owner refinement that
makes this precise is no longer pending: it is length-based and rig-validated
as of 2026-08-01, so `find_my_separated` is the class an operator actually
wants and `find_my_paired` is the noise to leave out. What remains for this
gate: every NON-Apple company id is still uncurated and would storm the same
way.
- **Trigger**: blocking. Must be resolved before `ble_bridge.enabled` is ever
  set in a real deployment.
- **Notes**: in the shipped `config/rules.yaml` template both
  `argus_ble_manufacturer_id` and the new `apple_find_my` rule are commented
  out, so the repo default is safe. **Verify the deployed rig config
  separately**. If `argus_ble_manufacturer_id` is uncommented there,
  enabling the bridge storms immediately with no further warning, and the
  decoder does not help because that rule matches company id, not class.

### BLE-G2: kismet_sources source-gate vs bridge provenance (BLOCKING)
Latent silent failure. The bridge stamps its observations with
`seen_by_sources=(f"ble:{adapter}",)`. E.g. `ble:hci1`. The poller's step-1
source gate admits an observation only when one of its `seen_by_sources` is a
member of the `kismet_sources` allowlist. If an operator's `kismet_sources`
lists the bare adapter name (`hci1`), the membership test against `ble:hci1`
fails and **every** bridge observation is dropped. The bridge would run,
scan, and buffer correctly while contributing nothing, with only DEBUG-level
drop logging to show for it. The alias-map expansion does not rescue this:
aliases come from Kismet's own `list_sources()`, which has no knowledge of the
bridge's synthetic source name.
- **Trigger**: blocking. Verify before enabling, not after.
- **Estimated**: read-only verification first. Inspect the deployed
  `kismet_sources` and decide the contract. If a change is needed the options
  are to document `ble:<adapter>` as the value operators must allowlist, or to
  exempt bridge-stamped provenance from the gate; the latter is a real code
  change with its own tests, so confirm the failure is actually present first.
- **Notes**: an operator whose `kismet_sources` is unset has no gate at all
  (`None` means no filter) and is unaffected.

### BLE-G3: startup health check blocks the bridge when Kismet is down
`Poller.__init__` runs `_startup_health_check()` when
`kismet_health_check_on_startup` is set, and that raises before `run_forever`
is ever reached, so with Kismet down the daemon never starts, and the BLE
bridge never starts either. The bridge is adapter-independent and does not need
Kismet to do useful work, so coupling its availability to Kismet's is arguably
wrong once the bridge is a real capture path rather than an experiment.
- **Trigger**: after the bridge is enabled, if a Kismet outage is observed to
  take BLE capture down with it.
- **Estimated**: small, but it is a policy decision before it is code. Should
  `ble_bridge.enabled` relax or bypass the Kismet startup health check, and
  does a Kismet-less daemon still deserve the startup banner and health
  semantics it currently gets? Decide the semantics, then implement + test.
- **Notes**: do NOT make this change speculatively. Today the coupling is
  harmless because the bridge is off by default.

### BLE-G4: bleak 3.x `adapter=` / BlueZScannerArgs deprecation
`bridges/ble.py::_make_scanner` passes `adapter=self.adapter` alongside
`bluez=BlueZScannerArgs(or_patterns=...)`. bleak is folding adapter selection
into the backend-args kwarg and will drop the standalone `adapter=` parameter,
at which point the scanner construction breaks on upgrade.
- **Trigger**: before any bleak major-version bump, or on the first deprecation
  warning observed on the rig.
- **Estimated**: a few lines. Fold the adapter into the `bluez=` kwarg. The
  module already carries an import-layout fallback for older/newer bleak module
  paths, so the compatibility pattern to follow is in place.
- **Notes**: the scan path is rig-only (`# pragma: no cover`), so this cannot
  be caught by the dev-box suite. It will surface as a runtime failure on the
  rig, not a test failure.

### BLE-G5: rig provenance, /opt/lynceus is not a git clone
The deployed tree at `/opt/lynceus` was installed from an unzipped `~/Downloads`
tree rather than a git clone, and no clone containing the bridge commits
(`07c561a`, `bb3d51c`, `ecfbf89`) exists on the rig. There is therefore no way
to confirm from the rig which revision is actually running, and no clean path to
deploy the bridge or roll it back.
- **Trigger**: before deploying the bridge to the rig.
- **Notes**: deployment hygiene, not a code defect, but it blocks trustworthy
  enablement, since "is the running code the code we reviewed?" is currently
  unanswerable. Land a real clone first.

### BLE-G6: adapter contention, Kismet claims the adapter the bridge needs
Confirmed on the rig 2026-08-01. `/etc/kismet/kismet_site.conf` declares both
Bluetooth adapters as Kismet sources (`hci0` and `hci1`), and
`BleBridgeConfig.adapter` defaults to `hci1`. Kismet holds the adapter for the
lifetime of the daemon, so with Kismet running there is no free BT adapter and
the bridge cannot scan. The 2026-08-01 capture only succeeded because Kismet
was stopped for it, which is not a state the daemon can ship in.
- **Trigger**: blocking, before enabling the bridge on the rig. Same gate class
  as BLE-G1/BLE-G2.
- **Estimated**: config only, no code. Drop the `source=hci1` line from
  `kismet_site.conf` so Kismet keeps `hci0`, and make the matching edit to
  `kismet_sources` in `/etc/lynceus/lynceus.yaml`, which currently lists both.
- **Notes**: adapter identity is easy to invert and worth stating once.
  `hci1` is the Intel, `28:C5:D2:0A:6D:D2`, HCI 5.3; `hci0` is the Realtek,
  `3C:78:95:9B:8A:EA`, HCI 5.1. Also on that rig config, and harmless but
  worth tidying in the same pass: `kismet_sources` lists the Wi-Fi adapter
  twice, and the file carries no `ble_bridge` key at all, so the
  `BleBridgeConfig` defaults govern (`enabled: False`). Note too that
  `~/.config/lynceus/lynceus.yaml` has diverged from the daemon's `/etc` copy
 . The unit runs `User=lynceus` with `ProtectHome=true` and cannot read
  `/home` at all, so the home copy is dev-only and must not be used to reason
  about production behaviour.

### BLE-G7: bleak absent from the interpreter
`bleak` is an optional extra (`lynceus[ble]`), so a stock install does not have
it. An enabled bridge in that state logs one warning at daemon start and then
behaves exactly like a working bridge that has heard nothing. The only gate an
operator reaches without misconfiguring anything.
- **Trigger**: covered. `check_bleak_available()` reports it, and
  `collect_bridge_warnings()` puts it first.
- **Notes**: recorded here because the code cites "BLE-G7" and this file had no
  such entry. Verified present and importable on the dev box with bleak 3.0.2,
  including the modern `bleak.args.bluez` path.

### BLE-G8: BlueZ does not publish AdvertisementMonitorManager1
The failure mode that actually bit, and the one no other gate could see.
bleak's passive scan needs `org.bluez.AdvertisementMonitorManager1`, which
BlueZ publishes only when `bluetoothd` runs with experimental features on.
Measured on the Linux dev box with **BlueZ 5.72 and kernel 7.0.0 — both
comfortably above the minimums the bridge's own error text quotes** — with
bleak installed, the adapter free and the config clean: all four other gates
returned green and the bridge captured nothing, looping `BLE scan failed
(passive scanning on Linux requires BlueZ >= 5.56 with --experimental
enabled...)`. Root cause proven by D-Bus introspection, not inferred: the
interface was absent while `Experimental` was commented out in
`/etc/bluetooth/main.conf`.
- **Trigger**: covered in code. `check_bluez_advertisement_monitor(adapter)`
  reports it, and `collect_bridge_warnings()` orders it directly below G7.
  **Still open on the rig**: whether the rig has experimental enabled is
  unverified. Its 2026-08-01 capture succeeding with Kismet stopped suggests
  yes, but that is an inference.
- **Estimated**: done for detection. The remedy is config plus a restart:
  set `Experimental = true` in `/etc/bluetooth/main.conf`, restart
  `bluetooth`, confirm with
  `busctl --system introspect org.bluez /org/bluez/<adapter> | grep
  AdvertisementMonitor`.
- **Notes**: this gate sits **upstream of BLE-G6**. Contention presumes the
  bridge could otherwise open an adapter; without the monitor interface it
  cannot, so check G8 before spending effort on G6. Detection is deliberately
  one-directional and stays silent on every ambiguous outcome (not Linux, no
  `busctl`, bluetoothd down, D-Bus refusal). It also requires positive proof
  the object is a real adapter (`org.bluez.Adapter1` present), because
  `busctl introspect` **exits 0 and prints only its header** for a path that
  does not exist — without that check a typo'd adapter name would draw a
  confident "enable experimental features" remedy.
  Status on the dev box as of 2026-08-02: `Experimental = true` is now set and
  both adapters publish the interface, so this box can finally test whether
  the bridge captures anything.

### Migration 014 replay drops every devices column added after it
`014_devices_remote_id.sql` is a full table rebuild with a hardcoded column
list, so replaying it (the "narrow recovery path" its own test docstring
describes, for a DB whose 014 row is missing but whose table was already
rebuilt), recreates `devices` at the 014-era shape and silently drops every
column added since. That is currently **`ble_device_class` alone**.
⚠️ This entry also named `ble_name` until 2026-08-14. Measured: `ble_name`
**survives** — it predates 014 and appears in 014's own `INSERT` column list.
Only columns added *after* 014 are dropped, which is the whole point of the
defect; naming a survivor beside the casualty made the entry read as a broader
data loss than it is. Verified: 11 columns before the replay, 10 after,
`ble_device_class` the only one missing.
- **Pinned**: `tests/test_db.py::test_migration_014_sql_replay_is_safe_rebuild`
  now asserts the drop in both directions (#54), so fixing this will fail that
  test and bring you to its docstring. Delete that assertion as part of the fix.
Surfaced while adding migration 023, which is the first migration to add a
`devices` column after 014; nothing had exercised the interaction before.
- **Trigger**: before anyone actually uses the 014 replay recovery path, or
  the next time a `devices` column is added.
- **Estimated**: investigation-first. Options include making the rebuild
  column list dynamic (`PRAGMA table_info`), or documenting the replay as
  "re-run migrations to head afterwards" and making the runner do so.
  Editing an already-applied migration in place is NOT an option.
- **Notes**: normal operation is unaffected. Migrations run in order, once,
  and 023 adds the column after 014 has run. This only bites on replay. The
  local `test_migration_014_sql_replay_is_safe_rebuild` was reworked to
  assert the CHECK constraint via a raw INSERT rather than `upsert_device`,
  so it tests the constraint instead of tripping on the dropped column.

### Find My / Apple Continuity payload decoder
**Status: landed (unreleased), and now actually reachable.**
`lynceus.ble_continuity` decodes the Continuity message type and resolves an
Apple advert to `find_my_separated` / `find_my` / `find_my_paired` /
`airpods` / `nearby` / `apple_unknown`; the class is persisted on the device
row (migration 023), shown on `/devices`, and matchable via the
`ble_device_class` rule type. Payload bytes are read in the bleak callback
and discarded there. Only the derived label survives, pinned by a
regression test. See the CHANGELOG `[Unreleased]` entries.

**Both gates this entry was waiting on are closed by the 2026-08-01 rig
capture** (~490 Apple TLVs, 3 message types, 0 structure failures):
- The bridge's BlueZ monitor was Flags-only and matched no Apple advert at
  all, so the decoder was unreachable in the field regardless of its
  correctness. Fixed. The Apple manufacturer-data pattern now leads the set.
- Separated state no longer rides a status bit. `_FIND_MY_SEPARATED_MASK`
  is deleted: `0x04` was never set across 204 Find My frames, so it reported
  "not separated" universally. Separation is read from advert length instead,
  three-valued, with unknown kept distinct from near-owner.

**What is still open is the part hardware cannot settle.** Passive
re-identification of a given tracker across time is cryptographically
foreclosed: the BLE address rotates and the Find My key rotates roughly
every 15 minutes, by design, specifically to defeat observers outside the
trust system. Apple's own stalking alerts work because an iPhone holds owner
keys and can query Apple's servers; no third-party passive listener can
replicate that on any adapter. An AirTag and an AirPods case also emit
identically-shaped `0x12` adverts, so they cannot be told apart.
- **Honest capability ceiling**: "an unfamiliar separated Find My emitter is
  in range, correlated within one rotation window", not "this specific
  AirTag is following you". Do not build heuristics that imply the latter,
  and do not describe the feature that way in the README.
- **Next arc**: follow-detection, a tracker that persists across locations
  versus an incidental one, bounded by that rotation window. Still wants the
  real-world capture corpus the stalking-heuristics entry describes.
- **Optional, low value**: a clean separated/paired ground-truth experiment
  (AirPods in a closed case, iPhone Bluetooth off via Settings rather than
  Control Centre, undisturbed 30 minutes). Two attempts on 2026-08-01 failed
 . The AirPods slept, and the phone's Bluetooth re-enabled itself 12 minutes
  in. The length-based rule does not depend on it; this would only raise
  confidence.

### D2 drone Remote-ID live field-path confirmation
The `drone_id_prefix` leading-substring matcher (v0.9.2) is correct but inert:
the live Kismet Remote-ID JSON field path (`kismet._DRONE_ID_PATHS`) is still an
unverified guess. No drone has been captured, so which path carries the serial
is unknown. `_DRONE_ID_PATHS` is unchanged until a live capture proves it.
- **Trigger**: a live drone Remote-ID capture on the rig, or a confirmed Kismet
  field-path reference.
- **Notes**: blocks nothing else. The matcher, capture coercion, and allowlist
  mirror are all in place and tested; this is the one runtime fact that can only
  come from real hardware. Likely confirmed alongside the BLE advertisement-
  payload bridge above.
