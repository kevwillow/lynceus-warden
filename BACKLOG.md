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

### BLE 16-bit short UUID expansion, SHIPPED
Was: extend `normalize_uuid` to accept 16-bit shorts and expand to the full
128-bit form via the standard base UUID (`0000XXXX-0000-1000-8000-00805F9B34FB`),
triggered when we observe a real-world miss.

The trigger fired and the work landed. The miss was total and silent: the
observation side required the dashed 128-bit form while the watchlist side
already expanded shorts, so an operator who watchlisted `fd5a` stored
`0000fd5a-0000-1000-8000-00805f9b34fb` and every advertisement of that device
arrived as `fd5a`, was rejected, and was dropped with a DEBUG line. The entry
could never fire. Both sides now call one function, measured on `main`:

    patterns.normalize_pattern('ble_uuid', 'fd5a') -> 0000fd5a-0000-1000-8000-00805f9b34fb
    kismet.normalize_uuid('fd5a')                  -> 0000fd5a-0000-1000-8000-00805f9b34fb

⚠️ Kept here rather than deleted because the old "parser drops shorts at DEBUG
level" note sat in this file long enough to be quoted as current, and was still
being repeated in `docs/PROJECT_STATUS.md` (in the shipped-limitations list AND
the deferred list) until 2026-08-24. An entry that describes a defect the
project has since removed is worse than no entry.

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

## Co-observation red team, 2026-08-06: unfixed items

Findings from adversarially attacking the co-observation explorer. The four confirmed defects were
fixed in PR #16, and `shared_probe_ssids`'s corpus-linear cost was fixed straight after and is no
longer on this list. That was the one item listed here that was a defect rather than a judgement.
What remains is hardening and one product question. Full register with every measurement is in
those PRs.

### ~~No `Cache-Control` on the co-observation 404~~ ✅ FIXED 2026-08-14 (#34)
`_absent()` now sends `Cache-Control: no-store`. It is the shared response for **both** "capability
off" and "no such device", so it is a statement about which MACs the operator has seen. That is the
exact fact the shared response exists to withhold. The previous protection was incidental (the CSRF
`Set-Cookie`) and would have vanished silently the day those cookies moved or became conditional.

### ~~The audit line is written before the query it describes~~ ✅ FIXED 2026-08-14 (#34)
⭐ **The fix was NOT "move the line after the query".** That re-introduces red-team finding 1 (fixed
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
defect. It is recorded so it is argued once, deliberately, rather than rediscovered.

## Production-readiness pass, 2026-08-13: unfixed items

Findings from the shippable/shareable audit at `d66d844`. The defects that were fixed are recorded
in `docs/AUDIT_REGISTER.md` (Wave 5, Findings 12–17) with their measurements. What follows is what
was found and deliberately **not** taken on in that remediation.

### ✅ RESOLVED 2026-08-25 (#234) — Web UI has no authentication: 23 unauthenticated state-changing routes
Measured: nothing in `src/lynceus/webui/` implements auth of any kind; loopback binding is the only
control, and `ui_allow_remote: true` (`config.py:178,368`) removes it. There are 23 `@app.post`
routes, including `/devices/{mac}/allowlist`, `/rules/{rule_type}/snooze` and
`/alerts/{id}/ack`. CSRF does not help against a direct LAN attacker, who simply reads the token.

Concrete attack: someone on the same network allowlists **their own** tracker; the operator is never
alerted and the UI shows nothing wrong. They can also read `/probes`, which is the probe-SSID history
of every device in range. That is the most sensitive data the system holds, and it is about
bystanders rather than the operator.

⭐ **CORRECTED 2026-08-21. The self-limiting half of this entry is gone, deliberately.** This said
the exposure was "partially self-limiting, by a bug rather than by design": `ui_allow_remote`
attached `Secure` to the CSRF cookie while the bundled Uvicorn serves plain HTTP, so a browser
never returned the cookie and every state-changing form answered 403. That bug is fixed, because
it made the one documented remote path unusable.

⛔ **It was never a control.** It stopped browsers, which means it stopped the operator. A caller
using curl sets both halves of the double-submit itself and was never impeded for a moment, and
`SameSite=Strict` already handled the browser-driven case. What it actually bought was that remote
deployments stayed broken enough that nobody left one running, which is an accident, not a defence.

⇒ What replaces it is honesty rather than a brake: `webui/server.py` now prints an unmissable
startup banner whenever the bind is off-loopback, naming that there is no authentication and that
`/probes` is bystander history. It goes to **stderr, not the logger**, so `log_level: ERROR`
cannot silence it, and it is keyed on the **bind host** rather than on `ui_allow_remote`, so
permitting remote access while staying on loopback stays quiet.

- **Trigger**: any deployment story beyond "loopback, single operator". A shared house, a second
  device, or the first user who asks for remote access.
- **Interim, and what the docs say now**: SSH port-forwarding or a private network such as
  Tailscale is the supported remote path. ✅ The loud startup warning is built.
- **Estimated**: real work. Session auth + a login surface + rate limiting, or delegate it to a
  reverse proxy and document that as the only supported remote mode.

### ✅ RESOLVED 2026-08-25 — single-operator password + session shipped

Kev chose the second of the three shapes above. `webui/auth.py` implements it: scrypt password
hashing, server-side sessions (8h idle / 7d absolute), per-client login rate limiting with a
lockout, and an **ASGI middleware** rather than per-route `Depends()` — 42 routes is a list a new
route falls off, and this repo has shipped that failure twice already. `lynceus-ui-passwd` writes
the hash to `ui_auth.json` in the state directory at `0600`.

⭐ **What actually closes the exposure is the refusal, not the password.** A password nobody sets
is a feature shipped switched off. `webui/server.remote_bind_refusal` makes `lynceus-ui` **exit 2
rather than start** on a non-loopback bind with no credential, printing the command that fixes it.
On loopback it stays opt-in, because there the bind is the control and forcing a password on every
existing single-operator install would be an upgrade that locks people out of their own dashboard.

⚠️ **Two things this deliberately does NOT do**, recorded so they are not mistaken for oversights:

1. **No TLS.** A password authenticates the operator; it does nothing about the wire. Off-loopback
   over plain HTTP the password and its session cookie are readable and replayable in transit —
   *worse* than the old exposure in one respect, because a credential outlives a snapshot. The
   startup banner now says exactly this, and the supported remote path is unchanged: tunnel it.
2. **No accounts, roles or per-user audit.** One operator, one password. If that stops being true,
   `webui/auth.py` is the wrong shape and should be replaced rather than extended.

Residual, and the honest limit: the rate limiter keys on the peer socket address, so behind a
reverse proxy every caller shares one bucket and one attacker can lock the operator out. Not a
supported deployment — both documented remote paths preserve the peer — and trusting an
`X-Forwarded-For` any unauthenticated caller can write would be worse. Stated in `auth.py`.

### Web UI auth red-team, 2026-08-25: findings deliberately NOT taken

A cold `gpt-5.6-sol` read of the auth surface at `f4e4f3b` returned 8 findings.
Four were real and fixed in #234 (the credentials double-read fail-open, the
last-one-wins CSRF cookie parser, the symlink-following credentials write, and a
`purge_expired` docstring that claimed a bound it does not provide). The rest are
recorded here so they are argued once rather than rediscovered by the next reader.

- **Unbounded request body on `/login`.** `csrf._read_body` accumulates every
  chunk into a list with no size limit, and `/login` is auth-exempt, so any caller
  who can reach the port can drive a Pi into memory pressure without a password,
  a session, or even a valid CSRF pair. ⚠️ **Pre-existing, not introduced by the
  auth work** — `_read_body` is untouched by #234 and the whole UI was
  unauthenticated before it. Genuinely worth fixing.
  - **Trigger**: any off-loopback deployment, or the first time the UI is put
    behind something that does not itself cap request bodies.
  - **Estimated**: small. A byte ceiling in `_read_body` plus a 413.

- **The login lockout is bypassed by rotating the source address.** The limiter
  keys on the peer address, so an attacker with a `/64` (or simply several hosts)
  sends four wrong passwords from each and never fills a bucket. ⭐ This is the
  MIRROR IMAGE of the residual recorded directly above, and both follow from the
  same key: a peer-keyed limiter over-groups behind a proxy and under-groups
  across a prefix. scrypt and the minimum length still bound useful guessing.
  - **Estimated**: a global failure budget alongside the per-client one, or
    per-prefix bucketing for v6. Both add a way to lock out the real operator, so
    this is a design conversation, not a patch.

- **Group/world-writable credentials are reported, never refused.** ⛔ **Not a
  defect — a deliberate decision**, stated in `server.py`: "refusing to start on a
  file they chmod'd themselves turns advice into an outage." The red team's added
  angle is fair and was not in the original reasoning: an over-broad mode is an
  **integrity** problem, not only a disclosure one, because a local principal who
  can write the file can substitute a hash they know and simply log in. POSIX ACLs
  are not examined at all. Recorded as a decision to revisit, not a bug.

- **`purge_expired` does not bound concurrent live sessions.** The misleading
  docstring was corrected in #234; the behaviour was not. Nothing removes a
  session inside both its idle and absolute windows, so a caller who knows the
  password can hold open arbitrarily many. Marginal — it requires the password —
  and a hard cap risks locking out an operator with several devices.
  - **Trigger**: if sessions ever stop being one-operator.

### ✅ RESOLVED 2026-08-14 (#31) — Silent pipeline death: the daemon stays alive with ingest stopped
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
  claims health it has not verified. Forcing `healthy = True` fails five tests.

### Test gaps worth pinning (analysis only, no tests written)
Ranked by consequence. The suite is **5,116 tests as measured 2026-08-25** (this line read
"~3,260" until then) and genuinely strong on rules, UI, import and
evidence; these are gaps *between* well-tested units, on failure paths.

- ~~**Watermark advances past a failed record.**~~ ✅ **FIXED 2026-08-14**, and it was a live
  defect rather than just a coverage gap: the device was measured permanently lost, because the
  watermark is set to the tick time while `last_seen` is older. Bounded hold
  (`POLL_WATERMARK_MAX_HOLDS`), which retries transient failures without reintroducing the
  poison-record livelock the unconditional advance was defending against. See audit register
  Finding 19.
- ~~**BLE flush → alert handoff.**~~ ✅ **COVERED 2026-08-14.** Measured: with the handoff broken,
  45 existing BLE tests still passed and the new suite caught it. See Finding 20.
- ~~**Migration replay atomicity.**~~ ✅ **PINNED 2026-08-14 (#29).** ⚠️ And the finding it
  produced had a **real state under a false cause**: a crash cannot reach the lossy replay, because
  `commit()` is inside the per-migration loop (`db.py:479`), so a crash at N leaves N+1..HEAD unrun
  and the column-adding migration has not run yet. The state (*schema ahead of stamp*) is real but
  reachable only via `rollback_to`'s skip-but-unstamp branches. #37 closes the accidental one.
- ~~**The real Kismet HTTP client.**~~ ✅ **PINNED 2026-08-14 (#29).**
- **`cli/bootstrap_kismet.py` (now 1,759 lines), PARTIALLY covered.** ✅ File modes (#25) and
  ✅ the named case above, `--interface` pointing at a device that is not present, which now warns
  rather than silently configuring a source Kismet cannot open (#36).
  ⚠️ ~~**Still unpinned:** distro detection, source-line generation, backup/atomic patching and
  dry-run.~~ ✅ **STALE — measured 2026-08-25 and all four were already covered** by
  `tests/test_bootstrap_kismet_behaviour.py`, which this entry predates. Believing it cost a
  session the start of a packet it did not need.
  ⇒ **Coverage is a number, so measure it rather than reasoning from this list.** Measured at
  `f9e7e3c`: **47%**, 340 of 643 statements missed. The genuinely-uncovered probe surfaces
  (`parse_iw_dev`, `parse_iw_phy_info_supports_monitor`, `filter_kismet_monitor_vifs`,
  `detect_bluetooth_interfaces`, `_shell_quote`, `backup_kismet_site_conf`,
  `find_stale_kismet_lockfiles`, `_build_parser`) were then pinned by 44 tests in
  `tests/test_bootstrap_kismet_probes.py`, taking it to **59%** (263 missed).
  ⚠️ **Still uncovered, counted rather than estimated** (statements missed, measured 2026-08-25):
  `run` 86, `install_kismet_apt_repo` 58, `_select_interfaces` 32, `install_kismet_package` 26,
  `detect_wifi_monitor_capable` 25, `print_unsupported_pointer` 15, `_prompt_yes_no` 13, `main` 12.
  These want subprocess mocking and an `input_fn` harness rather than pure-function
  input/output, which is why they were left: a different kind of test, not more of the same.
  🪤 `tests/test_bootstrap_kismet.py` is **gitignored** (it embeds the rig adapter MAC and account
  name), so anything written there is invisible to CI. New cover belongs in a tracked file with
  synthetic fixtures only.
- ~~**Clock jumps.**~~ ✅ **FIXED 2026-08-14 (#35)** for the retention half, and it was a live
  defect: measured **29 of 30** in-window sightings deleted on a +30d excursion, with `evidence.py`
  worse because it is on by default. ⛔ **Not fixable inside `retention.py`.** From there, "the
  clock jumped forward" and "the table holds only old rows" are the same observation, and an
  existing test *requires* the second to delete everything. Fixed with a `time.monotonic()` anchor
  in `Poller`, which declines to call the prunes at all while the clock is untrusted, with a bounded
  hold. ⚠️ ~~**Still open:** the `last_poll_ts` cursor half. A forward excursion still makes later
  polls ask Kismet for devices "since the future".~~ ✅ **STALE — the cursor half landed.**
  Verified 2026-08-25 against `c64a194`: `poller.py` takes the `watermark = None` branch when
  `clock_is_trusted` is false and logs that it is deliberately NOT advancing, so a jumped clock
  cannot poison `last_poll_ts`. Pinned by six tests in `tests/test_clock_jump_poll_watermark.py`,
  including that the hold neither spends nor resets the PERSIST-retry budget (`POLL_WATERMARK_HOLDS`
  belongs to PR #24, and an operator with a jumped clock AND a failing disk must not silently lose
  it). Both halves of the wall-clock class are now closed.

### ~~Heartbeat / dead-man's switch~~ ✅ SHIPPED 2026-08-14 (#31)
Built on migration 024's delivery-tracked path, as the sequencing below required. `heartbeat_enabled`
(default **false**) and `heartbeat_interval_hours` (default 24); migration 025 adds a `heartbeats`
table mirroring the alert delivery columns, and `/settings` reports whether the switch is armed and
when it last arrived.

⛔ **The invariant it rests on: it never claims health it has not verified.** A cheerful "still
watching" sent while ingest is dead is *worse* than no heartbeat, because it converts unease into
false confidence on the one channel the operator trusts. It names a wedged poll loop, failing
persists and undelivered alerts, and raises priority when unhealthy. 🪤 A quiet RF environment is
deliberately **not** unhealthy.

⚠️ **Open, and Kev's call: nothing prompts for it.** It is off by default and the setup wizard does
not offer it, so a safety feature ships unused. Adding a prompt is a UX decision with 200+ wizard
tests behind it.

The original rationale, kept because the sequencing argument is what made it correct:

The one genuinely new feature worth building, deferred until the delivery path is trustworthy
(audit register Finding 12). Every other failure mode now alerts. Kismet loss alerts and recovers,
systemd restarts on failure, the allowlist fails safe. But if the daemon dies, the host loses power,
the SD card wears out, or ntfy delivery itself breaks, the operator's phone simply goes quiet.
**Quiet is indistinguishable from "you are safe"**, which is the worst possible failure for this
product.

A configurable low-priority "still watching, N devices seen, last alert Xh ago" push makes silence
falsifiable, and continuously exercises the delivery path so a broken topic or auth token surfaces
within a day instead of at the moment it matters.
- **Trigger**: after Finding 12's delivery fix lands. Building it on the current fire-and-forget
  path would inherit the same defect.
- **Estimated**: ~150 LOC + config knob + tests. Cheap; the value is in the sequencing.

## Followups for technical debt

### ✅ RESOLVED 2026-08-25 — CSRF token rotation on session boundaries
~~v0.2 ships a single token per cookie session (8 hours). Rotation on
auth events comes when auth lands.~~

Auth landed (#234), and it landed **with** the rotation: a successful `/login`
appends a second `set-cookie` carrying a freshly generated CSRF token, because
the double-submit token is self-issued to anyone who can GET a page and one
collected before sign-in would otherwise still be valid after it.
`build_csrf_cookie` was lifted to module scope precisely so the login handler
could reuse the attribute list rather than grow a second copy that quietly loses
`SameSite`.

⚠️ **Logout does NOT rotate it**, and that asymmetry is deliberate rather than
overlooked: the login-side rule is "nothing an unauthenticated caller planted may
survive authentication", and a CSRF token with no session cookie beside it is
inert. Recorded so it is argued once rather than rediscovered.

⭐ A separate defect in the same area WAS found and fixed in #234: the CSRF
cookie parser was last-one-wins on duplicates while the session reader refuses
them, so a sibling origin under the same registrable domain could supply both
halves of the double-submit pair. Conflicting names are now dropped.

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

### Auto-shift-to-now in FakeKismetClient, SHIPPED
Was: extend FakeKismetClient with auto_shift_to_now / auto_shift_anchor_seconds
params, applied lazily on the first get_devices_since call, surfaced through
Config as kismet_fixture_auto_shift.

What shipped differs from the proposal above. FakeKismetClient now takes
shift_to_now: bool = False, applied eagerly in __init__ rather than lazily on
first get_devices_since, and surfaced through Config as
kismet_fixture_shift_to_now rather than kismet_fixture_auto_shift. The shift
anchors to FIXTURE_ANCHOR_LAG_SECONDS (one hour) before now rather than to
now itself, because the poll loop distrusts future-dated records: a fixture
shifted flush to the current instant produces timestamps that race ahead of
the poll interval and look like clock skew to the ingest path. Consumed by
`lynceus-quickstart --demo` (kismet_fixture_shift_to_now: true in the
generated demo config) so the bundled fixture always reads as fresh instead
of needing manual rebumping.

### Brittle position-sensitive layout tests
Several gitignored layout tests assert CSS rules via naive first-occurrence
string matching (e.g. content.find(".table-scroll") / find(".watchful-
actions")). These have tripped twice when a CSS *comment* contained the
matched selector literal before the real rule, forcing comment rewordings
that don't reflect a real code problem. Harden the matching to target the
actual rule (e.g. match a selector-plus-brace pattern, or parse the rule
block) rather than first textual occurrence.
⚠️ **NOT stale, and broader than written — audited 2026-08-25.** A cold pass proposed closing this
on the strength of `tests/test_webui.py:4036`, which *is* hardened
(`content.find("\n.table-scroll {")`, anchored on selector-plus-brace). But the naive form
survives in the same TRACKED file at `tests/test_webui.py:1812`
(`body.find(".ack-button-inline")`), so the entry should say "layout tests" rather than
"gitignored layout tests".
🪤 **The audit could not see the gitignored half at all**: all ten `tests/*.py` entries in
`.gitignore` are ABSENT from this checkout, so neither a local sweep nor CI can speak for them.
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
Apple device is exactly the Find My / Apple Continuity decoder arc, ~~which has
not started~~ ⚠️ **which has since LANDED (verified 2026-08-25):
`src/lynceus/ble_continuity.py` classifies an Apple advert into
`find_my_separated` / `find_my` / `find_my_paired` / `airpods` / `nearby`, and
its own entry below is marked "landed (unreleased), and now actually
reachable."** The remaining blocker for the README claim is therefore the
bridge being OFF by default (BLE-G1), not the decoder. Softening that claim
should not wait on either.
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
- ✅ **STALE ON BOTH COUNTS — verified 2026-08-25 at `c64a194`.**
  1. It does not fail. `pytest tests/test_diag_home_ack_flow.py -m diagnostic` → **1 passed**.
  2. It is not gitignored. `tests/test_diag_home_ack_flow.py` is **tracked**; `git check-ignore`
     returns nothing for it. The gitignored set is the ten files listed in `.gitignore`, and this
     is not one of them.
  ⇒ Nothing to do. Kept rather than deleted because the entry is the record of a belief that was
  acted on twice.

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

### ~~Kismet-died notification~~ ✅ SHIPPED in 0.9.1, entry was stale
Verified 2026-08-13: `poller.py:1257-1310` implements exactly this. A runtime
loss alerts once after `RUNTIME_KISMET_LOSS_THRESHOLD = 3` consecutive failed
ticks (~3 min at the default interval), re-probes `health_check()` to avoid
paging on a transient blip, and sends a **recovery** notification when Kismet
comes back. `priority_override=4` keeps it below the 5 reserved for
watchlist hits. Original text kept below for provenance:

> Lynceus can detect Kismet unreachability (via health_check) but doesn't
> currently alert via ntfy when this happens. Add a "lynceus infrastructure
> alert" tier that fires on kismet-down, db-locked, etc.

⚠️ The "db-locked, etc." half is **not** done. See "Silent pipeline death"
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
enablement gates below (BLE-G1 … BLE-G8); ~~BLE-G1 and BLE-G2 are blocking~~
**BLE-G1 is the only blocking gate left** — BLE-G2 was decided 2026-08-25 (keep
the source gate explicit), and G3/G4/G6/G8 were all found already implemented.
The payload-format-signature work that makes company ids useful is tracked
separately as the Find My / Apple Continuity decoder arc.
- **Trigger**: ~~gates BLE-G1 and BLE-G2 cleared~~ **BLE-G1 cleared** (G2 decided),
  then flip `ble_bridge.enabled`.
- **Notes**: passive-only, consistent with the project stance. Observe and
  match, never connect/pair/probe; the shipped scanner is passive-mode with no
  connect path. Pairs with the README-integrity follow-up (the README already
  claims BLE-UUID / AirTag-class recognition that rides this surface) and the
  D2 drone field-path confirmation below. D2 is unaffected by this landing and
  still needs a live drone capture.

### BLE-G1: watchlist curation before enabling the bridge (BLOCKING)

⭐ **MEASURED 2026-08-22 against the shipped `default_watchlist.csv` (41,508 rows,
schema_version=31). The gate is real and its PREMISE is wrong.** Every number
below is counted from the CSV in the wheel, not estimated.

**The premise that fails.** This entry used to say the curation decision "is
Argus-side data work, not lynceus-side code". The decision is Argus-side. The
mechanism to express it does not exist in lynceus, so the code half is not
optional:

    ble_manufacturer_id   3969 rows   3967 unknown, 2 cctv_camera
    ble_company_id         715 rows    713 unknown, 1 drone, 1 hacking_tool

Both Argus types collapse to the single watchlist `pattern_type`
`ble_manufacturer_id` (`IDENTIFIER_TYPE_MAP`, `import_argus.py:72`), so the rule
consumes **4,684 rows of which 4 carry an actionable category**. 0.085% signal.
3,969 distinct company ids is the Bluetooth SIG registry, which is to say every
Apple, Samsung, Google and Xiaomi device in range.

⚠️ **Those rows are in the database on every install TODAY.** The commented-out
rule is the only thing holding the storm back, and a commented YAML line is not
a safety boundary.

**Why no existing knob can fix it.** 80.3% of the whole corpus (33,329 rows) is
`device_category=unknown`, and of those, 17,778 are `mac_range` and 8,904 are
hostnames. So `suppress_categories: [unknown]` or
`device_category_severity: {unknown: drop}` would take out the backbone of the
detection that works. Checked one at a time, and each fails on a different
dimension:

    vendor_overrides       4,193 distinct BLE manufacturers, 180 of them also
                           own non-BLE rows, so dropping by vendor is collateral
    geographic_filter      BLE rows are scope '' (3969) / global (707) / US (8);
                           31,435 non-BLE rows are ALSO ''. Not disjoint
    confidence_*           3,968 of 3,969 sit at a flat 85. No discrimination
    pattern_overrides      assigns severity, does not suppress. "low" still fires

⇒ **No knob keys on `pattern_type`.** The needed predicate is the conjunction
`(pattern_type, device_category)` and the config language cannot say it.

**The gate is applied to three rules and describes only one.** The alert-storm
argument is about company ids. It is currently blocking two rules it does not
describe:

Counted at the watchlist `pattern_type` level, which is what a delegation rule
actually sees, across the whole shipped corpus:

    pattern_type          rows  actionable        rule state
    mac_range            17806    28 (0.16%)      commented
    ble_manufacturer_id   4684     4 (0.09%)      commented  <- this gate
    oui                    444   144 (32.4%)      commented
    drone_id_prefix        427   427 (100%)       commented, capture-path caveat
    ble_uuid               140   130 (92.9%)      commented, NO STATED REASON
    ssid_pattern            24    18 (75.0%)      LIVE
    ble_local_name          21    21 (100%)       commented
    ssid                     6     6 (100%)       LIVE
    mac                      4     4 (100%)       LIVE

⭐ **34 of the 23,556 imported rows can fire an alert today.** Everything else is
inert, because the only live delegation rules are `argus_mac`, `argus_ssid` and
`apple_find_my`.

> ⚠️ **Both numbers above are pre-2026-08-22 and the table above them is too.**
> The corpus is now **23,566** admitted rows (the S1 re-cut added 10), and the
> `ssid_pattern` row of that table is wrong in a way that mattered: it reads
> "24 rows, 18 categorised, LIVE", but **19 of those 24 were Python regexes in
> a column matched as a literal substring, so they could not fire at all** --
> the LIVE grading was the defect, not the summary. `ble_local_name` is worse:
> it was matched by strict SQL equality, so all 21 rows were dead including
> the 8 that were already literal. Both columns are re-cut and
> `ble_local_name` is now a substring match.
> ⇒ **The "34 that can fire" figure needs re-measuring against the new data
> and the current rule set before it is quoted again.** It is left here rather
> than guessed at. That is the context this gate sits in: the argument for keeping
a rule off has to be better than "its corpus is mostly noise", because by that
measure `oui`, `drone_id_prefix`, `ble_uuid` and `ble_local_name` are all being
held back by a gate written about company ids.

`argus_drone_id_prefix` is the one with a different and legitimate reason: it
shares the Kismet-surface caveat printed above it in `rules.yaml`, so it is a
capture-path question rather than a curation one. `argus_ble_uuid` is not.

`argus_ble_uuid` is commented out with **no stated reason at all**, sitting in a
block beside `argus_mac` and `argus_oui`. Its rule type is implemented end to
end, delegation included (`rules.py:1128`, `db.resolve_matched_ble_uuid_for_eval`),
and it does not need the BLE bridge, because Kismet surfaces
`kismet.device.base.service_uuids` directly (`kismet.py:566`) and the bridge
supplies the same field. Its 130 categorised rows are Hikvision and Dahua
cameras, Motorola police radio, and SoundThinking gunshot detection. For
comparison, `argus_ssid` was switched on in rc6+ on the strength of **10** Flock
rows.

🪤 **Do not read that 87% as permission to enable it.** The 10 uncategorised
`ble_uuid` rows are consumer platforms, all at confidence 65:

    fd44 / 0000fd44                        Apple Find My
    7dfc9000 .. 7dfc9003                   Tile
    fd5a / 0x0075                          Samsung
    fe9f                                   Google
    74278bda-b644-4520-8f0c-720eaf059935   Xiaomi

Enabling `argus_ble_uuid` as it ships storms on every Apple device in range. It
is the same defect as the company ids at 1/400th the scale, hiding inside the
type that otherwise looks clean. ⇒ **the same eligibility mechanism is needed
either way**, which is the argument for building it rather than curating a CSV.

🪤 **Two of those consumer UUIDs are harmless today only because they are
malformed.** Four rows in the shipped corpus are rejected by lynceus's own
normaliser, so they never reach the watchlist at all:

    fd5a / 0x0075                            two identifiers in one field
    fdcd / 0x02d0                            two identifiers in one field
    0002AB8-0000-1000-8000-00805f9b34fb      7 hex digits in the first group
    0x3080                                   0x prefix on a UUID

The first two are Samsung and Xiaomi. If Argus corrects the formatting, two more
consumer platforms land in the corpus uncategorised and the storm surface grows
with no change on this side. ⇒ a data-quality defect upstream is currently doing
a safety job, which is not a thing to rely on.

**This gate is now ENFORCED, not just described.** `tests/test_watchlist_rule_safety.py`
fails if any delegation rule ships enabled while its corpus still holds an
uncategorised consumer-platform identifier. It is keyed on the identifiers rather
than on a ratio, because `ble_uuid` is 92.9% categorised and still storms. It is
a take-effect pair, not a blocklist: the same rule against a corpus where Argus
has categorised `004c` passes, so curating the data is what unblocks the gate.

**What to build**, red-teamed with `gpt-5.6-sol` before writing any of it:

1. A **positive eligibility test on the matched row**, enforced in the rule, not
   in config. It protects databases that are already imported, needs no
   re-import, and cannot be defeated by import and runtime configuration
   disagreeing. ⛔ Do NOT express it as `device_category != 'unknown'`: that
   conflates taxonomy completeness with alert eligibility and assumes every
   named category is worth an alert. Name the eligible categories.
2. An **exact company-id allow override that outranks it**, so an operator can
   enable one known tracker vendor without enabling its category or its
   manufacturer.
3. Curating the shipped CSV is worth doing and **cannot be the gate**: it does
   nothing for installed databases, for a deployed config with the rule on, or
   for an operator importing a raw Argus export.

⛔ **The deeper point, and the reason not to just widen the allowlist later.** A
company id names a payload namespace, not a device that is following someone.
Apple was solved by DECODING the Continuity payload into `find_my_separated`,
not by listing `004c`. Alert-worthy evidence is a decoded role plus persistence
plus co-movement, and company id belongs upstream of that as a decoder hint. A
filter built to stop a storm is one edit away from hiding the tracker it was
looking for.

- **Trigger**: blocking for `argus_ble_manufacturer_id`. Must be resolved before
  `ble_bridge.enabled` is ever set in a real deployment.
- **Notes**: ⚠️ **CORRECTED 2026-08-20.** This said BOTH rules were commented out
  "so the repo default is safe", and #182 made half of that false. `apple_find_my`
  now ships **LIVE** (`config/rules.yaml:206`); only `argus_ble_manufacturer_id`
  is still commented out (`:148`). The repo default is still safe, but for a
  narrower reason than this note gave: `apple_find_my` matches `ble_device_class`,
  which **nothing but the passive BLE bridge populates**, so with the bridge off
  it cannot fire by construction. That is an argument from the capture path, not
  from the rule being disabled. ⇒ A note that is right for the wrong reason
  survives the change that falsifies it. **Verify the deployed rig config
  separately.** If `argus_ble_manufacturer_id` is uncommented there, enabling the
  bridge storms immediately, and the Continuity decoder does not help because that
  rule matches company id, not class.

### ✅ DECIDED 2026-08-25 — BLE-G2: kismet_sources source-gate vs bridge provenance
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
⭐ **MEASURED 2026-08-21. This entry OVERSTATES the severity, and the gate is
already built.** The read-only verification it asks for was done; here is what
is actually true:

1. **The check exists and is wired.** `ble_bridge_checks.py:339` warns
   *"kismet_sources is set but does not list 'ble:<adapter>' … it will scan and
   buffer correctly while contributing nothing"*, with the remedy *"Add
   'ble:<adapter>' to kismet_sources, or clear kismet_sources entirely."* It
   runs from `collect_bridge_warnings`, which is called by **both setup wizards**
   (`cli/setup.py:1188`, `setup/web/steps_capture.py:96`) **and `/settings`**
   (`webui/app.py:1287`).
2. ⛔ **"only DEBUG-level drop logging" is FALSE.** `poller.py:2033` emits an
   operator-facing **INFO** line per tick naming both sides:
   *"source_allowlist mismatch on tick: N records seen by sources=[…] not in
   allowlist=[…]"*, bounded to one line per tick.
3. **It reaches the UI too**: `/healthz` renders `dropped (allowlist mismatch)`
   (`healthz.html:54`) and the home page branches on it (`index.html:97`).

⇒ **The MECHANISM is real.** `ble:hci1` fails an exact-membership test against
`hci1` at `poller.py:1963` and every bridge observation is dropped. **The
"silent failure" framing is not.** Left here rather than deleted because the
mechanism still bites an operator who does not read logs or check `/settings`.

⚠️ **BLE-G6 and BLE-G8 are likewise already implemented:**
`CHECK_ADAPTER_CONTENTION` and `check_bluez_advertisement_monitor`, both wired
into `collect_bridge_warnings`, and correctly **ordered** (G8 upstream of G6,
because contention presumes an adapter the monitor interface could open).
⇒ ⭐ **Grep the shipped code before scoping a gate from this file.** Three gates
were scoped as work here and all three were already done.

- ✅ **DECIDED 2026-08-25 by Kev: keep the gate explicit. NO LONGER BLOCKING.**
  The open question was whether the gate should *exempt* bridge-stamped provenance
  rather than make the operator hand-write `ble:<adapter>`. It should not.
  ⛔ Auto-exempting would widen what a `kismet_sources` ENTRY MEANS: an operator
  who listed `hci1` to mean "only Kismet's HCI source" would silently start
  admitting a second, differently-sourced stream. That is a semantics change to a
  filter whose entire job is to be explicit, traded for removing a footgun that is
  already announced in four places.
  ⭐ **Four independent operator-facing surfaces, each re-verified 2026-08-25:**
  the readiness warning from `collect_bridge_warnings`, wired into the CLI wizard
  (`cli/setup.py:1188`), the web wizard (`setup/web/steps_capture.py:96`) **and**
  `/settings` (`webui/app.py:1309`); a per-tick **INFO** line naming both sides
  (`poller.py:2068` — `logger.info`, not DEBUG); `dropped (allowlist mismatch)` on
  `/healthz` (`healthz.html:54`); and the home-page branch (`index.html:98`).
  ⚠️ The mechanism is unchanged and still real — `ble:hci1` fails exact membership
  against `hci1` and every bridge observation is dropped. It is now a documented
  configuration requirement rather than an open gate. An operator whose
  `kismet_sources` is unset has no gate at all and is unaffected.
  🪤 **This entry was mis-scoped as work TWICE**, both times by reading its opening
  paragraph and stopping before the ⭐ MEASURED section that says the gate is
  already built. It is the fourth gate scoped from this file that was already done.
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
- ✅ **DONE — verified 2026-08-25.** `bridges/ble.py::_make_scanner` no longer passes a top-level
  `adapter=`; it constructs `bluez=BlueZScannerArgs(or_patterns=..., adapter=self.adapter)`, which
  is exactly the fix this entry proposes, with an inline note verifying against bleak 3.0.2 that
  the old form warns and this one does not.
- ~~**Trigger**: before any bleak major-version bump, or on the first deprecation
  warning observed on the rig.~~
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
Measured on the Linux dev box with **BlueZ 5.72 and kernel 7.0.0, both
comfortably above the minimums the bridge's own error text quotes**, with
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
  does not exist. Without that check a typo'd adapter name would draw a
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
**survives.** It predates 014 and appears in 014's own `INSERT` list, so the
rebuild carries it. Only columns added *after* 014 are dropped, which is the
whole point of the defect; naming a survivor beside the casualty made this read
as a broader data loss than it is. Verified: 11 columns before the replay, 10
after, `ble_device_class` the only one missing.
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
- ⚠️ **HALF STALE — verified 2026-08-25.** The premise "still an unverified guess" is no longer
  true: `kismet.py:467` records the paths as **VERIFIED against Kismet's source, 2026-08-02**
  (`phy_uav_drone.cc:128`, `phy_uav_drone.h:323`), and the five paths it replaced do not exist in
  Kismet at all — so the matcher could never have fired before. ⇒ The SECOND of this entry's own
  two trigger conditions is already met.
  ⛔ What remains is only the first: no drone has been captured, so the mapping is confirmed
  against source rather than against the wire. That is a smaller claim than the entry made.
- **Trigger**: ~~a live drone Remote-ID capture on the rig, or~~ a confirmed Kismet
  field-path reference ✅ — a live capture would now only raise confidence.
- **Notes**: blocks nothing else. The matcher, capture coercion, and allowlist
  mirror are all in place and tested; this is the one runtime fact that can only
  come from real hardware. Likely confirmed alongside the BLE advertisement-
  payload bridge above.
