# Audit register

Findings from the gap audit: **what a surface claims** vs **what the code does**. The bug class is
the control plane working while the payload never lands — the handler returns 200, the row is
written, the UI turns green, and the thing that was supposed to change never changes.

**Taken at**: `3704737`, 2026-08-02; waves 3–4 added at `4f62b2b`. **All ~16 surfaces covered.**

**Suite baseline at `3704737`, repo root**: `3060 passed, 1 failed, 1 skipped, 47 deselected` in
15m46s. The one failure was the Argus import drift, **since fixed** — at `962dab6` the suite is
`3064 passed, 1 skipped, 0 failed`, green for the first time. Both halves of that drift were on
Lynceus's side, not Argus's: see the commit for the nullable-confidence and accept-list reasoning.

Every entry below was confirmed at its file:line by re-reading the code, and from wave 3 onward by
reproducing it, not accepted from the auditor that reported it. **Six of the eleven reported
CORE-BROKEN findings did not survive that check** — see *Refuted* and *Rejected* below, and read
both before re-reporting any of them. The failure is always the same shape: a promise read more
broadly than it was written.

---

## 🔴 Finding 0 — adding a device to the watchlist from the UI does nothing

**Reproduced live**, not inferred. Run `scripts/audit/repro_watchlist_gap.py`.

**The promise**, verbatim: `Add {mac} to the watchlist? It will raise alerts on every future
sighting.` — `src/lynceus/webui/templates/_device_actions.html:31`

**What happens**: `POST /devices/{mac}/watchlist` calls `db.add_watchlist(...)`
(`webui/app.py:3204`). The row is written, the UI turns green, the entry appears on `/watchlist`.

**Where the chain stops**: `rules.py:804`. A `watchlist_mac` rule with **non-empty** `patterns`
matches in memory and never consults the database. Database rows are only consulted by the
*delegation* path, which requires an enabled `watchlist_mac` rule with **empty** `patterns`. In the
shipped `config/rules.yaml`, `argus_mac` (line 85) and `argus_mac_range` (line 51) are both
commented out — "Default is OFF; uncomment to enable". The only enabled empty-pattern rule is
`argus_ssid`, which is `watchlist_ssid`.

**Measured** against the shipped ruleset, unmodified:

```
watchlist rows in DB: 1 -> aa:bb:cc:dd:ee:ff (high)
enabled rules: [('hak5_pineapple_oui','watchlist_oui',1), ('known_bad_mac','watchlist_mac',1),
                ('rogue_ssids','watchlist_ssid',2), ('new_device_alert',...), ('argus_ssid','watchlist_ssid',0)]
RuleHits produced for that MAC: 0
```

**Why it survived**: both tests stop before the boundary. The route test builds a config with no
`rules_path` and asserts only that the row exists (`tests/test_device_actions.py:34`, `:71`). The
poll integration test **hand-injects** an empty-pattern `Ruleset` (`tests/test_alert_linkage.py:1197`),
supplying exactly the production wiring that is missing.

**Why manual testing cannot catch it**: the failure mode is an alert that does not fire. Everything
an operator can see — the confirmation, the row, the `/watchlist` entry — is correct. Nobody notices
silence.

⛔ **Decision required before fixing.** `config/rules.yaml:78-83` makes an explicit backward-compat
promise: "existing operator deployments see zero behavioral change unless they deliberately
uncomment one of the entries below." Enabling `argus_mac` by default breaks that promise on purpose.
The alternatives are to have the route refuse or warn when no delegation rule is active, or to have
the UI write an entry that matches regardless of ruleset shape. Not fixed unilaterally.

---

## 🔴 Finding 0b — Open Drone ID service name is not matched, and the code says so

`org.opendroneid.remoteid` — ASTM F3411 Remote ID, category `drone`, confidence 85 — arrives in the
Argus export as `identifier_type=wifi_aware_service_name`. That type is in neither
`IDENTIFIER_TYPE_MAP` nor `NON_RF_IDENTIFIER_TYPES`, so the importer drops it and logs
(`import_argus.py:578`):

> *"1 Argus identifier type(s) are neither mapped nor recorded as non-RF: wifi_aware_service_name=1.
> If any of these ARE observable over the air, Lynceus is silently not matching them."*

It **is** observable over the air — Remote ID broadcasts it as a Wi-Fi Aware (NAN) service name — and
the README advertises Remote-ID detection.

**Partly mitigated**: Lynceus does capture Remote ID by a different route,
`kismet.device.base.remote_id` → `serial_number` / `uas_id` (`kismet.py:411-412`), feeding the
`drone_id_prefix` rule type. So Remote-ID-broadcasting drones are not wholly invisible; what is
missed is the generic service name that marks *any* compliant broadcast.

⛔ **Deliberately left unfixed, and the warning deliberately left firing.** Filing
`wifi_aware_service_name` under `NON_RF_IDENTIFIER_TYPES` would silence it in one line and would be
**false**: that set means "resolved over IP, recovered by teardown, or paperwork — never broadcast"
(`import_argus.py:115-133`). A NAN service name is broadcast. Silencing a true warning with a false
classification is strictly worse than leaving a known gap visible.

Closing it properly needs a Wi-Fi Aware capture path — first question is whether Kismet exposes NAN
service names at all, which is unestablished. That is feature work, not drift.

---

## Confirmed

| # | Finding | Anchor | Bucket |
|---|---|---|---|
| 1 | `find("r1")` matches random token content, not the rule row, so the assertion window misses `fires`. Flaky, ~1 run in 100. Caused the single failure in a 17-minute suite run. | `tests/test_webui.py:1194` | 🔴 test defect |
| 2 | README claims "at runtime the only outbound connections are to the ntfy broker you configured and to GitHub". This omits Kismet, which every poll tick contacts and which accepts any `http(s)` host. | `README.md:136-138`, `src/lynceus/config.py:29-34`, `src/lynceus/kismet.py:655-660` | 🟡 doc inaccuracy |
| 3 | The UI writes `allowlist_ui.yaml`, a YAML file that changes alerting behaviour, while the README says "every config change happens out-of-band via `lynceus-setup` or the YAML". Defensible — it is a daemon-managed operational store, not `lynceus.yaml` — but the wording invites the opposite reading. | `src/lynceus/webui/app.py:2321`, `README.md:133-135` | 🟡 wording |

### Cross-cutting: the test suite is the accomplice

Three independent auditors each flagged the same pattern without being told to look for it. Every
one of these is a test that claims an end-to-end guarantee and mocks the boundary that would prove it:

| Claim | What the test actually does | Anchor |
|---|---|---|
| allowlist suppression works end to end | manually reloads the allowlist instead of exercising `Poller._maybe_reload_allowlist`; supplies no real notifier | `tests/test_webui.py:4556`, `:4566` |
| BLE bridge scans passively | replaces the scan boundary with `fake_scan` | `tests/test_poller_ble_bridge.py:54-57` |
| probe-SSID opt-out holds | substitutes `_ListClient` for the Kismet transport | `tests/test_tier1_capture.py:468-497` |

The production call paths were separately read and are correct. The point is narrower and still
matters: **these three guarantees currently rest on reading the code, not on the tests that cite
them.** One live end-to-end run would be worth more than all three.

---

## Refuted — do not re-report without new evidence

| Reported as | Why it does not hold |
|---|---|
| **CORE-BROKEN**: device silence secretly stops watchful tracking, contradicting "tracking continues regardless" | Three different mechanisms were conflated. The watch form's `snooze_duration` creates a *watchful entry* (`app.py:3246`, `create_watchful_from_alert`), not an allowlist entry, so its tooltip is accurate about its own control. Allowlist precedence is deliberate and documented three times: `poller.py:288-300` in-line, `WATCHFUL_SNOOZE_DESIGN.md:148`, and `:489-493` ("an allowlisted MAC under watchful snooze sees no `sighting_count`"). The cited `:569` describes the *per-alert* snooze, a fourth mechanism, which genuinely is orthogonal. |
| **CORE-BROKEN**: the read-only UI promise is false because 23 mutative POST routes exist | The promise is scoped: "surfaces state and never mutates **configuration**" (`README.md:133-135`). Acks, snoozes, notes and watchful entries are operational state, not configuration. The one residual point is recorded as finding 3 above, at its real severity. |

⭐ **The lesson to carry into wave 2.** Both refutations came from a delegate reading a promise more
broadly than it was written, then finding code that failed the broadened version. Quote the promise
verbatim before judging whether code violates it. A delegate's report is a lead, not a finding.

---

## ✅ Verified working end to end — do not re-audit before `3704737` changes

| Surface | Evidence |
|---|---|
| Passive only | Kismet integration exposes REST GETs only (`kismet.py:655-660`, `:680-686`, `:735-740`); no association or injection API exists. BLE constructs Bleak with `scanning_mode="passive"` (`bridges/ble.py:349-358`) and is really started by the daemon (`poller.py:1316-1319`). |
| Probe SSIDs off by default | Default `False` (`config.py:51`), propagated into the real poll (`poller.py:513-519`), gates extraction (`kismet.py:568-570`) and storage (`poller.py:229-237`). Evidence snapshots redact nested probe fields (`evidence.py:100-128`). |
| No telemetry (phone-home) | No analytics implementation or dependency; UI assets local (`templates/base.html:114-116`); ntfy POSTs only when configured (`notify.py:165`). See finding 2 for the wording gap. |
| Allowlist / device snooze | UI writes `allowlist_ui.yaml` (`app.py:2352`); poller reloads before each tick (`poller.py:1335`); match returns before both `add_alert` and `notifier.send` (`poller.py:286`, `:411`). |
| Rule snooze / unsnooze | POST commits or deletes the row (`app.py:3521`, `:3540`); every rule hit reads it before row creation and notification (`poller.py:386`). |

---

## Wave 2 — reported clean, with evidence

Nine surfaces swept. Eight returned no CORE-BROKEN finding; the ninth produced Finding 0 above.
These are **reported** clean, not independently re-verified line by line — treat as lower-confidence
than the ✅ list, which I did re-read.

Rules-engine match types (MAC, OUI, MAC range, BLE) all reachable from a live poll · alerts triage
(ack, unack, bulk-ack, ack-all-visible, notes, CSV) · `/healthz` and poll-tick observability · config
reload semantics, with no field documented hot-reloadable but read only at startup · multi-adapter
`kismet_source_locations` mapping reaching sighting rows · systemd hardening directives really
installed and consumed · migrations and rollback implemented and CLI-reachable · dark-mode
persistence and the no-flash claim.

⚠️ Wave 1 refuted three of four CORE-BROKEN claims on verification, so a delegate reporting *clean*
deserves the same scepticism as one reporting *broken*. Spot-check before relying on this section.

## Wave 3 — the two unread reports, now verified

`/settings` and the ntfy notifier had sat unread since wave 1. Both are now read and checked.

**ntfy notifier: CLEAN.** No CORE-BROKEN finding, and nothing on inspection.

**`/settings`: one confirmed, one refuted.** See Finding 4 below for the confirmed one.

Refuted — *"reconfigure records intent but does not activate it."* The report argued that because the
apply pipeline never restarts the daemon, the three cards pointing at `lynceus-setup --reconfigure`
promise something untrue. The promise, verbatim, is *"To change, run `lynceus-setup
--reconfigure`."* (`settings.html:49`, `:84`, `:172`) — it commits to how you change a setting and
says nothing about when it takes effect, and running it genuinely does change the setting. It is also
not *silently* wrong: `settings_view` builds its context from `app.state.config`
(`webui/app.py:3824`), the same startup config the daemon holds, so page and daemon agree and the
operator sees their change has not appeared. What remains is a guidance gap, not a broken feature —
the BLE and severity cards say "restart" and these three do not.

⚠️ That makes **four of five** CORE-BROKEN claims on this project refuted, every one for the same
reason. The rate is now high enough that a CORE-BROKEN label should be read as "unverified lead".

The watchlist report's second claim — provenance cross-links not universal, `webui/app.py:3766` and
`watchlist_detail.html:97` — remains unverified and lower severity.

---

## 🔴 Finding 4 — `/settings` prints a seeder command that cannot run

`/settings` tells the operator, verbatim:

> To add data, run `lynceus-import-argus --input <path>` or `lynceus-seed-watchlist --yaml <path>`.

(`settings.html:213-214`.) But `--db` is declared `required=True` (`cli/seed_watchlist.py:245`), so
the second command exits before doing anything:

```
$ lynceus-seed-watchlist --yaml /tmp/nonexistent.yaml
usage: lynceus-seed-watchlist [-h] --db DB [--threat-ouis] [--ble-uuids] [--yaml YAML]
                              [--log-level {DEBUG,INFO,WARNING,ERROR}]
lynceus-seed-watchlist: error: the following arguments are required: --db
exit=2
```

**Visibly wrong, not silently** — the operator gets a usage error. Cheap to fix: print the `--db`.

The sibling command is fine: `lynceus-import-argus --input <path>` clears argparse and fails only on
a missing file, so `--db` genuinely defaults there. The report's wider claim that page commands
should carry `--scope system` is a **NEEDS-DECISION**, not a defect — it depends on whether
system-scope installs are supported, which is not an auditor's call.

### ⚠️ Correction — the first fix caught one of the two sites

Recorded after the full suite failed at `d112a53`.

The remediation interpolated `system.db_path` at `settings.html:219` and stopped there. The data
card prints its "To add data" line from **two** branches, and the second — now `settings.html:229`,
the branch rendered whenever the watchlist has rows — kept the un-runnable form. The fix therefore
corrected the fresh-install case and left the case every populated install actually shows.

The auditor quoted one line number because it read the template once, and this register repeated the
single citation without checking. ⇒ **Grep for every occurrence of a string before calling a prose
fix complete.**

It surfaced only because
`tests/test_ui_settings.py::test_watchlist_data_card_zero_total_no_imports_shows_legacy_hint` pinned
the pre-fix literal and failed in the full run. The wave-4 DoD ran three targeted files and did not
include `test_ui_settings.py` — the file that the same session's own handoff (§3.2) names as
required for any UI change, after a narrow DoD had already hidden four failures once.

Now guarded by `test_settings_seeder_command_carries_required_db_flag`, parametrized over both
watchlist states, matching on the rendered command rather than a flag-order literal, and proven by
three A/B/A mutations: dropping `--db` from either branch, and hardcoding the path instead of
interpolating `system.db_path`, each flips the named parametrization pass → fail → pass.

---

## 🟡 Finding 5 — two diagnostics were silently observing nothing

`_extract_th_td` matched `<table>` and `<th>` with no allowance for attributes
(`tests/test_diag_dashboard_home_rich_info.py:87`, `:91`), and
`tests/test_diag_dashboard_devices_query.py:178` matched `<th>([^<]+)</th>`. Measured before the fix:

```
'recently seen devices'   headers=[] rows=0
'recent unacknowledged alerts'  headers=[] rows=0
bare '<table>' present in RENDERED html: False
```

Both tests **passed** throughout. Two causes, and only one is this session's:

- `/devices` has been unextractable **since v0.9.2**, when `_table_macro.html` began rendering
  sortable headers as `<th aria-sort=…><a class="th-sort">Label</a></th>`. A plain-text cell body
  cannot match that. Pre-existing, unrelated to accessibility work.
- The home page joined it when the a11y pass added `aria-label` to every `<table>`.

Fixed by tolerating attributes and stripping inner markup, and — the part that matters — by
asserting the extractor found something. A diagnostic that cannot fail is not a diagnostic. It now
reports 8 headers on the home page and 13 on `/devices`.

### ⚠️ Recurrence — a third blinded extractor, found by finally running the marker

`pytest -m diagnostic` had not been run at any point during the session that wrote the two fixes
above. Run at `3bdafba` it came back **46 passed, 1 failed** against a baseline of 47.

`tests/test_diag_home_ack_flow.py` extracted the home page's alert card with
`<article>\s*<header><strong>recent unacknowledged alerts</strong>`, and the dashboard restructure
moved that card to `<section class="block block-alerts">` with an `<h3>` heading. Nothing about the
ack control the diagnostic exists to observe changed — only its container. The extractor returned
the string `"(block not found)"`, and the run failed several assertions later on
`assert "hx-post" in block`, which reads as an htmx regression and is not one.

Two things this makes concrete, both already written down and neither obeyed:

1. **`.claude/gates.md` says a marker that excludes tests from the default run excludes them from
   every gate that matters.** `addopts` carries `-m 'not diagnostic'`, so 47 tests sat outside every
   gate for the whole session — including the one the same file records v0.9.5 as having shipped red.
2. **Anchoring on container markup is what keeps failing.** The repair anchors on the operator-facing
   heading text at any level, walks out to whichever `<section>`/`<article>` encloses it, and raises
   at the point of extraction instead of returning a sentinel that fails somewhere less informative.

Proven by four A/B/A mutations: removing the card's `hx-post` and renaming its heading each flip the
test pass → fail → pass; moving the container back to `<article>` (opener and closer together) and
demoting the heading to `<h2>` each leave it passing. Catching the defect and permitting the
variation are separate claims and both were measured.

⭐ **This is the cross-cutting lesson again, in a new place.** The register already records "the test
suite is the accomplice" for mocked boundaries. This is the same failure with no mock in sight: a
test that greps rendered HTML goes blind the moment the markup improves, and reports success.

---

## 🟡 Finding 6 — adding `scope` would have disarmed two regression guards

`tests/test_webui.py` asserted `"<th>Probes</th>" not in recent_section` and `"<th>Last SSID</th>"
not in recent_section`, each under a docstring saying the test "breaks deliberately" if that column
is added. Both literals stop matching once the header carries an attribute — so satisfying the a11y
floor's `scope` requirement would have left two guards permanently vacuous, and a future
`<th scope="col">Probes</th>` would have landed unnoticed.

Re-anchored to `">Probes</th>"` / `">Last SSID</th>"`, which is attribute-proof and strictly
stronger. **Proven, not assumed:** both columns were planted *with* `scope="col"` present; both
guards failed; both passed again on revert.

Four more places pinned a bare `<th>` and were re-anchored or repaired at the same time:
`test_ui_alert_metadata.py:871`, `test_webui.py:3533`, and the two extractors in Finding 5.

---

## 🟡 Finding 7 — two premises in `internal/audit-2026-08-02/ui-direction.md` are false

The doc drove a full dashboard rebuild, so its errors propagated into the build.

| Claim | Measured |
|---|---|
| "the current MAC links are mid-blue on near-black and are the worst offender" (`ui-direction.md:58`) | They inherit Pico's `--pico-primary` and pass AA in **both** themes: light `#0172ad` on `#fff` = **5.23:1**; dark `#01aaff` on `rgb(19,22.5,30.5)` = **7.05:1**. `.mac-cell` sets only `font-family` (`lynceus.css:105`). |
| "a strict CSP applies and the tool ships offline" (`ui-direction.md:42`) | **No CSP header is sent.** Nothing in `src/lynceus/webui/`, `deploy/` or `systemd/` sets one; the served response carries none. The offline/no-CDN discipline is real and worth keeping — its stated justification is not. |

The contrast claim did damage: acting on it, the build forced `#4ea8ff` for all themes with a
`#7ec3ff` dark override, lifting dark to 9.58:1 and dropping **light to 2.51:1** — a genuine AA
failure introduced in the name of accessibility. Reverted to Pico's defaults.

⚠️ Note for anyone who later adds a CSP: `base.html:13-15` runs an **inline** `<script>` to set the
theme before first paint. A strict CSP without a nonce or hash blocks it and reintroduces the
light-mode flash the inline script exists to prevent.

---

## Wave 4 — the last four surfaces. The sweep is complete.

Devices, probes, `lynceus-setup` and the Argus import path, all audited, all findings
independently reproduced by me before being recorded. **Two real code bugs, four prose defects, two
claims rejected.**

### 🔴 Finding 8 — `lynceus-setup --web` silently overwrites an existing config

Two promises say it must not:

> "Overwrite an existing config file. Without this flag the wizard refuses." (`cli/setup.py:1525`)

> "Every other flag (`--user`, `--system`, `--reconfigure`, `--skip-probes`, `--output`) works
> identically." (`docs/DEPLOYMENT.md:191`)

`main():1612` dispatches `--web` **before** `run_wizard()`, and both guards live inside
`_run_wizard_body` — each had exactly one call site (`:877`, `:882`). `run_wizard_server` has no
existence check, and `apply_config` calls `write_config(target_path, content)` unconditionally
(`setup/core.py:1218`). `_run_web_wizard`'s own docstring claims it "resolves scope and target path
the same way the CLI flow does", so this contradicted its stated intent.

The terminal path, for contrast, is correct:

```
$ lynceus-setup --output $T/lynceus.yaml     # no --reconfigure
Config already exists at /tmp/…/lynceus.yaml. Use --reconfigure to overwrite, or edit it manually.
exit=2                                        # file byte-identical afterwards
```

**Silently wrong, and destructive**: the browser wizard served the whole flow, took every answer,
then clobbered a hand-edited config. `--web --system` without sudo had the same root cause, failing
at write time instead of refusing up front.

**Fixed** — both preflights now run in `_run_web_wizard`, same helpers, same messages, same exit
code, so the two flows cannot drift again. Guarded by
`test_web_refuses_existing_config_without_reconfigure`, whose load-bearing assertion is that
`run_wizard_server` is **never reached**. Proven by deleting the fix: that test fails, the other 14
pass; restored, all 15 pass.

### 🔴 Finding 9 — `/probes` claimed "this view is empty" while displaying retained history

The notice at `probes_list.html:53` was gated only on `not probe_capture_enabled`, never on row
count. Turning capture off stops new writes (`poller.py:229-237`) but nothing purges
`devices.probe_ssids`. Measured:

```
capture enabled        : False
'view is empty' claim  : True
retained MAC on page   : True
retained SSID on page  : True
```

So the page told the operator their probe history was gone **while rendering it** — the wrong
direction for a privacy signal. **Fixed**: the notice now distinguishes "nothing new is being
recorded, the history below is still stored" from the genuinely-empty case. Guarded both ways and
proven by restoring the old single branch.

### 🟡 Finding 10 — three operator-facing strings contradicted a locked decision

`_device_actions.html:57`, `_alert_row.html:74` and visible page copy at `watchful_list.html:9` all
promised a **low-priority** watchful alert. `poller._emit_watchful_escalation` writes
`severity="high"` and sends `priority_override=4`, and its docstring records that as deliberate:
*"The severity / priority decoupling is intentional per the scare-factor mitigation locked
decision… It is NOT a default-mapping oversight."*

So the behaviour is right and the copy was wrong, in three places — the auditor found one. **Fixed**
to "high-severity", guarded by a negative assertion across all three files plus a companion test
pinning the poller's actual severity, so the pair cannot drift apart silently.

### 🟡 Finding 11 — README and a test docstring both overstated the `/probes` collapse rule

README said `/probes` *"keeps every SSID collapsed behind a click"*. It does not, deliberately.
Measured:

```
group=ssid    ssid_before_<details>=True    ← name visible by design
group=device  ssid_before_<details>=False   ← name collapsed, summary is "reveal 2 network(s)"
```

The real model is that the **device-to-network pairing** is always behind the reveal, and each
grouping exposes only one side. `probes_list.html:59-64` documents this, and
`test_route_ssid_grouping_name_visible_devices_collapsed` **asserts** it (`"HomeNet" not in
details`). `test_probes_tab.py`'s own module docstring claimed the opposite of its own test.

⭐ **This is the most instructive finding of the sweep.** The auditor read the README, reported the
ssid grouping as a broken privacy promise, and proposed moving the SSID inside `<details>` — which
would have overridden a documented decision and left the network-grouped view a column of "reveal N
devices" rows with no network names. **The prose was wrong, in two places, and the code was right.**
Both corrected.

### Rejected — do not re-report without new evidence

| Reported as | Why it does not hold |
|---|---|
| **CONFIRMED-BROKEN**: `--min-confidence` accepts values outside 0–100 | The help reads "hard-skip rows with confidence < N (0-100)" — the parenthetical documents the confidence *scale*, not an input contract, and nothing promises rejection. `/settings:203-209` already carries dedicated copy for "the import filters … dropped every row". Worth hardening (see below); not a broken promise. |
| **CONFIRMED-BROKEN**: the web landing page promises a bundled import although the default is Skip | `review.html:94-96` shows "Skip — no watchlist load (existing data preserved)" before the operator commits, and the apply dispatcher emits a skipped step. Landing copy is an overview of the pipeline, not a per-run guarantee. 🟡 wording at most. |

⇒ **Six of eleven CORE-BROKEN claims across all four waves have now been refuted or downgraded**,
every one from reading a promise more broadly than written. The label reads as a verdict when the
evidence supports only a lead. **Rename it in the audit spec before wave 5.**

### Verified working, with evidence — do not re-audit

- **Probe capture defaults and gating.** `probe_ssids=False` at runtime; `kismet.py:599` gates
  extraction; `poller.py:229-237` gates persistence; the evidence path redacts nested
  `probed_ssid_map` values (`evidence.py:100-128`).
- **Argus import numbers match the README exactly.** 41,508 rows → 23,441 imported, 17,952
  `unknown_type`, 19 `peer_collision`, 92 `in_import_dup`, 4 `normalization_failed`.
- **Importer idempotence**, by two real runs into one DB: `23441 0 0 0` then `0 0 23441 0`.
- **Schema-version tolerance**: `_check_argus_schema_version('999', …)` warns and continues.
- **Device list/detail projections and the silence/allowlist path**, including that the poller
  reloads the UI allowlist before every tick and matches before alert evaluation.
- **Finding 0 is closed.** The watchlist-MAC delegation now fires on the shipped ruleset:
  `RULE_HITS=[('argus_mac', 'watchlist_mac', 'high', 'aa:bb:cc:dd:ee:ff')]`.

## Still open

- `--min-confidence` takes no range validation. Not a broken promise, but the unattended
  `lynceus-refresh.timer` path makes it an operational trap: a typo'd threshold imports nothing and
  still exits 0. Cheap to harden at parse time. **Kev's call — behaviour change, not a fix.**
- Three cards (`settings.html:49`, `:84`, `:172`) say "To change, run `lynceus-setup --reconfigure`"
  without the "then restart" that the BLE and severity cards state. Guidance gap, see Wave 3.
- `sightings` is never pruned. Unchanged across four handoffs.
- The watchlist report's provenance-cross-link claim (`webui/app.py:3766`,
  `watchlist_detail.html:97`) remains unverified and lower severity.

## Method note

Do not run gates from a throwaway worktree. A worktree relocates `Path(__file__).parents[1].parent`
and **silently disables** the cross-repo Argus test — it skips rather than fails, so the suite looks
better than the repo root's baseline. Measured this session: worktree reported 0 Argus failures
where the repo root reports 1. See `.claude/gates.md`.
