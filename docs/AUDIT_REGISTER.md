# Audit register

Findings from the gap audit: **what a surface claims** vs **what the code does**. The bug class is
the control plane working while the payload never lands — the handler returns 200, the row is
written, the UI turns green, and the thing that was supposed to change never changes.

**Taken at**: `3704737`, 2026-08-02; waves 3–4 added at `5a64d8b`. **All ~16 surfaces covered.**

**Suite baseline at `3704737`, repo root**: `3060 passed, 1 failed, 1 skipped, 47 deselected` in
15m46s. The one failure was the Argus import drift, **since fixed** — at `962dab6` the suite is
`3064 passed, 1 skipped, 0 failed`, green for the first time. Both halves of that drift were on
Lynceus's side, not Argus's: see the commit for the nullable-confidence and accept-list reasoning.

Every entry below was confirmed at its file:line by re-reading the code, and from wave 3 onward by
reproducing it, not accepted from the auditor that reported it. **Six of the eleven reported
CORE-BROKEN findings did not survive that check** — see *Refuted* and *Rejected* below, and read
both before re-reporting any of them. The failure is always the same shape: a promise read more
broadly than it was written.

## Label policy — `CORE-BROKEN` is retired (wave 5+)

Auditors reported gaps as **CORE-BROKEN** / **CONFIRMED-BROKEN**, labels that read as verdicts. Six
of eleven did not survive reproduction — a rate high enough that the label was claiming more than the
evidence carried.

⛔ **From wave 5 on, do not use CORE-BROKEN.** Report a suspected gap as a **LEAD**: a claim to be
reproduced, not a verdict. A LEAD is promoted to a **Finding** only once it is reproduced at its
file:line, the way every confirmed finding below was — and a lead that fails reproduction is recorded
under *Refuted*, not quietly dropped. The historical `CORE-BROKEN`/`CONFIRMED-BROKEN` labels in the
tables below are left verbatim as a record of what was reported; read each with its disposition.

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

Recorded after the full suite failed at `a2d35db`.

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
above. Run at `e1ceadc` it came back **46 passed, 1 failed** against a baseline of 47.

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
| "a strict CSP applies and the tool ships offline" (`ui-direction.md:42`) | **Was false; now true.** No CSP header was sent — nothing in `src/lynceus/webui/`, `deploy/` or `systemd/` set one. ✅ **Closed 2026-08-07**: `webui/csp.py` sends a per-request nonce policy on every response. The claim was a premise the doc asserted rather than a control anyone had built, which is the point of the finding and why it stays recorded. The offline/no-CDN discipline was always real; its stated justification was not. |

The contrast claim did damage: acting on it, the build forced `#4ea8ff` for all themes with a
`#7ec3ff` dark override, lifting dark to 9.58:1 and dropping **light to 2.51:1** — a genuine AA
failure introduced in the name of accessibility. Reverted to Pico's defaults.

⚠️ Note for anyone who later adds a CSP: `base.html:13-15` runs an **inline** `<script>` to set the
theme before first paint. A strict CSP without a nonce or hash blocks it and reintroduces the
light-mode flash the inline script exists to prevent.

✅ **Handled when the CSP landed (2026-08-07).** Every inline script carries a per-request nonce, and
`test_webui_csp.py` fails if any inline `<script>` renders without the current one. Hashes were not
viable: the `data_table` macro *generates* `__lynTableApply("<table id>")` per table, so its body
differs per table and no static hash list could cover it.

🪤 **The trap that nearly landed silently**, recorded because it would have been invisible in review:
the macro is imported with `{% from "_table_macro.html" import data_table %}`, and a Jinja macro
**cannot see the caller's context** unless the import says `with context`. Without it,
`request.state.csp_nonce` renders as an EMPTY attribute inside the macro, the browser refuses that
script, and nothing errors — the table-state pre-paint applier just stops running and the
default→persisted column jump returns. All five import sites now say `with context`, and
`test_the_table_macro_script_gets_the_nonce_through_the_import` is the tripwire.

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
evidence supports only a lead. ✅ **Retired — see "Label policy" at the top; wave 5+ reports a LEAD.**

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
- **Finding 0 is closed** *on a configured deployment*. The watchlist-MAC delegation fires on the
  shipped ruleset: `RULE_HITS=[('argus_mac', 'watchlist_mac', 'high', 'aa:bb:cc:dd:ee:ff')]`.
  ⚠️ **Amended 2026-08-13 — its symptom is still reachable by another route.** That closure holds
  only where `rules_path` is wired. It is not wired on the default wizard path, so the button still
  writes a row that nothing consults. See Finding 16.

## Wave 5 — production-readiness pass, 2026-08-13

Scope: is this shippable/shareable, not is it built. Taken at `d66d844` with the `feat/csp` work
uncommitted in the tree. Three read-only delegate packets (`gpt-5.6-sol` ×2, `gpt-5.6-terra`)
supplied leads; **every lead was re-verified here before promotion, and the delegates' own ranking
was wrong twice** — a packet's #1 was weaker than a finding it listed further down, and one lead
(#12 below) was reported as a mechanism and only became a Finding once reproduced.

**Suite at the time of the pass, on the dirty `feat/csp` tree**: `5 failed, 3256 passed, 1 skipped,
47 deselected` in 18m09s, Python 3.11.14. All five failures are the uncommitted CSP work (Finding
13). ⚠️ The 18m09s is not comparable to the `.claude/gates.md` baseline — three delegate packets ran
concurrently and starved the suite into `D` state at 6.6% CPU with `/proc/pressure/io` at ~7% full
stall. `gates.md` warns about exactly this; heed it.

### 🔴 Finding 12 — a transient ntfy failure permanently swallows the alert for the whole dedup window

`poll_once` commits the alert row **before** attempting delivery, and the dedup gate keys on the
existence of that row, not on whether anyone was told:

- `poller.py:400-405` — dedup: `get_recent_alert_for_rule_and_mac(...) is not None` → `continue`
- `poller.py:411-419` — `db.add_alert(...)` commits
- `poller.py:449-456` — `notifier.send(...)`; a `False` return only logs a warning

So a send that fails is never retried: the next poll finds the row it just wrote and skips the emit
path entirely. At the default `alert_dedup_window_seconds: 3600` (`config.py:172`) one blip costs an
hour of alerting for that device+rule.

**Reproduced** with a notifier that fails poll 1 only, device in range for five 60s polls:

```
poll 1 (t+  0s) ntfy=DOWN : attempts=2  delivered=0
poll 2 (t+ 60s) ntfy=UP   : attempts=2  delivered=0
poll 3 (t+120s) ntfy=UP   : attempts=2  delivered=0
poll 4 (t+180s) ntfy=UP   : attempts=2  delivered=0
poll 5 (t+240s) ntfy=UP   : attempts=2  delivered=0
HIGH watchlist alert ever delivered?  NO
```

This is the money path's last step failing on its most likely error. Kismet gets urllib3
retry+backoff (`kismet.py:665-672`); ntfy gets nothing. The field deployment is mobile, so a data
blip is *most* likely exactly when something worth detecting is in range.

⭐ **Why it shipped, and the general lesson: there is no failing-notifier double in the suite.**
`NullNotifier`, `RecordingNotifier` (`notify.py:39,51`) and `_CountingNullNotifier`
(`test_integration.py:207`) all return `True` unconditionally. `test_notify.py` covers the unit-level
`False` return, but nothing composes "send failed" with "next poll". **A test double that can only
succeed cannot test a failure path**, and every integration test in the suite used one.

✅ **Fixed 2026-08-13 (migration 024).** Dedup now keys on **delivery**, not on row existence.
`alerts` gains `notified_at` (NULL = written but nobody told) and `notify_attempts`; the emit gate
distinguishes three states, and collapsing any two reintroduces a defect:

| State | Action | Why not otherwise |
|---|---|---|
| delivered in-window | suppress | the operator already knows |
| undelivered, attempts remaining | **retry the existing row** | emitting a new row instead would fill `/alerts` with duplicates of one detection every time ntfy blipped |
| undelivered, attempts spent | suppress the retry, leave `notified_at` NULL | still counted as undelivered on `/settings` rather than quietly forgotten |

`NOTIFY_MAX_ATTEMPTS = 4` bounds it — each attempt costs a blocking HTTP timeout on the poll path,
and ~4 minutes of tolerance matches `RUNTIME_KISMET_LOSS_THRESHOLD`'s. The attempt is counted
**before** the send, so a hung or unkillable notifier still burns one; counted after, a wedged send
would be retried forever and the bound would not be a bound. Evidence capture is skipped on a retry
(it is keyed to the original alert id and already stored).

**Re-measured, same scenario as the finding** — ntfy down for poll 1 only, device in range for five:

```
poll 1 (t+  0s) ntfy=DOWN : attempts=2  delivered=0
poll 2 (t+ 60s) ntfy=UP   : attempts=3  delivered=1   ← delivered on the very next poll
poll 3-5                  : attempts=3  delivered=1   ← and correctly deduplicated thereafter
HIGH alert rows: 1 (no duplicates)
```

⚠️ **A one-shot rule cannot be retried, by construction.** `new_non_randomized_device` fires only on
a device's *first* sighting, so if its notification fails there is no later poll on which the rule
matches again. That row stays `notified_at = NULL` permanently and is reported in the undelivered
count — which is the honest outcome, and the reason the count exists rather than a retry queue alone.

⭐ **Backfill decision, recorded because it is irreversible:** pre-migration rows are stamped
`notified_at = ts` (treated as delivered) rather than left NULL. Their true delivery state is
unknowable and can never be recovered; leaving them NULL would have reported every alert the database
has ever held as undelivered the moment an operator upgraded.

**`/settings` now reports the undelivered count.** ntfy *reachability* is a liveness probe — it says
the broker answered just now, not that anything ever arrived. A wrong topic or a stale auth token
passes reachability and drops every notification, and the operator's only symptom is silence, which
for this product is indistinguishable from "nothing is out there".

New `tests/test_notify_delivery.py` supplies the missing failing-notifier double (`OutageNotifier`,
parameterised over both `return False` and `raise`) and was validated by planting the original
dedup-on-row-existence logic back: **4 of its 7 tests fail**, all pass on revert.

⭐ **Adding a migration is a six-test change in this repo, and that is by design.** Migration 024
broke five further tests plus one already fixed, every one of them a deliberate manifest pin:
`test_migrations_dir_lists_both_files` (exact filename list), `test_rollback_one_step_each`,
`test_rollback_to_zero_then_reapply`, `test_rollback_to_specific_target`,
`test_validate.py::test_rollback_subcommand_to_zero` (all pinning `range(1, 24)` / max version 23),
and `test_list_alerts_shape_through_migrations` (exact projection key set). Updating the
`test_per_migration_up_down_up` parametrize bound is what first drove 024's **up→down→up roundtrip**,
which is the check that actually proves the down migration works — it passes.

⚠️ `notify_attempts` is deliberately **not** on `list_alerts`' public shape: it is retry bookkeeping
for the poller, not something a caller should branch on. `notified_at` is, because the
paged/unpaged distinction is exactly what Finding 12 turned on.

⇒ **Grep for the tests that pin a manifest BEFORE adding to it.** The standing rule from wave 1 is
"before changing markup, grep for tests pinning the old literal"; a migration list, a column
projection and a filename list are the same thing in a different costume. It was learned twice this
session — once on the wizard templates, once here — both times from a full-suite run rather than
from looking first.

### 🔴 Finding 13 — the CSP silently disables every confirmation dialog on destructive actions

A CSP nonce authorises `<script>` **elements**. It does not authorise inline `on*=` event
attributes — those need `'unsafe-inline'` or `'unsafe-hashes'`, which the policy correctly omits
(`webui/csp.py:36-52`). There are **11** `onsubmit="return confirm(...)"` handlers:
`alert_detail.html:125,139,144,162,176` and `_device_actions.html:31,57,82,89,106,121`.

**Measured in headless Chromium** against the real `build_policy()` output:

```
NONCED_SCRIPT_RAN=true          ← the CSP work does what it intends
MARKUP_HAS_ONSUBMIT_ATTR=true   ← markup looks correct on inspection
"Executing inline event handler violates the following Content Security
 Policy directive 'script-src 'self' 'nonce-…''. … The action has been blocked."
HANDLER_IS_LIVE_FUNCTION=false  ← the confirm() never runs
```

⚠️ **The failure mode is worse than "no dialog".** `onsubmit="return confirm(…)"` cancels submission
by returning false; when the handler is blocked outright it never returns anything, so **the form
submits immediately**. "Permanently silence this device" becomes a single unconfirmed click that
suppresses its future alerts — a destructive, security-relevant action losing its only guard.

⭐ **`test_webui_csp.py` could not catch this**: it inspects `<script>` tags exclusively
(`:115-127,130-151`). A guard that checks the mechanism you implemented will not notice the
mechanism you forgot. The regression test has to forbid `on*=` and `javascript:` in rendered markup.

✅ **Fixed 2026-08-13.** All 11 converted to `data-confirm="…"`, driven by one delegated
**capture-phase** submit listener in `lynceus.js`. Capture phase is load-bearing rather than
stylistic: these forms carry `hx-post`, htmx binds its own submit handler, and only a capture-phase
listener on `document` is guaranteed to run first and be able to cancel it. `hx-confirm` was
rejected as the fix because it would have covered only the six htmx forms in `_device_actions.html`
and none of the five plain forms in `alert_detail.html`.

**Verified in headless Chromium under the shipped policy**, not by reading:

```
FORM_FOUND=true  HAS_DATA_CONFIRM=true
CONFIRM_CALLED: Permanently silence aa:bb:cc:dd:ee:02? F…
SUBMIT_PROCEEDED_AFTER_DECLINE=false
```

🪤 **The first version of the regression test passed with the defect planted back in.** The forms
carrying the confirms are gated — the silence section needs `allowlist_configured`, the watchful and
alert-detail forms need an alert to exist — so a default-config fixture renders exactly **one** of
the eleven, and the assertions were vacuously true. The fixture now configures an allowlist path and
seeds an alert, asserts `seen >= 6` destructive forms before judging any of them, and was
re-validated by planting **both** failure shapes: the inline handler restored (2 tests fail) and the
confirm deleted outright with no replacement (1 test fails). ⇒ **Guarding against the defect is not
the same as rendering the code that carries it.**

### 🔴 Finding 13b — the same CSP work fails five tests, in two distinct ways

- **3 × `jinja2.exceptions.UndefinedError: 'request' is undefined`** —
  `test_columns_menu.py` (×2), `test_devices_column_layout.py`. `_table_macro.html:116` now reads
  `request.state.csp_nonce`, so the macro can no longer be rendered standalone by a unit test.
- **2 × "leaks the toggle state in the body"** — `test_webui.py:9285` and its sibling. The
  per-request nonce breaks byte-identical comparison between a disabled capability and a missing
  device.

⚠️ **The second pair must not be "fixed" by weakening the assertion.** That guard came out of the
co-observation red team and defends a real property. The property still holds — a random nonce
carries no information about toggle state — so the *oracle* is what is now wrong, not the invariant.
Normalise the nonce before comparing.

✅ **Fixed 2026-08-13.** The three macro tests now mirror the production import idiom — `with
context` plus a minimal request stub exposing `state.csp_nonce` — rather than being worked around
with a template-side `if request is defined` fallback, which would have reintroduced the
silent-empty-nonce failure the `with context` trap above describes. The two oracle tests compare
through `_body_without_nonce()`, which masks **only the nonce that response advertised in its own
header**, so any other divergence still fails. Re-validated by planting a one-character leak into
the disabled path (`" "` appended to the 404 message when the capability is off): the guard fails,
confirming that masking the nonce did not cost it its teeth.

### 🟡 Finding 14 — the setup wizard gets no CSP at all

`CSPMiddleware` is registered in `webui/app.py:1457` only. `setup/web/app.py:163-172` installs
`CSRFMiddleware` and `SetupTokenMiddleware` and nothing else, while
`setup/web/templates/_base.html:14,118` and `apply_progress.html:25` carry inline scripts. This is
the **more** sensitive of the two apps: it holds the Kismet API key and ntfy topic in flight and may
run as root. No concrete XSS sink was established there, so this is a risk amplifier rather than a
proven exploit — but the asymmetry is not deliberate, it is an omission.

✅ **Fixed 2026-08-13.** `CSPMiddleware` registered outermost in `setup/web/app.py` so the policy
also covers the 403 `SetupTokenMiddleware` returns — the response an unauthenticated caller sees
most. New `tests/test_setup_web_csp.py` mirrors the dashboard's guards, because the two apps are
separate FastAPI instances with separate stacks and a guard on one proves nothing about the other,
which is exactly how this gap arose.

⭐ **Applying the CSP surfaced five more inline handlers that would each have failed silently**, none
of which was in the original finding:

| Site | What breaks under the policy |
|---|---|
| `review.html:139`, `apply_complete.html:169,175` | Double-submit guards. `/apply` becomes double-clickable — on the step that writes config and, in system scope, chowns files. |
| `rssi.html:26` | The live readout stops tracking the slider; the operator drags it and reads a stale number. |
| `rules.html:146` | "Select all rule types" ticks and does nothing to the list below it. |

The double-submit guards needed an implementation, not just an attribute: the wizard deliberately
does **not** load `lynceus.js` (it ships its own theme toggle for the same reason), so
`data-disable-on-submit` would have been pure decoration. It is now wired in `_base.html`.
⇒ **Adding a CSP is not a header change; it is an audit of every inline handler in the app.**

🪤 **The fix for a silent-failure bug failed silently, in the same way.** The RSSI and select-all
replacement listeners were first appended **after `{% endblock %}`** in their templates. Both files
`{% extends "_base.html" %}`, and Jinja discards anything outside a block — so both scripts rendered
**nothing**, on pages that looked correct in source review. The new
`test_no_inline_event_handlers_on_any_wizard_step` passed throughout, because removing a handler and
never replacing it satisfies an absence assertion perfectly. Only a **pre-existing** wizard test
(`test_rules_page_carries_select_all_rule_types_checkbox`, which pins `querySelectorAll`) caught it —
a test written years earlier to prevent exactly "one half of the pair goes missing", firing for a
cause it could not have anticipated. ⇒ **Every absence assertion needs a presence assertion beside
it**; `test_each_converted_handler_has_a_live_replacement` is that half, and was validated by
re-planting the outside-the-block mistake.

⚠️ **Four existing tests pinned the old inline markup and broke** —
`test_setup_web_apply_complete.py` (×2), `test_setup_web_review.py`,
`test_setup_web_severity_rules.py`. They asserted the *mechanism* (`onsubmit=`, `onchange=`) rather
than the behaviour, so a legitimate CSP-driven migration read as a regression. Updated to pin both
halves — the per-form attribute **and** the listener implementing it. The lesson is the standing one
from wave 1: **before changing markup, grep for tests pinning the old literal.** It was not done
here, and the full-suite run is what caught it.

### 🔴 Finding 15 — two personal ntfy topics are published in an already-public repo

Two operator-specific ntfy topics were committed as sample values in
`docs/CONFIGURATION.md:126` and `:195`. **The values are deliberately not repeated here** — this
register is itself published, and restating a live shared secret in the document that reports it
leaking would undo the scrub and make it *more* discoverable, not less. `gh repo view`
reports the repository **PUBLIC**. An ntfy topic is a bidirectional shared secret: anyone who reads
it can subscribe to the operator's surveillance alerts — deriving location and what is near them —
and can publish forged alerts to their phone. The README already states that a topic is a secret,
which makes this a documentation error rather than a design one. Rotation is the operator's action;
the docs must carry obviously synthetic values.

### 🟡 Finding 16 — accepting every wizard default yields a system that can never alert

Argus-backed alerting is opt-in and `default=False` at both the top-level gate and per rule type
(`cli/setup.py:727-736,745-752`). Decline it and no `rules.yaml` is written, `rules_path` is left
unwired (`config.py:160`), and the daemon takes the empty branch at `poller.py:836-838`, logging
*"no rules_path configured; ruleset is empty — no alerts will fire"*.

**Reproduced**, two arms, one variable, against a planted watchlist row:

```
ARM A  accept wizard defaults    →  0 rule hits
ARM B  shipped rules.yaml wired  →  1 rule hit  (argus_mac, high)
```

Capture still works and the UI populates, so the install looks healthy. The home page does surface
the state — `_nav_tiles.html:42-49` renders "no ruleset configured" — but with **neutral** styling,
while a merely-stale watchlist earns a `warn` (`:35-37`). The one condition that means *nothing can
ever alert* is the only one not flagged. The reasoning in the comment there is sound as far as it
goes (an unset path must not cry wolf like an unreadable one) but it draws the wrong conclusion:
the answer is a third treatment, not the absence of one.

✅ **Fixed 2026-08-13.** The tile now reads **"no ruleset — nothing will alert"** and carries
`nav-tile-warn` — in words as well as colour, since colour is never the only carrier here. It stays
`warn` rather than the `alert` red, which is reserved for a ruleset that is configured and will not
load: unset is a legitimate fresh-install state, not a fault. The README quick start now names
opting into Argus alerting as required for a first alert, and documents the SSH-tunnel step for
`--web` on a headless box.

🪤 **Fixing it exposed a vacuous assertion in the very test that covered it.**
`test_home_rules_tile_distinguishes_unset_from_unreadable` asserted
`"nav-tile-alert" not in tiles.split("/rules")[1]`. The tile renders as
`<a class="nav-tile nav-tile-warn" href="/rules">`, so the **class precedes the href** and splitting
on the href discards it: that assertion could never have detected the class it existed to forbid,
and passed regardless of what the tile rendered. It only came to light because a *positive*
assertion was added beside it and failed. Both now go through a `_tile_for()` helper that extracts
the whole `<a>` element. ⇒ **A negative assertion over a substring you have not proved is in scope
is not a guard.** Third instance of this shape in the register; see the wave-1 entry on negative
assertions disarmed by an unrelated markup change.

### 🟡 Finding 17 — documentation claims a reader would act on, that are false

The README's credibility rests on "check the claims on this page yourself", which raises the cost of
each of these:

| Claim | Measured |
|---|---|
| `SECURITY.md:5,73` — "version **0.9.4**" | Shipped version is `0.9.5` (`pyproject.toml:7`). Stale on the security document specifically. |
| `config/rules.yaml:85` — "enabled by default as of 0.9.6" | ⚠️ **Partly refuted on re-check.** `b6f1961` (the commit that enables it) is in **no tag**, so 0.9.6 is genuinely the release it lands in — the claim is forward-looking, not false. It still reads as a live fact in a config shipped with 0.9.5. Reworded to say so explicitly rather than deleted. ⇒ *Check `git tag --contains` before calling a version reference stale.* |
| `README.md:368` step 1 `./install.sh --user` + `:385` step 4 `sudo systemctl enable --now …` | `--user` installs **no** systemd units (`install.sh:70`, `install_system()` at `:423` is the only writer). Following the documented short path yields "unit not found". |
| `README.md:304-309` — "3024 tests on a clone … full local suite is 3508" | Actual is ~3256, and `.claude/gates.md` records the local/clone split as history. |
| `README.md` — `--web` is "friendlier over SSH" | The wizard binds `127.0.0.1` (`cli/setup.py:1555-1560`); over SSH `localhost:8766` is the laptop, not the Pi. The required port-forwarding step is undocumented. |
| `README.md:75-81` — "Probe history … **with the reveals expanded**", alt-text "**five devices** … two of them sharing a network named `Hendricks_Home`" | The committed `docs/images/probes-history.png` shows **three** devices with every reveal **collapsed** (`reveal 2 network(s) ›`). The prose and alt-text describe a screenshot that is not the one in the repo, and the `Hendricks_Home` correlation the paragraph exists to demonstrate is not visible in it. |

### 🔴 Finding 18 — the threat model claimed a boundary the code stopped honouring

`README.md:483-484` (Privacy / threat model) stated:

> **Read-only UI is a security boundary.** Visibility supports operator awareness; mutability would
> erode the boundary, so it isn't there.

Measured: **23 `@app.post` routes** exist on the dashboard — ack, bulk-ack, note, snooze, allowlist,
allowlist/remove, watchlist, watch, and the five watchful actions. Mutability *is* there; it was
added deliberately, with CSRF and confirmation prompts, and the threat-model bullet was never
updated to match. This is worse than ordinary drift because it is a **security** claim: a reader
auditing Lynceus before trusting it is told there is no write surface to attack.

The same section was silent on the fact that the UI has **no authentication of any kind** (see
BACKLOG, "Web UI has no authentication"), so `ui_allow_remote: true` reads as an ordinary
remote-access convenience rather than "publish an unauthenticated surveillance dashboard to the
LAN". ✅ **Both corrected 2026-08-13**: the bullet now says what is and is not mutable and why, and
a new bullet documents SSH port-forwarding as the supported remote path.

⭐ **The general shape, and it is the third instance in this register:** the sentence was true when
written. Prose does not fail loudly when the code moves underneath it, which is why *"if you change
behaviour, change the sentence that describes it in the same commit"* is now in `CONTRIBUTING.md`.

⭐ **`Hendricks_Home` is NOT a data leak** — checked by opening the image. It appears only in README
prose and alt-text, never in a rendered screenshot, and the sample MACs are plainly synthetic
(`00:13:37:de:ad:be`, `b8:27:eb:01:02:03`). Reported as a possible personal-network identifier by a
delegate; **refuted here.** The real defect at that location is the screenshot drift above. Fixing it
is a content decision — either re-take the screenshot with the reveals expanded, or rewrite the
paragraph to describe the collapsed view that actually ships.

### Leads recorded but not promoted — reproduce before acting

Reported by delegates, code-verified but **not** reproduced at runtime here. Do not treat as
Findings until they are:

- Config rewrite preserves a permissive mode: `os.open(..., 0o600)` applies only on inode creation,
  so an existing `0644` config stays world-readable through a reconfigure (`setup/core.py:194-213`).
- `logger.debug(..., exc_info=True)` in the ntfy failure path can restore the raw topic that the
  WARNING line deliberately redacts (`notify.py:172-174`).
- Short-topic redaction reveals the whole value (`abc123` → `abc1•••23`) (`redact.py:22-33`).
- Export redaction misses indented/quoted keys and block scalars while reporting the field redacted
  (`redact.py:93-99,130-160`).
- Fresh-DB `chmod` failure warns and continues; existing DBs are never checked or repaired
  (`webui/server.py:41-53`).

## Wave 6 — the silent-failure gaps, 2026-08-14

Taken at `d60cdbb` (post-#19). Both items were reported by a delegate in Wave 5 as *untested*; both
turned out to be **broken**, not merely unguarded. Recorded separately because the difference
matters: a test that pins broken behaviour is worse than no test.

### 🔴 Finding 19 — an observation that fails to persist is lost permanently

`poll_once` ends with `set_state(LAST_POLL, now_ts)`, unconditionally. The next tick asks Kismet for
devices seen since that value, so an observation is re-fetchable only while its `last_seen` is at or
after the watermark. Any observation that failed to persist is therefore never asked for again.

⚠️ **This is the normal case, not a contrived one.** Kismet reports devices seen *during* the window
and the watermark is set to the window's **end**, so nearly every observation has a `last_seen` older
than the tick that processed it. Reproduced with the device last seen five seconds before the tick:

```
device last seen at 1699999995; tick ran at 1700000000
after poll 1: persisted=['01']  watermark=1700000000
after poll 2: asked Kismet since=1700000000 -> returned NOTHING
DOOMED recovered: False
```

A car with an ALPR that drives past once, during a transient DB failure, leaves **no alert, no row,
and one WARNING line**. For a tool whose entire job is noticing that device, that is the worst
failure available to it, and it is invisible.

🪤 **The obvious fix is wrong, and the code was already defending against it.** Holding the watermark
until everything persists means a record that fails *every* time freezes it forever: the daemon stays
alive and re-fetches the same window indefinitely, permanently blind to everything after it. That is
the A1 poison-record livelock, and the unconditional advance was the defence. **Both extremes lose
capture data; the bound is the design.**

✅ **Fixed** with a bounded hold: retry the failed window for up to `POLL_WATERMARK_MAX_HOLDS = 3`
consecutive ticks, then advance and log at **ERROR** — a permanent hole in detection coverage is not
a WARNING. Verified at both extremes by planting each: unconditional advance fails 4 of the 6 new
tests, unbounded hold fails 2. The retry window uses `min(failed_last_seen) - 1` because Kismet's
`/devices/last-time` boundary (strict vs inclusive) was **not** established here; a one-second overlap
costs an idempotent re-upsert, while guessing wrong the other way loses the device.

⚠️ **`tests/test_diag_a1_poison_record_livelock.py` states a conclusion its own recorded output
contradicts.** Its NOTES assert *"A1 REPRODUCES … last_poll never advances past its pre-poison
value"*, while its OBSERVED lines show `last_poll` advancing `1700001001 → 1700001002` and every
poison shape returning `None` rather than raising. Its cited line numbers (`poller.py:234/581`) are
stale by hundreds of lines. It is observation-only with no assertions, so nothing caught the drift.
⇒ **A diagnostic that records a narrative alongside its data will have the narrative rot first.**
Read the OBSERVED block, never the NOTES.

### 🔴 Finding 20 — breaking the BLE bridge's alert handoff is invisible to the entire BLE suite

`BleBridge._flush` calls `process_observation`; that one call is the only thing connecting the
decoders, buffer and scan loop to the product. **Measured** by neutering it:

| Suite | Result with the handoff broken |
|---|---|
| `test_ble_bridge_continuity`, `_odid`, `_scan_teardown`, `test_ble_scan_or_patterns`, `test_poller_ble_bridge` (45 tests) | **45 passed** |
| new `test_ble_bridge_flush_pipeline.py` | **5 failed** |

Adverts are still received, decoded and buffered; the buffer still drains on schedule; the thread
still starts and stops cleanly. No device row, no rule evaluation, no alert — and `/settings` still
reports a healthy bridge with decoded adverts, so the operator sees a working sensor that never
tells them anything.

✅ **Covered** by a test that walks the whole chain (callback → buffer → flush → device → rule →
alert → notifier), plus the negative case (a battery-service advert must persist *without*
alerting, so the positive test is not passing merely because everything alerts) and per-advert
failure isolation.

⚠️ Both gaps were invisible in a clone for the same reason: `tests/test_poller.py` and
`tests/test_ble_bridge.py` are among the ten files withheld for embedding the rig's own adapter MAC.
**The withheld files are disproportionately the ones covering the capture path**, so a contributor
running the public suite gets the least coverage exactly where the product's value is.

## Wave 7 — the CodeQL queue, triaged, 2026-08-14

Taken at `199bf79`. **The first wave sourced from an automated tool rather than from reading.**
`security-and-quality` had run for the first time and left a backlog: **48 security-severity alerts**
(26 high, 22 medium) plus ~880 `note`-level ones that are noise.

**Result: 10 real, 38 refuted** (Finding 24 was promoted and then withdrawn on verification). The distribution is the finding. CodeQL's value here was *not* its
verdicts — it was **wrong about most of what it flagged, and right about the two that mattered for a
reason it did not state**. Both real permission defects were reported as "world/group readable",
which is not the defect; the defect in each case is *what happens to a file that already exists*.

⇒ **An alert location is a lead, not a finding.** Every entry below was reproduced at its
`file:line` before promotion, per the register's standing rule. Triage was split across two
concurrent sessions and the delegate packets' verdicts were **overruled twice** — once in each
direction.

### 🔴 Finding 21 — rewriting the config keeps a permissive mode on the file holding the API key

`setup/core.py:211`. `_atomic_write` opens with `os.open(path, O_WRONLY|O_CREAT|O_TRUNC, mode)`.
**The mode argument applies only at creation**; POSIX ignores it when the file already exists, and
`os.open` reuses the same inode. So a `lynceus.yaml` that is already world-readable **stays
world-readable** and is then rewritten with the Kismet API key and the ntfy topic inside it.

```
ARM 1 fresh file    -> 0600            (the only case the existing tests cover)
ARM 2 pre-existing  -> before=0644 after=0644   (0600 was requested)
      world-readable = True    secrets in file = True
```

The docstring at `core.py:195-203` states the opposite in as many words — *"the file never exists on
disk with permissions broader than requested"*. That promise holds for a new file and is false for
every rewrite, which is the common case: `--reconfigure` rewrites.

🪤 **This was triaged as a false positive first, by me, and the docstring is why.** I read the
promise, confirmed `_atomic_write` was genuinely wired in at `core.py:524/533/566/1434` and
`cli/setup.py:786` rather than dead code, and concluded the hardening was real. It *is* real — for
the first call. **Confirming a guard is wired in says nothing about its second invocation.**
Found by session `e4288bb5` (packets W1-C and W1-D independently), reproduced independently here.

✅ **Fixed in PR #28** — `os.fchmod` on the **open descriptor**, before any content is written.
⛔ **It must stay `fchmod`-on-descriptor and must NOT be "simplified" to `os.chmod(path, mode)`.**
Two reasons: `O_TRUNC` has already emptied the file at that point, so the secret never exists on
disk under the broader bits; and a path-based `chmod` between the `open` and the `chmod` is
defeatable by a symlink swap, which an fd-based one is not.
⛔ **Not** the fix in Finding 22, which is its opposite. Both docstrings now carry that warning.

### 🔴 Finding 22 — a Kismet re-run silently widens an operator's own hardening

`cli/bootstrap_kismet.py:863`. `_atomic_write_bytes` writes a tmpfile, `chmod`s it, and
`os.replace`s it over the target — so the surviving inode is a **new** file carrying the *requested*
mode, discarding whatever the target had. Every rewrite resets the file to the `0o644` default.

`patch_kismet_site_conf` promises in its own docstring that operator customisations are *"preserved
verbatim"*. It preserves the **content** and drops the **permissions**. Kismet honours
`httpd_password=` in `kismet_site.conf`, so an operator who correctly hardened that file had it
widened by an unrelated `--add-source` run:

```
BEFORE: mode=0600  contains_secret=True
AFTER : mode=0644  contains_secret=True
```

⭐ **The two atomic writers need OPPOSITE fixes, and copy-pasting between them reintroduces the
other bug.** Finding 21's writer reuses the old inode → it must **enforce** the requested mode.
This one substitutes a new inode → it must **preserve** the old one.

🪤 **The delegate packet called this alert a false positive and was overruled by measurement.** Its
reasoning — the generated `kismet_site.conf` holds no *Lynceus* secret — was sound as far as it went,
and it even noted the exact mechanism before dismissing it: *"The patcher also preserves arbitrary
pre-existing content and resets the replacement to 0644."* The `httpd_password=` case settles it.

⚠️ **`cli/bootstrap_kismet.py` had no behavioural test of any kind** — 1,589 lines, zero references
to `patch_kismet_site_conf`, `_atomic_write_bytes` or `_atomic_write_text` anywhere under `tests/`.
That is how it survived. ✅ **Fixed in PR #25** (`8609fc9`), with the file's first tests. Both shapes
planted: no-preservation fails 4, hardcoded-`0o600` fails 5 — the second arm exists because that
"fix" would break the apt keyring and `sources.list`, which must stay world-readable.

### 🟡 Finding 23 — five URL guards could not fail on the defect they guard

`test_webui_evidence.py:104,141,400` and `test_ui_settings.py:185,310`, all checking a URL by
substring. A hostname is a right-anchored, dot-delimited hierarchy, so each was satisfiable by
appending a sub-domain. Repointing the alert-detail map link at
`https://www.openstreetmap.org.attacker.invalid/?mlat=...` left **all 17 tests in the evidence file
green**.

⭐ **Including the one whose entire job is the anchor's security attributes.**
`test_alert_detail_osm_link_opens_in_new_tab` located the anchor with a *prefix* search,
`body.find('href="https://www.openstreetmap.org')`, which the look-alike host also satisfies — so it
read `target`/`rel` off **the attacker's anchor** and reported the hijacked link as safe.

This is the same class as the `<script` vs `<SCRIPT>` hole CodeQL found in the CSP guards: a
completeness check blind in exactly the shape it exists to close. ✅ **Fixed in PR #26** — host
compared by equality on the parsed netloc, the validated anchor returned to the caller so attribute
checks cannot drift onto another element. Three shapes planted; previously-0 failures became 3, 2
and 1.

### ⬜ Finding 24 — WITHDRAWN on verification: the SSE traceback is behind a token gate

`setup/web/review.py:436-454, 879`. Promoted on the strength of the alert's location, with an
explicit unchased caveat — *"the setup routes appear token-scoped … but enforcement lives outside
the allowed files and could not be verified."* **Verified afterwards, and it inverts the finding:**

| Check | Result |
|---|---|
| Token gate exists? | `SetupTokenMiddleware` (`setup/web/auth.py:28`), `compare_digest` at `:70` |
| **Installed, or merely defined?** | **Installed** — `app.add_middleware(SetupTokenMiddleware, …)`, `setup/web/app.py:169` |
| Gates the SSE/apply route? | **Yes** — `TOKEN_EXEMPT_PATHS = ("/healthz", "/static")` only |
| Default bind | `127.0.0.1`; all-interfaces is supported, and the token still gates |

The traceback reaches **only a holder of the setup token** — the operator running first-run setup,
who already controls the whole configuration including the Kismet key and ntfy topic in flight. Four
tests pin it as intended. **A diagnostic feature, not a disclosure.**

⛔ **If anyone revisits this, do not "fix" it by deleting the traceback.** A wizard that says "Apply
failed" with no way to find out why, on a first-run flow possibly running as root, costs an operator
more than the traceback does. The useful version is "keep it, behind an explicit *show details*
toggle".

⭐ **Contrast with Finding 25, which is a difference in kind:** `/healthz.json` had **no**
authentication at all — loopback was the only control and `ui_allow_remote` removes it. That is why
25 was fixed and this one was withdrawn.

### 🟡 Finding 25 — a raw DB driver error is returned in an unauthenticated 503

`webui/app.py:1270` → `:1546-1552`. The `# noqa: BLE001 — surface the actual driver error` is
deliberate, but `/healthz.json` is unauthenticated and remote-reachable once `ui_allow_remote` is
set. Interacts with the standing no-auth finding. Recorded, not fixed. Found by session `e4288bb5`.

### Refuted — do not re-report these without new evidence

- **All 10 `py/clear-text-logging-sensitive-data` alerts.** `cli/setup.py:938-944` prints
  `_redact_kismet_api_key(token)`, which returns `***` under 12 chars and `first4...last4`
  otherwise — the raw token never reaches a `print`. The five `kismet.py` sites log **MAC addresses
  and datasource UUIDs**, which are this product's domain data, stored by design in the database at
  equal protection. `scripts/rebump_dev_fixture.py:123` is a dev-fixture dry-run table.
- **13 `py/log-injection` + 6 `py/url-redirection` in `webui/app.py`** — typed `int` path params
  logged with `%d`, MACs gated through `normalize_mac`, `%r` escaping CR/LF, and origin-relative
  `Location` headers with an allowlisted `rule_type`.
- **`py/stack-trace-exposure` at `app.py:1568`** — unreachable via a correlated early return at
  `:1546` that CodeQL did not model.
- **`py/overly-permissive-file` ×3 in `setup/core.py` at `:238`/`:277`** — `0640`/`0750` are the
  deliberate `root:lynceus` ownership split, *tighter* than the umask default. (`:211` is Finding
  21 and is real — same file, different line, opposite verdict.)
- **`py/overly-permissive-file` ×4 under `tests/`** — `0o777` is the **default parameter of a spy
  function** capturing which mode the real code requested; the tests then assert the real value
  (`0o600`/`0o640`) immediately after.
- **`py/jinja2/autoescape-false` at `test_webui.py:3414`** — a bare `Environment()` used only to
  test filter *selection*. `_device_label` returns a plain `str`, never `Markup`, and production
  renders through `Jinja2Templates` (`app.py:1437`), which enables autoescape.
- **`py/clear-text-storage-sensitive-data` at `core.py:209`** — ⚠️ **not refuted; reclassified as a
  Windows-only design item.** On POSIX the control is the `0600` mode, and that control is exactly
  what Finding 21's fix restores. But the alert sits on the **Windows branch** (`path.write_text`),
  where there are no mode bits at all and access is governed by the parent directory's inherited
  DACL — which this code never constrains. So "cleartext by design" is true on POSIX and overstated
  on Windows. **Not a patch: it needs DPAPI or an explicit DACL.** Tracked, not fixed.
- **`test_redact.py:264`** — flagged weak by a delegate; **left unpromoted because no one could
  construct a defect that slips past it** while its sibling `assert "user:pass" not in redacted`
  holds. Unproven is not the same as refuted, and it is recorded as unproven.

### ⛔ Correction — a claim in both 2026-08-14 handoffs is false

Both `HANDOFF_2026-08-14_HARDENING_AND_CI.md` (§5.2) and `HANDOFF_2026-08-14_ORCHESTRATION_PLAN.md`
(§2) assert, with a ⭐, that *"the two biggest high-severity buckets independently corroborate Wave 5
leads … the DEBUG ntfy-topic leak (`notify.py:172-174`)"*.

**CodeQL has zero `clear-text-logging` alerts in `notify.py`** — its only alert there is one
`py/ineffectual-statement` at `:36`. Every logger call that **interpolates the URL** uses
`safe_url = redact_topic_in_url(url)` (`:172`, `:180`). ⭐ **The leak is not an interpolated URL at
all**: `:174` passes no URL and leaks the raw topic through the urllib3 traceback that
`exc_info=True` renders. (Saying "every logger call is redacted" would be false and would make this
finding look self-contradictory — there are four calls and two pass no URL.) The
`overly-permissive-file` half of the claim is sound; the clear-text-logging half corroborates
nothing.

The underlying lead is nevertheless **real as behaviour and deliberate as design**. Measured:

```
[WARNING] raw topic in log? -> False   detail='ConnectionError (http://127.0.0.1:9/my-s•••23)'
[DEBUG  ] raw topic in log? -> True    via the urllib3 traceback, not the logger.debug message
```

`notify.py:121-125` predicts exactly this in a comment and calls it an intentional tradeoff. ⇒ It is
**a decision for the maintainer about whether that tradeoff is right**, not a defect to quietly
patch, and it must not be re-reported as a new CodeQL finding.

⚠️ **Four claims in this wave were wrong the same way, in both directions**, which is why it gets a
rule rather than four separate notes:

| Claim | Direction of the error |
|---|---|
| Handoff: "clear-text-logging corroborates the `notify.py` leak" | overstated — CodeQL flagged nothing there |
| My triage: "`setup/core.py` is already hardened" | understated — I read the docstring, not the rewrite path |
| Packet W1-C: "`bootstrap_kismet:863` is a false positive" | understated — it named the mechanism and dismissed it |
| Finding 24: "SSE traceback is a disclosure" | overstated — the route is behind an installed token gate |

⭐ **A plant that does not plant produces a passing suite that reads as proof. Four ways, all seen
here on 2026-08-14:**

| Failure | What catches it |
|---|---|
| plant breaks the file → pytest errors at collection, prints nothing | `ast.parse` the file after planting |
| plant's anchor never matches → nothing changes | assert the anchor EXISTS before replacing |
| plant hits a comment or the wrong occurrence | assert the anchor is **unique**, not merely present |
| restore leaves a stray file behind | verify the tree is CLEAN, not merely that tests went green |

All four end in a green run. The third was found by planting `replace("return", ...)` into a block
whose first literal `return` was inside the comment *"Kismet returns nothing"* — `ast.parse` passed,
the tests passed, and it was one step from being reported as evidence a guard was weak.

⭐ **An alert tells you where a value FLOWS. It never tells you who can REACH it.** Check the gate
before grading the finding. This cuts both ways: an unwired guard overstates safety, and an
unchecked gate overstates severity. Confirming a helper is wired in says nothing about its *second*
invocation, and confirming a value reaches a sink says nothing about *who* can stand at that sink.

## Round 8 — asserted guarantees, audited against the code, 2026-08-15

**Class:** *a comment or docstring that asserts a guarantee the code does not provide.*

Chosen because this project's failure record is overwhelmingly **prose, not logic**: a 12-day-stale
baseline in `.claude/gates.md`; a README test figure that rotted three times; `BACKLOG.md` naming
the wrong casualty column; **54% of the diagnostics' `file:line` citations rotted**; a green test in
`test_rules.py` asserting a false belief; and B5's own defending comment — *"a missed cleanup never
affects correctness"* — false for the case that mattered.

**Method.** MiniMax-M3 mechanically extracted every comment/docstring containing a guarantee word
(`never`, `always`, `cannot`, `guaranteed`, `impossible`, `must not`) together with the code it
governs — **165 records across 11 modules**. Three `gpt-5.6-sol` packets then adjudicated them at
high effort. **22 came back FALSE.** Every one was re-derived from the code before being recorded.

### 🔴 Finding 27 — the heartbeat claims health it has not verified

`poller._compose_heartbeat`. Its own docstring states the invariant:

> ⛔ *"The one invariant that matters: **this must never claim health it has not verified.** A
> heartbeat that says 'all good' while ingest is dead is strictly worse than no heartbeat at all."*

Measured:

```
devices admitted this tick          : 0
devices dropped by source allowlist : 412
devices stored in the DB            : 0
→ heartbeat healthy?                : True
→ message : "Still watching. 0 device sighting(s) in the last 24h, no alerts yet."
```

⭐ **That is the exact message a genuinely quiet environment produces.** The operator cannot
distinguish *"nothing is out there"* from *"my source allowlist matches none of Kismet's sources and
I am blind"* — the precise ambiguity the heartbeat exists to remove.

⭐ **The evidence is already recorded and simply not read.** The poller writes
`LAST_TICK_ADMITTED`, `DROPPED_SOURCE_ALLOWLIST`, `DROPPED_MIN_RSSI` and `DROPPED_UNPARSEABLE` every
tick; `_compose_heartbeat` reads only `LAST_TICK_COMPLETED_AT` and `WATERMARK_HOLDS`. The fix is a
clause, not a feature.

⚠️ **The threshold is a judgement, not a lookup.** `admitted == 0` alone must stay healthy — a quiet
RF environment is the normal case and flagging it trains the operator to ignore the channel. But
`admitted == 0 AND dropped_source_allowlist > 0` is not quiet: it is Kismet reporting devices the
config is discarding. ⛔ **Reported, not fixed** — `poller.py` was in flight in another session.

### 🟡 Finding 28 — a stale reason in `config.py`

`config.py:73` stated *"``sightings`` has no retention policy and is never pruned"* as the reason
`window_days` bounds the co-observation scan. True when written; false since opt-in retention
shipped. The bound is still needed — retention defaults to **off** — but an operator who *had*
enabled it was being told something false about their own install. ✅ Fixed here.

### Refuted on re-derivation — the adjudicator was wrong

- **`rules.py:515` and `:565`** — reported as: a non-string YAML key (`pattern_overrides: {123: high}`)
  reaches `raw_key.strip()` and raises `AttributeError`, disabling the whole severity layer.
  **False.** An `isinstance(raw_key, str)` guard sits four lines above the `.strip()`; all three
  malformed shapes (int, null, in both `pattern_overrides` and `vendor_severity`) log a warning and
  drop only that entry, exactly as the docstring promises. The adjudicator read the `.strip()` and
  missed the guard above it.
- **`notify.py:127`** — the DEBUG traceback topic leak is real but already recorded as a **deliberate
  tradeoff** (Wave 7 correction). Not a new finding.

⇒ **2 of 22 FALSE verdicts overturned on re-derivation, both downward.** Consistent with this
project's standing rule: *delegates' `file:line` citations hold up; their verdicts do not.*

### ⛔ Coverage limit

The instrument finds **asserted** guarantees — a guarantee word in a comment or docstring in
`src/*.py`. It does **not** see: a guarantee implied by a function's name or type signature;
guarantees stated in `docs/`, templates, or `README.md`; or a promise made only in a commit message.
**Absence of further findings is not proof of correctness.**

### DO-NOT-RE-AUDIT (round 8)

`retention.py`, `evidence.py`, `patterns.py`, `config.py`, `bridges/ble.py`, `allowlist.py`,
`notify.py`, `rules.py` and `kismet.py` have had every asserted guarantee adjudicated. `poller.py`
and `db.py` were adjudicated but carry **unfixed** findings — see Finding 27 and the list reported
to the `poller.py` owner on the session board.

## Round 9 — state-advancing writes, 2026-08-15

**Class:** *a write that advances persistent state using a value the code has not validated, or has
elsewhere decided not to trust.* The sibling of round 7's *"deletes a right one"* — this is
**"writes a wrong one"**. Class proposed by session `e4288bb5` from `record_watchful_sighting`, and
picked by Kev.

**Method.** MiniMax-M3 extracted **74 write sites** across `poller.py`, `db.py` and five leaf
modules, recording for each the value written, its provenance traced back through the file, and any
validation it passes. Three `gpt-5.6-sol` packets then adjudicated. **~30 came back PERMANENT.**

⛔ **Most did not survive re-derivation, and the fault is in my instrument, not their reasoning.**
The bulk of the PERMANENT verdicts are of the form *"if a caller passes `alert_id=True`,
`now_ts=0`, or `severity='critical'`, the database stores garbage"* — **API misuse, not a reachable
defect**, because no caller does that. I asked "what value **can** be written" and was correctly
answered with hypothetical callers. ⇒ **The question that separates a finding from a theory is
"what does a caller actually pass", and the extraction has to carry that or the adjudication cannot
know it.**

### 🔴 Finding 29 — `obs.last_seen` is bounded below, not above, and is written into `sightings.ts`

`DeviceObservation` carries a `first_seen` validator (`must be > 0`) and **no `last_seen`
validator**. Measured against the real parser:

```
last_time = 0, -5, 1     -> REJECTED
last_time = 4102444800   -> ACCEPTED   (year 2100)
```

`poller.py:321` passes `ts=obs.last_seen` straight into `insert_sighting`. Measured end to end:

```
sightings stored   : [1696544000, 4102444800]
30-day prune       : deleted=1, remaining=[4102444800]
'seen in last 24h' : 1
```

⇒ **The prune deleted the legitimate 40-day-old row and kept the bogus one.** A capture source with
a corrupt clock writes a sighting that is **immune to retention forever** *and* **counts as "seen in
the last 24 hours"**, because a future timestamp satisfies every recent-window query. The
co-observation corpus is contaminated the same way.

⛔ **Reported, not fixed.** The complete bound needs a clock to compare against, and the only layer
holding one is `poller.process_observation` (it already has `now_ts`). `kismet.py` could add a
static absurdity ceiling, but that catches only gross corruption — a source one year fast still
passes. The real check is `obs.last_seen <= now_ts + skew`, in `poller.py`, which was another
session's file for the duration of this round.

### Refuted on re-derivation

- **Watermark poisoning via `last_seen = 0`** — reported as: a failed observation with `last_seen=0`
  makes `watermark = min(now_ts, 0-1) = -1`, replaying the entire source history every tick. The
  arithmetic is correct **and the state is unreachable**: `last_time` values of `0`, `-5` and `1` are
  all rejected at parse. Refuted.
- **~25 further PERMANENT verdicts** — unreachable API-misuse shapes, as above.

⇒ **The findings that survived are exactly the ones driven by EXTERNAL or UNTRUSTED input** —
Kismet's `last_time`, and the wall clock. That is the class working as intended, and it is the
filter to apply first in the next round of this shape.

### ⛔ Coverage limit

⛔ **CORRECTION — this round's stated coverage was broader than its actual coverage.**
The text below originally read "in `src/lynceus/*.py`". **It was not.** The extraction packets were
given seven files — `poller.py`, `db.py`, `rules.py`, `allowlist.py`, `evidence.py`, `retention.py`,
`bridges/ble.py` — and **`webui/app.py` was never among them.** Round 7 did cover it; round 9 did
not, and the register claimed otherwise.

⇒ **That omission hid a real finding, and another session found it afterwards:**
`webui/app.py:3953` computes `expires_at = int(time.time()) + duration_seconds` — an **absolute
deadline from a completely ungated clock**. The web UI is a *separate process* from the poller and
contains **zero** references to `clock_trusted`, `ClockAnchor`, or any clock-trust notion. Measured:
an operator clicking "snooze 24h" while the host clock is +91 days wrong gets a snooze that lasts
**~92 days** — still silenced at +1h, +25h and +30d, resuming only at +92d.

⚠️ **And it is unreachable from every fix shipped in rounds 7–9**, all of which live in `poller.py`,
`retention.py`, `evidence.py` or `allowlist.py`. **A fix confined to the poller cannot close a write
performed by the web process.** Any future sweep of clock exposure must include `webui/`.

⇒ **The lesson is about the register, not the bug: a coverage limit is a claim, and it has to be
derived from what the instrument was actually pointed at — not from what it was named.** I wrote
"`src/lynceus/*.py`" from the class description rather than from the packet list, and the file that
was missing is the one that held the finding.

The instrument enumerated `INSERT INTO` / `UPDATE ... SET` / `set_state(` and `record_*`/`mark_*`/
`add_*`/`update_*` calls in **the seven files listed above only**. It does **not** see: a write performed through a
helper whose name hides it; a value corrupted before it reaches the write; writes in
`migrations/*.sql`; or **whether a hypothetical bad caller exists**, which is precisely the gap that
inflated the PERMANENT count. **Absence of further findings is not proof of correctness.**

### DO-NOT-RE-AUDIT (round 9)

`allowlist.py`, `evidence.py`, `retention.py` and `bridges/ble.py` had every state-advancing write
adjudicated and are clean for this class — the prune watermarks self-correct because a negative
elapsed is treated as due (#39), and the BLE buffer is not persistent. `poller.py` and `db.py` were
adjudicated but carry **Finding 29 unfixed**.

### 🔴 Finding 30 — the notifier has no TOTAL deadline, and a slow server blinds the tool

⚠️ **Threat-model finding, not merely robustness.** Raised as *"`notifier.send()` can hang, and
`except` cannot see it"*. **That stated mechanism is refuted** — `notify.py:165` passes
`timeout=self.timeout`, `requests` raises `Timeout`, and `:171` converts it to `False`:

```
STALLING  server (accepts, sends nothing) -> returned False after  3.0s   (timeout=3.0)
```

**But the instinct was right for a different reason.** `requests`' timeout is a **per-socket-read**
timeout, not a total deadline. Against a server that sends a valid 42-byte response one byte at a
time:

```
DRIBBLING server -> returned True after 58.5s   (20x the configured timeout)
```

⛔ **It returned `True`.** Not a timeout, not an error — a *successful delivery* that consumed 20×
its budget while the poll loop blocked for all of it. At the shipped 10s default the ceiling is
roughly `response_bytes × 10s` per call.

⭐ **Why this is worse here than a generic slowloris.** The operator points lynceus at an ntfy
server — often public, sometimes across a network someone else controls. **Anyone who can influence
or MITM that endpoint can stall the detection loop and blind the tool, while every log line and
every heartbeat reports successful delivery.** For a counter-surveillance tool, *"the channel that
tells you you are being followed can be silently slowed by whoever you are telling"* is a threat
model question.

⛔ **Unclaimed and deliberately unfixed — this needs Kev.** `requests` offers no total deadline, so
a real fix means a watchdog thread, a custom adapter, or moving the send off the poll thread. That
is a change to the notifier's contract, and picking the shape is a design decision rather than a
patch. Found by session `e4288bb5`; reproduced independently here before recording.

⇒ **The method lesson, which outranks the finding: refuting the stated MECHANISM is not the same as
clearing the CONCERN.** The adjudicator's reasoning was wrong and its instinct was right. Stopping
at *"timeout present, refuted, next"* would have missed a 20× overrun that reports success.

### ⭐ Round 9's instrument, reframed — keep this over the round's findings

Round 9 asked **"what value CAN be written"** and got ~30 PERMANENT verdicts, most of them
unreachable API-misuse (*"if a caller passes `alert_id=True`…"*). The survivors were, without
exception, the sites fed by **external or untrusted input** — Kismet's `last_time`, and the wall
clock.

⇒ **The question that would have found them directly is: *"which writes are driven by a value that
crossed a trust boundary?"*** — not *"which writes could store garbage"*. Same sweep, a fraction of
the noise. Use this framing for the next round of this shape.

## Round 10 — features that are configured but not connected, 2026-08-15

**The class:** a surface the operator can *use* — a form, a CLI flag, a config type — whose value
never reaches the code that would act on it. Not "wrong result": **no result**, silently, with the
write path reporting success.

**The instrument:** for each value the operator can store, store one and drive the real evaluation
path with an input that matches it exactly. ⭐ **Not a grep.** Every finding here is a behaviour two
or three layers from where the value is written, and no static search would have connected them.

⛔ **Coverage limit:** this swept the **watchlist** only. The allowlist, severity overrides, the
snooze/watchful surfaces and the wizard have the same shape — a stored value that some later layer
has to honour — and are **not** covered. Absence of a finding there is absence of a sweep.

### 🔴 Finding 31 — a `mac_range` watchlist row was stored, reported inserted, and could never match

Fixed in **PR #84**. `_lookup_mac_range_matches` reads the migration-011 partial index on
`(mac_range_prefix_length, mac_range_prefix)` and never looks at `pattern`. Only the Argus importer
populated those columns, so rows from the other two write paths were inert.

Measured with `argus_mac_range` **enabled**, so the ruleset was not the variable:

```
add_watchlist("3c:5a:b4:d/28")          prefix=None      -> *** NO ALERT ***
same row + derived columns populated    prefix=3c5ab4d   ->     ALERT
```

⭐ Reachable through a shipped CLI, which confirms the write in its own log line:

```
INFO: inserted mac_range/3c:5a:b4:d/28 (high)
row: pattern='3c:5a:b4:d/28' mac_range_prefix=None mac_range_prefix_length=None
```

**Direction: fails OPEN.** The operator is told they are being watched over and they are not.

⭐ **Keep this one for the shape, not the bug: two writers, one reader, and they disagreed about
which column carries the meaning.** `add_watchlist` and the seeder each had their own byte-for-byte
`INSERT`; the importer had a third that was correct. The evidence was in the seeder's own INFO line
the entire time and nobody read it as a defect.

### 🟡 Finding 32 — seven of ten watchlist pattern types produce no alert

**Not fixed — reserved for Kev, see below.** Pinned by
`tests/test_watchlist_pattern_types_are_wired.py` (#84), which fails in both directions.

| pattern_type | alerts? | why |
|---|---|---|
| `mac`, `ssid`, `ssid_pattern` | ✅ | `argus_mac` / `argus_ssid` ship enabled with `patterns: []` |
| `oui`, `ble_uuid`, `ble_local_name`, `ble_manufacturer_id`, `drone_id_prefix`, `mac_range` | ❌ | the delegating rule ships **commented out** |
| `imei_tac` | ❌ | **no `DeviceObservation` field exists at all** |

**Mechanism:** a rule consults the operator's SQLite watchlist only when its `patterns:` list is
EMPTY. A non-empty list disables DB delegation for that rule_type entirely — which is why
`watchlist_oui` *looks* present: `hak5_pineapple_oui` carries an inline `patterns: ["00:13:37"]`.

⭐ **The codebase already names this bug.** `config/rules.yaml:95`, explaining why exact-MAC
delegation was turned on: *"The promise protected a behaviour nobody wants — a watchlist that does
not watch."* Fixed for the exact-MAC case only.

⚠️ **`imei_tac` is a different class and no ruleset change can revive it.** Migration 021 admits it
and `add_watchlist` accepts it, but there is nothing on the observation to compare it against. It
needs capture-side work first.

### ⭐ Verify the CONTROL, not just the treatment — the round's real lesson

**Three invalid control values between two sessions in one morning, and every one produced a
confident finding rather than an obvious error:**

| Control used | Why it was invalid | What it "proved" |
|---|---|---|
| `de:ad:be` as an ordinary OUI | `0xDE` has the locally-administered bit set | "DB-delegated OUI matching is broken outright" |
| `aa:bb:cc` as an ordinary OUI | `0xAA` likewise | same, independently |
| `MyTarget*` as an ssid_pattern | it is a **substring needle**, not a glob — the `*` is literal | "`ssid_pattern` is a dead type" |

⇒ **A broken treatment case fails loudly; a broken control case fabricates a result.** Assert the
control behaves as a control before trusting the contrast — if the should-match case does not match,
the experiment is void, not informative. `ac:de:48` is the genuine universally-administered control.

### ⭐ When you derive a set, ITERATE over it — never transcribe it into cases

The round's count was first reported as "6 of 9" for what is **7 of 10**. The list of storable types
had been derived correctly from source and then **hand-copied into nine test cases**; the dropped
element was `imei_tac`, the one dead in the most interesting way.

⇒ A derived enumeration that is then transcribed has all the fragility of a hardcoded list and
**none of its visibility** — it *looks* derived. `CASES` in
`test_watchlist_pattern_types_are_wired.py` is such a transcription; it is safe only because
`test_the_admitted_types_are_exactly_the_ones_we_have_classified` parses the live CHECK constraint
and fails when the two diverge. That guard is what makes a transcription legitimate.

### DO-NOT-RE-AUDIT (round 10)

- **`ssid` / `ssid_pattern` / `mac` watchlist delivery** — measured alerting end to end, 2026-08-15.
- **`ssid_pattern` semantics** — substring, case-insensitive, `? LIKE '%'||pattern||'%'`. Not a glob.
  Do not re-report it as dead without checking the needle.
- **`mac_range` write path** — fixed and guarded (#84). The `/24` shape is rejected *on purpose*.
- **The `PROBE_SSIDS_PER_DEVICE_CAP` count cap** — already present; length is the unbounded axis.

## Round 11 — the connectivity class, finished: allowlist, severity overrides, notify, 2026-08-15

**Round 10's class**, swept over the three surfaces round 10 named as uncovered. Same instrument: for
each value the operator can store, **store one and drive the real path with an input that matches it
exactly.** Not a grep — every result below is a behaviour two or three layers from the write site.

⭐ **Round 10 asked whether a stored value produces a result. This round asks the mirror question:
whether a stored SUPPRESSION actually suppresses.** The two fail in opposite directions and only one
of them is eventually visible. A dead alert is noticed the day something happens and nobody was
warned. A dead suppression is never noticed at all — the operator is warned too often, concludes the
tool is noisy, and stops reading it.

### ✅ Measured and NOT broken

Recorded explicitly, because "we found nothing" is worthless without saying what was looked at.

| Surface | Instrument | Result |
|---|---|---|
| all **8** storable allowlist `pattern_type`s | store one, observe a device matching it exactly, drive `process_observation` | every type matches and suppresses — **no dead type** |
| all **11** `RuleType`s × all **5** runtime override keys | seed a watchlist row + metadata, drive `evaluate` with an override that would apply | all **8** delegation branches honour all 5; the 3 non-delegating types honour none |
| every `Severity` → `notify` | `SEVERITY_TO_PRIORITY` / `SEVERITY_TO_TAGS` against the `Severity` Literal | complete, distinct, correctly ordered |

⇒ **The allowlist is not a second Finding 32.** That was this round's leading hypothesis, and it is
refuted by measurement for all eight types.

### 🔴 Finding 33 — an explicit `mac` allowlist entry is silently defeated by an unrelated soft entry above it

**Fixed in this change.** `Allowlist.is_allowed` returned the **first** matching entry. Since the
hard/soft split (#82), the returned entry's `pattern_type` is what decides whether suppression
happens at all — `process_observation` asks `is_soft_attribute` about *that one entry*. So a SOFT
entry sitting earlier in the file answered for a device the operator had explicitly allowlisted by
MAC.

Measured on the shipped ruleset. One device, one watchlist row, the same two allowlist entries;
**only the file ORDER differs:**

```
hard `mac` entry only                 -> suppressed,  0 sent
hard `mac` first, then soft `name`    -> suppressed,  0 sent
soft `name` first, then hard `mac`    -> *** 2 ALERTS, 2 SENT ***
```

**Direction: fails NOISY.** The operator wrote "ignore this MAC", kept getting paged, and nothing in
the UI, the logs or the file hints that position matters.

⭐ **The prose is why nobody looked.** `allowlist.py`'s module docstring asserted the opposite —
*"Order does not affect matching semantics … the only entry field that matters for suppression is
the pattern itself."* True when written; falsified by #82 **three days earlier**, which made
`pattern_type` the deciding field and never revisited the sentence saying it could not be.

**Fix:** a HARD match outranks a SOFT one regardless of position; position still breaks ties WITHIN a
class, so the `expires_at` the audit line reports is unchanged for soft-only allowlists. ⚠️ Expiry is
applied FIRST — an expired hard entry must not out-rank a live soft one, which is the same defect
pointing the other way and strictly worse.

Guarded by `tests/test_allowlist_match_precedence.py`, which sweeps the derived soft × hard
cross-product rather than one example pair. Proven against four planted defects — the original plus
three distinct over-corrections (hard-only; preference-before-expiry; any-hard-entry-regardless-of-
match) — each failing and naming its own invariant.

### 🟡 Finding 34 — `evaluate`'s docstring understated override coverage by three rule_types

**Fixed (prose).** It said *"Only the five DB-delegation branches consult it"*. Measured: **eight**
do — every `watchlist_*` type plus `ble_uuid`. Wrong since the `ble_manufacturer_id` /
`drone_id_prefix` / `ble_local_name` branches landed.

⚠️ **Understating coverage is not the harmless direction.** An operator reading it concludes their
overrides are dead for three of the types they configured, and the obvious response is to go and
"wire up" branches that were never disconnected. **No grep would have caught this** — all eight call
sites were present and correct. Only running them shows which ones bite. Now measured rather than
asserted, by `tests/test_severity_paths_are_wired.py`.

### 🟡 Finding 35 — the allowlist cannot express `ssid_pattern`, and its own comment promised it could

**Prose fixed; the capability is a decision — see "Reserved for Kev".**

`AllowlistPatternType` admits 8 types. Its comment claimed it *"Mirrors the seven delegation
rule_types the watchlist supports so an operator can express suppression in any shape the watchlist
alerts on"*, and that the matchers *"pair 1:1 with `rules.evaluate`'s `watchlist_*` branches — drift
between the two surfaces silently allows an alert to fire that an operator believed they had
allowlisted."*

| Claim | Measured |
|---|---|
| "the seven delegation rule_types" | there are **eight** |
| "any shape the watchlist alerts on" | `ssid_pattern` is REJECTED — and it is one of only **three** watchlist types that fire today (Finding 32) |
| "pair 1:1 with `rules.evaluate`'s branches" | `ssid_pattern` dispatches under `watchlist_ssid` with no allowlist counterpart |

⇒ **The comment named the exact failure mode the codebase then exhibited.** An operator running the
shipped `argus_ssid` rule against the bundled `ssid_pattern` rows cannot express the matching
suppression — only an exact `ssid` or a `mac`, which silence one device rather than the class they
watched on. `imei_tac` is also absent but harmless: dead on both sides.

Pinned by `tests/test_allowlist_watchlist_type_parity.py`, which parses the live CHECK constraint so
the gap can neither widen nor close silently.

### ⭐ The round's real lesson — a fix can falsify prose three files away

#82 turned `pattern_type` from a field that did not affect suppression into **the field that decides
it**. Every sentence written before that describing `pattern_type` as inert became false, and nothing
failed, because comments do not have tests. Two of this round's three findings are exactly that
shape, and in Finding 33 the stale sentence was the single strongest reason not to look.

⇒ **When a change makes a field load-bearing, grep for the prose that says it isn't.** Round 9's
"prose, not code, is often the defect" generalises: the dangerous prose is not the wrong sentence, it
is the sentence that was *right* and quietly stopped being.

### ⛔ Coverage limit (round 11)

- **Swept:** the allowlist's 8 storable types end to end; all 11 `RuleType`s against all 5 runtime
  override keys; the `Severity` → notify maps.
- **NOT swept:** the snooze / watchful surfaces; the wizard's written values; `poller.py`'s gates
  beyond the allowlist branch; the UI's allowlist write path (session 2's write set); whether the
  primary allowlist file's YAML round-trip preserves types under hand-editing.
- ✅ **"the wizard's written values" is no longer uncovered** — session 3 swept it the same afternoon
  and found Finding 36 below. Kept in this list so the two entries do not disagree about what was
  looked at.
- ⚠️ **Measured against the SHIPPED `config/rules.yaml`.** Seven of ten watchlist types are dead by
  configuration (Finding 32), so a suppression for one of those has nothing to suppress in a default
  deployment. Every result above holds for the rules that actually fire.
- ⚠️ **In-memory rule paths are out of scope for overrides by construction** — an override keys on
  the matched watchlist row's category / vendor / `argus_record_id`, and an in-memory match resolves
  no row.
- ⚠️ **A soft allowlist match that is overridden by a watchlist hit also stops suppressing the
  ambient `new_non_randomized_device` notice.** Measured, and judged to MATCH the documented contract
  (*"Only an explicit watchlist hit overrides it"*) rather than to violate it. Recorded so the next
  sweep does not re-derive it as a finding.

### DO-NOT-RE-AUDIT (round 11)

- **Allowlist per-type suppression** — all 8 storable types measured end to end, 2026-08-15. No dead
  type. Do not re-report the allowlist as a mirror of Finding 32.
- **Runtime severity overrides per rule_type** — all 8 delegation branches × all 5 keys measured.
  `new_non_randomized_device` and `ble_device_class` ignoring overrides is **inherent** (they match
  no watchlist row), not a gap to close.
- **`notify.py` severity routing** — three severities, complete priority and tag maps, one channel.
  There is **no configurable minimum-severity filter**, so there is none to be disconnected. Do not
  go looking for one.
- **`SOFT_ALLOWLIST_PATTERN_TYPES` naming `ssid_pattern` and `imei_tac`** — deliberate, not drift.
  The classification covers the WATCHLIST's ten types so a future allowlist type cannot inherit hard
  suppressing power silently; `AllowlistPatternType` is the eight an operator can actually write.
- **CLI flags that are declared and never read** — all **54** `add_argument` flags across the 7
  `cli/` modules derived and checked, 2026-08-15. The 8 hits are all refuted (see Finding 38's method
  note): 4 × `action="version"`, 2 self-declared no-ops, 1 documented deprecation, and `--user`,
  whose dangerous case is refused by name. ⛔ **Do not re-run the static scan and report "clean" —
  it is blind to this class.** The flag in every real instance IS read; the behavioural pass is the
  one that finds things.

### 🔴 Finding 36 — `lynceus-setup --reconfigure` silently reverted 29 of 40 hand-edited settings

**Found and fixed by session 3 in PR #87 (`08299cc`); registered here, and the numbers below are an
INDEPENDENT reproduction, not a transcription of the PR.** Same class as rounds 10 and 11, pointing a
third way: rounds 10/11 asked whether a stored value reaches the code that acts on it, and this asks
whether a stored value **survives another operator-facing path**.

**Mechanism:** `--reconfigure` was a blind overwrite. `preflight_existing` gated only on whether the
file existed; nothing ever read the old one back. The wizard collects **10** answers and writes a
config carrying **40** settings, so every field the operator hand-edited was reset to its default
while the wizard reported success.

⭐ **Three separate surfaces offer hand-editing and `--reconfigure` as equivalent** — the generated
`lynceus.yaml` header, `preflight_existing`'s message, and the wizard's closing text — and one of
them destroyed the other's work.

**Measured** by seeding a non-default value for all 40 flattened settings and rotating only
`kismet_api_key` — the smallest plausible reason to re-run the wizard:

| | survived | lost |
|---|---|---|
| before (`350035a`) | 11 | **29** |
| after (`08299cc`) | **37** | 3 |

⚠️ **The three that remain are exactly the registered decision below, not a residual defect:**
`allowlist_path`, `db_path`, `severity_overrides_path`.

Worst individual losses: `heartbeat_enabled` True→False — **the dead-man's switch, off** — and
`ntfy_auth_token` dropped while `ntfy_url`/`ntfy_topic` survived, leaving a config that still
validates, still looks complete, and delivers nothing to an authenticated server.

⭐ **`ui_bind_port` was the sharpest case.** It was rendered from `DEFAULT_UI_PORT`, a **module
constant**, never from any wizard answer — so it was the one setting that *looked* operator-supplied
and was silently reset on every run.

**Fix:** carry forward every key the renderer does not emit, with the renderer-owned set **derived by
parsing the renderer's own output** rather than transcribed. Proven with five planted defects.

### 🔴 …and that fix introduced a regression, which this entry claimed for hours it had not

⛔ **`Config` sets `extra="forbid"`, so carrying an UNRECOGNISED key forward verbatim makes the
config fail to LOAD.** Found by a `gpt-5.6-sol` red-team of #87 and #90, fixed in **PR #96**
(`f0e6e9b`). Re-measured here rather than taken on report — one transposed letter,
`heartbeat_interal_hours`:

| | typo survives `--reconfigure`? | daemon starts? |
|---|---|---|
| at `08299cc` (post-#87) | **yes** | **NO** — `ValidationError` |
| at `f0e6e9b` (#96) | no, dropped and named | yes |

⇒ **Re-running setup is exactly what an operator does to RECOVER from a typo**, and #87 had quietly
made it the thing that *preserved* one. Carry-forward is now filtered to `Config.model_fields`, with
dropped keys named in the step message — a key removed silently is a typo the operator cannot find.

### 🪤 Why the original measurement could not have caught it — a limit of a DERIVED fixture

The 40-field sweep above seeded a non-default value for every field **derived from
`Config.model_fields`** — correctly, per "iterate the derived set, never transcribe it". ⇒ **That is
precisely why the fixture could never contain an unrecognised key.** The derivation that made the
sweep complete over known fields made it structurally blind to unknown ones, and it was reported as
"37 survived / 3 lost, residual fully accounted for" with no caveat.

⇒ **A derived fixture inherits the boundaries of whatever it derives from.** `Config.model_fields`
answers *"what settings exist"*; the code faces *"what might an operator's file contain"*, and
`extra="forbid"` is the seam where those diverge — the defect lived exactly in the gap. This does not
retract the iterate-don't-transcribe rule; it bounds it: **derive the set, then add a case from
outside what the source can express** — an unknown key, an extra column, a wrong-typed value.

⚠️ Two independent measurements of this finding also disagreed (13/27 vs 11/29) before agreeing —
see the note below. **Both the count and the coverage were qualified only after someone else
attacked the change.**

⛔ **Open, deliberately not fixed in #87 — a decision, not a patch.** `allowlist_path`,
`severity_overrides_path` and `db_path` are `apply_config` **arguments**, and both callers derive
them from `paths.default_*_path(scope)` rather than from the operator's config. An operator who
relocated their allowlist is repointed at a freshly scaffolded **EMPTY** one, so every device they
had suppressed starts alerting again. Coherent (`apply_config` scaffolds those files) but not
harmless. See "Reserved for Kev".

### ⚠️ Two sessions measured this and got different numbers — the method is the finding

Session 3's board reports **13 survived / 27 lost**; this independent run reports **11 / 29**. The
gap is entirely in how the three `apply_config` path arguments are counted — the very fields that are
the open decision above. Neither count is wrong; they answer slightly different questions.

⇒ **A count of "settings lost" is not a fact until the universe is stated.** Recorded because the
same trap bit twice in one afternoon in the other direction too: `Config.model_fields` is **33**, and
the correct universe for "settings an operator can write" is the **40** you get by flattening the
three sub-models (`capture`, `ble_bridge`, `co_observation`) one level. Reading 33 and disbelieving
40 was the first reaction here and it was wrong. **Publish the universe beside the number.**

### 🔴 Finding 37 — half the bundled OUI corpus lands in the watchlist and can never fire

**Measured 2026-08-15 while adopting PR #86.** Not fixed — dropping bundled rows changes the shipped
corpus, so it is a decision (see "Reserved for Kev"). ⭐ **This is Finding 32 one layer down**, in
session 2's framing: rows stored, counted, reported to the operator, and unable to ever fire. There
the cause was a rule shipped commented out; here it is data that no enabled rule could ever match.

Measured on the shipped `src/lynceus/data/default_watchlist.csv` (schema_version=31, exported
2026-06-03), with the CSV columns located **by name**:

```
oui rows in the bundled snapshot          444
  can fire                                223
  LOCALLY-ADMINISTERED (LA bit set)       221   <-- imported, and INERT
  reserved-exact (00:00:00/ff:ff:ff/…)      0
```

**Mechanism:** `rules.evaluate`'s `watchlist_oui` branch calls `_is_reserved_oui_mac` on the
**observation**, and it returns True for any MAC whose first octet has the locally-administered bit
set. So a device can never match an LA-prefixed watchlist row — the row is discarded before the DB is
consulted. `import_argus.py` filters only the exact string `00:00:00`, never the LA bit, so all 221
land.

⚠️ **An OUI with the LA bit set is not an IEEE assignment at all**, so these are almost certainly
randomised MACs that the upstream corpus recorded as if they were vendor prefixes. That makes them a
data-quality problem upstream as well as an inert-row problem here.

⭐ **GUARDED by `tests/test_bundled_oui_corpus_census.py`, and that guard is the actual fix for how
this finding came to exist.** The numbers above were prose-only for one afternoon, which is exactly
the state `import_argus.py`'s "~40 rows" was in when the corpus was re-exported underneath it. A
census recorded only in a register is the next stale comment. The guard derives the counts from the
CSV (columns located **by name**) and classifies with the real `_is_reserved_oui_mac`, so:

- the corpus is re-exported and the census shifts → **fails**, and the message names all three places
  that cite these figures (this entry, `db.py`'s refusal, `import_argus.py`'s placeholder skip).
  Updating one and not the others is precisely the bug being guarded.
- the upstream data is fixed, or an importer filter is added → **fails**, so the finding closes in
  the register rather than being discovered stale months later.

It also proves the inert rows inert **behaviourally**, driving the importer's direct-SQL bypass —
which since #86 is the only path that can still create such a row, because `add_watchlist` now
refuses them. Verified with four planted defects (a can-fire row appears; a `00:00:00` row returns;
the classifier neutered; the classifier over-corrected), each failing and naming its own invariant.

### ⛔ And the number used to justify the guard was zero

Both `import_argus.py:1077` and (copied verbatim into) PR #86's new write-time refusal justified
themselves with *"~40 rows with `pattern=00:00:00`"* in the bundled snapshot.

```
total data rows in the snapshot        41,508
identifier == '00:00:00', ANY type          0
```

**Zero.** The importer's placeholder skip matches that exact string, so it drops nothing from the
bundled data and `dropped_placeholder_oui` is always 0 for it. The claim was presumably true when
written (v0.7.9 Touch 7); the snapshot has been re-exported since. Both copies are corrected in #86.

⇒ **One wrong number in two files is how it survives a reader who checks only one.** The second copy
was written *this afternoon*, by a session that had read the first and had no reason to doubt it.
Third instance today of a change falsifying prose elsewhere — see round 11's lesson.

⚠️ **The conclusion the guard is right survives; only its stated reason was wrong.** The eval-time
guard is needed MORE than the comment claimed, for 221 rows rather than a phantom 40. A reviewer who
had checked the number and stopped there might have removed it.

### 🪤 Two near-misses in measuring this, both the same shape

- The 221 count was nearly published off a **guessed CSV column index**. The header sits on row 1
  behind a `# meta:` comment line, so `csv.reader`'s first row is not the header — the guess was
  right only by luck. **Locate columns by name.**
- Session 3's "`Config` has 40 fields" (Finding 36) was nearly reported as wrong because
  `Config.model_fields` is **33**. Both are right: 33 top-level, three of them sub-models, flattening
  to 40 operator-writable settings.

⇒ **Publish the universe beside the number.** In both cases the instinct to distrust a number was
correct and the reason for distrusting it was not.

### 🔴 Finding 38 — the setup warning for a Bluetooth adapter blamed the name, when the name was right

**Found and fixed by session 3 in PR #90 (`be65b8f`).** A fourth pointing of the same class: rounds
10/11 asked whether a stored value reaches the code that acts on it, Finding 36 asked whether it
survives another operator-facing path, and this asks whether **the diagnostic we already emit names
the right cause**.

`--interface-type` defaults to `wifi`, and `_warn_if_interface_absent` looks under
`/sys/class/net` for `wifi` and `/sys/class/bluetooth` for `bt`. So
`lynceus-bootstrap-kismet --interface hci0` — the obvious way to add a Bluetooth controller —
looked for `hci0` among the *network* interfaces and did not find it.

**Measured** on a host carrying a real `hci0` and `hci1` under `/sys/class/bluetooth`:

| invocation | warning emitted | line written |
|---|---|---|
| `--interface hci0` (default kind) | `not present under /sys/class/net … otherwise check the name` | `source=hci0:type=linuxwifi` |
| `--interface hci0 --interface-type bt` | *(none)* | `source=hci0:type=linuxbluetooth` |
| `--interface wlan99` | `not present under /sys/class/net … otherwise check the name` | `source=wlan99:type=linuxwifi` |

⛔ **Rows 1 and 3 are the same sentence and their fixes are opposite.** For `wlan99` the name is
wrong. For `hci0` the name is **right** and the *kind* is wrong; the fix is `--interface-type bt`,
which the message never mentioned.

⭐ **The failure mode is that the advice gets followed.** Check the name, find it correct, conclude
the warning is spurious, proceed — and land on `source=hci0:type=linuxwifi`, which Kismet cannot
open. That is the "configured, capturing nothing" state the warning exists to prevent, reached by
obeying the warning. ⇒ **#36 closed the silence and left the wrong diagnosis behind.** A diagnostic
that names the wrong cause is worse than none: it spends the operator's trust and then fails anyway.

**Fix:** consult the OTHER sysfs tree before blaming the name; when the adapter is found there,
quote the source line Kismet would have been given and name the flag. The suggestion is **derived
from `kind`**, so the mirror case (a wifi interface named with `--interface-type bt`) is the same
code path rather than a second branch that can drift. Still a WARNING, never a refusal — `--interface`
exists for remote rigs and not-yet-plugged-in adapters. A name absent from **both** trees still gets
the original advice, because for that case the advice was right; an **unreadable** other tree falls
back rather than guessing.

### 🪤 The sweep that found nothing, on a surface that was broken

Worth recording as method, because it nearly stopped the audit one step early.

Finding 38 was **not** found by the sweep aimed at it. That sweep derived all **54** `add_argument`
flags across the 7 CLI modules by AST, derived every `args.<dest>` read the same way, and diffed
them. It surfaced 8 declared-but-unread flags and **all 8 were refuted**:

| flag(s) | verdict |
|---|---|
| 4 × `--version` | `action="version"`; argparse consumes it |
| `--no-color` (`export_config`, `validate`) | help text says *"no-op in v1 … reserved for future"* — the operator is told |
| `--skip-install` (`bootstrap_kismet`) | documented **deprecated** no-op, stated in help, module docstring and an inline comment |
| `--user` (`setup`) | mutually-exclusive marker; its one dangerous case (root without `--system`) is **refused by name** |

⇒ **A declared-but-unread scan is structurally blind to this class, because in every real instance
the flag IS read.** `--interface wlan99` was read, stored, and written to `kismet_site.conf`. The
finding came from the pass afterwards: take each value the operator can set, follow it into the
artefact it lands in, and ask what the **consumer** of that artefact does with it.

⛔ **So "swept" must say which pass was run.** The static half is genuine coverage of the trivial
cases and is recorded as such — the CLI flag surface is now swept, not merely unexamined — but on
its own it would have licensed "no findings" on a surface carrying one.

⚠️ **The same caution applied to my own sweep claim, and it needed the same correction.** I reported
the vacuous-guard sweep of this track as "swept and clean" having measured **5 manifests**, while the
scan that fed it had surfaced **8 loop candidates**; 3 were dismissed by reading rather than by
measuring. All 8 have since been measured — emptying each collection and running the file that
claims to guard it, including `TOTAL_STEPS = 0` and `DELEGATION_RULES` against
`test_setup_web_severity_rules.py`, which the first pass never ran — and all 8 are genuinely caught.
**The claim was true; it was not yet true when I made it.**

⚠️ **And one of the tests for the fix initially graded the HOST, not the code.** The pre-existing
`sysfs` fixture patched only `_SYS_CLASS_NET`, so the new branch read the machine's real
`/sys/class/bluetooth`: green on a host with no controller, different on one with an `hci0`. Both
fixtures now patch both trees. Same family as the worktree-import trap — **a harness that resolves
part of its own environment silently grades something you did not choose.**

### ⛔ …and #90 shipped the SAME defect in the mirror direction. I filed this as "nothing residual".

**Corrected 2026-08-16 by the session that wrote the entry.** #90 taught the warning to name the
*other* kind when an interface is absent from the tree its `--interface-type` implies. But the two
trees are not symmetrical: `/sys/class/bluetooth` holds only controllers, so a hit there does prove
`bt` — while **`/sys/class/net` holds ethernet, loopback, bridges, VLANs, tunnels and every veth a
container ever made**, so a hit there proves nothing about wifi.

**Re-measured at `be65b8f` itself**, not taken from the later PR's account:

```
--interface eth0 --interface-type bt
  -> "The name is right and the kind is wrong -- pass --interface-type wifi."
```

`eth0` is a wired NIC. Following that advice yields `source=eth0:type=linuxwifi`, a source Kismet
cannot capture with — **recommended in the tool's own voice.** That is precisely the failure Finding
38 exists to describe: a confident diagnosis that walks the operator into "configured, capturing
nothing". Fixed in **PR #96** (`f0e6e9b`): the wifi suggestion now requires positive proof (the
cfg80211 `wireless` attribute), and a wired NIC is told what is actually wrong with it.

⇒ **The lesson is not "check the mirror case".** It is that #90's own framing —
*two causes with opposite fixes must not share one sentence* — was applied in one direction and not
the other, by the person who had just written that sentence. **A fix built on a principle should be
audited against its own principle before it is called complete.**

⚠️ **And "Nothing residual" was an overclaim of exactly the shape this register spent the day
correcting elsewhere** (Finding 36's, and the FIXED-claims audit that followed). It survived because
I wrote it in the same hour I wrote the fix, when the fix was the freshest thing I had and the least
examined. ⇒ **Do not write the disposition line in the same sitting as the fix.** Nothing else on
this page was wrong for that reason; this line was.

### 🔴 Finding 39 — a severity override silences a watchlist row, and nothing beside that row says so

**Found by session `d47d7e0b` from source; measured end to end here 2026-08-15 before being
believed.** ✅ **FIXED in PR #111 (`28572a7`) — and this time the ORIGINAL measurement was re-run,
not the fix's tests.** See "re-measured, including the part I expected to still be broken" below.

⭐ **Finding 32's class one layer down, and the third instance today.** A row the operator stored,
that `/watchlist` counts and renders like any other, which cannot produce an alert. Finding 32's
cause was a rule shipped commented out; Finding 37's was data no rule can match; this one is
**configuration in a third file** deciding it.

**Mechanism:** `_apply_runtime_overrides` returns `None` when the matched row's `manufacturer` is in
`suppress_vendors`, or its `device_category` is in `suppress_categories`. Every delegation branch
then emits nothing. Both keys come from `watchlist_metadata`, so **which rows are affected is
statically knowable per row** — which is precisely the argument Finding 32 makes for surfacing it.

**Measured.** The operator's own HIGH-severity `mac` row, metadata vendor `Flock Safety`, against
`suppress_vendors: [Flock Safety]`:

```
ALERTING    control, no overrides file  ->  ['argus_mac']
            with suppress_vendors       ->  *** NO ALERT ***

VISIBILITY  /watchlist        row rendered: YES    row-level signal: NONE
            /watchlist/{id}   row rendered: YES    row-level signal: NONE
```

⚠️ **The row was isolated, not the page.** `/watchlist` does contain the word "override" once — a
page-level grep would have called this a false positive and closed the finding. Within ±400
characters of the MAC there is nothing about suppression, override, inert or "cannot fire". ⇒ **The
same trap `d47d7e0b` hit from the other side**, where an assertion matched "cannot fire" inside a
per-row tooltip instead of the banner it named. **Isolate the element, both when asserting presence
and when concluding absence.**

⚠️ `webui/liveness.py` cannot see this. It derives liveness from the **loaded ruleset**, and this
suppression is data-driven — the overrides file plus `watchlist_metadata`. Not a defect in that
work; a different input it was never given.

### ✅ Re-measured 2026-08-16, including the part I expected to still be broken

⭐ **Applying this register's own new rule: re-run the finding's ORIGINAL measurement, not the fix's
tests.** The original was "row rendered, row-level signal NONE". Re-run against `28572a7`:

```
ALERTING    with suppress_vendors  ->  *** NO ALERT ***     (unchanged, and correct —
                                                             #111 is a visibility fix)
VISIBILITY  /watchlist        row-level signal: PRESENT
            /watchlist/{id}   "…matches, but a severity override drops its alerts. Its vendor
                               Flock Safety is listed under suppress_vendors in your severity
                               overrides, so the rule matches and the alert is discarded…"
```

The detail page names the **cause, the vendor and the key** — more than the finding asked for.

⚠️ **I then went looking for a residual and did not find one.** `/watchlist` shows only the token
`override` at row level, and "override" covers two states that could not be more different:
`suppress_vendors` **silences** a row, while `device_category_severity` merely **remaps** its
severity. A badge that cannot tell those apart would be a new instance of this very finding.

⇒ **Measured, one silenced row beside one remapped row:**

```
SILENCED (suppress_vendors)     ->  "ac:de:48:11:22:01  mac  override"
REMAPPED (device_category_severity) -> "ac:de:48:11:22:02  mac  low  …"
```

**The list distinguishes them** — a silenced row shows `override` where its severity would be; a
remapped row shows its severity. ⬜ **Concern refuted, recorded so nobody re-derives it.**

### ✅ Finding 42 — `/watchlist` showed a severity the runtime had already re-decided — FIXED by #125 (`2d11643`)

⛔ **I wrote this off.** The line here originally read: *"One unrelated fidelity note, NOT a defect
and not investigated further: the list shows a remapped row's stored severity, not the severity it
will actually alert at."* Session `d47d7e0b` measured the thing I declined to chase; **it is a
defect, and it is this very track's class.** Reproduced independently:

```
stored watchlist.severity          high
/watchlist list renders            high
severity the alert ACTUALLY has    low     (device_category_severity: {tracker: low})
```

**Mechanism:** `device_category_severity` is applied by the runtime layer at alert time, on top of
whatever the importer baked into `watchlist.severity`. `/watchlist` renders the stored column. ⇒ **An
operator triaging by the severity column is sorting and filtering on a number they will never
receive** — and the overrides file that decides the real value is one `/watchlist` already loads.

⚠️ **Not "will it fire" but "at what severity"**, which is why it reads as cosmetic and is not: the
severity column is the triage surface.

⛔ **NOT a mechanical fix.** "Just render the remapped value" is wrong — the stored value is real and
the runtime layer sits on top of it, so an honest rendering shows **both**, or marks the stored one
as superseded. That is a UI decision. Probe at `internal/session2-harnesses/sev_remap_probe.py`.

#### ✅ Disposition — FIXED by #125 (`2d11643`), written in by session 1 on 2026-08-16

Re-measured by its author against the **MERGED** tree with the **ORIGINAL** probe
(`internal/session2-harnesses/f42_rendered_probe.py`), not with the fix's own tests, and the probe's
control still worked. That order is the rule this file adopted after Finding 41 — see *Closed since
the audit*.

⭐ **The entry above recorded ONE axis and ONE surface. It is three of each**, and that widening is
the substance of the fix rather than a detail of it:

| | recorded here | actually |
|---|---|---|
| remapping axes | `device_category_severity` | + `vendor_severity`, + `pattern_overrides` |
| surfaces rendering the stored column | `/watchlist` | + `/watchlist/{id}`, + `/watchlist.csv` |

**Both values are now shown** — effective severity as the badge, the stored value struck through
beside it, and the axis and key that decided it named on the detail page. ⛔ **Rendering only the
effective value would have moved the same defect one surface along**: the stored column is real,
`/watchlist.csv` exports it and the `?severity=` filter is SQL over it.

⚠️ **The `?severity=` filter still filters on the STORED value, and now says so** rather than being
silently redefined. Making it remap-aware needs the full-table scan #111 refused on cost. A declared
limit, not a residual defect.

**Acceptance criterion (met):** a row whose stored severity is remapped by **any** of the three axes
shows the effective severity on all three surfaces with the stored value marked superseded, while a
row with no override is unchanged. Both halves — without the second, "always render the override"
passes trivially.

✅ **Re-measured independently at `330d2ee` by the register's own author**, not accepted from the
fix's author, because *"(met)"* written on someone else's report is the exact move this file's
disposition rule exists to stop. `f42_rendered_probe.py`, repointed at a fresh worktree (it asserts
the `lynceus` it imported comes from that tree): all three axes render `low` and emit `low` on all
three surfaces, **and the control — no overrides file — renders `high` and emits `high`.** The
control is the half that matters: it shows the probe can still print a *different* answer, so
"agree" is a result rather than a constant.

### 🪤 Twice now I have dismissed something as "not a defect" and been corrected by measurement

The other was the `d47d7e0b` clock finding, which I nearly closed on a PR title. ⇒ **"Not
investigated further" is a decision, and it deserves the same scepticism as a finding.** Writing the
observation down anyway is what let someone else measure it — ⭐ **flagging what you have decided not
to chase is cheap, and it is the only reason this one exists.**

### ⚠️ Finding 40 — an `oui` row on a reserved prefix cannot match even once its rule is enabled

**LATENT today, and that is the point.** `rules.py`'s `_is_reserved_oui_mac` discards the
**observation** before `resolve_matched_oui_for_eval` is consulted, so an `oui` row on a reserved or
locally-administered prefix can never match — **enabling the delegating rule does not change that.**

`oui` is dead-by-config today (Finding 32), so nothing is currently lost. ⛔ **It activates the moment
Kev enables the six commented-out delegating rules**, which is Kev-decision 1. Finding 37 measured
the scale: **221 of the 444 bundled `oui` rows are in exactly this state.**

⇒ **Recorded here so decision 1 is priced honestly.** "Enable the delegating rules" reads as a single
switch that turns `oui` on; in fact it would turn on **223 of 444 rows** and leave the rest silently
inert. Since #86 an operator can no longer *create* such a row by hand — `add_watchlist` refuses —
but the bundled corpus is imported by direct SQL and bypasses that refusal entirely.

### 🟡 Finding 41 — a snooze written on a backward-jumped clock silently lasts zero hours

**Found by session `d47d7e0b`; measured independently here before being recorded.**
🟡 **PARTIALLY MITIGATED, NOT CLOSED.** PR #106 (`5d9c593`) narrows the window at the web write;
**the DB/poller side is unclaimed and the defect is still reachable.** See "what #106 does and does
not reach" below — and ⛔ note that this entry said "✅ FIXED" for the length of one review, which is
recorded rather than quietly corrected.

A 24-hour rule-type snooze, written under three clock conditions:

```
correct clock (sanity)   purgeable=False  repaired=0  purged=0  ->  operator gets 24.0h
forward-jumped (+91d)    purgeable=False  repaired=1  purged=0  ->  operator gets 24.0h
backward-jumped (-6y)    purgeable=True   repaired=0  purged=1  ->  operator gets  0.0h
```

**Mechanism:** `repair_future_dated_rule_type_snoozes` keys on `added_at > now_ts` — a row written on
a clock that was BEHIND has `added_at` in the past, so the repair cannot see it, and
`cleanup_expired_rule_type_snoozes` then deletes it for having `expires_at <= now_ts`.

⚠️ **Direction: fails OPEN.** The device keeps alerting, so this is a **visibility** defect, not a
suppression one — `d47d7e0b` explicitly declined to grade it higher and that judgement is right.
Finding 32's class again: stored, accepted, does nothing, no signal.

⛔ **It cannot be repaired after the fact.** An `added_at` in the past is indistinguishable from an
ordinary old row, so a write-time refusal is the only honest fix — the same call #86 made for
reserved OUIs. ⚠️ Any such refusal must keep **permanent** allowlist entries allowed; blocking those
would stop someone suppressing a device during the very incident that made them look.

### ⭐ The reason it survived: two docstrings in one file contradicting each other

`test_the_repair_runs_before_the_purge` justified its ordering by claiming a backward-jumped snooze
is *"inside the operator's intended window — so purging first would delete the row the repair was
about to rescue."* ⇒ **Measured: no row is ever both purgeable and repairable.** "Repairable" means
`added_at` in the FUTURE, "purgeable" means `expires_at` in the PAST; disjoint for every coherent
write. **The ordering it guards cannot change any outcome.**

⚠️ **The inert assertion was not the danger — the rationale was.** It implied the backward jump is
handled. Nothing handles it. And `test_a_past_snooze_is_left_alone`, three functions above in the
same file, already stated the true rule: *"an already-expired snooze is the purge's business, not the
repair's."* **The defect lived in the gap between two confident, self-consistent, mutually
contradictory comments.**

⇒ **It was found by asking what the `added_at > now_ts` predicate structurally CANNOT match, rather
than by reading the comments.** A wrong rationale that is internally coherent survives every reading;
only interrogating the predicate finds it. The docstring is corrected and the disjointness is now
asserted (`test_no_snooze_is_both_purgeable_and_repairable`), so "the ordering is inert" cannot
silently stop being true.

### 🟡 What #106 does and does not reach — and the overclaim I nearly shipped

⛔ **#106 reads as if it closes this finding. It does not.** It refuses a duration-bearing write when
this host's clock reads earlier than a row *already recorded here*. **An install where EVERY row was
stamped by the same behind clock has no ahead-row to compare against**, so the check never fires and
the snooze dies on correction exactly as registered. Measured:

```
install where ALL history was stamped by the behind clock
  latest_alert_ts                      itself behind
  timed write on that same clock  ->   ALLOWED — the refusal does not fire
  after clock correction          ->   repaired=0 purged=1, operator gets 0.0h
```

⭐ `d47d7e0b` pinned that limitation as a TEST rather than a footnote
(`test_an_install_with_no_ahead_rows_is_a_known_blind_spot`), which is why it was catchable at all.

⛔ **I had already written "✅ FIXED in PR #106" into this entry and opened the PR carrying it.** The
author corrected me before it merged. ⇒ **A fix that addresses the surface a finding was reported
against is not the same as a fix that closes it**, and a conclusive-sounding PR title landing right
after a registration is precisely when that conflation happens. **The accurate line is "partially
mitigated at the web write; the DB/poller side is unclaimed."**

### ✅ The web-write half, verified rather than accepted — and my first verification was WRONG

`webui/clock.py` (#106) refuses a **duration-bearing** write when this host's clock reads earlier
than history it has already recorded, naming the delta and the source. ⭐ Permanent allowlist entries
are deliberately still allowed: blocking those would stop someone suppressing a device during the
very incident that made them look.

```
no history recorded yet, clock -6y   ->  allowed   (correct: no evidence either way)
correct clock (+60s)                 ->  allowed
clock BEHIND by 6 years              ->  REFUSED, naming the delta and the source
```

🪤 **My first run of that probe said the refusal did NOT fire, and I nearly reported the fix broken.**
The check compares against `latest_alert_ts` / `latest_delivered_heartbeat_ts` — timestamps the
**poller** wrote on this host. My probe had seeded a `rule_type_snoozes` row, which is not a history
source, so there were no candidates and "allowed" was the correct answer to the wrong question.

⇒ **The control was invalid, and the failure mode was pointed at someone else's merged work.** Every
other instance of this trap today produced a false finding about my own code; this one would have
produced a false accusation. **Assert your fixture actually populates the input the code reads,
before concluding the code ignores it.**

⚠️ **Two timestamp sources are deliberately EXCLUDED and that is not an oversight:** the poll
watermark carries Kismet's `last_seen` — a *different host's* clock — so a fast Kismet box would make
a correct local clock look behind and refuse writes that were fine. ⛔ **A fresh install with no
recorded history is a known blind spot**, pinned as such rather than papered over: on day one there
is no evidence either way and every write is allowed.

⇒ **On PR numbers:** this was first reported to me as landed in "#102", which is a different
session's setup/bootstrap work. **Verify a number against `gh pr view` before quoting it** — the
finding was real and the reference was not.

### ⛔ What is still open, so nobody reads this entry as closed

**The DB/poller side is unclaimed.** Closing Finding 41 needs one of:

1. a repair that can recognise a row written by a behind clock — ⚠️ **believed impossible after the
   fact**: an `added_at` in the past is indistinguishable from an ordinary old row, which is why
   #106 chose a write-time refusal; or
2. a durable monotonic anchor written alongside the row, so "when was this stamped" does not depend
   on the same clock that was wrong; or
3. an accepted, documented limitation — with the operator told at the point of the write, which is
   what #106 does for the cases it *can* see.

⚠️ **The residual is the install where the clock was behind for the whole of its recorded history.**
That is not exotic: an RTC-less Pi that has never had NTP reach it looks exactly like this on every
boot until the moment it is corrected.

#### 🟡 Disposition 2026-08-16 — the DB/poller half is now REPORTED, and option 1 was only half impossible

Measured with `internal/session1-harnesses/f41_poller_probe.py`, which asserts against `poller.py`'s
source that it still models the real call order (repair at `:1741`, purge at `:1817`, both inside the
one `if clock_trusted:` opened at `:1723`). **The operator asked for 24h in every row:**

```
CONTROL correct clock             trusted=True   repaired=0 purged=0   gets 24.0h
forward-jumped (+91d)             trusted=True   repaired=1 purged=0   gets 24.0h   <- already fixed
BACKWARD (-6y), clock now right   trusted=True   repaired=0 purged=1   gets  0.0h   <- the finding
BACKWARD (-6y), jump DETECTED     trusted=False  repaired=0 purged=0   gets  0.0h   <- see below
ordinary expired row              trusted=True   repaired=0 purged=1   gets  0.0h   <- correct
```

⛔ **The fourth row changes what this finding is about, and it contradicts how the entry above reads.**
Everything here framed `cleanup_expired_rule_type_snoozes` as the harm — *"and then deletes it"*. With
the clock-trust hold ACTIVE the row is **not** deleted and the operator **still gets zero**, because
`is_rule_type_snoozed` keys on `expires_at > now_ts` and that deadline is already in the past.
⇒ **#35's clock gate is not a mitigation for this defect; it delays the DELETE, not the harm. The
purge was never the cause — the past deadline is.** A row surviving on disk while being functionally
dead is the same shape as Finding 32: stored, counted, unable to do anything.

⭐ **Option 1 above — post-hoc detection, recorded as "believed impossible" — is impossible for CLOCK
reasoning and possible for ORDERING.** A row cannot predate its own database's first migration.
`find_impossible_rule_type_snoozes` uses `MIN(applied_at)` from `schema_migrations` as that floor.
Measured with `f41_migration_floor_probe.py`, **4/4 including the controls that decide it**:

| case | flagged | why it matters |
|---|---|---|
| BACKWARD (-6y), install was fine | **yes** | the dead-RTC shape — detected |
| ordinary expired row | **no** | ⛔ the control the whole thing rests on; flagging it would warn on every stale row on every install |
| healthy 24h snooze | no | |
| clock wrong since first migration | **no** | ⚠️ the blind spot, measured rather than caveated |

⚠️ **The blind spot is published beside the capability, because it is the register's own residual:**
`applied_at` is stamped `int(time.time())` (`db.py:478`) by the **same host clock**, so the floor is
wrong by the same amount on an install that was never right. **That half of Finding 41 remains
OPEN** — this closes the dead-RTC population, not the RTC-less-Pi one.

⛔ **`MIN(applied_at)`, not the version that created the table.** Hardcoding a migration number has
broken five call sites across four files here before.
⚠️ **This paragraph also called the minimum "strictly conservative … it can only flag fewer rows",
and that was FALSE** — see the correction below. A subset of an unsound heuristic is still unsound:
the floor itself can sit in the future.

✅ **Reported, NOT resurrected, and that is the design decision.** A snooze SUPPRESSES alerting, so
the safe direction is the one it already fails in — the device keeps alerting. Re-basing would
silently begin suppressing a rule type on the strength of a row whose real elapsed age is unknowable.
**What was wrong is that it happened silently**, and that is the half fixed. Pinned by
`test_an_impossible_snooze_is_reported_but_NOT_resurrected`, and the plausible "helpful" change —
sparing such rows from the purge — is one of the planted defects it kills.

🪤 **A guard of mine SURVIVED its plant, and the reason generalises.** The ordering test used
`str.index("db.find_impossible_rule_type_snoozes")`; the plant replaced the call with
`for ... in []:  # db.find_impossible_rule_type_snoozes()` and the needle **still matched, in the
comment left behind**. Rewritten to walk the AST for `Call` nodes. ⇒ **A guard that matches a
spelling passes any change that keeps the spelling** — and this is the second time that exact trap
has been recorded here.

**5 plants, 5 killed by the expected test** (`internal/session1-harnesses/plant_f41.py`), sources
verified **byte-identical to baseline** afterwards by content comparison rather than `git status` —
the work was uncommitted, so `git status` could never have told plant residue from the change itself.

#### ⛔ CORRECTION — a cold read of THIS fix found three real defects in it, and killed my "conservative" claim

**All three reproduced before being believed** (`internal/session1-harnesses/verify_sol_f41.py`), then
fixed. The paragraph above claiming `MIN(applied_at)` is *"strictly conservative … so it can only flag
fewer rows"* and that *"a false positive would tell an operator their snooze was discarded when it was
not"* — **that false positive is exactly what it did.**

| # | defect | measured |
|---|---|---|
| 1 | **The floor can sit in the FUTURE.** A database migrated while the clock read AHEAD (bad RTC or timezone at provisioning) stamps `applied_at` above every legitimate later write. | healthy 24h snooze: `flagged=True, active=True, purged=0` |
| 2 | **The query had no expiry condition at all**, so rows still IN FORCE were reported. The message told the operator a snooze *"has already passed"* and *"is being discarded"* — **about one they could watch working.** | `flagged=True active_at_now=True purged=0` |
| 3 | **Unbounded repetition.** Nothing marked a row reported, so any flagged row the purge did not remove was warned about **every poll cycle, forever.** | 4 consecutive cycles: `[1, 1, 1, 1]` |

⇒ **Fixed by scoping the report to exactly the rows the purge is about to delete**
(`added_at < floor AND expires_at <= now_ts`). That makes the message true about the row's fate, ends
the repetition without needing any "already reported" state, and removes the live-row false positive.
All three now measure `NOT REPRODUCED`.

⛔ **The message asserted three things the code had not established**, and this is the same class the
register already carries a rule about: that the clock *"was wrong"* (the schema stamp comes from that
same clock, so either side may be the wrong one), that the snooze suppressed **nothing** (it is in
force for the whole period before the correction), and that the row was expired at all. **Rewritten as
a DISAGREEMENT between the row and the schema history**, naming neither side as the wrong one.

⬜ **One finding REFUTED by measurement:** "a single malformed row hides every valid one" — the
`added_at` column is `NOT NULL`, so the row described cannot exist. Recorded so it is not re-raised.
🟡 **One left as a stated decision:** `added_at == floor` exactly is not flagged (strict `<`).

🪤 **And two of my own TESTS were beatable, found by a separate adversarial read of the suite:**
an implementation keying on **`expires_at < floor`** instead of `added_at` passed **all 34 tests** —
it would report every expired snooze ever written, the exact log-flood the scoping prevents — and the
returned tuple's middle element, which the poller renders as *"it is stamped X"*, was **sliced out of
the assertion**, so an implementation surfacing the wrong timestamp passed. Both now pinned;
the `expires_at` implementation was planted and **only** the new test failed, which is what proves
nothing else was covering it.

⇒ ⭐ **The transferable one: this fix was gated 6/0/0, had 5/5 plants killed, and was still wrong in
three ways.** Planting proves a guard catches the failure you modelled. It cannot tell you the
predicate is unsound, because the plants are written by the same person who wrote the predicate.

#### ⛔ ROUND 2 — the correction was read cold too, and the composed subsystem gave up a pre-existing race

Two `gpt-5.6-sol` packets: one on the correction's diff, one on the **composed** clock-repair
subsystem (all four repairs, the purge, the archive, the web gate, in execution order). Everything
below reproduced before being believed.

🔴 **A pre-existing TOCTOU in `repair_future_dated_rule_type_snoozes` — not introduced by any of this
work, and the composed read is the only thing that could have seen it.** The repair `SELECT`s outside
its transaction and then `UPDATE`d keyed **only on `rule_type`**. `add_rule_type_snooze` is
`INSERT OR REPLACE` **in a separate process**, so an operator replacing the row between the read and
the write got the OLD row's duration stamped onto their NEW snooze: **a fresh 1h snooze silently
became 24h.** ⇒ 23 extra hours of suppression nobody asked for, and **suppression is the direction
that hides a follower.** Fixed with a compare-and-swap on the values actually read; a row that changed
underneath is left alone and **not reported as repaired**, because that return value drives an
operator-facing WARNING.

⚠️ **The forward repairs RESTART the window rather than preserving the operator's deadline, and the
log line claimed otherwise.** A 24h snooze written on a +91d clock and corrected 12 real hours later
is re-based to `now + 24h` — **36 hours of total silence**. Nothing stored can fix it: both timestamps
came from the wrong clock, so elapsed real time is unrecoverable. The message said it *"runs for the
Nds the operator asked for"*; it now says **"for Nds FROM NOW"** and warns that the total may exceed
what was asked. **A limit, stated, not a patch.**

⛔ **My "reported once, not every cycle" claim was too strong.** The bound comes from the purge
deleting the row immediately after — but report and purge are two statements, not one transaction. If
the DELETE fails (locked, read-only, I/O error) or the process stops between them, the row is reported
again next tick. **Bounded in practice, not by construction**, and the docstring now says so.

🪤 **One unrenderable timestamp used to silence the whole batch.** `datetime.fromtimestamp` on an
out-of-range epoch raised out of the loop, so every REMAINING impossible snooze was purged with no
warning at all. Now formatted per row inside its own `try`.

🪤 **And the sharpest one, because it is about testing: a plant showed my own new test was theatre.**
`test_the_forward_repair_does_not_clobber_a_snooze_written_under_it` performed the competing write
**before** calling the repair — so the repair's own `SELECT` returned nothing, there was no race to
lose, and it passed with the compare-and-swap removed. Rewritten to interleave the write between the
`SELECT` and the `UPDATE` through a wrapping connection. ⇒ **A concurrency test that does not
interleave is not a concurrency test**, and only the plant could tell me.

⭐ **`find_impossible_rule_type_snoozes` now returns a NamedTuple (`ImpossibleSnooze`).** Swapping the
unpacking order at the call site — `for rule_type, duration, added_at in …` — showed the operator a
1970 timestamp while every value-checking test passed. Naming the fields makes the mistake
unrepresentable rather than merely detectable.

⬜ **REFUTED by measurement, recorded so it is not re-raised:** "the stored duration is not the
operator's duration, because the UI evaluates `time.time()` separately for each column". The handler
captures `now_ts = int(time.time())` **once** and derives both (`app.py`, the `/rules/{rule_type}/snooze`
POST). The delta is exactly the requested duration.

**4/4 plants killed by the expected test** (`internal/session1-harnesses/plant_f41_round2.py`).

📋 **Unverified leads from an M3 class sweep — NOT findings, and listed as leads on purpose.** The
sweep looked for *"a check whose reference value comes from the same untrusted source it is judging"*
and returned 17 candidates, most of which restate "a wrong clock makes clock-based logic wrong" — the
Finding 41 class, not new defects. **Two intersect areas Round 12 recorded as UNSWEPT and are worth
someone's time:** the retention prunes (`prune_old_evidence` / `prune_old_sightings`, where a
corrected-ahead clock may silently double the retention window) and `_check_poller`'s staleness test
(which decides whether the home page says the daemon is alive). ⛔ **Neither has been measured by
anyone.** Raw report at `internal/session1-harnesses/REPORT_M3D.md`.

> ✅ **CORRECTION, 2026-08-17 (session 3) — the retention half of that lead is REFUTED, measured.**
> The prunes do **not** double the retention window in either direction. Driven through
> `prune_old_sightings` with 40 daily sightings and `retention_days=30`, the oldest surviving row was
> **30.00 days**, and a second call the same day is a no-op, so the effective window is
> `retention_days` **+ at most one prune cadence (one day)** — never `2 × retention_days`.
>
> What is real is the OPPOSITE direction, and it was already found and fixed on 2026-08-14: a clock
> that is **AHEAD** deletes rows *inside* the window (+7d → 6 extra rows, +30d → 29, +365d → all 30),
> while a clock **BEHIND** under-deletes and so fails safe. That is gated by `clock_trusted` in
> `poll_once`, and the gate is properly proven by
> `test_clock_jump_anchor.py::test_poll_once_gates_both_prunes_on_the_flag`, a parametrised
> take-effect pair (prunes run when trusted, do not when not).
>
> ⛔ **Do not "fix" this inside `retention.py`.** `test_clock_jump_anchor.py`'s module docstring
> already records why a data-anchored clamp, a volume bound and a cutoff-plausibility bound each
> refuse a *legitimate* prune of a wholly-stale table, and why any elapsed-since-last-prune bound is
> computed from the same corrupt clock and so is circular.
>
> 🔴 **The residual that IS open**, and it is Finding 41's blind spot rather than a new one:
> `ClockAnchor` anchors at daemon start, so a clock **already wrong-and-ahead when it anchored**
> shows drift ≈ 0 forever and is trusted — prunes then run against it. The bounded-hold path (accept
> the jump after `CLOCK_JUMP_MAX_HOLDS`) is deliberate and logged at ERROR naming the consequence.
> Probe: `internal/session3-harnesses/retention_direction_probe.py`.
> **`_check_poller`'s staleness test remains unmeasured — that half of the lead still stands.**

## Rig round 1 — a cold cross-model read of the day's own work, 2026-08-16

Findings 33–40 and their guards were handed to codex (`gpt-5.6-sol` for the two behavioural
changes, `gpt-5.6-terra` for the guards) with bounded context and **no repo access**, and asked one
question about each guard: *what could be broken in the real system while this test still passes?*

⛔ **Every finding below was re-measured before being believed, and two were REFUTED.** A delegate's
finding is a draft.

### 🔴 The one that mattered — my auth guard would have passed once auth landed

`test_webui_post_routes_are_classified.py`'s behavioural anchor asserted `status_code in (200, 303)`.
⇒ **A login redirect is a 303.** The single test whose stated job was to notice authentication
arriving would have gone on passing the moment it did, leaving "Reserved for Kev" item 5 asserting an
exposure that no longer existed.

**Proven, not reasoned:** planting auth as a 303 redirect that mutates nothing, the OLD assertion
**passed**; the new one fails. The anchor now asserts the `rule_type_snoozes` row appears, so it
measures the mutation rather than the politeness of the refusal. 200-or-303 was also satisfied by a
validation bounce or a swallowed error — it could not tell "the caller changed the system" from "the
caller was turned away".

### 🟡 Two instrument defects in the census guard, both latent, both closed

- **Ragged rows were silently dropped.** `_rows()` filtered on `len(row) == len(header)` to avoid a
  crash; a malformed re-export would have lost rows **quietly**, and the 40,000-row floor only
  catches wholesale truncation. Measured: 0 dropped today, so nothing was wrong — but a census that
  discards its own inputs reports a clean number about a corpus it did not fully read. Now asserts
  zero dropped.
- **The can-fire control was selected at runtime** (`sorted(can_fire)[0]`), so a corpus re-export
  could silently change which prefix the test exercises. Now **named** (`00:04:7d`), with an
  assertion that it is still present and still classified can-fire.

### ⬜ REFUTED on measurement — recorded so they are not re-raised

- **"`ssid_pattern` / `imei_tac` have no `_entry_matches` branch, so a valid entry never matches."**
  ⇒ Neither type can be **constructed**: `AllowlistPatternType` rejects both (measured 2026-08-15,
  Finding 35). The trigger requires "load a valid `AllowlistEntry` with `pattern_type='ssid_pattern'`",
  which raises `ValidationError`. The unreachable branch is correct, not a gap.
- **"A POST route in a mounted sub-application would evade the route scan."** ⇒ The only `app.mount`
  is `StaticFiles` at `/static`, which registers no POST routes. Structurally true, currently empty.

### 🟡 A prose defect the rig found in `add_watchlist`, and why the CODE was left alone

Its docstring promised idempotence on `(pattern, pattern_type)` **unconditionally**. Validation runs
first, so a refused pattern raises `ValueError` **even when an identical row already exists** — and
such rows exist in every deployment, because the importer inserts with direct SQL (221 of 444 bundled
`oui` rows; Finding 37). Measured: `add_watchlist('02:00:00', 'oui')` raises against a DB that
already holds that row.

⭐ **The docstring was corrected rather than the ordering, deliberately.** "This row could never fire"
is a more useful answer than "it already exists", and `seed_watchlist` already logs it and counts it
as skipped exactly as it would a duplicate — so a seed run is not aborted. ⚠️ The same gap applies to
#84's `mac_range` refusal and predates this work.

### Round 2 — the three guards the first round did not review

⚠️ **The first round reviewed 2 of the 5 guards.** That is the partial-sweep shape this register
keeps recording, applied to my own use of the rig. The other three, sent cold:

- 🔴 **`test_severity_paths_are_wired.py` did not test the wiring its filename claims.** It built
  `RuntimeSeverityOverride` **directly** and handed it to `evaluate()`, so it proved the evaluator
  honours an *injected object* — never that `severity_overrides.yaml` reaches it. The loader could
  drop a key, or the poller pass `None` forever, and all 48 cases stayed green. ⇒ Measured first:
  the wiring **does** exist (`Poller.__init__` → `load_runtime_severity_overrides` → `evaluate`), so
  this was a coverage gap, not a live defect. Now driven from a real YAML file end to end.
- 🔴 **The notify tests inspected two dicts and never called `send()`** — it could hardcode a
  priority, swap the maps, or ignore severity entirely. Now drives the real POST path and reads the
  headers, including the `priority_override` case where a tag derived from the overridden priority
  would silently relabel every escalation.
- 🟡 **A missing control.** `test_a_soft_only_allowlist_still_suppresses_ambient_noise` never proved
  the device would alert *without* the allowlist; disable the ambient rule and it passes while soft
  allowlisting does nothing.
- 🟡 **The all-types sweep could not see a MISCLASSIFICATION**, because it parametrises over the
  implementation's own HARD/SOFT sets. Flip `oui` to soft and every cardinality, union and
  parametrised expectation still passes while the real system stops suppressing an explicit OUI
  allowlist. Now anchored to the criterion — *who controls the value* — restated independently.

All five proven by planted defect, each naming its own invariant.

### Complete disposition — all six of round 1's findings, including the two not fixed

⚠️ Recorded because a round that dispositions *most* of its findings and calls itself complete is the
same shape as sweeping most of a class. The four above plus:

- **A hard-allowlisted device whose ONLY hit is ambient gets no audit trail.** `watchlist_hits`
  excludes `new_non_randomized_device`, so the INFO loop is empty and only a DEBUG line is emitted.
  ⇒ **Judged correct as written:** the docstring promises the audit pass records *"any watchlist hits
  the allowlist just suppressed"*, and a new-device notice is not a watchlist hit. Recorded so it is
  not re-derived as a defect.
- **The dedup check-then-insert is racy.** Measured: **no UNIQUE constraint** on
  `(pattern, pattern_type)`, only a non-unique `idx_watchlist_pattern_type_pattern`. Two concurrent
  `add_watchlist` calls can both pass the existence check and both insert. ⇒ **Pre-existing, not
  introduced by #86** — but #86 routed the seeder through `add_watchlist`, so a seed run concurrent
  with operator clicks now shares the window. Not patched: a UNIQUE constraint is a migration and
  changes what an importer collision does.

### ⭐ What this round is evidence for

**All five guards I shipped had a hole, and none was visible from inside.** I wrote them, planted
defects against them, and proved they failed — and the plants I chose were the ones I already
believed in. The cold read asked the one question I could not ask myself: *what passes while broken?*

⇒ **The same partial-sweep shape recurred three times in one night, at three altitudes**, which is
worth more than any individual finding: round 10 swept the watchlist and not the allowlist; rig round
1 reviewed 2 of 5 guards; and this round's first write-up dispositioned 4 of 6 findings. **Each time
the omission looked like completion from inside.** The only reliable tell was someone — or something
— counting the set from outside.

⇒ Pair with Finding 36's amendment, where a red-team found the regression my own derived fixture was
structurally incapable of reaching. **Two independent instances in one day of a defect that was
unreachable from inside the measurement that missed it.**

## Round 12 — `poller.py`'s gate chain, driven rather than read, 2026-08-16

**The surface:** the register has said since round 11 that `poller.py`'s gates BEYOND the allowlist
branch were never swept. This round swept them with one instrument: **for each gate, store the value
that should trigger it and drive `process_observation` for real.** Nothing here was concluded by
reading the code.

⭐ **The class being hunted is round 11's:** *a stored value some later layer has to honour, which
silently does nothing.* It found one defect of a different and worse shape — a value the layer
**did** honour, whose failure to record it was invisible.

### ✅ The per-rule_type snooze gate — SWEPT and honest, do not re-audit

Every `rule_type` in the `RuleType` Literal (derived via `get_args`, never transcribed), each driven
through `process_observation` twice — once with no snooze, once with one stored:

```
10 of 11 rule_types : control 1 alert 1 send  ->  snoozed 0 alerts 0 sends, counter incremented
watchful_recurrence : control 0 alerts        ->  INVALID CONTROL, measured separately (below)
```

⚠️ `watchful_recurrence` is reported as **cannot-measure-this-way**, not as "the snooze works":
`evaluate` has no branch for it, so no `hit` ever carries that rule_type and the gate inside the
`for hit in hits:` loop can never see one. Its snooze is consulted at **two other sites** —
the escalation emit and `_retry_watchful_escalation` — and both were driven directly instead.

### 🔴 Finding 43 — a watchful escalation whose alert WRITE failed was lost permanently and silently

**FIXED** — measured, fixed and guarded in the same change; the original measurement was re-run
against the fix rather than the fix's own tests.

#74 hardened the escalation **send**. The layer above it — the `db.add_alert` that CREATES the row
the retry path looks for — still swallowed its exception and returned, while the main alert path
three hundred lines below deliberately **raises** for exactly that case. `escalated_at` was stamped
*before* the write, and `escalate_watchful_recurrence` fires once per entry, so a failed write left
an entry marked escalated with no alert row and `_retry_watchful_escalation` returns early when it
cannot find one. **Nothing re-drove it.**

Measured on a FOREVER watchful snooze — the operator's documented worst case, where the escalation
is the only signal that can still arrive — across eight further days of daily sightings:

```
                        esc rows  delivered  heartbeat
healthy DB                     1          1  healthy    "Still watching."
DELIVERY fails (#74's case)    1          0  UNHEALTHY  "1 alert(s) written but never delivered"
the WRITE fails                0          0  healthy    "Still watching."
```

⛔ **The third row is why this is worse than the defect #74 fixed.** It is identical to a healthy
install on the operator's only health channel: `count_undelivered_alerts` counts ROWS, and there is
no row to count. The single most important message this product sends — *that someone appears to be
following you* — was lost silently and permanently, and the tool reported itself healthy for it.

⚠️ **Reachable, not theoretical.** sqlite's `database is locked` is the condition the main alert
path's own measurement used, and the web UI is a separate process writing this same file.

**Fix:** stamp `escalated_at` only once the row exists. A failed write leaves the entry unescalated,
so the next sighting retries. Same principle the main path already applies one gate down (*dedup on
DELIVERY, not on row existence*). `outcome.counted` was also dropped from the escalation condition —
counting is debounced to once per 24h, so requiring it put the earliest possible recovery up to a day
away while the device is in front of the sensor every poll; `escalated_at is None` is what keeps it
firing once.

⭐ **The rule_type-snooze branch still stamps, deliberately, and that is load-bearing.** A snoozed
escalation writes no row by design (*detection runs, notification does not*), so without that stamp
it would be **indistinguishable from a failed write** — and the recovery would resurrect the alert
the operator deliberately silenced, the moment their snooze expired. Two causes, one observable
state: pinned as `test_a_snoozed_escalation_is_consumed_and_never_resurrected`.

⛔ **CORRECTION, made the same hour I wrote the claim.** This entry first said "escalated, no alert
row" **must mean exactly one thing**. A cold cross-model read refuted it and it is worth recording
rather than quietly editing: that holds for rows written *from this change onward*, and **not** for
an install that already hit the defect. Those entries are stamped escalated with no row today, and
after upgrading they stay lost — `_retry_watchful_escalation` still returns early on a missing row,
which is correct for a suppressed escalation and wrong for a legacy one, and nothing can now tell
them apart. **The fix is not retroactive, and no migration attempts to be.** Distinguishing them
would need a durable disposition (`suppressed_at`, or an escalation record linked to the entry)
rather than the absence of a row.

### ⭐ What the cold read found in this fix, and the guard hole it exposed

**My recovery test would have passed with the defect restored.** The change drops `outcome.counted`
from the escalation condition so recovery happens on the next POLL rather than the next counted
sighting — but every test I wrote drove sightings a **day** apart, so all of them recover either way.
Measured: with `outcome.counted` put back, **5 of 5 passed**. The claim was in the commit message and
in this entry; nothing guarded it. Now pinned by
`test_recovery_happens_on_the_NEXT_POLL_not_the_next_counted_day`, which drives the retry at +5
minutes, and by a plant that restores `outcome.counted`.

⇒ **This is the fourth consecutive round where a cold read found a hole in guards that had already
been proven with planted defects.** The plants were the ones I believed in. The tell here is
specific and reusable: **every case in the file shared one parameter value** (a one-day interval), so
no plant could distinguish a fix that depended on it from one that did not.

**Acceptance criterion, recorded now so this can be proven closed later:** with the escalation's
`add_alert` raising, (a) `escalated_at` stays NULL, (b) the write is retried on subsequent sightings
rather than attempted once, and (c) a single transient failure still ends with exactly one escalation
row, delivered. All three measured; four planted defects — the original ordering, dropping the
fire-once guard, dropping the snooze branch's stamp, and reporting a failed write as success — each
fail the suite, with unique anchors and a clean tree verified after every plant.

### 🔴 Finding 44 — the escalation row and its stamp are two transactions, so one duplicate is reachable — ✅ FIXED (migration 026)

**Closed by the generation-keyed escalation ledger. Both halves of the acceptance criterion are
proven, and the disposition is written from the MEASUREMENT, not from the PR body.**

`watchful_escalations(entry_id, generation)` carries a `UNIQUE` constraint, where `generation` is the
entry's `reset_count`. The alert INSERT and the reservation INSERT are **one transaction**, so "an
escalation was emitted for this generation" and "the alert row exists" cannot disagree — the previous
pair of writes could disagree, and the duplicate is what that disagreement looked like. A crossing
whose stamp failed now finds the reservation and recovers the stamp; a **reset** advances the
generation and escalates normally. 10 planted defects, 10 killed **by the expected test**, tree
verified byte-identical by content after each.

⛔ **The fix's FIRST CUT SHIPPED A WORSE DEFECT THAN THE ONE IT CLOSED, and only a cold read found
it.** The recovery path stamped `escalated_at = now_ts`. `_retry_watchful_escalation` passes
`escalated_at` to `get_recent_alert_for_rule_and_mac` as its `since_ts`, and that query filters
`ts >= since_ts` — so a stamp written days after the alert row's own `ts` put the row **permanently
out of the retry's reach**, with every surface showing the entry as escalated. Pre-fix that same case
re-emitted a duplicate: noisy, but it reached the operator. **I had traded a duplicate for a silent
permanent loss — the exact direction this finding's own text warns against.** Now stamped with the
ledger's `created_at` and the retry is driven in the same observation.
⇒ **A fix aimed at a fail-OPEN defect is exactly where a fail-CLOSED one gets introduced**, because
every instinct while writing it is pushing toward "emit less".

⚠️ **NOT backfilled, and the cost is stated rather than hidden.** An install already sitting in the
failed-stamp state at upgrade has no reservation, so its next crossing still costs the one duplicate,
once. A backfill from `escalated_at IS NOT NULL` cannot distinguish an emitted escalation from a
**snooze-consumed** one, so it would write rows asserting alerts that were never sent, permanently.

⛔ **RETRACTED, and it was mine, written the same hour as the fix.** I wrote here that "only the
poller emits escalations, so no second writer exists today". **False.** `process_observation` has
**two** callers — `poller.py` and `bridges/ble.py`, the latter inside a `ble-bridge` **thread** that
opens its **own** `Database` (*"OWN connection on its own path — WAL second writer"*). The
per-instance `RLock` does not serialise them. ⇒ [[audit-a-fix-against-its-own-principle]]: a
disposition written beside its own fix inherits the fix's blind spots. The claim cost one grep.

### 🔴 Finding 57 — a snooze-consumed generation had no ledger row, so a stale handler could resurrect it — ✅ FIXED

**The one escape hatch the UNIQUE constraint alone does not close, and it lands on the invariant the
suite already had a test for.**

Migration 026's ledger records **emission**, so a crossing consumed by the `watchful_recurrence`
rule_type snooze deliberately writes **no ledger row** — it emits nothing. But it *does* stamp
`escalated_at`. That combination is exactly what a reset needs (`escalated_at IS NOT NULL`), so:

1. generation *g* crosses while snoozed → stamped, no alert row, **no reservation**;
2. the operator resets → *g+1*, `escalated_at` NULL — legal;
3. a handler still holding the pre-reset view emits for *g*. The UNIQUE constraint has nothing to
   collide with, so the row is written **and delivered**.

Measured (`internal/session1-harnesses/` probe, then pinned as
`test_a_stale_generation_cannot_emit_after_a_snooze_consumed_reset`):

```
gen 0 snooze-consumed   escalated_at=1700086400  ledger=0  alerts=0
after reset             reset_count=1            escalated_at=None
stale emit for gen 0    returned=1700172800      alerts=1  delivered=1   ⛔
after the fix           returned=None            alerts=0  delivered=0
```

⇒ **The operator was sent "this device appears to be following you" for a generation they had both
SNOOZED and RESET** — the resurrection that
`test_a_snoozed_escalation_is_consumed_and_never_resurrected` exists one aisle over to forbid.

**Fix:** the reservation is now `INSERT ... SELECT ... WHERE id = ? AND reset_count = ? AND
escalated_at IS NULL AND archived_at IS NULL` rather than `INSERT ... VALUES`. A superseded,
consumed or archived entry yields **zero rows**, so nothing is written and nothing is sent.

⭐ **Two consequences worth carrying, both about my own earlier work:**
- **A guard of mine became unfailable and I removed it rather than leave it.** The old code
  re-SELECTed after `IntegrityError` to tell a UNIQUE collision from a FOREIGN KEY failure, because
  `INSERT ... VALUES` produced both. `INSERT ... SELECT` cannot reference a row that does not exist,
  so the FK can no longer fire and the re-check was unreachable. Its **plant survived**, which is
  what surfaced it. ⇒ A guard that cannot fail is a claim nobody is checking.
- **A test that pinned the MECHANISM had to be rewritten to pin the GUARANTEE.**
  `test_a_bad_entry_id_is_not_reported_as_already_escalated` required a specific exception *type*;
  the property that matters — nothing written, nothing delivered, no timestamp handed back — is
  unchanged and is what it asserts now.

⚠️ **Found by an M3 sweep of the poller, and the sweep's own interleaving was REFUTED**: it assumed a
reset could land mid-crossing, which it cannot (`reset_watchful_recurrence` requires
`escalated_at IS NOT NULL`, and a mid-crossing entry has NULL). The snooze-consumed variant is the
one that survives that refutation. ⇒ Reproduce the mechanism, not the report.

⛔ **NOT SWEPT, stated so this is not read as complete coverage:** `process_observation` itself.
Its packet was handed to M3 twice (once at 79 KB, once split to 41 KB) and returned an **empty
file** both times, and codex was rate-limited until 2026-08-20, so there was no second channel to
swap to. The function is unaudited for this defect shape.

### 🔴 Finding 58 — the MAIN alert dedup is a read-then-write, so one detection can alert twice — ✅ FIXED

**Closed by making the dedup check and the insert ONE statement**, via
`add_alert_if_none_since` (`INSERT ... SELECT ... WHERE NOT EXISTS`). Measured with a control, one
detection delivered to both writers:

```
CONTROL   sequential, one connection    alerts=1  sent=1
TREATMENT two connections, interleaved  alerts=2  sent=2      <- before
TREATMENT two connections, interleaved  alerts=1  sent=1      <- after
```

⛔ **Only ONE of the dedup's three arms became conditional, and that is the whole difficulty.**
*delivered* → skip; *undelivered, attempts spent* → skip; *undelivered, attempts remaining* →
**reuse the row and re-send**; *nothing recent* → write a new row. Only the last goes through the
conditional insert. Routing the RETRY arm through it turns a re-send into a silent skip and
reinstates **Wave 5 Finding 12**, where one failed send swallowed the alert for the whole window —
which is why `test_an_undelivered_alert_with_attempts_left_is_still_retried` is the second half of
the acceptance criterion and is planted against (`D3`).

⚠️ **The `alert_dedup_window_seconds == 0` path deliberately does NOT go through it.** With no window
there is nothing to be "recent" within, and suppressing there would silence an operator who
explicitly turned dedup off.

⛔ **THE FAULT-INJECTION SEAM FOR "THE ALERT WRITE FAILED" MOVED, AND THREE EXISTING GUARDS WENT
DARK.** `tests/test_alert_write_failure_is_retried.py` breaks `db.add_alert` to prove a confirmed
watchlist hit is not silently lost when it cannot be persisted. The new arm does not call
`add_alert`, so the injection stopped injecting. **They failed on their own precondition
(`_alerts(db) == 0`)** rather than passing vacuously — the only reason it was caught. ⇒ **Assert your
fault injection FIRED**, and when you move a write, grep for what injects failures into it. The
helper now breaks both seams and returns a `restore()` that undoes both; restoring only one left the
retry unable to write and produced a failure message that was true about the fixture and false about
the code.

⚠️ **A test that could not discriminate, found by its plant surviving.** The dedup-disabled test used
two DIFFERENT timestamps; with the window at 0, `since_ts` becomes `now_ts`, so an alert a second
earlier fails `ts >= since_ts` and the insert proceeds regardless. It now drives both observations at
the SAME timestamp — ordinary here, since a bridge flush and a poll tick routinely share a second.

⚠️ **The NULL-mac predicate is duplicated** between `get_recent_alert_for_rule_and_mac` and the
conditional insert, deliberately rather than shared, because the two must agree exactly — a drift
would make "recent" mean two different things and the dedup would silently change behaviour. Pinned
by `test_the_conditional_insert_and_the_dedup_read_agree_on_recent` for both a real mac and NULL.

Original measurement follows.

### (measurement) Finding 58 — the MAIN alert dedup is a read-then-write

**MEASURED, NOT PATCHED — deliberately, because it is the hottest path in the product and the fix
has to preserve three-way retry semantics. Registered so the measurement is not re-derived.**

`process_observation` reads `get_recent_alert_for_rule_and_mac` to decide whether this rule+mac was
already alerted inside `alert_dedup_window_seconds`, then calls `add_alert`. The read is not
re-asserted at the write, and the two callers of `process_observation` — the poll loop and the
`ble-bridge` thread — hold separate `Database` objects on separate connections.

Measured, one detection delivered to both writers, with a control:

```
CONTROL   sequential, one connection    alerts=1  sent=1
TREATMENT two connections, interleaved  alerts=2  sent=2   (barrier reached by both)
```

⇒ **One detection, two alert rows, two ntfy notifications.**

⚠️ **Graded fail-OPEN and ranked accordingly:** the operator is told twice, not never. That is why
this is registered rather than rushed — every escalation-path sibling (Findings 44a, 55, 57) either
lost a warning or fabricated one.

⛔ **Reachability is established, not assumed:** Kismet reports BLE devices and the bridge reports
BLE devices, so the same MAC can be observed by both within one dedup window. The probe drives the
real `process_observation` on two connections rather than calling `add_alert` directly.

⛔ **Why the obvious fix is not obvious.** The dedup branch is three-way — *delivered* → skip,
*undelivered with attempts spent* → skip, *undelivered with attempts left* → **reuse the row and
retry**. A `NOT EXISTS` guard on the INSERT closes the duplicate but must not turn the retry case
into a silent skip, which would reinstate Wave 5 Finding 12 (a failed send swallowed for the whole
window). Any fix needs the retry arm tested explicitly.

**Acceptance criterion (a conjunction):** two concurrent handlers of one detection produce exactly
one alert row and one notification, **AND** an undelivered alert with attempts remaining is still
retried on the next observation. The second half is not optional — it is the behaviour the dedup
exists to permit.

### 🔴 Finding 56 — the impossible-deadline reporter covered ONE of four deadline backends — ✅ FIXED (watchful half)

**The watchful-snooze backend now has its BACKWARD reporter.** The measurement below is what
established this was a fix rather than a documented limit, and it is kept in place.

`find_impossible_watchful_snoozes` uses the same ordering discriminator as its rule_type sibling —
a row cannot have been written before the schema that holds it existed — keyed on
`watchful_recurrence.created_at`. ⛔ **Not** `snooze_expires_at` and **not** `last_seen_at`: both are
deliberately re-written and clamped, so neither carries provenance.

⛔ **THE BOUND IS THE HALF A NAIVE PORT GETS WRONG.** The sibling is bounded for free — the purge
deletes the rule_type row immediately afterwards. **Watchful entries are never purged**, so a direct
port would re-emit the same warning on every poll cycle forever, which is #139's unbounded-repetition
defect (`[1,1,1,1]` per cycle) reintroduced on the one channel that must not be trained into noise.
Each entry is now reported at most once, remembered durably in `poller_state`. Both directions are
pinned: `..._reported_at_most_once` and `..._a_SECOND_impossible_entry_is_still_reported`, because
"report once" otherwise passes trivially by going deaf.

⛔ **A "tidy up the expired snooze" fix would have been catastrophic and was nearly written.**
`poller.py` reads `snooze_active = snooze_expires_at is None or snooze_expires_at > now_ts` — so
**NULL means snoozed FOREVER**, not "no snooze". Clearing an expired snooze to bound the reporting
would have made that suppression permanent. ⇒ [[count-the-readers-before-removing-a-write]].

⚠️ **Three false-positive shapes are each pinned by their own test**, because this class has already
shipped one: a healthy snooze, a snooze still IN FORCE (its duration outran the clock error — #139's
exact case), and a floor stamped by a clock that read AHEAD (`applied_at` comes from the same host
clock, so the floor sits above every legitimate later write — the false positive #135 shipped).

⭐ **Two plants taught more than they proved, both about my own code:**
- **`snooze_expires_at IS NOT NULL` CANNOT FAIL on its own** — SQLite's `NULL <= x` is never true, so
  the deadline comparison already excludes forever-snoozes. Its plant SURVIVED. Kept as a statement
  of intent and as cover for anyone making that comparison NULL-tolerant, and now **documented as
  redundant** so nobody reads it as load-bearing.
- **A half-made plant passed the test for the worst possible reason.** Making the predicate
  NULL-tolerant without also making the arithmetic NULL-safe let the row reach
  `int(exp) - int(created)`, which raised — and the never-raises guard turned that into the finder
  returning **nothing at all**. Total silence, scoring as a pass. ⇒ A plant must model the whole
  change; and a fail-safe diagnostic converts a predicate bug into silence, which is the cost of that
  design and is stated rather than discovered later.

⬜ **The other two backends still have no backward reporter, and cannot use this discriminator:**
`repair_future_dated_ui_entries` is the YAML allowlist, which has no `schema_migrations` row to
compare against; `_watchful_baselines` keys on `last_seen_at`, a clamped column. Closing those needs
a different mechanism, not a third copy of this one.

⚠️ **Unchanged residual:** an install whose clock has been wrong since its FIRST migration is
invisible to all of this, because the floor is wrong by the same amount.

Original measurement follows.

### (measurement) Finding 56 — the impossible-deadline reporter covers ONE of the four deadline backends

**MEASURED, NOT PATCHED. Registered so the reachability work is not re-derived a fourth time.**
This is handoff JOB 3, and the handoff's instruction was "measure reachability before building"
because the answer changes whether it is a fix or a documented limit. It is measured now.

The poller drives four forward clock repairs. Only `rule_type_snoozes` has a companion
**backward** reporter (`find_impossible_rule_type_snoozes`, #135/#139), which uses the ordering
discriminator *a row cannot predate its own database's first migration*
(`added_at < MIN(schema_migrations.applied_at)`).

Measured on `acd8ace` (`internal/session1-harnesses/f41_other_backends_probe.py`, run against a
fresh worktree — see the stale-tree warning below):

```
watchful snooze backend, operator asks for 24h:
  CONTROL correct clock             repaired=0   operator gets 24.0h of 24.0h   floor-detectable=False
  forward-jumped (+91d)             repaired=1   operator gets 24.0h of 24.0h   floor-detectable=False
  BACKWARD (-6y), clock now right   repaired=0   operator gets  0.0h of 24.0h   floor-detectable=True
```

⇒ **The backward case delivers ZERO of the 24 hours asked for, is SILENT, and IS detectable by the
same discriminator that already covers `rule_type_snoozes`.** So this is a fix, not a documented
limit — which is the thing that had to be established before building anything.

⚠️ **Grading, stated so it is not inflated:** `snooze_expires_at` gates the ORIGINAL alert pipeline
for that MAC, so the failure is **fail-OPEN** — the device keeps alerting. It is a *visibility*
defect (the operator believes they have silenced something for a day and have not), not a lost
warning. That is the same grading Finding 41 already carries, and it is why this sat behind
Findings 44 and 50.

⛔ **The fourth backend is different and must not be lumped in.** `repair_future_dated_ui_entries`
is the YAML allowlist, which has no `schema_migrations` row to compare against, so the ordering
discriminator does not exist for it. `_watchful_baselines` keys on `last_seen_at`, which is
deliberately CLAMPED and re-written, so it is not a provenance marker either — for a watchful entry
the provenance is `created_at`. Any fix must key on provenance columns, not on the deadline column.

**Acceptance criterion (a conjunction, both halves required):** a watchful snooze whose entry's
`created_at` predates the database's first migration and whose `snooze_expires_at` has passed is
reported to the operator as a disagreement, **AND** a healthy snooze on a correct clock — and one on
a database migrated while the clock read AHEAD — is NOT reported. The second half is not optional:
`MIN(applied_at)` is stamped by the same host clock, so a future-dated floor puts every legitimate
row below it, and #135 shipped exactly that false positive before #139 scoped it.

⚠️ **Unchanged residual:** an install whose clock has been wrong since its FIRST migration is
invisible to all of this, because the floor is wrong by the same amount.

### 🔴 Finding 55 — one observation could be counted TWICE, fabricating a "you are being followed" — ✅ FIXED

**The 24h sighting debounce is a read-modify-write with two writers.**
`record_watchful_sighting` SELECTs `last_seen_at`, computes
`gap = observed_at - last_seen_at`, and then issues
`UPDATE ... SET sighting_count = sighting_count + 1 WHERE id = ?`. The WHERE did
not re-assert `last_seen_at` — the value the decision was made from — and the
SELECT precedes any write, so it sits **outside** the write transaction.

⛔ **Its own docstring promised the property that fails:** *"Under-debounce
observations are TRUE no-ops... this is what makes same-cycle dedup organic: the
first counted observation in a cycle updates `last_seen_at = now_ts`; any
subsequent observation in the same cycle has `gap == 0` and is rejected."* True
of ONE writer, and it was written when there was one.

Measured with one observation delivered to both writers
(`internal/session1-harnesses/f41_sighting_debounce_probe.py`):

```
CONTROL   sequential, one connection    counted True, False   count +1
TREATMENT two connections, interleaved  counted True, True    count +2
after the CAS                           counted False, True   count +1
```

⚠️ **The direction is the serious one and it is not "just noise".** Over-counting
reaches the escalation threshold on FEWER real recurrences than the operator was
promised — a **fabricated** "this device appears to be following you". `poll_once`
already calls that unrecoverable: *"`escalated_at` is permanent, and the
operator's trust in the tool is more so."* Fixed with a compare-and-swap on
`last_seen_at`, plus re-asserting `archived_at IS NULL` so the web process cannot
have the row bumped after the operator closed it.

⭐ **Found by an M3 sweep of every `UPDATE`-bearing method in `db.py` for this one
shape.** It reported three candidates; **two were refuted by their own stated
`REFUTED IF` conditions** — `merge_device_probe_ssids` (the BLE bridge never
supplies `probe_ssids` and the poller guards on it, so there is one writer) and
`bulk_acknowledge_alerts` (the whole body is inside `with self._lock, self._conn:`
and only the single web process calls it). ⇒ **Requiring a refutation condition
per finding is what made the triage cheap**; 1 of 3 is a good yield precisely
because the other two died in minutes rather than becoming work.

### ⚠️ Every probe in `internal/session1-harnesses/` was resolving the STALE checkout

`WT = HERE.parents[2]` resolves to the checkout the FILE lives in — the shared
one, deliberately left alone and therefore **34 commits behind** on 2026-08-17,
missing migrations 026 and 027. A probe run there measures code that predates the
fix it is about. ⛔ **The existing `assert lynceus.__file__.startswith(WT)` does
not catch it:** it proves you imported from the tree you resolved, not that the
tree is current — which is why this was invisible for so long. All eleven now
resolve via `_worktree.resolve_worktree()`, which takes the tree from `argv[1]`,
**prints** it with its SHA, and **refuses to run** on a tree that does not contain
`origin/main`.

### 🔴 Finding 44a — two ways #152 could LOSE an escalation, both fail-closed — ✅ FIXED (#155)

**Found by a cold cross-model read of the MERGED #152 diff, both reproduced with controls before
being believed** (`internal/session1-harnesses/f44_coldread_probe.py`). Neither shipped in a release.

1. **A stale-generation stamp suppresses the next generation permanently.**
   `escalate_watchful_recurrence` was keyed on `id` + `escalated_at IS NULL` only. With two
   concurrent `process_observation` callers, a handler that decided about generation *g* can stamp
   generation *g+1* after an operator reset. That generation emitted no alert of its own, and the
   first-crossing branch requires `escalated_at IS NULL`, so **it can never escalate again.** Fixed
   with a compare-and-swap on `reset_count`. Control (the pre-fix statement on a second connection)
   still stamps, so the test discriminates.
   ⭐ **Third site of the Finding 53 shape** — `SELECT` outside, `UPDATE` keyed only on `id`.
   [[grep-for-the-next-first-match]] again, and this time on my own fresh fix.
2. **An unreadable ledger fell into the snooze-consumption branch**, which stamps `now_ts` without
   consulting the ledger — putting the stamp *after* a pending alert's `ts`, which the retry's
   `ts >= escalated_at` filter can then never match. Same permanent-undeliverability as the bug
   #152 already fixed, reached through the DEGRADED path. Fixed by distinguishing "no row" from
   "could not read" and always taking the emit path in the latter case, where the UNIQUE constraint
   is authoritative.

⬜ **GRADED DOWN after measurement, recorded so it is not re-derived:** the cold read also argued
that driving the retry inside the recovery observation can no-op under the delivery backoff, turning
a noisy path silent. The backoff after one failed attempt is **300 s** and is computed from the
alert's own `ts`, so any later poll clears it; polls are minutes apart and sightings days apart. It
is a bounded latency, not a loss, and the attempt accounting it preserves is the reason #74 exists.

⚠️ **Also corrected:** the timestamp census claimed `escalated_at` and `alerts.ts` are *"written
together"*. They are written in **separate transactions** — which is the entire reason Finding 44
exists. Both carry the same source instant and the 026 ledger preserves it across the gap.

Original registration follows, unchanged.

**Found by handing Finding 43's own fix to a cold cross-model read; confirmed by measurement.**

`_emit_watchful_escalation` writes the alert row, delivers it, and the caller then stamps
`escalated_at`. A failure **between** those two writes leaves a delivered row with no stamp, and the
next sighting takes the first-crossing branch again — **one duplicate escalation**.

Measured, with the stamp raising `database is locked` once after a successful row write:

```
before: the raise ESCAPED process_observation, abandoning every remaining hit
        on that device -- with the escalation alert already delivered
after:  guarded; 2 escalation rows across 9 days of sightings, >=1 delivered,
        the entry recovers its stamp and stops re-emitting
```

⭐ **Why it is not deduplicated here.** The obvious guard — "skip the write if an escalation row
already exists for this MAC" — **suppresses the genuine escalation of a RESET entry**, because
`reset_watchful_recurrence` clears `escalated_at` and the count but leaves the old alert row behind.
That is the unsafe direction: a device the operator restarted watching would never escalate again.
Closing this honestly needs an escalation record keyed to the entry **generation** (`reset_count` is
already on the row), i.e. a migration.

⚠️ **Direction: NOISY, and deliberately chosen.** One duplicate "this device appears to be following
you" against dropping the rest of the tick's alerts. The bound matters more than the duplicate —
re-emitting on every poll would train the operator to ignore the highest-severity thing this product
sends — so the bound, not the absence, is what is pinned:
`test_a_stamp_that_fails_after_the_row_lands_costs_at_most_one_duplicate`.

**Acceptance criterion:** an escalation is emitted at most once per entry generation, proven with a
failure injected between the row write and the stamp, AND a reset entry still escalates afterward.
The second half is what a naive dedup breaks, so it is not optional.

⛔ **Related, and NOT addressed by anything here:** the cold read also raised concurrent-poller
duplication and poller/web-UI reset and archive races. **Reachability was not established** — this
round measured a single-threaded poller only — so they are recorded as unverified leads rather than
findings. Do not cite them as defects without measuring who can actually reach them.

### ⛔ What this round could NOT see — stated so a partial sweep is not read as a complete one

- **The retention prunes and the clock-trust holds were NOT swept.** They are in `poll_once`, not
  `process_observation`, and this instrument does not reach them.
- **The allowlist gate was not re-measured** — round 11 swept it and it is on the do-not-re-audit
  list; this round assumed that result rather than re-proving it.
- **Concurrency was not tested.** Every measurement is single-threaded; the poller/web-UI race that
  makes `database is locked` reachable was *simulated* by raising, not reproduced.
- **Finding 41's DB/poller half remains open** and is unchanged by this round.

## ⛔ How Findings 45–48 got their numbers — a rule this file now owns

**Two sessions independently proposed "Finding 43" and "Finding 44" for four different findings**,
while Round 12 above was landing 43 and 44 into this file. Session 2 caught its own collision and
self-corrected; session 3's board text, its handoff and its 15:10 summary **all still say 43 and 44
and are wrong**. Assigned here, by the owner of this file, at write time:

| proposal | PR | assigned |
|---|---|---|
| inert/snoozed reported as a partition | #126 | **Finding 45** |
| the fifth mechanism is reportable for `mac` rows | #127 | **Finding 46** |
| a duplicate YAML key moves a suppression | #122 | **Finding 47** ⬅ proposed as 43 |
| the validator described two files as one | #121 | **Finding 48** ⬅ proposed as 44 |

⭐ **The rule, which is session 2's and is adopted verbatim: a finding number in a proposal is not
free until it is written down here.** Whoever writes this file re-reads the highest number **at write
time** and assigns; it is never inherited from the note that proposed it. Three sessions have now
paid for that lesson in the same night.

⚠️ **Round order below is by finding number, not by merge date.** Round 14's PRs (#121, #122) merged
*before* Round 13's (#125–#128). This file has never been chronological — Finding 42 sits above 40
and 41 — and ascending numbers is the more useful property in a reference document. Do not read
adjacency here as sequence.

## Round 13 — the watchlist's truthfulness surfaces, 2026-08-16

**Session 2's track: #125 → #126 → #127 → #128.** Every finding re-measured against the **merged**
tree with its original probe, controls confirmed still working. Finding 42's ✅ disposition is written
in place above, under Round 11, rather than duplicated here.

### 🔴 Finding 45 — two watchlist surfaces named opposite causes for the same row — FIXED by #126 (`dc00cd8`)

**The surfaces reported *inert* and *snoozed* as a partition, after #116 had fixed the model to let
them co-occur.** One row, one click apart:

```
model            inert_types=('ble_uuid',)  suppressed_types=('ble_uuid',)
/watchlist       row badge: inert          -> "edit rules.yaml"
/watchlist/{id}  snoozed ONLY, verbatim: "Nothing in rules.yaml needs changing."  <- FALSE
/watchlist.csv   can_fire=no, the snooze appeared nowhere
```

⛔ **Two contradictory diagnoses of one row, each naming a fix that alone restores nothing.** Edit
`rules.yaml` and the snooze still silences it; lift the snooze and no rule delegates to the type.
Same class as Finding 39 and the round-11 work: the operator is sent to fix the wrong file.

🪤 **The detail template still carried the comment that justified the chain** — *"mutually exclusive
by construction: liveness intersects the snooze set with the LIVE types"* — **describing code #116
had deleted.** [[a-fix-can-falsify-prose-three-files-away]] again, and the comment read as
authority. 🪤 `_can_fire`'s own docstring already stated the rule it was breaking.

⚠️ **A limit recorded, not a contract changed:** `/healthz.json`'s `live_rows` + `inert_rows` +
`snoozed_rows` **overlap and must not be summed** — a type that is both is counted twice. That is
correct for independent flags and wrong for anything treating them as a partition. Both type LISTS
are exported beside the counts so a consumer can intersect them, and `watchlist_liveness`'s docstring
now says so.

**Acceptance criterion:** a row that is BOTH inert and snoozed names both causes on all three
surfaces, AND a row that is only one of the two names only that one. Both halves — without the
second, "always print both" passes trivially while inventing a snooze that does not exist.

✅ **Both halves verified at `330d2ee` by the register's own author.** `cooccur_probe.py` drives the
co-occurring row: the list banner carries all three pills (`inert`, `snoozed`, `both`) and the detail
page explains both causes and states that fixing one alone restores nothing. The **second** half is
what the single-cause tests hold —
`test_a_snoozed_but_delegated_type_keeps_the_original_wording`,
`test_an_inert_but_unsnoozed_type_says_nothing_about_a_snooze`, and
`test_the_list_banner_names_the_co_occurrence_only_when_it_exists` — **55 passed** with
`test_yaml_duplicates.py` alongside. ⭐ That suite also opens with
`test_this_suite_is_testing_the_tree_it_lives_in`, which is the control this project learned to
demand after three separate wrong-tree results.

### 🟡 Finding 46 — the fifth silencing mechanism was reportable for `mac` rows all along — NARROWED by #127 (`776959f`)

`liveness.py` stated that an allowlist match **cannot** be reported per row, because the allowlist
suppresses by DEVICE and a watchlist row is a PATTERN. True for `oui`, `mac_range`, `ssid`,
`ssid_pattern`, `ble_*` and `drone_id_prefix`. **False for `mac`, which names exactly one device** —
and `mac` is the type this UI creates and one of the three the shipped ruleset delegates to.

Measured through `poller.process_observation`, not through the renderer:

```
hard `mac` allowlist entry          0 alerts   <- silenced, and nothing said so
expired entry                       2 alerts
entry for a different MAC           2 alerts
SOFT `ble_local_name` entry         2 alerts
no entries at all                   2 alerts
```

⭐ **The SOFT control is what fixed the marker's shape**, and it is the transferable part: under #82 a
**device-chosen** value must not mark a row, or an attacker broadcasting an allowlisted name would
paint the operator's own watchlist as suppressed. The control was not decoration — it changed the
fix.

**Acceptance criterion:** a `mac` row covered by a HARD allowlist entry is reported as suppressed by
the allowlist, while the same row under a SOFT (device-chosen) entry, an expired entry, or an entry
for another MAC is **not** so marked.

### ⭐ Rig round 2 — the composed cold read, and the three traps it caught in this session's own work

The three merged PRs were handed to codex `gpt-5.6-sol` with `liveness.py` and the full
`11893cc..776959f` diff inline, and one instruction: **state, per finding, exactly what would refute
you.** **12 findings → 6 reproduced, 1 refuted by measurement, 5 already-documented limits — and five
of the six were introduced by that same session, that same night.** All six fixed in #128
(`7eb96b8`). Raw output at `internal/session2-harnesses/rig_out.md`.

⛔ **The three worth carrying, because each is a fix that reads as complete and is not:**

1. **A HALF-scoped sentence.** #126 conditioned *"Nothing in `rules.yaml` needs changing"* and left
   the clause in front of it — *"the rules still match, the alerts are dropped until the snooze
   expires"* — rendering unconditionally, false in every clause for a type nothing delegates to.
   ⇒ **Scope the whole sentence; a conditional wrapped around the second half is a fix that reads as
   one.**
2. **The exact defect #116 exists to prevent, re-committed three PRs later.** The allowlist block
   named ONE covering entry when a MAC can be covered by an exact entry AND an `oui` entry at once —
   `override_suppression_axes` was made a tuple in #116 for precisely this. ⇒ **After fixing "reports
   one of several independent causes", grep the subsystem for the next place that returns the first
   match.**
3. **A fix for a claim that was itself a claim.** `sole_axis` answered a **COUNT** where the question
   was a **VALUE**: two axes can match and removing the winner can still land back on the stored
   severity (stored `high`, `pattern_overrides` → `low`, `vendor_severity` → `high`). Now computed by
   walking the engine's precedence one step down.

⬜ **The reviewer's TOP finding was REFUTED by measurement** — an unreadable overrides file leaves the
poller applying nothing either, so the UI and the engine agree. ⭐ **Following the refuted thread
found a real one anyway:** `/settings`'s overrides card read `paths.default_overrides_path("user")`
unconditionally and ignored `config.severity_overrides_path`, so an operator was shown the existence
of a file nothing reads and invited to create one there. Four states now — missing /
exists-but-nothing-configured / exists / **unreadable**.

## Round 14 — the allowlist YAML round-trip under hand-editing, 2026-08-16

**Session 3's track: #121 → #122 → #124.** Four jobs, **two ended in refutations**, and in both of
those what was actually wrong was the **guard** — transcribed, skipped by default, or resting on a
number nothing held still.

### 🔴 Finding 47 — a duplicate key in a hand-edited config file is silently obeyed, and in `allowlist.yaml` it points a suppression at a device nobody named — FIXED by #122 (`3a22b95`)

*State:* `yaml.safe_load` keeps the **LAST** duplicate key, with no error and no warning (PyYAML
6.0.3, measured). Every loader in this project uses it. In `allowlist.yaml` a stray second `pattern:`
line inside an entry leaves the entry reading exactly as intended — note and all — while the address
actually in force is the second one.

*Measured end to end through `is_allowed`, not through a parsed dict:*

```
stored pattern                 ac:de:48:99:99:99   (note still reads 'kev phone')
is_allowed(ac:de:48:00:11:22)  False   <- the device they MEANT still alerts
is_allowed(ac:de:48:99:99:99)  True    <- one they never named is silenced
lynceus-validate               OK (1 entry valid), exit 0
```

⇒ **Direction: fail-OPEN**, and doubly wrong — the intended device keeps alerting *and* an unnamed
one goes quiet. A duplicate top-level `entries:` key is the same mechanism one level up (two blocks
typed, the first discarded whole).

🪤 **Why nothing ever checked:** `tests/test_setup_wizard.py` justified its own no-duplicate guard
with *"the duplicate would break `yaml.safe_load` with a 'duplicate key' error and the daemon would
fail to start."* **Measured false.** The guard was right and its rationale was wrong — and
*"duplicates are self-detecting"* is a perfectly good explanation for why nobody looked.
[[prose-not-code-is-often-the-defect]], living inside a test.

*Fixed by:* `lynceus.yaml_duplicates`, wired to the allowlist loader (WARN, keeps the file) and to
`lynceus-validate` (ERROR with the key path and both line numbers, exit 1). ⭐ **The validator check
covers all five config files**, so `config.py`'s and `rules.py`'s identical exposure is reached at
the operator's surface without touching either loader.

✅ **Acceptance criterion:** a hand-edited `allowlist.yaml` carrying a duplicate `pattern:` inside an
entry (a) logs a WARNING at daemon load naming the line whose value was lost, **and** (b) makes
`lynceus-validate` exit 1 with an ERROR naming the key path and both line numbers. Closed only when
BOTH hold, and proven by re-running the ORIGINAL `is_allowed` measurement above — **not** #122's
tests.

⚠️ **Deliberately NOT closed by #122, and it is a decision rather than a gap:** the daemon still
LOADS the file (warn, not refuse). Refusing would drop every other suppression over one stray line —
the all-or-nothing failure `_validate_ui_entries` exists to undo. **If it should refuse, that is
Kev's call.**

### 🟡 Finding 48 — `lynceus-validate` blamed the operator's curated allowlist for a fault in the daemon-managed sibling — FIXED by #121 (`7c17f28`)

*State:* `validate_allowlist_yaml` loaded the primary file with `load_allowlist`, which **merges**
`allowlist_ui.yaml` — so a report about one file was computed from two.

| state | operator was told | true |
|---|---|---|
| valid primary + 1 malformed sibling entry | `allowlist.yaml` **invalid**, "would empty the allowlist at startup", exit 1 | poller loads `primary=2 ui=1`; **nothing is emptied**; the valid file is blamed |
| 2-entry primary + 3-entry sibling | primary "**5** entries valid" + sibling "3 entries valid" | five entries, rendered as eight |

*Cause:* the ERROR-log promotion attached to the **module-wide** `lynceus.allowlist` logger, so it
captured the sibling's records too. *Fixed* with `_load_primary` — the same loader minus the merge.
⚠️ **"would empty the allowlist at startup" was KEPT for genuine primary failures** — checked in
`poller.py`, not assumed.

✅ **Acceptance criterion:** with a valid primary beside a sibling holding one malformed entry,
`validate_allowlist_yaml(primary).valid` is True and none of its issues name the sibling path, **while
`validate_allowlist_ui_yaml(sibling)` still reports the bad entry.** Both halves — otherwise "the
primary is clean" passes trivially the moment the sibling stops being reported at all.

### ⬜ REFUTED — the importer has no unaccounted drop path. The GUARD was the defect. (#124, `30e9008`)

**Recorded as a refutation because that is the honest result**, and because the suspicion will
otherwise be re-raised. Measured across **14 row shapes** — placeholder OUI, unknown type,
normalization failure, in-import duplicate, peer collision, empty identifier, `ble_uuid`, `mac_range`
— **14 rows in, 14 rows accounted for**, and `render()` prints every counter. The suspicion does not
survive measurement.

🟡 **What IS wrong there is the guard.** The project's only reconciliation check lived inside
`test_cross_repo_live_argus_csv_imports_without_errors` and:

1. **transcribed** its counter list, omitting `operator_preserved` and `dropped_placeholder_oui`; and
2. **`pytest.skip`s** unless a live Argus CSV sits beside the repo — so it has effectively never run
   in CI.

On a CSV carrying one placeholder-OUI row the transcribed sum reports a **mismatch of 1 — a false
failure**. It has never fired only because the bundled snapshot has ZERO `00:00:00` rows (#86's
correction) and because it skips.
⇒ [[iterate-the-derived-set-dont-transcribe-it]], in the very guard that exists to prove accounting.

⭐ **Two of that round's four jobs ended in refutations, and both times the guard was the defect.**
That is the pattern worth carrying out of Round 14: when a suspicion about behaviour dies, check
whether the thing that *should* have detected it was ever able to.

🟡 **Residual — ✅ CLOSED by #130 (`68f5bb7`), and it was NOT small.** The text here originally read
*"Residual, **small** and named: `config.py` and `rules.py` still load with a plain `yaml.safe_load`
… a daemon-side warning for those two files is the remaining gap."* ⛔ **I wrote that, and it was
wrong within the hour it was written.** It is Finding 49 below: **six loaders** (three daemon, three
CLI) across five modules, with the **dead-man's switch** among the values a stray line can flip.
**"Small" was a guess wearing the clothes of a measurement** — the scope had been reasoned about,
never measured, and the word travelled anyway.

## Round 15 — the same duplicate-key mechanism, everywhere the operator does not type a command, 2026-08-16

### 🔴 Finding 49 — a duplicate key silently changed what the daemon ENFORCES, everywhere except the allowlist — FIXED by #130 (`68f5bb7`)

Finding 47 fixed `allowlist.yaml` at the loader and all five files at `lynceus-validate`. **Every
other loader was left on a plain `yaml.safe_load`** — deliberately, and in writing, in
`validate.py:_duplicate_key_issues`'s own docstring. This is the gap on the paths an operator never
runs by hand. Measured on `7eb96b8`, one stray line per case, **every one fail-OPEN**:

| file | duplicate key | value in force | what the daemon said |
|---|---|---|---|
| `rules.yaml` | top-level `rules:` | **first block discarded whole** (2 rules → 1) | `"1 active rules"` |
| `rules.yaml` | `enabled:` | rule off, despite `enabled: true` above it | `"0 active rules (1 disabled)"` |
| `rules.yaml` | `patterns:` | watched addresses swapped | `"1 active rules"` — **byte-identical to the correct file** |
| `severity_overrides.yaml` | `suppress_vendors:` | a vendor silenced | five counts, none looking wrong |
| `lynceus.yaml` | `heartbeat_enabled:` | **dead-man's switch disarmed** | **nothing, ever** |

⭐ **The organising fact, and it is why "the daemon already logs a count" was not a defence: every
startup signal this project emits narrates a COUNT.** A duplicate that changes a **value inside a
preserved structure** moves no count at all. The `patterns:` case prints a startup line identical to
the correct file's. `heartbeat_enabled` is worse — `poller.py:1252` returns early on every tick
without logging, so **the one feature whose entire purpose is to speak when nothing else can is
disarmed in silence.**

🪤 **The most plausible hand-edit is also the worst.** Appending a second top-level `rules:` block,
rather than extending the first, is the natural thing to do to a file whose top-level key is a list.
It discards every rule above it and reports the survivors as if they were everything.

⛔ **Three CLI loaders matter for a reason the runtime ones do not** — they bake the wrong value in at
**write** time, so a restart does not correct it: `import_argus.load_override_config` (the severity is
already in the watchlist), `seed_watchlist.seed_from_yaml` (Finding 47 pointed the other way — there a
duplicate *silenced* a device, here it *watches* one nobody named), and `setup/core._existing_mapping`,
whose answer `--reconfigure` carries forward **as though the operator had chosen it** (Finding 36 is
what happens when that function is wrong).

⭐ **The fix takes the lesson from #122's own near-miss, and this is the transferable part.** #122's
helper sat inside `_load_primary`'s `except Exception`, where a raise from the **diagnostic** was
reported as *"could not be parsed"* and became a valid file loading as **zero entries** with the
poller announcing `SUPPRESSION DISABLED`. Here the swallow-everything property is asserted where it
bites: `test_a_broken_detector_cannot_change_what_load_ruleset_returns` pins the loader's **return
value** with the detector throwing `MemoryError` — not merely that nothing propagated.
⇒ **A diagnostic must not be able to change the answer it is diagnosing.**

⚠️ **This paragraph originally also said the property was "implemented ONCE". It was not, until
`330d2ee`** — see the correction below, which is left in full because the way the false sentence got
here matters more than the sentence.

✅ **Acceptance criterion:** every `yaml.safe_load` site in `src/lynceus` is either wired to
`warn_duplicate_keys` or carries a **written exemption**, and a new loader cannot join silently.
Three guards, and it takes all three — `test_the_scan_finds_the_loaders_it_is_supposed_to_grade` (the
instrument's own control, because **a vacuous sweep has shipped in this repo before**),
`test_every_yaml_loader_is_wired_or_exempt_with_a_reason`, and `test_no_exemption_is_stale`.

#### ⛔ CORRECTION — that criterion was NOT met when I wrote it, and I wrote the overclaim myself

**Met at `330d2ee` (#133). NOT met at `68f5bb7`, which is the SHA the paragraph above was published
against.** The sentence *"a new loader cannot join silently"* was false, and the line that followed
it — *"the first is the one that matters: it is the difference between a sweep and a claim about a
sweep"* — praised an instrument that had a **bypass in it**. Both are deleted rather than softened.

A cold cross-model read of #130 (codex `gpt-5.6-sol`, high effort, *"state per finding exactly what
would refute you"*) found five real defects, **four of them in the guards themselves**. ⛔ **Five
planted defects had already been caught by those same guards** — fifth round running on this project
that **planting proves only the failure its author imagined.** Reproduced independently here on
`68f5bb7` before #133 landed:

| # | defect | how it slipped the guard |
|---|---|---|
| 1 | a key repeated **three** times named the wrong winner (`a:1/a:2/a:3` reported line 2, `safe_load` keeps line 3) | the guard transcribed the expected line instead of asking `safe_load` |
| 2 | `warn_duplicate_keys`, documented **"Never raises"**, could raise — the `try` wrapped the detection call, the **emit loop sat outside it** | `logger.warning` is not inert; a bad handler took the daemon down at startup on a file it had already parsed |
| 3 | the scan was **blind to `from yaml import safe_load`** | it matched only `ast.Attribute`; a bare `safe_load(path)` is an `ast.Name` — **a straight bypass of the anti-rot mechanism** |
| 4 | **"wired" was any called name containing `duplicate`** — an unrelated `deduplicate_cache()` certified a loader as protected | the fix for a *transcribed* list was a *loose* list; ⇒ **the answer to a transcribed list is a DERIVED one, not a loose one** |
| 5 | the three CLI loaders had **no behavioural tests**, only the AST assertion | **an AST guard proves a call exists; it cannot prove it fires on the file the loader read** |

**Verified by me on `330d2ee`, by reading the code rather than the PR body:** `_yaml_import_aliases`
now walks `ast.ImportFrom` and the site scan handles the `ast.Name` form; `_reporter_names()` derives
the reporter set by walking the tree and `sites[…] = bool(names & reporters)` is a set intersection,
carrying its own control (`assert "deduplicate_cache" not in reporters`); and the emit loop now sits
**inside** the `try`, with a nested reporter-of-last-resort. `tests/test_yaml_duplicates.py` and
`tests/test_webui_cause_cooccurrence.py`: **55 passed** at that SHA.

🪤 **And the mistake that is mine, not #130's: I transcribed a PR's self-description into this file
as established fact.** The entry above says the never-raise property is *"implemented once"* — I took
that from #130's body. It was **false when I wrote it**: `allowlist.py::_warn_on_duplicate_keys` kept
its own copy, **which carried defect 2 as well**. It delegates to `yaml_duplicates.warn_duplicate_keys`
as of #133, so the sentence is true now — but it was not true when this file asserted it.
⇒ **A PR body is the author's account of their own work. It is evidence, not a measurement**, and the
register is the wrong place to launder one into the other. Same class as the disposition rule this
file already carries: re-run the finding's ORIGINAL measurement, not the fix's own tests.

⬜ **Graded DOWN after measurement, recorded so nobody re-derives them:** the reviewer's
**resolved-key collision** (`on:` vs `true:`, YAML 1.1 booleans — `safe_load` collapses them and the
raw-text detector reports nothing) was called HIGH and is real, but measured through the actual
loaders pydantic's `extra="forbid"` rejects the resulting non-str key, so both files that matter
**fail CLOSED and loudly**. Pinned as a limit *with* that measurement, in a test that fails if a
loader ever starts ACCEPTING it. **Double-parse memory** and the **TOCTOU second read** are documented
limits, not defects, on config-sized files read once at startup.

### 🔴 Finding 50 — an operator reset cancels the retry of an escalation that was never delivered, and leaves a complaint nothing can clear — ✅ FIXED (migration 027)

**Closed with a THIRD delivery state, not by making the counter quieter.** Migration 027 adds
`alerts.notify_abandoned_at`; `reset_watchful_recurrence` stamps it, **in the same transaction as
the reset**, on that generation's undelivered escalation, and `count_undelivered_alerts` excludes it.
Both halves of the acceptance criterion are proven: after the reset the count returns to its
pre-escalation value, **AND** a genuinely undelivered alert on an entry the operator never touched
still raises it and keeps raising it. 8 planted defects, 8 killed by the expected test.

⭐ **It is deliberately NOT `notified_at`.** Stamping delivery would assert ntfy succeeded when
nothing established that — the class #74 and #146 exist to prevent. "The operator saw it in the UI
and acted" and "the notifier delivered it" are different facts and get different columns.
⚠️ The licence for "actioned" is a claim about the UI: the reset control renders **only** on an
escalated entry. If it is ever rendered elsewhere, that claim must be re-argued.

⛔ **Most of the plants attack the suppression being too WIDE, not too narrow**, because this fix
*removes* rows from a safety counter. `Q2` is the register's own named unsafe direction — a windowed
counter — and `Q3` marks every undelivered escalation rather than the one row the operator actioned.
A guard census (`test_only_the_reset_path_abandons_an_alert`) pins that the column has exactly **one**
writer, since a second one is how a counter that exists to break silence quietly stops counting.

⚠️ **Not backfilled and not defaulted:** every pre-existing undelivered row stays counted. A legacy
lookup handles installs that escalated *before* migration 026, which have no ledger row and are
precisely the population carrying a permanent complaint today.

⬜ **The retry-vs-acknowledgement disagreement is NOT resolved here and does not need to be.** Both
readings agreed the counter was wrong; only the counter is changed. Whether a reset should also keep
retrying delivery remains a product question for Kev.

Original registration follows, unchanged.

### (original registration) Finding 50 — an operator reset cancels the retry of an escalation that was never delivered

**Found by session 2, who did not fix it (outside their write set) and wrote it up with BOTH possible
dispositions rather than the one they preferred. Re-measured here before registering** —
`internal/session2-harnesses/reset_probe.py` part C, repointed at a fresh tree, notifier returning
`False` (ntfy down at the threshold cross):

```
CONTROL  no reset, device seen again   notifier calls 1 -> 2   attempts 2/4   notified_at None
TREATMENT operator clicks reset        notifier calls 1 -> 1   attempts 1/4   notified_at None
```

**Mechanism, confirmed in the code and not only in the probe:** #123 built `_retry_watchful_escalation`
so an escalation whose SEND failed is re-driven by seeing the device again (+0/+5/+15/+45 min). Its
first statement is `if escalated_at is None: return` (`poller.py:377`). `reset_watchful_recurrence`
sets `escalated_at = NULL`. ⇒ **the reset silently removes the retry path with 3 of 4 attempts
unspent, and no mechanism can ever spend them.** The documented give-up state is
`attempts >= NOTIFY_MAX_ATTEMPTS`, which this never reaches.

⛔ **The consequence outlives the argument about intent.** `count_undelivered_alerts()` takes an
optional `since_ts` and **both callers pass nothing** — `poller.py:1134` (the heartbeat) and
`app.py:1071` (`/settings`). The row stays `notified_at IS NULL` forever, so every such reset adds a
**permanent, unclearable** line to *"N alert(s) written but never delivered"* — on the one surface
whose entire value depends on the operator still reading it.

⚠️ **Session 2 offered two readings and asked for a measurement rather than a preference. The
measurement supports the second, and it also dissolves the disagreement:**

1. *"Not a defect — the reset form renders only on an escalated entry, so the operator saw the
   escalation; reset is an acknowledgement."* This is a **legitimate product argument about what
   reset means**, and nothing here refutes it.
2. *"A defect — the row is left uncounted-down and permanently counted."* **Confirmed.**

⇒ **Both readings agree the COUNTER is wrong.** Even if reset-as-acknowledgement is the right
semantics, a row the operator has actioned should stop being counted as an undelivered alert. The
disagreement is only about whether to keep retrying; it is not about whether the heartbeat should
carry a complaint forever.

🟡 **REGISTERED, NOT PATCHED — it is a decision about what `count_undelivered_alerts` MEANS**, not a
patch: "written but never delivered" and "written, undelivered, and abandoned by operator action" are
different states, and only the second is safe to stop counting. ⛔ **The unsafe direction is obvious
and must be named:** making the counter windowed (`since_ts`) to make the line go away would also
hide a genuinely broken ntfy topic, which is the exact silence that counter exists to break.

**Acceptance criterion:** after a reset on an entry whose escalation was never delivered, the
heartbeat's undelivered count returns to what it was before the escalation, **AND** a genuinely
undelivered alert on a healthy entry still raises it. The second half is not optional — without it,
"stop counting" passes trivially by counting nothing.

### 🔴 Finding 51 — a "reset" on a behind clock ARCHIVES the watchful entry the operator just said they were still watching

⛔ **This is the FAIL-CLOSED direction, and Finding 41's whole family has been graded fails-OPEN until
now.** Every earlier instance ends with the device still alerting, which is noisy but safe. This one
**drops the tracking of a possible follower**, silently, on the operator's own click.

**Mechanism.** Five web routes consult `refuse_if_clock_behind` before writing a deadline
(`app.py:2791, 2951, 4020, 4092, 4324`). **`watchful_reset_post` (`app.py:3039`) does not** — it calls
`db.reset_watchful_recurrence(entry_id, now_ts=int(time.time()))` straight through. `last_seen_at` is
the **sole lifecycle clock** for unactioned watchful entries, and
`auto_archive_watchful_recurrence` archives anything ≥ 90 days stale. So a reset performed while the
clock reads behind writes a `last_seen_at` that is already ancient, and the next poll archives it.

Measured (`internal/session1-harnesses/f41_reset_archive_probe.py`), on an escalated entry — which is
the only state where the reset form renders, so the precondition is satisfied rather than routed
around:

```
CONTROL correct clock        archived=0   entry still tracked=True
clock behind by 100 days     archived=1   entry still tracked=False
clock behind by 6 years      archived=1   entry still tracked=False
```

⇒ **The operator clicks the button that means *"I am still watching this device"* and the effect is
that the system stops watching it.** No warning, and `/watchful` simply no longer lists it.

⚠️ **Reachability is narrower than the other instances and must be stated:** the reset form renders
only on an **escalated** entry, so the operator must already have had a recurrence escalation. That
makes it rarer — and worse when it happens, because an escalated entry is by definition the one the
product most wants kept.

✅ **MITIGATED in `db.py` — the measured harm is closed; the route gate is still open and still
session 2's.** `reset_watchful_recurrence` now writes `last_seen_at = MAX(last_seen_at, ?)`, so a
reset can never move an entry **backwards** into the archive window. It is a no-op on a sane clock
(`now_ts` is already the larger value), which is why the existing walk-back test was unaffected.
Re-measured with the original probe: all three behind-clock cases now `archived=0, tracked=True`
against a control that still survives.

⚠️ **The clamp bounds the damage; it does not restore intent.** On a behind clock the entry keeps
whatever staleness it already had, so an entry ALREADY past the archive window still archives.
Nothing local can do better — if the clock is wrong there is no trustworthy "now" to move it to, and
inventing one is the same defect pointing the other way. **Refusing the write outright belongs at the
route, beside the other five**, which is the half below.

⭐ **Both halves are wanted, not either/or:** the clamp is defence in depth in the layer every caller
passes through, and the gate is the loud refusal that tells the operator their clock is wrong instead
of silently doing less than they asked.

🟡 **The ROUTE half is still open — the write is in `webui/app.py`, another session's write set**, and the
fix is a choice between two places: add the existing `refuse_if_clock_behind` gate to the reset route
(consistent with the other five, refuses loudly), or clamp inside `reset_watchful_recurrence`
(`db.py`) so no caller can archive-by-reset. ⛔ **Do not "fix" it by widening the archive window** —
that would delay archiving for every healthy entry to paper over one bad write.

**Acceptance criterion:** a reset performed with a `now_ts` far behind the entry's own history leaves
the entry tracked after `auto_archive_watchful_recurrence` runs, **AND** a genuinely stale entry — one
whose `last_seen_at` is ≥ 90 days old on a *correct* clock — is still archived. Both halves; without
the second, "never archive after a reset" passes trivially and the retention behaviour is lost.

## Round 16 — concurrency, and two classes I had closed in one place only, 2026-08-16

**Concurrency is no longer UNSWEPT.** Round 12 recorded that every measurement on this project was
single-threaded; session 3 measured it and handed the `db.py` half over.

### 🔴 Finding 52 — a request that FAILED leaves its write committed — CONTAINED, not architecturally fixed

The web process runs **42 sync route handlers on Starlette's THREADPOOL** against **one**
`app.state.db`, i.e. **one `sqlite3.Connection`** opened `check_same_thread=False`. `sqlite3`
transaction state is per-**CONNECTION**, not per-thread, so one thread's `with self._conn:` exit
commits **everything pending on that connection**, including another thread's half-finished work.
Reproduced with a barrier that asserts the interleaving actually happened:

```
A: BEGIN, INSERT 'A', then raise -> A's block rolls back
B: (concurrently) INSERT 'B', exits its block -> COMMIT
rows afterwards: ['A', 'B']      <- A rolled back and its write SURVIVED
```

⛔ **Both directions are reachable:** a suppression written by a FAILED request persists
(**fail-OPEN**), and symmetrically A's rollback can discard B's committed-looking write
(**fail-CLOSED** — the operator is told a watchlist row exists and it does not).

✅ **Contained by a reentrant lock** held across every one of `db.py`'s **34** transaction blocks.
Measured with the control that decides it — the OLD pattern still corrupts, the new one does not,
and the barrier fired in both:

```
CONTROL  `with self._conn:`               rows ['A','B']   A's failed write survived: True
FIXED    `with self._lock, self._conn:`   rows ['B']       A's failed write survived: False
```

🪤 **Session 3's original probe cannot see this fix, and reading it after the change would say
"still broken".** It reproduces C-1 through `with db._conn:` — the RAW connection — which bypasses
every `Database` method, so its output is unchanged by anything `db.py` does. **A harness must be
able to report a fix**; that one is a correct demonstration of a `sqlite3` property and not a
regression test. Mine drives the guarded pattern instead and carries the unlocked control.

⚠️ **CONTAINMENT, and the limit is the finding's residual.** A per-block lock fixes transaction
*ownership*. It does **not** give application-level atomicity — this interleaving still misbehaves:

```
A: lock; read "suppression present"; unlock
B: lock; delete the suppression; commit; unlock
A: acting on the stale read, skips creating the alert
```

⇒ **Still open: read→decide→write.** Closing it needs request-scoped connections and explicit units
of work — **a decision, not a patch**, and it is shared by all three tracks.
⚠️ Migrations and `rollback_to` write outside these blocks; both are admin-time, before traffic, and
deliberately out of scope. ⚠️ Three `async def` handlers touch the DB, so a contended lock briefly
blocks the event loop; transactions here are short and the trade is deliberate.

**Acceptance criterion:** a barrier test in which one thread's transaction fails while another
commits leaves ONLY the successful thread's row, **and** the guard asserting no bare
`with self._conn:` remains in `db.py`. Both halves — the first alone passes the moment someone adds
an unguarded block somewhere else.

### 🟡 Finding 53 — I added a compare-and-swap to ONE repair and left its two siblings without it

#142 fixed a stale-read overwrite in `repair_future_dated_rule_type_snoozes`. An M3 inventory of
every transaction block then found **the same shape in the two sibling repairs**, which I had not
looked at:

| repair | had CAS after #142 |
|---|---|
| `repair_future_dated_rule_type_snoozes` | ✅ (that was #142) |
| `repair_future_dated_watchful_snoozes` | ❌ |
| `repair_future_dated_watchful_baselines` | ❌ |

Both `SELECT … fetchall()` outside the transaction and then `UPDATE … WHERE id = ?` with no
predicate on the values read. ⛔ **Finding 52's lock does NOT cover these** — the poller and the web
UI are **separate processes**, so they hold separate connections and no in-process lock can
serialise them.

The baseline case is the sharper one: `last_seen_at` is the **sole lifecycle clock** for an
unactioned watchful entry, so a stale-read overwrite can move a row the operator just reset straight
into the archive window — **Finding 51's harm arriving from the other side**. Both now carry a CAS
and neither reports a repair it did not make, because that return value drives an operator-facing
WARNING.

⇒ ⭐ **[[grep-for-the-next-first-match]] for the third time on this project, and this time it was
mine.** After fixing "an UPDATE keyed only on its primary key", the very next action should have been
to grep for the other UPDATEs keyed only on their primary key.

### 🟡 Finding 54 — an unreadable `probe_ssids` value is silently overwritten, and the loss is indistinguishable from "never probed"

`merge_device_probe_ssids` decodes the stored JSON list. A corrupt blob **or one that is merely the
wrong SHAPE** yields `[]`, and the `UPDATE` on the next line writes that back. Measured, with a
control that discriminates:

```
CONTROL valid list            ["home-wifi"] -> ["home-wifi","cafe"]   original survives: True
corrupt JSON                  {not json     -> ["cafe"]               original survives: False
valid JSON, wrong shape dict  {"ssid":"x"}  -> ["cafe"]               original survives: False
valid JSON, wrong shape str   "home-wifi"   -> ["cafe"]               original survives: False
wrong shape + NO new ssids    {"ssid":"x"}  -> NULL                   original survives: False
```

⚠️ **The wrong-shape cases never reach the `except` at all** — they decode fine and simply are not
lists. A report describing this as *"a bare except"* is describing the wrong mechanism, and the
handler is in fact `except (json.JSONDecodeError, TypeError, ValueError)`.

✅ **Fixed by logging, deliberately not by preserving.** Keeping an unreadable blob would strand the
column forever; the defect was that the replacement was **SILENT** and left corruption
indistinguishable from the legitimate "this device has never probed anything". A WARNING now names
the MAC and the value. **Acceptance criterion:** an unusable stored value logs a WARNING naming the
device, **and** a valid value logs nothing — without the second half, "always warn" passes.

### 🪤 The prose defect this round, and it is the signature one

`poll_once`'s docstring said *"a device matching **any** allowlist entry is suppressed, **regardless
of any watchlist rules** it would have matched."* True when written; **false since #82**, which split
allowlist entries into HARD (radio-level) and SOFT (device-chosen) precisely so an attacker could not
suppress themselves by broadcasting an allowlisted name. The carve-out lives in
`process_observation` and the docstring never learned about it — for the whole hard/soft rollout.
Now corrected and pinned by a test that fails if the unconditional claim returns.

⬜ **REFUTED, so nobody re-derives it:** a reviewer also called the same docstring's *"order-preserving
and de-duplicating"* claim false because existing duplicates are not removed. The full sentence reads
*"existing SSIDs come first, then any new strings **not already present**"* — it describes de-duping
the NEW values against the existing ones, which is exactly what the code does. **Overstated, not a
defect.**

## Round 18 — `process_observation` swept line by line, and the delivery RETRY had no claim, 2026-08-19

**The largest unaudited surface in the codebase is now swept.** `process_observation`
(`poller.py:555–1309` at `61efb0a`, 755 lines) was named open in three consecutive handoffs; six M3
packets across two sessions returned empty on it. It was read by hand instead.

**The class hunted**: a value is READ, a decision is made from it, and a WRITE (or a SEND) happens
later, with no guarantee the value still holds. `process_observation` has **two callers** — the poll
loop and `bridges/ble.py:391`, on a `ble-bridge` **thread holding its own `Database` on its own
connection**, which `Database._lock` does not serialise — so "the poller is single-threaded" is not
available as a defence here.

### The map — every read→decide→write pair, at `61efb0a` line numbers

| # | pair | verdict |
|---|---|---|
| 1 | `583` `get_device` → `584` `is_new` → `588` `upsert_device`; `is_new` consumed at `1042` `evaluate` | ⬜ **refuted** — two writers both see `is_new=True`, but the alert is the only consumer and `add_alert_if_none_since` (F58) collapses it. With `alert_dedup_window_seconds = 0` duplicates are the documented, tested behaviour (`test_with_dedup_disabled_every_detection_writes_its_own_alert`). |
| 2 | `596` `merge_device_probe_ssids` → `truncated` → log only | ⬜ **refuted** — the decision drives a `logger.warning`, not a write. (The *internal* stale-read there is Finding 54, already registered.) |
| 3 | `626–645` `obs.last_seen` vs `now_ts` → clamp → `insert_sighting` | ⬜ **refuted** — both values are in-memory parameters; no DB read participates. |
| 4 | `655` `allowlist.is_allowed` → suppress → `return` | ⬜ **out of class** — in-memory allowlist object, re-read live per bridge flush. Session 3 owns it. |
| 5 | `793` `get_active_watchful_recurrence_by_mac` → `795` `record_watchful_sighting` | ⬜ **refuted** — the write re-SELECTs *inside* its transaction, returns `None` on a concurrent archive, and CAS-es `last_seen_at`. Guarded by `test_one_observation_cannot_be_counted_by_both_writers`. |
| 6 | `866` ledger read → decide emit vs recover → `add_watchful_escalation_alert` | ⬜ **refuted** — `UNIQUE(entry_id, generation)` (migration 026) is the authority; a failed read degrades to the emit path by design. |
| 7 | `793` stale `watchful_entry` → `1000` `elif watchful_entry.escalated_at` → `_retry_watchful_escalation` | 🔴 **REPRODUCED → Finding 61** |
| 8 | `1050` `resolve_matched_watchlist_id` → alert write with that FK | ⚠️ **UNMEASURED** — a watchlist row deleted between read and write would raise `IntegrityError` into the `except` at `1128`, which re-raises as `RuntimeError` and holds the watermark. That is the designed persist-failure path, so the cost is a held tick, not a lost alert. Not reproduced; recorded so it is not re-derived. |
| 9 | `1102` `get_recent_alert_for_rule_and_mac` → `1115` `retry_alert = recent` → `1256` attempt → `1265` `notifier.send` | 🔴 **REPRODUCED → Finding 62** |
| 10 | `_retry_watchful_escalation` `477–541` → `_deliver_watchful_escalation` `395` | 🔴 **REPRODUCED → Finding 63** |
| 11 | `1104` `is_rule_type_snoozed` → decide skip | ⬜ **refuted** — read→decide only; a snooze expiring mid-tick is benign in both directions. |
| 12 | `1281` `mark_alert_notified` | ⬜ **refuted** — a write with no participating read. |

⭐ **And the third path to the same mechanism was asked for and refuted.** The heartbeat has the
identical delivery-retry shape (`record_heartbeat_notify_attempt` → `notifier.send` →
`mark_heartbeat_notified`, `poller.py:1703–1726`). It is **not** exposed: the only caller is the poll
loop, `bridges/ble.py` sends no heartbeat, and `webui/` only READS heartbeat state
(`latest_delivered_heartbeat_ts`, `count_undelivered_heartbeats`). **One writer, so no claim is
needed** — recorded here so the next sweep does not re-derive it, and so that a future second sender
knows it must take the claim. `record_heartbeat_notify_attempt` was deliberately left unchanged.

⭐ **Six refutations against three findings, and the refutations are the load-bearing half.** This
project's audit is credible because 6 of 11 reported findings once failed reproduction and were
recorded as refuted; the same discipline applies to a sweep's own candidates.

### 🔴 Finding 61 — a reset the operator just performed still re-sent the escalation they cleared

`process_observation` decided one branch from **two different reads of the same row**. `watchful_entry`
is read at `793`, *before* `record_watchful_sighting`; `outcome.entry` is that row as it is *inside*
that write's transaction. The threshold branch (`997`) used the fresh one; the retry branch (`1000`)
used the stale one — and the neighbouring `_emit_watchful_escalation` call already used the fresh one,
so this was an inconsistency rather than a decision.

An operator **reset** landing between the two reads is where they disagree. Reset clears `escalated_at`
precisely so the retry stops (*"clearing `escalated_at` is what removes the retry path"* — Finding 50),
and marks the undelivered escalation `notify_abandoned_at` (migration 027). But
`get_recent_alert_for_rule_and_mac` does **not** filter that column and `_retry_watchful_escalation`
checked only `notified_at` and `notify_attempts`. Measured, reset applied at the seam on a genuinely
separate connection, against a control that resets *first*:

```
CONTROL   reset first, then observe   escalation sends=0   rows=1  abandoned=1
TREATMENT reset between the two reads  escalation sends=1   rows=1  abandoned=1
```

The operator clicked reset on the escalation they were looking at, and the tool told them again —
from the very row the reset had marked abandoned.

✅ **FIXED in two independent places, and both are load-bearing.** The call site now decides from
`outcome.entry`; `_retry_watchful_escalation` now refuses an abandoned row. ⛔ **Either alone closes
the reproduced case**, which is why they were planted separately: plant A (restore the stale read)
reddens only the call-site guard, plant B (remove the abandoned check) reddens only the mechanism
guard, and **only A+B together reproduce the probe**. An outcome-only assertion would have passed
under plant A while appearing to guard it — so the call-site test asserts *which entry the branch
decided from*, not merely that nothing was sent.

### 🔴 Finding 62 — the dedup gate's RETRY arm re-sent one alert to two writers

Finding 58 closed the read→decide→write race on the **insert** arm with `add_alert_if_none_since`,
and its docstring says the other arms are *"deliberately untouched"* — correctly, because routing a
re-send through a conditional INSERT would turn it into a silent skip and reinstate Wave 5
Finding 12. But the *undelivered, attempts left → reuse the row and retry* arm is **also** a
read→decide→send: `notified_at IS NULL` and `notify_attempts < NOTIFY_MAX_ATTEMPTS` are read at
`1102` and nothing re-asserts them at the `notifier.send` at `1265`. Measured, one detection
delivered to both writers, injection asserted to have fired at both:

```
CONTROL   sequential, one connection    alerts=1  sent=1  attempts=2
TREATMENT two connections, interleaved  alerts=1  sent=2  attempts=3
```

One detection; the operator told twice. **The same harm Finding 58 exists to prevent, reached
through the arm its fix excluded.** ⇒ [[a-fix-can-close-the-surface-not-the-mechanism]].

### 🔴 Finding 63 — the same mechanism, second site: the watchful escalation retry

`_retry_watchful_escalation` → `_deliver_watchful_escalation` has the identical shape. ⭐ **This is
not the first-crossing race**, which is closed: migration 026's `UNIQUE(entry_id, generation)`
reservation is taken when the row is **written**, so it bounds how many escalation rows exist and
says nothing about how many times an existing row is **delivered**. Measured:

```
CONTROL   sequential, one connection    escalation sends=1
TREATMENT two connections, interleaved  escalation sends=2
```

"This device appears to be following you" is the most serious message this product sends, and the
operator has no way to tell one sent twice from two real ones.

✅ **FIXED at the mechanism, not per site.** `record_alert_notify_attempt` gained an optional
`expected_attempts`, making the attempt counter that already bounds the retry into a **compare-and-swap
claim on the right to send** — no new column, no migration. Both call sites pass what their dedup read
saw. ⛔ **A lost claim and a raised exception are deliberately distinguishable**: a definite loss skips
(the winner is sending right now), an *error* still sends, because bookkeeping may never cost a
notification (`test_bookkeeping_failure_does_not_cost_the_notification`).

⛔ **The opposite direction was tested, not assumed** — this repo has already shipped a
duplicate-alert fix that made the alert undeliverable. `test_a_lost_claim_does_not_swallow_the_alert_when_the_winner_fails`
races two writers with the notifier **down**: the loser skips, the winner fails, `notified_at` stays
NULL, and the next tick still re-sends. Finding 12 is not reinstated.

⇒ ⭐ **[[ask-how-many-paths-reach-the-mechanism]].** Finding 58 was fixed at one site and the same
shape sat two branches away. The fix here is one primitive in `db.py` applied at both sites, and the
sweep above is what says there is no third.

### The `db.py` half — every method that both READS and WRITES, triaged

Derived, not transcribed: an AST pass over `db.py` (5820 lines) for methods containing a `SELECT`
**and** an `UPDATE`/`INSERT`/`DELETE`, with docstrings stripped **by line range**. ⚠️ The first
version stripped them by text substitution, which silently failed on indentation and produced **4
false positives** — `resolve_matched_ssid_pattern_for_eval` is read-only and was flagged because its
prose says *"escape on insert"*. ⇒ [[iterate-the-derived-set-dont-transcribe-it]] cuts both ways: a
derivation you have not calibrated is not better than a transcription.

**20 methods read and write. 10 re-assert the value they read at the write; 10 do not.** The triage
turns on **how many writers can reach it**, which for this codebase has one answer:

⭐ **`process_observation` is the ONLY function with two callers holding separate `Database`
instances.** Everything else — the whole web UI — is one process on one connection, where the
per-instance `RLock` genuinely does serialise. So the two-writer exposure is exactly *the set of
read-and-write methods reachable from `process_observation`*, which is six:

| method | re-assertion at the write | verdict |
|---|---|---|
| `add_alert_if_none_since` | `NOT EXISTS` inside the INSERT | ⬜ closed (F58) |
| `record_watchful_sighting` | CAS on `last_seen_at` | ⬜ closed (F55) |
| `escalate_watchful_recurrence` | `expected_reset_count` | ⬜ closed |
| `add_watchful_escalation_alert` | `UNIQUE(entry_id, generation)` | ⬜ closed (migration 026) |
| `record_alert_notify_attempt` | `expected_attempts` | ✅ **closed THIS round (F62/63)** |
| `merge_device_probe_ssids` | **none** | 🟡 **REPRODUCED → Finding 64** |

⇒ **With Finding 64 open, every read-and-write method on the two-writer path now carries a
re-assertion except that one.** That is a checkable statement, and it is the closing claim of this
round.

The other four unprotected methods (`upsert_metadata`, `_set_alert_ack`, `bulk_acknowledge_alerts`,
`promote_watchful_to_allowlist`, `reset_watchful_recurrence`, `create_watchful_from_alert`) are
⬜ **refuted for this class**: web-UI-only, one process, one connection. `rollback_to` is an explicit
`lynceus-validate` CLI action. `record_heartbeat_notify_attempt` is refuted by measurement above.

### 🟡 Finding 64 — two writers merging probe SSIDs silently lose one — ⛔ REPRODUCED, **NOT FIXED**

`merge_device_probe_ssids` (`db.py:761`) reads the stored JSON list, merges the new SSIDs in Python,
and writes it back `WHERE mac = ?` — **keyed on the primary key only**. `Database` sets no
`isolation_level`, so Python's `sqlite3` implicitly `BEGIN`s only before DML: the `SELECT` runs in
**autocommit, outside the UPDATE's transaction**, and `with self._conn:` does not begin eagerly.
Both writers read the same list; the second write wins whole. Reached from `process_observation:596`
on both writers whenever `capture.probe_ssids` is on. Measured, injection asserted to have fired at
both writers:

```
CONTROL   sequential   ['home-wifi', 'from-poller', 'from-bridge']
TREATMENT interleaved  ['home-wifi', 'from-poller']        <- 'from-bridge' silently dropped
```

⚠️ **It LOSES rather than erroring** — no `database is locked` — which is what confirms the read sits
outside the transaction.

⚠️ **Distinct from Finding 54**, which is about an *unreadable* stored value being overwritten. This
is a *readable* one being lost.

⛔ **Deliberately left unfixed this round, and here is the reason rather than an excuse.** The
obvious fix — CAS the UPDATE on the value read — has a fail-closed twin: a losing writer that simply
returns has *silently not merged*, which is the same silent evidence loss in a new costume. The
honest fix is a bounded read-CAS-retry loop, and that is a new behaviour on the capture hot path
that needs its own tests, its own planted defects and a full gate. ⇒ **Next session-2 round.**
Probe: `internal/session2-harnesses/probe_ssids_lost_update.py`.

⭐ Severity is 🟡, not 🔴: probe SSIDs are corroborating evidence, not an alert. Losing one narrows
the co-observation corpus; it does not cost the operator a notification.

## Hardening candidates — cost measured, trigger UNPROVEN

⭐ **A distinct verdict, and the register needs it.** These are not confirmed findings and they are
not refuted. Someone measured a real cost, and then could not show that anything can reach it.
Filing them under "still open" overstates them into work that looks owed; dropping them throws away
the measurement. They live here until someone proves reachability — at which point they graduate to
a numbered finding — or proves it is unreachable, at which point they move to Refuted.

⛔ **The rule that puts a thing here: an unbounded write is a LOCATION, not a severity, until you
show who can reach it.** Same bar every delegate finding is graded by; it applies to ours.

| # | Candidate | Cost, measured | What would settle it |
|---|---|---|---|
| H1 | No length bound on device-supplied strings (`kismet.py`) | 200 sightings × 64 KB name = 13.4 MB on disk, **58× a 32-byte baseline** | whether Kismet ever emits an oversized value |
| H2 | The notifier has no TOTAL deadline (**Finding 30**) | a slow server blinds the tool for the whole poll | Kev's call on the deadline value; the defect is real, the *number* is unproven |
| H3 | A temporary allowlist silence consumes "new device" status | the device is never new again once the silence lapses | whether operators use temporary silences that way |

### ⚠️ H1 — the reachability argument is aimed at the wrong field

Reported from `e4288bb5` with the 58× measurement, which reproduces. **The severity argument
attached to it does not**, and the correction changes the fix shape rather than the finding:

> "802.11 caps SSIDs at 32 bytes, so anything longer is malformed by definition."

`kismet.py:560` reads **`ssid = raw.get("kismet.device.base.name")`** — Kismet's *computed display
name* for the device, not the SSID information element. ⛔ **And it is the same key on both flagged
paths**: `_BLE_NAME_FIELD = "kismet.device.base.name"` (`kismet.py:286`, read at `:322`) populates
`ble_local_name` from that identical field. Two of the reported fields, one source. So:

- ⛔ **">32 bytes is malformed" does not hold for either field.** `base.name` is whatever Kismet
  decided to call the device; it is not required to be an SSID and is not bounded by the SSID IE.
  A rejection rule built on 32 bytes would drop **legitimate** records on both paths.
- ⭐ The field that *is* IE-shaped is **`probe_ssids`** (`dot11.probedssid.ssid`, `kismet.py:285`),
  and it is the one already capped — by **count** (`PROBE_SSIDS_PER_DEVICE_CAP = 50`), not length.
- ⇒ Even there the radio ceiling is **255 bytes, not 65,536** — the IE length field is one octet. The
  reachable amplification over a 32-byte baseline is ~8×, not 2048×.

⇒ **The conclusion "do not fix yet" stands, for a better reason than the one given.** The blocker is
not only that reachability is unproven; it is that **nobody has established what this field is
allowed to contain**, and a bound written without that will reject good records. ✅ The
`PROBE_SSIDS_PER_DEVICE_CAP` precedent shows the safe shape: bound the field whose contents are
specified, leave the free-text display name alone.

### ⭐ The generalisation — follow the provenance, not the label

Both halves of H1's wrong argument came from one move: **reasoning from the field's NAME in
lynceus's own model instead of from its SOURCE.** The attribute is called `ssid`, so it was taken to
hold an SSID, so 802.11 was taken to bound it. Nothing in the code says any of that.

⇒ **Check what populates a field before reasoning about what may legally be in it.** This is the
same discipline as **PR #82** one layer up: that fix split allowlist pattern types by **who controls
the value**, not by what the field is called — and the whole defect existed because a *device-chosen*
attribute had been given the authority of an operator-chosen one.

⚠️ And truncation is not free either way: capping `ssid` changes allowlist/watchlist **matching**
for any operator whose pattern is longer than the cap. Rejecting the record as unparseable — there
is already a counter for it — cannot corrupt matching, and is the shape to prefer if Kev wants this
hardened regardless of reachability.

## Reserved for Kev — decisions, not defects

⛔ **Do not decide these unilaterally.** Each changes behaviour for existing deployments.

### 0. ⭐ Finding 52's residual — read→decide→write is unprotected application-wide. **Kev's call, spans all three tracks.**

**Input written 2026-08-19 by session 2, at `61efb0a`. A proposal, not a merge — nothing here has
been implemented.**

**What is actually true today.** Finding 52's `_lock` fixed *transaction ownership* on one
connection. It never addressed *application atomicity*: a value read, decided from, and written
later. Round 18 swept `process_observation` — the largest single instance of the pattern — and found
**three live cases in one function** (Findings 61–63), each closed with a targeted primitive:
`add_alert_if_none_since` (F58), a CAS on `last_seen_at` (F55), a CAS on `notify_attempts` (F62/63),
`expected_reset_count` on the escalation stamp. **Four different bespoke guards for one class.**

**What it costs to keep doing this.** Each new write path must independently rediscover that it has
two writers. The evidence that this does not happen reliably is in the register: F58 was fixed at one
site and the identical shape sat two branches away for three weeks (F62), and F53 was "I added a CAS
to one repair and left its two siblings without it". ⛔ **The sweep is what found these, not the
guards** — nothing in the codebase makes the pattern fail loudly when a fifth site is added.

**The candidate fix, and its blast radius.** Request-scoped connections plus explicit units of work:

| what changes | scale, measured at `61efb0a` |
|---|---|
| `Database` becomes per-request/per-unit rather than one long-lived instance | `db.py` is **5820 lines**; ~42 sync web route handlers share `app.state.db` today |
| every route handler acquires and releases a unit of work | `webui/` — **session 3's track** |
| the poll loop and the `ble-bridge` thread each own their unit per observation | `poller.py`, `bridges/ble.py` — session 2's |
| the four bespoke CAS guards can then be re-expressed as ordinary transactions | but must NOT be removed before the units exist |

**What breaks.** (a) Every test constructing `Database(path)` and holding it — the fixtures in this
repo do this pervasively. (b) `check_same_thread=False` and the per-instance `RLock` become dead
weight and their removal is itself a behaviour change. (c) SQLite writer serialisation moves from
"one connection, one lock" to "many connections, WAL + busy_timeout", so **`database is locked`
becomes MORE reachable, not less**, until a retry policy exists. (d) The Pi is the target: more
connections is more memory and more fds on the smallest deployment.

**What happens if nothing is done.** Nothing breaks today — the three findings are closed and the
sweep is complete for `process_observation`. The cost is ongoing and cumulative: every new write path
is a coin flip, and the register shows the coin has landed wrong three times.

⚠️ **The trap, and it is measured, not theoretical.** The obvious fix for a lost update is a broader
lock, and this repo has already shipped a duplicate-alert fix that made the alert **undeliverable**,
plus a dedup guard on the wrong arm that turned a legitimate re-send into a silent skip (Wave 5
Finding 12). **Every fix in this class must be tested in the opposite direction**, which is why
Finding 61's fix ships with a test that races two writers with the notifier *down*.

⭐ **Session 2's recommendation: do NOT do this now.** Take the cheap half first — a single documented
primitive for "claim before you act" and a test that fails when a new write path skips it — and
defer request-scoped connections until something needs it that a CAS cannot express. The three
findings this round were all expressible as a CAS, which is evidence about the shape of the problem.

1. ⭐ **Should the six commented-out delegating rules ship ENABLED?** (Finding 32.) ⚠️ **Price this
   with Finding 40 in hand:** enabling `watchlist_oui` reads as one switch that turns the type on,
   but **221 of the 444 bundled `oui` rows are on reserved or locally-administered prefixes and stay
   inert regardless** — the eval-time guard discards the observation before the DB is consulted. So
   the switch turns on 223 rows, not 444, and nothing currently says which. Today an operator
   adding an `oui`, `ble_uuid`, `ble_local_name`, `ble_manufacturer_id`, `drone_id_prefix` or
   `mac_range` watchlist entry gets **no alert and no warning**. Enabling them changes what alerts
   for every existing deployment. The safe subset — warn in the UI when an entry's type has no
   delegating rule — is a separate, smaller change.
2. **`imei_tac` capture-side support**, or removing the type from the UI (Finding 32). It cannot work
   as shipped.
3. **The notifier's total deadline** (Finding 30 / H2) — the defect is real, the *number* is yours.
4. `rollback_to` refusing to unstamp a migration it could not revert — a documented contract.
5. ⭐ **Web UI authentication — the evidence is COMPLETE, so this is a priced decision rather than an
   open worry.** Measured by session `d47d7e0b`; **independently re-measured on `1e0fdef`**,
   2026-08-15, and unchanged (their run was at `0e199dd`, four merges earlier):

   ```
   POST routes, DERIVED from the live app                 23
   changed persistent state for an UNAUTHENTICATED caller 22
   refused — on a DOMAIN precondition, not access control  1   (/devices/{mac}/watch)
   control: the same requests with NO CSRF token         403   — CSRF refuses, and is not auth
   ```

   ⭐ **The route set is derived from the running app, not from the probe's own list.** Four merges
   landed between the two measurements; a route added by any of them would have been silently missed
   by a hardcoded list. Both agree at 23, so coverage is complete rather than assumed.

   ⚠️ **Method, because the number is only as good as it:** every POST issued with no credential of
   any kind, then **every row of every table plus both allowlist files** diffed after each request. A
   hand-picked fingerprint reports "no change" for whatever it forgot to look at, which turns an
   unmeasured route into a clean bill.

   **What an unauthenticated caller achieves:** silence an entire rule type (`/rules/{t}/snooze` —
   `rule_type_snoozes` 0→1 in one request); write an arbitrary allowlist pattern, so **a device can
   allowlist itself**; acknowledge **every** alert in one call (11 `alert_actions` rows); lift
   existing suppressions; and write operator-attributed notes and verdicts nobody typed.

   ⛔ **The scenario to price:** an adversary lynceus exists to notice, who can reach the port, can
   **allowlist their own MAC and snooze the rule type that would have caught them — one POST each —
   and the dashboard looks clean afterwards.**

   **What must NOT be double-counted, both verified as controls:**
   - **CSRF works and is not authentication.** Tokenless requests are refused 403, so a blind
     cross-site POST fails; a direct caller (curl, a script, anything on the LAN) simply GETs a page
     first to collect the cookie. `csrf.py`'s docstring is accurate and claims no more.
   - **The default bind is loopback**, and `config.py` refuses to start on a non-loopback host
     without an explicit `ui_allow_remote: true`. LAN exposure exists only where an operator opted
     in — but on a default install the surface is still every local user and process on the box.

   **Three shapes, ascending cost:** (a) a shared secret in a header/cookie for all non-GET routes;
   (b) single-user password + session; (c) leave it and document that the port is
   trusted-equivalent. ⚠️ **(c) is the current de-facto posture and is defensible for a
   loopback-only install** — the real gap there is that nothing says so anywhere an operator would
   read it. **Nothing has been implemented. This is Kev's call and it is large.**

   📌 The full per-route consequence table lives in `internal/session2-harnesses/auth_table.md`,
   which is **gitignored** — that is why the measurement is summarised here rather than referenced.
   Guarded by `tests/test_webui_post_routes_are_classified.py`, which fails when a POST route is
   added, so the surface cannot widen while this decision is outstanding.
6. The diagnostics assert-or-delete verdict; the heartbeat shipping off by default;
   `.mailmap`/dependabot authorship; de-identifying the withheld test files.
7. ⛔ **Rotating the two ntfy topics on the broker** — scrubbed from the tree, still live in git
   history. Reported dead 2026-08-15; **confirm and close** rather than leaving listed.
8. ⭐ **What does `--reconfigure` mean for a RELOCATED file?** (Finding 36.) `allowlist_path`,
   `severity_overrides_path` and `db_path` are `apply_config` arguments derived from
   `paths.default_*_path(scope)`, never read from the operator's config. So `--reconfigure` repoints
   an operator who moved their allowlist at a freshly scaffolded **empty** one, and every device they
   had suppressed starts alerting. **Adopt the operator's location, or relocate them?** Either answer
   is defensible and the current behaviour is one of them by accident rather than by choice. This is
   the whole residual of Finding 36 — 3 of the 40 settings — so deciding it closes the finding.
9. ⭐ **What to do about the 221 inert bundled OUI rows?** (Finding 37.) Half the shipped `oui`
   corpus is on locally-administered prefixes and can never match. Options, none free: drop them at
   import (changes the shipped corpus and the `/watchlist` count every operator already sees); keep
   them and surface them as inert in the UI (session 2's #91 does this for rules, not data); or fix
   it upstream in Argus, since an LA-bit "OUI" is not an IEEE assignment and is likely a randomised
   MAC recorded as a vendor prefix. ⛔ **Deliberately not patched** — any of the three changes what
   the operator sees.
10. ⭐ **Is "hard vs soft" the right boundary, given a MAC is also broadcast?** (#82, sharpened by the
    rig round.) The split treats `mac` / `mac_range` / `oui` as HARD because *"a device cannot present
    someone else's MAC without actively spoofing the address it transmits on, which is a different and
    more detectable act"*. ⚠️ **Nothing in lynceus detects that act** — "more detectable" is a
    property of the world, not of this tool. So an attacker who spoofs a MAC the operator has
    allowlisted gets **full suppression of an explicit watchlist hit**.
    ⛔ **#88 widened this, and I should say so plainly:** before it, a soft entry sitting above the
    hard one accidentally let such a hit through; now the hard entry wins regardless of order. That
    accident was the bug #88 fixed, and removing it is correct under the documented design — but the
    design's premise is what is worth re-examining, not the ordering. **Tightening to nothing, or
    dropping the hard class, both break the feature** (BLE randomises addresses, which is why soft
    matching exists). This is a design question, not a patch.
11. **Should the allowlist gain an `ssid_pattern` type?** (Finding 35.) `ssid_pattern` is one of only
   three watchlist types that fire on the shipped ruleset, and an operator cannot suppress by the
   same predicate they watched on — only by an exact `ssid` or a `mac`. ⚠️ It is not a free fix: a
   substring allowlist silences **everything** containing the needle, so one line in a hand-edited
   file could blanket-suppress a whole class. The comment claiming parity is now corrected either
   way; this is the capability question, and it is yours.

## Still open

⚠️ **Audited 2026-08-15 and four entries were removed as already closed** — see the note below this
list. Everything here has been checked against `main` on that date; a bullet with no date has not.

⛔ **RE-AUDITED 2026-08-16 at `7eb96b8` — and read what that sentence covers, because it is narrow.**
What was checked: that every open item known to the three tracks running that day appears here, and
that the file/line anchors below still point at what they name. **What was NOT checked: the substance
of any bullet.** Nothing here was re-measured. This is a completeness pass over the list, not a
verification pass over its claims — [[label-context-with-what-you-ran-not-what-you-concluded]], which
this file learned the hard way one section down.

**From the original audit — carried forward, none re-measured:**

- **The watchlist report's provenance-cross-link claim** — unverified, lower severity. Genuinely
  open: nobody has measured it. 🪤 **Its line anchors have ROTTED and are corrected here**: the entry
  cited `webui/app.py:3766`, which after #125–#128 is co-observation pair code and has nothing to do
  with provenance. Cite the file and the symbol, never the line — this file has now been bitten by a
  line number twice.
- **The ntfy DEBUG topic leak** — a maintainer decision, not a defect. See the correction above.
- **`py/clear-text-storage-sensitive-data` on the Windows branch** — needs DPAPI or an explicit
  DACL. Not a patch; a Windows-only design item.

**Open as of 2026-08-16, and absent from this list until now — which is exactly the failure the note
below describes, running in the other direction:**

- 🟡 **Finding 41 — the DB/poller half is now REPORTED; ONE POPULATION REMAINS OPEN.** ⚠️ This bullet
  said *"NOT STARTED and UNCLAIMED … the single largest open item in the file"* and is **narrowed,
  not closed** — re-read Finding 41's 2026-08-16 disposition rather than this line. A snooze written
  by a clock that was right at install and later fell back (**dead RTC battery**) is now detected by
  an ordering fact and warned about at WARNING. ⛔ **Still open: the install whose clock was wrong
  from its very first migration** — the floor is stamped by that same clock, so the discriminator is
  silent, and this is the RTC-less-Pi residual the entry always named. ⭐ Also recorded there: the
  clock-trust hold is **not** a mitigation for this defect, so the earlier framing of the purge as
  the harm was wrong.
- 🔴 **Finding 52's RESIDUAL — read→decide→write is still unprotected.** The lock fixes transaction
  ownership, not application atomicity: a thread can read state, another can change it, and the first
  acts on the stale read. Closing it needs request-scoped connections and explicit units of work —
  **a decision shared by all three tracks, not a patch.** ⚠️ Also still open: **C-2**, the
  allowlist YAML lost update (`add_ui_entry` read-modify-write), which is session 3's.
- 🟡 **Finding 51 — the `db.py` half is FIXED; the ROUTE half is open and is session 2's.**
  `reset_watchful_recurrence` now clamps `last_seen_at` so a reset cannot move an entry backwards
  into the archive window (measured: all behind-clock cases now survive). Still open:
  `watchful_reset_post` is the one duration-adjacent web write with **no `refuse_if_clock_behind`
  gate**, so the operator is never told their clock is wrong — they simply get less than they asked
  for. ⛔ Not to be "fixed" by widening the archive window.
- 📋 **UNVERIFIED LEADS, nobody has measured these** (from an M3 same-source-reference sweep; the
  rest of its 17 candidates restate the Finding 41 class): the **retention prunes**
  (`prune_old_evidence` / `prune_old_sightings`) may silently double the retention window after a
  clock correction, and **`_check_poller`'s staleness test** decides whether the home page claims the
  daemon is alive. Both sit in Round 12's UNSWEPT list. Cite as leads, never as findings.
  - ✅ **MEASURED 2026-08-17 (session 3): the retention half is REFUTED — the window does not
    double.** Oldest surviving row measured **30.00 days** on a 30-day policy; the effective window
    is `retention_days` + at most one prune cadence. The real exposure is the opposite direction (a
    clock AHEAD deletes *inside* the window), which was already found and gated on 2026-08-14 and is
    proven by a parametrised take-effect pair. Full correction beside the original entry above;
    probe `internal/session3-harnesses/retention_direction_probe.py`.
    ⚠️ **`_check_poller`'s staleness test is still unmeasured** — that half of the lead stands.
- 🟡 **Finding 50 — registered, NOT patched.** An operator reset cancels the retry of an undelivered
  escalation and leaves a permanent, unclearable line in the heartbeat's *"written but never
  delivered"* count. ⛔ The obvious fix — windowing the counter — is the **unsafe** direction: it
  would also hide a genuinely broken ntfy topic, which is the silence that counter exists to break.
- 🟡 **Finding 44 — registered, NOT patched.** One duplicate escalation is reachable between the row
  write and the stamp. ⛔ The obvious dedup is the **unsafe** direction (it suppresses the genuine
  escalation of a RESET entry); closing it honestly needs a generation-keyed escalation record, i.e.
  a migration.
- ~~🟡 **A daemon-side duplicate-key warning for `config.py` and `rules.py`** (Round 14 residual).~~
  ✅ **CLOSED by #130 (`68f5bb7`) — see Finding 49.** ⛔ **Struck through rather than deleted, because
  the half-life is the lesson:** this bullet was written into this list at 15:0x and was false by
  15:2x, in the same session, by another session's merge. It was also **understated** while it stood
  — "small", when the same mechanism silently disarms the dead-man's switch.
- ⚠️ **`/watchful/{entry_id}/reset` was never exercised** by Round 13's form-field sweep — it renders
  only on an already-escalated entry. **Unexamined, not cleared**, and the distinction is the point.
- ⚠️ **Round 12 named three things it could not see and they are still unseen:** the retention prunes
  and the clock-trust holds (both live in `poll_once`, which that instrument never reached), and
  **concurrency** — every measurement on that track was single-threaded, and the poller/web-UI race
  that makes `database is locked` reachable was *simulated by raising*, not reproduced.

⇒ **This list drifted in BOTH directions within two days**: on 2026-08-15 it held four bullets that
were already fixed, and on 2026-08-16 it was missing five items that were genuinely open — including
the biggest one. The first kind wastes a session's work; the second kind loses it. **A "Still open"
list is a claim with an expiry date, and it needs re-deriving from the rounds above, not editing in
place.**

⇒ **And the expiry is shorter than anyone writes it for.** One bullet above was added and closed
**inside the same hour, by a parallel session's merge that landed while this file was being
written**. With several sessions running, "still open" means *open at the moment of writing* and
nothing more. **Re-derive it, and never quote it to decide what to work on without re-reading `main`
first** — that is how two sessions end up building the same fix, which has already happened three
times on this project.

### 🪤 This section was itself stale, and said so in its own text

**Four of its six bullets were CLOSED**, and the register announced that inline while leaving them
filed under "Still open":

```
🟡 Finding 25 — fixed in PR #30.                                  <- filed under "Still open"
✅ Finding 21 is fixed (#28), Finding 22 (#25), Finding 23 (#26)  <- filed under "Still open"
```

Verified rather than believed before moving them — all four are on `main`: **#25 `8609fc9`,
#26 `4993e9c`, #28 `7571d57`, #30 `2dca5fb`.** Finding 24 was **withdrawn on verification**, which is
neither open nor fixed and now sits in Wave 7 where it was withdrawn.

⇒ **A "Still open" list is a claim with an expiry date, exactly like a number is.** Anyone scanning
it to answer *"what is outstanding?"* got four false positives — and the failure is in the direction
that wastes work, since each looks like something to go and fix. Same class as the day's other three:
prose that was accurate when written and quietly stopped being.

⇒ **Date the audit, not just the entries.** The header line above says when this list was last
checked against `main`, so the next reader knows how much to trust it rather than guessing.

## Closed since the audit

⚠️ **Audited 2026-08-16 by a cold cross-model read, for one specific failure: a finding marked FIXED
when only the SURFACE it was reported against was addressed.** That is not hypothetical — Finding 41
was marked ✅ FIXED here for the length of one review before its own fix's author corrected it.

⛔ **The audit found this heading doing the inverse of what "Still open" was doing yesterday:**
entries filed under ✅ whose own text says the residual is *not* closed. Marked inline below rather
than moved, because the fix genuinely landed and only the residual is open.

⇒ **Before adding a ✅ here, re-run the finding's ORIGINAL measurement — not the fix's own tests.**
A fix's tests pass and are usually honest; they simply cover what the fix set out to do. **The
question is how many paths reach the mechanism and whether the fix sits on all of them.**

### ✅ The four CANNOT TELLs, RESOLVED by supplying what the audit asked for

The 2026-08-16 audit returned **CANNOT TELL** for four "fixed" findings and named exactly what it
needed: the original reproducer and the patch. Both were supplied. ⭐ **Three closed at the
MECHANISM, not merely at the reported caller** — which is the distinction that had gone wrong in
Finding 41:

| finding | verdict | why it closes the mechanism |
|---|---|---|
| **21** — config rewrite left secrets world-readable | ✅ **CLOSED** | the defect was reusing an existing permissive inode, which `os.open(..., mode)` cannot change; the fix `os.fchmod()`s the **descriptor** before any secret is written |
| **22** — a Kismet re-run widened operator hardening | ✅ **CLOSED** | the defect was replacement with a NEW inode carrying default `0644`; the fix snapshots `S_IMODE` off the existing target and reuses it, while still honouring the requested mode when the file does not exist |
| **25** — raw driver error in an unauthenticated 503 | ✅ **CLOSED** | `_check_db()` returned `str(exc)` verbatim; the fix substitutes a fixed public message for **every** caught exception and keeps the detail in `logger.exception()` |
| **23** — five URL guards that could not fail | ⬜ **PARTIAL → REFUTED**, see below |

⇒ ⚠️ **`sightings` retention is deliberately absent.** Its original acceptance criterion was never
recorded, so **no evidence I could supply would resolve it.** It stays registered as unprovable
rather than guessed at.

### 🪤 The one PARTIAL was caused by MY packet, again — this time by truncation

The audit ruled Finding 23 **PARTIAL**, stating: *"no supplied hunk wires those three tests to
`_map_link()`"*, and that a look-alike host would still reach the old substring assertions.

⇒ **Measured: `_map_link` is wired at three call sites** (`tests/test_webui_evidence.py` lines 149,
190, 454) — exactly the three guards it named. **The verdict is wrong about the code and was
LITERALLY ACCURATE about what I sent it**; it even hedged, "*As shown*…".

**The cause, measured:**

```
commit message lines           42
full `git show` output        157
my packet kept (head -110)    110   <- window ends at `return tag, href`,
                                        the last line of the helper DEFINITION
```

⛔ **`head -N` on `git show` silently eats the diff when the commit message is long**, and this
project writes 40-line messages. The audit saw a helper being *defined* and never saw it *used*.

⇒ **This is the second false finding my own packet assembly produced, and it is a different shape
from the first.** The heading incident asserted a conclusion the evidence did not support; this one
**removed the evidence that would have changed the conclusion**. ⚠️ Truncation is the sneakier of the
two, because nothing is asserted — the context is merely incomplete, and `head -N` is the natural
thing to write. **Cap patches by `--stat` first, or pass the diff whole; never trim a `git show` by
line count.**

### ⬜ Refuted by the audit — recorded so it is not re-raised

The audit ranked **Finding 31 as PARTIAL**, on the grounds that the seeder is a second watchlist
writer that bypasses `add_watchlist` and would leave the derived `mac_range` columns NULL.
⇒ **Measured: false as of #86.** `cli/seed_watchlist.py` has no `INSERT INTO watchlist` at all — it
delegates to `add_watchlist`, and the only remaining bypass is the Argus importer, which **does**
populate `mac_range_prefix`/`_length` and **rejects** an underivable pattern rather than storing an
inert row.

### ⛔ CORRECTION — I blamed the wrong thing for that, in this file, an hour ago

The paragraph above originally ended: *"the audit reasoned from this register's own historical text
describing the pre-#86 state. A register that records history in the present tense will mislead the
next reader."* ⇒ **That explanation was wrong, and I published it here and in my notes before
checking it.** Finding 31's text is correctly PAST-tensed — *"`add_watchlist` and the seeder each
**had** their own byte-for-byte INSERT"*, *"rows from the other two write paths **were** inert."*
The register was not the source.

⭐ **The actual source was a heading I wrote in the audit prompt.** I pasted a grep under the label:

```
=== the OTHER writers that bypass add_watchlist (relevant to 31/37/40) ===
  src/lynceus/cli/import_argus.py:1361:  "INSERT INTO watchlist("
  src/lynceus/db.py:2704:               "INSERT INTO watchlist (pattern, pattern_type, ..."
  src/lynceus/db.py:2816:               "INSERT INTO watchlist_metadata(...)"
```

⛔ **`db.py:2704` IS `add_watchlist`.** `db.py:2816` writes a different table. **Not one line under
that heading is an `add_watchlist` bypass except the importer** — the label asserted a conclusion the
evidence beneath it did not support, and the reader believed the label.

⇒ **A heading you write over pasted evidence is read as a FINDING, not as a filing label.** It
carries your authority, it is not checked against the lines below it, and it is the one part of a
prompt nobody treats as a claim. **Label context with what you ran, never with what you concluded** —
`grep 'INSERT INTO watchlist' src/` describes the same three lines and asserts nothing.

⚠️ **And the meta-lesson, which is why this correction is in the register rather than quietly
amended:** I diagnosed a confident wrong finding with a confident wrong cause, in the same file, in
the same hour — and the wrong cause was *more* satisfying because it blamed a document rather than
me. **An explanation that fits is not evidence; check the artefact before publishing the diagnosis.**

### ✅ …so I tested the corrected diagnosis instead of asserting it too

⚠️ The paragraph above replaced one confident causal story with another. **A second explanation that
fits is still not evidence.** So it was run as a controlled A/B — same model, same effort, same
291-line context, **one line changed**:

| arm | the heading over the pasted grep | Finding 31 verdict |
|---|---|---|
| original | `the OTHER writers that bypass add_watchlist …` | **PARTIAL** — false |
| **control** (re-run of the original) | *unchanged* | **PARTIAL** — reproduces |
| **treatment** | `output of: grep -rn "INSERT INTO watchlist" src/lynceus/` | ✅ **CLOSED** — correct |

⭐ **The control is the arm that makes this mean anything.** Had the false finding not reproduced, the
treatment coming back clean would have been run-to-run variance read as a result — the exact shape of
the three invalid controls recorded in round 10.

⇒ **And the mechanism is visible in the control's own words:** *"the inline material still identifies
a seeder/direct `INSERT` in `db.py` that bypasses `add_watchlist`."* It is reading **`db.py:2704`,
which IS `add_watchlist`**, as a bypassing writer — because the heading said those lines were
bypasses. The treatment instead reasoned from the evidence: *"the supplied `INSERT` inventory no
longer shows an independent seeder insert."*

⚠️ **Honest n:** two runs of the control, one of the treatment. Small, and these models are
non-deterministic — but the effect is large, reproduced, and the causal mechanism is quoted verbatim
in the output rather than inferred. **Stated as a measured result with its sample size, not as a
law.**

- ✅ **`--min-confidence` range validation** — enforced at parse time (`_confidence_percent`, values
  outside 0–100 fail with exit 2), so a typo can no longer import nothing and exit 0. Was the
  behaviour change flagged "Kev's call"; done deliberately as the operational-trap fix it described.
- ✅ **The three `/settings` cards now say "then restart the daemon"**, matching the BLE and severity
  cards (`settings.html`).
- 🟡 **`sightings` retention — closed as a CAPABILITY, not as a behaviour.** Landed in PR #11
  (`sightings_retention_days`), **off by default**. ⚠️ If the original finding was "retention cannot
  be configured", this closes it; if it was "sightings grow without bound", **a default install still
  does exactly that.** Flagged by the 2026-08-16 audit and left as-is because the original acceptance
  criterion is not recorded — ⇒ **which is itself the lesson: a finding whose criterion was never
  written down cannot be proven closed.** The "unchanged across four handoffs" note is retired.
- 🟡 **Finding 36 — PARTIAL, not closed.** `--reconfigure` reverting hand-edited settings, fixed in
  PR #87 (`08299cc`) for 37 of the 40 settings, **plus a regression it introduced, fixed in #96**.
  ⛔ **Its residual is still reachable:** the three `apply_config` path arguments. An operator who
  relocated their allowlist and re-runs `--reconfigure` is still repointed at a freshly scaffolded
  empty one, and every device they had suppressed starts alerting. That is decision 8 under
  "Reserved for Kev" — **deciding it closes the finding; nothing else will.**
- ⚠️ **Finding 38** — the interface-kind misdiagnosis, fixed in PR #90 (`be65b8f`) **and then again
  in PR #96 (`f0e6e9b`), because #90 shipped the same defect in the mirror direction.** This line
  read "Nothing residual" and that was **false when I wrote it** — see the correction under Finding
  38 itself.
- ✅ **Finding 21** — a config rewrite leaving the secrets world-readable, fixed in PR #28
  (`7571d57`). Verified on `main` 2026-08-15; was misfiled under "Still open" until then.
- ✅ **Finding 22** — a Kismet re-run widening an operator's own hardening, fixed in PR #25
  (`8609fc9`). Verified on `main` 2026-08-15.
- ✅ **Finding 23** — five URL guards that could not fail on the defect they guard, fixed in PR #26
  (`4993e9c`). Verified on `main` 2026-08-15.
- ✅ **Finding 25** — a raw DB driver error returned in an unauthenticated 503, fixed in PR #30
  (`2dca5fb`). Verified on `main` 2026-08-15.
- ✅ **Finding 33** — a soft allowlist entry above a hard one silently defeating it, fixed in PR #88
  (`350035a`). Guarded by `tests/test_allowlist_match_precedence.py`.
- ✅ **Finding 31** — the inert `mac_range` row, fixed in PR #84. Guarded by
  `tests/test_watchlist_pattern_types_are_wired.py`.
- ⬜ **Finding 24** — **withdrawn on verification**, not fixed. Filed in Wave 7 where it was
  withdrawn; listed here only so nobody re-opens it looking for a fix that never existed.

## Method note

Do not run gates from a throwaway worktree. A worktree relocates `Path(__file__).parents[1].parent`
and **silently disables** the cross-repo Argus test — it skips rather than fails, so the suite looks
better than the repo root's baseline. Measured this session: worktree reported 0 Argus failures
where the repo root reports 1. See `.claude/gates.md`.

⭐ **A second, worse worktree trap, measured 2026-08-14.** The development venv has `lynceus`
installed **editable, pointing at the primary checkout**. Running `pytest` from a worktree therefore
imports the *primary checkout's* `src/`, not the worktree's — so the run grades a different tree than
the one you are editing, and says nothing about it:

```
cd /home/kev/lw-s1 && python -c "import lynceus; print(lynceus.__file__)"
  -> /home/kev/lynceus-warden/src/lynceus     # the WRONG tree, silently
PYTHONPATH=/home/kev/lw-s1/src  ... same command
  -> /home/kev/lw-s1/src/lynceus              # correct
```

Export `PYTHONPATH=<worktree>/src` before gating in one. 🪤 It produced a **false negative inside
this wave's own verification**: a reproduction script that hardcoded the primary checkout's path
reported the just-merged Finding 22 fix as still broken, because the primary checkout's `main` was
several commits behind. ⇒ **Assert which tree you imported before believing any worktree result.**

⭐ **This repo's CodeQL check reports a MOVED alert as a NEW one.** Measured on PR #28: the check
went red with *"3 new alerts including 3 high severity"*, one of which was
`py/clear-text-storage-sensitive-data` on an expression that is **byte-identical to the one already
open on `main`** — it had merely shifted from `core.py:209` to `:226` because a docstring above it
grew. Verified with `git show origin/main:src/lynceus/setup/core.py | sed -n '209p'` against the
branch's `:226`. ⇒ **Any PR that edits a docstring above a flagged line goes red for free. Diff the
flagged expression against `main` before treating a CodeQL alert as introduced.** The alert
re-anchors itself on merge. ⛔ Do not "fix" this by dismissing alerts or by rewriting a literal into
something the analyser cannot resolve — that games the tool and hides a tracked design item.

---

## Cross-cutting rules learned 2026-08-14 (Wave 7 fallout)

These came out of building on top of Wave 7's fixes rather than from the triage itself. Each is
**measured**, and each generalises past this repo.

### ⭐ An untrustworthy clock fails in OPPOSITE directions per subsystem

Session 3 measured a forward wall-clock excursion **deleting data inside the retention window**:
`retention_days=30`, 30 daily sightings, clock +30d → **29 of 30 deleted**. `evidence.py` carries
the same defect and is **on by default** (`evidence_retention_days: int = 90`, while sightings
retention is opt-in) — +90d deleted **9 of 10** snapshots under ten days old. A *backward* excursion
is the inverse: a future anchor stalls pruning for the whole excursion (no prune until +366d).

The same `0 <= elapsed < interval` guard fixes the stall in both retention and the heartbeat — but
**what "safe" means is opposite in the two places**:

| Subsystem | Clock cannot be trusted → | Because |
|---|---|---|
| Retention / evidence pruning | **do NOT prune** | deleting capture data is unrecoverable |
| Heartbeat / dead-man's switch | **DO send** | a spurious heartbeat costs one notification; a suppressed one costs the entire guarantee |

⛔ **If anyone later unifies these behind one clock helper, that asymmetry must survive the
refactor.** It is precisely the kind of distinction a tidy-up flattens into a single "is the clock
sane?" predicate, and flattening it silently breaks whichever side it did not have in mind.

⚠️ **Not fixable in the leaf modules, and that was proven rather than assumed.** In `retention.py`,
"the clock jumped forward" and "the table holds only old rows" are the *same observation*, and
`test_sightings_retention.py::test_returns_none_oldest_when_table_is_emptied` **requires** the second
to delete everything. Any elapsed-based bound is computed from the same corrupt clock — circular.
The wall clock enters at `poller.py:1555` and `:1654`; the leaf modules' `int(time.time())` defaults
are **dead in production** because the poller always passes `now_ts` down. ⇒ The real fix is a
`time.monotonic()` anchor taken at daemon start, serving retention, evidence and the heartbeat
together. **Not yet done.**

### ⭐ A template that asks for an undefined CSS class renders NOTHING, silently — and an undefined FILTER does not

1. Wizard replacement listeners appended **after `{% endblock %}`** — Jinja discards anything outside
   a block, so they rendered nothing while looking correct in source.
2. A filter form marked `class="grid"` against the **classless** Pico build, which defines no such
   class — eleven controls stacked full-width.
3. The heartbeat's `/settings` card used a `ts_to_local` filter and a `badge-status-warn` class,
   **neither of which exists**.

⛔ **CORRECTION — the sentence that stood here was wrong, and it was wrong in the direction that
overstates the problem.** It read: *"Jinja resolves an unknown filter or an unknown CSS class to
silence, never to an error."* **The filter half is false.** Measured against the real `/settings`
route with `| ts_to_local` planted back into the template (anchor asserted unique, plant verified
applied, tree verified clean after restore):

| What is undefined | Visibility | What catches it |
|---|---|---|
| Jinja **filter** | **LOUD** — `TemplateAssertionError` at *compile* time → HTTP **500** | any test asserting a 200, or a status-code crawl |
| **CSS class** / markup contract | **SILENT** — HTTP 200 with plausible-looking HTML | only a cross-check against the vendored `lynceus.css` |

⚠️ **Both historical instances are the silent kind** — the post-`{% endblock %}` listeners and
`class="grid"` against classless Pico are markup/CSS, not filters. So the class is *mostly* silent,
and the one filter case was the single member of it that was never actually dangerous.

⇒ **Three occurrences is still a pattern, but of the CSS/markup half only.** The rule stands with a
narrower blast radius: **assert the rendered output contains the thing, not merely that the page
rendered** — the presence-beside-absence rule applied to templates. A status-code crawl is
sufficient for filters and **useless** for markup contracts.

🪤 **How the wrong version got written, which is the more useful lesson:** two faults were found in
the same grep — a missing filter and a missing CSS class, in the same card — and a single mechanism
was inferred from finding them together. ⇒ **This is `an alert location is not a severity` at a
different altitude: having the location of two faults says nothing about whether they share a
cause.** Separate the symptoms before generalising from them. Corrected by the author of the
original claim, who measured it rather than defending it.

### ⚠️ Adding a migration breaks hardcoded version lists in five separate places

Migration 025 (heartbeats) broke `tests/test_validate.py:722`
(`assert db.applied_versions() == list(range(1, 25))`) **after** its author had already found and
updated the filename manifest, three rollback version literals and both config-documentation gates.
CI caught it; nothing local did.

⇒ **Before adding a migration, `grep` for the current HEAD version as a literal.** Better, derive
the list: `tests/test_migration_replay.py` discovers `HEAD_VERSIONS` by an **independent glob**,
deliberately not via `Database._iter_up_migration_files`, so a broken runner cannot grade itself —
and so a new migration does not start a scavenger hunt. That census correctly classified 025 as
`REPLAY_RAISES_OPERATIONAL` ("table heartbeats already exists") on the first migration added after
it landed.
