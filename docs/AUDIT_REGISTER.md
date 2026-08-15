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
name* for the device, not the SSID information element. So:

- ⛔ **">32 bytes is malformed" does not hold for this field.** `base.name` is whatever Kismet
  decided to call the device; it is not required to be an SSID and is not bounded by the SSID IE.
  A rejection rule built on 32 bytes would drop **legitimate** records.
- ⭐ The field that *is* IE-shaped is **`probe_ssids`** (`dot11.probedssid.ssid`, `kismet.py:285`),
  and it is the one already capped — by **count** (`PROBE_SSIDS_PER_DEVICE_CAP = 50`), not length.
- ⇒ Even there the radio ceiling is **255 bytes, not 65,536** — the IE length field is one octet. The
  reachable amplification over a 32-byte baseline is ~8×, not 2048×.

⇒ **The conclusion "do not fix yet" stands, for a better reason than the one given.** The blocker is
not only that reachability is unproven; it is that **nobody has established what this field is
allowed to contain**, and a bound written without that will reject good records. ✅ The
`PROBE_SSIDS_PER_DEVICE_CAP` precedent shows the safe shape: bound the field whose contents are
specified, leave the free-text display name alone.

⚠️ And truncation is not free either way: capping `ssid` changes allowlist/watchlist **matching**
for any operator whose pattern is longer than the cap. Rejecting the record as unparseable — there
is already a counter for it — cannot corrupt matching, and is the shape to prefer if Kev wants this
hardened regardless of reachability.

## Still open

- The watchlist report's provenance-cross-link claim (`webui/app.py:3766`,
  `watchlist_detail.html:97`) remains unverified and lower severity.
- 🟡 **Finding 25** — fixed in PR #30. **Finding 24 withdrawn**, see above.
- **The ntfy DEBUG topic leak** — a maintainer decision, not a defect. See the correction above.
- **`py/clear-text-storage-sensitive-data` on the Windows branch** — needs DPAPI or an explicit
  DACL. Not a patch; a Windows-only design item.
- ✅ **Finding 21 is fixed** (PR #28) and **Finding 22** (PR #25) and **Finding 23** (PR #26).

## Closed since the audit

- ✅ **`--min-confidence` range validation** — enforced at parse time (`_confidence_percent`, values
  outside 0–100 fail with exit 2), so a typo can no longer import nothing and exit 0. Was the
  behaviour change flagged "Kev's call"; done deliberately as the operational-trap fix it described.
- ✅ **The three `/settings` cards now say "then restart the daemon"**, matching the BLE and severity
  cards (`settings.html`).
- ✅ **`sightings` retention** — landed in PR #11 (`sightings_retention_days`, off by default). The
  "unchanged across four handoffs" note is retired.

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
