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

## Still open

- The watchlist report's provenance-cross-link claim (`webui/app.py:3766`,
  `watchlist_detail.html:97`) remains unverified and lower severity.

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
