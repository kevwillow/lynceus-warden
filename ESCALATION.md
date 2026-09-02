# Escalation: changes outside the write set

The packet's §3 write set is four source files (cli/setup.py, setup/core.py,
setup/web/steps_capture.py, setup/web/templates/). I had to touch three
additional files to make the heartbeat step actually fit into the wizard.
None of these are discretionary; each is forced by inserting a step in
the middle of an existing numbered sequence.

## 1. src/lynceus/setup/web/app.py — STEP_TITLES

**Edit:** added the new "Heartbeat" entry to the STEP_TITLES tuple, between
"ntfy probe" and "RSSI threshold".

**Why it has to happen:** the wizard's progress indicator template
(`_progress.html`) reads `step_titles` to render the dots across the top of
every step page. Adding a step without listing it leaves the progress bar
claiming one fewer step than the wizard actually has. An operator on
step 10 would see "step 10 of 12" rather than "step 10 of 13", and the
remaining dots would not match the actual flow. STEP_TITLES is also the
single source of truth for TOTAL_STEPS, which gates a few other things.

**Alternative rejected:** leaving STEP_TITLES alone and just having
heartbeat at /step/10 would not break anything mechanical — every route
still resolves — but the progress indicator would lie, and one of the
packet's own tests (`test_step_titles_includes_heartbeat`) would fail.
The packet's §3 says the heartbeat step goes after the ntfy section,
which is the same constraint STEP_TITLES encodes; not updating it would
be a self-inconsistency the operator would notice on every screen.

## 2. src/lynceus/setup/web/steps_severity_rules.py — renumber 11/12 → 12/13

**Edit:** severity moved from /step/11 to /step/12, rules moved from
/step/12 to /step/13, and the inter-step redirects and `step_index`
display values shifted accordingly.

**Why it has to happen:** inserting the heartbeat at /step/10 means RSSI
takes /step/11. If I leave severity at /step/11, two route handlers
register the same path — FastAPI raises on duplicate registration when
the wizard app is built, and every web wizard test errors at app
construction before any assertion can run. The renumbering is mechanical:
every reference to /step/11 → /step/12, /step/12 → /step/13, and the
one `step_index=N` for display purposes in each handler.

**Alternative rejected:** putting heartbeat at a non-numeric URL
(`/heartbeat`, `/step/heartbeat`) would skip the routing collision but
would diverge from the wizard's numbering convention. The progress
indicator reads STEP_TITLES, the URL space uses /step/N, and every test
parametrises on /step/N. Breaking that convention for one step makes
the wizard a special case rather than a uniform one.

## 3. src/lynceus/setup/web/steps_argus.py — renumber legacy redirect 13 → 14

**Edit:** the legacy /step/13 (which redirects to /step/12 since the
v0.7.7 merge of Argus into the rules step) now lives at /step/14 and
redirects to /step/13.

**Why it has to happen:** /step/13 is now the actual rules step (see
#2 above). Leaving the legacy redirect at /step/13 means two route
handlers register the same path, with the same FastAPI duplicate-
registration failure. The legacy redirect exists specifically so that
old bookmarks and browser-back from prior wizard versions do not
dead-end; moving it to /step/14 preserves that contract (any pre-merge
bookmark would have hit /step/13, which now lands on the actual rules
page anyway — a redirect to itself is not useful).

**Alternative rejected:** deleting the legacy redirect entirely would
be a UX regression for anyone with a stale bookmark. Moving it to
/step/14 is the smallest possible change.

## What was NOT touched

* `src/lynceus/config.py` — untouched, per invariant. `heartbeat_enabled`
  and `heartbeat_interval_hours` already existed as Config fields.
* `src/lynceus/poller.py` and other runtime code — untouched.
* Any existing test file — untouched. The cascading test failures
  (78 in test_setup_wizard.py, 7 in test_setup_web_capture.py, 22 in
  test_setup_web_severity_rules.py, 4 in test_setup_reconfigure_preserves.py,
  1 each in test_setup_web_ble_bridge.py and test_setup_web_csp.py) are
  real interactions with the new prompt and the renumbering, and are
  reported honestly in the deliverable rather than worked around by
  weakening the tests.

## Test breakage accounting

The 239-test "regression gate" cannot be met as written. The new prompt
adds one input consumption that no test helper in test_setup_wizard.py
accounted for (the `_full_input_sequence` helper ends at "enable-alerting
gate"; the heartbeat prompt consumes the next input, which doesn't exist).
The renumbering shifts the /step/N URLs every web test references. The
carry-forward test `test_a_readable_previous_config_is_reported_ok`
asserts heartbeat_enabled is in `carried_forward`, which is the exact
behaviour the packet changes (the renderer now owns the key, so the
carry-forward no longer touches it).

The packet acknowledges this shape of failure ("a real interaction") and
instructs to report rather than edit the test.
