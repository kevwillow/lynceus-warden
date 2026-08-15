# Changelog

All notable changes to this project will be documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- **A heartbeat, so that silence means something.** Every other failure mode in
  lynceus raises an alert. What was left is the daemon dying or notification
  delivery breaking — and there the operator's only symptom is silence, which
  looks exactly like "nothing is out there". With `heartbeat_enabled: true`,
  lynceus pushes a periodic "still watching, N sightings in the last 24h, last
  alert Xh ago", so a heartbeat that *stops* arriving is itself the signal.

  ⛔ It never claims health it has not verified. If the poll loop has wedged, if
  observations are failing to persist, or if alerts were written but never
  delivered, the heartbeat says so explicitly and is sent at a higher priority
  instead of the quiet one — a cheerful "all good" sent while ingest is dead
  would be worse than no heartbeat at all, because it converts unease into false
  confidence. A quiet RF environment is deliberately *not* treated as unhealthy;
  that is the normal case for this tool.

  It rides the delivery-tracked path added in migration 024, so a failed
  heartbeat is retried (bounded) rather than costing a whole interval of
  silence, and the interval is measured from the last *delivered* one rather
  than the last attempted one. `/settings` reports whether the switch is armed
  and when it last arrived, because a dead-man's switch nobody has verified is
  a guarantee nobody is actually getting. Off by default; requires ntfy.

- **A Content-Security-Policy, with a per-request nonce.** The UI had none —
  measured; only `CSRFMiddleware` was installed — while several internal
  documents asserted that "a strict CSP applies". Escaping was the only barrier
  between an operator-controlled MAC, SSID or location name and script
  execution. A nonce rather than hashes because the `data_table` macro
  *generates* an inline script per table, so no static hash list could cover
  it. `style-src` still allows inline: nine `style=` attributes remain and
  nonces do not apply to style *attributes*, so the compromise is confined to
  styles while `script-src` stays strict.

  ⚠️ **Adding a CSP is not a header change; it is an audit of every inline
  handler in the app**, and this one found sixteen. The dashboard had eleven
  `onsubmit="return confirm(...)"` guards on destructive actions. A nonce
  authorises `<script>` *elements*, never `on*=` attributes — verified in
  headless Chromium: *"Executing inline event handler violates the following
  Content Security Policy directive… The action has been blocked."* And the
  failure was worse than losing the dialog: `onsubmit` cancels a submit by
  *returning false*, so a handler blocked outright never returns and **the form
  submits immediately**. "Permanently silence this device" would have become a
  single unconfirmed click that suppresses its future alerts.

  All eleven now use `data-confirm` with one delegated capture-phase listener —
  capture phase because these forms carry `hx-post` and htmx binds its own
  submit handler. The setup wizard, which had **no CSP at all** despite holding
  the Kismet key and ntfy topic in flight and sometimes running as root, gets
  the same policy; applying it surfaced five more inline handlers there,
  including the double-submit guards on `/apply`.

- **Continuous integration.** `pytest`, `ruff check` and `python -m build` now
  run on every push and pull request across Python 3.11 and 3.12. The README
  invites readers to check its claims by running the suite, and until now
  nothing ran it automatically. The traps recorded in `.claude/gates.md` are
  encoded in the workflow rather than left as tribal knowledge — in particular
  that `ruff format --check` is red by design and is reported without gating,
  and that the packaging test skips itself silently when `python` is not on
  `PATH`.

- **`CONTRIBUTING.md`.** What the project wants (passive detection only; claims
  that survive checking; silence must never be ambiguous), how to run the
  gates, and the two testing habits that matter more here than volume: plant
  the defect before trusting a guard, and remember that a double which can only
  succeed cannot test a failure path.

- **A co-observation explorer, so you can see which devices keep turning up
  when you do.** `/devices/<mac>/co-observations` shows the other devices
  logged close in time to one device, at the same location. The query behind
  it has existed since 0.9.5 and **nothing called it** — the feature was
  complete in the database and invisible to an operator.

  **It makes no statistical claim, and that is the feature.** There is no
  score, no confidence band, no ranking of suspicion. Sensor uptime is not
  recorded anywhere in the schema, so absence of data cannot be told apart
  from a quiet device or a device that was not there, and no number would be
  defensible. The panel reports counts you read; it does not reach a verdict.
  An earlier scored design was withdrawn after it was measured returning
  maximum confidence for the always-present neighbour it existed to demote —
  that design now ships as a tombstone under `docs/superpowers/specs/` so the
  reasoning is not lost.

  Both run denominators are shown, because they are not the same number: five
  candidate runs inside one anchor run are not five events. The range and the
  proximity window are rendered, not merely requested, since `sightings` has
  no retention policy by default and an unstated horizon would silently
  control every result. Truncation is stated outright. Clicking a pair reveals
  **the actual logged sighting rows and the real Δt between them**, so a count
  can be audited rather than trusted — and that list says plainly that its
  rows are sighting pairs, not encounters.

  ⛔ **Off by default, and that is a security control rather than a
  preference.** Iterating the route across every MAC reconstructs an
  association graph. While the capability is off the route answers exactly as
  it does for a device that does not exist, so the toggle cannot be used to
  confirm which MACs you have seen. Every query is audit-logged. Enable with
  `co_observation.enabled: true`.

- **`sightings` can now be pruned, after never having a retention policy.**
  At a 60-second poll interval one continuously-present device adds roughly
  1,440 rows a day, so the table grew without bound and eventually filled a
  Pi. Set `sightings_retention_days` to bound it.

  ⛔ **Unset by default, meaning nothing is ever deleted** — exactly what
  every existing install already does. Deleting observation history is
  irreversible, and an upgrade that silently discarded your evidence would be
  a data-loss bug shipped as a feature. Alerts are never touched; they are
  your record of what was decided and outlive the observations behind them.

  Two things worth knowing if you turn it on. `devices.sighting_count` is an
  incrementing counter rather than a row count, so pruning cannot decrement
  it — `/devices/<mac>` therefore states outright that older sightings were
  deleted, instead of letting "showing N of M" imply they are still
  retrievable. And retention may not be shorter than
  `co_observation.window_days` while that panel is on, because the panel would
  then claim a period the database no longer covers; that is rejected when the
  config loads.

- **Lynceus now receives ASTM F3411 Remote ID over BLE, not just DJI's
  DroneID.** Kismet's UAV phy decodes DJI's proprietary format, which was 51 of
  427 drone rows in the reference capture — 12%. The other 88% broadcast the
  open standard and were invisible. A drone's serial now arrives through the
  BLE bridge and matches the existing `watchlist_drone_id_prefix` rules.

  Two things were in the way, and the second was not the obvious one. The
  bridge never read `service_data`, which is where Remote ID rides. But fixing
  that alone would have changed nothing, because the frame never arrived: the
  passive scan matches adverts against a BlueZ pattern set, and a Remote ID
  advert is a *single* service-data element filling all 31 bytes of the legacy
  payload — no Flags element, no manufacturer data, so it matched nothing and
  BlueZ dropped it before the bridge ever saw it.

  Adding the pattern took the set to eight, and eight is one too many. That
  ceiling was measured rather than assumed, over matched 20-second windows:
  seven patterns captured 14 devices / 81 frames, eight captured **nothing at
  all** — and eight captured nothing even with no Remote ID pattern involved,
  which is what proves the limit is the *count* and not the new pattern. So one
  Flags value (`0x00`) was traded for it and the set stays at seven. What that
  trade costs was undetectable over those windows, which is not the same as
  zero.

  The wire format is verified against two independent sides of the reference
  implementation rather than written from memory. The decoder keeps the
  bridge's existing promise: it reads the advertisement payload, returns the
  derived serial, and retains nothing.

  ⚠️ **This has not yet been tested against a real drone.** Every test uses
  fixtures built from the specification, and the Wi-Fi half of the standard is
  not implemented.

- **Every web UI page now carries the AGPL §13 source offer** — version,
  licence identifier, and a link to the corresponding source, in the footer.

  It is rendered from Jinja environment globals rather than from each route's
  context dictionary, and that is a deliberate choice rather than a
  convenience: the site header's version number comes from per-route context,
  so a handler that forgets the key renders an empty string. For a version
  number that is cosmetic. For a licence obligation it is a compliance failure
  that nothing would report. The guard enumerates routes from the app itself
  instead of a hardcoded list — currently 10 HTML routes, all covered — because
  a list stops covering a new route silently, which is a failure mode this
  project has now hit three times.

  ⚠️ If you modify Lynceus and let anyone else reach your instance, §13 makes
  *your* modified source the thing that has to be offered. Point
  `SOURCE_URL` in `webui/app.py` at wherever you publish it.

### Changed

- **The alert action buttons no longer resize when you use them.** Acknowledge,
  unack and Watch were sized by their own labels — measured at 124px, and 68px
  for Watch — so acknowledging a row swapped the label to "unack" and the
  button shrank under the cursor. All three now occupy one fixed rectangle
  (150×44) in every state, and the state is carried by colour: solid for the
  action that is available, muted outline for the undo. 44px because that is
  the tap-target floor this project already applies to the home page's ack
  button and had never applied here — these were 30px tall.

- **The action column is pinned, so the buttons are always on screen.** Both
  alert tables are wider than a 1400px viewport (the /alerts table measured
  2120px inside a 1360px wrapper), and the action column sat past the right
  edge behind a horizontal scroll. It is now sticky. The column budget was cut
  as well — 2120px to 1739px — by capping the columns that were spending
  width on nothing: the checkbox column alone took 75px to hold a 13px control.

- **The /alerts filter form stopped eating the page.** It marks itself
  `class="grid"`, and the vendored Pico is the *classless* edition which
  defines no such class — the identical trap already documented for
  `.container-fluid`. Eleven filter controls therefore stacked full-width and
  pushed the first alert roughly 450px down the page. The stylesheet now
  supplies the grid the template always asked for, and the page is 5863px tall
  instead of 8341px.

- **The homepage got navigation tiles and a chart worth reading.** Six tiles
  carry live counts and link to each section, so "is anything wrong over
  there?" is answerable without clicking. The alerts-per-day strip — one flat
  colour, no axis, no dates, so a busy day and a bad day drew the same bar — is
  now stacked by severity with a labelled axis and a legend, backed by a new
  `alerts_per_day_by_severity` query. The screenshots in `docs/images/` were
  regenerated: all five were taken at v0.9.4, before the dashboard restructure,
  and showed a homepage that no longer existed.

- **Relicensed from MIT to AGPL-3.0-or-later, with a commercial licence
  available.** The intent is unchanged from what the project has always been:
  use it, run it, modify it, sell it. What the new licence adds is
  reciprocity — everyone you pass it to gets the same freedoms and the same
  source. AGPL rather than plain GPL because §13 extends that obligation to
  people who only ever reach the software *over a network*, and a daemon whose
  primary interface is a web UI is exactly the case GPL leaves open.

  If you want to build Lynceus into something closed, that is what
  [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md) is for.

  **This is not retroactive, and that matters.** Every release up to and
  including 0.9.5 was published under MIT, and those rights are irrevocable for
  those versions. Anyone who took the code under MIT keeps it. AGPL binds from
  this commit forward. Dual licensing is only possible at all because the
  repository has a single copyright holder; `.mailmap` is now tracked so that
  `git log --format='%aN <%aE>' | sort -u` returns one line in a clone and not
  just on the author's machine.

  The dependency closure was scanned before committing to this: all 23 runtime
  packages are MIT, BSD-3-Clause, Apache-2.0, MPL-2.0 or PSF-2.0. **No GPL-2.0-
  only dependency exists**, which is the one licence that would have been
  incompatible. The vendored Pico CSS keeps its own MIT licence.

### Fixed

- **A watchlist entry for a Bluetooth tracker could never match anything.**
  This is the one that matters most, because it is the thing the tool is for.
  Bluetooth devices announce themselves with a short service code — `fd5a` is
  Apple's Find My, the one an AirTag uses. When you added `fd5a` to your
  watchlist, Lynceus expanded it to the full-length form the standard defines.
  When it *saw* that same code on the air, it did not: it rejected the short
  form as invalid and quietly discarded it. So the two halves of the tool were
  writing the same thing down in two different ways, and a tracker following
  you could sit in range all day without ever matching the rule you had written
  to catch it. There was no error to notice — the discard was logged at debug
  level, which nobody reads.

  Both halves now write it the same way. ⚠️ The first attempt at this fix went
  too far: it reused the watchlist's text handling on the incoming-signal side
  as well, and that handling also strips a piece of commentary the surveillance
  database is allowed to attach to a code. Correct when reading a watchlist
  file, wrong when reading the air — it would have accepted, as a genuine
  sighting, something that was never broadcast. The incoming side is now
  strict again and only the shared expansion is shared.

- **A clock jump no longer deletes a rule you silenced.** If you tell Lynceus
  to stop alerting on a category for a week, that instruction is stored with an
  expiry date and checked against the system clock. When the clock leapt
  forward — an NTP correction after boot on a Pi with no battery-backed clock —
  the housekeeping pass read those expiry dates against the wrong time and
  deleted the ones it thought had lapsed. Measured: a snooze set to last seven
  days was **erased at a jump of eight**, and putting the clock right did not
  bring it back. You would simply start receiving alerts you had deliberately
  turned off, with nothing to explain why. The same jump also retired entries
  from the watchful list early.

  Both now pause while the clock is untrusted and resume once it settles, which
  is the same treatment the retention cleanups already had.

- **When the "Kismet has stopped" warning failed to send, you were never told
  again.** Lynceus watches Kismet, and when Kismet disappears it pushes one
  "Kismet unreachable" message. That message is the only thing standing between
  you and hours of silence that looks exactly like a quiet street. It was sent
  once and then recorded as delivered whether or not it actually arrived — so
  if your phone was out of signal at that moment, which is likeliest while you
  are moving, the warning was gone and nothing tried again. Measured with
  notifications failing: **one attempt, nothing delivered, and no retry across
  seven polls**, while capture stayed stopped. Worse, when Kismet came back you
  were sent "Kismet reachable again", announcing the end of an outage nobody
  had told you about.

  It now tries up to four times and only treats the warning as delivered when
  it actually is. If all four fail it says so plainly in the log instead of
  claiming success, and it will not announce a recovery from an outage you were
  never warned of.

- **Your watchlist total was wrong, and it under-counted the newest entries.**
  The list of pattern types the app knew about had drifted two migrations behind
  the database, which accepts ten. Rows of the two newest types — SSID patterns
  and IMEI TACs — were counted as zero rather than reported, so `/healthz.json`
  under-reported the watchlist and the `/settings` breakdown hid them. Measured
  on three entries of three types:

  ```
  rows actually in the watchlist : 3
  total the app reported         : 1
  ```

  The same stale list also made **"add to watchlist" fail outright** for those
  two types, and made the YAML seeder skip six of the ten. There were three
  independently drifted copies of the list; there is now one, checked against
  the database's own constraint so a future migration cannot outgrow it quietly.

- **Filtering the watchlist by a type the page did not recognise silently showed
  you everything.** `/watchlist` and `/watchlist.csv` dropped an unrecognised
  filter and answered with every row, with nothing saying the filter had been
  ignored. The filter is still lenient — old bookmarks keep working — but the
  page now says *"filter ignored — showing all entries"* and names it, and the
  CSV export logs a warning rather than quietly exporting everything.

- **A clock jump no longer deletes data inside your retention window.** If the
  system clock leapt forward — an NTP correction after boot on a Pi with no
  real-time clock — pruning computed its cutoff from the wrong time and deleted
  sightings that were well inside the window. Measured: with a 30-day retention
  and 30 daily sightings, a +30d jump deleted **29 of 30**. Evidence snapshots
  had the same fault and are on by default: a +90d jump deleted **9 of 10**
  snapshots less than ten days old. A jump *backwards* was the mirror image —
  pruning stalled for the entire excursion, measured at a full year.

- **A clock jump no longer blinds the daemon to every device.** The poll cursor
  was written from the jumped clock, so later polls asked Kismet for devices
  "since the future" and got nothing back — for as long as the excursion lasted,
  looking exactly like a quiet environment. Unlike a skipped prune this was
  persistent: the bad value was already stored, so correcting the clock did not
  undo it.

- **Re-running the Kismet setup no longer widens the permissions on your own
  hardened config.** `lynceus-bootstrap-kismet` rewrote `kismet_site.conf` by
  replacing the file, which reset it to world-readable each time. Kismet honours
  `httpd_password=` there, so an operator who had correctly locked that file to
  `0600` had it reopened to `0644` — password still inside — by an unrelated
  `--add-source` run. Measured `0600 → 0644`. It now keeps whatever permissions
  the file already had.

- **Re-writing the main config no longer leaves your Kismet API key
  world-readable.** `lynceus.yaml` was written in a way that only set safe
  permissions when creating the file for the first time. Every rewrite —
  including `--reconfigure` — left an already-permissive file exactly as it was
  and put the Kismet API key and ntfy topic back into it. Measured: a `0644`
  config stayed `0644` with the secrets in cleartext.

- **`/healthz.json` no longer hands a raw database error to anyone who asks.**
  The endpoint is unauthenticated and reachable from the network once
  `ui_allow_remote` is set, and it returned the underlying SQLite driver message
  — including the database file path — on failure. The real error still goes to
  the server log.

- **`--interface` now warns when the device you named is not there.** It used to
  accept any name without checking, write a capture source for it, and report
  success — so a typo produced a sensor that captured nothing while looking
  healthy. It is a **warning, not a refusal**: the flag exists to configure
  adapters that are not plugged in yet, and blocking that would break the reason
  it was added.

- **Acknowledging every alert at once now asks first.** The bulk acknowledge
  button on `/alerts` took a single click to acknowledge every matching alert,
  and there is no bulk undo — reversing it meant acknowledging each alert back
  individually.

- **"← Previous" is visually distinct from "Next" again in the setup wizard.**
  Both rendered as identical filled primary buttons on all thirteen steps: the
  class meant to de-emphasise the back button matched no rule in the stylesheet
  the wizard actually loads, and an earlier fix that made the two buttons the
  same size removed the last thing distinguishing them.

- **A device whose sighting fails to persist is no longer lost forever.** The
  poll watermark advanced to the tick time unconditionally, and the next tick
  asks Kismet only for devices seen since that value — so any observation that
  failed to persist was never asked for again. That is the normal case, not an
  edge one: Kismet reports devices seen *during* the window while the watermark
  is set to the window's **end**, so nearly every observation has a `last_seen`
  older than the tick that processed it. Measured with the device last seen five
  seconds before the tick:

  ```
  device last seen at 1699999995; tick ran at 1700000000
  after poll 1: persisted=['01']  watermark=1700000000
  after poll 2: asked Kismet since=1700000000 -> returned NOTHING
  ```

  A car with an ALPR that drives past once, during a disk hiccup, left no
  alert, no row, and one WARNING line.

  ⚠️ The obvious fix is wrong, and the old code was already defending against
  it: holding the watermark until everything persists lets a record that fails
  *every* time freeze it forever, leaving the daemon alive and permanently
  blind to everything after it. Both extremes lose capture data, so the bound
  is the design — the failed window is retried for up to three consecutive
  ticks, then abandoned with an **ERROR**, because a permanent hole in
  detection coverage is not a warning. Verified by planting both extremes.

- **A transient ntfy failure no longer swallows the alert for a full hour.**
  The alert row was committed *before* delivery was attempted, and the dedup
  gate keyed on that row existing. So a send that failed logged a warning and
  was never retried: the next poll found the row it had just written and
  skipped the emit path entirely. At the default `alert_dedup_window_seconds`
  of 3600, **one blip cost an hour of alerting for that device and rule.**

  Measured with a notifier failing a single poll while the device stayed in
  range for five: two send attempts, **zero delivered**, no further attempt.
  This is the product's reason to exist failing on its most likely error — the
  deployment is mobile, so a data blip is *most* likely exactly when something
  worth detecting is nearby.

  Dedup now keys on **delivery**. Migration 024 adds `notified_at` (NULL means
  written but nobody told) and `notify_attempts`. Three states, and collapsing
  any two reintroduces a defect: delivered in-window suppresses; undelivered
  with attempts left **retries the existing row** — emitting a new one would
  fill `/alerts` with duplicates of one detection every time ntfy hiccuped;
  undelivered with attempts spent stops retrying but stays `NULL`, so it is
  still counted rather than quietly forgotten. Bounded at four attempts,
  counted *before* each send so a wedged notifier cannot retry forever.

  Re-measured on the same scenario: delivered on the very next poll, one alert
  row, correctly deduplicated thereafter.

  ⚠️ A one-shot rule cannot be retried by construction —
  `new_non_randomized_device` only fires on a device's first sighting, so a
  failed send there has no later poll to retry on. That row stays undelivered
  and is reported as such, which is why the count exists and not just a retry.

  **`/settings` now shows undelivered alerts.** Reachability is a *liveness*
  probe: it says the broker answered just now, not that anything arrived. A
  wrong topic or a stale auth token passes reachability and drops every
  notification, and the operator's only symptom is silence — which for this
  tool is indistinguishable from "nothing is out there".

  Why it survived a green suite: **every notifier double in the repo returned
  `True` unconditionally.** A double that cannot fail cannot test a failure
  path. `tests/test_notify_delivery.py` adds one that can.

- **The dashboard tells you when it cannot alert at all.** Argus-backed
  alerting is opt-in and defaults to *no*, and declining it writes no
  `rules.yaml` — so accepting every setup default produces a daemon that
  captures, populates the dashboard, and can never raise an alert. Measured
  two ways against a device placed on the watchlist: **0 rule hits** on the
  default path, **1** with the shipped ruleset wired.

  The home page did surface it, as an unstyled tile reading "no ruleset
  configured" — ranked *below* a merely-stale watchlist, which gets a warning.
  The one condition meaning nothing can ever alert was the only one not
  flagged. It now reads **"no ruleset — nothing will alert"** and carries the
  warning treatment, in words as well as colour. It stays short of the red
  reserved for a ruleset that is configured and will not load: an unset path
  is a legitimate fresh-install state, not a fault.

- **The filter button sat 20px above every other control, on all six list
  pages.** Pico gives a bare `<button>` a 20px bottom margin, and the grid
  aligns *margin* boxes, so the button floated exactly its own margin above the
  inputs beside it. It had also kept Pico's full ~3rem height while its
  neighbours were deliberately reduced — so fixing only the margin would have
  bottom-aligned a button standing 16px proud instead. Both corrected;
  measured `bottomSpread=0, topSpread=0` across `/alerts`, `/allowlist`,
  `/devices`, `/probes`, `/watchful`, `/watchlist` and `/rules`.

- **One co-observation page no longer re-scans the whole capture 25 times.**
  `shared_probe_ssids` counted, for each shared network name, how many devices
  in the entire capture had ever probed it — a correlated subquery expanding
  `probe_ssids` with `json_each`, and no index can find a JSON array element by
  value, so every call visited the whole corpus. The page then called it once
  per candidate, up to 25 per render.

  Measured with SQLite's progress handler, growing only the count of unrelated
  devices: 100 → 208 ticks, 300 → 616, 900 → 1840, 2700 → 5512. A dead-straight
  2.04 ticks per added device. That is the same shape as the
  `candidate_coverage` column the v3.1 amendment *rejected* for measuring 8.95×
  at 9× corpus; this one measured 8.85× and shipped, because the corpus-cost
  guard its sibling query got was never extended to it.

  The corpus scan itself is irreducible while SSIDs live in a JSON array —
  exact rarity is a question about the whole capture. What is gone is the
  per-candidate multiplier: one scan per page instead of 25. A page render with
  25 candidates against an 8,000-device capture drops from 240,763 progress
  ticks to 8,826, a **27× reduction**, and the displayed numbers are unchanged —
  the new query is checked row-for-row against the implementation it replaced,
  including the malformed-payload, non-array, non-string-element and
  no-shared-names cases.

  ⚠️ In the default configuration this cost never arose: probe capture is off,
  so the query returned immediately. It only affected operators who had turned
  probe capture on.

- **The co-observation audit log records the misses, not only the hits.**
  Decision 6 rejected rate limiting and kept the audit log as the *only*
  enumeration control. With the capability enabled, a request for a MAC that is
  not in the database returned 404 and logged nothing at all: the audit line sat
  next to the query it described, one branch after the existence check returned.
  Enumeration is overwhelmingly misses, since the attacker is guessing MACs, so
  a sweep of 20,000 MACs holding 50 real devices left 50 lines indistinguishable
  from ordinary browsing and 19,950 silent probes. The control chosen to make
  enumeration visible was blind to it.

  The inversion was the tell: with the capability *off* every request was
  logged, so the trail was complete when there was nothing to steal and full of
  holes when there was. Every branch now logs, and the drill-down — which
  returns the exact times two devices were logged together — is recorded
  separately with its target named, instead of hiding behind the generic query
  line.

  ⚠️ This does not reopen the probe oracle. The added lines are server-side
  only; every response is byte-identical to before, re-verified across the full
  toggle × MAC-state × parameter-validity matrix.

- **A location named with an ampersand no longer breaks the co-observation
  drill-down.** `location_id` was interpolated into the drill-down link
  protected only by Jinja autoescaping, which escapes HTML metacharacters and
  not URL ones. A site called `Home & Office` rendered `loc=Home &amp; Office`,
  so the browser sent `loc=Home` plus a stray parameter, the exact-match gate
  failed, and the drill-down silently rendered nothing — 200, no error, evidence
  section simply absent. The panel exists so a count can be checked against the
  rows behind it rather than taken on trust, and for any site with an ampersand
  in its name it had quietly stopped being checkable.

  With a crafted location it was worse than a broken link: Starlette keeps the
  last value of a scalar query parameter, so one candidate's link could resolve
  to a different one and the page would show the wrong pair under the right
  heading. Location IDs are operator configuration rather than captured data, so
  the crafted form needs config access; the accidental form needs only an
  ampersand in a place name.

- **The co-observation coverage split no longer promotes the weaker
  association.** The rule was a single condition — at least 20 runs *and* a
  shared share of 25% or less — so the run-count gate produced a cliff that ran
  backwards. A device sharing 1 of its own 19 runs (5.3%) was shown as a primary
  candidate, while one sharing 5 of its own 20 (25%), a five times stronger
  overlap by the panel's own measure, was set aside as explained away. Nothing
  under 20 runs could be set aside however weak its association.

  The cause was two buckets for three states: "too few runs to classify" was
  rendered identically to "not explained away". There is now a third group,
  **Too few runs to say**, which states plainly that it is not a weaker version
  of the main table but the set the panel cannot place either way. The 20-run
  threshold is kept rather than tuned — it is the right caution, it was simply
  being used to make a claim it cannot support. A thin record with a *high*
  share deliberately stays a primary candidate: a short record is a reason to
  withhold judgement about a small share, never a reason to set aside a large
  overlap.

  ⚠️ The thresholds themselves (20 runs, 25%) are still validated only against
  seeded data, never a real capture.

- **A clean BLE shutdown no longer reports itself as a crash.** On bleak 3.x —
  which is what a fresh `pip install 'lynceus[ble]'` gets you — stopping the
  scanner raises a D-Bus error on the *normal* path, because BlueZ has already
  discarded the scan monitor by the time it is asked to. The bridge treated
  that as a scan failure, logged "BLE scan failed; restarting in 5s", and
  slept. Every ordinary shutdown looked like a fault, and a genuine error
  occurring in the same cycle would have been hidden behind the fake one. Only
  that one specific error is now tolerated; every other teardown failure still
  surfaces.

## [0.9.5] - 2026-08-02

The BLE bridge shipped in 0.9.4 with a prompt asking whether you wanted it,
and one way to answer yes and get nothing. `bleak` was never a dependency of
anything, so no documented install path put it in the venv, and an enabled
bridge logged a single warning at startup and then behaved exactly like a
working bridge that had heard nothing. `/settings` made it worse by naming
two causes, neither of them the real one. That is closed, and the rest of
this entry is the surrounding drift it surfaced.

### Added

- **The test suite is in the repository.** `tests/` was excluded by three
  overlapping patterns, so a clone carried nothing and `make test` exited 5
  with "no tests collected". A reader could not check a single claim the
  README made, and CI had nothing to gate on, which is an odd position for a
  project that tells you to read the source before trusting it.

  118 files ship, 110 of them test modules, covering the rules engine, the
  importer, the database and its migrations, the web UI, the setup wizard,
  redaction, CSRF, and the Continuity decoder. A clone runs 3024 tests; the
  full local suite is 3508.

  Eleven files stay out, and the reason is the one the README always gave:
  they describe a real rig. Six embed the capture adapter's identity, as the
  `wlx<mac>` interface name or the `00:c0:ca` OUI it derives from, one hard-
  codes the rig account path, and one is a capture-chain probe document. They
  are now listed by name in `.gitignore` so the exclusion can be audited,
  rather than inferred from a `*tests*` glob. A new test that hard-codes a
  real adapter or host belongs on that list.

  Publishing them turned `ruff check` red for the first time, because ruff
  respects `.gitignore` and had never linted the directory. 81 mechanical
  findings, all fixed.

- **Screenshots in the README.** The dashboard, the alerts triage row, the
  watchlist filtered to plate readers, and the `/settings` card reporting a
  missing `bleak`. Captured against the repo's synthetic fixtures, so every
  MAC on screen is a test value rather than a real capture.

- **`bleak` is now an installable extra, and a missing install is reported
  rather than inferred.** `pip install 'lynceus[ble]'` provides it, pinned
  `>=0.22,<4.0`. The upper bound is deliberate: bleak 3.0 deprecated the
  `adapter=` kwarg that `bridges/ble.py::_make_scanner` passes and moved
  adapter selection onto `BlueZScannerArgs`, so 4.0 is where the current
  call breaks. `install.sh` still does not install it, because the bridge
  ships off and the extra pulls a D-Bus and BlueZ stack a Kismet-only
  deployment never touches.

  The new `check_bleak_available` probes the interpreter with `find_spec`,
  so neither the web UI nor the wizard drags bleak's asyncio and D-Bus
  machinery into its process to ask a yes/no question. It is deliberately
  one-directional: a missing package is decisive and warns, a present one
  says nothing, because bleak also needs BlueZ 5.55 and a free adapter and
  neither is visible from there. `check_bridge_readiness` keeps its pure,
  config-only contract; a new `collect_bridge_warnings` composes the
  environment check with the three config gates and is what `/settings`,
  `lynceus-setup`, and `lynceus-setup --web` all call. The environment
  check leads, since with no scan library the other findings are academic.

### Fixed

- **The wizard's setup token no longer reaches the uvicorn access log.**
  The token rides in the query string, which is how an operator gets it
  into a browser, and uvicorn builds its access-log request line from the
  full path including the query. Every wizard request therefore printed
  `GET /?token=<secret>` to stdout, which is journald on a headless host
  and a file under `sudo lynceus-setup --web | tee install.log`. Low
  severity on its own, since the token is per-run and the server binds
  loopback, but `cli/setup.py` already redacts the ntfy topic from the
  wizard summary for exactly this reason. The dashboard keeps its access
  log; nothing secret appears in its URLs.
- **`/settings` no longer explains a dead bridge with the wrong causes.**
  With bleak absent and the configuration otherwise clean, the readiness
  result was empty and the panel said the likely causes were no Apple
  device in range or an adapter unavailable at daemon start. The
  environment check now fires first, so that branch cannot be reached
  while a real explanation exists.
- **A wholly-unmatched Argus import no longer reads as breakage.** Roughly
  43% of the bundled corpus (17,952 of 41,508 rows) is intelligence with
  no passive-RF expression: hostnames, cloud endpoints, certificate
  hashes, firmware strings, regulatory codes. Those now log at DEBUG and
  report as an expected split naming each type and count. The point is the
  inverse case: an Argus release that adds a genuinely RF-observable type
  Lynceus has not mapped raises a WARNING naming it, instead of vanishing
  into the same bucket and quietly shrinking coverage.
- **The BLE smoke runner's production guard no longer depends on one
  developer's home directory**, and the non-loopback bind error no longer
  cites v0.2 as the version with no auth layer.

### Changed

- **`make lint` and `make format-check` are separate targets.** `lint` runs
  `ruff check .` and is expected to pass. Formatter drift moved to its own
  target, which currently fails and will until someone does a dedicated
  reformatting pass; folding it into `lint` only teaches people to ignore a
  permanently red gate.
- **Three README claims that overstated were corrected**, including the
  watchlist row count, which quoted the export size rather than what actually
  lands in the database.
- **The configuration reference covers every field.** Six had drifted past
  the docs, including both nested blocks (`capture` and `ble_bridge`),
  which are the privacy-relevant ones. `docs/PROJECT_STATUS.md` stopped
  claiming a version number, having fallen two minor releases behind twice.

## [0.9.4] - 2026-08-01

The Bluetooth work from 0.9.3 met real hardware, and real hardware had
notes. Two of them were the kind that do not announce themselves: the
bridge could not see a single Apple device and said nothing about it, and
the flag meant to tell a tracker away from its owner apart from one on its
owner's desk was reading a bit that is always zero. Both are fixed, both
were found by pointing a passive capture at the thing rather than by
reasoning about it, and the release notes say what was measured.

Setup now also asks whether you want the bridge at all, instead of leaving
it as a config key you had to already know about, and warns you about the
three ways an enabled bridge quietly does nothing.

### Added

- **Setup now asks whether you want the passive BLE bridge, and `/settings`
  tells you afterwards whether it is doing anything.** The bridge defaults
  to off and had no prompt anywhere, so the only way to find it was to read
  the source. Both wizard front-ends, `lynceus-setup` and
  `lynceus-setup --web`, now ask, directly after the other BLE capture
  question, and the generated `lynceus.yaml` always carries a live
  `ble_bridge:` block (explanatory comments above it, not commented out),
  so the setting is visible and hand-editable either way.

  The prompt leads with what the bridge actually is, because the natural
  assumption is wrong in a way that matters: it is a capture path of its
  own, not a decoder running over Kismet's data. Kismet's Bluetooth
  datasource hands over no advertisement payload, which is why the bridge
  opens its own passive scan, and why it needs an adapter Kismet is not
  already capturing on.

  **Warn, then allow.** Three known configurations make an enabled bridge
  silently useless or noisy: Kismet holding the same adapter, a
  `kismet_sources` list that omits the bridge's own `ble:<adapter>`
  provenance and therefore drops every observation it produces, and a raw
  company-id rule that alerts on an entire vendor. All three are decidable
  from configuration alone, so the wizard prints what would go wrong along
  with the fix, and still lets you say yes. Blocking would override an
  operator who knows their setup better than the check does.

  The new `/settings` card reports status, adapter, and a per-class
  breakdown of what has actually been decoded. That count comes from
  `devices.ble_device_class`, which is the right evidence precisely because
  only the bridge ever writes it, so a non-empty breakdown means capturing
  *and* decoding rather than merely enabled. Readiness is shown whether or
  not the bridge is on, so the card answers "what would stop this working if
  I turned it on" as well as "this is on but quiet", and when there are no
  warnings and nothing decoded, it says which explanations are left instead
  of leaving a silence that reads as working. Read-only, like the rest of
  the page.

### Fixed

- **The passive BLE bridge could not see a single Apple device, and said
  nothing about it.** The BlueZ `AdvertisementMonitor` was keyed only on
  the Flags AD element. Apple Continuity adverts are non-connectable and
  carry no Flags element at all, so the monitor never fired for them: the
  bridge started cleanly, logged no error, and reported zero Apple devices
  forever. Every AirTag, AirPod, and Find My accessory in range was
  invisible, which also made the whole 0.9.3 Continuity decoder dead code
  the moment it shipped. The Apple manufacturer-data pattern (AD type
  `0xff`, company id `004c`) now leads the pattern set. Measured on the rig
  over matched 20-second windows: Flags-only found 0 devices and 0 frames
  on both runs; with the manufacturer pattern, 7 devices / 61 frames and 5
  devices / 5 frames. The Flags patterns are kept, so non-Apple capture is
  unchanged. The set now sits at exactly 7, which is also where BlueZ
  starts silently dropping the monitor, so it cannot grow without trading
  something away.

- **Find My separated-from-owner state was decided by a status bit that is
  always zero.** 0.9.3 shipped `_FIND_MY_SEPARATED_MASK = 0x04` marked
  UNVALIDATED, on the theory that it was inert until a rig capture
  confirmed it. It was worse than inert. Across 204 Find My frames from 5
  devices (both advert forms, iPhone present and absent), bit `0x04` was
  never set once, so the mask reported "not separated" for every device on
  earth, including genuinely separated ones. A mask pointing at a
  permanently-zero bit is indistinguishable from a correct one that was
  never exercised, and it looks implemented.

  Separation is now read from the advert's structure instead. A tracker
  away from its owner broadcasts the long form carrying rotating public-key
  material for the finder network; one near its owner broadcasts a short
  status-only form. That is a shape we observed directly rather than a bit
  whose meaning we guessed, and it matches the offline-finding layout
  documented by OpenHaystack and Heinrich et al.

  The state is three-valued, and unknown is a real value: `find_my_separated`
  (long form), `find_my_paired` (short form), and `find_my` for any advert
  in neither observed form. Unknown never collapses into "not separated",
  and it outranks `find_my_paired` when one advert carries several messages.
  The commented-out example rule in `config/rules.yaml` now matches
  `find_my_separated` and `find_my` and deliberately omits `find_my_paired`,
  which every passing stranger's own tracker emits.

  Note for anyone who has already written a rule: `find_my` used to be the
  class for *every* Find My advert and is now only the unknown-form case, so
  a rule matching `find_my` alone covers much less than it did. The bridge
  ships disabled and the example rule ships commented out, so no configured
  deployment changes behaviour on upgrade.

## [0.9.3] - 2026-07-28

Lynceus learns to listen to Bluetooth properly, and to tell your AirPods
apart from something worth worrying about. Both new pieces ship switched
off. Read the honest-status notes before you turn them on.

### Added

- **A passive BLE bridge, so the BLE matchers have something to match on
  (off by default).** The `ble_uuid`, `ble_manufacturer_id`, and drone
  Remote-ID matchers have shipped for several releases and fired zero
  times in the field. That was never their fault. Kismet's classic
  Bluetooth datasource hands over no advertisement payload, so the company
  ids and service UUIDs they look for never arrived.
  `lynceus.bridges.ble.BleBridge` opens a passive BlueZ/`bleak` scan on
  its own adapter and pushes what it hears through the same matching and
  alerting path the poll loop already uses.

  It runs on a tick. A per-MAC buffer keeps the latest advert, then
  flushes on its own interval (defaulting to `poll_interval_seconds`) as
  one observation per MAC. It holds its own `Database()` handle instead of
  sharing the poll loop's connection, which makes it a WAL second writer
  by design. Set `ble_bridge.enabled` and `run_forever` starts it in a
  daemon thread, then stops and joins it in the same `finally` that closes
  the poller's DB. A bridge that fails to start logs the failure and steps
  aside, so the flag cannot take your daemon down with it. Passive
  throughout: it listens and matches, and it never connects, pairs, or
  probes. Validated on hardware from inside the daemon, with real adverts
  captured, FK-safe alert rows written, and a clean shutdown on signal.

- **Apple adverts resolve to a device class, so `004c` stops meaning "some
  Apple thing".** Every Apple device shares company id `004c`: your phone,
  your watch, the AirPods two seats over, and the tracker you actually
  care about. Matching that id alone would page you for each of them and
  train you to ignore the alerts, which lands you worse off than having no
  alerts at all. `lynceus.ble_continuity` reads the Continuity message
  type inside the advertisement payload and sorts it into `find_my`,
  `airpods`, `nearby`, or `apple_unknown`. When one advert carries several
  messages, the most surveillance-relevant class wins, so a tracker cannot
  hide behind a co-emitted Nearby message. Truncated or malformed payloads
  produce no class rather than a guess.

  The payload bytes do not stick around. The decoder reads them inside the
  bleak callback and drops them there. Only the label gets buffered,
  stored, or matched, and a regression test fails if someone starts
  buffering raw bytes later.

  The class lands on the device row (migration 023, nullable, where NULL
  means "we don't know" and `apple_unknown` means "we saw an Apple advert
  and couldn't name it") and shows up on `/devices` and device detail. A
  new `ble_device_class` rule type alerts on the classes you name. Unlike
  the `watchlist_*` types it does not delegate to the DB, so patterns are
  required and the rule's own severity is what fires. It ships commented
  out.

  **Honest status.** Nobody has pointed this decoder at a real AirTag yet.
  Its tests build their own payloads, which proves the parser
  self-consistent and proves nothing about Apple. Treat it as built and
  unproven until someone runs a capture. Separated-from-owner state, the
  part that would tell a tracker riding in a stranger's bag from one on
  your own keyring, rests on a status bit nobody has confirmed against
  hardware. That bit sits in one constant marked UNVALIDATED, the shipped
  rule example matches `find_my` (which leans only on the well-established
  message-type byte), and promoting `find_my_separated` takes a one-line
  rules.yaml edit once a capture settles it. `_DRONE_ID_PATHS` carries the
  same warning for the same reason.

### Changed

- **`poll_once` handed its per-observation work to a shared
  `process_observation(...)`.** The device-upsert, sighting, rule-eval,
  FK-safe-alert sequence used to sit inline, reachable only from a Kismet
  poll tick. It is now a module-level function that `poll_once` calls per
  admitted observation and the BLE bridge calls per flushed one, so the
  bridge reuses the exact persistence and alerting path (including the
  ordering that guarantees a device row exists before an alert points at
  it) instead of growing a parallel copy that drifts. Behavior stays put:
  poll behavior, counters, drop gates, and logging are unchanged.

## [0.9.2] - 2026-06-17

### Added

- **ntfy alert notifications now carry the device type at a glance.** Every
  rule-triggered alert notification gains a trailing
  `| radio: <type> | category: <category>` on the message body: `radio` is the
  Kismet radio-layer type off the observation (`wifi` / `ble` / `bt_classic` /
  `remote_id`) and `category` is the matched Argus
  `watchlist_metadata.device_category`. Both are display-only and never
  inferred; an absent category renders a neutral em-dash (which also
  distinguishes "no Argus category" from a literal Argus category of
  `unknown`). The line is always appended after the existing
  vendor/confidence suffix, so that suffix is unchanged. (Kismet up/down
  notifications are intentionally left as-is, they carry no device.)

- **The watchful-recurrence escalation notification now carries the same
  device type/category line.** The synthetic `watchful_recurrence` escalation
  ntfy gains the trailing `| radio: <type> | category: <category>`, consistent
  with the main alert. The escalation has no observation in scope, so it does a
  cheap guarded lookup at the compose site. `radio` off the persisted
  `devices` row (by the entry's MAC) and `category` off the matched
  `watchlist_metadata.device_category` (by the entry's `matched_watchlist_id`,
  which is absent for non-Argus watches), reusing the same `build_type_suffix`
  helper. Display-only and never inferred; a missing device/metadata row or a
  lookup error renders the neutral em-dash without breaking escalation. The
  stored alert row is unchanged. The suffix is appended to the ntfy body only.

- **The /alerts list now has a "Category" column showing the matched device's
  Argus device category.** When an alert matched an Argus watchlist row that
  carries a `device_category` (e.g. `drone`, `camera`), that category is shown
  in a new column beside the MAC; alerts with no Argus match, or a match
  without a category, render a neutral em-dash. Display-only: the value is the
  matched `watchlist_metadata.device_category` verbatim, never inferred for
  non-Argus devices. The column is rendered from the shared `_alert_row.html`
  partial, so htmx in-place row swaps (ack / unack / watch) retain it, and the
  thin action-row budget is untouched (the action cell's contents are
  unchanged).

- **Columns can now be shown or hidden per table, persisted per browser.** Each
  resizable table (devices, watchlist, watchful, allowlist) gains a "columns"
  disclosure above it listing one checkbox per column; unchecking one hides that
  column, re-checking restores it, and the choice is remembered in the same
  per-table `localStorage` entry as column order and widths (so it survives
  reloads and is wiped by the same "reset columns" control). Hiding collapses
  only the column's `<col>` to zero width under the table's fixed layout, cells
  are never removed, so the remaining columns keep their widths and order, the
  table just narrows, and a guard prevents hiding the last visible column. No
  new server state or endpoints: like resize and reorder, this is browser-only
  presentation, and a no-JS browser simply shows every column.

- **The "columns" menu now carries a small funnel glyph as a discoverability
  cue.** A dependency-free inline SVG (no icon font or library, mirroring the
  RSSI sparkline) sits before the "columns" label on every table that offers the
  show/hide menu, hinting that the disclosure filters which columns are visible.
  It inherits the label's muted color via `currentColor`, so it tracks the
  light/dark theme and the hover darken with no per-theme rule, and the native
  disclosure marker is kept. Gated on the hide feature: the resize-only tables
  (probes) and non-table surfaces never show it.

- **Acknowledging, un-acknowledging, or watching an alert on /alerts now updates
  that one row in place instead of reloading the whole page.** With JavaScript
  enabled the per-row ack / unack / watch buttons post via htmx and the server
  re-renders just that alert's row in its new state (an acked row flips to show
  ✓ and an "unack" button, and back again), swapped over the row so the scroll
  position, the active filters, and the rest of the table are preserved. No
  full reload. The row is RE-rendered, not removed (unlike the home page's
  recent-alerts card, which posts to the same ack route to drop its row),
  because /alerts is a mixed acknowledged + unacknowledged list where an acked
  alert stays visible. A no-JavaScript browser is unaffected: the same forms
  POST normally and get the usual 303 redirect back to the list. (This built on
  un-nesting the per-row forms from the bulk-ack form, see Fixed.)

### Changed

- **Client-side column resize / reorder / per-browser persistence now covers
  the watchlist, watchful, and allowlist tables too, and the resize affordance
  is clearer at rest.** The `data_table` macro's opt-in layer (first shipped on
  the devices table) is extended to three more server-rendered list tables:
  each now carries a keyed `<colgroup>`, per-column resize grips, a pre-paint
  applier call, and a "reset columns" control, with column order and widths
  persisted in `localStorage` per browser. The conversion is purely additive.
  every table's existing columns, cells, sorting, filtering, pagination, and
  row actions are unchanged; only the resize/reorder/persistence chrome is
  added. Of the remaining list surfaces, **probes** is now resizable too
  (resize-only, see below); **alerts** stays deferred (its select-checkbox +
  inline ack/watch action columns wrapped in a bulk-ack form fight the
  fixed-layout/overflow clamp the resize layer requires), and **rules** is
  excluded outright. It renders as article cards, not a table. Separately, the
  rest-state column separator that signals
  a draggable boundary was faint enough to miss, so its opacity is raised from
  `0.28` to `0.50` (and the hover/drag weight from `0.80` to `0.95` to keep a
  visible darken-on-hover contrast); both remain tweakable via the
  `--lyn-col-separator-rest` / `--lyn-col-separator-active` custom properties.

- **The /probes tab's columns are now resizable (resize-only).** Both group-by
  views, network → devices and device → networks, opt into the `data_table`
  macro's resize/reorder grips, per-column widths, and "reset columns" control,
  each persisted per browser under its own key (the two views are distinct
  column schemas, so they get separate `probes-ssid` / `probes-device` ids).
  Unlike the other resizable tables, probes deliberately gets **no show/hide
  columns menu**: the PII-sensitive reveal rows are untouched and stay collapsed
  by default. This was unblocked by splitting the macro's single opt-in into
  independent `resize` / `hide` feature flags (both default off, explicit
  opt-in), so a table can take resize without the hide menu; the four existing
  resizable tables are unchanged. They request both. Browser-only presentation,
  as before: no new server state, and a no-JS browser renders every column.

- **The /probes tab now defaults to 50 rows per page (was 25), matching the
  /devices default.** 25 was the lowest default of any list page, so the probes
  tab paged out sooner than the rest for no strong reason; the SSID reveals stay
  collapsed by default, so a larger page is not a privacy regression. Only the
  default changes. The page-size dropdown and the `?page_size` override already
  offered the full set (10–500) and are unchanged, and the choice is not
  persisted across visits.

### Performance

- **Two hot-path indexes (migration 022) cut watchlist-eval and `/devices`-sort
  latency on large tables.** `idx_watchlist_pattern_type_pattern` on
  `watchlist(pattern_type, pattern)` turns the per-observation simple-equality
  lookup from a full watchlist SCAN into an index SEARCH (miss latency
  ~0.72ms → ~0.013ms on a 30k-row watchlist), so the common case, a device
  not on the watchlist, can LIMIT-exit early instead of scanning the whole
  table. `idx_devices_last_seen` on `devices(last_seen)` removes the TEMP
  B-TREE sort behind the default `/devices` page's `ORDER BY last_seen DESC`
  (first-page latency ~17.4ms → ~0.52ms on 30k devices). Both indexes are
  non-UNIQUE (duplicate `(pattern_type, pattern)` rows are legitimate, and a
  UNIQUE index would reject valid data), distinct from the partial
  `idx_watchlist_mac_range_prefix`; the `/alerts` hot path was checked and
  needs no new index (`idx_alerts_ts` already yields a reverse index scan).
  Reversible via the paired `022_hot_path_indexes_down.sql`.

- **The poller now ensures each distinct location once per tick instead of once
  per admitted observation.** `poll_once` called `ensure_location`, a write
  transaction (`INSERT … ON CONFLICT(id) DO UPDATE`), once before the loop and
  again for every admitted observation, so a typical single-location tick with
  five observations issued six location-write commits for one distinct location
  (and it scaled 1:1 with observations). The loop now tracks the location ids
  already ensured this tick, seeded with the pre-loop default, and ensures a
  location only the first time it is seen, dropping the common all-default-
  location case to a single write. This is not pure dedup: a
  `source_locations`-remapped observation genuinely targets a different
  location, and every distinct remapped location is still ensured exactly once.

### Fixed

- **A single unparseable Kismet device record no longer aborts the entire poll
  tick.** A record that cleared the early None-returning guards in
  `parse_kismet_device` but then failed a pydantic validator/coercion (e.g.
  `first_seen <= 0`, `last_seen < first_seen`, a non-coercible rssi/oui_vendor)
  raised `ValidationError` at the unguarded `DeviceObservation` construction.
  Because the batch is materialized eagerly outside `poll_once`'s
  per-observation try/except, that raise discarded every co-batched good record
  and left `last_poll` un-advanced, so each subsequent tick re-queried the same
  window and re-hit the same poison record, a livelock (the daemon stayed alive
  via the per-tick catch but was frozen forever). The construction is now
  wrapped to log a WARNING with the source MAC and return `None`, mirroring the
  existing missing-field/bad-mac drops: the record is counted in the unparseable
  tally and skipped, the batch's good records persist, and `last_poll` advances
  normally.

- **A corrupt primary allowlist now retains the last-good suppression instead of
  failing open.** A parse/validation error in `_load_primary` was swallowed and
  returned an empty `Allowlist`, and the mid-run reload guarded only
  `FileNotFoundError`, so a corrupt allowlist dropped every suppression at once,
  flowing previously-allowlisted devices into rule eval, firing alerts and
  storming ntfy (the deleted-file case was already fail-safe; only the corrupt
  case failed open, an asymmetry). `_load_primary` now raises
  `AllowlistParseError` on a parse failure (a valid-but-empty file still parses
  cleanly to an empty allowlist); the mid-run reload catches it and retains the
  last-good allowlist with a WARNING, symmetric with the deleted-file path. At
  startup there is no last-good, so it starts empty (detection keeps running) but
  makes the degraded state un-missable. A CRITICAL log plus an operator ntfy
  that suppression is disabled. A missing primary still raises (config error).
  The lenient corrupt→empty path is preserved for the web-UI read views and the
  validate CLI.

- **An Argus import that collides with an operator-seeded watchlist row now
  preserves the operator's severity and reports the conflict instead of silently
  overwriting it.** When an incoming Argus row's natural key
  (`pattern` + `pattern_type`) collided with a watchlist row carrying no Argus
  metadata, a YAML seed or hand edit, the import used to overwrite the
  operator's severity and description with the Argus values, attach Argus
  metadata, and count the row as `imported_new`, with no signal. Operator
  decision now overrides Argus on collision: the operator-seeded branch keeps the
  existing severity and description (no UPDATE), attaches no Argus metadata (so
  the row keeps reading operator-seeded on later imports rather than silently
  re-enabling the overwrite), counts the row in a new `operator_preserved` bucket
  surfaced in the report, and emits a per-row WARNING naming the kept vs declined
  severities. The disagreement re-reports on every subsequent import until the
  operator resolves it.

- **A wholly-failed Argus import now exits non-zero and does not record a fresh
  import run.** Per-row write failures were swallowed (`errors += 1; continue`)
  and never re-raised, `record_import_run` was called unconditionally, and
  `main()` returned 1 only when `import_csv` raised, so a totally-failed import
  returned exit 0 and wrote a fresh `import_runs` row, making the `/settings`
  staleness card and the poller startup log claim a recent refresh that imported
  nothing. Keyed on real write failures only (never on the G4
  `operator_preserved` intentional declines): a total failure (errors, nothing
  written) now returns non-zero and skips `record_import_run`, so freshness stays
  at the last good import; a partial failure also exits non-zero (every routine
  drop has its own counter, so anything left in `errors` is a real problem worth
  surfacing in cron) while still recording freshness, because data changed. Clean
  and conflict-only imports are unchanged.

- **`drone_id_prefix` watchlist entries now match a captured Remote-ID serial by
  leading-substring, and captured serials are separator-stripped before
  matching.** Argus stores the longest-common-prefix of a registered serial
  range for `drone_id_prefix`, not a full serial, so the prior whole-string
  equality match missed every real (longer) Remote-ID serial. Matching is now
  leading-substring, longest-prefix-wins
  (`substr(captured, 1, length(pattern)) = pattern`, which keeps binary
  case-sensitivity and carries no wildcard metacharacters), applied consistently
  across DB eval, the in-memory rules path, and the allowlist drone branch (so a
  prefix-allowlisted drone stays suppressed). Capture-side,
  `_coerce_drone_id_prefix` now strips whitespace, NUL padding, and separator
  punctuation and uppercases before the shape check (strip-don't-reject) rather
  than dropping any serial with an embedded separator. **Inert until a live drone
  capture confirms the field path:** the live Kismet Remote-ID JSON path
  (`_DRONE_ID_PATHS`) is still an unverified guess and is unchanged by this fix.
  the matcher is correct but will not fire until a real drone is captured.

- **Pico and the app's own styles now load in CSS cascade layers, so app rules
  win over Pico without per-control specificity hacks.** Pico (classless v2.1.1)
  ships unlayered, and several of its form-control defaults are attribute
  selectors (notably `button[type=submit], input:not([type=checkbox],[type=radio]),
  select, textarea { width: 100% }` at specificity (0,1,1)), which outranked the
  app's (0,1,0) class overrides (e.g. `.device-action-btn { width: auto }`),
  leaving those overrides silently dead unless re-scoped to a higher specificity
  per control. A small `app.css` entry now declares `@layer pico, app;` and
  `@import`s Pico into the `pico` layer and `lynceus.css` into the `app` layer;
  because a later-declared layer outranks an earlier one regardless of selector
  weight, every app rule now beats every Pico rule, while any control with no
  app rule keeps its Pico styling untouched (the deliberately bare-Pico filter
  forms and alert-detail controls are unaffected). `base.html` now loads only
  `app.css`; the vendored Pico file is unchanged. Browser-verified: an app-ruled
  control collapses from Pico's full width to its content width, while a
  bare-Pico control stays full width.

- **The "columns" menu's show/hide checkboxes now render as proper boxes
  instead of thin slivers.** The checkbox rule carried a `width: auto`, but Pico
  draws checkboxes as `appearance: none` 1.25em squares and excludes them from
  its `width: 100%` form reset, so the override was never needed and, on an
  appearance-none box, `width: auto` collapsed it to its (zero) content width
  plus borders, i.e. a ~4px sliver. Dropping the declaration lets Pico's square
  stand; the surrounding label is a flex row whose `gap` still spaces the box
  from its text. (Independent of the cascade-layer change above, the app rule
  already won here, just with the wrong value.)

- **The /watchful "promote", "investigate", and "confirmed-safe" actions now
  read as buttons, matching the reset/dismiss actions in the same row.** They are
  `<details><summary>` disclosures (clicking the summary reveals a note field +
  submit), but the summary rendered as raw "emoji text ›" accordion text, so the
  action row was a jumble of two buttons and three link-like labels. The
  summaries are now styled to match the sibling action buttons (same size, fill,
  radius, and height, via Pico's theme-aware tokens so they track light/dark),
  while the disclosure behavior is unchanged (the markup is untouched; clicking
  still reveals the note + submit). Pico's float-right accordion chevron is
  suppressed on these: the trailing ellipsis in each label ("promote…") already
  signals that the action opens further input, distinguishing them from the
  ellipsis-less reset/dismiss. The opened disclosure's submit button, which had
  rendered full-width (Pico's `button { width: 100% }`), is now content-sized
  like the rest, now that app rules win via the cascade layer.

- **The /alerts per-row action controls now sit at the buttons' height on one
  compact line, instead of standing as tall as a full input.** A previous fix
  re-scoped the note/select/button widths so the row held one line, but it never
  touched their HEIGHT: Pico forces an explicit ~3rem height on the note input
  and a 1rem margin-bottom on every input/select/button, and gives the snooze
  select a 1rem + 1.5rem dropdown-arrow gutter, so the note input (~53px) and
  select (~49px) towered over the ~26px buttons, making the row ~70px tall, and
  the fat gutter ate into the row's width budget. Those height/margin/gutter
  declarations were dead before the cascade-layer change (Pico's element rules
  outranked the app's class selectors); now that app rules win, the note input's
  forced height is defeated, the margins are zeroed, and the select's vertical
  padding and arrow gutter are trimmed (the gutter still clears the chevron), so
  every control matches the buttons' height. The row drops from ~70px to ~29px
  and keeps a comfortable single-line fit.

- **The first alert row's "Acknowledge" / "unack" button now acts on that row
  instead of silently triggering bulk-acknowledge.** The per-row ack/unack/watch
  forms were nested inside the "Acknowledge selected" bulk form that wrapped the
  whole table, which HTML forbids. The browser dropped the first row's inner
  form, so its button submitted the bulk-ack form (acting on the checkbox
  selection) rather than that single alert, and the remaining per-row forms were
  left fragile DOM-nested children of the bulk form. The bulk-ack form is now a
  standalone form that does not wrap the table; the per-row selection checkboxes
  associate with it by id via the HTML `form=` attribute, so bulk
  select-and-acknowledge still works, while every per-row action form is a real,
  un-nested form that targets its own route. No server-side route or behaviour
  change.

- **Toggling a column's checkbox in the "columns" menu now repaints the box
  immediately instead of lagging behind the column reflow.** The change handler
  ran the heavy fixed-layout `<col>` reflow and the `localStorage` write
  synchronously, which deferred the native `:checked` repaint until that work
  finished, so the checkbox appeared to stick a beat behind the click. The hide
  work is now deferred via `requestAnimationFrame` so the browser paints the
  checkbox first; the last-visible-column guard stays synchronous, so trying to
  hide the final column still snaps the box back at once. Hide behaviour is
  otherwise identical. Only the paint timing changed.

- **Resizing a column now tracks the pointer 1:1 instead of drifting and
  sometimes inverting.** Opted-in tables flip to `table-layout: fixed` but kept
  Pico's `width: 100%` with no explicit total, so whenever the column widths
  summed to less than the container the engine redistributed the surplus across
  the columns. The grabbed column's delta leaked into its neighbours, making a
  resize drag track non-deterministically in both directions. This was a
  pre-existing fixed-layout surplus-distribution issue, not a math error in the
  resize handler. The table's total width is now pinned to the sum of its
  `<col>` widths, on every load (first-visit freeze and reload alike) and kept
  in sync during the drag, so it stays in the anchored, sum-driven regime:
  only the grabbed column changes width, and the `.table-scroll` wrapper's
  existing `overflow-x: auto` absorbs any resulting overflow. The same pin makes
  hiding a column narrow the table (the visible-width sum drops) rather than
  re-growing the remaining columns. Browser-only presentation; persisted widths
  and the reorder/reset controls are unchanged.

- **The /alerts action column is now a single compact line instead of a
  too-tall stack, and no longer overflows on horizontal scroll.** Pre-existing
  issue, not a regression from the column resize/reorder arc. `/alerts` is a
  bare table (no `data-table-id`), so the global `.table-scroll th,td {
  white-space: nowrap }` rule forced the action cell's two inline forms (note
  input + Acknowledge, snooze select + Watch) onto one unbroken line that spilled
  to its full ~23rem content width. A first attempt stacked each form on its own
  row (`flex: 1 0 100%`), which only made the cell taller, because a deeper
  cause was hiding underneath: Pico's reset sizes form controls full-width via
  `button[type=submit], input:not([type=checkbox],[type=radio]), select, textarea
  { width: 100% }` at specificity `(0,1,1)`, which outranks the `(0,1,0)` class
  rules meant to keep the note and buttons compact, so the note width and the
  `29ce7be` button `width: auto` were silently dead and every control rendered
  full-width and stacked. The action wrapper is now a single-line flex row, and
  the compact-sizing rules are re-scoped under `.alert-action-controls` (lifting
  them to `(0,2,0)` so they win over Pico), restoring the intended content-sized,
  `width: auto`-matched buttons and a 10ch note, but only inside the /alerts
  action cell, so the home page recent-alerts card (which shares the button
  classes but not this wrapper) is untouched. The widest row now measures ~344px,
  inside the `max-width: 22rem` upper bound that is kept as a belt-and-suspenders
  cap (flex-wrap falls back to wrapping rather than re-spilling), so the column
  can never regress to the original overflow.

- **The "reset columns" control now sits above each resizable table instead
  of below it.** The control was emitted after the table, so on a long list an
  operator had to scroll to the bottom to find the way back to the default
  layout. It now renders immediately above the `.table-scroll` wrapper. The
  control is a sibling of (not inside) that wrapper, so a top placement does
  not scroll away with the table's horizontal overflow; the pre-paint applier
  `<script>` stays below the table, where it must run after the table parses.

- **Resizing a column to its minimum no longer lets the resize grip overlay
  the column label.** Opted-in tables flip to `table-layout: fixed`, where the
  `<col>` inline width is authoritative and a CSS `min-width` on the cell is
  inert, so the effective floor is the JS clamp in the resize handler, which
  was `32px`: narrow enough that the 12px grip rode up over the header text.
  The floor is raised to `72px` so a fully-collapsed column still clears the
  grip plus the label padding; an interim `64px` floor cleared most tables, but
  the widest one (devices, 12 columns) still showed a live label/grip overlap,
  so the floor was nudged up until that cleared too. (A column whose width was
  already persisted below `72px` keeps that width until "reset columns" is
  clicked, the floor governs new drags, not a retroactive migration.)

- **The devices table's column-resize affordance is now discoverable at
  rest.** The drag-to-resize grip rendered at `opacity: 0` and only appeared
  on hover, so the resize/reorder feature was effectively invisible. An
  operator had no cue that a column boundary was draggable. The grip's
  vertical bar now doubles as a faint, persistent column separator (visible
  without hovering) that darkens when hovered or dragged, signalling it is a
  handle. Both weights are exposed as tweakable custom properties
  (`--lyn-col-separator-rest`, `--lyn-col-separator-active`) and all colours
  still derive from the existing theme tokens, so the change is theme-aware by
  construction. This is a CSS-level change to the shared grip styling used by
  the `data_table` macro, so it takes effect wherever the macro opts in
  (currently the devices table).

## [0.9.1] - 2026-06-03

### Added

- **The running daemon now sends an ntfy alert when it loses Kismet mid-run,
  paired with a "recovered" alert when Kismet returns.** Field testing
  surfaced a silent gap: when Kismet went down under a *running* daemon,
  lynceus detected the failure (poll ticks raising) but never notified the
  operator, who found it only by forensics. The poll loop now runs a small
  de-duped state machine: after three consecutive failed ticks (matching the
  startup check's retry tolerance; ~3 minutes at the default 60s interval) it
  confirms Kismet is genuinely unreachable via the existing health check and
  sends exactly **one** "Kismet unreachable" notification, then exactly **one**
  paired "Kismet reachable again" notification on the next successful poll.
  only if a "down" was sent, and never repeating either while the state holds.
  The alert is **runtime-only**: it fires solely from the poll loop, never from
  the startup health check, so a Kismet that is down at boot still fails fast
  and crash-loops without spamming the operator. It is marked as
  infrastructure (a distinct `Lynceus: Kismet …` title, high tone, priority
  below the level reserved for opted-in watchlist hits) and bypasses the
  device-alert pipeline, so it is never processed as or confused with a device
  detection. The de-dup state is in-memory. The daemon stays up across a loss
  episode, and a restart can't strand a stale "down" because the startup check
  gates re-entry to the loop.

### Changed

- **ntfy notifications, the alerts list, and alert detail now show both the
  matched (watchlist/Argus) vendor and the Kismet OUI vendor when they
  disagree, so a divergence reads as reconciliation instead of contradiction.**
  A watchlist match can attribute a device to one vendor (e.g. "Flock Safety")
  while Kismet's OUI lookup says another (e.g. "Liteon Technology"). Field
  testing hit exactly this: the phone showed one vendor and the devices page
  showed another, with no way to tell they described the same device. Three
  surfaces now reconcile the two. The **notification** body appends the OUI
  vendor in parentheses only when it differs from the matched vendor,
  `vendor: Flock Safety (OUI: Liteon Technology)`, and shows the matched
  vendor alone on agreement (compared case-insensitively, trimmed) or when
  Kismet has no OUI vendor, so the common case stays compact. The **alert
  detail** page already rendered both fields but labelled each just "vendor:"
 . The actual source of the confusion; they now read "matched vendor:" and
  "OUI vendor:". The **alerts list** appends `(OUI: …)` to the vendor subtitle
  under the same divergence rule. This is display-only. No detection,
  matching, vendor data, OUI lookup, or severity is touched; it surfaces
  fields that already existed. The **devices list** is intentionally left
  showing the OUI vendor alone: a device maps to zero, one, or many watchlist
  matches, so there is no single matched vendor to show there without
  misleading.

- **The homepage "recently seen" table now shows up to 25 devices (was 10),
  in a vertically scrollable card with a "view all devices" link.** In a
  dense RF environment (hundreds of devices in range) the 10-row cap hid
  most recent activity. The table now surfaces the 25 most-recently-seen
  devices (ordered by `last_seen` descending, the same order the `/devices`
  page uses, so the link lands on a consistently sorted list), inside a
  height-capped scrollable region whose column header stays put while
  scrolling, with a "showing N of M" count line beneath it. The cap is a
  ceiling, not a floor: fewer devices render fewer rows.

- **`lynceus-setup` now guides the ntfy broker-URL field and verifies the
  topic with a real test-publish, on both the web wizard and the CLI.** Field
  testing surfaced a silent misconfiguration: the operator put the full
  `ntfy.sh/<topic>` in the URL field *and* `<topic>` in the topic field, so
  the daemon POSTed to `<url>/<topic>/<topic>`, a dead topic nothing was
  subscribed to, with zero feedback at setup. Two non-destructive changes
  close the gap. (1) The URL field's help text now states it is the **server
  base only** (for the public service, just `https://ntfy.sh`) and warns
  against appending the topic, naming the `<url>/<topic>/<topic>` failure
  mode. (2) The setup test-publish now routes through `notify.py`'s real send
  path, so it POSTs with the exact headers/format the daemon uses, and prints
  the **resolved `<url>/<topic>` target** (topic-redacted, so a doubled topic
  stays visible), before asking the operator to confirm receipt on their
  phone. The messaging is deliberately honest: a 2xx confirms only that the
  broker *accepted* the publish (ntfy creates topics on demand), NOT that the
  phone is subscribed to that topic, so it is never worded as "configured
  successfully". The operator's URL is never normalized or rewritten.
  self-hosted brokers with custom hosts or reverse-proxy subpaths are left
  exactly as entered. The test-publish remains skippable (`--skip-probes` /
  the wizard's skip path) and never hard-blocks setup completion.

### Fixed

- **`lynceus-setup --web` now prints manual-access guidance when it can't
  auto-open a browser.** On a headless host, under `sudo`, or with no
  `DISPLAY`, `webbrowser.open` fails and the wizard previously printed only a
  terse one-liner. The open-failed path now prints prominent guidance: the
  tokenized URL and, when the bind is loopback (the default), an
  `ssh -L <port>:127.0.0.1:<port>` tunnel example with a note that the wizard
  binds to localhost by design; a non-loopback bind names the bind host and
  omits the tunnel. Detection and printed output only. No binding behaviour
  changes.

- **Corrected the `X-Sequence-ID` explanation from 0.9.0 (documentation and
  code comment only: no behavior change).** The 0.9.0 entry and the
  `notify.py` comment stated that ntfy's server/broker treats messages
  sharing an `X-Sequence-ID` as updates that overwrite the prior one. Per
  ntfy's current docs, that REPLACE behavior applies only to
  *scheduled/delayed* messages before delivery; once delivered, the server
  keeps both messages. Lynceus publishes immediately, so the "broker
  overwrites delivered alerts" rationale was inaccurate. The publish path
  still stamps a **unique** `X-Sequence-ID` per alert, that is unchanged and
  correct, but it is now documented as a *defensive* measure to keep each
  detection a distinct message (the pre-0.9.0 path set no id and detections
  were observed collapsing to a single entry in the operator's ntfy view),
  not as reliance on a server-side overwrite. Which layer (the ntfy server
  vs. the ntfy client app) was collapsing them is not documented upstream, so
  no mechanism is asserted.

- **The Probes tab's per-row reveal no longer reflows other rows' disclosure
  arrows when one row is expanded, no longer clips long network names, and
  centers the arrow.** The reveal is a native `<details>` inside a
  `.table-scroll` cell, whose `white-space: nowrap` (which drives the table's
  horizontal scroll) is inherited into the revealed list. Two defects followed
  from that, plus a third from the marker: Pico draws the `<summary>` marker as
  a `float: right` chevron on a block-level summary, so the chevron sits at the
  right edge of the summary box, which fills the table *column*. Because table
  columns share one width across all rows, expanding one row forced its
  un-wrapped content to widen the shared column, and every other (collapsed)
  row's right-floated chevron then slid to the new right edge, and, while the
  column was narrow, the floated chevron wrapped *below* the summary text. The
  same `nowrap` also stopped long probed-network names from wrapping, so they
  overflowed the cell, and the floated chevron sat off-center against the text.
  Two CSS rules, scoped to the probe reveals alone (matched by their
  `.probe-reveal` list, so no other table's `<details>` is touched), fix all
  three: the reveal list opts out of the cell's `nowrap` so names wrap, and the
  summary marker is laid out inline (not floated) so it anchors to the text.
  isolated from the shared column width and centered against it. Display-only;
  the collapse-by-default privacy behavior and the reveal toggle are unchanged.

## [0.9.0] - 2026-06-01

### Added

- **A new Probes tab aggregates probe SSIDs across all devices.** The
  per-device "Probes" column now has an aggregated sibling at `/probes`
  that rolls `devices.probe_ssids` up two ways: by **device** (which
  networks each device probed, the default) and by **network** (which
  devices probed for each SSID), switchable with a grouping toggle. It is
  the most privacy-sensitive screen in the tool, it concentrates the
  network history of strangers passing the sensor, so it is built
  PII-first: the sensitive list in each grouping is **collapsed by
  default** behind a native expand/reveal control, so identity-revealing
  detail never leaks on load. In **device** grouping the per-device list of
  probed networks, the device's own fingerprint, stays collapsed, the row
  showing only the *count* of networks probed. In **network** grouping the
  network name is a visible, scannable row header, but the list of *which
  devices* probed for it, the sensitive concentration there, stays
  collapsed behind the reveal.
  Search, filtering, and pagination mirror the devices/watchful convention
  exactly. A plain form-GET `q` (100-char cap, whitespace-is-unfiltered),
  server-side filtering, and the URL-encoded query carried across pages
  with the active grouping. Network grouping unnests the JSON arrays with
  SQLite `json_each` and paginates on the grouped result, fetching each
  page's device lists in a single bounded query (capped per network) so the
  view never loads every probe per request or fans out into an N+1; a
  malformed legacy probe row skips silently rather than erroring the page.
  Capture defaults off, so the tab carries the same honest "probe-SSID
  capture is disabled" note as the devices probing filter. It is entirely
  read-only. No new capture, collection, or mutation; it only reads and
  aggregates probe data that already exists.

- **The devices page gained a search bar.** A free-text box now filters
  the /devices list by substring, mirroring the existing /watchful search:
  the same `q` query parameter, a plain form GET (no live-search), the
  same 100-character cap, and the same empty/whitespace-is-unfiltered
  handling. Because the devices table surfaces more identity than the
  MAC-only watchful rows, the search matches across four columns at once.
  the MAC, the BLE name, the vendor (OUI), and the device's last SSID (the
  value shown in the "Last SSID" column). Matching is case-insensitive, so
  `sony` finds a "Sony" device. The search composes with the existing
  type / randomized / probing filters, the quick-filter preset chips, and
  pagination rather than replacing them: the active query is carried in the
  URL across pages and shown in the filter summary. It is a read-only
  filter. No new mutation surface is added.

- **The device-detail page gained an operator action panel.** From a
  device's per-MAC page the operator can now (1) add the MAC to the
  watchlist with a severity, (2) watch the device on the watchful
  surface, and (3) silence future alerts for it (permanently or for a
  fixed window, with a matching un-silence control). These are
  deliberate, sanctioned mutations on the otherwise read-only dashboard:
  each reuses an existing flow rather than inventing a parallel one: the
  watchlist add uses the real severity model (low / med / high), watchful
  tracking is created from the device's most-recent alert (so it is only
  offered when an alert exists), and silencing reuses the same allowlist
  suppression the per-alert triage page already uses. Each action mirrors
  the home-page ack pattern: an htmx in-place swap re-renders just the
  panel, with a no-JavaScript form POST → 303 fallback, the `_csrf` token
  enforced identically on both paths, and a confirm step so nothing fires
  on a stray click. Controls are touch-sized for phone use, and the panel
  is a section on the page rather than an inline-table popover.
  Adding the MAC to **rules** was intentionally left out of this arc:
  `rules.yaml` is operator configuration with no incremental write
  surface, and editing it from the dashboard would breach the read-only
  boundary. It is deferred to its own feature.

### Changed

- **Acknowledging an alert on the home page now removes just that row in
  place instead of reloading the whole page.** The recent-unacknowledged
  card's Acknowledge control gained an htmx `outerHTML` swap: clicking it
  drops only the acked row from the table, with no full-document reload.
  This fixes two long-standing annoyances of the old POST → 303 → GET /
  flow. The page jumping back to the top, and a live-poll insert arriving
  between render and reload making the acked row look like it was
  "replaced" by a different alert rather than removed. The change is
  progressive enhancement: the plain form POST and CSRF token are kept
  intact, so a browser with JavaScript disabled still gets the original
  full-reload behavior, and CSRF is enforced identically on both paths.
  Trade-off (deliberate): the visible list shrinks 10 → 9 per ack; the
  11th unacknowledged alert does not backfill into the table until the
  next full page load.

- **The dashboard top-nav tabs are now separated by a vertical divider.**
  The tab links (home, alerts, watchful, …) previously sat in a flex row
  with only whitespace between them, so it wasn't obvious where one tab
  ended and the next began; a 1px vertical rule now delimits each pair.
  It reuses the existing top-nav border token, so the divider tracks the
  light/dark theme toggle, and the theme-toggle button (already set off at
  the right edge) is unaffected. Purely cosmetic. No behavior change.

### Fixed

- **Every `lynceus-setup` prompt with a default now says that Enter keeps
  it.** The wizard's free-text prompts already applied their default on a
  bare Enter, the shared `prompt_default` helper has always returned the
  default for empty input, but the prompt line only showed the value in
  `[brackets]` with no cue that Enter accepts it. The ntfy URL and topic
  prompts (which take no default) carried explicit `(Enter to skip …)` /
  `(Enter to accept …)` cues, so the bracketed prompts read inconsistently:
  the Kismet API URL, RSSI threshold, and severity-overrides path showed a
  default but never told the operator Enter would keep it. The helper now
  renders `… [default] (Enter to keep default):` for every defaulted prompt,
  so the whole wizard signals its Enter behaviour the same way. Behaviour is
  unchanged (empty Enter still resolves to the default); only the label gains
  the cue. No default values, prompt order, or wizard flow changed.

- **The web UI now fills the browser width instead of sitting in a narrow
  centered column.** `base.html` marks the page `<main>` as
  `.container-fluid`, Pico's vocabulary for a full-bleed container, but the
  vendored stylesheet is Pico's *classless* edition, which never defines that
  class. Its `body>main` rule instead capped the content at a responsive
  `max-width` (1200px, 1450px on very wide screens) and centered it, so on a
  wide monitor the topnav, tables, and every page sat in a narrow column with
  empty gutters while the nav bar's full-width border made the wasted space
  obvious. A single override in `lynceus.css` (`body > main.container-fluid`)
  restores the template's intent: it drops the cap and keeps symmetric
  horizontal padding (reusing Pico's own spacing token) so content reaches the
  viewport edges without touching them. Layout-only. No change to table data,
  columns, queries, or pagination. Narrow/phone viewports are unaffected
  (they were already below Pico's first max-width breakpoint).

- **Silenced devices now show a "silenced" badge in the /devices list.**
  Silencing a device from its detail page (permanently, or temporarily for
  a chosen window), persisted correctly (the detail page already showed
  "Silenced" / "Silenced until …"), but the device *list* gave no feedback:
  its query reads only the devices table and the template had no silenced
  state, so the operator saw nothing change after silencing. The list now
  resolves silence state for the page's MACs in one pass (both allowlist
  files read once, reusing the same matcher the detail and alert surfaces
  use, so list and detail agree on `mac` / `oui` / `mac_range` matches and
  on expiry) and renders the established snoozed badge per row: an
  indefinite "silenced" label for permanent silences, and "silenced (until
  …)" with the remaining time for temporary ones. An expired temporary
  snooze shows no badge, matching the suppression it no longer performs.
  A render-only fix. Snooze durations, suppression, and semantics are
  unchanged.

- **ntfy alerts no longer overwrite each other: each detection is now its
  own message.** Confirmed at the ntfy history level: the topic's in-app
  message list showed a single entry being overwritten on every alert rather
  than a growing list, so only the most recent detection survived. ntfy
  treats messages that share a sequence identifier (`X-Sequence-ID` /
  `Sequence-ID` / `SID`) as updates that replace the prior one; the publish
  path now stamps a **unique** `X-Sequence-ID` (a fresh UUID) on every send,
  forcing the broker to keep each alert as its own append-only history entry.
  Scoped strictly to how the publish identifies the message. Alert content,
  firing thresholds, and the `(rule_name, mac)` dedup window are unchanged.

- **Three `--system` deployment bugs surfaced by a real Raspberry Pi
  (Debian Trixie, Python 3.13) bring-up.** All three stem from code that
  assumed the invoking/interactive user is also the runtime user. False
  for a `--system` + systemd install, where the daemon runs as the
  dedicated `lynceus` service user (and Kismet as root). (1) **Config probe
  no longer crashes on a permission-denied `/etc/lynceus`.**
  `resolve_existing_config()` probed both scopes with bare `Path.exists()`,
  which re-raises `PermissionError` (unlike `os.path.exists`); a
  non-`lynceus`-group account running `lynceus-quickstart` couldn't `stat()`
  inside the `0750 root:lynceus` config dir and the wizard aborted. An
  inaccessible path at a scope is now treated as absent. (2) **`--system`
  installs non-editable.** `install.sh` ran `pip install -e` for both
  scopes, leaving `/opt/lynceus/.venv` with an `__editable__*.pth` pointing
  into the operator's `$HOME`, which the `lynceus` service user can't
  traverse, so the systemd daemon crashed at import on every start. The
  `--system` branch now installs the package into the venv
  (`$HOME`-independent); `--user` stays editable for dev convenience. (3)
  **The setup wizard validates the auto-located Kismet API key.**
  `lynceus-setup --system` offered `$SUDO_USER`'s `~/.kismet/` key first and
  unvalidated; against a root-run (systemd) Kismet that key returned 401.
  Under `--system` the wizard now probes `/root/.kismet/` first, validates
  each candidate against the live Kismet, and offers only a key that
  authenticates. Falling back to a clearly-flagged unverified offer only
  when Kismet isn't reachable yet.

- **Pagination and filter links on /devices and /watchful now URL-encode
  the search term and other text params.** The links built their query
  string by raw concatenation, so a search containing `&`, `#`, `+`, or a
  space, common now that the /devices search matches vendor / BLE name /
  SSID, produced a broken URL: an unencoded `q=AT&T` truncated the query
  string at the bare `&`, silently dropping the search term and every
  param after it when paging. Each text-valued value is now run through
  the `urlencode` filter (the `=`/`&` separators are left intact), so
  `AT&T` rides the link as `q=AT%26T` and pagination, the filter summary,
  and the preset chips all preserve the active search. /watchful shared
  the same latent pattern and is fixed identically. Read-only filter
  pages. This is purely a URL-construction correctness fix.

- **The /alerts, /allowlist, and /watchlist pagination links now
  URL-encode their text params too.** Those three list pages carried the
  same raw-concatenation pattern in their pagination navs (`'q=' ~ q` …
  `qs | join('&')`), so a search containing `&`, `#`, `+`, or a space
  truncated or mis-parsed the query string the moment the operator paged,
  silently dropping the active filter. Each text-valued value. `q`,
  `search`, `severity`, `rule_type`, `window`, `since`, `until`,
  `has_note`, `has_action` on /alerts; `q`, `source`, `status`, `type` on
  /allowlist; `q`, `pattern_type`, `severity`, `device_category` on
  /watchlist. Is now run through the `urlencode` filter, leaving the
  `=`/`&` separators intact. The alerts filter-summary line keeps showing
  the raw term as display text (it is HTML-autoescaped, not a URL); only
  the href construction changed. Read-only filter pages. A
  URL-construction correctness fix, matching the /devices and /watchful
  fix above.

## [0.8.0] - 2026-05-29

### Added

- **Setup wizard warns when a selected capture source isn't one Kismet is
  capturing from.** Step 4 previously validated only "at least one
  selected", so an operator could tick a source Kismet doesn't actually
  capture (e.g. `hci1` when Kismet binds `hci0`) and apply it. After which
  every observation from that source is silently dropped by the poller's
  `source_allowlist` gate (no alerts, no error, empty database). The wizard
  now compares the checkbox selection against the sources Kismet reported
  (its live datasources plus `kismet_site.conf`) and, on a mismatch,
  re-renders the step with a loud warning naming the offending source,
  reusing the existing silent-drop warning surface. It does not block: a
  `Continue anyway` submit proceeds, the operator's deliberate
  unchecks are preserved, and a free-text `manual_source` entry (the
  remote/advanced case) stays exempt.

- **The daemon warns at startup when an allowlisted source is absent from
  Kismet's live sources.** After the existing Kismet health check, the
  poller enumerates Kismet's live datasources and logs a WARNING for any
  `kismet_sources` entry not present among them, naming the missing source
  and listing the live ones, so an unplugged USB adapter, an `hciN` index
  reorder, or a wizard mis-pick is visible in `journalctl` at boot instead
  of only as silent per-tick drops. The presence check matches on source
  name, interface, or capture interface (so a VIF-targeted config doesn't
  false-warn), never blocks startup, and is skipped when no allowlist is
  configured or Kismet's source list can't be fetched.

- **The daemon logs which config file and scope it loaded at startup.** One
  INFO line, `config: using <path> (<scope>)`, names the resolved
  `lynceus.yaml` and whether it came from the user scope (`~/.config`), the
  system scope (`/etc`), or a custom `--config` path; `lynceus-quickstart`
  prints the same provenance for the file it resolved before launching. A
  scope mismatch is now visible at a glance in `journalctl` instead of
  inferred from a downstream failure. Resolution semantics (user-scope-first)
  are unchanged.

- **Startup warns when a config in the other scope is being shadowed.** When
  the loaded config is a canonical user/system file and a config *also*
  exists in the other canonical scope, that second file is silently ignored
 . The trap behind a stale-key death ("I configured `/etc` but quickstart
  read `~/.config`"). The daemon (and quickstart) now emit one WARNING naming
  both files, stating which is in use, and flagging which copy is newer, since
  an ignored-but-newer copy usually means the edit landed in the unused scope.
  Non-blocking.

- **The /devices dashboard gains type and probing filters for sorting a
  large capture.** The type dropdown now exposes *Bluetooth (any)*, a
  query-only alias expanding to BLE + Classic Bluetooth, alongside BLE,
  Classic Bluetooth, and *Drone (Remote ID)*, the latter two previously
  reachable only by a hand-crafted URL. A new probing tri-state
  (any/yes/no) isolates devices that emitted a probe request, i.e. carry
  a non-empty stored probe SSID. Because probe-SSID capture is off by
  default, the filter bar shows an honest note beside the probing
  control when it is disabled. The view will be empty, and enabling it
  carries a privacy tradeoff. The dashboard enables nothing and stays
  read-only; no schema or capture-config change. (`bluetooth` is never a
  stored `device_type`, only a query alias.)

- **Quick-filter preset chips above the /devices table.** A row of plain
  GET links, All / Wi-Fi / Bluetooth / Drones / Probing, sets the
  relevant filter params for a "tab feel" while staying on the app's
  filter-bar convention (not a tab widget). The preset matching the
  current params is highlighted.

- **The `--web` setup wizard auto-opens a browser at its tokenized URL.**
  Once the wizard server is serving, `lynceus-setup --web` opens the
  operator's browser at `http://127.0.0.1:8766/?token=…` (mirroring
  `lynceus-quickstart`'s launch), so the operator lands on the form
  instead of copy-pasting the URL. It degrades cleanly where no browser
  can open (under sudo, headless, or no `DISPLAY`), falling back to the
  prominent URL+token print that is still shown. A new `--no-browser`
  flag opts out (headless hosts, the smoke harness).

- **Dark mode for the `--web` setup wizard.** The wizard follows the
  browser's `prefers-color-scheme` by default (Pico v2) and adds a small
  topnav toggle that cycles auto → light → dark and persists the choice
  to `localStorage`, with an inline `<head>` bootstrap so a forced choice
  never flashes the OS default. Scoped to the wizard templates only; the
  read-only dashboard is untouched.

- **`lynceus-quickstart --system`.** Resolves and launches against the
  system-scope config (`/etc/lynceus`) instead of the user-scope-first
  default. An explicit override for operators who ran
  `sudo lynceus-setup --system`. It does not change resolution
  precedence; it points quickstart at the system scope. Mutually
  exclusive with `--config`. Correspondingly, `lynceus-setup --system`
  now prints a next-steps note that quickstart reads the user scope by
  default, so the matching launch is `lynceus-quickstart --system`.

### Changed

- **`lynceus-bootstrap-kismet` no longer installs Kismet by default.**
  The common case is a host that already has Kismet, so installing via
  apt is now opt-in behind a new `--install` flag; the default assumes
  Kismet is present and only configures it (`kismet_site.conf` source
  lines + `kismet` group membership). `--skip-install` is accepted as a
  no-op for backward compatibility, and `--no-network` now overrides an
  explicit `--install`. Both wizard surfaces (web + terminal) had their
  instructional copy updated to match (the web wizard's "Install +
  configure" pointer now shows `--install`; the apply-complete reminder
  drops the redundant `--skip-install`).

- **The setup wizard's Argus step (step 12) shows watchlist-loading
  first.** The "how to load Argus" choice now renders above the
  per-rule-type alerting opt-ins, so the operator decides whether/how to
  load the watchlist before staging per-type enables (which read `0` on a
  first install until Apply imports the bundled snapshot). Visual order
  only. All form fields and POST handling are unchanged.

### Fixed

- **`lynceus-quickstart` no longer crashes when a root-owned config exists in
  the other scope.** The cross-scope shadow check probed the other scope's
  config with `Path.exists()`, which *propagates* `PermissionError` (rather
  than returning `False` like `os.path.exists`) when the parent directory
  isn't traversable by the current user, so a regular interactive account
  running `lynceus-quickstart` with a root-owned `/etc/lynceus` present died
  with `PermissionError [Errno 13]` before launch. The check now treats an
  unreadable other-scope file (`EACCES`) as present-but-unreadable: the shadow
  warning still fires, with hedged wording instead of an mtime comparison, and
  any other probe error is treated as absent rather than crashing. `ENOENT`
  still means absent; resolution precedence and config reads are unchanged.
  The fix lives in the shared `paths` helper, so both daemon startup and
  quickstart are covered.

- **Install / setup copy no longer points at the removed `--skip-install`
  default.** After `lynceus-bootstrap-kismet` flipped to assume-installed by
  default (apt install is now opt-in behind `--install`), `install.sh`'s
  "Next steps", the README, `docs/DEPLOYMENT.md`, and the setup wizard's
  kismet-sources recovery hint still described the bare command as
  apt-installing Kismet and recommended `--skip-install` (now a deprecated
  no-op) for non-apt distros. All four surfaces now show the flipped
  convention: the bare invocation configures capture sources + `kismet` group
  on any distro, and `--install` adds the apt repo + package on
  Debian/Ubuntu/Kali. Copy only. No install behaviour changed.

- **`lynceus-bootstrap-kismet` exits cleanly on Ctrl-C.** `main()` caught
  `BootstrapError` but not `KeyboardInterrupt`, so interrupting mid-run (e.g.
  during the apt step) dumped Python's default unhandled-exception traceback.
  It now prints a one-line `cancelled.` and exits 130, matching
  `lynceus-setup`'s convention. (The `--web` wizard already shut down cleanly
  via uvicorn's own signal handler.)

- **Capture-adapter rows in the setup wizard now show vendor / model / USB
  ID.** USB string descriptors (`manufacturer`, `product`, `idVendor`,
  `idProduct`) were read off the USB *interface* sysfs node
  (`/sys/class/bluetooth/<hci>/device/` resolves to `…:1.0/`), but they live
  one level up on the USB *device* node, so they read as empty and
  Bluetooth adapters rendered as bare `(USB btusb)` / `(Internal btusb)`
  with nothing to choose by. That is what led an operator on a
  two-Bluetooth-adapter rig to uncheck the correct dongle and check the
  wrong internal controller, silently dropping the entire BLE pipeline. The
  descriptor reads now walk up to the device node (the same resolution the
  `removable` flag already relied on), and each row leads with the vendor +
  model + USB ID printed on the adapter while labelling the cryptic `hciN` /
  `wlxN` kernel name explicitly as the *interface*. The `Kismet calls this …`
  anchor is clarified as the capture source the pipeline actually receives
  data from.

- **`lynceus-bootstrap-kismet` adapter-selection prompts now show vendor /
  model / USB ID too.** The CLI's interface prompts (`Use Bluetooth
  controller hci0 — …`) share `format_adapter_descriptor` with the wizard,
  but that formatter still led with the bare `(USB btusb)` /
  `(Internal btusb)` parenthetical and surfaced only one of
  product / vendor / USB ID, so the same Bluetooth mis-pick the wizard rows
  just closed was still live on the surface that actually writes
  `source=hciN` into `kismet_site.conf`. The descriptor now leads with the
  vendor + model + `VID:PID` printed on the adapter and demotes the bus /
  `removable` surface and driver to plain `·`-separated annotations
  (`· USB`, `· Internal`, `· btusb driver`), matching the wizard row. The
  `Internal` distinction for built-in modules (`removable=fixed`) is kept as
  an annotation rather than the misleading bare lead; adapters with no
  readable USB descriptors still fall back to the bare interface name. What
  bootstrap writes is unchanged. Only the operator-facing labels improve.

- **The startup Kismet health-check failure message is now actionable.** It
  previously raised one generic `Kismet unreachable at startup: <error>` for
  every failure mode, so a stale or wrong-scope API key read identically to
  Kismet being down. A 401 that took two forensic diagnostics to trace. The
  daemon now distinguishes an auth rejection (Kismet answered `401`/`403`:
  names the config file the rejected key came from and points at
  `lynceus-setup` / `kismet_api_key`, noting the key may be stale, revoked, or
  from the wrong scope) from an unreachable Kismet (no HTTP response: names
  the URL and asks whether Kismet is running). The fail-fast exit and the
  `kismet_health_check_on_startup=false` escape hatch are unchanged. Only the
  wording. `KismetClient.health_check()` now reports the HTTP `status_code` to
  support the distinction.

- **`lynceus-quickstart` no longer leaks port 8765 on an abnormal exit, and
  surfaces the daemon's error prominently.** Children run in their own session
  so a terminal Ctrl+C doesn't race them, but an *abnormal* quickstart exit
  (terminal closed → `SIGHUP`, `kill -9`) runs neither the Ctrl+C handler nor
  the supervisor, orphaning the UI and leaving `uvicorn` bound to 8765
  (`address already in use` on the next launch). On Linux each child now
  registers `PR_SET_PDEATHSIG` so the kernel reaps it whenever quickstart
  dies, however it dies. On daemon death, quickstart also extracts the
  daemon's actionable error (the health-check guidance above) and re-prints it
  as a `>>> daemon error: …` callout instead of burying it in the output tail.

- **Device timestamps on /devices and the device-detail page now render
  as human-readable UTC.** `first_seen` / `last_seen` and the
  device-detail sightings `ts` column showed raw epoch integers while
  /alerts already rendered ISO-8601; they now use the same `unix_to_iso`
  filter and `<time>` element, so an operator reads a real date instead
  of a 10-digit number.

- **/devices pagination clamps out-of-range values instead of 400ing.**
  The page did bespoke validation that returned 400 for a page below 1
  or a page_size outside [10, 500]; every other list page clamps
  silently via the shared pagination helper. A stale `?page=999`
  bookmark or a hand-edited page_size now lands on the last valid page /
  falls back to the default, matching the rest of the UI.

- **Probe-SSID extraction now reads the field Kismet actually emits.** The
  parser read probed SSIDs from `dot11.device.last_probed_ssid_csum_map`
  and iterated it as a dict, but that key does not exist in Kismet's
  output, so on real hardware the read silently returned nothing (0 of
  8,156 Wi-Fi devices in the operator's live 11k-device capture ever got
  probe SSIDs, leaving the /devices probing filter dead on the rig).
  Kismet serializes the collection as a *list* of records under
  `dot11.device.probed_ssid_map`, each carrying the leaf
  `dot11.probedssid.ssid`; the extractor now reads that field and iterates
  the list. A missing field still yields nothing and empty/wildcard
  broadcast-probe SSIDs are still skipped. The capture gate
  (`capture.probe_ssids` + Wi-Fi only) and the SSID redaction / persistence
  path are unchanged. This only makes the already-gated extraction work.

- **Wi-Fi WDS and Wi-Fi Ad-Hoc device types are no longer dropped at
  ingest.** Both IEEE802.11 strings appear in every sampled session of the
  operator's live capture (~10-20 devices/session) but were absent from the
  parser's type map, so the records dropped silently. Both now map to
  `wifi`. `Wi-Fi WDS` is distinct from the already-mapped `Wi-Fi WDS AP`;
  no other taxonomy change.

## [0.7.9] - 2026-05-26

### Fixed

- **`install.sh` refuses `--user` under `sudo`** rather than silently
  installing to `/root/.local/share/lynceus/`. Under sudo, `$HOME`
  resolves to `/root` on most distros, so the install would land in
  the wrong directory (not the operator's home and not where any
  subsequent non-sudo `lynceus-*` invocation would look). The new
  refusal mirrors the existing `lynceus-setup` refusal at
  `src/lynceus/cli/setup.py:1412` and prints both correct recovery
  invocations side-by-side: `sudo ./install.sh` for system-wide, or
  `./install.sh --user` (no sudo) for user scope. Auto-resolved scope
  (no explicit `--user` flag) is unaffected: `EUID=0` still routes to
  `--system`. The refusal is bypassed during `--dry-run` so an
  operator can still preview the user-scope plan from a root shell.

- **`lynceus-bootstrap-kismet` closing pointer specifies `--system`**
  for the system-scope path. Previously the closing block recommended
  `sudo lynceus-setup --web`; operators following the install.sh
  `--system` → bootstrap-kismet → setup flow would then hit the
  wizard's refusal-to-run-as-root-without-`--system` at the next
  step. Step 6 now reads `sudo lynceus-setup --system --web` (and
  `sudo lynceus-setup --system` for the terminal alternative), with
  a one-paragraph explanation of why `--system` is mandatory so an
  operator who removes the flag knows the constraint.

- **Home page Acknowledge button now stays on the home page.**
  Clicking Acknowledge on the recent-unacknowledged-alerts card on
  `/` previously redirected to `/alerts`; the operator lost the rest
  of their home-page context. The redirect-target helper now
  whitelists `/` alongside the existing `/alerts*` whitelist, so
  Referer-driven redirects land back on the surface the operator
  was actually using. Off-app and unknown referers still fall back
  to the route's stated default (no open-redirect surface).

- **`/alerts` Acknowledge and Watch buttons render at matched
  dimensions.** The Watch button previously had no CSS rule and fell
  through to Pico's default submit-button shape (full-width, tall),
  while Acknowledge sat next to it as a compact inline button -- the
  row looked visually unbalanced. Both classes now share a single
  CSS block (`width: auto`, matching padding and line-height) so they
  cannot silently drift apart. The snooze dropdown picks up the same
  compact font so it lines up with its sibling button.

- **`/watchful` Actions column aligns its mixed children.** Each
  cell on `/watchful` mixes `<form>` buttons (reset, dismiss) with
  `<details>` disclosures (promote, investigate, confirmed safe).
  Without an explicit container the form buttons rendered at one
  baseline while the disclosure summaries sat at another, and
  narrow viewports clipped past the cell edge instead of wrapping.
  `display: flex` + `align-items: center` + `flex-wrap: wrap` on
  `.watchful-actions` pins every action to the row centerline and
  flows them onto a second line when the column is narrow.

- **`argus_oui` rule filters reserved and locally-administered OUIs
  at match time.** Real-world devices transmitting all-zeros source
  MACs (Kismet's representation of malformed-source probe frames,
  spoofed devices, broadcast artifacts), broadcast frames, and
  multicast frames no longer fire `argus_oui` alerts against the
  placeholder watchlist entries the bundled Argus snapshot uses
  for CCTV vendors with unknown real OUIs. Filtered categories:
  `00:00:00`, `ff:ff:ff`, IPv4 multicast (`01:00:5e` prefix), IPv6
  multicast (`33:33` prefix), and locally-administered bit set
  (second nibble of first octet ∈ {2, 6, a, e} -- catches docker
  bridges, MAC privacy rotation, virtual NICs). Filter sits in
  `rules.py` before the DB lookup so the SQL never runs for
  known-bogus prefixes. The in-memory `rule.patterns` path is
  intentionally unaffected -- operators who hand-author a
  `rules.yaml` with `patterns: ["00:00:00"]` are doing it
  deliberately.

- **`lynceus-import-argus` skips Argus rows with `identifier=00:00:00
  identifier_type=oui` at import time.** Belt and suspenders: the
  rules-engine filter (above) defends regardless of data, and the
  importer filter keeps the watchlist clean of placeholder entries
  that can never produce a meaningful match. The bundled snapshot
  ships ~40 rows of this shape (all CCTV vendors where no real OUI
  was known upstream); they drop cleanly on next import. New
  `dropped_placeholder_oui` counter surfaces in the run summary
  alongside the existing drop buckets; an INFO log line per row
  names the `argus_record_id` so operators can audit without
  diffing the table.

- **Device RSSI=0 renders as em-dash** on the home page recent-seen
  card, `/devices` table, and `/devices/<mac>` detail view. Kismet
  returns 0 for devices it has not directly heard from (learned via
  another device's beacon list or BLE scan response rather than
  measured), so a literal "0" misleadingly suggested a noise-floor
  signal. Both `rssi=0` and `rssi=null` now collapse to the same
  em-dash placeholder. Display-only change; storage and queries are
  unchanged.

## [0.7.8] - 2026-05-26

### Fixed

- **Wi-Fi captures now admit correctly when Kismet stamps them with a
  monitor-mode VIF name** (e.g. `kismon0`) rather than the parent
  adapter name (e.g. `wlx00c0cab966f8`). Kismet's `linux_wifi` capture
  path always creates an auto-VIF for monitor mode and credits captured
  frames to the VIF's name; the v0.7.7 smoke probe on Parrot traced
  219/220 Wi-Fi observations dropping silently at the
  `source_allowlist` gate because the operator-configured
  `kismet_sources: [wlx00c0cab966f8, hci1]` value didn't match the
  stamped `kismon0` source name. The poller now resolves the allowlist
  through Kismet's `/datasource/all_sources.json` mapping, grouping
  rows by UUID so the parent name and the auto-VIF name admit
  interchangeably. BLE (`hci0`/`hci1`) was unaffected because
  `linux_bluetooth` stamps observations with the literal configured
  name (no VIF indirection). Failure to fetch the source list logs a
  WARNING and the gate falls back to literal matching. Operator can
  see why captures might be dropping without the poller crashing.

- **`/devices` Type column no longer truncates** on narrower viewports.
  An inline `white-space: nowrap` now lives on the column's `<th>` and
  `<td>` directly, belt-and-suspenders against any future override of
  the `.table-scroll` global rule that landed in v0.7.7 for
  `/watchlist`.

### Changed

- **`/devices` page-size dropdown now offers 250 and 500** in addition
  to the existing 10/25/50/100/200 options, for operators investigating
  large device sets in one view. The route's hard cap moved from 200 to
  500; above-cap values still 400 cleanly.

## [0.7.7] - 2026-05-26

### Fixed

- **`lynceus-bootstrap-kismet` no longer offers Kismet's own
  monitor-mode VIFs as operator-selectable Wi-Fi interfaces.**
  Previously, on hosts where an earlier Kismet runtime had left a
  `kismon*` VIF behind in `/sys/class/net` (the v0.7.6 smoke probe v2
  on Parrot caught this), bootstrap-kismet listed it alongside its
  parent adapter as a capture candidate. Operators who selected it
  got duplicate `source=` lines targeting the same physical adapter;
  both fought for the phy lockfile and neither captured. The filter
  requires two signals, the `kismon*` name pattern AND a phy shared
  with another candidate, so an operator-renamed adapter that
  happens to start with `kismon` won't be false-positive filtered.

- **`lynceus-bootstrap-kismet` now warns on stale root-owned Kismet
  capture-helper lockfiles** (e.g.
  `/tmp/.kismet_cap_linux_wifi_interface_lock`) and names the
  cleanup command (`sudo rm <path>`). Previously these caused silent
  capture failure. The capture helper running as the kismet user
  can't unlink a root-owned file in `/tmp`'s sticky-bit dir, so
  every retry attempts every 5 seconds for hours with nothing
  visible to the operator. Read-only by design; bootstrap names the
  remove command rather than auto-removing (a stale-looking lockfile
  may belong to a legitimate session).

- **`lynceus-bootstrap-kismet` now warns on lingering `kismon*`
  VIFs in sysfs** from prior Kismet runtimes that didn't tear down
  cleanly, naming `sudo iw dev <name> del` as the cleanup command.

- **Wizard step 4 now pre-fills `source=` selections from
  `/etc/kismet/kismet_site.conf`** when present. Previously a re-run
  of the wizard required the operator to re-select adapters from
  scratch even when `bootstrap-kismet` had already configured them
, and any drift between the two configs caused source_allowlist
  mismatches at runtime (the analogous bug bit on Wi-Fi during the
  v0.7.6 saga; this closes the gap on Bluetooth and any second
  re-run). Identifiers in `kismet_site.conf` that don't match
  current OS detection render in a separate "Previously configured
  (currently disconnected)" fieldset, pre-checked so the existing
  config is preserved on apply.

- **Wizard steps 12 (severity rules) and 13 (argus loading)
  merged into a unified "Argus configuration" step.** Operators
  conceptually treat Argus setup as a single decision; splitting
  it across two pages added friction without unlocking any new
  configuration. `/step/13` stays mounted as a 303 redirect to
  `/step/12` so bookmarks and browser-back from prior sessions
  don't dead-end. The apply pipeline is unchanged.

- **Wizard apply-complete page now has cleaner vertical spacing**
  between the apply transcript, watchlist summary, bootstrap
  reminder, and next-steps articles. Per-article margin-top
  additions; no structural rework.

- **Dashboard `/watchlist` page table now scrolls horizontally on
  narrow viewports** rather than squashing all the columns into
  illegible widths. The `.table-scroll` wrapper was already in
  place with `overflow-x: auto`, but without `white-space: nowrap`
  on the cells the table never exceeded the wrapper's width
  (cells wrapped text) so the scroll never engaged. The nowrap
  rule applies to every page using `.table-scroll` (devices,
  alerts, allowlist, watchlist, watchful, the index dashboard
  cards). They all share the same surface and the squash
  symptom would fire anywhere a row's content wraps.

- **`lynceus-import-argus` schema-version accept list extended to
  cover 28-30.** The refreshed bundled CSV from v0.7.6 Tier 4
  declares `schema_version=30`, which was outside the prior
  accept-list `["25", "26", "27"]` and tripped a WARN on every
  bundled import. The floor stays at 25 for backward compat;
  the ceiling at 30 keeps the forward-incompat surface intact
  (v31+ still WARN-don't-abort until landed). Operator override
  via `argus_schema_version_accept_list` in
  `severity_overrides.yaml` is unchanged.

## [0.7.6] - 2026-05-25

### Added

- **Dashboard home page now surfaces watchlist record count and
  snapshot date** with graceful handling for a new
  "no watchlist loaded" state. Previously the freshness signal
  lived only on `/settings`. A single line below the last-poll
  heartbeat reads `Watchlist: 41,428 records · snapshot
  2026-05-25` for a fresh import, the same content with a
  `stale` badge when the import predates
  `watchlist_staleness_warn_days`, and
  `Watchlist: not loaded (configure)` with a deep link to
  `/settings#watchlist-freshness` when no import has been
  recorded. Legacy pre-migration-012 installs that don't have
  the `import_runs` table yet fall through to the not-loaded
  state instead of 500-ing the home page.

### Changed

- **Argus watchlist loading is now opt-in via the web wizard.**
  The wizard's argus step (`lynceus-setup --web` → step 13)
  presents four choices: **Skip** (default), **Use bundled
  snapshot**, **Fetch from GitHub**, and **Import from file**.
  Previously the bundled snapshot was auto-imported on first
  apply; reflects that Lynceus is a standalone product enhanced
  by, but not dependent on, the Argus database. Existing
  watchlist data is preserved when operators re-run the wizard
  and choose Skip ("Skip" means "don't run the importer," not
  "clear the watchlist"). GitHub-mode network failures degrade
  to an `ApplyStep` warning so the apply still completes and the
  operator can retry, switch modes, or proceed without a
  refresh. The interactive CLI wizard (`lynceus-setup` without
  `--web`) still auto-imports the bundled snapshot; that path
  is the legacy default and unchanged in this release.

- **Bundled Argus snapshot refreshed from
  `kevwillow/argus-db@69a9355` (41,428 records, exported
  2026-05-25).** Previous bundle was ~22,533 records exported
  2026-05-17. The new bundle's schema_version is 30
  (importer's accept-list is `["25", "26", "27"]`; the warn-don't-
  abort layer logs the unknown value on import and admits the
  rows anyway).

### Fixed

- **Devices now appear in the dashboard when Kismet captures them.**
  Previously lynceus extracted a UUID-shaped identifier from Kismet's
  per-source `seenby` field rather than the user-facing source name;
  the resulting mismatch against `kismet_sources` in lynceus.yaml
  caused 100% of observations to drop silently at the source allowlist
  filter. The v0.7.5 INFO aggregation log made this visible by naming
  the UUID-shaped values Kismet was actually emitting; this release
  closes the underlying parser bug. The parser now correctly extracts
  source names from the nested `kismet.common.seenby.source` field
  in Kismet device records (the dict carrying
  `kismet.datasource.name`), with a UUID fallback when the nested
  shape resolves to nothing. Verified against a live Parrot-OS Kismet
  probe. A prior fix in this release cycle targeted a flat field
  name that doesn't exist in real Kismet output and devices were
  still dropping silently against the source allowlist despite the
  cross-check passing.

- **Wizard's Previous and Next buttons now render at matched widths.**
  Previously the Next submit button picked up an uncontested
  `width: 100%` from the underlying form-control styles, visibly
  stretching it within the flex footer while Previous sat at its
  content width. The wizard-footer rule now declares `width: auto`
  alongside the existing min-width + padding pins so the two buttons
  render as a matched pair on every step.

- **Wizard apply now creates an empty allowlist file at a default
  location and persists the path into lynceus.yaml**, so the
  dashboard's allowlist page no longer reads "No allowlist_path
  configured" on a fresh install. The scaffold writes to
  `~/.config/lynceus/allowlist.yaml` under `--user` and
  `/etc/lynceus/allowlist.yaml` under `--system`, with a single
  comment header explaining how to add entries. Pre-existing
  allowlist files are kept untouched on re-runs.

- **Wizard step 4 now preserves existing capture-source selections
  on re-runs.** When an operator re-runs the wizard against a host
  with an existing `lynceus.yaml`, the step 4 form does not pre-check
  previously-configured adapters today; a re-running operator clicking
  Next on an empty form previously hit "Pick at least one capture
  source" and had to manually re-check the same adapters they already
  had configured. The POST handler now reads the existing config and
  treats an empty submission as "keep the existing list." First-run
  installs (no on-disk config, or an existing config with an empty
  kismet_sources list) still error so the operator can't accidentally
  advance with no capture sources.

- **Built-in Bluetooth and Wi-Fi adapters now render as "Internal"
  rather than "USB" on bootstrap-kismet prompts and the wizard's
  step 4 row labels.** v0.7.5 surfaced bus + driver from sysfs, but
  motherboard BT modules and on-board Wi-Fi modules connected via
  internal USB hubs report `bus=usb` to the kernel and read
  identically to genuinely-external dongles ("USB btusb" on both
  hci0 and hci1 with no other disambiguator). The kernel also
  exposes a `removable` flag on the parent USB device (`fixed` for
  built-in, `removable` for hot-pluggable); surfacing it lets the
  label render "Internal btusb" for the on-board module so the
  contrast with an external dongle is visible at a glance. PCI/SDIO
  adapters and kernels that don't expose `removable` fall back to
  the v0.7.5 bus-name behavior unchanged.

- **Wizard step 2 now includes inline guidance for generating a
  Kismet API key when one was already auto-located on disk.** v0.7.5
  showed the walkthrough only when no key was on disk; an operator
  who selected "Use a different key (paste below)" on the located
  branch had no in-page signpost to the Kismet UI steps. A default-
  closed `<details>` disclosure now ships on both branches so the
  walkthrough (Settings → Login Configuration → API Keys, name
  `lynceus`, role `readonly`) is reachable regardless of which
  radio the operator picked.

- **Dashboard settings page now distinguishes "no import has run"
  from "import ran and dropped all rows by filters" when the
  watchlist shows zero entries.** Previously the watchlist-data
  card said "To add data, run lynceus-import-argus..." whenever
  `total=0`, including the case where the wizard's bundled import
  had just run and the import filters dropped every row. Operators
  read the message and concluded "nothing happened" when in fact
  the import ran and admitted zero. The card now branches on the
  presence of an `import_runs` row: a recent import with zero
  admitted rows renders a red-tinted notice citing the dropped
  count from the CSV's `# meta:` line, the filter names operators
  see in journalctl drop logs, and a `journalctl -u lynceus`
  pointer for per-record drop reasons.

- **Dashboard allowlist page now shows inline editing instructions
  with the file path and a copy-pasteable YAML format example when
  the allowlist is empty.** Tier 1's scaffolded default allowlist
  made the "configured + empty" state the default fresh-install
  shape; previously the page just said "No allowlist entries."
  with no signal about how to populate the file outside the
  in-page Add form. The new empty-state article surfaces the
  exact `allowlist_path` the route loaded from, a two-entry YAML
  example, the supported `pattern_type` vocabulary, and a daemon-
  restart reminder.

- **Wizard apply-complete page now reminds operators to run
  `sudo lynceus-bootstrap-kismet --skip-install` if they haven't
  already**, since lynceus can't observe any devices until Kismet
  is configured for capture (interfaces in monitor mode, `source=`
  lines in `kismet_site.conf`, group membership). v0.7.5's
  bootstrap-kismet closing pointer signposted setup at the end of
  its run, but setup didn't signpost back. An operator running
  setup first had no in-page reminder to run bootstrap-kismet,
  and could stand up a clean daemon that quietly saw nothing. The
  reminder is always shown on success (reassurance shape) so
  operators who already ran bootstrap-kismet just see it
  confirmed; those who haven't get the signal they needed.

- **`db_path` is now consistently resolved from `lynceus.yaml`
  across the daemon and the quickstart launcher.** Previously the
  wizard imported the bundled watchlist into the canonical XDG/FHS
  data path (`~/.local/share/lynceus/lynceus.db` under user scope,
  `/var/lib/lynceus/lynceus.db` under system) but never wrote
  `db_path:` into the rendered config. The daemon, loading the
  same yaml later, fell through to a CWD-relative
  `"lynceus.db"` default and opened a different SQLite file,
  leaving the freshly-imported watchlist invisible to the live
  process. Wizard apply now persists `db_path:` explicitly, and
  the config loader back-fills the canonical path for legacy
  yamls that omit the field.

- **Bluetooth Classic devices reported by Kismet as `BR/EDR` and
  Wi-Fi bridge devices reported as `Wi-Fi WDS AP` are now
  recognized.** Both type strings live in real Kismet captures
  but were absent from the parser's type map and silently dropped
  as unparseable; the Parrot-OS smoke surfaced ~6 unparseable
  drops per tick on a captureful host that were almost entirely
  these two types.

## [0.7.5] - 2026-05-25

### Added

- **Daemon now logs which source names Kismet is reporting when
  observations get dropped under the source allowlist.** When the
  per-tick heartbeat shows admitted=0 with the drop count under
  `source_allowlist`, operators previously had to flip the daemon to
  debug level (or hand-query Kismet's REST API) to see WHICH source
  names were mismatching the lynceus.yaml configuration. The daemon
  now emits one INFO line per affected tick naming the actual source
  names Kismet is reporting alongside what lynceus expects, so the
  fix path ("edit kismet_site.conf source= line OR rerun
  `sudo lynceus-setup --web`") is visible directly in journalctl.
  Bounded to one line per tick regardless of how many records drop;
  the per-record DEBUG line is preserved for forensic detail at
  debug level.

- **lynceus-bootstrap-kismet's adapter-selection prompts now name the
  vendor / product / bus / driver.** Each Wi-Fi or Bluetooth row in
  the interactive selection previously read as just the bare kernel
  interface name (`Use Wi-Fi interface wlx00c0cab966f8 ...?`), which
  left operators with two same-kind USB dongles unable to tell which
  was which. Rows now render the same disambiguating descriptor the
  web wizard's step 4 uses
  (`Use Wi-Fi interface wlx00c0cab966f8 — Alfa AWUS036ACS (USB rt2800usb) ...?`),
  shared via a single helper so the bootstrap CLI and the web wizard
  stay aligned going forward.

- **lynceus-bootstrap-kismet's closing pointer now leads with the web
  wizard.** Step 6 of the "Next steps" block previously named
  `sudo lynceus-setup` (the terminal-based wizard); on first-run
  bootstraps it now leads with `sudo lynceus-setup --web` and
  mentions the terminal-based fallback for headless / no-browser
  setups. Operators following the bootstrap path land in the
  recommended browser-based form by default.

### Changed

- **Wizard's apply-time Kismet source-name cross-check now shows
  BOTH lists when they don't align.** The warning previously named
  only the lynceus side ("Kismet doesn't currently expose these
  source name(s): wlan0"), leaving operators unable to tell whether
  to edit kismet_site.conf or re-run the wizard. The new message
  surfaces what Kismet actually exposes AND what lynceus.yaml
  expects side-by-side, names any matched source explicitly, and
  points at both fix paths inline ("edit /etc/kismet/kismet_site.conf
  source= line(s) ... OR re-run `sudo lynceus-setup --web` to select
  adapters that match Kismet's current configuration"). The existing
  `--skip-install` / DEPLOYMENT.md hint clause for non-apt distros is
  preserved on the end of the message.

## [0.7.4] - 2026-05-25

### Added

- **Daemon now logs the type strings of any Kismet device records it
  can't categorize.** The parser silently drops device records whose
  `kismet.device.base.type` isn't in its known-type table. The per-
  tick unparseable counter reflects the drop, but operators couldn't
  see WHICH type strings were causing the drops without re-
  instrumenting. The daemon now emits a debug-level log line at each
  drop naming the unrecognized type and the device's MAC. Operators
  with unexplained drop counts can capture the frequency table on
  their host with
  `journalctl -u lynceus -p debug | grep 'unrecognized type' | sort | uniq -c`;
  recognized types will extend in the next release based on what
  surfaces. Debug level (not info) so production journals stay clean
  unless the operator opts in.

- **Last seen signal strength and SSID on the devices list.** The
  `/devices` table previously showed first-seen / last-seen
  timestamps and a sighting count, but to learn whether a sighted
  device was strong-signal-right-now (probably nearby) versus
  weak-and-drifting (probably ambient), or to read the SSID it most
  recently associated with, operators had to click into each
  device's detail page. The list now surfaces "Last RSSI" and
  "Last SSID" columns drawn from the most recent sighting per
  device, so a sweep of the page is enough to triage what's worth
  drilling into. The home page's "recently seen devices" block adds
  the "Last RSSI" column too (SSID stays on the deeper list, SSID
  strings can be long and would clutter the at-a-glance view).
  Devices with no sightings, and probe-only Wi-Fi devices with no
  associated network, render an em-dash in those cells.

### Fixed

- **Wizard's Previous and Next buttons now render at matched sizes.**
  The footer button pair on every wizard step picked up extra vertical
  margin on the Next button (the real `<button>`) that the Previous
  link (an `<a role="button">`) never inherited, leaving the pair
  visibly off-baseline on smoke. The fix pins the residual margin and
  display-type properties on both elements inside the existing
  `.wizard-footer` rule so they resolve to the same rendered box
  model regardless of element type or browser default.

- **Wizard's adapter selection page now shows a disambiguating
  identifier even for adapters without USB string descriptors.**
  Internal SoC Wi-Fi (e.g. Raspberry Pi's brcmfmac) and USB devices
  that omit the optional vendor / product descriptors previously
  rendered with only their interface name and MAC, making two such
  adapters indistinguishable to the operator. The row label now falls
  back through the VID:PID pair to the bare driver module name when
  the higher-priority fields are absent, so every row carries
  *something* the operator can use to tell adapters apart.

- **Dashboard's filter forms on alerts, watchful, and watchlist now
  use consistent search labels.** Three of the four search-bearing
  dashboard pages read as a stray lowercase "q" next to the filter
  input, where allowlist already read "search"; the inconsistency
  looked like a UI bug. The watchful and watchlist pages now match
  allowlist's "search" label, and the alerts page (which has two
  search inputs, device fields vs rule name / message) reads as
  "device search" and "rule search" so the two filters are
  distinguishable at a glance. Form `name="q"` is unchanged, so
  bookmarked filter URLs continue to work.

- **Recovery hint for source-name mismatches now points operators on
  non-apt distros at `--skip-install`.** When `verify_kismet_sources`
  reports a mismatch or can't reach Kismet, the recovery copy used
  to suggest only the bare `lynceus-bootstrap-kismet` invocation,
  which dead-ends on Parrot/Fedora/Arch/RHEL because the apt-install
  path only covers Debian/Ubuntu/Kali. The hint now names the
  supported distro matrix inline and points operators on others at
  `lynceus-bootstrap-kismet --skip-install` (the distro-agnostic
  configure path) plus the new `docs/DEPLOYMENT.md` subsection that
  walks through the manual Kismet install. No change to cross-check
  logic or status determination. Operator-readable copy only.

- **Wizard now wires the severity-overrides file path into
  `lynceus.yaml`.** The wizard's apply step scaffolds
  `severity_overrides.yaml` to disk so operators have a starting
  point for runtime severity tweaks, but pre-fix it did not write
  the resulting path back into the main config. `lynceus.yaml`
  was emitted without a `severity_overrides_path:` field. On next
  daemon start the override file was silently unused (the runtime
  layer logged "severity_overrides_path not set in lynceus.yaml") so
  edits to `device_category_severity` or `suppress_categories` had
  no effect until the operator hand-edited the config to wire the
  path in. The wizard now persists the scaffolded path into
  `lynceus.yaml`; edits to the runtime sections take effect on
  daemon restart with no further config surgery. Existing
  `lynceus.yaml` files without the field continue to load
  unchanged. The daemon falls back to the same "layer disabled"
  startup log as before.

## [0.7.3] - 2026-05-25

### Added

- **Wizard verifies your selected capture sources match what Kismet
  actually exposes.** Picking adapter names in wizard step 4 that don't
  match Kismet's `source=<dev>:name=<name>` entries silently dropped
  every observation from those adapters. The dashboard looked broken
  for no visible reason and operators had no breadcrumb until they
  enabled DEBUG logging. The wizard now cross-checks during apply
  that your selected sources match what Kismet exposes; if they don't,
  you'll see a warning naming the specific mismatched source(s) and
  pointing at the recovery path (`lynceus-bootstrap-kismet` for a
  green-field install, or a `kismet_site.conf` name edit if the names
  drifted). The warning is non-blocking, setup still completes, and
  if Kismet wasn't reachable at apply time the cross-check skips
  rather than failing, so you can re-run the wizard once Kismet is
  up. See `docs/DEPLOYMENT.md` § Common issues #6 for the full
  operator reference.

- **Per-tick observability on the dashboard, in journalctl, and on
  `/healthz`.** A working poll loop that drops every observation at a
  configuration gate previously looked identical to a dead daemon.
  operators had to enable DEBUG logging or open a SQLite shell to
  tell them apart. Each poll cycle now writes admitted-and-dropped
  counts to the database (one row per counter in `poller_state`,
  overwritten in place so the table stays bounded), emits a single
  INFO heartbeat line of the form `poll tick: N admitted, M dropped
  (source_allowlist=…, min_rssi=…, unparseable=…)`, and surfaces the
  same data in three places: the "last poll" card on the home page
  shows admitted/dropped counts with a relative-time stamp, the HTML
  `/healthz` page renders a "last poll tick" block, and
  `/healthz.json` extends the `poller` check with a `poll_tick`
  object plus an `is_stale` boolean (true when the most-recent tick
  is more than 2× the configured poll interval old). The three
  drop-reason labels are operator-readable: "allowlist mismatch"
  flags observations from a Kismet datasource not in
  `kismet_sources`; "below signal threshold" flags observations
  weaker than the configured `min_rssi`; "unrecognized device type"
  flags Kismet records whose device type isn't in the Lynceus type
  map (e.g. RTL433 traffic from a 433 MHz datasource running in
  parallel). See `docs/CONFIGURATION.md` § Poll-tick observability
  for the full operator reference.

- **Richer per-device info on the dashboard.** The `/devices` list and
  the home page's "recently seen devices" block previously showed only
  a Device label (resolved to the OUI vendor when no friendly name
  was known) plus type / timestamps / sighting count, so a Sony
  WH-1000XM4 headset was indistinguishable from any other row whose
  vendor happened to be Cambridge Silicon Radio. The list now surfaces
  the Kismet-extracted BLE advertised name as its own column, so
  operators read "Sony WH-1000XM4" directly off the row instead of
  resolving it through the label fallback chain. The Device label
  itself now prefers the BLE name over the vendor fallback, fixing the
  same mis-identification on the home page. The OUI vendor is
  promoted from a label-fallback into its own visible column on both
  pages, so vendor and BLE name can be scanned independently. The
  deeper `/devices` page also gains a Probes column listing the
  SSIDs the device has been observed probing for. A forensic detail
  useful for triaging unknown sightings (e.g. spotting a device that
  probes for "DEA-WiFi"); the home page keeps its scannable shape
  and does not show this column. All four columns degrade to an
  em-dash when the underlying Kismet data is absent, so devices
  observed before Kismet's BLE name / probe extraction was enabled
  render cleanly.

### Fixed

- **Three wizard chrome and step-4 residuals from v0.7.2 smoke.** The
  top-nav strip ("lynceus-setup vX.Y.Z") rendered as floating letters
  above the form because Pico's classless build leaves a bare `<nav>`
  with no card chrome of its own; the wizard's `<nav>` now carries a
  visible header band (card-style background + bottom border) so the
  page reads as a deliberate app header instead of an unstyled DOM.
  The Previous/Next button pair still rendered at slightly different
  heights even after v0.7.2's horizontal-axis normalization, because
  Pico's `<a role="button">` inherits anchor line-height and `<button>`
  uses the UA-default form-control line-height; the sizing rule now
  also pins vertical padding, line-height, and box-sizing so both
  element types resolve to the same rendered box model, including
  step 3's two-button "Cancel / Continue anyway" footer, which
  semantically can't be the anchor-then-button pair other steps use.
  Step 4's adapter rows previously labelled each adapter with only
  kind + MAC, so an operator with two USB Wi-Fi dongles plugged in
  could only tell which row was which by squinting at MAC prefixes;
  rows now surface the USB Product string + bus + driver in the
  label (e.g. `wlan1 [Wi-Fi] — Alfa AWUS036ACS (USB rt2800usb) ·
  MAC ...`) when sysfs exposes them, and degrade gracefully to the
  prior shape on internal (non-USB) adapters or hosts where the
  wizard process can't read `device/*` descriptors.

- **Filter form on `/devices` no longer 400s on the default
  submission.** Clicking the "filter" button on the devices page
  without changing the form selections previously dropped the
  operator on a raw JSON `{"detail": "invalid device_type"}` page,
  because the form's "any" `<option value="">` posted an empty
  string that slipped past the allowlist guard. The route now
  normalizes empty-string filter params to "no filter" at entry, so
  the default form submission renders the unfiltered list as
  intended. Hand-edited URLs with actually invalid values (e.g.
  `?device_type=cellular`) still 400, but the operator now lands on
  a same-themed HTML error page that names the bad value and offers
  a back link, instead of a JSON blob with no recovery path. The
  HTML error page is global. Any HTTPException raised by the read-
  only web UI now renders with the standard chrome and a back link
  for any browser client.

## [0.7.2] - 2026-05-24

### Fixed

- **Smoke-driven wizard UX fixes round 2.** Second pass of v0.7.1 on
  real Pi hardware surfaced four more paper cuts that this patch
  addresses. The Kismet sources page (step 4) is reworked: instead of
  building the source list from Kismet's probe response (which left
  operators with a dead-end "highlighted box that doesn't do anything"
  on first-run boxes where Kismet has nothing configured), the page
  now enumerates OS-side capture adapters directly (Wi-Fi from
  `/sys/class/net/*/wireless`, Bluetooth from `/sys/class/bluetooth/`)
  and renders each as a checkbox row with kind, MAC, and (when
  matched) the corresponding Kismet source name. The Kismet probe
  result is shown above as a read-only sanity-check panel so
  operators can spot mismatches between what Kismet knows and what the
  OS exposes. Multiple sources can now be picked in a single submit
  rather than juggling separate Wi-Fi/Bluetooth widgets. On hosts
  where OS enumeration finds nothing (Windows dev, container without
  device passthrough), a manual-text fallback lets a remote operator
  still type the Kismet source name. The RSSI threshold page (step
  10) replaces the negative-dBm number input with a range slider
  whose extremes are labelled with the concrete trade-off in operator terms ("catches more weak / distant devices, more false positives" vs "catches fewer; only strong / nearby devices, higher confidence") plus a tip below naming the -80 dBm default, so
  the operator drags toward intent without ever resolving the
  sign-convention confusion that v0.7.1's inline copy didn't land.
  Previous/Next button sizing across every step template is
  normalized via an explicit `min-width` + padding rule in
  `_base.html` so the button row reads as a matched pair regardless
  of label width (was previously uneven because `<a role="button">`
  and `<button>` rendered at each label's natural text width). Page
  centering is tightened with three new rules: an explicit
  `main.container` max-width pin with viewport-side gutter, a section
  divider under each step's H1, and a card-style background on the
  step's `<form>` so the input block visually separates from the
  prose intro instead of reading as one continuous wall of text.

## [0.7.1] - 2026-05-24

### Fixed

- **Smoke-driven Linux fixes.** Post-release smoke of v0.7.0 on real
  Pi hardware surfaced a handful of paper cuts that this patch
  addresses: the bundled Argus watchlist import needed a longer
  timeout on Pi-class hosts (now 600s, was 120s, the bundled CSV
  grew to ~22.5k records and per-row sqlite commits dominate wall
  time on SD storage); the `chown_db_files` step's skipped reason in
  user-scope installs now reads "Not applicable for user-scope
  install (DB files are already owned by the operator)" instead of
  the alarming-looking "scope=user" literal; the web wizard's
  completion page now surfaces scope-adapted next steps (`lynceus-
  quickstart` for `--user`, `sudo systemctl enable --now lynceus.
  service lynceus-ui.service` for `--system`) so operators who
  reached the wizard via `--web` discover how to actually start the
  daemon; the Kismet sources page (step 4) now renders each source's
  `capture_interface` and Kismet-issued UUID alongside the interface
  name so operators on multi-adapter hosts can unambiguously match a
  wizard row against Kismet's web-UI Datasources page; step 12
  (rules engine) gained a "Select all rule types" checkbox that
  toggles every per-type checkbox at once via a one-line inline
  handler; the RSSI threshold page (step 10) carries a new inline
  hint explaining the negative-dBm sign convention so the browser's
  number-arrow direction (up = closer to 0 = stricter) does not
  read as "reversed"; the Cancel button on the kismet-sources
  dead-end branch was normalized from Pico's accent-color
  `contrast` variant to the standard `secondary` variant for
  consistency with every other Cancel button in the wizard; and
  `install.sh`'s closing "Next steps" block now mentions `lynceus-
  setup --web` as a browser-based alternative to the CLI wizard.

## [0.7.0] - 2026-05-24

### Added

- **Browser-based `lynceus-setup --web` wizard.** A second frontend
  for the first-run configuration ceremony. Invoke `lynceus-setup
  --web` and the command prints a loopback URL with a single-use
  setup token; opening that URL in a browser walks you through a
  12-step form that mirrors the interactive CLI flow question-for-
  question (Kismet URL / API key / probe / source selection /
  capture toggles / ntfy URL and topic / RSSI / severity overrides /
  per-rule-type alerting opt-ins). Every page validates input
  through the same `Config` constructor the daemon loads from disk,
  so the wizard can't produce a configuration the daemon will
  refuse. The review page renders the validated config with secrets
  redacted (Kismet API key head/tail, ntfy topic head + bullets +
  tail), and clicking Apply runs the same write + chown + bundled-
  import chain the CLI wizard executes. Live progress streams to
  the browser step-by-step via Server-Sent Events, and the
  completion page renders a per-step transcript with status icons.
  Re-run is offered on failure (atomic file writes and dedup'd
  bundled import make the apply chain safe to re-run); when
  re-running over an existing config, the page warns that
  hand-edits to `lynceus.yaml` or `rules.yaml` since the last apply
  will be clobbered. Clicking Done cleanly shuts down the wizard
  server; Ctrl-C in the launching terminal is the manual fallback,
  and a 10-minute post-apply grace window auto-exits if you walk
  away without clicking Done. Loopback-bound by default on port
  8766 (one above `lynceus-ui`'s default 8765 to avoid collision
  with a running dashboard); `--bind 0.0.0.0` is the explicit
  remote opt-out, and `--port` overrides the default. The CLI flow
  (`lynceus-setup` without `--web`) is unchanged when this flag is
  absent.

### Changed

- **Internal refactor: `lynceus-setup` now drives its file-write
  chain through a shared core.** No operator-visible behavior
  change. The wizard's prompts, output lines, exit codes, and the
  `--system` permissions sequence are byte-for-byte identical to
  v0.6.3. The deterministic write + import + chown chain moved out
  of the CLI module into a new `lynceus.setup` package that returns
  a structured per-step report. This is the foundation that lets
  the new web wizard reuse the exact same apply logic with a
  different progress sink. Known parity quirk carried forward: the
  wizard scaffolds `severity_overrides.yaml` but does NOT persist
  `severity_overrides_path` into `lynceus.yaml`. Pre-dates this
  refactor, flagged for future cleanup.

### Fixed

- **`lynceus-setup` (CLI) exits cleanly on Ctrl-C or Ctrl-D.**
  Previously, hitting Ctrl-C mid-wizard surfaced an unhandled-
  exception traceback to stderr; Ctrl-D (or stdin closing) raised
  an `EOFError` traceback for the same reason. Both signals now
  exit cleanly with `Wizard cancelled, no changes written.` to
  stderr and exit code 130. No files are written on cancellation.
  A companion fix reconfigures `sys.stderr` to UTF-8 alongside the
  v0.6.3 stdout reconfigure, closing a latent Windows cp1252 crash
  path during apply-failure logging.

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
  "the wizard is done" signal. Indistinguishable from a hang. The
  wizard now prints an explicit `Setup complete, exiting.` boundary
  (with a flushed stdout) as its final visible line so the
  end-of-flow handoff is unambiguous. As defensive insurance against
  a separate failure mode, the bundled-watchlist auto-import
  subprocess now has a 120s timeout. If `lynceus-import-argus`
  itself ever hangs (stuck sqlite lock, malformed DB), the wizard
  kills it and surfaces a clear "exceeded timeout (process killed)"
  error instead of waiting forever.

- **`lynceus-bootstrap-kismet --reset-config` clears stale adapter
  entries.** Previously, re-running bootstrap after physically removing
  an adapter left the old `source=<iface>` line in `kismet_site.conf`
  forever. The patcher was append-only by design (to preserve
  operator hand-edits like `:channel_list=...`), and had no way to
  drop a line. The new flag backs up the existing
  `kismet_site.conf` to `kismet_site.conf.bak-<unix-ts>` (so any
  non-source hand-edits like `httpd_*`, `server_name`, `log_prefix`
  survive in the backup, recoverable by `mv` back), then writes a
  fresh file from the current interface detection. Default behaviour
  unchanged. Re-runs without the flag still preserve everything.
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
  adds `imei_tac` (IMEI Type Allocation Code, the first 8 digits of
  an IMEI, populated via regulatory channels) as a new
  identifier_type. It ships at 0 rows initially, with backfills
  arriving in v1.5.x. Migration 021 admits `imei_tac` in the
  watchlist `pattern_type` CHECK and the importer's identifier-type
  map gains the matching entry. Without the migration, the first
  v1.5.x backfill would fail the SQLite CHECK on INSERT. Runtime
  alerting on `imei_tac` is deferred. There is no Kismet-observable
  surface for IMEI TAC values, so no matcher, no `device_category`
  default, and no severity default land in this release. Once Argus
  publishes a concrete TAC corpus, runtime alerting can be wired up;
  same posture as `icao_24bit_address`.
## [0.6.1] - 2026-05-22

### Fixed

- **`lynceus-bootstrap-kismet --skip-install` now works on every Linux
  distro.** Previously the flag only worked on Debian, Ubuntu, and Kali.
  Operators on Mint, Parrot, Devuan, etc. saw an "unsupported distro"
  message and the script exited without doing anything, even though
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
  from the Bluetooth spec). Useful for Flock devices that broadcast
  names like `Penguin`, `FS Ext Battery`, `Flock`, `FLOCK`, and
  `Flock-*` variants. This bumps Flock detection from 3 watchlist rows
  to 20, a 6.7× yield jump for the most operationally relevant
  target. Names match case-sensitively and exactly (wildcards are
  planned for a later release). Surfaces in the watchlist filter
  dropdown, the `/allowlist` add-form, the setup wizard (now 8
  delegation rules), and a commented-out template in
  `config/rules.yaml` (off by default for privacy). Requires
  `capture.ble_friendly_names: true` in `lynceus.yaml` to fire,
  without it, BLE names aren't captured at all.

- **Placeholder severity setting for automotive telematics.** Argus
  v1.4.1 added an `automotive_telematics` device category but hasn't
  shipped any rows in it yet (coming in v1.4.2). The setup wizard now
  seeds a commented example so the category shows up in your config
  when the data arrives. No runtime change.

- **Warning if an Argus export's schema version is unexpected.** The
  importer now checks the `schema_version` in incoming Argus CSV
  exports against an accept-list (default: versions 25 and 26).
  Unknown versions print a warning but the import still proceeds.
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
UI-related. The new `/alerts` keyboard-shortcut JS in particular has
lighter coverage by its nature.

### Added

- **Keyboard shortcuts on `/alerts`.** Triage the alert queue without
  reaching for the mouse:

  - `/`, focus the search bar
  - `n`, next page
  - `p`, previous page
  - `?`, toggle a help panel listing all shortcuts
  - `Esc`. Close the help panel, or reset filters if the panel is
    already closed

  Shortcuts don't fire while you're typing in a text field (so `/` and
  `?` land as characters in the search box) or when you're holding
  Ctrl / Cmd / Alt (so OS and browser shortcuts still win). The page
  remains fully usable with JavaScript disabled. Every shortcut has a
  mouse equivalent. A small "Press `?` for keyboard shortcuts" hint
  sits near the page counter for discoverability. Scope is `/alerts`
  only for now; other pages to follow. Row-selection shortcuts
  (`j` / `k` / `a` / `Enter`) are deferred. They need a selected-row
  UI primitive that doesn't exist yet.

- **Hour-and-minute precision on `/alerts` date filters.** You can now
  filter by something like "Tuesday 14:00 to Wednesday 09:00" directly
  in the filter bar. Previously only whole days worked, which
  overstated any sub-day window. Date pickers swap from date-only to
  datetime-local; times are interpreted as UTC (no timezone config,
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
  unnecessary SQL writes, even though nothing in the source had
  actually changed. Two distinct duplicate shapes in the upstream
  Argus data caused this; both are now caught at import time. A
  no-op re-import now produces exactly 1 SQL write (the import-run
  log entry).

  As a side benefit, when duplicates do exist in the source CSV, the
  importer now picks the highest-severity entry instead of whichever
  appeared first in the file. The motivating case was a Flock Safety
  row pair where the first-in-file entry would have been flagged
  `low` and the second `med`. Previously the `low` entry silently
  won; now the `med` one does. Counter math now balances cleanly:
  `imported_new + dropped_peer_collision + dropped_in_import_dup +
  dropped_unknown_type = total_input_rows`.

  Two new counters (`dropped_peer_collision` and
  `dropped_in_import_dup`) appear in import reports. No schema
  changes, no migration. Existing databases with thrashed timestamps
  need nothing; the next import is idempotent against them.

## [0.5.0] - 2026-05-20

Release status: This release has not yet been validated against real Kismet + ntfy + systemd on Linux hardware. The test suite covers 2434 tests on Windows / 2450 on Linux at this commit, plus 21 diagnostic tests. Functional correctness is asserted by tests; deployment behavior is documented in `docs/DEPLOYMENT.md` and `docs/KALI_SMOKE_CHECKLIST.md` but unsmoked at this tag. If you hit issues, file via the project tracker with browser + Python version + relevant journalctl excerpt. The most likely class of bugs is UI-related. The keyboard-shortcut JS and the operator-facing templates have lighter coverage by their nature.

### Added

- **Clearer filtered indicator on `/alerts`, plus `Esc` to reset.** The bare "reset filters" link is replaced with a single summary that names which filters are active and their values, e.g. `Filtered by: severity=high, since=2026-05-01, q=apple -- reset filters (or press Esc)`. No more scanning the form to figure out why a result count is narrow. Pressing `Esc` resets filters, with an input-focus guard so typing into the search box is unaffected. First keyboard shortcut on the webui; scoped to `/alerts` only. The watchful / watchlist / allowlist pages keep their existing bare-link rendering.

- **`docs/DEPLOYMENT.md`: end-to-end install runbook.** Walks a fresh Kali / Debian / Ubuntu host through prerequisites, clone + install, Kismet bootstrap, API key creation, `lynceus-setup`, optional Argus refresh, `lynceus-validate` preflight, systemd enable (system install) or `lynceus-quickstart` foreground (dev/demo), and smoke verification. Each step carries action + expected output + brief explanation, so you can paste and tell whether it worked. A "Common issues" section covers the five failure modes that surface most often: Kismet API key auto-detect, PATH not picking up `lynceus-*`, adapter not in monitor mode, ntfy topic mismatch, and systemd unit permission-denied. README gains a "Getting started" link to the new runbook.

- **Migration rollback via `lynceus-validate rollback --target-version N`.** Every shipped DB migration (001..019) now ships a paired down-file, and the new subcommand walks the applied chain in descending order to undo them. Defaults to the canonical DB path for `--scope user|system`; `--db PATH` overrides for off-canonical installs or copies. Interactive runs prompt for an explicit `yes`; scripted use requires `--yes`. The legacy `lynceus-validate --scope user` invocation is preserved verbatim for existing scripts. Most migrations reverse cleanly. CHECK-relaxation migrations (011, 013, 014, 019) abort with `CHECK constraint failed` if rows of the now-disallowed type exist. Delete them or restore from backup, then re-run. Migration 010 (watchlist-pattern normalization) is IRREVERSIBLE; the runner logs a WARNING, marks it un-applied so the chain can continue, and runs no SQL. **BACK UP YOUR DB BEFORE INVOKING ROLLBACK.** See [`docs/CONFIGURATION.md` §Database migration rollback](docs/CONFIGURATION.md#database-migration-rollback) for the full flow.

- **`/watchlist.csv`: streaming CSV export of the filtered watchlist.** Sibling of `/alerts.csv`. "Export CSV" link sits next to the pagination summary on `/watchlist`; the href carries the current filter query string (pattern_type, severity, device_category, q). Pagination is bypassed. The export covers every matching row, up to the full ~22k-row Argus corpus. Filename: `watchlist-YYYYMMDDTHHMMSSZ.csv` (ISO UTC, sorts lexicographically). Column projection is wider than the list page: surfaces the full Argus provenance you'd otherwise click through to per-row (`argus_record_id`, `device_category`, `confidence`, `vendor`, `source`, `source_url`, `source_excerpt`, `fcc_id`, `geographic_scope`, `first_seen`, `last_verified`, `notes`) plus the row itself. YAML-seeded rows without Argus metadata export with empty cells in the metadata columns. Streamed; no row cap. Invalid filter values silently fall back to "all" (matches the list route); `q` capped at 100 chars.

- **`/alerts.csv`: streaming CSV export of the filtered alerts.** "Export CSV" link next to the pagination summary on `/alerts`. The href carries the current query string, so the download mirrors the visible filter state exactly (severity, acknowledged, since/until, search, rule_type, q, window, has_note, has_action). Pagination is bypassed. Filename: `alerts-YYYYMMDDTHHMMSSZ.csv`. Column order is stable and parser-friendly, with both watchlist and Argus-provenance join fields surfaced so you get vendor / confidence / category offline without clicking through. Streamed; no row cap. Invalid severity still 400s; other invalid filter values silent-fall-back to "all". No CSRF (GET-only).

- **`/alerts` `has_action` filter: triage-state-aware dropdown.** `any / with action taken / without action taken`, default `any`, alongside the existing `has_note`. An alert counts as "actioned" if any of three signals applies: a per-alert snooze (active entry in `allowlist_ui.yaml`), a permanent allowlist match (active entry in `allowlist.yaml`), or watchful tracking (the alert's MAC has a non-archived watchful row). The watchful signal is mac-scoped. Every alert from a MAC under an active watchful entry inherits the actioned status, matching the actual suppression effect. Expired snoozes are skipped. Rule-type snoozes are intentionally NOT in scope (that surface is system-wide, not per-alert). Notes are also out of scope. Combine with `has_note` for workflows like `?has_action=with_action&has_note=without_note` ("actioned but unannotated"). Composes with every existing filter; pagination counts honor it; bulk-ack via `/alerts/ack-all-visible` mirrors it cleanly. Allowlist YAML loads are lazy, only when `has_action` is engaged, so the default `/alerts` page stays YAML-cost-free. Pattern types other than `mac` and `oui` are out of scope here (see the `mac_range` parity bullet below for the follow-up).

- **Per-alert snooze: operator-pickable duration.** The snooze form on the alert detail page grows a duration selector: `1h / 24h / 7d / 30d / forever`, replacing the bare "Snooze for 24h" button. Default stays `24h`, and a form submission without a duration produces the same `expires_at` and provenance note as before, so existing links / scripts behave identically. `1h` is new and lives on per-alert snooze only ("shut up about this for an hour while I look into it"); the watchful triage selector stays at four options since 1h doesn't fit recurrence-tracking semantics. The `forever` option writes a NULL `expires_at` but records distinct provenance (`"snoozed forever via webui"`) so you can tell from `allowlist_ui.yaml` which surface produced the entry. Unknown duration values return 400 with no YAML side-effect. CSRF and the `confirm()` safety prompt are unchanged.

- **Per-rule_type snooze.** New `rule_type_snoozes` table (migration 017) lets you silence all alerts from a specific rule_type for a bounded window (`1h / 4h / 24h / 7d / 30d`). Controls live on `/rules` per row: rule_types without an active snooze get a collapsible "snooze..." form with a duration dropdown and optional note; snoozed ones get a badge (expiry rendered relative and absolute in the tooltip), the note, and an "unsnooze" button. A new `status=all|snoozed|active` filter on the page lets you narrow to "what's currently silenced?". Distinct from per-alert snooze: rule-type snooze mutes the whole rule class at the alert-emit boundary. The rule still evaluates, but DB write, evidence capture, and ntfy emit are all gated during the window (the operator's whole point in snoozing is "don't page me"). Expired snoozes are filtered at gate-check time and physically deleted on the poller cycle. A periodic INFO line in the daemon, `rule_type snooze suppressed N alert(s) in last ~Ts: <breakdown>`, surfaces suppression counts to `journalctl` so you can confirm it's doing its job beyond the badge. Re-snoozing an active rule_type overwrites the prior expiry (no need to unsnooze first).

- **Watchful snooze: backend.** Recurrence-aware third snooze surface; the daemon-side machinery lands first, UI follows in the next bullets. New `watchful_recurrence` table (migration 018) tracks per-MAC observations under watchful snooze, counts sightings on a >=24h gap debounce, and emits a synthetic `watchful_recurrence` rule_type alert at ntfy priority 4 on the 4th sighting (1 initial + 3 counted recurrences). A 90-day no-observation auto-archive runs on the poller cycle (alongside rule_type snooze and evidence-prune housekeeping). Gate ordering is allowlist -> watchful -> rule eval -> rule_type snooze -> per-alert snooze -> emit, so allowlist precedence wins: an allowlisted MAC under watchful snooze sees no sighting count increment and no escalation alert. Severity stays `high` for `/alerts` and `/rules` rendering; only the ntfy priority drops to 4 for the scare-factor mitigation. With no entries in the table, poll cycles are byte-identical to pre-feature behavior.

- **Watchful snooze: operator actions.** HTTP-and-DB plumbing for the five operator actions on watchful entries, plus the triage entry-point from `/alerts`. CSRF-protected throughout. Routes: `/alerts/{id}/watch` to start watching from the alert list, and `/watchful/{id}/{dismiss,promote,reset,investigate,confirm-safe}` for the action surface. All return 303 redirects, validate snooze duration against `{forever, 24h, 7d, 30d}`, cap operator notes at 4096 chars, and return 400 for stateful preconditions. The auto-archive sweep coexists cleanly with operator-driven archives. `promote` writes to `allowlist.yaml` and archives atomically (YAML first, DB second, best-effort YAML rollback on race). `confirm-safe` archives but does NOT create an allowlist entry. The operator's signal is "this entry is benign", not "never alert me on this MAC again". No schema change.

- **Watchful snooze: UI.** Closes the loop. New `/watchful` page lists tracked devices with filter (status / state / window / MAC substring), pagination (25 / 50 / 100 / 200; default 50), per-entry action buttons, and a recurrence-digest section. A new `/watchful/<id>` detail page mirrors `/alerts/<id>` with full state, cross-links to source alert / matched watchlist row / device record, and the same action panel. Topnav gains `/watchful` between `/alerts` and `/devices`. `/alerts` grows a per-row "Watch" button (`24h / 7d / 30d / forever`, default `30d`) that posts to the triage route. All five action POSTs redirect to `/watchful?success=<token>` so you stay in context and see a banner per the `/rules` flash convention. Action visibility honors the state guard: reset only on escalated entries; archived entries are read-only. Promote (red, "never alert me on this MAC again") and confirmed-safe (green, "close as benign") are visually distinct. Conflating them would silently break the threat-model intuition. The recurrence digest is a section on `/watchful` (not a separately-emitted notification): groups escalations from the last 8 ISO weeks, most recent first. Copy stays non-alarmist: "watchful", "recurrence", "sighting", "tracked device" rather than "threat" / "intrusion" / "danger".

- **SSID dimension activated end-to-end.** Three changes land together. The `watchlist_ssid` rule type is unchanged on the operator-facing surface, but its DB-delegation mode now dispatches both exact-match and substring patterns from one rule, the bundled `argus_ssid` rule is enabled by default, and the bundled `default_watchlist.csv` is refreshed from the 2026-05-17 Argus snapshot so fresh installs alert on Flock-class equipment out of the box.

  Migration 019 admits `ssid_pattern` in the watchlist `pattern_type` CHECK. A new substring matcher (case-insensitive) joins the existing exact-match path: exact is consulted first, substring falls back on miss; severity flows from whichever DB row fires.

  `lynceus-import-argus` learns the `ssid_pattern` identifier. The 5 ssid_pattern rows from the Argus snapshot (`flock`, `Flock`, `FLOCK`, `FS Ext Battery`, `Penguin`) flow into the watchlist at the `device_category`-derived severity. Rows whose `ssid_exact` value contains a literal `*` (e.g. Argus's `Flock-*` row) log a WARNING and are imported anyway. The `*` never matches a real WiFi observation, so the row sits dormant until Argus fixes the typing upstream.

  `default_watchlist.csv` refresh: 22533 records exported 2026-05-17, replacing the prior 63-row / zero-SSID-coverage snapshot. `config/rules.yaml`'s `argus_ssid` template is uncommented and enabled. `docs/ARGUS_RESIDUALS.md` updated to reflect `ssid_pattern` moving from deferred to admitted (deferred drops from 2 types / 21 rows to 1 type / 16 rows).

  Operationally: a Kismet observation of `Flock-230503` (exact ssid) or `My-Penguin-AP` (substring) now alerts at the matched row's severity on a fresh install with the bundled config.

- **`mac_range` parity in `/alerts` `has_action` filter and the alert-detail "Allowlisted" badge.** Operators allowlisting a vendor block via a `mac_range` entry (e.g. `aa:bb:cc:d/28`) now see affected alerts flagged as actioned on the list filter AND get the Allowlisted status on each alert's detail page. Both surfaces previously covered only `mac` and `oui`. `mac_range` was the deliberate omission tracked in `BACKLOG.md`. The same bit-level matcher drives the live poll path, the detail page, the CSV export's `action_taken` column, and the list-page filter. No per-surface re-implementation that could drift. `/28` and `/36` are the only prefix lengths admitted (both nibble-aligned), so no operator-visible caveat about prefix alignment.

### Performance

- **`/watchlist/<id>` detail page: single-row read instead of full-table scan.** The route used to load every watchlist row (up to ~22k after a full Argus import) and pick the matching one in Python on every detail-page request. It now reads one row per request. Same template, same fields, same 404 path for missing ids, just no longer the scaling footgun the docstring already called out for the list page.

### Fixed

- **`/alerts?has_action=with_action` no longer 500s when NULL-mac alerts coexist with a `mac_range` allowlist entry.** The `with_action` SQL clause invoked the mac-range matcher (a Python UDF) without a NULL guard, so any NULL-mac alert in the table caused the query to raise and the page to 500. NULL-mac alerts are legitimate (pre-migration-015 historical rows; certain `new_non_randomized_device` early failures). Each predicate now carries an inner `mac IS NOT NULL AND ...` guard. `with_action` returns 200 and excludes NULL-mac alerts (they can't carry a mac-keyed action signal); `without_action` behavior is unchanged.

### Documentation

- **Multi-rule emit policy made explicit.** A single observation that matches N enabled rules emits N alerts: one per matching rule, each carrying its own severity from its own DB row (for `watchlist_*` and `ble_uuid` delegation rules) or from `rule.severity` (for in-memory pattern rules). There is no "highest-severity wins", "first-match wins", or "merge into one alert" step: every matching rule is its own alert. A device on the watchlist by mac, oui, AND ssid produces three alert rows at three potentially-different severities for the same observation. This is intentional. The audit-first design treats each rule as an independent reason to surface the observation, and the dedup window (configurable, default N minutes) collapses near-duplicates downstream so ntfy doesn't drown in repeats. Behavior is locked; `BACKLOG.md` carries a future-consideration entry for an opt-in single-emit-with-resolved-severity mode if operators ask for it.

## [0.4.0-rc6] - 2026-05-17

Mostly cleanup. rc5 shipped the big feature push. `/watchlist` search, filter, and pagination; `/rules` statistics; `lynceus-export-config`; the Argus residuals audit. rc6 closes two normalization gaps the audit surfaced, corrects one audit verdict that was wrong on inspection, and adds per-alert triage notes (plus a matching `/alerts` filter) that operators were working around with external trackers.

### Fixed

- **Importer now admits 17 Argus rows that previously dropped as `unknown_type`.** The rc5 residuals audit (`docs/ARGUS_RESIDUALS.md`) flagged `ble_company_id` (7 rows) and `ble_service_uuid` (10 rows) as semantic duplicates of the already-admitted `ble_manufacturer_id` and `ble_uuid` types. Separated only by the Argus label and a couple of input-shape variants (16-bit and 32-bit Bluetooth SIG short forms, plus Argus's dual-form rendering like `"fd5a / 0x0075"` for Samsung SmartTag / Tile rows). The importer now accepts both. Admit count moves 22,294 → 22,311; dropped 239 → 222. No schema change, no migration.

- **Corrected one audit verdict from "needs smoke" to "drop entirely".** The rc5 audit deferred 49 `device_class_id` rows on plausibility. Going row-by-row, all 49 are DJI drone model-class enum codes (e.g. `'1'='Inspire 1'`). Labels for decoding the DroneID device-type byte, not per-device identifiers. Admitting them would alert on every DJI drone of that model class in range. Per-device Remote-ID coverage is already handled by the admitted `drone_id_prefix`. The audit report is regenerated; total dropped row count is unchanged at 222, only the reason changed.

### Added

- **Per-alert triage notes.** Closes the "what did I conclude about this alert?" gap operators were working around with external trackers. The alert detail page gains a notes section: an editable textarea (4096-char cap), Save and Clear buttons (Clear behind a confirm prompt), and a relative "Last updated N ago" stamp. Notes are plain text, one per alert, replace-on-update. Markdown, history, and multi-operator audit trail are deferred. Empty or whitespace-only text clears the note. Migration 016 adds nullable `note` and `note_updated_at` columns to `alerts`. The `/alerts` list shows a small indicator on rows that carry a note, with a 50-character tooltip preview. The full rationale stays on the detail page so it isn't visible over the shoulder.

- **`has_note` filter on `/alerts`.** Pairs with the list-page note indicator so the triage loop closes: notes → indicator → filter. Three values: `any` (default, unchanged behaviour), `with_note`, and `without_note`. Invalid values fall back to `any`, matching the existing `rule_type` / `window` convention. Bulk-ack via `/alerts/ack-all-visible` honours the filter exactly, so it always operates on the set the operator can see. Pagination links carry the filter through; the default `any` is omitted from URLs so the no-params baseline stays clean.

## [0.4.0-rc5] - 2026-05-17

Release status: alerting for `ble_manufacturer_id` and `drone_id_prefix` rule types needs Kismet probe-path verification on real hardware before it fires on live observations. The import, DB, rules engine, wizard, and `/watchlist` UI all work, but until the Kismet field paths are confirmed against a real capture, the observation fields read `None` and the delegation rules fire zero alerts. See the bullet below for the workaround.

### Added

- **`/watchlist` gets search, filter, and pagination.** A full Argus import lands ~22k rows, and the pre-rc5 page rendered every one in a single pass. Genuinely unbrowsable. The page now has a filter bar (substring `q` across pattern / manufacturer / argus_record_id / device_category, plus dropdowns for `pattern_type`, `severity`, and `device_category`) and offset pagination matching `/alerts` (`page` + `page_size` in {25, 50, 100, 200}, default 50). The "where did I just import that row to?" pain finally has an answer: type the `argus_record_id` substring into `q` and the row surfaces. Filter state round-trips through the URL so a filtered view is bookmarkable. Invalid filter values silently fall back to "all"; out-of-range pages clamp to the last valid page (no 404 on a typo'd `?page=999`). The `device_category` dropdown is populated live from the DB, with `(uncategorized)` as a dedicated option for YAML-seeded rows that lack a category. No schema change, no new indexes. 22k-row scans complete well under the 500ms perf budget.

- **`/rules` shows per-rule fire count and "last fired" stamp.** Answers "is this rule worth keeping?" at a glance. Each rule row carries its fire count over a configurable window plus a relative "last fired" stamp ("3h ago" / "5d ago" / ", " if never). A `since` dropdown matches the `/alerts` convention (`1h` / `24h` / `7d` / `30d` / `all`) with `7d` as the default, so a fresh visit reads "what fired this week." Sort defaults to `rules.yaml` order; opt into `count_desc` / `count_asc` via the sort dropdown for "high-volume rules first." URL params round-trip. `/rules?since=24h&sort=count_desc` bookmarks exactly that view. No schema change, no caching; stats aggregate live from the `alerts` table on every render.

- **`lynceus-export-config`: bundle config (and optionally state) into a portable `tar.gz`.** Closes the missing "save / share / back up my config" surface alongside `lynceus-validate`, `lynceus-bootstrap-kismet`, and `lynceus-setup`. Four use cases: backup before an upgrade, machine-to-machine migration, sanitized snapshot for support, template-sharing with another operator.

  **Safe by default.** A bare invocation produces a config-only archive with credentials redacted. `kismet_api_key`, `ntfy_auth_token`, `ntfy_topic`, and `user:pass@` userinfo in `ntfy_url`. Paste-into-chat-safe. Redaction is line-based and preserves your comments, key ordering, and whitespace.

  **Opt-outs are explicit.** `--include-secrets` disables redaction (for personal backups you're keeping on your own host). `--include-state` adds the SQLite database (and any `.db-shm` / `.db-wal` sidecars) under `state/` in the archive. Off by default because the DB can be large and carries observed MACs. State files are never redacted; an anonymized state export is deferred.

  **Self-describing archive.** Layout is `lynceus-export-<scope>-<UTC-timestamp>/` with `README.txt` (restore guide), `manifest.json` (version, scope, timestamp, redaction policy, per-file sha256), `config/<name>.yaml`, and (when included) `state/`. Re-hashing on restore catches transport damage.

  **Other flags.** `--scope {user,system,auto}` defaults to `auto`. `--output` refuses to overwrite (unless `--force`), refuses a directory, refuses an unwritable parent. `--dry-run` prints the inventory and produces no archive. Cross-platform (pure `tarfile` + `pathlib`, no shell calls), read-only, no network, no daemon dependency. Registered in both `pyproject.toml` and `install.sh`.

- **Auto-refresh timer for the Argus watchlist (`lynceus-refresh.service` + `lynceus-refresh.timer`).** Closes the loop with the rc4 staleness indicator. The indicator detects stale data, the timer prevents it. Default cadence is `OnCalendar=weekly` with `RandomizedDelaySec=30min` (spreads load across deployments) and `Persistent=true` (catches missed runs after reboots), comfortably faster than the default 30-day `watchlist_staleness_warn_days`. The oneshot service re-runs `lynceus-import-argus --scope system --from-github` under `User=lynceus` with the same hardening posture as `lynceus.service`.

  **Default-off: operator opt-in.** `install.sh --system` copies both unit files and runs `daemon-reload` but does NOT enable the timer. Enabling it is the only Lynceus surface that opts a host into recurring outbound network calls, so it stays an explicit decision. The `install.sh` offline invariant still holds. Enable with:

  ```sh
  sudo systemctl enable --now lynceus-refresh.timer
  ```

  Want a different cadence? `sudo systemctl edit lynceus-refresh.timer` and write a drop-in. A transient GitHub outage fails the oneshot run and journals under `journalctl -u lynceus-refresh.service`; the next scheduled fire retries. No `Restart=` directive. Tight retry loops on a sustained outage burn through the GitHub API budget. `uninstall.sh` removes the unit files; `--purge` also wipes `/var/lib/lynceus/`. User-scope installs don't ship the timer.

- **`/alerts` filter bar grows `rule_type` / `q` / `window`, and `/alerts` + `/allowlist` share pagination.** Both pages now route through a single helper with the same `per_page` set (`{25, 50, 100, 200}`, default `50`), the same footer copy, and the same clamp-silently semantics for out-of-range inputs. New `/alerts` filters:

  - `rule_type=<literal>`. Narrow by the rule's `rule_type`. Invalid values fall back to "any" rather than 400.
  - `q=<substring>`. Case-insensitive substring against MAC, message, and manufacturer. Distinct from the pre-existing `search` (which matches `rule_name` + `message`); both apply alongside if both are set.
  - `window=1h|24h|7d|30d`. Relative time window resolved server-side at request time. A shared link means the same recency to any operator. Combines with absolute `since` / `until` by taking the tighter lower bound.

  Pre-rc5 query params keep byte-identical semantics. Bookmarked URLs resolve unchanged. `page_size=10` is dropped (move to `25`); other invalid values silently fall back to `50` rather than 400.

  **Schema change: `alerts.rule_type TEXT`** (migration 015). The value was carried in-memory since day one but never persisted; the new filter forced it. Historical rows pre-rc5 carry `NULL`; "any" includes them, a specific `rule_type=...` excludes them.

  Out-of-range behaviour is "clamp silently" rather than 4xx. `?page=999` lands on the last valid page, `?per_page=37` falls back to default, `?rule_type=bogus` ignores the filter. Stale bookmarks survive ruleset extensions. The `/alerts/ack-all-visible` POST mirrors the GET filter set byte-identical, so bulk-ack can never act on alerts the operator can't see.

- **`/allowlist` management surface: search, filter, add, bulk remove.** Closes the "edit `allowlist_ui.yaml` by hand" gap that's existed since the per-alert mutation routes landed. You can now do the full lifecycle from the browser.

  **Filter bar.** Four query params, all AND together, all round-trip through the URL:

  - `q=<substring>`. Case-insensitive against pattern + note.
  - `source=primary|ui|all`. Primary = your `allowlist.yaml`, UI = daemon-managed `allowlist_ui.yaml`.
  - `status=active|snoozed|expired|all`. Expired entries are no longer suppressing but stay rendered so you can bulk-clean them.
  - `type=mac|oui|ssid|mac_range|ble_uuid|ble_manufacturer_id|drone_id_prefix|all`.

  **Add-entry form.** Collapsible `<details>` above the table; expands on validation error so the rejected input survives the round-trip. Inputs pass through the same canonicalization the importer uses, so a pasted uppercase MAC or `0x004C`-shaped manufacturer id ends up in canonical form. Successful add redirects with a one-shot flash.

  **Bulk remove.** Checkboxes on UI-source rows only. The handler reads the file once, filters in memory, and emits a single atomic write covering all N selections: one mtime tick for the poller's reload watcher rather than N.

  **Primary file is hard read-only.** The daemon never writes to `allowlist.yaml`. The UI enforces this by construction: primary rows render with a `[primary]` badge and no checkbox; a hostile submission enlisting a primary key alongside legitimate UI keys fails atomically (HTTP 400, no partial removes). `POST /allowlist/add` writes only to `allowlist_ui.yaml`.

  Allowlist entries now accept all seven pattern types (the four added since `mac`/`oui`/`ssid`, `mac_range`, `ble_uuid`, `ble_manufacturer_id`, `drone_id_prefix`), so an alert keyed off any watchlist type has an allowlist counterpart.

- **`lynceus-bootstrap-kismet`: new helper that takes a fresh Debian / Ubuntu / Kali host from "no Kismet installed" to "ready for `lynceus-setup`."** Closes the "what do I do before running lynceus-setup?" gap.

  Scope is bounded by Kismet's apt-repo coverage: Debian (`bookworm`, `trixie`), Ubuntu (`focal`, `jammy`, `noble`, `plucky`), Kali. On any other distro it prints a pointer to <https://www.kismetwireless.net/packages/> and exits 0.

  What it does, in order: refuses to run if not root (exit 2), reads `/etc/os-release` for the distro gate, installs Kismet via apt if not already on PATH (with `DEBIAN_FRONTEND=noninteractive` to bypass the suid-root prompt), auto-detects Wi-Fi monitor-mode-capable interfaces and Bluetooth controllers (Y/n per interface with default Y), patches `/etc/kismet/kismet_site.conf` append-only with `source=<iface>:type=linuxwifi` or `:type=linuxbluetooth` lines (atomic write, idempotent, your `name=` / `channel_list=` customizations are preserved), adds `$SUDO_USER` to the `kismet` group, then prints next steps (log out + back in, start Kismet, set password, create the API key, run `sudo lynceus-setup`).

  **`install.sh` stays offline.** This script is the one that uses the network for apt; the threat-model invariant that `install.sh` curls no third parties is unchanged.

  **Idempotent on every step**. Re-running on a partially-set-up host skips work already done. Flags: `--skip-install` (Kismet already present), `--interface <name>` (repeatable, with `--interface-type {wifi,bt}`), `--no-network` (refuse apt, for air-gapped hosts, implies `--skip-install`), `--dry-run` (preview only), `--yes` (accept all defaults, for scripted bootstrap). Exit codes: 0 success / unsupported-distro, 1 recoverable failure, 2 tool-level failure.

  Wired into `install.sh`'s `CONSOLE_SCRIPTS` symlink layer and `pyproject.toml`; the post-install hint and the `lynceus-setup` "if Kismet isn't installed" block both point at it. End-to-end testing is manual-smoke against a fresh Debian/Ubuntu/Kali VM.

- **`lynceus-setup` auto-locates an existing Kismet API key.** The wizard reads Kismet's per-user `~/.kismet/session.db` (under `--system` also checks `$SUDO_USER`'s home and `/root/.kismet/`) and picks the best match: a key named `lynceus`, else `readonly`, else `admin`, else the first non-empty token. On hit, it shows the source path, a redacted preview (`abcd…wxyz`), and asks `Use this key? [Y/n]`. Y skips the manual copy-paste flow.

  Purely additive: every failure mode (missing file, malformed JSON, no usable entry, Windows host) silently falls through to the existing manual walkthrough. The located key is never echoed in full. Only the head/tail preview. No new dependencies, no new config fields, no network calls, read-only against Kismet's files.

- **`GET /healthz.json`: machine-readable health endpoint for monitoring integration.** Returns JSON with overall status plus per-check details (DB reachability, daemon liveness, watchlist freshness, ruleset count, alert counts). Read-only, no auth, derived from existing DB + filesystem state. No new tables, no heartbeat infrastructure, no daemon-side changes.

  HTTP semantics follow the standard monitoring convention: 200 when status is `ok`, 503 when `error`. Currently only the DB-reachable check flips the top-level status; the rest return `ok` with values your monitoring tool can threshold against.

  Response shape:

      {
        "status": "ok" | "error",
        "version": "0.4.0rc5",
        "checks": {
          "db": {"status": ..., "detail": ... | null},
          "poller": {"status": ..., "last_poll_at": ...,
                        "seconds_since_poll": ...,
                        "last_observation_at": ...,
                        "seconds_since_observation": ...},
          "watchlist": {"status": ..., "total_rows": ...,
                        "by_pattern_type": {...},
                        "last_imported_at": ...,
                        "days_since_import": ..., "stale": ...},
          "ruleset": {"status": ..., "active_rules": ...,
                        "rules_path_configured": ...},
          "alerts": {"status": ..., "total": ...,
                        "last_hour": ...}
        }
      }

  The `poller` check carries `last_poll_at` (daemon-alive proxy) and `last_observation_at` (Kismet-returning-data proxy). The `watchlist.stale` boolean uses the same `watchlist_staleness_warn_days` threshold the startup log and `/settings` card already use.

  **Shape-stability commitment:** existing keys never disappear; future releases only add keys. Pin against this shape without expecting churn. The existing HTML `/healthz` (topnav, `docs/SMOKE.md`, `lynceus-quickstart` readiness probe) is unchanged.

  Example:

      curl -sS http://127.0.0.1:8765/healthz.json | jq .

  Polling at 30s adds no measurable load. Out of scope for v1: auth, Prometheus `/metrics`, response caching, configurable thresholds.

- **`lynceus-validate` CLI: read-only configuration validator.** Catches typos, schema errors, malformed values, and missing referenced paths at edit time instead of at the next daemon restart. Wraps the existing loaders so the diagnoses match what the daemon would hit.

  Covers the five files you may maintain:

  - `lynceus.yaml`. Pydantic schema check; missing-file ERROR for each populated `*_path` reference.
  - `rules.yaml`. Surfaces ruleset loader errors (duplicate names, invalid `rule_type`, malformed patterns); empty ruleset is a WARNING.
  - `severity_overrides.yaml`. Louder at edit time than the daemon. Unknown top-level keys get a Levenshtein hint (`'supress_categories' -- did you mean 'suppress_categories'?`); unknown Argus categories WARN; `pattern_overrides` keys not matching the 16-hex `argus_record_id` shape ERROR.
  - `allowlist.yaml`. Pydantic validation; entries with `expires_at` in the past WARN.
  - `allowlist_ui.yaml`. Same shape; missing file is normal.

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

- **Alert detail page gains triage buttons: Allowlist, Snooze 24h, Remove.** Triaging a false positive no longer means editing `allowlist.yaml` and restarting: one click on `/alerts/<id>` writes a MAC-keyed entry to `allowlist_ui.yaml`, the poller picks it up on the next tick via the mtime watch, and future alerts for that device are suppressed immediately.

  Three POST routes under `/alerts/{id}`:

  - `/allowlist`. Permanent entry (no `expires_at`), note prefix `added via webui at <ISO>`.
  - `/snooze`. Entry with `expires_at = now + 86400`. The fixed 24h window is the only UI cadence; custom durations stay YAML-only.
  - `/allowlist/remove`. Idempotent removal by MAC. Returns 303 whether the entry existed or not.

  All three share the same validation: alert exists (404 otherwise), alert carries a MAC (400 otherwise, alerts without one can't be triaged this way), `allowlist_path` is configured (400 otherwise). CSRF protection is the standard `_csrf` form field + `lynceus_csrf` cookie.

  The detail page renders one of three triage states: **not allowlisted** (Allowlist + Snooze 24h buttons), **permanently allowlisted** (status line + Remove button if the match came from the UI sibling; explanatory hint pointing at `allowlist.yaml` if it came from the primary, the daemon cannot edit that file), **snoozed** ("Snoozed until <ISO> (N hours remaining)" with Cancel snooze button on UI-sibling matches). The triage section is omitted entirely when `allowlist_path` is unset or the alert has no MAC.

- **Allowlist supports temporary entries via `expires_at`, and the daemon picks up edits without a restart.** Three operator-facing changes land together:

  - `AllowlistEntry` gains optional `expires_at` (Unix epoch seconds; `None` = permanent) and `added_at`. Both default to `None` so existing `allowlist.yaml` files parse unchanged. Entries past their `expires_at` are silently skipped at poll time. The "snooze expired" path.

  - The poller stat()s the allowlist file(s) before every tick and reloads when mtime moves. Daemon restart is no longer required for allowlist edits. A deleted primary triggers a WARNING and the daemon retains its last-known-good entries rather than dropping every suppression at once (defends against mid-rename and fat-fingered-rm). Each reload emits a single INFO line: `allowlist reloaded: N operator entries + M UI entries`.

  - Storage splits into two files. `allowlist.yaml` (operator-curated primary, path from `Config.allowlist_path`) is read-only from the daemon's perspective. Your hand-formatting, comments, and key ordering are preserved indefinitely. A sibling `allowlist_ui.yaml` (path derived by inserting `_ui` before the suffix, e.g. `/etc/lynceus/allowlist.yaml` → `/etc/lynceus/allowlist_ui.yaml`) is daemon-managed: created on first write, merged into the in-memory allowlist at load. Absent is normal pre-first-write; a malformed UI file logs WARNING and is treated as empty so a corrupt sibling can't cripple suppression; a malformed primary logs ERROR and is treated as empty (pre-rc5 would have crashed the poller init).

  The existing audit INFO line at the suppression site keeps its `Allowlist suppressed watchlist hit: rule=… mac=… severity=…` prefix verbatim, `journalctl` greps are unaffected, and appends ` (expires <ISO>)` only when the matched entry has an `expires_at`.

- **`ble_manufacturer_id` and `drone_id_prefix` rows from Argus now land in the watchlist.** Pre-rc5, every row of these two types hit the importer's identifier-type gate and dropped to `dropped_unknown_type` without reaching the DB. Against the live `argus_export.csv` snapshot at `exported_at=2026-05-14T22:34:07Z`:

  - `ble_manufacturer_id`: 3,969 rows (Bluetooth SIG 16-bit Company Identifiers, e.g. `0x004C` for Apple).
  - `drone_id_prefix`: 427 rows (ANSI/CTA-2063-A Remote-ID serial prefixes, e.g. `21239ESA2`).

  `dropped_unknown_type` for that snapshot moves from 4,635 → 239, exactly the sum of the two new types.

  Migration 013 rebuilds the `watchlist` table to relax the `pattern_type` CHECK (mirroring migration 011's mac_range pattern; SQLite cannot modify a CHECK via `ALTER TABLE`). No new metadata columns: both new types are equality-shaped at the string level. Canonical forms: `ble_manufacturer_id` lowercases and strips the `0x` prefix (`'0x004C'` → `'004c'`) so the runtime equality against Kismet's bare-hex emission is direct; `drone_id_prefix` preserves case (`'21239ESA2'` → `'21239ESA2'`) because ANSI/CTA-2063-A serials are case-sensitive per the standard.

- **`watchlist_ble_manufacturer_id` and `watchlist_drone_id_prefix` rule types.** Same empty-patterns-delegates-to-DB shape established by `watchlist_mac` / `watchlist_oui` / `watchlist_ssid` / `ble_uuid` in rc4: a single empty-patterns rule of the new type enables alert-firing for every matching watchlist row of that type; severity comes from the matched DB row; the runtime override layer (`suppress_vendors`, `suppress_categories`, `pattern_overrides`, `device_category_severity`) applies transparently. Non-empty patterns also accepted and normalized at load time (so `0x004C` in `rules.yaml` matches the bare-hex `004c` on the observation). The setup wizard grows two per-type prompts, each gated by a row-count check so operators with an empty pattern_type don't see them. Re-run `lynceus-setup --reconfigure` to add the new types to an existing install.

  **CAVEAT: runtime alerting needs Kismet probe-path verification.** The Kismet device parser gained two new optional observation fields (`ble_manufacturer_id`, `drone_id_prefix`) populated via best-effort extractors that walk a small table of likely Kismet field paths. These paths come from public Kismet schema docs, NOT a live capture. The codebase had no prior consumer of either surface. Until the paths are confirmed and corrected against a real Kismet emission, both fields read `None` on real hardware and the delegation rules fire zero alerts. The import + DB + rules-engine + wizard pipeline is load-bearing in the meantime: rows land in the watchlist DB, appear in the `/watchlist` UI, and show on the `/settings` count card; only the alert-time match against a live observation is gated on probe-path verification. Promoting a confirmed path to the front of the probe table is a one-line edit.

  **Drone Remote-ID structural gates closed.** The initial rc5 cut shipped with two gates that blocked Remote-ID observations independent of probe-path uncertainty: the Kismet type map admitted only Wi-Fi / BTLE / Bluetooth, and the `devices.device_type` CHECK constraint from migration 001 would have rejected the Remote-ID category. Both are now closed: migration 014 rebuilds `devices` to add `'remote_id'` to the CHECK; the type map maps `'Remote ID'` and `'Remote ID Drone'` to the new category; the drone-ID probe table is re-anchored on the canonical `kismet.device.base.*` paths (`kismet.device.base.remote_id.serial_number` / `.uas_id`) with the older `remoteid.device.basic_id.*` paths retained as fallbacks; the `/devices?device_type=...` query handler admits the new value (the dropdown still lists three types, pass the query param directly for a Remote-ID-only view, dropdown polish tracked separately).

- **Annotation walk now covers all 7 pattern_types.** Alerts fired by the two new delegation rule types were landing with `matched_watchlist_id=NULL` because the rc4 annotation walk only knew the original five types. `rule_name` and severity were right, but the alert → watchlist-row click-through, ntfy enrichment, and audit trail all keyed off `matched_watchlist_id` and went cold. The walk now covers all seven in tiebreaker order: `mac > oui > ble_manufacturer_id > mac_range > drone_id_prefix > ssid > ble_uuid`. The poller passes the new observation fields through to the annotation call. No DB schema change.

  **Operator UX note for BT- and Remote-ID-capable deployments.** Operators running Kismet with the BT scanner enabled gain 3,969 BLE manufacturer signatures on re-import; Remote-ID-enabled deployments gain 427 drone serial-prefix signatures. Both fire alerts as soon as the Kismet probe-path verification lands.

### Documentation

- **Argus residuals audit.** New `docs/ARGUS_RESIDUALS.md` characterizes the ~239 Argus rows still dropped as `unknown_type`, plus a re-runnable diagnostic at `scripts/audit_residuals.py` that regenerates the report against any Argus snapshot. Each of the 31 distinct residual types is classified by Kismet observation surface (`verified-lynceus`, `verified-kismet-docs`, `plausible-needs-smoke`, `no-observation-surface`, `normalization-variant`) with a mechanical per-type recommendation. Surfaces two normalization gaps (`ble_company_id`, `ble_service_uuid`) that overlap admitted pattern_types and would be fixed in the importer's normalization layer rather than via new Kismet surfaces. The script lives in `scripts/` and is deliberately not a `[project.scripts]` entry. Operator surface stays unchanged.

- **Doc-rot sweep.** `SECURITY.md` version refreshed from `0.3.0-rc1` to `0.4.0-rc5`. `PROJECT_STATUS.md` reworded for 0.4 reality. `SMOKE.md` header drops its stale `(v0.2)` pin. `WINDOWS_DEV.md` drops the "live reload is on the v0.3 backlog" promise and points `git clone` at `lynceus-warden`. `docs/CONFIGURATION.md` webui-routes tables grow `/watchlist`, `/settings`, `/healthz.json`, the rc5 `/alerts` filter additions, the `/allowlist` management routes (`/allowlist/add`, `/allowlist/bulk_remove`), and the per-alert allowlist + snooze mutations. Confirmed rot only. No stylistic rewrites.

### Changed

- **`lynceus-setup` Kismet + ntfy sections ship with inline context for first-time operators.** Pre-rc5, the wizard asked `Kismet API token (input hidden):` with no preceding explanation. A fresh operator had to go elsewhere to figure out where API keys live, what role to pick, and what the ntfy topic was for. Each section now opens with a `═══`-underlined header, a short explanation of what the value is and why Lynceus needs it, and (for the Kismet API key) a step-by-step walkthrough of where to generate one in the Kismet web UI. The ntfy section calls out the topic-as-shared-secret property up front so you pick something unguessable rather than reading the warning after the fact in the generated `lynceus.yaml`.

  No prompts were added, removed, or reordered. Defaults are unchanged. Existing operators tab through at the same pace. Plain ASCII + box-drawing only (no emoji, no ANSI), so it still looks right tee'd into an install log.

- **`vendor_severity`: runtime vendor-level severity remap on `severity_overrides.yaml`.** Closes the runtime override matrix at vendor × remap. "All devices from this vendor should be `high`" is now a single line instead of N entries under `pattern_overrides` or a manual sweep across `device_category_severity`. The matrix closes to **remap × {category, vendor, row} + suppress × {category, vendor}**.

  **Schema.** `vendor_severity: dict[str, severity]`. Keys are manufacturer strings (matched against `watchlist_metadata.vendor`); values are `"low"` / `"med"` / `"high"`. Keys normalized at load time (lowercase + strip) and matched case-insensitive exact. `"  Axon Enterprise, Inc. "`, `"axon enterprise, inc."`, and `"AXON ENTERPRISE, INC."` all match the same row. Substring / regex deliberately not supported (`"Apple"` would otherwise match `"Pineapple Computing"`).

  **Precedence (most-specific wins):**

  1. `suppress_vendors`. Vendor suppress.
  2. `suppress_categories`. Category suppress.
  3. `pattern_overrides`. Row-level remap.
  4. `vendor_severity` (new). Vendor-level remap.
  5. `device_category_severity`. Category-level remap.

  Suppression at either layer always wins over any remap. Per-row UNSUPPRESS is explicitly not a feature. NULL manufacturer falls through to the category remap.

  **Why not extend `vendor_overrides` at runtime.** `vendor_overrides`' `"drop"` sentinel means skip-at-import; a runtime interpretation would silently overload the meaning and produce a footgun. `vendor_overrides` stays import-time-only by design.

  **Tolerant parsing.** Non-string keys, empty-after-strip keys, and invalid severity values each drop with a WARNING; the rest of the dict parses normally. One malformed entry never disables the whole layer.

  The wizard's `severity_overrides.yaml` starter template gains a `vendor_severity:` block adjacent to `vendor_overrides` with a `# LAYER: RUNTIME` tag and a worked example targeting surveillance-camera vendors. The `/settings` runtime-keys card lists it alongside the four existing runtime keys. In-memory pattern rules (rules with non-empty `patterns`) are unaffected. Runtime overrides apply only to DB-delegation matches. No DB schema change.

### Fixed

- **Poller now logs a grep-able INFO line on every ruleset load.** Pre-rc5 the loader was called silently at init, leaving no startup signal that `rules.yaml` had actually been read. Symmetric with the watchlist-staleness and runtime-severity-overrides lines:

      loaded ruleset from <path>: N active rules
      loaded ruleset from <path>: N active rules (M disabled)
      no rules_path configured; ruleset is empty. No alerts will fire

  The empty-state line catches the failure mode where the wizard wrote `rules.yaml` but `rules_path` was never wired in `lynceus.yaml`. Pre-fix the daemon ran with no alerting and no log line explaining why.

- **`/settings` watchlist-freshness card now lists all 7 pattern_types.** rc5 landed `ble_manufacturer_id` and `drone_id_prefix` in the DB and importer, but the Jinja template on the freshness card was never extended past the five rc4 types. Operators saw the new rows in `lynceus-import-argus` stdout and could `SELECT` them out of SQLite, but the card silently rendered zero for both. The backing helper was already returning all 7 keys; only the template was stale. Caught pre-smoke during runbook verification.

## [0.4.0-rc4] - 2026-05-15

### Added

- **Argus `mac_range` rows now land in the watchlist.** Pre-rc4, every `mac_range` row from Argus hit the importer's identifier-type gate and was silently dropped. About 17,798 of 22,532 rows in the current Argus export, none of which could contribute to detections. Migration 011 relaxes the watchlist `pattern_type` check to admit `mac_range`, adds nibble-precision prefix columns, and a partial index over them. The importer accepts both canonical CIDR shapes (`aa:bb:cc:d/28`, `aa:bb:cc:dd:e/36`) and legacy bare-prefix rows (canonicalized on disk with one INFO log line per row so you can watch the legacy count drop to zero). Unrecognized shapes go to the existing `normalization_failed` counter rather than being silently accepted.

  This rc lands the schema + import path only. `mac_range` rows appear in the watchlist UI but the poller cannot yet match a sighted MAC against them. Runtime matching arrives in the next bullet.

- **`watchlist_mac_range` rule type: first DB-delegated rule in Lynceus.** Closes the runtime-matching gap above. A single empty-patterns `watchlist_mac_range` entry in `rules.yaml` enables alert-firing for every matching `mac_range` row in the watchlist DB. No need to duplicate patterns across the DB and `rules.yaml`. `/36` matches sort ahead of `/28` (more specific wins); `/watchlist` detail renders the prefix length plus a block-class annotation (MA-M `/28` = 1,048,576 addresses; MA-S/IAB `/36` = 4,096).

  **Severity comes from the matched DB row, NOT `rule.severity`.** The importer wrote per-row severity from `device_category` at import time; reading it back at alert time is the only path that respects that data. The bundled `config/rules.yaml` template calls this out where the example sits.

  **Alert volume after enabling.** Shipped commented-out; default is OFF. Uncommenting enables alert-firing for any MAC inside any of the 17,786 IEEE-registry rows imported by `lynceus-import-argus`. All of those rows carry `device_category = 'unknown'`, which maps to `low`, so enabling fires `low` alerts at whatever rate observed MACs fall inside the IEEE allocations Argus catalogued (predominantly enterprise / embedded / medical / industrial vendors). If `low` is the wrong tier for this volume, tune via `severity_overrides.yaml` (see runtime layer below) or use the allowlist to scope by geography.

- **DB delegation extended to `watchlist_mac`, `watchlist_oui`, `watchlist_ssid`, and `ble_uuid`.** Before this change, only `watchlist_mac_range` fired via DB delegation; the 63 bundled `default_watchlist.csv` rows plus every Argus-imported mac/oui/ssid/ble_uuid row stayed inert unless you manually copied their patterns into `rules.yaml`. Now a single empty-patterns rule per type fires alerts for every matching DB row of that type. Same idiom as `watchlist_mac_range`. Rules with non-empty patterns see byte-identical behaviour.

  All four ship commented-out in `config/rules.yaml`; default OFF. The matched row's severity flows into the alert (rule severity is ignored for empty-patterns delegation). Per-row severity is populated by `lynceus-import-argus` from `device_category`:

  - `imsi_catcher`, `alpr`, `hacking_tool` → `high`
  - `body_cam`, `drone`, `gunshot_detect`, `in_vehicle_router` → `med`
  - `unknown` and anything unlisted → `low`

  Before enabling a delegation entry, run `lynceus-list-watchlist --pattern-type mac` (and the other three types) to see the severity distribution in your DB. If a category's default is wrong for your environment, tune via `--override-file severity_overrides.yaml` at import time, or via the runtime layer below.

- **Runtime severity layer: `severity_overrides.yaml` now applies at alert time, not just at import time.** Pre-rc4, the wizard scaffolded the file and `lynceus-import-argus --override-file` consumed it, but the daemon never read it. Retuning severities meant re-importing the full ~22,500-row Argus corpus. Now the poller reads the file at startup and transforms DB-delegation matches at alert construction.

  Two keys take effect at runtime:

  - **`device_category_severity`** (existing key, now both layers). Import bakes per-category remap into `watchlist.severity` at write time (unchanged); runtime re-applies the same map at alert time. Set `unknown: med` in the file, restart the daemon, and the 17,786 IEEE-registry `mac_range` rows fire at `med` on the next poll. No re-import.
  - **`suppress_categories`** (new, runtime only). A delegation match whose `device_category` is in the list emits no alert (no row in `alerts`, no ntfy push). The watchlist row stays; only alert emission is silenced. An INFO log line per suppression names the rule, category, and watchlist row for forensics.

  Opt-in: set `severity_overrides_path` in `lynceus.yaml` to your file. Unset means runtime layer disabled; malformed YAML logs a WARNING and falls back to pass-through (the poller never crashes on this file). In-memory pattern rules (non-empty `patterns`) are unaffected. Runtime overrides apply only to DB-delegation matches. The import-time consumer is byte-identical pre/post.

  The wizard's starter file gains inline `# LAYER:` tags on each section (`IMPORT-TIME` / `RUNTIME` / `BOTH`) so you can see at a glance whether a change needs a re-import or just a daemon restart. The `/settings` severity-overrides card mirrors the same wording.

- **`lynceus-setup` enable-alerting flow: wizard now wires up alerts end-to-end.** Pre-rc4, running the wizard left you with a configured daemon and imported watchlist but no alerts: you had to copy `config/rules.yaml`, uncomment the right delegation entries by hand, and add `rules_path` to `lynceus.yaml`. The wizard now drives all three.

  Between bundled-watchlist import and "Setup complete", a single gate fires: `Enable Argus-backed alerting? [y/N]`. Default is NO. An operator who hits Enter completes the wizard in the exact pre-rc4 state (no alerts). Saying yes prompts per-rule-type with the current DB row count (`Enable watchlist_mac_range (17,786 MAC ranges)? [y/N]`); types with zero rows are skipped silently. Selected entries land as active in a fresh `rules.yaml` at the scope-appropriate path (`/etc/lynceus/rules.yaml` under `--system`, `~/.config/lynceus/rules.yaml` under `--user`); the rest ship as commented templates. `rules_path` then gets appended to the already-written `lynceus.yaml`.

  Re-runs treat hand-edits as sacred: if `rules.yaml` already exists, a separate `Overwrite? [y/N]` prompt fires (default NO). Declining leaves the file untouched but still wires `rules_path` when previously unset. Recovers the "I copied the file but never wired it up" case. All defaults are NO, matching Lynceus's privacy-conservative posture: a wizard run with all defaults gets a Lynceus that observes but does not alert. `new_non_randomized_device` and any custom pattern-bearing rules still require manual edits.

- **`suppress_vendors`: runtime manufacturer-level alert suppression.** Sits adjacent to `suppress_categories` on the same runtime layer: a delegation alert whose matched watchlist row carries a manufacturer in the list emits no alert. The watchlist row stays in the DB; only alert emission is silenced. Edit the file, restart the daemon, no re-import.

  Comparison is case-insensitive exact match. Entries are normalized (lowercase + strip) at load and at eval. So `"  Mitsubishi Electric US, Inc. "`, `"mitsubishi electric us, inc."`, and `"MITSUBISHI ELECTRIC US, INC."` all match. Substring / regex was rejected: `"Apple"` would otherwise match `"Pineapple Computing"`. Configure with the canonical vendor string from the watchlist row. The same value Argus emits in its `manufacturer` column.

  Precedence: `suppress_vendors` checks first (most specific), then `suppress_categories`, then `device_category_severity`. Vendor wins because manufacturer is the more specific axis. NULL manufacturer rows skip the check entirely and fall through. `vendor_overrides` is unchanged. Its import-time `"drop"` sentinel keeps its skip-at-import semantic; `suppress_vendors` is strictly additive at runtime.

- **`pattern_overrides`: runtime row-level severity remap by `argus_record_id`.** Closes the runtime severity-tuning matrix at the row axis. Use case: "the specific Flock camera at my workplace → high; everything else in `alpr` → low." Without this knob you could only set `alpr → low` (and lose the workplace signal) or `alpr → high` (and over-alert on every camera).

  Schema: `pattern_overrides: dict[str, severity]`. Keys are the 16-hex `argus_record_id` Argus emits (case-normalized at load time so copy-paste case doesn't matter); values are `low` / `med` / `high`. Precedence sits between suppression and category remap: `suppress_vendors` → `suppress_categories` → `pattern_overrides` → `device_category_severity`. Suppression at either layer always wins over a row-level remap. Per-row UNSUPPRESS is explicitly not a feature; use the allowlist for per-row alert suppression instead.

  Argus-imported rows only. The 63 bundled `default_watchlist.csv` rows and any rows added via `lynceus-seed-watchlist` without metadata have no stable identifier and skip the check. For non-Argus row-level tuning, use `device_category_severity` (category granularity) or the allowlist (per-row suppression). Load-time validation is per-entry tolerant: bad keys or values get a WARNING and drop, the rest of the dict parses. The wizard's starter template gains a `pattern_overrides:` block with an inline SQL query you can paste to find an `argus_record_id` for a row of interest.

- **Watchlist staleness indicator: startup WARNING + `/settings` freshness card.** Pre-rc4 the daemon ran silently against whatever was last imported; boot a system that had been off for two months and you had no way to tell threat data was 60+ days behind. The settings page's "last imported" field made it worse by surfacing a per-row local-clock proxy that flipped to "now" on every re-import of a stale CSV.

  Migration 012 adds an `import_runs` table that persists one row per successful `lynceus-import-argus`: local-clock `imported_at`, Argus-side `exported_at` parsed from the CSV's `# meta:` line, the canonical Argus-side `record_count`, and a free-form `source` (absolute path for `--input`, `owner/repo@ref` for `--from-github`). The poller reads the most-recent row at startup; the `/settings` freshness card reads it on every render. Both surfaces agree by construction.

  Startup log shapes:

  - Within threshold: `INFO watchlist: N rows total, most recent Argus import D days ago (exported YYYY-MM-DD)`.
  - Over threshold: `WARNING watchlist: N rows total, most recent Argus import D days ago (exported YYYY-MM-DD); consider 'lynceus-import-argus --from-github' to refresh`.
  - No imports recorded (fresh install): `INFO watchlist: N rows total, no Argus import metadata recorded`. Deliberately INFO, not WARNING. A fresh install where you haven't run the importer yet is the expected state right after `lynceus-setup`.

  New `watchlist_staleness_warn_days: int = 30` config field (matches Argus's nominal release cadence; tune via `lynceus.yaml` for slower cadences). Validated `>= 1`. The `/settings` 'Watchlist freshness' card renders status badge, Argus exported date, locally imported date, age in days, source string, record count, and a pattern-type breakdown. Refresh hint shows the exact command, only in the stale branch. Read-only. No "Force refresh" button. The misleading `last_imported_ts = MAX(updated_at)` field on the existing watchlist data card is removed. Imports from before migration 012 don't appear on the card; the next refresh starts the signal cleanly.

### Fixed

- **Runtime severity-overrides loader now logs INFO at every load outcome, not just on missing-file.** The Kali live-validation runbook promised "an INFO line confirming the runtime severity-overrides file was loaded" but the initial implementation logged INFO only on the missing-file path; successful-load and disabled-via-None returned silently. Three new INFO lines now cover the three non-failure outcomes. Active-keys (names the path and the count of active remaps and suppressions), empty-keys (parses cleanly but no runtime keys uncommented; layer is effectively pass-through), and `severity_overrides_path` unset (names the field and points at the canonical paths under `--system` and `--user`). All three are greppable via the literal `runtime severity overrides`. The four failure modes (missing file, unreadable file, malformed YAML, validation error) still log at WARNING and are unchanged.

- **`lynceus-import-argus --from-github` default `--repo` was pointing at a non-existent repository.** rc3 hard-coded `kevlattice/argus` as the default; the actual Argus repo is `kevwillow/argus-db`. The headline rc3 feature 404'd on the `/releases/latest` API call and operators saw an opaque `HTTPError` instead of a successful refresh. Passing `--repo OWNER/NAME` for a fork still works the same way.

- **`lynceus-import-argus --from-github` no longer crashes when the Argus repo has no published GitHub Releases.** rc4 still required `/repos/{repo}/releases/latest` to return a tag, but `kevwillow/argus-db` ships its CSV on every commit and does not cut formal Releases. The API returned 404, `raise_for_status()` raised `HTTPError`, and `--from-github` was unusable. The resolver now treats a 404 on `/releases/latest` as "no published releases" and falls back to the `main` branch with a WARNING (`No published releases for {repo}; falling back to 'main'. Pin a tag with --ref for reproducibility.`). Other non-200 statuses (500, 403) still propagate. A transient GitHub outage must not silently degrade to importing whatever `main` happens to be.

- **`lynceus-import-argus --override-file` is now scope-strict.** Pre-fix, the argparse default was hard-coded to `/etc/lynceus/severity_overrides.yaml` regardless of `--scope`. On a host with a system install (`/etc/lynceus` is `0750 root:lynceus`), an unprivileged user running the importer with `--scope user` hit the system path via the default and crashed with `PermissionError`. The flag now defaults to `None`; resolution is scope-aware. User-scope only probes the user-scope path, system-scope only the system path, no cross-scope fallback. Explicit `--override-file <path>` is used verbatim. `PermissionError` on the probe is now converted into an actionable message that names the offending path.

- **`lynceus-setup` refuses sudo-without-`--system` to prevent silent scope misplacement.** Reproduced in the rc4 live smoke: `sudo lynceus-setup --reconfigure` (no `--system`) silently regenerated `/root/.config/lynceus/lynceus.yaml` while the system daemon kept reading `/etc/lynceus/lynceus.yaml`. Operator believed they'd reconfigured the daemon, but it was still running the stale config. The wizard now refuses early when `euid=0` and `--system` is not passed, prints both correct invocations side-by-side, and exits 2. Three legitimate combinations are unchanged: root + `--system`, non-root alone, non-root + `--system` (still hits the existing "use sudo" preflight). Windows is a no-op. After upgrading, operators who hit this in rc4 should re-run `sudo lynceus-setup --system --reconfigure` to bring `/etc/lynceus/lynceus.yaml` back into sync.

### Changed

- **All `kevlattice/lynceus` GitHub URLs replaced with `kevwillow/lynceus-warden`** to reflect the upstream account + repo rename. Touches `pyproject.toml` (Homepage / Repository / Issues, which flow into PyPI metadata), `SECURITY.md`, the `git clone` URL in the README, and the `Documentation=` line in both systemd unit files (visible in `systemctl status` and journalctl context). The GitHub-side redirect from `kevwillow/lynceus.git` to `kevwillow/lynceus-warden.git` is still active, so older clones continue to push and pull, but new clones should use the canonical URL.

## [0.4.0-rc3] - 2026-05-15

> **⚠️ Broken release: superseded by [0.4.0-rc4](#040-rc4---2026-05-15). Do not install.**
>
> The headline `lynceus-import-argus --from-github` feature shipped
> with a non-existent default `--repo` (`kevlattice/argus`); the API
> release lookup 404s before the fetch can start, and operators see
> an opaque `HTTPError` instead of a successful refresh. Fixed in
> rc4 (`kevwillow/argus-db`). The `v0.4.0-rc3` tag has been deleted
> from the GitHub remote to prevent accidental installs from the
> tag; the commit history remains for reference.

### Added

- **`lynceus-import-argus --from-github` for one-command watchlist refresh.** Fetches `exports/argus_export.csv` from [`kevwillow/argus-db`](https://github.com/kevwillow/argus-db) over HTTPS and runs the existing idempotent import. Replacing the old three-step scp + find-the-db + import flow. Defaults to the latest tagged release (not `main`) so one bad upstream push can't poison every operator. `--ref` overrides (tag, branch, or commit; `--ref main` allowed for bleeding-edge), and `--repo OWNER/NAME` swaps the source for forks. Fetched CSVs land in `<data-dir>/argus-cache/<ref>__argus_export.csv` for a forensic trail. No GitHub token required. TLS verify on, 15s/30s timeouts. `install.sh` stays OFFLINE; only this one CLI talks to the network. `--input` remains for air-gapped operators. The two flags are mutually exclusive, exactly one required.

- **`lynceus-import-argus --db` now defaults to the canonical scope path.** Previously `--db` was required, so every invocation hand-rolled `/var/lib/lynceus/lynceus.db` or `~/.local/share/lynceus/lynceus.db`. Now the same XDG-aware resolver the setup wizard and daemon use picks the right path when `--db` is omitted. New `--scope user|system` selects the default scope (defaults to `user`); pass `--db` explicitly to override. Existing scripts passing `--db` are unaffected.

- **Scope-aware uninstall in `install.sh --uninstall`.** Now accepts both `--user` and `--system`, closing the gap where only system installs had a clean reversal path. Flag order is now free: `--uninstall --user` and `--user --uninstall` both work. `--purge` now errors unless `--uninstall` is also passed. `--user --purge` deletes `~/.config/lynceus`, `~/.local/share/lynceus`, and `~/.local/state/lynceus` (the latter two hold `lynceus.db` and logs). Without `--purge`, only the venv at `~/.local/share/lynceus/.venv` is removed. Your database survives. If no `--user` install artifact is found, the script prints where it looked and suggests `sudo install.sh --uninstall --system` in case you picked the wrong scope, then exits 0 rather than running no-op `rm`s.

- **Top-level `uninstall.sh` wrapper.** Operators look for an `uninstall.sh` next to `install.sh`; we now ship one. Thin shell wrapper. Auto-detects scope by venv marker (`~/.local/share/lynceus/.venv` for `--user`, `/opt/lynceus/.venv` for `--system`), refuses to guess if both exist (lists them, asks you to be explicit), prints where it looked if neither is present, and otherwise execs `install.sh --uninstall --user|--system` with `--purge` and `--dry-run` passed through. Like `install.sh`, it is OFFLINE. No network access of any kind.

## [0.4.0-rc2] - 2026-05-15

### Security

- **Allowlist suppression of watchlist hits is now audit-logged.** Previously the allowlist-then-evaluate ordering meant an allowlist entry could silently disable any watchlist rule whose pattern overlapped. Anyone with write access to the allowlist file got an undocumented watchlist kill-switch with zero log signal. The poll loop now re-evaluates rules on the allowlisted-suppression path and emits an INFO line per suppressed hit: `Allowlist suppressed watchlist hit: rule=<name> mac=<mac> severity=<sev>`. Grep `journalctl` to review whether your allowlist is too permissive. `new_non_randomized_device` hits are intentionally excluded. The whole point of allowlisting is to silence those, and logging would mean one INFO line per allowlisted device per poll cycle.

- **ntfy topic no longer leaks in notifier logs, wizard summary, or probe-failure output.** The topic is a shared-secret URL path component on public ntfy brokers. Anyone who knows it can both subscribe and publish forged alerts. The web UI already redacted it; three other surfaces did not:

  - The notifier logged the full POST URL on every network failure plus the `requests` exception string (which itself embeds the URL). Leaking the topic twice per failure into `journalctl`.
  - `lynceus-setup` wizard printed the raw topic to stdout at the end of a run, lingering in scrollback and any tee'd install log.
  - The wizard's ntfy probe printed `str(exc)` verbatim on failure. Same exception-embeds-URL leak.

  All three now redact the topic to `prefix•••suffix` form. The notifier and wizard probe log only the exception type name plus the topic-redacted URL on failure; full exception detail is reserved for DEBUG operation.

### Added

- **Dark mode for the web UI.** Auto-follows the OS via `prefers-color-scheme: dark`, with a `theme: auto / light / dark` toggle in the topnav. Cycles auto → light → dark → auto and persists to `localStorage` (`lynceus-theme` key) across reloads. Pico CSS handles standard elements; `lynceus.css` adds matching dark variants for severity / confidence / status badges, topnav border, sparkline bar fill, severity-tinted alert rows, and the table-scroll fade gradient. Light-mode rendering is byte-identical to pre-change. Operators who keep their OS in light and never touch the toggle see no visual change. A small synchronous `<head>` bootstrap reads the stored choice before the stylesheet loads, so there is no flash of `prefers-color-scheme` on a forced theme.

- **`lynceus-import-argus --min-confidence N` row-skip flag.** Hard-skips rows where `confidence < N` before any DB write; skipped rows land in a new `dropped_low_confidence` counter shown in both per-bucket and trailing-summary report lines, plus a per-row INFO log so the count is debuggable. Distinct from the YAML-configured `confidence_downgrade_threshold` (which downgrades severity tier, `high` → `med` → `low`, but still imports the row): `--min-confidence` is a hard pre-DB filter, the threshold is a severity nudge. Both can be active simultaneously. Intended workflow: `--min-confidence=80 --dry-run` against an incoming push to confirm the high-conf subset lands cleanly, then re-run without the flag for the full export. Default unset (no filtering), so existing scripts are unaffected.

- **`evidence_snapshots.do_not_publish` column** (migration 009). Forward-compat for v0.5.0 public-feed export. No producers or consumers in v0.4.0. Defaults to 0. Adding the column now while the table is small avoids a destructive migration when v0.5.0 ships.

### Documentation

- **`SECURITY.md` gains a "Data at rest" section.** Documents that `lynceus.db` is unencrypted, that `evidence_snapshots` carries the most sensitive data Lynceus has shipped (probe SSIDs gated by `capture.probe_ssids`, operator GPS gated by `evidence_store_gps`), and that the WAL sidecar retains rows after a logical `DELETE`. Includes the `PRAGMA wal_checkpoint(TRUNCATE)` recipe for operators who need to flush WAL before a backup or hand-off.

- **`CONFIGURATION.md` field-reference table now lists the v0.4.0 evidence knobs** (`evidence_capture_enabled`, `evidence_retention_days`, `evidence_store_gps`).

### Performance

- **`captured_at` index for the evidence retention prune** (migration 008). The daily `DELETE FROM evidence_snapshots WHERE captured_at < ?` no longer falls back to a full table scan. The pre-existing `(mac, captured_at DESC)` index leads with `mac` and is not usable for an unconstrained range scan; this becomes a real cost on Pi-class hardware after weeks of operation on a busy site.

### Changed

- **`lynceus-import-argus` now emits a per-row INFO log line on every `identifier_type` drop.** Pre-change, `mac_range` rows and rows carrying an unknown `identifier_type` were silently swallowed into the `dropped_mac_range` / `dropped_unknown_type` counters. Visible in the final report but with no row-level trail. The new lines carry `argus_record_id`, the raw identifier_type value, and a stable reason token (`mac_range_unsupported` / `unknown_identifier_type`), so the forensic question is answered by `journalctl | grep "argus import: skipping"`. INFO not WARNING because these are expected drops per the Argus contract, not anomalies. They must surface for debuggability but must not upgrade the ntfy threshold or screen-flood on large imports.

### Fixed

- **Importer now tolerates four timestamp shapes in the Argus CSV's `first_seen` / `last_verified` columns.** Pre-fix, the parser only accepted the space-separated `"%Y-%m-%d %H:%M:%S"` shape, but Argus codified its canonical emission as ISO-8601 UTC with `Z` suffix (e.g. `"2026-05-14T06:13:42Z"`), and older write-paths had emitted at least four distinct shapes. The strict parser rejected every Z-form value and silently dropped the matching watchlist rows. Smoke against the live 22,532-row export showed **50 imported / 53 errors** pre-fix; post-fix the same dry-run reports **103 imported / 0 errors**. The parser now accepts: canonical Z form, ISO with explicit UTC offset, space-separated treated as UTC (backward compat with archived exports), and date-only midnight UTC. Non-zero offsets are coerced to UTC. Unparseable shapes still raise so a future fifth shape surfaces immediately rather than landing silently.

- **Migration 007 (`evidence_snapshots`) now uses `IF NOT EXISTS` guards on its CREATE statements.** Re-running on a DB where 007's objects exist but the `schema_migrations` row was never written (interrupted runner, crash mid-script) is now a no-op rather than raising `sqlite3.OperationalError: table evidence_snapshots already exists`. Narrow partial-apply hardening. The broader migration-runner atomicity work stays deferred to v0.4.1. A follow-up sweep will apply the same guards to the other migrations.

- **Watchlist patterns are now normalized at write time.** Pre-fix, `lynceus-seed-watchlist` and `lynceus-import-argus` inserted operator-supplied patterns verbatim. The poller normalizes its observation MAC to lowercase colon-separated form before lookup, so a watchlist row stored as `"AA:BB:CC:DD:EE:FF"` silently never linked to the alert that fired for `"aa:bb:cc:dd:ee:ff"`. The alert was still written, but `matched_watchlist_id` landed `NULL`, dropping the entire Argus metadata enrichment (vendor, confidence, source URL, severity hint) from the alert detail page. Both the YAML seeder and the Argus CSV importer now canonicalize before insert: lowercase, colon-separated MACs, lowercase BLE UUIDs (hyphens preserved), case-sensitive SSIDs pass through. Migration 010 normalizes pre-existing rows in place; idempotent. `lynceus-import-argus` adds a `normalization_failed` counter to its report; `lynceus-seed-watchlist` emits a WARNING per rejection plus a rolled-up summary.

- **`lynceus-import-argus` now case-normalizes `identifier_type` before the allowlist check.** Pre-fix, a row from Argus with `identifier_type="BLE_SERVICE"` (uppercase) missed the lowercase keys in the importer's type map and silently dropped into `dropped_unknown_type` with no per-row log line. The importer now lowercases and strips whitespace before lookup, so high-confidence `ble_service` rows that happen to ship as `BLE_SERVICE` are no longer lost without warning.

- **Freshly-created user-mode databases are now `chmod 0600` on POSIX.** Previously the file landed at the process umask (typically `0644`, world-readable on multi-user boxes). System-mode installs already get `0640 root:lynceus` from setup; this fix only affects user-mode where evidence rows could otherwise be readable by any local account. Existing databases keep operator-set modes; the chmod runs only on first creation. No-op on Windows.

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
  - Capture is wrapped in a broad try/except, a malformed Kismet record must never derail the alert path, and failures log at WARNING, not ERROR.
  - Daily housekeeping runs at most once per 24h from the poll loop.
  - Alert detail page `/alerts/{id}` surfaces evidence: the captured Kismet record in a collapsed `<details>` block, an inline SVG sparkline of the 60-sample RSSI history (no external chart library, Lynceus stays offline-capable), and an OpenStreetMap link for the captured GPS fix when present (not Google Maps, privacy posture matters here). Older alerts that predate v0.4.0, or alerts where capture was disabled, render a "No evidence captured" placeholder.
  - CLI export commands intentionally deferred to a follow-up.

## [0.3.0-rc2] - 2026-05-08

### Fixed

- **Setup wizard no longer crashes on a fresh box during the bundled-watchlist import.** On a clean install the data directory (`~/.local/share/lynceus`, `/var/lib/lynceus`) didn't exist yet, and sqlite refused to open the DB with "unable to open database file". The wizard now creates the data and log directories before invoking `lynceus-import-argus`.

### Added

- **Bluetooth source selection in `lynceus-setup`.** On Linux the wizard enumerates `hci*` adapters and, when one is present, offers to append it to `kismet_sources` so Tier 1 BLE enrichment has a source to draw on. macOS and Windows print a one-line note saying BT enumeration isn't implemented. Configure Kismet's BT source manually.
- **ntfy is now skippable in the wizard.** Pressing Enter at the broker URL prompt skips ntfy entirely. `ntfy_url` and `ntfy_topic` are written empty, the publish probe is suppressed, and the daemon's null-notifier fallback handles it. If you do set a URL, an empty topic re-prompts (topic is required when URL is set).

### Changed

- **Severity-overrides prompt explains itself and rejects obvious non-paths.** The prompt now prints what `severity_overrides.yaml` is for before asking for a path, and inputs like `na`, `skip`, or `none` are rejected with "That doesn't look like a file path" instead of silently landing in the wrong place.
- **Retired the optional "additional Argus CSV" prompt.** It was redundant on top of the bundled-watchlist auto-import, and its yes/no/path loop was a frequent source of copy-paste mistakes. The wizard now closes with a one-line hint pointing at `lynceus-import-argus --input <path>` for later imports.

## [0.3.0-rc1] - 2026-05-08

### Added

- **Argus integration.** First-class support for the Argus surveillance-equipment signature dataset. Migration `004_watchlist_metadata` adds a metadata table storing Argus record id, device category, confidence, vendor, source attribution, FCC id, geographic scope, and verification timestamps alongside each watchlist entry. `lynceus-seed-watchlist` accepts an optional `metadata:` block per entry. New `lynceus-import-argus` CLI ingests the Argus dual-artifact CSV (signatures + metadata) into the watchlist. A new `/watchlist` page lists entries and per-device detail surfaces vendor, category, confidence, source, and notes. Alerts now record `matched_watchlist_id` (migration `005_alert_watchlist_link`) so triage carries metadata end-to-end, and the `/alerts` view plus the ntfy notification body include vendor and confidence so push notifications are actionable without opening the UI.

- **Tier 1 passive metadata capture.** Migration `006_tier1_capture` adds `probe_ssids` and `ble_name` columns to devices. WiFi probe-request SSID capture is opt-in via `capture.probe_ssids` (default off, privacy-conservative). BLE friendly-name capture from GAP advertisements is on by default. The BLE service-UUID enrichment dictionary now covers more consumer-tracker and accessory profiles.

- **CLI tooling for getting a fresh install running without hand-editing YAML.** `lynceus-quickstart` brings up the daemon and web UI together against a sane default config for dev/demo use. `lynceus-setup` is the interactive wizard. Live Kismet and ntfy connection probes, optional Argus dataset import, and a first-run auto-import of the bundled default watchlist.

- **Read-only `/settings` page** in the web UI surfacing capture configuration, Kismet and ntfy connection status, watchlist origin breakdown, and basic system info. Sensitive values (Kismet API token, ntfy topic) are redacted server-side. Observability only. No mutation endpoints.

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
