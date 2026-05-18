# Watchful Snooze — Design Document

Status: design (no code). Targets v0.4.0-rc6.

## Overview

Watchful snooze is a third snooze surface for Lynceus, alongside the
permanent allowlist and the time-bounded snoozes introduced earlier in
the rc cycle. It exists for a specific operator situation: an alert
fires, the operator looks at it, and the operator's honest answer is
*"I'm not sure — probably fine, but I want to know if it comes back."*
That answer doesn't fit either of the existing surfaces. Allowlisting
the device says "this is fine forever," which is a stronger claim than
the operator actually wants to make. Snoozing for 30 days says "shut up
about this until November," which silently drops the question the
operator was asking. Watchful snooze captures the real intent: stop
alerting for now, but track the device, and tell me if it keeps showing
up.

A device under watchful snooze is silently tracked across subsequent
sightings. Recurrences are counted with a 24-hour debounce so a device
that lingers nearby (a neighbor's phone parked in range for an evening)
doesn't burn through the counter. When the device has been observed on
four distinct days, an escalation alert fires — separate rule type,
separate notification, separate row in the alerts table — and the entry
is surfaced prominently on a new `/watchful` page for the operator to
review.

The feature is built for a single operator running Lynceus on personal
hardware. Its tone is descriptive, not alarmist. It is not a stalker
detector; it is a "track devices the operator wanted to track" surface,
and the language across the UI, notifications, and audit log reflects
that.

## Conceptual model

Watchful snooze sits alongside three existing suppression surfaces.
Each handles a different shape of operator intent:

| Surface | Storage | Scope | Expiry | Escalates? | Operator intent |
|---|---|---|---|---|---|
| **Permanent allowlist** | `allowlist.yaml`, operator-edited | Pattern (`mac` / `oui` / `ssid` / …) | None | No | "This is fine forever." |
| **Per-alert snooze** | `allowlist_ui.yaml`, UI-managed | Observation attributes | `expires_at` timestamp | No | "Shut up about this specific alert for a while." |
| **Per-rule_type snooze** (rc6) | `rule_type_snoozes` DB row, UI-managed | A whole `rule_type` | Bounded window | No | "Shut up about this entire alert class for a while." |
| **Watchful snooze** (this doc) | `watchful_tracking` DB row, UI-managed | A specific MAC | Bounded by recurrence/auto-archive | **Yes**, on threshold | "Probably fine — tell me if it keeps showing up." |

Watchful snooze is the only one of the four that escalates. It is also
the only one whose entry's lifecycle is shaped by the device's own
behavior (sightings) rather than by a fixed timer or a static config.
That difference is the whole point: the other three are operator
*decisions* about what to suppress. Watchful is an operator *question*
the system gets to keep answering.

## Use cases

Three concrete operator scenarios, each ending in a different outcome.

**1. "I think this device is fine, but I want to know if I keep seeing
it."** Operator gets an alert on an unknown smart-home device an
upstairs neighbor probably owns. It looks innocuous, but they're not
sure. They click watchful snooze with the default 30-day duration. Over
the next few weeks, the device shows up twice — once on a Saturday
afternoon, once a week later in the evening. Both sightings are
recorded; neither triggers a new alert. The operator checks `/watchful`
during their weekly review, sees two non-escalated entries with low
counts, and confirms the device is the neighbor's. They click "promote
to permanent allowlist." The entry transitions to `promoted`; an
allowlist entry is appended with the note "promoted from watchful."

**2. "I want to know if a tracker follows me across multiple
locations."** Operator runs Lynceus across two Pi sites — home and
office. An unknown BLE device shows up at home one Tuesday. They put it
under watchful snooze (24-hour duration; aggressive). The same MAC
appears at the office the next morning, at home that evening, and at
home again the following Tuesday. Sighting four trips the threshold.
The operator gets a priority-4 ntfy push titled "watchful escalation:
recurrence threshold reached" with the message describing four
sightings across two locations. They open `/alerts`, see the escalation
row, click through to the underlying watchful entry, mark it for
active investigation, and add the note "appeared at both sites — pull
sightings detail." Tracking continues; no further escalations fire
until they take definitive action.

**3. "I want to verify a device is actually neighbors-not-watchers."**
Operator alerts on what they suspect is a recently-installed building
camera. They watchful-snooze it. Over six weeks the device is observed
nineteen times — always in the same RSSI band, always overnight, never
moving. The operator opens `/watchful`, reviews the sighting timeline,
concludes it's a fixed installation rather than a mobile tracker,
clicks "mark as confirmed not suspicious." The entry transitions to
`confirmed_safe`; this MAC is permanently exempt from future watchful
tracking regardless of what the underlying rule does.

## Lifecycle

What happens at each event in a tracking entry's life. All state
transitions are persisted; nothing is held only in memory.

**Operator clicks "watchful snooze" on an alert.** A new
`watchful_tracking` row is created with `state = 'tracking'`,
`sighting_count = 1`, `first_alert_id` pointing at the triggering
alert, and `last_observation_at` set to the alert's observation
timestamp. The operator picks a snooze duration from {forever, 24h,
7d, 30d}; `snooze_until` is set accordingly (NULL for forever). The
original alert's row is updated to reference the new tracking entry,
so the alerts UI can show "watchful snooze active" inline.

**Same MAC observed within 24h of last sighting.** The poll loop's
watchful gate (see *Integration with existing surfaces*) finds the
active tracking entry, updates `last_observation_at` to the new
observation time, but does *not* increment `sighting_count`. No alert
is emitted. This is the same-room-ambient case: a device sitting
nearby for hours produces many observations and one sighting.

**Same MAC observed >24h after the last sighting.** The poll loop
increments `sighting_count`, updates both `last_observation_at` and
`last_counted_sighting_at` to the new observation time. Still no
alert if `sighting_count` is below 4. The /watchful page reflects the
new count on the next render.

**Fourth sighting reached.** `sighting_count` transitions from 3 to 4
on a counted recurrence. The poll loop updates state to `escalated`,
sets `escalated_at`, and emits a synthetic alert via the existing alert
pipeline (`db.add_alert` + `notifier.send`). The alert has
`rule_type = 'watchful_recurrence'`, severity per the open question
below, and an ntfy priority of 4. The alert's message describes the
recurrence in operator-readable terms: *"Device aa:bb:cc:dd:ee:ff seen
4 times since first watch on 2026-05-18. Review at /watchful/12."*

**Recurrence after escalation.** The poll loop continues to update
`last_observation_at` and increment `sighting_count` past 4. **No
further escalation alerts fire** while the entry remains in `escalated`
state. This is intentional: the operator has been notified once, the
entry is surfaced on /watchful, and additional pings would degrade
into noise. The /watchful page reflects the climbing count so the
operator can see the device is still active.

**Operator action: dismiss.** State transitions to `dismissed`. The
tracking gate ignores this entry on future polls; future sightings of
this MAC produce normal alert-pipeline behavior (the underlying rule
fires again the next time it matches). The entry is retained in the
DB for audit.

**Operator action: promote to allowlist.** State transitions to
`promoted`. A new entry is appended to the daemon-managed
`allowlist_ui.yaml` with `expires_at: None` (permanent) and a note
recording the provenance. Subsequent sightings are suppressed by the
normal allowlist precedence in `poll_once`. The watchful entry remains
in the DB for audit. (Detail in *Integration with existing surfaces*.)

**Operator action: reset count.** State stays `tracking`,
`sighting_count` resets to 1, `last_counted_sighting_at` resets to the
current timestamp, `reset_count` increments. `first_watched_at` and
`first_alert_id` are unchanged — the operator's mental model is "start
over from now," but the historical anchor stays for the audit trail.

**Operator action: mark for active investigation.** A separate flag
(`under_investigation`) is set; an optional note is stored. The
tracking state itself is unchanged; this is purely a UI surfacing
signal. The /watchful page shows flagged entries at the top.

**Operator action: mark as confirmed-not-suspicious.** State
transitions to `confirmed_safe`. Future watchful-snooze attempts on
this MAC find the existing `confirmed_safe` entry and refuse to create
a new tracking row. This MAC is permanently exempt from watchful
tracking regardless of what the operator does later in the UI — a
stricter exit than dismiss, because the operator is making a positive
statement about the device, not just declining to watch it.

**90 days without observation.** A daily housekeeping pass (piggybacked
on the existing evidence-prune cycle) transitions any entry whose
`last_observation_at + 90 days < now` to `archived`, regardless of
prior state — including `escalated` entries the operator never acted
on. Archived entries are retained read-only and visible on the
/watchful archived view. They do not count toward future recurrence
detection.

## Data model

Single new table, single new migration. Column rationale follows the
table.

```sql
CREATE TABLE watchful_tracking (
    id                          INTEGER PRIMARY KEY,
    mac                         TEXT    NOT NULL,
    state                       TEXT    NOT NULL,
    first_alert_id              INTEGER REFERENCES alerts(id),
    first_watched_at            INTEGER NOT NULL,
    last_observation_at         INTEGER NOT NULL,
    last_counted_sighting_at    INTEGER NOT NULL,
    sighting_count              INTEGER NOT NULL DEFAULT 1,
    snooze_duration             TEXT    NOT NULL,
    snooze_until                INTEGER,
    under_investigation         INTEGER NOT NULL DEFAULT 0,
    investigation_note          TEXT,
    reset_count                 INTEGER NOT NULL DEFAULT 0,
    escalated_at                INTEGER,
    state_changed_at            INTEGER NOT NULL,
    state_changed_note          TEXT,
    CHECK (state IN (
        'tracking', 'escalated', 'dismissed',
        'promoted', 'confirmed_safe', 'archived'
    )),
    CHECK (snooze_duration IN ('forever', '24h', '7d', '30d'))
);

CREATE UNIQUE INDEX idx_watchful_mac_active
    ON watchful_tracking(mac)
    WHERE state IN ('tracking', 'escalated');

CREATE INDEX idx_watchful_state
    ON watchful_tracking(state);

CREATE INDEX idx_watchful_last_observation
    ON watchful_tracking(last_observation_at)
    WHERE state IN ('tracking', 'escalated');
```

- **`mac`** is the canonical identifier for recurrence matching.
  Stored normalized (lower-hex, colon-separated) per
  `lynceus.kismet.normalize_mac`. Not unique in the table — a MAC
  may have one active row plus many historical rows (dismissed,
  promoted, archived). The partial unique index enforces "at most one
  active row per MAC" without preventing the audit trail.
- **`state`** drives the lifecycle state machine. CHECK constraint
  enumerates the legal values; transitions are enforced in the data
  access layer rather than the schema (SQLite doesn't do enum
  transition constraints).
- **`first_alert_id`** is a FK reference to the alert that prompted the
  watch. Nullable because the alerts table may rotate (no automatic
  rotation today, but the FK is defensively nullable rather than
  cascading).
- **`first_watched_at`** is the timestamp the operator clicked the
  button. Used for the /watchful timeline and the "watched since"
  display.
- **`last_observation_at`** is the most recent observation timestamp,
  updated on *every* sighting (including ambient repeats). It is the
  anchor for the 24-hour recurrence debounce.
- **`last_counted_sighting_at`** is the timestamp of the last
  observation that incremented `sighting_count`. Separate from
  `last_observation_at` to make the auto-archive logic
  ("`last_observation_at + 90d < now`") and the recurrence logic
  ("debounce from `last_observation_at`") use orthogonal anchors that
  read cleanly in code.
- **`sighting_count`** starts at 1 (the initial sighting is the alert
  that prompted the watch) and increments on each counted recurrence.
  When it transitions 3 → 4 on a counted recurrence, escalation fires.
- **`snooze_duration`** is stored as a label rather than an integer of
  seconds, because the UI surfaces it back to the operator and labels
  are stable across reads. The four values map: `'forever' → NULL`,
  `'24h' → 86400`, `'7d' → 604800`, `'30d' → 2592000`.
- **`snooze_until`** is the absolute epoch timestamp at which the
  snooze expires, NULL for forever. When `snooze_until < now` and the
  entry is still in `tracking` state, the entry transitions back to
  effectively-inactive (see open question below).
- **`under_investigation`** and **`investigation_note`** form the
  visual-flag mechanism. The flag is orthogonal to state — an entry
  can be flagged in any active state.
- **`reset_count`** tracks how many times the operator has reset the
  entry. Surfaced on /watchful as a small audit indicator
  ("reset twice") so the operator can see they've been giving the
  device extra chances.
- **`escalated_at`** is the timestamp escalation fired, NULL while the
  entry has never escalated. Distinct from `state_changed_at` so
  re-entries into `escalated` (which shouldn't happen, but the data
  model doesn't preclude) preserve the original escalation timestamp.
- **`state_changed_at`** and **`state_changed_note`** record the most
  recent state transition. Sufficient for v1; if richer audit is
  needed later, a separate `watchful_state_history` table is a clean
  extension.

The two partial indexes (`mac_active` and `last_observation`) keep the
hot path — finding the active entry for an incoming observation —
narrow and fast. The full-table `state` index supports the /watchful
filter UI.

## Recurrence detection algorithm

Given an observation `obs` for MAC `M` arriving at the watchful gate
with timestamp `t`:

1. **Resolve the active entry.** Look up the row where `mac = M` and
   `state IN ('tracking', 'escalated')`. The partial unique index
   guarantees at most one row. If none exists, the observation flows
   through to the rest of the poll loop unchanged.
2. **Check snooze expiry.** If `snooze_until IS NOT NULL` and
   `snooze_until < t`, the snooze has expired (see open question on
   exact post-expiry behavior). For the rest of this section, assume
   the snooze is still active.
3. **Check the debounce gap.** Compute `gap = t - last_observation_at`.
   If `gap <= 86400` (24 hours): same-room ambient case. Update
   `last_observation_at = t` and stop. Sighting count unchanged. No
   alert.
4. **Count the sighting.** `gap > 86400`: counted recurrence. Update
   `last_observation_at = t`, `last_counted_sighting_at = t`,
   `sighting_count += 1`.
5. **Check the escalation threshold.** If `sighting_count == 4` and
   `state == 'tracking'`: transition state to `escalated`, set
   `escalated_at = t`, set `state_changed_at = t`, emit a synthetic
   alert via the existing alert-pipeline path with
   `rule_type = 'watchful_recurrence'`. If `sighting_count > 4`:
   already escalated, no additional alert emitted (anti-spam — see
   *Escalation behavior*).
6. **Continue.** The observation continues through the rest of the
   poll loop. Watchful tracking does not suppress the original alert
   pipeline by itself; that is the snooze layer's job (see *Integration*).

**Edge cases for the algorithm:**

- **First sighting after creation.** The tracking entry is created with
  `sighting_count = 1`, `last_observation_at` set to the alert's
  observation timestamp. The next observation goes through the
  algorithm above. The "first sighting" itself is the alert that
  triggered the watch — the operator's mental model is "I'm at 1, three
  more triggers escalation."
- **Sighting at exactly the 24-hour boundary.** `gap > 86400` is a
  strict greater-than. At exactly `gap == 86400` (one second short of
  25 hours from the prior observation, counted in epoch seconds), the
  observation is treated as ambient. This matches the locked decision's
  ">24 hours" wording.
- **Multiple observations during the same poll cycle.** The poll loop
  processes observations one at a time. If two observations of the same
  MAC arrive in the same poll batch, the first one updates state, the
  second one sees the just-updated `last_observation_at` and is treated
  as ambient. This is correct: two observations within the same poll
  window are by definition <24h apart.
- **Observations spread across multiple APs simultaneously.** The MAC
  is the canonical identifier; multiple seeing-sources for the same MAC
  in the same poll resolve to a single observation upstream (in the
  Kismet client merge). Even if they didn't, the algorithm is
  idempotent under "same MAC observed twice within seconds" — see the
  prior bullet.

## Escalation behavior

When `sighting_count` trips from 3 to 4 on a counted recurrence, the
gate emits a new alert. The alert flows through the standard pipeline
(`db.add_alert`, then `notifier.send`), so it appears in `/alerts`, has
its own row, and counts toward `/rules` statistics like any other
alert. Per the locked decisions:

- **`rule_type = 'watchful_recurrence'`.** A new rule type, distinct
  from the watchlist rules. Implementation note in *Open questions*
  about extending the `RuleType` literal and how this synthetic
  rule_type integrates with the yaml-defined ruleset.
- **Severity.** TBD per the open question on priority-4 plumbing.
  Conceptually: notable, not urgent. Worth waking the operator's
  notification surface but not the dramatic-tone high-severity
  treatment.
- **ntfy priority 4.** One bump above the default-3 (`med` severity)
  and one below the maximum-5 (`high` severity, currently used for
  watchlist hits the operator explicitly opted to take seriously). In
  the ntfy app this renders with a slightly stronger notification
  presentation than default — a different tone or vibration pattern on
  most clients — without the dramatic treatment ntfy reserves for
  priority-5 / `urgent`. The current notify.py mapping is
  `low/med/high → 2/3/5`; priority 4 has no pre-existing severity
  binding, which is precisely why the plumbing is an open question.
- **Message.** Operator-readable. Format: *"Device <mac> seen N times
  since first watch on <date>. Review at /watchful/<id>."* Avoids
  alarmist language. The operator already chose to watch this device;
  the escalation is information, not a panic alarm.

**Subsequent recurrences after escalation: stay quiet until operator
action.** This is the recommended behavior in the locked decisions and
it is the right call. A device that has tripped the threshold doesn't
need to keep paging the operator — the operator already knows. The
/watchful page surfaces the current count, the timeline, and the
flagged-investigation state. If the operator wants the alert to fire
again, the "reset count" action does that explicitly: the entry
returns to `tracking`, the count restarts, and a future fourth sighting
fires a new escalation.

The trade-off here is real: an escalated entry the operator never
addresses sits silently until the 90-day archive sweep. The
mitigation is the /watchful weekly digest (see *Operator interface*)
which gives the operator a regular touchpoint without per-recurrence
spam.

## Operator interface

What the operator sees and where.

**On `/alerts`.** Each alert row's triage area gains a "watchful
snooze" option alongside the existing snooze and allowlist actions. The
option opens a small picker for duration (default 30d; choices forever
/ 24h / 7d / 30d). After enabling, the alert row shows a
"watchful snooze active" indicator with a link to the tracking entry.
The existing per-alert snooze and per-rule_type snooze are unchanged;
watchful is a third sibling action, not a replacement.

**On `/watchful` (new page).** A list of tracking entries with state
columns:

```
+------------------------------------------------------------------+
| State      | MAC               | Count | Last seen | First watched|
|------------+-------------------+-------+-----------+--------------|
| ESCALATED  | aa:bb:cc:dd:ee:ff |  6    | 2h ago    | 2026-04-12   |
| tracking   | aa:bb:cc:11:22:33 |  2    | 1d ago    | 2026-05-09   |
| tracking   | aa:bb:cc:44:55:66 |  1    | 3d ago    | 2026-05-15   |
+------------------------------------------------------------------+
```

Entries are sorted by: investigation-flagged first, then by state
(`escalated` before `tracking`), then by `last_observation_at`
descending. The list defaults to showing active entries
(`tracking`, `escalated`); a filter toggle reveals
`dismissed`/`promoted`/`confirmed_safe`/`archived` for review.

Per-entry actions live in the entry detail view (`/watchful/<id>`):
dismiss, promote to allowlist, reset count, mark for active
investigation (toggles the flag, opens a note text area),
mark as confirmed-not-suspicious. Each action is a POST with CSRF (per
existing webui conventions). Each action shows a confirmation step.
"Mark as confirmed-not-suspicious" gets a stronger confirmation
("This permanently exempts the MAC from future watchful tracking. Are
you sure?") because the action is non-reversible from the UI.

**Weekly digest.** A `/watchful` section at the top of the dashboard
(or a small standalone digest view) summarizing the past week:
escalations fired, sightings recorded, entries reaching investigation
flag, entries archived. This is the deliberate anti-spam surface — the
operator gets one regular touchpoint rather than push notifications
for every recurrence past threshold. The digest is render-on-load, not
emailed or pushed.

**ntfy on escalation.** A single priority-4 push describing the
escalation. Body format follows existing notification conventions
(severity prefix, message body, watchlist metadata suffix if the
original rule had any).

## Integration with existing surfaces

**Per-alert snooze vs watchful snooze.** Per-alert snooze is for *"I've
already decided this is fine."* Watchful snooze is for *"I'm not sure
— tell me if it comes back."* The UI labels and tooltips reflect this:
the per-alert snooze button reads "Snooze (Xh)" and the watchful button
reads "Watchful snooze (Xd) — tell me if it recurs." Operator guidance
in the docs: prefer per-alert snooze when the operator is confident the
alert is noise; prefer watchful when the operator wants ongoing
visibility.

**Per-rule_type snooze applied to `watchful_recurrence`.** Supported
and consistent: the operator can mute the entire `watchful_recurrence`
class temporarily, which gates the escalation alert at the existing
rule_type snooze gate in the poll loop. Watchful detection itself
continues — `sighting_count` still increments and entries still
transition to `escalated` — but the escalation alert is suppressed
until the rule_type snooze expires. This is consistent with how
rule_type snooze treats every other rule type: detection runs;
notification doesn't.

**Allowlist promotion path.** "Promote to permanent allowlist" appends
to the daemon-managed `allowlist_ui.yaml` (the UI-write sibling file
derived by `derive_ui_path`). The operator-curated primary
`allowlist.yaml` is read-only from the daemon's perspective per the
existing allowlist module contract — the daemon never edits it, which
is the property that lets operators hand-format and comment the file
without fear of clobbering. The promote write therefore lands as a UI
entry with `expires_at: None` (permanent), the matching `pattern_type`
(typically `mac`), and a provenance note:

```yaml
- pattern: aa:bb:cc:dd:ee:ff
  pattern_type: mac
  expires_at: null
  note: "promoted from watchful on 2026-05-18 (entry #12)"
```

The watchful tracking row's state transitions to `promoted` and remains
in the DB for audit. Future sightings hit the allowlist gate first and
never reach the watchful gate at all. An operator who wants the entry
moved into the operator-curated `allowlist.yaml` does so by hand — the
same path used for any other UI-written allowlist entry the operator
decides to make canonical.

**Existing alert-flow gate location.** The watchful tracking gate
inserts in `poll_once` *after* `db.insert_sighting` (so every
observation is recorded regardless of watchful state) and *before* the
allowlist suppression check. This ordering matters:

- After `insert_sighting`: the sighting goes into the DB unconditionally;
  watchful tracking augments the record but doesn't replace it.
- Before allowlist suppression: a tracked MAC that the operator later
  allowlists still gets the suppression precedence. The watchful entry
  remains in its own state (probably `promoted`), and the allowlist
  audit log records the suppression as usual.

This places the watchful gate at a different point in the loop than
the rc6 per-rule_type snooze gate, which is at alert-emit time
(inside the `for hit in hits` block, before `db.add_alert`). The two
gates do different things: rule_type snooze suppresses output;
watchful tracking observes input.

## Scare-factor mitigations

These are deliberate. Future contributors: please don't strip them
without thinking through the operator-experience consequences.

- **Descriptive UI language, not alarmist.** "Seen N times since first
  watch — review?" rather than "STALKER DETECTED" or "TRACKER ALERT."
  Rationale: most watchful-snooze targets are neighbors, smart-home
  devices, or stray BLE peripherals. Alarmist language trains operators
  to dismiss the surface as noise. Calm language preserves signal.
- **"Mark as confirmed-not-suspicious" is a real permanent exit.** Once
  the operator makes that affirmative judgment, the system honors it
  forever for that MAC. Rationale: an operator who's done the work to
  confirm a device is safe should not be re-paged about it. The
  permanent-exit path is the trust-the-operator path.
- **Default escalation is priority 4, not 5.** Notable, not urgent.
  Rationale: a recurrence is information, not a panic-alarm. Reserving
  priority 5 for severity-`high` watchlist hits preserves the meaning
  of the ntfy max-priority tier — operators who get a priority-5 push
  should know it's serious.
- **Weekly digest instead of per-recurrence pings.** The /watchful page
  aggregates rather than pinging. Rationale: a single weekly review is
  a sustainable operator practice; per-recurrence pings degrade into
  background noise within days.
- **The /watchful list defaults to active entries only.** Dismissed,
  promoted, confirmed-safe, and archived entries are behind a filter.
  Rationale: the operator's daily concern is the active set; the
  historical audit trail is available when needed but not in the way.

## Edge cases

**MAC randomization defeats recurrence detection.** A device that
rotates its MAC between sightings will produce a new tracking entry
each time (or no tracking at all, if the operator didn't watchful-snooze
each new MAC). The 24-hour-debounce recurrence rule has no way to
recognize "this is the same device under a new MAC." This is a known
fundamental limitation of MAC-based correlation, not specific to
watchful. Lynceus records randomization status per device — the
`DeviceObservation.is_randomized` flag is populated via
`is_locally_administered(mac)` at parse time — so the /watchful UI can
surface a "randomized" indicator on each entry, letting the operator
reason about which entries are subject to this limitation. The doc
captures the limitation explicitly so operators understand the threat
model:

> Watchful snooze tracks by MAC address. Devices that rotate MACs
> between sightings (modern phones, by design) will not be detected as
> recurring. The /watchful UI shows the randomized flag on each entry
> so operators can reason about which entries are subject to this
> limitation.

Cross-rotation correlation is on the BACKLOG (alongside the multi-
location stalking heuristics in `BACKLOG.md` and the corresponding
known-limitations in `docs/PROJECT_STATUS.md`).

**Device snoozed via /alerts (per-alert snooze) AND watchful-snoozed.**
Both records exist; precedence rule: the per-alert snooze suppresses
the original alert until it expires (existing rc-cycle behavior), and
the watchful gate still tracks every observation. The two are
orthogonal. If the per-alert snooze expires before the watchful
threshold trips, future alerts under the original rule type fire
normally — watchful does not suppress those.

**Operator removes watchful snooze before any recurrence.** Equivalent
to "dismiss" with the entry having `sighting_count = 1`. State
transitions to `dismissed`. No further tracking. The MAC has no special
status; future observations behave as if the watchful entry never
existed.

**Database survives daemon restart.** Yes. `watchful_tracking` is a
regular SQLite table; the daemon's only in-memory state is config and
the kismet client. State persistence is the DB.

**Concurrent operations.** An operator clicks "dismiss" on /watchful
while the poll loop is mid-iteration with a sighting for that MAC.
SQLite serializes writes; the dismiss-update and the
poll-loop-increment compete on the same row. Resolution: the poll loop
re-reads the row at the start of its per-observation transaction
(SELECT for the active entry, UPDATE within the same transaction). If
the state has changed between the SELECT and a write attempt to a
`dismissed` row, the UPDATE no-ops (WHERE state IN ('tracking',
'escalated') filter). The poll loop logs at DEBUG and continues. The
operator's dismiss wins; the lost sighting is recorded in the
`sightings` table as usual but not reflected in the now-dismissed
watchful entry.

**Watchful snooze entry whose pattern_type matches an existing
allowlist entry.** Resolution: allowlist precedence wins (allowlist is
checked first in `poll_once`). The watchful entry is never reached for
that MAC. The watchful entry remains in the DB in whatever state it
was in, but it's effectively orphaned — sightings stop arriving at the
watchful gate. The /watchful UI should surface this case ("this entry's
MAC matches an allowlist pattern; tracking is effectively paused") so
the operator can decide whether to dismiss the watchful entry or
remove the allowlist entry.

## Open questions

Real ambiguity that emerged during writing. Each is a decision point
for the implementation prompt.

**OQ-1: How does ntfy priority 4 get expressed?** `notify.py`'s
`SEVERITY_TO_PRIORITY` maps `low/med/high → 2/3/5`. Priority 4 is
unused, and the `Notifier.send` signature today is
`(severity, title, message)` — there is no per-call override knob.
Options:

- (a) Add a new severity tier between `med` and `high` (call it
  `notable`?), with its own priority and tag. Touches the `Severity`
  literal, the rules engine, the watchlist schema, the UI severity
  badge.
- (b) Add an optional `priority_override: int | None = None` parameter
  to `Notifier.send` (and a matching `Tags` override, or a sane default
  tag for the override path). Alerts default to severity-mapped
  priority; the watchful escalation emit-site passes
  `priority_override=4`. Minimal touch surface: notify.py gains one
  optional arg, poller.py passes it at the watchful emit-site, no
  schema changes.
- (c) Add a rule_type-keyed priority lookup inside `notify.py` — a
  small dict mapping `rule_type → priority` that overrides the
  severity-mapped default. Requires plumbing `rule_type` through to
  the notifier (which currently takes `severity` only).

Recommendation: **(b)** — smallest schema change, no new public
abstractions, and the override knob localized at exactly the surface
that needs it. The `Severity` literal stays a three-tier UX concept;
the priority bump is an emit-time decision the poller makes for one
specific synthetic alert class.

**Decision point for implementation prompt.**

**OQ-2: Registration of the `watchful_recurrence` rule_type.** The
existing `RuleType` literal in `rules.py` lists seven user-defined
types (`watchlist_mac`, `watchlist_oui`, `watchlist_ssid`,
`watchlist_mac_range`, `ble_uuid`, `watchlist_ble_manufacturer_id`,
`watchlist_drone_id_prefix`) plus one system-emitted type
(`new_non_randomized_device`). The `watchful_recurrence` type is
system-emitted (the poll loop generates it; users don't author it in
yaml). The literal needs extending. The `Rule` model's validator
branches (each rule_type spelled out explicitly per the comment block
at `rules.py:51`) need an additional branch for `watchful_recurrence`
— following the `new_non_randomized_device` precedent of
patterns-forbidden, since synthetic rule_types don't admit
user-authored patterns. The /rules page needs to render system-emitted
rule_types differently (no patterns to show; statistics column still
useful).

Recommendation: extend the literal, add the validator branch
(patterns must be empty), and surface system-emitted rule types in a
separate UI section on /rules so operators understand they can't
configure them via yaml.

**Decision point for implementation prompt.**

**OQ-3: What happens when `snooze_until` expires while the entry is in
`tracking` state but hasn't yet escalated?** Options:

- (a) The entry transitions to `dismissed` automatically. Tracking
  stops. Future observations of the MAC behave as if the watchful
  entry never existed.
- (b) The entry stays in `tracking` but `snooze_until` becomes
  irrelevant; observations continue to count toward the threshold,
  and escalation still fires if reached.
- (c) The entry stays in `tracking` until either escalation fires or
  the auto-archive at 90d of inactivity, treating `snooze_until` as a
  *display preference* rather than a behavioral gate.

The locked decisions specify the snooze duration choices ({forever,
24h, 7d, 30d}) but don't clarify post-expiry semantics. The semantic
the operator likely expects from a "30-day watchful snooze" is *"watch
this device for 30 days; if nothing happens in that window, drop it."*
That points to (a).

Recommendation: **(a)**. At `snooze_until < now`, the daily
housekeeping pass transitions the entry to `dismissed` with a state
note "snooze expired without recurrence." The operator sees the
entry on /watchful's dismissed view if they look for it; the
journalctl audit line records the transition.

**Decision point for implementation prompt.**

**OQ-4: Does the original alert that triggered the watchful snooze
count as sighting 1?** The lifecycle text above assumes yes
(`sighting_count` starts at 1; threshold of 4 = initial alert + 3
counted recurrences). This is consistent with the locked decision
("4 total sightings (initial + 3 additional)"). Documenting it
explicitly so the implementation doesn't accidentally start the count
at 0.

Recommendation: **starts at 1.** Resolved by the locked decision but
worth re-confirming during implementation.

**OQ-5: Location dimension in recurrence detection.** The 24-hour
debounce treats all observations equivalently regardless of source.
The poller already tracks per-source location via `source_locations`
and the per-observation `effective_location_id`. Should an observation
at a different Pi/location count differently than one at the same
source? Operator-relevant case: a tracker that hops locations should
escalate faster than a smart-home device that ambient-repeats at one
location.

Recommendation: **uniform treatment for v1.** Cross-location stalking
heuristics are explicit future work (already on the BACKLOG as
"Stalking heuristics (multi-location detection)" and reflected in
`docs/PROJECT_STATUS.md`'s known-limitations). Surface the location
dimension on the /watchful detail view so the operator can see
"seen at home twice, office once" without the system making
inferences from that. The v1 algorithm stays uniform-time-only;
multi-location heuristics get their own design pass.

**Decision point for implementation prompt** (mostly for
"how do we surface location distribution in the UI without changing
the algorithm").

**OQ-6: Operator action endpoints — REST shape.** Five operator
actions (dismiss, promote, reset, flag-investigate, mark-safe) plus
the alert-side watchful-snooze creation. Two reasonable URL shapes:

- (a) Action-per-endpoint:
  `POST /watchful/<id>/dismiss`, `/promote`, `/reset`, etc.
- (b) Single state-transition endpoint:
  `POST /watchful/<id>/state` with form-body `action=dismiss`.

Recommendation: **(a).** Each action gets its own endpoint, matching
the existing `/alerts/<id>/ack` pattern in the webui. CSRF middleware
covers them uniformly. The `/flag-investigate` and `/unflag-investigate`
toggles get their own endpoints for the same reason.

**Decision point for implementation prompt.**

**OQ-7: Auto-archive interaction with escalated entries.** The locked
decisions say "Tracking entries are auto-archived after 90 days of no
recurrence." An escalated entry the operator never addresses sits at
`escalated` state until either operator action or 90 days of no
observation. After 90d of no observation, does the entry go straight
to `archived` (losing the `escalated` marker), or to a separate
`escalated_then_archived` state for audit clarity?

Recommendation: **archive uniformly.** State transitions to `archived`
regardless of prior state. The audit trail is preserved in
`state_changed_at` + `escalated_at` (the latter remains non-NULL on
archived entries that escalated before aging out). Adding a separate
post-escalation state is data-model bloat for a case the operator
rarely looks at.

**Decision point for implementation prompt.**

**OQ-8: Reset-from-escalated. Allowed?** The lifecycle text describes
reset transitioning from `tracking` (count resets, state stays
`tracking`). What about reset from `escalated`? Operator's plausible
intent: *"I've reviewed, I want to give this device another chance to
behave."* That maps to state → `tracking`, count → 1.

Recommendation: **allow reset from `escalated`,** with state →
`tracking` and `escalated_at` cleared. The audit trail preserves the
prior escalation in `state_changed_at` history (if we add the history
table) or, for v1, in `reset_count > 0` plus the journalctl audit
line. The UI confirmation should be explicit: "this clears the
escalation and restarts the watch."

**Decision point for implementation prompt.**

## Implementation outline

A touch list, not a prompt. The implementation prompt will turn this
into concrete touches.

- **New migration** (next number after `017_rule_type_snoozes.sql`).
  SQL per *Data model*.
- **New table** `watchful_tracking` per *Data model* with the three
  indexes.
- **`db.py` additions:** CRUD for the table (resolve-active,
  create-tracking, record-ambient-observation,
  record-counted-recurrence, state transitions per action,
  list-active, list-with-filter, archive-stale-entries,
  expire-snoozes).
- **`rules.py`:** extend `RuleType` literal to include
  `watchful_recurrence`; extend the `Rule` validator to handle it
  similarly to `new_non_randomized_device` (patterns must be empty).
- **`notify.py`:** plumb priority 4 per OQ-1's decision.
- **Tracking gate in `poller.py`:** insert between `db.insert_sighting`
  and the allowlist suppression check. Implements the algorithm in
  *Recurrence detection algorithm*. Emits an escalation alert via the
  existing `db.add_alert` + `notifier.send` path when threshold trips.
- **Auto-archive housekeeping:** piggyback on the daily-housekeeping
  pattern (mirrors `maybe_prune_evidence` at `poller.py:325`). Single
  SQL UPDATE that transitions tracking/escalated entries with stale
  `last_observation_at` to `archived`. Idempotent and cheap.
- **Snooze-expiry housekeeping:** same housekeeping pass also handles
  `snooze_until` expiry per OQ-3's decision.
- **POST routes** (action-per-endpoint per OQ-6):
  `/alerts/<id>/watchful-snooze` (creates the tracking entry),
  `/watchful/<id>/dismiss`,
  `/watchful/<id>/promote`,
  `/watchful/<id>/reset`,
  `/watchful/<id>/flag-investigate`,
  `/watchful/<id>/unflag-investigate`,
  `/watchful/<id>/confirm-safe`.
- **New `/watchful` page** + template. Active-entries list view,
  filter for inactive states, per-entry detail view, weekly digest
  block.
- **`/alerts` UI update:** add "watchful snooze" button to the existing
  alert triage area; render "watchful snooze active" indicator on
  rows with a linked watchful entry.
- **`/rules` UI update:** surface `watchful_recurrence` as a
  system-emitted rule type (per OQ-2).
- **`/allowlist` UI update:** none. Promoted-from-watchful entries
  appear in the normal allowlist view (UI-managed source); the
  provenance is recorded in the entry's `note` field.
- **Tests** (categories, not specific tests):
  - Recurrence algorithm: 24h-boundary cases, ambient-debounce,
    multi-observation single poll, multi-source single MAC.
  - Threshold tripping: count transitions, escalation alert emission,
    no-double-emit on subsequent recurrences.
  - State transitions: each operator action's effect on state,
    `confirmed_safe` permanent-exit semantics, reset-from-escalated
    per OQ-8.
  - Housekeeping: 90d auto-archive, snooze-expiry transition per OQ-3.
  - Concurrency: poll loop vs operator action on the same row.
  - Integration: allowlist precedence over watchful, rule_type snooze
    of `watchful_recurrence` suppressing emission while detection
    continues, per-alert snooze + watchful coexistence.
  - UI: CSRF on all POST routes, action confirmations,
    confirmed-safe stronger confirmation flow.
- **CHANGELOG entry** under `[0.4.0-rc6] Added`, modeled on the
  per-rule_type snooze entry's structure: feature summary, design
  motivation, configuration surface, link to this doc.

## Future work (deferred)

Explicitly out of scope for the first implementation. Listing them
here so the implementation prompt doesn't accidentally pick them up,
and so the BACKLOG has a place to point.

- **Per-operator tracking.** Lynceus is single-operator by design.
  Multi-operator watchful state (who watchful-snoozed what, who
  dismissed) is not in scope.
- **ML-based threshold tuning.** The 4-sighting / 24h-debounce
  parameters are fixed in v1. Adaptive tuning based on per-operator
  noise levels is future work, and probably not the right next step
  either — operator-explainable rules are more valuable than
  hyperparameter optimization.
- **Cross-device pattern detection.** "Multiple devices following you"
  is a real surveillance concern but a different feature: it requires
  device co-occurrence analysis across sightings, not per-MAC
  recurrence detection. Separate design doc when the time comes.
- **Geographic clustering.** Devices appearing across physically
  distinct regions (different cities, not just different Pi sources)
  is a cross-Pi correlation problem — see the BACKLOG's existing
  multi-location-stalking-heuristics item.
- **MAC randomization correlation.** The fundamental limitation
  documented in *Edge cases*. Cross-rotation correlation requires
  passive fingerprinting and is its own substantial design exercise.
  Out of scope here.
- **External threat-feed integration.** A watchful entry could be
  enriched with external reputation data (Argus already provides
  watchlist provenance; threat feeds are a step further). Future
  surface; not entangled with v1.
