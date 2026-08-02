# Device co-observation explorer — design v3

**Supersedes** the withdrawn `2026-08-02-copresence-correlation-design.md` (v1), whose lift statistic
was measured to return `10.000 / strong` for the always-present neighbour it existed to demote.
v2 was red-teamed before implementation; this is v2 with those eleven findings applied.

**Status**: proposed, not implemented. **Depends on**: nothing new. No schema change.

## Requirement

Show the operator which other devices keep turning up at the same time as this one.

## Decision 1 — no score, no confidence, no band, no ranking of suspicion

The output is evidence the operator reads, not a judgement the software makes.

There is no labelled corpus, no ground truth, no measured false-positive rate, and — decisively —
**sensor uptime is not recorded anywhere in the schema**, so absence of data cannot be distinguished
from absence of a device. Every quantity that would make a statistical claim defensible is
unavailable. A score computed anyway carries false authority exactly where a false positive tells a
frightened person that a specific neighbour is following them.

This deletes v1 findings 2, 3, 5, 6, 7, 15 and 16 outright — all were properties of `lift`,
`expected` or the bands.

## Decision 2 — co-observation is proximity between real sightings

⭐ **Changed in v3.** v2 bucketed time into fixed windows. That has an alignment artifact with no
defensible answer: at `W=60min`, sightings at 10:00 and 10:59 are "co-observed" 59 minutes apart,
while 10:59:59 and 11:00:00 are not, one second apart. Presets expose the sensitivity; they do not
cure it.

v3 uses a **proximity criterion**, which is alignment-free and translation-invariant:

> Anchor sighting `a` and candidate sighting `c` are **co-observed** when
> `c.location_id = a.location_id` and `|c.ts - a.ts| <= W`.

Every co-observation is therefore a pair of **real logged rows** with a real Δt. Nothing is
interpolated, floored, or bucketed. This also resolves v2 finding 3: "the exact shared timestamps"
now exist, because they are the two sighting rows.

**The panel shows the Δt distribution** (min, median, max) alongside the counts, so "more shared
runs" can never be silently read as "closer temporal correspondence" — the operator sees the actual
tightness.

## Decision 3 — the counting unit is the observation run

"Visit" is retired. A **observation run** is a gap-split sequence of one device's sightings at one
location, split on gaps greater than `gap_seconds`. The term is deliberately weaker than "visit": at
a 15-minute threshold an anchor continuously present 09:00–17:00 but logged every 16 minutes during
sensor trouble becomes 31 runs, and calling those 31 "visits" implies 31 encounters that may have
been one continuous episode.

Run boundaries are labelled in the UI as inferred from observations, never as arrival and departure,
and `gap_seconds` is displayed with the results.

**Run membership is defined by the sighting rows**, not by interval containment: a run is *shared* if
it contains at least one sighting that is co-observed per Decision 2. That is unambiguous and
implementable, which v2's window-to-visit mapping was not (finding 8).

## What is returned, per candidate, per location

| Field | Meaning |
|---|---|
| `shared_anchor_runs` / `anchor_total_runs` | anchor runs containing a co-observed sighting, and the denominator |
| `shared_candidate_runs` / `candidate_total_runs` | same, candidate side, and its denominator |
| `shared_days` | distinct **local** calendar days with a co-observation |
| `candidate_coverage` | candidate's observed runs ÷ all runs logged at that location in range |
| `delta_min` / `delta_median` / `delta_max` | seconds between co-observed sightings |
| `first_shared_ts` / `last_shared_ts` | the earliest and latest co-observed **anchor** sighting |

Both sides are returned because they are **not the same number**. v1 returned only the candidate
side, so five candidate runs inside one anchor run read as five independent events and the statistic
changed depending on which device you anchored (findings 9, 10). Showing both makes the
pseudo-replication visible rather than hiding it in one count.

Every denominator is returned, so no ratio is rendered that the data does not carry (v2 finding 7).

Counts are **per location, never pooled** — v1 joined on `location_id` then summed across locations,
quietly implementing the cross-location follow-detection the spec declared a non-goal (finding 14).

`shared_days` uses the **operator's configured timezone**. Unix-time date conversion in UTC reports
23:55 and 00:05 Eastern as one day when they are two (v2 finding 10).

## Decision 4 — observation coverage is a property of one device

Candidates above `coverage_threshold` appear in a separate **"high observation coverage"** section,
not hidden.

⚠️ Renamed from v2's "ubiquity", and its explanation deleted. Saying a router "is present for
everything" is a causal claim the data does not support: a router detectable in 95 of 100 logged
runs is 95% **observable**, not 95% present, and a phone physically present the whole time may be
detectable in 8 (v2 finding 1). The section reports observation coverage and says only that.

The denominator is **per-location distinct runs within the selected range** — a global denominator
would break the per-location promise everywhere else.

This is deliberately not v1's `ambient` flag, which was `lift < 1.5`: a claim about the *relationship*
derived from the broken statistic. Coverage is a claim about the candidate alone, verifiable by
counting rows.

## Decision 5 — the query is anchored and two-stage

⭐ **Changed in v3.** v1 built gap-split spans for **every MAC in the window** before filtering. At
2,000 continuously observed devices, 90 days of 60-second polling is ~259 million rows; `marked`
must scan and sort all of them, then `numbered` makes another window pass. SQLite spills the sort and
blocks the request (v2 finding 5). Mutation testing never exposed this, because mutation tests do not
measure cost.

Three stages, each index-bounded:

1. **Anchor runs** — one indexed lookup on `idx_sightings_mac_ts` for `:mac` within range. Small.
2. **Candidate discovery** — for the anchor's sighting times only, read
   `[t - W, t + W]` at the same location via `idx_sightings_ts`. This yields the candidate MAC set
   and every co-observed pair directly. Bounded by anchor sightings × W, never by corpus size.
3. **Segmentation** — gap-split runs computed **only for the anchor and the discovered candidates**.

Pagination must never require segmenting the whole corpus.

## Presentation

- **Timeline-led.** Anchor runs in order, co-observed devices beneath each. Clicking one reveals both
  devices' actual sighting rows and the Δt between them.
- **The range is explicit and visible**, and is part of the request, every denominator and the
  rendered header. `sightings` is never pruned, so an unstated horizon silently controls every
  result: a router with 300 shared runs from January would outsort a device with 20 from this week
  (v2 finding 4).
- **Sort is navigation, not suspicion.** Default `shared_anchor_runs DESC`, then most recent. The
  control reads "Sort by shared observation runs". Never "most associated", never "strength".
- **Truncation is visible** — "showing 25 of 137 devices". v1 truncated by raw volume at `LIMIT 25`
  with nothing telling the operator the interesting device was never retrieved (finding 4).
- **`W` presets** of 1 / 5 / 15 minutes, with the chosen value displayed. A relationship that
  dissolves as `W` tightens is information the operator should have.
- **Probe SSIDs are unverified metadata**, shown with `corpus_devices`, and **promote nothing** —
  there is no band left to promote. v1 treated `attwifi` (20,000 devices) identically to a unique
  SSID (finding 5).

### Caveats rendered in the panel, not only the docs

- "Co-observed" means both were logged within `W` of each other at one location. Nothing more.
- Missing data cannot distinguish sensor downtime, a quiet device, and absence.
- Randomized MACs cannot reliably be merged into one device.
- A MAC is not a person. Mesh nodes, AP radios and hotspots co-occur naturally (finding 17).

## Carried fixes

| Finding | Fix |
|---|---|
| v1 18 / v2 9 | `probe_ssids` must satisfy `json_valid()` **and** `json_type(...)='array'`, with non-string elements skipped and `COUNT(DISTINCT mac)` for `corpus_devices`. `json_valid()` alone is insufficient: `"attwifi"` is valid JSON that `json_each` yields as one scalar SSID |
| v1 22 | Invariant `0 <= shared_X_runs <= X_total_runs` on **each** denominator; violation raises rather than rendering a confident number |
| v1 24 | Web tests inject a clock. v1's fixtures used a 2023 constant against real `time.time()`, so every one would have failed |

## Non-goals, unchanged

Alerting. Identity resolution across MAC randomization. Any new capture path or schema change.
Follow-detection across locations.

## Decision 6 — the panel is opt-in and audited (v1 finding 19 / v2 finding 11)

Even with no score, iterating `/devices/{mac}/copresence` across every MAC reconstructs an
association graph; a stolen operator session can request 20,000 endpoints even though each page
shows 25.

**Decided**: the panel ships behind a **capability toggle that is off by default**, and every
co-presence query is **audit-logged**. A stolen session cannot enumerate a feature that is not
enabled, which is the only control here that changes the exposure rather than slowing it — rate
limiting alone merely paces exfiltration. The route must return the same response when the
capability is off as when the device does not exist, so the toggle is not itself a probe oracle.

This also means the feature cannot be reached by accident, which matters for a capability whose
output is a list of devices that keep appearing near a person.
