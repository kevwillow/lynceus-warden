# Device co-presence correlation — design v1 (WITHDRAWN)

> ⛔ **WITHDRAWN. Do not implement this. It is kept only so the reference in
> `2026-08-02-co-observation-explorer-design.md` resolves, and so the reason it
> failed is not lost.**
>
> **Superseded by** `2026-08-02-co-observation-explorer-design.md`, which is
> implemented.
>
> **Why it was withdrawn.** The `lift` statistic this document specifies was
> measured returning **`10.000 / strong`** for the always-present neighbour it
> existed to demote, ranking it *above* a genuine follower, with `ambient`
> reading `False`. Reproduced against the built scorer on 2026-08-03:
>
> ```
> aa:always:on     lift= 10.000  band=strong   ambient=False
> bb:follows:you   lift=  8.000  band=strong   ambient=False
> ```
>
> The flaw is structural, not a tuning problem. A device present whenever the
> anchor is present has `observed = together / candidate_visits = 1.0` **by
> construction**, so `lift = 1 / base_rate` — meaning the *rarer* the anchor,
> the *higher* an ambient device scores. The `ambient` flag keys off
> `lift <= 1.5`, which such a device can never reach. The numerator counts
> visits while the denominator measures time, and this document's own module
> docstring conceded that mismatch.
>
> A second, independent defect: the query segments **every MAC in the window**
> before filtering, roughly 259M rows at 2,000 devices over 90 days.
>
> ⚠️ The replacement makes **no statistical claim at all**, deliberately: sensor
> uptime is not recorded anywhere in the schema, so absence of data cannot be
> distinguished from absence of a device, and no score is defensible. A score
> computed anyway carries false authority exactly where a false positive tells a
> frightened person that a specific neighbour is following them.

---

# Device co-presence correlation — design

**Date**: 2026-08-02
**Status**: ⛔ **WITHDRAWN 2026-08-03 — never implemented, and must not be.** (The line below
read "approved design, not yet implemented" and is preserved here only to show what it said;
approval was withdrawn once the statistic was measured. See the header.)
**Depends on**: nothing new. Runs on `sightings` (migration 001) and
`devices.probe_ssids` / `devices.is_randomized` as they exist today.

## Problem

The operator can see that a device was here, and that another device was here.
They cannot see that the two keep turning up *together*. That relationship is the
difference between "a phone passed by" and "a phone that is where I am, when I am,
repeatedly" — and it is currently invisible, even though every byte needed to
compute it is already in the database.

This design adds a read-only view that surfaces the relationship and shows its
evidence. It does not raise alerts, and it deliberately does not decide anything.

## Non-goals

- **Alerting.** No rule type, no scheduled evaluation, no notification. A false
  positive here tells someone that a specific person is following them. That
  judgement stays with the operator until real captures give us a false-positive
  rate. Revisit only then.
- **Identity resolution across MAC randomization.** Linking a phone's rotating
  MACs into one logical device is a separate, harder arc. See "Coverage ceiling".
- **Any new capture path.** No new fields, no new probes, and no schema change is
  required to ship this. `capture.probe_ssids` stays off by default. (One optional
  covering index is discussed under "Visit segmentation"; it is a performance
  follow-up to be added only if measured, not part of the feature.)
- **Follow-detection across locations.** The BLE Continuity decoder design already
  records this as a later arc wanting a real capture corpus. Unchanged.

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Unit of inference | Co-presence between two distinct devices | Not "one phone across MACs"; that is identity resolution, deferred |
| Anchor | Device-anchored panel on `/devices/<mac>` | Bounded query cost; matches the workflow, where the operator arrives with a device in mind |
| Segmentation | Gap-split visits, default 15 min | One 6-hour stay counts once, not 360 times; survives a missed poll tick |
| Ranking | Co-presence lift against corpus base rates | The whole defence against confident nonsense |
| Probe SSIDs | Corroborating evidence only | Ranking must work with probe capture off, which is the default |
| Output | Evidence + confidence band | Never a bare score, never a verdict |
| History window | 30 days by default, configurable | `sightings` is never pruned; an unbounded scan is not viable |

## Architecture

Three units with one job each.

### 1. `Database.list_copresence_candidates()`

SQL only. Segments visits, counts overlaps, returns raw integers. It makes no
judgements and computes no scores, so its tests are about counting, not opinion.

```python
def list_copresence_candidates(
    self,
    mac: str,
    *,
    since_ts: int,
    gap_seconds: int = 900,
    limit: int = 25,
) -> list[dict]
```

Each row carries `mac`, `together`, `candidate_visits`, plus the anchor-level
`anchor_visits`, `anchor_present_seconds` and `observed_seconds` needed to score it.
Defined precisely, because the scorer's meaning depends on it:

| Field | Meaning |
|---|---|
| `together` | Count of the **candidate's** visits that overlapped any anchor visit |
| `candidate_visits` | The candidate's total visits within the window |
| `anchor_visits` | The anchor's total visits within the window. Display context only; the formula does not use it |
| `anchor_present_seconds` | Summed duration of the anchor's visits within the window |
| `observed_seconds` | Total seconds spanned by the window itself, i.e. `now - since_ts`, not the union of anyone's visits |

### 2. `src/lynceus/copresence.py`

A pure module, stdlib only, no project imports beyond a dataclass. Takes the counts
above and returns a scored finding. Never touches a database, never raises.

```python
def score(
    *,
    together: int,
    candidate_visits: int,
    anchor_present_seconds: int,
    observed_seconds: int,
    shared_rare_ssids: tuple[SharedSsid, ...] = (),
) -> CopresenceFinding
```

This is the same split that `ble_continuity.py` and `ble_bridge_checks.py` already
use: the judgement lives in a total function that can be table-tested exhaustively
without fixtures.

### 3. The panel

A section on `/devices/<mac>`, collapsed by default and loaded on demand via htmx,
following the reveals-collapsed pattern `/probes` already uses. Lazy-loading matters
here: this is the one query in the request path that scans a time range rather than
hitting a single indexed row.

## Visit segmentation

SQLite window functions over `sightings`, using the existing `idx_sightings_mac_ts`:

```sql
WITH marked AS (
  SELECT mac, ts, location_id,
         CASE WHEN ts - LAG(ts) OVER (PARTITION BY mac ORDER BY ts) > :gap
              THEN 1 ELSE 0 END AS is_new
  FROM sightings
  WHERE ts >= :since_ts
),
numbered AS (
  SELECT mac, ts, location_id,
         SUM(is_new) OVER (PARTITION BY mac ORDER BY ts) AS visit_no
  FROM marked
),
spans AS (
  SELECT mac, location_id, visit_no,
         MIN(ts) AS start_ts, MAX(ts) AS end_ts
  FROM numbered
  GROUP BY mac, visit_no
)
```

A gap longer than `gap_seconds` closes a visit. Two visits co-occur when their
intervals intersect and share a `location_id`:

```sql
a.start_ts <= b.end_ts AND b.start_ts <= a.end_ts
AND a.location_id = b.location_id
```

**Cost is controlled by anchoring first.** The anchor's spans come from a single
indexed `mac` lookup. Candidate sightings are then restricted to those time windows
via `idx_sightings_ts`. The all-pairs computation never happens, and a device that
is rarely present prunes the scan to almost nothing. `since_ts` bounds the rest.

If profiling later shows the candidate scan is fetching rows to read `mac`, a
covering index on `sightings(ts, mac)` would make it index-only. That is a one-line
migration and should be added only if measured, not on suspicion.

## Scoring

```
observed = together / candidate_visits
expected = anchor_present_seconds / observed_seconds
lift     = observed / expected
```

`observed` is the fraction of the candidate's own visits that coincided with the
anchor. `expected` is the prior probability that any given moment is one where the
anchor is present.

This is what discounts ambient devices. A neighbour's always-on Raspberry Pi
co-occurs with everything, so its `observed` converges on `expected` and its lift
converges on 1. It is tagged **ambient** and sorted below genuinely correlated
devices, rather than dominating the list by sheer volume — which is exactly the
"confident nonsense" outcome rarity weighting exists to prevent.

⚠️ **This is a heuristic, not a calibrated probability.** The numerator counts
visits and the denominator measures time, so `lift` is interpretable and correctly
ordered but is not a likelihood ratio and must never be rendered as one. It carries
no units and no error bars.

### Confidence bands

`weak` / `moderate` / `strong`, derived from lift, absolute support and
corroboration. Absolute support gates the top: fewer than five co-occurrences can
never exceed `weak`, so two coincidences cannot read as meaningful no matter how
extreme the lift. A band is always shown *alongside* its inputs, never instead of
them.

### Probe SSIDs

Additive evidence only. A shared SSID is displayed with its corpus rarity, counted
by unnesting `devices.probe_ssids` with `json_each` exactly as `list_probe_ssids`
already does:

```
+ shares "chalkfarm-guest" (2 devices in corpus have ever probed it)
```

Two devices sharing `attwifi` means nothing; two sharing an odd SSID is close to
conclusive that they belong to one household or workplace. Rarity is what separates
those, so the count is always shown.

Corroboration may raise a band. It never creates a row and never changes ordering.
With `capture.probe_ssids` off — the default — rows render identically minus that
line, which is the property that keeps the feature useful for a stock install.

## Coverage ceiling

State these in the UI, not only here. Every one of them makes the view weaker than
a naive reading suggests.

- ⚠️ **Randomized MACs fragment the history, and they fragment it worst for the
  devices that matter most.** A phone that rotates its MAC becomes a new `devices`
  row with a fresh visit count, so a long-running relationship is split across
  several short ones and systematically *under*-counted. The modern phone this arc
  most wants to correlate is the one it sees least well. This is the direct
  analogue of the wildcard-probe ceiling that shaped the original PNL framing: a
  bound to cite, not a target to chase. Closing it means identity resolution.
- **Co-presence at a fixed sensor means "both were near my sensor."** In a home or
  an office the honest prior is housemates, neighbours, and the operator's own
  devices. Benign explanations dominate and the copy must say so.
- **`location_id` is `"default"` unless `kismet_source_locations` is configured**,
  so the same-location constraint usually admits everything and discriminates
  nothing.
- **Base rates drift.** `sightings` is never pruned, so the corpus is all-time. A
  neighbour who moved out six months ago still weights the denominator. The 30-day
  window limits the numerator but the drift is real.
- **The probe-SSID cap freezes early.** `merge_device_probe_ssids` appends then
  truncates at `PROBE_SSIDS_PER_DEVICE_CAP = 50`, so once a device reaches the cap
  every later SSID is dropped. Corroboration is biased toward what was seen first,
  and absent entirely for devices that hit the cap long ago.
- **Probe capture is off by default**, so most installs get no corroboration at all.

## Error handling

The scorer is total: zero visits, zero observed seconds and a zero denominator all
return a finding with lift `None` and band `weak` rather than raising or dividing by
zero. A device with no sightings in the window yields an empty list, which the
panel renders as "nothing to show", not as an error. Malformed `probe_ssids` JSON is
already tolerated by the existing readers and is skipped the same way here.

## Testing

- **Scorer**, table-driven and exhaustive: ambient device converges on lift ≈ 1;
  low support cannot exceed `weak`; zero denominators return `None` rather than
  raising; corroboration raises a band but never reorders.
- ⭐ **The load-bearing guard**: a device present 100% of the time must rank
  *below* one co-present in 38 of 41 visits. That is the confident-nonsense failure
  written down as a test, and it should be verified by mutation — break the lift
  denominator and confirm this test is what goes red.
- **Segmentation**, on seeded `sightings` fixtures: a gap exactly at the threshold
  does not split; a gap one second over does; a single missed poll tick does not
  split a visit; one long stay counts as one visit.
- **Overlap**, including the boundary case where one visit ends on the exact second
  another begins.
- **Rendering** with `capture.probe_ssids` off, proving the panel is complete
  without corroboration.

## Open questions

- Whether the 30-day default is right, or whether the window should adapt to how
  sparse the anchor's history is. Decide against a real corpus.
- Whether `sightings` needs a retention policy of its own. Out of scope here, but
  this design is the first consumer that scans the table by time range rather than
  by `mac`, so it is the first thing that will feel the unbounded growth.
