# Find My / Apple Continuity BLE payload decoder — design

**Date**: 2026-07-28
**Status**: approved design, not yet implemented
**Depends on**: the passive BLE bridge (`07c561a`, `bb3d51c`, `ecfbf89`)

## Problem

Every Apple BLE device advertises under Bluetooth SIG company id `004c`. Matching
on `ble_manufacturer_id` alone therefore alerts on every iPhone, AirPods, and Watch
in range — the reason BLE-G1 blocks enabling the bridge. The discriminator that
separates a tracker from a passer-by's earbuds lives in the Apple Continuity
advertisement payload, not in the company id.

This decoder turns `004c` into a device class, which is what makes the bridge
safely enableable.

## Non-goals

- Follow-detection (a tracker persisting across locations) — a later arc that
  wants the real-world capture corpus the stalking-heuristics backlog entry
  describes.
- Decoding Continuity types beyond the three below.
- Any active BLE behavior. The passive-only stance is unchanged: observe and
  match, never connect, pair, or probe.

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Payload retention | Decode in the bleak callback; retain only the derived label | Keeps "we never retain advertisement content" literally true |
| Decoder scope | Find My, proximity-pairing (AirPods), Nearby | Correct alerting plus useful triage; wider set costs a lookup table |
| Match surface | Standalone `ble_device_class` rule type in rules.yaml | The class is an observation property, not a curated identifier |
| Persistence | `devices.ble_device_class` column + UI | Makes ambient Apple devices legible instead of identical `004c` rows |

## Architecture

New module `src/lynceus/ble_continuity.py`, a total pure function:

```python
classify(company_id: int, payload: bytes) -> str | None
```

Stdlib only, no project imports. Returns `None` for any non-Apple company id and
for unparseable input. Never raises. It is the only code in the project that sees
raw advertisement bytes, and nothing it returns contains them.

Class vocabulary: `find_my`, `find_my_separated`, `airpods`, `nearby`,
`apple_unknown`.

### TLV iteration and priority

A Continuity payload may carry several concatenated type-length-value messages —
a phone can emit Nearby and Find My in the same advert. `classify` walks the whole
TLV chain and resolves to the single highest-priority class found:

```
find_my_separated > find_my > airpods > nearby > apple_unknown
```

Surveillance-relevant classes outrank ambient ones, so a tracker is never masked
by a co-emitted Nearby message. Walking stops at the first malformed length rather
than attempting to resync; a partial result from a bad parse is worse than none.

### Confidence split

The message-type byte is well established. The Find My status bit is not. The
design contains that uncertainty rather than spreading it:

- `find_my`, `airpods`, `nearby` derive from the **type byte** — trustworthy
  immediately, ship enabled.
- `find_my_separated` derives from one named constant,
  `_FIND_MY_SEPARATED_MASK`, whose docstring states it is unvalidated and pending
  a real rig capture — the same treatment `_DRONE_ID_PATHS` receives for D2.

The shipped rule example matches `find_my`, which is correct however the mask
resolves. Promoting `find_my_separated` into the alerting set is a one-line
rules.yaml edit after rig validation. No guessed bitmask gates the arc.

## Data flow

```
bleak callback
  -> _record_advert: classify(cid, bytes) -> label; bytes die with the local
  -> _BufferEntry.device_class (label only)
  -> _build_observation: ble_device_class=<label>
  -> process_observation (unchanged)
       -> upsert_device  -> devices.ble_device_class
       -> rules.evaluate -> ble_device_class rule -> RuleHit -> alert + ntfy
```

## Components

### 1. `src/lynceus/ble_continuity.py` (new)

Constants for the Apple company id and the three message types; the priority
ordering; `_FIND_MY_SEPARATED_MASK` with its pending-validation docstring.

### 2. `src/lynceus/bridges/ble.py`

- `_record_advert` gains one call into the decoder. `manufacturer_data` arrives
  as `{company_id: payload_bytes}`; iterate items, classify each, keep the
  highest-priority label. The existing company-id key extraction is unchanged.
  Raw bytes never leave the callback scope.
- `_BufferEntry` gains `device_class: str | None`.
- `_build_observation` passes `ble_device_class=entry.device_class`.
- The stale comment at `_build_observation` claiming "ble fields get blanked"
  is corrected to name only `ble_service_uuids` (see below).

### 3. `src/lynceus/kismet.py`

`DeviceObservation` gains `ble_device_class: str | None = None`.

**Accuracy note**: the `_drop_uuids_for_non_ble` model validator currently blanks
only `ble_service_uuids` — `ble_manufacturer_id` is not blanked. Extend that
validator to also blank `ble_device_class` when `device_type != "ble"`, since a
class is meaningless on a non-BLE observation. Two lines; prevents a nonsense
value persisting if a future caller sets the field wrongly.

The Kismet poll path leaves the field `None` permanently — classic HCI has no
payload — so there is no Kismet-side behavior change.

### 4. Migration `023_devices_ble_device_class.sql` (+ `_down`)

Adds nullable `ble_device_class TEXT` to `devices`. Confirmed 022 is current.

### 5. `src/lynceus/db.py`

`upsert_device` writes the class **coalescing, not clobbering**: an advert that
decodes to `None` must not erase a previously stored class. Adverts are
intermittent, and a device that showed Find My once should not silently lose that
label on the next partial capture. This gets a dedicated test — it is the kind of
thing that regresses quietly.

### 6. `src/lynceus/rules.py`

- `RuleType` literal gains `ble_device_class`.
- Validator branch **requires non-empty patterns** — the inverse of
  `watchlist_mac_range`. Empty patterns mean "delegate to the watchlist DB" in the
  existing convention, and there is no watchlist behind this type.
- `evaluate()` gains a branch: set membership of `obs.ble_device_class` against
  `rule.patterns`. Severity comes from rules.yaml (config-driven, not delegated).

### 7. `config/rules.yaml`

A commented-out example matching `find_my`, mirroring how
`argus_ble_manufacturer_id` ships commented.

### 8. Web UI

A class column on `/devices` and a row on device detail, rendering a neutral
em-dash when `None` — following the Category column convention from 0.9.2 rather
than inventing a new empty-state treatment.

## Error handling

The decoder is total, so there is no call-site try/except to get wrong.
Non-Apple company ids return `None` before any parsing. Truncated, zero-length,
and malformed-length payloads return `None`. The bridge's existing
per-observation containment covers everything downstream; no new failure mode
reaches the poll loop.

## Testing

- **Decoder** — byte-vector table tests: each message type, multi-TLV priority
  resolution, truncated and zero-length payloads, bad length bytes, non-Apple
  company id, empty dict.
- **Privacy regression** — assert `_BufferEntry` exposes no raw payload and that
  `_record_advert` retains only the label. This test is what keeps the retention
  invariant from eroding later; it is the reason this approach is defensible.
- **Rules** — match, non-match, and the empty-patterns validation error.
- **DB** — migration up/down, and the coalescing upsert.
- **UI** — column renders; em-dash on `None`.

Tests are gitignored in this repo (OPSEC) and are not committed.

## Implementation phasing

Each step is independently testable and leaves the tree green:

1. Decoder module + tests (no wiring — pure, verifiable in isolation)
2. Bridge wiring + `DeviceObservation` field + privacy regression test
3. Migration 023 + coalescing upsert
4. `ble_device_class` rule type + rules.yaml example
5. UI column + detail row

## Open item carried forward

`_FIND_MY_SEPARATED_MASK` needs validation against a real rig capture before
`find_my_separated` is promoted into any alerting rule. Track alongside the D2
drone field-path entry — same shape: matcher built and tested, one runtime fact
obtainable only from hardware.
