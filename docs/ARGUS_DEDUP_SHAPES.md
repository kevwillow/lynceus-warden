# Argus Dedup Shapes Audit

Generated: 2026-05-21
Argus snapshot: `src/lynceus/data/default_watchlist.csv`
Argus schema_version: 21
Argus record_count (meta): 22533
Total CSV rows: 22533

Sibling of [`ARGUS_RESIDUALS.md`](ARGUS_RESIDUALS.md), which audits
the dropped pattern *types*. This document audits the dropped
pattern *rows* — Argus emissions that the Lynceus importer's per-
row dispatch gates so the bundled-CSV no-op re-import is
idempotent (v0.6.0). Two bucket shapes:

- **Bucket A — peer-collide via natural-key collision.** Argus
  emits two or more rows with distinct `argus_record_id`s that
  the Lynceus canonicalizer collapses to the same `(pattern,
  pattern_type)`. First row admitted; peers gated to
  `dropped_peer_collision`.
- **Bucket B — within-import duplicate `argus_record_id` with
  content drift.** Argus emits the same `argus_record_id` 2-3×
  within a single CSV with different metadata fields. First
  occurrence admitted; later occurrences gated to
  `dropped_in_import_dup`.

Both buckets originate in Argus emissions. Lynceus gates these
rows at import time as a layered defense; the canonical fix is
upstream-side canonicalization in Argus. This document captures
the Lynceus-side evidence and remains the authoritative
inventory for why specific rows are gated even if upstream
cleanup hasn't landed.

## Bucket A — peer-collide via natural-key collision

15 groups, 31 rows, 16 gated peers (sum members − 1 per group).
0 of 15 groups differ on `device_category` — the original BACKLOG
hypothesis was falsified. The actual discriminator is
`manufacturer` (vendor-name shape drift across crowdsourced and
canonical-IEEE feeds), case/leading-zero normalization, and
dual-form CIDR/bare-prefix rendering.

### Breakdown by pattern_type

| pattern_type | groups | rows |
|---|---|---|
| `mac_range` | 8 | 16 |
| `ble_manufacturer_id` | 6 | 13 |
| `ble_uuid` | 1 | 2 |

### `mac_range` legacy bare-prefix vs CIDR (8 groups)

Argus emitted the same prefix range twice — once as a legacy bare
prefix string (e.g. `10:63:a3:1`) and once as the canonical CIDR
form (e.g. `10:63:a3:1/28`). Both canonicalize via
`canonicalize_mac_range_pattern` to the CIDR form. Manufacturer
strings differ between the two (full IEEE-registered name vs
shorthand). All `device_category="unknown"`.

| canonical pattern | argus_record_ids | manufacturers (raw) |
|---|---|---|
| `10:63:a3:1/28` | `9f9f5f687fcacdc4`, `680c0ee96dc158ee` | Jacobs / Jacobs Technology, Inc. |
| `8c:1f:64:a9:8/36` | `b75eecc481e8be2a`, `ac6775957e93ac7f` | Jacobs / Jacobs Technology, Inc. |
| `70:b3:d5:7c:b/36` | `5dbcec4e3576bc7e`, `f2afff8bc97e7f72` | KeyW / KeyW Corporation |
| `70:b3:d5:98:7/36` | `45d38a052c7edd14`, `61e8bb5f20e7d8f2` | Axis Communications / AXIS CORPORATION |
| `00:50:c2:2a:5/36` | `51a6820b4c5b770c`, `b273a32fabad161a` | Septier / Septier Communication Ltd |
| `00:50:c2:36:0/36` | `bd03be93a4feca40`, `8969421d67270115` | Digital Receiver Technology (same on both) |
| `00:50:c2:a3:2/36` | `9f2b46bbcab904fb`, `20b4238f91a61816` | Harris / Harris Designs of NRV, Inc. |
| `00:50:c2:be:7/36` | `148de34cadb52fd8`, `bab7d7789413ce46` | Genetec / Genetec Inc. |

### `ble_manufacturer_id` case / leading-zero variants (6 groups)

Argus emitted the same 16-bit Bluetooth SIG manufacturer ID twice
or more — sometimes as the canonical 4-hex-char string, sometimes
with a shorter representation. `normalize_pattern("ble_manufacturer_id", …)`
folds both shapes to lowercase canonical 4-hex. Manufacturer
strings differ (IEEE-registered name vs blank).

| canonical pattern | argus_record_ids | raw identifiers | mfgs |
|---|---|---|---|
| `004c` | `e3d910aa58b6c6fa`, `8ec06543743079d7`, `438e8b02d97a2714` | `0x004C`, `0x4C`, `0x004C` | Apple, Inc. / `<blank>` / `<blank>` |
| `02ff` | `06dd1ab4fced910c`, `7bd2b2995ac48732` | `0x02FF`, `0x02FF` | Silicon Laboratories / `<blank>` |
| `022b` | `c927c5178dce8742`, `db0c6407d189198f` | `0x022B`, `0x022B` | Tesla, Inc. / `<blank>` |
| `022a` | `a052312922edd271`, `f506aef7e0180d2e` | `0x022A`, `0x022A` | Stamer Musikanlagen GMBH / `<blank>` |
| `0183` | `f7495b2ac06a42bc`, `a0ffc786e80394da` | `0x0183`, `0x0183` | Walt Disney / `<blank>` |
| `010c` | `8df00a86bc1475ce`, `285f963670394ab2` | `0x010C`, `0x010C` | Transducers Direct, LLC / `<blank>` |

The `004c` group has 3 distinct argus_record_ids (Apple, Inc.,
plus two blank-vendor records — one as `0x4C` short-form, one as
`0x004C`). This is the only 3-member group in Bucket A.

### `ble_uuid` short-form (1 group)

| canonical pattern | argus_record_ids | raw identifiers |
|---|---|---|
| `0000fd44-0000-1000-8000-00805f9b34fb` | `1d584ff62e9c33fe`, `0605a36eacc5ccd2` | `fd44`, `0000fd44` |

Both raw shapes are valid Bluetooth SIG 16-bit assigned-number
shorthand; `normalize_pattern("ble_uuid", …)` expands to the full
128-bit form via the standard base UUID
(`0000XXXX-0000-1000-8000-00805F9B34FB`).

## Bucket B — within-import duplicate `argus_record_id` with content drift

12 sets, 25 rows, 13 raw "extra" rows (sum c−1 per set). Of those
13, 11 reach the within-import-dup gate and increment
`dropped_in_import_dup`; the remaining 2 belong to two sets whose
`identifier_type` is `ble_protocol_byte_table` — not in
`IDENTIFIER_TYPE_MAP`, so all occurrences are dropped to
`dropped_unknown_type` before reaching the seen-argus_ids gate.

The dominant shape is Argus's `primary_registry` vs `crowdsourced`
OUI overlay for drone vendors: Argus emits one row from the IEEE
MA-L OUI registry (high confidence, vendor name populated) and
one or more rows from crowdsourced recon-tool observations (lower
confidence, vendor name blank). Both rows carry the same Argus
record id because Argus models them as one record with multiple
source citations.

### `oui` primary_registry vs crowdsourced overlay (8 sets)

| argus_record_id | count | identifier | content drift |
|---|---|---|---|
| `1c452b196c10dab1` | 3 | `90:3a:e6` | Parrot/`unknown`/conf=85/primary_registry vs ``/`drone`/conf=65/crowdsourced (×2) |
| `2fde1a991a0cd103` | 2 | `48:1c:b9` | DJI/conf=80/primary_registry vs ``/conf=65/crowdsourced |
| `8f6d7a48b568c851` | 2 | `60:60:1f` | DJI/conf=80/primary_registry vs ``/conf=65/crowdsourced |
| `b5dd85cdbeb03302` | 2 | `00:12:1c` | Parrot/`unknown`/conf=85/primary_registry vs ``/`drone`/conf=65/crowdsourced |
| `3680762fce7effc7` | 2 | `90:03:b7` | Parrot/`unknown`/conf=85/primary_registry vs ``/`drone`/conf=65/crowdsourced |
| `e6f69467b726c22c` | 2 | `a0:14:3d` | Parrot/`unknown`/conf=85/primary_registry vs ``/`drone`/conf=65/crowdsourced |
| `99696ff1930ae2c6` | 2 | `34:d2:62` | DJI/conf=80/primary_registry vs ``/conf=65/crowdsourced |
| `0e6ef5183f5a20a6` | 2 | `00:26:7e` | Parrot/`unknown`/conf=85/primary_registry vs ``/`drone`/conf=65/crowdsourced |

### `ssid_exact` dual device_category (2 sets)

| argus_record_id | count | identifier | content drift |
|---|---|---|---|
| `69248a5dad0c2eab` | 2 | `Flock` | Flock Safety/`gunshot_detect`/conf=65 vs Flock Safety/`alpr`/conf=65 |
| `ef29f65fa5ed8a78` | 2 | `Flock-230503` | Flock Safety/`gunshot_detect`/conf=65 vs Flock Safety/`alpr`/conf=65 |

Flock Safety operationally ships both ALPR cameras and the
Raven gunshot-detection product. Argus models both `device_category`
classifications per row by emitting two copies sharing the same
`argus_record_id`. The Lynceus first-occurrence-wins gate binds
the watchlist row to whichever category Argus emits first
(`gunshot_detect` in the current snapshot). For severity-override
edge cases that depend on which category survives, the v0.7.0+
schema-side rework outlined in BACKLOG is the structural fix; the
v0.6.0 gate keeps the operational counters honest in the
meantime.

### `ble_protocol_byte_table` (2 sets, gated upstream as unknown_type)

| argus_record_id | count | identifier_type | dropped at |
|---|---|---|---|
| `dd792e9c8772afb6` | 2 | `ble_protocol_byte_table` | `dropped_unknown_type` (not in IDENTIFIER_TYPE_MAP) |
| `2e09e621034d5b02` | 2 | `ble_protocol_byte_table` | `dropped_unknown_type` (not in IDENTIFIER_TYPE_MAP) |

These don't count toward `dropped_in_import_dup` (the
within-import-dup gate fires after type validation). They're
included here for inventory completeness; both occurrences land
in `dropped_unknown_type` per the residual-types audit in
[`ARGUS_RESIDUALS.md`](ARGUS_RESIDUALS.md).

## Summary

- **Bucket A peer-collide gated**: 16 rows
  - 8 `mac_range`, 6 `ble_manufacturer_id`, 1 `ble_uuid`
    (one 3-member group; 14 two-member groups)
- **Bucket B within-import dup gated**: 11 rows
  - 8 `oui` primary_registry/crowdsourced overlay sets (8 extras)
  - 2 `ssid_exact` Flock dual-category sets (2 extras)
  - 1 `oui` 3-member set contributing the 11th extra
- **Total dropped at import-side dedup gates**: 27 rows
- **Bundled-CSV first import after gates**: 22289 imported_new /
  16 dropped_peer_collision / 11 dropped_in_import_dup / 217
  dropped_unknown_type / 22533 total_rows (invariant balances)
- **Bundled-CSV no-op re-import**: 1 mutating SQL statement (the
  `import_runs` staleness-signal INSERT); 0 writes to `watchlist`
  or `watchlist_metadata`

## Upstream tracking

These shapes originate in Argus emissions. The upstream-side fix
is per-record canonicalization in Argus — emit one record per
canonical `(pattern, pattern_type)` shape, merging
manufacturer / source / category per a documented policy; emit
one record per `argus_record_id` (no within-CSV duplication).

Tracking against the Argus repo
(`kevwillow/argus-db#TBD`, issue to be filed by the operator
out-of-band against the Argus repo). The Lynceus-side gates
remain in place as defense-in-depth regardless of upstream
landing — first-wins is operationally honest; rejecting the
duplicate emission entirely would silently lose Argus-side
information.

## Methodology

Bucket A and Bucket B are derived by an independent parse pass
against the bundled CSV, separate from the importer's own
counters (which are themselves the path being audited):

- `parse_argus_csv` reads rows; `IDENTIFIER_TYPE_MAP` filters
  unknown identifier types.
- For each survivor: `normalize_pattern` (or
  `parse_mac_range_pattern` + `canonicalize_mac_range_pattern`
  for the `mac_range` family) yields the canonical
  `(pattern, pattern_type)` tuple. Rows are grouped by that
  tuple.
- A group is in Bucket A if it has more than one distinct
  `argus_record_id` member; Bucket B is the set of
  `argus_record_id`s appearing more than once across all rows.
- The two buckets are disjoint at the canonical-pattern level
  for the current snapshot — all 15 nk-collide groups contain
  argus_record_ids that appear exactly once, and all 12
  dup-argus_record_id sets resolve to a single canonical
  pattern per set.

The diagnostic test
`tests/test_diag_import.py::test_diag_import_argus_bundled_csv_dedup_shapes`
runs this analysis end-to-end against the actual bundled CSV,
exercises the importer twice, and pins the second-run mutation
count plus the bucket inventory cross-check. Its output lands
in `tests/diagnostic_output/test_diag_import_argus_bundled_csv_dedup_shapes.log`.

## Re-running

    .venv/Scripts/python.exe -m pytest -m diagnostic \
        tests/test_diag_import.py::test_diag_import_argus_bundled_csv_dedup_shapes

Re-run after each Argus snapshot refresh; the diagnostic log
regenerates against the new CSV. If the bucket-A pattern_type
breakdown shifts (e.g. a new `pattern_type` joins the
peer-collide class), this document needs an entry refresh. If
Bucket B drops to zero, upstream canonicalization has landed and
the within-import-dup gate moves to defense-only.
