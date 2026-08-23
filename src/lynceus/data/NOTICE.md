# Bundled threat-data notice

`default_watchlist.csv` in this directory is a snapshot exported from
[Argus](https://github.com/kevwillow/argus-db), a sibling project that curates
identifiers (OUIs, MAC ranges, individual MACs, BLE manufacturer IDs, drone
Remote-ID prefixes, and SSIDs) associated with surveillance and tracking
equipment.

## Snapshot

- **Source:** Argus CSV export (`schema_version=31`)
- **Exported at:** 2026-06-03T16:50:47Z
- **Records:** 41518
- **Locally re-cut:** 2026-08-22. 32 `ssid_pattern` / `ble_local_name`
  identifiers shipped as Python regexes into columns Lynceus matches as
  literal case-insensitive substrings, so they could never match anything
  while `/watchlist` and `/healthz.json` graded them live. They are re-cut as
  literal stems; a handful that no literal stem can express safely were
  dropped. The file is therefore no longer a byte-for-byte Argus export --
  hence `local_recut=` in its meta line.
- **Identifier types (admitted, 23566 of 41518 rows):**
  17806 mac_range, 4684 ble_manufacturer_id (incl. ble_company_id alias),
  444 oui, 427 drone_id_prefix, 140 ble_uuid (incl. ble_service /
  ble_service_uuid aliases), 41 SSID (35 ssid_pattern + 6 ssid_exact alias
  to ssid), 20 ble_local_name, 4 mac.
- **Dropped at import:** 17952 rows across residual identifier types
  Argus has added since the last bundle refresh
  (see `docs/ARGUS_RESIDUALS.md` for the per-type breakdown).

⚠️ **Every count above was RE-MEASURED on 2026-08-22 and five of them were
already wrong** -- before the re-cut, not because of it. The file said 17796
mac_range (17806), 4674 ble_manufacturer_id (4684), 417 oui (444), 75 ble_uuid
(140) and ~18067 dropped (17952). A provenance document that drifts from the
data it describes is worse than none, because it is read as authority. If you
change the CSV, re-derive this block rather than adjusting it:
`tests/test_bundled_oui_corpus_census.py` pins the totals and will tell you
they moved, but only the totals.

This snapshot is provided as a development starting point so that a fresh
Lynceus install has useful threat data on day one. It is not authoritative
beyond the export date and will become stale as Argus accumulates new
findings.

## Refreshing

To replace the bundled snapshot with a newer Argus export at runtime:

    lynceus-import-argus --input <path-to-fresh-export.csv>

Or pull the latest published snapshot directly from the Argus GitHub release:

    lynceus-import-argus --from-github

Operators who maintain their own Argus instance can drop a fresh export over
this file and rebuild the wheel; that is how new Lynceus releases pick up
upstream Argus changes.
