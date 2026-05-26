# Bundled threat-data notice

`default_watchlist.csv` in this directory is a snapshot exported from
[Argus](https://github.com/kevwillow/argus-db), a sibling project that curates
identifiers (OUIs, MAC ranges, individual MACs, BLE manufacturer IDs, drone
Remote-ID prefixes, and SSIDs) associated with surveillance and tracking
equipment.

## Snapshot

- **Source:** Argus CSV export (`schema_version=30`)
- **Exported at:** 2026-05-25T02:33:05Z
- **Records:** 41428
- **Identifier types (admitted, 23571 of 41428 rows):**
  17804 mac_range, 4684 ble_manufacturer_id (incl. ble_company_id alias),
  462 oui, 427 drone_id_prefix, 139 ble_uuid (incl. ble_service /
  ble_service_uuid aliases), 30 SSID (24 ssid_pattern + 6 ssid_exact alias
  to ssid), 21 ble_local_name, 4 mac.
- **Dropped at import:** ~17857 rows across residual identifier types
  Argus has added since the last bundle refresh
  (see `docs/ARGUS_RESIDUALS.md` for the per-type breakdown).

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
