# Bundled threat-data notice

`default_watchlist.csv` in this directory is a snapshot exported from
[Argus](https://github.com/kevlattice/argus), a sibling project that curates
identifiers (OUIs, MAC ranges, individual MACs) associated with surveillance
and tracking equipment.

## Snapshot

- **Source:** Argus CP11-format CSV export (`schema_version=8`)
- **Exported at:** 2026-05-07T20:17:59Z
- **Records:** 63
- **Identifier types:** 54 OUI, 8 mac_range, 1 mac

This snapshot is provided as a development starting point so that a fresh
Lynceus install has useful threat data on day one. It is not authoritative
beyond the export date and will become stale as Argus accumulates new
findings.

## Refreshing

To replace the bundled snapshot with a newer Argus export at runtime:

    lynceus-import-argus --input <path-to-fresh-export.csv>

Operators who maintain their own Argus instance can drop a fresh export over
this file and rebuild the wheel; that is how new Lynceus releases pick up
upstream Argus changes.
