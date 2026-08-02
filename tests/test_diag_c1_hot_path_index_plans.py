"""Diagnostic: C1 — hot-path queries and whether they SCAN or SEARCH at
Argus scale, on the real migrated schema with ~30k seeded rows.

VERIFY-ONLY. No production code is touched. Observation-only dump.

Hot paths under scrutiny (exact SQL traced to current main):
  1. watchlist-eval simple equality  (db.py:748-756, _lookup_simple_watchlist_match)
        WHERE w.pattern_type = ? AND w.pattern = ?
  2. watchlist-eval mac_range         (db.py:898-908, _resolve_mac_range_eval)
        WHERE w.pattern_type='mac_range' AND mac_range_prefix_length=? AND mac_range_prefix=?
  3. /devices list                    (db.py:1947-1956, list_devices default sort)
        FROM devices ORDER BY last_seen DESC, mac LIMIT ? OFFSET ?
  4. /alerts list                     (db.py:1432-1434 + 1377, list_alerts)
        FROM alerts a LEFT JOIN watchlist ... ORDER BY a.ts DESC, a.id DESC LIMIT ? OFFSET ?

All indexes on the migrated schema (enumerated from migrations):
  sightings(mac,ts), sightings(ts), alerts(ts), alerts(acknowledged) partial,
  watchlist(mac_range_prefix_length, mac_range_prefix) PARTIAL pattern_type='mac_range',
  watchlist_metadata.watchlist_id UNIQUE (auto), evidence_* , import_runs,
  rule_type_snoozes, watchful_recurrence. NOTE: there is NO index on
  watchlist(pattern_type, pattern) and NO index on devices.last_seen.
"""

from __future__ import annotations

import time

import pytest

from lynceus.db import (
    DEVICES_SORT_EXPRESSIONS,
    Database,
)

pytestmark = pytest.mark.diagnostic

N = 30_000

# Exact SQL strings copied from current main (projection elided where it
# does not affect the query plan; EXPLAIN QUERY PLAN is projection-
# independent for FROM/WHERE/JOIN/ORDER BY).
SQL_WATCHLIST_SIMPLE = (
    "SELECT w.id AS id, w.severity AS severity, "
    "m.device_category AS device_category, m.vendor AS manufacturer, "
    "m.argus_record_id AS argus_record_id "
    "FROM watchlist w "
    "LEFT JOIN watchlist_metadata m ON m.watchlist_id = w.id "
    "WHERE w.pattern_type = ? AND w.pattern = ? LIMIT 1"
)
SQL_WATCHLIST_MAC_RANGE = (
    "SELECT w.id AS id, w.severity AS severity "
    "FROM watchlist w "
    "LEFT JOIN watchlist_metadata m ON m.watchlist_id = w.id "
    "WHERE w.pattern_type = 'mac_range' "
    "AND w.mac_range_prefix_length = ? AND w.mac_range_prefix = ? LIMIT 1"
)


def _devices_list_sql() -> str:
    order_expr = DEVICES_SORT_EXPRESSIONS["last_seen"]
    tiebreak = "" if order_expr == "mac" else ", mac"
    return (
        "SELECT mac, device_type, first_seen, last_seen, sighting_count, "
        "oui_vendor, is_randomized, notes, probe_ssids, ble_name, "
        "(SELECT rssi FROM sightings WHERE sightings.mac = devices.mac "
        "ORDER BY ts DESC, id DESC LIMIT 1) AS last_rssi, "
        "(SELECT ssid FROM sightings WHERE sightings.mac = devices.mac "
        "ORDER BY ts DESC, id DESC LIMIT 1) AS last_ssid "
        f"FROM devices ORDER BY {order_expr} DESC{tiebreak} LIMIT ? OFFSET ?"
    )


SQL_ALERTS_LIST = (
    "SELECT a.id "
    "FROM alerts a "
    "LEFT JOIN watchlist w ON w.id = a.matched_watchlist_id "
    "LEFT JOIN watchlist_metadata m ON m.watchlist_id = w.id "
    "ORDER BY a.ts DESC, a.id DESC LIMIT ? OFFSET ?"
)


def _seed(db: Database) -> None:
    c = db._conn
    c.execute("INSERT INTO locations(id,label) VALUES ('default','Default')")
    # watchlist: 26k simple-equality rows (mac/oui/ssid/ble_uuid) + 4k
    # mac_range rows with the prefix columns populated.
    simple_rows = []
    for i in range(N - 4000):
        pt = ("mac", "oui", "ssid", "ble_uuid")[i % 4]
        simple_rows.append((f"pat-{pt}-{i:08d}", pt, "med", f"d{i}", None, None))
    range_rows = []
    for i in range(4000):
        # 36-bit prefix = 9 hex chars
        range_rows.append(
            (f"range-{i:08d}", "mac_range", "high", f"r{i}",
             f"{i:09x}", 36)
        )
    with c:
        c.executemany(
            "INSERT INTO watchlist(pattern,pattern_type,severity,description,"
            "mac_range_prefix,mac_range_prefix_length) VALUES (?,?,?,?,?,?)",
            simple_rows + range_rows,
        )
    # devices + sightings + alerts at scale.
    dev_rows = []
    sight_rows = []
    alert_rows = []
    for i in range(N):
        mac = f"{i // 256 % 256:02x}:{i % 256:02x}:cc:dd:ee:ff"
        # unique mac via index in two octets won't cover 30k; widen:
        mac = (f"{(i >> 24) & 255:02x}:{(i >> 16) & 255:02x}:"
               f"{(i >> 8) & 255:02x}:{i & 255:02x}:ee:ff")
        dev_rows.append((mac, "wifi", 1_700_000_000 + i, 1_700_000_000 + (i * 7 % 90000),
                         i % 50, "Vend", i % 2, None))
        sight_rows.append((mac, 1_700_000_000 + i, -40 - (i % 50), f"ssid{i%100}", "default"))
        alert_rows.append((1_700_000_000 + (i * 13 % 90000), "rule_x", mac,
                           "msg", ("low", "med", "high")[i % 3], i % 2))
    with c:
        c.executemany(
            "INSERT INTO devices(mac,device_type,first_seen,last_seen,"
            "sighting_count,oui_vendor,is_randomized,notes) VALUES (?,?,?,?,?,?,?,?)",
            dev_rows,
        )
        c.executemany(
            "INSERT INTO sightings(mac,ts,rssi,ssid,location_id) VALUES (?,?,?,?,?)",
            sight_rows,
        )
        c.executemany(
            "INSERT INTO alerts(ts,rule_name,mac,message,severity,acknowledged) "
            "VALUES (?,?,?,?,?,?)",
            alert_rows,
        )
    c.execute("ANALYZE")


def _plan(db: Database, sql: str, params) -> list[str]:
    rows = db._conn.execute("EXPLAIN QUERY PLAN " + sql, params).fetchall()
    return [str(r["detail"]) for r in rows]


def _verdict(plan: list[str]) -> str:
    joined = " | ".join(plan)
    scans = [p for p in plan if p.strip().startswith("SCAN")]
    if scans:
        return f"SCAN PRESENT -> {joined}"
    return f"all SEARCH/indexed -> {joined}"


def test_diag_c1_hot_path_index_plans(diag, tmp_path):
    db = Database(str(tmp_path / "c1.db"))
    diag.fixture(f"seeding {N} watchlist + {N} devices + {N} sightings + {N} alerts")
    t0 = time.perf_counter()
    _seed(db)
    diag.fixture(f"seed wall-clock: {time.perf_counter() - t0:.2f}s")

    # Confirm the index inventory actually present on the built DB.
    idx = db._conn.execute(
        "SELECT name, tbl_name FROM sqlite_master WHERE type='index' "
        "ORDER BY tbl_name, name"
    ).fetchall()
    diag.observed("--- indexes on built schema ---")
    for r in idx:
        diag.observed(f"  {r['tbl_name']}.{r['name']}")

    # ---- 1. watchlist-eval simple equality ----------------------------
    diag.section("1. watchlist-eval simple equality (db.py:748-756)")
    # Worst case: a pattern that exists near the end of the table.
    target = f"pat-mac-{N - 4001 - 4:08d}"
    plan = _plan(db, SQL_WATCHLIST_SIMPLE, ("mac", target))
    diag.observed(f"EXPLAIN: {_verdict(plan)}")
    # wall-clock a miss (worst case: full scan, no early LIMIT exit)
    t = time.perf_counter()
    for _ in range(20):
        db._conn.execute(SQL_WATCHLIST_SIMPLE, ("mac", "pat-mac-does-not-exist")).fetchone()
    miss_ms = (time.perf_counter() - t) / 20 * 1000
    t = time.perf_counter()
    for _ in range(20):
        db._conn.execute(SQL_WATCHLIST_SIMPLE, ("mac", target)).fetchone()
    hit_ms = (time.perf_counter() - t) / 20 * 1000
    diag.observed(f"wall-clock: miss={miss_ms:.3f}ms/query  hit(late-row)={hit_ms:.3f}ms/query")
    diag.notes(
        "Missing index: watchlist(pattern_type, pattern). Every non-"
        "mac_range eval lookup (mac/oui/ssid/ble_uuid/ble_manufacturer_id/"
        "ble_local_name/drone_id_prefix) scans the whole watchlist. A miss "
        "(common: most devices are NOT on the watchlist) cannot LIMIT-exit "
        "early, so it pays the full scan every observation, multiplied by "
        "the number of pattern types probed per observation."
    )

    # ---- 2. watchlist-eval mac_range ----------------------------------
    diag.section("2. watchlist-eval mac_range (db.py:898-908)")
    plan = _plan(db, SQL_WATCHLIST_MAC_RANGE, (36, f"{12345:09x}"))
    diag.observed(f"EXPLAIN: {_verdict(plan)}")
    diag.notes(
        "Covered by partial index idx_watchlist_mac_range_prefix "
        "(migration 011/021). mac_range is the ONE eval path that is "
        "already indexed -- contrast with path 1."
    )

    # ---- 3. /devices list ---------------------------------------------
    diag.section("3. /devices list default sort (db.py:1947-1956)")
    dsql = _devices_list_sql()
    plan = _plan(db, dsql, (200, 0))
    diag.observed(f"EXPLAIN: {_verdict(plan)}")
    t = time.perf_counter()
    for _ in range(10):
        db._conn.execute(dsql, (200, 0)).fetchall()
    dev_ms = (time.perf_counter() - t) / 10 * 1000
    diag.observed(f"wall-clock first-page: {dev_ms:.3f}ms/query")
    diag.notes(
        "Missing index: devices(last_seen). ORDER BY last_seen DESC has no "
        "supporting index, so the default /devices page SCANs devices and "
        "builds a TEMP B-TREE to sort -- the full table is materialized + "
        "sorted before LIMIT 200 is applied. The per-row correlated "
        "subqueries on sightings ARE indexed (idx_sightings_mac_ts)."
    )

    # ---- 4. /alerts list ----------------------------------------------
    diag.section("4. /alerts list default (db.py:1432-1434 + 1377)")
    plan = _plan(db, SQL_ALERTS_LIST, (100, 0))
    diag.observed(f"EXPLAIN: {_verdict(plan)}")
    t = time.perf_counter()
    for _ in range(10):
        db._conn.execute(SQL_ALERTS_LIST, (100, 0)).fetchall()
    alert_ms = (time.perf_counter() - t) / 10 * 1000
    diag.observed(f"wall-clock first-page: {alert_ms:.3f}ms/query")
    diag.notes(
        "alerts.id is the rowid, so idx_alerts_ts(ts) is effectively "
        "(ts, id); ORDER BY a.ts DESC, a.id DESC maps to a reverse index "
        "scan. The two LEFT JOINs use the watchlist PK and the "
        "watchlist_metadata.watchlist_id UNIQUE index. Whether this needs "
        "a new index is what the EXPLAIN above decides -- report as-found."
    )

    db.close()
