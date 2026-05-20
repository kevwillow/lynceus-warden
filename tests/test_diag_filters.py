"""Diagnostic dumps for the /alerts has_action filter and mac_range parity.

The has_action SQL clause builder lives in ``db._alert_filter_clauses``
(``src/lynceus/db.py:1357``) and OR's together:
- ``mac IN (...)``               for allowlist mac entries
- ``mac LIKE 'oui:%'``           per allowlist oui entry
- ``mac_in_mac_range(mac, ?)``   per allowlist mac_range entry (SQL func)
- ``EXISTS (SELECT 1 FROM watchful_recurrence ...)``

These tests trace the actual SQL the DB layer emits, count the
invocations of the connection-registered ``mac_in_mac_range`` SQL
function, and dump the EXPLAIN QUERY PLAN. Reviewer offline checks:
- Is the SQL the expected shape?
- Does the query plan use indexes or fall back to full-table scans?
- Does mac_in_mac_range get called once per (row, range_pattern), as
  expected from the per-pattern OR clause?
"""

from __future__ import annotations

import pytest
import yaml
from fastapi.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.patterns import mac_in_mac_range
from lynceus.webui.app import create_app

pytestmark = pytest.mark.diagnostic


NOW_TS = 1_700_000_000


def _write_allowlist(tmp_path, entries):
    path = tmp_path / "allowlist.yaml"
    path.write_text(yaml.safe_dump({"entries": entries}), encoding="utf-8")
    return path


def _seed_alert(db: Database, mac: str | None, *, ts: int = NOW_TS) -> int:
    # alerts.mac is a FK to devices.mac; upsert a device row first so
    # the insert satisfies the constraint. None-mac alerts skip the
    # device upsert (FK accepts NULL).
    if mac is not None:
        db.ensure_location("diagloc", "Diagnostic")
        db.upsert_device(
            mac=mac, device_type="wifi", oui_vendor=None,
            is_randomized=0, now_ts=ts,
        )
    return db.add_alert(
        ts=ts,
        rule_name="diag-rule",
        mac=mac,
        message=f"diag alert mac={mac}",
        severity="med",
        rule_type="watchlist_mac",
    )


def _install_sql_trace(db: Database, captured: list[str]) -> None:
    """Capture every SQL statement the connection executes."""
    db._conn.set_trace_callback(captured.append)


def _wrap_mac_in_mac_range(db: Database) -> dict:
    """Re-register the SQL function with a counting wrapper.

    The Database constructor registers ``mac_in_mac_range`` (db.py:365).
    Re-registering with the same name supersedes that binding for this
    connection -- the wrapper still delegates to the production matcher
    so behavior is byte-identical; only the invocation count is added.
    """
    counter = {"calls": 0, "args_sample": []}

    def counting(mac, pattern):
        counter["calls"] += 1
        if len(counter["args_sample"]) < 8:
            counter["args_sample"].append((mac, pattern))
        return mac_in_mac_range(mac, pattern)

    db._conn.create_function("mac_in_mac_range", 2, counting, deterministic=True)
    return counter


# ---------------------------------------------------------------------------
# Test 1 — emitted SQL + query plan with mac/oui/mac_range entries
# ---------------------------------------------------------------------------


def test_diag_has_action_sql_emitted(diag, tmp_path):
    allowlist_path = _write_allowlist(
        tmp_path,
        [
            {"pattern": "aa:bb:cc:11:22:33", "pattern_type": "mac"},
            {"pattern": "aa:bb:cc:11:22:44", "pattern_type": "mac"},
            {"pattern": "de:ad:be", "pattern_type": "oui"},
            {"pattern": "aa:bb:cc:d/28", "pattern_type": "mac_range"},
            {"pattern": "11:22:33:4/28", "pattern_type": "mac_range"},
            {"pattern": "aa:bb:cc:11:2/36", "pattern_type": "mac_range"},
        ],
    )
    config = Config(
        db_path=str(tmp_path / "diag.db"),
        allowlist_path=str(allowlist_path),
    )
    db = Database(config.db_path)
    diag.fixture("allowlist: 2 mac + 1 oui + 3 mac_range entries")

    # Seed an alert per allowlist class so the filter has something to match.
    a_mac = _seed_alert(db, "aa:bb:cc:11:22:33")
    a_oui = _seed_alert(db, "de:ad:be:99:99:99")
    a_range = _seed_alert(db, "aa:bb:cc:dd:e0:11")
    a_unrelated = _seed_alert(db, "11:11:11:11:11:11")
    # NULL-mac alert deliberately omitted here -- see
    # test_diag_has_action_null_mac_invocation below for that path.
    diag.fixture(f"seeded alert ids: mac={a_mac}, oui={a_oui}, "
                 f"range={a_range}, unrelated={a_unrelated}")

    captured: list[str] = []
    _install_sql_trace(db, captured)

    app = create_app(config, db)
    diag.exercise("GET /alerts?has_action=with_action via TestClient")
    with TestClient(app) as client:
        try:
            resp = client.get("/alerts", params={"has_action": "with_action"})
            diag.observed(f"HTTP status: {resp.status_code}")
        except Exception as exc:  # noqa: BLE001 -- diagnostic, surface + dump
            diag.observed(f"GET raised: {type(exc).__name__}: {exc}")
            resp = None

    # Find the alert-list SELECT among captured statements.
    select_sqls = [
        s for s in captured
        if "FROM alerts" in s and "SELECT" in s.upper()
    ]
    diag.observed(f"captured SQL statement count: {len(captured)}")
    diag.observed(f"FROM alerts SELECTs: {len(select_sqls)}")
    if select_sqls:
        diag.observed("--- last alerts SELECT (sanitized: param values bound "
                      "separately, only the SQL text is captured here) ---")
        diag.observed(select_sqls[-1])

        # EXPLAIN QUERY PLAN against the captured statement, parameter-free.
        # SQLite tolerates ? placeholders in EXPLAIN; the plan is structural
        # and does not depend on actual bound values.
        try:
            plan_rows = db._conn.execute(
                "EXPLAIN QUERY PLAN " + select_sqls[-1]
            ).fetchall()
            diag.observed("--- EXPLAIN QUERY PLAN ---")
            for row in plan_rows:
                diag.observed(f"  {tuple(row)}")
        except Exception as exc:  # noqa: BLE001 -- diagnostic, swallow + dump
            diag.observed(f"EXPLAIN QUERY PLAN raised: {type(exc).__name__}: {exc}")

    diag.notes("Per db.py:1438, every mac_range pattern contributes one "
               "mac_in_mac_range(mac, ?) clause OR'd into the action_clauses "
               "list. With 3 mac_range entries, expect 3 such clauses; with "
               "2 mac entries, expect one IN(?,?) clause; with 1 oui, expect "
               "one LIKE clause.")
    db.close()


# ---------------------------------------------------------------------------
# Test 2 — alert MAC matches BOTH a mac entry AND a mac_range entry
# ---------------------------------------------------------------------------


def test_diag_has_action_precedence(diag, tmp_path):
    target_mac = "aa:bb:cc:dd:e0:11"
    range_entry = "aa:bb:cc:d/28"  # /28 covers any mac starting with aa:bb:cc:d?
    assert mac_in_mac_range(target_mac, range_entry), (
        "sanity: mac_in_mac_range should match target_mac under range_entry"
    )

    allowlist_path = _write_allowlist(
        tmp_path,
        [
            {"pattern": target_mac, "pattern_type": "mac"},
            {"pattern": range_entry, "pattern_type": "mac_range"},
        ],
    )
    config = Config(
        db_path=str(tmp_path / "diag.db"),
        allowlist_path=str(allowlist_path),
    )
    db = Database(config.db_path)
    diag.fixture(f"allowlist entries: mac={target_mac!r} AND "
                 f"mac_range={range_entry!r}")
    diag.fixture(f"target alert mac={target_mac!r} matches BOTH entries")

    alert_id = _seed_alert(db, target_mac)
    diag.fixture(f"seeded alert id={alert_id}")

    app = create_app(config, db)
    with TestClient(app) as client:
        diag.exercise("GET /alerts?has_action=with_action")
        list_resp = client.get("/alerts", params={"has_action": "with_action"})
        diag.observed(f"/alerts has_action=with_action status: {list_resp.status_code}")
        diag.observed(f"alert row id={alert_id} present in HTML: "
                      f"{f'/alerts/{alert_id}' in list_resp.text}")

        diag.exercise("GET /alerts.csv?has_action=with_action")
        csv_resp = client.get("/alerts.csv",
                              params={"has_action": "with_action"})
        diag.observed(f"/alerts.csv status: {csv_resp.status_code}")
        # Last column is action_taken; pull the matching data row.
        rows = [r for r in csv_resp.text.splitlines() if r.startswith(f"{alert_id},")]
        diag.observed(f"matching CSV data rows: {rows}")

        diag.exercise(f"GET /alerts/{alert_id}")
        detail_resp = client.get(f"/alerts/{alert_id}")
        diag.observed(f"detail page status: {detail_resp.status_code}")
        # Look for the human-rendered allowlist disposition string.
        for token in ("allowlist", "mac_range", "snooze", "permanent"):
            diag.observed(f"  detail-page contains {token!r}: "
                          f"{token in detail_resp.text}")

    diag.notes("SQL OR semantic: the alert is included whenever ANY action "
               "signal matches; the matched signal identity is not surfaced "
               "by the filter. The /alerts/<id> detail page resolves a single "
               "match via _resolve_allowlist_match -- primary file before UI "
               "sibling, no precedence between mac/mac_range within a file.")
    db.close()


# ---------------------------------------------------------------------------
# Test 3 — per-alert snooze (UI allowlist sibling) AND permanent allowlist
# ---------------------------------------------------------------------------


def test_diag_has_action_with_snooze_and_allowlist(diag, tmp_path):
    target_mac = "aa:bb:cc:11:22:33"

    # Primary allowlist.yaml -> permanent entry.
    primary = tmp_path / "allowlist.yaml"
    primary.write_text(
        yaml.safe_dump({"entries": [
            {"pattern": target_mac, "pattern_type": "mac",
             "note": "diag-permanent"}
        ]}),
        encoding="utf-8",
    )

    # UI sibling allowlist_ui.yaml -> per-alert snooze entry.
    # ``derive_ui_path`` produces a fixed sibling name (allowlist_ui.yaml).
    from lynceus.allowlist import derive_ui_path
    ui_path = derive_ui_path(primary)
    ui_path.write_text(
        yaml.safe_dump({"entries": [
            {"pattern": target_mac, "pattern_type": "mac",
             "expires_at": NOW_TS + 3600, "added_at": NOW_TS - 60,
             "note": "diag-snooze"}
        ]}),
        encoding="utf-8",
    )

    config = Config(
        db_path=str(tmp_path / "diag.db"),
        allowlist_path=str(primary),
    )
    db = Database(config.db_path)
    diag.fixture(f"primary allowlist: {target_mac} (permanent)")
    diag.fixture(f"UI sibling allowlist: {target_mac} (snooze, expires "
                 f"{NOW_TS + 3600})")

    alert_id = _seed_alert(db, target_mac)
    diag.fixture(f"seeded alert id={alert_id} mac={target_mac}")

    app = create_app(config, db)
    with TestClient(app) as client:
        diag.exercise("GET /alerts?has_action=with_action")
        r = client.get("/alerts", params={"has_action": "with_action"})
        diag.observed(f"status: {r.status_code}")
        diag.observed(f"alert id link present: "
                      f"{f'/alerts/{alert_id}' in r.text}")

        diag.exercise("GET /alerts.csv?has_action=with_action")
        c = client.get("/alerts.csv", params={"has_action": "with_action"})
        for row in c.text.splitlines():
            if row.startswith(f"{alert_id},"):
                diag.observed(f"CSV row for alert {alert_id}: {row!r}")

        diag.exercise(f"GET /alerts/{alert_id}")
        d = client.get(f"/alerts/{alert_id}")
        diag.observed(f"detail status: {d.status_code}")
        for token in ("diag-permanent", "diag-snooze", "Remove",
                      "Permanent", "snooze"):
            diag.observed(f"  detail-page contains {token!r}: "
                          f"{token in d.text}")

    diag.notes("_resolve_allowlist_match consults the primary file FIRST; "
               "the UI sibling only wins when the primary misses. With both "
               "files matching, the operator sees the permanent disposition "
               "and the snooze entry is invisible from the detail page.")
    db.close()


# ---------------------------------------------------------------------------
# Test 4 — count of mac_in_mac_range SQL-function invocations
# ---------------------------------------------------------------------------


def test_diag_mac_range_sql_function_invocation(diag, tmp_path):
    # 50 mac_range allowlist entries -- enough to make the per-row,
    # per-pattern call count observable without bundling the full
    # 17,795 production set into a test fixture.
    n_ranges = 50
    n_alerts = 30
    mac_range_patterns = [
        f"aa:bb:cc:{i:02x}:0/28" for i in range(n_ranges)
    ]
    allowlist_path = _write_allowlist(
        tmp_path,
        [{"pattern": p, "pattern_type": "mac_range"} for p in mac_range_patterns],
    )
    config = Config(
        db_path=str(tmp_path / "diag.db"),
        allowlist_path=str(allowlist_path),
    )
    db = Database(config.db_path)

    for i in range(n_alerts):
        _seed_alert(db, f"99:88:77:66:55:{i:02x}")
    diag.fixture(f"allowlist mac_range entries: {n_ranges}")
    diag.fixture(f"alerts seeded: {n_alerts} (none in any range)")

    counter = _wrap_mac_in_mac_range(db)
    diag.fixture("re-registered mac_in_mac_range as a counting wrapper "
                 "around lynceus.patterns.mac_in_mac_range")

    app = create_app(config, db)
    with TestClient(app) as client:
        diag.exercise("GET /alerts?has_action=with_action")
        r = client.get("/alerts", params={"has_action": "with_action"})
        diag.observed(f"status: {r.status_code}")
        diag.observed(f"mac_in_mac_range invocation count: {counter['calls']}")
        diag.observed(f"expected upper bound n_alerts * n_ranges = "
                      f"{n_alerts * n_ranges} (per-row, per-pattern)")
        diag.observed(f"first {len(counter['args_sample'])} (mac, pattern) "
                      f"calls: {counter['args_sample']}")

    diag.notes("SQLite may short-circuit OR clauses left-to-right; if the "
               "leading IN(?,?) clause was emitted (it isn't, because no mac "
               "entries are present), mac_in_mac_range would be skipped for "
               "matched rows. Here only mac_range clauses fire, so every "
               "(row, pattern) pair invokes the function.")
    db.close()


# ---------------------------------------------------------------------------
# Test 5 — has_action filter behavior when an alert has NULL mac
# ---------------------------------------------------------------------------


def test_diag_has_action_null_mac_invocation(diag, tmp_path):
    allowlist_path = _write_allowlist(
        tmp_path,
        [{"pattern": "aa:bb:cc:d/28", "pattern_type": "mac_range"}],
    )
    config = Config(
        db_path=str(tmp_path / "diag.db"),
        allowlist_path=str(allowlist_path),
    )
    db = Database(config.db_path)

    # NULL-mac alert: alerts.mac is NULL-able. Production code paths that
    # write NULL-mac rows include pre-migration-015 historical alerts and
    # certain new_non_randomized_device early failures.
    null_alert_id = _seed_alert(db, None)
    diag.fixture(f"allowlist: 1 mac_range entry")
    diag.fixture(f"seeded NULL-mac alert id={null_alert_id}")

    app = create_app(config, db)
    with TestClient(app) as client:
        diag.exercise("GET /alerts?has_action=with_action with NULL-mac alert "
                      "in table AND mac_range allowlist active")
        try:
            r = client.get("/alerts", params={"has_action": "with_action"})
            diag.observed(f"with_action HTTP status: {r.status_code}")
            diag.observed(f"NULL-mac alert listed: "
                          f"{f'/alerts/{null_alert_id}' in r.text}")
        except Exception as exc:  # noqa: BLE001
            diag.observed(f"with_action GET raised: "
                          f"{type(exc).__name__}: {exc}")

        diag.exercise("GET /alerts?has_action=without_action")
        try:
            r = client.get("/alerts", params={"has_action": "without_action"})
            diag.observed(f"without_action HTTP status: {r.status_code}")
            diag.observed(f"NULL-mac alert listed: "
                          f"{f'/alerts/{null_alert_id}' in r.text}")
        except Exception as exc:  # noqa: BLE001
            diag.observed(f"without_action GET raised: "
                          f"{type(exc).__name__}: {exc}")

    diag.notes("mac_in_mac_range(None, pattern) raises AttributeError "
               "(patterns.py:286 calls .replace on the mac arg). The "
               "without_action SQL clause already guards with `mac IS NULL "
               "OR NOT ...` (db.py:1463); with_action has no such guard. "
               "Whether this surfaces as a 500 to the operator depends on "
               "whether SQLite short-circuits the OR before hitting the "
               "mac_in_mac_range call.")
    db.close()
