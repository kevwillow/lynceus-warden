"""Diagnostic trace for the dashboard /devices route (smoke findings #5/#6).

Smoke v0.7.2: dashboard /devices list is empty despite Kismet
actively seeing devices (#5); even when it does render, per-row
detail is thin (#6).

This diagnostic answers two questions:

  Q1 — Given a populated devices table, what does the /devices
       route actually emit? Exact SQL, exact template context,
       exact rendered HTML.

  Q2 — Which DB-side fields are AVAILABLE per row but NOT
       surfaced through the route's query + template? The gap
       between PRAGMA table_info(devices) and the SELECT column
       list in db.list_devices is the answer to #6.

Also reproduces the empty-state behavior so the next prompt can
distinguish "no devices in DB" (Touch 3 daemon-side issue) from
"devices in DB but route filters them out" (Touch 4 UI-side issue).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import create_app

pytestmark = pytest.mark.diagnostic


# Reuse the daemon-side fixture so the device rows the dashboard sees
# are byte-identical to what poll_once would have persisted (Touch 3
# established this happy-path mapping).
FIXTURE_PATH = Path(__file__).parent / "fixtures" / "kismet_devices.json"


def _seed_devices(db: Database, now_ts: int) -> int:
    """Hand-seed the devices table with a small representative mix:
    wifi + ble + bt_classic, randomized + non-randomized, with and
    without oui_vendor, with and without ble_name + probe_ssids — so
    the diagnostic exercises every column the schema exposes."""
    db.ensure_location("default", "Default Location")
    rows = [
        # mac, device_type, oui_vendor, is_randomized, ble_name, probe_ssids
        ("a4:83:e7:11:22:33", "wifi", "Apple", 0, None, '["HomeNet", "Guest"]'),
        ("02:11:22:33:44:55", "wifi", None, 1, None, None),
        ("06:aa:bb:cc:dd:ee", "ble", "Unknown", 1, "Tile_AB12", None),
        ("00:1a:7d:da:71:11", "bt_classic", "Cambridge Silicon", 0,
         "Sony WH-1000XM4", None),
        ("5a:11:22:33:44:55", "ble", "Apple", 1, None, None),
    ]
    for mac, kind, vendor, rand, ble_name, probe_ssids in rows:
        db.upsert_device(
            mac=mac,
            device_type=kind,
            oui_vendor=vendor,
            is_randomized=rand,
            now_ts=now_ts,
        )
        # Direct UPDATE for the additive columns (ble_name + probe_ssids
        # land via separate helpers in production). Backfilling them
        # here lets the diagnostic show whether the route's SELECT
        # surfaces them.
        with db._conn:
            db._conn.execute(
                "UPDATE devices SET ble_name = ?, probe_ssids = ? WHERE mac = ?",
                (ble_name, probe_ssids, mac),
            )
    return len(rows)


def _normalize_sql(sql: str) -> str:
    """Collapse whitespace so SQL captures stay readable in the log."""
    return re.sub(r"\s+", " ", sql).strip()


def test_diag_dashboard_devices_query(diag, tmp_path):
    # -----------------------------------------------------------------
    # Section 1 — DB schema vs. route query: what's AVAILABLE vs.
    # what's SELECTed.
    # -----------------------------------------------------------------
    diag.section("schema gap: devices table columns vs. list_devices SELECT")
    config = Config(
        db_path=str(tmp_path / "diag.db"),
        kismet_health_check_on_startup=False,
        evidence_capture_enabled=False,
    )
    db = Database(config.db_path)
    pragma_rows = list(db._conn.execute("PRAGMA table_info(devices)"))
    columns_in_schema = [r["name"] for r in pragma_rows]
    diag.fixture(f"devices schema columns: {columns_in_schema}")
    # SELECT in list_devices, copied from db.py:1810 — keep both in
    # sync if the helper changes.
    list_devices_columns = [
        "mac", "device_type", "first_seen", "last_seen",
        "sighting_count", "oui_vendor", "is_randomized", "notes",
    ]
    diag.fixture(f"list_devices SELECTs: {list_devices_columns}")
    schema_set = set(columns_in_schema)
    list_set = set(list_devices_columns)
    diag.observed(
        f"columns in schema but NOT selected: "
        f"{sorted(schema_set - list_set)}"
    )
    diag.observed(
        "  -> these fields are persisted by the poller (per Touch 3) "
        "but invisible to the dashboard /devices route. ble_name in "
        "particular is the BLE friendly name (e.g. 'Sony WH-1000XM4') "
        "that the device-label filter falls back on; probe_ssids is "
        "the JSON list of SSIDs the device was probing for. Both are "
        "core Kismet-sourced detail #6 calls out as 'missing'."
    )

    # -----------------------------------------------------------------
    # Section 2 — populated DB: SQL trace + template context +
    # rendered HTML
    # -----------------------------------------------------------------
    diag.section("populated DB: SQL + template context + rendered HTML")
    seeded = _seed_devices(db, now_ts=1_700_001_000)
    diag.fixture(f"seeded {seeded} devices (mix of wifi/ble/bt_classic, "
                 "randomized/non-randomized, with/without vendor + ble_name + "
                 "probe_ssids)")

    # SQL trace.
    captured: list[str] = []
    db._conn.set_trace_callback(captured.append)

    # Build app + intercept the TemplateResponse to capture the exact
    # context dict the route hands the template.
    app = create_app(config, db)
    captured_contexts: list[tuple[str, dict]] = []
    _orig = app.state.templates.TemplateResponse

    def _capture(request, name=None, context=None, **kwargs):
        if context is not None:
            captured_contexts.append((name or "<unknown>", dict(context)))
        return _orig(request=request, name=name, context=context, **kwargs)

    app.state.templates.TemplateResponse = _capture  # type: ignore[assignment]

    with TestClient(app) as client:
        resp = client.get("/devices")

    diag.observed(f"GET /devices status: {resp.status_code}")

    # Show every SELECT the route issued (filter to just the SELECTs
    # so the log doesn't drown in housekeeping noise).
    selects = [
        _normalize_sql(s) for s in captured
        if s.strip().upper().startswith("SELECT")
    ]
    diag.observed(f"SELECT statements emitted by route: {len(selects)}")
    for s in selects:
        diag.observed(f"  {s}")

    # Show the captured template context.
    diag.observed(f"TemplateResponse calls: {len(captured_contexts)}")
    for tmpl, ctx in captured_contexts:
        diag.observed(f"  -> template={tmpl!r}")
        for k, v in ctx.items():
            if k == "devices":
                diag.observed(f"     context[devices] = list of {len(v)} dicts:")
                for i, row in enumerate(v):
                    diag.observed(f"       devices[{i}] = {dict(row)}")
                continue
            diag.observed(f"     context[{k}] = {v!r}")

    # What does the template actually surface? Extract the table
    # header + one data row.
    body = resp.text
    headers = re.findall(r"<th>([^<]+)</th>", body)
    diag.observed(f"rendered <th> header cells: {headers}")
    # Each row is <tr>...<td>cells</td>...</tr>; grab cells from the
    # first data row inside <tbody>.
    tbody_m = re.search(r"<tbody>(.*?)</tbody>", body, flags=re.DOTALL)
    tbody = tbody_m.group(1) if tbody_m else ""
    first_tr = re.search(r"<tr[^>]*>(.*?)</tr>", tbody, flags=re.DOTALL)
    if first_tr:
        cells = re.findall(r"<td[^>]*>(.*?)</td>", first_tr.group(1), flags=re.DOTALL)
        diag.observed(f"first row <td> cell count: {len(cells)}")
        for i, cell in enumerate(cells):
            compact = re.sub(r"\s+", " ", cell).strip()
            diag.observed(f"  td[{i}] = {compact!r}")
    else:
        diag.observed("first row <tr>: NOT FOUND")

    # Cross-check: enumerate fields the template references but the
    # row dict doesn't carry — those are silently rendered as the
    # Jinja2 Undefined string (typically empty). And vice-versa.
    rendered_fields = set()
    for ph in re.findall(r"\{\{\s*d\.([a-zA-Z_][a-zA-Z0-9_]*)", _devices_template()):
        rendered_fields.add(ph)
    diag.observed(
        f"fields the devices_list.html template references on each "
        f"row: {sorted(rendered_fields)}"
    )
    if captured_contexts and captured_contexts[0][1].get("devices"):
        row_keys = set(captured_contexts[0][1]["devices"][0].keys())
        diag.observed(f"keys actually present on each row: {sorted(row_keys)}")
        diag.observed(
            f"fields referenced by template but missing from row: "
            f"{sorted(rendered_fields - row_keys)}"
        )
        diag.observed(
            f"fields present on row but never referenced by template: "
            f"{sorted(row_keys - rendered_fields)}"
        )

    db.close()

    # -----------------------------------------------------------------
    # Section 3 — empty DB: what does the route render?
    # -----------------------------------------------------------------
    diag.section("empty DB: what does the operator see?")
    config2 = Config(
        db_path=str(tmp_path / "empty.db"),
        kismet_health_check_on_startup=False,
        evidence_capture_enabled=False,
    )
    db2 = Database(config2.db_path)
    app2 = create_app(config2, db2)
    with TestClient(app2) as client2:
        resp2 = client2.get("/devices")
    diag.observed(f"GET /devices (empty DB) status: {resp2.status_code}")
    # Surface the empty-state message so the smoke complaint
    # "list is empty" has a known literal to look for.
    empty_state_m = re.search(
        r"<em>([^<]*No devices[^<]*)</em>", resp2.text
    )
    if empty_state_m:
        diag.observed(
            f"empty-state copy: {empty_state_m.group(1)!r} — the "
            "operator sees this both when the DB is genuinely empty "
            "AND when devices are in the DB but a filter excludes "
            "every row. The two cases are indistinguishable from the "
            "page; total_count shows 0 in both."
        )
    else:
        diag.observed("empty-state literal NOT FOUND in rendered output")
    db2.close()

    # -----------------------------------------------------------------
    # Section 4 — what a richer query + template would surface.
    # -----------------------------------------------------------------
    diag.section("hypothetical: rich SELECT + template extension")
    diag.observed(
        "If list_devices SELECTed (ble_name, probe_ssids) in addition "
        "to the current 8 columns, and devices_list.html added "
        "columns/Tooltips for them, the per-row info would gain:\n"
        " - BLE friendly name (Sony WH-1000XM4 vs. raw MAC + Cambridge "
        "Silicon vendor)\n"
        " - probe SSIDs the device was looking for (forensic gold for "
        "the operator: device probing HomeNet + WorkVPN identifies "
        "itself out of randomized chaff)\n"
        "These two columns alone close most of finding #6. A second-"
        "order improvement: JOIN against sightings to surface "
        "first_seen_rssi / last_seen_rssi / last_seen_ssid per device "
        "row without forcing the operator to click into /devices/<mac>."
    )

    diag.notes(
        "Finding #5 (empty list): if a populated DB renders correctly "
        "via this diagnostic (Section 2 — 5 rows displayed), the bug "
        "is upstream of the route. Combine with Touch 3's working "
        "hypothesis (source_allowlist silent drop) to confirm.\n"
        "Finding #6 (thin per-row info): the gap is concretely BOTH "
        "the SELECT (omits ble_name + probe_ssids) AND the template "
        "(no columns to render them even if SELECT'd). Section 1 "
        "documents the available columns; Section 4 lists the "
        "easy-win additions."
    )


def _devices_template() -> str:
    """Read devices_list.html so the diagnostic doesn't hard-code its
    field list — if the template grows new {{ d.foo }} references
    between now and the fix prompt, this diag re-scans it on rerun."""
    path = (
        Path(__file__).resolve().parent.parent
        / "src" / "lynceus" / "webui" / "templates" / "devices_list.html"
    )
    return path.read_text(encoding="utf-8")
