"""Diagnostic comparing rendered per-device fields on home + /devices
to the Kismet-sourced fields available in the DB (smoke finding #6).

Smoke v0.7.2: 'Dashboard home page + devices page lack rich
Kismet-sourced detail per device.'

This diagnostic enumerates, per page:

  - every column the device row dict carries when the page renders
  - every cell the template actually surfaces per row
  - the set of Kismet-sourced fields available in the underlying DB
    schema that NEITHER page surfaces today

The inventory spans the devices table (Kismet-derived static metadata
the poller persists per upsert) and the sightings table (time-series
RSSI + SSID per observation, which the dashboard could JOIN to give
per-device 'last RSSI' / 'last SSID' without forcing a click into
/devices/<mac>).

Complements Touch 4 (which traces the /devices route's SQL + filter
error path); this one focuses on the field-inventory gap that closes
#6.
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


def _seed_rich(db: Database, now_ts: int) -> int:
    """Seed a mix of devices + sightings that exercises every Kismet-
    sourced field the schema can carry, so the rendered output shows
    which fields drop out per-page."""
    db.ensure_location("default", "Default Location")
    db.ensure_location("garage", "Garage Repeater")
    rows = [
        # (mac, kind, vendor, rand, ble_name, probe_ssids JSON)
        ("a4:83:e7:11:22:33", "wifi", "Apple", 0, None, '["HomeNet"]'),
        ("06:aa:bb:cc:dd:ee", "ble", "Unknown", 1, "Tile_AB12", None),
        ("00:1a:7d:da:71:11", "bt_classic", "Cambridge Silicon",
         0, "Sony WH-1000XM4", None),
        ("5a:11:22:33:44:55", "ble", "Apple", 1, None, None),
    ]
    for mac, kind, vendor, rand, ble_name, probe in rows:
        db.upsert_device(
            mac=mac, device_type=kind, oui_vendor=vendor,
            is_randomized=rand, now_ts=now_ts,
        )
        with db._conn:
            db._conn.execute(
                "UPDATE devices SET ble_name = ?, probe_ssids = ? WHERE mac = ?",
                (ble_name, probe, mac),
            )
        # Two sightings per device so last_seen can differ from
        # first_seen and a JOIN-based last_rssi/last_ssid feature
        # has something to surface.
        db.insert_sighting(
            mac=mac, ts=now_ts - 600, rssi=-62, ssid=None, location_id="default"
        )
        db.insert_sighting(
            mac=mac, ts=now_ts - 60, rssi=-48,
            ssid=("HomeNet" if kind == "wifi" else None),
            location_id="garage",
        )
    return len(rows)


def _extract_th_td(html: str, section_marker: str) -> tuple[list[str], list[list[str]]]:
    """Pull <th> headers + <td> cells from the first <table> that
    appears AFTER the given marker substring in `html`. Returns
    (headers, rows-of-cells). Used to slice 'recently seen devices'
    out of the home page (multiple tables on the page) and the
    devices list out of /devices."""
    idx = html.find(section_marker)
    if idx < 0:
        return [], []
    table_m = re.search(r"<table>(.*?)</table>", html[idx:], flags=re.DOTALL)
    if not table_m:
        return [], []
    table = table_m.group(1)
    headers = re.findall(r"<th>([^<]*)</th>", table)
    rows: list[list[str]] = []
    tbody_m = re.search(r"<tbody>(.*?)</tbody>", table, flags=re.DOTALL)
    if tbody_m:
        for tr in re.findall(r"<tr[^>]*>(.*?)</tr>", tbody_m.group(1), flags=re.DOTALL):
            cells = [
                re.sub(r"\s+", " ", c).strip()
                for c in re.findall(r"<td[^>]*>(.*?)</td>", tr, flags=re.DOTALL)
            ]
            rows.append(cells)
    return headers, rows


def test_diag_dashboard_home_rich_info(diag, tmp_path):
    config = Config(
        db_path=str(tmp_path / "diag.db"),
        kismet_health_check_on_startup=False,
        evidence_capture_enabled=False,
    )
    db = Database(config.db_path)
    seeded = _seed_rich(db, now_ts=1_700_001_000)

    # -----------------------------------------------------------------
    # Section 1 — DB inventory: Kismet-sourced fields per device.
    # -----------------------------------------------------------------
    diag.section("inventory: Kismet-sourced fields available per device")
    devices_cols = [
        r["name"] for r in db._conn.execute("PRAGMA table_info(devices)")
    ]
    sightings_cols = [
        r["name"] for r in db._conn.execute("PRAGMA table_info(sightings)")
    ]
    diag.fixture(f"seeded {seeded} devices, 2 sightings each (rssi varies)")
    diag.observed(f"devices table columns: {devices_cols}")
    diag.observed(f"sightings table columns: {sightings_cols}")
    diag.observed(
        "Kismet-sourced static columns (persisted at poller upsert):\n"
        "  oui_vendor    -- Kismet's manuf field, e.g. 'Apple', 'Cambridge Silicon'\n"
        "  is_randomized -- locally-administered MAC bit, 1=randomized\n"
        "  ble_name      -- BLE GAP Complete Local Name (gated on capture.ble_friendly_names)\n"
        "  probe_ssids   -- JSON list of SSIDs probed for "
        "(gated on capture.probe_ssids)\n"
        "Kismet-sourced time-series columns (per sighting):\n"
        "  rssi          -- last signal strength in dBm\n"
        "  ssid          -- associated SSID when wifi+observed\n"
        "  location_id   -- which capture source / location saw it"
    )

    # Dump every device row + its sightings so the rendering
    # comparison below has concrete content to point at.
    diag.observed("--- devices table contents ---")
    for row in db._conn.execute(
        "SELECT mac, device_type, oui_vendor, is_randomized, "
        "ble_name, probe_ssids, first_seen, last_seen, sighting_count "
        "FROM devices ORDER BY mac"
    ):
        diag.observed(f"  {dict(row)}")
    diag.observed("--- sightings table contents (per-device) ---")
    for row in db._conn.execute(
        "SELECT mac, ts, rssi, ssid, location_id FROM sightings "
        "ORDER BY mac, ts"
    ):
        diag.observed(f"  {dict(row)}")

    # -----------------------------------------------------------------
    # Section 2 — home page rendering: 'recently seen devices' table.
    # -----------------------------------------------------------------
    diag.section("rendered: home page 'recently seen devices' table")
    app = create_app(config, db)
    with TestClient(app) as client:
        home_resp = client.get("/")
    diag.observed(f"GET / status: {home_resp.status_code}")
    headers, rows = _extract_th_td(home_resp.text, "recently seen devices")
    diag.observed(f"<th> headers under 'recently seen devices': {headers}")
    diag.observed(f"row count: {len(rows)}")
    for i, cells in enumerate(rows):
        diag.observed(f"  row[{i}] = {cells}")

    home_template = (
        Path(__file__).resolve().parent.parent
        / "src" / "lynceus" / "webui" / "templates" / "index.html"
    ).read_text(encoding="utf-8")
    # Pull the recently-seen-devices block from the source so the
    # diag is self-contained.
    home_section_m = re.search(
        r"<article>\s*<header><strong>recently seen devices</strong>.*?</article>",
        home_template,
        flags=re.DOTALL,
    )
    if home_section_m:
        block = home_section_m.group(0)
        diag.observed("--- index.html 'recently seen devices' block (verbatim) ---")
        for line in block.splitlines():
            diag.observed(f"  {line}")
    # Fields the template references on a device row (best-effort
    # regex; flags both `{{ d.foo }}` AND `d.foo` inside Jinja tags).
    field_refs = set(re.findall(r"\bd\.([a-zA-Z_][a-zA-Z0-9_]*)", home_template))
    # Plus the | device_label filter consumes d as a whole object
    # which calls .get('friendly_name') and .get('oui_vendor').
    diag.observed(
        f"fields the home template references on each row: {sorted(field_refs)}"
    )
    diag.observed(
        "  + the device_label filter (webui/app.py:582) reads "
        "device.get('friendly_name') with fallback to "
        "device.get('oui_vendor'). Neither is in the SELECT'd row "
        "dict today (friendly_name doesn't exist as a column; "
        "oui_vendor IS selected — so filter ALWAYS falls through "
        "to vendor). ble_name (the actual BLE friendly name) "
        "would be the natural friendly_name source but is not "
        "selected by list_devices (per Touch 4)."
    )

    # -----------------------------------------------------------------
    # Section 3 — /devices list page rendering.
    # -----------------------------------------------------------------
    diag.section("rendered: /devices list page")
    with TestClient(app) as client:
        dev_resp = client.get("/devices")
    diag.observed(f"GET /devices status: {dev_resp.status_code}")
    dev_headers, dev_rows = _extract_th_td(dev_resp.text, "<h2>devices</h2>")
    diag.observed(f"<th> headers on /devices: {dev_headers}")
    diag.observed(f"row count: {len(dev_rows)}")
    for i, cells in enumerate(dev_rows):
        diag.observed(f"  row[{i}] = {cells}")

    # -----------------------------------------------------------------
    # Section 4 — gap: fields IN the DB but on NEITHER page.
    # -----------------------------------------------------------------
    diag.section("gap: persisted fields surfaced on NEITHER page")
    rendered_field_kinds = {
        # Mapped to what the rendered <th> column actually shows.
        "home": set(headers),
        "devices": set(dev_headers),
    }
    diag.observed(f"home columns rendered: {rendered_field_kinds['home']}")
    diag.observed(f"/devices columns rendered: {rendered_field_kinds['devices']}")
    diag.observed(
        "Persisted but unsurfaced (closing these is the #6 fix):\n"
        "  ble_name      -- not SELECTed by list_devices; even if it "
        "were, neither template has a column for it. Operator can't "
        "tell 'Sony WH-1000XM4' from a raw MAC.\n"
        "  probe_ssids   -- not SELECTed; no column. Forensic gold for "
        "fingerprinting a randomized device.\n"
        "  oui_vendor    -- IS SELECTed but only used by the "
        "device_label filter as the 'Device' cell fallback. Never "
        "shown explicitly as 'Vendor: Apple' — the label cell just "
        "shows 'Apple' with no key. Operator can't tell that 'Apple' "
        "is the vendor vs. a friendly name.\n"
        "  is_randomized -- shown on /devices via a checkmark, NOT "
        "shown on home at all.\n"
        "  last sighting's rssi -- NOT in either row dict (would "
        "require a sightings JOIN). Lets operator triage 'is this "
        "device close right now?' without clicking into /devices/<mac>.\n"
        "  last sighting's ssid -- same.\n"
        "  distinct location_ids -- if the operator runs multi-source, "
        "knowing whether a MAC is seen by alfa-2.4ghz vs builtin-bt "
        "is high-signal triage info. Not in either row.\n"
        "  alert count for the device -- not in either row. Two queries "
        "(this device's alerts, severity bucketing) would let the "
        "page badge devices that have triggered watchlist alerts."
    )

    # -----------------------------------------------------------------
    # Section 5 — concrete recipe for closing #6.
    # -----------------------------------------------------------------
    diag.section("concrete recipe")
    diag.observed(
        "Minimum-viable fix to address smoke #6 (per Touch 4 + this "
        "diagnostic combined):\n"
        "  1. src/lynceus/db.py list_devices (db.py:1810):\n"
        "       SELECT ... oui_vendor, is_randomized, notes, ble_name, "
        "probe_ssids FROM devices ...\n"
        "     (additive; no row-dict consumer breaks since\n"
        "     dict-keyed access ignores unknown extras).\n"
        "  2. src/lynceus/webui/app.py _device_label (app.py:582):\n"
        "     change priority to ble_name -> friendly_name -> "
        "oui_vendor -> '—' so the 'Sony WH-1000XM4' row stops "
        "rendering as 'Cambridge Silicon'.\n"
        "  3. src/lynceus/webui/templates/devices_list.html: add\n"
        "     <th>Vendor</th><th>BLE name</th><th>Probes</th> with "
        "matching <td>s. The probes column is a comma-joined render "
        "of json.loads(d.probe_ssids); empty list/None renders blank.\n"
        "  4. (Optional, stretch) JOIN sightings in list_devices to "
        "add last_rssi + last_ssid columns. Adds one ORDER BY ts DESC "
        "LIMIT 1 subquery per row OR one window-function pass; both "
        "tolerable at typical row counts."
    )

    db.close()

    diag.notes(
        "Smoke #6 root cause is two-layered (per Touch 4 + this "
        "diag): the DB has more Kismet-sourced detail than the "
        "row dict SELECTs, AND the templates have no columns to "
        "render even the fields they do receive. Section 5 lists "
        "the four-step minimum-viable fix; the first three are "
        "essentially free (no schema migration, no new query), the "
        "fourth is a stretch goal for richer triage."
    )
