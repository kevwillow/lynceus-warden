"""Local validation for the 0.9.2 roll-out of the client-side column
resize + reorder + per-table persistence layer to watchlist / watchful /
allowlist (mirrors tests/test_devices_column_layout.py per converted table).

Scope is identical to the devices file: the only server-side testable
surface is the opt-in markup the data_table macro emits and the column-key
integrity the JS positional-permutation depends on. The drag/resize pointer
interaction and __lynTableApply's corruption resilience are browser-only and
covered by code-reading + the operator rig checklist.

tests/ is gitignored; this file is local-only and never committed. Run with
the pinned 3.11 venv.
"""

from __future__ import annotations

import re

from fastapi.testclient import TestClient

from lynceus.config import CaptureConfig, Config
from lynceus.db import Database
from lynceus.webui.app import create_app

# Per-table column keys, in render order, mirrored from each *_list.html so a
# column added/renamed/reordered without updating the key wiring trips a test
# rather than silently corrupting persisted layouts.
WATCHLIST_KEYS = [
    "pattern",
    "pattern_type",
    "severity",
    "description",
    "vendor",
    "device_category",
    "argus_id",
    "confidence",
]
WATCHFUL_KEYS = [
    "id",
    "mac",
    "state",
    "sightings",
    "first_seen",
    "last_seen",
    "escalated",
    "snooze_until",
    "source",
    "actions",
]
ALLOWLIST_KEYS = [
    "select",
    "pattern_type",
    "pattern",
    "source",
    "status",
    "note",
    "expires",
    "added",
]


def _make_app(tmp_path, *, allowlist_path=None):
    config = Config(
        db_path=str(tmp_path / "rollout.db"),
        kismet_health_check_on_startup=False,
        evidence_capture_enabled=False,
        **({"allowlist_path": str(allowlist_path)} if allowlist_path else {}),
    )
    db = Database(config.db_path)
    db.ensure_location("default", "Default Location")
    return create_app(config, db), db


def _seed_watchlist(db):
    with db._conn:
        db._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
            "VALUES (?, 'mac', 'low', 'test entry')",
            ("aa:bb:cc:dd:ee:ff",),
        )


def _seed_watchful(db):
    with db._conn:
        db._conn.execute(
            "INSERT INTO watchful_recurrence("
            "mac, created_at, first_seen_at, last_seen_at, sighting_count) "
            "VALUES (?, ?, ?, ?, ?)",
            ("aa:bb:cc:11:22:33", 1000, 1000, 1000, 1),
        )


def _colgroup_and_header_keys(html):
    colgroup = html[html.index("<colgroup>") : html.index("</colgroup>")]
    col_keys = re.findall(r'<col data-col-key="([^"]+)"', colgroup)
    thead = html[html.index("<thead>") : html.index("</thead>")]
    th_keys = re.findall(r'data-col-key="([^"]+)"', thead)
    return col_keys, th_keys


# --- route-level: each converted table CARRIES the layer ------------------


def test_watchlist_route_carries_layer(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        _seed_watchlist(db)
        with TestClient(app) as client:
            r = client.get("/watchlist")
        assert r.status_code == 200
        assert 'data-table-id="watchlist"' in r.text
        assert "col-resizer" in r.text
        assert 'data-table-reset="watchlist"' in r.text
        assert 'window.__lynTableApply("watchlist")' in r.text
    finally:
        db.close()


def test_watchful_route_carries_layer(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        _seed_watchful(db)
        with TestClient(app) as client:
            r = client.get("/watchful")
        assert r.status_code == 200
        assert 'data-table-id="watchful"' in r.text
        assert "col-resizer" in r.text
        assert 'data-table-reset="watchful"' in r.text
        assert 'window.__lynTableApply("watchful")' in r.text
    finally:
        db.close()


def test_allowlist_route_carries_layer(tmp_path):
    allowlist_path = tmp_path / "allowlist.yaml"
    allowlist_path.write_text(
        "entries:\n  - pattern: aa:bb:cc:dd:ee:ff\n    pattern_type: mac\n",
        encoding="utf-8",
    )
    app, db = _make_app(tmp_path, allowlist_path=allowlist_path)
    try:
        with TestClient(app) as client:
            r = client.get("/allowlist")
        assert r.status_code == 200
        assert 'data-table-id="allowlist"' in r.text
        assert "col-resizer" in r.text
        assert 'data-table-reset="allowlist"' in r.text
        assert 'window.__lynTableApply("allowlist")' in r.text
        # The disabled select-all checkbox header survived the macro move
        # (label passed through |safe, not escaped into visible text).
        assert 'id="select-all-noop"' in r.text
    finally:
        db.close()


# --- column-key integrity: colgroup <-> header parity, in order -----------


def test_watchlist_colgroup_keys_match_header_keys_in_order(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        _seed_watchlist(db)
        with TestClient(app) as client:
            html = client.get("/watchlist").text
        col_keys, th_keys = _colgroup_and_header_keys(html)
        assert col_keys == WATCHLIST_KEYS
        assert th_keys == WATCHLIST_KEYS
        assert "" not in col_keys
    finally:
        db.close()


def test_watchful_colgroup_keys_match_header_keys_in_order(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        _seed_watchful(db)
        with TestClient(app) as client:
            html = client.get("/watchful").text
        col_keys, th_keys = _colgroup_and_header_keys(html)
        assert col_keys == WATCHFUL_KEYS
        assert th_keys == WATCHFUL_KEYS
        assert "" not in col_keys
    finally:
        db.close()


def test_allowlist_colgroup_keys_match_header_keys_in_order(tmp_path):
    allowlist_path = tmp_path / "allowlist.yaml"
    allowlist_path.write_text(
        "entries:\n  - pattern: aa:bb:cc:dd:ee:ff\n    pattern_type: mac\n",
        encoding="utf-8",
    )
    app, db = _make_app(tmp_path, allowlist_path=allowlist_path)
    try:
        with TestClient(app) as client:
            html = client.get("/allowlist").text
        col_keys, th_keys = _colgroup_and_header_keys(html)
        assert col_keys == ALLOWLIST_KEYS
        assert th_keys == ALLOWLIST_KEYS
        assert "" not in col_keys
    finally:
        db.close()


# --- isolation: the still-unconverted list tables carry NO layer ----------


def test_unconverted_list_pages_do_not_carry_layer(tmp_path):
    """alerts stays a bare table this arc (HAZARD: its bulk-ack form + inline
    action controls fight fixed-layout/overflow); rules is not a table. Neither
    should emit the macro-only markers. (probes was converted to resize-only --
    its positive coverage is in test_probes_resize_only below.) A bare
    'data-table-id' substring is NOT a valid marker -- base.html defines the
    literal table[data-table-id="..."] selector on every page -- so assert on
    the resize grip + reset control, which only the opted-in macro emits."""
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            # Seed an alert so /alerts renders its (unconverted) table, not
            # the empty state -- a real negative, not a vacuous one. The
            # alerts.mac FK requires the device row first.
            db.upsert_device("aa:bb:cc:11:22:33", "wifi", None, 0, 1000)
            db.add_alert(
                ts=1000, rule_name="r", mac="aa:bb:cc:11:22:33",
                message="m", severity="low",
            )
            for path in ("/alerts", "/rules"):
                r = client.get(path)
                assert r.status_code == 200, f"{path} -> {r.status_code}"
                for marker in ("col-resizer", "data-table-reset"):
                    assert marker not in r.text, f"{path} leaked {marker!r}"
    finally:
        db.close()


# --- probes: resize-only conversion (two schemas, two table_ids) ----------

# The two probes groupings are distinct schemas, each its own keyed table.
PROBES_DEVICE_KEYS = ["device", "mac", "type", "vendor", "last_seen", "networks"]
PROBES_SSID_KEYS = ["device_count", "network"]


def _make_probes_app(tmp_path):
    config = Config(
        db_path=str(tmp_path / "probes.db"),
        kismet_health_check_on_startup=False,
        evidence_capture_enabled=False,
        capture=CaptureConfig(probe_ssids=True),
    )
    db = Database(config.db_path)
    db.ensure_location("default", "Default Location")
    db.upsert_device(mac="aa:aa:aa:aa:aa:aa", device_type="wifi",
                     oui_vendor="Apple", is_randomized=0, now_ts=1000)
    db.merge_device_probe_ssids("aa:aa:aa:aa:aa:aa", ["HomeNet", "Starbucks"])
    return create_app(config, db), db


def test_probes_resize_only_both_groupings_carry_layer(tmp_path):
    """Each probes grouping carries the resize grips + reset under its own
    table_id, but NEITHER the hide menu (resize-only) NOR a sort affordance
    (probes has no sortable columns)."""
    app, db = _make_probes_app(tmp_path)
    try:
        with TestClient(app) as client:
            views = {
                "probes-device": client.get("/probes?group=device").text,
                "probes-ssid": client.get("/probes?group=ssid").text,
            }
        for tid, html in views.items():
            assert f'data-table-id="{tid}"' in html
            assert "col-resizer" in html
            assert f'data-table-reset="{tid}"' in html
            assert f'window.__lynTableApply("{tid}")' in html
            # resize-only: the hide menu and the sort <a> must NOT appear.
            assert "data-cols-for" not in html, f"{tid} leaked the hide menu"
            assert "col-toggle" not in html, f"{tid} leaked a hide toggle"
            assert "th-sort" not in html, f"{tid} leaked a sort affordance"
    finally:
        db.close()


def test_probes_resize_only_colgroup_keys_match_headers(tmp_path):
    app, db = _make_probes_app(tmp_path)
    try:
        with TestClient(app) as client:
            device = client.get("/probes?group=device").text
            ssid = client.get("/probes?group=ssid").text
        dev_cols, dev_ths = _colgroup_and_header_keys(device)
        assert dev_cols == PROBES_DEVICE_KEYS
        assert dev_ths == PROBES_DEVICE_KEYS
        ssid_cols, ssid_ths = _colgroup_and_header_keys(ssid)
        assert ssid_cols == PROBES_SSID_KEYS
        assert ssid_ths == PROBES_SSID_KEYS
    finally:
        db.close()
