"""Local validation for the /devices client-side column resize + reorder +
per-table persistence layer (0.9.2 table-UX arc, Touch 3 -- commit b792f42).

IMPORTANT scope note -- read before extending:
  The persistence mechanism is **browser localStorage only**
  (localStorage["lynceus-table:<id>"]). There is NO server-side storage,
  no write endpoint, no DB column-state table. The server's only role is
  rendering the opt-in markup (the data_table macro) and shipping the
  client applier (window.__lynTableApply in base.html). Therefore the
  *server-side* testable surface is:

    1. The macro's opt-IN contract: when table_id is set it emits the
       data-table-id, the keyed <colgroup>, per-th data-col-key + resize
       grip, the pre-paint applier invocation, and the reset control.
    2. The macro's opt-OUT contract: when table_id is omitted it emits
       NONE of that -- the proof that unmigrated tables render as before.
    3. Route-level ISOLATION: /devices carries the layer; the still-
       unconverted list pages (alerts/probes) do NOT. (watchlist + watchful
       + allowlist were converted in the 0.9.2 roll-out -- their positive
       coverage lives in test_rollout_column_layout.py.)
    4. Column-key INTEGRITY: every devices column carries a stable key and
       the rendered <colgroup> col-keys correspond 1:1, in order, to the
       <thead> th keys -- the invariant __lynTableApply's positional
       permutation depends on (a future column added without a key, or a
       key/col mismatch, would silently corrupt reorder).
    5. The applier is actually DEFINED in <head> (the macro invokes it; a
       missing definition would be a silent no-op).

  What these tests deliberately do NOT cover (browser-only, no JS runtime
  in this suite -- verified by code-reading + the operator manual
  checklist instead):
    - the drag-to-resize / drag-to-reorder pointer interaction (lynceus.js)
    - __lynTableApply's corruption resilience (malformed JSON, stored
      order referencing an unknown column, bad width values, colspan rows).
      Reviewed in base.html: each failure mode degrades to the
      server-rendered default. Exercise it manually via devtools (inject
      a bad localStorage["lynceus-table:devices"] value, reload).

tests/ is gitignored; this file is local-only validation and is never
committed. Run with the pinned 3.11 venv.
"""

from __future__ import annotations

import re

from fastapi.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import create_app

# The 12 devices columns, in render order, as declared in devices_list.html.
# Mirrored here so a column added/renamed/reordered without updating the key
# wiring trips a test rather than silently corrupting persisted layouts.
EXPECTED_KEYS = [
    "device",
    "mac",
    "device_type",
    "oui_vendor",
    "ble_name",
    "ble_device_class",
    "probes",
    "is_randomized",
    "first_seen",
    "last_seen",
    "last_rssi",
    "last_ssid",
    "sighting_count",
]


def _make_app(tmp_path):
    config = Config(
        db_path=str(tmp_path / "collayout.db"),
        kismet_health_check_on_startup=False,
        evidence_capture_enabled=False,
    )
    db = Database(config.db_path)
    db.ensure_location("default", "Default Location")
    # Seed one device so the /devices table actually renders -- the template
    # gates the whole <table> behind {% if devices %}, so an empty DB would
    # show the "no devices" empty state and never emit the layer.
    with db._conn:
        db._conn.execute(
            "INSERT INTO devices(mac, device_type, first_seen, last_seen, "
            "sighting_count, oui_vendor, is_randomized, ble_name) "
            "VALUES (?,?,?,?,?,?,?,?)",
            ("11:22:33:44:55:66", "wifi", 100, 200, 3, "acme", 0, "node"),
        )
    db.insert_sighting("11:22:33:44:55:66", 1000, -42, "net-x", "default")
    return create_app(config, db), db


# Two columns: one sortable (exercises the sort <a> + grip coexistence path),
# one plain. Distinct keys so order is unambiguous.
_COLS = (
    "{% set cols = ["
    "{'label':'Alpha','sort':'a','key':'a'},"
    "{'label':'Beta','key':'b'}"
    "] %}"
)


class _NonceRequest:
    """Minimal stand-in for the request the macro reads.

    ⚠️ `with context` on the import is NOT optional and is not cosmetic: a
    Jinja macro cannot see the caller's context without it, so
    `request.state.csp_nonce` renders EMPTY, the browser refuses that script,
    and nothing errors -- the table-state applier just stops running. Every
    production import site says `with context` for this reason
    (docs/AUDIT_REGISTER.md, Wave 5), so these renders mirror it rather than
    working around it with a template-side fallback."""

    class state:
        csp_nonce = "testnonce"


def _render_macro(env, *, table_id):
    # v0.9.2 per-feature flags: table_id alone no longer enables the layer;
    # the four converted tables pass resize=true, hide=true to keep the full
    # resize/reorder + hide-menu + reset layer this suite asserts.
    arg = f", table_id='{table_id}', resize=true, hide=true" if table_id else ""
    tpl = (
        "{% from '_table_macro.html' import data_table with context %}"
        + _COLS
        + "{% call data_table(cols, '/devices', 'page_size=50', 'a', 'asc'"
        + arg
        + ") %}<tr><td>cellA</td><td>cellB</td></tr>{% endcall %}"
    )
    return env.from_string(tpl).render(request=_NonceRequest)


# --- 1. macro opt-IN contract --------------------------------------------


def test_macro_emits_full_layer_when_table_id_set(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        html = _render_macro(app.state.templates.env, table_id="t1")
        # table marker
        assert 'data-table-id="t1"' in html
        # keyed colgroup, in column order
        assert "<colgroup>" in html
        assert '<col data-col-key="a">' in html
        assert '<col data-col-key="b">' in html
        assert html.index('data-col-key="a"') < html.index('data-col-key="b"')
        # per-th key + resize grip (one grip per column)
        assert html.count('class="col-resizer"') == 2
        # pre-paint applier invocation for THIS table id
        assert 'window.__lynTableApply("t1")' in html
        # reset control
        assert 'data-table-reset="t1"' in html
        assert "reset columns" in html
        # caller body still lands in the tbody
        assert "cellA" in html and "cellB" in html
    finally:
        db.close()


# --- 2. macro opt-OUT contract (isolation core) --------------------------


def test_macro_omits_entire_layer_when_table_id_absent(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        html = _render_macro(app.state.templates.env, table_id=None)
        for marker in (
            "data-table-id",
            "<colgroup",
            "data-col-key",
            "col-resizer",
            "__lynTableApply",
            "data-table-reset",
        ):
            assert marker not in html, f"opt-out leaked {marker!r}"
        # ...but the table still renders normally: sort link + caller body.
        assert "th-sort" in html
        assert "cellA" in html and "cellB" in html
    finally:
        db.close()


# --- 3. route-level isolation --------------------------------------------


def test_devices_route_carries_layer(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/devices")
        assert r.status_code == 200
        assert 'data-table-id="devices"' in r.text
        assert "col-resizer" in r.text
        assert 'data-table-reset="devices"' in r.text
        assert 'window.__lynTableApply("devices")' in r.text
    finally:
        db.close()


def test_other_list_pages_do_not_carry_layer(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            # /alerts stays a bare table (deferred HAZARD); /probes was
            # converted to resize-only (covered in test_rollout_column_layout).
            for path in ("/alerts",):
                r = client.get(path)
                assert r.status_code == 200, f"{path} -> {r.status_code}"
                # NB: a bare "data-table-id" substring is NOT a valid marker --
                # base.html's __lynTableApply defines the literal
                # table[data-table-id="...] on EVERY page. The macro-only
                # markers are the resize grip class and the reset control.
                for marker in ("col-resizer", "data-table-reset"):
                    assert marker not in r.text, f"{path} leaked {marker!r}"
    finally:
        db.close()


# --- 4. column-key integrity (the permutation invariant) -----------------


def test_devices_colgroup_keys_match_header_keys_in_order(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            html = client.get("/devices").text

        colgroup = html[html.index("<colgroup>") : html.index("</colgroup>")]
        col_keys = re.findall(r'<col data-col-key="([^"]+)"', colgroup)

        thead = html[html.index("<thead>") : html.index("</thead>")]
        th_keys = re.findall(r'data-col-key="([^"]+)"', thead)

        # Every declared column has a non-empty key; colgroup and header
        # agree 1:1 in order (what __lynTableApply's positional permutation
        # relies on to move keyless <td>s in lockstep).
        assert col_keys == EXPECTED_KEYS
        assert th_keys == EXPECTED_KEYS
        assert "" not in col_keys  # no column shipped without a key
    finally:
        db.close()


# --- 5. applier is actually shipped --------------------------------------


def test_applier_defined_in_head(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            html = client.get("/devices").text
        # The macro invokes window.__lynTableApply(...); base.html must
        # define it, or the pre-paint call is a silent no-op.
        assert "window.__lynTableApply = function" in html
    finally:
        db.close()
