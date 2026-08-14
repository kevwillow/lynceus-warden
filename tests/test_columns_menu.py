"""Local validation for Touch D: the columns show/hide menu (data_table macro).

tests/ is gitignored; local-only validation, never committed. Run with the
pinned 3.11 venv.

Server-side testable surface (mirrors test_devices_column_layout's scope note --
the hide/show interaction, persistence, last-column guard, and reorder-then-hide
mapping are browser-only and are verified by code-reading + the operator's
eyes-on rig check):
  1. macro opt-IN: when table_id is set it emits the columns menu
     ([data-cols-for], one .col-toggle checkbox per column, each carrying its
     data-col-toggle key and rendered checked == visible-by-default).
  2. macro opt-OUT: when table_id is omitted, no menu markup leaks.
  3. raw-HTML label fallback: a column whose label is raw HTML (the allowlist
     select-all checkbox) gets a sane text menu label (its key) instead of
     nesting an <input> inside the menu <label>.
  4. route-level: /devices renders the menu with one checkbox per declared
     column key, in order.
"""

from __future__ import annotations

import re

from fastapi.testclient import TestClient
from markupsafe import Markup

from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import create_app

DEVICES_KEYS = [
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
        db_path=str(tmp_path / "colmenu.db"),
        kismet_health_check_on_startup=False,
        evidence_capture_enabled=False,
    )
    db = Database(config.db_path)
    db.ensure_location("default", "Default Location")
    with db._conn:
        db._conn.execute(
            "INSERT INTO devices(mac, device_type, first_seen, last_seen, "
            "sighting_count, oui_vendor, is_randomized, ble_name) "
            "VALUES (?,?,?,?,?,?,?,?)",
            ("11:22:33:44:55:66", "wifi", 100, 200, 3, "acme", 0, "node"),
        )
    db.insert_sighting("11:22:33:44:55:66", 1000, -42, "net-x", "default")
    return create_app(config, db), db


class _NonceRequest:
    """Minimal stand-in for the request the macro reads.

    ⚠️ `with context` on the import is NOT optional: a Jinja macro cannot see
    the caller's context without it, so `request.state.csp_nonce` renders
    EMPTY, the browser refuses that script, and nothing errors -- the
    table-state applier silently stops running. Production import sites all
    say `with context` (docs/AUDIT_REGISTER.md, Wave 5); these renders mirror
    that rather than papering over it with a template-side fallback."""

    class state:
        csp_nonce = "testnonce"


def _render(env, cols_literal, *, table_id):
    # v0.9.2 per-feature flags: table_id alone no longer enables the layer;
    # the hide menu needs hide=true (resize=true mirrors the converted tables
    # and gives the reset control its resize-or-hide trigger).
    arg = f", table_id='{table_id}', resize=true, hide=true" if table_id else ""
    tpl = (
        "{% from '_table_macro.html' import data_table with context %}"
        + cols_literal
        + "{% call data_table(cols, '/x', '', '', ''"
        + arg
        + ") %}<tr><td>c</td></tr>{% endcall %}"
    )
    return env.from_string(tpl).render(request=_NonceRequest)


_TWO_COLS = "{% set cols = [{'label':'Alpha','key':'a'},{'label':'Beta','key':'b'}] %}"


def test_macro_emits_columns_menu_when_table_id_set(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        html = _render(app.state.templates.env, _TWO_COLS, table_id="t1")
        assert 'data-cols-for="t1"' in html
        # one toggle per column, each keyed and checked (visible) by default
        assert html.count('class="col-toggle"') == 2
        assert 'data-col-toggle="a"' in html
        assert 'data-col-toggle="b"' in html
        assert html.count("checked") >= 2
        # reset control still present (not displaced by the new menu)
        assert 'data-table-reset="t1"' in html
        assert "reset columns" in html
    finally:
        db.close()


def test_macro_omits_columns_menu_when_table_id_absent(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        html = _render(app.state.templates.env, _TWO_COLS, table_id=None)
        for marker in ("data-cols-for", "col-toggle", "columns-menu"):
            assert marker not in html, f"opt-out leaked {marker!r}"
    finally:
        db.close()


def test_raw_html_first_label_falls_back_to_key(tmp_path):
    # Mirror the allowlist select-all column: label is raw HTML, key is 'select'.
    app, db = _make_app(tmp_path)
    try:
        env = app.state.templates.env
        env.globals["_RAW"] = Markup('<input type="checkbox" id="select-all-noop" disabled>')
        cols = (
            "{% set cols = [{'label':_RAW,'key':'select'},{'label':'pattern','key':'pattern'}] %}"
        )
        html = _render(env, cols, table_id="allow")
        # Isolate the menu panel and confirm its first label is the text "select",
        # not a nested <input> from the raw-HTML label.
        menu = html[html.index("columns-menu-list") : html.index("</details>")]
        # the only inputs inside the menu are the .col-toggle checkboxes (2),
        # i.e. the raw select-all <input> did NOT get injected as a label.
        assert menu.count("<input") == 2, menu
        assert re.search(r'data-col-toggle="select"[^>]*>\s*select\s*<', menu), menu
    finally:
        env.globals.pop("_RAW", None)
        db.close()


def test_devices_route_renders_menu_with_all_column_keys(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            html = client.get("/devices").text
        assert 'data-cols-for="devices"' in html
        menu = html[html.index('data-cols-for="devices"') : html.index("</details>")]
        keys = re.findall(r'data-col-toggle="([^"]+)"', menu)
        assert keys == DEVICES_KEYS
        # every menu checkbox starts checked (all columns visible by default)
        assert menu.count("checked") == len(DEVICES_KEYS)
    finally:
        db.close()
