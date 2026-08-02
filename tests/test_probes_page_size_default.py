"""Local validation for Touch C: /probes default page size raised 25 -> 50.

tests/ is gitignored; this file is local-only validation and is never
committed. Run with the pinned 3.11 venv.

Scope: this is a *default constant* change only -- the dropdown vocabulary and
the ?page_size override already existed and are unchanged, and the choice is
NOT persisted. So the testable surface is:
  1. the constant itself is 50 and 50 is a member of the allowed set;
  2. a /probes request with no ?page_size renders 50 as the selected option;
  3. the page-size dropdown still offers the full allowed set;
  4. an explicit ?page_size still overrides the default (override path intact).
"""

from __future__ import annotations

import re

from fastapi.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui import app as webui_app
from lynceus.webui.app import (
    _PROBES_PER_PAGE_ALLOWED,
    _PROBES_PER_PAGE_DEFAULT,
    create_app,
)


def _make_app(tmp_path):
    config = Config(
        db_path=str(tmp_path / "probes_pagesize.db"),
        kismet_health_check_on_startup=False,
        evidence_capture_enabled=False,
    )
    db = Database(config.db_path)
    db.ensure_location("default", "Default Location")
    return create_app(config, db), db


def test_probes_default_constant_is_50_and_in_allowed_set():
    assert _PROBES_PER_PAGE_DEFAULT == 50
    assert 50 in _PROBES_PER_PAGE_ALLOWED
    # match /devices default exactly (the brief's "match devices")
    assert _PROBES_PER_PAGE_DEFAULT == webui_app._DEVICES_PER_PAGE_DEFAULT


def _selected_page_size(html: str) -> int:
    # The probes filter form renders <option value="N" selected>N</option>.
    m = re.search(r'<option value="(\d+)"\s+selected\s*>', html)
    assert m, "no selected page-size option found in /probes"
    return int(m.group(1))


def test_probes_no_param_selects_50(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            html = client.get("/probes").text
        assert _selected_page_size(html) == 50
    finally:
        db.close()


def test_probes_dropdown_still_offers_full_allowed_set(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            html = client.get("/probes").text
        # Every allowed value is offered as an <option value="N">.
        for n in _PROBES_PER_PAGE_ALLOWED:
            assert f'<option value="{n}"' in html, f"missing page-size option {n}"
    finally:
        db.close()


def test_probes_explicit_param_still_overrides_default(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            html = client.get("/probes?page_size=100").text
        assert _selected_page_size(html) == 100
    finally:
        db.close()
