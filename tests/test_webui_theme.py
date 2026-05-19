"""Tests guarding the dark-mode theme bootstrap + toggle UI surface.

Regression target: 3d3e979 (feat(webui): inline <head> theme bootstrap
to eliminate FOUC). Asserts:

  1. The synchronous theme-bootstrap script is present in <head> on
     every operator-facing page, and it runs BEFORE the stylesheet
     link so it can set data-theme before first paint.
  2. The bootstrap reader and the lynceus.js writer share the same
     localStorage key ("lynceus-theme"). Drift between writer and
     reader would silently re-introduce FOUC for any operator on a
     forced theme.
  3. The topnav theme-toggle button (with the data-theme-toggle hook)
     is present on every operator-facing page.

Page coverage extends test_topnav_present_on_every_page
(test_webui.py:1842) to also include /watchlist, /watchful, /settings
which that test predates.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import create_app


def _make_app(tmp_path):
    config = Config(db_path=str(tmp_path / "ui.db"))
    db = Database(config.db_path)
    app = create_app(config, db)
    return app, db


def _seed_minimal(db, now_ts=1700000000):
    db.ensure_location("default", "Default")
    db.upsert_device(
        mac="aa:bb:cc:dd:ee:ff",
        device_type="wifi",
        oui_vendor="TestVendor",
        is_randomized=0,
        now_ts=now_ts,
    )
    db.insert_sighting(
        mac="aa:bb:cc:dd:ee:ff",
        ts=now_ts,
        rssi=-50,
        ssid="test",
        location_id="default",
    )
    return db.add_alert(
        ts=now_ts,
        rule_name="test_rule",
        mac="aa:bb:cc:dd:ee:ff",
        message="test alert",
        severity="low",
    )


# Every operator-facing GET route that renders the base template. The
# detail-page entries get .format()ed with the seeded ids below.
PAGE_TEMPLATES = (
    "/",
    "/healthz",
    "/alerts",
    "/alerts/{alert_id}",
    "/devices",
    "/devices/{mac}",
    "/rules",
    "/allowlist",
    "/watchful",
    "/watchlist",
    "/settings",
)


@pytest.mark.webui
def test_theme_bootstrap_script_present_in_head_on_every_page(tmp_path):
    """Inline FOUC bootstrap must render in <head> before the stylesheet.

    Without it, operators who picked light or dark see a flash of the
    OS-default theme between first paint and deferred lynceus.js
    running. The two literal substrings asserted here are the unique
    fingerprint of the bootstrap snippet — specific enough that no
    page body could collide.

    Ordering matters: the bootstrap must come before the lynceus.css
    link so data-theme is on <html> before CSS is parsed. Otherwise
    the forced-theme palette can still flash for one frame.
    """
    app, db = _make_app(tmp_path)
    try:
        alert_id = _seed_minimal(db)
        mac = "aa:bb:cc:dd:ee:ff"

        with TestClient(app) as client:
            for tmpl in PAGE_TEMPLATES:
                path = tmpl.format(alert_id=alert_id, mac=mac)
                resp = client.get(path)
                assert resp.status_code == 200, (
                    f"{path} returned {resp.status_code}"
                )
                text = resp.text

                assert 'localStorage.getItem("lynceus-theme")' in text, (
                    f"{path}: FOUC bootstrap localStorage read missing"
                )
                assert 'setAttribute("data-theme"' in text, (
                    f"{path}: FOUC bootstrap data-theme setter missing"
                )

                idx_bootstrap = text.find(
                    'localStorage.getItem("lynceus-theme")'
                )
                idx_css = text.find("lynceus.css")
                assert idx_bootstrap >= 0 and idx_css >= 0
                assert idx_bootstrap < idx_css, (
                    f"{path}: bootstrap script must precede lynceus.css "
                    f"to avoid FOUC (found bootstrap at {idx_bootstrap}, "
                    f"css at {idx_css})"
                )
    finally:
        db.close()


@pytest.mark.webui
def test_theme_toggle_button_present_on_every_page(tmp_path):
    """Every operator-facing page must render the topnav theme toggle.

    Extends test_topnav_present_on_every_page (test_webui.py:1842) to
    cover the theme-toggle button specifically and to include
    /watchlist, /watchful, /settings which that test predates.
    """
    app, db = _make_app(tmp_path)
    try:
        alert_id = _seed_minimal(db)
        mac = "aa:bb:cc:dd:ee:ff"

        with TestClient(app) as client:
            for tmpl in PAGE_TEMPLATES:
                path = tmpl.format(alert_id=alert_id, mac=mac)
                resp = client.get(path)
                assert resp.status_code == 200, (
                    f"{path} returned {resp.status_code}"
                )
                assert "data-theme-toggle" in resp.text, (
                    f"{path}: theme-toggle button hook missing"
                )
                assert 'class="theme-toggle"' in resp.text, (
                    f"{path}: .theme-toggle class on toggle button missing"
                )
    finally:
        db.close()


@pytest.mark.webui
def test_bootstrap_and_toggle_share_storage_key(tmp_path):
    """Bootstrap reader and toggle writer must use the same localStorage key.

    If they ever drift (one says "lynceus-theme", the other says
    "theme"), the forced-theme case silently re-introduces FOUC: the
    bootstrap reads nothing matching what the toggle wrote, leaves
    data-theme unset, and the page flashes prefers-color-scheme before
    deferred lynceus.js applies the stored choice on its own.
    """
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            page = client.get("/")
            js = client.get("/static/lynceus.js")
        assert page.status_code == 200
        assert js.status_code == 200
        assert 'localStorage.getItem("lynceus-theme")' in page.text
        assert '"lynceus-theme"' in js.text
        assert "localStorage" in js.text
    finally:
        db.close()
