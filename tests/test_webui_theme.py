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


def _seed_detail_ids(db, alert_id, now_ts=1700000000):
    """Seed the DETAIL pages too, so they are exercised rather than skipped.

    ⛔ `/watchful/{entry_id}` and `/watchlist/{watchlist_id}` were covered by
    NOTHING: absent from both hardcoded "every page" lists, and silently
    dropped by the derived enumeration because no id was seeded for them. The
    unseeded-parameter assertion in `html_get_paths` is what surfaced them —
    a guard that skips what it cannot construct hides exactly the pages nobody
    remembered to list.
    """
    watchlist_id, _ = db.add_watchlist(
        pattern="aa:bb:cc:dd:ee:ff", pattern_type="mac", severity="low",
        description="seeded for detail-page coverage",
    )
    entry_id = db.create_watchful_from_alert(alert_id, None, now_ts)
    return {"watchlist_id": watchlist_id, "entry_id": entry_id}


# ⛔ This was a hand-maintained tuple of 11 paths, described as "every
# operator-facing GET route". The app serves 18 GET routes. `/probes` was in
# neither this list nor the topnav guard's, so it could ship with no theme
# bootstrap and no navigation while both stayed green -- and `/probes` renders
# probe-SSID history, the most sensitive data this tool holds.
#
# ⭐ Deriving is CORRECT here, unlike the migration-filename manifest in
# tests/test_db.py, and the difference is worth stating because the two look
# alike. There, both sides would have read the filesystem -- the expectation
# would have been derived from the same glob it was checked against, so it
# could never fail. Here the corpus comes from the ROUTER and the expectation
# is "each renders a theme bootstrap": genuinely independent sources. The rule
# is not "derive manifests", it is that the two sides must read different
# things.
#
# Modelled on the AGPL source-link guard (tests/test_webui.py), which already
# enumerates from `app.routes` and asserts a floor. Same shape, same reasons.

def html_get_paths(app, **subs):
    """Every GET route on ``app``, with ``{param}`` substituted from ``subs``.

    Returns concrete paths. Routes whose parameters have no seeded value are
    skipped and REPORTED by the caller's floor assertion rather than silently
    dropped -- a filter that excluded everything would make any loop over this
    vacuous and green.

    Non-HTML responses (``/alerts.csv``, ``/healthz.json``) are NOT excluded
    here by name: the caller filters on the response's own content-type, so a
    new export route needs no edit to this function and cannot be forgotten.
    """
    import re as _re

    paths = []
    for route in app.routes:
        if "GET" not in (getattr(route, "methods", None) or set()):
            continue
        path = getattr(route, "path", "")
        if not path or path.startswith("/static"):
            continue
        if path in ("/openapi.json", "/docs", "/redoc", "/docs/oauth2-redirect"):
            continue
        # `{mac:path}` -> `mac`; converters are not part of the name.
        names = [m.split(":")[0] for m in _re.findall(r"\{([^}]+)\}", path)]
        # ⛔ An unseeded parameter is an ERROR, not a reason to skip. Skipping
        # means a newly added route is never requested, and the count floor
        # cannot notice because it counts what WAS checked. Measured: adding
        # `/reports/{report_id}` without seeding `report_id` left every
        # assertion green while the new page went entirely untested.
        unseeded = [n for n in names if n not in subs or subs[n] is None]
        if unseeded:
            raise AssertionError(
                f"route {path} has no seeded value for {unseeded}. Add one to "
                f"the caller's subs= so the page is actually exercised; do not "
                f"let it drop silently out of coverage."
            )
        for n in names:
            path = _re.sub(r"\{" + _re.escape(n) + r"(:[^}]+)?\}", str(subs[n]), path)
        paths.append(path)
    return sorted(set(paths))


@pytest.mark.webui
def test_theme_bootstrap_script_present_in_head_on_every_page(tmp_path):
    """Inline FOUC bootstrap must render in <head> before the stylesheet.

    Without it, operators who picked light or dark see a flash of the
    OS-default theme between first paint and deferred lynceus.js
    running. The two literal substrings asserted here are the unique
    fingerprint of the bootstrap snippet — specific enough that no
    page body could collide.

    Ordering matters: the bootstrap must come before the app.css
    link so data-theme is on <html> before CSS is parsed. Otherwise
    the forced-theme palette can still flash for one frame. (app.css is
    the cascade-layer entry that @imports Pico + lynceus.css; the page's
    only stylesheet link.)
    """
    app, db = _make_app(tmp_path)
    try:
        alert_id = _seed_minimal(db)
        mac = "aa:bb:cc:dd:ee:ff"

        checked = []
        # ⛔ follow_redirects=False. With following ON, `/probes` redirecting
        # to `/` returns the HOME page's 200 HTML -- topnav and theme bootstrap
        # included -- and the guard appends "/probes" to `checked`. Measured:
        # both guards stay green while /probes stops rendering, and even the
        # explicit `"/probes" in checked` canary passes.
        with TestClient(app, follow_redirects=False) as client:
            for path in html_get_paths(
                app, alert_id=alert_id, mac=mac, **_seed_detail_ids(db, alert_id)
            ):
                resp = client.get(path)
                # ⛔ A 5xx is never a legitimate reason to skip. Without this,
                # a page that started erroring would be silently dropped from
                # coverage -- and if any page were added in the same change the
                # count floor below would still pass. That is the one way a
                # page can vanish from this guard unnoticed.
                # 404 stays skippable: /devices/{mac}/co-observations is
                # feature-gated off by default and correctly 404s.
                assert resp.status_code < 500, (
                    f"{path} returned {resp.status_code}; a broken page must "
                    f"fail this guard, not be skipped by it"
                )
                assert not (300 <= resp.status_code < 400), (
                    f"{path} redirected ({resp.status_code}); a redirect would "
                    f"otherwise be counted as this page having rendered"
                )
                if resp.status_code != 200:
                    continue
                if "text/html" not in resp.headers.get("content-type", ""):
                    continue
                checked.append(path)
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
                idx_css = text.find("app.css")
                assert idx_bootstrap >= 0 and idx_css >= 0
                assert idx_bootstrap < idx_css, (
                    f"{path}: bootstrap script must precede app.css "
                    f"to avoid FOUC (found bootstrap at {idx_bootstrap}, "
                    f"css at {idx_css})"
                )
        # ⭐ A filter that excluded everything would make the loop vacuous and
        # green -- the exact failure the old hardcoded list had, just faster.
        assert len(checked) >= 14, (
            f"only checked {len(checked)} HTML pages ({checked}); the route "
            f"enumeration is excluding pages it should cover"
        )
        assert "/probes" in checked, (
            "/probes was the page missing from BOTH hardcoded lists; it must "
            "stay covered by the derived enumeration"
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

        checked = []
        # ⛔ follow_redirects=False. With following ON, `/probes` redirecting
        # to `/` returns the HOME page's 200 HTML -- topnav and theme bootstrap
        # included -- and the guard appends "/probes" to `checked`. Measured:
        # both guards stay green while /probes stops rendering, and even the
        # explicit `"/probes" in checked` canary passes.
        with TestClient(app, follow_redirects=False) as client:
            for path in html_get_paths(
                app, alert_id=alert_id, mac=mac, **_seed_detail_ids(db, alert_id)
            ):
                resp = client.get(path)
                # ⛔ A 5xx is never a legitimate reason to skip. Without this,
                # a page that started erroring would be silently dropped from
                # coverage -- and if any page were added in the same change the
                # count floor below would still pass. That is the one way a
                # page can vanish from this guard unnoticed.
                # 404 stays skippable: /devices/{mac}/co-observations is
                # feature-gated off by default and correctly 404s.
                assert resp.status_code < 500, (
                    f"{path} returned {resp.status_code}; a broken page must "
                    f"fail this guard, not be skipped by it"
                )
                assert not (300 <= resp.status_code < 400), (
                    f"{path} redirected ({resp.status_code}); a redirect would "
                    f"otherwise be counted as this page having rendered"
                )
                if resp.status_code != 200:
                    continue
                if "text/html" not in resp.headers.get("content-type", ""):
                    continue
                checked.append(path)
                assert "data-theme-toggle" in resp.text, (
                    f"{path}: theme-toggle button hook missing"
                )
                assert 'class="theme-toggle"' in resp.text, (
                    f"{path}: .theme-toggle class on toggle button missing"
                )
        assert len(checked) >= 14, (
            f"only checked {len(checked)} HTML pages ({checked}); the route "
            f"enumeration is excluding pages it should cover"
        )
        assert "/probes" in checked
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
        # ⛔ follow_redirects=False. With following ON, `/probes` redirecting
        # to `/` returns the HOME page's 200 HTML -- topnav and theme bootstrap
        # included -- and the guard appends "/probes" to `checked`. Measured:
        # both guards stay green while /probes stops rendering, and even the
        # explicit `"/probes" in checked` canary passes.
        with TestClient(app, follow_redirects=False) as client:
            page = client.get("/")
            js = client.get("/static/lynceus.js")
        assert page.status_code == 200
        assert js.status_code == 200
        assert 'localStorage.getItem("lynceus-theme")' in page.text
        assert '"lynceus-theme"' in js.text
        assert "localStorage" in js.text
    finally:
        db.close()
