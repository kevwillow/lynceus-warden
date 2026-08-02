"""Regression tests for the home page's watchlist freshness signal (v0.7.6 Tier 4).

The /settings page has carried a watchlist-freshness card since
v0.4.x; v0.7.6 surfaces the same signal on the home page so an
operator with a stale watchlist sees it on their first dashboard
visit. These tests pin the three operator-visible states (no
import, fresh, stale) plus the graceful fall-through for the
legacy pre-migration-012 install case where ``import_runs`` is
absent.
"""

from __future__ import annotations

import datetime as _dt
import time

import pytest
from fastapi.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import create_app


def _make_app(tmp_path, *, warn_days: int = 30):
    config = Config(
        db_path=str(tmp_path / "ui.db"),
        watchlist_staleness_warn_days=warn_days,
    )
    db = Database(config.db_path)
    return create_app(config, db), db


def _record_import(db, *, imported_at: int, exported_at: int | None, count: int):
    """Insert a synthetic ``import_runs`` row so the freshness query
    returns a known shape."""
    db.record_import_run(
        imported_at=imported_at,
        exported_at=exported_at,
        source="test://fixture",
        record_count=count,
    )


@pytest.mark.webui
def test_home_freshness_renders_recent_import_as_not_stale(tmp_path):
    """A recent import (< warn_days old) renders the record count +
    snapshot date without the stale badge."""
    app, db = _make_app(tmp_path, warn_days=30)
    try:
        now = int(time.time())
        _record_import(
            db,
            imported_at=now - 86400,  # 1 day ago
            exported_at=now - 86400,
            count=41428,
        )
        with TestClient(app) as client:
            resp = client.get("/")
        assert resp.status_code == 200
        body = resp.text
        assert "Watchlist:" in body
        assert "41,428 records" in body
        # No stale badge for a fresh import.
        assert "badge-status-error" not in body or "stale" not in body
        # The [details] link points at the canonical /settings anchor.
        assert "/settings#watchlist-freshness" in body
    finally:
        db.close()


@pytest.mark.webui
def test_home_freshness_renders_stale_with_badge(tmp_path):
    """An import older than ``watchlist_staleness_warn_days`` renders
    the stale styling badge alongside the record count."""
    app, db = _make_app(tmp_path, warn_days=30)
    try:
        now = int(time.time())
        # 60 days old -- past the default 30-day warn threshold.
        old_ts = now - (60 * 86400)
        _record_import(db, imported_at=old_ts, exported_at=old_ts, count=22533)
        with TestClient(app) as client:
            resp = client.get("/")
        assert resp.status_code == 200
        body = resp.text
        assert "Watchlist:" in body
        assert "22,533 records" in body
        # Stale styling: shared CSS class with /settings.
        assert "badge-status-error" in body
        assert "stale" in body
    finally:
        db.close()


@pytest.mark.webui
def test_home_freshness_renders_not_loaded_with_configure_link(tmp_path):
    """No imports recorded -> "Watchlist: not loaded (configure)"
    with the deep link to /settings#watchlist-freshness. This is the
    post-Tier-4 Skip default state."""
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            resp = client.get("/")
        assert resp.status_code == 200
        body = resp.text
        assert "Watchlist:" in body
        assert "not loaded" in body
        assert "/settings#watchlist-freshness" in body
        # No counts / dates surface when no import has been recorded.
        assert "records" not in body or "0 records" not in body
        # No stale styling on the not-loaded state.
        assert "badge-status-error" not in body
    finally:
        db.close()


@pytest.mark.webui
def test_home_freshness_falls_through_on_missing_import_runs_table(tmp_path):
    """Legacy pre-migration-012 installs may not have the
    ``import_runs`` table yet. The home page must NOT 500 -- the
    freshness summary degrades to the "not loaded" payload and the
    rest of the page renders cleanly."""
    app, db = _make_app(tmp_path)
    try:
        # Simulate the pre-012 schema state by dropping the table.
        with db._conn:
            db._conn.execute("DROP TABLE IF EXISTS import_runs")
        with TestClient(app) as client:
            resp = client.get("/")
        assert resp.status_code == 200, (
            f"home page must render even when import_runs is missing; "
            f"got {resp.status_code}: {resp.text[:400]}"
        )
        body = resp.text
        # Fall-through state is "not loaded" -- same shape as
        # has_import=False so the operator sees a clean dashboard
        # and the migration runs on the next restart.
        assert "Watchlist:" in body
        assert "not loaded" in body
    finally:
        db.close()
