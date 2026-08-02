"""Tests for the rc5 /watchlist search + filter + pagination upgrade.

Covers both halves of the upgrade:

* The new ``Database.list_watchlist_filtered`` DB helper and its
  ``_build_watchlist_filter_clauses`` shared filter-builder. The
  COUNT half and the page half MUST stay in lockstep; the
  consistency tests below guard the same invariant /alerts
  ack-all-visible depends on.

* The /watchlist GET route layer: query-param plumbing, filter
  state round-trip through pagination links, silent fallbacks on
  invalid filter values, and the "uncategorized" sentinel.

Existing tests in ``test_ui_watchlist.py`` cover the pre-rc5
default render path (which still must work byte-for-byte for the
no-query-params case) -- those tests stay green after this
upgrade and form a backward-compat guard.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database, WatchlistRow
from lynceus.webui.app import create_app


def _make_app(tmp_path):
    config = Config(db_path=str(tmp_path / "ui.db"))
    db = Database(config.db_path)
    app = create_app(config, db)
    return app, db


def _add_watchlist(
    db: Database,
    pattern: str,
    pattern_type: str = "mac",
    severity: str = "med",
    description: str | None = None,
) -> int:
    with db._conn:
        cur = db._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
            "VALUES (?, ?, ?, ?)",
            (pattern, pattern_type, severity, description),
        )
        return int(cur.lastrowid)


def _add_meta(db: Database, watchlist_id: int, **fields) -> int:
    payload = {
        "argus_record_id": fields.pop("argus_record_id", f"rec-{watchlist_id}"),
        "device_category": fields.pop("device_category", "test_category"),
    }
    payload.update(fields)
    return db.upsert_metadata(watchlist_id, payload)


# ---------------------------------------------------------------------------
# DB layer: list_watchlist_filtered single-dimension filters.
# ---------------------------------------------------------------------------


def test_filtered_no_filters_returns_all(tmp_path):
    db = Database(str(tmp_path / "x.db"))
    try:
        _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "high")
        _add_watchlist(db, "11:22:33", "oui", "med")
        rows, total = db.list_watchlist_filtered(page=1, per_page=50)
        assert total == 2
        assert len(rows) == 2
        assert all(isinstance(r, WatchlistRow) for r in rows)
    finally:
        db.close()


def test_filtered_pattern_type(tmp_path):
    db = Database(str(tmp_path / "x.db"))
    try:
        _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "high")
        _add_watchlist(db, "11:22:33", "oui", "med")
        _add_watchlist(db, "DangerNet", "ssid", "low")
        rows, total = db.list_watchlist_filtered(pattern_type="oui", page=1, per_page=50)
        assert total == 1
        assert [r.pattern_type for r in rows] == ["oui"]
        assert rows[0].pattern == "11:22:33"
    finally:
        db.close()


def test_filtered_severity(tmp_path):
    db = Database(str(tmp_path / "x.db"))
    try:
        _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "high", "h1")
        _add_watchlist(db, "aa:bb:cc:dd:ee:02", "mac", "med", "m1")
        _add_watchlist(db, "aa:bb:cc:dd:ee:03", "mac", "high", "h2")
        rows, total = db.list_watchlist_filtered(severity="high", page=1, per_page=50)
        assert total == 2
        assert all(r.severity == "high" for r in rows)
    finally:
        db.close()


def test_filtered_q_matches_pattern_substring(tmp_path):
    db = Database(str(tmp_path / "x.db"))
    try:
        _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "high")
        _add_watchlist(db, "11:22:33", "oui", "med")
        _add_watchlist(db, "DangerNet", "ssid", "low")
        rows, total = db.list_watchlist_filtered(q="dd:ee", page=1, per_page=50)
        assert total == 1
        assert rows[0].pattern == "aa:bb:cc:dd:ee:01"
    finally:
        db.close()


def test_filtered_q_matches_vendor_substring(tmp_path):
    db = Database(str(tmp_path / "x.db"))
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "x")
        _add_meta(db, wid, vendor="Axon Enterprise")
        _add_watchlist(db, "11:22:33", "oui", "med", "no-meta")
        rows, total = db.list_watchlist_filtered(q="axon", page=1, per_page=50)
        assert total == 1
        assert rows[0].vendor == "Axon Enterprise"
    finally:
        db.close()


def test_filtered_q_matches_argus_record_id_substring(tmp_path):
    db = Database(str(tmp_path / "x.db"))
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "x")
        _add_meta(db, wid, argus_record_id="argus-a3f2-001")
        _add_watchlist(db, "11:22:33", "oui", "med", "no-meta")
        rows, total = db.list_watchlist_filtered(q="a3f2", page=1, per_page=50)
        assert total == 1
        assert rows[0].argus_record_id == "argus-a3f2-001"
    finally:
        db.close()


def test_filtered_q_matches_device_category_substring(tmp_path):
    db = Database(str(tmp_path / "x.db"))
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "x")
        _add_meta(db, wid, device_category="surveillance_camera")
        _add_watchlist(db, "11:22:33", "oui", "med", "no-meta")
        rows, total = db.list_watchlist_filtered(q="surveillance", page=1, per_page=50)
        assert total == 1
        assert rows[0].device_category == "surveillance_camera"
    finally:
        db.close()


def test_filtered_q_case_insensitive(tmp_path):
    db = Database(str(tmp_path / "x.db"))
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "x")
        _add_meta(db, wid, vendor="ContosoCorp")
        rows, total = db.list_watchlist_filtered(q="CONTOSO", page=1, per_page=50)
        assert total == 1
    finally:
        db.close()


def test_filtered_device_category_exact(tmp_path):
    db = Database(str(tmp_path / "x.db"))
    try:
        wid1 = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "x")
        _add_meta(db, wid1, device_category="drone")
        wid2 = _add_watchlist(db, "aa:bb:cc:dd:ee:02", "mac", "med", "x")
        _add_meta(db, wid2, device_category="surveillance_camera")
        rows, total = db.list_watchlist_filtered(device_category="drone", page=1, per_page=50)
        assert total == 1
        assert rows[0].device_category == "drone"
    finally:
        db.close()


def test_filtered_device_category_uncategorized_sentinel(tmp_path):
    """The __none__ sentinel selects rows with no metadata JOIN partner."""
    db = Database(str(tmp_path / "x.db"))
    try:
        wid1 = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "x")
        _add_meta(db, wid1, device_category="drone")
        _add_watchlist(db, "11:22:33", "oui", "med", "no-meta-1")
        _add_watchlist(db, "DangerNet", "ssid", "low", "no-meta-2")
        rows, total = db.list_watchlist_filtered(
            device_category=Database._WATCHLIST_UNCATEGORIZED_SENTINEL,
            page=1,
            per_page=50,
        )
        assert total == 2
        assert all(r.device_category is None for r in rows)
    finally:
        db.close()


def test_filtered_combined_q_and_pattern_type_and_severity(tmp_path):
    db = Database(str(tmp_path / "x.db"))
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "high", "x")
        _add_meta(db, wid, vendor="Acme")
        _add_watchlist(db, "aa:bb:cc:dd:ee:02", "mac", "med", "y")  # wrong severity
        _add_watchlist(db, "aa:bb:cc:dd:ee:03", "oui", "high", "z")  # wrong type
        _add_watchlist(db, "DangerNet", "ssid", "high", "Acme-net")  # wrong type, matching q
        rows, total = db.list_watchlist_filtered(
            q="acme",
            pattern_type="mac",
            severity="high",
            page=1,
            per_page=50,
        )
        assert total == 1
        assert rows[0].pattern == "aa:bb:cc:dd:ee:01"
    finally:
        db.close()


def test_filtered_null_vendor_does_not_error_on_q(tmp_path):
    """COALESCE in the filter builder must keep NULL vendor harmless."""
    db = Database(str(tmp_path / "x.db"))
    try:
        _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "x")  # no meta
        rows, total = db.list_watchlist_filtered(q="anything", page=1, per_page=50)
        # Should not match (pattern doesn't contain "anything"); no error.
        assert total == 0
        assert rows == []
    finally:
        db.close()


# ---------------------------------------------------------------------------
# DB layer: validation.
# ---------------------------------------------------------------------------


def test_filtered_invalid_pattern_type_raises(tmp_path):
    db = Database(str(tmp_path / "x.db"))
    try:
        with pytest.raises(ValueError, match="pattern_type"):
            db.list_watchlist_filtered(pattern_type="bogus", page=1, per_page=50)
    finally:
        db.close()


def test_filtered_invalid_severity_raises(tmp_path):
    db = Database(str(tmp_path / "x.db"))
    try:
        with pytest.raises(ValueError, match="severity"):
            db.list_watchlist_filtered(severity="crit", page=1, per_page=50)
    finally:
        db.close()


def test_filtered_invalid_page_raises(tmp_path):
    db = Database(str(tmp_path / "x.db"))
    try:
        with pytest.raises(ValueError, match="page"):
            db.list_watchlist_filtered(page=0, per_page=50)
        with pytest.raises(ValueError, match="page"):
            db.list_watchlist_filtered(page=-5, per_page=50)
    finally:
        db.close()


# ---------------------------------------------------------------------------
# DB layer: pagination math.
# ---------------------------------------------------------------------------


def test_filtered_pagination_full_page(tmp_path):
    db = Database(str(tmp_path / "x.db"))
    try:
        for i in range(100):
            _add_watchlist(db, f"aa:bb:cc:dd:ee:{i:02x}", "mac", "med", f"d{i}")
        rows, total = db.list_watchlist_filtered(page=1, per_page=25)
        assert total == 100
        assert len(rows) == 25
        rows_page2, _ = db.list_watchlist_filtered(page=2, per_page=25)
        assert len(rows_page2) == 25
        # Ensure no overlap between pages 1 and 2.
        ids_p1 = {r.id for r in rows}
        ids_p2 = {r.id for r in rows_page2}
        assert ids_p1.isdisjoint(ids_p2)
    finally:
        db.close()


def test_filtered_pagination_last_page_partial(tmp_path):
    db = Database(str(tmp_path / "x.db"))
    try:
        for i in range(60):
            _add_watchlist(db, f"aa:bb:cc:dd:ee:{i:02x}", "mac", "med", f"d{i}")
        # per_page=25 -> 60/25 = 3 pages, last has 10.
        rows, total = db.list_watchlist_filtered(page=3, per_page=25)
        assert total == 60
        assert len(rows) == 10
    finally:
        db.close()


def test_filtered_pagination_count_consistency_under_filter(tmp_path):
    """COUNT and page query MUST apply the same filter set. The
    per-page row count summed across all pages must equal the
    reported total -- the same invariant /alerts ack-all-visible
    depends on."""
    db = Database(str(tmp_path / "x.db"))
    try:
        # Mix severities so a severity-filtered total != raw total.
        for i in range(40):
            _add_watchlist(db, f"aa:bb:cc:dd:ee:{i:02x}", "mac", "high", f"d{i}")
        for i in range(40, 70):
            _add_watchlist(db, f"aa:bb:cc:dd:ee:{i:02x}", "mac", "med", f"d{i}")
        rows_p1, total = db.list_watchlist_filtered(severity="high", page=1, per_page=15)
        rows_p2, total2 = db.list_watchlist_filtered(severity="high", page=2, per_page=15)
        rows_p3, total3 = db.list_watchlist_filtered(severity="high", page=3, per_page=15)
        assert total == total2 == total3 == 40
        assert len(rows_p1) + len(rows_p2) + len(rows_p3) == 40
        all_ids = {r.id for r in rows_p1 + rows_p2 + rows_p3}
        assert len(all_ids) == 40
    finally:
        db.close()


def test_filtered_sort_severity_then_pattern_then_id(tmp_path):
    """Sort order is total + deterministic across pagination."""
    db = Database(str(tmp_path / "x.db"))
    try:
        _add_watchlist(db, "z:pattern", "mac", "low", "low-z")
        _add_watchlist(db, "a:pattern", "mac", "high", "high-a")
        _add_watchlist(db, "m:pattern", "mac", "med", "med-m")
        _add_watchlist(db, "b:pattern", "mac", "high", "high-b")
        rows, _ = db.list_watchlist_filtered(page=1, per_page=50)
        descs = [r.description for r in rows]
        assert descs == ["high-a", "high-b", "med-m", "low-z"]
    finally:
        db.close()


# ---------------------------------------------------------------------------
# DB layer: distinct_watchlist_device_categories.
# ---------------------------------------------------------------------------


def test_distinct_device_categories_returns_sorted_unique(tmp_path):
    db = Database(str(tmp_path / "x.db"))
    try:
        wid1 = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "x")
        _add_meta(db, wid1, device_category="surveillance_camera")
        wid2 = _add_watchlist(db, "aa:bb:cc:dd:ee:02", "mac", "med", "x")
        _add_meta(db, wid2, device_category="drone")
        wid3 = _add_watchlist(db, "aa:bb:cc:dd:ee:03", "mac", "med", "x")
        _add_meta(db, wid3, device_category="drone")  # duplicate
        cats = db.distinct_watchlist_device_categories()
        assert cats == ["drone", "surveillance_camera"]
    finally:
        db.close()


def test_distinct_device_categories_excludes_null(tmp_path):
    db = Database(str(tmp_path / "x.db"))
    try:
        _add_watchlist(db, "11:22:33", "oui", "med")  # no metadata -> NULL category
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "x")
        _add_meta(db, wid, device_category="drone")
        cats = db.distinct_watchlist_device_categories()
        assert cats == ["drone"]
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Route layer: backward compat (no query params).
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_route_no_params_renders_first_page(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "high", "Threat A")
        _add_watchlist(db, "11:22:33", "oui", "med", "Threat B")
        with TestClient(app) as client:
            r = client.get("/watchlist")
        assert r.status_code == 200
        assert "Threat A" in r.text
        assert "Threat B" in r.text
        assert "Page 1 of 1" in r.text
        assert "2 total" in r.text
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Route layer: filter dimensions.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_route_q_filter(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "x")
        _add_meta(db, wid, vendor="Axon Enterprise")
        _add_watchlist(db, "11:22:33", "oui", "med", "no-meta")
        with TestClient(app) as client:
            r = client.get("/watchlist?q=axon")
        assert r.status_code == 200
        assert "Axon Enterprise" in r.text
        assert "11:22:33" not in r.text
        assert "1 total" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_route_pattern_type_filter(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "high")
        _add_watchlist(db, "11:22:33", "oui", "high")
        with TestClient(app) as client:
            r = client.get("/watchlist?pattern_type=oui")
        assert r.status_code == 200
        assert "11:22:33" in r.text
        assert "aa:bb:cc:dd:ee:01" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_route_severity_filter(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "high", "h-a")
        _add_watchlist(db, "aa:bb:cc:dd:ee:02", "mac", "low", "l-a")
        with TestClient(app) as client:
            r = client.get("/watchlist?severity=high")
        assert r.status_code == 200
        assert "h-a" in r.text
        assert "l-a" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_route_device_category_filter(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        wid1 = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "drone-row")
        _add_meta(db, wid1, device_category="drone")
        wid2 = _add_watchlist(db, "aa:bb:cc:dd:ee:02", "mac", "med", "camera-row")
        _add_meta(db, wid2, device_category="surveillance_camera")
        with TestClient(app) as client:
            r = client.get("/watchlist?device_category=drone")
        assert r.status_code == 200
        assert "drone-row" in r.text
        assert "camera-row" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_route_uncategorized_filter(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "has-meta-row")
        _add_meta(db, wid, device_category="drone")
        _add_watchlist(db, "11:22:33", "oui", "med", "bare-row")
        with TestClient(app) as client:
            r = client.get("/watchlist?device_category=__none__")
        assert r.status_code == 200
        assert "bare-row" in r.text
        assert "has-meta-row" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_route_combined_filters(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "high", "match")
        _add_meta(db, wid, vendor="Acme")
        _add_watchlist(db, "aa:bb:cc:dd:ee:02", "mac", "low", "wrong-sev")
        _add_watchlist(db, "11:22:33", "oui", "high", "wrong-type")
        with TestClient(app) as client:
            r = client.get("/watchlist?q=Acme&pattern_type=mac&severity=high")
        assert r.status_code == 200
        assert "match" in r.text
        assert "wrong-sev" not in r.text
        assert "wrong-type" not in r.text
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Route layer: invalid filter values silently fall back to "all".
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_route_invalid_severity_falls_back(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "high", "row-a")
        with TestClient(app) as client:
            r = client.get("/watchlist?severity=bogus")
        assert r.status_code == 200
        assert "row-a" in r.text  # not filtered out
    finally:
        db.close()


@pytest.mark.webui
def test_route_invalid_pattern_type_falls_back(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "high", "row-a")
        with TestClient(app) as client:
            r = client.get("/watchlist?pattern_type=lol")
        assert r.status_code == 200
        assert "row-a" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_route_invalid_device_category_falls_back(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "high", "row-a")
        _add_meta(db, wid, device_category="drone")
        with TestClient(app) as client:
            r = client.get("/watchlist?device_category=nonexistent")
        assert r.status_code == 200
        assert "row-a" in r.text
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Route layer: pagination clamping + edge cases.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_route_pagination_100_rows_25_per_page(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        for i in range(100):
            _add_watchlist(db, f"aa:bb:cc:dd:ee:{i:02x}", "mac", "med", f"d{i}")
        with TestClient(app) as client:
            r = client.get("/watchlist?page_size=25")
        assert r.status_code == 200
        assert "Page 1 of 4" in r.text
        assert "100 total" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_route_page_over_max_clamps_to_last(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        for i in range(10):
            _add_watchlist(db, f"aa:bb:cc:dd:ee:{i:02x}", "mac", "med", f"d{i}")
        with TestClient(app) as client:
            r = client.get("/watchlist?page=999&page_size=25")
        assert r.status_code == 200
        assert "Page 1 of 1" in r.text
        # The page is clamped silently, so rows still render.
        assert "d0" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_route_page_negative_falls_back_to_1(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "row-a")
        with TestClient(app) as client:
            r = client.get("/watchlist?page=-1")
        assert r.status_code == 200
        assert "Page 1 of 1" in r.text
        assert "row-a" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_route_per_page_invalid_falls_back_to_default(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "row-a")
        with TestClient(app) as client:
            r = client.get("/watchlist?page_size=999")
        assert r.status_code == 200
        assert "per_page=50" in r.text  # default
    finally:
        db.close()


@pytest.mark.webui
def test_route_empty_result_shows_empty_state(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "row-a")
        with TestClient(app) as client:
            r = client.get("/watchlist?q=zzznonsense")
        assert r.status_code == 200
        assert "No watchlist entries match" in r.text
        # Reset link surfaces when filters are active.
        assert 'href="/watchlist"' in r.text
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Route layer: filter state round-trip through pagination links.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_route_pagination_links_preserve_pattern_type(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        for i in range(60):
            _add_watchlist(db, f"aa:bb:cc:dd:ee:{i:02x}", "oui", "med", f"d{i}")
        with TestClient(app) as client:
            r = client.get("/watchlist?pattern_type=oui&page_size=25&page=2")
        assert r.status_code == 200
        assert "pattern_type=oui" in r.text
        # Next link should target page 3 with state preserved.
        assert "page=3" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_route_pagination_links_preserve_q(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        for i in range(60):
            _add_watchlist(db, f"aa:bb:cc:dd:ee:{i:02x}", "mac", "med", f"d{i}")
        with TestClient(app) as client:
            r = client.get("/watchlist?q=aa&page_size=25&page=2")
        assert r.status_code == 200
        assert "q=aa" in r.text
        assert "page=3" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_route_pagination_links_preserve_severity(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        for i in range(60):
            _add_watchlist(db, f"aa:bb:cc:dd:ee:{i:02x}", "mac", "high", f"d{i}")
        with TestClient(app) as client:
            r = client.get("/watchlist?severity=high&page_size=25&page=2")
        assert r.status_code == 200
        assert "severity=high" in r.text
        assert "page=3" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_route_pagination_links_preserve_device_category(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        for i in range(60):
            wid = _add_watchlist(db, f"aa:bb:cc:dd:ee:{i:02x}", "mac", "med", f"d{i}")
            _add_meta(db, wid, device_category="drone")
        with TestClient(app) as client:
            r = client.get("/watchlist?device_category=drone&page_size=25&page=2")
        assert r.status_code == 200
        assert "device_category=drone" in r.text
        assert "page=3" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_route_reset_link_clears_all_params(tmp_path):
    """Reset link in the filter bar points to bare /watchlist."""
    app, db = _make_app(tmp_path)
    try:
        _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "high")
        with TestClient(app) as client:
            r = client.get("/watchlist?severity=high&q=foo")
        assert r.status_code == 200
        assert 'href="/watchlist"' in r.text
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Route layer: filter-bar dropdown population.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_route_pattern_type_dropdown_lists_all_seven(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/watchlist")
        assert r.status_code == 200
        for pt in (
            "mac",
            "oui",
            "ssid",
            "ble_uuid",
            "mac_range",
            "ble_manufacturer_id",
            "drone_id_prefix",
        ):
            assert f'value="{pt}"' in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_route_device_category_dropdown_populated_from_db(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "x")
        _add_meta(db, wid, device_category="quadcopter_drone")
        with TestClient(app) as client:
            r = client.get("/watchlist")
        assert r.status_code == 200
        assert "quadcopter_drone" in r.text
        # The uncategorized option is always present.
        assert "(uncategorized)" in r.text
    finally:
        db.close()
