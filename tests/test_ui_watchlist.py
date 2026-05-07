"""Tests for the read-only watchlist UI added in v0.3.

Covers the /watchlist list page and /watchlist/<id> detail page that
surface watchlist_metadata fields (vendor, confidence, source, etc.)
when present, and degrade gracefully to the bare watchlist row when
no metadata exists.
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
# /watchlist list page — smoke and shape.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_watchlist_list_returns_200_and_heading(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/watchlist")
        assert r.status_code == 200
        assert "watchlist" in r.text.lower()
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_list_renders_all_entries(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "high", "Threat A")
        _add_watchlist(db, "11:22:33", "oui", "med", "Threat B")
        _add_watchlist(db, "DangerNet", "ssid", "low", "Threat C")
        with TestClient(app) as client:
            r = client.get("/watchlist")
        assert r.status_code == 200
        assert "aa:bb:cc:dd:ee:01" in r.text
        assert "11:22:33" in r.text
        assert "DangerNet" in r.text
        assert "Threat A" in r.text
        assert "Threat B" in r.text
        assert "Threat C" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_list_mixed_metadata_renders_cleanly(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        wid_with = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "high", "with-meta")
        _add_meta(db, wid_with, vendor="Acme", confidence=85)
        _add_watchlist(db, "aa:bb:cc:dd:ee:02", "mac", "low", "no-meta")
        with TestClient(app) as client:
            r = client.get("/watchlist")
        assert r.status_code == 200
        assert "with-meta" in r.text
        assert "no-meta" in r.text
        assert "Acme" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_list_empty_renders_clean(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/watchlist")
        assert r.status_code == 200
        # Page should not crash on empty data.
        assert "<table" in r.text or "no watchlist entries" in r.text.lower()
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Confidence badge color thresholds.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("confidence", "expected_class"),
    [
        (0, "badge-conf-low"),
        (29, "badge-conf-low"),
        (30, "badge-conf-med"),
        (69, "badge-conf-med"),
        (70, "badge-conf-high"),
        (99, "badge-conf-high"),
        (100, "badge-conf-high"),
    ],
)
@pytest.mark.webui
def test_watchlist_list_confidence_badge_thresholds(tmp_path, confidence, expected_class):
    app, db = _make_app(tmp_path)
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "x")
        _add_meta(db, wid, confidence=confidence)
        with TestClient(app) as client:
            r = client.get("/watchlist")
        assert r.status_code == 200
        assert expected_class in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_list_confidence_null_no_badge(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "no-conf")
        # Metadata exists but confidence is NULL.
        _add_meta(db, wid, vendor="Acme")
        with TestClient(app) as client:
            r = client.get("/watchlist")
        assert r.status_code == 200
        # No confidence-tier class should appear when confidence is NULL.
        assert "badge-conf-low" not in r.text
        assert "badge-conf-med" not in r.text
        assert "badge-conf-high" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_list_confidence_no_metadata_no_badge(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "no-meta")
        with TestClient(app) as client:
            r = client.get("/watchlist")
        assert r.status_code == 200
        assert "badge-conf-low" not in r.text
        assert "badge-conf-med" not in r.text
        assert "badge-conf-high" not in r.text
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Vendor column.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_watchlist_list_vendor_present_renders(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "x")
        _add_meta(db, wid, vendor="ContosoCorp")
        with TestClient(app) as client:
            r = client.get("/watchlist")
        assert r.status_code == 200
        assert "ContosoCorp" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_list_vendor_null_no_string(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "x")
        with TestClient(app) as client:
            r = client.get("/watchlist")
        assert r.status_code == 200
        # No "None" or "null" strings leaking into the rendered HTML.
        assert ">None<" not in r.text
        assert ">null<" not in r.text
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Row links to detail.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_watchlist_list_row_links_to_detail(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "x")
        with TestClient(app) as client:
            r = client.get("/watchlist")
        assert r.status_code == 200
        assert f'href="/watchlist/{wid}"' in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_list_sort_severity_desc_pattern_asc(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        # Insert in scrambled order — page should re-sort.
        _add_watchlist(db, "aa:bb:cc:dd:ee:02", "mac", "low", "low-2")
        _add_watchlist(db, "aa:bb:cc:dd:ee:04", "mac", "high", "high-2")
        _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "low", "low-1")
        _add_watchlist(db, "aa:bb:cc:dd:ee:03", "mac", "high", "high-1")
        _add_watchlist(db, "aa:bb:cc:dd:ee:05", "mac", "med", "med-1")
        with TestClient(app) as client:
            r = client.get("/watchlist")
        assert r.status_code == 200
        # Find rendered order of descriptions: high-1, high-2, med-1, low-1, low-2.
        descs = ["high-1", "high-2", "med-1", "low-1", "low-2"]
        positions = [r.text.index(d) for d in descs]
        assert positions == sorted(positions)
    finally:
        db.close()


# ---------------------------------------------------------------------------
# /watchlist/<id> detail page.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_watchlist_detail_with_metadata_renders_all_fields(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "high", "Suspicious thing")
        _add_meta(
            db,
            wid,
            argus_record_id="argus-001",
            device_category="surveillance_camera",
            vendor="Acme Security",
            confidence=82,
            source="vendor_docs",
            source_url="https://example.com/datasheet",
            source_excerpt="A short excerpt.",
            fcc_id="ABC1234XYZ",
            geographic_scope="US-CA",
            first_seen=1_700_000_000,
            last_verified=1_700_500_000,
            notes="some_internal_notes",
        )
        with TestClient(app) as client:
            r = client.get(f"/watchlist/{wid}")
        assert r.status_code == 200
        text = r.text
        assert "aa:bb:cc:dd:ee:01" in text
        assert "Suspicious thing" in text
        assert "surveillance_camera" in text
        assert "Acme Security" in text
        assert "82" in text
        assert "vendor_docs" in text
        assert "https://example.com/datasheet" in text
        assert "A short excerpt." in text
        assert "ABC1234XYZ" in text
        assert "US-CA" in text
        assert "some_internal_notes" in text
        assert "argus-001" in text
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_detail_no_metadata_section_omitted(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "no-meta")
        with TestClient(app) as client:
            r = client.get(f"/watchlist/{wid}")
        assert r.status_code == 200
        # Section heading must not render at all when metadata is absent.
        text_lower = r.text.lower()
        assert "<h3>metadata</h3>" not in text_lower
        # Argus footer label should also be absent.
        assert "argus_record_id" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_detail_source_url_attrs(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "x")
        _add_meta(db, wid, source_url="https://example.com/evidence")
        with TestClient(app) as client:
            r = client.get(f"/watchlist/{wid}")
        assert r.status_code == 200
        # The source URL anchor must include both target=_blank and rel="noopener noreferrer".
        # We look for them within a 250-char window around the URL.
        idx = r.text.find("https://example.com/evidence")
        assert idx != -1
        window_start = max(0, idx - 250)
        window = r.text[window_start : idx + 250]
        assert 'target="_blank"' in window
        assert 'rel="noopener noreferrer"' in window
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_detail_no_source_url_no_link(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "x")
        _add_meta(db, wid, vendor="Acme")  # No source_url.
        with TestClient(app) as client:
            r = client.get(f"/watchlist/{wid}")
        assert r.status_code == 200
        # No empty hrefs, no broken external link tag.
        assert 'href=""' not in r.text
        assert 'href="None"' not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_detail_long_excerpt_collapsed(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        long_excerpt = "L" * 500  # >200 chars triggers collapse
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "x")
        _add_meta(db, wid, source_excerpt=long_excerpt)
        with TestClient(app) as client:
            r = client.get(f"/watchlist/{wid}")
        assert r.status_code == 200
        # Long excerpt is wrapped in a <details> element (CSS-only collapse).
        assert "<details" in r.text
        assert long_excerpt in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_detail_short_excerpt_inline(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        short = "Just 50 chars or so of source-evidence excerpt."
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "x")
        _add_meta(db, wid, source_excerpt=short)
        with TestClient(app) as client:
            r = client.get(f"/watchlist/{wid}")
        assert r.status_code == 200
        # Short excerpt rendered without <details> wrapper.
        # The rendered short excerpt should not be inside a <details> block.
        idx = r.text.find(short)
        assert idx != -1
        # Check that the closest <details ...> tag does not enclose this excerpt.
        # Simpler: just ensure no <details> tag was emitted for excerpts in the
        # detail-page context. We allow other <details> elsewhere if needed.
        before = r.text[:idx]
        last_open = before.rfind("<details")
        last_close = before.rfind("</details>")
        assert last_open == -1 or last_close > last_open
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_detail_404_for_missing_id(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/watchlist/99999")
        assert r.status_code == 404
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_detail_argus_record_id_in_footer(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "x")
        _add_meta(db, wid, argus_record_id="argus-zzz-123")
        with TestClient(app) as client:
            r = client.get(f"/watchlist/{wid}")
        assert r.status_code == 200
        assert "argus-zzz-123" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_detail_dates_formatted_utc(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        # 1700000000 = 2023-11-14 22:13:20 UTC
        # 1700500000 = 2023-11-20 17:06:40 UTC
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "x")
        _add_meta(db, wid, first_seen=1_700_000_000, last_verified=1_700_500_000)
        with TestClient(app) as client:
            r = client.get(f"/watchlist/{wid}")
        assert r.status_code == 200
        assert "2023-11-14 22:13 UTC" in r.text
        assert "2023-11-20 17:06 UTC" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_detail_null_dates_no_none_string(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "x")
        # Metadata present but date fields are NULL.
        _add_meta(db, wid, vendor="Acme")
        with TestClient(app) as client:
            r = client.get(f"/watchlist/{wid}")
        assert r.status_code == 200
        assert ">None<" not in r.text
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Navigation link.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_watchlist_nav_link_appears_on_watchlist_page(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/watchlist")
        assert r.status_code == 200
        assert 'href="/watchlist"' in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_nav_link_appears_on_other_pages(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r_root = client.get("/")
            r_alerts = client.get("/alerts")
            r_devices = client.get("/devices")
        assert 'href="/watchlist"' in r_root.text
        assert 'href="/watchlist"' in r_alerts.text
        assert 'href="/watchlist"' in r_devices.text
    finally:
        db.close()


# ---------------------------------------------------------------------------
# XSS regression — Jinja autoescape must escape all metadata fields.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_xss_vendor_escaped_on_list(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "x")
        _add_meta(db, wid, vendor="Acme</script><b>boom")
        with TestClient(app) as client:
            r = client.get("/watchlist")
        assert r.status_code == 200
        assert "Acme</script><b>boom" not in r.text
        assert "Acme&lt;/script&gt;&lt;b&gt;boom" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_xss_vendor_escaped_on_detail(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "x")
        _add_meta(db, wid, vendor='Acme"<img src=x onerror=1>')
        with TestClient(app) as client:
            r = client.get(f"/watchlist/{wid}")
        assert r.status_code == 200
        assert "<img src=x onerror=1>" not in r.text
        assert "&lt;img src=x onerror=1&gt;" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_xss_source_excerpt_escaped(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "x")
        _add_meta(db, wid, source_excerpt="<script>alert(1)</script>")
        with TestClient(app) as client:
            r = client.get(f"/watchlist/{wid}")
        assert r.status_code == 200
        assert "<script>alert(1)</script>" not in r.text
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_xss_notes_escaped(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "x")
        _add_meta(db, wid, notes="<iframe src=evil></iframe>")
        with TestClient(app) as client:
            r = client.get(f"/watchlist/{wid}")
        assert r.status_code == 200
        assert "<iframe src=evil></iframe>" not in r.text
        assert "&lt;iframe src=evil&gt;&lt;/iframe&gt;" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_xss_description_escaped_on_list(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "<script>alert('xss')</script>")
        with TestClient(app) as client:
            r = client.get("/watchlist")
        assert r.status_code == 200
        assert "<script>alert('xss')</script>" not in r.text
        assert "&lt;script&gt;alert(" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_xss_description_escaped_on_detail(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "<b>bold</b>")
        with TestClient(app) as client:
            r = client.get(f"/watchlist/{wid}")
        assert r.status_code == 200
        assert "<b>bold</b>" not in r.text
        assert "&lt;b&gt;bold&lt;/b&gt;" in r.text
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Smoke regression: existing v0.2 routes unaffected.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_existing_v02_routes_still_render(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            for path in ["/", "/alerts", "/devices", "/rules", "/allowlist", "/healthz"]:
                r = client.get(path)
                assert r.status_code == 200, f"{path} returned {r.status_code}"
    finally:
        db.close()
