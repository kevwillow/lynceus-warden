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


@pytest.mark.webui
def test_watchlist_nav_active_on_list_page(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/watchlist")
        assert r.status_code == 200
        assert 'href="/watchlist" class="active"' in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_nav_active_on_detail_page(tmp_path):
    # Mirrors the /watchful/<id> active-state pin in test_ui_watchful.py:
    # the /watchlist nav link must carry class="active" on the detail
    # page too, so operators don't lose their sense of place after
    # clicking through from the list.
    app, db = _make_app(tmp_path)
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "x")
        with TestClient(app) as client:
            r = client.get(f"/watchlist/{wid}")
        assert r.status_code == 200
        assert 'href="/watchlist" class="active"' in r.text
        # Other nav links must NOT be active simultaneously.
        assert 'href="/alerts" class="active"' not in r.text
        assert 'href="/devices" class="active"' not in r.text
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
# mac_range rendering — list + detail surface canonical CIDR + prefix length.
# ---------------------------------------------------------------------------


def _add_mac_range_watchlist(
    db: Database,
    pattern: str,
    prefix: str,
    length: int,
    severity: str = "low",
    description: str | None = None,
) -> int:
    with db._conn:
        cur = db._conn.execute(
            "INSERT INTO watchlist("
            "pattern, pattern_type, severity, description, "
            "mac_range_prefix, mac_range_prefix_length) "
            "VALUES (?, 'mac_range', ?, ?, ?, ?)",
            (pattern, severity, description, prefix, length),
        )
        return int(cur.lastrowid)


@pytest.mark.webui
def test_watchlist_list_renders_mac_range_canonical_cidr(tmp_path):
    """List page renders the canonical CIDR pattern verbatim from
    the pattern column (post-Part 1 write-time canonicalization).
    No per-type formatting; if pattern column rendered uniformly is
    correct, this passes without template changes."""
    app, db = _make_app(tmp_path)
    try:
        _add_mac_range_watchlist(
            db,
            "aa:bb:cc:d/28",
            "aabbccd",
            28,
            description="Argus mac_range corpus row",
        )
        with TestClient(app) as client:
            r = client.get("/watchlist")
        assert r.status_code == 200
        assert "aa:bb:cc:d/28" in r.text
        assert "Argus mac_range corpus row" in r.text
        assert "mac_range" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_detail_renders_mac_range_prefix_length(tmp_path):
    """Detail page surfaces the prefix length explicitly for mac_range
    entries, alongside the canonical CIDR pattern. Operators triaging
    an alert tied to a mac_range row need the prefix length to
    distinguish 'vendor /28 owns a million MACs' from 'specific
    device identifier' — different operational responses."""
    app, db = _make_app(tmp_path)
    try:
        wid = _add_mac_range_watchlist(
            db,
            "aa:bb:cc:dd:e/36",
            "aabbccdde",
            36,
            severity="high",
            description="MA-S /36 example",
        )
        with TestClient(app) as client:
            r = client.get(f"/watchlist/{wid}")
        assert r.status_code == 200
        assert "aa:bb:cc:dd:e/36" in r.text
        assert "/36" in r.text
        # The block-size annotation for /36 is the MA-S / IAB hint.
        assert "MA-S" in r.text or "IAB" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_detail_mac_range_28_shows_ma_m_annotation(tmp_path):
    """The /28 detail page surfaces MA-M block-size context. The two
    annotations (/28 → MA-M 1,048,576 addresses; /36 → MA-S / IAB
    4,096 addresses) are presentational but help operators size the
    blast radius of a watchlist hit at a glance."""
    app, db = _make_app(tmp_path)
    try:
        wid = _add_mac_range_watchlist(db, "aa:bb:cc:d/28", "aabbccd", 28)
        with TestClient(app) as client:
            r = client.get(f"/watchlist/{wid}")
        assert r.status_code == 200
        assert "/28" in r.text
        assert "MA-M" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_detail_non_mac_range_does_not_render_prefix_length(tmp_path):
    """Regression guard: the new prefix-length block is gated on
    pattern_type='mac_range'. A plain mac row must NOT render the
    MA-M/MA-S annotations or a stray '/28' / '/36' marker."""
    app, db = _make_app(tmp_path)
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "high", "plain mac")
        with TestClient(app) as client:
            r = client.get(f"/watchlist/{wid}")
        assert r.status_code == 200
        assert "MA-M" not in r.text
        assert "MA-S" not in r.text
        assert "prefix length" not in r.text.lower()
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


# ---------------------------------------------------------------------------
# /watchlist.csv -- streaming CSV export of the filtered watchlist.
# ---------------------------------------------------------------------------

import csv as _csv  # noqa: E402 -- top-of-section, self-contained
import io as _io  # noqa: E402


def _parse_csv_response(body: str) -> tuple[list[str], list[list[str]]]:
    reader = _csv.reader(_io.StringIO(body))
    rows = list(reader)
    if not rows:
        return [], []
    return rows[0], rows[1:]


_WATCHLIST_CSV_HEADER = [
    "id",
    "pattern",
    "pattern_type",
    "severity",
    "description",
    "mac_range_prefix",
    "mac_range_prefix_length",
    "argus_record_id",
    "device_category",
    "confidence",
    "vendor",
    "source",
    "source_url",
    "source_excerpt",
    "fcc_id",
    "geographic_scope",
    "first_seen_iso_utc",
    "first_seen_unix",
    "last_verified_iso_utc",
    "last_verified_unix",
    "notes",
]


@pytest.mark.webui
def test_watchlist_csv_returns_200_with_content_type_and_disposition(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "row")
        with TestClient(app) as client:
            r = client.get("/watchlist.csv")
        assert r.status_code == 200
        assert "text/csv" in r.headers["content-type"]
        cd = r.headers["content-disposition"]
        assert cd.startswith('attachment; filename="watchlist-')
        assert cd.endswith('Z.csv"')
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_csv_filename_is_iso_utc_timestamped(tmp_path):
    import re
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/watchlist.csv")
        cd = r.headers["content-disposition"]
        m = re.search(r'filename="watchlist-(\d{8}T\d{6}Z)\.csv"', cd)
        assert m is not None, f"filename did not match expected shape: {cd}"
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_csv_header_row_columns_stable_order(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/watchlist.csv")
        header, _ = _parse_csv_response(r.text)
        assert header == _WATCHLIST_CSV_HEADER
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_csv_empty_db_returns_header_only(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/watchlist.csv")
        assert r.status_code == 200
        header, data_rows = _parse_csv_response(r.text)
        assert header == _WATCHLIST_CSV_HEADER
        assert data_rows == []
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_csv_emits_one_row_per_entry(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "high", "a")
        _add_watchlist(db, "aa:bb:cc:dd:ee:02", "mac", "med", "b")
        _add_watchlist(db, "aa:bb:cc:dd:ee:03", "mac", "low", "c")
        with TestClient(app) as client:
            r = client.get("/watchlist.csv")
        _, data_rows = _parse_csv_response(r.text)
        assert len(data_rows) == 3
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_csv_respects_pattern_type_filter(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "mac-row")
        _add_watchlist(db, "DangerSSID", "ssid", "med", "ssid-row")
        with TestClient(app) as client:
            r = client.get("/watchlist.csv?pattern_type=mac")
        _, data_rows = _parse_csv_response(r.text)
        assert len(data_rows) == 1
        # pattern_type is column index 2
        assert data_rows[0][2] == "mac"
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_csv_respects_severity_filter(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "high", "high-row")
        _add_watchlist(db, "aa:bb:cc:dd:ee:02", "mac", "low", "low-row")
        with TestClient(app) as client:
            r = client.get("/watchlist.csv?severity=high")
        _, data_rows = _parse_csv_response(r.text)
        assert len(data_rows) == 1
        # severity column index 3
        assert data_rows[0][3] == "high"
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_csv_respects_device_category_filter(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        wid1 = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "x")
        _add_meta(db, wid1, device_category="lpr")
        wid2 = _add_watchlist(db, "aa:bb:cc:dd:ee:02", "mac", "med", "y")
        _add_meta(db, wid2, device_category="surveillance_camera")
        with TestClient(app) as client:
            r = client.get("/watchlist.csv?device_category=lpr")
        _, data_rows = _parse_csv_response(r.text)
        assert len(data_rows) == 1
        # device_category index 8
        assert data_rows[0][8] == "lpr"
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_csv_respects_q_substring_filter(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        wid1 = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "x")
        _add_meta(db, wid1, vendor="Acme Surveillance")
        wid2 = _add_watchlist(db, "11:22:33:44:55:66", "mac", "med", "y")
        _add_meta(db, wid2, vendor="Globex Corp")
        with TestClient(app) as client:
            r = client.get("/watchlist.csv?q=acme")
        _, data_rows = _parse_csv_response(r.text)
        assert len(data_rows) == 1
        # vendor column index 10
        assert "Acme" in data_rows[0][10]
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_csv_composes_multiple_filters(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        wid1 = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "high", "match")
        _add_meta(db, wid1, vendor="Acme")
        _add_watchlist(db, "aa:bb:cc:dd:ee:02", "mac", "low", "wrong-severity")
        wid3 = _add_watchlist(db, "DangerNet", "ssid", "high", "wrong-type")
        _add_meta(db, wid3, vendor="Acme")
        with TestClient(app) as client:
            r = client.get("/watchlist.csv?pattern_type=mac&severity=high&q=acme")
        _, data_rows = _parse_csv_response(r.text)
        assert len(data_rows) == 1
        # pattern column index 1
        assert data_rows[0][1] == "aa:bb:cc:dd:ee:01"
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_csv_includes_full_metadata_join(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "high", "full row")
        _add_meta(
            db,
            wid,
            argus_record_id="argus-007",
            device_category="lpr",
            confidence=85,
            vendor="Acme",
            source="vendor_docs",
            source_url="https://example.com/d",
            source_excerpt="A short excerpt.",
            fcc_id="ABC1234XYZ",
            geographic_scope="US-CA",
            first_seen=1_700_000_000,
            last_verified=1_700_500_000,
            notes="some_internal_notes",
        )
        with TestClient(app) as client:
            r = client.get("/watchlist.csv")
        _, data_rows = _parse_csv_response(r.text)
        assert len(data_rows) == 1
        row = data_rows[0]
        # Header indexes from _WATCHLIST_CSV_HEADER above.
        assert row[1] == "aa:bb:cc:dd:ee:01"  # pattern
        assert row[7] == "argus-007"  # argus_record_id
        assert row[8] == "lpr"  # device_category
        assert row[9] == "85"  # confidence
        assert row[10] == "Acme"  # vendor
        assert row[11] == "vendor_docs"  # source
        assert row[12] == "https://example.com/d"  # source_url
        assert row[13] == "A short excerpt."  # source_excerpt
        assert row[14] == "ABC1234XYZ"  # fcc_id
        assert row[15] == "US-CA"  # geographic_scope
        # first_seen_iso_utc / first_seen_unix / last_verified_iso_utc / last_verified_unix
        assert row[16] == "2023-11-14T22:13:20Z"
        assert row[17] == "1700000000"
        assert row[18] == "2023-11-20T17:06:40Z"
        assert row[19] == "1700500000"
        assert row[20] == "some_internal_notes"
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_csv_no_metadata_row_renders_empty_join_cells(tmp_path):
    # LEFT JOIN: a watchlist row without a watchlist_metadata partner
    # must still appear, with empty cells for the join columns
    # (no "None" string, no "null").
    app, db = _make_app(tmp_path)
    try:
        _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "high", "bare row")
        with TestClient(app) as client:
            r = client.get("/watchlist.csv")
        _, data_rows = _parse_csv_response(r.text)
        assert len(data_rows) == 1
        row = data_rows[0]
        assert row[1] == "aa:bb:cc:dd:ee:01"
        # All metadata-join cells are empty strings.
        for idx in range(7, 21):
            assert row[idx] == ""
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_csv_is_a_streaming_response(tmp_path):
    from starlette.responses import StreamingResponse
    from starlette.requests import Request

    app, db = _make_app(tmp_path)
    try:
        route = next(r for r in app.routes if getattr(r, "path", None) == "/watchlist.csv")
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/watchlist.csv",
            "query_string": b"",
            "headers": [],
            "app": app,
        }
        req = Request(scope=scope)
        resp = route.endpoint(
            request=req,
            q=None, pattern_type=None, severity=None, device_category=None,
        )
        assert isinstance(resp, StreamingResponse)
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_csv_link_visible_on_list_page(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/watchlist")
        assert r.status_code == 200
        assert "/watchlist.csv" in r.text
        assert "Export CSV" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_csv_link_passes_through_query_string(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/watchlist?pattern_type=mac&severity=high")
        assert r.status_code == 200
        assert "/watchlist.csv?pattern_type=mac" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_csv_invalid_pattern_type_silently_falls_back(tmp_path):
    # Mirrors the list-route clamp posture: invalid pattern_type
    # -> silent fallback to "all", export returns 200 with all rows.
    app, db = _make_app(tmp_path)
    try:
        _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med", "x")
        with TestClient(app) as client:
            r = client.get("/watchlist.csv?pattern_type=bogus")
        assert r.status_code == 200
        _, data_rows = _parse_csv_response(r.text)
        assert len(data_rows) == 1
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_csv_q_too_long_returns_400(tmp_path):
    # Same input-validation posture as the list route.
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get(f"/watchlist.csv?q={'x' * 101}")
        assert r.status_code == 400
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_csv_xss_field_values_csv_escaped(tmp_path):
    # csv.writer applies QUOTE_MINIMAL: cells containing special
    # CSV chars (comma, quote, newline) are properly escaped. No
    # HTML escaping needed in CSV output, but we verify no naive
    # string corruption either.
    app, db = _make_app(tmp_path)
    try:
        wid = _add_watchlist(
            db, "aa:bb:cc:dd:ee:01", "mac", "med",
            'descr,with,commas and "quotes" inside',
        )
        _add_meta(db, wid, notes="line1\nline2 with comma, end")
        with TestClient(app) as client:
            r = client.get("/watchlist.csv")
        _, data_rows = _parse_csv_response(r.text)
        # csv.reader round-trips QUOTE_MINIMAL cleanly: data_rows[0][4]
        # is the original description string.
        assert data_rows[0][4] == 'descr,with,commas and "quotes" inside'
        # notes column index 20
        assert data_rows[0][20] == "line1\nline2 with comma, end"
    finally:
        db.close()
