"""Tests for the alert detail page's Evidence section.

Covers the read-only surface added in v0.4.0 that exposes the captured
``evidence_snapshots`` row on ``/alerts/{id}``: the Kismet record block,
the RSSI sparkline SVG, and the OpenStreetMap GPS link. Includes unit
tests for ``render_rssi_sparkline`` (fixed-input snapshot, all-equal
flat line, empty input).
"""

from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.evidence import capture_evidence
from lynceus.webui.app import create_app, render_rssi_sparkline

MAC = "aa:bb:cc:dd:ee:01"


def _kismet_record(
    *,
    with_signal_rrd: bool = True,
    with_location: bool = True,
    minute_vec: list[int] | None = None,
    rrd_last_time: int = 1700000100,
) -> dict:
    record: dict = {
        "kismet.device.base.macaddr": MAC,
        "kismet.device.base.type": "Wi-Fi AP",
        "kismet.device.base.first_time": 1699999100,
        "kismet.device.base.last_time": 1700000100,
        "kismet.device.base.manuf": "TestVendor",
    }
    if with_signal_rrd:
        if minute_vec is None:
            minute_vec = [-50 - (i % 30) for i in range(60)]
        record["kismet.device.base.signal"] = {
            "kismet.common.signal.last_signal": -50,
            "kismet.common.signal.signal_rrd": {
                "kismet.common.rrd.last_time": rrd_last_time,
                "kismet.common.rrd.minute_vec": minute_vec,
            },
        }
    if with_location:
        record["kismet.device.base.location"] = {
            "kismet.common.location.last": {
                "kismet.common.location.geopoint": [-122.4194, 37.7749],
                "kismet.common.location.alt": 52.0,
                "kismet.common.location.time_sec": 1700000095,
            }
        }
    return record


def _make_app(tmp_path):
    config = Config(db_path=str(tmp_path / "ui.db"))
    db = Database(config.db_path)
    db.upsert_device(MAC, "wifi", "TestVendor", 0, 1700000000)
    app = create_app(config, db)
    return app, db


def _make_alert(db, *, with_evidence: bool = True, kismet_record: dict | None = None) -> int:
    aid = db.add_alert(
        ts=1700000000, rule_name="test_rule", mac=MAC, message="boom", severity="high"
    )
    if with_evidence:
        record = kismet_record if kismet_record is not None else _kismet_record()
        # store_gps=True so the GPS-rendering paths in the UI tests below
        # (OSM link, lat/lon display) actually have data to render. The
        # webui tests are exercising "what happens when GPS is present"
        # — the privacy-default behaviour is covered by test_evidence.py.
        rid = capture_evidence(db, aid, MAC, record, now_ts=1700000200, store_gps=True)
        assert rid is not None
    return aid


# ---------------------------------------------------------------------------
# /alerts/{id} integration tests
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_alert_detail_with_evidence_renders_all_sections(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        aid = _make_alert(db)
        with TestClient(app) as client:
            r = client.get(f"/alerts/{aid}")
        assert r.status_code == 200
        body = r.text
        assert "<h2>Evidence</h2>" in body
        assert "Full Kismet record" in body
        assert "TestVendor" in body
        assert "<svg" in body and 'aria-label="RSSI history' in body
        assert "<polyline" in body
        assert "37.7749" in body
        assert "-122.4194" in body
        assert "openstreetmap.org" in body
        assert 'rel="noopener noreferrer"' in body
    finally:
        db.close()


@pytest.mark.webui
def test_alert_detail_without_evidence_shows_placeholder(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        aid = _make_alert(db, with_evidence=False)
        with TestClient(app) as client:
            r = client.get(f"/alerts/{aid}")
        assert r.status_code == 200
        body = r.text
        assert "<h2>Evidence</h2>" in body
        assert "No evidence captured for this alert." in body
        assert 'aria-label="RSSI history' not in body
        assert "openstreetmap.org" not in body
    finally:
        db.close()


@pytest.mark.webui
def test_alert_detail_with_evidence_but_no_rssi_history_omits_sparkline(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        # No signal_rrd in the record → rssi_history_json is NULL.
        aid = _make_alert(db, kismet_record=_kismet_record(with_signal_rrd=False))
        with TestClient(app) as client:
            r = client.get(f"/alerts/{aid}")
        assert r.status_code == 200
        body = r.text
        assert "Full Kismet record" in body
        assert 'aria-label="RSSI history' not in body
        assert "<polyline" not in body
        # GPS still present (location was included).
        assert "openstreetmap.org" in body
    finally:
        db.close()


@pytest.mark.webui
def test_alert_detail_with_evidence_but_no_gps_omits_gps_section(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        aid = _make_alert(db, kismet_record=_kismet_record(with_location=False))
        with TestClient(app) as client:
            r = client.get(f"/alerts/{aid}")
        assert r.status_code == 200
        body = r.text
        assert "Full Kismet record" in body
        assert 'aria-label="RSSI history' in body
        assert "openstreetmap.org" not in body
        assert "Captured location:" not in body
    finally:
        db.close()


@pytest.mark.webui
def test_alert_detail_with_corrupt_kismet_record_renders_fallback(tmp_path, caplog):
    app, db = _make_app(tmp_path)
    try:
        aid = _make_alert(db)
        # Defense-in-depth: simulate disk corruption by overwriting the
        # JSON column with malformed bytes after capture. Should not happen
        # in production but the page must not crash on it.
        db._conn.execute(
            "UPDATE evidence_snapshots SET kismet_record_json = ? WHERE alert_id = ?",
            ("{not-valid-json", aid),
        )
        db._conn.commit()
        with caplog.at_level(logging.WARNING, logger="lynceus.webui.app"):
            with TestClient(app) as client:
                r = client.get(f"/alerts/{aid}")
        assert r.status_code == 200
        body = r.text
        assert "Kismet record could not be parsed" in body
        assert "Traceback" not in body
        assert any(
            "could not be parsed" in rec.getMessage() and rec.levelname == "WARNING"
            for rec in caplog.records
        )
    finally:
        db.close()


# ---------------------------------------------------------------------------
# render_rssi_sparkline unit tests
# ---------------------------------------------------------------------------


def test_render_rssi_sparkline_fixed_input_snapshot():
    history = [{"ts": 100 - i, "rssi": -50 - i} for i in range(5)]
    svg = render_rssi_sparkline(history)
    expected = (
        '<svg xmlns="http://www.w3.org/2000/svg" class="rssi-sparkline" '
        'width="200" height="40" viewBox="0 0 200 40" '
        'role="img" aria-label="RSSI history over the last 60 seconds">'
        '<polyline fill="none" stroke="currentColor" stroke-width="1.5" '
        'points="0.00,0.00 50.00,10.00 100.00,20.00 150.00,30.00 200.00,40.00"/>'
        '<text x="198" y="10" text-anchor="end" font-size="9" '
        'fill="currentColor">min: -54 max: -50</text>'
        "</svg>"
    )
    assert svg == expected


def test_render_rssi_sparkline_all_equal_values_flat_line():
    history = [{"ts": i, "rssi": -60} for i in range(10)]
    svg = render_rssi_sparkline(history)
    # Flat midline → every y is 20.00 (height/2). No NaN/inf, no exception.
    assert "20.00" in svg
    assert "min: -60 max: -60" in svg
    # No NaN slipped through the formatting.
    assert "nan" not in svg.lower()


def test_render_rssi_sparkline_empty_returns_empty_string():
    assert render_rssi_sparkline([]) == ""
    assert render_rssi_sparkline(None) == ""


def test_render_rssi_sparkline_decoded_history_round_trips_via_db(tmp_path):
    """End-to-end: db.get_evidence_for_alert decodes rssi_history_json
    and render_rssi_sparkline accepts it without further unwrapping."""
    db = Database(str(tmp_path / "rt.db"))
    try:
        db.upsert_device(MAC, "wifi", "TestVendor", 0, 1700000000)
        aid = db.add_alert(ts=1700000000, rule_name="r", mac=MAC, message="m", severity="low")
        capture_evidence(db, aid, MAC, _kismet_record(), now_ts=1700000200)
        evidence = db.get_evidence_for_alert(aid)
        assert evidence is not None
        assert isinstance(evidence["rssi_history"], list)
        svg = render_rssi_sparkline(evidence["rssi_history"])
        assert svg.startswith("<svg")
        assert "<polyline" in svg
    finally:
        db.close()


# ---------------------------------------------------------------------------
# get_evidence_for_alert direct unit tests
# ---------------------------------------------------------------------------


def test_get_evidence_for_alert_returns_none_when_absent(tmp_path):
    db = Database(str(tmp_path / "n.db"))
    try:
        db.upsert_device(MAC, "wifi", "TestVendor", 0, 1700000000)
        aid = db.add_alert(ts=1700000000, rule_name="r", mac=MAC, message="m", severity="low")
        assert db.get_evidence_for_alert(aid) is None
    finally:
        db.close()


def test_get_evidence_for_alert_decodes_json_columns(tmp_path):
    db = Database(str(tmp_path / "j.db"))
    try:
        db.upsert_device(MAC, "wifi", "TestVendor", 0, 1700000000)
        aid = db.add_alert(ts=1700000000, rule_name="r", mac=MAC, message="m", severity="low")
        capture_evidence(db, aid, MAC, _kismet_record(), now_ts=1700000200, store_gps=True)
        evidence = db.get_evidence_for_alert(aid)
        assert evidence is not None
        assert isinstance(evidence["kismet_record"], dict)
        assert evidence["kismet_record"]["kismet.device.base.macaddr"] == MAC
        assert isinstance(evidence["rssi_history"], list)
        assert evidence["kismet_record_corrupt"] is False
        assert evidence["rssi_history_corrupt"] is False
        assert evidence["gps_lat"] == pytest.approx(37.7749)
    finally:
        db.close()


def test_get_evidence_for_alert_flags_corrupt_kismet_json(tmp_path):
    db = Database(str(tmp_path / "c.db"))
    try:
        db.upsert_device(MAC, "wifi", "TestVendor", 0, 1700000000)
        aid = db.add_alert(ts=1700000000, rule_name="r", mac=MAC, message="m", severity="low")
        capture_evidence(db, aid, MAC, _kismet_record(), now_ts=1700000200)
        db._conn.execute(
            "UPDATE evidence_snapshots SET kismet_record_json = ? WHERE alert_id = ?",
            ("{bad", aid),
        )
        db._conn.commit()
        evidence = db.get_evidence_for_alert(aid)
        assert evidence is not None
        assert evidence["kismet_record"] is None
        assert evidence["kismet_record_corrupt"] is True
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Non-finite GPS guard
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_alert_detail_hides_gps_when_lat_is_nan(tmp_path):
    """REGRESSION: a row with non-finite gps_lat (e.g. nan from a
    pre-H-2 install or a hand-edited DB) used to render a malformed
    OSM URL like mlat=nan&mlon=...&map=18/nan/... Hiding the entire
    GPS section is the safe fallback. H-2 prevents new captures from
    storing non-finite values; this test pins the read-side guard."""
    app, db = _make_app(tmp_path)
    try:
        aid = _make_alert(db)
        # Stomp on the captured row directly so we drive the real
        # SELECT path with non-finite floats coming back from SQLite.
        db._conn.execute(
            "UPDATE evidence_snapshots SET gps_lat = ?, gps_lon = ? WHERE alert_id = ?",
            (float("nan"), 0.0, aid),
        )
        db._conn.commit()
        with TestClient(app) as client:
            r = client.get(f"/alerts/{aid}")
        assert r.status_code == 200
        body = r.text
        # No OSM link, no "nan" string, no "Captured location" line.
        assert "openstreetmap.org" not in body
        assert "nan" not in body.lower()
        assert "Captured location" not in body
    finally:
        db.close()


@pytest.mark.webui
def test_alert_detail_osm_link_opens_in_new_tab(tmp_path):
    """REGRESSION: the OSM link previously had rel="noopener noreferrer"
    but no target="_blank", so clicking it navigated the operator off
    the alert page (losing pagination/filter context). Must match the
    watchlist source_url link's behaviour: open in a new tab."""
    app, db = _make_app(tmp_path)
    try:
        aid = _make_alert(db)
        with TestClient(app) as client:
            r = client.get(f"/alerts/{aid}")
        assert r.status_code == 200
        body = r.text
        assert "openstreetmap.org" in body
        # Find the OSM <a> and assert it has both attributes.
        osm_anchor_start = body.find('href="https://www.openstreetmap.org')
        assert osm_anchor_start != -1
        osm_anchor_end = body.find(">", osm_anchor_start)
        osm_anchor = body[osm_anchor_start:osm_anchor_end]
        assert 'target="_blank"' in osm_anchor
        assert 'rel="noopener noreferrer"' in osm_anchor
    finally:
        db.close()


@pytest.mark.webui
def test_alert_detail_hides_gps_when_lon_is_inf(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        aid = _make_alert(db)
        db._conn.execute(
            "UPDATE evidence_snapshots SET gps_lat = ?, gps_lon = ? WHERE alert_id = ?",
            (37.7749, float("inf"), aid),
        )
        db._conn.commit()
        with TestClient(app) as client:
            r = client.get(f"/alerts/{aid}")
        assert r.status_code == 200
        body = r.text
        assert "openstreetmap.org" not in body
        assert "inf" not in body.lower()
    finally:
        db.close()
