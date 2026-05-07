"""Tests for surfacing watchlist_metadata on alert detail, alert list, and ntfy.

Read-only UI extension built on top of the matched_watchlist_id linkage from
prompt 25b. The schema and rules engine are unchanged; this layer only renders
metadata fields when they exist on the matched watchlist row, and falls back
cleanly to the v0.2 surface when they don't.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.kismet import FakeKismetClient
from lynceus.notify import RecordingNotifier
from lynceus.poller import poll_once
from lynceus.rules import Rule, Ruleset
from lynceus.webui.app import create_app

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "kismet_devices.json"


# ---------------------------------------------------------------------------
# Shared test helpers.
# ---------------------------------------------------------------------------


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


def _add_alert(
    db: Database,
    *,
    ts: int = 1700000500,
    rule_name: str = "watchlist_hit",
    mac: str | None = None,
    message: str = "matched",
    severity: str = "med",
    matched_watchlist_id: int | None = None,
) -> int:
    # Satisfy the alerts.mac → devices.mac FK by upserting the device first.
    if mac is not None:
        existing = db.get_device(mac)
        if existing is None:
            db.upsert_device(mac, "wifi", "Acme", 0, ts)
    return db.add_alert(
        ts=ts,
        rule_name=rule_name,
        mac=mac,
        message=message,
        severity=severity,
        matched_watchlist_id=matched_watchlist_id,
    )


# ---------------------------------------------------------------------------
# Alert detail page — vendor + confidence inline.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_alert_detail_with_metadata_renders_vendor_inline(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "high", "linked")
        _add_meta(db, wid, vendor="ContosoCorp", confidence=80)
        aid = _add_alert(
            db,
            mac="aa:bb:cc:dd:ee:01",
            severity="high",
            message="boom",
            matched_watchlist_id=wid,
        )
        with TestClient(app) as client:
            r = client.get(f"/alerts/{aid}")
        assert r.status_code == 200
        assert "ContosoCorp" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alert_detail_with_metadata_high_confidence_uses_high_badge(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "high")
        _add_meta(db, wid, vendor="Acme", confidence=85)
        aid = _add_alert(
            db,
            mac="aa:bb:cc:dd:ee:01",
            severity="high",
            matched_watchlist_id=wid,
        )
        with TestClient(app) as client:
            r = client.get(f"/alerts/{aid}")
        assert r.status_code == 200
        assert "badge-conf-high" in r.text
        assert "85" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alert_detail_with_metadata_med_confidence_uses_med_badge(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med")
        _add_meta(db, wid, vendor="Acme", confidence=50)
        aid = _add_alert(
            db,
            mac="aa:bb:cc:dd:ee:01",
            severity="med",
            matched_watchlist_id=wid,
        )
        with TestClient(app) as client:
            r = client.get(f"/alerts/{aid}")
        assert r.status_code == 200
        assert "badge-conf-med" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alert_detail_with_metadata_low_confidence_uses_low_badge(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "low")
        _add_meta(db, wid, vendor="Acme", confidence=10)
        aid = _add_alert(
            db,
            mac="aa:bb:cc:dd:ee:01",
            severity="low",
            matched_watchlist_id=wid,
        )
        with TestClient(app) as client:
            r = client.get(f"/alerts/{aid}")
        assert r.status_code == 200
        assert "badge-conf-low" in r.text
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Alert detail page — source URL.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_alert_detail_source_url_link_with_attrs(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med")
        _add_meta(db, wid, source_url="https://example.com/evidence")
        aid = _add_alert(
            db,
            mac="aa:bb:cc:dd:ee:01",
            severity="med",
            matched_watchlist_id=wid,
        )
        with TestClient(app) as client:
            r = client.get(f"/alerts/{aid}")
        assert r.status_code == 200
        idx = r.text.find("https://example.com/evidence")
        assert idx != -1
        window = r.text[max(0, idx - 250) : idx + 250]
        assert 'target="_blank"' in window
        assert 'rel="noopener noreferrer"' in window
        assert "View source evidence" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alert_detail_no_source_url_no_link(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med")
        _add_meta(db, wid, vendor="Acme")
        aid = _add_alert(
            db,
            mac="aa:bb:cc:dd:ee:01",
            severity="med",
            matched_watchlist_id=wid,
        )
        with TestClient(app) as client:
            r = client.get(f"/alerts/{aid}")
        assert r.status_code == 200
        assert "View source evidence" not in r.text
        assert 'href=""' not in r.text
        assert 'href="None"' not in r.text
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Alert detail page — source excerpt.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_alert_detail_source_excerpt_short_inline(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        short = "Short evidence excerpt about the matched device."
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med")
        _add_meta(db, wid, source_excerpt=short)
        aid = _add_alert(
            db,
            mac="aa:bb:cc:dd:ee:01",
            severity="med",
            matched_watchlist_id=wid,
        )
        with TestClient(app) as client:
            r = client.get(f"/alerts/{aid}")
        assert r.status_code == 200
        assert short in r.text
        idx = r.text.find(short)
        before = r.text[:idx]
        last_open = before.rfind("<details")
        last_close = before.rfind("</details>")
        # Either no <details> appears at all before the excerpt, or any prior
        # <details> tag has been closed before the excerpt — i.e. the excerpt
        # is not wrapped in a <details>.
        assert last_open == -1 or last_close > last_open
    finally:
        db.close()


@pytest.mark.webui
def test_alert_detail_source_excerpt_long_collapsed_in_details(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        long_excerpt = "L" * 500
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med")
        _add_meta(db, wid, source_excerpt=long_excerpt)
        aid = _add_alert(
            db,
            mac="aa:bb:cc:dd:ee:01",
            severity="med",
            matched_watchlist_id=wid,
        )
        with TestClient(app) as client:
            r = client.get(f"/alerts/{aid}")
        assert r.status_code == 200
        assert long_excerpt in r.text
        idx = r.text.find(long_excerpt)
        before = r.text[:idx]
        last_open = before.rfind("<details")
        last_close = before.rfind("</details>")
        # The long excerpt is wrapped in <details>: the most recent <details>
        # tag before the excerpt has not been closed yet.
        assert last_open != -1
        assert last_close < last_open
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Alert detail page — "View matched watchlist entry" link.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_alert_detail_view_matched_watchlist_link(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "high")
        _add_meta(db, wid, vendor="Acme", confidence=80)
        aid = _add_alert(
            db,
            mac="aa:bb:cc:dd:ee:01",
            severity="high",
            matched_watchlist_id=wid,
        )
        with TestClient(app) as client:
            r = client.get(f"/alerts/{aid}")
        assert r.status_code == 200
        assert f'href="/watchlist/{wid}"' in r.text
        assert "View matched watchlist entry" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alert_detail_match_no_metadata_still_has_view_link(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "high", "no metadata")
        # No metadata row added.
        aid = _add_alert(
            db,
            mac="aa:bb:cc:dd:ee:01",
            severity="high",
            matched_watchlist_id=wid,
        )
        with TestClient(app) as client:
            r = client.get(f"/alerts/{aid}")
        assert r.status_code == 200
        assert f'href="/watchlist/{wid}"' in r.text
        assert "View matched watchlist entry" in r.text
        # No metadata rendered.
        assert "badge-conf-low" not in r.text
        assert "badge-conf-med" not in r.text
        assert "badge-conf-high" not in r.text
        assert "View source evidence" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alert_detail_no_match_no_metadata_section(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        aid = _add_alert(db, mac=None, severity="med", message="systemic")
        with TestClient(app) as client:
            r = client.get(f"/alerts/{aid}")
        assert r.status_code == 200
        assert "systemic" in r.text
        assert "View matched watchlist entry" not in r.text
        assert "View source evidence" not in r.text
        assert "badge-conf-low" not in r.text
        assert "badge-conf-med" not in r.text
        assert "badge-conf-high" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alert_detail_no_match_renders_v02_shape(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        db.upsert_device("aa:bb:cc:dd:ee:09", "wifi", "Acme", 0, 100)
        aid = _add_alert(
            db,
            mac="aa:bb:cc:dd:ee:09",
            severity="high",
            message="boom-msg",
            rule_name="my_rule",
        )
        with TestClient(app) as client:
            r = client.get(f"/alerts/{aid}")
        assert r.status_code == 200
        # The v0.2 surface fields all still render (regression).
        assert "boom-msg" in r.text
        assert "my_rule" in r.text
        assert "aa:bb:cc:dd:ee:09" in r.text
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Alert list page — vendor subtitle.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_alerts_list_vendor_subtitle_when_metadata(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "high")
        _add_meta(db, wid, vendor="ContosoCorp", confidence=85)
        db.upsert_device("aa:bb:cc:dd:ee:01", "wifi", "Acme", 0, 100)
        _add_alert(
            db,
            mac="aa:bb:cc:dd:ee:01",
            severity="high",
            message="matched-row",
            matched_watchlist_id=wid,
        )
        with TestClient(app) as client:
            r = client.get("/alerts")
        assert r.status_code == 200
        assert "ContosoCorp" in r.text
        assert "alert-vendor-subtitle" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_no_vendor_subtitle_without_metadata(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "high")
        # No metadata row.
        db.upsert_device("aa:bb:cc:dd:ee:01", "wifi", "Acme", 0, 100)
        _add_alert(
            db,
            mac="aa:bb:cc:dd:ee:01",
            severity="high",
            message="bare-row",
            matched_watchlist_id=wid,
        )
        with TestClient(app) as client:
            r = client.get("/alerts")
        assert r.status_code == 200
        assert "alert-vendor-subtitle" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_no_vendor_subtitle_without_match(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        _add_alert(db, mac=None, severity="med", message="systemic", matched_watchlist_id=None)
        with TestClient(app) as client:
            r = client.get("/alerts")
        assert r.status_code == 200
        assert "alert-vendor-subtitle" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_subtitle_only_in_matched_row(tmp_path):
    """Two alerts: one matched-with-vendor, one matched-without-vendor. Vendor
    subtitle appears only against the row that actually has metadata."""
    app, db = _make_app(tmp_path)
    try:
        wid_with = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "high")
        _add_meta(db, wid_with, vendor="WithVendor")
        wid_bare = _add_watchlist(db, "aa:bb:cc:dd:ee:02", "mac", "med")
        db.upsert_device("aa:bb:cc:dd:ee:01", "wifi", "Acme", 0, 100)
        db.upsert_device("aa:bb:cc:dd:ee:02", "wifi", "Acme", 0, 100)
        _add_alert(
            db,
            ts=1700000600,
            mac="aa:bb:cc:dd:ee:01",
            severity="high",
            message="row-with-vendor",
            matched_watchlist_id=wid_with,
        )
        _add_alert(
            db,
            ts=1700000700,
            mac="aa:bb:cc:dd:ee:02",
            severity="med",
            message="row-without-vendor",
            matched_watchlist_id=wid_bare,
        )
        with TestClient(app) as client:
            r = client.get("/alerts")
        assert r.status_code == 200
        # "WithVendor" appears exactly once (in the matched row).
        assert r.text.count("WithVendor") == 1
        # The subtitle class appears exactly once (only the with-vendor row).
        assert r.text.count("alert-vendor-subtitle") == 1
    finally:
        db.close()


# ---------------------------------------------------------------------------
# list_alerts_with_match preserves order of list_alerts.
# ---------------------------------------------------------------------------


def test_list_alerts_with_match_preserves_list_alerts_order(tmp_path):
    db = Database(str(tmp_path / "order.db"))
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "high")
        _add_meta(db, wid, vendor="Acme", confidence=80)
        db.upsert_device("aa:bb:cc:dd:ee:01", "wifi", "Acme", 0, 1000)
        # Insert alerts at known timestamps with mixed match/no-match.
        for i, (ts, mac, match) in enumerate(
            [
                (1000, None, None),
                (2000, "aa:bb:cc:dd:ee:01", wid),
                (3000, None, None),
                (4000, "aa:bb:cc:dd:ee:01", wid),
                (5000, None, None),
            ]
        ):
            db.add_alert(
                ts=ts,
                rule_name=f"r{i}",
                mac=mac,
                message=f"m{i}",
                severity="med",
                matched_watchlist_id=match,
            )
        bare = db.list_alerts()
        joined = db.list_alerts_with_match()
        assert [r["id"] for r in bare] == [r["id"] for r in joined]
        assert [r["ts"] for r in bare] == [r["ts"] for r in joined]
    finally:
        db.close()


# ---------------------------------------------------------------------------
# ntfy notification body (via poll_once + RecordingNotifier).
# ---------------------------------------------------------------------------


def _ntfy_run(tmp_path, *, watchlist_pattern, metadata_fields, rule_pattern):
    """Run a single poll cycle that should match the apple MAC in the kismet
    fixture against `watchlist_pattern`. If `metadata_fields` is non-None, a
    metadata row is inserted on the watchlist row before the poll. Returns
    the list of recorded notifier calls."""
    db_path = str(tmp_path / "lyn.db")
    db = Database(db_path)
    try:
        wid = _add_watchlist(db, watchlist_pattern, "mac", "high")
        if metadata_fields is not None:
            _add_meta(db, wid, **metadata_fields)
        config = Config(
            kismet_fixture_path=str(FIXTURE_PATH),
            db_path=db_path,
            location_id="testloc",
            location_label="Test Location",
            alert_dedup_window_seconds=0,
        )
        client = FakeKismetClient(str(FIXTURE_PATH))
        rs = Ruleset(
            rules=[
                Rule(
                    name="apple_mac",
                    rule_type="watchlist_mac",
                    severity="high",
                    patterns=[rule_pattern],
                )
            ]
        )
        rec = RecordingNotifier()
        poll_once(client, db, config, 1700001000, ruleset=rs, notifier=rec)
        return rec.calls
    finally:
        db.close()


def test_ntfy_body_appends_vendor_and_confidence(tmp_path):
    calls = _ntfy_run(
        tmp_path,
        watchlist_pattern="a4:83:e7:11:22:33",
        metadata_fields={"vendor": "Flock", "confidence": 90},
        rule_pattern="a4:83:e7:11:22:33",
    )
    assert any(" | vendor: Flock | confidence: 90" in msg for _, _, msg in calls)


def test_ntfy_body_appends_only_vendor(tmp_path):
    calls = _ntfy_run(
        tmp_path,
        watchlist_pattern="a4:83:e7:11:22:33",
        metadata_fields={"vendor": "Flock"},  # no confidence
        rule_pattern="a4:83:e7:11:22:33",
    )
    matched = [m for _, _, m in calls if "Flock" in m]
    assert matched, f"expected vendor in some message, got: {calls!r}"
    for m in matched:
        assert " | vendor: Flock" in m
        assert "confidence" not in m


def test_ntfy_body_appends_only_confidence(tmp_path):
    calls = _ntfy_run(
        tmp_path,
        watchlist_pattern="a4:83:e7:11:22:33",
        metadata_fields={"confidence": 42},
        rule_pattern="a4:83:e7:11:22:33",
    )
    matched = [m for _, _, m in calls if "confidence: 42" in m]
    assert matched, f"expected confidence in some message, got: {calls!r}"
    for m in matched:
        assert " | confidence: 42" in m
        assert "vendor" not in m


def test_ntfy_body_unchanged_when_metadata_present_but_fields_null(tmp_path):
    # Metadata row exists but vendor and confidence are both NULL.
    calls = _ntfy_run(
        tmp_path,
        watchlist_pattern="a4:83:e7:11:22:33",
        metadata_fields={"source": "vendor_docs"},  # no vendor/confidence
        rule_pattern="a4:83:e7:11:22:33",
    )
    assert calls, "expected at least one notification"
    for _, _, m in calls:
        assert "vendor:" not in m
        assert "confidence:" not in m


def test_ntfy_body_unchanged_when_no_metadata_row(tmp_path):
    # Watchlist row exists, but no metadata row.
    calls = _ntfy_run(
        tmp_path,
        watchlist_pattern="a4:83:e7:11:22:33",
        metadata_fields=None,
        rule_pattern="a4:83:e7:11:22:33",
    )
    assert calls, "expected at least one notification"
    for _, _, m in calls:
        assert "vendor:" not in m
        assert "confidence:" not in m


def test_ntfy_body_unchanged_when_no_match(tmp_path):
    # Rule fires but the watchlist DB row doesn't exist for the matched MAC,
    # so matched_watchlist_id is NULL and there's no metadata to append.
    db_path = str(tmp_path / "lyn.db")
    db = Database(db_path)
    try:
        config = Config(
            kismet_fixture_path=str(FIXTURE_PATH),
            db_path=db_path,
            location_id="testloc",
            location_label="Test Location",
            alert_dedup_window_seconds=0,
        )
        client = FakeKismetClient(str(FIXTURE_PATH))
        rs = Ruleset(
            rules=[
                Rule(
                    name="apple_mac",
                    rule_type="watchlist_mac",
                    severity="high",
                    patterns=["a4:83:e7:11:22:33"],
                )
            ]
        )
        rec = RecordingNotifier()
        poll_once(client, db, config, 1700001000, ruleset=rs, notifier=rec)
        assert rec.calls, "expected the rule to fire and notify"
        for _, _, m in rec.calls:
            assert "vendor:" not in m
            assert "confidence:" not in m
    finally:
        db.close()


def test_ntfy_title_unchanged_with_metadata(tmp_path):
    """Title format is governed by the existing severity routing — metadata
    must not perturb it."""
    calls = _ntfy_run(
        tmp_path,
        watchlist_pattern="a4:83:e7:11:22:33",
        metadata_fields={"vendor": "Flock", "confidence": 90},
        rule_pattern="a4:83:e7:11:22:33",
    )
    titles = [t for _, t, _ in calls]
    assert all(t == "lynceus: HIGH alert" for t in titles), titles


# ---------------------------------------------------------------------------
# XSS — Jinja autoescape.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_xss_vendor_escaped_on_alert_detail(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med")
        _add_meta(db, wid, vendor='Acme"<img src=x onerror=1>')
        aid = _add_alert(
            db,
            mac="aa:bb:cc:dd:ee:01",
            severity="med",
            matched_watchlist_id=wid,
        )
        with TestClient(app) as client:
            r = client.get(f"/alerts/{aid}")
        assert r.status_code == 200
        assert "<img src=x onerror=1>" not in r.text
        assert "&lt;img src=x onerror=1&gt;" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_xss_vendor_escaped_on_alerts_list(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "high")
        _add_meta(db, wid, vendor="Acme</script><b>boom")
        db.upsert_device("aa:bb:cc:dd:ee:01", "wifi", "Acme", 0, 100)
        _add_alert(
            db,
            mac="aa:bb:cc:dd:ee:01",
            severity="high",
            matched_watchlist_id=wid,
        )
        with TestClient(app) as client:
            r = client.get("/alerts")
        assert r.status_code == 200
        assert "Acme</script><b>boom" not in r.text
        assert "Acme&lt;/script&gt;&lt;b&gt;boom" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_xss_source_excerpt_escaped(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        wid = _add_watchlist(db, "aa:bb:cc:dd:ee:01", "mac", "med")
        _add_meta(db, wid, source_excerpt="<script>alert(1)</script>plain")
        aid = _add_alert(
            db,
            mac="aa:bb:cc:dd:ee:01",
            severity="med",
            matched_watchlist_id=wid,
        )
        with TestClient(app) as client:
            r = client.get(f"/alerts/{aid}")
        assert r.status_code == 200
        assert "<script>alert(1)</script>" not in r.text
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in r.text
    finally:
        db.close()
