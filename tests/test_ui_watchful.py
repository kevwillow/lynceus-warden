"""Tests for the Phase 2a watchful-snooze operator POST routes.

Six routes cover the operator-action surface plus the /alerts triage
entry-point. All are CSRF-protected via the global middleware (the
`_csrf` form field), return 303 on success, and reject malformed input
with HTTPException 400.

Phase 2b lands the UI; these tests assert backend semantics only --
status codes, redirect targets, DB-state transitions, and the
"already-actioned" rejection pattern.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from lynceus.allowlist import derive_ui_path, load_allowlist
from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import create_app
from lynceus.webui.csrf import CSRF_COOKIE_NAME, CSRF_FORM_FIELD

WATCHFUL_MAC = "aa:bb:cc:11:22:33"


def _make_app(tmp_path, *, with_allowlist: bool = False):
    db_path = str(tmp_path / "ui.db")
    if with_allowlist:
        allowlist_path = tmp_path / "allowlist.yaml"
        allowlist_path.write_text("entries: []\n", encoding="utf-8")
        config = Config(db_path=db_path, allowlist_path=str(allowlist_path))
    else:
        config = Config(db_path=db_path)
    db = Database(db_path)
    app = create_app(config, db)
    return app, db, config


def _csrf_setup(client):
    """Bootstrap the CSRF cookie + return the token to use in form posts."""
    resp = client.get("/alerts")
    cookie = resp.cookies[CSRF_COOKIE_NAME]
    return cookie


def _insert_watchful(
    db,
    mac=WATCHFUL_MAC,
    *,
    created_at=1000,
    first_seen_at=1000,
    last_seen_at=1000,
    sighting_count=1,
    snooze_expires_at=None,
    escalated_at=None,
    archived_at=None,
):
    cur = db._conn.execute(
        "INSERT INTO watchful_recurrence("
        "mac, created_at, first_seen_at, last_seen_at, sighting_count, "
        "snooze_expires_at, escalated_at, archived_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            mac,
            created_at,
            first_seen_at,
            last_seen_at,
            sighting_count,
            snooze_expires_at,
            escalated_at,
            archived_at,
        ),
    )
    db._conn.commit()
    return cur.lastrowid


def _seed_alert(db, *, mac=WATCHFUL_MAC, watchlist_id=None, ts=1000):
    if mac is not None:
        db.upsert_device(mac, "wifi", None, 0, ts)
    return db.add_alert(
        ts=ts, rule_name="r", mac=mac, message="m", severity="low",
        matched_watchlist_id=watchlist_id,
    )


# --- CSRF rejection (one parametrized check covers all six routes) ----------


@pytest.mark.webui
@pytest.mark.parametrize(
    "method_path",
    [
        # /alerts/{id}/watch needs a real alert id; /watchful/{id}/*
        # need a real entry id. Use id=1 in every URL; the CSRF check
        # fires before the route handler so the id never gets looked up.
        ("POST", "/alerts/1/watch"),
        ("POST", "/watchful/1/dismiss"),
        ("POST", "/watchful/1/promote"),
        ("POST", "/watchful/1/reset"),
        ("POST", "/watchful/1/investigate"),
        ("POST", "/watchful/1/confirm-safe"),
    ],
)
def test_route_without_csrf_returns_403(tmp_path, method_path):
    method, path = method_path
    app, db, _ = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            client.cookies.clear()
            r = client.request(method, path)
        assert r.status_code == 403
        assert "CSRF" in r.text
    finally:
        db.close()


# --- /alerts/{id}/watch -----------------------------------------------------


@pytest.mark.webui
def test_watch_alert_creates_watchful_entry_with_24h_snooze(tmp_path):
    app, db, _ = _make_app(tmp_path)
    try:
        alert_id = _seed_alert(db)
        with TestClient(app, follow_redirects=False) as client:
            token = _csrf_setup(client)
            r = client.post(
                f"/alerts/{alert_id}/watch",
                data={CSRF_FORM_FIELD: token, "snooze_duration": "24h"},
            )
        assert r.status_code == 303
        entry = db.get_active_watchful_recurrence_by_mac(WATCHFUL_MAC)
        assert entry is not None
        assert entry.source_alert_id == alert_id
        assert entry.snooze_expires_at is not None
        # The snooze window is "now + 24h"; >= alert ts + 24h holds.
        assert entry.snooze_expires_at >= 1000 + 86400
    finally:
        db.close()


@pytest.mark.webui
def test_watch_alert_forever_snooze_is_null(tmp_path):
    app, db, _ = _make_app(tmp_path)
    try:
        alert_id = _seed_alert(db)
        with TestClient(app, follow_redirects=False) as client:
            token = _csrf_setup(client)
            r = client.post(
                f"/alerts/{alert_id}/watch",
                data={CSRF_FORM_FIELD: token, "snooze_duration": "forever"},
            )
        assert r.status_code == 303
        entry = db.get_active_watchful_recurrence_by_mac(WATCHFUL_MAC)
        assert entry.snooze_expires_at is None
    finally:
        db.close()


@pytest.mark.webui
def test_watch_alert_invalid_snooze_duration_returns_400(tmp_path):
    app, db, _ = _make_app(tmp_path)
    try:
        alert_id = _seed_alert(db)
        with TestClient(app, follow_redirects=False) as client:
            token = _csrf_setup(client)
            r = client.post(
                f"/alerts/{alert_id}/watch",
                data={CSRF_FORM_FIELD: token, "snooze_duration": "5y"},
            )
        assert r.status_code == 400
        assert db.get_active_watchful_recurrence_by_mac(WATCHFUL_MAC) is None
    finally:
        db.close()


@pytest.mark.webui
def test_watch_alert_missing_alert_returns_404(tmp_path):
    app, db, _ = _make_app(tmp_path)
    try:
        with TestClient(app, follow_redirects=False) as client:
            token = _csrf_setup(client)
            r = client.post(
                "/alerts/9999/watch",
                data={CSRF_FORM_FIELD: token, "snooze_duration": "24h"},
            )
        assert r.status_code == 404
    finally:
        db.close()


@pytest.mark.webui
def test_watch_alert_duplicate_active_mac_returns_400(tmp_path):
    """The application-layer 'one active watchful per MAC' invariant
    surfaces as HTTPException 400 from the route, not 500."""
    app, db, _ = _make_app(tmp_path)
    try:
        _insert_watchful(db)
        alert_id = _seed_alert(db)
        with TestClient(app, follow_redirects=False) as client:
            token = _csrf_setup(client)
            r = client.post(
                f"/alerts/{alert_id}/watch",
                data={CSRF_FORM_FIELD: token, "snooze_duration": "24h"},
            )
        assert r.status_code == 400
    finally:
        db.close()


# --- /watchful/{id}/dismiss -------------------------------------------------


@pytest.mark.webui
def test_dismiss_archives_entry(tmp_path):
    app, db, _ = _make_app(tmp_path)
    try:
        entry_id = _insert_watchful(db)
        with TestClient(app, follow_redirects=False) as client:
            token = _csrf_setup(client)
            r = client.post(
                f"/watchful/{entry_id}/dismiss",
                data={CSRF_FORM_FIELD: token},
            )
        assert r.status_code == 303
        assert db.get_watchful_recurrence(entry_id).archived_at is not None
    finally:
        db.close()


@pytest.mark.webui
def test_dismiss_already_archived_still_redirects(tmp_path):
    """Dismiss is idempotent per the helper spec -- second call returns
    303 with no DB change rather than 4xx."""
    app, db, _ = _make_app(tmp_path)
    try:
        entry_id = _insert_watchful(db, archived_at=2000)
        with TestClient(app, follow_redirects=False) as client:
            token = _csrf_setup(client)
            r = client.post(
                f"/watchful/{entry_id}/dismiss",
                data={CSRF_FORM_FIELD: token},
            )
        assert r.status_code == 303
        # archived_at unchanged.
        assert db.get_watchful_recurrence(entry_id).archived_at == 2000
    finally:
        db.close()


@pytest.mark.webui
def test_dismiss_missing_entry_returns_404(tmp_path):
    app, db, _ = _make_app(tmp_path)
    try:
        with TestClient(app, follow_redirects=False) as client:
            token = _csrf_setup(client)
            r = client.post(
                "/watchful/9999/dismiss", data={CSRF_FORM_FIELD: token},
            )
        assert r.status_code == 404
    finally:
        db.close()


# --- /watchful/{id}/promote -------------------------------------------------


@pytest.mark.webui
def test_promote_archives_and_writes_allowlist(tmp_path):
    app, db, config = _make_app(tmp_path, with_allowlist=True)
    try:
        entry_id = _insert_watchful(db)
        with TestClient(app, follow_redirects=False) as client:
            token = _csrf_setup(client)
            r = client.post(
                f"/watchful/{entry_id}/promote",
                data={CSRF_FORM_FIELD: token, "note": "known printer"},
            )
        assert r.status_code == 303
        assert db.get_watchful_recurrence(entry_id).archived_at is not None
        allowlist = load_allowlist(config.allowlist_path)
        assert len(allowlist.entries) == 1
        entry = allowlist.entries[0]
        assert entry.pattern == WATCHFUL_MAC
        assert entry.pattern_type == "mac"
        # The route prepends a provenance marker and appends the operator's note.
        assert "promoted from watchful entry" in (entry.note or "")
        assert "known printer" in (entry.note or "")
        assert entry.expires_at is None
    finally:
        db.close()


@pytest.mark.webui
def test_promote_without_note_still_writes_provenance(tmp_path):
    app, db, config = _make_app(tmp_path, with_allowlist=True)
    try:
        entry_id = _insert_watchful(db)
        with TestClient(app, follow_redirects=False) as client:
            token = _csrf_setup(client)
            r = client.post(
                f"/watchful/{entry_id}/promote",
                data={CSRF_FORM_FIELD: token},
            )
        assert r.status_code == 303
        allowlist = load_allowlist(config.allowlist_path)
        assert len(allowlist.entries) == 1
        assert "promoted from watchful entry" in (allowlist.entries[0].note or "")
    finally:
        db.close()


@pytest.mark.webui
def test_promote_already_archived_returns_400_and_no_allowlist_write(tmp_path):
    app, db, config = _make_app(tmp_path, with_allowlist=True)
    try:
        entry_id = _insert_watchful(db, archived_at=2000)
        with TestClient(app, follow_redirects=False) as client:
            token = _csrf_setup(client)
            r = client.post(
                f"/watchful/{entry_id}/promote",
                data={CSRF_FORM_FIELD: token},
            )
        assert r.status_code == 400
        # And: the allowlist UI file was not even created.
        assert not derive_ui_path(
            __import__("pathlib").Path(config.allowlist_path)
        ).exists()
    finally:
        db.close()


@pytest.mark.webui
def test_promote_missing_entry_returns_404(tmp_path):
    app, db, _ = _make_app(tmp_path, with_allowlist=True)
    try:
        with TestClient(app, follow_redirects=False) as client:
            token = _csrf_setup(client)
            r = client.post(
                "/watchful/9999/promote", data={CSRF_FORM_FIELD: token},
            )
        assert r.status_code == 404
    finally:
        db.close()


@pytest.mark.webui
def test_promote_without_allowlist_path_returns_400(tmp_path):
    """If allowlist_path isn't configured there's nothing to write to,
    so the route refuses before touching the DB. Matches the existing
    /alerts/{id}/allowlist precondition pattern."""
    app, db, _ = _make_app(tmp_path)  # no allowlist
    try:
        entry_id = _insert_watchful(db)
        with TestClient(app, follow_redirects=False) as client:
            token = _csrf_setup(client)
            r = client.post(
                f"/watchful/{entry_id}/promote",
                data={CSRF_FORM_FIELD: token},
            )
        assert r.status_code == 400
        # DB unchanged.
        assert db.get_watchful_recurrence(entry_id).archived_at is None
    finally:
        db.close()


# --- /watchful/{id}/reset ---------------------------------------------------


@pytest.mark.webui
def test_reset_walks_back_from_escalated(tmp_path):
    app, db, _ = _make_app(tmp_path)
    try:
        entry_id = _insert_watchful(
            db, sighting_count=4, escalated_at=2000,
        )
        with TestClient(app, follow_redirects=False) as client:
            token = _csrf_setup(client)
            r = client.post(
                f"/watchful/{entry_id}/reset", data={CSRF_FORM_FIELD: token},
            )
        assert r.status_code == 303
        row = db.get_watchful_recurrence(entry_id)
        assert row.escalated_at is None
        assert row.sighting_count == 1
        assert row.reset_count == 1
    finally:
        db.close()


@pytest.mark.webui
def test_reset_from_tracking_returns_400(tmp_path):
    app, db, _ = _make_app(tmp_path)
    try:
        entry_id = _insert_watchful(db)  # escalated_at = None
        with TestClient(app, follow_redirects=False) as client:
            token = _csrf_setup(client)
            r = client.post(
                f"/watchful/{entry_id}/reset", data={CSRF_FORM_FIELD: token},
            )
        assert r.status_code == 400
    finally:
        db.close()


@pytest.mark.webui
def test_reset_already_archived_returns_400(tmp_path):
    app, db, _ = _make_app(tmp_path)
    try:
        entry_id = _insert_watchful(
            db, escalated_at=2000, archived_at=3000,
        )
        with TestClient(app, follow_redirects=False) as client:
            token = _csrf_setup(client)
            r = client.post(
                f"/watchful/{entry_id}/reset", data={CSRF_FORM_FIELD: token},
            )
        assert r.status_code == 400
    finally:
        db.close()


@pytest.mark.webui
def test_reset_missing_entry_returns_404(tmp_path):
    app, db, _ = _make_app(tmp_path)
    try:
        with TestClient(app, follow_redirects=False) as client:
            token = _csrf_setup(client)
            r = client.post(
                "/watchful/9999/reset", data={CSRF_FORM_FIELD: token},
            )
        assert r.status_code == 404
    finally:
        db.close()


# --- /watchful/{id}/investigate --------------------------------------------


@pytest.mark.webui
def test_investigate_sets_flag_and_note_without_archiving(tmp_path):
    app, db, _ = _make_app(tmp_path)
    try:
        entry_id = _insert_watchful(db)
        with TestClient(app, follow_redirects=False) as client:
            token = _csrf_setup(client)
            r = client.post(
                f"/watchful/{entry_id}/investigate",
                data={CSRF_FORM_FIELD: token, "note": "near front door"},
            )
        assert r.status_code == 303
        row = db.get_watchful_recurrence(entry_id)
        assert row.flagged_for_investigation == 1
        assert row.operator_note == "near front door"
        # Entry stays active.
        assert row.archived_at is None
    finally:
        db.close()


@pytest.mark.webui
def test_investigate_already_archived_returns_400(tmp_path):
    app, db, _ = _make_app(tmp_path)
    try:
        entry_id = _insert_watchful(db, archived_at=2000)
        with TestClient(app, follow_redirects=False) as client:
            token = _csrf_setup(client)
            r = client.post(
                f"/watchful/{entry_id}/investigate",
                data={CSRF_FORM_FIELD: token, "note": "n"},
            )
        assert r.status_code == 400
    finally:
        db.close()


@pytest.mark.webui
def test_investigate_oversize_note_returns_400(tmp_path):
    app, db, _ = _make_app(tmp_path)
    try:
        entry_id = _insert_watchful(db)
        with TestClient(app, follow_redirects=False) as client:
            token = _csrf_setup(client)
            r = client.post(
                f"/watchful/{entry_id}/investigate",
                data={CSRF_FORM_FIELD: token, "note": "x" * 5000},
            )
        assert r.status_code == 400
    finally:
        db.close()


# --- /watchful/{id}/confirm-safe -------------------------------------------


@pytest.mark.webui
def test_confirm_safe_flags_and_archives(tmp_path):
    app, db, _ = _make_app(tmp_path)
    try:
        entry_id = _insert_watchful(db)
        with TestClient(app, follow_redirects=False) as client:
            token = _csrf_setup(client)
            r = client.post(
                f"/watchful/{entry_id}/confirm-safe",
                data={CSRF_FORM_FIELD: token, "note": "neighbour TV"},
            )
        assert r.status_code == 303
        row = db.get_watchful_recurrence(entry_id)
        assert row.confirmed_safe == 1
        assert row.operator_note == "neighbour TV"
        assert row.archived_at is not None
    finally:
        db.close()


@pytest.mark.webui
def test_confirm_safe_does_not_write_allowlist(tmp_path):
    """Confirmed-safe is distinct from promote: no allowlist entry is
    created. The same MAC appearing tomorrow can still raise a fresh
    watchlist hit."""
    app, db, config = _make_app(tmp_path, with_allowlist=True)
    try:
        entry_id = _insert_watchful(db)
        with TestClient(app, follow_redirects=False) as client:
            token = _csrf_setup(client)
            r = client.post(
                f"/watchful/{entry_id}/confirm-safe",
                data={CSRF_FORM_FIELD: token, "note": "benign"},
            )
        assert r.status_code == 303
        # Allowlist primary unchanged; UI file never created.
        allowlist = load_allowlist(config.allowlist_path)
        assert allowlist.entries == []
        ui_path = derive_ui_path(
            __import__("pathlib").Path(config.allowlist_path)
        )
        assert not ui_path.exists()
    finally:
        db.close()


@pytest.mark.webui
def test_confirm_safe_already_archived_returns_400(tmp_path):
    app, db, _ = _make_app(tmp_path)
    try:
        entry_id = _insert_watchful(db, archived_at=2000)
        with TestClient(app, follow_redirects=False) as client:
            token = _csrf_setup(client)
            r = client.post(
                f"/watchful/{entry_id}/confirm-safe",
                data={CSRF_FORM_FIELD: token, "note": "x"},
            )
        assert r.status_code == 400
    finally:
        db.close()


# ===================== Phase 2b: GET /watchful + detail page ===============
# Renders the operator-facing UI: filter form, pagination, per-row
# action buttons (state-conditional), recurrence digest, triage button
# on /alerts, and topnav entry.


def _now_ts():
    import time
    return int(time.time())


@pytest.mark.webui
def test_watchful_get_returns_empty_state_when_no_entries(tmp_path):
    app, db, _ = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/watchful")
        assert r.status_code == 200
        assert "watchful" in r.text.lower()
        assert "No watchful entries yet" in r.text
        # Digest empty-state copy renders cleanly.
        assert "No recurrences escalated" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_watchful_get_renders_rows_with_state_badges(tmp_path):
    app, db, _ = _make_app(tmp_path)
    try:
        _insert_watchful(db, mac="aa:bb:cc:00:00:01")
        _insert_watchful(
            db, mac="aa:bb:cc:00:00:02",
            sighting_count=4, escalated_at=2000,
        )
        with TestClient(app) as client:
            r = client.get("/watchful")
        assert r.status_code == 200
        assert "aa:bb:cc:00:00:01" in r.text
        assert "aa:bb:cc:00:00:02" in r.text
        assert "badge-watchful-tracking" in r.text
        assert "badge-watchful-escalated" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_watchful_get_filter_archived_excludes_active(tmp_path):
    app, db, _ = _make_app(tmp_path)
    try:
        _insert_watchful(db, mac="aa:bb:cc:00:00:01")  # active
        _insert_watchful(
            db, mac="aa:bb:cc:00:00:02", archived_at=2000,
        )
        with TestClient(app) as client:
            r = client.get("/watchful?status=archived")
        assert r.status_code == 200
        assert "aa:bb:cc:00:00:02" in r.text
        assert "aa:bb:cc:00:00:01" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_watchful_get_filter_state_escalated_excludes_tracking(tmp_path):
    app, db, _ = _make_app(tmp_path)
    try:
        _insert_watchful(db, mac="aa:bb:cc:00:00:01")  # tracking
        _insert_watchful(
            db, mac="aa:bb:cc:00:00:02",
            sighting_count=4, escalated_at=2000,
        )
        with TestClient(app) as client:
            r = client.get("/watchful?state=escalated")
        assert r.status_code == 200
        assert "aa:bb:cc:00:00:02" in r.text
        assert "aa:bb:cc:00:00:01" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_watchful_get_filter_window_24h(tmp_path):
    """Window narrows on last_seen_at; entries older than the window
    are excluded."""
    app, db, _ = _make_app(tmp_path)
    try:
        now = _now_ts()
        # one recent (last_seen_at = now), one old (5 days ago)
        _insert_watchful(
            db, mac="aa:bb:cc:00:00:01",
            first_seen_at=now, last_seen_at=now,
        )
        _insert_watchful(
            db, mac="aa:bb:cc:00:00:02",
            first_seen_at=now - 5 * 86400,
            last_seen_at=now - 5 * 86400,
        )
        with TestClient(app) as client:
            r = client.get("/watchful?window=24h")
        assert r.status_code == 200
        assert "aa:bb:cc:00:00:01" in r.text
        assert "aa:bb:cc:00:00:02" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_watchful_get_filter_mac_substring(tmp_path):
    app, db, _ = _make_app(tmp_path)
    try:
        _insert_watchful(db, mac="aa:bb:cc:00:00:01")
        _insert_watchful(db, mac="dd:ee:ff:11:22:33")
        with TestClient(app) as client:
            r = client.get("/watchful?q=dd:ee")
        assert r.status_code == 200
        assert "dd:ee:ff:11:22:33" in r.text
        assert "aa:bb:cc:00:00:01" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_watchful_get_pagination_renders_two_pages(tmp_path):
    """50 entries with page_size=25 → 2 pages; next link present on
    page 1; prev link present on page 2."""
    app, db, _ = _make_app(tmp_path)
    try:
        for i in range(50):
            _insert_watchful(
                db, mac=f"aa:bb:cc:00:{i // 256:02x}:{i % 256:02x}",
            )
        with TestClient(app) as client:
            r1 = client.get("/watchful?page_size=25")
            r2 = client.get("/watchful?page_size=25&page=2")
        assert r1.status_code == 200 and r2.status_code == 200
        # Page 1: 25 rows visible (count by checking pagination footer).
        assert "page=2" in r1.text  # next-link
        assert "50 total" in r1.text
        # Page 2: prev-link to page 1.
        assert "page=1" in r2.text
    finally:
        db.close()


@pytest.mark.webui
def test_watchful_get_invalid_filters_silently_fall_back(tmp_path):
    """Per the clamp posture: a stale bookmark with unknown filter
    values lands on the unfiltered page, not 400. Matches /alerts
    /rules behavior."""
    app, db, _ = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/watchful?status=bogus&state=foo&window=99h&page_size=37")
        assert r.status_code == 200
    finally:
        db.close()


# --- Per-entry action-button visibility ------------------------------------


@pytest.mark.webui
def test_watchful_get_escalated_row_shows_all_five_actions(tmp_path):
    app, db, _ = _make_app(tmp_path)
    try:
        _insert_watchful(
            db, sighting_count=4, escalated_at=2000,
        )
        with TestClient(app) as client:
            r = client.get("/watchful")
        assert r.status_code == 200
        # Each action button has a unique CSS class for visibility checks.
        assert "watchful-action-reset" in r.text
        assert "watchful-action-dismiss" in r.text
        assert "watchful-action-promote" in r.text
        assert "watchful-action-investigate" in r.text
        assert "watchful-action-safe" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_watchful_get_tracking_row_hides_reset(tmp_path):
    """Reset is only meaningful from escalated (Phase 2a state guard).
    The button is hidden on tracking entries so the operator can't
    click it and see a 400."""
    app, db, _ = _make_app(tmp_path)
    try:
        _insert_watchful(db)  # tracking
        with TestClient(app) as client:
            r = client.get("/watchful")
        assert r.status_code == 200
        assert "watchful-action-dismiss" in r.text
        assert "watchful-action-promote" in r.text
        assert "watchful-action-investigate" in r.text
        assert "watchful-action-safe" in r.text
        # Reset hidden:
        assert "watchful-action-reset" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_watchful_get_archived_row_shows_no_actions(tmp_path):
    """Archived entries are read-only. None of the Phase 2a action
    helpers accept already-archived input (dismiss is idempotent but
    pointless; the rest reject with ValueError) so the entire action
    panel is suppressed."""
    app, db, _ = _make_app(tmp_path)
    try:
        _insert_watchful(db, archived_at=2000)
        with TestClient(app) as client:
            r = client.get("/watchful?status=archived")
        assert r.status_code == 200
        assert "watchful-action-reset" not in r.text
        assert "watchful-action-dismiss" not in r.text
        assert "watchful-action-promote" not in r.text
        assert "watchful-action-investigate" not in r.text
        assert "watchful-action-safe" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_watchful_get_action_forms_carry_csrf(tmp_path):
    """Each action form has a hidden _csrf input rendered by the
    csrf_token jinja global. Verified once across all five buttons."""
    app, db, _ = _make_app(tmp_path)
    try:
        _insert_watchful(
            db, sighting_count=4, escalated_at=2000,
        )
        with TestClient(app) as client:
            r = client.get("/watchful")
        assert r.status_code == 200
        # Five action forms, five _csrf inputs in the row.
        assert r.text.count('name="_csrf"') >= 5
    finally:
        db.close()


@pytest.mark.webui
def test_watchful_get_promote_and_safe_are_visually_distinct(tmp_path):
    """The two close-the-entry actions must read differently in the
    template so an operator doesn't conflate 'close as benign' with
    'never alert me on this MAC again'. Test pins the load-bearing
    distinction strings."""
    app, db, _ = _make_app(tmp_path)
    try:
        _insert_watchful(db)
        with TestClient(app) as client:
            r = client.get("/watchful")
        assert r.status_code == 200
        # Promote: explicitly permanent.
        assert "permanent allowlist" in r.text
        # Confirmed-safe: explicitly NOT permanent (template phrasing).
        assert "Unlike" in r.text and "promote" in r.text
    finally:
        db.close()


# --- Weekly digest ---------------------------------------------------------


@pytest.mark.webui
def test_watchful_digest_empty_state(tmp_path):
    """With no escalations in the window, the digest section renders
    its empty-state copy, not a blank panel."""
    app, db, _ = _make_app(tmp_path)
    try:
        # Tracking entry has no escalated_at → not in digest.
        _insert_watchful(db)
        with TestClient(app) as client:
            r = client.get("/watchful")
        assert r.status_code == 200
        assert "No recurrences escalated" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_watchful_digest_groups_escalations_by_iso_week(tmp_path):
    """Escalations across three distinct ISO weeks render as three
    digest entries. Verifies the week-grouping path and that all
    three week labels appear in the rendered page."""
    import datetime as _dt
    app, db, _ = _make_app(tmp_path)
    try:
        now = _now_ts()
        # Three escalations spaced 7-10 days apart so they fall in
        # different ISO weeks. Use offsets that comfortably cross
        # week boundaries regardless of which weekday today is.
        for i, offset_days in enumerate((0, 9, 18)):
            ts = now - offset_days * 86400
            _insert_watchful(
                db,
                mac=f"aa:bb:cc:00:00:{i:02x}",
                sighting_count=4,
                escalated_at=ts,
                last_seen_at=ts,
            )
        with TestClient(app) as client:
            r = client.get("/watchful")
        assert r.status_code == 200
        # The three escalations should produce three distinct
        # ISO-week labels (YYYY-Www format).
        iso_labels = set()
        for offset_days in (0, 9, 18):
            iy, iw, _wd = _dt.datetime.fromtimestamp(
                now - offset_days * 86400, tz=_dt.UTC,
            ).isocalendar()
            iso_labels.add(f"{iy}-W{iw:02d}")
        # All three labels should appear; collapse rare collisions.
        labels_present = sum(1 for lbl in iso_labels if lbl in r.text)
        assert labels_present == len(iso_labels)
        # Each MAC should appear in the digest.
        for i in range(3):
            assert f"aa:bb:cc:00:00:{i:02x}" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_watchful_digest_excludes_escalations_older_than_window(tmp_path):
    """Default digest window is 8 weeks. An escalation 20 weeks old
    must not appear in the digest, even though the row itself still
    exists in the table."""
    app, db, _ = _make_app(tmp_path)
    try:
        now = _now_ts()
        # 20 weeks ago = well outside the 8-week window
        old_ts = now - 20 * 7 * 86400
        _insert_watchful(
            db, mac="aa:bb:cc:00:00:01",
            sighting_count=4, escalated_at=old_ts, last_seen_at=old_ts,
        )
        with TestClient(app) as client:
            r = client.get("/watchful")
        assert r.status_code == 200
        # Empty-state copy renders since no escalations fall in the
        # 8-week window.
        assert "No recurrences escalated" in r.text
    finally:
        db.close()


# --- GET /watchful/{id} detail page ----------------------------------------


@pytest.mark.webui
def test_watchful_detail_renders_for_existing_entry(tmp_path):
    app, db, _ = _make_app(tmp_path)
    try:
        entry_id = _insert_watchful(db, sighting_count=4, escalated_at=2000)
        with TestClient(app) as client:
            r = client.get(f"/watchful/{entry_id}")
        assert r.status_code == 200
        assert f"watchful entry #{entry_id}" in r.text
        assert WATCHFUL_MAC in r.text
        # Action buttons present because not archived.
        assert "watchful-action-promote" in r.text
        assert "watchful-action-reset" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_watchful_detail_hides_actions_for_archived(tmp_path):
    app, db, _ = _make_app(tmp_path)
    try:
        entry_id = _insert_watchful(db, archived_at=2000)
        with TestClient(app) as client:
            r = client.get(f"/watchful/{entry_id}")
        assert r.status_code == 200
        assert "Read-only" in r.text
        assert "watchful-action-promote" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_watchful_detail_returns_404_for_missing(tmp_path):
    app, db, _ = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/watchful/9999")
        assert r.status_code == 404
    finally:
        db.close()


@pytest.mark.webui
def test_watchful_detail_links_source_alert_and_watchlist(tmp_path):
    app, db, _ = _make_app(tmp_path)
    try:
        # Set up: a watchlist entry + an alert, then a watchful row
        # referencing both.
        wl_cur = db._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
            "VALUES (?, 'mac', 'low', 'test')",
            (WATCHFUL_MAC,),
        )
        db._conn.commit()
        wl_id = wl_cur.lastrowid
        alert_id = _seed_alert(db, mac=WATCHFUL_MAC, watchlist_id=wl_id)
        # Direct INSERT bypasses helper signature; source/matched cols.
        cur = db._conn.execute(
            "INSERT INTO watchful_recurrence("
            "mac, created_at, first_seen_at, last_seen_at, sighting_count, "
            "source_alert_id, matched_watchlist_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (WATCHFUL_MAC, 1000, 1000, 1000, 1, alert_id, wl_id),
        )
        db._conn.commit()
        entry_id = cur.lastrowid
        with TestClient(app) as client:
            r = client.get(f"/watchful/{entry_id}")
        assert r.status_code == 200
        assert f"/alerts/{alert_id}" in r.text
        assert f"/watchlist/{wl_id}" in r.text
    finally:
        db.close()


# --- Action-redirect target + success flash --------------------------------


@pytest.mark.webui
def test_dismiss_redirect_lands_on_watchful_with_success_token(tmp_path):
    """Phase 2b updated the action redirect target. The Phase 2a tests
    asserted only the 303 status; here we pin the new Location."""
    app, db, _ = _make_app(tmp_path)
    try:
        entry_id = _insert_watchful(db)
        with TestClient(app, follow_redirects=False) as client:
            token = _csrf_setup(client)
            r = client.post(
                f"/watchful/{entry_id}/dismiss",
                data={CSRF_FORM_FIELD: token},
            )
        assert r.status_code == 303
        assert "/watchful" in r.headers["location"]
        assert "success=dismissed" in r.headers["location"]
    finally:
        db.close()


@pytest.mark.webui
def test_success_flash_renders_on_watchful_get(tmp_path):
    app, db, _ = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/watchful?success=dismissed")
        assert r.status_code == 200
        assert "flash-success" in r.text
        assert "Entry dismissed" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_unknown_success_token_silently_drops_flash(tmp_path):
    """A stale URL with ?success=foo must not render an arbitrary
    string in the flash banner."""
    app, db, _ = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/watchful?success=evil-html-injection")
        assert r.status_code == 200
        assert "flash-success" not in r.text
    finally:
        db.close()


# --- Triage button on /alerts ----------------------------------------------


@pytest.mark.webui
def test_alerts_list_renders_watch_button_for_alerts_with_mac(tmp_path):
    app, db, _ = _make_app(tmp_path)
    try:
        _seed_alert(db, mac="aa:bb:cc:11:22:33")
        with TestClient(app) as client:
            r = client.get("/alerts")
        assert r.status_code == 200
        # Form action posts to the Phase 2a route.
        assert "/watch" in r.text
        assert 'name="snooze_duration"' in r.text
        # All four locked snooze options present.
        for opt in ("24h", "7d", "30d", "forever"):
            assert f'value="{opt}"' in r.text
        # 30d selected by default per locked decision.
        assert 'value="30d" selected' in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_watch_form_omits_1h_option(tmp_path):
    """B1 added a 1h bucket to the shared ``_SNOOZE_DURATIONS`` map.
    The watchful triage selector on /alerts is intentionally left
    alone (recurrence-tracking semantics don't fit a 1h window — 1h
    is per-alert snooze territory). This test pins the
    visible-surface invariant against accidental template drift that
    would expose ``1h`` to operators on the watchful surface.

    Scoped to the ``watch-snooze-select`` element so the assertion
    doesn't catch the ``value="1h"`` that appears in the unrelated
    ``window`` filter dropdown on the same page.
    """
    import re as _re

    app, db, _ = _make_app(tmp_path)
    try:
        _seed_alert(db, mac="aa:bb:cc:11:22:33")
        with TestClient(app) as client:
            r = client.get("/alerts")
        assert r.status_code == 200
        m = _re.search(
            r'<select[^>]*class="watch-snooze-select"[^>]*>(.*?)</select>',
            r.text,
            flags=_re.DOTALL,
        )
        assert m is not None
        watch_select = m.group(1)
        # Exactly four options — same shape Phase 2b locked in.
        assert watch_select.count("<option") == 4
        assert 'value="1h"' not in watch_select
    finally:
        db.close()


@pytest.mark.webui
def test_alerts_list_hides_watch_button_for_alerts_without_mac(tmp_path):
    """Alerts without a MAC (pure SSID matches, e.g.) can't be triaged
    into the MAC-keyed watchful surface; the button is hidden so the
    operator never sees a button that 400s on click."""
    app, db, _ = _make_app(tmp_path)
    try:
        db.add_alert(
            ts=1000, rule_name="r", mac=None,
            message="m", severity="low",
        )
        with TestClient(app) as client:
            r = client.get("/alerts")
        assert r.status_code == 200
        # No /watch form element rendered. The CSS class
        # 'watch-button-inline' is unique to the triage form so a
        # negative grep is a sound test.
        assert "watch-button-inline" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_watch_post_creates_watchful_and_redirects(tmp_path):
    """End-to-end: operator clicks Watch on an alert; row appears on
    /watchful. Phase 2a route tests covered the POST mechanics; this
    pins the operator-visible loop."""
    app, db, _ = _make_app(tmp_path)
    try:
        alert_id = _seed_alert(db, mac="aa:bb:cc:11:22:33")
        with TestClient(app, follow_redirects=False) as client:
            token = _csrf_setup(client)
            r = client.post(
                f"/alerts/{alert_id}/watch",
                data={CSRF_FORM_FIELD: token, "snooze_duration": "30d"},
            )
        assert r.status_code == 303
        # Row created and visible on /watchful.
        with TestClient(app) as client:
            r2 = client.get("/watchful")
        assert "aa:bb:cc:11:22:33" in r2.text
    finally:
        db.close()


# --- Topnav ----------------------------------------------------------------


@pytest.mark.webui
def test_topnav_contains_watchful_link_on_every_page(tmp_path):
    """The /watchful link must appear in the topnav of every page that
    includes _topnav.html so the operator can reach the surface from
    anywhere."""
    app, db, _ = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            for path in ("/", "/alerts", "/healthz"):
                r = client.get(path)
                assert r.status_code == 200
                assert 'href="/watchful"' in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_topnav_active_state_on_watchful_page(tmp_path):
    app, db, _ = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/watchful")
        assert r.status_code == 200
        # active CSS class on the /watchful nav link.
        assert 'href="/watchful" class="active"' in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_topnav_active_state_on_watchful_detail_page(tmp_path):
    app, db, _ = _make_app(tmp_path)
    try:
        entry_id = _insert_watchful(db)
        with TestClient(app) as client:
            r = client.get(f"/watchful/{entry_id}")
        assert r.status_code == 200
        assert 'href="/watchful" class="active"' in r.text
    finally:
        db.close()
