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
