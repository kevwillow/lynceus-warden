"""Local-only validation for the watchful-escalation ntfy type/category suffix.

Gitignored (tests/ is excluded from the index); never staged. Covers the
guarded device+metadata lookup added at the escalation compose site so the
escalation ntfy carries " | radio: <type> | category: <category>" consistent
with the main alert path (85eb163), without breaking escalation when the
device/metadata is absent or the lookup raises.
"""

import pytest

from lynceus.db import Database, WatchfulRecurrence
from lynceus.notify import RecordingNotifier
from lynceus.poller import _emit_watchful_escalation

NOW = 1_700_000_000


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "lynceus.db")


@pytest.fixture
def db(db_path):
    d = Database(db_path)
    yield d
    d.close()


def _entry(db, mac, *, matched_watchlist_id):
    """Minimal escalated WatchfulRecurrence for the emitter, backed by a REAL
    row.

    ⛔ ``id`` used to be the literal 1, with no row behind it. Migration 026's
    ledger has ``entry_id INTEGER NOT NULL REFERENCES watchful_recurrence(id)``
    and ``PRAGMA foreign_keys`` is ON, so the escalation write now fails for an
    entry that does not exist -- which is correct, and which these tests were
    quietly relying on not being checked. The other fields stay synthetic
    because this file is about the ntfy SUFFIX, not the lifecycle.
    """
    src = db.add_alert(
        ts=NOW, rule_name="watchlisted mac", mac=mac, message="seen",
        severity="high", rule_type="watchlist_mac",
    )
    entry_id = db.create_watchful_from_alert(src, None, NOW)
    assert entry_id is not None, "fixture failed: no watchful entry created"
    return WatchfulRecurrence(
        id=entry_id,
        mac=mac,
        created_at=NOW,
        first_seen_at=NOW - 86_400 * 5,
        last_seen_at=NOW,
        sighting_count=4,
        snooze_expires_at=None,
        escalated_at=NOW,
        archived_at=None,
        source_alert_id=None,
        matched_watchlist_id=matched_watchlist_id,
        confirmed_safe=0,
        flagged_for_investigation=0,
        operator_note=None,
        reset_count=0,
    )


def _seed_match(db, *, device_category):
    wid, _ = db.add_watchlist(pattern="AA:BB:CC:DD:EE:FF", pattern_type="mac", severity="high")
    db.upsert_metadata(wid, {"argus_record_id": "ARG-1", "device_category": device_category})
    return wid


def _message(notifier):
    assert len(notifier.calls) == 1
    return notifier.calls[0][2]  # (severity, title, message)


def test_escalation_ntfy_includes_radio_and_category(db):
    mac = "AA:BB:CC:DD:EE:FF"
    db.upsert_device(mac, "ble", None, 0, NOW)
    wid = _seed_match(db, device_category="drone")
    notifier = RecordingNotifier()

    _emit_watchful_escalation(db, notifier, _entry(db, mac, matched_watchlist_id=wid), NOW)

    assert _message(notifier).endswith(" | radio: ble | category: drone")


def test_escalation_ntfy_category_placeholder_when_no_match(db):
    mac = "AA:BB:CC:DD:EE:FF"
    db.upsert_device(mac, "wifi", None, 0, NOW)
    notifier = RecordingNotifier()

    # Non-Argus watchful entry: matched_watchlist_id is None -> category absent.
    _emit_watchful_escalation(db, notifier, _entry(db, mac, matched_watchlist_id=None), NOW)

    assert _message(notifier).endswith(" | radio: wifi | category: —")


def test_escalation_ntfy_radio_placeholder_when_device_lookup_empty(db, monkeypatch):
    # alerts.mac REFERENCES devices(mac), so a successful escalation alert
    # write implies the device row exists; the only realistic way the device
    # lookup yields nothing is a None return. Verify the guard renders a radio
    # placeholder while category still resolves, and the escalation still sends.
    mac = "AA:BB:CC:DD:EE:FF"
    db.upsert_device(mac, "ble", None, 0, NOW)
    wid = _seed_match(db, device_category="drone")
    notifier = RecordingNotifier()

    monkeypatch.setattr(db, "get_device", lambda _mac: None)

    _emit_watchful_escalation(db, notifier, _entry(db, mac, matched_watchlist_id=wid), NOW)

    assert _message(notifier).endswith(" | radio: — | category: drone")


def test_escalation_sends_gracefully_when_lookup_raises(db, monkeypatch):
    mac = "AA:BB:CC:DD:EE:FF"
    db.upsert_device(mac, "ble", None, 0, NOW)
    wid = _seed_match(db, device_category="drone")
    notifier = RecordingNotifier()

    def _boom(_mac):
        raise RuntimeError("db locked")

    monkeypatch.setattr(db, "get_device", _boom)

    # Lookup raises -> placeholders, escalation still composes & sends, no error.
    _emit_watchful_escalation(db, notifier, _entry(db, mac, matched_watchlist_id=wid), NOW)

    assert _message(notifier).endswith(" | radio: — | category: —")


def test_escalation_db_alert_message_has_no_suffix(db):
    """Parity with the main alert: the stored alert message stays clean;
    the type suffix is appended to the ntfy body only."""
    mac = "AA:BB:CC:DD:EE:FF"
    db.upsert_device(mac, "ble", None, 0, NOW)
    wid = _seed_match(db, device_category="drone")
    notifier = RecordingNotifier()

    _emit_watchful_escalation(db, notifier, _entry(db, mac, matched_watchlist_id=wid), NOW)

    row = db._conn.execute(
        "SELECT message FROM alerts WHERE rule_name = 'watchful_recurrence'"
    ).fetchone()
    assert "radio:" not in row["message"]
    assert "category:" not in row["message"]
    # ntfy body, by contrast, carries the suffix
    assert "radio: ble" in _message(notifier)
