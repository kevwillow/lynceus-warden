"""The escalation alert must not be lost by one failed send.

`_emit_watchful_escalation` wrote its alert row and then called `notifier.send`
fire-and-forget — the shape PR #19 removed from the main alert path and that the
heartbeat was deliberately built to avoid. The escalation kept it, in the worst
possible place.

Measured before this fix, with ntfy down at the moment the threshold was
crossed, across eight further days of the device continuing to follow:

    alert row : notified_at=None, notify_attempts=0
    notifier  : called ONCE, never again
    heartbeat : "1 alert written but never delivered", permanently

⚠️ `escalate_watchful_recurrence` is idempotent by design, so nothing re-drove
it. One transient blip permanently lost the single most important message this
product sends.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lynceus.config import Config  # noqa: E402
from lynceus.db import Database  # noqa: E402
from lynceus.kismet import DeviceObservation  # noqa: E402
from lynceus.poller import (  # noqa: E402
    NOTIFY_MAX_ATTEMPTS,
    process_observation,
)

NOW = 1_700_000_000
DAY = 86_400
MAC = "aa:bb:cc:dd:ee:01"


class _NoAllowlist:
    def is_allowed(self, obs, *, now_ts=None):
        return None


class _NoRules:
    rules = ()

    def evaluate(self, *a, **k):
        return []


class _Notifier:
    """Matches the real `Notifier.send` keyword signature.

    ⚠️ A fake with the wrong signature raises TypeError, which the production
    code catches and logs — so the test sees "no notification" and reads as a
    product bug. That cost a real detour; keep these parameter names.
    """

    def __init__(self, *, up: bool = True):
        self.up = up
        self.sent_at: list[int] = []
        self.now = 0

    def send(self, severity=None, title=None, message=None, priority_override=None):
        self.sent_at.append(self.now)
        return self.up


@pytest.fixture()
def rig(tmp_path):
    db = Database(str(tmp_path / "w.db"))
    db.ensure_location("home", "Home")
    cfg = Config(db_path=str(tmp_path / "w.db"), rules_path="config/rules.yaml")
    db.upsert_device(
        mac=MAC, device_type="wifi", oui_vendor=None, is_randomized=0, now_ts=NOW
    )
    db.insert_sighting(mac=MAC, ts=NOW, rssi=-40, ssid=None, location_id="home")
    alert_id = db.add_alert(
        ts=NOW, rule_name="r", mac=MAC, message="m", severity="high"
    )
    db.mark_alert_notified(alert_id, now_ts=NOW)
    db.create_watchful_from_alert(alert_id, None, NOW)
    yield db, cfg
    db.close()


def _see(db, cfg, notifier, ts):
    notifier.now = ts
    process_observation(
        DeviceObservation(
            mac=MAC,
            device_type="wifi",
            first_seen=ts,
            last_seen=ts,
            rssi=-40,
            ssid=None,
            oui_vendor=None,
            is_randomized=False,
        ),
        db,
        cfg,
        ts,
        effective_location_id="home",
        effective_location_label="Home",
        ensured_locations={"home"},
        processed_counter=[0],
        admitted_counter=[0],
        ruleset=_NoRules(),
        allowlist=_NoAllowlist(),
        notifier=notifier,
        clock_trusted=True,
    )


def _escalate(db, cfg, notifier):
    """Drive the entry to its threshold crossing."""
    for day in (1, 2, 3):
        _see(db, cfg, notifier, NOW + day * DAY)
    return NOW + 3 * DAY


def _escalation_row(db):
    row = db._conn.execute(
        "SELECT id, ts, notified_at, notify_attempts FROM alerts "
        "WHERE rule_name = 'watchful_recurrence'"
    ).fetchone()
    return dict(row) if row else None


def test_a_failed_escalation_is_retried(rig):
    """The core fix. Before it, the notifier was called once and never again."""
    db, cfg = rig
    n = _Notifier(up=False)
    t0 = _escalate(db, cfg, n)
    assert _escalation_row(db) is not None, "precondition: the entry escalated"
    assert len(n.sent_at) == 1

    # The device is still there. Beyond the backoff, so a retry is due.
    _see(db, cfg, n, t0 + 600)
    assert len(n.sent_at) == 2, (
        "the escalation was never retried; one blip loses it permanently"
    )


def test_a_retried_escalation_lands_when_ntfy_recovers(rig):
    """⭐ The point of the whole thing: the operator eventually gets told."""
    db, cfg = rig
    n = _Notifier(up=False)
    t0 = _escalate(db, cfg, n)
    n.up = True
    _see(db, cfg, n, t0 + 600)

    row = _escalation_row(db)
    assert row["notified_at"] is not None, "delivery was never recorded"
    assert db.count_undelivered_alerts() == 0


def test_a_delivered_escalation_is_never_re_sent(rig):
    """⚠️ The over-fire case. Retrying forever would spam the operator with
    'you are being followed' — which destroys trust in the alert faster than
    losing it does."""
    db, cfg = rig
    n = _Notifier(up=True)
    t0 = _escalate(db, cfg, n)
    assert len(n.sent_at) == 1

    for i in range(1, 40):
        _see(db, cfg, n, t0 + i * 3600)
    assert len(n.sent_at) == 1, (
        f"escalation re-sent {len(n.sent_at)} times after being delivered"
    )


def test_retries_are_bounded(rig):
    """Unbounded retry against a permanently dead topic is its own failure."""
    db, cfg = rig
    n = _Notifier(up=False)
    t0 = _escalate(db, cfg, n)
    for i in range(1, 200):
        _see(db, cfg, n, t0 + i * 300)
    assert len(n.sent_at) == NOTIFY_MAX_ATTEMPTS, (
        f"{len(n.sent_at)} attempts; expected {NOTIFY_MAX_ATTEMPTS}"
    )
    assert _escalation_row(db)["notify_attempts"] == NOTIFY_MAX_ATTEMPTS


def test_the_attempts_are_spaced_out(rig):
    """⭐ The retry driver is 'we saw the device again', which on a 5-minute
    poll fires every 5 minutes. Unspaced, all four attempts burn inside twenty
    minutes — against a phone out of signal, which is likeliest exactly while
    the operator is moving. Four attempts covering one outage is a coin flip.
    """
    db, cfg = rig
    n = _Notifier(up=False)
    t0 = _escalate(db, cfg, n)
    for i in range(1, 200):
        _see(db, cfg, n, t0 + i * 300)

    offsets = [round((t - t0) / 60) for t in n.sent_at]
    assert offsets == [0, 5, 15, 45], f"attempt spacing changed: {offsets} minutes"
    assert offsets[-1] >= 40, "the four attempts no longer span a useful window"


def test_a_rule_type_snooze_suppresses_the_retry(rig):
    """A retry is still a notification. If the operator silenced
    `watchful_recurrence`, retrying past that is ignoring them."""
    db, cfg = rig
    n = _Notifier(up=False)
    t0 = _escalate(db, cfg, n)
    before = len(n.sent_at)

    db.add_rule_type_snooze(
        "watchful_recurrence", expires_at=t0 + 7 * DAY, added_at=t0
    )
    for i in range(1, 40):
        _see(db, cfg, n, t0 + i * 300)
    assert len(n.sent_at) == before, "a snoozed rule_type was still notified"


def test_the_happy_path_still_fires_exactly_once(rig):
    """⚠️ The 'good thing must still happen' twin: none of the above may come
    at the cost of the escalation itself."""
    db, cfg = rig
    n = _Notifier(up=True)
    _escalate(db, cfg, n)
    assert len(n.sent_at) == 1
    row = _escalation_row(db)
    assert row["notified_at"] is not None
    assert row["notify_attempts"] == 1


def test_a_suppressed_escalation_is_counted_in_the_audit_summary(rig):
    """The hourly suppression summary is what an operator greps to see what
    their snoozes are actually catching. The ordinary rule_type-snooze branch
    counted; the escalation branch only logged.

    ⭐ So the one suppression the summary most needed to report — a
    "this device keeps following you" escalation that the operator's own snooze
    silenced — was the one it omitted. Measured before the fix: escalation
    reached and suppressed, summary reports `{}`.
    """
    db, cfg = rig
    n = _Notifier(up=True)
    db.add_rule_type_snooze(
        "watchful_recurrence", expires_at=NOW + 30 * DAY, added_at=NOW
    )
    counter: dict[str, int] = {}

    for day in (1, 2, 3):
        ts = NOW + day * DAY
        n.now = ts
        process_observation(
            DeviceObservation(
                mac=MAC,
                device_type="wifi",
                first_seen=ts,
                last_seen=ts,
                rssi=-40,
                ssid=None,
                oui_vendor=None,
                is_randomized=False,
            ),
            db,
            cfg,
            ts,
            effective_location_id="home",
            effective_location_label="Home",
            ensured_locations={"home"},
            processed_counter=[0],
            admitted_counter=[0],
            ruleset=_NoRules(),
            allowlist=_NoAllowlist(),
            notifier=n,
            clock_trusted=True,
            rule_type_suppression_counter=counter,
        )

    row = db._conn.execute(
        "SELECT escalated_at FROM watchful_recurrence"
    ).fetchone()
    assert row["escalated_at"] is not None, "precondition: the entry escalated"
    assert not n.sent_at, "precondition: the snooze suppressed the notification"
    assert counter.get("watchful_recurrence") == 1, (
        f"the audit summary omits the suppressed escalation: {counter}"
    )
