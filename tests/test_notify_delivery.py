"""Notification DELIVERY, as distinct from notification formatting.

⭐ Why this file exists. `tests/test_notify.py` covers the ntfy request shape
thoroughly -- headers, priorities, tags, auth, timeouts, redaction, and the
`False` return on a transport error. What nothing covered was the composition
of "the send failed" with "the next poll runs", and that gap hid a defect on
the product's reason to exist:

    poll_once committed the alert row BEFORE attempting delivery, and the
    dedup gate keyed on that row's existence. A send that failed logged a
    warning and was never retried -- the next poll found the row it had just
    written and skipped the emit path entirely. At the default
    alert_dedup_window_seconds of 3600, ONE transient ntfy failure cost a
    full hour of alerting for that device and rule.

⛔ The reason it survived a green suite is worth stating plainly, because it
generalises: **every notifier double in this repo returned True
unconditionally.** `NullNotifier`, `RecordingNotifier` and
`_CountingNullNotifier` cannot express failure, so no integration test could
reach the failure path no matter how many were written. A test double that can
only succeed cannot test a failure path.

See docs/AUDIT_REGISTER.md, Wave 5, Finding 12.
"""

from __future__ import annotations

import pytest

from lynceus.allowlist import Allowlist
from lynceus.config import Config
from lynceus.db import Database
from lynceus.kismet import DeviceObservation
from lynceus.notify import Notifier
from lynceus.poller import NOTIFY_MAX_ATTEMPTS, process_observation
from lynceus.rules import load_ruleset

_MAC = "aa:bb:cc:dd:ee:ff"
_T0 = 1_700_000_000


class OutageNotifier(Notifier):
    """A notifier that can FAIL -- the double this suite was missing.

    ``down_until_poll`` is the last poll number that fails; delivery succeeds
    from the next one. ``attempts`` records every call, so a test can assert
    on retries actually being made rather than on their side effects.
    """

    def __init__(self, down_until_poll: int = 0, *, raise_instead: bool = False):
        self.down_until_poll = down_until_poll
        self.raise_instead = raise_instead
        self.poll = 0
        self.attempts: list[tuple[int, str]] = []
        self.delivered: list[tuple[int, str]] = []

    def send(self, severity, title, message, priority_override=None) -> bool:
        self.attempts.append((self.poll, title))
        if self.poll <= self.down_until_poll:
            if self.raise_instead:
                raise ConnectionError("ntfy unreachable")
            return False
        self.delivered.append((self.poll, title))
        return True


@pytest.fixture
def pipeline(tmp_path):
    """A correctly-configured operator: watchlist row + shipped ruleset."""
    db = Database(str(tmp_path / "d.db"))
    db.add_watchlist(
        pattern=_MAC, pattern_type="mac", severity="high", description="Flock ALPR"
    )
    config = Config(db_path=str(tmp_path / "d.db"), rules_path="config/rules.yaml")
    ruleset = load_ruleset(config.rules_path)
    yield db, config, ruleset
    db.close()


def _poll(db, config, ruleset, notifier, *, ts):
    process_observation(
        DeviceObservation(
            mac=_MAC,
            device_type="wifi",
            first_seen=ts,
            last_seen=ts,
            rssi=-40,
            ssid=None,
            oui_vendor=None,
            is_randomized=False,
        ),
        db,
        config,
        ts,
        effective_location_id="home",
        effective_location_label="Home",
        ensured_locations=set(),
        processed_counter=[0],
        admitted_counter=[0],
        ruleset=ruleset,
        allowlist=Allowlist(),
        notifier=notifier,
    )


def _high_alerts(db):
    return [a for a in db.list_alerts() if a["severity"] == "high"]


# --- the defect ----------------------------------------------------------


@pytest.mark.parametrize("raise_instead", [False, True], ids=["returns_False", "raises"])
def test_a_transient_failure_is_retried_and_eventually_delivered(pipeline, raise_instead):
    """⭐ THE regression test for Finding 12.

    ntfy is down for poll 1 only -- a mobile-data blip while walking past a
    camera, which is exactly when this deployment is most likely to lose
    connectivity. Before the fix this produced: 2 attempts, 0 delivered, and
    no further attempt for the remaining 3599 seconds of the dedup window.
    """
    db, config, ruleset = pipeline
    notifier = OutageNotifier(down_until_poll=1, raise_instead=raise_instead)
    for i in range(1, 6):
        notifier.poll = i
        _poll(db, config, ruleset, notifier, ts=_T0 + (i - 1) * 60)

    watchlist_attempts = [p for p, title in notifier.attempts if "HIGH" in title]
    watchlist_delivered = [p for p, title in notifier.delivered if "HIGH" in title]
    assert len(watchlist_attempts) >= 2, (
        f"the failed send was never retried: attempts on polls {watchlist_attempts}"
    )
    assert watchlist_delivered, "the operator was never told, despite ntfy recovering"
    assert watchlist_delivered[0] == 2, "should have been delivered on the very next poll"


def test_a_retry_reuses_the_row_and_does_not_duplicate_the_alert(pipeline):
    """A flaky server must not fill /alerts with copies of one detection."""
    db, config, ruleset = pipeline
    notifier = OutageNotifier(down_until_poll=2)
    for i in range(1, 5):
        notifier.poll = i
        _poll(db, config, ruleset, notifier, ts=_T0 + (i - 1) * 60)
    highs = _high_alerts(db)
    assert len(highs) == 1, f"expected one alert row, got {len(highs)}"
    assert highs[0]["notified_at"] is not None, "delivered row was never stamped"


def test_delivered_alerts_are_still_deduplicated(pipeline):
    """The fix must not turn dedup off. A healthy notifier sees exactly one
    send for a device that stays in range across many polls."""
    db, config, ruleset = pipeline
    notifier = OutageNotifier(down_until_poll=0)  # never fails
    for i in range(1, 11):
        notifier.poll = i
        _poll(db, config, ruleset, notifier, ts=_T0 + (i - 1) * 60)
    highs = [t for _, t in notifier.attempts if "HIGH" in t]
    assert len(highs) == 1, f"dedup broken: {len(highs)} sends for one in-range device"
    assert len(_high_alerts(db)) == 1


def test_retries_are_bounded(pipeline):
    """An unbounded retry costs a blocking HTTP timeout on every poll. When
    the attempts are spent the row stays UNDELIVERED rather than being
    silently forgotten -- /settings still has to be able to report it."""
    db, config, ruleset = pipeline
    notifier = OutageNotifier(down_until_poll=99)  # never recovers
    for i in range(1, 12):
        notifier.poll = i
        _poll(db, config, ruleset, notifier, ts=_T0 + (i - 1) * 60)
    highs = [t for _, t in notifier.attempts if "HIGH" in t]
    assert len(highs) == NOTIFY_MAX_ATTEMPTS, (
        f"expected {NOTIFY_MAX_ATTEMPTS} bounded attempts, got {len(highs)}"
    )
    row = _high_alerts(db)[0]
    assert row["notified_at"] is None, "a never-delivered alert must not look delivered"
    assert db.count_undelivered_alerts() >= 1


def test_bookkeeping_failure_does_not_cost_the_notification(pipeline, monkeypatch):
    """⛔ `process_observation` runs inside a per-observation try/except in
    `poll_once`, so an unguarded raise from the delivery bookkeeping would
    abandon the whole observation -- no notification for this hit, and none
    for any remaining hit on the same device.

    Losing the attempt counter costs at worst one extra retry later. Losing
    the send means the operator is never told, which is the exact failure
    Finding 12 exists to close. The trade is not close, so the bookkeeping is
    the part allowed to fail.
    """
    db, config, ruleset = pipeline
    notifier = OutageNotifier(down_until_poll=0)  # a healthy notifier

    def boom(*a, **kw):
        raise RuntimeError("database is locked")

    monkeypatch.setattr(db, "record_alert_notify_attempt", boom)
    notifier.poll = 1
    _poll(db, config, ruleset, notifier, ts=_T0)

    assert notifier.delivered, (
        "a failure writing the attempt counter suppressed the notification entirely"
    )
    assert any("HIGH" in title for _, title in notifier.delivered)


def test_stamp_failure_still_delivers_and_does_not_abort(pipeline, monkeypatch):
    """The mirror case: delivery succeeded but stamping it failed. The send
    already happened, so the worst outcome is one duplicate on a later poll --
    strictly better than abandoning the observation."""
    db, config, ruleset = pipeline
    notifier = OutageNotifier(down_until_poll=0)

    def boom(*a, **kw):
        raise RuntimeError("database is locked")

    monkeypatch.setattr(db, "mark_alert_notified", boom)
    notifier.poll = 1
    _poll(db, config, ruleset, notifier, ts=_T0)

    assert notifier.delivered, "the notification itself must still go out"
    # The row is unstamped, so it stays retryable rather than being lost.
    assert db.count_undelivered_alerts() >= 1


def test_settings_reports_undelivered_alerts(tmp_path):
    """⭐ Silence must be falsifiable.

    ntfy reachability is a LIVENESS probe: it says the broker answered just
    now, not that anything ever arrived. A wrong topic or a stale auth token
    passes reachability and drops every notification, and the operator's only
    symptom is silence -- which for this product is indistinguishable from
    "nothing is out there". This card is the difference between those two.
    """
    from fastapi.testclient import TestClient

    from lynceus.webui.app import create_app

    db = Database(str(tmp_path / "s.db"))
    for i in range(3):
        mac = f"aa:bb:cc:dd:ee:0{i}"
        db.upsert_device(mac, "wifi", "Acme", 0, _T0)
        db.add_alert(
            ts=_T0 + i, rule_name="r", mac=mac, message="m",
            severity="high", rule_type="watchlist_mac",
        )
    # One DELIVERED alert, so a naive "count all alerts" implementation fails.
    db.upsert_device("ff:ff:ff:ff:ff:ff", "wifi", "Acme", 0, _T0)
    delivered = db.add_alert(
        ts=_T0 + 900, rule_name="r", mac="ff:ff:ff:ff:ff:ff", message="m",
        severity="low", rule_type="watchlist_mac",
    )
    db.mark_alert_notified(delivered, now_ts=_T0 + 900)

    assert len(db.list_alerts()) == 4
    assert db.count_undelivered_alerts() == 3, "delivered alerts must not be counted"

    config = Config(
        db_path=str(tmp_path / "s.db"),
        ntfy_url="https://ntfy.sh",
        ntfy_topic="lynceus-x-9f2a1b",
    )
    app = create_app(config, db)
    with TestClient(app) as client:
        body = client.get("/settings").text
    assert "undelivered" in body
    assert "badge-status-error" in body, "3 undelivered alerts rendered without a warning"
    db.close()


def test_the_alert_row_survives_a_failed_notification(pipeline):
    """Delivery failure must not lose the detection. The row is the operator's
    fallback: they can still find it on /alerts even if the push never
    arrived."""
    db, config, ruleset = pipeline
    notifier = OutageNotifier(down_until_poll=99)
    notifier.poll = 1
    _poll(db, config, ruleset, notifier, ts=_T0)
    assert len(_high_alerts(db)) == 1
    assert db.count_undelivered_alerts(since_ts=_T0 - 1) == len(
        [a for a in db.list_alerts() if a["notified_at"] is None]
    )
