"""The three race interceptions must be VISIBLE in a default deployment.

⛔ Why this file exists. Findings 61, 62 and 63 each shipped a guard that
intercepts a real race — a duplicate "this device appears to be following you",
and an escalation the operator had just cleared. Those guards work. But two of
the three logged at **DEBUG** and the third logged **nothing**, and
``Config.log_level`` defaults to ``INFO`` — so in every default deployment a
guard could be firing constantly and no operator, and no maintainer, could ever
know.

⭐ **The count is the deliverable.** `internal/specs/SPEC_unit_of_work.md`
proposes migrating ~37 write paths onto a unit-of-work primitive to close this
class structurally. Nobody has ever measured how often the class actually
fires. These lines are that measurement, and a sustained **zero** is a real
answer — the cheapest one available.

⇒ [[an-instruments-threshold-sets-the-severity]]: a WARNING+ filter once
reported this repo "silent" for cases that logged at INFO. Capture wide, filter
at analysis.
"""

from __future__ import annotations

import logging

import pytest

from lynceus.allowlist import Allowlist
from lynceus.config import Config
from lynceus.db import Database
from lynceus.kismet import DeviceObservation
from lynceus.notify import Notifier
from lynceus.poller import (
    RACE_INTERCEPT_LOG_PREFIX,
    _deliver_watchful_escalation,
    _retry_watchful_escalation,
    process_observation,
)
from lynceus.rules import Rule, Ruleset

MAC = "ac:de:48:11:22:34"
T0 = 1_700_000_000


class Recorder(Notifier):
    def __init__(self):
        self.sent = []

    def send(self, severity, title, message, priority_override=None) -> bool:
        self.sent.append((severity, title, message))
        return True


def _intercept_records(caplog):
    """Every emitted interception line, with its level."""
    return [
        r for r in caplog.records if RACE_INTERCEPT_LOG_PREFIX in r.getMessage()
    ]


# ─────────────────────────── site 1: the escalation claim ───────────────────


def test_a_lost_escalation_claim_is_visible_at_the_default_log_level(caplog, tmp_path):
    """Finding 63's guard firing means a duplicate escalation was stopped."""

    class ClaimLost(Database):
        def record_alert_notify_attempt(self, alert_id, *, expected_attempts=None):
            return None  # the CAS missed: another writer is sending

    db = ClaimLost(str(tmp_path / "a.db"))
    notifier = Recorder()

    with caplog.at_level(logging.DEBUG):
        delivered = _deliver_watchful_escalation(
            db, notifier, alert_id=1, mac=MAC, body="b", now_ts=T0, expected_attempts=0
        )

    assert delivered is False
    assert not notifier.sent, "a lost claim must not send"
    recs = _intercept_records(caplog)
    assert recs, f"no interception line; got {[r.getMessage() for r in caplog.records]}"
    assert all(r.levelno >= logging.INFO for r in recs), (
        "the line is below the default log_level (INFO), so it is invisible in "
        f"production: {[(r.levelname, r.getMessage()) for r in recs]}"
    )


# ───────────────────────── site 3: the abandoned refusal ────────────────────


def test_a_refused_abandoned_escalation_is_visible_at_the_default_log_level(
    caplog, tmp_path
):
    """Finding 61's guard firing means a reset the operator made was honoured."""

    class Abandoned(Database):
        def get_recent_alert_for_rule_and_mac(self, rule_name, mac, since_ts):
            return {
                "id": 7,
                "notified_at": None,
                "notify_attempts": 0,
                "notify_abandoned_at": T0,
            }

    db = Abandoned(str(tmp_path / "b.db"))
    notifier = Recorder()

    class Entry:
        id = 1
        mac = MAC
        escalated_at = T0
        reset_count = 0

    with caplog.at_level(logging.DEBUG):
        _retry_watchful_escalation(db, notifier, Entry(), T0 + 100)

    assert not notifier.sent, "an abandoned escalation must not be re-sent"
    recs = _intercept_records(caplog)
    assert recs, f"no interception line; got {[r.getMessage() for r in caplog.records]}"
    assert all(r.levelno >= logging.INFO for r in recs), (
        "invisible at the default log_level: "
        f"{[(r.levelname, r.getMessage()) for r in recs]}"
    )


# ────────────────────── site 2: the ordinary dedup retry arm ────────────────


@pytest.fixture
def undelivered_alert(tmp_path):
    """A real watchlisted alert that was never delivered, attempts remaining."""
    path = str(tmp_path / "c.db")
    db = Database(path)
    db.add_watchlist(
        pattern=MAC, pattern_type="mac", severity="high", description="tracker"
    )
    db.upsert_device(
        mac=MAC, device_type="wifi", oui_vendor=None, is_randomized=0, now_ts=T0
    )
    db.add_alert(
        ts=T0,
        rule_name="watchlisted mac",
        mac=MAC,
        message="seen",
        severity="high",
        rule_type="watchlist_mac",
    )  # notified_at stays NULL: undelivered, retryable
    ruleset = Ruleset(
        rules=[Rule(name="watchlisted mac", rule_type="watchlist_mac", severity="high")]
    )
    return path, ruleset


def test_a_lost_alert_claim_is_visible_at_the_default_log_level(
    caplog, undelivered_alert
):
    """Finding 62's guard firing means one detection was not told twice."""
    path, ruleset = undelivered_alert

    class ClaimLost(Database):
        def record_alert_notify_attempt(self, alert_id, *, expected_attempts=None):
            return None

    db = ClaimLost(path)
    notifier = Recorder()
    obs = DeviceObservation(
        mac=MAC,
        device_type="wifi",
        first_seen=T0 + 60,
        last_seen=T0 + 60,
        rssi=-40,
        ssid=None,
        oui_vendor=None,
        is_randomized=False,
    )

    with caplog.at_level(logging.DEBUG):
        process_observation(
            obs,
            db,
            Config(db_path=path),
            T0 + 60,
            effective_location_id="home",
            effective_location_label="Home",
            ensured_locations=set(),
            processed_counter=[0],
            admitted_counter=[0],
            ruleset=ruleset,
            clock_trusted=True,
            allowlist=Allowlist(),
            notifier=notifier,
        )

    recs = _intercept_records(caplog)
    assert recs, f"no interception line; got {[r.getMessage() for r in caplog.records]}"
    assert all(r.levelno >= logging.INFO for r in recs), (
        "invisible at the default log_level: "
        f"{[(r.levelname, r.getMessage()) for r in recs]}"
    )


# ───────────────── the opposite direction: no false positives ───────────────


def test_the_ordinary_path_emits_no_interception_line(caplog, undelivered_alert):
    """⛔ A count is worthless if the line fires when nothing was intercepted.

    The instrument exists so `grep -c` answers "how often did this class
    actually fire". If the happy path emits it too, every number it produces is
    noise and the step-3 decision would be made on a fabricated denominator.
    """
    path, ruleset = undelivered_alert
    db = Database(path)  # real claim: it succeeds
    notifier = Recorder()
    obs = DeviceObservation(
        mac=MAC,
        device_type="wifi",
        first_seen=T0 + 60,
        last_seen=T0 + 60,
        rssi=-40,
        ssid=None,
        oui_vendor=None,
        is_randomized=False,
    )

    with caplog.at_level(logging.DEBUG):
        process_observation(
            obs,
            db,
            Config(db_path=path),
            T0 + 60,
            effective_location_id="home",
            effective_location_label="Home",
            ensured_locations=set(),
            processed_counter=[0],
            admitted_counter=[0],
            ruleset=ruleset,
            clock_trusted=True,
            allowlist=Allowlist(),
            notifier=notifier,
        )

    assert notifier.sent, "fixture check: the ordinary path must actually deliver"
    assert not _intercept_records(caplog), (
        "the interception line fired on a delivery that was NOT intercepted: "
        f"{[r.getMessage() for r in _intercept_records(caplog)]}"
    )
