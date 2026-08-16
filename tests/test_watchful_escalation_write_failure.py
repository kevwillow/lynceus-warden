"""The escalation ALERT WRITE, as distinct from its delivery.

⭐ Why this file exists. #74 hardened the SEND: a watchful escalation that was
written but not delivered is now retried, because losing it means the operator
is never told that someone appears to be following them. Nothing covered the
layer above — the ``db.add_alert`` that CREATES the row the retry path looks
for.

``escalated_at`` used to be stamped BEFORE that write was attempted, with
``escalate_watchful_recurrence``'s idempotency standing in for a first-crossing
guard. So a write that raised left the entry marked escalated with no alert
row, and ``_retry_watchful_escalation`` returns early when it cannot find the
row. Nothing re-drove it. Measured on a FOREVER watchful snooze — where the
escalation is the only signal that can arrive — across eight further days of
daily sightings:

    healthy DB            esc rows 1  delivered 1  heartbeat: healthy
    DELIVERY fails (#74)  esc rows 1  delivered 0  heartbeat: UNHEALTHY
    the WRITE fails       esc rows 0  delivered 0  heartbeat: healthy

⛔ The third row is the defect, and the heartbeat column is why it is worse
than the one #74 fixed: it is byte-identical to a healthy install on the
operator's only health channel. ``count_undelivered_alerts`` counts ROWS, and
there is no row to count.

⚠️ ``sqlite3.OperationalError: database is locked`` is reachable here: the web
UI is a separate process writing this same file. It is the condition the main
alert path's own measurement used.

Both directions fail:

  * the stamp moving back before the write  -> test_a_failed_escalation_write_...
  * recovery not actually happening         -> test_the_escalation_is_recovered_...
  * an over-correction that re-emits        -> test_a_delivered_escalation_fires_once
  * losing the snooze/failure distinction   -> test_a_snoozed_escalation_is_consumed_...
"""

from __future__ import annotations

import pytest

from lynceus.allowlist import Allowlist
from lynceus.config import Config
from lynceus.db import Database
from lynceus.kismet import DeviceObservation
from lynceus.notify import Notifier
from lynceus.poller import process_observation
from lynceus.rules import Rule, Ruleset

MAC = "ac:de:48:11:22:33"  # universally-administered; a locally-administered OUI
                           # is dropped by the reserved-OUI guard and reads
                           # exactly like an entry that never matched.
T0 = 1_700_000_000
DAY = 86400


class RecordingNotifier(Notifier):
    def __init__(self, deliver: bool = True):
        self.sent: list[str] = []
        self.deliver = deliver

    def send(self, severity, title, message, priority_override=None) -> bool:
        self.sent.append(title)
        return self.deliver


class _LockedOnEscalationWrite:
    """Proxy whose ``add_alert`` raises for the escalation write only.

    ``fail_first_n=None`` fails forever; an int fails that many times and then
    lets the write through, which is the transient-blip case.
    """

    def __init__(self, db, fail_first_n: int | None = None):
        self._db = db
        self._fail_first_n = fail_first_n
        self.blocked = 0

    def add_alert(self, **kw):
        if kw.get("rule_type") == "watchful_recurrence" and (
            self._fail_first_n is None or self.blocked < self._fail_first_n
        ):
            self.blocked += 1
            raise RuntimeError("database is locked")
        return self._db.add_alert(**kw)

    def __getattr__(self, name):
        return getattr(self._db, name)


def _obs(ts: int) -> DeviceObservation:
    return DeviceObservation(
        mac=MAC, device_type="wifi", first_seen=ts, last_seen=ts, rssi=-40,
        ssid=None, oui_vendor=None, is_randomized=False,
    )


@pytest.fixture
def watched(tmp_path):
    """An operator who watchlisted this device HIGH, then chose to watch it
    with a FOREVER snooze — so the escalation is the only signal left."""
    path = str(tmp_path / "w.db")
    db = Database(path)
    db.add_watchlist(pattern=MAC, pattern_type="mac", severity="high",
                     description="suspected tracker")
    db.upsert_device(mac=MAC, device_type="wifi", oui_vendor=None,
                     is_randomized=0, now_ts=T0)
    src = db.add_alert(ts=T0, rule_name="watchlisted mac", mac=MAC,
                       message="seen", severity="high", rule_type="watchlist_mac")
    db.mark_alert_notified(src, now_ts=T0)
    entry_id = db.create_watchful_from_alert(src, None, T0)
    assert entry_id is not None, "fixture failed: no watchful entry created"
    assert db.get_watchful_recurrence(entry_id).snooze_expires_at is None, (
        "fixture failed: the snooze must be 'forever' or the main alert path "
        "still fires and this file measures the wrong thing"
    )
    ruleset = Ruleset(rules=[
        Rule(name="watchlisted mac", rule_type="watchlist_mac", severity="high")
    ])
    yield db, Config(db_path=path), ruleset, entry_id
    db.close()


def _observe_at(db, config, ruleset, notifier, ts):
    """One observation at an EXACT timestamp."""
    process_observation(
        _obs(ts), db, config, ts,
        effective_location_id="home", effective_location_label="Home",
        ensured_locations=set(), processed_counter=[0], admitted_counter=[0],
        ruleset=ruleset, clock_trusted=True, allowlist=Allowlist(),
        notifier=notifier,
    )


def _sightings(db, config, ruleset, notifier, *, days, start_day=1):
    """One sighting per day. ``start_day`` exists because a second call that
    silently restarted at day 1 would feed timestamps BACKWARD -- which reads
    like "and then time passed" and is not."""
    for d in range(start_day, start_day + days):
        _observe_at(db, config, ruleset, notifier, T0 + d * DAY)
    return start_day + days  # the next unused day


def _escalation_rows(db):
    return db._conn.execute(
        "SELECT id, notified_at FROM alerts WHERE rule_type='watchful_recurrence'"
    ).fetchall()


def test_the_threshold_is_actually_crossed_in_this_fixture(watched):
    """The CONTROL. Without it, every assertion below could pass because the
    escalation never happened at all rather than because the code is right."""
    db, config, ruleset, entry_id = watched
    notifier = RecordingNotifier()
    _sightings(db, config, ruleset, notifier, days=8)
    entry = db.get_watchful_recurrence(entry_id)
    assert entry.sighting_count >= Database.WATCHFUL_RECURRENCE_ESCALATION_THRESHOLD
    assert entry.escalated_at is not None, "control: the entry never escalated"
    assert len(_escalation_rows(db)) == 1, "control: no escalation alert written"
    assert notifier.sent, "control: nothing was ever sent"


def test_a_failed_escalation_write_leaves_the_entry_unescalated(watched):
    """The defect. A write that raises must NOT leave the entry stamped
    escalated — that state is what makes the loss permanent, because
    `escalate_watchful_recurrence` fires once and the retry path needs a row."""
    db, config, ruleset, entry_id = watched
    proxy = _LockedOnEscalationWrite(db, fail_first_n=None)  # locked forever
    notifier = RecordingNotifier()
    _sightings(proxy, config, ruleset, notifier, days=8)

    assert proxy.blocked >= 1, "the plant never fired: no escalation write attempted"
    entry = db.get_watchful_recurrence(entry_id)
    # ABSENCE: no row was written.
    assert _escalation_rows(db) == [], "an escalation row exists despite a locked DB"
    # PRESENCE beside it: the entry is still eligible to escalate, which is the
    # whole point — an unescalated entry is one the next sighting retries.
    assert entry.escalated_at is None, (
        "entry was stamped escalated with no alert row: nothing will ever "
        "re-drive this escalation"
    )
    assert entry.sighting_count >= Database.WATCHFUL_RECURRENCE_ESCALATION_THRESHOLD
    # And it must keep TRYING while the device is still being seen.
    assert proxy.blocked > 1, (
        f"the write was attempted only {proxy.blocked}x across 8 days of "
        "sightings; a single attempt is the give-up behaviour this fixes"
    )


def test_the_escalation_is_recovered_after_a_transient_failure(watched):
    """The fix, measured end to end: one blip, then the operator IS told."""
    db, config, ruleset, entry_id = watched
    proxy = _LockedOnEscalationWrite(db, fail_first_n=1)  # one transient blip
    notifier = RecordingNotifier()
    _sightings(proxy, config, ruleset, notifier, days=8)

    assert proxy.blocked == 1, "the plant did not fire exactly once"
    rows = _escalation_rows(db)
    assert len(rows) == 1, f"expected exactly one recovered escalation, got {len(rows)}"
    assert rows[0]["notified_at"] is not None, "recovered row was never delivered"
    assert db.get_watchful_recurrence(entry_id).escalated_at is not None
    assert notifier.sent, "the operator was never told"


def test_recovery_happens_on_the_NEXT_POLL_not_the_next_counted_day(watched):
    """The `outcome.counted` drop, pinned.

    ⛔ A cold cross-model read caught this: every other test here drives
    sightings a DAY apart, so all of them pass with `outcome.counted` restored
    — the next day's sighting is counted and recovers anyway. They prove
    recovery happens; none of them proves it happens PROMPTLY.

    Counting is debounced to once per 24h. If the escalation condition requires
    a counted sighting, a failed write cannot be retried until the next counted
    one, i.e. up to a day later, while the device is in front of the sensor
    every poll. This drives the retry at +5 MINUTES — an under-debounce
    observation — which is the interval that actually matters."""
    db, config, ruleset, entry_id = watched
    proxy = _LockedOnEscalationWrite(db, fail_first_n=1)
    notifier = RecordingNotifier()
    next_day = _sightings(proxy, config, ruleset, notifier, days=3)

    # The threshold was reached and the one write attempt was consumed.
    assert proxy.blocked == 1, "the plant did not fire exactly once"
    assert _escalation_rows(db) == [], "precondition: no row should exist yet"
    entry = db.get_watchful_recurrence(entry_id)
    assert entry.escalated_at is None, "precondition: entry must be unescalated"
    assert entry.sighting_count >= Database.WATCHFUL_RECURRENCE_ESCALATION_THRESHOLD

    # Five minutes later: an ordinary poll, far inside the 24h debounce.
    ts = T0 + (next_day - 1) * DAY + 300
    _observe_at(proxy, config, ruleset, notifier, ts)

    rows = _escalation_rows(db)
    assert len(rows) == 1, (
        "the escalation was NOT recovered on the next poll; it is waiting for "
        "the next COUNTED sighting, up to 24h away, while the device is being "
        "seen every five minutes"
    )
    assert rows[0]["notified_at"] is not None, "recovered row was never delivered"
    assert db.get_watchful_recurrence(entry_id).escalated_at is not None


def test_a_stamp_that_fails_after_the_row_lands_costs_at_most_one_duplicate(watched):
    """The other side of the window, from the cold read — and the residual is
    REAL, so this pins the bound rather than claiming there is no window.

    The row write and the `escalated_at` stamp are two transactions. A failure
    between them leaves a row with no stamp, and the next sighting takes the
    first-crossing branch again. That costs ONE duplicate escalation (Finding
    44: closing it needs a generation-keyed escalation record, i.e. a
    migration).

    ⛔ What must NOT happen, and is what this actually guards: the failure
    escaping `process_observation` and abandoning the rest of the tick, the
    operator not being told at all, or the duplication being UNBOUNDED — one
    extra warning is tolerable, a new "this device is following you" every poll
    for a week trains the operator to ignore the alert that matters."""
    db, config, ruleset, entry_id = watched

    class _StampFailsOnce:
        def __init__(self, inner):
            self._db = inner
            self.blocked = 0

        def escalate_watchful_recurrence(self, entry_id_, ts):
            if self.blocked == 0:
                self.blocked += 1
                raise RuntimeError("database is locked")
            return self._db.escalate_watchful_recurrence(entry_id_, ts)

        def __getattr__(self, name):
            return getattr(self._db, name)

    proxy = _StampFailsOnce(db)
    notifier = RecordingNotifier()
    next_day = _sightings(proxy, config, ruleset, notifier, days=3)
    assert proxy.blocked == 1, "the plant never fired: no stamp was attempted"
    # The row landed even though the stamp did not.
    assert len(_escalation_rows(db)) == 1, "precondition: the row should exist"

    # Six more days of sightings: the duplication must not keep growing.
    _sightings(proxy, config, ruleset, notifier, days=6, start_day=next_day)
    rows = _escalation_rows(db)
    assert len(rows) <= 2, (
        f"a failed STAMP produced {len(rows)} escalation rows across 9 days of "
        "sightings; the window costs at most ONE duplicate, so this is "
        "re-emitting on every sighting"
    )
    assert any(r["notified_at"] is not None for r in rows), (
        "the operator was never told, which is the failure this must not have"
    )
    assert db.get_watchful_recurrence(entry_id).escalated_at is not None, (
        "the entry never recovered its escalated stamp, so it stays eligible "
        "to re-emit forever"
    )


def test_a_delivered_escalation_fires_exactly_once(watched):
    """The OVER-CORRECTION. Retrying the write must not become 'emit a new
    escalation on every sighting' — that fills /alerts with duplicates of one
    detection and trains the operator to ignore the highest-severity thing
    this product sends."""
    db, config, ruleset, entry_id = watched
    notifier = RecordingNotifier()
    _sightings(db, config, ruleset, notifier, days=20)
    assert len(_escalation_rows(db)) == 1, "escalation emitted more than once"
    assert len(notifier.sent) == 1, f"sent {len(notifier.sent)} times, expected 1"


def test_a_snoozed_escalation_is_consumed_and_never_resurrected(watched):
    """The distinction the fix depends on, and the reason the snooze branch
    still stamps `escalated_at`.

    ⛔ 'escalated_at set, no alert row' must mean exactly one thing. A snoozed
    escalation deliberately writes no row (detection runs, notification does
    not). If the snooze branch did not stamp, that state would be
    indistinguishable from a failed write — and the recovery would resurrect
    the alert the operator deliberately silenced, the moment the snooze
    expired."""
    db, config, ruleset, entry_id = watched
    db.add_rule_type_snooze("watchful_recurrence", expires_at=T0 + 5 * DAY,
                            added_at=T0)
    assert db.is_rule_type_snoozed("watchful_recurrence", T0 + DAY) is not None, (
        "fixture failed: the snooze the gate reads is not active"
    )
    notifier = RecordingNotifier()
    # crossing happens while snoozed
    next_day = _sightings(db, config, ruleset, notifier, days=3)

    entry = db.get_watchful_recurrence(entry_id)
    assert entry.escalated_at is not None, (
        "a snoozed escalation must still be CONSUMED, or it is indistinguishable "
        "from a failed write and gets resurrected when the snooze expires"
    )
    assert _escalation_rows(db) == [], "snooze did not suppress the emit"

    # Keep going FORWARD, well past the snooze's expiry: it must stay silenced.
    end_day = _sightings(db, config, ruleset, notifier, days=20, start_day=next_day)
    assert db.is_rule_type_snoozed("watchful_recurrence", T0 + end_day * DAY) is None, (
        "fixture failed: the snooze never expired during the run, so 'still "
        "silenced' below would pass for the wrong reason"
    )
    assert _escalation_rows(db) == [], (
        "the escalation the operator snoozed was resurrected after expiry"
    )
    assert notifier.sent == [], "a suppressed escalation was delivered later"
