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
from lynceus.poller import _emit_watchful_escalation, process_observation
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
    """Proxy whose escalation alert write raises.

    ``fail_first_n=None`` fails forever; an int fails that many times and then
    lets the write through, which is the transient-blip case.

    ⛔ The seam is ``add_watchful_escalation_alert``, not ``add_alert``. It
    moved when migration 026 made the alert row and its generation reservation
    one transaction (Finding 44), and this proxy silently stopped firing --
    every test here still passed its interesting assertions because the
    escalation simply succeeded. What caught it was ``assert proxy.blocked``,
    which every test in this file makes before asserting anything else.
    ⇒ **A plant that stops firing must be an ERROR, not a pass.** Do not remove
    those assertions to "simplify" a test; they are the only thing standing
    between a renamed seam and a file of tests that measure nothing.
    """

    def __init__(self, db, fail_first_n: int | None = None):
        self._db = db
        self._fail_first_n = fail_first_n
        self.blocked = 0

    def add_watchful_escalation_alert(self, entry_id, generation, **kw):
        if self._fail_first_n is None or self.blocked < self._fail_first_n:
            self.blocked += 1
            raise RuntimeError("database is locked")
        return self._db.add_watchful_escalation_alert(
            entry_id, generation, **kw
        )

    def __getattr__(self, name):
        return getattr(self._db, name)


class _StampFailsOnceProxy:
    """Proxy whose FIRST ``escalate_watchful_recurrence`` raises.

    This is the Finding 44 window: the alert row lands, the stamp does not.
    Module-level because three tests need it; the earlier inline copy inside
    ``test_a_stamp_that_fails_after_the_row_lands_costs_no_duplicate`` is left
    where it is so that test stays readable on its own.
    """

    def __init__(self, db):
        self._db = db
        self.blocked = 0

    def escalate_watchful_recurrence(self, entry_id_, ts, **kw):
        # ⚠️ `**kw` is load-bearing: the stamp gained an `expected_reset_count`
        # compare-and-swap, and a proxy with the old signature raises
        # TypeError, which the caller's `except Exception` swallows as "the
        # stamp failed". The plant then appears to fire while measuring
        # nothing.
        if self.blocked == 0:
            self.blocked += 1
            raise RuntimeError("database is locked")
        return self._db.escalate_watchful_recurrence(entry_id_, ts, **kw)

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
        "SELECT id, ts, notified_at FROM alerts "
        "WHERE rule_type='watchful_recurrence' ORDER BY id"
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


def test_a_stamp_that_fails_after_the_row_lands_costs_no_duplicate(watched):
    """FINDING 44, first half of the acceptance criterion: an escalation is
    emitted at most once per entry generation, proven with a failure injected
    between the row write and the stamp.

    ⭐ This test used to be called `..._costs_at_most_one_duplicate` and
    asserted `len(rows) <= 2`, because that WAS the behaviour: the row write
    and the stamp are two transactions, so a failure between them left a row
    with no stamp and the next sighting re-took the first-crossing branch.
    Migration 026 makes the row write reserve `(entry_id, reset_count)` in the
    same transaction, so the re-take now finds the reservation and recovers the
    stamp instead of emitting again. The bound is exactly 1, not "at most 2".

    ⛔ The three things that must NOT happen are unchanged: the failure escaping
    `process_observation` and abandoning the rest of the tick, the operator not
    being told at all, or the duplication being unbounded. `== 1` covers the
    last two and is checked below alongside the first.

    ⚠️ The conjunction's SECOND half — that a reset entry still escalates — is
    `test_a_reset_entry_escalates_again_after_a_recovered_stamp`. Without it
    this test passes trivially for a dedup that never escalates anything."""
    db, config, ruleset, entry_id = watched

    class _StampFailsOnce:
        def __init__(self, inner):
            self._db = inner
            self.blocked = 0

        def escalate_watchful_recurrence(self, entry_id_, ts, **kw):
            if self.blocked == 0:
                self.blocked += 1
                raise RuntimeError("database is locked")
            return self._db.escalate_watchful_recurrence(entry_id_, ts, **kw)

        def __getattr__(self, name):
            return getattr(self._db, name)

    proxy = _StampFailsOnce(db)
    notifier = RecordingNotifier()
    next_day = _sightings(proxy, config, ruleset, notifier, days=3)
    assert proxy.blocked == 1, "the plant never fired: no stamp was attempted"
    # The row landed even though the stamp did not.
    assert len(_escalation_rows(db)) == 1, "precondition: the row should exist"

    # Six more days of sightings: no duplicate at all, and no growth.
    _sightings(proxy, config, ruleset, notifier, days=6, start_day=next_day)
    rows = _escalation_rows(db)
    assert len(rows) == 1, (
        f"a failed STAMP produced {len(rows)} escalation rows across 9 days of "
        "sightings; the generation ledger (migration 026) must make this "
        "exactly 1 -- 2 is the pre-fix behaviour, more is re-emitting on "
        "every sighting"
    )
    assert any(r["notified_at"] is not None for r in rows), (
        "the operator was never told, which is the failure this must not have"
    )
    # ⛔ Row count alone is not the claim. An implementation that re-SENT the
    # existing row on every recovery would satisfy every assertion above while
    # the operator's phone buzzed once per sighting for a week.
    assert len(notifier.sent) == 1, (
        f"the operator was told {len(notifier.sent)} times about one detection"
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


# ---------------------------------------------------------------------------
# Finding 44 — the generation-keyed escalation ledger (migration 026).
#
# The acceptance criterion is a CONJUNCTION and both halves live here:
#   1. at most one escalation per entry generation, proven with a failure
#      injected between the row write and the stamp
#        -> test_a_stamp_that_fails_after_the_row_lands_costs_no_duplicate
#   2. a RESET entry still escalates afterwards
#        -> test_a_reset_entry_escalates_again_after_a_recovered_stamp
#
# ⛔ The second half is not optional and it is not decoration. The obvious
# dedup — "skip the write if an escalation alert row already exists for this
# MAC" — passes half 1 perfectly and silences a device the operator
# deliberately restarted watching. Suppression is the direction that hides a
# follower, so a fix that only satisfies half 1 is worse than the defect.
# ---------------------------------------------------------------------------


def _ledger_rows(db):
    return db._conn.execute(
        "SELECT entry_id, generation, alert_id FROM watchful_escalations "
        "ORDER BY generation"
    ).fetchall()


def _cross_threshold(db, config, ruleset, notifier, entry_id, *, start_day):
    """Drive counted sightings until the entry is over the escalation
    threshold, and return the next unused day.

    ⚠️ The number of sightings is DERIVED from the threshold constant, not
    transcribed. A hardcoded 3 would keep passing if the threshold moved and
    would then be measuring an entry that never crossed.
    """
    needed = Database.WATCHFUL_RECURRENCE_ESCALATION_THRESHOLD - (
        db.get_watchful_recurrence(entry_id).sighting_count
    )
    assert needed > 0, (
        "the entry is already at or over the threshold, so this helper would "
        "drive zero sightings and prove nothing"
    )
    return _sightings(
        db, config, ruleset, notifier, days=needed, start_day=start_day
    )


def test_a_reset_entry_escalates_again_after_a_recovered_stamp(watched):
    """FINDING 44, second half of the acceptance criterion — and the half that
    a naive dedup breaks.

    The hardest ordering deliberately: the first escalation goes through the
    RECOVERY path (its stamp fails, the next sighting recovers it without
    emitting), so generation 0 is reserved AND the entry carries a
    reset-eligible `escalated_at`. The operator then resets, which is them
    saying "I have seen this, start the count again". The device keeps
    following them, the threshold is crossed a second time, and the escalation
    MUST arrive.

    ⛔ If this ever fails, the dedup has started keying on something that does
    not move when the operator resets, and a device the operator chose to keep
    watching can never escalate again."""
    db, config, ruleset, entry_id = watched
    proxy = _StampFailsOnceProxy(db)
    notifier = RecordingNotifier()

    next_day = _cross_threshold(
        proxy, config, ruleset, notifier, entry_id, start_day=1
    )
    assert proxy.blocked == 1, "the plant never fired: no stamp was attempted"
    # Recovery poll: the stamp lands, still exactly one escalation.
    next_day = _sightings(
        proxy, config, ruleset, notifier, days=1, start_day=next_day
    )
    assert len(_escalation_rows(db)) == 1, (
        "precondition: the recovery emitted a duplicate, so this test would "
        "not be measuring the reset"
    )
    entry = db.get_watchful_recurrence(entry_id)
    assert entry.escalated_at is not None, (
        "precondition: the stamp never recovered, so the reset below would be "
        "rejected and this test would pass for the wrong reason"
    )
    assert [tuple(r) for r in _ledger_rows(db)] == [
        (entry_id, 0, _escalation_rows(db)[0]["id"])
    ], "precondition: generation 0 is not reserved, or not linked to its row"

    # The operator resets: "I have seen it; start counting again."
    reset_ts = T0 + next_day * DAY
    after = db.reset_watchful_recurrence(entry_id, reset_ts)
    assert after.reset_count == 1, "the reset did not advance the generation"
    assert after.escalated_at is None

    # It keeps following them, and the threshold is crossed a second time.
    _cross_threshold(
        proxy, config, ruleset, notifier, entry_id, start_day=next_day + 1
    )

    rows = _escalation_rows(db)
    assert len(rows) == 2, (
        f"a RESET entry escalated {len(rows) - 1} more times, expected 1. The "
        "dedup is suppressing the genuine escalation of an entry the operator "
        "deliberately restarted watching -- the unsafe direction, and the "
        "reason this needed a generation and not a per-MAC check"
    )
    assert rows[1]["notified_at"] is not None, (
        "the second escalation was written but never delivered to the operator"
    )
    assert len(notifier.sent) == 2, (
        f"expected exactly two deliveries across both generations, got "
        f"{len(notifier.sent)} -- one per genuine escalation and no re-sends"
    )
    assert [(r["entry_id"], r["generation"]) for r in _ledger_rows(db)] == [
        (entry_id, 0),
        (entry_id, 1),
    ], "the ledger did not record one reservation per generation"


def test_a_snoozed_crossing_reserves_nothing_so_the_two_states_stay_distinct(
    watched,
):
    """The ledger records EMISSION, not consumption.

    A crossing suppressed by the rule_type snooze writes no alert row, so it
    must write no reservation either. Reserving there would make the ledger
    assert an alert was emitted that the operator's snooze deliberately
    stopped, and any future reader of this table would inherit that claim."""
    db, config, ruleset, entry_id = watched
    db.add_rule_type_snooze(
        "watchful_recurrence", expires_at=T0 + 5 * DAY, added_at=T0
    )
    assert db.is_rule_type_snoozed("watchful_recurrence", T0 + DAY) is not None, (
        "fixture failed: the snooze the gate reads is not active"
    )
    notifier = RecordingNotifier()
    _cross_threshold(db, config, ruleset, notifier, entry_id, start_day=1)

    assert db.get_watchful_recurrence(entry_id).escalated_at is not None, (
        "control: the crossing never happened, so 'reserved nothing' below "
        "would pass for the wrong reason"
    )
    assert _escalation_rows(db) == [], "control: the snooze did not suppress"
    assert _ledger_rows(db) == [], (
        "a snooze-consumed crossing reserved a generation, so the ledger now "
        "claims an escalation alert was emitted that was never sent"
    )


def test_a_recovered_stamp_is_not_counted_as_a_snooze_suppression(watched):
    """Honesty of the hourly suppression summary.

    The recovery path re-stamps an entry whose escalation was already emitted.
    That is not a suppression and must not appear in the counter an operator
    greps to see what their snoozes are catching -- least of all as the
    highest-severity suppression the product can report, for an escalation the
    snooze never touched.

    ⛔ The snooze is added AFTER the escalation is emitted and BEFORE the
    recovery poll, and that ordering is the whole test. A first draft ran with
    no snooze at all, so the counter stayed empty whether the ledger was
    consulted before the snooze or after it, and the test could not fail. The
    ordering here is the only arrangement where the two possible orderings of
    that branch give different answers."""
    db, config, ruleset, entry_id = watched
    proxy = _StampFailsOnceProxy(db)
    notifier = RecordingNotifier()
    counter: dict[str, int] = {}

    def _observe(ts):
        process_observation(
            _obs(ts), proxy, config, ts,
            effective_location_id="home", effective_location_label="Home",
            ensured_locations=set(), processed_counter=[0],
            admitted_counter=[0], ruleset=ruleset, clock_trusted=True,
            allowlist=Allowlist(), notifier=notifier,
            rule_type_suppression_counter=counter,
        )

    needed = Database.WATCHFUL_RECURRENCE_ESCALATION_THRESHOLD - 1
    for d in range(1, needed + 1):
        _observe(T0 + d * DAY)
    assert proxy.blocked == 1, "the plant never fired: no stamp was attempted"
    assert len(_escalation_rows(db)) == 1, "precondition: nothing was emitted"
    assert counter == {}, "precondition: the crossing was already suppressed"

    # NOW the operator snoozes the rule_type. The escalation above already
    # happened; only its stamp is missing.
    recovery_ts = T0 + (needed + 1) * DAY
    db.add_rule_type_snooze(
        "watchful_recurrence", expires_at=recovery_ts + 5 * DAY, added_at=T0
    )
    assert db.is_rule_type_snoozed("watchful_recurrence", recovery_ts), (
        "fixture failed: the snooze is not active at the recovery poll, so "
        "this test cannot tell the two branch orderings apart"
    )

    # The recovery poll, with that snooze active.
    _observe(recovery_ts)
    assert db.get_watchful_recurrence(entry_id).escalated_at is not None, (
        "precondition: the stamp was never recovered, so there was no "
        "recovery to mis-count"
    )
    assert counter.get("watchful_recurrence", 0) == 0, (
        "the recovery was counted as a rule_type snooze suppression, so the "
        f"summary reports {counter} for an escalation that was emitted and "
        "delivered before that snooze existed"
    )
    assert len(_escalation_rows(db)) == 1, (
        "the recovery emitted a second escalation despite the ledger"
    )


def test_a_failed_alert_insert_leaves_no_reservation(watched):
    """⛔ The FAIL-CLOSED direction of the Finding 44 fix, and it is worse than
    the defect it replaces.

    A reservation that survived a failed alert INSERT would burn the
    generation: `escalated_at` stays NULL so the entry keeps crossing, and
    every crossing then finds the reservation and "recovers" a stamp for an
    escalation that was never written or sent. The operator is never told, and
    unlike the duplicate this fix removes, nothing ever heals it.

    The two writes are one transaction precisely so this cannot happen. This
    drives the second one into the ground and checks the first rolled back."""
    db, config, ruleset, entry_id = watched
    boom = RuntimeError("database is locked")

    def _explode(**kw):
        raise boom

    original = db._insert_alert_row
    db._insert_alert_row = _explode
    try:
        with pytest.raises(RuntimeError):
            db.add_watchful_escalation_alert(
                entry_id, 0, ts=T0 + DAY, mac=MAC,
                message="seen 4 times", severity="high",
            )
    finally:
        db._insert_alert_row = original

    assert _ledger_rows(db) == [], (
        "the reservation survived a failed alert insert, so generation 0 is "
        "burned: the entry can never escalate again and nothing will heal it"
    )
    assert _escalation_rows(db) == [], "an alert row was written after all"

    # And the generation is still available, which is the point.
    alert_id = db.add_watchful_escalation_alert(
        entry_id, 0, ts=T0 + 2 * DAY, mac=MAC,
        message="seen 4 times", severity="high",
    )
    assert alert_id is not None, (
        "the retry after a rolled-back failure was refused, so the rollback "
        "left something behind"
    )
    assert [(r["entry_id"], r["generation"]) for r in _ledger_rows(db)] == [
        (entry_id, 0)
    ]


def test_a_bad_entry_id_writes_nothing_and_escalates_nothing(watched):
    """A generation that cannot be reserved must never look like a success.

    ⛔ This test used to require a FOREIGN KEY error to surface, because the
    reservation was an `INSERT ... VALUES` and a nonexistent `entry_id` was the
    only way to get 0 rows. It is now an `INSERT ... SELECT` conditioned on the
    entry still being at this generation, so "no such entry" and "the
    generation moved on" both arrive the same way: **zero rows inserted**.

    The property that actually matters is unchanged and is what is asserted
    here -- nothing is written, nothing is delivered, and the caller is NOT
    handed a timestamp it would stamp. Requiring a specific exception TYPE was
    pinning the mechanism rather than the guarantee.
    """
    db, config, ruleset, entry_id = watched
    missing = entry_id + 9999
    assert db.get_watchful_recurrence(missing) is None, (
        "fixture failed: the id chosen for 'missing' actually exists"
    )
    result = db.add_watchful_escalation_alert(
        missing, 0, ts=T0 + DAY, mac=MAC,
        message="seen 4 times", severity="high",
    )
    assert result is None, f"a nonexistent entry produced an alert id: {result!r}"
    assert _escalation_rows(db) == [], "an alert row was written for no entry"
    assert _ledger_rows(db) == [], "a reservation was written for no entry"


def test_the_unique_constraint_alone_prevents_the_duplicate(watched):
    """⭐ Proves the claim the code makes about itself, which nothing else here
    was proving.

    `_watchful_generation_already_emitted` is documented as an optimisation
    whose failure "degrades to the ordinary emit path, where the UNIQUE
    constraint still prevents a duplicate". Every other test in this file
    exercises the pre-check, which short-circuits before the constraint is ever
    reached -- so a plant that removed the constraint entirely
    (`INSERT OR REPLACE`) left the whole suite GREEN. The claim was true and
    untested, which is the state a comment is most dangerous in.

    Here the pre-check RAISES, so the poller falls through to the emit path and
    the constraint is the only thing standing between the operator and a second
    "this device appears to be following you"."""
    db, config, ruleset, entry_id = watched

    class _NoLedgerReads(_StampFailsOnceProxy):
        """Stamp fails once (the Finding 44 window), and the ledger PRE-CHECK
        is unreadable while ``ledger_down`` is set."""

        def __init__(self, inner):
            super().__init__(inner)
            self.precheck_attempts = 0
            self.ledger_down = True

        def watchful_generation_escalated_at(self, entry_id_, generation):
            self.precheck_attempts += 1
            if self.ledger_down:
                raise RuntimeError("database is locked")
            return self._db.watchful_generation_escalated_at(
                entry_id_, generation
            )

    proxy = _NoLedgerReads(db)
    notifier = RecordingNotifier()

    next_day = _cross_threshold(
        proxy, config, ruleset, notifier, entry_id, start_day=1
    )
    assert proxy.blocked == 1, "the plant never fired: no stamp was attempted"
    assert len(_escalation_rows(db)) == 1, "precondition: nothing was emitted"

    # The recovery poll, with the pre-check unavailable.
    next_day = _sightings(
        proxy, config, ruleset, notifier, days=1, start_day=next_day
    )
    assert proxy.precheck_attempts > 0, (
        "the pre-check was never consulted, so this test never reached the "
        "degraded path it exists to measure"
    )
    assert len(_escalation_rows(db)) == 1, (
        "with the ledger pre-check failing, the UNIQUE constraint did not stop "
        "the duplicate -- so the comment claiming it would is false"
    )
    # ⭐ And the entry is deliberately left UNSTAMPED here. The constraint says
    # a row exists but the ledger cannot say WHEN, and stamping `now_ts` over
    # an older alert row is the permanent-loss bug
    # `test_a_crash_between_the_committed_write_and_the_send_still_reaches_the_operator`
    # exists for. Refusing is fail-open: nothing is emitted, nothing is lost,
    # and the next readable poll recovers it.
    assert db.get_watchful_recurrence(entry_id).escalated_at is None, (
        "the entry was stamped from a ledger that could not be read, so the "
        "stamp is a guess -- and a guess later than the alert row's ts makes "
        "the escalation permanently undeliverable"
    )

    # The database recovers; the very next poll heals the entry.
    proxy.ledger_down = False
    _sightings(proxy, config, ruleset, notifier, days=1, start_day=next_day)
    assert len(_escalation_rows(db)) == 1, "the self-heal emitted a duplicate"
    entry = db.get_watchful_recurrence(entry_id)
    assert entry.escalated_at == _escalation_rows(db)[0]["ts"], (
        "the recovered stamp does not match the alert row it refers to, so "
        "the retry lookup cannot find that row"
    )


def test_a_crash_between_the_committed_write_and_the_send_still_reaches_the_operator(
    watched,
):
    """⛔ THE FAIL-CLOSED REGRESSION the generation ledger introduced, found by
    a cold cross-model read of this very diff and reproduced before being
    believed.

    The alert row and its reservation commit, and the process dies before the
    notifier is called. The row exists, `notified_at` is NULL, `escalated_at`
    is NULL. On the next sighting the ledger says "already emitted", so the
    recovery path runs -- and the first cut of that path did two things wrong:

      1. it stamped `escalated_at = now_ts`. `_retry_watchful_escalation`
         passes `escalated_at` to `get_recent_alert_for_rule_and_mac` as
         `since_ts`, which filters `ts >= since_ts`. A stamp days after the
         alert row's own `ts` makes that row invisible to the retry FOREVER --
         the escalation is permanently undeliverable while every surface shows
         the entry as escalated;
      2. it did not drive the retry at all, and the branch that does is an
         `elif`, so delivery waited for a further sighting that may never come.

    Before the ledger existed this case was noisy but safe: the next sighting
    re-emitted and delivered. Trading a duplicate for a silent permanent loss
    is the exact direction Finding 44 says not to go."""
    db, config, ruleset, entry_id = watched
    notifier = RecordingNotifier()

    import lynceus.poller as poller_mod

    real_deliver = poller_mod._deliver_watchful_escalation
    died = {"count": 0}

    def _die_before_sending(*a, **kw):
        died["count"] += 1
        raise RuntimeError("process died after the commit, before the send")

    poller_mod._deliver_watchful_escalation = _die_before_sending
    try:
        with pytest.raises(RuntimeError):
            _cross_threshold(
                db, config, ruleset, notifier, entry_id, start_day=1
            )
    finally:
        poller_mod._deliver_watchful_escalation = real_deliver

    assert died["count"] == 1, "the plant never fired: delivery was not reached"
    rows = _escalation_rows(db)
    assert len(rows) == 1, "precondition: the alert row did not commit"
    assert rows[0]["notified_at"] is None, "precondition: it was delivered anyway"
    assert db.get_watchful_recurrence(entry_id).escalated_at is None, (
        "precondition: the entry was stamped, so this is not the crash window"
    )
    assert notifier.sent == [], "precondition: the operator was already told"
    original_ts = rows[0]["ts"]

    # The very next poll must reach the operator.
    _observe_at(db, config, ruleset, notifier, T0 + 40 * DAY)

    assert len(_escalation_rows(db)) == 1, "the recovery emitted a duplicate"
    assert len(notifier.sent) == 1, (
        f"the operator was told {len(notifier.sent)} times on the next poll; "
        "the escalation must arrive exactly once"
    )
    entry = db.get_watchful_recurrence(entry_id)
    assert entry.escalated_at == original_ts, (
        f"escalated_at was stamped {entry.escalated_at} but the alert row is "
        f"at {original_ts}. The retry looks up `ts >= escalated_at`, so a "
        "later stamp makes this escalation permanently undeliverable"
    )
    assert _escalation_rows(db)[0]["notified_at"] is not None, (
        "the alert row is still unmarked, so the heartbeat will report it as "
        "undelivered forever"
    )


def test_the_unique_constraint_actually_exists_in_the_schema(watched):
    """The manifest test proves a FILENAME exists and the replay census proves
    the migration raises "table already exists". Neither proves the table has
    the UNIQUE constraint the whole dedup rests on -- an implementation could
    drop it and pass both, then let two writers each insert a reservation.

    Asserted against sqlite's own metadata rather than the migration text, so
    a constraint that failed to apply is caught rather than one that was merely
    typed."""
    db, _config, _ruleset, _entry_id = watched
    indexes = db._conn.execute(
        "PRAGMA index_list('watchful_escalations')"
    ).fetchall()
    unique_cols = []
    for idx in indexes:
        if not idx["unique"]:
            continue
        cols = [
            r["name"]
            for r in db._conn.execute(f"PRAGMA index_info('{idx['name']}')")
        ]
        unique_cols.append(cols)
    assert ["entry_id", "generation"] in unique_cols, (
        "watchful_escalations has no UNIQUE(entry_id, generation); the dedup "
        f"has no database-level guard at all. Unique indexes present: "
        f"{unique_cols}"
    )


def test_a_failure_while_linking_the_alert_rolls_back_the_whole_write(watched):
    """The third statement is inside the transaction too.

    ⚠️ `test_a_failed_alert_insert_leaves_no_reservation` fails BEFORE the
    alert INSERT, so it cannot see a refactor that commits the reservation and
    the alert early and only then links them. That shape leaves a committed
    reservation whose `alert_id` is NULL -- and because the recovery path
    checks row EXISTENCE, it would treat the generation as complete. This
    injects the failure at the link instead."""
    db, _config, _ruleset, entry_id = watched
    real_conn = db._conn

    class _FailOnTheLink:
        """⚠️ `sqlite3.Connection.execute` is read-only, so the injection has
        to be a delegating proxy. It must forward `__enter__`/`__exit__` to the
        REAL connection or the rollback under test never happens and the test
        passes for the wrong reason."""

        def __enter__(self):
            return real_conn.__enter__()

        def __exit__(self, *exc):
            return real_conn.__exit__(*exc)

        def execute(self, sql, *a, **kw):
            if sql.strip().startswith("UPDATE watchful_escalations SET alert_id"):
                raise RuntimeError("database is locked")
            return real_conn.execute(sql, *a, **kw)

        def __getattr__(self, name):
            return getattr(real_conn, name)

    db._conn = _FailOnTheLink()
    try:
        with pytest.raises(RuntimeError):
            db.add_watchful_escalation_alert(
                entry_id, 0, ts=T0 + DAY, mac=MAC,
                message="seen 4 times", severity="high",
            )
    finally:
        db._conn = real_conn

    assert _ledger_rows(db) == [], (
        "the reservation survived a failure at the link step, so the "
        "generation is burned and the entry can never escalate"
    )
    assert _escalation_rows(db) == [], (
        "the alert row survived while its reservation did not, so the two "
        "writes are not actually one transaction"
    )


def test_the_connection_uses_implicit_transactions(watched):
    """The atomicity of every test above rests on one connection setting.

    `sqlite3.Connection` as a context manager COMMITS or ROLLS BACK; it does
    not itself BEGIN. Under `isolation_level=None` (autocommit) each statement
    commits on its own, so the reservation would survive a failed alert INSERT
    and burn the generation silently. Nothing else in this file would notice,
    because they all run on a connection built the right way.

    Pinned here rather than assumed, so a future change to how `Database`
    connects fails loudly next to the code that depends on it."""
    db, _config, _ruleset, _entry_id = watched
    assert db._conn.isolation_level is not None, (
        "the connection is in autocommit mode; the escalation write is no "
        "longer atomic and a failed alert INSERT will burn the generation"
    )


# ---------------------------------------------------------------------------
# Post-merge corrections to #152, all three found by a cold cross-model read of
# the MERGED diff and each reproduced before being believed
# (internal/session1-harnesses/f44_coldread_probe.py).
# ---------------------------------------------------------------------------


def test_a_stale_generation_stamp_is_refused(watched):
    """⛔ THE FAIL-CLOSED ONE. A stamp keyed only on `id` can land on a
    generation that never emitted, and that generation can then NEVER escalate.

    Reachable because `process_observation` runs concurrently in two places:
    the poll loop and the `ble-bridge` thread, which holds its OWN `Database`
    on its own connection ("WAL second writer"), so the per-instance lock does
    not serialise them. Two handlers mid-crossing for generation g, plus an
    operator reset to g+1, and the slower stamp lands on g+1.

    ⚠️ The CONTROL is the pre-fix SQL run on a second connection. If it ever
    stops stamping, this test has stopped being able to tell the two apart."""
    db, config, ruleset, entry_id = watched
    notifier = RecordingNotifier()
    _cross_threshold(db, config, ruleset, notifier, entry_id, start_day=1)
    entry = db.get_watchful_recurrence(entry_id)
    assert entry.escalated_at is not None, "precondition: never escalated"
    stale_generation, stale_stamp = entry.reset_count, entry.escalated_at

    db.reset_watchful_recurrence(entry_id, T0 + 40 * DAY)
    after = db.get_watchful_recurrence(entry_id)
    assert after.reset_count == stale_generation + 1
    assert after.escalated_at is None

    # CONTROL: the pre-fix statement still stamps, so the test discriminates.
    db._conn.execute(
        "UPDATE watchful_recurrence SET escalated_at = ? "
        "WHERE id = ? AND escalated_at IS NULL AND archived_at IS NULL",
        (stale_stamp, entry_id),
    )
    assert db.get_watchful_recurrence(entry_id).escalated_at is not None, (
        "the control did not reproduce the pre-fix behaviour, so a pass below "
        "proves nothing"
    )
    db._conn.execute(
        "UPDATE watchful_recurrence SET escalated_at = NULL WHERE id = ?",
        (entry_id,),
    )

    # TREATMENT: the compare-and-swap refuses the stale generation.
    assert db.escalate_watchful_recurrence(
        entry_id, stale_stamp, expected_reset_count=stale_generation
    ) is None, "a stamp for a superseded generation was accepted"
    assert db.get_watchful_recurrence(entry_id).escalated_at is None, (
        "generation "
        f"{after.reset_count} was marked escalated by a handler that decided "
        f"about generation {stale_generation}; it emitted no alert of its own "
        "and can now never escalate"
    )

    # And the current generation still escalates normally.
    _cross_threshold(db, config, ruleset, notifier, entry_id, start_day=41)
    assert len(_escalation_rows(db)) == 2, (
        "the current generation could not escalate after the stale stamp was "
        "refused"
    )


def test_an_unreadable_ledger_never_reaches_the_snooze_branch(watched):
    """⛔ The other permanent-undeliverability route, reached through the
    DEGRADED path rather than the ordinary one.

    The snooze-consumption branch stamps `now_ts` without consulting the
    ledger. If the ledger read merely FAILED -- rather than returning "no row"
    -- and a snooze happens to be active, that branch stamps a time later than
    the pending alert's `ts`, and the retry's `ts >= escalated_at` filter can
    never find that row again.

    Refusing to stamp is the safe answer: nothing is emitted (the UNIQUE
    constraint sees to that), nothing is lost, and the next readable poll
    recovers properly."""
    db, config, ruleset, entry_id = watched
    notifier = RecordingNotifier(deliver=False)  # ntfy down: row stays pending

    proxy = _StampFailsOnceProxy(db)
    day = _cross_threshold(proxy, config, ruleset, notifier, entry_id,
                           start_day=1)
    rows = _escalation_rows(db)
    assert proxy.blocked == 1 and len(rows) == 1, "precondition failed"
    assert db.get_watchful_recurrence(entry_id).escalated_at is None, (
        "precondition: already recovered, so the branch under test is "
        "unreachable"
    )
    alert_ts = rows[0]["ts"]

    db.add_rule_type_snooze("watchful_recurrence",
                            expires_at=T0 + (day + 30) * DAY, added_at=T0)

    class _LedgerUnreadable:
        def __init__(self, inner):
            self._db = inner
            self.reads = 0

        def watchful_generation_escalated_at(self, *a, **kw):
            self.reads += 1
            raise RuntimeError("database is locked")

        def __getattr__(self, name):
            return getattr(self._db, name)

    blind = _LedgerUnreadable(db)
    _sightings(blind, config, ruleset, notifier, days=1, start_day=day)
    assert blind.reads > 0, "the ledger read was never attempted"

    stamp = db.get_watchful_recurrence(entry_id).escalated_at
    assert stamp is None or stamp <= alert_ts, (
        f"escalated_at was stamped {stamp}, later than the pending alert at "
        f"{alert_ts}. The retry looks up `ts >= escalated_at`, so that "
        "escalation can never be delivered"
    )
    assert len(_escalation_rows(db)) == 1, "a duplicate was emitted"


def test_three_generations_each_escalate_exactly_once(watched):
    """⚠️ Two generations is not enough to pin the keying.

    `generation = min(entry.reset_count, 1)` passes every 0-then-1 test in this
    file while permanently suppressing generation 2. Drive emit -> reset ->
    emit -> reset -> emit and require three distinct reservations, three alert
    rows and three deliveries."""
    db, config, ruleset, entry_id = watched
    notifier = RecordingNotifier()
    day = 1
    for expected_generation in range(3):
        assert (
            db.get_watchful_recurrence(entry_id).reset_count
            == expected_generation
        ), "the entry is not on the generation this iteration expects"
        day = _cross_threshold(db, config, ruleset, notifier, entry_id,
                               start_day=day)
        assert len(_escalation_rows(db)) == expected_generation + 1, (
            f"generation {expected_generation} did not emit its escalation"
        )
        if expected_generation < 2:
            db.reset_watchful_recurrence(entry_id, T0 + day * DAY)
            day += 1

    rows = _escalation_rows(db)
    assert len(rows) == 3, f"expected 3 escalations, got {len(rows)}"
    assert all(r["notified_at"] is not None for r in rows), (
        "an escalation was written but never delivered"
    )
    assert len(notifier.sent) == 3, (
        f"expected exactly 3 deliveries, got {len(notifier.sent)}"
    )
    assert [(r["entry_id"], r["generation"]) for r in _ledger_rows(db)] == [
        (entry_id, 0), (entry_id, 1), (entry_id, 2)
    ], "the ledger did not record one reservation per generation"


def test_a_stale_generation_cannot_emit_after_a_snooze_consumed_reset(watched):
    """⛔ The escape hatch the UNIQUE constraint alone does NOT close.

    A generation consumed by the rule_type snooze is STAMPED (so a reset is
    legal) but has NO ledger row -- the ledger records EMISSION, and a snoozed
    crossing emits nothing. So for that generation the constraint has nothing
    to collide with, and a handler still holding the pre-reset view can emit
    and DELIVER an escalation for a generation the operator both snoozed and
    reset.

    Measured before the fix: `alerts=1 delivered=1`. That directly defeats
    `test_a_snoozed_escalation_is_consumed_and_never_resurrected`, one aisle
    over.

    Found by an M3 sweep of the poller; the sweep's own interleaving was
    refuted (a reset needs `escalated_at IS NOT NULL`, which a mid-crossing
    entry does not have) and this is the one variant that survives that
    refutation."""
    db, _config, _ruleset, entry_id = watched
    notifier = RecordingNotifier()

    # Generation 0 consumed by a snooze: stamped, no alert row, no ledger row.
    db.escalate_watchful_recurrence(entry_id, T0 + DAY, expected_reset_count=0)
    assert _escalation_rows(db) == [], "precondition: a snoozed crossing emits nothing"
    assert _ledger_rows(db) == [], "precondition: and reserves nothing"

    # The operator resets -- legal, because escalated_at IS NOT NULL.
    db.reset_watchful_recurrence(entry_id, T0 + 2 * DAY)
    moved = db.get_watchful_recurrence(entry_id)
    assert moved.reset_count == 1 and moved.escalated_at is None

    # A handler still holding the PRE-reset view emits for generation 0.
    stale = moved._replace(reset_count=0, escalated_at=None)
    stamp = _emit_watchful_escalation(db, notifier, stale, T0 + 2 * DAY)

    assert stamp is None, (
        f"the stale handler was told to stamp {stamp}; generation 0 is gone"
    )
    assert _escalation_rows(db) == [], (
        "an escalation was written for a generation the operator had both "
        "snoozed and reset"
    )
    assert notifier.sent == [], (
        f"the operator was sent {notifier.sent} for a generation they snoozed "
        "and then reset"
    )
    assert db.get_watchful_recurrence(entry_id).escalated_at is None, (
        "the current generation was stamped by a handler that decided about "
        "an older one"
    )
