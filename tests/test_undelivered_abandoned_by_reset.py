"""Finding 50 — an operator reset left a permanent, unclearable complaint.

⭐ Why this file exists. `_retry_watchful_escalation` re-drives an escalation the
operator was never told about (#74). Its first statement is
`if escalated_at is None: return`. `reset_watchful_recurrence` sets
`escalated_at = NULL`. So a reset silently removes the retry path with up to 3 of
4 attempts unspent, and nothing can ever spend them -- the documented give-up
state is `attempts >= NOTIFY_MAX_ATTEMPTS`, which that row never reaches.

The row therefore stays `notified_at IS NULL` forever, and
`count_undelivered_alerts()` is called with NO window by both the heartbeat
(`poller.py`) and `/settings`. Every such reset adds a permanent line to
"N alert(s) written but never delivered", on the one surface whose entire value
depends on the operator still reading it.

⛔ The unsafe fix, named so nobody reaches for it later: windowing the counter
would also hide a genuinely broken ntfy topic, which is the exact silence that
counter exists to break. The counter must complain forever about a real failure.
Only rows the operator has demonstrably ACTIONED may stop counting, and they get
their own state (migration 027) rather than a lie in `notified_at`.

**Acceptance criterion, a CONJUNCTION and both halves live here:**
  1. after such a reset the count returns to its pre-escalation value
       -> test_a_reset_clears_the_permanent_undelivered_complaint
  2. a genuinely undelivered alert on a healthy entry STILL raises it
       -> test_a_genuinely_undelivered_alert_still_raises_the_count
Without (2), "stop counting" passes trivially by counting nothing.
"""

from __future__ import annotations

import pytest

from lynceus import poller
from lynceus.allowlist import Allowlist
from lynceus.config import Config
from lynceus.db import Database
from lynceus.kismet import DeviceObservation
from lynceus.notify import Notifier
from lynceus.poller import _retry_watchful_escalation, process_observation
from lynceus.rules import Rule, Ruleset

MAC = "ac:de:48:11:22:33"
OTHER_MAC = "ac:de:48:77:88:99"
T0 = 1_700_000_000
DAY = 86400


class DeadNotifier(Notifier):
    """ntfy is down at exactly the moment the threshold is crossed."""

    def __init__(self, deliver: bool = False):
        self.sent: list[str] = []
        self.deliver = deliver

    def send(self, severity, title, message, priority_override=None) -> bool:
        self.sent.append(title)
        return self.deliver


def _obs(mac: str, ts: int) -> DeviceObservation:
    return DeviceObservation(
        mac=mac, device_type="wifi", first_seen=ts, last_seen=ts, rssi=-40,
        ssid=None, oui_vendor=None, is_randomized=False,
    )


@pytest.fixture
def watched(tmp_path):
    path = str(tmp_path / "w.db")
    db = Database(path)
    ruleset = Ruleset(rules=[
        Rule(name="watchlisted mac", rule_type="watchlist_mac", severity="high")
    ])
    entries = {}
    for mac in (MAC, OTHER_MAC):
        db.add_watchlist(pattern=mac, pattern_type="mac", severity="high",
                         description="suspected tracker")
        db.upsert_device(mac=mac, device_type="wifi", oui_vendor=None,
                         is_randomized=0, now_ts=T0)
        src = db.add_alert(ts=T0, rule_name="watchlisted mac", mac=mac,
                           message="seen", severity="high",
                           rule_type="watchlist_mac")
        db.mark_alert_notified(src, now_ts=T0)
        eid = db.create_watchful_from_alert(src, None, T0)
        assert eid is not None, "fixture failed: no watchful entry created"
        entries[mac] = eid
    yield db, Config(db_path=path), ruleset, entries
    db.close()


def _observe(db, config, ruleset, notifier, mac, ts):
    process_observation(
        _obs(mac, ts), db, config, ts,
        effective_location_id="home", effective_location_label="Home",
        ensured_locations=set(), processed_counter=[0], admitted_counter=[0],
        ruleset=ruleset, clock_trusted=True, allowlist=Allowlist(),
        notifier=notifier,
    )


def _escalate(db, config, ruleset, notifier, mac, *, start_day=1):
    """Drive counted sightings until this entry escalates. Returns next day.

    ⚠️ The number of sightings is DERIVED from the threshold constant. A
    transcribed 3 would keep passing if the threshold moved, while measuring an
    entry that never crossed.
    """
    day = start_day
    for _ in range(Database.WATCHFUL_RECURRENCE_ESCALATION_THRESHOLD):
        _observe(db, config, ruleset, notifier, mac, T0 + day * DAY)
        day += 1
    return day


def _escalation_rows(db, mac=None):
    sql = ("SELECT id, mac, notified_at, notify_abandoned_at, notify_attempts "
           "FROM alerts WHERE rule_type='watchful_recurrence'")
    params = ()
    if mac is not None:
        sql += " AND mac = ?"
        params = (mac,)
    return db._conn.execute(sql + " ORDER BY id", params).fetchall()


def test_the_fixture_actually_escalates_and_actually_fails_delivery(watched):
    """The CONTROL for every test below.

    Without it, "the count went back to zero" could mean the escalation never
    happened, or that it was delivered normally -- neither of which is the state
    Finding 50 is about."""
    db, config, ruleset, entries = watched
    notifier = DeadNotifier()
    _escalate(db, config, ruleset, notifier, MAC)

    rows = _escalation_rows(db, MAC)
    assert len(rows) == 1, "control: the entry never escalated"
    assert rows[0]["notified_at"] is None, "control: delivery did not fail"
    assert notifier.sent, "control: the notifier was never called"
    assert db.get_watchful_recurrence(entries[MAC]).escalated_at is not None
    assert db.count_undelivered_alerts() == 1, (
        "control: the undelivered complaint this finding is about never appeared"
    )


def test_a_reset_clears_the_permanent_undelivered_complaint(watched):
    """FINDING 50, first half: after a reset the count returns to its
    pre-escalation value.

    The reset is what removes the retry path, so the row can never become
    delivered and can never reach the give-up state. Leaving it counted means
    the heartbeat carries a complaint that no action by the operator or the
    daemon can ever clear."""
    db, config, ruleset, entries = watched
    notifier = DeadNotifier()
    before = db.count_undelivered_alerts()
    next_day = _escalate(db, config, ruleset, notifier, MAC)
    assert db.count_undelivered_alerts() == before + 1, (
        "precondition: the escalation did not raise the count"
    )

    db.reset_watchful_recurrence(entries[MAC], T0 + next_day * DAY)

    assert db.count_undelivered_alerts() == before, (
        "after a reset the undelivered count did not return to its "
        "pre-escalation value, so the heartbeat carries a complaint nothing "
        "can ever clear"
    )
    row = _escalation_rows(db, MAC)[0]
    assert row["notify_abandoned_at"] is not None, "the row was not abandoned"
    assert row["notified_at"] is None, (
        "the row was marked DELIVERED, which asserts ntfy succeeded when "
        "nothing established that -- abandoned is not delivered"
    )


def test_a_genuinely_undelivered_alert_still_raises_the_count(watched):
    """FINDING 50, second half, and NOT optional.

    ⛔ Without this, "stop counting" passes trivially by counting nothing. A
    broken ntfy topic is the silence this counter exists to break, and the fix
    must not have bought quiet by going blind.

    Two devices: one is reset (abandoned), one is not. The second must keep
    complaining forever."""
    db, config, ruleset, entries = watched
    notifier = DeadNotifier()
    next_day = _escalate(db, config, ruleset, notifier, MAC)
    next_day = _escalate(db, config, ruleset, notifier, OTHER_MAC,
                         start_day=next_day)
    assert db.count_undelivered_alerts() == 2, (
        "precondition: both escalations should be undelivered"
    )

    db.reset_watchful_recurrence(entries[MAC], T0 + next_day * DAY)

    assert db.count_undelivered_alerts() == 1, (
        "the reset of ONE entry changed the count for the other -- the "
        "abandonment is not scoped to the row the operator actioned"
    )
    other = _escalation_rows(db, OTHER_MAC)[0]
    assert other["notify_abandoned_at"] is None, (
        "an entry the operator never touched was marked abandoned; a broken "
        "ntfy topic would now be invisible"
    )

    # And it stays complaining, however long the daemon runs.
    for extra in range(1, 40):
        _observe(db, config, ruleset, notifier, OTHER_MAC,
                 T0 + (next_day + extra) * DAY)
    assert db.count_undelivered_alerts() >= 1, (
        "the genuinely undelivered alert stopped being counted over time, so "
        "a broken notifier ages quietly out of the heartbeat"
    )


def test_a_delivered_escalation_is_never_marked_abandoned(watched):
    """Abandonment must not touch a row the operator actually received.

    Marking one would be a lie in the safe-LOOKING direction: the abandoned set
    would stop meaning "the operator actioned an alert that never arrived"."""
    db, config, ruleset, entries = watched
    notifier = DeadNotifier(deliver=True)
    next_day = _escalate(db, config, ruleset, notifier, MAC)
    row = _escalation_rows(db, MAC)[0]
    assert row["notified_at"] is not None, (
        "precondition: this test needs a DELIVERED escalation"
    )
    assert db.count_undelivered_alerts() == 0

    db.reset_watchful_recurrence(entries[MAC], T0 + next_day * DAY)

    row = _escalation_rows(db, MAC)[0]
    assert row["notify_abandoned_at"] is None, (
        "a delivered escalation was marked abandoned"
    )
    assert db.count_undelivered_alerts() == 0


def test_a_reset_abandons_only_this_generations_escalation(watched):
    """Across generations: escalate, reset, escalate again, reset again.

    ⚠️ The second reset must abandon the SECOND escalation. A fix that keyed on
    "the newest watchful_recurrence alert for this MAC" without regard to which
    generation is being reset would mark the wrong row here, and the first
    generation's complaint would come back."""
    db, config, ruleset, entries = watched
    notifier = DeadNotifier()

    next_day = _escalate(db, config, ruleset, notifier, MAC)
    db.reset_watchful_recurrence(entries[MAC], T0 + next_day * DAY)
    next_day += 1
    assert db.count_undelivered_alerts() == 0

    next_day = _escalate(db, config, ruleset, notifier, MAC,
                         start_day=next_day)
    rows = _escalation_rows(db, MAC)
    assert len(rows) == 2, (
        f"precondition: the reset entry did not escalate again ({len(rows)} "
        "escalation rows); Finding 44's second half is what makes it"
    )
    assert db.count_undelivered_alerts() == 1

    db.reset_watchful_recurrence(entries[MAC], T0 + next_day * DAY)

    rows = _escalation_rows(db, MAC)
    assert [r["notify_abandoned_at"] is not None for r in rows] == [True, True], (
        "both generations' escalations should be abandoned after both resets; "
        f"got {[r['notify_abandoned_at'] for r in rows]}"
    )
    assert db.count_undelivered_alerts() == 0


def test_the_legacy_lookup_abandons_an_escalation_with_no_ledger_row(watched):
    """The fallback path, which is the ONLY thing that helps an install that
    escalated BEFORE migration 026 landed.

    Those rows have no `watchful_escalations` entry, and they are precisely the
    ones carrying a permanent complaint today. Simulated by deleting the ledger
    row, which is exactly the state a pre-026 database is in."""
    db, config, ruleset, entries = watched
    notifier = DeadNotifier()
    next_day = _escalate(db, config, ruleset, notifier, MAC)

    db._conn.execute("DELETE FROM watchful_escalations")
    db._conn.commit()
    assert db._conn.execute(
        "SELECT COUNT(*) FROM watchful_escalations"
    ).fetchone()[0] == 0, "precondition: the ledger row survived the delete"
    assert db.count_undelivered_alerts() == 1

    db.reset_watchful_recurrence(entries[MAC], T0 + next_day * DAY)

    assert db.count_undelivered_alerts() == 0, (
        "an escalation with no ledger row was not abandoned, so every install "
        "that escalated before migration 026 keeps its permanent complaint"
    )


def test_only_the_reset_path_abandons_an_alert(watched):
    """⛔ A suppression on a safety counter must have exactly ONE writer.

    A second one is how a counter that exists to break silence quietly stops
    counting. Asserted against the source rather than by enumerating behaviours,
    because the risk is a future call site nobody thought to test."""
    import ast
    from pathlib import Path

    import lynceus.db as _db

    src = Path(_db.__file__).read_text(encoding="utf-8")
    writers = [
        node.lineno
        for node in ast.walk(ast.parse(src))
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and "notify_abandoned_at = ?" in node.value
    ]
    assert len(writers) == 1, (
        f"{len(writers)} statements write notify_abandoned_at (db.py lines "
        f"{writers}); each one can silence the undelivered counter"
    )
    callers = [
        node.func.attr
        for node in ast.walk(ast.parse(src))
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "_abandon_watchful_escalation_alert"
    ]
    assert len(callers) == 1, (
        f"the abandon helper has {len(callers)} call sites, expected 1 "
        "(reset_watchful_recurrence)"
    )


def test_the_heartbeat_stops_complaining_after_the_reset(watched):
    """End to end on the surface the finding is actually about.

    The register's harm is not a number in the database, it is a line in the
    heartbeat the operator reads. Driven through `_compose_heartbeat` rather
    than asserted on the counter, because that is the claim."""
    from lynceus.poller import _compose_heartbeat

    db, config, ruleset, entries = watched
    notifier = DeadNotifier()
    next_day = _escalate(db, config, ruleset, notifier, MAC)

    _healthy, body = _compose_heartbeat(db, config, now_ts=T0 + next_day * DAY)
    assert "never delivered" in body, (
        f"precondition: the heartbeat never carried the complaint: {body!r}"
    )

    db.reset_watchful_recurrence(entries[MAC], T0 + next_day * DAY)

    _healthy, body = _compose_heartbeat(db, config, now_ts=T0 + next_day * DAY)
    assert "never delivered" not in body, (
        "the heartbeat still reports an undelivered alert that no action by "
        f"the operator or the daemon can ever clear: {body!r}"
    )


def test_an_abandoned_escalation_is_never_retried(watched):
    """⛔ FINDING 50's mark must also BIND the retry, not just the counter.

    The reset stops re-delivery by clearing `escalated_at` -- that is the whole
    mechanism, per this file's header. It follows that anything still holding a
    PRE-RESET copy of the entry can drive exactly one send the reset was meant
    to prevent, because `_retry_watchful_escalation` re-reads the alert row but
    never re-reads the entry, and `get_recent_alert_for_rule_and_mac` does not
    filter `notify_abandoned_at`.

    This drives the helper with a stale entry directly, so it guards the
    MECHANISM rather than one caller. The caller-side guard is the next test;
    they fail independently and both are needed.
    """
    db, config, ruleset, entries = watched
    next_day = _escalate(db, config, ruleset, DeadNotifier(), MAC)
    stale = db.get_watchful_recurrence(entries[MAC])
    assert stale.escalated_at is not None, (
        "precondition: the entry never escalated, so there is no stale copy to hold"
    )
    reset_at = T0 + next_day * DAY
    db.reset_watchful_recurrence(entries[MAC], reset_at)
    row = _escalation_rows(db, MAC)[0]
    assert row["notify_abandoned_at"] is not None, "precondition: the reset did not abandon the row"
    assert row["notified_at"] is None, "precondition: the row must still be undelivered"

    live = DeadNotifier(deliver=True)
    _retry_watchful_escalation(db, live, stale, reset_at + 3600)

    assert live.sent == [], (
        f"an ABANDONED escalation was re-sent {len(live.sent)} time(s) -- the "
        "operator reset this entry while looking at that very escalation, and "
        "the tool told them again anyway"
    )


def test_a_reset_landing_between_the_two_entry_reads_does_not_resend(watched, monkeypatch):
    """⛔ `process_observation` decided from TWO different reads of one entry.

    `watchful_entry` is read at poller.py:793, before
    `record_watchful_sighting`; `outcome.entry` is the row as it is INSIDE that
    write's transaction. The threshold branch used the fresh one and the retry
    branch used the stale one. A reset landing between them is where they
    disagree. Measured against a control that resets BEFORE the observation:

        CONTROL   reset first, then observe   escalation sends=0
        TREATMENT reset between the reads     escalation sends=1

    The operator clicked reset on the escalation they were looking at, and were
    told about it again.
    """
    db, config, ruleset, entries = watched
    next_day = _escalate(db, config, ruleset, DeadNotifier(), MAC)
    assert _escalation_rows(db, MAC)[0]["notified_at"] is None, (
        "precondition: the escalation was delivered, so there is nothing to re-send"
    )
    later = T0 + next_day * DAY
    path = config.db_path
    fired: list = []

    class ResetAtSeam(Database):
        """A second writer resets the entry after the gate has read it."""

        def get_active_watchful_recurrence_by_mac(self, mac):
            entry = super().get_active_watchful_recurrence_by_mac(mac)
            if entry is not None and entry.escalated_at is not None and not fired:
                fired.append(1)
                other = Database(path)  # a genuinely separate connection
                try:
                    other.reset_watchful_recurrence(entry.id, later)
                finally:
                    other.close()
            return entry

    # Spy on the retry branch so the test can see WHICH entry it decided from.
    seen_entries: list = []
    real_retry = poller._retry_watchful_escalation

    def spy(db_, notifier_, entry, now_ts):
        seen_entries.append(entry.escalated_at)
        return real_retry(db_, notifier_, entry, now_ts)

    live = DeadNotifier(deliver=True)
    racer = ResetAtSeam(path)
    monkeypatch.setattr(poller, "_retry_watchful_escalation", spy)
    try:
        _observe(racer, config, ruleset, live, MAC, later)
    finally:
        racer.close()

    assert fired, (
        "the reset never landed at the seam -- this test would pass vacuously"
    )
    escalations = [t for t in live.sent if "escalation" in t]
    assert escalations == [], (
        f"a reset landing between the two reads still re-sent the escalation "
        f"({len(escalations)} send(s)) -- the retry branch decided from the "
        "pre-reset copy of the entry"
    )
    # ⛔ And assert the DECISION, not only its outcome. The abandoned-row check
    # inside `_retry_watchful_escalation` also suppresses the send, so an
    # outcome-only assertion passes with the stale read still in place and
    # guards the other layer by accident. What belongs here is that the branch
    # was taken from the POST-WRITE entry.
    assert [e for e in seen_entries if e is not None] == [], (
        "the retry branch was entered from the pre-reset entry "
        f"(escalated_at={[getattr(e, 'escalated_at', None) for e in seen_entries]}) "
        "-- it decided from `watchful_entry`, read before the write, instead of "
        "`outcome.entry`, read inside it"
    )
