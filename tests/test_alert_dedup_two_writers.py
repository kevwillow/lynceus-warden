"""Finding 58 — the MAIN alert dedup is a read-then-write with two writers.

`process_observation` reads `get_recent_alert_for_rule_and_mac` to decide
whether this rule+mac was already alerted inside the dedup window, then writes.
The read is not re-asserted at the write, and there are TWO callers of
`process_observation`: the poll loop, and the `ble-bridge` thread, which opens
its OWN `Database` on its own connection, so `Database._lock` does not
serialise them.

Measured before the fix, one detection delivered to both:

    CONTROL   sequential, one connection    alerts=1  sent=1
    TREATMENT two connections, interleaved  alerts=2  sent=2

⛔ The dedup branch is THREE-way and only ONE arm may become conditional:

    delivered                        -> skip
    undelivered, attempts spent      -> skip
    undelivered, attempts remaining  -> REUSE the row and re-send
    nothing recent                   -> write a new row     <- only this one

Routing the retry arm through the conditional insert would turn a re-send into
a silent skip and reinstate Wave 5 Finding 12, where one failed send swallowed
the alert for the whole window. That is why the second acceptance test here is
not optional.
"""

from __future__ import annotations

import threading

import pytest

from lynceus.allowlist import Allowlist
from lynceus.config import Config
from lynceus.db import Database
from lynceus.kismet import DeviceObservation
from lynceus.notify import Notifier
from lynceus.poller import process_observation
from lynceus.rules import Rule, Ruleset

MAC = "ac:de:48:11:22:33"
T0 = 1_700_000_000


class Recorder(Notifier):
    def __init__(self, deliver: bool = True):
        self.sent: list[str] = []
        self.deliver = deliver
        self.lock = threading.Lock()

    def send(self, severity, title, message, priority_override=None) -> bool:
        with self.lock:
            self.sent.append(title)
        return self.deliver


def _obs(ts: int) -> DeviceObservation:
    return DeviceObservation(
        mac=MAC, device_type="wifi", first_seen=ts, last_seen=ts, rssi=-40,
        ssid=None, oui_vendor=None, is_randomized=False,
    )


@pytest.fixture
def watched(tmp_path):
    path = str(tmp_path / "dedup.db")
    db = Database(path)
    db.add_watchlist(pattern=MAC, pattern_type="mac", severity="high",
                     description="suspected tracker")
    db.ensure_location("home", "Home")
    db.close()
    ruleset = Ruleset(rules=[
        Rule(name="watchlisted mac", rule_type="watchlist_mac", severity="high")
    ])
    yield path, ruleset


def _run(db, config, ruleset, notifier, ts):
    process_observation(
        _obs(ts), db, config, ts,
        effective_location_id="home", effective_location_label="Home",
        ensured_locations=set(), processed_counter=[0], admitted_counter=[0],
        ruleset=ruleset, clock_trusted=True, allowlist=Allowlist(),
        notifier=notifier,
    )


def _alerts(path):
    db = Database(path)
    try:
        return db._conn.execute(
            "SELECT id, notified_at, notify_attempts FROM alerts "
            "WHERE rule_name='watchlisted mac' ORDER BY id"
        ).fetchall()
    finally:
        db.close()


def test_two_writers_of_one_detection_produce_one_alert_and_one_notification(
    watched,
):
    """FINDING 58, first half.

    ⚠️ Asserts the interleaving ACTUALLY happened before asserting the outcome.
    Without that a pass can mean "the race never occurred", which is what most
    concurrency tests silently measure."""
    path, ruleset = watched
    config = Config(db_path=path)
    notifier = Recorder()
    barrier = threading.Barrier(2, timeout=10)
    reached: list[str] = []
    errors: list[BaseException] = []

    class _Barriered(Database):
        def add_alert_if_none_since(self, **kw):
            if kw.get("rule_name") == "watchlisted mac":
                reached.append(threading.current_thread().name)
                barrier.wait()
            return super().add_alert_if_none_since(**kw)

    def handler(name):
        db = _Barriered(path)
        try:
            _run(db, config, ruleset, notifier, T0)
        except BaseException as e:  # noqa: BLE001 - reported below
            errors.append(e)
        finally:
            db.close()

    threads = [threading.Thread(target=handler, args=(n,), name=n)
               for n in ("poll-loop", "ble-bridge")]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=25)

    assert len(reached) == 2, (
        f"only {len(reached)} writer(s) reached the alert write, so the two "
        "never raced and this test proves nothing"
    )
    assert not errors, f"a handler raised: {errors!r}"
    rows = _alerts(path)
    assert len(rows) == 1, (
        f"one detection produced {len(rows)} alert rows; the operator sees the "
        "same device reported twice"
    )
    assert len(notifier.sent) == 1, (
        f"the operator was notified {len(notifier.sent)} times about one "
        "detection"
    )


def test_an_undelivered_alert_with_attempts_left_is_still_retried(watched):
    """FINDING 58, second half, and NOT optional.

    ⛔ The conditional insert must apply ONLY to the "write a new row" arm. If
    the retry arm were routed through it, an undelivered alert would be
    silently skipped instead of re-sent -- Wave 5 Finding 12, where one failed
    send swallowed the alert for the whole dedup window.

    Here ntfy is down for the first observation and up for the second, inside
    the same dedup window."""
    path, ruleset = watched
    config = Config(db_path=path)
    down = Recorder(deliver=False)
    db = Database(path)
    try:
        _run(db, config, ruleset, down, T0)
        rows = _alerts(path)
        assert len(rows) == 1 and rows[0]["notified_at"] is None, (
            f"precondition: expected one undelivered alert, got {[dict(r) for r in rows]}"
        )
        assert len(down.sent) == 1, "precondition: the first send was not attempted"

        up = Recorder(deliver=True)
        _run(db, config, ruleset, up, T0 + 1)

        assert len(up.sent) == 1, (
            "the undelivered alert was NOT retried -- the dedup swallowed it "
            "for the rest of the window, which is Wave 5 Finding 12"
        )
        rows = _alerts(path)
        assert len(rows) == 1, (
            f"the retry wrote a NEW row instead of reusing the existing one: "
            f"{[dict(r) for r in rows]}"
        )
        assert rows[0]["notified_at"] is not None, (
            "the retry succeeded but the row was not marked delivered"
        )
    finally:
        db.close()


def test_a_delivered_alert_inside_the_window_still_suppresses(watched):
    """The dedup's whole purpose, unchanged. Without this the fix could 'pass'
    by never deduping at all."""
    path, ruleset = watched
    config = Config(db_path=path)
    notifier = Recorder()
    db = Database(path)
    try:
        _run(db, config, ruleset, notifier, T0)
        _run(db, config, ruleset, notifier, T0 + 1)
        assert len(_alerts(path)) == 1, "the dedup window stopped suppressing"
        assert len(notifier.sent) == 1, "the operator was notified twice"
    finally:
        db.close()


def test_with_dedup_disabled_every_detection_writes_its_own_alert(watched):
    """`alert_dedup_window_seconds == 0` disables the window entirely, and that
    path must NOT go through the conditional insert -- there is no window to be
    'recent' within, and suppressing there would silence an operator who
    explicitly turned dedup off.

    ⚠️ Both observations are at the SAME timestamp, deliberately. With
    different ones this test cannot discriminate: routing the disabled path
    through the conditional insert computes `since_ts = now_ts - 0 = now_ts`,
    so an alert written a second earlier fails `ts >= since_ts` and the insert
    proceeds anyway. The plant survived exactly that way. Two observations
    inside one second are ordinary here -- the bridge flush and a poll tick
    routinely share a second.
    """
    path, ruleset = watched
    config = Config(db_path=path, alert_dedup_window_seconds=0)
    notifier = Recorder()
    db = Database(path)
    try:
        _run(db, config, ruleset, notifier, T0)
        _run(db, config, ruleset, notifier, T0)
        assert len(_alerts(path)) == 2, (
            "dedup is disabled, so both detections must be recorded even when "
            "they share a timestamp"
        )
        assert len(notifier.sent) == 2
        # and across seconds too, which is the ordinary case
        _run(db, config, ruleset, notifier, T0 + 1)
        assert len(_alerts(path)) == 3
    finally:
        db.close()


def test_the_conditional_insert_and_the_dedup_read_agree_on_recent(tmp_path):
    """⛔ The NULL-mac predicate is duplicated between
    `get_recent_alert_for_rule_and_mac` and `add_alert_if_none_since`. If the
    two ever disagree, this method's idea of "recent" stops matching the
    caller's and the dedup silently changes meaning.

    Driven for BOTH a real mac and a NULL mac, which is where the two SQL
    fragments are easiest to get subtly different."""
    db = Database(str(tmp_path / "agree.db"))
    try:
        db.ensure_location("home", "Home")
        db.upsert_device(mac=MAC, device_type="wifi", oui_vendor=None,
                         is_randomized=0, now_ts=T0)
        for mac in (MAC, None):
            first = db.add_alert_if_none_since(
                ts=T0, rule_name="r", mac=mac, message="m", severity="high",
                matched_watchlist_id=None, rule_type="watchlist_mac",
                since_ts=T0 - 100,
            )
            assert first is not None, f"the first insert was refused for mac={mac!r}"
            seen = db.get_recent_alert_for_rule_and_mac("r", mac, T0 - 100)
            assert seen is not None and seen["id"] == first, (
                f"the dedup READ cannot see the row the conditional INSERT just "
                f"wrote for mac={mac!r}; the two predicates disagree"
            )
            again = db.add_alert_if_none_since(
                ts=T0 + 1, rule_name="r", mac=mac, message="m", severity="high",
                matched_watchlist_id=None, rule_type="watchlist_mac",
                since_ts=T0 - 100,
            )
            assert again is None, (
                f"the conditional INSERT wrote a second row for mac={mac!r} "
                "although the read considers one recent"
            )
    finally:
        db.close()
