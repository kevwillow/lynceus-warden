"""Two WRITERS racing the same escalation — the test #152 said was owed.

⛔ Why this is not hypothetical. `process_observation` has TWO callers:
`poller.py`'s main loop and `bridges/ble.py`, which runs inside a `ble-bridge`
THREAD and opens its **own** `Database`:

    db = Database(db_path)  # OWN connection on its own path -- WAL second writer

`Database._lock` is a `threading.RLock` held per-INSTANCE, so it does **not**
serialise those two. The web UI is additionally a separate PROCESS on the same
file. #152's register entry claimed "only the poller emits escalations, so no
second writer exists today"; that was false and is retracted.

So the `UNIQUE(entry_id, generation)` constraint from migration 026 is not
belt-and-braces here — it is the only thing standing between two concurrent
handlers and two "this device appears to be following you" alerts for one
detection.

⭐ Every test here asserts the interleaving ACTUALLY HAPPENED (the barrier was
reached by both threads) before asserting the outcome. Without that, a pass can
mean "the race never occurred", which is what most concurrency tests silently
measure. See `a-concurrency-test-that-does-not-interleave-is-not-one`.
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
DAY = 86400


class Recorder(Notifier):
    def __init__(self):
        self.sent: list[str] = []
        self.lock = threading.Lock()

    def send(self, severity, title, message, priority_override=None) -> bool:
        with self.lock:
            self.sent.append(title)
        return True


def _obs(ts: int) -> DeviceObservation:
    return DeviceObservation(
        mac=MAC, device_type="wifi", first_seen=ts, last_seen=ts, rssi=-40,
        ssid=None, oui_vendor=None, is_randomized=False,
    )


@pytest.fixture
def primed(tmp_path):
    """A watchful entry sitting ONE counted sighting below the threshold.

    Built through the real helpers, then advanced with a direct UPDATE so the
    next observation from EITHER writer crosses. `last_seen_at` is pushed well
    back so the 24h debounce does not swallow the crossing sighting.
    """
    path = str(tmp_path / "race.db")
    db = Database(path)
    db.add_watchlist(pattern=MAC, pattern_type="mac", severity="high",
                     description="suspected tracker")
    db.upsert_device(mac=MAC, device_type="wifi", oui_vendor=None,
                     is_randomized=0, now_ts=T0)
    src = db.add_alert(ts=T0, rule_name="watchlisted mac", mac=MAC,
                       message="seen", severity="high",
                       rule_type="watchlist_mac")
    db.mark_alert_notified(src, now_ts=T0)
    entry_id = db.create_watchful_from_alert(src, None, T0)
    assert entry_id is not None, "fixture failed: no watchful entry"
    below = Database.WATCHFUL_RECURRENCE_ESCALATION_THRESHOLD - 1
    with db._lock, db._conn:
        db._conn.execute(
            "UPDATE watchful_recurrence SET sighting_count = ?, "
            "last_seen_at = ? WHERE id = ?",
            (below, T0, entry_id),
        )
    entry = db.get_watchful_recurrence(entry_id)
    assert entry.sighting_count == below and entry.escalated_at is None, (
        "fixture failed: the entry is not one sighting below the threshold"
    )
    ruleset = Ruleset(rules=[
        Rule(name="watchlisted mac", rule_type="watchlist_mac", severity="high")
    ])
    yield path, Config(db_path=path), ruleset, entry_id
    db.close()


def _escalation_rows(db):
    return db._conn.execute(
        "SELECT id, ts, notified_at FROM alerts "
        "WHERE rule_type='watchful_recurrence' ORDER BY id"
    ).fetchall()


def _ledger_rows(db):
    return db._conn.execute(
        "SELECT entry_id, generation FROM watchful_escalations "
        "ORDER BY generation"
    ).fetchall()


def test_two_connections_racing_the_reservation_produce_one_escalation(primed):
    """The constraint, driven directly, across two real connections.

    Both writers are inside `add_watchful_escalation_alert` at the same moment.
    Exactly one may come away with an alert id; the other must get None, and
    NOTHING may be written for it."""
    path, _config, _ruleset, entry_id = primed
    barrier = threading.Barrier(2, timeout=10)
    reached = []

    class _Barriered(Database):
        def add_watchful_escalation_alert(self, *a, **kw):
            reached.append(threading.current_thread().name)
            barrier.wait()
            return super().add_watchful_escalation_alert(*a, **kw)

    results: dict[str, object] = {}

    def writer(name):
        db = _Barriered(path)
        try:
            results[name] = db.add_watchful_escalation_alert(
                entry_id, 0, ts=T0 + DAY, mac=MAC,
                message="seen 4 times", severity="high",
            )
        except Exception as e:  # recorded, not swallowed
            results[name] = e
        finally:
            db.close()

    threads = [threading.Thread(target=writer, args=(n,), name=n)
               for n in ("poll-loop", "ble-bridge")]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)

    assert len(reached) == 2, (
        f"only {len(reached)} writer(s) reached the barrier, so the two never "
        "actually raced and this test proves nothing"
    )
    for name, value in results.items():
        assert not isinstance(value, Exception), (
            f"{name} raised instead of losing cleanly: {value!r}"
        )
    winners = [n for n, v in results.items() if v is not None]
    assert len(winners) == 1, (
        f"{len(winners)} writers each got an alert id ({results}); the UNIQUE "
        "constraint did not serialise them"
    )

    verify = Database(path)
    try:
        assert len(_escalation_rows(verify)) == 1, (
            "two concurrent writers produced "
            f"{len(_escalation_rows(verify))} escalation alerts for one "
            "detection -- the operator is told twice"
        )
        assert len(_ledger_rows(verify)) == 1, "two reservations for one generation"
    finally:
        verify.close()


def test_two_observation_handlers_crossing_together_emit_once(primed):
    """End to end: the poll loop and the bridge thread handle the SAME crossing.

    This is the shape that actually exists in the daemon -- two
    `process_observation` calls on separate `Database` objects -- rather than a
    hand-driven db call."""
    path, config, ruleset, entry_id = primed
    barrier = threading.Barrier(2, timeout=10)
    reached = []
    notifier = Recorder()
    errors: list[BaseException] = []

    class _Barriered(Database):
        def add_watchful_escalation_alert(self, *a, **kw):
            reached.append(threading.current_thread().name)
            barrier.wait()
            return super().add_watchful_escalation_alert(*a, **kw)

    def handler(name):
        db = _Barriered(path)
        try:
            process_observation(
                _obs(T0 + 5 * DAY), db, config, T0 + 5 * DAY,
                effective_location_id="home", effective_location_label="Home",
                ensured_locations=set(), processed_counter=[0],
                admitted_counter=[0], ruleset=ruleset, clock_trusted=True,
                allowlist=Allowlist(), notifier=notifier,
            )
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
        f"only {len(reached)} handler(s) reached the escalation write, so the "
        "two never raced; this test would pass for the wrong reason"
    )
    assert not errors, f"a handler raised: {errors!r}"

    verify = Database(path)
    try:
        rows = _escalation_rows(verify)
        assert len(rows) == 1, (
            f"the poll loop and the bridge thread emitted {len(rows)} "
            "escalations for one detection"
        )
        assert len(_ledger_rows(verify)) == 1
        assert len(notifier.sent) == 1, (
            f"the operator was told {len(notifier.sent)} times about one "
            "detection"
        )
        assert verify.get_watchful_recurrence(entry_id).escalated_at is not None, (
            "neither handler stamped the entry, so it stays eligible to "
            "re-emit forever"
        )
    finally:
        verify.close()


class _HoldTheCountingUpdate:
    """Connection proxy that pauses a writer between its SELECT and its UPDATE.

    ⚠️ Must forward `__enter__`/`__exit__` to the real connection, or the
    transaction the method relies on never happens and the test measures
    something else entirely.
    """

    def __init__(self, conn, reached, release):
        self._c = conn
        self._reached = reached
        self._release = release

    def __enter__(self):
        return self._c.__enter__()

    def __exit__(self, *e):
        return self._c.__exit__(*e)

    def execute(self, sql, *a, **kw):
        if sql.strip().startswith("UPDATE watchful_recurrence") and (
            "sighting_count + 1" in sql
        ):
            self._reached.set()
            self._release.wait(timeout=10)
        return self._c.execute(sql, *a, **kw)

    def __getattr__(self, n):
        return getattr(self._c, n)


def test_one_observation_cannot_be_counted_by_both_writers(primed):
    """⛔ The 24h debounce is a read-modify-write, and it has two writers.

    `record_watchful_sighting` SELECTs `last_seen_at`, computes the gap, and
    then UPDATEs. Keyed only on `id`, both the poll loop and the `ble-bridge`
    thread could read the same `last_seen_at`, both decide "counted", and both
    increment — one observation counted twice.

    ⚠️ The direction is the serious one: over-counting reaches the escalation
    threshold on fewer real recurrences than promised, i.e. a FABRICATED "this
    device appears to be following you". `poll_once` calls that unrecoverable.

    Measured before the fix: sequential +1, interleaved **+2**
    (`internal/session1-harnesses/f41_sighting_debounce_probe.py`).
    """
    path, _config, _ruleset, entry_id = primed
    at = T0 + 5 * DAY

    control = Database(path)
    try:
        base = control.get_watchful_recurrence(entry_id).sighting_count
        first = control.record_watchful_sighting(entry_id, at)
        second = control.record_watchful_sighting(entry_id, at)
        assert first.counted and not second.counted, (
            "control: the documented single-writer behaviour does not hold, so "
            "this test cannot attribute anything to the race"
        )
        assert (
            control.get_watchful_recurrence(entry_id).sighting_count == base + 1
        ), "control: sequential double-observation did not increment by exactly 1"
        # put it back so the treatment starts from the same state
        with control._lock, control._conn:
            control._conn.execute(
                "UPDATE watchful_recurrence SET sighting_count = ?, "
                "last_seen_at = ? WHERE id = ?",
                (base, T0, entry_id),
            )
    finally:
        control.close()

    reached, release = threading.Event(), threading.Event()
    outcomes: dict[str, object] = {}
    db_a, db_b = Database(path), Database(path)
    try:
        db_a._conn = _HoldTheCountingUpdate(db_a._conn, reached, release)

        def poll_loop():
            outcomes["a"] = db_a.record_watchful_sighting(entry_id, at)

        def ble_bridge():
            reached.wait(timeout=10)
            outcomes["b"] = db_b.record_watchful_sighting(entry_id, at)
            release.set()

        ta = threading.Thread(target=poll_loop, name="poll-loop")
        tb = threading.Thread(target=ble_bridge, name="ble-bridge")
        ta.start(), tb.start(), ta.join(timeout=25), tb.join(timeout=25)

        assert reached.is_set(), (
            "the first writer never reached its UPDATE, so the two never "
            "interleaved and this test would pass for the wrong reason"
        )
        assert "b" in outcomes, "the second writer never ran; nothing raced"
        counted = [k for k, v in outcomes.items() if getattr(v, "counted", False)]
        assert len(counted) == 1, (
            f"{len(counted)} writers counted the SAME observation ({outcomes}); "
            "the entry now escalates on fewer real recurrences than the "
            "operator was promised"
        )
        final = db_b.get_watchful_recurrence(entry_id).sighting_count
        assert final == base + 1, (
            f"one observation moved sighting_count by {final - base}, expected 1"
        )
    finally:
        db_a.close(), db_b.close()
