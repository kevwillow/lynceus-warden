"""Two clock-jump defects that round 7's sweep did not cover.

Round 7 gated the *destructive* clock-driven operations -- the retention and
evidence prunes, the snooze cleanup. Both bugs pinned here survived it because
neither is a delete:

  * `record_watchful_sighting` is a state-ADVANCING write. It fabricates
    recurrence evidence on a forward jump and then freezes real counting for
    the length of the jump.
  * `maybe_emit_heartbeat` deliberately fails toward sending, which is correct,
    but a forward jump leaves a permanent future anchor and every subsequent
    corrected tick sends again.

⭐ Every test here asserts on OBSERVED STATE -- counts, timestamps, delivery
tallies -- rather than on the presence of a gate. A test that greps for
`if clock_trusted:` passes just as happily when the gate is moved somewhere it
does nothing; these fail unless the harm is actually absent.
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
    maybe_emit_heartbeat,
    process_observation,
)

NOW = 1_700_000_000
DAY = 86_400
MAC = "aa:bb:cc:dd:ee:01"


# --------------------------------------------------------------------------
# watchful recurrence
# --------------------------------------------------------------------------


@pytest.fixture()
def wdb(tmp_path):
    db = Database(str(tmp_path / "w.db"))
    db.ensure_location("home", "Home")
    yield db
    db.close()


@pytest.fixture()
def minimal_config(tmp_path):
    """The shipped ruleset path, so this exercises the real pipeline shape."""
    return Config(db_path=str(tmp_path / "w.db"), rules_path="config/rules.yaml")


def _seed_watchful(db, *, ts=NOW) -> int:
    db.upsert_device(
        mac=MAC, device_type="wifi", oui_vendor=None, is_randomized=0, now_ts=ts
    )
    db.insert_sighting(mac=MAC, ts=ts, rssi=-40, ssid=None, location_id="home")
    alert_id = db.add_alert(
        ts=ts, rule_name="r", mac=MAC, message="m", severity="high"
    )
    return db.create_watchful_from_alert(alert_id, None, ts)


def _row(db, entry_id: int) -> dict:
    return dict(
        db._conn.execute(
            "SELECT sighting_count, last_seen_at, escalated_at "
            "FROM watchful_recurrence WHERE id = ?",
            (entry_id,),
        ).fetchone()
    )


def _observe(db, config, ruleset, notifier, *, ts, clock_trusted):
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
        config,
        ts,
        effective_location_id="home",
        effective_location_label="Home",
        ensured_locations={"home"},
        processed_counter=[0],
        admitted_counter=[0],
        ruleset=ruleset,
        allowlist=_EmptyAllowlist(),
        notifier=notifier,
        clock_trusted=clock_trusted,
    )


class _EmptyAllowlist:
    def is_allowed(self, obs, *, now_ts=None):
        return None


class _Ruleset:
    """No rules: this suite is about recurrence bookkeeping, not alerting."""

    rules = ()

    def evaluate(self, *a, **k):
        return []


class _Notifier:
    def __init__(self):
        self.sends = []

    def send(self, *a, **k):
        self.sends.append((a, k))
        return True

    def __getattr__(self, name):
        return self.send


def test_an_untrusted_clock_cannot_manufacture_a_recurrence(wdb, minimal_config):
    """The +24h jump that used to invent a sighting must now change nothing.

    Measured before the gate existed: sighting_count went 1 -> 2 and
    `counted` was True, on a clock that had not really advanced a day.
    """
    entry_id = _seed_watchful(wdb)
    before = _row(wdb, entry_id)

    _observe(
        wdb,
        minimal_config,
        _Ruleset(),
        _Notifier(),
        ts=NOW + DAY,
        clock_trusted=False,
    )

    assert _row(wdb, entry_id) == before, (
        "a jumped clock advanced watchful recurrence state; a fabricated "
        "count walks the entry toward a false 'you are being followed' "
        "escalation"
    )


def test_an_untrusted_clock_cannot_freeze_future_counting(wdb, minimal_config):
    """The harm that outlives the jump: a future `last_seen_at`.

    Measured before the gate: a +91d jump wrote last_seen_at 91 days ahead,
    after which genuine sightings stopped counting until day 92 -- the tool
    goes silent about a device that really is following the operator, which is
    strictly worse than the fabricated count.
    """
    entry_id = _seed_watchful(wdb)
    _observe(
        wdb,
        minimal_config,
        _Ruleset(),
        _Notifier(),
        ts=NOW + 91 * DAY,
        clock_trusted=False,
    )

    assert _row(wdb, entry_id)["last_seen_at"] <= NOW, (
        "watchful last_seen_at was written into the future"
    )

    # The clock is corrected. A real sighting a day later must still count.
    _observe(
        wdb,
        minimal_config,
        _Ruleset(),
        _Notifier(),
        ts=NOW + DAY,
        clock_trusted=True,
    )
    assert _row(wdb, entry_id)["sighting_count"] == 2, (
        "recurrence counting stayed frozen after the clock was corrected"
    )


def test_a_trusted_clock_still_counts_normally(wdb, minimal_config):
    """The gate must not be a blanket off-switch.

    ⚠️ Without this, deleting the whole watchful block passes the two tests
    above -- the commonest way a guard proves nothing.
    """
    entry_id = _seed_watchful(wdb)
    _observe(
        wdb,
        minimal_config,
        _Ruleset(),
        _Notifier(),
        ts=NOW + DAY,
        clock_trusted=True,
    )
    assert _row(wdb, entry_id)["sighting_count"] == 2
    assert _row(wdb, entry_id)["last_seen_at"] == NOW + DAY


def test_clock_trusted_is_required_and_has_no_default():
    """A caller that has not considered clock trust must not compile.

    The BLE bridge fed `int(time.time())` into this path with no anchor at
    all; a permissive default is exactly what let that go unnoticed.
    """
    import inspect

    param = inspect.signature(process_observation).parameters["clock_trusted"]
    assert param.default is inspect.Parameter.empty, (
        "clock_trusted acquired a default; a new caller can now inherit the "
        "unsafe value by omission"
    )
    assert param.kind is inspect.Parameter.KEYWORD_ONLY


def test_the_ble_bridge_forms_its_own_clock_opinion():
    """The bridge flushes off its own wall-clock read, so it needs its own
    anchor -- it cannot borrow the Poller's, and passing a literal True would
    reopen the defect through the second door."""
    import ast

    src = Path(__file__).resolve().parents[1] / "src/lynceus/bridges/ble.py"
    tree = ast.parse(src.read_text())
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if getattr(node.func, "id", "") != "process_observation":
            continue
        kw = {k.arg: k.value for k in node.keywords}
        assert "clock_trusted" in kw, "bridge call lost its clock_trusted argument"
        assert not isinstance(kw["clock_trusted"], ast.Constant), (
            "the bridge passes a constant for clock_trusted, so a jumped "
            "clock reaches watchful recurrence through the BLE path"
        )
        break
    else:
        pytest.fail("no process_observation call found in ble.py")


# --------------------------------------------------------------------------
# heartbeat future anchor
# --------------------------------------------------------------------------


class _HbConfig:
    heartbeat_enabled = True
    heartbeat_interval_hours = 24
    heartbeat_topic = "t"
    heartbeat_priority = None
    ntfy_topic = "t"
    ntfy_server = "s"


def test_a_forward_jump_costs_at_most_one_extra_heartbeat(tmp_path):
    """The comment promised "one notification"; the code sent one per tick.

    Measured before the clamp: 300 corrected 60s ticks produced 300 sends,
    because the future row won `MAX(notified_at)` forever. Extrapolated over a
    91-day excursion at a 60s poll interval: ~131,040 deliveries.
    """
    db = Database(str(tmp_path / "h.db"))
    notifier = _Notifier()
    cfg = _HbConfig()

    maybe_emit_heartbeat(db, cfg, notifier, now_ts=NOW)
    assert len(notifier.sends) == 1, "the first heartbeat should arm the switch"

    maybe_emit_heartbeat(db, cfg, notifier, now_ts=NOW + 91 * DAY)  # the jump
    after_jump = len(notifier.sends)

    for i in range(1, 301):  # clock corrected; 300 real ticks
        maybe_emit_heartbeat(db, cfg, notifier, now_ts=NOW + 7200 + i * 60)

    assert len(notifier.sends) == after_jump, (
        f"{len(notifier.sends) - after_jump} heartbeats sent across 300 "
        "corrected ticks; a future anchor is still winning the interval "
        "comparison"
    )
    db.close()


def test_the_dead_mans_switch_still_fires_after_the_excursion(tmp_path):
    """⚠️ The clamp must not buy quiet by breaking the guarantee.

    Suppressing the heartbeat is the failure it exists to remove: an operator
    reads silence as "the daemon is dead". Once a real interval elapses, it
    must send.
    """
    db = Database(str(tmp_path / "h.db"))
    notifier = _Notifier()
    cfg = _HbConfig()

    maybe_emit_heartbeat(db, cfg, notifier, now_ts=NOW)
    maybe_emit_heartbeat(db, cfg, notifier, now_ts=NOW + 91 * DAY)
    baseline = len(notifier.sends)

    maybe_emit_heartbeat(db, cfg, notifier, now_ts=NOW + DAY + 60)
    assert len(notifier.sends) == baseline + 1, (
        "the heartbeat went silent after a clock excursion; the dead-man's "
        "switch must fail toward sending"
    )
    db.close()


def test_the_web_ui_still_sees_the_unclamped_truth(tmp_path):
    """An operator diagnosing a clock problem needs the bad timestamp shown.

    The clamp belongs to scheduling only -- pinned because "sanitise it
    everywhere" is the obvious wrong generalisation of this fix.
    """
    db = Database(str(tmp_path / "h.db"))
    hb_id = db.insert_heartbeat(ts=NOW + 91 * DAY, healthy=True, message="m")
    db.mark_heartbeat_notified(hb_id, now_ts=NOW + 91 * DAY)

    assert db.latest_delivered_heartbeat_ts() == NOW + 91 * DAY
    assert db.latest_delivered_heartbeat_ts(not_after=NOW) is None
    db.close()


class _DownNotifier:
    """ntfy unreachable: nothing is ever delivered, so `last_delivered` stays
    None and scheduling falls back to composition time."""

    def send(self, *a, **k):
        return False

    def __getattr__(self, name):
        return self.send


def test_the_undelivered_path_does_not_storm_either(tmp_path):
    """The second door, found only because a planted defect went uncaught.

    The delivered-reference clamp does nothing here: with a down topic nothing
    is ever delivered, so scheduling falls back to the newest heartbeat ROW --
    and after a jump that row is future-dated.

    ⚠️ Both obvious fallbacks are wrong and this test rejects both. Using
    `latest["ts"]` unclamped gives a negative elapsed and sends every tick;
    falling back to None means "never sent one, send promptly", which composes
    a brand-new row every tick and defeats the bounded retry. Measured at 200
    new rows across 200 corrected ticks for each.

    The retry counter advances once per TICK, so the jump must come after
    attempts are spent -- otherwise the retry branch returns before scheduling
    is reached and the future row is never composed at all.
    """
    db = Database(str(tmp_path / "h.db"))
    cfg = _HbConfig()
    notifier = _DownNotifier()

    def count():
        return db._conn.execute("SELECT COUNT(*) c FROM heartbeats").fetchone()["c"]

    for i in range(5):  # spend the four attempts on the first row
        maybe_emit_heartbeat(db, cfg, notifier, now_ts=NOW + i * 60)
    maybe_emit_heartbeat(db, cfg, notifier, now_ts=NOW + 91 * DAY)  # the jump
    for i in range(1, 9):  # let the future row spend its attempts too
        maybe_emit_heartbeat(db, cfg, notifier, now_ts=NOW + 7200 + i * 60)

    baseline = count()
    for i in range(9, 209):
        maybe_emit_heartbeat(db, cfg, notifier, now_ts=NOW + 7200 + i * 60)

    assert count() == baseline, (
        f"composed {count() - baseline} heartbeat rows across 200 corrected "
        "ticks; a future-dated row is still driving scheduling"
    )
    db.close()


class _FlakyNotifier:
    def __init__(self):
        self.up = True
        self.calls = 0

    def send(self, *a, **k):
        self.calls += 1
        return self.up

    def __getattr__(self, name):
        return self.send


def _down_topic_run(tmp_path, *, jump):
    """Deliver one heartbeat, drop the topic, optionally jump, then run 200
    corrected ticks. Returns (rows composed, delivery attempts)."""
    db = Database(str(tmp_path / f"h{int(jump)}.db"))
    cfg = _HbConfig()
    n = _FlakyNotifier()

    def rows():
        return db._conn.execute("SELECT COUNT(*) c FROM heartbeats").fetchone()["c"]

    maybe_emit_heartbeat(db, cfg, n, now_ts=NOW)
    n.up = False
    if jump:
        maybe_emit_heartbeat(db, cfg, n, now_ts=NOW + 91 * DAY)
        for i in range(4):  # spend the future row's attempts
            maybe_emit_heartbeat(db, cfg, n, now_ts=NOW + 91 * DAY + i * 60)

    base_rows, base_calls = rows(), n.calls
    for i in range(1, 201):
        maybe_emit_heartbeat(db, cfg, n, now_ts=NOW + DAY + 7200 + i * 60)
    out = (rows() - base_rows, n.calls - base_calls)
    db.close()
    return out


def test_a_future_row_does_not_shadow_the_retry_candidate(tmp_path):
    """A clock jump must make NO difference to delivery behaviour.

    ⭐ Asserted as an A/B against the no-jump baseline rather than against an
    absolute count. `latest_heartbeat` orders by `ts DESC`, so a heartbeat
    composed during a jump stays "most recent" after correction and shadows
    every genuinely-newest row in retry selection; its own attempts being spent,
    each tick falls through and composes another row that is shadowed in turn.
    Measured before the bound: 197 rows and 200 attempts across 200 corrected
    ticks, one attempt per row -- the bounded retry completely defeated.

    ⚠️ Both arms compose some rows: with a permanently down topic and an
    overdue interval the scheduler composes afresh once attempts are spent.
    That is pre-existing, has nothing to do with clocks, and is exactly why the
    baseline is the right comparand -- an absolute assertion here would either
    encode that behaviour as intended or fail whenever it is tuned.
    """
    jumped = _down_topic_run(tmp_path, jump=True)
    baseline = _down_topic_run(tmp_path, jump=False)

    assert jumped == baseline, (
        f"a clock jump changed delivery behaviour: {jumped} rows/attempts vs "
        f"{baseline} without one; a future-dated row is still shadowing the "
        "retry candidate"
    )


# --------------------------------------------------------------------------
# the heartbeat's own invariant: never claim health it has not verified
# --------------------------------------------------------------------------


def _health(tmp_path, *, admitted, src=0, rssi=0, unparseable=0, tick=True):
    from lynceus.config import Config
    from lynceus.poller import (
        STATE_KEY_LAST_TICK_ADMITTED,
        STATE_KEY_LAST_TICK_COMPLETED_AT,
        STATE_KEY_LAST_TICK_DROPPED_MIN_RSSI,
        STATE_KEY_LAST_TICK_DROPPED_SOURCE_ALLOWLIST,
        STATE_KEY_LAST_TICK_DROPPED_UNPARSEABLE,
        _compose_heartbeat,
    )

    db = Database(str(tmp_path / f"c{admitted}{src}{rssi}{unparseable}{int(tick)}.db"))
    cfg = Config(
        db_path=str(tmp_path / "c.db"),
        rules_path="config/rules.yaml",
        heartbeat_enabled=True,
    )
    if tick:
        db.set_state(STATE_KEY_LAST_TICK_COMPLETED_AT, str(NOW))
    db.set_state(STATE_KEY_LAST_TICK_ADMITTED, str(admitted))
    db.set_state(STATE_KEY_LAST_TICK_DROPPED_SOURCE_ALLOWLIST, str(src))
    db.set_state(STATE_KEY_LAST_TICK_DROPPED_MIN_RSSI, str(rssi))
    db.set_state(STATE_KEY_LAST_TICK_DROPPED_UNPARSEABLE, str(unparseable))
    out = _compose_heartbeat(db, cfg, now_ts=NOW + 60)
    db.close()
    return out


def test_a_blind_daemon_does_not_report_itself_healthy(tmp_path):
    """`_compose_heartbeat`'s docstring names one invariant:

        "this must never claim health it has not verified. A heartbeat that
        says 'all good' while ingest is dead is strictly worse than no
        heartbeat at all."

    Measured on main, it did exactly that: a tick where the source allowlist
    discarded all 412 devices Kismet reported returned healthy=True with the
    message "Still watching. 0 device sighting(s) in the last 24h" -- byte for
    byte what a genuinely quiet site receives. Found by session 2bb4a6a3.
    """
    healthy, message = _health(tmp_path, admitted=0, src=412)
    assert healthy is False, "claimed health while discarding every device"
    assert "412" in message and "source allowlist" in message, (
        f"the operator is not told WHY they are blind: {message!r}"
    )


def test_every_discard_reason_counts(tmp_path):
    """⚠️ Not just the source allowlist. Any reason that discards everything
    leaves the operator equally blind, and pinning only the measured one is how
    a guard ends up matching a single rendering of the problem."""
    for kwargs, needle in (
        ({"rssi": 88}, "min_rssi"),
        ({"unparseable": 9}, "unparseable"),
    ):
        healthy, message = _health(tmp_path, admitted=0, **kwargs)
        assert healthy is False, f"{needle}: claimed health while blind"
        assert needle in message


def test_a_quiet_site_is_still_healthy(tmp_path):
    """⭐ The whole point of the threshold. `admitted == 0` alone must NOT be a
    fault -- a quiet RF environment is normal, and crying wolf about it trains
    the operator to ignore the one channel that matters. The signal is
    contradiction (devices reported AND all discarded), never silence."""
    healthy, message = _health(tmp_path, admitted=0)
    assert healthy is True, f"a quiet site was reported as a fault: {message!r}"
    assert "Still watching" in message


def test_a_working_filter_is_not_a_fault(tmp_path):
    """Dropping most devices while admitting some is the filter doing its job."""
    healthy, _ = _health(tmp_path, admitted=7, src=400)
    assert healthy is True


def test_a_malformed_counter_cannot_take_the_heartbeat_down(tmp_path):
    """This function is what REPORTS faults, so it has to survive them."""
    from lynceus.config import Config
    from lynceus.poller import (
        STATE_KEY_LAST_TICK_ADMITTED,
        STATE_KEY_LAST_TICK_COMPLETED_AT,
        STATE_KEY_LAST_TICK_DROPPED_SOURCE_ALLOWLIST,
        _compose_heartbeat,
    )

    db = Database(str(tmp_path / "bad.db"))
    cfg = Config(
        db_path=str(tmp_path / "bad.db"),
        rules_path="config/rules.yaml",
        heartbeat_enabled=True,
    )
    db.set_state(STATE_KEY_LAST_TICK_COMPLETED_AT, str(NOW))
    db.set_state(STATE_KEY_LAST_TICK_ADMITTED, "not-a-number")
    db.set_state(STATE_KEY_LAST_TICK_DROPPED_SOURCE_ALLOWLIST, "")
    healthy, message = _compose_heartbeat(db, cfg, now_ts=NOW + 60)
    assert isinstance(healthy, bool) and message
    db.close()


# --------------------------------------------------------------------------
# a capture source's clock is not our clock
# --------------------------------------------------------------------------


def _sighting_ts(db, mac=MAC):
    return [r["ts"] for r in db._conn.execute(
        "SELECT ts FROM sightings WHERE mac = ? ORDER BY ts", (mac,)
    )]


def _observe_at(db, config, notifier, *, source_ts, now_ts):
    """Feed an observation whose SOURCE timestamp differs from our clock."""
    process_observation(
        DeviceObservation(
            mac=MAC,
            device_type="wifi",
            first_seen=source_ts,
            last_seen=source_ts,
            rssi=-40,
            ssid=None,
            oui_vendor=None,
            is_randomized=False,
        ),
        db,
        config,
        now_ts,
        effective_location_id="home",
        effective_location_label="Home",
        ensured_locations={"home"},
        processed_counter=[0],
        admitted_counter=[0],
        ruleset=_Ruleset(),
        allowlist=_EmptyAllowlist(),
        notifier=notifier,
        clock_trusted=True,
    )


def test_a_future_source_timestamp_cannot_outlive_retention(wdb, minimal_config):
    """`DeviceObservation` bounds `last_seen` below and NOT above.

    Measured against the real parser: `last_time` of 0, -5 and 1 are all
    REJECTED, but 4102444800 (year 2100) is ACCEPTED and written straight into
    `sightings.ts`. End to end, before the clamp:

        stored        : [1693088000, 4102444800]
        30-day prune  : deleted=1, remaining=[4102444800]
        seen last 24h : 1

    ⚠️ The prune deleted the LEGITIMATE 40-day-old row and kept the bogus one.
    Found by session 2bb4a6a3's round 9 sweep.
    """
    year_2100 = 4102444800
    _observe_at(wdb, minimal_config, _Notifier(), source_ts=year_2100, now_ts=NOW)

    stored = _sighting_ts(wdb)
    assert stored, "the observation was dropped; a real detection must survive"
    assert max(stored) <= NOW, (
        f"a future sighting timestamp reached the database: {stored}. It would "
        "never be pruned and would satisfy every recent-window query forever."
    )

    # And it must actually be pruneable: 30 days later, it is gone.
    cutoff = NOW + 30 * DAY
    wdb._conn.execute("DELETE FROM sightings WHERE ts < ?", (cutoff,))
    wdb._conn.commit()
    assert _sighting_ts(wdb) == [], "the clamped row still resisted retention"


def test_the_detection_is_kept_not_discarded(wdb, minimal_config):
    """⭐ Clamping, not rejecting. The device really was seen -- only the
    source's opinion of when is wrong -- and for a stalking-detection tool,
    discarding a real detection is the worse error.

    ⚠️ Without this, "fixing" the bug by dropping the observation entirely
    passes the test above.
    """
    _observe_at(wdb, minimal_config, _Notifier(), source_ts=4102444800, now_ts=NOW)
    assert _sighting_ts(wdb) == [NOW], (
        "the observation should be recorded at our clock, not dropped"
    )


def test_an_honest_source_timestamp_is_left_alone(wdb, minimal_config):
    """The clamp must not rewrite timestamps that are merely slightly stale.

    A sighting a few minutes old is normal -- capture sources batch, and the
    poll tick lags the observation. Only the future is impossible.
    """
    slightly_old = NOW - 600
    _observe_at(wdb, minimal_config, _Notifier(), source_ts=slightly_old, now_ts=NOW)
    assert _sighting_ts(wdb) == [slightly_old], (
        "a legitimate recent timestamp was rewritten"
    )


def test_the_clamp_cannot_bound_our_own_clock(wdb, minimal_config):
    """⛔ The documented LIMIT of the clamp, pinned so it is visible.

    The clamp bounds a capture SOURCE's clock against OUR clock. It cannot
    bound our clock against itself: when both are wrong, the sighting is
    recorded at the jumped `now_ts`, and a future-dated sighting is once again
    immune to retention.

    Measured — source says year 2100, our clock has jumped +91d:

        sightings = [NOW, NOW+91d]

    ⭐ This is strictly better than the unclamped behaviour (year 2100 rather
    than +91d) and strictly worse than correct. The general fix is the open
    question of what ALL observation persistence should do on an untrusted
    clock — a blanket `clock_trusted` gate is the wrong answer there, because
    it would discard real capture data, which is the one thing this tool must
    not do. Recorded here so the next person finds the boundary in a test
    rather than in production.

    ⚠️ If this test starts failing because sightings are now bounded by
    something better than `now_ts`, that is progress: delete it and say so.
    """
    _observe_at(
        wdb, minimal_config, _Notifier(), source_ts=4102444800, now_ts=NOW + 91 * DAY
    )
    stored = _sighting_ts(wdb)
    assert stored == [NOW + 91 * DAY], (
        f"expected the jumped now_ts to be recorded, got {stored}"
    )
    assert max(stored) < 4102444800, (
        "the source's absurd timestamp reached the database; the clamp is not "
        "working at all"
    )
