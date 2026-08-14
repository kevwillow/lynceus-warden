"""The poll watermark, and the observations it can silently lose.

⭐ Why this file exists. `poll_once` ends by writing `last_poll_ts = now_ts`,
and the next tick asks Kismet for devices seen since that value. A device is
therefore re-fetchable only while its `last_seen` is at or after the watermark.
Advancing unconditionally -- which is what the code did -- means any
observation that failed to persist is never asked for again:

    device last seen at 1699999995; tick ran at 1700000000
    after poll 1: persisted=['01']  watermark=1700000000
    after poll 2: asked Kismet since=1700000000 -> returned NOTHING
    DOOMED recovered: False

That is the normal case, not a contrived one: Kismet reports devices seen
*during* the window and the watermark is set to the window's END, so nearly
every observation has a `last_seen` older than the tick that processes it. A
device that appears once -- a car with an ALPR driving past -- during a
transient DB failure leaves no alert, no row, and one WARNING line.

⛔ The obvious fix is wrong. "Hold the watermark until everything persists"
means a record that fails every time freezes it forever, and the daemon
re-fetches the same window indefinitely: alive, and permanently blind. That is
the A1 poison-record livelock, and the unconditional advance was the defence
against it. Both extremes lose capture data; the bound is the design.

⚠️ `tests/test_poller.py` is one of the ten files withheld from the repo (it
embeds the rig's own adapter MAC), so this behaviour has no coverage at all in
a clone. These tests are deliberately written against the public API only.
"""

from __future__ import annotations

import logging
from unittest.mock import patch

import pytest

from lynceus.allowlist import Allowlist
from lynceus.config import Config
from lynceus.db import Database
from lynceus.kismet import DeviceObservation
from lynceus.notify import RecordingNotifier
from lynceus.poller import (
    POLL_WATERMARK_MAX_HOLDS,
    STATE_KEY_LAST_POLL,
    poll_once,
)
from lynceus.rules import Ruleset

_T = 1_700_000_000
#: Five seconds before the tick that processes it. This offset is the whole
#: point: with `last_seen == now_ts` the device survives an unconditional
#: advance by luck, which is exactly how a naive test of this would pass
#: against broken code.
_SEEN_AT = _T - 5

_GOOD = "aa:bb:cc:dd:ee:01"
_DOOMED = "aa:bb:cc:dd:ee:02"


def _obs(mac: str, ts: int) -> DeviceObservation:
    return DeviceObservation(
        mac=mac,
        device_type="wifi",
        first_seen=ts,
        last_seen=ts,
        rssi=-40,
        ssid=None,
        oui_vendor="Acme",
        is_randomized=False,
    )


class _Kismet:
    """Devices seen once at `_SEEN_AT` and never again.

    The boundary is inclusive (`last_seen >= since`), which is the MOST
    generous reading of Kismet's `/devices/last-time` semantics. If the real
    endpoint is strictly-greater the loss is worse, never better, so a test
    that passes here passes there.
    """

    def __init__(self, macs):
        self.macs = macs
        self.queries: list[int] = []

    def get_devices_since(self, since, **_kw):
        self.queries.append(since)
        return [o for o in (_obs(m, _SEEN_AT) for m in self.macs) if o.last_seen >= since]


class _KismetStillInRange:
    """A device that keeps being seen, tick after tick.

    ⚠️ Needed wherever a test must fail the SAME device across ticks that are
    not all held. `_Kismet` reports one sighting at `_SEEN_AT`, so as soon as
    the watermark advances normally the device falls out of the window and
    cannot fail again -- which silently turns such a test into an assertion
    about nothing.
    """

    def __init__(self, mac):
        self.mac = mac
        self.queries: list[int] = []

    def get_devices_since(self, since, **_kw):
        self.queries.append(since)
        # last_seen tracks "now-ish" so the device is always in the window.
        return [_obs(self.mac, max(since, _SEEN_AT))]


@pytest.fixture
def env(tmp_path):
    db = Database(str(tmp_path / "w.db"))
    config = Config(db_path=str(tmp_path / "w.db"))
    yield db, config
    db.close()


def _tick(client, db, config, ts):
    poll_once(
        client,
        db,
        config,
        ts,
        ruleset=Ruleset(),
        allowlist=Allowlist(),
        notifier=RecordingNotifier(),
    )


def _macs(db):
    return {d["mac"] for d in db.list_devices()}


def test_a_transient_persist_failure_is_retried_not_lost(env):
    """⭐ THE regression test. One device fails to persist while the DB
    hiccups; the DB recovers on the next tick and the device must come back."""
    db, config = env
    client = _Kismet([_GOOD, _DOOMED])
    real = db.upsert_device

    def flaky(mac, *a, **kw):
        if mac == _DOOMED:
            raise RuntimeError("database is locked")
        return real(mac, *a, **kw)

    with patch.object(db, "upsert_device", side_effect=flaky):
        _tick(client, db, config, _T)
    assert _macs(db) == {_GOOD}, "the healthy device should still have persisted"

    # DB healthy again.
    _tick(client, db, config, _T + 60)
    assert _DOOMED in _macs(db), (
        "the failed observation was never re-fetched -- the watermark advanced "
        "past its last_seen and Kismet will never be asked for that window again"
    )


def test_the_retry_window_covers_the_failed_device(env):
    """The watermark must land at or below the failed device's `last_seen`.
    Asserting the mechanism, not just the outcome, so a fix that happens to
    work for the fixture's timing but not in general still fails here."""
    db, config = env
    client = _Kismet([_DOOMED])

    def always_fail(*_a, **_kw):
        raise RuntimeError("database is locked")

    with patch.object(db, "upsert_device", side_effect=always_fail):
        _tick(client, db, config, _T)

    watermark = int(db.get_state(STATE_KEY_LAST_POLL))
    assert watermark <= _SEEN_AT, (
        f"watermark {watermark} is past the failed device's last_seen {_SEEN_AT}; "
        "it will not be re-fetched"
    )


def test_a_permanently_failing_record_does_not_livelock(env, caplog):
    """⛔ The other half, and the reason the naive fix is wrong.

    A record that fails on every tick must not freeze the watermark. Left
    unbounded the daemon stays alive and re-fetches the same window forever --
    permanently blind to everything after it, which is far worse than losing
    the one record."""
    db, config = env
    client = _Kismet([_DOOMED])

    def always_fail(*_a, **_kw):
        raise RuntimeError("poison record")

    with caplog.at_level(logging.ERROR, logger="lynceus.poller"):
        with patch.object(db, "upsert_device", side_effect=always_fail):
            for i in range(POLL_WATERMARK_MAX_HOLDS + 2):
                _tick(client, db, config, _T + i * 60)

    watermark = int(db.get_state(STATE_KEY_LAST_POLL))
    assert watermark >= _T, (
        f"watermark stuck at {watermark}: the poll loop is livelocked on a "
        "record that cannot be persisted"
    )
    # Giving up is a permanent hole in detection coverage, so it must be loud
    # enough for an operator to find. Nothing else reports it.
    assert any("giving up" in r.message.lower() for r in caplog.records), (
        "capture data was dropped permanently and nothing said so at ERROR"
    )


def test_holds_are_bounded_to_the_configured_maximum(env):
    """Pins the bound itself. Off-by-one here means either one fewer retry
    than intended, or an extra tick of blindness per poison record."""
    db, config = env
    client = _Kismet([_DOOMED])

    def always_fail(*_a, **_kw):
        raise RuntimeError("poison record")

    held = 0
    with patch.object(db, "upsert_device", side_effect=always_fail):
        for i in range(POLL_WATERMARK_MAX_HOLDS + 1):
            _tick(client, db, config, _T + i * 60)
            if int(db.get_state(STATE_KEY_LAST_POLL)) <= _SEEN_AT:
                held += 1
    assert held == POLL_WATERMARK_MAX_HOLDS, (
        f"held the watermark {held} times, expected {POLL_WATERMARK_MAX_HOLDS}"
    )


def test_a_clean_tick_resets_the_hold_counter(env):
    """Otherwise the budget is consumed for the daemon's lifetime: three
    unrelated hiccups hours apart would leave the next real failure with no
    retries at all."""
    db, config = env
    # A device that STAYS in range, so it can fail again after a clean tick.
    client = _KismetStillInRange(_DOOMED)
    real = db.upsert_device
    state = {"fail": True}

    def sometimes(mac, *a, **kw):
        if state["fail"]:
            raise RuntimeError("database is locked")
        return real(mac, *a, **kw)

    with patch.object(db, "upsert_device", side_effect=sometimes):
        # Spend the entire hold budget.
        for i in range(POLL_WATERMARK_MAX_HOLDS):
            _tick(client, db, config, _T + i * 60)
        state["fail"] = False
        _tick(client, db, config, _T + POLL_WATERMARK_MAX_HOLDS * 60)  # clean -> reset
        state["fail"] = True
        before = int(db.get_state(STATE_KEY_LAST_POLL))
        _tick(client, db, config, _T + (POLL_WATERMARK_MAX_HOLDS + 1) * 60)

    after = int(db.get_state(STATE_KEY_LAST_POLL))
    # With the budget restored this failure is hold 1 of N, so the watermark is
    # pulled BACK. Without the reset the budget was already spent and it would
    # advance instead, abandoning the device on its first failure.
    assert after < before, (
        "the hold counter did not reset on a clean tick, so this failure got no "
        "retry at all -- three unrelated hiccups would exhaust the budget for "
        "the daemon's lifetime"
    )


def test_a_clean_tick_advances_the_watermark_normally(env):
    """The common path must be untouched: no failures, no holding."""
    db, config = env
    client = _Kismet([_GOOD])
    _tick(client, db, config, _T)
    assert int(db.get_state(STATE_KEY_LAST_POLL)) == _T
    assert _macs(db) == {_GOOD}
