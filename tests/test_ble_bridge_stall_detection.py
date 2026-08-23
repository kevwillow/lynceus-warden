"""A BLE bridge thread that is ALIVE but scanning nothing is not "running".

`_observe_ble_bridge` graded the bridge on `thread.is_alive()` alone. That is a
liveness test for the *thread*, not for the *capture*, and the two come apart on
the one failure this bridge is built to survive:

    while not stop.is_set():
        try:
            await self._scan_until_stop(stop)
        except Exception as exc:      # bleak/BlueZ failure
            logger.warning("BLE scan failed (%s); restarting in %.0fs", ...)
            await asyncio.wait_for(stop.wait(), timeout=_RESTART_BACKOFF_SECONDS)

The restart-with-backoff loop is correct — an adapter that comes back should be
picked up without a daemon restart. But while it spins, the thread is alive
forever, `is_alive()` is True forever, the status is written "running" forever,
and `_compose_heartbeat` tells the operator "Still watching" while no BLE device
in the room is being seen. That is precisely the claim-health-you-have-not-
verified failure the heartbeat's own docstring forbids, and it is the same shape
as the dead-bridge case that clause 4 was added for — arriving through a path
`is_alive()` cannot see.

⚠️ The trap in fixing it is the opposite direction. A QUIET room is the normal
case for this tool: a bridge that scans perfectly and sees zero devices must
stay healthy. So the liveness signal cannot be "did an advert arrive" — it has
to be "is the scan loop still turning", which the tick flush provides whether or
not anything was buffered. `test_a_quiet_scan_is_still_alive` is the control
that pins that direction, and without it a fix that graded on device count would
pass every other test in this file.

⚠️ "not running" and "stalled" get SEPARATE sentences deliberately. An operator
told "the BLE bridge is not running" checks whether the process is up, finds it
up, and dismisses the warning — the true cause never gets named and the fault
survives the investigation.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import pytest

from lynceus.allowlist import Allowlist
from lynceus.bridges.ble import BleBridge
from lynceus.config import BleBridgeConfig, Config
from lynceus.db import Database
from lynceus.notify import NullNotifier
from lynceus.poller import (
    BLE_BRIDGE_FAILED,
    BLE_BRIDGE_RUNNING,
    BLE_BRIDGE_STALLED,
    STATE_KEY_BLE_BRIDGE_SCAN_TS,
    STATE_KEY_BLE_BRIDGE_STATUS,
    STATE_KEY_LAST_TICK_COMPLETED_AT,
    Poller,
    _compose_heartbeat,
    effective_ble_flush_interval,
)
from lynceus.rules import Ruleset

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "kismet_devices.json"


# --------------------------------------------------------------------------
# Layer 1 — does the BRIDGE publish a scan-liveness stamp, and only when the
# scan is genuinely up?
# --------------------------------------------------------------------------


class _FakeScanner:
    """Stands in for BleakScanner, which is not installed in this venv."""

    def __init__(self) -> None:
        self.started = False
        self.stopped = False

    async def start(self) -> None:
        self.started = True

    async def stop(self) -> None:
        self.stopped = True


def _bridge(tmp_path, db_path: str, *, flush_interval: float = 0.01) -> BleBridge:
    return BleBridge(
        db=Database(db_path),
        config=Config(db_path=str(tmp_path / "lynceus.db")),
        ruleset=Ruleset(),
        allowlist_provider=Allowlist,
        notifier=NullNotifier(),
        severity_overrides=None,
        location_id="default",
        location_label="Default Location",
        adapter="hci0",
        flush_interval=flush_interval,
    )


@pytest.fixture()
def bridge_db(tmp_path):
    """The bridge owns its connection and CLOSES it in run()'s finally, so the
    assertions have to read the same file through a second handle rather than
    the one the bridge just shut."""
    path = str(tmp_path / "bridge.db")
    db = Database(path)
    db.ensure_location("default", "Default Location")
    db.close()
    yield path


def _stamp(path: str) -> str | None:
    db = Database(path)
    try:
        return db.get_state(STATE_KEY_BLE_BRIDGE_SCAN_TS)
    finally:
        db.close()


def test_a_quiet_scan_is_still_alive(tmp_path, bridge_db, monkeypatch):
    """⭐ THE CONTROL. Zero adverts, zero devices, scanner working perfectly.

    A fix that stamped liveness on advert arrival, or on flush COUNT, would
    report a stalled bridge for every operator in a quiet room — which is most
    of them, most of the time. The stamp has to come from the scan loop
    turning, not from the room being busy.
    """
    import lynceus.bridges.ble as ble_mod

    monkeypatch.setattr(ble_mod, "_BLEAK_IMPORT_ERROR", None)
    bridge = _bridge(tmp_path, bridge_db)
    monkeypatch.setattr(bridge, "_make_scanner", _FakeScanner)

    asyncio.run(bridge.run(duration=0.12))

    raw = _stamp(bridge_db)
    assert raw, "a working scan recorded no liveness stamp at all"
    assert abs(int(time.time()) - int(raw)) <= 5


def test_a_failing_scan_never_records_liveness(tmp_path, bridge_db, monkeypatch):
    """THE DEFECT. Every scan attempt raises; the thread stays alive and retries.

    Nothing may advance the stamp on this path, or the poller has no way to
    tell this apart from a healthy bridge.
    """
    import lynceus.bridges.ble as ble_mod

    monkeypatch.setattr(ble_mod, "_BLEAK_IMPORT_ERROR", None)
    bridge = _bridge(tmp_path, bridge_db)

    async def always_fails(self, stop):
        raise OSError("[org.bluez.Error.NotReady] Resource Not Ready")

    monkeypatch.setattr(ble_mod.BleBridge, "_scan_until_stop", always_fails, raising=True)

    asyncio.run(bridge.run(duration=0.05))

    assert not _stamp(bridge_db), (
        "a bridge whose every scan raised recorded itself as scanning"
    )


def test_an_unavailable_bleak_never_records_liveness(tmp_path, bridge_db, monkeypatch):
    """The other never-scans path: the flag is on but bleak is not installed."""
    import lynceus.bridges.ble as ble_mod

    monkeypatch.setattr(ble_mod, "_BLEAK_IMPORT_ERROR", ImportError("no bleak"))
    bridge = _bridge(tmp_path, bridge_db)

    asyncio.run(bridge.run(duration=0.05))

    assert not _stamp(bridge_db)


# --------------------------------------------------------------------------
# Layer 2 — does the POLLER grade on that stamp rather than on is_alive()?
# --------------------------------------------------------------------------


class _LiveThread:
    def is_alive(self) -> bool:
        return True


class _DeadThread:
    def is_alive(self) -> bool:
        return False


def _poller(tmp_path, **ble):
    ble.setdefault("enabled", True)
    return Poller(
        Config(
            kismet_fixture_path=str(FIXTURE_PATH),
            db_path=str(tmp_path / "lynceus.db"),
            location_id="testloc",
            location_label="Test Location",
            ble_bridge=BleBridgeConfig(**ble),
        )
    )


def _graded(poller, thread) -> str | None:
    poller._observe_ble_bridge(thread)
    return poller.db.get_state(STATE_KEY_BLE_BRIDGE_STATUS)


def test_the_stall_window_is_derived_from_the_flush_interval(tmp_path):
    """Not an invented tolerance: the bridge stamps once per flush, so the
    window is the same 2x-the-refresh-interval convention `_compose_heartbeat`
    already uses for poll-tick staleness."""
    assert effective_ble_flush_interval(_poller(tmp_path, flush_interval=30).config) == 30
    # Unset flush_interval falls back to the poll interval, exactly as
    # _start_ble_bridge computes it — one derivation, not two.
    poller = _poller(tmp_path)
    assert effective_ble_flush_interval(poller.config) == poller.config.poll_interval_seconds


def test_a_live_thread_with_a_fresh_stamp_is_running(tmp_path):
    """The PERMIT half. Without this, "always stalled" passes the guard below."""
    poller = _poller(tmp_path, flush_interval=30)
    poller.db.set_state(STATE_KEY_BLE_BRIDGE_SCAN_TS, str(int(time.time())))
    assert _graded(poller, _LiveThread()) == BLE_BRIDGE_RUNNING


def test_a_live_thread_whose_scan_stopped_is_stalled(tmp_path):
    """THE GUARD. is_alive() is True and the bridge has captured nothing for
    twenty minutes; the old code wrote "running" here."""
    poller = _poller(tmp_path, flush_interval=30)
    poller.db.set_state(STATE_KEY_BLE_BRIDGE_SCAN_TS, str(int(time.time()) - 1200))
    assert _graded(poller, _LiveThread()) == BLE_BRIDGE_STALLED


def test_a_stamp_dated_in_the_future_is_stalled_not_fresh(tmp_path):
    """`now - stamp` on a clock that jumped BACKWARDS is negative, and a bare
    `age > window` reads that as "extremely recent" and reports healthy — the
    exact defect `_compose_heartbeat`'s clause 1 already carries a guard for.
    Same shape, so the same `0 <= age` bound, not a second opinion about it."""
    poller = _poller(tmp_path, flush_interval=30)
    poller.db.set_state(STATE_KEY_BLE_BRIDGE_SCAN_TS, str(int(time.time()) + 90_000))
    assert _graded(poller, _LiveThread()) == BLE_BRIDGE_STALLED


def test_a_corrupt_stamp_does_not_read_as_healthy(tmp_path):
    poller = _poller(tmp_path, flush_interval=30)
    poller.db.set_state(STATE_KEY_BLE_BRIDGE_SCAN_TS, "not-a-timestamp")
    poller._ble_bridge_started_at = int(time.time()) - 10_000
    assert _graded(poller, _LiveThread()) == BLE_BRIDGE_STALLED


def test_a_bridge_still_warming_up_is_not_reported_stalled(tmp_path):
    """A freshly started bridge has not reached its first flush yet. Grading it
    stalled would fire a false alarm on every single daemon start."""
    poller = _poller(tmp_path, flush_interval=30)
    poller._ble_bridge_started_at = int(time.time())
    assert _graded(poller, _LiveThread()) == BLE_BRIDGE_RUNNING


def test_a_bridge_that_never_reached_its_first_scan_is_stalled(tmp_path):
    """Warm-up grace is bounded. A bridge that has never once stamped, long
    after start, never came up at all."""
    poller = _poller(tmp_path, flush_interval=30)
    poller._ble_bridge_started_at = int(time.time()) - 3600
    assert _graded(poller, _LiveThread()) == BLE_BRIDGE_STALLED


def test_a_dead_thread_is_still_failed_not_stalled(tmp_path):
    """The pre-existing case must keep its own verdict AND its own sentence."""
    poller = _poller(tmp_path, flush_interval=30)
    poller.db.set_state(STATE_KEY_BLE_BRIDGE_SCAN_TS, str(int(time.time())))
    assert _graded(poller, _DeadThread()) == BLE_BRIDGE_FAILED


def test_a_disabled_bridge_writes_nothing(tmp_path):
    """The default install. Absent stays absent — a permanent warning about a
    feature nobody turned on is one the operator learns to ignore."""
    poller = _poller(tmp_path, enabled=False)
    assert _graded(poller, _LiveThread()) is None


# --------------------------------------------------------------------------
# Layer 3 — does the operator get told, in words that name the right cause?
# --------------------------------------------------------------------------


def test_the_heartbeat_is_unhealthy_when_the_bridge_has_stalled(tmp_path):
    db = Database(str(tmp_path / "hb.db"))
    try:
        db.ensure_location("default", "Default")
        db.set_state(STATE_KEY_LAST_TICK_COMPLETED_AT, str(int(time.time())))
        db.set_state(STATE_KEY_BLE_BRIDGE_STATUS, BLE_BRIDGE_STALLED)
        healthy, message = _compose_heartbeat(
            db, Config(db_path=str(tmp_path / "hb.db")), now_ts=int(time.time())
        )
        assert healthy is False, (
            "the heartbeat reported healthy while the BLE bridge had stopped "
            "scanning — trackers in range would not be seen and nothing said so"
        )
        assert "Kismet capture is unaffected" in message
    finally:
        db.close()


def test_stalled_and_failed_do_not_share_one_sentence(tmp_path):
    """Two causes, two remedies. "not running" sends the operator to check
    whether the process is up; for a stalled bridge it IS up, they find nothing
    wrong, and they stop trusting the warning."""
    cfg = Config(db_path=str(tmp_path / "hb.db"))
    messages = {}
    for status in (BLE_BRIDGE_FAILED, BLE_BRIDGE_STALLED):
        db = Database(str(tmp_path / f"hb-{status}.db"))
        try:
            db.ensure_location("default", "Default")
            db.set_state(STATE_KEY_LAST_TICK_COMPLETED_AT, str(int(time.time())))
            db.set_state(STATE_KEY_BLE_BRIDGE_STATUS, status)
            messages[status] = _compose_heartbeat(db, cfg, now_ts=int(time.time()))[1]
        finally:
            db.close()
    assert messages[BLE_BRIDGE_FAILED] != messages[BLE_BRIDGE_STALLED]
    assert "not running" in messages[BLE_BRIDGE_FAILED]
    assert "not running" not in messages[BLE_BRIDGE_STALLED]
