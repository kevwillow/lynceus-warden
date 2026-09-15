"""Local-only tests for BLE bridge wiring into the Poller daemon lifecycle.

The scan is mocked; no adapter/bleak required. (This file IS tracked — it is
`tests/test_ble_bridge.py` that .gitignore withholds, not this one. An earlier
version of this docstring said "tests/ is gitignored — never committed", which
would have told anyone adding a regression test here that it could never reach
CI.) Verifies the flag-gated, additive behavior: OFF (default) starts no
bridge; ON starts a thread that stops + joins cleanly and closes its OWN
Database on shutdown.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from lynceus.config import BleBridgeConfig, Config
from lynceus.poller import Poller

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "kismet_devices.json"


def _cfg(tmp_path, **ble):
    return Config(
        kismet_fixture_path=str(FIXTURE_PATH),
        db_path=str(tmp_path / "lynceus.db"),
        location_id="testloc",
        location_label="Test Location",
        ble_bridge=BleBridgeConfig(**ble),
    )


def test_default_flag_off():
    assert Config().ble_bridge.enabled is False


def test_flush_interval_validation_rejects_non_positive():
    with pytest.raises(ValueError):
        BleBridgeConfig(flush_interval=0)


def test_flag_off_does_not_start_bridge(tmp_path, mocker):
    poller = Poller(_cfg(tmp_path))  # default: disabled
    spy = mocker.spy(poller, "_start_ble_bridge")
    poller._stop_flag = True  # zero poll iterations; straight to finally
    poller.run_forever()
    spy.assert_not_called()


def test_flag_on_starts_stops_joins_and_closes_db(tmp_path, monkeypatch):
    import lynceus.bridges.ble as ble_mod

    monkeypatch.setattr(ble_mod, "_BLEAK_IMPORT_ERROR", None)

    async def fake_scan(self, stop):
        await stop.wait()

    monkeypatch.setattr(ble_mod.BleBridge, "_scan_until_stop", fake_scan, raising=True)

    poller = Poller(_cfg(tmp_path, enabled=True))
    created: dict = {}
    orig = poller._start_ble_bridge

    def spy_start():
        bridge, thread = orig()
        created["bridge"] = bridge
        created["thread"] = thread
        return bridge, thread

    monkeypatch.setattr(poller, "_start_ble_bridge", spy_start)

    poller._stop_flag = True  # run_forever starts the bridge then tears it down
    poller.run_forever()

    assert "bridge" in created  # the bridge was actually started
    created["thread"].join(timeout=5)
    assert not created["thread"].is_alive()  # stopped + joined cleanly
    # The bridge's OWN Database connection was closed on shutdown.
    with pytest.raises(sqlite3.ProgrammingError):
        created["bridge"].db._conn.execute("SELECT 1")


def test_run_once_does_not_start_bridge(tmp_path, mocker):
    poller = Poller(_cfg(tmp_path, enabled=True))
    spy = mocker.spy(poller, "_start_ble_bridge")
    poller.run_once()
    spy.assert_not_called()


def _ble_ready(monkeypatch):
    """Make the bridge startable without a real adapter."""
    import lynceus.bridges.ble as ble_mod

    monkeypatch.setattr(ble_mod, "_BLEAK_IMPORT_ERROR", None)

    async def fake_scan(self, stop):
        await stop.wait()

    monkeypatch.setattr(ble_mod.BleBridge, "_scan_until_stop", fake_scan, raising=True)


def test_a_failed_bridge_status_write_does_not_take_down_the_daemon(tmp_path, monkeypatch):
    """⛔ The compensating write shared the failure domain of the failure it compensates.

    The bridge fails to start (no adapter). The handler then records that fact
    with ``set_state(FAILED)`` -- into the SAME database, which is the thing
    that is unavailable. SPEC_unit_of_work.md §4a calls ``database is locked``
    "the normal steady state of the default deployment", because the web UI and
    the bridge write this file from their own connections.

    That second raise escaped ``run_forever`` BEFORE the poll loop's protective
    ``try``. ``main()`` catches it and returns 1, and
    ``systemd/lynceus.service`` sets ``Restart=on-failure`` / ``RestartSec=5s``
    -- so an OPTIONAL add-on's failure handler crash-looped the daemon every
    five seconds and took Kismet polling, the primary function, down with it.
    On a full disk, permanently.
    """
    from lynceus.poller import BLE_BRIDGE_FAILED

    poller = Poller(_cfg(tmp_path, enabled=True))

    def no_adapter():
        raise RuntimeError("no BLE adapter")

    monkeypatch.setattr(poller, "_start_ble_bridge", no_adapter)

    real_set_state = poller.db.set_state
    attempted: list[str] = []

    def failing_set_state(key, value):
        if value == BLE_BRIDGE_FAILED:
            attempted.append(value)
            raise sqlite3.OperationalError("database is locked")
        return real_set_state(key, value)

    monkeypatch.setattr(poller.db, "set_state", failing_set_state)

    poller._stop_flag = True
    poller.run_forever()  # ⛔ must NOT raise -- this is the whole assertion

    # ⛔ The write was genuinely attempted. A "fix" that simply stopped
    # recording the status would pass the line above while destroying the
    # observability this handler exists to provide.
    assert attempted == [BLE_BRIDGE_FAILED]


def test_a_bridge_that_started_is_still_stopped_when_its_status_write_fails(
    tmp_path, monkeypatch
):
    """⛔ The opposite direction: do not trade a crash for an orphan.

    The handler set ``bridge, bridge_thread = None, None`` -- discarding the
    only handles to a thread that was ALREADY RUNNING, so ``_stop_ble_bridge``
    got ``None`` and could not drain it. The daemon then polls on with a live
    scanner the database reports as FAILED.
    """
    from lynceus.poller import BLE_BRIDGE_RUNNING

    _ble_ready(monkeypatch)
    poller = Poller(_cfg(tmp_path, enabled=True))

    created: dict = {}
    orig = poller._start_ble_bridge

    def spy_start():
        bridge, thread = orig()
        created["bridge"], created["thread"] = bridge, thread
        return bridge, thread

    monkeypatch.setattr(poller, "_start_ble_bridge", spy_start)

    real_set_state = poller.db.set_state

    def failing_status(key, value):
        if value == BLE_BRIDGE_RUNNING:  # only the RUNNING write fails here
            raise sqlite3.OperationalError("database is locked")
        return real_set_state(key, value)

    monkeypatch.setattr(poller.db, "set_state", failing_status)

    poller._stop_flag = True
    poller.run_forever()

    assert "thread" in created, "the bridge really did start"
    created["thread"].join(timeout=5)
    assert not created["thread"].is_alive(), (
        "the bridge started but its handles were discarded, so shutdown could "
        "not stop it -- a live scanner the daemon has lost track of"
    )


def test_a_raise_while_logging_the_start_cannot_orphan_a_scanning_thread(
    tmp_path, monkeypatch
):
    """⛔ Same class, third site: inside the helper, between start and return.

    The caller's only handle to the thread exists once ``_start_ble_bridge``
    RETURNS. Anything raisable between ``thread.start()`` and that return
    leaves a scanner running that nobody holds -- and a logging handler writing
    to a closed pipe is enough (``BrokenPipeError``). The fix logs first, so a
    raise here happens while the thread is still unstarted.
    """
    import threading

    import lynceus.poller as poller_mod

    _ble_ready(monkeypatch)
    poller = Poller(_cfg(tmp_path, enabled=True))

    def exploding_info(*a, **k):
        raise BrokenPipeError("stdout closed")

    monkeypatch.setattr(poller_mod.logger, "info", exploding_info)

    before = {t for t in threading.enumerate() if t.name == "ble-bridge"}
    with pytest.raises(BrokenPipeError):
        poller._start_ble_bridge()
    after = {t for t in threading.enumerate() if t.name == "ble-bridge"}

    orphans = [t for t in after - before if t.is_alive()]
    assert not orphans, (
        "a BLE scanner thread is running and nothing holds a handle to it: "
        f"{orphans}"
    )
