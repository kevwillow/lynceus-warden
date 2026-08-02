"""Local-only tests for BLE bridge wiring into the Poller daemon lifecycle.

tests/ is gitignored — never committed. The scan is mocked; no adapter/bleak
required. Verifies the flag-gated, additive behavior: OFF (default) starts no
bridge; ON starts a thread that stops + joins cleanly and closes its OWN
Database on shutdown.
"""

from __future__ import annotations

import sqlite3
import threading
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
