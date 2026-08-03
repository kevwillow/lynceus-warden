"""The scanner teardown race, and why it must not reach the restart path.

Measured 2026-08-03 against bleak 3.0.2 on BlueZ 5.72, over roughly fourteen
consecutive passive scans: ``BleakScanner.stop()`` raises

    BleakDBusError [org.bluez.Error.DoesNotExist] Does Not Exist

on the **normal** teardown path, when BlueZ has already discarded the
AdvertisementMonitor. ``pyproject.toml`` pins ``bleak>=0.22,<4.0``, so an
operator installing today gets 3.0.2 and hits this on every scan stop.

``_scan_until_stop`` used ``async with scanner:``, so that raised out of
``__aexit__`` into the caller's ``except Exception`` at ble.py:478 — which logs
"BLE scan failed (...); restarting in 5s" and sleeps. A clean shutdown reported
a failure that never happened, and any real error in the same cycle would be
masked behind this one.

⛔ The fix must stay narrow. Swallowing every stop() exception would hide a
genuinely broken teardown, which is why the tests below pin BOTH directions:
this one D-Bus error is tolerated, everything else still propagates.

bleak is not installed in the project venv, so the exception is reproduced
structurally — bleak's ``BleakDBusError`` carries the error name on a
``dbus_error`` attribute, verified against 3.0.2.
"""

from __future__ import annotations

import asyncio

import pytest

from lynceus.allowlist import Allowlist
from lynceus.bridges.ble import BleBridge, _is_monitor_already_gone
from lynceus.config import Config
from lynceus.db import Database
from lynceus.notify import NullNotifier
from lynceus.rules import Ruleset


class _FakeDBusError(Exception):
    """Shaped like bleak.exc.BleakDBusError, which we cannot import here."""

    def __init__(self, dbus_error: str, details: str = "") -> None:
        super().__init__(f"[{dbus_error}] {details}")
        self.dbus_error = dbus_error
        self.dbus_error_details = details


class _Scanner:
    def __init__(self, raise_on_stop: Exception | None = None) -> None:
        self.raise_on_stop = raise_on_stop
        self.stopped = False

    async def stop(self) -> None:
        self.stopped = True
        if self.raise_on_stop is not None:
            raise self.raise_on_stop


@pytest.fixture
def bridge(tmp_path):
    db = Database(":memory:")
    config = Config(db_path=str(tmp_path / "lynceus.db"))
    b = BleBridge(
        db=db,
        config=config,
        ruleset=Ruleset(),
        allowlist_provider=lambda: Allowlist(),
        notifier=NullNotifier(),
        severity_overrides=None,
        location_id="default",
        location_label="Default Location",
        adapter="hci1",
        flush_interval=60,
    )
    yield b
    db.close()


# --- recognising the one error we tolerate -----------------------------------


def test_the_bluez_monitor_race_is_recognised():
    exc = _FakeDBusError("org.bluez.Error.DoesNotExist", "Does Not Exist")
    assert _is_monitor_already_gone(exc) is True


def test_another_bluez_error_is_not_recognised():
    """A monitor that failed to unregister is a real problem, not a race."""
    assert _is_monitor_already_gone(_FakeDBusError("org.bluez.Error.Failed")) is False


def test_a_not_ready_adapter_is_not_recognised():
    """NotReady means the adapter died under us — that must still surface."""
    assert _is_monitor_already_gone(_FakeDBusError("org.bluez.Error.NotReady")) is False


def test_a_plain_exception_is_not_recognised():
    assert _is_monitor_already_gone(RuntimeError("boom")) is False


def test_a_lookalike_message_without_the_attribute_is_not_recognised():
    """Match the D-Bus error NAME, not the text of the message.

    A string search for "DoesNotExist" would swallow any exception whose
    message happened to quote it, including one raised by our own code.
    """
    assert _is_monitor_already_gone(RuntimeError("org.bluez.Error.DoesNotExist")) is False


# --- the teardown itself ------------------------------------------------------


def test_stop_scanner_swallows_the_teardown_race(bridge):
    scanner = _Scanner(_FakeDBusError("org.bluez.Error.DoesNotExist", "Does Not Exist"))
    asyncio.run(bridge._stop_scanner(scanner))  # must not raise
    assert scanner.stopped is True


def test_stop_scanner_reraises_a_real_failure(bridge):
    scanner = _Scanner(_FakeDBusError("org.bluez.Error.NotReady", "Resource Not Ready"))
    with pytest.raises(Exception) as excinfo:
        asyncio.run(bridge._stop_scanner(scanner))
    assert excinfo.value.dbus_error == "org.bluez.Error.NotReady"


def test_stop_scanner_reraises_a_non_dbus_failure(bridge):
    scanner = _Scanner(RuntimeError("boom"))
    with pytest.raises(RuntimeError, match="boom"):
        asyncio.run(bridge._stop_scanner(scanner))


def test_stop_scanner_is_quiet_on_a_clean_stop(bridge):
    scanner = _Scanner()
    asyncio.run(bridge._stop_scanner(scanner))
    assert scanner.stopped is True


def test_the_swallowed_race_is_still_logged(bridge, caplog):
    """Tolerated is not invisible — it must leave a trace to debug from."""
    scanner = _Scanner(_FakeDBusError("org.bluez.Error.DoesNotExist", "Does Not Exist"))
    with caplog.at_level("DEBUG", logger="lynceus.bridges.ble"):
        asyncio.run(bridge._stop_scanner(scanner))
    assert any("DoesNotExist" in r.getMessage() for r in caplog.records)
