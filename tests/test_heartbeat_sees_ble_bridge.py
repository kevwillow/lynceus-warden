"""The heartbeat must notice when the BLE bridge has died.

The heartbeat exists for one reason: to make silence mean something. Its
docstring says it "must never claim health it has not verified".

⚠️ Every clause it had watched the KISMET path — tick recency, the persist
watermark, undelivered alerts. None of them observed the BLE bridge, and
`is_alive()` appeared exactly once in poller.py, in the shutdown join. So the
bridge could die at startup (adapter unplugged or renamed) or mid-run (thread
crash), Kismet polling would carry on normally, and the heartbeat would keep
reporting "still watching" while every BLE-only device — the trackers and tags
this tool exists to find — went unseen until someone restarted the daemon.

🪤 The trap in fixing it is the opt-in default. `ble_bridge.enabled` is False on
a normal install, so a naive "bridge not running -> unhealthy" check would make
every default install report a fault forever, and an operator who sees a
permanent warning learns to ignore the channel. Absent status therefore means
"never enabled" and stays silent; only enabled-then-dead is a problem.
"""

from __future__ import annotations

import pytest

from lynceus.config import Config
from lynceus.db import Database
from lynceus.poller import (
    BLE_BRIDGE_FAILED,
    BLE_BRIDGE_RUNNING,
    BLE_BRIDGE_STOPPED,
    STATE_KEY_BLE_BRIDGE_STATUS,
    STATE_KEY_LAST_TICK_COMPLETED_AT,
    _compose_heartbeat,
)

NOW = 1_700_000_000


@pytest.fixture()
def db(tmp_path):
    database = Database(str(tmp_path / "hb.db"))
    database.ensure_location("default", "Default")
    # A healthy baseline: a tick has just completed, nothing else is wrong.
    database.set_state(STATE_KEY_LAST_TICK_COMPLETED_AT, str(NOW))
    yield database
    database.close()


@pytest.fixture()
def config(tmp_path):
    return Config(db_path=str(tmp_path / "hb.db"))


def _health(db, config):
    healthy, message = _compose_heartbeat(db, config, now_ts=NOW)
    return healthy, message


# --- presence assertions --------------------------------------------------
# Without these, "unhealthy when the bridge is dead" is equally satisfied by a
# heartbeat that reports unhealthy always, which would be a worse defect than
# the one under test and would look identical in a single-case check.


def test_healthy_when_the_bridge_was_never_enabled(db, config):
    """The DEFAULT install. No status key has ever been written."""
    healthy, message = _health(db, config)
    assert healthy is True, f"a default install reported unhealthy: {message}"
    assert "BLE bridge" not in message


def test_healthy_when_the_bridge_is_running(db, config):
    db.set_state(STATE_KEY_BLE_BRIDGE_STATUS, BLE_BRIDGE_RUNNING)

    healthy, message = _health(db, config)

    assert healthy is True, message
    assert "BLE bridge" not in message


def test_healthy_after_a_clean_shutdown(db, config):
    """"stopped" is an orderly stop, not a fault. Without this the next start
    would inherit a stale verdict about a process that has already ended."""
    db.set_state(STATE_KEY_BLE_BRIDGE_STATUS, BLE_BRIDGE_STOPPED)

    healthy, _ = _health(db, config)

    assert healthy is True


# --- the guard ------------------------------------------------------------


def test_unhealthy_when_the_bridge_has_died(db, config):
    """The measured gap: everything else looks fine, so the heartbeat used to
    say "still watching" while BLE capture was dead."""
    db.set_state(STATE_KEY_BLE_BRIDGE_STATUS, BLE_BRIDGE_FAILED)

    healthy, message = _health(db, config)

    assert healthy is False, (
        "the heartbeat reported healthy while the BLE bridge was dead — "
        "trackers in range would not be seen and nothing would say so"
    )
    assert "BLE bridge is not running" in message


def test_the_message_says_kismet_is_unaffected(db, config):
    """An operator reading "the BLE bridge is not running" needs to know
    whether they have lost everything or one path. Saying so is the difference
    between an actionable warning and an alarming one."""
    db.set_state(STATE_KEY_BLE_BRIDGE_STATUS, BLE_BRIDGE_FAILED)

    _, message = _health(db, config)

    assert "Kismet capture is unaffected" in message


def test_a_dead_bridge_is_reported_alongside_other_problems(db, config):
    """The clause must add to the problem list, not replace it. A fix that
    returned early on the first problem would hide the others."""
    db.set_state(STATE_KEY_BLE_BRIDGE_STATUS, BLE_BRIDGE_FAILED)
    db.set_state(STATE_KEY_LAST_TICK_COMPLETED_AT, str(NOW - 100_000))

    healthy, message = _health(db, config)

    assert healthy is False
    assert "BLE bridge is not running" in message
    assert "no poll tick" in message
