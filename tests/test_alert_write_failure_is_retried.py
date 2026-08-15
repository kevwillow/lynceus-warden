"""A confirmed hit must not be lost because the alert row failed to write.

The rule has already MATCHED: a watchlisted device is in range and the operator
has not been told yet. Everything after that point is the money path.

`process_observation` used to catch any exception from `db.add_alert`, log a
warning and `continue` to the next hit. The device and sighting rows were
written just above it, so the tick completed and looked entirely normal.

Measured before the fix, with `add_alert` raising sqlite's "database is locked"
against a real fixture device:

    healthy : 5 devices, 5 sightings, 1 alert, 1 notification
    failing : 5 devices, 5 sightings, 0 alerts, 0 notifications, holds = 0

⭐ `holds = 0` is what made it permanent. The watermark advanced past the
window, so Kismet was never asked for it again and the hit could not return on
a later tick. "database is locked" is an ordinary event on a Pi with an SD card,
and the optional BLE bridge writing concurrently makes it likelier.

The fix raises instead, handing the failure to the persist-retry path
`poll_once` already has (`failed_last_seen`), which holds the watermark and
retries the window — bounded by POLL_WATERMARK_MAX_HOLDS so a genuinely
poisonous record still cannot livelock the daemon.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from lynceus.config import Config
from lynceus.db import Database
from lynceus.kismet import FakeKismetClient
from lynceus.poller import STATE_KEY_WATERMARK_HOLDS, poll_once
from lynceus.rules import Rule, Ruleset

FIXTURE = Path(__file__).parent / "fixtures" / "kismet_devices.json"
MAC = "a4:83:e7:11:22:33"
#: ⚠️ Chosen to sit AFTER the target device's last_time (1_700_000_100) so the
#: watermark decision actually discriminates. With NOW *before* it, the device
#: is inside the window on every poll regardless of whether the watermark was
#: held, and the retry test passes even with the defect planted — measured.
NOW = 1_700_000_150


class _Recorder:
    def __init__(self):
        self.calls = []

    def send(self, severity, title, message, priority_override=None):
        self.calls.append(title)
        return True


@pytest.fixture()
def env(tmp_path):
    cfg = Config(db_path=str(tmp_path / "a.db"), kismet_fixture_path=str(FIXTURE))
    db = Database(cfg.db_path)
    db.ensure_location("default", "Default")
    db.add_watchlist(pattern=MAC, pattern_type="mac", severity="high", description="tracker")
    ruleset = Ruleset(
        rules=[Rule(name="tracker", rule_type="watchlist_mac", severity="high", enabled=True)]
    )
    yield cfg, db, FakeKismetClient(str(FIXTURE)), ruleset
    db.close()


def _alerts(db) -> int:
    return db._conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]


def _break_add_alert(db):
    def boom(*a, **k):
        raise sqlite3.OperationalError("database is locked")

    real = db.add_alert
    db.add_alert = boom
    return real


# --- presence assertion ---------------------------------------------------
# Without this, "the hit survives a failure" is equally satisfied by a poller
# that alerts twice on every tick, or by one whose watchlist never matches at
# all — both of which would look identical in the failure case alone.


def test_a_healthy_tick_alerts_exactly_once(env):
    cfg, db, client, ruleset = env
    notifier = _Recorder()

    poll_once(client, db, cfg, NOW, ruleset=ruleset, notifier=notifier)

    assert _alerts(db) == 1
    assert len(notifier.calls) == 1
    assert (db.get_state(STATE_KEY_WATERMARK_HOLDS) or "0") == "0"


# --- the guard ------------------------------------------------------------


def test_an_alert_write_failure_is_recorded_as_a_persist_failure(env):
    """It must reach the machinery that holds the watermark. Silently moving
    past the window is what made the loss permanent."""
    cfg, db, client, ruleset = env
    _break_add_alert(db)

    poll_once(client, db, cfg, NOW, ruleset=ruleset, notifier=_Recorder())

    assert _alerts(db) == 0
    assert int(db.get_state(STATE_KEY_WATERMARK_HOLDS) or "0") >= 1, (
        "an alert write failed and nothing recorded it — the watermark will "
        "advance past the window and the confirmed hit is gone for good"
    )


def test_the_hit_still_reaches_the_operator_on_the_retry(env):
    """The whole point. A transient lock must cost a tick, not the alert."""
    cfg, db, client, ruleset = env
    real = _break_add_alert(db)
    notifier = _Recorder()

    poll_once(client, db, cfg, NOW, ruleset=ruleset, notifier=notifier)
    assert _alerts(db) == 0 and notifier.calls == []

    db.add_alert = real  # the lock clears
    poll_once(client, db, cfg, NOW + 60, ruleset=ruleset, notifier=notifier)

    assert _alerts(db) == 1, "the confirmed hit never came back after the retry"
    assert notifier.calls == ["lynceus: HIGH alert"]


# --- the limitation, pinned ------------------------------------------------


def test_a_new_device_alert_is_NOT_recovered_by_the_retry(env):
    """⛔ KNOWN LIMITATION of the fix above, pinned so it cannot rot.

    `new_non_randomized_device` fires only the first time a device is seen. The
    device row is written by `upsert_device` BEFORE the alert write, so once the
    alert write fails the device is already known — and on the retry the rule
    correctly does not fire again. The retry recovers watchlist hits; it does
    not recover first-sighting alerts.

    Measured: control fires 2 new-device alerts; with the alert write failing on
    the first tick, 0 fire and 0 are recovered by the retry.

    Fixing this properly means either ordering the alert write before the device
    write, or carrying "this device was new" across the retry. Both are larger
    changes than this one, and both risk the device row being lost instead —
    which is worse, because device identity is what every later sighting hangs
    off. Recorded rather than rushed.

    ⇒ If you make the retry recover these, this test fails. That is the intent:
    come here, read this, and delete it as part of the fix.
    """
    cfg, db, client, ruleset = env
    new_dev_rules = Ruleset(
        rules=[
            Rule(
                name="newdev",
                rule_type="new_non_randomized_device",
                severity="med",
                enabled=True,
            )
        ]
    )
    real = _break_add_alert(db)

    poll_once(client, db, cfg, NOW, ruleset=new_dev_rules, notifier=_Recorder())
    assert _alerts(db) == 0

    db.add_alert = real
    poll_once(client, db, cfg, NOW + 60, ruleset=new_dev_rules, notifier=_Recorder())

    assert _alerts(db) == 0, (
        "a new-device alert was recovered by the retry — if that is deliberate, "
        "the limitation documented here is fixed and this test should go"
    )
