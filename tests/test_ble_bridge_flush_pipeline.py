"""The BLE bridge's handoff into the alert pipeline.

⭐ Why this file exists. The bridge's parts are all covered — the Continuity
decoder, the ODID decoder, the advert callback, the buffer's privacy
guarantees, the OR-pattern scan args, teardown races, and the Poller's
start/stop lifecycle. What nothing covered is the ONE line that connects them
to the product: `_flush` calling `process_observation`.

Delete or break that call and every existing BLE test stays green while every
BLE detection silently stops. Adverts are still received, decoded, and
buffered; the buffer is still drained on schedule; the bridge thread still
runs and shuts down cleanly. No device row is written, no rule is evaluated,
no alert fires, and nothing anywhere says so — the operator sees a healthy
bridge reporting decoded adverts on /settings and simply never gets told about
anything it heard.

That is the same failure class as the delivery defect in Wave 5 Finding 12:
the pipeline's last step failing quietly, in a tool where silence reads as
safety.

⚠️ `tests/test_ble_bridge.py` is one of the ten files withheld from the repo
(it embeds the rig's own adapter MAC), so a clone has no coverage of `_flush`
at all — the only tracked mention is a config-validation test for
`flush_interval`, which never calls the method.
"""

from __future__ import annotations

import pytest

from lynceus.allowlist import Allowlist
from lynceus.bridges.ble import BleBridge, _BufferEntry
from lynceus.config import Config
from lynceus.db import Database
from lynceus.notify import RecordingNotifier
from lynceus.rules import Rule, Ruleset

_MAC = "c0:ff:ee:00:11:22"
_NOW = 1_700_000_000
#: Flock Safety's registered prefix is not needed here; any watchlisted OUI
#: proves the rule path. The MAC is locally-administered so it also exercises
#: the randomized-address derivation.
_UUID = "0000fd6f-0000-1000-8000-00805f9b34fb"


@pytest.fixture
def bridge(tmp_path):
    """A bridge wired exactly as the Poller wires it, minus the radio."""
    db = Database(str(tmp_path / "ble.db"))
    config = Config(db_path=str(tmp_path / "ble.db"))
    notifier = RecordingNotifier()
    ruleset = Ruleset(
        rules=[
            Rule(
                name="ble_uuid_watch",
                rule_type="ble_uuid",
                severity="high",
                patterns=[_UUID],
                description="a service UUID on the watchlist",
            )
        ]
    )
    b = BleBridge(
        db=db,
        config=config,
        ruleset=ruleset,
        # `Allowlist` itself satisfies the Callable[[], Allowlist] contract and
        # constructs a fresh empty one per call, exactly as the lambda did.
        # Flagged by CodeQL (py/unnecessary-lambda) on this PR.
        allowlist_provider=Allowlist,
        notifier=notifier,
        severity_overrides=None,
        location_id=config.location_id,
        location_label=config.location_label,
        adapter="hci0",
        flush_interval=1.0,
    )
    yield b, db, notifier
    db.close()


def _buffer_one(b, *, uuids=(_UUID,)):
    """Put one decoded advert in the buffer, as the scan callback would."""
    b._buffer[_MAC] = _BufferEntry(
        first_seen=_NOW,
        last_seen=_NOW,
        rssi=-55,
        manufacturer_ids=(),
        service_uuids=tuple(uuids),
    )


def test_a_buffered_advert_reaches_device_sighting_alert_and_notifier(bridge):
    """⭐ The whole chain in one assertion set: callback → buffer → flush →
    device → rule → alert → notification. This is the test whose absence let
    the handoff go unguarded."""
    b, db, notifier = bridge
    _buffer_one(b)

    flushed = b._flush(_NOW)

    assert flushed == 1, "the buffered advert was not handed to the pipeline"
    macs = {d["mac"] for d in db.list_devices()}
    assert _MAC in macs, "no device row: the advert never reached process_observation"

    alerts = db.list_alerts()
    assert alerts, "the advert persisted but raised no alert despite matching a rule"
    assert alerts[0]["mac"] == _MAC
    assert alerts[0]["severity"] == "high"

    assert notifier.calls, "an alert was written but the operator was never notified"
    severity, title, _message = notifier.calls[0]
    assert severity == "high"
    assert "HIGH" in title


def test_the_device_is_stored_as_ble_not_wifi(bridge):
    """`device_type` must be "ble" or the BLE-specific fields are blanked on
    the way through, which would make the UUID matchers permanently inert --
    the exact reason the bridge exists."""
    b, db, _notifier = bridge
    _buffer_one(b)
    b._flush(_NOW)
    row = next(d for d in db.list_devices() if d["mac"] == _MAC)
    assert row["device_type"] == "ble"


def test_the_buffer_is_drained_so_one_advert_alerts_once(bridge):
    """A buffer that is not cleared re-emits the same sighting every flush
    interval, which would bury the operator in duplicates of one device."""
    b, db, _notifier = bridge
    _buffer_one(b)
    assert b._flush(_NOW) == 1
    assert b._buffer == {}, "buffer not drained; the same advert will flush again"
    assert b._flush(_NOW + 1) == 0


def test_a_non_matching_advert_persists_without_alerting(bridge):
    """The negative case, so the test above is not passing merely because
    everything alerts. Capture and detection are separate concerns."""
    b, db, notifier = bridge
    _buffer_one(b, uuids=("0000180f-0000-1000-8000-00805f9b34fb",))  # battery service
    b._flush(_NOW)
    assert _MAC in {d["mac"] for d in db.list_devices()}, "capture should still happen"
    assert not db.list_alerts(), "a battery-service advert must not raise an alert"
    assert not notifier.calls


def test_one_failing_advert_does_not_stop_the_others(bridge):
    """`_flush` guards each observation, so a single bad advert must not cost
    the rest of the window -- the bridge's equivalent of poll_once's
    per-observation boundary."""
    b, db, _notifier = bridge
    other = "c0:ff:ee:00:11:33"
    _buffer_one(b)
    b._buffer[other] = _BufferEntry(
        first_seen=_NOW, last_seen=_NOW, rssi=-60,
        manufacturer_ids=(), service_uuids=(_UUID,),
    )
    real = db.upsert_device

    def flaky(mac, *a, **kw):
        if mac == _MAC:
            raise RuntimeError("database is locked")
        return real(mac, *a, **kw)

    import unittest.mock

    with unittest.mock.patch.object(db, "upsert_device", side_effect=flaky):
        flushed = b._flush(_NOW)

    assert flushed == 1, "the healthy advert should still have been processed"
    assert other in {d["mac"] for d in db.list_devices()}
