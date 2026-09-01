"""The bridge must carry the BLE local name, or a whole rule type is unfirable.

⛔ Measured 2026-09-01 against a live scan. `_detection_callback` read `rssi`,
`manufacturer_data`, `service_uuids` and `service_data` from bleak's
`AdvertisementData` and **dropped `local_name`**, which is that object's first
field. So `DeviceObservation.ble_local_name` was `None` on every observation the
bridge ever produced, and `watchlist_ble_local_name` could not fire on a
bridge-only deployment. `shadow_seen:ble_local_name` sat at **0** through a run
in which BLE devices were being captured and stored.

That rule's entire corpus is **Flock Safety device names: 12 rows, 100%
actionable** — the highest signal-to-noise of any watchlist type in the shipped
data, switched off at the capture layer by omission rather than by decision.

🪤 **Why nothing caught it.** `rules.py`'s matcher comments say `ble_local_name`
is None "when capture.ble_friendly_names is disabled or when the Kismet record
carries no name field" — written when Kismet was the only source, and never
revisited when the bridge landed. Every existing bridge test constructs
`_BufferEntry` directly, so none of them exercises the callback's field list.
⇒ A test that builds the buffer by hand cannot see a field the callback forgot.
"""

from __future__ import annotations

import pytest

from lynceus.allowlist import Allowlist
from lynceus.bridges.ble import BleBridge, _BufferEntry
from lynceus.config import CaptureConfig, Config
from lynceus.db import Database
from lynceus.notify import RecordingNotifier
from lynceus.rules import Rule, Ruleset

_MAC = "c0:ff:ee:00:11:22"
_NOW = 1_700_000_000
#: A real shape from the shipped corpus: Flock Safety cameras identify by name.
_WATCHED_NAME = "FlockSafety-Falcon"


class _Advert:
    """The subset of bleak's AdvertisementData the callback reads.

    ⚠️ Deliberately NOT a mock with auto-attributes. The callback uses
    `getattr(..., default)` for every field, so a permissive mock would satisfy
    it no matter which fields it asked for, and this file exists precisely
    because it asked for the wrong set.
    """

    def __init__(self, *, local_name=None, service_uuids=(), manufacturer_data=None):
        self.local_name = local_name
        self.service_uuids = tuple(service_uuids)
        self.manufacturer_data = manufacturer_data or {}
        self.service_data = None
        self.rssi = -55


class _Device:
    def __init__(self, address):
        self.address = address


def _make_bridge(tmp_path, *, friendly_names=True, rules=()):
    db = Database(str(tmp_path / "ble.db"))
    config = Config(
        db_path=str(tmp_path / "ble.db"),
        capture=CaptureConfig(ble_friendly_names=friendly_names),
    )
    notifier = RecordingNotifier()
    b = BleBridge(
        db=db,
        config=config,
        ruleset=Ruleset(rules=list(rules)),
        allowlist_provider=Allowlist,
        notifier=notifier,
        severity_overrides=None,
        location_id=config.location_id,
        location_label=config.location_label,
        adapter="hci0",
        flush_interval=1.0,
    )
    return b, db, notifier


@pytest.fixture
def bridge(tmp_path):
    b, db, notifier = _make_bridge(tmp_path)
    yield b, db, notifier
    db.close()


def test_the_callback_actually_reads_local_name_off_the_advert(bridge):
    """The regression, at the exact layer that had the defect.

    ⛔ Drives `_detection_callback`, NOT `_record_advert`. The bug was the
    callback's argument list; calling `_record_advert` directly would pass with
    the defect present, which is how every existing bridge test missed it.
    """
    b, _db, _n = bridge
    b._detection_callback(_Device(_MAC), _Advert(local_name=_WATCHED_NAME))

    entry = b._buffer.get(_MAC)
    assert entry is not None, "the advert was not buffered at all"
    assert entry.local_name == _WATCHED_NAME, (
        "the callback dropped local_name; DeviceObservation.ble_local_name will "
        "be None and watchlist_ble_local_name can never fire from the bridge"
    )


def test_the_observation_carries_the_name(bridge):
    b, _db, _n = bridge
    b._detection_callback(_Device(_MAC), _Advert(local_name=_WATCHED_NAME))
    obs = b._build_observation(_MAC, b._buffer[_MAC])
    assert obs.ble_local_name == _WATCHED_NAME


def test_a_named_device_fires_the_watchlist_rule_end_to_end(tmp_path):
    """⭐ The one that proves the product works: advert -> alert.

    Everything else here could pass while the rule stayed unfirable.
    """
    rule = Rule(
        name="flock_by_name",
        rule_type="watchlist_ble_local_name",
        severity="high",
        patterns=[_WATCHED_NAME],
        description="Flock Safety camera identified by BLE local name",
    )
    b, db, notifier = _make_bridge(tmp_path, rules=[rule])
    try:
        b._detection_callback(_Device(_MAC), _Advert(local_name=_WATCHED_NAME))
        flushed = b._flush(_NOW)
        assert flushed == 1, "the advert never reached the pipeline"

        alerts = db.list_alerts()
        assert alerts, (
            "a device broadcasting a watchlisted BLE local name raised no alert; "
            "the bridge -> rule path for watchlist_ble_local_name is broken"
        )
        assert alerts[0]["mac"] == _MAC
        assert alerts[0]["severity"] == "high"
        assert notifier.calls, "the alert was stored but never notified"
    finally:
        db.close()


def test_an_unwatched_name_does_not_alert(tmp_path):
    """The control. Without this, the test above passes if EVERYTHING alerts."""
    rule = Rule(
        name="flock_by_name",
        rule_type="watchlist_ble_local_name",
        severity="high",
        patterns=[_WATCHED_NAME],
        description="Flock Safety camera identified by BLE local name",
    )
    b, db, notifier = _make_bridge(tmp_path, rules=[rule])
    try:
        b._detection_callback(_Device(_MAC), _Advert(local_name="SomeonesAirpods"))
        b._flush(_NOW)
        assert not db.list_alerts(), "an unwatched BLE name raised an alert"
    finally:
        db.close()


def test_the_capture_optout_is_honoured(tmp_path):
    """`capture.ble_friendly_names: false` must mean None from BOTH sources.

    ⛔ Kismet gates its extraction on this flag. If the bridge ignored it, an
    operator's opt-out would silently mean "opted out of one capture backend",
    which is worse than not offering the toggle.
    """
    b, db, _n = _make_bridge(tmp_path, friendly_names=False)
    try:
        b._detection_callback(_Device(_MAC), _Advert(local_name=_WATCHED_NAME))
        obs = b._build_observation(_MAC, b._buffer[_MAC])
        assert obs.ble_local_name is None, (
            "capture.ble_friendly_names is off and the bridge emitted the name anyway"
        )
    finally:
        db.close()


def test_the_name_survives_later_adverts_that_carry_none(bridge):
    """⭐ Stickiness, and it is not a nicety.

    A BLE device usually puts its name in the SCAN RESPONSE, not in every
    advertisement, so a named device sends many later adverts with
    `local_name=None`. Overwriting on those would blank the name before the
    flush and the rule would see None on a device that DID identify itself.

    ⚠️ This is the failure that a short bench test would never reproduce, and
    that a real deployment would hit constantly.
    """
    b, _db, _n = bridge
    b._detection_callback(_Device(_MAC), _Advert(local_name=_WATCHED_NAME))
    for _ in range(5):
        b._detection_callback(_Device(_MAC), _Advert(local_name=None))

    assert b._buffer[_MAC].local_name == _WATCHED_NAME, (
        "a nameless follow-up advert blanked the name; on real hardware most "
        "adverts carry no name and the rule would almost never fire"
    )


def test_a_newer_name_still_replaces_the_old_one(bridge):
    """Sticky must not mean frozen: a device that renames is not stuck."""
    b, _db, _n = bridge
    b._detection_callback(_Device(_MAC), _Advert(local_name="OldName"))
    b._detection_callback(_Device(_MAC), _Advert(local_name="NewName"))
    assert b._buffer[_MAC].local_name == "NewName"


def test_an_empty_name_is_none_not_empty_string(bridge):
    """Same contract as Kismet's `_extract_ble_name`: non-empty str, else None.

    The two sources feed one rule that matches by equality, so a divergence
    here would make the same device match from one backend and miss from the
    other.
    """
    b, _db, _n = bridge
    b._detection_callback(_Device(_MAC), _Advert(local_name=""))
    assert b._buffer[_MAC].local_name is None


def test_a_non_string_name_does_not_crash_the_callback(bridge):
    """The callback runs on the radio thread; a bad advert must not kill it."""
    b, _db, _n = bridge
    b._detection_callback(_Device(_MAC), _Advert(local_name=b"\xff\xfe"))
    assert b._buffer[_MAC].local_name is None


def test_an_advert_object_without_local_name_at_all_is_tolerated(bridge):
    """Older bleak backends may not expose the attribute; getattr must default.

    ⚠️ Pins the `getattr(..., None)` rather than attribute access, so a future
    tidy-up to `advertisement_data.local_name` cannot silently break older
    backends.
    """

    class _Bare:
        rssi = -40
        manufacturer_data = {}
        service_uuids = ()
        service_data = None

    b, _db, _n = bridge
    b._detection_callback(_Device(_MAC), _Bare())
    assert b._buffer[_MAC].local_name is None


def test_buffer_entry_defaults_to_none(tmp_path):
    """Existing tests construct `_BufferEntry` without the new field; they must
    keep working, and the default must be the safe one."""
    entry = _BufferEntry(
        first_seen=_NOW, last_seen=_NOW, rssi=-50, manufacturer_ids=(), service_uuids=()
    )
    assert entry.local_name is None
