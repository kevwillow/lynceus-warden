"""Local-only tests for Continuity classification inside the BLE bridge.

tests/ is gitignored — these are NEVER committed (see project memory).

The privacy guard here is load-bearing: the bridge's whole justification
for decoding payloads at all is that it retains only the derived label.
If someone later buffers raw bytes, test_buffer_entry_retains_no_raw_payload
fails and forces that decision back into review.
"""

from __future__ import annotations

import dataclasses

import pytest

from lynceus.allowlist import Allowlist
from lynceus.ble_continuity import CLASS_AIRPODS, CLASS_FIND_MY
from lynceus.bridges.ble import BleBridge, _BufferEntry
from lynceus.config import Config
from lynceus.db import Database
from lynceus.kismet import DeviceObservation
from lynceus.notify import NullNotifier
from lynceus.rules import Ruleset


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


def _tlv(msg_type: int, body: bytes) -> bytes:
    return bytes([msg_type, len(body)]) + body


def _obs(**overrides):
    base = dict(
        device_type="ble",
        mac="aa:bb:cc:dd:ee:ff",
        first_seen=1,
        last_seen=2,
        rssi=-50,
        ssid=None,
        oui_vendor=None,
        is_randomized=False,
    )
    base.update(overrides)
    return DeviceObservation(**base)


def test_observation_accepts_device_class():
    assert _obs(ble_device_class=CLASS_FIND_MY).ble_device_class == CLASS_FIND_MY


def test_device_class_blanked_for_non_ble():
    obs = _obs(device_type="wifi", ble_device_class=CLASS_FIND_MY)
    assert obs.ble_device_class is None


def test_service_uuids_still_blanked_for_non_ble():
    # Guards the pre-existing half of the validator we are extending.
    obs = _obs(
        device_type="wifi",
        ble_service_uuids=("0000180d-0000-1000-8000-00805f9b34fb",),
    )
    assert obs.ble_service_uuids == ()


def test_buffer_entry_retains_no_raw_payload():
    """PRIVACY REGRESSION GUARD — see module docstring."""
    field_types = {f.name: f.type for f in dataclasses.fields(_BufferEntry)}
    assert "device_class" in field_types
    for name, typ in field_types.items():
        assert "bytes" not in str(typ), f"{name} may retain raw payload bytes"


def test_record_advert_stores_label_not_bytes(bridge):
    bridge._record_advert(
        mac_raw="AA:BB:CC:DD:EE:FF",
        rssi=-60,
        manufacturer_data={0x004C: _tlv(0x12, b"\x00")},
        service_uuids=(),
    )
    entry = bridge._buffer["aa:bb:cc:dd:ee:ff"]
    assert entry.device_class == CLASS_FIND_MY
    assert 0x004C in entry.manufacturer_ids


def test_record_advert_none_for_non_apple(bridge):
    bridge._record_advert(
        mac_raw="AA:BB:CC:DD:EE:11",
        rssi=-60,
        manufacturer_data={0x0075: b"\x01\x02"},
        service_uuids=(),
    )
    assert bridge._buffer["aa:bb:cc:dd:ee:11"].device_class is None


def test_rebuffered_advert_updates_class(bridge):
    """The existing-entry branch must refresh the class, not keep the first."""
    for payload in (_tlv(0x10, b"\x05"), _tlv(0x07, b"\x01")):
        bridge._record_advert(
            mac_raw="AA:BB:CC:DD:EE:22",
            rssi=-60,
            manufacturer_data={0x004C: payload},
            service_uuids=(),
        )
    assert bridge._buffer["aa:bb:cc:dd:ee:22"].device_class == CLASS_AIRPODS


def test_build_observation_carries_class(bridge):
    bridge._record_advert(
        mac_raw="AA:BB:CC:DD:EE:33",
        rssi=-60,
        manufacturer_data={0x004C: _tlv(0x07, b"\x01")},
        service_uuids=(),
    )
    mac = "aa:bb:cc:dd:ee:33"
    obs = bridge._build_observation(mac, bridge._buffer[mac])
    assert obs.ble_device_class == CLASS_AIRPODS
