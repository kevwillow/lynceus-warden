"""Remote-ID (ASTM F3411) plumbing through the BLE bridge.

THE regression this file exists for is
``test_detection_callback_forwards_service_data``. Measured 2026-08-03: the
bridge's bleak callback passed only ``manufacturer_data`` and
``service_uuids`` into ``_record_advert``, and ODID arrives in *service data* —
so the payload never entered the program at all. A decoder alone does not fix
that; the callback has to hand the field over.

The privacy guard is load-bearing for the same reason it is in
``test_ble_bridge_continuity.py``: the bridge's justification for reading
advertisement payloads at all is that it keeps only the derived label. Widening
the buffer to hold ODID bytes would quietly turn a privacy-preserving bridge
into a payload recorder, on a tool whose README promises otherwise.
"""

from __future__ import annotations

import dataclasses
from types import SimpleNamespace

import pytest

from lynceus.allowlist import Allowlist
from lynceus.ble_odid import ODID_SERVICE_UUID
from lynceus.bridges.ble import BleBridge, _BufferEntry
from lynceus.config import Config
from lynceus.db import Database
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


def _odid_payload(serial: bytes = b"21239ESA2") -> bytes:
    """One ODID Basic ID service-data value, laid out from the spec.

    See tests/test_ble_odid.py for the full provenance of this layout.
    """
    message = (
        bytes([(0x0 << 4) | 2])
        + bytes([(1 << 4) | 2])
        + serial.ljust(20, b"\x00")
        + b"\x00\x00\x00"
    )
    return bytes([0x0D, 0x00]) + message


def _odid_service_data(serial: bytes = b"21239ESA2") -> dict:
    return {ODID_SERVICE_UUID: _odid_payload(serial)}


# --- the buffer --------------------------------------------------------------


def test_record_advert_extracts_the_drone_id_prefix(bridge):
    bridge._record_advert(
        mac_raw="AA:BB:CC:DD:EE:FF",
        rssi=-60,
        manufacturer_data={},
        service_uuids=(),
        service_data=_odid_service_data(),
    )
    assert bridge._buffer["aa:bb:cc:dd:ee:ff"].drone_id_prefix == "21239ESA2"


def test_a_hyphenated_serial_lands_in_canonical_form(bridge):
    """One canonical form across ingest paths — the Kismet coercion's job."""
    bridge._record_advert(
        mac_raw="AA:BB:CC:DD:EE:A1",
        rssi=-60,
        manufacturer_data={},
        service_uuids=(),
        service_data=_odid_service_data(b"1596f3-an4x8y"),
    )
    assert bridge._buffer["aa:bb:cc:dd:ee:a1"].drone_id_prefix == "1596F3AN4X8Y"


def test_non_odid_service_data_yields_no_prefix(bridge):
    bridge._record_advert(
        mac_raw="AA:BB:CC:DD:EE:22",
        rssi=-60,
        manufacturer_data={},
        service_uuids=(),
        service_data={"0000fe9f-0000-1000-8000-00805f9b34fb": b"\x01\x02\x03"},
    )
    assert bridge._buffer["aa:bb:cc:dd:ee:22"].drone_id_prefix is None


def test_absent_service_data_yields_no_prefix(bridge):
    bridge._record_advert(
        mac_raw="AA:BB:CC:DD:EE:33",
        rssi=-60,
        manufacturer_data={},
        service_uuids=(),
        service_data=None,
    )
    assert bridge._buffer["aa:bb:cc:dd:ee:33"].drone_id_prefix is None


def test_rebuffered_advert_refreshes_the_prefix(bridge):
    """The existing-entry branch must update, mirroring device_class.

    A drone whose first advert in a window is a Location message and whose
    second is a Basic ID must end the window identified, not anonymous.
    """
    bridge._record_advert(
        mac_raw="AA:BB:CC:DD:EE:44",
        rssi=-60,
        manufacturer_data={},
        service_uuids=(),
        service_data=None,
    )
    bridge._record_advert(
        mac_raw="AA:BB:CC:DD:EE:44",
        rssi=-60,
        manufacturer_data={},
        service_uuids=(),
        service_data=_odid_service_data(),
    )
    assert bridge._buffer["aa:bb:cc:dd:ee:44"].drone_id_prefix == "21239ESA2"


def test_a_later_advert_without_odid_does_not_erase_the_prefix(bridge):
    """Sticky within the window — latest-wins would blank almost every drone.

    An ODID transmitter rotates its message types: Basic ID, then Location,
    then System, then Operator ID. Only the Basic ID carries the serial, so
    most adverts in any flush window decode to None. If a later serial-less
    advert cleared the field the way ``device_class`` is cleared, the flush
    would emit an anonymous observation nearly every time and the whole
    receiver would be pointless. This is the one place the ODID field
    deliberately does NOT mirror the Continuity field's latest-wins rule.
    """
    bridge._record_advert(
        mac_raw="AA:BB:CC:DD:EE:AA",
        rssi=-60,
        manufacturer_data={},
        service_uuids=(),
        service_data=_odid_service_data(),
    )
    bridge._record_advert(
        mac_raw="AA:BB:CC:DD:EE:AA",
        rssi=-61,
        manufacturer_data={},
        service_uuids=(),
        service_data=None,
    )
    assert bridge._buffer["aa:bb:cc:dd:ee:aa"].drone_id_prefix == "21239ESA2"


def test_a_second_drone_id_on_the_same_mac_replaces_the_first(bridge):
    """Sticky must not mean frozen: a newly decoded serial still wins."""
    bridge._record_advert(
        mac_raw="AA:BB:CC:DD:EE:BB",
        rssi=-60,
        manufacturer_data={},
        service_uuids=(),
        service_data=_odid_service_data(b"21239ESA2"),
    )
    bridge._record_advert(
        mac_raw="AA:BB:CC:DD:EE:BB",
        rssi=-60,
        manufacturer_data={},
        service_uuids=(),
        service_data=_odid_service_data(b"1596F3AN4X8Y"),
    )
    assert bridge._buffer["aa:bb:cc:dd:ee:bb"].drone_id_prefix == "1596F3AN4X8Y"


# --- privacy -----------------------------------------------------------------


def test_buffer_entry_retains_no_raw_payload():
    """PRIVACY REGRESSION GUARD — see module docstring."""
    field_types = {f.name: f.type for f in dataclasses.fields(_BufferEntry)}
    assert "drone_id_prefix" in field_types
    for name, typ in field_types.items():
        assert "bytes" not in str(typ), f"{name} may retain raw payload bytes"
        assert "dict" not in str(typ), f"{name} may retain the service-data map"


def test_the_recorded_entry_holds_no_payload_bytes_anywhere(bridge):
    """Values, not just declared types — a field typed str can still hold bytes."""
    bridge._record_advert(
        mac_raw="AA:BB:CC:DD:EE:55",
        rssi=-60,
        manufacturer_data={},
        service_uuids=(),
        service_data=_odid_service_data(),
    )
    entry = bridge._buffer["aa:bb:cc:dd:ee:55"]
    payload = _odid_payload()
    # ⚠️ A sweep needs a floor before it judges anything. Both assertions below
    # live inside the loop, so if `dataclasses.fields(entry)` ever came back
    # empty — a refactor of _BufferEntry, a swap to a plain class — the body
    # would never run and this test would pass having checked nothing. That
    # matters more here than usual: what it verifies is a PRIVACY guarantee,
    # that raw ODID payload bytes never reach the buffered entry. A vacuous
    # pass reports that guarantee as held.
    fields = dataclasses.fields(entry)
    assert len(fields) >= 4, f"expected _BufferEntry to carry fields, got {fields!r}"
    for field in fields:
        value = getattr(entry, field.name)
        assert not isinstance(value, (bytes, bytearray)), field.name
        assert payload not in repr(value).encode("utf-8", "replace"), field.name


# --- the observation ---------------------------------------------------------


def test_build_observation_carries_the_drone_id_prefix(bridge):
    bridge._record_advert(
        mac_raw="AA:BB:CC:DD:EE:66",
        rssi=-60,
        manufacturer_data={},
        service_uuids=(),
        service_data=_odid_service_data(),
    )
    mac = "aa:bb:cc:dd:ee:66"
    obs = bridge._build_observation(mac, bridge._buffer[mac])
    assert obs.drone_id_prefix == "21239ESA2"


def test_build_observation_leaves_the_prefix_none_without_odid(bridge):
    bridge._record_advert(
        mac_raw="AA:BB:CC:DD:EE:77",
        rssi=-60,
        manufacturer_data={},
        service_uuids=(),
        service_data=None,
    )
    mac = "aa:bb:cc:dd:ee:77"
    obs = bridge._build_observation(mac, bridge._buffer[mac])
    assert obs.drone_id_prefix is None


# --- the callback: THE measured regression -----------------------------------


def test_detection_callback_forwards_service_data(bridge):
    """Measured 2026-08-03: it did not, so ODID never entered the program."""
    device = SimpleNamespace(address="AA:BB:CC:DD:EE:88")
    advert = SimpleNamespace(
        rssi=-55,
        manufacturer_data={},
        service_uuids=(),
        service_data=_odid_service_data(),
    )
    bridge._detection_callback(device, advert)
    assert bridge._buffer["aa:bb:cc:dd:ee:88"].drone_id_prefix == "21239ESA2"


def test_detection_callback_tolerates_an_advert_without_service_data(bridge):
    """Not every bleak backend populates the attribute."""
    device = SimpleNamespace(address="AA:BB:CC:DD:EE:99")
    advert = SimpleNamespace(rssi=-55, manufacturer_data={}, service_uuids=())
    bridge._detection_callback(device, advert)
    assert bridge._buffer["aa:bb:cc:dd:ee:99"].drone_id_prefix is None
