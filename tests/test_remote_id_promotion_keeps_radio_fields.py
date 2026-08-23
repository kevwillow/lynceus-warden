"""Promoting a drone to `remote_id` must not blind every other rule type.

Kismet's UAV phy DECORATES rather than types: a Remote-ID drone arrives typed
"Wi-Fi Device" or "BTLE" carrying an extra `uav.device` component
(phy_uav_drone.cc:111,128). `parse_kismet_device` reads that component and
promotes `device_type` to "remote_id".

⛔ The promotion happens BEFORE the field-extraction block, and every gate in
that block keys on `device_type`:

    if device_type == "wifi":  ssid = ...
    if capture_probe_ssids and device_type == "wifi":  probe_ssids = ...
    if device_type == "ble":   ble_service_uuids = ...
    if capture_ble_name and device_type == "ble":  ble_name = ...
    if device_type == "ble":   ble_manufacturer_id = ...

So the promotion silently switched all five off. Measured on the clean tree,
against two records differing ONLY by the presence of the uav component:

    wifi drone            type=wifi      ssid='DJI-Phantom4'  probes=()
    wifi drone + uav      type=remote_id ssid=None            probes=None

    ble drone             type=ble       ble_name='Mavic-Air-2'  uuids=1
    ble drone + uav       type=remote_id ble_name=None           uuids=0

⭐ Those are exactly the columns the bundled drone signatures match on. A DJI
drone that broadcasts Remote-ID -- which is the entire point of Remote-ID, and
is what a current DJI airframe does by law -- therefore arrives with its SSID
stripped, so the `ssid_pattern` rows aimed at DJI cannot fire for it.

The two facts are separable. `device_type` is a CLASSIFICATION and promoting it
is correct. The extraction gates are asking a different question -- which radio
actually carried this advert -- and that does not change when the classification
does. This pins them apart.
"""

from __future__ import annotations

import pytest

from lynceus.kismet import parse_kismet_device

UAV = {"uav.device": {"uav.serialnumber": "1581F5FMD2400ABC"}}

WIFI_DRONE = {
    "kismet.device.base.macaddr": "02:11:22:33:44:55",
    "kismet.device.base.type": "Wi-Fi Device",
    "kismet.device.base.first_time": 1_700_000_000,
    "kismet.device.base.last_time": 1_700_000_100,
    "kismet.device.base.name": "DJI-Phantom4",
    # The shape REAL Kismet 2025.09 emits, checked against
    # tests/fixtures/kismet_devices_real_2025_09.json: a LIST under
    # dot11.device.probed_ssid_map. Building it the other way round makes the
    # control return () and the whole comparison vacuous.
    "dot11.device": {
        "dot11.device.probed_ssid_map": [{"dot11.probedssid.ssid": "HomeNet-5G"}]
    },
}

BLE_DRONE = {
    "kismet.device.base.macaddr": "02:11:22:33:44:66",
    "kismet.device.base.type": "BTLE",
    "kismet.device.base.first_time": 1_700_000_000,
    "kismet.device.base.last_time": 1_700_000_100,
    "kismet.device.base.name": "Mavic-Air-2",
    "kismet.device.base.service_uuids": ["0000fd6f-0000-1000-8000-00805f9b34fb"],
}


def _parse(record):
    return parse_kismet_device(
        dict(record), capture_probe_ssids=True, capture_ble_name=True
    )


# --- the promotion itself still has to work -------------------------------
# Without these, "keep the radio fields" is equally satisfied by not promoting
# at all, which would be a worse defect and would look identical below.


def test_a_wifi_record_with_a_uav_component_is_still_promoted():
    assert _parse({**WIFI_DRONE, **UAV}).device_type == "remote_id"


def test_a_ble_record_with_a_uav_component_is_still_promoted():
    assert _parse({**BLE_DRONE, **UAV}).device_type == "remote_id"


def test_the_serial_is_still_extracted():
    assert _parse({**WIFI_DRONE, **UAV}).drone_id_prefix == "1581F5FMD2400ABC"


def test_a_record_without_the_component_is_not_promoted():
    assert _parse(WIFI_DRONE).device_type == "wifi"


# --- the guard: promotion must not strip the radio's own fields -----------


@pytest.mark.parametrize(
    ("field", "expected"),
    [
        ("ssid", "DJI-Phantom4"),
        ("probe_ssids", ("HomeNet-5G",)),
    ],
)
def test_a_promoted_wifi_drone_keeps_its_wifi_fields(field, expected):
    """The SSID is how the bundled `ssid_pattern` signatures find a DJI
    airframe. Promotion used to delete it on exactly the aircraft that
    announce themselves."""
    plain = getattr(_parse(WIFI_DRONE), field)
    promoted = getattr(_parse({**WIFI_DRONE, **UAV}), field)
    assert plain == expected, "the control record lost the field too — bad fixture"
    assert promoted == expected, (
        f"adding a uav component stripped {field}: {plain!r} -> {promoted!r}"
    )


@pytest.mark.parametrize(
    ("field", "expected"),
    [
        ("ble_local_name", "Mavic-Air-2"),
        ("ble_service_uuids", ("0000fd6f-0000-1000-8000-00805f9b34fb",)),
    ],
)
def test_a_promoted_ble_drone_keeps_its_ble_fields(field, expected):
    plain = getattr(_parse(BLE_DRONE), field)
    promoted = getattr(_parse({**BLE_DRONE, **UAV}), field)
    assert plain == expected, "the control record lost the field too — bad fixture"
    assert promoted == expected, (
        f"adding a uav component stripped {field}: {plain!r} -> {promoted!r}"
    )


# --- and must not START extracting fields the radio cannot carry ----------
# The mirror-image error: gating on the arrival radio must not be relaxed into
# "extract everything for everyone". A Wi-Fi record has no BLE advertisement.


def test_a_promoted_wifi_drone_gains_no_ble_fields():
    obs = _parse({**WIFI_DRONE, **UAV})
    assert obs.ble_local_name is None
    assert obs.ble_service_uuids == ()
    assert obs.ble_manufacturer_id is None


def test_a_promoted_ble_drone_gains_no_wifi_fields():
    obs = _parse({**BLE_DRONE, **UAV})
    assert obs.ssid is None
    assert obs.probe_ssids is None


def test_capture_toggles_still_gate_the_promoted_record():
    """Promotion must not become a way round the operator's capture opt-out."""
    obs = parse_kismet_device(
        {**BLE_DRONE, **UAV}, capture_probe_ssids=False, capture_ble_name=False
    )
    assert obs.device_type == "remote_id"
    assert obs.ble_local_name is None
    obs = parse_kismet_device(
        {**WIFI_DRONE, **UAV}, capture_probe_ssids=False, capture_ble_name=False
    )
    assert obs.probe_ssids is None
    # ssid is NOT behind a capture toggle — it is the base identifier — so it
    # must survive here, or this test would be pinning the wrong thing.
    assert obs.ssid == "DJI-Phantom4"
