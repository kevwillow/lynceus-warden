"""Tests for the Kismet client."""

import logging
from pathlib import Path

import pytest
import requests
from pydantic import ValidationError

from talos.kismet import (
    DeviceObservation,
    FakeKismetClient,
    KismetClient,
    is_locally_administered,
    normalize_mac,
    normalize_uuid,
    parse_kismet_device,
)

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "kismet_devices.json"


def _wifi_ap_raw() -> dict:
    return {
        "kismet.device.base.macaddr": "a4:83:e7:11:22:33",
        "kismet.device.base.type": "Wi-Fi AP",
        "kismet.device.base.first_time": 1700000000,
        "kismet.device.base.last_time": 1700000100,
        "kismet.device.base.signal": {"kismet.common.signal.last_signal": -45},
        "kismet.device.base.manuf": "Apple",
        "kismet.device.base.name": "HomeNet",
    }


# ------------------------- is_locally_administered -------------------------


def test_lab_set_lowercase():
    assert is_locally_administered("02:11:22:33:44:55") is True


def test_lab_set_uppercase():
    assert is_locally_administered("AA:BB:CC:DD:EE:FF") is True


def test_lab_clear_zero_octet():
    assert is_locally_administered("00:11:22:33:44:55") is False


def test_lab_clear_apple_oui():
    assert is_locally_administered("a4:83:e7:11:22:33") is False


def test_lab_set_06_octet():
    assert is_locally_administered("06:aa:bb:cc:dd:ee") is True


def test_lab_hyphen_separator():
    assert is_locally_administered("02-11-22-33-44-55") is True


def test_lab_uppercase_hyphen():
    assert is_locally_administered("AA-BB-CC-DD-EE-FF") is True


def test_lab_invalid_raises():
    with pytest.raises(ValueError):
        is_locally_administered("not a mac")


def test_lab_short_raises():
    with pytest.raises(ValueError):
        is_locally_administered("02:11:22:33:44")


def test_lab_non_hex_raises():
    with pytest.raises(ValueError):
        is_locally_administered("zz:11:22:33:44:55")


# ------------------------------- normalize_mac -----------------------------


def test_norm_uppercase():
    assert normalize_mac("AA:BB:CC:DD:EE:FF") == "aa:bb:cc:dd:ee:ff"


def test_norm_hyphens():
    assert normalize_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"


def test_norm_whitespace():
    assert normalize_mac("  AA:BB:CC:DD:EE:FF  ") == "aa:bb:cc:dd:ee:ff"


def test_norm_already_normal_idempotent():
    val = "aa:bb:cc:dd:ee:ff"
    assert normalize_mac(normalize_mac(val)) == val


# ----------------------------- parse_kismet_device --------------------------


def test_parse_wifi_ap_with_ssid():
    obs = parse_kismet_device(_wifi_ap_raw())
    assert obs is not None
    assert obs.ssid == "HomeNet"
    assert obs.device_type == "wifi"
    assert obs.is_randomized is False


def test_parse_wifi_client_randomized():
    raw = {
        "kismet.device.base.macaddr": "02:11:22:33:44:55",
        "kismet.device.base.type": "Wi-Fi Client",
        "kismet.device.base.first_time": 1700000000,
        "kismet.device.base.last_time": 1700000200,
        "kismet.device.base.signal": {"kismet.common.signal.last_signal": -67},
    }
    obs = parse_kismet_device(raw)
    assert obs is not None
    assert obs.is_randomized is True
    assert obs.device_type == "wifi"


def test_parse_ble_forces_ssid_none():
    raw = {
        "kismet.device.base.macaddr": "06:aa:bb:cc:dd:ee",
        "kismet.device.base.type": "BTLE",
        "kismet.device.base.first_time": 1700000000,
        "kismet.device.base.last_time": 1700000300,
        "kismet.device.base.name": "ShouldBeIgnored",
    }
    obs = parse_kismet_device(raw)
    assert obs is not None
    assert obs.ssid is None
    assert obs.device_type == "ble"


def test_parse_bt_classic():
    raw = {
        "kismet.device.base.macaddr": "00:1a:7d:da:71:11",
        "kismet.device.base.type": "Bluetooth",
        "kismet.device.base.first_time": 1700000000,
        "kismet.device.base.last_time": 1700000400,
    }
    obs = parse_kismet_device(raw)
    assert obs is not None
    assert obs.device_type == "bt_classic"
    assert obs.ssid is None


def test_parse_unsupported_type_returns_none():
    raw = {
        "kismet.device.base.macaddr": "11:22:33:44:55:66",
        "kismet.device.base.type": "RTL433",
        "kismet.device.base.first_time": 1700000000,
        "kismet.device.base.last_time": 1700000500,
    }
    assert parse_kismet_device(raw) is None


def test_parse_missing_mac_returns_none():
    raw = {
        "kismet.device.base.type": "Wi-Fi AP",
        "kismet.device.base.first_time": 1700000000,
        "kismet.device.base.last_time": 1700000100,
    }
    assert parse_kismet_device(raw) is None


def test_parse_missing_first_time_returns_none():
    raw = {
        "kismet.device.base.macaddr": "a4:83:e7:11:22:33",
        "kismet.device.base.type": "Wi-Fi AP",
        "kismet.device.base.last_time": 1700000100,
    }
    assert parse_kismet_device(raw) is None


def test_parse_missing_signal_yields_none_rssi():
    raw = _wifi_ap_raw()
    raw["kismet.device.base.signal"] = {}
    obs = parse_kismet_device(raw)
    assert obs is not None
    assert obs.rssi is None


def test_parse_missing_signal_dict_yields_none_rssi():
    raw = _wifi_ap_raw()
    del raw["kismet.device.base.signal"]
    obs = parse_kismet_device(raw)
    assert obs is not None
    assert obs.rssi is None


def test_parse_missing_manuf_yields_none_vendor():
    raw = _wifi_ap_raw()
    del raw["kismet.device.base.manuf"]
    obs = parse_kismet_device(raw)
    assert obs is not None
    assert obs.oui_vendor is None


def test_parse_invalid_mac_returns_none():
    raw = _wifi_ap_raw()
    raw["kismet.device.base.macaddr"] = "not-a-mac"
    assert parse_kismet_device(raw) is None


def test_parse_logs_warning_on_drop(caplog):
    raw = {
        "kismet.device.base.type": "Wi-Fi AP",
        "kismet.device.base.first_time": 1700000000,
        "kismet.device.base.last_time": 1700000100,
    }
    with caplog.at_level(logging.WARNING, logger="talos.kismet"):
        result = parse_kismet_device(raw)
    assert result is None
    assert any(r.levelname == "WARNING" for r in caplog.records)


# --------------------------- DeviceObservation -----------------------------


def _valid_obs_kwargs(**overrides) -> dict:
    base = {
        "mac": "aa:bb:cc:dd:ee:ff",
        "device_type": "wifi",
        "first_seen": 1700000000,
        "last_seen": 1700000100,
        "rssi": None,
        "ssid": None,
        "oui_vendor": None,
        "is_randomized": True,
    }
    base.update(overrides)
    return base


def test_observation_rejects_uppercase_mac():
    with pytest.raises(ValidationError):
        DeviceObservation(**_valid_obs_kwargs(mac="AA:BB:CC:DD:EE:FF"))


def test_observation_rejects_last_before_first():
    with pytest.raises(ValidationError):
        DeviceObservation(**_valid_obs_kwargs(first_seen=1700000200, last_seen=1700000100))


def test_observation_frozen():
    obs = DeviceObservation(**_valid_obs_kwargs())
    with pytest.raises(ValidationError):
        obs.mac = "11:22:33:44:55:66"


# ----------------------------- FakeKismetClient ----------------------------


def test_fake_loads_returns_supported_only():
    client = FakeKismetClient(str(FIXTURE_PATH))
    obs = client.get_devices_since(0)
    assert len(obs) == 5


def test_fake_filters_since_ts_inclusive():
    client = FakeKismetClient(str(FIXTURE_PATH))
    obs = client.get_devices_since(1700000300)
    assert len(obs) == 3
    assert {o.device_type for o in obs} == {"ble", "bt_classic"}


def test_fake_filters_excludes_strictly_older():
    client = FakeKismetClient(str(FIXTURE_PATH))
    obs = client.get_devices_since(1700000301)
    assert len(obs) == 2
    assert {o.device_type for o in obs} == {"ble", "bt_classic"}


def test_fake_no_http(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("http should not be called")

    monkeypatch.setattr(requests, "get", boom)
    client = FakeKismetClient(str(FIXTURE_PATH))
    obs = client.get_devices_since(0)
    assert len(obs) == 5


# -------------------------------- KismetClient -----------------------------


def _stub_get(mocker, json_data, raise_status=False):
    mock_get = mocker.patch("talos.kismet.requests.get")
    response = mock_get.return_value
    response.json.return_value = json_data
    if raise_status:
        response.raise_for_status.side_effect = requests.HTTPError("500")
    else:
        response.raise_for_status.return_value = None
    return mock_get


def test_real_url_construction(mocker):
    mock_get = _stub_get(mocker, [])
    client = KismetClient(base_url="http://x:2501")
    client.get_devices_since(1234)
    assert mock_get.call_args.args[0] == "http://x:2501/devices/last-time/1234/devices.json"


def test_real_strips_trailing_slash(mocker):
    mock_get = _stub_get(mocker, [])
    client = KismetClient(base_url="http://x:2501/")
    client.get_devices_since(1234)
    assert mock_get.call_args.args[0] == "http://x:2501/devices/last-time/1234/devices.json"


def test_real_auth_cookie_set(mocker):
    mock_get = _stub_get(mocker, [])
    client = KismetClient(base_url="http://x:2501", api_key="abc")
    client.get_devices_since(1234)
    assert mock_get.call_args.kwargs.get("cookies") == {"KISMET": "abc"}


def test_real_no_auth_cookie(mocker):
    mock_get = _stub_get(mocker, [])
    client = KismetClient(base_url="http://x:2501")
    client.get_devices_since(1234)
    cookies = mock_get.call_args.kwargs.get("cookies")
    assert cookies is None or cookies == {}


def test_real_timeout_passed(mocker):
    mock_get = _stub_get(mocker, [])
    client = KismetClient(base_url="http://x:2501", timeout=5.0)
    client.get_devices_since(1234)
    assert mock_get.call_args.kwargs.get("timeout") == 5.0


def test_real_http_error_propagates(mocker):
    _stub_get(mocker, [], raise_status=True)
    client = KismetClient(base_url="http://x:2501")
    with pytest.raises(requests.HTTPError):
        client.get_devices_since(1234)


def test_real_non_list_response_raises_value_error(mocker):
    _stub_get(mocker, {"not": "a list"})
    client = KismetClient(base_url="http://x:2501")
    with pytest.raises(ValueError):
        client.get_devices_since(1234)


def test_real_returned_observations_match_parser(mocker):
    raw = _wifi_ap_raw()
    _stub_get(mocker, [raw])
    client = KismetClient(base_url="http://x:2501")
    result = client.get_devices_since(0)
    expected = parse_kismet_device(raw)
    assert len(result) == 1
    assert result[0] == expected


# ------------------------------- normalize_uuid ----------------------------


_AIRTAG_UUID = "0000fd5a-0000-1000-8000-00805f9b34fb"


def test_normalize_uuid_lowercase():
    assert normalize_uuid("0000FD5A-0000-1000-8000-00805F9B34FB") == _AIRTAG_UUID


def test_normalize_uuid_strips_whitespace():
    assert normalize_uuid("  0000fd5a-0000-1000-8000-00805f9b34fb  ") == _AIRTAG_UUID


def test_normalize_uuid_rejects_short_form():
    with pytest.raises(ValueError):
        normalize_uuid("fd5a")


def test_normalize_uuid_rejects_no_dashes():
    with pytest.raises(ValueError):
        normalize_uuid("0000fd5a000010008000" + "00805f9b34fb")


# --------------- DeviceObservation ble_service_uuids -----------------------


def test_observation_silently_drops_uuids_on_wifi():
    obs = DeviceObservation(
        **_valid_obs_kwargs(
            device_type="wifi",
            ble_service_uuids=(_AIRTAG_UUID,),
        )
    )
    assert obs.ble_service_uuids == ()


# ------------------- parse_kismet_device BLE UUID extraction ----------------


def _ble_raw(uuids: list[str] | None = None) -> dict:
    raw = {
        "kismet.device.base.macaddr": "5a:11:22:33:44:55",
        "kismet.device.base.type": "BTLE",
        "kismet.device.base.first_time": 1700000000,
        "kismet.device.base.last_time": 1700000600,
        "kismet.device.base.signal": {"kismet.common.signal.last_signal": -75},
        "kismet.device.base.manuf": "Apple",
    }
    if uuids is not None:
        raw["kismet.device.base.service_uuids"] = uuids
    return raw


def test_parse_ble_extracts_and_normalizes_uuids():
    raw = _ble_raw(["0000FD5A-0000-1000-8000-00805F9B34FB"])
    obs = parse_kismet_device(raw)
    assert obs is not None
    assert obs.device_type == "ble"
    assert obs.ble_service_uuids == (_AIRTAG_UUID,)


def test_parse_ble_drops_malformed_uuid_logs_debug(caplog):
    raw = _ble_raw([_AIRTAG_UUID, "fd5a"])
    with caplog.at_level(logging.DEBUG, logger="talos.kismet"):
        obs = parse_kismet_device(raw)
    assert obs is not None
    assert obs.ble_service_uuids == (_AIRTAG_UUID,)
    assert any(r.levelname == "DEBUG" for r in caplog.records)
    assert not any(
        r.levelname == "WARNING" and "uuid" in r.getMessage().lower() for r in caplog.records
    )


def test_parse_ble_no_service_uuids_field_yields_empty_tuple():
    raw = _ble_raw(uuids=None)
    obs = parse_kismet_device(raw)
    assert obs is not None
    assert obs.ble_service_uuids == ()


# -------------------------- seen_by_sources / seenby ------------------------


def _seenby(source: str | None = None, uuid: str | None = None) -> dict:
    entry: dict = {
        "kismet.common.seenby.first_time": 1700000000,
        "kismet.common.seenby.last_time": 1700000100,
    }
    if source is not None:
        entry["kismet.common.seenby.source"] = source
    if uuid is not None:
        entry["kismet.common.seenby.uuid"] = uuid
    return entry


def test_observation_seen_by_sources_default_empty():
    obs = DeviceObservation(**_valid_obs_kwargs())
    assert obs.seen_by_sources == ()


def test_observation_rejects_oversized_seen_by():
    with pytest.raises(ValidationError):
        DeviceObservation(**_valid_obs_kwargs(seen_by_sources=tuple(f"src-{i}" for i in range(17))))


def test_observation_rejects_empty_string_source():
    with pytest.raises(ValidationError):
        DeviceObservation(**_valid_obs_kwargs(seen_by_sources=("", "real")))


def test_observation_frozen_seen_by_immutable():
    obs = DeviceObservation(**_valid_obs_kwargs(seen_by_sources=("a", "b")))
    with pytest.raises(TypeError):
        obs.seen_by_sources[0] = "c"


def test_parse_extracts_seenby_source_field():
    raw = _wifi_ap_raw()
    raw["kismet.device.base.seenby"] = [_seenby(source="alfa-2.4ghz")]
    obs = parse_kismet_device(raw)
    assert obs is not None
    assert obs.seen_by_sources == ("alfa-2.4ghz",)


def test_parse_falls_back_to_uuid_when_source_missing():
    raw = _wifi_ap_raw()
    raw["kismet.device.base.seenby"] = [_seenby(uuid="11111111-2222-3333-4444-555555555555")]
    obs = parse_kismet_device(raw)
    assert obs is not None
    assert obs.seen_by_sources == ("11111111-2222-3333-4444-555555555555",)


def test_parse_skips_seenby_entries_with_neither_field():
    raw = _wifi_ap_raw()
    raw["kismet.device.base.seenby"] = [{}, _seenby(source="alfa")]
    obs = parse_kismet_device(raw)
    assert obs is not None
    assert obs.seen_by_sources == ("alfa",)


def test_parse_dedups_seenby_preserving_order():
    raw = _wifi_ap_raw()
    raw["kismet.device.base.seenby"] = [
        _seenby(source="alfa"),
        _seenby(source="builtin"),
        _seenby(source="alfa"),
    ]
    obs = parse_kismet_device(raw)
    assert obs is not None
    assert obs.seen_by_sources == ("alfa", "builtin")


def test_parse_caps_seenby_at_16():
    raw = _wifi_ap_raw()
    raw["kismet.device.base.seenby"] = [_seenby(source=f"src-{i}") for i in range(20)]
    obs = parse_kismet_device(raw)
    assert obs is not None
    assert len(obs.seen_by_sources) == 16
    assert obs.seen_by_sources[0] == "src-0"
    assert obs.seen_by_sources[-1] == "src-15"


def test_parse_no_seenby_field_yields_empty_tuple():
    raw = _wifi_ap_raw()
    obs = parse_kismet_device(raw)
    assert obs is not None
    assert obs.seen_by_sources == ()


def test_parse_seenby_not_a_list_yields_empty_tuple():
    raw = _wifi_ap_raw()
    raw["kismet.device.base.seenby"] = "malformed"
    obs = parse_kismet_device(raw)
    assert obs is not None
    assert obs.seen_by_sources == ()


# ------------------------------- health_check ------------------------------


def test_kismet_client_health_check_success(mocker):
    mock_get = mocker.patch("talos.kismet.requests.get")
    response = mock_get.return_value
    response.json.return_value = {"kismet.system.version": "2024-01-R1"}
    response.raise_for_status.return_value = None
    client = KismetClient(base_url="http://x:2501")
    result = client.health_check()
    assert result == {"reachable": True, "version": "2024-01-R1", "error": None}
    assert mock_get.call_args.args[0] == "http://x:2501/system/status.json"


def test_kismet_client_health_check_http_error(mocker):
    mock_get = mocker.patch("talos.kismet.requests.get")
    response = mock_get.return_value
    response.raise_for_status.side_effect = requests.HTTPError("500 Server Error")
    client = KismetClient(base_url="http://x:2501")
    result = client.health_check()
    assert result["reachable"] is False
    assert result["version"] is None
    assert result["error"]
    assert "500" in result["error"]


def test_kismet_client_health_check_transport_error(mocker):
    mock_get = mocker.patch("talos.kismet.requests.get")
    mock_get.side_effect = requests.ConnectionError("connection refused")
    client = KismetClient(base_url="http://x:2501")
    result = client.health_check()
    assert result["reachable"] is False
    assert result["version"] is None
    assert "connection refused" in result["error"]


def test_kismet_client_health_check_no_version_key(mocker):
    mock_get = mocker.patch("talos.kismet.requests.get")
    response = mock_get.return_value
    response.json.return_value = {"some.other.key": "value"}
    response.raise_for_status.return_value = None
    client = KismetClient(base_url="http://x:2501")
    result = client.health_check()
    assert result["reachable"] is True
    assert result["version"] is None


def test_fake_kismet_client_health_check(monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("http should not be called")

    monkeypatch.setattr(requests, "get", boom)
    client = FakeKismetClient(str(FIXTURE_PATH))
    result = client.health_check()
    assert result == {"reachable": True, "version": "fake-fixture", "error": None}
