"""Tests for the Kismet client."""

import logging
from pathlib import Path

import pytest
import requests
from pydantic import ValidationError

from lynceus.kismet import (
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
    with caplog.at_level(logging.WARNING, logger="lynceus.kismet"):
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
    """Patch ``requests.Session.get`` at class level — the KismetClient now
    drives every HTTP call through its mounted Session (with urllib3 Retry),
    not through the module-level ``requests.get`` shortcut. MagicMock does
    not implement the descriptor protocol, so ``call_args.args[0]`` is the
    URL the client passed (no implicit ``self``)."""
    mock_get = mocker.patch("requests.sessions.Session.get")
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
    with caplog.at_level(logging.DEBUG, logger="lynceus.kismet"):
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


# ------------------------- raw_record / capture gate ------------------------


def test_parse_kismet_device_omits_raw_record_when_capture_disabled():
    """REGRESSION: parse_kismet_device unconditionally attaching the
    full Kismet device record to every observation costs multi-MB of
    memory per poll batch on busy sites — even when evidence capture
    is off and the data will never be consumed. The flag gates the
    attachment at the source."""
    obs = parse_kismet_device(_wifi_ap_raw(), evidence_capture_enabled=False)
    assert obs is not None
    assert obs.raw_record is None


def test_parse_kismet_device_populates_raw_record_when_capture_enabled():
    obs = parse_kismet_device(_wifi_ap_raw(), evidence_capture_enabled=True)
    assert obs is not None
    assert obs.raw_record is not None
    assert obs.raw_record["kismet.device.base.macaddr"] == "a4:83:e7:11:22:33"


def test_parse_kismet_device_default_omits_raw_record():
    """The default is False (privacy/memory conservative). Direct
    callers without an explicit kwarg get the cheap behaviour."""
    obs = parse_kismet_device(_wifi_ap_raw())
    assert obs is not None
    assert obs.raw_record is None


# ------------------------------- health_check ------------------------------


def test_kismet_client_health_check_success(mocker):
    mock_get = mocker.patch("requests.sessions.Session.get")
    response = mock_get.return_value
    response.json.return_value = {"kismet.system.version": "2024-01-R1"}
    response.raise_for_status.return_value = None
    client = KismetClient(base_url="http://x:2501")
    result = client.health_check()
    assert result == {"reachable": True, "version": "2024-01-R1", "error": None}
    assert mock_get.call_args.args[0] == "http://x:2501/system/status.json"


def test_kismet_client_health_check_http_error(mocker):
    mock_get = mocker.patch("requests.sessions.Session.get")
    response = mock_get.return_value
    response.raise_for_status.side_effect = requests.HTTPError("500 Server Error")
    client = KismetClient(base_url="http://x:2501")
    result = client.health_check()
    assert result["reachable"] is False
    assert result["version"] is None
    assert result["error"]
    assert "500" in result["error"]


def test_kismet_client_health_check_transport_error(mocker):
    mock_get = mocker.patch("requests.sessions.Session.get")
    mock_get.side_effect = requests.ConnectionError("connection refused")
    client = KismetClient(base_url="http://x:2501")
    result = client.health_check()
    assert result["reachable"] is False
    assert result["version"] is None
    assert "connection refused" in result["error"]


def test_kismet_client_health_check_no_version_key(mocker):
    mock_get = mocker.patch("requests.sessions.Session.get")
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


# ------------------------------- list_sources -----------------------------


def _source_record(
    *,
    name: str,
    interface: str = "",
    capture_interface: str = "",
    uuid: str = "",
    driver: str = "linuxwifi",
    running: bool = True,
    extra: dict | None = None,
) -> dict:
    """Build a Kismet datasource record matching the on-the-wire shape.

    Mirrors what an operator sees from
    ``curl -s -b "KISMET=<token>" http://127.0.0.1:2501/datasource/all_sources.json``
    against a real Kismet instance. The wizard's silent-drop bug was caught
    by exactly this kind of capture during the rc1 shakedown.
    """
    rec: dict = {
        "kismet.datasource.name": name,
        "kismet.datasource.interface": interface,
        "kismet.datasource.capture_interface": capture_interface,
        "kismet.datasource.uuid": uuid,
        "kismet.datasource.running": 1 if running else 0,
        "kismet.datasource.type_driver": {
            "kismet.datasource.driver.type": driver,
        },
    }
    if extra:
        rec.update(extra)
    return rec


def test_list_sources_url_construction(mocker):
    mock_get = _stub_get(mocker, [])
    client = KismetClient(base_url="http://x:2501")
    client.list_sources()
    assert mock_get.call_args.args[0] == "http://x:2501/datasource/all_sources.json"


def test_list_sources_strips_trailing_slash(mocker):
    mock_get = _stub_get(mocker, [])
    client = KismetClient(base_url="http://x:2501/")
    client.list_sources()
    assert mock_get.call_args.args[0] == "http://x:2501/datasource/all_sources.json"


def test_list_sources_passes_auth_cookie(mocker):
    mock_get = _stub_get(mocker, [])
    client = KismetClient(base_url="http://x:2501", api_key="abc")
    client.list_sources()
    assert mock_get.call_args.kwargs.get("cookies") == {"KISMET": "abc"}


def test_list_sources_no_auth_cookie_when_absent(mocker):
    mock_get = _stub_get(mocker, [])
    client = KismetClient(base_url="http://x:2501")
    client.list_sources()
    cookies = mock_get.call_args.kwargs.get("cookies")
    assert cookies is None or cookies == {}


def test_list_sources_uses_client_timeout(mocker):
    """The client's configured timeout must be passed to ``requests.get``;
    the wizard wires this up to 5s via ``PROBE_TIMEOUT_SECONDS`` so a wedged
    Kismet doesn't hang the setup flow."""
    mock_get = _stub_get(mocker, [])
    client = KismetClient(base_url="http://x:2501", timeout=5.0)
    client.list_sources()
    assert mock_get.call_args.kwargs.get("timeout") == 5.0


def test_list_sources_parses_realistic_response(mocker):
    """Realistic Kismet payload — captured during rc1 shakedown — with one
    Wi-Fi source mapped to wlan1mon and one Bluetooth source on hci0."""
    raw = [
        _source_record(
            name="external_wifi",
            interface="wlan1",
            capture_interface="wlan1mon",
            uuid="5fe308bd-0000-0000-0000-00c0caaaaaaa",
            driver="linuxwifi",
            running=True,
        ),
        _source_record(
            name="local_bt",
            interface="hci0",
            capture_interface="hci0",
            uuid="6fe308bd-0000-0000-0000-00c0cabbbbbb",
            driver="linuxbluetooth",
            running=True,
        ),
    ]
    _stub_get(mocker, raw)
    client = KismetClient(base_url="http://x:2501")
    sources = client.list_sources()
    assert len(sources) == 2
    wifi = sources[0]
    assert wifi["name"] == "external_wifi"
    assert wifi["interface"] == "wlan1"
    assert wifi["capture_interface"] == "wlan1mon"
    assert wifi["uuid"] == "5fe308bd-0000-0000-0000-00c0caaaaaaa"
    assert wifi["driver"] == "linuxwifi"
    assert wifi["running"] is True
    bt = sources[1]
    assert bt["name"] == "local_bt"
    assert bt["driver"] == "linuxbluetooth"


def test_list_sources_returns_normalized_dict_keys(mocker):
    raw = [_source_record(name="external_wifi", interface="wlan1")]
    _stub_get(mocker, raw)
    client = KismetClient(base_url="http://x:2501")
    sources = client.list_sources()
    assert len(sources) == 1
    expected_keys = {"name", "interface", "capture_interface", "uuid", "driver", "running"}
    assert set(sources[0].keys()) == expected_keys


def test_list_sources_empty_response_returns_empty_list(mocker):
    _stub_get(mocker, [])
    client = KismetClient(base_url="http://x:2501")
    assert client.list_sources() == []


def test_list_sources_filters_non_running_by_default(mocker):
    raw = [
        _source_record(name="active_wifi", driver="linuxwifi", running=True),
        _source_record(name="errored_wifi", driver="linuxwifi", running=False),
    ]
    _stub_get(mocker, raw)
    client = KismetClient(base_url="http://x:2501")
    sources = client.list_sources()
    assert [s["name"] for s in sources] == ["active_wifi"]


def test_list_sources_only_running_false_returns_all(mocker):
    raw = [
        _source_record(name="active_wifi", running=True),
        _source_record(name="errored_wifi", running=False),
    ]
    _stub_get(mocker, raw)
    client = KismetClient(base_url="http://x:2501")
    sources = client.list_sources(only_running=False)
    assert {s["name"] for s in sources} == {"active_wifi", "errored_wifi"}
    by_name = {s["name"]: s for s in sources}
    assert by_name["errored_wifi"]["running"] is False


def test_list_sources_extracts_driver_from_nested_field(mocker):
    """The driver name lives at type_driver -> kismet.datasource.driver.type
    (a nested dict, not a flat string). Verify we don't accidentally read
    the wrong key path."""
    raw = [
        {
            "kismet.datasource.name": "external_wifi",
            "kismet.datasource.interface": "wlan1",
            "kismet.datasource.capture_interface": "wlan1mon",
            "kismet.datasource.uuid": "u1",
            "kismet.datasource.running": 1,
            "kismet.datasource.type_driver": {
                "kismet.datasource.driver.type": "linuxwifi",
                "kismet.datasource.driver.description": "Linux Wi-Fi",
            },
        }
    ]
    _stub_get(mocker, raw)
    client = KismetClient(base_url="http://x:2501")
    sources = client.list_sources()
    assert sources[0]["driver"] == "linuxwifi"


def test_list_sources_handles_missing_type_driver(mocker):
    """An older or partial Kismet record without the nested driver block
    must not crash; driver becomes empty string and the source still
    appears in the output."""
    raw = [
        {
            "kismet.datasource.name": "old_source",
            "kismet.datasource.running": 1,
        }
    ]
    _stub_get(mocker, raw)
    client = KismetClient(base_url="http://x:2501")
    sources = client.list_sources()
    assert len(sources) == 1
    assert sources[0]["driver"] == ""
    assert sources[0]["name"] == "old_source"


def test_list_sources_raises_on_http_401(mocker):
    mock_get = mocker.patch("requests.sessions.Session.get")
    response = mock_get.return_value
    response.raise_for_status.side_effect = requests.HTTPError("401 Unauthorized")
    client = KismetClient(base_url="http://x:2501")
    with pytest.raises(requests.HTTPError) as excinfo:
        client.list_sources()
    assert "401" in str(excinfo.value)


def test_list_sources_raises_on_http_500(mocker):
    mock_get = mocker.patch("requests.sessions.Session.get")
    response = mock_get.return_value
    response.raise_for_status.side_effect = requests.HTTPError("500 Server Error")
    client = KismetClient(base_url="http://x:2501")
    with pytest.raises(requests.HTTPError) as excinfo:
        client.list_sources()
    assert "500" in str(excinfo.value)


def test_list_sources_raises_on_malformed_json(mocker):
    mock_get = mocker.patch("requests.sessions.Session.get")
    response = mock_get.return_value
    response.json.side_effect = ValueError("Expecting value: line 1 column 1 (char 0)")
    response.raise_for_status.return_value = None
    client = KismetClient(base_url="http://x:2501")
    with pytest.raises(ValueError):
        client.list_sources()


def test_list_sources_raises_on_non_list_response(mocker):
    _stub_get(mocker, {"not": "a list"})
    client = KismetClient(base_url="http://x:2501")
    with pytest.raises(ValueError):
        client.list_sources()


def test_list_sources_raises_on_connection_error(mocker):
    mock_get = mocker.patch("requests.sessions.Session.get")
    mock_get.side_effect = requests.ConnectionError("connection refused")
    client = KismetClient(base_url="http://x:2501")
    with pytest.raises(requests.ConnectionError):
        client.list_sources()


def test_list_sources_skips_non_dict_entries(mocker):
    """Defense in depth: a malformed Kismet response containing a stray
    string or null in the array shouldn't crash the wizard — those entries
    are silently dropped."""
    raw = [
        _source_record(name="real_source"),
        "garbage",
        None,
    ]
    _stub_get(mocker, raw)
    client = KismetClient(base_url="http://x:2501")
    sources = client.list_sources()
    assert [s["name"] for s in sources] == ["real_source"]


# ----------------- H5: urllib3 Retry mounted on Session ---------------------


def test_h5_session_retry_mounted_for_https():
    """Structural regression: the HTTPS adapter must carry our Retry policy.
    Pre-fix the client had no ``_session`` attribute at all — the lookup
    here would raise ``AttributeError`` long before the Retry inspection.
    """
    client = KismetClient(base_url="https://kismet.example.com:2501")
    adapter = client._session.get_adapter("https://kismet.example.com:2501")
    retry = adapter.max_retries
    assert retry.total == 3
    assert retry.backoff_factor == 0.5
    assert 502 in retry.status_forcelist
    assert 503 in retry.status_forcelist
    assert 504 in retry.status_forcelist
    # urllib3 stores allowed_methods uppercase; GET must be retried.
    assert "GET" in retry.allowed_methods


def test_h5_session_retry_mounted_for_http():
    """Same Retry policy must apply on plain HTTP — Kismet's REST API on a
    LAN often runs over plain HTTP, and that path must retry too."""
    client = KismetClient(base_url="http://kismet.example.com:2501")
    adapter = client._session.get_adapter("http://kismet.example.com:2501")
    retry = adapter.max_retries
    assert retry.total == 3
    assert retry.backoff_factor == 0.5


def test_h5_get_devices_since_recovers_via_retry_aware_adapter(mocker):
    """Behavioural regression: with the configured ``max_retries.total``
    on the mounted adapter, a transport-level failure pattern of
    *fail-fail-success* surfaces as a successful response to the caller.

    Pre-fix: ``KismetClient`` had no ``_session``, so swapping in a
    test adapter (and indeed the whole Retry concept) wasn't an option —
    the first ``ConnectionError`` from ``requests.get`` propagated to the
    poll loop and crashed the daemon.

    Post-fix: a ``_RetryAwareAdapter`` mounted on ``client._session``
    consults ``self.max_retries.total`` (which is 3, per the production
    config) and absorbs up to three transient errors before surfacing
    one. Two failures before success is well within that envelope, so
    ``get_devices_since`` returns ``[]`` cleanly.
    """
    from requests.adapters import HTTPAdapter

    class _RetryAwareAdapter(HTTPAdapter):
        """Documentation-style adapter that respects ``max_retries.total``
        when simulating transport-level failures. Mirrors the contract
        urllib3's ``Retry`` enforces on the production ``HTTPAdapter``
        without requiring a live socket."""

        def __init__(self, fail_first_n: int, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.fail_first_n = fail_first_n
            self.send_calls = 0

        def send(self, request, **kwargs):
            allowance = self.max_retries.total + 1
            for _ in range(allowance):
                self.send_calls += 1
                if self.send_calls <= self.fail_first_n:
                    continue
                response = requests.Response()
                response.status_code = 200
                response._content = b"[]"
                response.url = request.url
                response.headers["Content-Type"] = "application/json"
                return response
            raise requests.ConnectionError("transport exhausted")

    client = KismetClient(base_url="http://kismet.test:2501")
    flaky = _RetryAwareAdapter(
        fail_first_n=2,
        max_retries=client._session.get_adapter("http://kismet.test:2501").max_retries,
    )
    client._session.mount("http://", flaky)

    result = client.get_devices_since(0)
    assert result == []
    assert flaky.send_calls == 3


def test_h5_4xx_does_not_trigger_retry(mocker):
    """Auth and client-error responses must NOT be retried — the operator
    fixed a bad token by editing config, not by waiting. 401 must surface
    immediately on the first attempt."""
    mock_get = mocker.patch("requests.sessions.Session.get")
    response = mock_get.return_value
    response.raise_for_status.side_effect = requests.HTTPError("401 Unauthorized")
    client = KismetClient(base_url="http://x:2501")
    with pytest.raises(requests.HTTPError) as exc_info:
        client.get_devices_since(0)
    assert "401" in str(exc_info.value)
    assert mock_get.call_count == 1


def test_h5_all_three_methods_use_self_session():
    """Source-level grep: every HTTP-issuing method on KismetClient must go
    through ``self._session`` so the mounted Retry adapter is engaged. The
    rc1 silent-drop bug had ``list_sources`` slip through with a bare
    ``requests.get`` despite the rest of the client being session-aware —
    a recurrence would re-introduce the no-retry path on that call.
    """
    src = Path(__file__).resolve().parent.parent / "src" / "lynceus" / "kismet.py"
    text = src.read_text(encoding="utf-8")
    # Find the KismetClient class body (bounded by the next class or EOF).
    start = text.index("class KismetClient")
    end = text.index("\nclass ", start + 1) if "\nclass " in text[start + 1 :] else len(text)
    body = text[start:end]
    # No bare ``requests.get`` on the class — must always go through the Session.
    assert "requests.get" not in body, (
        "KismetClient must not call requests.get directly; route through self._session"
    )
    # Each of the three HTTP-issuing methods must hit self._session.get.
    assert body.count("self._session.get(") == 3
