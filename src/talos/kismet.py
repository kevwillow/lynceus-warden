"""Kismet REST API client: query devices, alerts, and channel state."""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Literal

import requests
from pydantic import BaseModel, ConfigDict, field_validator, model_validator

logger = logging.getLogger(__name__)

_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")

_TYPE_MAP: dict[str, Literal["wifi", "ble", "bt_classic"]] = {
    "Wi-Fi AP": "wifi",
    "Wi-Fi Client": "wifi",
    "Wi-Fi Bridged": "wifi",
    "Wi-Fi Device": "wifi",
    "BTLE": "ble",
    "Bluetooth": "bt_classic",
}


class DeviceObservation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    mac: str
    device_type: Literal["wifi", "ble", "bt_classic"]
    first_seen: int
    last_seen: int
    rssi: int | None
    ssid: str | None
    oui_vendor: str | None
    is_randomized: bool

    @field_validator("mac")
    @classmethod
    def _validate_mac(cls, v: str) -> str:
        if not _MAC_RE.match(v):
            raise ValueError(f"invalid mac: {v!r}")
        return v

    @field_validator("first_seen")
    @classmethod
    def _validate_first_seen(cls, v: int) -> int:
        if v <= 0:
            raise ValueError("first_seen must be > 0")
        return v

    @model_validator(mode="after")
    def _validate_last_after_first(self) -> DeviceObservation:
        if self.last_seen < self.first_seen:
            raise ValueError("last_seen must be >= first_seen")
        return self


def normalize_mac(mac: str) -> str:
    s = mac.strip().lower().replace("-", ":")
    if not _MAC_RE.match(s):
        raise ValueError(f"invalid mac: {mac!r}")
    return s


def is_locally_administered(mac: str) -> bool:
    norm = normalize_mac(mac)
    first_octet = int(norm[:2], 16)
    return bool(first_octet & 0x02)


def parse_kismet_device(raw: dict) -> DeviceObservation | None:
    raw_mac = raw.get("kismet.device.base.macaddr")
    kismet_type = raw.get("kismet.device.base.type")
    first_time = raw.get("kismet.device.base.first_time")
    last_time = raw.get("kismet.device.base.last_time")

    if raw_mac is None or kismet_type is None or first_time is None or last_time is None:
        logger.warning("dropping kismet device, missing required field: mac=%r", raw_mac)
        return None

    device_type = _TYPE_MAP.get(kismet_type)
    if device_type is None:
        return None

    try:
        mac = normalize_mac(raw_mac)
    except ValueError:
        logger.warning("dropping kismet device, malformed mac: %r", raw_mac)
        return None

    signal = raw.get("kismet.device.base.signal")
    rssi = signal.get("kismet.common.signal.last_signal") if isinstance(signal, dict) else None

    oui_vendor = raw.get("kismet.device.base.manuf")

    if device_type == "wifi":
        ssid = raw.get("kismet.device.base.name")
    else:
        ssid = None

    return DeviceObservation(
        mac=mac,
        device_type=device_type,
        first_seen=first_time,
        last_seen=last_time,
        rssi=rssi,
        ssid=ssid,
        oui_vendor=oui_vendor,
        is_randomized=is_locally_administered(mac),
    )


class KismetClient:
    def __init__(self, base_url: str, api_key: str | None = None, timeout: float = 10.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def get_devices_since(self, since_ts: int) -> list[DeviceObservation]:
        url = f"{self.base_url}/devices/last-time/{since_ts}/devices.json"
        kwargs: dict[str, Any] = {"timeout": self.timeout}
        if self.api_key:
            kwargs["cookies"] = {"KISMET": self.api_key}
        response = requests.get(url, **kwargs)
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, list):
            raise ValueError(f"expected list response, got {type(data).__name__}")
        results: list[DeviceObservation] = []
        for raw in data:
            obs = parse_kismet_device(raw)
            if obs is not None:
                results.append(obs)
        return results


class FakeKismetClient(KismetClient):
    def __init__(self, fixture_path: str) -> None:
        super().__init__(base_url="", api_key=None)
        self._fixture_path = fixture_path
        with open(fixture_path, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise ValueError(f"fixture must be a list, got {type(data).__name__}")
        self._fixture: list[dict] = data

    def get_devices_since(self, since_ts: int) -> list[DeviceObservation]:
        results: list[DeviceObservation] = []
        for raw in self._fixture:
            if raw.get("kismet.device.base.last_time", 0) >= since_ts:
                obs = parse_kismet_device(raw)
                if obs is not None:
                    results.append(obs)
        return results
