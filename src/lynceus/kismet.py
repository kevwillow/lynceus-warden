"""Kismet REST API client: query devices, alerts, and channel state."""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Literal

import requests
from pydantic import BaseModel, ConfigDict, field_validator, model_validator
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

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
    ble_service_uuids: tuple[str, ...] = ()
    seen_by_sources: tuple[str, ...] = ()
    probe_ssids: tuple[str, ...] | None = None
    ble_name: str | None = None
    # Carries the original Kismet device record so the alert path can hand
    # it to evidence capture without a second REST call. Only populated by
    # parse_kismet_device — test stubs that build observations directly
    # leave this None and the capture path no-ops.
    raw_record: dict | None = None

    @field_validator("mac")
    @classmethod
    def _validate_mac(cls, v: str) -> str:
        if not _MAC_RE.match(v):
            raise ValueError(f"invalid mac: {v!r}")
        return v

    @field_validator("ble_service_uuids")
    @classmethod
    def _validate_uuids(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        for u in v:
            if not _UUID_RE.match(u):
                raise ValueError(f"invalid ble service uuid: {u!r}")
        return v

    @field_validator("seen_by_sources")
    @classmethod
    def _validate_seen_by_sources(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        if len(v) > 16:
            raise ValueError(f"seen_by_sources may have at most 16 entries, got {len(v)}")
        for s in v:
            if not isinstance(s, str) or not s:
                raise ValueError(f"seen_by_sources entries must be non-empty strings: {s!r}")
        return v

    @field_validator("probe_ssids")
    @classmethod
    def _validate_probe_ssids(cls, v: tuple[str, ...] | None) -> tuple[str, ...] | None:
        if v is None:
            return None
        for s in v:
            if not isinstance(s, str):
                raise ValueError(f"probe_ssids entries must be strings: {s!r}")
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

    @model_validator(mode="after")
    def _drop_uuids_for_non_ble(self) -> DeviceObservation:
        if self.device_type != "ble" and self.ble_service_uuids:
            object.__setattr__(self, "ble_service_uuids", ())
        return self


def normalize_mac(mac: str) -> str:
    s = mac.strip().lower().replace("-", ":")
    if not _MAC_RE.match(s):
        raise ValueError(f"invalid mac: {mac!r}")
    return s


def normalize_uuid(s: str) -> str:
    norm = s.strip().lower()
    if not _UUID_RE.match(norm):
        raise ValueError(f"invalid uuid: {s!r}")
    return norm


def is_locally_administered(mac: str) -> bool:
    norm = normalize_mac(mac)
    first_octet = int(norm[:2], 16)
    return bool(first_octet & 0x02)


_DOT11_DEVICE_FIELD = "dot11.device"
_PROBED_SSID_MAP_FIELD = "dot11.device.last_probed_ssid_csum_map"
_PROBED_SSID_RECORD_FIELD = "dot11.probedssid.ssid"
_BLE_NAME_FIELD = "kismet.device.base.name"


def _extract_probe_ssids(raw: dict) -> tuple[str, ...]:
    """Pull probed-SSID strings out of a Wi-Fi client's dot11.device sub-tree.

    Only called when ``capture.probe_ssids`` is True — opt-out callers
    must not invoke this function so the data does not enter memory.
    """
    dot11 = raw.get(_DOT11_DEVICE_FIELD)
    if not isinstance(dot11, dict):
        return ()
    csum_map = dot11.get(_PROBED_SSID_MAP_FIELD)
    if not isinstance(csum_map, dict):
        return ()
    collected: list[str] = []
    seen: set[str] = set()
    for record in csum_map.values():
        if not isinstance(record, dict):
            continue
        ssid = record.get(_PROBED_SSID_RECORD_FIELD)
        if not isinstance(ssid, str) or not ssid:
            continue
        if ssid in seen:
            continue
        seen.add(ssid)
        collected.append(ssid)
    return tuple(collected)


def _extract_ble_name(raw: dict) -> str | None:
    """Pull the BLE friendly name out of a kismet device record.

    Only called when ``capture.ble_friendly_names`` is True. Returns
    None when the field is absent or an empty string.
    """
    name = raw.get(_BLE_NAME_FIELD)
    if isinstance(name, str) and name:
        return name
    return None


def parse_kismet_device(
    raw: dict,
    *,
    capture_probe_ssids: bool = False,
    capture_ble_name: bool = False,
    evidence_capture_enabled: bool = False,
) -> DeviceObservation | None:
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

    ble_service_uuids: tuple[str, ...] = ()
    if device_type == "ble":
        raw_uuids = raw.get("kismet.device.base.service_uuids") or []
        if isinstance(raw_uuids, list):
            normalized: list[str] = []
            for u in raw_uuids:
                if not isinstance(u, str):
                    logger.debug("dropping non-string ble service uuid: %r", u)
                    continue
                try:
                    normalized.append(normalize_uuid(u))
                except ValueError:
                    logger.debug("dropping malformed ble service uuid: %r", u)
            ble_service_uuids = tuple(normalized)

    seen_by_sources: tuple[str, ...] = ()
    raw_seenby = raw.get("kismet.device.base.seenby")
    if isinstance(raw_seenby, list):
        collected: list[str] = []
        seen: set[str] = set()
        for entry in raw_seenby:
            if not isinstance(entry, dict):
                continue
            label: str | None = None
            for key in ("kismet.common.seenby.source", "kismet.common.seenby.uuid"):
                v = entry.get(key)
                if isinstance(v, str) and v:
                    label = v
                    break
            if label is None or label in seen:
                continue
            seen.add(label)
            collected.append(label)
            if len(collected) >= 16:
                break
        seen_by_sources = tuple(collected)

    probe_ssids: tuple[str, ...] | None = None
    if capture_probe_ssids and device_type == "wifi":
        probe_ssids = _extract_probe_ssids(raw)

    ble_name: str | None = None
    if capture_ble_name and device_type == "ble":
        ble_name = _extract_ble_name(raw)

    return DeviceObservation(
        mac=mac,
        device_type=device_type,
        first_seen=first_time,
        last_seen=last_time,
        rssi=rssi,
        ssid=ssid,
        oui_vendor=oui_vendor,
        is_randomized=is_locally_administered(mac),
        ble_service_uuids=ble_service_uuids,
        seen_by_sources=seen_by_sources,
        probe_ssids=probe_ssids,
        ble_name=ble_name,
        # Only carry the full Kismet record forward when evidence
        # capture is enabled. Each record is tens of KB; for a poll
        # batch of hundreds of devices, holding all of them in memory
        # until poll_once returns is multi-MB of needless overhead
        # when the evidence path will not consume them.
        raw_record=raw if evidence_capture_enabled else None,
    )


class KismetClient:
    def __init__(self, base_url: str, api_key: str | None = None, timeout: float = 10.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        # Mount a urllib3 Retry policy so a single Kismet 5xx, transient
        # connection error, or read timeout no longer crashes the poll
        # tick. Auth (4xx) failures are caller's problem — retrying won't
        # change the answer — so they are NOT in status_forcelist.
        self._session = requests.Session()
        retry = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=(502, 503, 504),
            allowed_methods=("GET",),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)

    def get_devices_since(
        self,
        since_ts: int,
        *,
        capture_probe_ssids: bool = False,
        capture_ble_name: bool = False,
        evidence_capture_enabled: bool = False,
    ) -> list[DeviceObservation]:
        url = f"{self.base_url}/devices/last-time/{since_ts}/devices.json"
        kwargs: dict[str, Any] = {"timeout": self.timeout}
        if self.api_key:
            kwargs["cookies"] = {"KISMET": self.api_key}
        response = self._session.get(url, **kwargs)
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, list):
            raise ValueError(f"expected list response, got {type(data).__name__}")
        results: list[DeviceObservation] = []
        for raw in data:
            obs = parse_kismet_device(
                raw,
                capture_probe_ssids=capture_probe_ssids,
                capture_ble_name=capture_ble_name,
                evidence_capture_enabled=evidence_capture_enabled,
            )
            if obs is not None:
                results.append(obs)
        return results

    def health_check(self) -> dict:
        url = f"{self.base_url}/system/status.json"
        kwargs: dict[str, Any] = {"timeout": self.timeout}
        if self.api_key:
            kwargs["cookies"] = {"KISMET": self.api_key}
        try:
            response = self._session.get(url, **kwargs)
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as e:
            return {"reachable": False, "version": None, "error": str(e)}
        except ValueError as e:
            return {"reachable": False, "version": None, "error": f"invalid json: {e}"}
        version: str | None = None
        if isinstance(data, dict):
            v = data.get("kismet.system.version")
            if isinstance(v, str) and v:
                version = v
        return {"reachable": True, "version": version, "error": None}

    def list_sources(self, *, only_running: bool = True) -> list[dict[str, Any]]:
        """Query Kismet's configured datasources.

        Returns one normalized dict per source with keys: ``name``,
        ``interface``, ``capture_interface``, ``uuid``, ``driver``,
        ``running``. The ``name`` is the value Kismet uses on the wire and
        is what the poller filters against — distinct from the kernel
        interface (``wlan1``) and the actual capture interface
        (``wlan1mon``). Misalignment between the wizard-prompted value and
        the source name is the silent-drop bug this method fixes.

        Sources whose ``kismet.datasource.running`` is falsy are excluded by
        default (a source in error state can't produce observations and
        offering it to the operator just confuses things).

        Raises ``requests.HTTPError`` on non-2xx responses, ``ValueError``
        on malformed JSON or non-list payloads, and ``requests.RequestException``
        subclasses (Timeout, ConnectionError) on transport failures. Caller
        decides how to handle each.
        """
        url = f"{self.base_url}/datasource/all_sources.json"
        kwargs: dict[str, Any] = {"timeout": self.timeout}
        if self.api_key:
            kwargs["cookies"] = {"KISMET": self.api_key}
        response = self._session.get(url, **kwargs)
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, list):
            raise ValueError(f"expected list response, got {type(data).__name__}")
        sources: list[dict[str, Any]] = []
        for raw in data:
            if not isinstance(raw, dict):
                continue
            running = bool(raw.get("kismet.datasource.running", False))
            if only_running and not running:
                continue
            type_driver = raw.get("kismet.datasource.type_driver")
            driver = ""
            if isinstance(type_driver, dict):
                d = type_driver.get("kismet.datasource.driver.type")
                if isinstance(d, str):
                    driver = d
            sources.append(
                {
                    "name": str(raw.get("kismet.datasource.name") or ""),
                    "interface": str(raw.get("kismet.datasource.interface") or ""),
                    "capture_interface": str(raw.get("kismet.datasource.capture_interface") or ""),
                    "uuid": str(raw.get("kismet.datasource.uuid") or ""),
                    "driver": driver,
                    "running": running,
                }
            )
        return sources


class FakeKismetClient(KismetClient):
    def __init__(self, fixture_path: str) -> None:
        super().__init__(base_url="", api_key=None)
        self._fixture_path = fixture_path
        with open(fixture_path, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise ValueError(f"fixture must be a list, got {type(data).__name__}")
        self._fixture: list[dict] = data

    def get_devices_since(
        self,
        since_ts: int,
        *,
        capture_probe_ssids: bool = False,
        capture_ble_name: bool = False,
        evidence_capture_enabled: bool = False,
    ) -> list[DeviceObservation]:
        results: list[DeviceObservation] = []
        for raw in self._fixture:
            if raw.get("kismet.device.base.last_time", 0) >= since_ts:
                obs = parse_kismet_device(
                    raw,
                    capture_probe_ssids=capture_probe_ssids,
                    capture_ble_name=capture_ble_name,
                    evidence_capture_enabled=evidence_capture_enabled,
                )
                if obs is not None:
                    results.append(obs)
        return results

    def health_check(self) -> dict:
        return {"reachable": True, "version": "fake-fixture", "error": None}
