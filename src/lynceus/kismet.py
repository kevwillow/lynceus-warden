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
_BLE_MANUF_ID_RE = re.compile(r"^[0-9a-f]{4}$")
_DRONE_ID_RE = re.compile(r"^[A-Z0-9]{3,32}$")

_TYPE_MAP: dict[str, Literal["wifi", "ble", "bt_classic", "remote_id"]] = {
    "Wi-Fi AP": "wifi",
    "Wi-Fi Client": "wifi",
    "Wi-Fi Bridged": "wifi",
    "Wi-Fi Device": "wifi",
    "BTLE": "ble",
    "Bluetooth": "bt_classic",
    # Remote-ID Kismet device-type strings — UNVERIFIED guesses
    # against a live Kismet capture as of 2026-05-17. The Lynceus
    # codebase had no prior consumer of Remote-ID records, and
    # Kismet's exact emission for ASTM F3411 Remote-ID devices
    # varies by version + datasource configuration. The two
    # forms below cover the most plausible canonical shapes
    # (Kismet's general convention is "Hyphenated Title Case" for
    # the radio family, but Remote-ID-specific docs sometimes
    # use the bare "Remote ID" string).
    #
    # Operator follow-up: capture a live Remote-ID record from
    # /devices/views/all/devices.json and confirm the actual
    # kismet.device.base.type value. Add the confirmed string to
    # the front of this map; remove any stale guesses behind it.
    # See the rc5 CHANGELOG caveat for the residual probe-path
    # verification step.
    "Remote ID": "remote_id",
    "Remote ID Drone": "remote_id",
}


class DeviceObservation(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    mac: str
    device_type: Literal["wifi", "ble", "bt_classic", "remote_id"]
    first_seen: int
    last_seen: int
    rssi: int | None
    ssid: str | None
    oui_vendor: str | None
    is_randomized: bool
    ble_service_uuids: tuple[str, ...] = ()
    seen_by_sources: tuple[str, ...] = ()
    probe_ssids: tuple[str, ...] | None = None
    # BLE Core Spec §4.5.2 Complete Local Name extracted from the
    # Kismet device record via _extract_ble_name (gated on
    # capture_ble_name / capture.ble_friendly_names). Field name
    # matches the watchlist pattern_type 'ble_local_name' so the
    # rule matcher can read obs.ble_local_name against a pattern_type=
    # 'ble_local_name' DB row directly. None when capture is disabled
    # or the field is absent in the record. The devices.ble_name
    # column (migrations 006/014) is a separate forensic surface and
    # retains its historical name — renaming the column would force
    # an unnecessary table-rebuild migration.
    ble_local_name: str | None = None
    # Canonical persistent form of the Bluetooth SIG 16-bit Company
    # Identifier extracted from the BTLE advertisement payload — 4
    # lowercase hex chars, no '0x' prefix (e.g. '004c' for Apple).
    # Matches the form stored in watchlist.pattern for pattern_type
    # 'ble_manufacturer_id' so rules.evaluate's watchlist_ble_
    # manufacturer_id branch can equality-lookup directly. None
    # when not present in the Kismet record — see _extract_ble_
    # manufacturer_id for the field-path uncertainty caveat.
    ble_manufacturer_id: str | None = None
    # Canonical persistent form of an ANSI/CTA-2063-A Remote-ID
    # serial-number prefix extracted from a drone Remote-ID
    # broadcast — uppercase ASCII alphanumeric, 3-32 chars (e.g.
    # '21239ESA2'). Matches the form stored in watchlist.pattern
    # for pattern_type 'drone_id_prefix'. None when not present in
    # the Kismet record — see _extract_drone_id_prefix for the
    # field-path uncertainty caveat.
    drone_id_prefix: str | None = None
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

    @field_validator("ble_manufacturer_id")
    @classmethod
    def _validate_ble_manufacturer_id(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if not _BLE_MANUF_ID_RE.match(v):
            raise ValueError(
                f"invalid ble_manufacturer_id: {v!r} "
                f"(expected 4 lowercase hex chars, no '0x' prefix)"
            )
        return v

    @field_validator("drone_id_prefix")
    @classmethod
    def _validate_drone_id_prefix(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if not _DRONE_ID_RE.match(v):
            raise ValueError(
                f"invalid drone_id_prefix: {v!r} "
                f"(expected 3-32 uppercase ASCII alphanumeric chars)"
            )
        return v

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


# Kismet field-path table for BLE manufacturer-specific advertisement
# data. UNVERIFIED against a live Kismet capture as of 2026-05-17 —
# the Lynceus codebase had no prior consumer of this surface, so the
# paths here are derived from public Kismet schema documentation
# rather than confirmed against an emission. Each entry is a
# dotted-key sequence walked depth-first; the first path that
# resolves to a parseable 16-bit company id wins.
#
# Operators verifying this against a live deployment:
#   1. Capture one BTLE device record JSON (Kismet REST
#      /devices/by-mac/<mac>/device.json).
#   2. Identify the field name carrying the manufacturer-data
#      company id (often nested under an advertising_data / adv_data
#      structure with a 'company' / 'company_id' / 'cid' leaf).
#   3. Add the confirmed path to the front of this tuple; remove the
#      stale guesses behind it.
#
# Until then the resolver returns None for nearly every observation,
# the watchlist_ble_manufacturer_id delegation rule fires zero
# alerts on real hardware, and the import + DB pipeline is the only
# half of the feature that's load-bearing.
_BLE_MANUFACTURER_ID_PATHS: tuple[tuple[str, ...], ...] = (
    ("kismet.device.base.advdata", "manufacturer_data", "company_id"),
    ("kismet.device.base.advdata", "manufacturer_data", "company"),
    ("kismet.device.base.advdata", "company_id"),
    ("bluetooth.device.adv_data", "manufacturer_data", "company_id"),
    ("bluetooth.device.adv_data", "manufacturer_data", "company"),
    ("bluetooth.device", "manufacturer", "company_id"),
)


def _walk(raw: dict, path: tuple[str, ...]) -> object:
    cursor: object = raw
    for key in path:
        if isinstance(cursor, dict):
            cursor = cursor.get(key)
        elif isinstance(cursor, list) and cursor and isinstance(cursor[0], dict):
            # Manufacturer data is sometimes a list of dicts (one per
            # advertised company). Walk the first entry — multi-company
            # advertisements are vanishingly rare and the watchlist
            # equality lookup keys off a single company id anyway.
            cursor = cursor[0].get(key)
        else:
            return None
        if cursor is None:
            return None
    return cursor


def _coerce_ble_manufacturer_id(value: object) -> str | None:
    """Normalize a Kismet manufacturer-data company id to canonical form.

    Accepts int (BLE spec native shape) or hex/decimal-string (some
    decoders emit the human-readable hex form). Returns the canonical
    4-lowercase-hex-char string, or None for any value that can't be
    coerced cleanly (None, empty string, out-of-range int, non-hex).
    """
    if value is None:
        return None
    if isinstance(value, bool):
        # bool is an int subclass; reject explicitly. A true/false leaf
        # at one of the probe paths means we walked into a flag, not
        # the company id field.
        return None
    if isinstance(value, int):
        if not 0 <= value <= 0xFFFF:
            return None
        return f"{value:04x}"
    if isinstance(value, str):
        s = value.strip().lower()
        if not s:
            return None
        if s.startswith("0x"):
            s = s[2:]
        if not s or len(s) > 4 or not all(c in "0123456789abcdef" for c in s):
            return None
        return s.zfill(4)
    return None


def _extract_ble_manufacturer_id(raw: dict) -> str | None:
    """Best-effort extraction of the BLE company id from a Kismet record.

    See _BLE_MANUFACTURER_ID_PATHS for the field-path caveat. Returns
    None when no path resolves to a coercible value, which is the
    expected state until the paths are confirmed against a live
    capture.
    """
    for path in _BLE_MANUFACTURER_ID_PATHS:
        coerced = _coerce_ble_manufacturer_id(_walk(raw, path))
        if coerced is not None:
            return coerced
    return None


# Kismet field-path table for Remote-ID drone serial-number prefixes.
# Same UNVERIFIED caveat as _BLE_MANUFACTURER_ID_PATHS — Kismet's
# Remote-ID datasource (uavmon / similar) is a separate optional
# module and the Lynceus codebase had no prior consumer of its
# emission. Paths derived from public schema documentation; first
# match wins. The serial-number field typically lives under a
# remoteid.device.basic_id structure with leaves named 'serial',
# 'serial_number', or 'uas_id' depending on the broadcast variant
# (ANSI/CTA-2063-A Serial vs. CAA Registration vs. UAS UUID), or
# under the canonical Kismet kismet.device.base.* prefix that
# every other Kismet field uses.
#
# As of rc5 (migration 014 + _TYPE_MAP extension landing in the
# same commit) Remote-ID-typed records are admitted by _TYPE_MAP
# and devices.device_type, so a record reaching this helper has
# already cleared the type-layer gate. Drone Remote-ID can also
# arrive on records typed as 'Wi-Fi Device' (OCABS transmitters)
# or 'BTLE' (BT-RID broadcast variants), which is why this helper
# runs on every observation regardless of device_type — see the
# control-flow comment in parse_kismet_device.
#
# Operator follow-up: capture a live Remote-ID record from
# /devices/views/all/devices.json and confirm which path actually
# resolves; add the confirmed path to the front of this tuple and
# remove any stale guesses behind it. See the rc5 CHANGELOG
# caveat for the residual probe-path verification step.
_DRONE_ID_PATHS: tuple[tuple[str, ...], ...] = (
    # kismet.device.base.* prefix matches the convention every
    # other top-level Kismet field uses (kismet.device.base.type,
    # kismet.device.base.signal, kismet.device.base.advdata, …).
    # Most plausible canonical shape for the Remote-ID payload.
    ("kismet.device.base.remote_id", "serial_number"),
    ("kismet.device.base.remote_id", "uas_id"),
    # remoteid.device.basic_id — the structure name mirrors the
    # ASTM F3411 message-type field ("Basic ID"); leaves named
    # 'serial', 'serial_number', or 'uas_id' cover the broadcast
    # variants (ANSI/CTA-2063-A Serial, CAA Registration, UAS
    # UUID). Retained as fallbacks for older / alternate Kismet
    # RID datasources that may not use the kismet.device.base.*
    # prefix.
    ("remoteid.device.basic_id", "serial"),
    ("remoteid.device.basic_id", "serial_number"),
    ("remoteid.device.basic_id", "uas_id"),
)


def _coerce_drone_id_prefix(value: object) -> str | None:
    """Normalize a Kismet Remote-ID serial-number to canonical form.

    Accepts string; uppercases + strips. Returns the canonical
    uppercase ASCII alphanumeric string (3-32 chars), or None for
    any value that fails the shape check.
    """
    if not isinstance(value, str):
        return None
    s = value.strip().upper()
    if not (3 <= len(s) <= 32):
        return None
    if not s.isascii() or not s.isalnum():
        return None
    return s


def _extract_drone_id_prefix(raw: dict) -> str | None:
    """Best-effort extraction of a Remote-ID drone serial prefix.

    See _DRONE_ID_PATHS for the field-path caveat. Returns None
    when no path resolves to a coercible value, which is the
    expected state until the paths are confirmed against a live
    capture AND _TYPE_MAP is extended to admit Remote-ID device
    records.
    """
    for path in _DRONE_ID_PATHS:
        coerced = _coerce_drone_id_prefix(_walk(raw, path))
        if coerced is not None:
            return coerced
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
        logger.debug(
            "dropping kismet device, unrecognized type: type=%r mac=%r",
            kismet_type, raw_mac,
        )
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
            # Real Kismet emits two identifiers per seenby entry:
            # kismet.common.seenby.name (the user-facing source name,
            # defaulting to the interface name when no name= is set
            # on the kismet_site.conf source= line) and
            # kismet.common.seenby.uuid (the per-source UUID Kismet
            # generates at startup). The poller's source_allowlist
            # gate equality-matches against the names in the
            # operator's lynceus.yaml `kismet_sources:` list, which
            # are the human-readable names — so prefer the name
            # field. UUID fallback keeps records admittable if a
            # future Kismet revision drops the name field on some
            # source variant; the operator can then put UUIDs in
            # their allowlist to recover.
            name_v = entry.get("kismet.common.seenby.name")
            uuid_v = entry.get("kismet.common.seenby.uuid")
            label: str | None = None
            if isinstance(name_v, str) and name_v:
                label = name_v
            elif isinstance(uuid_v, str) and uuid_v:
                label = uuid_v
                logger.debug(
                    "seenby name missing, falling back to uuid: mac=%r uuid=%r",
                    raw_mac, uuid_v,
                )
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

    # BLE manufacturer id is BLE-specific. Probe the advertisement
    # data only on ble records — Wi-Fi devices don't have a 16-bit
    # company id in their adverts. Drone Remote-ID is type-agnostic
    # at the probe layer (Kismet's RID datasource may carry the
    # serial on records typed as 'Wi-Fi Device' for OCABS
    # transmitters or 'BTLE' for BT-RID, depending on broadcast
    # variant), so it runs on every record that reaches this point.
    ble_manufacturer_id: str | None = None
    if device_type == "ble":
        ble_manufacturer_id = _extract_ble_manufacturer_id(raw)
    drone_id_prefix = _extract_drone_id_prefix(raw)

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
        ble_local_name=ble_name,
        ble_manufacturer_id=ble_manufacturer_id,
        drone_id_prefix=drone_id_prefix,
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
        unparseable_counter: list[int] | None = None,
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
            if obs is None:
                if unparseable_counter is not None:
                    unparseable_counter[0] += 1
                continue
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
        unparseable_counter: list[int] | None = None,
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
                if obs is None:
                    if unparseable_counter is not None:
                        unparseable_counter[0] += 1
                    continue
                results.append(obs)
        return results

    def health_check(self) -> dict:
        return {"reachable": True, "version": "fake-fixture", "error": None}
