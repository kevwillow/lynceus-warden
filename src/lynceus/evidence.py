"""Evidence snapshot capture and retention.

When an alert fires, capture_evidence persists the full Kismet device
record at that moment, the recent RSSI history pulled from Kismet's
signal RRD, and (when present) the GPS fix. The captured row is the
foundational artefact for transparency reporting, FOIA requests,
journalism use cases, and v0.4.1 movement-aware alerting.

The capture is wrapped in a broad try/except: a malformed Kismet record
must NEVER prevent the alert itself from firing. Failures are logged at
WARNING — visible without being alarming — and the function returns
None so the caller can carry on.
"""

from __future__ import annotations

import json
import logging
import math
import time
from typing import Any

from .config import CaptureConfig
from .db import Database

logger = logging.getLogger(__name__)

STATE_KEY_LAST_EVIDENCE_PRUNE = "last_evidence_prune_ts"

# Kismet record paths.
_SIGNAL_KEY = "kismet.device.base.signal"
_SIGNAL_RRD_KEY = "kismet.common.signal.signal_rrd"
_RRD_LAST_TIME_KEY = "kismet.common.rrd.last_time"
_RRD_MINUTE_VEC_KEY = "kismet.common.rrd.minute_vec"

_LOCATION_KEY = "kismet.device.base.location"
_LOCATION_LAST_KEY = "kismet.common.location.last"
_LOCATION_GEOPOINT_KEY = "kismet.common.location.geopoint"
_LOCATION_ALT_KEY = "kismet.common.location.alt"
_LOCATION_TIME_KEY = "kismet.common.location.time_sec"

# Redaction targets — Kismet keys that carry the data the operator's
# capture toggles are meant to gate. These can appear at any nesting
# depth (inside seenby blocks, nested probed-SSID maps, etc.) so the
# walker recurses over both dicts and lists.
_PROBE_SSID_KEYS = frozenset(
    {
        "dot11.device.last_probed_ssid_csum_map",
        "dot11.probedssid.ssid",
    }
)
_BLE_NAME_KEYS = frozenset(
    {
        "btle.device.name",
        "btle.advertised.name",
    }
)
# kismet.device.base.name is the SSID for Wi-Fi devices and the BLE
# friendly name for BLE/Bluetooth devices. Strip it only when the device
# type at the top level is BLE-related; this preserves Wi-Fi SSIDs that
# are needed for triage.
_BLE_DEVICE_TYPES = frozenset({"BTLE", "Bluetooth"})
_DEVICE_TYPE_KEY = "kismet.device.base.type"
_DEVICE_NAME_KEY = "kismet.device.base.name"


def _sanitize_floats(obj: Any) -> Any:
    """Return a copy of obj with non-finite floats replaced by None.

    Kismet RRD blocks occasionally carry float('inf') / float('nan') as
    "no data" sentinels. json.dumps with default allow_nan=True emits
    these as the literal tokens Infinity / NaN, which are not valid
    JSON — strict consumers (FOIA export pipelines, journalist tooling)
    reject them. Walks dicts and lists recursively; non-container
    leaves are returned unchanged so the caller's cost is one pass.
    """
    if isinstance(obj, float) and not math.isfinite(obj):
        return None
    if isinstance(obj, dict):
        return {k: _sanitize_floats(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize_floats(item) for item in obj]
    return obj


def _json_default(obj: Any) -> str:
    """Custom json.dumps default that hex-encodes bytes/bytearray.

    Kismet plugin extensions occasionally return raw byte fields (binary
    BSSIDs, non-UTF-8 SSIDs). Stdlib json raises TypeError on bytes
    without a default; the previous default=str path stringified them as
    the literal repr ("b'\\xff\\xfe'") which is ugly and tool-hostile.
    Hex round-trips cleanly through any JSON consumer.
    """
    if isinstance(obj, bytes | bytearray):
        return obj.hex()
    return str(obj)


def _redact_kismet_record(record: dict, capture: CaptureConfig) -> dict:
    """Return a redacted deep copy of a Kismet device record.

    Honors ``capture.probe_ssids`` and ``capture.ble_friendly_names``:
    when either toggle is False, the corresponding fields are stripped
    everywhere they appear in the nested structure. The input record is
    never mutated — capture must not have side effects on data the
    poller is about to hand to other code paths.
    """
    is_ble_device = record.get(_DEVICE_TYPE_KEY) in _BLE_DEVICE_TYPES
    strip_ble_base_name = (not capture.ble_friendly_names) and is_ble_device

    def _walk(node: Any) -> Any:
        if isinstance(node, dict):
            out: dict = {}
            for k, v in node.items():
                if not capture.probe_ssids and k in _PROBE_SSID_KEYS:
                    continue
                if not capture.ble_friendly_names and k in _BLE_NAME_KEYS:
                    continue
                if strip_ble_base_name and k == _DEVICE_NAME_KEY:
                    continue
                out[k] = _walk(v)
            return out
        if isinstance(node, list):
            return [_walk(item) for item in node]
        return node

    return _walk(record)


def _extract_rssi_history(kismet_record: dict) -> list[dict] | None:
    """Pull the last-minute RSSI series out of the Kismet signal RRD.

    Returns a list of ``{"ts": ..., "rssi": ...}`` ordered oldest-first,
    or None when the RRD block is absent or malformed. Each per-second
    sample's timestamp is derived from ``last_time`` minus its offset
    in the reversed ``minute_vec``.
    """
    signal = kismet_record.get(_SIGNAL_KEY)
    if not isinstance(signal, dict):
        return None
    rrd = signal.get(_SIGNAL_RRD_KEY)
    if not isinstance(rrd, dict):
        return None
    minute_vec = rrd.get(_RRD_MINUTE_VEC_KEY)
    last_time = rrd.get(_RRD_LAST_TIME_KEY)
    if not isinstance(minute_vec, list) or not isinstance(last_time, int):
        return None
    return [{"ts": last_time - i, "rssi": v} for i, v in enumerate(reversed(minute_vec))]


def _extract_gps(kismet_record: dict) -> dict[str, Any]:
    """Return ``{"lat", "lon", "alt", "captured_at"}`` — values are None
    when the location block is absent or the relevant key is missing."""
    out: dict[str, Any] = {"lat": None, "lon": None, "alt": None, "captured_at": None}
    loc = kismet_record.get(_LOCATION_KEY)
    if not isinstance(loc, dict):
        return out
    last = loc.get(_LOCATION_LAST_KEY)
    if not isinstance(last, dict):
        return out
    geopoint = last.get(_LOCATION_GEOPOINT_KEY)
    if isinstance(geopoint, list) and len(geopoint) >= 2:
        # Kismet's geopoint is [lon, lat], not [lat, lon].
        try:
            out["lon"] = float(geopoint[0])
            out["lat"] = float(geopoint[1])
        except (TypeError, ValueError):
            pass
    alt = last.get(_LOCATION_ALT_KEY)
    if isinstance(alt, int | float):
        out["alt"] = float(alt)
    captured_at = last.get(_LOCATION_TIME_KEY)
    if isinstance(captured_at, int):
        out["captured_at"] = captured_at
    return out


def capture_evidence(
    db: Database,
    alert_id: int,
    mac: str,
    kismet_record: Any,
    *,
    now_ts: int | None = None,
    capture: CaptureConfig | None = None,
    store_gps: bool = False,
) -> int | None:
    """Persist an evidence snapshot for the given alert.

    Returns the new row id on success, or None on capture failure (in
    which case a WARNING is logged). Never raises — the alert path is
    too important to derail on a malformed Kismet record.

    ``capture`` gates which sensitive fields are persisted into
    ``kismet_record_json``. When the operator has disabled probe-SSID or
    BLE-friendly-name capture, those fields must not slip into evidence
    via the verbatim-record path. Defaults to a fresh ``CaptureConfig``
    (probe_ssids=False, ble_friendly_names=True) so direct callers
    without an explicit config get the privacy-conservative behaviour.

    ``store_gps`` gates whether the GPS columns (gps_lat/lon/alt and
    gps_captured_at) are populated. The geopoint Kismet emits is the
    receiver's GPS fix, not the observed device's, so persisting it
    builds a high-resolution operator-movement log. Opt-in by default;
    when False the columns stay NULL even if the record contains
    location data.
    """
    try:
        if now_ts is None:
            now_ts = int(time.time())
        if capture is None:
            capture = CaptureConfig()
        if not isinstance(kismet_record, dict):
            raise TypeError(f"kismet_record must be a dict, got {type(kismet_record).__name__}")
        kismet_record = _redact_kismet_record(kismet_record, capture)
        kismet_record = _sanitize_floats(kismet_record)
        # json.dumps with _json_default copes with datetime / set / Decimal
        # / bytes values that occasionally sneak into Kismet records via
        # plugin extensions. It still raises on circular references —
        # that path is deliberately exercised by the regression test.
        kismet_record_json = json.dumps(kismet_record, default=_json_default)
        rssi_history = _extract_rssi_history(kismet_record)
        gps = (
            _extract_gps(kismet_record)
            if store_gps
            else {"lat": None, "lon": None, "alt": None, "captured_at": None}
        )
        rssi_history_json = (
            json.dumps(_sanitize_floats(rssi_history)) if rssi_history is not None else None
        )
        with db._conn:
            cur = db._conn.execute(
                "INSERT INTO evidence_snapshots("
                "alert_id, mac, captured_at, kismet_record_json, "
                "rssi_history_json, gps_lat, gps_lon, gps_alt, gps_captured_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    alert_id,
                    mac,
                    now_ts,
                    kismet_record_json,
                    rssi_history_json,
                    gps["lat"],
                    gps["lon"],
                    gps["alt"],
                    gps["captured_at"],
                ),
            )
            return int(cur.lastrowid)
    except Exception as exc:
        logger.warning(
            "Failed to capture evidence for alert %s (mac %s): %s",
            alert_id,
            mac,
            exc,
        )
        return None


def prune_old_evidence(
    db: Database,
    retention_days: int,
    *,
    now_ts: int | None = None,
) -> tuple[int, int | None]:
    """Delete evidence rows older than ``retention_days``.

    Returns ``(rows_deleted, oldest_remaining_captured_at)``. The second
    element is None when the table is empty after pruning. Logs at INFO
    so a daily run leaves an audit trail in journalctl.
    """
    if now_ts is None:
        now_ts = int(time.time())
    cutoff = now_ts - retention_days * 86400
    with db._conn:
        cur = db._conn.execute(
            "DELETE FROM evidence_snapshots WHERE captured_at < ?",
            (cutoff,),
        )
        deleted = cur.rowcount
        oldest_row = db._conn.execute("SELECT MIN(captured_at) FROM evidence_snapshots").fetchone()
    oldest = int(oldest_row[0]) if oldest_row and oldest_row[0] is not None else None
    logger.info("Pruned %d evidence snapshots older than %d days", deleted, retention_days)
    return deleted, oldest


def maybe_prune_evidence(
    db: Database,
    retention_days: int,
    *,
    now_ts: int | None = None,
    interval_seconds: int = 86400,
) -> bool:
    """Run prune_old_evidence at most once per ``interval_seconds``.

    Returns True when prune actually executed, False when it was skipped
    because the previous run is too recent. State is recorded under
    ``STATE_KEY_LAST_EVIDENCE_PRUNE`` in the existing poller_state table.
    """
    if now_ts is None:
        now_ts = int(time.time())
    last_raw = db.get_state(STATE_KEY_LAST_EVIDENCE_PRUNE)
    if last_raw is not None:
        try:
            last = int(last_raw)
        except (TypeError, ValueError):
            last = 0
        if now_ts - last < interval_seconds:
            return False
    prune_old_evidence(db, retention_days, now_ts=now_ts)
    db.set_state(STATE_KEY_LAST_EVIDENCE_PRUNE, str(now_ts))
    return True
