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
import time
from typing import Any

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
) -> int | None:
    """Persist an evidence snapshot for the given alert.

    Returns the new row id on success, or None on capture failure (in
    which case a WARNING is logged). Never raises — the alert path is
    too important to derail on a malformed Kismet record.
    """
    try:
        if now_ts is None:
            now_ts = int(time.time())
        if not isinstance(kismet_record, dict):
            raise TypeError(f"kismet_record must be a dict, got {type(kismet_record).__name__}")
        # json.dumps with default=str copes with datetime / set / Decimal
        # values that occasionally sneak into Kismet records via plugin
        # extensions. It still raises on circular references — that path
        # is deliberately exercised by the regression test.
        kismet_record_json = json.dumps(kismet_record, default=str)
        rssi_history = _extract_rssi_history(kismet_record)
        gps = _extract_gps(kismet_record)
        rssi_history_json = json.dumps(rssi_history) if rssi_history is not None else None
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
