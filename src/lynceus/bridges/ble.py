"""Passive BLE capture bridge — tick-model core + standalone smoke runner.

Promotes the rig-validated passive-scan recipe and DeviceObservation
construction from ``scripts/spike_ble_bridge.py`` into a dependency-injected
core that reuses ``poller.process_observation`` instead of the spike's direct
``evaluate`` -> ``add_alert`` path. A per-MAC dedup buffer is flushed on its own
tick interval; each buffered MAC becomes ONE BLE observation run through the
shared pipeline.

This increment is deliberately NOT wired into the Poller and enables no rule or
curation of its own — it passes whatever ruleset/allowlist it is handed straight
through. The bridge owns its OWN ``Database`` on ``config.db_path`` (the WAL
second-writer pattern); it never shares the Poller's connection or mutates
Poller-owned state.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import shutil
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from ..allowlist import Allowlist
from ..ble_continuity import classify_manufacturer_data
from ..config import load_config
from ..db import Database
from ..kismet import DeviceObservation, normalize_mac, normalize_uuid
from ..notify import NullNotifier, build_notifier
from ..poller import process_observation
from ..rules import Ruleset, load_ruleset, load_runtime_severity_overrides

logger = logging.getLogger(__name__)

# bleak is rig-only; absent on the dev box. Guarded so the module stays
# importable (unit tests mock the pipeline; the scan path is never exercised
# off-rig). Mirrors scripts/spike_ble_bridge.py:74-84.
try:
    from bleak import BleakScanner

    try:
        from bleak.args.bluez import BlueZScannerArgs, OrPattern
    except ImportError:  # older bleak module layout fallback
        from bleak.backends.bluezdbus.advertisement_monitor import OrPattern
        from bleak.backends.bluezdbus.scanner import BlueZScannerArgs
    _BLEAK_IMPORT_ERROR: str | None = None
except Exception as _exc:  # pragma: no cover - rig-only path
    _BLEAK_IMPORT_ERROR = f"{type(_exc).__name__}: {_exc}"

# Passive AdvertisementMonitor recipe promoted verbatim from the spike
# (scripts/spike_ble_bridge.py:97-103): BlueZ needs a non-empty or_patterns set
# and drops the monitor above ~7 patterns; the working set is the Flags AD type
# (0x01) with each of these single content bytes.
_FLAGS_AD_TYPE = 0x01
_FLAGS_CONTENT_BYTES = (0x06, 0x1A, 0x02, 0x04, 0x05, 0x00)

# Rig prod DB — the bridge WRITES (devices/sightings), so a smoke run must never
# target it. Promoted from scripts/spike_ble_bridge.py:88.
_PROD_DB_PATH = "/home/guru/.local/share/lynceus/lynceus.db"

# Backoff before restarting the scan after a bleak/BlueZ failure.
_RESTART_BACKOFF_SECONDS = 5.0


def _derive_is_randomized(mac: str) -> bool:
    """Spike-grade randomized-address guess from the address MSBs.

    BLE address randomness is signalled by the HCI address-type field, which
    bleak's AdvertisementData does not surface here; this is a heuristic on the
    top two bits of the most-significant octet: 0b11 (static random) and 0b01
    (resolvable private) are treated as randomized. Imperfect for public
    addresses by design — but is_randomized only feeds the
    new_non_randomized_device rule, which this increment does not enable, so it
    has no bearing on capture. Promoted from scripts/spike_ble_bridge.py:106-118.
    """
    first_octet = int(mac[:2], 16)
    return (first_octet >> 6) in (0b11, 0b01)


@dataclass
class _BufferEntry:
    """Latest advert seen for a MAC within the current flush window."""

    first_seen: int
    last_seen: int
    rssi: int | None
    manufacturer_ids: tuple[int, ...]
    service_uuids: tuple[str, ...]
    # Derived Continuity label only — never raw payload bytes.
    device_class: str | None = None


class BleBridge:
    """Dependency-injected passive BLE bridge core.

    All collaborators are injected so the next increment can hand it the
    Poller's already-built deps (ruleset, allowlist, notifier,
    severity_overrides) unchanged. The bridge keeps a per-MAC buffer of the
    latest advert and flushes it on ``flush_interval`` through
    ``process_observation``.
    """

    def __init__(
        self,
        *,
        db: Database,
        config,
        ruleset,
        allowlist_provider: Callable[[], Allowlist],
        notifier,
        severity_overrides,
        location_id: str,
        location_label: str,
        adapter: str,
        flush_interval: float,
    ) -> None:
        self.db = db
        self.config = config
        self.ruleset = ruleset
        # Allowlist is read LIVE at each flush via this provider, so the Poller's
        # hot-reloaded allowlist (reassigned atomically on edit) reaches the
        # bridge without rebuilding it. The standalone runner passes a lambda
        # returning a fixed Allowlist. ruleset/notifier/config/severity_overrides
        # are build-once and stay fixed.
        self._allowlist_provider = allowlist_provider
        self.notifier = notifier
        self.severity_overrides = severity_overrides
        self.location_id = location_id
        self.location_label = location_label
        self.adapter = adapter
        self.flush_interval = flush_interval
        self._buffer: dict[str, _BufferEntry] = {}
        # Bridge-lived: tracks locations already ensured so process_observation
        # does not re-commit the row on every flush (it owns the dedup check).
        self._ensured_locations: set[str] = set()
        # Bridge-owned per-rule_type suppression breakdown handed to
        # process_observation. Accumulates across flushes; not surfaced in this
        # increment (no periodic summary yet).
        self._rule_type_suppression_counter: dict[str, int] = {}
        # Thread-safe stop plumbing. stop() may be called from another thread
        # (the Poller's shutdown path) before or after run() has built its event
        # loop; _stop_requested bridges that gap and run() re-checks it on entry.
        self._stop_requested = threading.Event()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._asyncio_stop: asyncio.Event | None = None

    # --- buffer + observation construction (the unit-tested seams) ---------

    def _record_advert(
        self,
        *,
        mac_raw: str,
        rssi: int | None,
        manufacturer_data,
        service_uuids,
    ) -> None:
        """Fold one advertisement into the per-MAC buffer (latest wins)."""
        try:
            mac = normalize_mac(mac_raw)  # lowercases + validates against _MAC_RE
        except ValueError:
            return  # non-MAC address form (e.g. a macOS UUID) — skip, never buffer
        now = int(time.time())
        # Keep only the company-id keys; the advert payload bytes are not needed
        # and are dropped (privacy-lean — we never retain advertisement content).
        manufacturer_ids = tuple(manufacturer_data or ())
        uuids = tuple(service_uuids or ())
        # Raw payload bytes are read HERE and nowhere else, and only the
        # derived label is kept — see ble_continuity's module docstring.
        device_class = classify_manufacturer_data(manufacturer_data)
        existing = self._buffer.get(mac)
        if existing is None:
            self._buffer[mac] = _BufferEntry(
                first_seen=now,
                last_seen=now,
                rssi=rssi,
                manufacturer_ids=manufacturer_ids,
                service_uuids=uuids,
                device_class=device_class,
            )
        else:
            # Keep the latest advert's fields; preserve the window's first_seen.
            existing.last_seen = now
            existing.rssi = rssi
            existing.manufacturer_ids = manufacturer_ids
            existing.service_uuids = uuids
            existing.device_class = device_class

    @staticmethod
    def _select_manufacturer_id(manufacturer_ids) -> str | None:
        """Pick a Bluetooth SIG 16-bit Company Identifier as canonical hex.

        ``f"{cid:04x}"`` with a ``0 <= cid <= 0xffff`` guard, matching the
        ble_manufacturer_id field validator (kismet.py:19). One advert almost
        always carries a single company id; when several are present we pick the
        lowest for a deterministic choice (curation is a later increment).
        Promoted from scripts/spike_ble_bridge.py:169-172.
        """
        valid = sorted(c for c in manufacturer_ids if isinstance(c, int) and 0 <= c <= 0xFFFF)
        return f"{valid[0]:04x}" if valid else None

    @staticmethod
    def _normalize_uuids(service_uuids) -> tuple[str, ...]:
        """Lowercase + validate to full 128-bit form, dropping anything invalid."""
        out: list[str] = []
        for u in service_uuids:
            try:
                out.append(normalize_uuid(u))
            except (ValueError, TypeError):
                logger.debug("dropping invalid BLE service uuid: %r", u)
        return tuple(out)

    def _build_observation(self, mac: str, entry: _BufferEntry) -> DeviceObservation:
        """Build ONE BLE DeviceObservation for a buffered MAC.

        Construction promoted from scripts/spike_ble_bridge.py:179-189, with
        provenance (``seen_by_sources``) and service UUIDs added for the bridge.
        """
        return DeviceObservation(
            device_type="ble",  # MUST be "ble" or ble fields get blanked (kismet.py:196)
            mac=mac,
            first_seen=entry.first_seen,
            last_seen=entry.last_seen,
            rssi=entry.rssi,
            ssid=None,
            oui_vendor=None,
            is_randomized=_derive_is_randomized(mac),
            ble_manufacturer_id=self._select_manufacturer_id(entry.manufacturer_ids),
            ble_service_uuids=self._normalize_uuids(entry.service_uuids),
            seen_by_sources=(f"ble:{self.adapter}",),
            ble_device_class=entry.device_class,
        )

    def _flush(self, now_ts: int) -> int:
        """Drain the buffer: one process_observation call per buffered MAC.

        Returns the number of observations handed to the pipeline. The buffer is
        cleared up front so adverts arriving during the flush land in a fresh
        window.
        """
        if not self._buffer:
            return 0
        buffered = list(self._buffer.items())
        self._buffer = {}
        # Fresh per-flush accumulators, mirroring poll_once's per-tick pair
        # (process_observation mutates them in place). The bridge does not
        # surface these counts in this increment.
        processed = [0]
        admitted = [0]
        allowlist = self._allowlist_provider()  # LIVE read — picks up hot reloads
        count = 0
        for mac, entry in buffered:
            try:
                obs = self._build_observation(mac, entry)
                process_observation(
                    obs,
                    self.db,
                    self.config,
                    now_ts,
                    effective_location_id=self.location_id,
                    effective_location_label=self.location_label,
                    ensured_locations=self._ensured_locations,
                    processed_counter=processed,
                    admitted_counter=admitted,
                    ruleset=self.ruleset,
                    allowlist=allowlist,
                    notifier=self.notifier,
                    severity_overrides=self.severity_overrides,
                    rule_type_suppression_counter=self._rule_type_suppression_counter,
                )
            except Exception as exc:
                logger.warning("BLE flush: process_observation failed for %s: %s", mac, exc)
                continue
            count += 1
        return count

    # --- scan loop (rig-only; not unit-tested — no adapter off-rig) --------

    def _ensure_startup_location(self) -> None:
        """Ensure the default location once at startup.

        Uses the Database's default busy_timeout (5s, the Python sqlite3
        default). Explicit busy_timeout tuning for the WAL second-writer case is
        a hardening follow-up and intentionally NOT done here — this increment
        must not modify the shared Database class.
        """
        if self.location_id not in self._ensured_locations:
            self.db.ensure_location(self.location_id, self.location_label)
            self._ensured_locations.add(self.location_id)

    def _detection_callback(self, device, advertisement_data) -> None:
        self._record_advert(
            mac_raw=device.address,
            rssi=getattr(advertisement_data, "rssi", None),
            manufacturer_data=getattr(advertisement_data, "manufacturer_data", None) or {},
            service_uuids=tuple(getattr(advertisement_data, "service_uuids", None) or ()),
        )

    def _make_scanner(self):  # pragma: no cover - rig-only path
        if _BLEAK_IMPORT_ERROR is not None:
            raise RuntimeError(f"bleak is not importable here: {_BLEAK_IMPORT_ERROR}")
        or_patterns = [OrPattern(0, _FLAGS_AD_TYPE, bytes([b])) for b in _FLAGS_CONTENT_BYTES]
        return BleakScanner(
            detection_callback=self._detection_callback,
            scanning_mode="passive",  # passive-only invariant — never active
            bluez=BlueZScannerArgs(or_patterns=or_patterns),
            adapter=self.adapter,
        )

    async def _scan_until_stop(self, stop: asyncio.Event) -> None:  # pragma: no cover - rig-only
        scanner = self._make_scanner()
        async with scanner:
            logger.info(
                "BLE passive scan started on %s (flush every %ss)",
                self.adapter,
                self.flush_interval,
            )
            while not stop.is_set():
                try:
                    await asyncio.wait_for(stop.wait(), timeout=self.flush_interval)
                except TimeoutError:
                    self._flush(int(time.time()))  # tick flush
                else:
                    break  # stop signalled

    def stop(self) -> None:
        """Request shutdown (thread-safe).

        Signals the scan + flush loops to exit; run()'s finally then drains the
        buffer and closes the bridge's own Database. Safe to call before run()
        has built its loop — run() re-checks ``_stop_requested`` on entry.
        """
        self._stop_requested.set()
        loop = self._loop
        ev = self._asyncio_stop
        if loop is not None and ev is not None:
            try:
                loop.call_soon_threadsafe(ev.set)
            except RuntimeError:
                pass  # loop already closed — run() has exited

    async def run(self, *, duration: float | None = None) -> None:
        """Continuous passive scan until stop(); restarts on bleak/BlueZ failure.

        ``duration`` bounds the run (standalone smoke test); omit for the
        continuous daemon loop driven by stop(). A final flush drains the buffer
        and the bridge's OWN Database is closed at shutdown — the bridge owns its
        connection lifecycle so the threaded poller case needs no extra cleanup.
        """
        self._loop = asyncio.get_running_loop()
        self._asyncio_stop = asyncio.Event()
        stop = self._asyncio_stop
        if self._stop_requested.is_set():
            stop.set()  # stop() raced ahead of the loop — honor it immediately
        if duration is not None:
            self._loop.call_later(duration, stop.set)
        try:
            self._ensure_startup_location()
            if _BLEAK_IMPORT_ERROR is not None:
                # Flag enabled but bleak unavailable (e.g. dev box / missing
                # dependency): log once and fall through to a clean shutdown
                # rather than crashing the daemon — the scan simply never runs.
                logger.warning(
                    "BLE bridge enabled but bleak is unavailable (%s); scan disabled",
                    _BLEAK_IMPORT_ERROR,
                )
            else:
                while not stop.is_set():
                    try:
                        await self._scan_until_stop(stop)
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:  # bleak/BlueZ failure — log, back off, restart
                        logger.warning(
                            "BLE scan failed (%s); restarting in %.0fs",
                            exc,
                            _RESTART_BACKOFF_SECONDS,
                        )
                        try:
                            await asyncio.wait_for(stop.wait(), timeout=_RESTART_BACKOFF_SECONDS)
                        except TimeoutError:
                            pass
        finally:
            self._flush(int(time.time()))  # drain whatever is buffered at shutdown
            self.db.close()  # bridge owns its connection lifecycle


# --- standalone CLI runner (rig smoke test only) --------------------------


def _guard_not_prod(db_path: str, config_db_path: str | None) -> None:
    """Hard-exit if the chosen DB resolves to a prod DB (the bridge writes)."""
    target = os.path.realpath(os.path.expanduser(db_path))
    for prod in (_PROD_DB_PATH, config_db_path):
        if prod and target == os.path.realpath(os.path.expanduser(prod)):
            sys.exit(
                f"REFUSING TO RUN: --db resolves to a prod DB ({prod}). This bridge "
                "WRITES devices/sightings. Copy it first, e.g.:\n"
                f"  cp {prod} /tmp/ble_bridge_smoke.db\n"
                "then re-run with --db /tmp/ble_bridge_smoke.db (or omit --db to use a "
                "throwaway temp copy)."
            )


def _make_temp_db(source_path: str) -> str:
    """Default DB target: a throwaway temp copy of the config DB.

    Copies the config DB when it exists so a smoke run exercises realistic data
    without ever writing prod; otherwise leaves an empty file for Database to
    migrate fresh.
    """
    fd, tmp = tempfile.mkstemp(prefix="ble_bridge_smoke_", suffix=".db")
    os.close(fd)
    src = os.path.expanduser(source_path)
    if os.path.exists(src):
        shutil.copy2(src, tmp)
    return tmp


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Passive BLE bridge — standalone rig smoke runner")
    parser.add_argument("--config", required=True, help="path to lynceus.yaml")
    parser.add_argument(
        "--db",
        default=None,
        help="own Database path; default: a throwaway temp copy of config db_path",
    )
    parser.add_argument("--adapter", default="hci1", help="BlueZ adapter (default: hci1)")
    parser.add_argument(
        "--flush-interval",
        type=int,
        default=None,
        help="tick-flush seconds (its own interval); default: config.poll_interval_seconds",
    )
    parser.add_argument(
        "--duration", type=int, default=60, help="run seconds then stop (default: 60)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="NullNotifier (no ntfy); default builds the config notifier",
    )
    args = parser.parse_args(argv)

    if _BLEAK_IMPORT_ERROR is not None:
        sys.exit(
            f"bleak is not importable here ({_BLEAK_IMPORT_ERROR}). Run on the rig "
            "in a python that has bleak installed."
        )

    config = load_config(args.config)
    db_path = args.db if args.db else _make_temp_db(config.db_path)
    _guard_not_prod(db_path, config.db_path)

    ruleset = load_ruleset(config.rules_path) if config.rules_path else Ruleset()
    allowlist = Allowlist()  # default empty — curation deferred
    notifier = NullNotifier() if args.dry_run else build_notifier(config)
    severity_overrides = load_runtime_severity_overrides(config.severity_overrides_path)
    flush_interval = (
        args.flush_interval if args.flush_interval is not None else config.poll_interval_seconds
    )

    db = Database(db_path)  # OWN connection on its own path — WAL second writer
    bridge = BleBridge(
        db=db,
        config=config,
        ruleset=ruleset,
        allowlist_provider=lambda: allowlist,  # standalone: fixed allowlist
        notifier=notifier,
        severity_overrides=severity_overrides,
        location_id=config.location_id,
        location_label=config.location_label,
        adapter=args.adapter,
        flush_interval=flush_interval,
    )
    print(
        f"[ble-bridge] passive scan on {args.adapter} for {args.duration}s, "
        f"flush every {flush_interval}s — DB={db_path}"
    )
    try:
        asyncio.run(bridge.run(duration=args.duration))
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
