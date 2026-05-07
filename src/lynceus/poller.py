"""Poll loop: fetch from Kismet on an interval, persist, and trigger rule eval."""

from __future__ import annotations

import argparse
import logging
import signal
import time

from . import __version__
from .allowlist import Allowlist, load_allowlist
from .config import Config, load_config
from .db import Database
from .kismet import FakeKismetClient, KismetClient
from .notify import Notifier, NullNotifier, build_metadata_suffix, build_notifier
from .rules import Ruleset, evaluate, load_ruleset

STATE_KEY_LAST_POLL = "last_poll_ts"

logger = logging.getLogger(__name__)


def build_kismet_client(config: Config) -> KismetClient:
    if config.kismet_fixture_path:
        return FakeKismetClient(config.kismet_fixture_path)
    return KismetClient(
        config.kismet_url,
        api_key=config.kismet_api_key,
        timeout=config.kismet_timeout_seconds,
    )


def poll_once(
    client: KismetClient,
    db: Database,
    config: Config,
    now_ts: int,
    *,
    ruleset: Ruleset | None = None,
    allowlist: Allowlist | None = None,
    notifier: Notifier | None = None,
    source_allowlist: frozenset[str] | None = None,
    source_locations: dict[str, str] | None = None,
) -> int:
    if ruleset is None:
        ruleset = Ruleset()
    if allowlist is None:
        allowlist = Allowlist()
    if notifier is None:
        notifier = NullNotifier()
    last_poll_str = db.get_state(STATE_KEY_LAST_POLL)
    last_poll_ts = int(last_poll_str) if last_poll_str else 0
    db.ensure_location(config.location_id, config.location_label)
    observations = client.get_devices_since(last_poll_ts)
    processed = 0
    for obs in observations:
        try:
            if source_allowlist is not None:
                if not obs.seen_by_sources:
                    logger.debug(
                        "obs %s has no source attribution, dropping under source_allowlist",
                        obs.mac,
                    )
                    continue
                if not any(s in source_allowlist for s in obs.seen_by_sources):
                    logger.debug(
                        "obs %s sources %r not in allowlist, dropping",
                        obs.mac,
                        obs.seen_by_sources,
                    )
                    continue
            if config.min_rssi is not None and obs.rssi is not None and obs.rssi < config.min_rssi:
                logger.debug(
                    "obs %s rssi=%s below min_rssi=%s, dropping",
                    obs.mac,
                    obs.rssi,
                    config.min_rssi,
                )
                continue

            effective_location_id = config.location_id
            effective_location_label = config.location_label
            if source_locations is not None:
                for src in obs.seen_by_sources:
                    if src in source_locations:
                        effective_location_id = source_locations[src]
                        if effective_location_id != config.location_id:
                            effective_location_label = effective_location_id
                        break

            existing_device = db.get_device(obs.mac)
            is_new = existing_device is None
            db.ensure_location(effective_location_id, effective_location_label)
            db.upsert_device(
                mac=obs.mac,
                device_type=obs.device_type,
                oui_vendor=obs.oui_vendor,
                is_randomized=int(obs.is_randomized),
                now_ts=now_ts,
            )
            db.insert_sighting(
                mac=obs.mac,
                ts=obs.last_seen,
                rssi=obs.rssi,
                ssid=obs.ssid,
                location_id=effective_location_id,
            )
            processed += 1
            if allowlist.is_allowed(obs):
                logger.debug("allowlisted, suppressing alerts: %s", obs.mac)
                continue
            hits = evaluate(ruleset, obs, is_new_device=is_new)
            matched_watchlist_id: int | None = None
            if any(h.rule_type != "new_non_randomized_device" for h in hits):
                matched_watchlist_id = db.resolve_matched_watchlist_id(
                    mac=obs.mac,
                    ssid=obs.ssid,
                    ble_service_uuids=obs.ble_service_uuids,
                )
            for hit in hits:
                if config.alert_dedup_window_seconds > 0:
                    since = now_ts - config.alert_dedup_window_seconds
                    if (
                        db.get_recent_alert_for_rule_and_mac(hit.rule_name, hit.mac, since)
                        is not None
                    ):
                        logger.debug("dedup-skip %s/%s", hit.rule_name, hit.mac)
                        continue
                hit_match_id = (
                    matched_watchlist_id if hit.rule_type != "new_non_randomized_device" else None
                )
                try:
                    db.add_alert(
                        ts=now_ts,
                        rule_name=hit.rule_name,
                        mac=hit.mac,
                        message=hit.message,
                        severity=hit.severity,
                        matched_watchlist_id=hit_match_id,
                    )
                except Exception as e:
                    logger.warning("Failed to write alert %s for %s: %s", hit.rule_name, hit.mac, e)
                    continue
                title = f"lynceus: {hit.severity.upper()} alert"
                suffix = ""
                if hit_match_id is not None:
                    try:
                        md = db.get_metadata_by_watchlist_id(hit_match_id)
                        suffix = build_metadata_suffix(md)
                    except Exception:
                        suffix = ""
                try:
                    ok = notifier.send(
                        severity=hit.severity,
                        title=title,
                        message=hit.message + suffix,
                    )
                    if not ok:
                        logger.warning("Notifier returned False for %s/%s", hit.rule_name, hit.mac)
                except Exception as e:
                    logger.warning("Notifier raised for %s/%s: %s", hit.rule_name, hit.mac, e)
        except Exception as e:
            logger.warning("Failed to persist observation %s: %s", obs.mac, e)
            continue
    db.set_state(STATE_KEY_LAST_POLL, str(now_ts))
    return processed


class Poller:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.db = Database(config.db_path)
        self.client = build_kismet_client(config)
        if config.kismet_health_check_on_startup:
            health = self.client.health_check()
            if not health.get("reachable"):
                err = health.get("error") or "unknown error"
                logger.error("Kismet health check failed at startup: %s", err)
                raise RuntimeError(
                    f"Kismet unreachable at startup: {err}. "
                    "Set kismet_health_check_on_startup=false to skip this check."
                )
        self._source_allowlist: frozenset[str] | None = (
            frozenset(config.kismet_sources) if config.kismet_sources else None
        )
        self.ruleset = load_ruleset(config.rules_path) if config.rules_path else Ruleset()
        self.allowlist = (
            load_allowlist(config.allowlist_path) if config.allowlist_path else Allowlist()
        )
        self.notifier: Notifier = build_notifier(config)
        self._stop_flag = False

    def _on_signal(self, signum: int, frame: object) -> None:
        self._stop_flag = True

    def _interruptible_sleep(self, seconds: int) -> None:
        for _ in range(seconds):
            if self._stop_flag:
                return
            time.sleep(1)

    def run_forever(self) -> None:
        try:
            signal.signal(signal.SIGTERM, self._on_signal)
            signal.signal(signal.SIGINT, self._on_signal)
        except ValueError:
            pass
        try:
            while not self._stop_flag:
                poll_once(
                    self.client,
                    self.db,
                    self.config,
                    int(time.time()),
                    ruleset=self.ruleset,
                    allowlist=self.allowlist,
                    notifier=self.notifier,
                    source_allowlist=self._source_allowlist,
                    source_locations=self.config.kismet_source_locations,
                )
                self._interruptible_sleep(self.config.poll_interval_seconds)
        except KeyboardInterrupt:
            self._stop_flag = True
        finally:
            self.db.close()

    def run_once(self) -> int:
        try:
            return poll_once(
                self.client,
                self.db,
                self.config,
                int(time.time()),
                ruleset=self.ruleset,
                allowlist=self.allowlist,
                notifier=self.notifier,
                source_allowlist=self._source_allowlist,
                source_locations=self.config.kismet_source_locations,
            )
        finally:
            self.db.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="lynceus")
    parser.add_argument("--config", required=True)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)

    try:
        config = load_config(args.config)
        logging.basicConfig(level=config.log_level)
        poller = Poller(config)
        if args.once:
            poller.run_once()
        else:
            poller.run_forever()
        return 0
    except Exception:
        logger.exception("fatal error in main")
        return 1
