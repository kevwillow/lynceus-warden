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
from .notify import Notifier, NullNotifier, build_notifier
from .rules import Ruleset, evaluate, load_ruleset

STATE_KEY_LAST_POLL = "last_poll_ts"

logger = logging.getLogger(__name__)


def build_kismet_client(config: Config) -> KismetClient:
    if config.kismet_fixture_path:
        return FakeKismetClient(config.kismet_fixture_path)
    return KismetClient(config.kismet_url, api_key=config.kismet_api_key)


def poll_once(
    client: KismetClient,
    db: Database,
    config: Config,
    now_ts: int,
    *,
    ruleset: Ruleset | None = None,
    allowlist: Allowlist | None = None,
    notifier: Notifier | None = None,
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
            existing_device = db.get_device(obs.mac)
            is_new = existing_device is None
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
                location_id=config.location_id,
            )
            processed += 1
            if allowlist.is_allowed(obs):
                logger.debug("allowlisted, suppressing alerts: %s", obs.mac)
                continue
            hits = evaluate(ruleset, obs, is_new_device=is_new)
            for hit in hits:
                if config.alert_dedup_window_seconds > 0:
                    since = now_ts - config.alert_dedup_window_seconds
                    if (
                        db.get_recent_alert_for_rule_and_mac(hit.rule_name, hit.mac, since)
                        is not None
                    ):
                        logger.debug("dedup-skip %s/%s", hit.rule_name, hit.mac)
                        continue
                try:
                    db.add_alert(
                        ts=now_ts,
                        rule_name=hit.rule_name,
                        mac=hit.mac,
                        message=hit.message,
                        severity=hit.severity,
                    )
                except Exception as e:
                    logger.warning("Failed to write alert %s for %s: %s", hit.rule_name, hit.mac, e)
                    continue
                title = f"talos: {hit.severity.upper()} alert"
                try:
                    ok = notifier.send(severity=hit.severity, title=title, message=hit.message)
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
            )
        finally:
            self.db.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="talos")
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
