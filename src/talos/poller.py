"""Poll loop: fetch from Kismet on an interval, persist, and trigger rule eval."""

from __future__ import annotations

import argparse
import logging
import signal
import time

from . import __version__
from .config import Config, load_config
from .db import Database
from .kismet import FakeKismetClient, KismetClient

STATE_KEY_LAST_POLL = "last_poll_ts"

logger = logging.getLogger(__name__)


def build_kismet_client(config: Config) -> KismetClient:
    if config.kismet_fixture_path:
        return FakeKismetClient(config.kismet_fixture_path)
    return KismetClient(config.kismet_url, api_key=config.kismet_api_key)


def poll_once(client: KismetClient, db: Database, config: Config, now_ts: int) -> int:
    last_poll_str = db.get_state(STATE_KEY_LAST_POLL)
    last_poll_ts = int(last_poll_str) if last_poll_str else 0
    db.ensure_location(config.location_id, config.location_label)
    observations = client.get_devices_since(last_poll_ts)
    processed = 0
    for obs in observations:
        try:
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
                poll_once(self.client, self.db, self.config, int(time.time()))
                self._interruptible_sleep(self.config.poll_interval_seconds)
        except KeyboardInterrupt:
            self._stop_flag = True
        finally:
            self.db.close()

    def run_once(self) -> int:
        try:
            return poll_once(self.client, self.db, self.config, int(time.time()))
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
