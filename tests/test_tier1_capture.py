"""Tests for Tier 1 passive metadata capture: probe SSIDs, BLE friendly
names, and the BLE service-name enrichment dictionary.

Coverage targets the four moving pieces:

1. Schema migration 006 adds nullable ``probe_ssids`` and ``ble_name``
   columns to ``devices`` and is idempotent against fresh and pre-006
   databases.
2. Config schema accepts the ``capture`` block, defaults to off-for-
   probes / on-for-BLE-name, and rejects unknown keys.
3. The poller honors the toggles end-to-end — probes land as a JSON
   array when the flag is on, stay NULL when off (and the underlying
   Kismet field is never read), with per-device dedup and a 50-entry
   cap.
4. ``lookup_service_name`` resolves SIG-standard 16-bit UUIDs from any
   reasonable input form and returns None on unknown input.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path

import pytest
from pydantic import ValidationError

from lynceus.config import CaptureConfig, Config, load_config
from lynceus.db import Database
from lynceus.kismet import (
    DeviceObservation,
    parse_kismet_device,
)
from lynceus.poller import poll_once
from lynceus.seeds.ble_service_names import (
    SERVICE_NAMES,
    lookup_service_name,
)

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "kismet_devices.json"


# ----------------------------- helpers --------------------------------------


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "lynceus.db")


@pytest.fixture
def db(db_path):
    d = Database(db_path)
    yield d
    d.close()


def _wifi_raw_with_probes(mac: str, probes: list[str], last_time: int = 1700000100) -> dict:
    """Build a minimal Kismet device record carrying probed SSIDs."""
    csum_map = {f"csum_{i}": {"dot11.probedssid.ssid": probe} for i, probe in enumerate(probes)}
    return {
        "kismet.device.base.macaddr": mac,
        "kismet.device.base.type": "Wi-Fi Client",
        "kismet.device.base.first_time": 1700000000,
        "kismet.device.base.last_time": last_time,
        "kismet.device.base.signal": {"kismet.common.signal.last_signal": -55},
        "kismet.device.base.manuf": "Probey Inc",
        "kismet.device.base.name": "ClientNet",
        "dot11.device": {
            "dot11.device.last_probed_ssid_csum_map": csum_map,
        },
    }


def _ble_raw_with_name(mac: str, name: str | None) -> dict:
    raw: dict = {
        "kismet.device.base.macaddr": mac,
        "kismet.device.base.type": "BTLE",
        "kismet.device.base.first_time": 1700000000,
        "kismet.device.base.last_time": 1700000200,
        "kismet.device.base.signal": {"kismet.common.signal.last_signal": -65},
        "kismet.device.base.manuf": "Apple",
    }
    if name is not None:
        raw["kismet.device.base.name"] = name
    return raw


class _AccessTrackingDict(dict):
    """Dict subclass that records every key consulted via ``.get``/``[]``.

    Used to assert that opt-out genuinely prevents the poller from
    reading probe-SSID fields out of the raw Kismet payload.
    """

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.accessed: list[str] = []

    def get(self, key, default=None):
        self.accessed.append(key)
        return super().get(key, default)

    def __getitem__(self, key):
        self.accessed.append(key)
        return super().__getitem__(key)


class _SingleObsClient:
    def __init__(self, observations: list[DeviceObservation]) -> None:
        self._obs = observations
        self.last_kwargs: dict = {}

    def get_devices_since(
        self,
        since_ts: int,
        *,
        capture_probe_ssids: bool = False,
        capture_ble_name: bool = False,
    ) -> list[DeviceObservation]:
        self.last_kwargs = {
            "capture_probe_ssids": capture_probe_ssids,
            "capture_ble_name": capture_ble_name,
        }
        return list(self._obs)


def _make_config(db_path: str, **overrides) -> Config:
    base = {
        "kismet_fixture_path": str(FIXTURE_PATH),
        "db_path": db_path,
        "location_id": "testloc",
        "location_label": "Test Location",
    }
    base.update(overrides)
    return Config(**base)


# ============================== migration ===================================


def test_migration_006_applied_on_fresh_db(db):
    versions = {row[0] for row in db._conn.execute("SELECT version FROM schema_migrations")}
    assert 6 in versions


def test_devices_table_has_probe_ssids_column(db):
    cols = {row[1] for row in db._conn.execute("PRAGMA table_info(devices)")}
    assert "probe_ssids" in cols


def test_devices_table_has_ble_name_column(db):
    cols = {row[1] for row in db._conn.execute("PRAGMA table_info(devices)")}
    assert "ble_name" in cols


def test_new_columns_default_to_null(db):
    db.upsert_device("aa:bb:cc:00:00:01", "wifi", "ACME", 0, 1700000000)
    row = db._conn.execute(
        "SELECT probe_ssids, ble_name FROM devices WHERE mac = ?",
        ("aa:bb:cc:00:00:01",),
    ).fetchone()
    assert row["probe_ssids"] is None
    assert row["ble_name"] is None


def test_migration_006_idempotent_across_two_opens(db_path):
    Database(db_path).close()
    second = Database(db_path)
    versions = [row[0] for row in second._conn.execute("SELECT version FROM schema_migrations")]
    second.close()
    assert versions.count(6) == 1


def test_migration_006_preserves_existing_devices_with_null_columns(db_path):
    """Simulate an upgrade from a pre-006 DB by manually rolling back to
    schema_version <= 5 with the new columns absent, then re-opening.

    SQLite has no real DROP COLUMN before 3.35, but we can simulate the
    pre-upgrade shape by writing a row, dropping the migration record
    for 006, dropping the columns via table-rebuild, and re-opening.
    """
    db = Database(db_path)
    db.upsert_device("aa:bb:cc:11:22:33", "wifi", "ACME", 0, 1700000000)
    db._conn.execute("DELETE FROM schema_migrations WHERE version = 6")
    # Rebuild the devices table without the v0.6 columns.
    db._conn.executescript(
        """
        CREATE TABLE devices_old(
            mac TEXT PRIMARY KEY,
            device_type TEXT NOT NULL CHECK(device_type IN ('wifi','ble','bt_classic')),
            first_seen INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            sighting_count INTEGER NOT NULL DEFAULT 0,
            oui_vendor TEXT,
            is_randomized INTEGER NOT NULL CHECK(is_randomized IN (0,1)),
            notes TEXT
        );
        INSERT INTO devices_old(mac, device_type, first_seen, last_seen,
                                sighting_count, oui_vendor, is_randomized, notes)
            SELECT mac, device_type, first_seen, last_seen, sighting_count,
                   oui_vendor, is_randomized, notes FROM devices;
        DROP TABLE devices;
        ALTER TABLE devices_old RENAME TO devices;
        """
    )
    db._conn.commit()
    db.close()

    reopened = Database(db_path)
    cols = {row[1] for row in reopened._conn.execute("PRAGMA table_info(devices)")}
    assert "probe_ssids" in cols
    assert "ble_name" in cols
    row = reopened._conn.execute(
        "SELECT mac, probe_ssids, ble_name FROM devices WHERE mac = ?",
        ("aa:bb:cc:11:22:33",),
    ).fetchone()
    assert row is not None
    assert row["probe_ssids"] is None
    assert row["ble_name"] is None
    reopened.close()


# ============================== config ======================================


def test_capture_defaults_off_for_probes_on_for_ble(tmp_path):
    cfg_path = tmp_path / "lynceus.yaml"
    cfg_path.write_text("", encoding="utf-8")
    cfg = load_config(str(cfg_path))
    assert cfg.capture.probe_ssids is False
    assert cfg.capture.ble_friendly_names is True


def test_capture_probe_ssids_true_accepted(tmp_path):
    cfg_path = tmp_path / "lynceus.yaml"
    cfg_path.write_text("capture:\n  probe_ssids: true\n", encoding="utf-8")
    cfg = load_config(str(cfg_path))
    assert cfg.capture.probe_ssids is True
    assert cfg.capture.ble_friendly_names is True


def test_capture_probe_ssids_false_explicit(tmp_path):
    cfg_path = tmp_path / "lynceus.yaml"
    cfg_path.write_text("capture:\n  probe_ssids: false\n", encoding="utf-8")
    cfg = load_config(str(cfg_path))
    assert cfg.capture.probe_ssids is False


def test_capture_ble_friendly_names_true_explicit(tmp_path):
    cfg_path = tmp_path / "lynceus.yaml"
    cfg_path.write_text("capture:\n  ble_friendly_names: true\n", encoding="utf-8")
    cfg = load_config(str(cfg_path))
    assert cfg.capture.ble_friendly_names is True


def test_capture_ble_friendly_names_false_accepted(tmp_path):
    cfg_path = tmp_path / "lynceus.yaml"
    cfg_path.write_text("capture:\n  ble_friendly_names: false\n", encoding="utf-8")
    cfg = load_config(str(cfg_path))
    assert cfg.capture.ble_friendly_names is False


def test_capture_unknown_subkey_rejected(tmp_path):
    cfg_path = tmp_path / "lynceus.yaml"
    cfg_path.write_text("capture:\n  probe_ssids: true\n  unknown_field: 1\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        load_config(str(cfg_path))


def test_capture_block_with_both_keys(tmp_path):
    cfg_path = tmp_path / "lynceus.yaml"
    cfg_path.write_text(
        "capture:\n  probe_ssids: true\n  ble_friendly_names: false\n",
        encoding="utf-8",
    )
    cfg = load_config(str(cfg_path))
    assert cfg.capture.probe_ssids is True
    assert cfg.capture.ble_friendly_names is False


def test_capture_config_model_directly():
    c = CaptureConfig()
    assert c.probe_ssids is False
    assert c.ble_friendly_names is True


def test_capture_config_rejects_extra_field_directly():
    with pytest.raises(ValidationError):
        CaptureConfig(probe_ssids=False, ble_friendly_names=True, foo=True)


# ============================== parser ======================================


def test_parse_probe_ssids_flag_off_yields_none():
    raw = _wifi_raw_with_probes("00:11:22:33:44:55", ["MyHome", "Cafe"])
    obs = parse_kismet_device(raw, capture_probe_ssids=False)
    assert obs is not None
    assert obs.probe_ssids is None


def test_parse_probe_ssids_flag_on_yields_tuple():
    raw = _wifi_raw_with_probes("00:11:22:33:44:55", ["MyHome", "Cafe"])
    obs = parse_kismet_device(raw, capture_probe_ssids=True)
    assert obs is not None
    assert obs.probe_ssids == ("MyHome", "Cafe")


def test_parse_probe_ssids_flag_off_does_not_read_dot11_subtree():
    raw = _AccessTrackingDict(_wifi_raw_with_probes("00:11:22:33:44:55", ["MyHome"]))
    parse_kismet_device(raw, capture_probe_ssids=False)
    assert "dot11.device" not in raw.accessed


def test_parse_probe_ssids_flag_on_does_read_dot11_subtree():
    raw = _AccessTrackingDict(_wifi_raw_with_probes("00:11:22:33:44:55", ["MyHome"]))
    parse_kismet_device(raw, capture_probe_ssids=True)
    assert "dot11.device" in raw.accessed


def test_parse_probe_ssids_dedups_within_payload():
    raw = _wifi_raw_with_probes("00:11:22:33:44:55", ["MyHome", "MyHome", "Cafe", "Cafe"])
    obs = parse_kismet_device(raw, capture_probe_ssids=True)
    assert obs is not None
    assert obs.probe_ssids == ("MyHome", "Cafe")


def test_parse_probe_ssids_skips_empty_strings():
    raw = _wifi_raw_with_probes("00:11:22:33:44:55", ["MyHome", "", "Cafe"])
    obs = parse_kismet_device(raw, capture_probe_ssids=True)
    assert obs is not None
    assert obs.probe_ssids == ("MyHome", "Cafe")


def test_parse_probe_ssids_returns_empty_when_no_dot11_block():
    raw = {
        "kismet.device.base.macaddr": "00:11:22:33:44:55",
        "kismet.device.base.type": "Wi-Fi Client",
        "kismet.device.base.first_time": 1700000000,
        "kismet.device.base.last_time": 1700000100,
    }
    obs = parse_kismet_device(raw, capture_probe_ssids=True)
    assert obs is not None
    assert obs.probe_ssids == ()


def test_parse_probe_ssids_skipped_for_ble_devices():
    """Probe SSIDs are a Wi-Fi concept; BLE records don't carry them."""
    raw = _ble_raw_with_name("06:aa:bb:cc:dd:ee", None)
    raw["dot11.device"] = {
        "dot11.device.last_probed_ssid_csum_map": {
            "0": {"dot11.probedssid.ssid": "ShouldNotBeRead"}
        }
    }
    obs = parse_kismet_device(raw, capture_probe_ssids=True, capture_ble_name=True)
    assert obs is not None
    assert obs.probe_ssids is None


def test_parse_ble_name_flag_off_yields_none():
    raw = _ble_raw_with_name("06:aa:bb:cc:dd:ee", "Kev's AirPods")
    obs = parse_kismet_device(raw, capture_ble_name=False)
    assert obs is not None
    assert obs.ble_name is None


def test_parse_ble_name_flag_on_extracts_name():
    raw = _ble_raw_with_name("06:aa:bb:cc:dd:ee", "Kev's AirPods")
    obs = parse_kismet_device(raw, capture_ble_name=True)
    assert obs is not None
    assert obs.ble_name == "Kev's AirPods"


def test_parse_ble_name_empty_string_yields_none():
    raw = _ble_raw_with_name("06:aa:bb:cc:dd:ee", "")
    obs = parse_kismet_device(raw, capture_ble_name=True)
    assert obs is not None
    assert obs.ble_name is None


def test_parse_ble_name_skipped_for_wifi_devices():
    raw = _wifi_raw_with_probes("00:11:22:33:44:55", [])
    obs = parse_kismet_device(raw, capture_ble_name=True)
    assert obs is not None
    assert obs.ble_name is None


# ============================== poller ======================================


def test_poller_probe_ssids_on_persists_json_array(db, db_path):
    obs = DeviceObservation(
        mac="aa:bb:cc:dd:ee:01",
        device_type="wifi",
        first_seen=1700000000,
        last_seen=1700000100,
        rssi=-55,
        ssid=None,
        oui_vendor=None,
        is_randomized=False,
        probe_ssids=("MyHome", "Cafe"),
    )
    cfg = _make_config(
        db_path,
        capture={"probe_ssids": True, "ble_friendly_names": True},
    )
    poll_once(_SingleObsClient([obs]), db, cfg, 1700001000)
    row = db._conn.execute("SELECT probe_ssids FROM devices WHERE mac = ?", (obs.mac,)).fetchone()
    assert row["probe_ssids"] is not None
    assert json.loads(row["probe_ssids"]) == ["MyHome", "Cafe"]


def test_poller_probe_ssids_off_keeps_column_null(db, db_path):
    obs = DeviceObservation(
        mac="aa:bb:cc:dd:ee:02",
        device_type="wifi",
        first_seen=1700000000,
        last_seen=1700000100,
        rssi=-55,
        ssid=None,
        oui_vendor=None,
        is_randomized=False,
        probe_ssids=None,
    )
    cfg = _make_config(
        db_path,
        capture={"probe_ssids": False, "ble_friendly_names": True},
    )
    poll_once(_SingleObsClient([obs]), db, cfg, 1700001000)
    row = db._conn.execute("SELECT probe_ssids FROM devices WHERE mac = ?", (obs.mac,)).fetchone()
    assert row["probe_ssids"] is None


def test_poller_passes_capture_flag_to_kismet_client(db, db_path):
    obs = DeviceObservation(
        mac="aa:bb:cc:dd:ee:03",
        device_type="wifi",
        first_seen=1700000000,
        last_seen=1700000100,
        rssi=-55,
        ssid=None,
        oui_vendor=None,
        is_randomized=False,
    )
    cfg = _make_config(
        db_path,
        capture={"probe_ssids": True, "ble_friendly_names": False},
    )
    client = _SingleObsClient([obs])
    poll_once(client, db, cfg, 1700001000)
    assert client.last_kwargs == {
        "capture_probe_ssids": True,
        "capture_ble_name": False,
    }


def test_poller_probe_ssids_opt_out_does_not_read_kismet_field(db, db_path):
    """End-to-end opt-out: the poller goes through the real Fake client
    on a payload that contains probe SSIDs in an access-tracking dict;
    none of the probe-related keys should ever be touched."""
    raw = _AccessTrackingDict(_wifi_raw_with_probes("00:11:22:33:44:99", ["MyHome", "Cafe"]))

    class _ListClient:
        def __init__(self) -> None:
            self.kwargs: dict = {}

        def get_devices_since(self, since_ts, *, capture_probe_ssids=False, capture_ble_name=False):
            self.kwargs = {
                "capture_probe_ssids": capture_probe_ssids,
                "capture_ble_name": capture_ble_name,
            }
            obs = parse_kismet_device(
                raw,
                capture_probe_ssids=capture_probe_ssids,
                capture_ble_name=capture_ble_name,
            )
            return [obs] if obs is not None else []

    cfg = _make_config(
        db_path,
        capture={"probe_ssids": False, "ble_friendly_names": False},
    )
    client = _ListClient()
    poll_once(client, db, cfg, 1700001000)
    assert client.kwargs == {
        "capture_probe_ssids": False,
        "capture_ble_name": False,
    }
    # Critical: the probe-SSID-related keys must never be read.
    assert "dot11.device" not in raw.accessed
    assert "dot11.device.last_probed_ssid_csum_map" not in raw.accessed
    row = db._conn.execute(
        "SELECT probe_ssids FROM devices WHERE mac = ?",
        ("00:11:22:33:44:99",),
    ).fetchone()
    assert row["probe_ssids"] is None


def test_poller_probe_ssids_dedup_across_two_polls(db, db_path):
    cfg = _make_config(
        db_path,
        capture={"probe_ssids": True, "ble_friendly_names": True},
    )
    obs1 = DeviceObservation(
        mac="aa:bb:cc:dd:ee:04",
        device_type="wifi",
        first_seen=1700000000,
        last_seen=1700000100,
        rssi=-55,
        ssid=None,
        oui_vendor=None,
        is_randomized=False,
        probe_ssids=("MyHome", "Cafe"),
    )
    obs2 = DeviceObservation(
        mac="aa:bb:cc:dd:ee:04",
        device_type="wifi",
        first_seen=1700000000,
        last_seen=1700000200,
        rssi=-55,
        ssid=None,
        oui_vendor=None,
        is_randomized=False,
        probe_ssids=("Cafe", "Library"),
    )
    poll_once(_SingleObsClient([obs1]), db, cfg, 1700001000)
    poll_once(_SingleObsClient([obs2]), db, cfg, 1700002000)
    row = db._conn.execute(
        "SELECT probe_ssids FROM devices WHERE mac = ?",
        ("aa:bb:cc:dd:ee:04",),
    ).fetchone()
    assert json.loads(row["probe_ssids"]) == ["MyHome", "Cafe", "Library"]


def test_poller_probe_ssids_dedup_within_single_poll(db, db_path):
    raw = _wifi_raw_with_probes("aa:bb:cc:dd:ee:05", ["MyHome", "MyHome", "Cafe"])
    obs = parse_kismet_device(raw, capture_probe_ssids=True)
    cfg = _make_config(
        db_path,
        capture={"probe_ssids": True, "ble_friendly_names": True},
    )
    poll_once(_SingleObsClient([obs]), db, cfg, 1700001000)
    row = db._conn.execute(
        "SELECT probe_ssids FROM devices WHERE mac = ?",
        ("aa:bb:cc:dd:ee:05",),
    ).fetchone()
    assert json.loads(row["probe_ssids"]) == ["MyHome", "Cafe"]


def test_poller_probe_ssids_cap_at_50_emits_warning(db, db_path, caplog):
    probes = [f"net-{i:02d}" for i in range(51)]
    obs = DeviceObservation(
        mac="aa:bb:cc:dd:ee:06",
        device_type="wifi",
        first_seen=1700000000,
        last_seen=1700000100,
        rssi=-55,
        ssid=None,
        oui_vendor=None,
        is_randomized=False,
        probe_ssids=tuple(probes),
    )
    cfg = _make_config(
        db_path,
        capture={"probe_ssids": True, "ble_friendly_names": True},
    )
    with caplog.at_level(logging.WARNING, logger="lynceus.poller"):
        poll_once(_SingleObsClient([obs]), db, cfg, 1700001000)
    row = db._conn.execute(
        "SELECT probe_ssids FROM devices WHERE mac = ?",
        ("aa:bb:cc:dd:ee:06",),
    ).fetchone()
    stored = json.loads(row["probe_ssids"])
    assert len(stored) == 50
    assert stored[:3] == ["net-00", "net-01", "net-02"]
    assert any(
        r.levelname == "WARNING" and "probe_ssids cap" in r.getMessage() for r in caplog.records
    )


def test_poller_probe_ssids_cap_not_warning_under_threshold(db, db_path, caplog):
    probes = [f"net-{i:02d}" for i in range(50)]
    obs = DeviceObservation(
        mac="aa:bb:cc:dd:ee:07",
        device_type="wifi",
        first_seen=1700000000,
        last_seen=1700000100,
        rssi=-55,
        ssid=None,
        oui_vendor=None,
        is_randomized=False,
        probe_ssids=tuple(probes),
    )
    cfg = _make_config(
        db_path,
        capture={"probe_ssids": True, "ble_friendly_names": True},
    )
    with caplog.at_level(logging.WARNING, logger="lynceus.poller"):
        poll_once(_SingleObsClient([obs]), db, cfg, 1700001000)
    assert not any("probe_ssids cap" in r.getMessage() for r in caplog.records)


def test_poller_ble_name_on_persists_string(db, db_path):
    obs = DeviceObservation(
        mac="06:aa:bb:cc:dd:01",
        device_type="ble",
        first_seen=1700000000,
        last_seen=1700000100,
        rssi=-65,
        ssid=None,
        oui_vendor="Apple",
        is_randomized=True,
        ble_name="Kev's AirPods",
    )
    cfg = _make_config(
        db_path,
        capture={"probe_ssids": False, "ble_friendly_names": True},
    )
    poll_once(_SingleObsClient([obs]), db, cfg, 1700001000)
    row = db._conn.execute("SELECT ble_name FROM devices WHERE mac = ?", (obs.mac,)).fetchone()
    assert row["ble_name"] == "Kev's AirPods"


def test_poller_ble_name_off_keeps_column_null(db, db_path):
    obs = DeviceObservation(
        mac="06:aa:bb:cc:dd:02",
        device_type="ble",
        first_seen=1700000000,
        last_seen=1700000100,
        rssi=-65,
        ssid=None,
        oui_vendor="Apple",
        is_randomized=True,
        ble_name=None,
    )
    cfg = _make_config(
        db_path,
        capture={"probe_ssids": False, "ble_friendly_names": False},
    )
    poll_once(_SingleObsClient([obs]), db, cfg, 1700001000)
    row = db._conn.execute("SELECT ble_name FROM devices WHERE mac = ?", (obs.mac,)).fetchone()
    assert row["ble_name"] is None


def test_poller_ble_name_latest_write_wins(db, db_path):
    cfg = _make_config(
        db_path,
        capture={"probe_ssids": False, "ble_friendly_names": True},
    )
    obs1 = DeviceObservation(
        mac="06:aa:bb:cc:dd:03",
        device_type="ble",
        first_seen=1700000000,
        last_seen=1700000100,
        rssi=-65,
        ssid=None,
        oui_vendor="Apple",
        is_randomized=True,
        ble_name="OldName",
    )
    obs2 = DeviceObservation(
        mac="06:aa:bb:cc:dd:03",
        device_type="ble",
        first_seen=1700000000,
        last_seen=1700000200,
        rssi=-65,
        ssid=None,
        oui_vendor="Apple",
        is_randomized=True,
        ble_name="NewName",
    )
    poll_once(_SingleObsClient([obs1]), db, cfg, 1700001000)
    poll_once(_SingleObsClient([obs2]), db, cfg, 1700002000)
    row = db._conn.execute(
        "SELECT ble_name FROM devices WHERE mac = ?",
        ("06:aa:bb:cc:dd:03",),
    ).fetchone()
    assert row["ble_name"] == "NewName"


def test_poller_default_config_keeps_probes_off_ble_on(db, db_path):
    """With a default capture block, probes stay NULL even if the obs
    carries them, but BLE names propagate."""
    cfg = _make_config(db_path)
    wifi_obs = DeviceObservation(
        mac="aa:bb:cc:dd:ee:08",
        device_type="wifi",
        first_seen=1700000000,
        last_seen=1700000100,
        rssi=-55,
        ssid=None,
        oui_vendor=None,
        is_randomized=False,
        probe_ssids=("LeakedNet",),
    )
    ble_obs = DeviceObservation(
        mac="06:aa:bb:cc:dd:04",
        device_type="ble",
        first_seen=1700000000,
        last_seen=1700000100,
        rssi=-65,
        ssid=None,
        oui_vendor="Apple",
        is_randomized=True,
        ble_name="DefaultName",
    )
    poll_once(_SingleObsClient([wifi_obs, ble_obs]), db, cfg, 1700001000)
    wifi_row = db._conn.execute(
        "SELECT probe_ssids FROM devices WHERE mac = ?", (wifi_obs.mac,)
    ).fetchone()
    ble_row = db._conn.execute(
        "SELECT ble_name FROM devices WHERE mac = ?", (ble_obs.mac,)
    ).fetchone()
    # probe_ssids defaults off, so even though the obs carries them, no write.
    assert wifi_row["probe_ssids"] is None
    # ble_friendly_names defaults on.
    assert ble_row["ble_name"] == "DefaultName"


# ============================== db helpers ==================================


def test_merge_device_probe_ssids_handles_unknown_mac(db):
    stored, truncated = db.merge_device_probe_ssids("aa:bb:cc:00:00:99", ["MyHome"])
    assert stored == 0
    assert truncated is False


def test_merge_device_probe_ssids_initial_write(db):
    db.upsert_device("aa:bb:cc:00:00:10", "wifi", "ACME", 0, 1700000000)
    stored, truncated = db.merge_device_probe_ssids("aa:bb:cc:00:00:10", ["MyHome", "Cafe"])
    assert stored == 2
    assert truncated is False
    row = db._conn.execute(
        "SELECT probe_ssids FROM devices WHERE mac = ?",
        ("aa:bb:cc:00:00:10",),
    ).fetchone()
    assert json.loads(row["probe_ssids"]) == ["MyHome", "Cafe"]


def test_merge_device_probe_ssids_dedups_against_existing(db):
    db.upsert_device("aa:bb:cc:00:00:11", "wifi", "ACME", 0, 1700000000)
    db.merge_device_probe_ssids("aa:bb:cc:00:00:11", ["MyHome", "Cafe"])
    stored, truncated = db.merge_device_probe_ssids(
        "aa:bb:cc:00:00:11", ["Cafe", "Library", "MyHome"]
    )
    assert stored == 3
    assert truncated is False
    row = db._conn.execute(
        "SELECT probe_ssids FROM devices WHERE mac = ?",
        ("aa:bb:cc:00:00:11",),
    ).fetchone()
    assert json.loads(row["probe_ssids"]) == ["MyHome", "Cafe", "Library"]


def test_merge_device_probe_ssids_truncates_to_cap(db):
    db.upsert_device("aa:bb:cc:00:00:12", "wifi", "ACME", 0, 1700000000)
    probes = [f"n-{i:03d}" for i in range(75)]
    stored, truncated = db.merge_device_probe_ssids("aa:bb:cc:00:00:12", probes)
    assert stored == 50
    assert truncated is True


def test_merge_device_probe_ssids_skips_non_strings(db):
    db.upsert_device("aa:bb:cc:00:00:13", "wifi", "ACME", 0, 1700000000)
    stored, truncated = db.merge_device_probe_ssids("aa:bb:cc:00:00:13", ["MyHome", "", "Cafe"])
    assert stored == 2
    assert truncated is False


def test_merge_device_probe_ssids_corrupt_json_recovers(db):
    db.upsert_device("aa:bb:cc:00:00:14", "wifi", "ACME", 0, 1700000000)
    db._conn.execute(
        "UPDATE devices SET probe_ssids = ? WHERE mac = ?",
        ("not-valid-json{", "aa:bb:cc:00:00:14"),
    )
    db._conn.commit()
    stored, truncated = db.merge_device_probe_ssids("aa:bb:cc:00:00:14", ["Recovered"])
    assert stored == 1
    assert truncated is False


def test_update_device_ble_name_writes_value(db):
    db.upsert_device("06:aa:bb:cc:dd:10", "ble", "Apple", 1, 1700000000)
    db.update_device_ble_name("06:aa:bb:cc:dd:10", "AirPods Pro")
    row = db._conn.execute(
        "SELECT ble_name FROM devices WHERE mac = ?",
        ("06:aa:bb:cc:dd:10",),
    ).fetchone()
    assert row["ble_name"] == "AirPods Pro"


def test_update_device_ble_name_overwrites(db):
    db.upsert_device("06:aa:bb:cc:dd:11", "ble", "Apple", 1, 1700000000)
    db.update_device_ble_name("06:aa:bb:cc:dd:11", "First")
    db.update_device_ble_name("06:aa:bb:cc:dd:11", "Second")
    row = db._conn.execute(
        "SELECT ble_name FROM devices WHERE mac = ?",
        ("06:aa:bb:cc:dd:11",),
    ).fetchone()
    assert row["ble_name"] == "Second"


# ============================== UUID dictionary =============================


def test_lookup_service_name_heart_rate_short_form():
    assert lookup_service_name("180d") == "Heart Rate"


def test_lookup_service_name_heart_rate_uppercase_short_form():
    assert lookup_service_name("180D") == "Heart Rate"


def test_lookup_service_name_heart_rate_with_0x_prefix():
    assert lookup_service_name("0x180D") == "Heart Rate"


def test_lookup_service_name_heart_rate_colon_byte_form():
    assert lookup_service_name("00:00:18:0D") == "Heart Rate"


def test_lookup_service_name_heart_rate_full_128_dashed():
    assert lookup_service_name("0000180d-0000-1000-8000-00805f9b34fb") == "Heart Rate"


def test_lookup_service_name_heart_rate_full_128_uppercase():
    assert lookup_service_name("0000180D-0000-1000-8000-00805F9B34FB") == "Heart Rate"


def test_lookup_service_name_heart_rate_undashed_128():
    assert lookup_service_name("0000180d000010008000" + "00805f9b34fb") == "Heart Rate"


def test_lookup_service_name_battery_service():
    assert lookup_service_name("180f") == "Battery Service"


def test_lookup_service_name_device_information():
    assert lookup_service_name("180a") == "Device Information"


def test_lookup_service_name_immediate_alert():
    assert lookup_service_name("1802") == "Immediate Alert"


def test_lookup_service_name_link_loss():
    assert lookup_service_name("1803") == "Link Loss"


def test_lookup_service_name_current_time_service():
    assert lookup_service_name("1805") == "Current Time Service"


def test_lookup_service_name_environmental_sensing():
    assert lookup_service_name("181a") == "Environmental Sensing"


def test_lookup_service_name_human_interface_device():
    assert lookup_service_name("1812") == "Human Interface Device"


def test_lookup_service_name_unknown_returns_none():
    # 16-bit value not registered in the dict.
    assert lookup_service_name("dead") is None


def test_lookup_service_name_nonsense_input_returns_none():
    assert lookup_service_name("not-a-uuid") is None
    assert lookup_service_name("") is None
    assert lookup_service_name("18") is None  # too short
    assert lookup_service_name("zzzz") is None  # non-hex


def test_lookup_service_name_does_not_collide_with_tracker_uuids():
    """Generic SIG services dict should not duplicate v0.2 tracker UUIDs."""
    from lynceus.seeds.ble_uuids import TRACKER_UUIDS

    tracker_patterns = {entry["pattern"] for entry in TRACKER_UUIDS}
    overlap = tracker_patterns & set(SERVICE_NAMES.keys())
    assert overlap == set()


def test_service_names_dict_minimum_count():
    assert len(SERVICE_NAMES) >= 30


def test_service_names_dict_all_canonical_form():
    for key in SERVICE_NAMES:
        assert key.startswith("0000")
        assert key.endswith("-0000-1000-8000-00805f9b34fb")
        assert len(key) == 36


def test_service_names_no_duplicate_human_names():
    """Same human-readable name should not map to multiple UUIDs."""
    names = list(SERVICE_NAMES.values())
    assert len(names) == len(set(names)), "duplicate names in SERVICE_NAMES"


def test_lookup_service_name_handles_none_input():
    """Defensive: caller might hand us a None from a dict.get()."""
    assert lookup_service_name(None) is None  # type: ignore[arg-type]


def test_lookup_service_name_lookup_is_o1_dict_access():
    """Sanity: SERVICE_NAMES is a plain dict, not a regex registry."""
    assert isinstance(SERVICE_NAMES, dict)


# ============================== sqlite raw shape ============================


def test_probe_ssids_column_is_text(db_path):
    """Schema-level: probe_ssids and ble_name are TEXT NULL (no CHECK)."""
    conn = sqlite3.connect(db_path)
    Database(db_path).close()  # apply migrations
    cols = list(conn.execute("PRAGMA table_info(devices)"))
    by_name = {c[1]: c for c in cols}
    assert by_name["probe_ssids"][2].upper() == "TEXT"
    assert by_name["probe_ssids"][3] == 0  # NOT NULL flag = 0 (nullable)
    assert by_name["ble_name"][2].upper() == "TEXT"
    assert by_name["ble_name"][3] == 0
    conn.close()
