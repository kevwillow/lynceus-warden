"""Tests for the poller daemon."""

import logging
import threading
from pathlib import Path

import pytest

from lynceus import __version__
from lynceus.allowlist import Allowlist, AllowlistEntry
from lynceus.config import Config
from lynceus.db import Database
from lynceus.kismet import FakeKismetClient, KismetClient
from lynceus.notify import Notifier, RecordingNotifier
from lynceus.poller import (
    STATE_KEY_LAST_POLL,
    Poller,
    build_kismet_client,
    main,
    poll_once,
)
from lynceus.rules import Rule, Ruleset

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "kismet_devices.json"


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "lynceus.db")


@pytest.fixture
def db(db_path):
    d = Database(db_path)
    yield d
    d.close()


@pytest.fixture
def config(db_path):
    return Config(
        kismet_fixture_path=str(FIXTURE_PATH),
        db_path=db_path,
        location_id="testloc",
        location_label="Test Location",
    )


@pytest.fixture
def fake_client():
    return FakeKismetClient(str(FIXTURE_PATH))


def test_poll_once_empty_returns_zero(db, config, fake_client):
    db.set_state(STATE_KEY_LAST_POLL, "9999999999")
    count = poll_once(fake_client, db, config, 9999999999)
    assert count == 0


def test_poll_once_processes_supported_devices(db, config, fake_client):
    count = poll_once(fake_client, db, config, 1700001000)
    assert count == 5
    devices = db._conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    sightings = db._conn.execute("SELECT COUNT(*) FROM sightings").fetchone()[0]
    assert devices == 5
    assert sightings == 5


def test_poll_once_advances_state(db, config, fake_client):
    poll_once(fake_client, db, config, 1700001000)
    assert db.get_state(STATE_KEY_LAST_POLL) == "1700001000"


def test_poll_once_uses_last_poll_ts(db, config, fake_client, monkeypatch):
    db.set_state(STATE_KEY_LAST_POLL, "1700000300")
    captured: list[int] = []
    orig = fake_client.get_devices_since

    def spy(since_ts, **kwargs):
        captured.append(since_ts)
        return orig(since_ts, **kwargs)

    monkeypatch.setattr(fake_client, "get_devices_since", spy)
    poll_once(fake_client, db, config, 1700001000)
    assert captured == [1700000300]


def test_poll_once_default_last_poll_ts_zero(db, config, fake_client, monkeypatch):
    captured: list[int] = []
    orig = fake_client.get_devices_since

    def spy(since_ts, **kwargs):
        captured.append(since_ts)
        return orig(since_ts, **kwargs)

    monkeypatch.setattr(fake_client, "get_devices_since", spy)
    poll_once(fake_client, db, config, 1700001000)
    assert captured == [0]


def test_poll_once_continues_on_observation_error(db, config, fake_client, monkeypatch):
    orig_upsert = db.upsert_device
    state = {"n": 0}

    def flaky(*args, **kwargs):
        state["n"] += 1
        if state["n"] == 2:
            raise RuntimeError("simulated persistence failure")
        return orig_upsert(*args, **kwargs)

    monkeypatch.setattr(db, "upsert_device", flaky)
    count = poll_once(fake_client, db, config, 1700001000)
    assert count == 4


def test_poll_once_ensures_location_first(db, config, fake_client):
    poll_once(fake_client, db, config, 1700001000)
    rows = db._conn.execute("SELECT id, label FROM locations").fetchall()
    assert any(r["id"] == "testloc" and r["label"] == "Test Location" for r in rows)


def test_build_kismet_client_chooses_fake():
    cfg = Config(kismet_fixture_path=str(FIXTURE_PATH))
    client = build_kismet_client(cfg)
    assert isinstance(client, FakeKismetClient)


def test_build_kismet_client_chooses_real():
    cfg = Config(kismet_fixture_path=None)
    client = build_kismet_client(cfg)
    assert isinstance(client, KismetClient)
    assert not isinstance(client, FakeKismetClient)


def test_run_forever_stops_on_flag(config):
    def runner():
        poller = Poller(config)
        poller._stop_flag = True
        poller.run_forever()

    thread = threading.Thread(target=runner)
    thread.start()
    thread.join(timeout=2)
    assert not thread.is_alive()


def test_run_once_returns_count_and_closes_db(config, mocker):
    poller = Poller(config)
    spy = mocker.spy(poller.db, "close")
    count = poller.run_once()
    assert count == 5
    assert spy.call_count == 1


def test_main_once_with_valid_config_returns_zero(tmp_path):
    cfg_path = tmp_path / "lynceus.yaml"
    db_file = tmp_path / "lynceus.db"
    cfg_path.write_text(
        f"kismet_fixture_path: {FIXTURE_PATH.as_posix()}\n"
        f"db_path: {db_file.as_posix()}\n"
        "location_id: t\n"
        "location_label: Test\n",
        encoding="utf-8",
    )
    rc = main(["--config", str(cfg_path), "--once"])
    assert rc == 0


def test_main_missing_config_returns_one(tmp_path):
    rc = main(["--config", str(tmp_path / "nonexistent.yaml"), "--once"])
    assert rc == 1


def test_main_invalid_config_returns_one(tmp_path):
    cfg_path = tmp_path / "lynceus.yaml"
    cfg_path.write_text("log_level: TRACE\n", encoding="utf-8")
    rc = main(["--config", str(cfg_path), "--once"])
    assert rc == 1


def test_main_version_flag(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert __version__ in captured.out or __version__ in captured.err


# --------------------- rules / allowlist integration ---------------------


def _alerts_count(db: Database) -> int:
    return db._conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]


def test_poll_once_no_rules_writes_no_alerts(db, config, fake_client):
    poll_once(fake_client, db, config, 1700001000)
    assert _alerts_count(db) == 0


def test_poll_once_watchlist_oui_hit_creates_alert(db, config, fake_client):
    rs = Ruleset(
        rules=[
            Rule(
                name="apple_oui",
                rule_type="watchlist_oui",
                severity="high",
                patterns=["a4:83:e7"],
                description="Apple OUI",
            )
        ]
    )
    poll_once(fake_client, db, config, 1700001000, ruleset=rs)
    rows = db._conn.execute("SELECT rule_name, mac, severity, message FROM alerts").fetchall()
    assert len(rows) == 1
    assert rows[0]["rule_name"] == "apple_oui"
    assert rows[0]["mac"] == "a4:83:e7:11:22:33"
    assert rows[0]["severity"] == "high"
    assert "a4:83:e7:11:22:33" in rows[0]["message"]
    assert "Apple OUI" in rows[0]["message"]


def test_poll_once_new_device_rule_fires_only_on_first_poll(db, config, fake_client):
    rs = Ruleset(
        rules=[Rule(name="new_dev", rule_type="new_non_randomized_device", severity="low")]
    )
    cfg_no_dedup = config.model_copy(update={"alert_dedup_window_seconds": 0})

    poll_once(fake_client, db, cfg_no_dedup, 1700001000, ruleset=rs)
    first_count = _alerts_count(db)
    # Two non-randomized devices in the fixture: a4:83:e7:... and 00:1a:7d:...
    assert first_count == 2

    # Rewind state so FakeKismetClient returns the same devices again.
    db.set_state(STATE_KEY_LAST_POLL, "0")
    poll_once(fake_client, db, cfg_no_dedup, 1700002000, ruleset=rs)
    assert _alerts_count(db) == first_count


def test_poll_once_allowlist_suppresses_alert(db, config, fake_client):
    rs = Ruleset(
        rules=[
            Rule(
                name="apple_mac",
                rule_type="watchlist_mac",
                severity="high",
                patterns=["a4:83:e7:11:22:33"],
            )
        ]
    )
    al = Allowlist(entries=[AllowlistEntry(pattern="a4:83:e7:11:22:33", pattern_type="mac")])
    poll_once(fake_client, db, config, 1700001000, ruleset=rs, allowlist=al)
    assert _alerts_count(db) == 0


def test_poll_once_dedup_within_window_skips_duplicate(db, config, fake_client):
    rs = Ruleset(
        rules=[
            Rule(
                name="apple_mac",
                rule_type="watchlist_mac",
                severity="high",
                patterns=["a4:83:e7:11:22:33"],
            )
        ]
    )
    db.upsert_device("a4:83:e7:11:22:33", "wifi", "Apple", 0, 1699000000)
    db.add_alert(
        ts=1700000900,
        rule_name="apple_mac",
        mac="a4:83:e7:11:22:33",
        message="prior",
        severity="high",
    )
    cfg = config.model_copy(update={"alert_dedup_window_seconds": 3600})
    poll_once(fake_client, db, cfg, 1700001000, ruleset=rs)
    assert _alerts_count(db) == 1


def test_poll_once_dedup_outside_window_creates_new_alert(db, config, fake_client):
    rs = Ruleset(
        rules=[
            Rule(
                name="apple_mac",
                rule_type="watchlist_mac",
                severity="high",
                patterns=["a4:83:e7:11:22:33"],
            )
        ]
    )
    db.upsert_device("a4:83:e7:11:22:33", "wifi", "Apple", 0, 1699000000)
    db.add_alert(
        ts=1699993800,
        rule_name="apple_mac",
        mac="a4:83:e7:11:22:33",
        message="ancient",
        severity="high",
    )
    cfg = config.model_copy(update={"alert_dedup_window_seconds": 3600})
    poll_once(fake_client, db, cfg, 1700001000, ruleset=rs)
    assert _alerts_count(db) == 2


def test_poll_once_dedup_window_zero_disables_dedup(db, config, fake_client):
    rs = Ruleset(
        rules=[
            Rule(
                name="apple_mac",
                rule_type="watchlist_mac",
                severity="high",
                patterns=["a4:83:e7:11:22:33"],
            )
        ]
    )
    db.upsert_device("a4:83:e7:11:22:33", "wifi", "Apple", 0, 1699000000)
    db.add_alert(
        ts=1700000900,
        rule_name="apple_mac",
        mac="a4:83:e7:11:22:33",
        message="prior",
        severity="high",
    )
    cfg = config.model_copy(update={"alert_dedup_window_seconds": 0})
    poll_once(fake_client, db, cfg, 1700001000, ruleset=rs)
    assert _alerts_count(db) == 2


def test_poll_once_alert_write_error_does_not_abort_poll(db, config, fake_client, monkeypatch):
    rs = Ruleset(
        rules=[Rule(name="new_dev", rule_type="new_non_randomized_device", severity="low")]
    )
    cfg = config.model_copy(update={"alert_dedup_window_seconds": 0})

    orig_add = db.add_alert
    state = {"calls": 0}

    def flaky_add(**kwargs):
        state["calls"] += 1
        if state["calls"] == 1:
            raise RuntimeError("simulated alert write failure")
        return orig_add(**kwargs)

    monkeypatch.setattr(db, "add_alert", flaky_add)
    count = poll_once(fake_client, db, cfg, 1700001000, ruleset=rs)
    assert count == 5
    assert state["calls"] >= 2
    assert _alerts_count(db) >= 1


# --------------------------- notifier integration ---------------------------


class _RaisingNotifier(Notifier):
    def __init__(self) -> None:
        self.calls = 0

    def send(self, severity, title, message):
        self.calls += 1
        raise RuntimeError("notifier blew up")


class _FalseNotifier(Notifier):
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []

    def send(self, severity, title, message):
        self.calls.append((severity, title, message))
        return False


def test_poll_once_notifier_called_for_alert(db, config, fake_client):
    rs = Ruleset(
        rules=[
            Rule(
                name="apple_oui",
                rule_type="watchlist_oui",
                severity="high",
                patterns=["a4:83:e7"],
                description="Apple OUI",
            )
        ]
    )
    rec = RecordingNotifier()
    poll_once(fake_client, db, config, 1700001000, ruleset=rs, notifier=rec)
    assert len(rec.calls) == 1
    severity, title, message = rec.calls[0]
    assert severity == "high"
    assert title == "lynceus: HIGH alert"
    assert "a4:83:e7:11:22:33" in message
    assert "Apple OUI" in message


def test_poll_once_notifier_not_called_when_no_hits(db, config, fake_client):
    rec = RecordingNotifier()
    poll_once(fake_client, db, config, 1700001000, notifier=rec)
    assert rec.calls == []


def test_poll_once_notifier_not_called_for_allowlisted(db, config, fake_client):
    rs = Ruleset(
        rules=[
            Rule(
                name="apple_mac",
                rule_type="watchlist_mac",
                severity="high",
                patterns=["a4:83:e7:11:22:33"],
            )
        ]
    )
    al = Allowlist(entries=[AllowlistEntry(pattern="a4:83:e7:11:22:33", pattern_type="mac")])
    rec = RecordingNotifier()
    poll_once(fake_client, db, config, 1700001000, ruleset=rs, allowlist=al, notifier=rec)
    assert rec.calls == []


def test_poll_once_notifier_not_called_for_dedup_skip(db, config, fake_client):
    rs = Ruleset(
        rules=[
            Rule(
                name="apple_mac",
                rule_type="watchlist_mac",
                severity="high",
                patterns=["a4:83:e7:11:22:33"],
            )
        ]
    )
    db.upsert_device("a4:83:e7:11:22:33", "wifi", "Apple", 0, 1699000000)
    db.add_alert(
        ts=1700000900,
        rule_name="apple_mac",
        mac="a4:83:e7:11:22:33",
        message="prior",
        severity="high",
    )
    cfg = config.model_copy(update={"alert_dedup_window_seconds": 3600})
    rec = RecordingNotifier()
    poll_once(fake_client, db, cfg, 1700001000, ruleset=rs, notifier=rec)
    assert rec.calls == []


def test_poll_once_notifier_called_after_dedup_window(db, config, fake_client):
    rs = Ruleset(
        rules=[
            Rule(
                name="apple_mac",
                rule_type="watchlist_mac",
                severity="high",
                patterns=["a4:83:e7:11:22:33"],
            )
        ]
    )
    db.upsert_device("a4:83:e7:11:22:33", "wifi", "Apple", 0, 1699000000)
    db.add_alert(
        ts=1699993800,
        rule_name="apple_mac",
        mac="a4:83:e7:11:22:33",
        message="ancient",
        severity="high",
    )
    cfg = config.model_copy(update={"alert_dedup_window_seconds": 3600})
    rec = RecordingNotifier()
    poll_once(fake_client, db, cfg, 1700001000, ruleset=rs, notifier=rec)
    assert len(rec.calls) == 1


def test_poll_once_notifier_failure_does_not_prevent_alert_db_row(db, config, fake_client):
    rs = Ruleset(
        rules=[
            Rule(
                name="apple_mac",
                rule_type="watchlist_mac",
                severity="high",
                patterns=["a4:83:e7:11:22:33"],
            )
        ]
    )
    notifier = _RaisingNotifier()
    count = poll_once(fake_client, db, config, 1700001000, ruleset=rs, notifier=notifier)
    assert count == 5
    assert _alerts_count(db) == 1
    assert notifier.calls == 1


def test_poll_once_notifier_returning_false_logs_warning_but_continues(
    db, config, fake_client, caplog
):
    rs = Ruleset(
        rules=[Rule(name="new_dev", rule_type="new_non_randomized_device", severity="low")]
    )
    cfg = config.model_copy(update={"alert_dedup_window_seconds": 0})
    notifier = _FalseNotifier()
    with caplog.at_level(logging.WARNING, logger="lynceus.poller"):
        poll_once(fake_client, db, cfg, 1700001000, ruleset=rs, notifier=notifier)
    assert len(notifier.calls) == 2
    assert any(r.levelname == "WARNING" for r in caplog.records)


# ----------------- multi-source filtering / per-source location -------------


from lynceus.kismet import DeviceObservation  # noqa: E402


def test_poll_once_no_source_allowlist_processes_all_supported(db, config, fake_client):
    count = poll_once(fake_client, db, config, 1700001000, source_allowlist=None)
    assert count == 5


def test_poll_once_source_allowlist_filters_to_subset(db, config, fake_client):
    count = poll_once(
        fake_client,
        db,
        config,
        1700001000,
        source_allowlist=frozenset(["builtin-bt"]),
    )
    # Devices [2] (BTLE), [3] (Bluetooth), [5] (BTLE/AirTag) are seen by builtin-bt.
    assert count == 3
    types = [
        r["device_type"] for r in db._conn.execute("SELECT device_type FROM devices").fetchall()
    ]
    assert set(types) == {"ble", "bt_classic"}


def test_poll_once_source_allowlist_drops_obs_without_seenby(db, config, monkeypatch):
    obs = DeviceObservation(
        mac="aa:bb:cc:dd:ee:ff",
        device_type="wifi",
        first_seen=1700000000,
        last_seen=1700000100,
        rssi=-50,
        ssid=None,
        oui_vendor=None,
        is_randomized=False,
        seen_by_sources=(),
    )

    class _SingleObsClient:
        def get_devices_since(self, since_ts, **kwargs):
            return [obs]

    count = poll_once(
        _SingleObsClient(),
        db,
        config,
        1700001000,
        source_allowlist=frozenset(["alfa-2.4ghz"]),
    )
    assert count == 0
    assert db._conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 0


def test_poll_once_min_rssi_drops_weak_observations(db, config):
    weak = DeviceObservation(
        mac="aa:bb:cc:dd:ee:01",
        device_type="wifi",
        first_seen=1700000000,
        last_seen=1700000100,
        rssi=-90,
        ssid=None,
        oui_vendor=None,
        is_randomized=False,
    )
    strong = DeviceObservation(
        mac="aa:bb:cc:dd:ee:02",
        device_type="wifi",
        first_seen=1700000000,
        last_seen=1700000100,
        rssi=-50,
        ssid=None,
        oui_vendor=None,
        is_randomized=False,
    )

    class _C:
        def get_devices_since(self, since_ts, **kwargs):
            return [weak, strong]

    cfg = config.model_copy(update={"min_rssi": -80})
    count = poll_once(_C(), db, cfg, 1700001000)
    assert count == 1
    macs = [r["mac"] for r in db._conn.execute("SELECT mac FROM devices").fetchall()]
    assert macs == ["aa:bb:cc:dd:ee:02"]


def test_poll_once_min_rssi_none_observation_kept_under_filter(db, config):
    obs = DeviceObservation(
        mac="aa:bb:cc:dd:ee:01",
        device_type="wifi",
        first_seen=1700000000,
        last_seen=1700000100,
        rssi=None,
        ssid=None,
        oui_vendor=None,
        is_randomized=False,
    )

    class _C:
        def get_devices_since(self, since_ts, **kwargs):
            return [obs]

    cfg = config.model_copy(update={"min_rssi": -80})
    count = poll_once(_C(), db, cfg, 1700001000)
    assert count == 1


def test_poll_once_per_source_location_override(db, config, fake_client):
    poll_once(
        fake_client,
        db,
        config,
        1700001000,
        source_locations={"builtin-bt": "indoor"},
    )
    # BTLE/Bluetooth devices: macs from fixture seenby builtin-bt.
    bt_macs = ("06:aa:bb:cc:dd:ee", "00:1a:7d:da:71:11", "5a:11:22:33:44:55")
    wifi_macs = ("a4:83:e7:11:22:33", "02:11:22:33:44:55")
    rows = db._conn.execute("SELECT mac, location_id FROM sightings").fetchall()
    by_mac = {r["mac"]: r["location_id"] for r in rows}
    for m in bt_macs:
        assert by_mac[m] == "indoor"
    for m in wifi_macs:
        assert by_mac[m] == "testloc"
    loc_ids = {r["id"] for r in db._conn.execute("SELECT id FROM locations").fetchall()}
    assert "indoor" in loc_ids
    assert "testloc" in loc_ids


def test_poll_once_per_source_location_falls_back_to_default(db, config, fake_client):
    poll_once(
        fake_client,
        db,
        config,
        1700001000,
        source_locations={"alfa-5ghz": "wifi-loft"},
    )
    rows = db._conn.execute("SELECT mac, location_id FROM sightings").fetchall()
    for r in rows:
        assert r["location_id"] == "testloc"


def test_poll_once_combined_filters_apply_independently(db, config):
    obs_strong_wrong_src = DeviceObservation(
        mac="aa:bb:cc:dd:ee:01",
        device_type="wifi",
        first_seen=1700000000,
        last_seen=1700000100,
        rssi=-50,
        ssid=None,
        oui_vendor=None,
        is_randomized=False,
        seen_by_sources=("rtl-sdr",),
    )
    obs_weak_right_src = DeviceObservation(
        mac="aa:bb:cc:dd:ee:02",
        device_type="wifi",
        first_seen=1700000000,
        last_seen=1700000100,
        rssi=-95,
        ssid=None,
        oui_vendor=None,
        is_randomized=False,
        seen_by_sources=("alfa",),
    )
    obs_good = DeviceObservation(
        mac="aa:bb:cc:dd:ee:03",
        device_type="wifi",
        first_seen=1700000000,
        last_seen=1700000100,
        rssi=-50,
        ssid=None,
        oui_vendor=None,
        is_randomized=False,
        seen_by_sources=("alfa",),
    )

    class _C:
        def get_devices_since(self, since_ts, **kwargs):
            return [obs_strong_wrong_src, obs_weak_right_src, obs_good]

    cfg = config.model_copy(update={"min_rssi": -80})
    count = poll_once(_C(), db, cfg, 1700001000, source_allowlist=frozenset(["alfa"]))
    assert count == 1
    macs = [r["mac"] for r in db._conn.execute("SELECT mac FROM devices").fetchall()]
    assert macs == ["aa:bb:cc:dd:ee:03"]


def test_poller_init_health_check_passes_with_fake(config):
    poller = Poller(config)
    poller.db.close()


def test_poller_init_health_check_fails_raises(tmp_path, monkeypatch):
    import requests as _requests

    cfg = Config(
        db_path=str(tmp_path / "lynceus.db"),
        kismet_url="http://127.0.0.1:1",
    )

    def boom(*args, **kwargs):
        raise _requests.ConnectionError("connection refused: nobody home")

    monkeypatch.setattr("lynceus.kismet.requests.get", boom)
    with pytest.raises(RuntimeError) as exc_info:
        Poller(cfg)
    msg = str(exc_info.value)
    assert "Kismet unreachable at startup" in msg
    assert "kismet_health_check_on_startup=false" in msg


def test_poller_init_health_check_skipped_when_disabled(tmp_path, monkeypatch):
    import requests as _requests

    cfg = Config(
        db_path=str(tmp_path / "lynceus.db"),
        kismet_url="http://127.0.0.1:1",
        kismet_health_check_on_startup=False,
    )

    def boom(*args, **kwargs):
        raise _requests.ConnectionError("would fail")

    monkeypatch.setattr("lynceus.kismet.requests.get", boom)
    poller = Poller(cfg)
    poller.db.close()
