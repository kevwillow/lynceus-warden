"""Tests for the poller daemon."""

import logging
import threading
from pathlib import Path

import pytest

from talos import __version__
from talos.allowlist import Allowlist, AllowlistEntry
from talos.config import Config
from talos.db import Database
from talos.kismet import FakeKismetClient, KismetClient
from talos.notify import Notifier, RecordingNotifier
from talos.poller import (
    STATE_KEY_LAST_POLL,
    Poller,
    build_kismet_client,
    main,
    poll_once,
)
from talos.rules import Rule, Ruleset

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "kismet_devices.json"


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "talos.db")


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
    assert count == 4
    devices = db._conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
    sightings = db._conn.execute("SELECT COUNT(*) FROM sightings").fetchone()[0]
    assert devices == 4
    assert sightings == 4


def test_poll_once_advances_state(db, config, fake_client):
    poll_once(fake_client, db, config, 1700001000)
    assert db.get_state(STATE_KEY_LAST_POLL) == "1700001000"


def test_poll_once_uses_last_poll_ts(db, config, fake_client, monkeypatch):
    db.set_state(STATE_KEY_LAST_POLL, "1700000300")
    captured: list[int] = []
    orig = fake_client.get_devices_since

    def spy(since_ts):
        captured.append(since_ts)
        return orig(since_ts)

    monkeypatch.setattr(fake_client, "get_devices_since", spy)
    poll_once(fake_client, db, config, 1700001000)
    assert captured == [1700000300]


def test_poll_once_default_last_poll_ts_zero(db, config, fake_client, monkeypatch):
    captured: list[int] = []
    orig = fake_client.get_devices_since

    def spy(since_ts):
        captured.append(since_ts)
        return orig(since_ts)

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
    assert count == 3


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
    assert count == 4
    assert spy.call_count == 1


def test_main_once_with_valid_config_returns_zero(tmp_path):
    cfg_path = tmp_path / "talos.yaml"
    db_file = tmp_path / "talos.db"
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
    cfg_path = tmp_path / "talos.yaml"
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
    assert count == 4
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
    assert title == "talos: HIGH alert"
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
    assert count == 4
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
    with caplog.at_level(logging.WARNING, logger="talos.poller"):
        poll_once(fake_client, db, cfg, 1700001000, ruleset=rs, notifier=notifier)
    assert len(notifier.calls) == 2
    assert any(r.levelname == "WARNING" for r in caplog.records)
