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


def test_poll_once_threads_capture_flag_through_to_parser(db, config, fake_client, monkeypatch):
    """REGRESSION: poll_once must propagate evidence_capture_enabled
    down to parse_kismet_device so observations don't carry the full
    Kismet record in memory when capture is off."""
    config_off = Config(
        kismet_fixture_path=config.kismet_fixture_path,
        db_path=config.db_path,
        location_id=config.location_id,
        location_label=config.location_label,
        evidence_capture_enabled=False,
    )
    captured_kwargs: dict = {}
    orig = fake_client.get_devices_since

    def spy(since_ts, **kwargs):
        captured_kwargs.update(kwargs)
        return orig(since_ts, **kwargs)

    monkeypatch.setattr(fake_client, "get_devices_since", spy)
    poll_once(fake_client, db, config_off, 1700001000)
    assert captured_kwargs.get("evidence_capture_enabled") is False
    # And every observation that *would* have been alerted has no
    # raw_record attached: confirm by re-running through the parser
    # directly with the same flag.
    obs_list = fake_client.get_devices_since(0, evidence_capture_enabled=False)
    assert obs_list
    assert all(o.raw_record is None for o in obs_list)


def test_poll_once_threads_capture_flag_when_enabled(db, config, fake_client, monkeypatch):
    captured_kwargs: dict = {}
    orig = fake_client.get_devices_since

    def spy(since_ts, **kwargs):
        captured_kwargs.update(kwargs)
        return orig(since_ts, **kwargs)

    monkeypatch.setattr(fake_client, "get_devices_since", spy)
    poll_once(fake_client, db, config, 1700001000)
    # Default config has evidence_capture_enabled=True.
    assert captured_kwargs.get("evidence_capture_enabled") is True
    obs_list = fake_client.get_devices_since(0, evidence_capture_enabled=True)
    assert obs_list
    assert all(o.raw_record is not None for o in obs_list)


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


def test_allowlist_suppresses_watchlist_hit_logs_audit(db, config, fake_client, caplog):
    """L-RULES-2: an allowlist entry that hides a watchlist hit emits an INFO
    audit line. Without this, allowlist write access is a silent watchlist
    kill-switch — operators have no journalctl trail of what was suppressed."""
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
    with caplog.at_level(logging.INFO, logger="lynceus.poller"):
        poll_once(fake_client, db, config, 1700001000, ruleset=rs, allowlist=al)
    assert _alerts_count(db) == 0
    import re

    assert re.search(r"Allowlist suppressed watchlist hit: rule=.*mac=.*", caplog.text)
    assert "apple_mac" in caplog.text
    assert "a4:83:e7:11:22:33" in caplog.text


def test_allowlist_match_without_watchlist_match_does_not_log(db, config, fake_client, caplog):
    """An allowlisted device that wouldn't have matched any watchlist rule is
    the normal case (operator-known device just doing its thing) — emitting
    an audit line for it would spam journalctl with non-events."""
    rs = Ruleset(
        rules=[
            Rule(
                name="other_mac",
                rule_type="watchlist_mac",
                severity="high",
                patterns=["de:ad:be:ef:00:01"],
            )
        ]
    )
    al = Allowlist(entries=[AllowlistEntry(pattern="a4:83:e7:11:22:33", pattern_type="mac")])
    with caplog.at_level(logging.INFO, logger="lynceus.poller"):
        poll_once(fake_client, db, config, 1700001000, ruleset=rs, allowlist=al)
    assert _alerts_count(db) == 0
    assert "Allowlist suppressed" not in caplog.text


def test_normal_watchlist_hit_no_allowlist_no_suppression_log(db, config, fake_client, caplog):
    """Regression guard: the new audit-log block must not fire on the normal
    alert path (no allowlist entry, watchlist matches, alert written)."""
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
    with caplog.at_level(logging.INFO, logger="lynceus.poller"):
        poll_once(fake_client, db, config, 1700001000, ruleset=rs)
    assert _alerts_count(db) == 1
    assert "suppressed" not in caplog.text


def test_allowlist_suppression_log_includes_severity(db, config, fake_client, caplog):
    """The severity field in the audit line lets operators triage which
    suppressions to investigate first — a high-severity watchlist rule
    silenced by allowlist is a different signal than a low-severity one."""
    rs = Ruleset(
        rules=[
            Rule(
                name="apple_mac_high",
                rule_type="watchlist_mac",
                severity="high",
                patterns=["a4:83:e7:11:22:33"],
            )
        ]
    )
    al = Allowlist(entries=[AllowlistEntry(pattern="a4:83:e7:11:22:33", pattern_type="mac")])
    with caplog.at_level(logging.INFO, logger="lynceus.poller"):
        poll_once(fake_client, db, config, 1700001000, ruleset=rs, allowlist=al)
    assert "severity=high" in caplog.text


def test_poll_once_docstring_pins_allowlist_precedence_paragraph():
    """Docstring regression guard: future refactors must not drop the
    Allowlist precedence note from poll_once."""
    assert poll_once.__doc__ is not None
    assert "Allowlist precedence" in poll_once.__doc__


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

    # Skip the per-attempt sleep so this test runs sub-second instead of waiting
    # the full default backoff schedule.
    monkeypatch.setattr("lynceus.poller.HEALTH_CHECK_RETRY_BACKOFF", [0.0, 0.0, 0.0])
    monkeypatch.setattr("requests.sessions.Session.get", boom)
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

    monkeypatch.setattr("requests.sessions.Session.get", boom)
    poller = Poller(cfg)
    poller.db.close()


# ----------------- H3: startup health-check retry with backoff --------------


def test_poller_init_health_check_retries_then_succeeds(tmp_path, monkeypatch):
    """Two transient health-check failures followed by success: poller starts
    cleanly. Pre-fix this raised on the first failure (no retry loop)."""
    cfg = Config(
        db_path=str(tmp_path / "lynceus.db"),
        kismet_url="http://127.0.0.1:1",
    )

    monkeypatch.setattr("lynceus.poller.HEALTH_CHECK_RETRY_BACKOFF", [0.0, 0.0, 0.0])

    results = iter(
        [
            {"reachable": False, "version": None, "error": "Conn refused"},
            {"reachable": False, "version": None, "error": "Conn refused"},
            {"reachable": True, "version": "2024-01-R1", "error": None},
        ]
    )

    def fake_health_check(self):
        return next(results)

    monkeypatch.setattr(
        "lynceus.kismet.KismetClient.health_check",
        fake_health_check,
    )
    poller = Poller(cfg)
    try:
        # Sanity: only 3 results were produced; nothing else consumed.
        with pytest.raises(StopIteration):
            next(results)
    finally:
        poller.db.close()


def test_poller_init_health_check_all_attempts_fail_raises(tmp_path, monkeypatch):
    """All three startup attempts fail: RuntimeError mentions Kismet and
    points operators at the config switch."""
    cfg = Config(
        db_path=str(tmp_path / "lynceus.db"),
        kismet_url="http://127.0.0.1:1",
    )

    monkeypatch.setattr("lynceus.poller.HEALTH_CHECK_RETRY_BACKOFF", [0.0, 0.0, 0.0])
    monkeypatch.setattr(
        "lynceus.kismet.KismetClient.health_check",
        lambda self: {"reachable": False, "version": None, "error": "boom"},
    )
    with pytest.raises(RuntimeError) as exc_info:
        Poller(cfg)
    msg = str(exc_info.value)
    assert "Kismet" in msg
    assert "kismet_health_check_on_startup" in msg
    assert "boom" in msg


def test_poller_init_health_check_backoff_schedule_honored(tmp_path, monkeypatch):
    """Sleep is invoked between attempts 1->2 and 2->3 with the configured
    waits, and NOT after the final failed attempt (we raise instead)."""
    cfg = Config(
        db_path=str(tmp_path / "lynceus.db"),
        kismet_url="http://127.0.0.1:1",
    )

    monkeypatch.setattr("lynceus.poller.HEALTH_CHECK_RETRY_BACKOFF", [2.0, 4.0, 8.0])
    monkeypatch.setattr(
        "lynceus.kismet.KismetClient.health_check",
        lambda self: {"reachable": False, "version": None, "error": "down"},
    )
    sleeps: list[float] = []
    monkeypatch.setattr("lynceus.poller.time.sleep", lambda s: sleeps.append(s))
    with pytest.raises(RuntimeError):
        Poller(cfg)
    assert sleeps == [2.0, 4.0]


# ----------------- H4: top-level exception handler in run_forever -----------


def test_run_forever_continues_past_connection_error(config, monkeypatch):
    """A transient ConnectionError mid-poll must NOT exit the daemon.

    Pre-fix: the first ConnectionError escaped the while loop and crashed
    the daemon — poll_once would have been called exactly once. After the
    fix the loop swallows it, logs at ERROR, and proceeds to the next tick.
    The third side effect raises KeyboardInterrupt to break out cleanly.
    """
    import requests as _requests

    poller = Poller(config)
    calls: list[int] = []

    def fake_poll(client, db, cfg, now_ts, **kwargs):
        calls.append(now_ts)
        if len(calls) == 1:
            raise _requests.ConnectionError("kismet flapping")
        if len(calls) == 2:
            return 0
        raise KeyboardInterrupt()

    monkeypatch.setattr("lynceus.poller.poll_once", fake_poll)
    monkeypatch.setattr(poller, "_interruptible_sleep", lambda s: None)

    with pytest.raises(KeyboardInterrupt):
        poller.run_forever()
    assert len(calls) == 3


def test_run_forever_continues_past_validation_error(config, monkeypatch):
    """A pydantic ValidationError from a malformed device record mid-poll
    must not crash the daemon either."""
    from pydantic import BaseModel

    poller = Poller(config)
    calls: list[int] = []

    class _Tiny(BaseModel):
        x: int

    def fake_poll(client, db, cfg, now_ts, **kwargs):
        calls.append(now_ts)
        if len(calls) == 1:
            _Tiny(x="not-an-int")  # raises ValidationError
        if len(calls) == 2:
            return 0
        raise KeyboardInterrupt()

    monkeypatch.setattr("lynceus.poller.poll_once", fake_poll)
    monkeypatch.setattr(poller, "_interruptible_sleep", lambda s: None)

    with pytest.raises(KeyboardInterrupt):
        poller.run_forever()
    assert len(calls) == 3


def test_run_forever_logs_error_with_traceback_on_swallowed_exception(config, monkeypatch, caplog):
    """The swallowed exception must land in journalctl with exc_info so
    operators can diagnose without strace."""
    import requests as _requests

    poller = Poller(config)
    calls: list[int] = []

    def fake_poll(client, db, cfg, now_ts, **kwargs):
        calls.append(now_ts)
        if len(calls) == 1:
            raise _requests.ConnectionError("transient")
        raise KeyboardInterrupt()

    monkeypatch.setattr("lynceus.poller.poll_once", fake_poll)
    monkeypatch.setattr(poller, "_interruptible_sleep", lambda s: None)

    with caplog.at_level(logging.ERROR, logger="lynceus.poller"):
        with pytest.raises(KeyboardInterrupt):
            poller.run_forever()
    error_records = [r for r in caplog.records if r.levelname == "ERROR"]
    assert len(error_records) == 1
    # exc_info must be populated so the traceback is rendered in journalctl.
    assert error_records[0].exc_info is not None
    assert error_records[0].exc_info[0] is _requests.ConnectionError


def test_run_forever_sleeps_between_swallowed_exception_and_next_tick(config, monkeypatch):
    """After swallowing an exception we must wait the configured poll
    interval before retrying — a tight loop on a persistent error would
    DoS Kismet on every restart cycle."""
    import requests as _requests

    poller = Poller(config)
    calls: list[int] = []

    def fake_poll(client, db, cfg, now_ts, **kwargs):
        calls.append(now_ts)
        if len(calls) == 1:
            raise _requests.ConnectionError("transient")
        raise KeyboardInterrupt()

    sleeps: list[int] = []
    monkeypatch.setattr("lynceus.poller.poll_once", fake_poll)
    monkeypatch.setattr(poller, "_interruptible_sleep", lambda s: sleeps.append(s))

    with pytest.raises(KeyboardInterrupt):
        poller.run_forever()
    # The sleep ran exactly once — after the swallowed exception, before
    # the second iteration that raises KeyboardInterrupt.
    assert sleeps == [poller.config.poll_interval_seconds]


def test_run_forever_propagates_keyboard_interrupt_and_closes_db(config, monkeypatch):
    """SIGINT (KeyboardInterrupt) must escape run_forever — Ctrl+C should
    actually stop the daemon — and the DB must close on the way out."""
    poller = Poller(config)
    closed: list[bool] = []
    orig_close = poller.db.close

    def closing():
        closed.append(True)
        orig_close()

    monkeypatch.setattr(poller.db, "close", closing)

    def boom(*args, **kwargs):
        raise KeyboardInterrupt()

    monkeypatch.setattr("lynceus.poller.poll_once", boom)

    with pytest.raises(KeyboardInterrupt):
        poller.run_forever()
    assert closed == [True]


def test_run_forever_propagates_system_exit_and_closes_db(config, monkeypatch):
    """SystemExit must escape too — ``systemctl stop`` and any explicit
    ``sys.exit()`` from a deeper layer should not be swallowed."""
    poller = Poller(config)
    closed: list[bool] = []
    orig_close = poller.db.close

    def closing():
        closed.append(True)
        orig_close()

    monkeypatch.setattr(poller.db, "close", closing)

    def boom(*args, **kwargs):
        raise SystemExit(2)

    monkeypatch.setattr("lynceus.poller.poll_once", boom)

    with pytest.raises(SystemExit) as exc_info:
        poller.run_forever()
    assert exc_info.value.code == 2
    assert closed == [True]


def test_poller_init_health_check_retry_logs_info(tmp_path, monkeypatch, caplog):
    """Each retry emits an INFO log line that includes the attempt counter."""
    cfg = Config(
        db_path=str(tmp_path / "lynceus.db"),
        kismet_url="http://127.0.0.1:1",
    )

    monkeypatch.setattr("lynceus.poller.HEALTH_CHECK_RETRY_BACKOFF", [0.0, 0.0, 0.0])
    monkeypatch.setattr(
        "lynceus.kismet.KismetClient.health_check",
        lambda self: {"reachable": False, "version": None, "error": "down"},
    )
    with caplog.at_level(logging.INFO, logger="lynceus.poller"):
        with pytest.raises(RuntimeError):
            Poller(cfg)
    info_lines = [r.getMessage() for r in caplog.records if r.levelname == "INFO"]
    # Two retry log lines (between attempts 1->2 and 2->3); none after the final
    # failure since we raise immediately.
    assert len(info_lines) == 2
    assert "attempt 1/3" in info_lines[0]
    assert "attempt 2/3" in info_lines[1]
    assert "retrying in" in info_lines[0]
