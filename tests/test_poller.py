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
    emit_startup_banner,
    log_watchlist_staleness,
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


# --------------------- TTY-gated startup banner -----------------------------
#
# Banner shows on direct invocation (`lynceus --config foo.yaml` from a
# terminal); suppressed under quickstart (stdout piped to TeeSupervisor)
# and systemd (stdout captured to journalctl). Service-mode startup logs
# a single INFO line carrying the same counts so operators grepping
# journalctl see a clear start marker without box-drawing garbage.


def test_emit_startup_banner_tty_prints_ascii_banner_and_subtitle(capsys):
    emit_startup_banner(active_rules=12, source_count=2, is_tty=True)
    out = capsys.readouterr().out
    # ASCII banner: the recognisable figlet-LYNCEUS upper line.
    assert "the watcher daemon" in out
    # Dynamic subtitle: version + counts + ctrl-c hint.
    assert __version__ in out
    assert "12 rules" in out
    assert "2 interfaces" in out
    assert "ctrl-c to stop" in out


def test_emit_startup_banner_non_tty_suppresses_banner_logs_one_line(caplog, capsys):
    caplog.set_level(logging.INFO, logger="lynceus.poller")
    emit_startup_banner(active_rules=7, source_count=1, is_tty=False)
    # Banner suppressed entirely in service mode — operators grep
    # journalctl, the ASCII art would be noise.
    out = capsys.readouterr().out
    assert "the watcher daemon" not in out
    # One clear INFO line with the same counts so the start signal is
    # still visible.
    matching = [
        rec.getMessage()
        for rec in caplog.records
        if "Lynceus daemon started" in rec.getMessage()
    ]
    assert len(matching) == 1
    assert "7 rules active" in matching[0]
    assert "1 interfaces" in matching[0]


def test_emit_startup_banner_isatty_defaults_to_stdout_when_unset(monkeypatch, capsys):
    """Without an explicit is_tty override, the helper consults
    file.isatty() so production calls work correctly. capsys replaces
    stdout with a non-TTY buffer, which is the same shape the systemd
    capture sees — so without an override we get the service-mode
    branch and the banner is suppressed."""
    emit_startup_banner(active_rules=3, source_count=0)
    out = capsys.readouterr().out
    assert "the watcher daemon" not in out


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


# ---------------------------------------------------------------------------
# log_watchlist_staleness — startup freshness signal.
# ---------------------------------------------------------------------------
#
# Three branches: no imports recorded → INFO "no metadata"; fresh
# (within threshold) → INFO with days+exported date; stale (over
# threshold) → WARNING with refresh hint. Tests exercise each
# directly via log_watchlist_staleness() — the Poller.__init__ wiring
# is covered by smoke (any existing test that constructs a Poller
# would hit the assertion if the call were broken).


def _seed_watchlist_row(db: Database) -> None:
    """Minimum to make row_count > 0 in the staleness log line."""
    with db._conn:
        db._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
            "VALUES ('aa:bb:cc:dd:ee:01', 'mac', 'low', NULL)"
        )


def test_log_watchlist_staleness_no_imports_logs_info_no_metadata(db, caplog):
    """Backward-compat invariant: an empty DB / no imports yet logs
    a single INFO line saying so. No WARNING — a fresh install where
    the operator hasn't run lynceus-import-argus yet would warn at
    every startup otherwise, which is exactly the noise the prompt
    called out as not-the-MVP."""
    _seed_watchlist_row(db)
    with caplog.at_level(logging.INFO, logger="lynceus.poller"):
        log_watchlist_staleness(db, 30, now_ts=1700000000)
    msgs = [r for r in caplog.records if r.name == "lynceus.poller"]
    assert len(msgs) == 1
    assert msgs[0].levelno == logging.INFO
    assert "no Argus import metadata recorded" in msgs[0].getMessage()
    assert "1 rows total" in msgs[0].getMessage()


def test_log_watchlist_staleness_fresh_logs_info(db, caplog):
    """Within-threshold data logs INFO with row count + days + the
    exported date. No refresh hint — operator action is not needed."""
    _seed_watchlist_row(db)
    # exported_at = 5 days before now_ts → well under default 30.
    now_ts = 1700000000
    five_days_ago = now_ts - 5 * 86400
    db.record_import_run(
        imported_at=five_days_ago,
        exported_at=five_days_ago,
        source="/x.csv",
        record_count=1,
    )
    with caplog.at_level(logging.INFO, logger="lynceus.poller"):
        log_watchlist_staleness(db, 30, now_ts=now_ts)
    msgs = [r for r in caplog.records if r.name == "lynceus.poller"]
    assert len(msgs) == 1
    assert msgs[0].levelno == logging.INFO
    assert "5 days ago" in msgs[0].getMessage()
    assert "1 rows total" in msgs[0].getMessage()
    # No refresh hint on the INFO path — that's only on the WARNING.
    assert "lynceus-import-argus --from-github" not in msgs[0].getMessage()


def test_log_watchlist_staleness_stale_logs_warning_with_refresh_hint(db, caplog):
    """Over-threshold data flips to WARNING with the refresh hint —
    the load-bearing signal. An operator running journalctl can spot
    the WARNING without grepping for a specific pattern, and the
    hint names the exact command to run."""
    _seed_watchlist_row(db)
    now_ts = 1700000000
    forty_days_ago = now_ts - 40 * 86400
    db.record_import_run(
        imported_at=forty_days_ago,
        exported_at=forty_days_ago,
        source="/x.csv",
        record_count=1,
    )
    with caplog.at_level(logging.WARNING, logger="lynceus.poller"):
        log_watchlist_staleness(db, 30, now_ts=now_ts)
    msgs = [r for r in caplog.records if r.name == "lynceus.poller"]
    assert len(msgs) == 1
    assert msgs[0].levelno == logging.WARNING
    assert "40 days ago" in msgs[0].getMessage()
    assert "lynceus-import-argus --from-github" in msgs[0].getMessage()


def test_log_watchlist_staleness_threshold_is_configurable(db, caplog):
    """warn_days is operator-tunable per deployment cadence — kiosk /
    air-gapped operators on a slower cadence configure a longer
    threshold to avoid noisy WARNINGs. The same data that's INFO at
    threshold=30 must flip to WARNING at threshold=5."""
    _seed_watchlist_row(db)
    now_ts = 1700000000
    ten_days_ago = now_ts - 10 * 86400
    db.record_import_run(
        imported_at=ten_days_ago,
        exported_at=ten_days_ago,
        source="/x.csv",
        record_count=1,
    )
    # threshold=30 → 10-day-old data is fresh.
    with caplog.at_level(logging.INFO, logger="lynceus.poller"):
        log_watchlist_staleness(db, 30, now_ts=now_ts)
    msgs_30 = [r for r in caplog.records if r.name == "lynceus.poller"]
    assert len(msgs_30) == 1
    assert msgs_30[0].levelno == logging.INFO

    caplog.clear()
    # threshold=5 → same data is stale.
    with caplog.at_level(logging.INFO, logger="lynceus.poller"):
        log_watchlist_staleness(db, 5, now_ts=now_ts)
    msgs_5 = [r for r in caplog.records if r.name == "lynceus.poller"]
    assert len(msgs_5) == 1
    assert msgs_5[0].levelno == logging.WARNING


def test_log_watchlist_staleness_falls_back_to_imported_at_when_exported_at_null(
    db, caplog
):
    """Legacy / free-form-meta imports land with exported_at=None.
    The age calculation must fall back to imported_at rather than
    crashing — the local-clock timestamp is a strict lower bound on
    the data's age (data can be older than imported_at but never
    newer)."""
    _seed_watchlist_row(db)
    now_ts = 1700000000
    fifty_days_ago = now_ts - 50 * 86400
    db.record_import_run(
        imported_at=fifty_days_ago,
        exported_at=None,  # legacy / unparseable meta
        source="/legacy.csv",
        record_count=None,
    )
    with caplog.at_level(logging.WARNING, logger="lynceus.poller"):
        log_watchlist_staleness(db, 30, now_ts=now_ts)
    msgs = [r for r in caplog.records if r.name == "lynceus.poller"]
    assert len(msgs) == 1
    assert msgs[0].levelno == logging.WARNING
    assert "50 days ago" in msgs[0].getMessage()
    # When exported_at is None, the rendered exported date falls
    # through to "unknown" rather than guessing.
    assert "exported unknown" in msgs[0].getMessage()


def test_log_watchlist_staleness_fires_at_poller_init(tmp_path, caplog):
    """Smoke wiring: constructing a Poller logs the staleness line
    (here, the no-metadata branch). Belt to the suspenders of the
    direct unit tests above — proves the call site in
    Poller.__init__ is actually reached."""
    cfg = Config(
        kismet_fixture_path=str(FIXTURE_PATH),
        db_path=str(tmp_path / "lynceus.db"),
    )
    with caplog.at_level(logging.INFO, logger="lynceus.poller"):
        poller = Poller(cfg)
    try:
        msgs = [
            r for r in caplog.records
            if r.name == "lynceus.poller" and "watchlist:" in r.getMessage()
        ]
        assert len(msgs) == 1
    finally:
        poller.db.close()


# -----------------------------------------------------------------------------
# Ruleset-load startup log. Counterpart to the watchlist staleness signal
# and the runtime severity overrides log: every startup-time load the
# operator can configure ships with a grep-able INFO line so a smoke
# runbook can deterministically verify the layer is wired.
# -----------------------------------------------------------------------------


def test_poller_init_logs_loaded_ruleset_all_enabled(tmp_path, caplog):
    """rules_path set, every rule enabled → INFO log emits the bare
    'N active rules' form (no '(M disabled)' parenthetical). Exact
    literal is a live-smoke runbook grep target."""
    rules_path = tmp_path / "rules.yaml"
    rules_path.write_text(
        "rules:\n"
        "  - name: r1\n"
        "    rule_type: watchlist_mac\n"
        "    severity: med\n"
        "  - name: r2\n"
        "    rule_type: watchlist_oui\n"
        "    severity: low\n",
        encoding="utf-8",
    )
    cfg = Config(
        kismet_fixture_path=str(FIXTURE_PATH),
        db_path=str(tmp_path / "lynceus.db"),
        rules_path=str(rules_path),
    )
    with caplog.at_level(logging.INFO, logger="lynceus.poller"):
        poller = Poller(cfg)
    try:
        msgs = [
            r.getMessage() for r in caplog.records
            if r.name == "lynceus.poller" and "loaded ruleset" in r.getMessage()
        ]
        assert len(msgs) == 1
        assert msgs[0] == f"loaded ruleset from {rules_path}: 2 active rules"
    finally:
        poller.db.close()


def test_poller_init_logs_loaded_ruleset_with_disabled(tmp_path, caplog):
    """rules_path set with mixed enabled/disabled → log emits
    '(M disabled)' parenthetical so the operator sees the gap."""
    rules_path = tmp_path / "rules.yaml"
    rules_path.write_text(
        "rules:\n"
        "  - name: r1\n"
        "    rule_type: watchlist_mac\n"
        "    severity: med\n"
        "  - name: r2\n"
        "    rule_type: watchlist_oui\n"
        "    severity: low\n"
        "    enabled: false\n",
        encoding="utf-8",
    )
    cfg = Config(
        kismet_fixture_path=str(FIXTURE_PATH),
        db_path=str(tmp_path / "lynceus.db"),
        rules_path=str(rules_path),
    )
    with caplog.at_level(logging.INFO, logger="lynceus.poller"):
        poller = Poller(cfg)
    try:
        msgs = [
            r.getMessage() for r in caplog.records
            if r.name == "lynceus.poller" and "loaded ruleset" in r.getMessage()
        ]
        assert len(msgs) == 1
        assert msgs[0] == (
            f"loaded ruleset from {rules_path}: 1 active rules (1 disabled)"
        )
    finally:
        poller.db.close()


def test_poller_init_logs_no_rules_path_configured(tmp_path, caplog):
    """rules_path unset → INFO log makes the empty-ruleset state
    explicit so the operator doesn't silently run with no alerting."""
    cfg = Config(
        kismet_fixture_path=str(FIXTURE_PATH),
        db_path=str(tmp_path / "lynceus.db"),
    )
    assert cfg.rules_path is None
    with caplog.at_level(logging.INFO, logger="lynceus.poller"):
        poller = Poller(cfg)
    try:
        msgs = [
            r.getMessage() for r in caplog.records
            if r.name == "lynceus.poller" and "rules_path" in r.getMessage()
        ]
        assert len(msgs) == 1
        assert msgs[0] == (
            "no rules_path configured; ruleset is empty — no alerts will fire"
        )
        assert poller.ruleset.rules == []
    finally:
        poller.db.close()


# ----------------------- allowlist mtime watch + audit-line ------------------


def _write(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")


def test_allowlist_mtime_watch_reloads_on_primary_change(tmp_path, caplog):
    """Editing the operator-curated primary file is picked up at the next
    poll tick without a daemon restart."""
    primary = tmp_path / "allowlist.yaml"
    _write(primary, "entries: []\n")
    cfg = Config(
        kismet_fixture_path=str(FIXTURE_PATH),
        db_path=str(tmp_path / "lynceus.db"),
        location_id="testloc",
        location_label="Test Location",
        allowlist_path=str(primary),
    )
    poller = Poller(cfg)
    try:
        assert poller.allowlist.entries == []
        _write(
            primary,
            "entries:\n  - pattern: aa:bb:cc:dd:ee:ff\n    pattern_type: mac\n",
        )
        # Force mtime to differ; on a fast filesystem the second write may
        # land in the same st_mtime tick as the first.
        import os as _os

        st = primary.stat()
        _os.utime(primary, (st.st_atime, st.st_mtime + 1))
        with caplog.at_level(logging.INFO, logger="lynceus.poller"):
            poller._maybe_reload_allowlist()
        assert len(poller.allowlist.entries) == 1
        assert poller.allowlist.entries[0].pattern == "aa:bb:cc:dd:ee:ff"
        assert any(
            "allowlist reloaded" in r.getMessage()
            and "1 operator entries" in r.getMessage()
            and "0 UI entries" in r.getMessage()
            for r in caplog.records
            if r.name == "lynceus.poller"
        )
    finally:
        poller.db.close()


def test_allowlist_mtime_watch_reloads_on_ui_file_appearance(tmp_path):
    """A UI sibling appearing for the first time (e.g., first /alerts/<id>/snooze
    button click) trips a reload on the next tick — daemon needs no restart."""
    primary = tmp_path / "allowlist.yaml"
    _write(primary, "entries: []\n")
    cfg = Config(
        kismet_fixture_path=str(FIXTURE_PATH),
        db_path=str(tmp_path / "lynceus.db"),
        location_id="testloc",
        location_label="Test Location",
        allowlist_path=str(primary),
    )
    poller = Poller(cfg)
    try:
        assert poller.allowlist.entries == []
        from lynceus.allowlist import AllowlistEntry as _Entry
        from lynceus.allowlist import add_ui_entry as _add
        from lynceus.allowlist import derive_ui_path as _derive

        _add(
            _derive(primary),
            _Entry(
                pattern="11:22:33:44:55:66",
                pattern_type="mac",
                added_at=1_799_000_000,
            ),
        )
        poller._maybe_reload_allowlist()
        assert len(poller.allowlist.entries) == 1
        assert poller.allowlist.entries[0].pattern == "11:22:33:44:55:66"
    finally:
        poller.db.close()


def test_allowlist_mtime_watch_no_change_no_reload(tmp_path, caplog):
    """Steady-state cost guarantee: a tick with no file change does not
    re-parse YAML or emit the reload INFO line."""
    primary = tmp_path / "allowlist.yaml"
    _write(
        primary,
        "entries:\n  - pattern: aa:bb:cc:dd:ee:ff\n    pattern_type: mac\n",
    )
    cfg = Config(
        kismet_fixture_path=str(FIXTURE_PATH),
        db_path=str(tmp_path / "lynceus.db"),
        location_id="testloc",
        location_label="Test Location",
        allowlist_path=str(primary),
    )
    poller = Poller(cfg)
    try:
        # The init-time load already happened; mtime cache is populated.
        first_id = id(poller.allowlist)
        with caplog.at_level(logging.INFO, logger="lynceus.poller"):
            poller._maybe_reload_allowlist()
            poller._maybe_reload_allowlist()
        assert id(poller.allowlist) == first_id  # same object, no reload
        assert not any(
            "allowlist reloaded" in r.getMessage()
            for r in caplog.records
            if r.name == "lynceus.poller"
        )
    finally:
        poller.db.close()


def test_allowlist_mtime_watch_handles_deleted_primary(tmp_path, caplog):
    """If the operator deletes the primary file mid-run (rename in progress,
    fat-fingered ``rm``), the daemon retains its last-known-good allowlist
    rather than emptying suppression. A WARNING is logged. The next tick
    will reload when the file reappears."""
    primary = tmp_path / "allowlist.yaml"
    _write(
        primary,
        "entries:\n  - pattern: aa:bb:cc:dd:ee:ff\n    pattern_type: mac\n",
    )
    cfg = Config(
        kismet_fixture_path=str(FIXTURE_PATH),
        db_path=str(tmp_path / "lynceus.db"),
        location_id="testloc",
        location_label="Test Location",
        allowlist_path=str(primary),
    )
    poller = Poller(cfg)
    try:
        assert len(poller.allowlist.entries) == 1
        primary.unlink()
        with caplog.at_level(logging.WARNING, logger="lynceus.poller"):
            poller._maybe_reload_allowlist()
        # Entries retained.
        assert len(poller.allowlist.entries) == 1
        assert any(
            "vanished" in r.getMessage()
            for r in caplog.records
            if r.name == "lynceus.poller"
        )
    finally:
        poller.db.close()


def test_allowlist_mtime_watch_noop_when_no_allowlist_path(tmp_path):
    """Configs without ``allowlist_path`` skip the mtime check entirely."""
    cfg = Config(
        kismet_fixture_path=str(FIXTURE_PATH),
        db_path=str(tmp_path / "lynceus.db"),
        location_id="testloc",
        location_label="Test Location",
        # No allowlist_path.
    )
    poller = Poller(cfg)
    try:
        poller._maybe_reload_allowlist()
        assert poller.allowlist.entries == []
    finally:
        poller.db.close()


def test_audit_line_includes_expires_suffix_for_snooze_entry(db, config, fake_client, caplog):
    """An entry with non-None ``expires_at`` is a snooze; the audit line
    must annotate the expiry so operators reading journalctl can tell
    temporary suppression apart from permanent allowlisting."""
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
    expires_ts = 1_900_000_000
    al = Allowlist(
        entries=[
            AllowlistEntry(
                pattern="a4:83:e7:11:22:33",
                pattern_type="mac",
                expires_at=expires_ts,
                added_at=1_800_000_000,
            )
        ]
    )
    with caplog.at_level(logging.INFO, logger="lynceus.poller"):
        poll_once(fake_client, db, config, 1_800_000_000, ruleset=rs, allowlist=al)
    # The audit line still fires, AND it includes the expires suffix in ISO form.
    assert "Allowlist suppressed watchlist hit:" in caplog.text
    assert "(expires 2030-03-17T17:46:40Z)" in caplog.text


def test_audit_line_no_expires_suffix_for_permanent_entry(db, config, fake_client, caplog):
    """A permanent entry (no ``expires_at``) keeps the pre-rc5 audit-line
    shape so operators grepping for the existing prefix are unaffected."""
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
    al = Allowlist(
        entries=[AllowlistEntry(pattern="a4:83:e7:11:22:33", pattern_type="mac")]
    )
    with caplog.at_level(logging.INFO, logger="lynceus.poller"):
        poll_once(fake_client, db, config, 1_800_000_000, ruleset=rs, allowlist=al)
    assert "Allowlist suppressed watchlist hit:" in caplog.text
    assert "(expires" not in caplog.text


def test_expired_entry_does_not_suppress_in_poll(db, config, fake_client):
    """An expired snooze entry is silently skipped at poll time; the
    watchlist hit fires normally."""
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
    al = Allowlist(
        entries=[
            AllowlistEntry(
                pattern="a4:83:e7:11:22:33",
                pattern_type="mac",
                expires_at=1_700_000_000,
            )
        ]
    )
    poll_once(fake_client, db, config, 1_800_000_000, ruleset=rs, allowlist=al)
    assert _alerts_count(db) == 1


# ---------------------------------------------------------------------------
# rc6 rule_type snooze gate.
# ---------------------------------------------------------------------------


def _apple_oui_ruleset() -> Ruleset:
    """Apple-OUI rule that will fire on the fixture's a4:83:e7 device."""
    return Ruleset(
        rules=[
            Rule(
                name="apple_oui",
                rule_type="watchlist_oui",
                severity="high",
                patterns=["a4:83:e7"],
            )
        ]
    )


def test_rule_type_snooze_suppresses_emit(db, config, fake_client):
    """An active rule_type snooze for watchlist_oui suppresses the
    alert emit — no row in alerts. The RuleHit was still produced
    (rules.evaluate ran); only db.add_alert is gated."""
    rs = _apple_oui_ruleset()
    db.add_rule_type_snooze(
        rule_type="watchlist_oui",
        expires_at=1_700_001_500,
        added_at=1_700_001_000,
    )
    poll_once(fake_client, db, config, 1_700_001_000, ruleset=rs)
    assert _alerts_count(db) == 0


def test_rule_type_snooze_other_rule_type_not_suppressed(db, config, fake_client):
    """Snoozing watchlist_mac doesn't gate watchlist_oui — suppressions
    are per rule_type, not global."""
    rs = _apple_oui_ruleset()
    db.add_rule_type_snooze(
        rule_type="watchlist_mac",
        expires_at=1_700_001_500,
        added_at=1_700_001_000,
    )
    poll_once(fake_client, db, config, 1_700_001_000, ruleset=rs)
    assert _alerts_count(db) == 1


def test_rule_type_snooze_expired_does_not_suppress(db, config, fake_client):
    """A snooze whose expires_at has passed is gracefully ignored at
    gate time — the alert fires normally. Mirrors the allowlist
    expired-entry behavior (see test_expired_entry_does_not_suppress_in_poll)."""
    rs = _apple_oui_ruleset()
    db.add_rule_type_snooze(
        rule_type="watchlist_oui",
        expires_at=1_700_000_000,
        added_at=1_699_999_000,
    )
    poll_once(fake_client, db, config, 1_700_001_000, ruleset=rs)
    assert _alerts_count(db) == 1


def test_rule_type_snooze_accumulates_into_counter(db, config, fake_client):
    """The optional suppression_counter dict accumulates per rule_type
    when poll_once gates an emit. The Poller passes its own dict so
    multi-tick accumulation works; tests pass a local dict to inspect
    the gate behavior directly."""
    rs = _apple_oui_ruleset()
    db.add_rule_type_snooze(
        rule_type="watchlist_oui",
        expires_at=1_700_001_500,
        added_at=1_700_001_000,
    )
    counter: dict[str, int] = {}
    poll_once(
        fake_client,
        db,
        config,
        1_700_001_000,
        ruleset=rs,
        rule_type_suppression_counter=counter,
    )
    assert counter == {"watchlist_oui": 1}


def test_rule_type_snooze_counter_none_means_no_accumulation(db, config, fake_client):
    """Passing counter=None (default) still gates the emit correctly;
    only the breakdown accumulation is skipped. Confirms the gate's
    correctness contract is independent of the counter argument."""
    rs = _apple_oui_ruleset()
    db.add_rule_type_snooze(
        rule_type="watchlist_oui",
        expires_at=1_700_001_500,
        added_at=1_700_001_000,
    )
    # No counter arg → default None.
    poll_once(fake_client, db, config, 1_700_001_000, ruleset=rs)
    assert _alerts_count(db) == 0


def test_rule_type_snooze_skips_notifier(db, config, fake_client):
    """Notifier.send must NOT be called for suppressed emits. The
    operator's whole point in snoozing is "don't page me about this
    rule_type" — leaking the alert to ntfy/push would defeat the
    feature even if no DB row is written."""
    rs = _apple_oui_ruleset()
    db.add_rule_type_snooze(
        rule_type="watchlist_oui",
        expires_at=1_700_001_500,
        added_at=1_700_001_000,
    )
    rec = RecordingNotifier()
    poll_once(fake_client, db, config, 1_700_001_000, ruleset=rs, notifier=rec)
    assert rec.calls == []


def test_poll_once_cleans_up_expired_rule_type_snoozes(db, config, fake_client):
    """poll_once invokes cleanup_expired_rule_type_snoozes at end of
    tick; expired rows physically vanish from the table on the next
    poll. The gate's expires_at > now_ts filter already handles
    correctness between cycles — cleanup is the housekeeping that
    keeps steady-state row count bounded."""
    db.add_rule_type_snooze(
        rule_type="watchlist_oui",
        expires_at=1_700_000_000,
        added_at=1_699_999_000,
    )
    db.add_rule_type_snooze(
        rule_type="watchlist_mac",
        expires_at=1_700_002_000,
        added_at=1_700_000_000,
    )
    poll_once(fake_client, db, config, 1_700_001_000)
    remaining = {
        r["rule_type"]
        for r in db._conn.execute(
            "SELECT rule_type FROM rule_type_snoozes"
        ).fetchall()
    }
    assert remaining == {"watchlist_mac"}  # only the active one survives


def test_poller_suppression_log_flushes_after_interval(db, config, fake_client, monkeypatch, caplog):
    """The Poller emits the breakdown INFO line when
    SUPPRESSION_LOG_INTERVAL_SECONDS has elapsed and the counter has
    accumulated entries. We shrink the interval to 0 so a single
    poll-tick is enough to trip the flush; the resulting log line
    carries the rule_type breakdown."""
    from lynceus import poller as poller_mod

    monkeypatch.setattr(poller_mod, "SUPPRESSION_LOG_INTERVAL_SECONDS", 0)
    rs = _apple_oui_ruleset()
    db.add_rule_type_snooze(
        rule_type="watchlist_oui",
        expires_at=1_700_010_000,
        added_at=1_700_001_000,
    )

    cfg = config.model_copy(
        update={
            "kismet_health_check_on_startup": False,
            "rules_path": None,
            "allowlist_path": None,
        }
    )
    p = Poller(cfg)
    try:
        # Inject the test ruleset directly; the Poller's normal load
        # path doesn't apply here.
        p.ruleset = rs
        # Anchor the cadence so any positive elapsed seconds will
        # exceed the (now-zero) interval. Subsequent poll_once call
        # will tick the in-process clock past it.
        p._last_suppression_log_ts = 0
        with caplog.at_level(logging.INFO, logger="lynceus.poller"):
            # Pump the gate path via direct poll_once: it accumulates
            # into p._rule_type_suppression_counter, then we trigger
            # the flush manually to keep the test independent of the
            # internal run_forever loop machinery.
            poll_once(
                fake_client,
                p.db,
                cfg,
                1_700_001_000,
                ruleset=rs,
                rule_type_suppression_counter=p._rule_type_suppression_counter,
            )
            p._maybe_flush_suppression_summary(now_ts=1_700_001_500)
    finally:
        p.db.close()

    assert "rule_type snooze suppressed" in caplog.text
    assert "watchlist_oui=1" in caplog.text


def test_poller_suppression_log_skips_when_counter_empty(db, config, fake_client, monkeypatch, caplog):
    """An idle hour (no suppressions) doesn't produce a log line —
    only the cadence anchor moves forward. Avoids spamming journalctl
    with '0 suppressed' lines."""
    from lynceus import poller as poller_mod

    monkeypatch.setattr(poller_mod, "SUPPRESSION_LOG_INTERVAL_SECONDS", 0)
    cfg = config.model_copy(
        update={
            "kismet_health_check_on_startup": False,
            "rules_path": None,
            "allowlist_path": None,
        }
    )
    p = Poller(cfg)
    try:
        p._last_suppression_log_ts = 0
        with caplog.at_level(logging.INFO, logger="lynceus.poller"):
            p._maybe_flush_suppression_summary(now_ts=1_700_001_500)
    finally:
        p.db.close()

    assert "rule_type snooze suppressed" not in caplog.text
    # And the cadence anchor advanced to "now" so we don't burst-log
    # on the next non-empty counter.
    assert p._last_suppression_log_ts == 1_700_001_500


# ===================== watchful_recurrence integration (migration 018) =====
# Poller-side coverage of the watchful gate: ordering vs allowlist + rule
# eval, escalation emit shape (severity high AND ntfy priority 4),
# matched_watchlist_id propagation, post-escalation anti-spam, and the
# 90d auto-archive housekeeping pass. Phase 2 (operator UI) lands the
# create surface; Phase 1 tests INSERT directly into the table.

WATCHFUL_TEST_MAC = "a4:83:e7:11:22:33"  # first fixture device


def _insert_watchful_for_poller(
    db,
    mac=WATCHFUL_TEST_MAC,
    *,
    created_at=1000,
    first_seen_at=1000,
    last_seen_at=1000,
    sighting_count=1,
    snooze_expires_at=None,
    escalated_at=None,
    archived_at=None,
    source_alert_id=None,
    matched_watchlist_id=None,
):
    cur = db._conn.execute(
        "INSERT INTO watchful_recurrence("
        "mac, created_at, first_seen_at, last_seen_at, sighting_count, "
        "snooze_expires_at, escalated_at, archived_at, "
        "source_alert_id, matched_watchlist_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            mac,
            created_at,
            first_seen_at,
            last_seen_at,
            sighting_count,
            snooze_expires_at,
            escalated_at,
            archived_at,
            source_alert_id,
            matched_watchlist_id,
        ),
    )
    db._conn.commit()
    return cur.lastrowid


def _watchful_row(db, mac=WATCHFUL_TEST_MAC):
    return db._conn.execute(
        "SELECT * FROM watchful_recurrence WHERE mac = ? "
        "ORDER BY id DESC LIMIT 1",
        (mac,),
    ).fetchone()


def test_watchful_tracking_gate_increments_count_on_qualifying_observation(
    db, config, fake_client
):
    """Active watchful entry + observation with gap >= 24h must
    increment sighting_count and update last_seen_at to now_ts.
    """
    _insert_watchful_for_poller(db, last_seen_at=1_700_000_000, sighting_count=1)
    poll_once(fake_client, db, config, 1_700_086_400)  # exactly 24h later
    row = _watchful_row(db)
    assert row["sighting_count"] == 2
    assert row["last_seen_at"] == 1_700_086_400


def test_watchful_gate_no_op_when_no_active_entry(db, config, fake_client):
    """Backward-compat invariant: with no watchful entries in the
    table, the poll cycle's behavior is byte-identical to pre-rc6.
    Sightings persist, no escalation, no archives."""
    poll_once(fake_client, db, config, 1_700_001_000)
    sightings = db._conn.execute("SELECT COUNT(*) FROM sightings").fetchone()[0]
    alerts = _alerts_count(db)
    watchful_rows = db._conn.execute(
        "SELECT COUNT(*) FROM watchful_recurrence"
    ).fetchone()[0]
    assert sightings == 5
    assert alerts == 0
    assert watchful_rows == 0


def test_watchful_escalation_emits_high_severity_priority_4_alert(
    db, config, fake_client
):
    """Threshold-cross emits an alert with severity='high' (so /alerts
    and /rules render the high badge consistent with operator intent)
    AND notifier.send is called with priority_override=4 (so ntfy
    prominence is the scare-factor-mitigated 4, not the urgent-5
    reserved for severity=high watchlist hits). BOTH must hold.
    """
    # sighting_count=3 + one counted recurrence = threshold cross at 4
    _insert_watchful_for_poller(
        db, last_seen_at=1_700_000_000, sighting_count=3,
    )
    rec = RecordingNotifier()
    poll_once(fake_client, db, config, 1_700_086_400, notifier=rec)

    # Alert row was written with rule_type=watchful_recurrence severity=high
    rows = db._conn.execute(
        "SELECT severity, rule_type, mac FROM alerts WHERE rule_type = ?",
        ("watchful_recurrence",),
    ).fetchall()
    assert len(rows) == 1
    assert rows[0]["severity"] == "high"
    assert rows[0]["mac"] == WATCHFUL_TEST_MAC

    # Notifier saw severity=high AND priority_override=4
    matching = [
        (rec.calls[i], rec.priority_overrides[i])
        for i in range(len(rec.calls))
        if "watchful escalation" in rec.calls[i][1]
    ]
    assert len(matching) == 1
    (severity, _title, _msg), override = matching[0]
    assert severity == "high"
    assert override == 4

    # State transition: escalated_at set
    row = _watchful_row(db)
    assert row["sighting_count"] == 4
    assert row["escalated_at"] is not None


def test_watchful_escalation_propagates_matched_watchlist_id(
    db, config, fake_client
):
    """matched_watchlist_id on the watchful entry must propagate into
    the escalation alert's matched_watchlist_id column, so the alert
    row carries the original rule's provenance for the /alerts triage
    surface and downstream metadata enrichment."""
    # Seed a watchlist row so the FK is satisfied
    cur = db._conn.execute(
        "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
        "VALUES (?, ?, ?, ?)",
        ("a4:83:e7:11:22:33", "mac", "high", "test"),
    )
    db._conn.commit()
    watchlist_id = cur.lastrowid

    _insert_watchful_for_poller(
        db,
        last_seen_at=1_700_000_000,
        sighting_count=3,
        matched_watchlist_id=watchlist_id,
    )
    poll_once(fake_client, db, config, 1_700_086_400)

    alert = db._conn.execute(
        "SELECT matched_watchlist_id FROM alerts WHERE rule_type = ?",
        ("watchful_recurrence",),
    ).fetchone()
    assert alert is not None
    assert alert["matched_watchlist_id"] == watchlist_id


def test_watchful_allowlist_short_circuits_no_sighting_no_escalation(
    db, config, fake_client
):
    """Locked gate ordering: allowlist -> watchful -> rule eval. An
    allowlisted MAC under watchful snooze MUST see:
    1) sighting_count UNCHANGED
    2) NO escalation alert fires, even when sighting_count=3 would
       cross the threshold on this cycle.
    Both assertions are the operator-facing semantic guarantee --
    they pin 'allowlist precedence wins' against future regressions
    that might re-order the gates."""
    _insert_watchful_for_poller(
        db, last_seen_at=1_700_000_000, sighting_count=3,
    )
    al = Allowlist(
        entries=[AllowlistEntry(pattern=WATCHFUL_TEST_MAC, pattern_type="mac")]
    )
    rec = RecordingNotifier()
    poll_once(
        fake_client, db, config, 1_700_086_400, allowlist=al, notifier=rec,
    )

    # sighting_count unchanged (gate never reached)
    row = _watchful_row(db)
    assert row["sighting_count"] == 3
    assert row["last_seen_at"] == 1_700_000_000
    assert row["escalated_at"] is None

    # No escalation alert fired
    escalation_alerts = db._conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE rule_type = ?",
        ("watchful_recurrence",),
    ).fetchone()[0]
    assert escalation_alerts == 0
    assert not any("watchful escalation" in c[1] for c in rec.calls)


def test_watchful_post_escalation_sightings_do_not_re_fire(
    db, config, fake_client
):
    """Subsequent recurrences after escalation MUST NOT emit new alerts
    (design doc anti-spam rule). Sighting count continues climbing on
    the row -- /watchful UI (Phase 2) shows the count -- but the
    notifier sees no new escalation."""
    _insert_watchful_for_poller(
        db,
        last_seen_at=1_700_000_000,
        sighting_count=5,
        escalated_at=1_700_000_000,
    )
    rec = RecordingNotifier()
    poll_once(fake_client, db, config, 1_700_086_400, notifier=rec)

    row = _watchful_row(db)
    assert row["sighting_count"] == 6  # count continued
    assert row["escalated_at"] == 1_700_000_000  # original escalation ts preserved
    assert _alerts_count(db) == 0
    assert not any("watchful escalation" in c[1] for c in rec.calls)


def test_watchful_rule_type_snooze_suppresses_emit_but_state_transitions(
    db, config, fake_client
):
    """Per the design doc: per-rule_type snooze on watchful_recurrence
    suppresses the escalation alert/notification, but watchful
    detection itself continues. State transitions (sighting_count
    increment, escalated_at set) still happen so the /watchful UI
    reflects the climbing count and a Phase 2 'unsnooze rule_type'
    would surface what was suppressed."""
    _insert_watchful_for_poller(
        db, last_seen_at=1_700_000_000, sighting_count=3,
    )
    db.add_rule_type_snooze(
        "watchful_recurrence",
        expires_at=1_700_999_999,
        added_at=1_700_000_000,
    )
    rec = RecordingNotifier()
    poll_once(fake_client, db, config, 1_700_086_400, notifier=rec)

    row = _watchful_row(db)
    # State transition happened
    assert row["sighting_count"] == 4
    assert row["escalated_at"] is not None
    # But the alert was NOT written and the notifier did NOT fire
    escalation_alerts = db._conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE rule_type = ?",
        ("watchful_recurrence",),
    ).fetchone()[0]
    assert escalation_alerts == 0
    assert not any("watchful escalation" in c[1] for c in rec.calls)


def test_watchful_active_snooze_suppresses_original_alert_pipeline(
    db, config, fake_client
):
    """OQ-3 (b): while snooze_expires_at > now_ts, the watchful gate
    `continue`s past rule eval for this MAC -- the ORIGINAL alert
    pipeline (underlying watchlist rules) is suppressed. Sightings
    persist; the escalation alert remains an independent surface
    that fires if threshold cross occurs."""
    _insert_watchful_for_poller(
        db,
        last_seen_at=1_700_000_000,
        sighting_count=1,
        snooze_expires_at=1_700_999_999,  # snooze still active
    )
    rs = Ruleset(
        rules=[
            Rule(
                name="apple_mac",
                rule_type="watchlist_mac",
                severity="high",
                patterns=[WATCHFUL_TEST_MAC],
            )
        ]
    )
    poll_once(fake_client, db, config, 1_700_086_400, ruleset=rs)
    # Under active watchful snooze, the original watchlist alert
    # MUST NOT fire.
    original_alerts = db._conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE rule_type = ?",
        ("watchlist_mac",),
    ).fetchone()[0]
    assert original_alerts == 0


def test_watchful_expired_snooze_allows_original_alert_to_fire(
    db, config, fake_client
):
    """OQ-3 (b): snooze_expires_at <= now_ts means the snooze gate no
    longer suppresses original alerts. The underlying watchlist rule
    fires normally. This pairs with the active-snooze test above to
    pin the snooze-expiry behavioral inflection."""
    _insert_watchful_for_poller(
        db,
        last_seen_at=1_700_000_000,
        sighting_count=1,
        snooze_expires_at=1_700_000_500,  # already expired
    )
    rs = Ruleset(
        rules=[
            Rule(
                name="apple_mac",
                rule_type="watchlist_mac",
                severity="high",
                patterns=[WATCHFUL_TEST_MAC],
            )
        ]
    )
    poll_once(fake_client, db, config, 1_700_086_400, ruleset=rs)
    original_alerts = db._conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE rule_type = ?",
        ("watchlist_mac",),
    ).fetchone()[0]
    assert original_alerts == 1


def test_watchful_housekeeping_archives_90d_quiet_entries(
    db, config, fake_client, caplog
):
    """Auto-archive runs on every poll cycle; entries with
    last_seen_at >= 90d stale transition to archived and log an INFO
    line. The log line gates on count > 0 to avoid spamming journalctl
    on cycles with no archives."""
    _insert_watchful_for_poller(
        db,
        mac="aa:bb:cc:00:00:99",  # not in fixture; archive runs regardless
        last_seen_at=1_700_000_000,
    )
    with caplog.at_level(logging.INFO, logger="lynceus.poller"):
        poll_once(fake_client, db, config, 1_700_000_000 + 86400 * 90)
    row = db._conn.execute(
        "SELECT archived_at FROM watchful_recurrence WHERE mac = ?",
        ("aa:bb:cc:00:00:99",),
    ).fetchone()
    assert row["archived_at"] is not None
    assert "archived 1 entries (90d quiet-stretch reached)" in caplog.text


def test_watchful_housekeeping_does_not_archive_on_snooze_expiry(
    db, config, fake_client
):
    """OQ-3 resolution guard: an entry whose snooze_expires_at is
    long-expired but whose last_seen_at is recent MUST NOT be
    auto-archived. The 90d quiet-stretch since last_seen_at is the
    sole lifecycle clock; snooze_expires_at has no housekeeping
    effect."""
    _insert_watchful_for_poller(
        db,
        mac="aa:bb:cc:00:00:88",
        last_seen_at=1_700_000_000,           # recent
        snooze_expires_at=1_500_000_000,      # expired ages ago
    )
    poll_once(fake_client, db, config, 1_700_001_000)
    row = db._conn.execute(
        "SELECT archived_at FROM watchful_recurrence WHERE mac = ?",
        ("aa:bb:cc:00:00:88",),
    ).fetchone()
    assert row["archived_at"] is None


def test_watchful_housekeeping_quiet_cycle_no_log(
    db, config, fake_client, caplog
):
    """A poll cycle with no archive candidates MUST NOT emit the
    archive INFO line. Avoids journalctl spam on the steady-state
    case (most cycles have nothing to archive)."""
    with caplog.at_level(logging.INFO, logger="lynceus.poller"):
        poll_once(fake_client, db, config, 1_700_001_000)
    assert "archived" not in caplog.text or "90d" not in caplog.text
