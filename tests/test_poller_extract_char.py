"""Characterization tests for the poll_once -> process_observation extract.

LOCAL ONLY -- tests/ is gitignored; this file is never committed. It guards the
behavior-preserving move of poll_once's per-observation core, with emphasis on
the persist-point count-retention semantics: processed/admitted are threaded by
reference (single-element lists) so the increment taken at the persist point is
RETAINED even when the alert pipeline raises past the caller's per-obs except.
"""

import logging
from pathlib import Path

import pytest

from lynceus.allowlist import Allowlist, AllowlistEntry
from lynceus.config import Config
from lynceus.db import Database
from lynceus.kismet import DeviceObservation
from lynceus.notify import RecordingNotifier
from lynceus.rules import Rule, Ruleset
import lynceus.poller as poller_mod
from lynceus.poller import poll_once

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "kismet_devices.json"


def _obs(mac, *, is_randomized=False, seen_by_sources=(), raw_record=None):
    return DeviceObservation(
        mac=mac,
        device_type="wifi",
        first_seen=1700000000,
        last_seen=1700001000,
        rssi=-50,
        ssid=None,
        oui_vendor="TestVendor",
        is_randomized=is_randomized,
        seen_by_sources=tuple(seen_by_sources),
        raw_record=raw_record,
    )


def _boom(*args, **kwargs):
    raise RuntimeError("post-persist boom")


class _ListClient:
    """Minimal KismetClient stand-in that yields a fixed observation list."""

    def __init__(self, observations):
        self._observations = list(observations)

    def get_devices_since(self, since_ts, **kwargs):
        return list(self._observations)


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


def _new_dev_ruleset():
    return Ruleset(rules=[Rule(name="newdev", rule_type="new_non_randomized_device", severity="low")])


# --- THE acceptance test: count retained across a post-persist raise ----------


def test_post_persist_raise_retains_count_and_continues(db, config, monkeypatch, caplog):
    """capture_evidence runs AFTER the persist-point increment and is NOT locally
    wrapped, so forcing it to raise reproduces the exact scenario the in-place
    accumulator exists for: the count must survive the raise and the loop must
    continue to the next observation."""
    o1 = _obs("aa:bb:cc:dd:ee:01", raw_record={"kismet": "record"})  # capture entered -> raises
    o2 = _obs("aa:bb:cc:dd:ee:02", raw_record=None)                  # capture skipped -> clean
    monkeypatch.setattr(poller_mod, "capture_evidence", _boom)
    caplog.set_level(logging.WARNING)

    result = poll_once(
        _ListClient([o1, o2]), db, config, 1700002000,
        ruleset=_new_dev_ruleset(), notifier=RecordingNotifier(),
    )

    # Would be 1 if o1's persist-point increment were lost on the raise.
    assert result == 2
    assert db._conn.execute("SELECT COUNT(*) FROM sightings").fetchone()[0] == 2
    assert any(
        "Failed to persist observation" in r.getMessage()
        and "aa:bb:cc:dd:ee:01" in r.getMessage()
        for r in caplog.records
    )


def test_post_persist_raise_single_obs_count_retained(db, config, monkeypatch):
    o1 = _obs("aa:bb:cc:dd:ee:01", raw_record={"kismet": "record"})
    monkeypatch.setattr(poller_mod, "capture_evidence", _boom)

    result = poll_once(
        _ListClient([o1]), db, config, 1700002000,
        ruleset=_new_dev_ruleset(), notifier=RecordingNotifier(),
    )

    assert result == 1
    assert db._conn.execute("SELECT COUNT(*) FROM sightings").fetchone()[0] == 1


# --- accumulator threading: ensured_locations dedup + count aggregation --------


def test_ensured_locations_dedup_and_count_aggregate(db, config, monkeypatch):
    calls = []
    real_ensure = db.ensure_location

    def spy(loc_id, label):
        calls.append(loc_id)
        return real_ensure(loc_id, label)

    monkeypatch.setattr(db, "ensure_location", spy)

    observations = [
        _obs("aa:bb:cc:dd:ee:01", seen_by_sources=("srcA",)),
        _obs("aa:bb:cc:dd:ee:02", seen_by_sources=("srcB",)),
        _obs("aa:bb:cc:dd:ee:03", seen_by_sources=("srcA",)),
    ]
    source_locations = {"srcA": "loc2", "srcB": "loc2"}

    result = poll_once(
        _ListClient(observations), db, config, 1700002000,
        source_locations=source_locations,
    )

    assert result == 3                       # all three persisted/counted
    assert calls[0] == "testloc"             # default location ensured at tick start
    assert calls.count("loc2") == 1          # remapped location ensured ONCE across the batch


# --- control-flow paths preserved (outer returns / inner continues) -----------


def test_allowlisted_suppresses_alert_but_counts(db, config):
    """Outer return path (allowlist-suppress): the allowlisted obs is still
    persisted/counted before the early return, and the loop continues."""
    o1 = _obs("aa:bb:cc:dd:ee:01")  # allowlisted -> suppressed
    o2 = _obs("aa:bb:cc:dd:ee:02")  # not allowlisted -> alert fires
    allow = Allowlist(entries=[AllowlistEntry(pattern="aa:bb:cc:dd:ee:01", pattern_type="mac")])

    result = poll_once(
        _ListClient([o1, o2]), db, config, 1700002000,
        ruleset=_new_dev_ruleset(), allowlist=allow, notifier=RecordingNotifier(),
    )

    assert result == 2  # allowlisted obs still admitted
    macs = [r[0] for r in db._conn.execute("SELECT mac FROM alerts").fetchall()]
    assert "aa:bb:cc:dd:ee:01" not in macs
    assert "aa:bb:cc:dd:ee:02" in macs


def test_new_device_fires_known_device_persists(db, config):
    """is_new is computed inside process_observation; new -> rule fires,
    known (second tick) -> rule does not fire but obs is still counted."""
    mac = "aa:bb:cc:dd:ee:01"
    rs = _new_dev_ruleset()
    notifier = RecordingNotifier()

    r1 = poll_once(_ListClient([_obs(mac)]), db, config, 1700002000, ruleset=rs, notifier=notifier)
    assert r1 == 1
    assert db._conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1

    r2 = poll_once(_ListClient([_obs(mac)]), db, config, 1700003000, ruleset=rs, notifier=notifier)
    assert r2 == 1
    assert db._conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1  # no new alert


def test_rule_type_snooze_suppresses_emit_but_counts(db, config):
    """Inner continue (rule_type snooze): emit suppressed, suppression counter
    accumulates, observation still persisted/counted."""
    db.add_rule_type_snooze(
        rule_type="new_non_randomized_device",
        expires_at=1700002000 + 3600,
        added_at=1700002000,
    )
    counter: dict[str, int] = {}

    result = poll_once(
        _ListClient([_obs("aa:bb:cc:dd:ee:01")]), db, config, 1700002000,
        ruleset=_new_dev_ruleset(), notifier=RecordingNotifier(),
        rule_type_suppression_counter=counter,
    )

    assert result == 1
    assert db._conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0
    assert counter.get("new_non_randomized_device") == 1


def test_dedup_suppresses_second_emit_but_counts(db, config):
    """Inner continue (dedup): a watchlist_mac rule fires on both ticks for the
    same mac; the second emit is deduped within the window, both obs counted."""
    mac = "aa:bb:cc:dd:ee:01"
    rs = Ruleset(rules=[Rule(name="wm", rule_type="watchlist_mac", severity="high", patterns=[mac])])
    notifier = RecordingNotifier()

    r1 = poll_once(_ListClient([_obs(mac)]), db, config, 1700002000, ruleset=rs, notifier=notifier)
    r2 = poll_once(_ListClient([_obs(mac)]), db, config, 1700002500, ruleset=rs, notifier=notifier)

    assert r1 == 1 and r2 == 1
    # default alert_dedup_window_seconds=3600; 500s apart -> second deduped.
    assert db._conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1
