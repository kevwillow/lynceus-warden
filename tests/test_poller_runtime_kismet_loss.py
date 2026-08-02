"""Runtime Kismet-loss paired alert (0.9.1 arc).

The daemon detected Kismet being down via the startup health check but,
once running, never NOTIFIED the operator when Kismet disappeared mid-run
(field finding: 189 crash-loops, discovered by forensics). These tests pin
the RUNTIME-only paired/de-duped alert:

  - One "down" infra alert on SUSTAINED loss (RUNTIME_KISMET_LOSS_THRESHOLD
    consecutive failed ticks, confirmed by health_check()), never repeated.
  - One paired "recovered" alert on the next good tick, ONLY if a "down"
    fired.
  - A single transient failed poll (below threshold) never alerts.
  - A poll tick that failed for a NON-Kismet reason (health_check reports
    reachable) never alerts.
  - The STARTUP health-check failure path NEVER fires the alert. This is the
    central 189-spam regression guard: re-introducing startup-time alerting
    is the bug this whole feature is gated against.

Tests are gitignored (OPSEC) — run locally, never committed.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from lynceus.config import Config
from lynceus.notify import RecordingNotifier
from lynceus.poller import RUNTIME_KISMET_LOSS_THRESHOLD, Poller

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "kismet_devices.json"

DOWN_TITLE = "Lynceus: Kismet unreachable"
RECOVERED_TITLE = "Lynceus: Kismet reachable again"


@pytest.fixture
def config(tmp_path):
    return Config(
        kismet_fixture_path=str(FIXTURE_PATH),
        db_path=str(tmp_path / "lynceus.db"),
        location_id="testloc",
        location_label="Test Location",
    )


def _loss_poller(config, *, reachable: bool):
    """Build a Poller whose startup health check passes (FakeKismetClient),
    then swap in a RecordingNotifier and a client stub whose health_check()
    reports the desired reachability for the runtime-loss confirmation."""
    poller = Poller(config)
    rec = RecordingNotifier()
    poller.notifier = rec
    poller.client = SimpleNamespace(
        health_check=lambda: {
            "reachable": reachable,
            "version": None,
            "error": None if reachable else "connection refused: nobody home",
            "status_code": None,
        }
    )
    return poller, rec


def _downs(rec):
    return [c for c in rec.calls if c[1] == DOWN_TITLE]


def _recovereds(rec):
    return [c for c in rec.calls if c[1] == RECOVERED_TITLE]


def test_runtime_loss_fires_exactly_one_down(config):
    poller, rec = _loss_poller(config, reachable=False)
    for _ in range(RUNTIME_KISMET_LOSS_THRESHOLD):
        poller._note_kismet_poll_result(poll_failed=True)
    downs = _downs(rec)
    assert len(downs) == 1
    severity, title, message = downs[0]
    # Infra-tier mechanism (I4): high tone, distinct title, priority_override=4
    # so it stays out of the priority-5 reserved for opted-in watchlist hits.
    assert severity == "high"
    assert title == DOWN_TITLE
    assert poller.config.kismet_url in message
    assert "RF capture stopped" in message
    assert rec.priority_overrides[rec.calls.index(downs[0])] == 4


def test_persistent_loss_does_not_repeat_down(config):
    poller, rec = _loss_poller(config, reachable=False)
    # Many more failed ticks than the threshold — still exactly one "down".
    for _ in range(RUNTIME_KISMET_LOSS_THRESHOLD + 10):
        poller._note_kismet_poll_result(poll_failed=True)
    assert len(_downs(rec)) == 1


def test_recovery_after_down_fires_exactly_one_recovered(config):
    poller, rec = _loss_poller(config, reachable=False)
    for _ in range(RUNTIME_KISMET_LOSS_THRESHOLD):
        poller._note_kismet_poll_result(poll_failed=True)
    assert len(_downs(rec)) == 1
    # First good tick after a down -> exactly one paired "recovered".
    poller._note_kismet_poll_result(poll_failed=False)
    recovereds = _recovereds(rec)
    assert len(recovereds) == 1
    severity, title, _message = recovereds[0]
    assert severity == "high"
    assert title == RECOVERED_TITLE
    assert rec.priority_overrides[rec.calls.index(recovereds[0])] == 4
    # Further good ticks must NOT keep firing "recovered".
    poller._note_kismet_poll_result(poll_failed=False)
    poller._note_kismet_poll_result(poll_failed=False)
    assert len(_recovereds(rec)) == 1


def test_recovery_without_prior_down_fires_nothing(config):
    poller, rec = _loss_poller(config, reachable=True)
    # Healthy ticks with no preceding down episode -> no alerts at all.
    for _ in range(5):
        poller._note_kismet_poll_result(poll_failed=False)
    assert rec.calls == []


def test_single_transient_failure_below_threshold_does_not_alert(config):
    poller, rec = _loss_poller(config, reachable=False)
    # One short of the threshold: no alert.
    for _ in range(RUNTIME_KISMET_LOSS_THRESHOLD - 1):
        poller._note_kismet_poll_result(poll_failed=True)
    assert rec.calls == []
    # A success resets the streak, so it takes a FULL fresh threshold again.
    poller._note_kismet_poll_result(poll_failed=False)
    assert rec.calls == []
    for _ in range(RUNTIME_KISMET_LOSS_THRESHOLD - 1):
        poller._note_kismet_poll_result(poll_failed=True)
    assert rec.calls == []


def test_threshold_reached_but_kismet_reachable_does_not_alert(config):
    # poll_once can raise for reasons that are NOT Kismet being unreachable
    # (DB write error, malformed-device ValidationError). health_check()
    # reports reachable, so no false "Kismet down" page must fire.
    poller, rec = _loss_poller(config, reachable=True)
    for _ in range(RUNTIME_KISMET_LOSS_THRESHOLD + 3):
        poller._note_kismet_poll_result(poll_failed=True)
    assert _downs(rec) == []


def test_startup_health_check_failure_does_not_fire_alert(config, monkeypatch):
    """189-spam regression guard: the STARTUP health-check failure path must
    NEVER emit a Kismet-loss alert, even with a live notifier present and
    Kismet reporting unreachable. Alerting only belongs on the runtime loop."""
    poller = Poller(config)  # startup passes (FakeKismetClient reachable)
    rec = RecordingNotifier()
    poller.notifier = rec
    # Force the startup probe to report unreachable so _startup_health_check
    # exhausts its retries and raises — the crash-loop trigger.
    poller.client = SimpleNamespace(
        health_check=lambda: {
            "reachable": False,
            "version": None,
            "error": "connection refused",
            "status_code": None,
        }
    )
    # Don't actually sleep through the backoff schedule.
    monkeypatch.setattr("lynceus.poller.HEALTH_CHECK_RETRY_BACKOFF", [0.0, 0.0, 0.0])
    with pytest.raises(RuntimeError):
        poller._startup_health_check()
    assert rec.calls == []  # the startup path fired nothing


def test_run_forever_runtime_loss_fires_one_down_through_real_loop(config, monkeypatch):
    """End-to-end: the alert is actually wired into run_forever and uses the
    real consecutive-failure threshold (not just the unit-level helper)."""
    import requests as _requests

    poller = Poller(config)
    rec = RecordingNotifier()
    poller.notifier = rec
    poller.client = SimpleNamespace(
        health_check=lambda: {
            "reachable": False,
            "version": None,
            "error": "connection refused",
            "status_code": None,
        }
    )
    calls: list[int] = []

    def fake_poll(client, db, cfg, now_ts, **kwargs):
        calls.append(now_ts)
        if len(calls) <= RUNTIME_KISMET_LOSS_THRESHOLD:
            raise _requests.ConnectionError("kismet down")
        raise KeyboardInterrupt()  # break the loop cleanly after the down fires

    monkeypatch.setattr("lynceus.poller.poll_once", fake_poll)
    monkeypatch.setattr(poller, "_interruptible_sleep", lambda s: None)

    with pytest.raises(KeyboardInterrupt):
        poller.run_forever()
    assert len(_downs(rec)) == 1


def test_run_forever_recovery_pair_through_real_loop(config, monkeypatch):
    """End-to-end: sustained loss then recovery yields exactly one down and
    one recovered through the real loop."""
    import requests as _requests

    poller = Poller(config)
    rec = RecordingNotifier()
    poller.notifier = rec
    poller.client = SimpleNamespace(
        health_check=lambda: {
            "reachable": False,
            "version": None,
            "error": "connection refused",
            "status_code": None,
        }
    )
    calls: list[int] = []

    def fake_poll(client, db, cfg, now_ts, **kwargs):
        calls.append(now_ts)
        if len(calls) <= RUNTIME_KISMET_LOSS_THRESHOLD:
            raise _requests.ConnectionError("kismet down")
        if len(calls) == RUNTIME_KISMET_LOSS_THRESHOLD + 1:
            return 0  # Kismet back -> successful poll -> recovery edge
        raise KeyboardInterrupt()

    monkeypatch.setattr("lynceus.poller.poll_once", fake_poll)
    monkeypatch.setattr(poller, "_interruptible_sleep", lambda s: None)

    with pytest.raises(KeyboardInterrupt):
        poller.run_forever()
    assert len(_downs(rec)) == 1
    assert len(_recovereds(rec)) == 1
