"""The dead-man's switch: does silence stay falsifiable?

Every *other* failure mode in this tool now alerts. What was left is the daemon
dying or delivery breaking, where the operator's only symptom is silence --
indistinguishable from "nothing is out there". The heartbeat exists to remove
that ambiguity.

⛔ The invariant these tests exist for, and the reason a subtly wrong heartbeat
is worse than none: **it must never claim health it has not verified.** A
cheerful "still watching" sent while ingest is dead converts an operator's
vague unease into false confidence, on the exact channel they rely on to be
warned that surveillance equipment is near them. `test_never_claims_health_*`
is the load-bearing case here; if it is ever weakened, the feature is a
liability rather than a safeguard.

The delivery half mirrors `test_notify_delivery.py` because the heartbeat rides
migration 024's delivery-tracked path deliberately. Building it fire-and-forget
would inherit the defect PR #19 fixed, and here it would be worse: a *missing*
heartbeat reads as "the daemon is dead", so a silently-dropped one sends an
operator to check hardware when the real fault was one transient ntfy blip.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from lynceus.config import Config
from lynceus.db import Database
from lynceus.poller import (
    NOTIFY_MAX_ATTEMPTS,
    POLL_WATERMARK_MAX_HOLDS,
    STATE_KEY_LAST_TICK_COMPLETED_AT,
    STATE_KEY_WATERMARK_HOLDS,
    _compose_heartbeat,
    maybe_emit_heartbeat,
)

NOW = 1_700_000_000
HOUR = 3600


class RecordingNotifier:
    """A double that can FAIL -- the whole point of Wave 5 Finding 12 was that
    every notifier double in the repo returned True unconditionally, and a
    double that cannot fail cannot test a failure path."""

    def __init__(self, ok: bool = True, raises: bool = False) -> None:
        self.ok = ok
        self.raises = raises
        self.sent: list[dict] = []

    def send(self, severity, title, message, priority_override=None) -> bool:
        if self.raises:
            raise RuntimeError("notifier exploded")
        self.sent.append({"severity": severity, "title": title, "message": message})
        return self.ok


@pytest.fixture()
def db(tmp_path):
    d = Database(str(tmp_path / "hb.db"))
    d.ensure_location("default", "Default")
    yield d
    d.close()


def _healthy_state(db, *, now_ts=NOW):
    """The state a genuinely healthy daemon leaves behind."""
    db.set_state(STATE_KEY_LAST_TICK_COMPLETED_AT, str(now_ts))
    db.set_state(STATE_KEY_WATERMARK_HOLDS, "0")


def _cfg(**kw):
    return Config(db_path=":memory:", heartbeat_enabled=True, **kw)


# --- the load-bearing invariant --------------------------------------------


def test_never_claims_health_when_the_daemon_has_stopped_ticking(db):
    """Process alive, poll loop wedged. The heartbeat must say so."""
    db.set_state(STATE_KEY_LAST_TICK_COMPLETED_AT, str(NOW - 3600))
    db.set_state(STATE_KEY_WATERMARK_HOLDS, "0")
    healthy, message = _compose_heartbeat(db, _cfg(), now_ts=NOW)
    assert healthy is False
    assert "NOT FULLY WATCHING" in message
    assert "no poll tick" in message
    assert "Still watching." not in message


def test_never_claims_health_when_observations_fail_to_persist(db):
    """Silent pipeline death: ticking fine, but nothing reaches the database.

    Today the only symptom is one ERROR line in a log nobody is tailing.
    """
    _healthy_state(db)
    db.set_state(STATE_KEY_WATERMARK_HOLDS, str(POLL_WATERMARK_MAX_HOLDS))
    healthy, message = _compose_heartbeat(db, _cfg(), now_ts=NOW)
    assert healthy is False
    assert "failing to persist" in message
    assert "capture data is being lost" in message


def test_never_claims_health_when_alerts_went_undelivered(db):
    _healthy_state(db)
    db.upsert_device(mac="aa:bb:cc:dd:ee:01", device_type="wifi", oui_vendor=None,
                     is_randomized=0, now_ts=NOW - 120)
    db.add_alert(ts=NOW - 60, rule_name="r", mac="aa:bb:cc:dd:ee:01",
                 message="m", severity="high")
    healthy, message = _compose_heartbeat(db, _cfg(), now_ts=NOW)
    assert healthy is False
    assert "never delivered" in message


def test_never_claims_health_before_the_first_poll_tick(db):
    """A fresh install that has never polled is not healthy, it is unproven."""
    healthy, message = _compose_heartbeat(db, _cfg(), now_ts=NOW)
    assert healthy is False
    assert "no poll tick has ever completed" in message


def test_a_quiet_environment_is_healthy_not_broken(db):
    """🪤 Zero devices must NOT read as unhealthy.

    A quiet RF environment is the normal case for this tool. Flagging it would
    train the operator to ignore the warning that matters, which is the same
    alert-fatigue failure the severity model exists to avoid.
    """
    _healthy_state(db)
    healthy, message = _compose_heartbeat(db, _cfg(), now_ts=NOW)
    assert healthy is True
    assert "Still watching." in message
    assert "0 device sighting(s)" in message


def test_unhealthy_heartbeat_is_not_sent_at_low_priority(db):
    """A problem report must not ride the same quiet channel as an FYI."""
    db.set_state(STATE_KEY_LAST_TICK_COMPLETED_AT, str(NOW - 3600))
    n = RecordingNotifier()
    db.insert_heartbeat(ts=NOW - 25 * HOUR, healthy=True, message="old")
    db.mark_heartbeat_notified(1, now_ts=NOW - 25 * HOUR)
    maybe_emit_heartbeat(db, _cfg(), n, now_ts=NOW)
    assert len(n.sent) == 1
    assert n.sent[0]["severity"] != "low"
    assert "NOT fully watching" in n.sent[0]["title"]


# --- scheduling -------------------------------------------------------------


def test_disabled_by_default_sends_nothing(db):
    _healthy_state(db)
    n = RecordingNotifier()
    assert maybe_emit_heartbeat(db, Config(db_path=":memory:"), n, now_ts=NOW) is False
    assert n.sent == []


def test_the_first_heartbeat_fires_promptly(db):
    """⭐ The first one must NOT wait a full interval.

    It is the operator's confirmation that the switch is armed. Deferring it
    means a misconfigured ntfy topic is discovered a day later, or never --
    and 'my dead-man's switch was never working' is the worst possible thing
    to learn from its absence.
    """
    _healthy_state(db)
    n = RecordingNotifier()
    assert maybe_emit_heartbeat(db, _cfg(), n, now_ts=NOW) is True
    assert len(n.sent) == 1


def test_a_restart_loop_cannot_spam_the_topic(db):
    """The counterpart risk to firing promptly: delivery stamps notified_at,
    so the interval gate applies across restarts, not just within one process."""
    _healthy_state(db)
    n = RecordingNotifier()
    assert maybe_emit_heartbeat(db, _cfg(), n, now_ts=NOW) is True
    for i in range(1, 6):  # five "restarts" inside the interval
        assert maybe_emit_heartbeat(db, _cfg(), n, now_ts=NOW + i * 60) is False
    assert len(n.sent) == 1


def test_a_backward_clock_jump_does_not_stall_the_switch(db):
    """🪤 The dead-man's switch must fail TOWARD sending.

    With a bare `elapsed < interval` test, a wall clock that jumps backward
    suppresses every heartbeat for the whole excursion -- the switch goes
    silent, and silence is exactly what the operator reads as "the daemon is
    dead". Session 3 measured the same shape stalling retention pruning for
    366 days (`retention.py:118`, `evidence.py:324`).

    Note the direction is subsystem-specific: an untrustworthy clock means
    "do not prune" there and "do send" here.
    """
    _healthy_state(db)
    n = RecordingNotifier()
    assert maybe_emit_heartbeat(db, _cfg(), n, now_ts=NOW) is True
    # Clock yanked a year into the past. elapsed is now hugely negative.
    _healthy_state(db, now_ts=NOW - 366 * 24 * HOUR)
    assert maybe_emit_heartbeat(db, _cfg(), n, now_ts=NOW - 366 * 24 * HOUR) is True, (
        "backward clock jump silenced the dead-man's switch"
    )
    assert len(n.sent) == 2


def test_fires_once_the_interval_has_elapsed(db):
    _healthy_state(db, now_ts=NOW + 25 * HOUR)
    n = RecordingNotifier()
    db.insert_heartbeat(ts=NOW, healthy=True, message="old")
    db.mark_heartbeat_notified(1, now_ts=NOW)
    assert maybe_emit_heartbeat(db, _cfg(), n, now_ts=NOW + 25 * HOUR) is True
    assert len(n.sent) == 1


def test_does_not_fire_twice_inside_one_interval(db):
    _healthy_state(db, now_ts=NOW + 25 * HOUR)
    n = RecordingNotifier()
    db.insert_heartbeat(ts=NOW, healthy=True, message="old")
    db.mark_heartbeat_notified(1, now_ts=NOW)
    assert maybe_emit_heartbeat(db, _cfg(), n, now_ts=NOW + 25 * HOUR) is True
    assert maybe_emit_heartbeat(db, _cfg(), n, now_ts=NOW + 25 * HOUR + 60) is False
    assert len(n.sent) == 1


# --- delivery tracking (the migration-024 path) -----------------------------


def test_the_interval_clock_runs_from_delivery_not_composition(db):
    """⭐ A heartbeat nobody received has not proved anything.

    If the clock ran from composition, one failed send would buy a full
    interval of silence -- exactly the defect PR #19 fixed for alerts.
    """
    _healthy_state(db)
    failing = RecordingNotifier(ok=False)
    assert maybe_emit_heartbeat(db, _cfg(), failing, now_ts=NOW + 25 * HOUR) is False
    row = db.latest_heartbeat()
    assert row["notified_at"] is None
    assert row["notify_attempts"] == 1
    assert db.latest_delivered_heartbeat_ts() is None

    # Next tick, seconds later -- it must retry, not wait another 24h.
    working = RecordingNotifier(ok=True)
    assert maybe_emit_heartbeat(db, _cfg(), working, now_ts=NOW + 25 * HOUR + 60) is True
    assert len(working.sent) == 1
    assert db.latest_heartbeat()["notified_at"] is not None


def test_retry_reuses_the_row_rather_than_composing_a_second(db):
    _healthy_state(db)
    failing = RecordingNotifier(ok=False)
    maybe_emit_heartbeat(db, _cfg(), failing, now_ts=NOW + 25 * HOUR)
    first_id = db.latest_heartbeat()["id"]
    maybe_emit_heartbeat(db, _cfg(), failing, now_ts=NOW + 25 * HOUR + 60)
    assert db.latest_heartbeat()["id"] == first_id, "composed a duplicate instead of retrying"
    assert db.latest_heartbeat()["notify_attempts"] == 2


def test_retries_are_bounded(db):
    """Each attempt costs a blocking HTTP timeout on the poll path."""
    _healthy_state(db)
    failing = RecordingNotifier(ok=False)
    for i in range(NOTIFY_MAX_ATTEMPTS + 3):
        maybe_emit_heartbeat(db, _cfg(), failing, now_ts=NOW + 25 * HOUR + i * 60)
    assert len(failing.sent) == NOTIFY_MAX_ATTEMPTS
    assert db.latest_heartbeat()["notified_at"] is None


def test_undelivered_heartbeats_are_counted_for_settings(db):
    _healthy_state(db)
    failing = RecordingNotifier(ok=False)
    maybe_emit_heartbeat(db, _cfg(), failing, now_ts=NOW + 25 * HOUR)
    assert db.count_undelivered_heartbeats() == 1


def test_a_raising_notifier_does_not_escape(db):
    """The heartbeat reports that the pipeline is broken; it must never BE the
    thing that breaks it."""
    _healthy_state(db)
    maybe_emit_heartbeat(db, _cfg(), RecordingNotifier(raises=True), now_ts=NOW + 25 * HOUR)
    assert db.latest_heartbeat()["notify_attempts"] == 1


def test_no_notifier_configured_is_a_no_op(db):
    _healthy_state(db)
    assert maybe_emit_heartbeat(db, _cfg(), None, now_ts=NOW + 25 * HOUR) is False


# --- config -----------------------------------------------------------------


def test_interval_of_zero_is_rejected(db):
    """A 0-hour interval is a flood, not a heartbeat, and would train the
    operator to mute the topic the ALERTS also arrive on."""
    with pytest.raises(ValueError):
        Config(db_path=":memory:", heartbeat_interval_hours=0)


# --- /settings surface ------------------------------------------------------
#
# 🪤 Both of these caught a real bug while this feature was being written: the
# first draft used a `ts_to_local` filter and a `badge-status-warn` class,
# NEITHER of which existed at the time. An undefined Jinja filter and an
# undefined CSS class both fail silently -- the documented classless-Pico trap
# in this repo. A card that renders nothing looks identical to a card that is
# simply absent.
#
# ⚠️ UPDATED: `badge-status-warn` now EXISTS -- it was added with the heartbeat
# freshness states, which needed a middle tier for "nothing has been established
# here". The assertion below therefore no longer names it. Naming one forbidden
# class pinned the historical mistake rather than the invariant, and would have
# blocked any future legitimate use of that tier; what actually matters is that
# every class this card emits HAS a rule, which is now checked derivedly.


@pytest.mark.webui
def test_settings_renders_the_heartbeat_card(tmp_path):
    from fastapi.testclient import TestClient

    from lynceus.webui.app import create_app

    cfg = Config(
        db_path=str(tmp_path / "s.db"),
        ntfy_url="https://ntfy.example",
        ntfy_topic="secret-topic",
        heartbeat_enabled=True,
        heartbeat_interval_hours=12,
    )
    d = Database(cfg.db_path)
    d.ensure_location("default", "Default")
    try:
        with TestClient(create_app(cfg, d)) as client:
            body = client.get("/settings").text
        assert "heartbeat" in body
        assert "every 12h" in body, "interval not rendered — filter or key wrong"
        assert "armed" in body
        # ⭐ DERIVED, not a forbidden-name list: every badge class this card
        # actually emits must have a CSS rule. That is the invariant the old
        # `"badge-status-warn" not in body` assertion was reaching for, stated
        # so that adding a legitimate tier does not fail it.
        css = (
            Path(__file__).resolve().parents[1]
            / "src/lynceus/webui/static/lynceus.css"
        ).read_text(encoding="utf-8")
        emitted = set(re.findall(r'class="(badge-status-[a-z-]+)"', body))
        assert emitted, "the card emits no status badge at all"
        # 🪤 A BOUNDARY, not a substring. The first version tested
        # `f".{c}" not in css`, and a plant that renamed the rule to
        # `.badge-status-warnXX` sailed straight through it -- the needle is a
        # PREFIX of the string it has to distinguish. Same shape this repo has
        # recorded before; the plant is the only reason it was caught.
        undefined = sorted(
            c for c in emitted
            if not re.search(rf"\.{re.escape(c)}\s*[{{,]", css)
        )
        assert not undefined, (
            f"the card emits {undefined} with no CSS rule; an undefined class "
            f"renders unstyled and silently, which is indistinguishable from "
            f"the card being absent"
        )
    finally:
        d.close()


@pytest.mark.webui
def test_settings_warns_when_heartbeats_are_undelivered(tmp_path):
    from fastapi.testclient import TestClient

    from lynceus.webui.app import create_app

    cfg = Config(
        db_path=str(tmp_path / "s2.db"),
        ntfy_url="https://ntfy.example",
        ntfy_topic="secret-topic",
        heartbeat_enabled=True,
    )
    d = Database(cfg.db_path)
    d.ensure_location("default", "Default")
    try:
        d.insert_heartbeat(ts=NOW, healthy=True, message="never got there")
        with TestClient(create_app(cfg, d)) as client:
            body = client.get("/settings").text
        assert "is NOT" in body and "arriving" in body, (
            "an undelivered heartbeat must be visible — the operator is trusting "
            "a guarantee that is not being met"
        )
    finally:
        d.close()


# --- wiring into poll_once --------------------------------------------------
#
# ⛔ Every test above calls `maybe_emit_heartbeat` DIRECTLY. All of them would
# still pass if the call site in `poll_once` were deleted -- the exact defect
# PR #18 existed to fix for `maybe_prune_evidence`, whose own wiring had no test
# at all while the function it called was thoroughly covered. A dead-man's
# switch that is never called is worse than none, because its silence is
# indistinguishable from the failure it is supposed to report.
#
# These are a TAKE-EFFECT PAIR on purpose. A test that only proves a heartbeat
# IS sent would pass against code that ignores the setting and always sends; one
# that only proves nothing is sent would pass against code that never sends. Two
# settings, one input, opposite outcomes -- no fixed behaviour satisfies both.


def _poll_once_with(tmp_path, notifier, **config_kwargs):
    from lynceus.kismet import FakeKismetClient
    from lynceus.poller import poll_once

    fixture = tmp_path / "empty.json"
    fixture.write_text("[]", encoding="utf-8")
    cfg = Config(
        db_path=str(tmp_path / "wiring.db"),
        kismet_fixture_path=str(fixture),
        **config_kwargs,
    )
    d = Database(cfg.db_path)
    d.ensure_location("default", "Default")
    try:
        poll_once(FakeKismetClient(str(fixture)), d, cfg, NOW, notifier=notifier)
        return d, cfg
    finally:
        d.close()


def test_poll_once_actually_emits_the_heartbeat(tmp_path):
    """The call site exists and fires. Delete it and this is the only test
    in the file that notices."""
    n = RecordingNotifier()
    _poll_once_with(tmp_path, n, heartbeat_enabled=True)
    assert len(n.sent) == 1, "poll_once did not emit a heartbeat"
    assert "watching" in n.sent[0]["title"]


def test_poll_once_emits_nothing_when_the_heartbeat_is_disabled(tmp_path):
    """The other half of the pair: the setting is actually consulted."""
    n = RecordingNotifier()
    _poll_once_with(tmp_path, n, heartbeat_enabled=False)
    assert n.sent == [], "poll_once sent a heartbeat while disabled"
