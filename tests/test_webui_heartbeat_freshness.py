"""The dead-man's switch needs a liveness check of its own.

`/settings` says, in its own words, that the heartbeat is what distinguishes
*"nothing is out there"* from *"the daemon died"*. It then answered **"delivered
at least once, ever"**. Measured before this change
(`internal/session2-harnesses/heartbeat_surface_probe.py`), heartbeat enabled on
a 24-hour interval:

    CONTROL delivered 0d ago,   clock correct       [on]  last delivered just now
            delivered 400d ago, clock correct       [on]  last delivered 400d ago
            delivered 400d ago, clock behind 500d   [on]  last delivered 2025-07-14 UTC

Every row green, for a switch 400 intervals overdue.

⛔ **`undelivered` does not cover this, and that is the whole point.** It counts
heartbeats *composed but not delivered*; a daemon that has stopped composes
nothing, so the counter reads 0 and the card falls through to the healthy
branch. **The failure that matters most leaves every counter at zero.**

Nothing else covered it either: `/healthz.json` has six checks (db, poller,
watchlist, clock, ruleset, alerts) and none is the heartbeat.
"""

from __future__ import annotations

import re
import time
from pathlib import Path

from starlette.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import (
    FUTURE_SKEW_SECONDS,
    clock_stamped_freshness,
    create_app,
    heartbeat_liveness,
    poll_tick_liveness,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
HOUR = 3600
DAY = 86_400


def test_this_suite_is_testing_the_tree_it_lives_in():
    import lynceus.webui.app as under_test

    assert Path(under_test.__file__).resolve().is_relative_to(REPO_ROOT)


def _prose(html: str) -> str:
    """Visible text: comments and tags dropped, entities decoded."""
    import html as H

    t = re.sub(r"<!--.*?-->", " ", html, flags=re.S)
    t = re.sub(r"<[^>]+>", " ", t)
    return H.unescape(" ".join(t.split()))


def _app(tmp_path, *, interval_hours: int = 24):
    allowlist = tmp_path / "allow.yaml"
    allowlist.write_text("entries: []\n", encoding="utf-8")
    cfg = Config(
        db_path=str(tmp_path / "s.db"),
        rules_path=str(REPO_ROOT / "config/rules.yaml"),
        allowlist_path=str(allowlist),
        kismet_health_check_on_startup=False,
        heartbeat_enabled=True,
        heartbeat_interval_hours=interval_hours,
        ntfy_url="https://ntfy.sh",
        ntfy_topic="t",
    )
    db = Database(cfg.db_path)
    db.ensure_location("default", "Default")
    return cfg, db


def _delivered(db, *, days_ago: int, now: int) -> None:
    """A heartbeat that WAS delivered, and none since — the dead daemon."""
    hid = db.insert_heartbeat(ts=now - days_ago * DAY, healthy=True, message="alive")
    db.mark_heartbeat_notified(hid, now_ts=now - days_ago * DAY)


def _card(html: str) -> str:
    found = re.search(r"heartbeat\s+(\S+)\s+(.{0,200})", _prose(html))
    return f"{found.group(1)} {found.group(2)}" if found else ""


# --------------------------------------------------------------------------
# 1. The shared predicate, and the fact that it IS shared.
# --------------------------------------------------------------------------

NOW = 1_770_000_000


def test_clock_stamped_freshness_has_three_states():
    assert clock_stamped_freshness(None, now_ts=NOW, stale_after_seconds=100) == {
        "staleness_known": True,
        "is_stale": False,
        "ahead_by_seconds": 0,
    }
    fresh = clock_stamped_freshness(NOW - 10, now_ts=NOW, stale_after_seconds=100)
    assert fresh["staleness_known"] is True and fresh["is_stale"] is False
    stale = clock_stamped_freshness(NOW - 101, now_ts=NOW, stale_after_seconds=100)
    assert stale["staleness_known"] is True and stale["is_stale"] is True

    ahead = clock_stamped_freshness(
        NOW + FUTURE_SKEW_SECONDS + 1, now_ts=NOW, stale_after_seconds=100
    )
    assert ahead["staleness_known"] is False
    assert ahead["is_stale"] is None, (
        "None means unknown; False would be the clean bill this change removes"
    )
    assert ahead["ahead_by_seconds"] > FUTURE_SKEW_SECONDS


def test_a_stamp_inside_the_skew_band_is_still_decided():
    """⭐ The control. A helper answering "cannot tell" to everything would
    satisfy every undecidability assertion in this file."""
    state = clock_stamped_freshness(
        NOW + FUTURE_SKEW_SECONDS - 1, now_ts=NOW, stale_after_seconds=100
    )
    assert state["staleness_known"] is True
    assert state["is_stale"] is False


def test_the_heartbeat_uses_ITS_OWN_interval_not_the_pollers(tmp_path):
    """⛔ The two surfaces share a predicate, not a threshold. A heartbeat is
    hours; a poll tick is seconds. Wiring the heartbeat to `poll_interval_
    seconds` would report a perfectly healthy switch as stopped within minutes.
    """
    cfg, db = _app(tmp_path, interval_hours=24)
    try:
        now = int(time.time())
        # Well past two POLL intervals (2 minutes) and well inside two
        # HEARTBEAT intervals (48 hours).
        state = heartbeat_liveness(now - 6 * HOUR, cfg, now_ts=now)
        assert state["is_stale"] is False, (
            "6h into a 24h interval is healthy; this is reading the wrong knob"
        )
        assert heartbeat_liveness(now - 49 * HOUR, cfg, now_ts=now)["is_stale"] is True
        # And the poll tick still reads its own.
        tick = {"completed_at": now - 6 * HOUR}
        assert poll_tick_liveness(tick, cfg, now_ts=now)["is_stale"] is True
    finally:
        db.close()


def test_one_staleness_threshold_per_surface_and_no_duplicates():
    """⛔ `/healthz` (HTML) once carried its own copy of the poll-tick
    arithmetic, `_check_poller` a second and the home page an implicit third —
    which is how two surfaces came to disagree about whether the daemon was
    alive. The heartbeat card then turned out to have NO copy, the same bug from
    the other end. Each threshold belongs in exactly one place.
    """
    source = (REPO_ROOT / "src/lynceus/webui/app.py").read_text(encoding="utf-8")
    poll = [
        line.strip()
        for line in source.splitlines()
        if "poll_interval_seconds" in line and "* 2" in line
    ]
    beat = [
        line.strip()
        for line in source.splitlines()
        if "heartbeat_interval_hours" in line and "* 2" in line
    ]
    assert len(poll) == 1, f"poll-tick threshold appears {len(poll)}x: {poll}"
    assert len(beat) == 1, f"heartbeat threshold appears {len(beat)}x: {beat}"


# --------------------------------------------------------------------------
# 2. What the operator is actually told.
# --------------------------------------------------------------------------


def test_a_heartbeat_that_has_stopped_is_not_reported_as_on(tmp_path):
    cfg, db = _app(tmp_path)
    now = int(time.time())
    _delivered(db, days_ago=400, now=now)
    try:
        with TestClient(create_app(cfg, db)) as client:
            card = _card(client.get("/settings").text)
    finally:
        db.close()

    assert "stopped" in card, f"a switch 400 intervals overdue still reads: {card!r}"
    assert not re.match(r"^on\b", card), "the green badge survived"
    assert "400d ago" in card, "the operator is not told how long it has been"
    assert "check the daemon is running" in card.lower(), (
        "a state with no next step is one the operator learns to scroll past"
    )


def test_a_heartbeat_arriving_normally_is_still_reported_as_on(tmp_path):
    """⭐ The control, and the half that stops the test above passing trivially:
    a card that said "stopped" unconditionally would satisfy it perfectly."""
    cfg, db = _app(tmp_path)
    now = int(time.time())
    _delivered(db, days_ago=0, now=now)
    try:
        with TestClient(create_app(cfg, db)) as client:
            card = _card(client.get("/settings").text)
    finally:
        db.close()

    assert re.match(r"^on\b", card), f"a live heartbeat is not reported healthy: {card!r}"
    assert "stopped" not in card
    assert "clock disagrees" not in card


def test_a_heartbeat_just_inside_two_intervals_is_still_on(tmp_path):
    """The boundary from the healthy side. One missed beat is a transient
    delivery failure — which `undelivered` reports separately — not a stopped
    switch."""
    cfg, db = _app(tmp_path, interval_hours=24)
    now = int(time.time())
    hid = db.insert_heartbeat(ts=now - 40 * HOUR, healthy=True, message="alive")
    db.mark_heartbeat_notified(hid, now_ts=now - 40 * HOUR)
    try:
        with TestClient(create_app(cfg, db)) as client:
            card = _card(client.get("/settings").text)
    finally:
        db.close()

    assert re.match(r"^on\b", card), f"40h into a 48h tolerance is not stopped: {card!r}"


def test_a_delivery_ahead_of_the_clock_is_undecidable_not_healthy(tmp_path):
    """⚠️ Driven by moving the PROCESS clock, not the row: `app.py` calls
    `time.time()` through the module, so the card and the renderer see the same
    wrong "now" they would on the box."""
    cfg, db = _app(tmp_path)
    now = int(time.time())
    _delivered(db, days_ago=400, now=now)
    real_time = time.time
    try:
        with TestClient(create_app(cfg, db)) as client:
            time.time = lambda: float(now - 500 * DAY)
            card = _card(client.get("/settings").text)
    finally:
        time.time = real_time
        db.close()

    assert "clock disagrees" in card, f"card reads: {card!r}"
    assert "stopped" not in card, (
        "staleness is not established when the stamp is ahead; asserting it "
        "sends the operator to restart a daemon that may be fine"
    )
    assert not re.match(r"^on\b", card)
    assert "timedatectl" in card, "the operator is not told how to fix it"


def test_the_undelivered_state_still_wins_over_staleness(tmp_path):
    """⚠️ Ordering. A composed-but-undelivered heartbeat is a channel failure
    with a different fix (topic/auth) from a stopped daemon, and it is the more
    specific diagnosis — so it must keep precedence."""
    cfg, db = _app(tmp_path)
    now = int(time.time())
    _delivered(db, days_ago=400, now=now)
    db.insert_heartbeat(ts=now, healthy=True, message="never delivered")
    try:
        with TestClient(create_app(cfg, db)) as client:
            card = _card(client.get("/settings").text)
    finally:
        db.close()

    assert "never delivered" in card, f"the channel failure was masked: {card!r}"
    assert "stopped" not in card


def test_a_heartbeat_that_has_NEVER_fired_is_not_reported_as_healthy(tmp_path):
    """⛔ The sibling of the "stopped" state, and the first version of this
    change left it green.

    "armed" with an ok badge is right on a fresh install and wrong on one where
    the heartbeat was enabled months ago and has never once fired — and those
    two are INDISTINGUISHABLE from stored state, because the config records
    that the heartbeat is on and never when it was turned on. Measured with the
    daemon polling normally and zero heartbeat rows: `[armed]`, green, forever.

    ⇒ The page states the condition the OPERATOR can check rather than choosing
    the reassuring reading on their behalf.
    """
    cfg, db = _app(tmp_path, interval_hours=24)
    now = int(time.time())
    # The daemon is alive and polling — this is not a dead-daemon case.
    db.set_state("last_tick_completed_at", str(now))
    db.set_state("last_tick_admitted", "1")
    for key in (
        "last_tick_dropped_source_allowlist",
        "last_tick_dropped_min_rssi",
        "last_tick_dropped_unparseable",
    ):
        db.set_state(key, "0")
    try:
        with TestClient(create_app(cfg, db)) as client:
            card = _card(client.get("/settings").text)
    finally:
        db.close()

    assert "unproven" in card, f"a switch that never fired reads: {card!r}"
    assert "badge-status-warn" not in card, "sanity: _card strips tags"
    assert "If you enabled this more than 24h ago" in card, (
        "the operator is not given the one test they can actually run — the "
        "page cannot know when the switch was enabled, but they do"
    )
    assert "stopped" not in card, (
        "nothing has stopped; nothing ever started. Different diagnosis, "
        "different fix."
    )


def test_the_never_fired_state_yields_once_a_heartbeat_arrives(tmp_path):
    """⭐ The control for the test above. A card stuck on "unproven" would
    satisfy it forever."""
    cfg, db = _app(tmp_path, interval_hours=24)
    now = int(time.time())
    _delivered(db, days_ago=0, now=now)
    try:
        with TestClient(create_app(cfg, db)) as client:
            card = _card(client.get("/settings").text)
    finally:
        db.close()

    assert "unproven" not in card
    assert re.match(r"^on\b", card), f"a delivered heartbeat is not healthy: {card!r}"


def test_a_delivery_stamped_at_epoch_zero_is_not_reported_as_never_delivered(tmp_path):
    """⛔ A FALSY-but-present timestamp, and the template threw away a correct
    verdict because of it.

    `{% elif heartbeat.last_delivered_at and heartbeat.is_stale %}` short-circuits
    on `0`, so a heartbeat delivered at epoch 0 fell through to "none has arrived
    yet" — about a heartbeat that HAD been delivered, and in the milder tier. The
    predicate had it right (`is_stale: True`); only the guard was wrong.

    ⚠️ Not hypothetical on this project's hardware: an RTC-less Pi boots to a
    bogus clock and the daemon can deliver before NTP corrects it.

    Same class as `{% if is_stale %}` sending a `None` down the green branch —
    truthiness applied to a value whose falsy member is meaningful.
    """
    cfg, db = _app(tmp_path)
    hid = db.insert_heartbeat(ts=0, healthy=True, message="alive")
    db.mark_heartbeat_notified(hid, now_ts=0)
    try:
        stamp = db.latest_delivered_heartbeat_ts()
        verdict = heartbeat_liveness(stamp, cfg, now_ts=int(time.time()))
        with TestClient(create_app(cfg, db)) as client:
            card = _card(client.get("/settings").text)
    finally:
        db.close()

    assert stamp == 0 and not stamp, "premise: the stamp is present AND falsy"
    assert verdict["is_stale"] is True, "premise: the model already had it right"

    assert "stopped" in card, f"the correct verdict was discarded by the guard: {card!r}"
    assert "none has arrived yet" not in card, (
        "a heartbeat that WAS delivered is reported as never delivered"
    )
    assert "unproven" not in card
