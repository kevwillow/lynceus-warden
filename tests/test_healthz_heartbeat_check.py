"""`/healthz.json` reports the dead-man's switch.

⛔ **This endpoint said nothing about the heartbeat at all** — six checks, the
word appeared nowhere, and `status: "ok"` came back beside a switch 400
intervals overdue. That was *silence*, not a false claim, which is why it was
left as a decision rather than fixed as a bug.

It is added because `poller.poll_tick` and the heartbeat fail **independently**:
the daemon can be polling perfectly while ntfy is broken, and a monitoring tool
watching `poll_tick.is_stale` had no way to see the second.

⭐ The point of this suite is AGREEMENT. `/settings` and this endpoint answer the
same question, so they share `heartbeat_liveness` — and every state is driven
through **both** here, because sharing a helper is not the same as agreeing.
"""

from __future__ import annotations

import html as _html
import re
import time
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import create_app

REPO_ROOT = Path(__file__).resolve().parents[1]
DAY = 86_400
HOUR = 3600


def test_this_suite_is_testing_the_tree_it_lives_in():
    import lynceus.webui.app as under_test

    assert Path(under_test.__file__).resolve().is_relative_to(REPO_ROOT)


def _visible(html: str) -> str:
    t = re.sub(r"<!--.*?-->", " ", html, flags=re.S)
    t = re.sub(r"<[^>]+>", " ", t)
    return _html.unescape(" ".join(t.split()))


def _app(tmp_path, *, enabled=True, interval_hours=24):
    # ⚠️ mkdir here, not at each call site: callers pass `tmp_path / "<case>"`
    # to get isolated DBs within one test, and a missing parent fails as a
    # FileNotFoundError on the allowlist write — which reads like a fixture bug
    # in the product rather than in the helper.
    tmp_path.mkdir(parents=True, exist_ok=True)
    allow = tmp_path / "a.yaml"
    allow.write_text("entries: []\n", encoding="utf-8")
    cfg = Config(
        db_path=str(tmp_path / "s.db"),
        rules_path=str(REPO_ROOT / "config/rules.yaml"),
        allowlist_path=str(allow),
        kismet_health_check_on_startup=False,
        heartbeat_enabled=enabled,
        heartbeat_interval_hours=interval_hours,
        ntfy_url="https://ntfy.sh",
        ntfy_topic="t",
    )
    db = Database(cfg.db_path)
    db.ensure_location("default", "Default")
    return cfg, db


def _delivered(db, *, days_ago, now):
    hid = db.insert_heartbeat(ts=now - days_ago * DAY, healthy=True, message="alive")
    db.mark_heartbeat_notified(hid, now_ts=now - days_ago * DAY)


def _both(cfg, db, *, behind_days=0):
    """The JSON check and the /settings card badge, from ONE app instance."""
    now = int(time.time())
    real_time = time.time
    try:
        with TestClient(create_app(cfg, db)) as client:
            if behind_days:
                time.time = lambda: float(now - behind_days * DAY)
            body = client.get("/healthz.json").json()
            page = _visible(client.get("/settings").text)
    finally:
        time.time = real_time
    badge = re.search(r"heartbeat\s+(\S+)", page)
    return body, (badge.group(1) if badge else "?")


# --------------------------------------------------------------------------
# 1. The five states, and that BOTH surfaces say the same thing in each.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "enabled", "days_ago", "behind", "want_stale", "want_known", "want_badge"),
    [
        ("delivered just now", True, 0, 0, False, True, "on"),
        ("stopped 400 days ago", True, 400, 0, True, True, "stopped"),
        ("delivery ahead of the clock", True, 400, 500, None, False, "clock"),
        ("enabled, never delivered", True, None, 0, None, False, "armed,"),
        ("heartbeat disabled", False, 0, 0, None, False, "off"),
    ],
)
def test_the_json_and_the_page_agree_in_every_state(
    tmp_path, label, enabled, days_ago, behind, want_stale, want_known, want_badge
):
    """⭐ The first row is the control: if both surfaces had simply stopped
    working they would "agree" everywhere, so a live heartbeat must still read
    healthy on both."""
    cfg, db = _app(tmp_path, enabled=enabled)
    now = int(time.time())
    if days_ago is not None:
        _delivered(db, days_ago=days_ago, now=now)
    try:
        body, badge = _both(cfg, db, behind_days=behind)
    finally:
        db.close()

    hb = body["checks"]["heartbeat"]
    assert hb["is_stale"] is want_stale, label
    assert hb["staleness_known"] is want_known, label
    assert badge.startswith(want_badge), f"{label}: page badge is {badge!r}"


def test_is_stale_is_never_a_reassuring_false_without_a_verified_delivery(tmp_path):
    """⛔ The invariant behind the table above, stated once.

    `is_stale: false` is a CLEAN BILL. It may only appear when a delivery was
    actually seen and actually recent. The three states that establish nothing —
    disabled, never delivered, stamp ahead of the clock — must all report None.

    🪤 This caught a real defect while the check was being written:
    `clock_stamped_freshness(None, ...)` answers known-and-not-stale for a
    missing stamp, which is right for the POLL TICK (a fresh install, whose
    surface says "waiting for first poll") and wrong here. The endpoint would
    have reported a clean bill for exactly the state /settings warns about.
    """
    now = int(time.time())

    for label, enabled, days_ago in [
        ("disabled", False, 0),
        ("never delivered", True, None),
    ]:
        cfg, db = _app(tmp_path / label.replace(" ", "_"), enabled=enabled)
        if days_ago is not None:
            _delivered(db, days_ago=days_ago, now=now)
        try:
            body, _ = _both(cfg, db)
        finally:
            db.close()
        hb = body["checks"]["heartbeat"]
        assert hb["is_stale"] is None, f"{label} reported a verdict it cannot support"
        assert hb["staleness_known"] is False, label


# --------------------------------------------------------------------------
# 2. The fields a monitoring tool actually reads.
# --------------------------------------------------------------------------


def test_seconds_since_delivery_is_null_rather_than_negative(tmp_path):
    """Shares `age_since`, so a delivery stamped ahead reports None instead of a
    negative that every `> threshold` alert silently passes."""
    cfg, db = _app(tmp_path)
    now = int(time.time())
    _delivered(db, days_ago=400, now=now)
    try:
        ahead, _ = _both(cfg, db, behind_days=500)
    finally:
        db.close()

    assert ahead["checks"]["heartbeat"]["seconds_since_delivery"] is None


def test_seconds_since_delivery_is_a_real_number_when_the_clock_agrees(tmp_path):
    """⭐ The control for the test above."""
    cfg, db = _app(tmp_path)
    now = int(time.time())
    _delivered(db, days_ago=400, now=now)
    try:
        body, _ = _both(cfg, db)
    finally:
        db.close()

    assert body["checks"]["heartbeat"]["seconds_since_delivery"] > 399 * DAY


def test_undelivered_is_reported_beside_staleness_not_folded_into_it(tmp_path):
    """⚠️ Two different faults with two different fixes: a broken channel
    (topic/auth) and a stopped daemon. A tool must be able to tell them apart,
    and `undelivered` stays 0 when the daemon has stopped — because a daemon
    that has stopped composes nothing."""
    cfg, db = _app(tmp_path)
    now = int(time.time())
    _delivered(db, days_ago=0, now=now)
    db.insert_heartbeat(ts=now, healthy=True, message="never sent")
    try:
        body, _ = _both(cfg, db)
    finally:
        db.close()

    hb = body["checks"]["heartbeat"]
    assert hb["undelivered"] == 1
    assert hb["is_stale"] is False, "a channel failure is not a stopped daemon"


def test_a_stopped_heartbeat_does_not_flip_the_top_level_status(tmp_path):
    """⚠️ Matches the clock and ruleset checks: only the DB check drives
    top-level status, so a stopped heartbeat must not start paging whoever
    alerts on `status`. The condition lives in its own fields."""
    cfg, db = _app(tmp_path)
    now = int(time.time())
    _delivered(db, days_ago=400, now=now)
    try:
        body, _ = _both(cfg, db)
    finally:
        db.close()

    assert body["checks"]["heartbeat"]["is_stale"] is True
    assert body["checks"]["heartbeat"]["status"] == "ok"
    assert body["status"] == "ok"


def test_a_raising_heartbeat_check_does_not_delete_the_other_six(tmp_path, monkeypatch):
    """⛔ Wired through `_safe_check` like every sibling. One check blowing up
    must not take the report down with it — the defect #161 fixed, and a new
    check is exactly how it would come back."""
    cfg, db = _app(tmp_path)
    monkeypatch.setattr(
        Database,
        "count_undelivered_heartbeats",
        lambda self: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    try:
        with TestClient(create_app(cfg, db)) as client:
            body = client.get("/healthz.json").json()
    finally:
        db.close()

    assert {"db", "poller", "watchlist", "ruleset", "clock", "alerts"} <= set(
        body["checks"]
    ), "a raising heartbeat check deleted its siblings"
    assert body["checks"]["heartbeat"]["status"] == "error"
