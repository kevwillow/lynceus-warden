"""A reference timestamp in the FUTURE is not "today", and therefore not "fresh".

Three surfaces computed an age as ``max(0, now - reference)``. Clamping a
negative delta to zero turns *"this is stamped in the future"* into *"this
happened just now"*, which every staleness test downstream reads as healthy.

⚠️ **This needs no local clock fault to reach.** The watchlist's reference is
``exported_at``, stamped by the ARGUS host — a different machine — so a
future-dated export is the ordinary cross-host case.

Measured before the fix, watchlist imported 365 days ago, export dated 30 days
ahead (`internal/session2-harnesses/` probes):

    /settings card   status=fresh    age_days=0
    home summary     is_stale=False
    /healthz.json    stale=True      days_since_import=365

Two surfaces called it fresh and one called it stale, for the same watchlist at
the same instant — the clamp on one reference, a different reference on the
other. And in `_check_poller`, `seconds_since_poll` / `seconds_since_observation`
went NEGATIVE (-34,560,000 against a control of +34,560,000), which silently
satisfies every `seconds_since_poll > threshold` a monitoring tool can write.
"""

from __future__ import annotations

import re
import time
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import (
    FUTURE_SKEW_SECONDS,
    _watchlist_freshness_card,
    _watchlist_freshness_summary,
    age_days_since,
    age_since,
    create_app,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
DAY = 86_400
NOW = 1_770_000_000


def test_this_suite_is_testing_the_tree_it_lives_in():
    import lynceus.webui.app as under_test

    assert Path(under_test.__file__).resolve().is_relative_to(REPO_ROOT)


def _prose(html: str) -> str:
    import html as H

    t = re.sub(r"<!--.*?-->", " ", html, flags=re.S)
    t = re.sub(r"<[^>]+>", " ", t)
    return H.unescape(" ".join(t.split()))


def _app(tmp_path):
    allow = tmp_path / "allow.yaml"
    allow.write_text("entries: []\n", encoding="utf-8")
    cfg = Config(
        db_path=str(tmp_path / "s.db"),
        rules_path=str(REPO_ROOT / "config/rules.yaml"),
        allowlist_path=str(allow),
        kismet_health_check_on_startup=False,
    )
    db = Database(cfg.db_path)
    db.ensure_location("default", "Default")
    return cfg, db


# --------------------------------------------------------------------------
# 1. The helper.
# --------------------------------------------------------------------------


def test_a_past_reference_still_gives_an_ordinary_age():
    """⭐ The control for everything below. If the past side moved, this change
    would be a rewrite of every age in the UI wearing a bug fix's clothes."""
    assert age_since(NOW - 3600, now_ts=NOW) == 3600
    assert age_days_since(NOW - 400 * DAY, now_ts=NOW) == 400
    assert age_days_since(NOW - 1, now_ts=NOW) == 0
    assert age_since(None, now_ts=NOW) is None


def test_a_future_reference_is_unknown_not_zero():
    """Both halves: not the old answer, AND the right one. Asserting only
    ``!= 0`` would pass on a negative, which is the other wrong answer."""
    for ahead in (FUTURE_SKEW_SECONDS + 1, DAY, 400 * DAY):
        assert age_since(NOW + ahead, now_ts=NOW) is None, f"{ahead}s ahead"
        assert age_days_since(NOW + ahead, now_ts=NOW) is None


def test_ordinary_cross_host_skew_is_still_an_age_of_zero():
    """⚠️ The boundary from the other side, and the reason this is not simply
    "reject anything ahead". Argus and this host can be seconds apart; that is
    a zero-day-old import, not an unanswerable question."""
    assert age_since(NOW + FUTURE_SKEW_SECONDS, now_ts=NOW) == 0
    assert age_days_since(NOW + FUTURE_SKEW_SECONDS, now_ts=NOW) == 0
    assert age_since(NOW + FUTURE_SKEW_SECONDS + 1, now_ts=NOW) is None


def test_no_surface_clamps_an_age_with_max_zero_any_more():
    """⛔ The clamp existed in THREE places and a sweep found the other two
    after a review named only one. A fourth copy would reintroduce it silently.
    """
    source = (REPO_ROOT / "src/lynceus/webui/app.py").read_text(encoding="utf-8")
    clamps = [
        line.strip()
        for line in source.splitlines()
        if re.search(r"max\(0,\s*\(?now_ts\s*-", line)
    ]
    assert not clamps, (
        f"an age is being clamped to zero again, which reads a future "
        f"reference as 'just now': {clamps}"
    )


# --------------------------------------------------------------------------
# 2. The three watchlist surfaces, and that they now agree.
# --------------------------------------------------------------------------


def _seed(db, *, imported_days_ago: int, export_ahead_days: int | None, now: int):
    db.record_import_run(
        imported_at=now - imported_days_ago * DAY,
        exported_at=None if export_ahead_days is None else now + export_ahead_days * DAY,
        source="argus",
        record_count=10,
    )


@pytest.mark.parametrize(
    ("label", "export_ahead", "card_status", "summary_stale"),
    [
        ("export 365d in the past", -365, "stale", True),
        ("export today", 0, "fresh", False),
        ("export 30d in the FUTURE", 30, "unknown", None),
    ],
)
def test_the_freshness_surfaces_agree_across_all_three_states(
    tmp_path, label, export_ahead, card_status, summary_stale
):
    """⭐ The controls are the first two rows: they must be untouched, or the
    third row is passing because the surfaces stopped working entirely."""
    cfg, db = _app(tmp_path)
    now = int(time.time())
    _seed(db, imported_days_ago=365, export_ahead_days=export_ahead, now=now)
    try:
        card = _watchlist_freshness_card(
            db, cfg.watchlist_staleness_warn_days, now_ts=now
        )
        summary = _watchlist_freshness_summary(
            db, cfg.watchlist_staleness_warn_days, now_ts=now
        )
    finally:
        db.close()

    assert card["status"] == card_status, label
    assert summary["is_stale"] is summary_stale, label
    assert summary["staleness_known"] is (summary_stale is not None)
    if card_status == "unknown":
        assert card["age_days"] is None, "an unknown age must not report a number"


def test_healthz_reports_the_unknown_import_age_as_null_not_false(tmp_path):
    cfg, db = _app(tmp_path)
    now = int(time.time())
    # ⚠️ imported_at itself ahead — healthz keys on the IMPORT timestamp, not
    # the export, so this is the input that reaches its clamp.
    db.record_import_run(
        imported_at=now + 30 * DAY, exported_at=None, source="argus", record_count=10
    )
    try:
        with TestClient(create_app(cfg, db)) as client:
            w = client.get("/healthz.json").json()["checks"]["watchlist"]
    finally:
        db.close()

    assert w["days_since_import"] is None, "a future import is not 0 days old"
    assert w["stale"] is None, "None means unknown; False was the clean bill"
    assert w["staleness_known"] is False


def test_healthz_still_decides_when_it_can(tmp_path):
    """⭐ The control. A check answering "unknown" to everything would satisfy
    the test above perfectly."""
    cfg, db = _app(tmp_path)
    now = int(time.time())
    db.record_import_run(
        imported_at=now - 400 * DAY, exported_at=None, source="argus", record_count=10
    )
    try:
        with TestClient(create_app(cfg, db)) as client:
            w = client.get("/healthz.json").json()["checks"]["watchlist"]
    finally:
        db.close()

    assert w["days_since_import"] == 400
    assert w["stale"] is True
    assert w["staleness_known"] is True


# --------------------------------------------------------------------------
# 3. The poller's two raw deltas.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("ahead_days", [400, 1])
def test_seconds_since_never_goes_negative(tmp_path, ahead_days):
    """A negative "seconds since" silently satisfies every `> threshold` a
    monitoring tool can write, so a daemon dead for a year read as fine."""
    cfg, db = _app(tmp_path)
    now = int(time.time())
    stamp = now + ahead_days * DAY
    db.upsert_device(
        mac="aa:bb:cc:dd:ee:ff", device_type="wifi", oui_vendor="V",
        is_randomized=0, now_ts=stamp,
    )
    db.insert_sighting(
        mac="aa:bb:cc:dd:ee:ff", ts=stamp, rssi=-50, ssid="n", location_id="default"
    )
    db.set_state("last_poll_ts", str(stamp))
    try:
        with TestClient(create_app(cfg, db)) as client:
            p = client.get("/healthz.json").json()["checks"]["poller"]
    finally:
        db.close()

    for key in ("seconds_since_poll", "seconds_since_observation"):
        assert p[key] is None or p[key] >= 0, f"{key} = {p[key]}"
        assert p[key] is None, (
            f"{key} should be unknown for a stamp {ahead_days}d ahead, got {p[key]}"
        )


def test_seconds_since_is_a_real_number_when_the_clock_agrees(tmp_path):
    """⭐ The control for the test above."""
    cfg, db = _app(tmp_path)
    now = int(time.time())
    stamp = now - 400 * DAY
    db.upsert_device(
        mac="aa:bb:cc:dd:ee:ff", device_type="wifi", oui_vendor="V",
        is_randomized=0, now_ts=stamp,
    )
    db.insert_sighting(
        mac="aa:bb:cc:dd:ee:ff", ts=stamp, rssi=-50, ssid="n", location_id="default"
    )
    db.set_state("last_poll_ts", str(stamp))
    try:
        with TestClient(create_app(cfg, db)) as client:
            p = client.get("/healthz.json").json()["checks"]["poller"]
    finally:
        db.close()

    assert p["seconds_since_poll"] > 399 * DAY
    assert p["seconds_since_observation"] > 399 * DAY


# --------------------------------------------------------------------------
# 4. What the operator actually reads.
# --------------------------------------------------------------------------


def test_settings_says_it_cannot_tell_rather_than_guessing(tmp_path):
    """⛔ The template branched `fresh` / else-`stale`, so an unknown status
    would have rendered a confident "stale" — the same overclaim from the other
    end. Three branches now."""
    cfg, db = _app(tmp_path)
    now = int(time.time())
    _seed(db, imported_days_ago=365, export_ahead_days=30, now=now)
    try:
        with TestClient(create_app(cfg, db)) as client:
            page = _prose(client.get("/settings").text)
    finally:
        db.close()

    assert "cannot tell" in page
    assert "ahead of this machine's clock" in page
    assert "Argus stamps" in page, (
        "the operator is not told this can happen with a good local clock"
    )
    assert "stale (older than" not in page, "a verdict nothing established"
    assert "fresh (within" not in page


def test_the_home_page_does_not_call_an_unknown_age_fresh(tmp_path):
    cfg, db = _app(tmp_path)
    now = int(time.time())
    _seed(db, imported_days_ago=365, export_ahead_days=30, now=now)
    try:
        with TestClient(create_app(cfg, db)) as client:
            page = _prose(client.get("/").text)
    finally:
        db.close()

    assert "age unknown" in page
    assert re.search(r"\bfresh\b", page) is None, (
        "None is falsy, so `{% if is_stale %}` sent the unknown case straight "
        "to the green branch"
    )


@pytest.mark.parametrize(
    ("export_ahead", "needle"), [(-365, "stale"), (0, "fresh")]
)
def test_the_home_page_verdicts_are_unchanged_when_the_age_IS_known(
    tmp_path, export_ahead, needle
):
    """⭐ Both controls for the test above, in both directions."""
    cfg, db = _app(tmp_path)
    now = int(time.time())
    _seed(db, imported_days_ago=365, export_ahead_days=export_ahead, now=now)
    try:
        with TestClient(create_app(cfg, db)) as client:
            page = _prose(client.get("/").text)
    finally:
        db.close()

    assert needle in page
    assert "age unknown" not in page
