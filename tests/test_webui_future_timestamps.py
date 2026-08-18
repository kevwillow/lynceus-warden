"""A timestamp ahead of this clock is not "just now".

``relative_time`` collapsed EVERY future timestamp to "just now", justified as
*"defensive against clock skew"*. Measured, that made two different claims false,
and they fail in opposite directions:

    /rules,   a rule_type snooze with 6h left   "snoozed (until just now)"
    /devices, a device silence with 6h left     "silenced (until just now)"

        -> an ``expires_at`` is in the future for EVERY suppression still in
           force, so the badge announced the suppression was over exactly while
           it was working. Suppression is the direction that hides a follower.

    home page, daemon dead 365d, clock behind   "just now"
    /healthz.json, same                          is_stale: false

        -> a tick stamped ahead of a behind clock is the one case where nothing
           can be concluded about the daemon, and it was scored healthy. An
           RTC-less Pi booting before NTP is exactly that state, and it is this
           project's target hardware.

⭐ The skew defence is real and is kept, bounded to ``FUTURE_SKEW_SECONDS`` —
which is the POLLER's own clamp, not a number chosen here. ``sightings.ts``
carries the capture source's clock, and ``record_observation`` accepts it up to
``CLOCK_JUMP_TOLERANCE_SECONDS`` ahead before rewriting it, so anything inside
that band was deliberately stored as "close enough to now" by the writer. Six
hours ahead is not skew.

⚠️ The past side keeps its own separate 60-second bucket. The two are asymmetric
on purpose and for different reasons; see
``test_the_two_windows_are_ASYMMETRIC_and_each_is_pinned_to_its_reason``.

Probes: ``internal/session2-harnesses/future_timestamp_sweep.py`` and
``poller_liveness_probe.py`` (gitignored), both run against a worktree of the
tree without this change and against this one.
"""

from __future__ import annotations

import re
import time
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from lynceus.allowlist import AllowlistEntry, add_ui_entry, derive_ui_path
from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import (
    FUTURE_SKEW_SECONDS,
    JUST_NOW_SECONDS,
    create_app,
    poll_tick_liveness,
    relative_time,
    unix_to_utc_human,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
HOUR = 3600
DAY = 86_400
MAC = "aa:bb:cc:dd:ee:ff"
ABSOLUTE = re.compile(r"\d{4}-\d\d-\d\d \d\d:\d\d UTC")


def test_this_suite_is_testing_the_tree_it_lives_in():
    """``pyproject``'s ``pythonpath = ["src"]`` defeats ``PYTHONPATH``, so a
    worktree run silently imports the primary checkout."""
    import lynceus.webui.app as under_test

    assert Path(under_test.__file__).resolve().is_relative_to(REPO_ROOT)


def _prose(html: str) -> str:
    """Visible text: comments and TAGS dropped, whitespace collapsed. Matching
    raw html lets a phrase surviving only in a ``title=`` attribute satisfy an
    assertion about what the operator can read."""
    text = re.sub(r"<!--.*?-->", " ", html, flags=re.S)
    text = re.sub(r"<[^>]+>", " ", text)
    return " ".join(text.split())


def _app(tmp_path):
    allowlist = tmp_path / "allow.yaml"
    allowlist.write_text("entries: []\n", encoding="utf-8")
    cfg = Config(
        db_path=str(tmp_path / "s.db"),
        rules_path=str(REPO_ROOT / "config/rules.yaml"),
        allowlist_path=str(allowlist),
        kismet_health_check_on_startup=False,
    )
    db = Database(cfg.db_path)
    db.ensure_location("default", "Default")
    now = int(time.time())
    db.upsert_device(
        mac=MAC, device_type="wifi", oui_vendor="V", is_randomized=0, now_ts=now
    )
    db.insert_sighting(mac=MAC, ts=now, rssi=-50, ssid="n", location_id="default")
    return cfg, db, now


def _dead_daemon(db, *, dead_for_days: int, now: int) -> None:
    """The daemon completed one tick and then stopped. Nothing has written a
    tick since — that IS the dead daemon."""
    db.set_state("last_tick_completed_at", str(now - dead_for_days * DAY))
    db.set_state("last_tick_admitted", "7")
    for key in (
        "last_tick_dropped_source_allowlist",
        "last_tick_dropped_min_rssi",
        "last_tick_dropped_unparseable",
    ):
        db.set_state(key, "0")


# --------------------------------------------------------------------------
# 1. The filter. Both directions, and the boundary in BOTH of them.
# --------------------------------------------------------------------------

NOW = 1_770_000_000


@pytest.mark.parametrize(
    ("offset", "expected"),
    [
        (-(FUTURE_SKEW_SECONDS - 1), "just now"),  # ahead, inside the skew band
        (+(JUST_NOW_SECONDS - 1), "just now"),  # behind, inside the display bucket
        # ⚠️ 120s exists because a plant found this list blind. Every other past
        # case sat outside BOTH windows, so widening the past bucket from 60 to
        # the 300-second skew band changed nothing here and the plant survived.
        # A guard against "the past side is unchanged" needs a point inside the
        # band it must NOT adopt.
        (+120, "2m ago"),
        (+600, "10m ago"),
        (+3 * HOUR, "3h ago"),
        (+5 * DAY, "5d ago"),
    ],
)
def test_the_past_side_and_the_skew_window_are_unchanged(offset, expected):
    """⭐ The control for everything below. 21 template call sites use this
    filter; if the past side moved, the change would be a UI rewrite wearing a
    bug fix's clothes."""
    assert relative_time(NOW - offset, now_ts=NOW) == expected


@pytest.mark.parametrize("ahead", [FUTURE_SKEW_SECONDS + 1, 30 * 60, 6 * HOUR, 3 * DAY])
def test_a_timestamp_ahead_of_the_clock_renders_as_an_instant(ahead):
    """Both halves: not the old answer, AND the right one. Asserting only
    ``!= "just now"`` would pass on an empty string."""
    rendered = relative_time(NOW + ahead, now_ts=NOW)

    assert rendered != "just now", f"{ahead}s ahead still collapses to 'just now'"
    assert ABSOLUTE.fullmatch(rendered), f"expected an absolute instant, got {rendered!r}"
    assert rendered == unix_to_utc_human(NOW + ahead)


def test_the_two_windows_are_ASYMMETRIC_and_each_is_pinned_to_its_reason():
    """⛔ The two sides answer different questions and must not be collapsed.

    The PAST bucket is a display convention: 60 seconds, unchanged, because
    widening it would silently rewrite 21 existing call sites (a 2-minute-old
    row would start reading "just now").

    The FUTURE band is a skew ALLOWANCE, and its size is not a taste — it is
    the bound the daemon itself enforces. `poller.record_observation` accepts a
    capture source's `last_seen` up to `CLOCK_JUMP_TOLERANCE_SECONDS` ahead and
    only clamps beyond that, so anything inside was deliberately stored as
    "close enough to now" by the writer. A narrower display window would flag
    values the poller blessed — this UI disagreeing with the daemon about what
    counts as a clock problem, which is what `CLOCK_BEHIND_TOLERANCE_SECONDS`
    documents itself as existing to prevent.

    ⚠️ Derived, not transcribed: the alignment is asserted against the poller's
    own constant, so moving one and not the other fails here.
    """
    from lynceus.poller import CLOCK_JUMP_TOLERANCE_SECONDS

    assert FUTURE_SKEW_SECONDS == CLOCK_JUMP_TOLERANCE_SECONDS, (
        "the display would flag a timestamp the poller deliberately stored"
    )
    assert JUST_NOW_SECONDS == 60, (
        "the past-side bucket moved; that rewrites every relative time in the UI"
    )
    assert FUTURE_SKEW_SECONDS > JUST_NOW_SECONDS, "the asymmetry is the point"

    # Four sides, because a threshold checked from one side is unchecked.
    assert relative_time(NOW + FUTURE_SKEW_SECONDS, now_ts=NOW) == "just now"
    assert relative_time(NOW + FUTURE_SKEW_SECONDS + 1, now_ts=NOW) != "just now"
    assert relative_time(NOW - (JUST_NOW_SECONDS - 1), now_ts=NOW) == "just now"
    assert relative_time(NOW - JUST_NOW_SECONDS, now_ts=NOW) != "just now"

    # ⭐ And the band between them, which only exists because of the asymmetry:
    # a sighting 2 minutes ahead is ordinary skew, 2 minutes behind is an age.
    assert relative_time(NOW + 120, now_ts=NOW) == "just now"
    assert relative_time(NOW - 120, now_ts=NOW) == "2m ago"


def test_the_python_and_javascript_formatters_agree_about_the_future():
    """⭐ ``lynceus.js:formatStamp`` had already made this call — *"Future
    timestamps: render as fully-qualified absolute (don't say 'in 3 hours')"* —
    while the Python one collapsed to "just now". Two formatters answering the
    same question differently is how a UI ends up asserting two things at once,
    so the JS comment is pinned rather than left as the only record."""
    js = (REPO_ROOT / "src/lynceus/webui/static/lynceus.js").read_text(encoding="utf-8")

    # ⚠️ Normalised before matching, and the first version of this test was not:
    # the rationale is a WRAPPED comment (`(don't say` / `// "in 3 hours")`), so
    # a literal needle reported the sentence missing when it was right there.
    # Same failure the HTML assertions in this repo keep hitting — fix the
    # matcher, not the string.
    prose = " ".join(js.replace("//", " ").split())

    assert "if (delta < 0) {" in js, "the JS future branch has moved or gone"
    assert 'don\'t say "in 3 hours"' in prose, (
        "the JS rationale for absolute-in-the-future is gone; if the JS side "
        "changed its mind, the Python side has to be revisited with it"
    )


# --------------------------------------------------------------------------
# 2. A suppression still IN FORCE says how long it lasts.
# --------------------------------------------------------------------------


def test_a_rule_type_snooze_in_force_does_not_read_as_over(tmp_path):
    cfg, db, now = _app(tmp_path)
    db.add_rule_type_snooze(
        rule_type="watchlist_mac", expires_at=now + 6 * HOUR, added_at=now, note="t"
    )
    try:
        with TestClient(create_app(cfg, db)) as client:
            page = _prose(client.get("/rules").text)
    finally:
        db.close()

    found = re.search(r"snoozed \(until\s*(.{0,30}?)\s*\)", page)
    assert found, f"the snooze badge is not rendered at all: {page[:300]}"
    assert "just now" not in found.group(1), (
        f"a snooze with 6h left renders {found.group(1)!r} — it reads as OVER "
        f"while it is still suppressing alerts"
    )
    assert ABSOLUTE.fullmatch(found.group(1)), (
        f"expected the expiry instant, got {found.group(1)!r}"
    )


def test_a_device_silence_in_force_does_not_read_as_over(tmp_path):
    cfg, db, now = _app(tmp_path)
    add_ui_entry(
        derive_ui_path(Path(cfg.allowlist_path)),
        AllowlistEntry(
            pattern=MAC,
            pattern_type="mac",
            note="t",
            added_at=now,
            expires_at=now + 6 * HOUR,
        ),
    )
    try:
        with TestClient(create_app(cfg, db)) as client:
            page = _prose(client.get("/devices").text)
    finally:
        db.close()

    found = re.search(r"silenced \(until\s*(.{0,30}?)\s*\)", page)
    assert found, f"the silence badge is not rendered at all: {page[:300]}"
    assert "just now" not in found.group(1)
    assert ABSOLUTE.fullmatch(found.group(1))


# --------------------------------------------------------------------------
# 3. Liveness: three states, because the operator's next step differs.
# --------------------------------------------------------------------------


def test_poll_tick_liveness_never_polled_keeps_its_documented_answer(tmp_path):
    """⚠️ Not stale and KNOWN. There is no tick to be stale, the home page
    carries the "waiting for first poll" signal, and flagging a fresh install
    would be a startup-window false positive."""
    cfg, db, _now = _app(tmp_path)
    try:
        state = poll_tick_liveness(None, cfg, now_ts=int(time.time()))
    finally:
        db.close()

    assert state == {"staleness_known": True, "is_stale": False, "ahead_by_seconds": 0}


def test_poll_tick_liveness_decides_normally_on_a_sane_clock(tmp_path):
    """⭐ The control. Without it, a helper that answered "unknown" to
    everything would satisfy every assertion in this section."""
    cfg, db, now = _app(tmp_path)
    try:
        fresh = poll_tick_liveness({"completed_at": now}, cfg, now_ts=now)
        # ⚠️ Days, not `interval * 2 + 60`. A plant found that fixture weak: the
        # margin was ~3 minutes, which sits INSIDE the 300-second skew band, so
        # a defect widening "undecidable" to cover behind-ticks too left this
        # test green. A "clearly stale" fixture has to be clearly stale.
        stale_at = now - 10 * DAY
        stale = poll_tick_liveness({"completed_at": stale_at}, cfg, now_ts=now)
        barely = poll_tick_liveness(
            {"completed_at": now - (cfg.poll_interval_seconds * 2 + 60)},
            cfg,
            now_ts=now,
        )
    finally:
        db.close()

    assert fresh == {"staleness_known": True, "is_stale": False, "ahead_by_seconds": 0}
    assert stale["staleness_known"] is True
    assert stale["is_stale"] is True
    # The threshold itself still decides, just past the 2x-interval boundary.
    assert barely["staleness_known"] is True
    assert barely["is_stale"] is True


def test_a_tick_stamped_ahead_is_undecidable_not_healthy(tmp_path):
    """⛔ ``is_stale`` must be None, never False. False is a verdict, and the
    verdict it delivered was "the daemon is fine" for a daemon dead a year."""
    cfg, db, now = _app(tmp_path)
    try:
        state = poll_tick_liveness(
            {"completed_at": now + 400 * DAY}, cfg, now_ts=now
        )
    finally:
        db.close()

    assert state["staleness_known"] is False
    assert state["is_stale"] is None, (
        "None means unknown; False would be the old clean bill of health"
    )
    assert state["ahead_by_seconds"] > 399 * DAY


def test_a_tick_inside_the_skew_window_is_still_decided(tmp_path):
    """The boundary from the other side: ordinary cross-host skew must not make
    every install report an undecidable daemon."""
    cfg, db, now = _app(tmp_path)
    try:
        state = poll_tick_liveness(
            {"completed_at": now + FUTURE_SKEW_SECONDS - 1}, cfg, now_ts=now
        )
    finally:
        db.close()

    assert state["staleness_known"] is True
    assert state["is_stale"] is False


@pytest.mark.parametrize("path", ["/", "/healthz"])
def test_the_html_surfaces_say_the_clock_disagrees_rather_than_just_now(
    tmp_path, path
):
    """Both HTML surfaces, because both render the same tick through the same
    filter and only one of them had ever been looked at.

    ⚠️ Driven by moving the PROCESS clock, not by moving the tick: `app.py`
    calls `time.time()` through the module, so the gate and the renderer see
    the same wrong "now" they would on the box.
    """
    cfg, db, now = _app(tmp_path)
    _dead_daemon(db, dead_for_days=365, now=now)
    real_time = time.time
    try:
        with TestClient(create_app(cfg, db)) as client:
            time.time = lambda: float(now - 400 * DAY)
            page = _prose(client.get(path).text)
    finally:
        time.time = real_time
        db.close()

    assert "clock disagrees" in page, (
        f"{path} does not tell the operator the timestamp cannot be read as "
        f"liveness: {page[:400]}"
    )
    assert "just now" not in page, (
        f"{path} still reports a daemon dead for a year as current"
    )


@pytest.mark.parametrize("path", ["/", "/healthz"])
def test_the_html_surfaces_report_a_dead_daemon_normally_on_a_good_clock(
    tmp_path, path
):
    """⭐ The other half of the conjunction, and the half that stops the test
    above passing trivially: a page that printed "clock disagrees"
    unconditionally would satisfy it perfectly."""
    cfg, db, now = _app(tmp_path)
    _dead_daemon(db, dead_for_days=365, now=now)
    try:
        with TestClient(create_app(cfg, db)) as client:
            page = _prose(client.get(path).text)
    finally:
        db.close()

    assert "clock disagrees" not in page, "a sane clock must not be flagged"
    assert "365d ago" in page, f"{path} no longer reports how long it has been"


def test_healthz_json_reports_the_dead_daemon_as_undecidable(tmp_path):
    cfg, db, now = _app(tmp_path)
    _dead_daemon(db, dead_for_days=365, now=now)
    real_time = time.time
    try:
        with TestClient(create_app(cfg, db)) as client:
            time.time = lambda: float(now - 400 * DAY)
            skewed = client.get("/healthz.json").json()
            time.time = real_time
            sane = client.get("/healthz.json").json()
    finally:
        time.time = real_time
        db.close()

    skewed_tick = skewed["checks"]["poller"]["poll_tick"]
    assert skewed_tick["staleness_known"] is False
    assert skewed_tick["is_stale"] is None
    assert skewed_tick["ahead_by_seconds"] > 0

    # The control, from the same app in the same test: the verdict is still made
    # when it can be.
    sane_tick = sane["checks"]["poller"]["poll_tick"]
    assert sane_tick["staleness_known"] is True
    assert sane_tick["is_stale"] is True
    assert sane_tick["ahead_by_seconds"] == 0


def test_every_staleness_threshold_lives_in_exactly_one_place():
    """⛔ `/healthz` (HTML) once carried its own copy of the poll-tick
    arithmetic, `_check_poller` a second and the home page an implicit third —
    which is how two surfaces came to disagree about whether the daemon was
    alive. Each threshold belongs in exactly one place.

    ⭐ **DERIVED over every threshold, not a hand-listed pair.** This replaces
    two guards — one here and one in `test_webui_heartbeat_freshness.py` — that
    each hardcoded one config knob. The second strictly subsumed the first, so
    one rule was asserted twice in two files: the same duplication-breeds-
    divergence problem these guards exist to prevent, committed in the guards
    themselves. A third knob is covered the moment it is written.
    """
    source = (REPO_ROOT / "src/lynceus/webui/app.py").read_text(encoding="utf-8")
    knobs = re.findall(r"max\(1,\s*config\.(\w+)\)", source)

    # ⚠️ Non-vacuity FIRST. A regex that stopped matching would make every
    # assertion below trivially true, i.e. report "no duplication" — the most
    # reassuring possible answer from a broken instrument.
    assert knobs, (
        "the derivation found no staleness threshold at all in app.py; the "
        "pattern has stopped matching, not the thresholds stopped existing"
    )
    assert set(knobs) >= {"poll_interval_seconds", "heartbeat_interval_hours"}, (
        f"a known threshold knob is no longer derived: {sorted(set(knobs))}"
    )

    duplicated = sorted({k for k in knobs if knobs.count(k) > 1})
    assert not duplicated, (
        f"these staleness thresholds are computed in more than one place: "
        f"{duplicated}. Two copies of one predicate is how two surfaces end up "
        f"disagreeing; put it behind a single helper."
    )

