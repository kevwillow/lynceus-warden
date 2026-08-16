"""A duration is only meaningful if the clock stamping it is.

The web UI is a separate process from the poller and has no ``ClockAnchor``. It
computes ``expires_at = int(time.time()) + duration`` and persists that absolute
deadline, so a wrong host clock stores a deadline wrong by the same amount.

⭐ **The forward jump is already repaired and this suite does not re-test it.**
``repair_future_dated_rule_type_snoozes`` and its three siblings re-base rows
whose ``added_at`` lies in the future, and the poller calls all four under
``clock_trusted``. Measured at +91 days: a 24-hour snooze is re-based to exactly
24.0 hours.

⛔ **The BACKWARD jump is what this suite is about.** Every one of those repairs
keys on ``added_at > now_ts``. A clock *behind* at write time leaves ``added_at``
in the past and ``expires_at`` already elapsed, so nothing matches it and
``cleanup_expired_*`` deletes it as expired:

    measured, clock 6 years behind at write, then corrected
        operator asked for : 24h of silence
        repaired by poller : []
        purged by cleanup  : 1
        got                : 0h

    control, clock +91d at write  -> repaired to 24.0h  ✅
    sanity,  clock correct        -> 24.0h              ✅

An RTC-less Raspberry Pi — this project's target hardware — boots with a stale
clock and syncs later, so "behind at write" is its normal state.

⇒ It cannot be repaired after the fact (``added_at`` in the past is
indistinguishable from an ordinary old row), so it is refused at the write.
"""

from __future__ import annotations

import ast
import re
import time
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import _parse_form_expires_at, create_app
from lynceus.webui.clock import (
    CLOCK_BEHIND_TOLERANCE_SECONDS,
    clock_behind_recorded_history,
    refuse_if_clock_behind,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
APP_SOURCE = REPO_ROOT / "src/lynceus/webui/app.py"
DAY = 86_400
MAC = "aa:bb:cc:dd:ee:ff"


def test_this_suite_is_testing_the_tree_it_lives_in():
    """``pyproject``'s ``pythonpath = ["src"]`` defeats ``PYTHONPATH``, so a
    worktree run silently imports the primary checkout."""
    import lynceus.webui.clock as under_test

    assert Path(under_test.__file__).resolve().is_relative_to(REPO_ROOT)


def _prose(html: str) -> str:
    return " ".join(re.sub(r"<!--.*?-->", " ", html, flags=re.S).split())


def _app(tmp_path, *, alert_offset: int = 0):
    """A live app whose newest recorded alert sits ``alert_offset`` seconds
    ahead of the real clock. Positive offset = this process reads BEHIND
    recorded history, which is the condition under test."""
    allowlist = tmp_path / "allow.yaml"
    allowlist.write_text("entries: []\n", encoding="utf-8")
    cfg = Config(
        db_path=str(tmp_path / "s.db"),
        rules_path=str(REPO_ROOT / "config/rules.yaml"),
        allowlist_path=str(allowlist),
    )
    db = Database(cfg.db_path)
    db.ensure_location("default", "Default")
    now = int(time.time())
    db.upsert_device(mac=MAC, device_type="wifi", oui_vendor="V", is_randomized=0, now_ts=now)
    db.insert_sighting(mac=MAC, ts=now, rssi=-50, ssid="n", location_id="default")
    db.add_alert(
        ts=now + alert_offset, rule_name="argus_mac", mac=MAC, message="m", severity="high"
    )
    return cfg, db, create_app(cfg, db)


# --------------------------------------------------------------------------
# 1. The predicate. Both directions, and the boundary.
# --------------------------------------------------------------------------


def test_a_clock_behind_recorded_history_is_detected(tmp_path):
    cfg, db, _ = _app(tmp_path, alert_offset=30 * DAY)
    try:
        state = clock_behind_recorded_history(db, int(time.time()))
    finally:
        db.close()

    assert state["behind"] is True
    assert state["behind_by"] > 29 * DAY
    assert state["source"], "a refusal has to name its evidence"


def test_a_correct_clock_is_not_flagged(tmp_path):
    """⭐ The control. A false 'your clock is wrong, refusing to snooze' would
    be worse than the defect this prevents, so the negative case matters more
    than the positive one."""
    cfg, db, _ = _app(tmp_path, alert_offset=0)
    try:
        state = clock_behind_recorded_history(db, int(time.time()))
    finally:
        db.close()

    assert state["behind"] is False
    assert state["behind_by"] == 0
    assert refuse_if_clock_behind(db, int(time.time())) is None


@pytest.mark.parametrize(("offset", "expected"), [(240, False), (360, True)])
def test_the_tolerance_boundary(tmp_path, offset, expected):
    """Ordinary NTP slew and round-off must not trip this. Both sides of the
    boundary are asserted — a threshold tested only from the far side is a
    threshold nobody has checked.

    🪤 **These offsets are LITERAL seconds on purpose, and that is the whole
    point of this test.** They were originally written as
    ``CLOCK_BEHIND_TOLERANCE_SECONDS ± 60``, which made the test *circular*:
    a planted defect setting the constant to 0 moved the test's own inputs to
    -60/+60 and both cases still passed. The test derived its points from the
    very value it was checking, so it could not fail. Found by that plant.

    ⇒ The literal side is asserted against the constant here, once, so a
    deliberate change to the threshold has to be made in both places and an
    accidental one fails.
    """
    assert CLOCK_BEHIND_TOLERANCE_SECONDS == 300, (
        "the threshold moved; update these literal offsets deliberately rather "
        "than letting them follow it"
    )
    cfg, db, _ = _app(tmp_path, alert_offset=offset)
    try:
        assert clock_behind_recorded_history(db, int(time.time()))["behind"] is expected
    finally:
        db.close()


def test_a_fresh_install_with_no_history_is_not_behind(tmp_path):
    """Day one has recorded nothing, so there is nothing to be behind. ⛔ Not a
    refusal: no evidence either way must not read as evidence of a fault."""
    allowlist = tmp_path / "allow.yaml"
    allowlist.write_text("entries: []\n", encoding="utf-8")
    cfg = Config(db_path=str(tmp_path / "s.db"), allowlist_path=str(allowlist))
    db = Database(cfg.db_path)
    try:
        state = clock_behind_recorded_history(db, int(time.time()))
        assert state["behind"] is False
        assert state["newest_ts"] is None
        assert refuse_if_clock_behind(db, int(time.time())) is None
    finally:
        db.close()


def test_a_future_poll_watermark_does_NOT_trigger_a_refusal(tmp_path):
    """⚠️ The poll watermark carries Kismet's ``last_seen`` — a DIFFERENT
    machine's clock. Including it would let a Kismet host running fast refuse
    writes on a perfectly correct local machine.

    This is a negative assertion about a deliberate exclusion, which is the
    kind that rots silently, so it is pinned."""
    cfg, db, _ = _app(tmp_path, alert_offset=0)
    try:
        db.set_state("last_poll_ts", str(int(time.time()) + 365 * DAY))
        assert clock_behind_recorded_history(db, int(time.time()))["behind"] is False
    finally:
        db.close()


def test_a_future_stamped_record_also_refuses(tmp_path):
    """⛔ Pins a known FALSE POSITIVE as accepted behaviour rather than leaving
    it to surprise someone.

    The web UI and the poller share a host and therefore a clock, so
    ``now < newest_record`` means the clock jumped BACKWARD since that row was
    written. Two situations produce identical database state — the clock is
    wrong now, or the row was stamped by a past fast clock — and nothing local
    can separate them. Both refuse.

    The trade is deliberate: a false refusal is recoverable (clear message,
    permanent entries still work, clears as the row ages out), while silently
    accepting the real case gives the operator a suppression they believe in
    and never get.
    """
    cfg, db, _ = _app(tmp_path, alert_offset=30 * DAY)
    try:
        state = clock_behind_recorded_history(db, int(time.time()))
    finally:
        db.close()

    assert state["behind"] is True, (
        "if this ever stops refusing, the trade above was changed -- make sure "
        "that was deliberate and that the real case is still caught"
    )


def test_an_install_with_no_ahead_rows_is_a_known_blind_spot(tmp_path):
    """⚠️ Pins the limitation, so the guard is not read as complete cover.

    An install where EVERY row was written by the same behind clock has no
    ahead-row to compare against. The check does not fire, and the snooze still
    dies when the clock is corrected. This narrows the window; it does not
    close it.
    """
    cfg, db, _ = _app(tmp_path, alert_offset=-30 * DAY)
    try:
        state = clock_behind_recorded_history(db, int(time.time()))
    finally:
        db.close()

    assert state["behind"] is False, (
        "the blind spot closed -- if that was deliberate, delete this test and "
        "say so; if not, something is now firing on rows written in the PAST"
    )


def test_the_tolerance_matches_the_pollers(tmp_path):
    """Two components disagreeing about what counts as a clock problem is how
    an operator is told the clock is fine on one page and broken on another.
    Read from ``poller`` rather than restated, so they cannot drift."""
    from lynceus.poller import CLOCK_JUMP_TOLERANCE_SECONDS

    assert CLOCK_BEHIND_TOLERANCE_SECONDS == CLOCK_JUMP_TOLERANCE_SECONDS


# --------------------------------------------------------------------------
# 2. Which routes must be guarded — DERIVED from the source, not listed.
# --------------------------------------------------------------------------

_DURATION_CONSTANTS = {"_SNOOZE_DURATIONS", "_RULE_TYPE_SNOOZE_DURATION_SECONDS"}


def _post_handlers() -> dict[str, dict]:
    """Every ``@app.post`` handler, with whether it reads a duration constant
    and whether it calls the clock guard.

    ⭐ Derived, so a NEW snooze route is covered the moment it is written. A
    hand-listed set of guarded routes would be a manifest, and a manifest of
    "the routes we remembered" is exactly what this project keeps finding
    already-stale.
    """
    tree = ast.parse(APP_SOURCE.read_text(encoding="utf-8"))
    out: dict[str, dict] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        posts = [
            d
            for d in node.decorator_list
            if isinstance(d, ast.Call)
            and isinstance(d.func, ast.Attribute)
            and d.func.attr == "post"
        ]
        if not posts:
            continue
        names = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
        out[node.name] = {
            "route": posts[0].args[0].value if posts[0].args else "?",
            "duration_bearing": bool(names & _DURATION_CONSTANTS),
            "guarded": "refuse_if_clock_behind" in ast.unparse(node.body),
        }
    return out


def test_every_duration_bearing_route_is_guarded_and_no_other_one_is():
    """Both directions. A missing guard silently stores a dead deadline; a
    spurious one blocks an operator from an action a wrong clock cannot spoil.
    """
    handlers = _post_handlers()

    assert len(handlers) >= 23, (
        f"only found {len(handlers)} @app.post handlers; the AST derivation has "
        f"probably stopped matching"
    )
    duration = {n for n, h in handlers.items() if h["duration_bearing"]}
    guarded = {n for n, h in handlers.items() if h["guarded"]}

    assert len(duration) >= 5, f"expected at least 5 duration-bearing routes, got {duration}"
    assert duration == guarded, (
        f"duration-bearing but UNGUARDED (will store a dead deadline): "
        f"{sorted(duration - guarded)}; guarded but carries no duration "
        f"(blocks an operator for nothing): {sorted(guarded - duration)}"
    )


def test_the_allowlist_add_expiry_is_absolute_and_so_needs_no_guard():
    """⚠️ Pins the one exception the derivation above relies on. `/allowlist/add`
    accepts an `expires_at` and is deliberately NOT guarded, because the
    operator types an ABSOLUTE instant — there is no ``now +`` arithmetic for a
    wrong clock to corrupt.

    Asserted behaviourally rather than trusted as a comment: the same input
    must parse to the same epoch no matter what the clock reads.
    """
    assert _parse_form_expires_at("2030-01-01T00:00") == 1_893_456_000
    assert _parse_form_expires_at("2030-01-01T00:00:00Z") == 1_893_456_000
    assert _parse_form_expires_at("") is None
    assert _parse_form_expires_at(None) is None


# --------------------------------------------------------------------------
# 3. The behaviour, on a live app. Both shapes.
# --------------------------------------------------------------------------

#: route -> form payload. ⚠️ A transcription, and legitimate ONLY because
#: ``test_the_behavioural_cases_cover_every_derived_route`` fails when it
#: diverges from the AST-derived set above.
DURATION_ROUTES = [
    ("/alerts/1/snooze", {"snooze_duration": "24h"}),
    ("/alerts/1/watch", {"snooze_duration": "24h"}),
    (f"/devices/{MAC}/snooze", {"snooze_duration": "24h"}),
    (f"/devices/{MAC}/watch", {"snooze_duration": "24h"}),
    ("/rules/watchlist_mac/snooze", {"duration_seconds": "86400"}),
]

PERMANENT_ROUTES = [
    ("/alerts/1/allowlist", {}),
    (f"/devices/{MAC}/allowlist", {}),
]


def test_the_behavioural_cases_cover_every_derived_route():
    """The guard that makes the transcription above legitimate."""
    derived = {n for n, h in _post_handlers().items() if h["duration_bearing"]}

    assert len(DURATION_ROUTES) == len(derived), (
        f"{len(derived)} duration-bearing routes are derived from the source but "
        f"{len(DURATION_ROUTES)} are exercised below — add the new one"
    )


def _post_all(client, routes):
    client.get("/")
    token = client.cookies.get("lynceus_csrf")
    return {
        path: client.request(
            "POST", path, data={**data, "_csrf": token}, follow_redirects=False
        ).status_code
        for path, data in routes
    }


def test_a_clock_behind_history_refuses_every_duration_write(tmp_path):
    cfg, db, app = _app(tmp_path, alert_offset=30 * DAY)
    try:
        with TestClient(app) as client:
            codes = _post_all(client, DURATION_ROUTES)
    finally:
        db.close()

    assert set(codes.values()) == {400}, f"not all duration writes refused: {codes}"


def test_a_clock_behind_history_still_allows_PERMANENT_suppression(tmp_path):
    """⛔ The over-correction shape, and the one that would matter most in an
    incident. A permanent allowlist entry carries no deadline, so a wrong clock
    cannot spoil it — blocking it would stop an operator suppressing a device
    during exactly the event that made them look."""
    cfg, db, app = _app(tmp_path, alert_offset=30 * DAY)
    try:
        with TestClient(app) as client:
            codes = _post_all(client, PERMANENT_ROUTES)
    finally:
        db.close()

    assert set(codes.values()) == {303}, f"a permanent write was blocked: {codes}"


def test_a_correct_clock_refuses_nothing(tmp_path):
    """⭐ The control for both tests above. If the app refused everything
    regardless, the first test would pass for the wrong reason."""
    cfg, db, app = _app(tmp_path, alert_offset=0)
    try:
        with TestClient(app) as client:
            codes = _post_all(client, DURATION_ROUTES + PERMANENT_ROUTES)
    finally:
        db.close()

    assert set(codes.values()) == {303}, f"a write was refused on a good clock: {codes}"


def test_the_refusal_names_the_delta_the_evidence_and_the_fix(tmp_path):
    """"Clock error" tells an operator nothing they can act on.

    ⚠️ Asserted against the RENDERED error page, not the exception's `detail`.
    This app renders `HTTPException` as HTML, so a message that reached the
    exception but not the page would be invisible to the person who needs it —
    and a `.json()` assertion would have passed anyway.
    """
    cfg, db, app = _app(tmp_path, alert_offset=30 * DAY)
    try:
        with TestClient(app) as client:
            client.get("/")
            token = client.cookies.get("lynceus_csrf")
            response = client.request(
                "POST",
                "/rules/watchlist_mac/snooze",
                data={"duration_seconds": "86400", "_csrf": token},
                follow_redirects=False,
            )
    finally:
        db.close()

    assert response.status_code == 400
    assert response.headers["content-type"].startswith("text/html")
    page = _prose(response.text)

    assert "hours EARLIER than" in page, "the operator is not told how far off it is"
    assert "expire the moment the clock is corrected" in page, (
        "the message claims more than the check knows -- the suppression does "
        "work until the clock is fixed"
    )
    assert "the two disagree about what time it is" in page, (
        "the message asserts the clock is wrong; the check cannot know that, "
        "and overclaiming sends the operator to fix the wrong thing"
    )
    assert "timedatectl" in page, "the operator is not told how to fix it"
    assert "permanent allowlist entries are unaffected" in page.lower(), (
        "without this an operator reads the refusal as 'suppression is broken' "
        "and stops trying to suppress anything"
    )


# --------------------------------------------------------------------------
# 4. The read surfaces.
# --------------------------------------------------------------------------

SETTINGS_NOTE = "clock reads behind events already recorded"


@pytest.mark.parametrize(
    ("offset", "expected"), [(30 * DAY, True), (0, False)]
)
def test_settings_reports_the_clock_only_when_it_is_wrong(tmp_path, offset, expected):
    cfg, db, app = _app(tmp_path, alert_offset=offset)
    try:
        with TestClient(app) as client:
            body = _prose(client.get("/settings").text)
    finally:
        db.close()

    assert (body.count(SETTINGS_NOTE) == 1) is expected


@pytest.mark.parametrize(
    ("offset", "expected"), [(30 * DAY, True), (0, False)]
)
def test_healthz_reports_the_clock(tmp_path, offset, expected):
    cfg, db, app = _app(tmp_path, alert_offset=offset)
    try:
        with TestClient(app) as client:
            body = client.get("/healthz.json").json()
    finally:
        db.close()

    check = body["checks"]["clock"]
    assert check["behind"] is expected
    assert check["blocks_duration_writes"] is expected
    # ⭐ status stays ok either way: only the DB check drives the top level, so
    # a drifted host must not start paging whoever alerts on `status`.
    assert check["status"] == "ok"
    assert body["status"] == "ok"
    if expected:
        assert check["behind_by_seconds"] > 29 * DAY
        assert check["newest_recorded_at"], "the operator needs the timestamp to compare"
    else:
        assert check["behind_by_seconds"] == 0


def test_a_duration_LONGER_than_the_gap_is_allowed(tmp_path):
    """⭐ The refusal used to be duration-blind, and said such a write "would
    never take effect". False: the deadline is ``now + duration`` on the writing
    clock, so it works until the clock is corrected — and if the duration
    exceeds the gap it SURVIVES that correction with time to spare.

    Refusing it blocked a write that works. Found by a cold read of the composed
    subsystem; no planted defect could have, because I had not modelled the
    case."""
    cfg, db, _live_app = _app(tmp_path, alert_offset=2 * 3600)  # clock 2h behind
    try:
        now = int(time.time())
        assert refuse_if_clock_behind(db, now, 1 * 3600) is not None, (
            "a 1h suppression cannot survive a 2h gap and must still be refused"
        )
        assert refuse_if_clock_behind(db, now, 24 * 3600) is None, (
            "a 24h suppression outlives a 2h gap; refusing it blocks a write "
            "that works"
        )
        # ⚠️ The duration-blind call keeps the old conservative behaviour, so an
        # un-updated caller cannot silently start allowing dead writes.
        assert refuse_if_clock_behind(db, now) is not None
    finally:
        db.close()
