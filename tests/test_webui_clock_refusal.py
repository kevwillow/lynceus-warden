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
#: A second device, so the escalated watchful entry the reset route needs does
#: not collide with the alert the /alerts routes act on.
WATCHFUL_MAC = "aa:bb:cc:dd:ee:01"
WATCHFUL_ENTRY_ID = 1


def test_this_suite_is_testing_the_tree_it_lives_in():
    """``pyproject``'s ``pythonpath = ["src"]`` defeats ``PYTHONPATH``, so a
    worktree run silently imports the primary checkout."""
    import lynceus.webui.clock as under_test

    assert Path(under_test.__file__).resolve().is_relative_to(REPO_ROOT)


def _prose(html: str) -> str:
    """The VISIBLE text of a page: comments dropped, tags dropped, whitespace
    collapsed.

    ⚠️ Tags are dropped for two reasons, and the second one has bitten this
    repo twice. A needle spanning ``<code>``/``<strong>`` reports a surface
    silent when it is speaking; and matching RAW html lets a phrase that
    survives only inside a ``title=`` attribute satisfy an assertion about
    what the operator can READ. Both are properties of the helper, so both are
    fixed here rather than in each needle.
    """
    text = re.sub(r"<!--.*?-->", " ", html, flags=re.S)
    text = re.sub(r"<[^>]+>", " ", text)
    return " ".join(text.split())


def _app(tmp_path, *, alert_offset: int = 0, watchful_stale_days: int = 1):
    """A live app whose newest recorded alert sits ``alert_offset`` seconds
    ahead of the real clock. Positive offset = this process reads BEHIND
    recorded history, which is the condition under test.

    ⚠️ Also seeds watchful entry 1, ESCALATED, on a SECOND mac. The reset route
    is one of the writes under test and it renders only on an escalated entry —
    a real domain precondition, satisfied rather than routed around. It has to
    be a second mac: building it from alert 1 would make ``/alerts/1/watch``
    a duplicate, which answers 200-with-a-template instead of the 303 the
    behavioural cases below read as "allowed".
    """
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

    seen = now - watchful_stale_days * DAY
    db.upsert_device(
        mac=WATCHFUL_MAC, device_type="wifi", oui_vendor="V", is_randomized=0, now_ts=seen
    )
    db.insert_sighting(mac=WATCHFUL_MAC, ts=seen, rssi=-50, ssid="n", location_id="default")
    watch_alert = db.add_alert(
        ts=seen, rule_name="argus_mac", mac=WATCHFUL_MAC, message="m", severity="high"
    )
    entry_id = db.create_watchful_from_alert(
        alert_id=watch_alert, snooze_duration_seconds=None, now_ts=seen
    )
    db.escalate_watchful_recurrence(entry_id, escalated_at=seen)
    assert entry_id == WATCHFUL_ENTRY_ID, f"fixture drift: watchful entry is {entry_id}"
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
#
# ⭐ There are TWO ways a web write can be spoiled by a behind clock, and until
# Finding 51 this section only knew about one of them:
#
#   a. it stores ``now + duration`` as an absolute deadline  (the five snoozes)
#   b. it stamps a column that a destructive, now-relative deadline is
#      computed FROM                                         (the reset)
#
# (b) was invisible here because the derivation asked "does this handler read a
# duration constant?", and a reset reads none — so the old assertion did not
# merely miss the reset route, it actively asserted the reset route must NOT be
# guarded. Both halves are now derived, (b) out of `db.py` itself.
# --------------------------------------------------------------------------

_DURATION_CONSTANTS = {"_SNOOZE_DURATIONS", "_RULE_TYPE_SNOOZE_DURATION_SECONDS"}
DB_SOURCE = REPO_ROOT / "src/lynceus/db.py"


def _lifecycle_deadline_columns() -> set[str]:
    """Columns that ``db.py`` computes a DESTRUCTIVE, now-relative deadline from.

    A method qualifies when it both derives a cutoff as ``now_ts - self.<CONST>``
    and uses it in a statement that deletes or archives; the column is whichever
    one that statement compares against the cutoff. Today that is exactly
    ``auto_archive_watchful_recurrence`` → ``last_seen_at``, but nothing here
    knows that: a second such deadline is picked up the moment it is written.
    """
    tree = ast.parse(DB_SOURCE.read_text(encoding="utf-8"))
    columns: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        if not re.search(r"now_ts - self\.[A-Z_]+", ast.unparse(node)):
            continue
        for lit in ast.walk(node):
            if not (isinstance(lit, ast.Constant) and isinstance(lit.value, str)):
                continue
            sql = " ".join(lit.value.split())
            if not re.search(r"\bDELETE\b|archived_at\s*=", sql, re.I):
                continue
            columns.update(re.findall(r"(\w+) <= \?", sql))
    return columns


def _lifecycle_clock_writers() -> set[str]:
    """``db.py`` methods that STAMP one of those columns from a bound parameter.

    ⚠️ Bound parameter, not any assignment: ``sighting_count = sighting_count +
    1`` is arithmetic on stored state and no clock can spoil it. What matters is
    a value this process's clock supplied.
    """
    columns = _lifecycle_deadline_columns()
    tree = ast.parse(DB_SOURCE.read_text(encoding="utf-8"))
    writers: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for lit in ast.walk(node):
            if not (isinstance(lit, ast.Constant) and isinstance(lit.value, str)):
                continue
            sql = " ".join(lit.value.split())
            if "?" not in sql or not re.search(r"\bSET\b", sql, re.I):
                continue
            if any(re.search(rf"\bSET\b.*\b{c}\s*=", sql, re.I) for c in columns):
                writers.add(node.name)
    return writers


def _post_handlers() -> dict[str, dict]:
    """Every ``@app.post`` handler, with why it must be guarded and whether it is.

    ⭐ Derived, so a NEW snooze route — or a new route stamping the lifecycle
    clock — is covered the moment it is written. A hand-listed set of guarded
    routes would be a manifest, and a manifest of "the routes we remembered" is
    exactly what this project keeps finding already-stale.
    """
    writers = _lifecycle_clock_writers()
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
        db_calls = {
            n.func.attr
            for n in ast.walk(node)
            if isinstance(n, ast.Call)
            and isinstance(n.func, ast.Attribute)
            and isinstance(n.func.value, ast.Name)
            and n.func.value.id == "db"
        }
        duration_bearing = bool(names & _DURATION_CONSTANTS)
        stamps_lifecycle_clock = bool(db_calls & writers)
        out[node.name] = {
            "route": posts[0].args[0].value if posts[0].args else "?",
            "duration_bearing": duration_bearing,
            "stamps_lifecycle_clock": stamps_lifecycle_clock,
            "must_be_guarded": duration_bearing or stamps_lifecycle_clock,
            "guarded": "refuse_if_clock_behind" in ast.unparse(node.body),
        }
    return out


def test_the_lifecycle_clock_derivation_is_not_vacuous():
    """⭐ The control for the derivation above, and it is not decoration.

    Both halves are regex-over-AST. If either silently stopped matching, every
    handler would score ``stamps_lifecycle_clock: False``, the assertion below
    would collapse back to the duration-only set it had before Finding 51 —
    and it would then fail by declaring the reset route's guard *spurious*,
    i.e. point at the fix instead of at the broken instrument.
    """
    columns = _lifecycle_deadline_columns()
    assert columns, (
        "no destructive now-relative deadline found in db.py; the derivation "
        "has stopped matching, not the deadline stopped existing"
    )
    assert "last_seen_at" in columns, (
        f"the 90-day watchful auto-archive keys on last_seen_at; derived {columns}"
    )

    writers = _lifecycle_clock_writers()
    assert "reset_watchful_recurrence" in writers, (
        f"the operator reset stamps the lifecycle clock; derived {writers}"
    )
    # ⚠️ Named because a reader will ask. Both are poller-side today, and that
    # is precisely why the check is on the METHOD rather than on a route list:
    # wiring either into a web handler must inherit the guard automatically.
    assert {"record_watchful_sighting", "repair_future_dated_watchful_baselines"} <= writers


def test_every_clock_stamped_route_is_guarded_and_no_other_one_is():
    """Both directions. A missing guard silently stores a dead deadline, or
    quietly buys less tracking than the operator asked for; a spurious one
    blocks an operator from an action a wrong clock cannot spoil.
    """
    handlers = _post_handlers()

    assert len(handlers) >= 23, (
        f"only found {len(handlers)} @app.post handlers; the AST derivation has "
        f"probably stopped matching"
    )
    must = {n for n, h in handlers.items() if h["must_be_guarded"]}
    guarded = {n for n, h in handlers.items() if h["guarded"]}

    assert len({n for n, h in handlers.items() if h["duration_bearing"]}) >= 5, (
        f"expected at least 5 duration-bearing routes, got {sorted(must)}"
    )
    assert {n for n, h in handlers.items() if h["stamps_lifecycle_clock"]} == {
        "watchful_reset_post"
    }, "the set of routes stamping the lifecycle clock has changed"
    assert must == guarded, (
        f"clock-stamped but UNGUARDED (stores a dead deadline, or silently "
        f"shortens a watch): {sorted(must - guarded)}; guarded but stamps "
        f"nothing a clock can spoil (blocks an operator for nothing): "
        f"{sorted(guarded - must)}"
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
GUARDED_ROUTES = [
    ("/alerts/1/snooze", {"snooze_duration": "24h"}),
    ("/alerts/1/watch", {"snooze_duration": "24h"}),
    (f"/devices/{MAC}/snooze", {"snooze_duration": "24h"}),
    (f"/devices/{MAC}/watch", {"snooze_duration": "24h"}),
    ("/rules/watchlist_mac/snooze", {"duration_seconds": "86400"}),
    (f"/watchful/{WATCHFUL_ENTRY_ID}/reset", {}),
]

PERMANENT_ROUTES = [
    ("/alerts/1/allowlist", {}),
    (f"/devices/{MAC}/allowlist", {}),
]


def test_the_behavioural_cases_cover_every_derived_route():
    """The guard that makes the transcription above legitimate."""
    derived = {n for n, h in _post_handlers().items() if h["must_be_guarded"]}

    assert len(GUARDED_ROUTES) == len(derived), (
        f"{len(derived)} clock-stamped routes are derived from the source but "
        f"{len(GUARDED_ROUTES)} are exercised below — add the new one"
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
            codes = _post_all(client, GUARDED_ROUTES)
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
            codes = _post_all(client, GUARDED_ROUTES + PERMANENT_ROUTES)
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


# --------------------------------------------------------------------------
# 5. Finding 51's route half — the reset, whose loss is a property of the ROW.
#
# `reset_watchful_recurrence` stamps `last_seen_at`, the sole lifecycle clock
# for an unactioned entry, and `auto_archive_watchful_recurrence` archives
# anything that column says is 90 days quiet. Measured through the real POST
# route on the tree WITHOUT this gate (gitignored:
# `internal/session2-harnesses/f51_route_verify.py`), days of continued
# tracking granted by a click meaning "I am still watching this device":
#
#     correct clock, 89d stale     90.0d      <- control
#     behind  30d,   89d stale     60.0d
#     behind 100d,   89d stale      1.0d
#     behind 100d,   95d stale     ARCHIVED   the entry is dropped outright
#     behind 100d,    1d stale     89.0d      the cost of refusing: harmless
#
# ⛔ Session 1's `MAX(last_seen_at, ?)` clamp is what stops rows 3 and 5 being
# *worse*; it does not restore the intent, and row 4 still archives. The clamp
# bounds the damage silently, the gate is what tells the operator.
# --------------------------------------------------------------------------


def _reset(client, entry_id: int = WATCHFUL_ENTRY_ID):
    client.get("/")
    token = client.cookies.get("lynceus_csrf")
    return client.request(
        "POST",
        f"/watchful/{entry_id}/reset",
        data={"_csrf": token},
        follow_redirects=False,
    )


def test_a_reset_on_a_behind_clock_is_refused_AND_writes_nothing(tmp_path):
    """Half one of the acceptance criterion.

    ⚠️ The status code is the weaker half. A 400 that had already stamped the
    row would be the worst of both — the operator told the write failed while
    the watch was quietly shortened — so every column the reset touches is
    compared before and after.
    """
    cfg, db, app = _app(tmp_path, alert_offset=30 * DAY, watchful_stale_days=89)
    try:
        before = db.get_watchful_recurrence(WATCHFUL_ENTRY_ID)
        with TestClient(app) as client:
            response = _reset(client)
        after = db.get_watchful_recurrence(WATCHFUL_ENTRY_ID)
    finally:
        db.close()

    assert before.escalated_at is not None, (
        "fixture control: the entry must really be escalated, or the route "
        "would have refused it for a reason that is not the clock"
    )
    assert response.status_code == 400
    assert after.last_seen_at == before.last_seen_at
    assert after.escalated_at == before.escalated_at
    assert after.sighting_count == before.sighting_count
    assert after.reset_count == before.reset_count


def test_a_reset_on_a_correct_clock_still_resets(tmp_path):
    """Half two, and the half that stops half one passing trivially: a route
    that refused every reset would satisfy the first test perfectly.

    ⚠️ Asserts the STATE, not the 303. A redirect proves the handler returned;
    it does not prove the quiet clock restarted, which is the entire content of
    the operator's click.
    """
    cfg, db, app = _app(tmp_path, alert_offset=0, watchful_stale_days=89)
    try:
        before = db.get_watchful_recurrence(WATCHFUL_ENTRY_ID)
        with TestClient(app) as client:
            response = _reset(client)
        after = db.get_watchful_recurrence(WATCHFUL_ENTRY_ID)
        granted = (
            after.last_seen_at
            + Database.WATCHFUL_RECURRENCE_ARCHIVE_QUIET_SECONDS
            - int(time.time())
        )
    finally:
        db.close()

    assert response.status_code == 303
    assert after.escalated_at is None
    assert after.sighting_count == 1
    assert after.reset_count == before.reset_count + 1
    assert granted > Database.WATCHFUL_RECURRENCE_ARCHIVE_QUIET_SECONDS - DAY, (
        f"the reset must restart the full quiet window; granted {granted / DAY:.1f}d "
        f"of {Database.WATCHFUL_RECURRENCE_ARCHIVE_QUIET_SECONDS / DAY:.0f}d"
    )


def test_the_reset_refusal_describes_a_reset_and_not_a_suppression(tmp_path):
    """⛔ The five snooze routes explain a DEADLINE THAT EXPIRES. A reset stores
    no deadline and nothing expires, so reusing that sentence would send the
    operator hunting for a snooze that does not exist — and a warning naming
    the wrong cause gets followed, gets nowhere, and gets dismissed the next
    time it is right.

    ⚠️ Asserted against the RENDERED page's visible text, so a message that
    reached the exception but not the operator would fail here.
    """
    cfg, db, app = _app(tmp_path, alert_offset=30 * DAY, watchful_stale_days=89)
    try:
        with TestClient(app) as client:
            response = _reset(client)
    finally:
        db.close()

    assert response.status_code == 400
    assert response.headers["content-type"].startswith("text/html")
    page = _prose(response.text)

    quiet_days = Database.WATCHFUL_RECURRENCE_ARCHIVE_QUIET_SECONDS // DAY
    assert "hours EARLIER than" in page, "the operator is not told how far off it is"
    assert "the two disagree about what time it is" in page, (
        "the message asserts the clock is wrong; the check cannot know that"
    )
    assert f"auto-archived {quiet_days} days" in page, (
        "the consequence is the archive window, and it is named so the operator "
        "can tell whether it matters to this entry"
    )
    assert "stays escalated" in page, (
        "without this the operator reads a refusal as 'the entry was dropped' "
        "and the refusal becomes scarier than the defect"
    )
    assert "timedatectl" in page, "the operator is not told how to fix it"

    assert "deleted as expired" not in page, "that is the SNOOZE consequence"
    assert "suppression" not in page.lower(), (
        "a reset suppresses nothing; the snooze wording must not leak in"
    )


def test_the_reset_gate_is_deliberately_duration_BLIND(tmp_path):
    """⭐ Pins the design decision a future reader will want to "improve".

    Passing ``duration_seconds=WATCHFUL_RECURRENCE_ARCHIVE_QUIET_SECONDS`` looks
    like the precise thing to do — it is what the reset buys — and it is
    measurably wrong. The operator's loss is ``min(entry_staleness, behind_by)``,
    a property of the ROW, so no duration argument can express it: at a 30-day
    gap an 89-day-stale entry keeps 60 of its 90 days, and the duration-bearing
    call waves it straight through.

    The counterfactual is driven here rather than described, so this fails if
    someone adds the argument.
    """
    cfg, db, app = _app(tmp_path, alert_offset=30 * DAY, watchful_stale_days=89)
    try:
        with TestClient(app) as client:
            response = _reset(client)
        counterfactual = refuse_if_clock_behind(
            db,
            int(time.time()),
            Database.WATCHFUL_RECURRENCE_ARCHIVE_QUIET_SECONDS,
            action="watchful_reset",
        )
    finally:
        db.close()

    assert counterfactual is None, (
        "the premise of this test has changed: a duration-bearing call no "
        "longer allows a 30-day gap"
    )
    assert response.status_code == 400, (
        "the route allowed a reset that costs the operator a third of the "
        "window — it is passing a duration it must not pass"
    )


def test_an_unknown_action_raises_rather_than_explaining_the_wrong_cause(tmp_path):
    """A typo'd action must not silently fall back to the suppression wording:
    that is the failure the parameter exists to prevent, delivered by the thing
    meant to prevent it."""
    cfg, db, _app_unused = _app(tmp_path, alert_offset=30 * DAY)
    try:
        with pytest.raises(ValueError, match="action must be one of"):
            refuse_if_clock_behind(db, int(time.time()), action="watchful-reset")
    finally:
        db.close()


def test_the_refusal_does_not_promise_the_entry_will_survive_the_wait(tmp_path):
    """⛔ The first version of this message said the entry *"stays escalated and
    tracked meanwhile, so nothing is lost by waiting"*. Measured on the tree
    that shipped it, that was false for exactly the entries this gate exists
    for: one already past the quiet window is archived by ordinary housekeeping
    while the operator goes to fix the clock, and an archived entry cannot be
    reset at all.

    Both halves are driven here rather than described, so restoring the shorter
    sentence fails.
    """
    cfg, db, app = _app(tmp_path, alert_offset=30 * DAY, watchful_stale_days=95)
    try:
        with TestClient(app) as client:
            refused = _reset(client)
            # The operator goes to check the clock. The poller housekeeps
            # meanwhile -- nothing exotic, this is the ordinary quiet-window
            # sweep, and the entry is already 95 days quiet.
            archived_count = db.auto_archive_watchful_recurrence(int(time.time()))
            retry = _reset(client)
        row = db.get_watchful_recurrence(WATCHFUL_ENTRY_ID)
        page = _prose(refused.text)
    finally:
        db.close()

    assert refused.status_code == 400
    assert archived_count == 1, "the fixture is not exercising the at-risk entry"
    assert row.archived_at is not None
    assert retry.status_code == 400, (
        "the premise has changed: an archived entry can now be reset, so the "
        "warning below may no longer be needed"
    )

    assert "nothing is lost by waiting" not in page, (
        "the message promises a survival it cannot deliver for this entry"
    )
    assert "can still be archived while the clock is wrong" in page, (
        "the operator is not warned that waiting can cost them the entry"
    )
    assert "an archived entry cannot be reset" in page, (
        "without this the warning has no consequence attached and reads as noise"
    )


def test_an_entry_INSIDE_the_window_really_does_survive_the_wait(tmp_path):
    """⭐ The control for the test above, and the reason the message still says
    the entry is not dismissed. If housekeeping archived every refused entry,
    the warning would be an understatement rather than a correction — and the
    honest message would be a different one again."""
    cfg, db, app = _app(tmp_path, alert_offset=30 * DAY, watchful_stale_days=89)
    try:
        with TestClient(app) as client:
            refused = _reset(client)
            archived_count = db.auto_archive_watchful_recurrence(int(time.time()))
        row = db.get_watchful_recurrence(WATCHFUL_ENTRY_ID)
        page = _prose(refused.text)
    finally:
        db.close()

    assert refused.status_code == 400
    assert archived_count == 0
    assert row.archived_at is None, "an entry inside the window must survive"
    assert row.escalated_at is not None, "and must still be escalated"
    assert "is not dismissed and nothing is deleted" in page
