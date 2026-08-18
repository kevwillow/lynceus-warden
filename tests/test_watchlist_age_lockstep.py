"""`/settings` and the poller's startup log must agree about the watchlist's age.

`_watchlist_freshness_card`'s docstring has always said the two are *"deliberately
kept in lockstep so an operator who sees a WARNING in journalctl can open
/settings and see the same numbers without reconciling"* — and nothing checked
it. It was an instruction to future authors, which is the weakest kind of
guarantee this repo has.

⛔ **It had already stopped being true.** Removing `max(0, now - reference)` from
the three web surfaces left the poller's copy in place, so for a watchlist
imported 365 days ago whose Argus export is dated 30 days ahead:

    /settings card   status=unknown   age_days=None
    poller startup   INFO  "most recent Argus import 0 days ago"

Two surfaces, two answers, and the daemon's was the reassuring one at the
quieter log level. ⚠️ **No local clock fault is needed to reach it**:
`exported_at` carries the ARGUS host's clock.

This suite drives BOTH implementations over the same inputs. They are
deliberately not shared code — `webui` does not depend on `poller`, and this
repo already made that call for `CLOCK_BEHIND_TOLERANCE_SECONDS` vs
`CLOCK_JUMP_TOLERANCE_SECONDS` ("not imported … the test asserts they stay equal
instead"). This is that same decision, for behaviour rather than a constant.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

import pytest

from lynceus.config import Config
from lynceus.db import Database
from lynceus.poller import CLOCK_JUMP_TOLERANCE_SECONDS, log_watchlist_staleness
from lynceus.webui.app import FUTURE_SKEW_SECONDS, _watchlist_freshness_card

REPO_ROOT = Path(__file__).resolve().parents[1]
DAY = 86_400
WARN_DAYS = 30


def test_this_suite_is_testing_the_tree_it_lives_in():
    import lynceus.poller as under_test

    assert Path(under_test.__file__).resolve().is_relative_to(REPO_ROOT)


def _seeded(tmp_path, *, imported_days_ago: int, export_offset_days: int | None):
    cfg = Config(
        db_path=str(tmp_path / "s.db"), allowlist_path=str(tmp_path / "a.yaml")
    )
    db = Database(cfg.db_path)
    db.ensure_location("default", "Default")
    now = int(time.time())
    db.record_import_run(
        imported_at=now - imported_days_ago * DAY,
        exported_at=None if export_offset_days is None else now + export_offset_days * DAY,
        source="argus",
        record_count=10,
    )
    return db, now


def _poller_says(db, now, caplog) -> tuple[str, str]:
    """(levelname, message) of the single line the startup check emits."""
    caplog.clear()
    with caplog.at_level(logging.INFO, logger="lynceus.poller"):
        log_watchlist_staleness(db, WARN_DAYS, now_ts=now)
    lines = [r for r in caplog.records if "watchlist:" in r.getMessage()]
    assert len(lines) == 1, f"expected exactly one line, got {[r.getMessage() for r in lines]}"
    return lines[0].levelname, lines[0].getMessage()


@pytest.mark.parametrize(
    ("label", "export_offset", "want_status", "want_level"),
    [
        ("export dated a year ago", -365, "stale", "WARNING"),
        ("export dated today", 0, "fresh", "INFO"),
        ("export dated 30d AHEAD", 30, "unknown", "WARNING"),
    ],
)
def test_the_two_surfaces_agree_in_every_state(
    tmp_path, caplog, label, export_offset, want_status, want_level
):
    """⭐ The first two rows are the controls. If the surfaces agreed only
    because both had stopped working, they would agree here too — and they must
    still say `stale` and `fresh` respectively, at the matching log level."""
    db, now = _seeded(tmp_path, imported_days_ago=365, export_offset_days=export_offset)
    try:
        card = _watchlist_freshness_card(db, WARN_DAYS, now_ts=now)
        level, message = _poller_says(db, now, caplog)
    finally:
        db.close()

    assert card["status"] == want_status, label
    assert level == want_level, f"{label}: card={card['status']} but log is {level}"

    if want_status == "unknown":
        assert card["age_days"] is None
        assert "cannot be established" in message, message
        assert "0 days ago" not in message, (
            "the clamp is back: a future reference is being reported as today"
        )
    else:
        assert card["age_days"] is not None
        assert f"{card['age_days']} days ago" in message, (
            f"the two surfaces disagree about the NUMBER: card says "
            f"{card['age_days']}, log says {message!r}"
        )


def test_both_sides_use_the_same_skew_tolerance():
    """⚠️ Derived, not transcribed. The two constants are deliberately separate
    (webui must not import poller), so the thing that can rot is their equality
    — which is what this asserts, exactly as the repo already does for the
    clock-behind pair."""
    assert FUTURE_SKEW_SECONDS == CLOCK_JUMP_TOLERANCE_SECONDS, (
        "the web UI and the daemon would disagree about what counts as "
        "ordinary cross-host skew, which is how one says 'fresh' while the "
        "other says 'cannot tell' about the same watchlist"
    )


def test_ordinary_cross_host_skew_still_reads_as_an_age_on_BOTH_sides(tmp_path, caplog):
    """⛔ The over-correction control. Argus and this host sitting a minute apart
    is normal; if either side called that 'unknown', every install with two
    clocks would lose its staleness signal."""
    db = Database(str(tmp_path / "s.db"))
    db.ensure_location("default", "Default")
    now = int(time.time())
    db.record_import_run(
        imported_at=now - 365 * DAY,
        exported_at=now + CLOCK_JUMP_TOLERANCE_SECONDS - 1,
        source="argus",
        record_count=10,
    )
    try:
        card = _watchlist_freshness_card(db, WARN_DAYS, now_ts=now)
        level, message = _poller_says(db, now, caplog)
    finally:
        db.close()

    assert card["status"] == "fresh", "a minute of skew is not an unknown age"
    assert card["age_days"] == 0
    assert level == "INFO"
    assert "0 days ago" in message
