"""A future anchor must not freeze the suppression audit line.

`_maybe_flush_suppression_summary` gates on `now_ts - _last_suppression_log_ts`.
A forward clock jump clears the counter AND stamps the anchor at the jumped
time, so after the clock is corrected the elapsed check is negative on every
tick and the audit line stays silent for the length of the jump.

⭐ Repaired by self-healing rather than by gating on `clock_trusted`. A gate
alone would not be enough: `ClockAnchor` re-anchors after CLOCK_JUMP_MAX_HOLDS
and then reports a persistently-wrong clock as trusted, so the future anchor can
be written on a tick this method considers perfectly legitimate. The state has
to be repairable once it exists, not merely hard to reach.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lynceus.poller import (  # noqa: E402
    SUPPRESSION_LOG_INTERVAL_SECONDS,
    Poller,
)

NOW = 1_700_000_000
DAY = 86_400


class _JustTheCounter:
    """The flush machinery without standing up a Kismet client or a DB.

    Binds the real method, so this exercises production code rather than a copy.
    """

    def __init__(self, *, anchor: int, counter: dict[str, int]):
        self._last_suppression_log_ts = anchor
        self._rule_type_suppression_counter = dict(counter)

    _maybe_flush_suppression_summary = Poller._maybe_flush_suppression_summary


def test_a_future_anchor_does_not_freeze_the_audit_line():
    """Measured before the repair, with a +8 day jump: the counter was cleared,
    the anchor was stamped 8 days ahead, and no summary flushed again until day
    8 — roughly 8 days of lost audit cadence from one bad tick."""
    p = _JustTheCounter(anchor=NOW, counter={"watchlist_hit": 5})
    p._maybe_flush_suppression_summary(now_ts=NOW + 8 * DAY)  # the jump
    assert p._last_suppression_log_ts == NOW + 8 * DAY, (
        "precondition: the jump should have stamped a future anchor"
    )

    # Clock corrected. The very next tick must repair the anchor.
    p._rule_type_suppression_counter = {"watchlist_hit": 3}
    p._maybe_flush_suppression_summary(now_ts=NOW + 3600)
    assert p._last_suppression_log_ts == NOW + 3600, (
        "the future anchor survived; the audit line stays silent until wall "
        "time catches up with it"
    )

    # And normal cadence resumes immediately afterwards.
    p._maybe_flush_suppression_summary(
        now_ts=NOW + 3600 + SUPPRESSION_LOG_INTERVAL_SECONDS + 60
    )
    assert p._rule_type_suppression_counter == {}, (
        "the summary did not flush on the normal cadence after the repair"
    )


def test_the_repair_does_not_flush_or_lose_the_counter():
    """⚠️ The repairing tick must not be treated as a flush.

    Clearing the counter here would discard suppressions the operator has not
    been told about — trading a cadence bug for a data-loss one, which is the
    lazier 'fix' and would pass the test above.
    """
    p = _JustTheCounter(anchor=NOW + 8 * DAY, counter={"watchlist_hit": 7})
    p._maybe_flush_suppression_summary(now_ts=NOW)
    assert p._rule_type_suppression_counter == {"watchlist_hit": 7}, (
        "the repair threw away accumulated suppression counts"
    )


def test_an_honest_anchor_is_left_alone():
    """The repair must only fire on a future anchor.

    ⚠️ Without this, re-anchoring unconditionally passes the first test and
    silently resets the cadence on every single tick.
    """
    p = _JustTheCounter(anchor=NOW, counter={"watchlist_hit": 2})
    p._maybe_flush_suppression_summary(now_ts=NOW + 60)  # well under the interval
    assert p._last_suppression_log_ts == NOW, "an honest anchor was rewritten"
    assert p._rule_type_suppression_counter == {"watchlist_hit": 2}


def test_the_normal_cadence_still_works():
    """The whole point: a legitimate interval must still flush."""
    p = _JustTheCounter(anchor=NOW, counter={"watchlist_hit": 4})
    p._maybe_flush_suppression_summary(
        now_ts=NOW + SUPPRESSION_LOG_INTERVAL_SECONDS + 60
    )
    assert p._rule_type_suppression_counter == {}
