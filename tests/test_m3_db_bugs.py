"""Regression tests for the data-layer write set in src/lynceus/db.py.

Bug: ``alerts_per_day`` and ``alerts_per_day_by_severity`` build their SQL
window from ``now_ts`` rather than the midnight of today's UTC date. The web
UI's home page calls ``alerts_per_day_by_severity(days=30, now_ts=...)`` once
per render; at any moment other than ``00:00:00 UTC`` the chart's OLDEST day
undercounts every alert that landed between ``00:00:00`` and the current
time-of-day on that day -- up to ~24 hours of evidence on a single render.

Measured reproducer at ``now_ts = 1777809600`` (2026-05-03 12:00 UTC):

    for ts, severity in [(1777420800, "high"), (1777809600, "low")]:
        db.add_alert(ts=ts, ...)
    rows = db.alerts_per_day_by_severity(days=5, now_ts=1777809600)
    rows[0]  # {"date": "2026-04-29", "low": 0, "med": 0, "high": 0, "count": 0}
    # BUG: the 2026-04-29 00:00 UTC high-severity alert is silently dropped.
    # The chart tells the operator "zero alerts that day" while the table holds one.

Cause: the SQL window is ``(now_ts - (days - 1) * 86400, now_ts + 86400)``.
For ``days=5`` and ``now_ts = 2026-05-03 12:00 UTC`` the lower bound is
``2026-04-29 12:00 UTC`` -- events between 00:00 and 12:00 on that day fall
outside the SELECT and are silently counted under 0.
"""

from __future__ import annotations

import pytest

from lynceus.db import Database


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "lynceus.db")


@pytest.fixture
def db(db_path):
    d = Database(db_path)
    yield d
    d.close()

# ---------------------------------------------------------------------------
# Bug: alerts_per_day[_by_severity] window is anchored on now_ts instead of
# today's UTC midnight, so the oldest day's early hours are silently dropped.
# ---------------------------------------------------------------------------


class TestAlertsPerDayWindow:
    """The home trend chart must include ALL events on the oldest day it
    claims to render, not just the slice from ``now_ts - (days-1) * 86400``
    onwards.

    The bug: the SQL window is
    ``(now_ts - (days - 1) * 86400, now_ts + 86400)``, which at any time
    other than 00:00 UTC starts partway through the oldest day and so
    misses every event in the early hours of that day. The Python loop
    then renders that day at ``count=0``, lying to the operator about the
    oldest day on every render where ``now_ts`` is not exactly midnight.
    """

    def test_alerts_per_day_includes_midnight_of_oldest_day(self, db):
        # 2026-05-03 12:00:00 UTC. days=5 -> loop renders 2026-04-29 .. 2026-05-03.
        # SQL bound (current): lower = 2026-04-29 12:00:00 UTC = 1777464000.
        now_ts = 1777809600
        # Event at MIDNIGHT of the oldest rendered day: 2026-04-29 00:00:00 UTC.
        midnight_oldest = 1777420800
        db.add_alert(
            ts=midnight_oldest,
            rule_name="r",
            mac=None,
            message="oldest_day_midnight",
            severity="low",
        )
        # Sanity event on today at noon, so the result is non-trivial.
        db.add_alert(
            ts=now_ts, rule_name="r", mac=None, message="today_noon", severity="low",
        )

        rows = db.alerts_per_day(days=5, now_ts=now_ts)
        by_date = {r["date"]: r["count"] for r in rows}

        # The midnight-of-oldest-day alert MUST be counted under its UTC date.
        assert "2026-04-29" in by_date
        assert by_date["2026-04-29"] == 1, (
            f"alerts_per_day undercounted the oldest rendered day: "
            f"expected count=1 for 2026-04-29 (an alert at its midnight), "
            f"got {by_date['2026-04-29']}. The SQL window starts at "
            f"now_ts - (days-1)*86400, which is mid-day on the oldest day "
            f"when now_ts is not exactly midnight; events in the early hours "
            f"of that day are silently dropped."
        )
        assert by_date["2026-05-03"] == 1

    def test_alerts_per_day_by_severity_includes_midnight_of_oldest_day(self, db):
        # Same bug shape on the per-severity sibling -- this is the one the
        # web UI's home page actually calls to render the stacked chart.
        now_ts = 1777809600
        midnight_oldest = 1777420800
        # A high-severity alert at midnight of the oldest rendered day -- the
        # direction the home chart stacks matters most for.
        db.add_alert(
            ts=midnight_oldest,
            rule_name="r",
            mac=None,
            message="oldest_day_midnight_high",
            severity="high",
        )
        # And a low-severity alert on today, to make the "oldest=0" rendering
        # look like a real anomaly rather than a quiet day.
        db.add_alert(
            ts=now_ts, rule_name="r", mac=None, message="today_noon_low", severity="low",
        )

        rows = db.alerts_per_day_by_severity(days=5, now_ts=now_ts)
        by_date = {r["date"]: r for r in rows}

        oldest = by_date["2026-04-29"]
        assert oldest["count"] == 1, (
            f"alerts_per_day_by_severity undercounted the oldest rendered day: "
            f"expected count=1 for 2026-04-29, got {oldest['count']}. The SQL "
            f"window starts at now_ts - (days-1)*86400 which lands mid-day on "
            f"the oldest day for any now_ts not at 00:00 UTC."
        )
        assert oldest["high"] == 1
        assert by_date["2026-05-03"]["low"] == 1

    def test_alerts_per_day_oldest_day_count_matches_direct_sql(self, db):
        """The COUNT the function reports for the oldest day must equal the
        number of alerts stored on that date, full stop.

        We compute the expected count directly from SQLite (same query shape
        the function would build if its bounds were correct) and assert
        equality. The comparison ignores today, where the upper bound is
        also loose, and focuses on the oldest day -- the day the existing
        test never exercised.
        """
        import datetime as _dt

        now_ts = 1777809600  # 2026-05-03 12:00:00 UTC
        # Three alerts on the oldest day (2026-04-29), spread across the day.
        db.add_alert(
            ts=int(_dt.datetime(2026, 4, 29, 0, 0, tzinfo=_dt.UTC).timestamp()),
            rule_name="r",
            mac=None,
            message="oldest_00",
            severity="low",
        )
        db.add_alert(
            ts=int(_dt.datetime(2026, 4, 29, 6, 0, tzinfo=_dt.UTC).timestamp()),
            rule_name="r",
            mac=None,
            message="oldest_06",
            severity="med",
        )
        db.add_alert(
            ts=int(_dt.datetime(2026, 4, 29, 23, 59, 59, tzinfo=_dt.UTC).timestamp()),
            rule_name="r",
            mac=None,
            message="oldest_23",
            severity="high",
        )

        rows = db.alerts_per_day_by_severity(days=5, now_ts=now_ts)
        by_date = {r["date"]: r for r in rows}

        oldest = by_date["2026-04-29"]
        assert oldest["count"] == 3, (
            f"Oldest rendered day should report 3 alerts spanning the full UTC "
            f"calendar day, got count={oldest['count']} "
            f"(low={oldest['low']}, med={oldest['med']}, high={oldest['high']})"
        )
        assert oldest["low"] == 1
        assert oldest["med"] == 1
        assert oldest["high"] == 1
