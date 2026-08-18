"""A stored value we could not read must not be reported as a measurement.

`_read_last_tick_stats` returned `None` for BOTH "the daemon has never polled"
and "the stored timestamp is present but unparseable". `poll_tick_liveness`
answers the never-polled question with `staleness_known: True, is_stale: False`
— so a daemon dead for a year, whose timestamp had been corrupted, reported as
a fresh install waiting for its first poll. Measured before the fix:

    state                   staleness_known  is_stale  admitted  dropped_min_rssi
    never polled (CONTROL)  True             False     0         0
    healthy tick (CONTROL)  True             False     42        7
    completed_at CORRUPT    True             False     0         0
    counters CORRUPT        True             False     0         0

Two separate lies in that third row: it asserted a liveness verdict it could not
support, AND it discarded `admitted=42` / `dropped_min_rssi=7`, which were
sitting readable in the database — one corrupt timestamp zeroed the whole tick.

⭐ This is the mirror image of #161. There, `_check_watchlist` RAISED on the same
corruption class and took the whole endpoint down; here `_check_poller`
SWALLOWED it and reported health. Two adjacent checks in one endpoint, the same
input, opposite failure modes, both wrong.

⚠️ The third state already existed — session 2 built it for the ahead-of-clock
case (#153). This routes the unreadable case onto it rather than inventing a
fourth, because "no verdict is supportable" is the same answer for both.
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import _check_poller, _read_last_tick_stats, create_app

NOW = int(time.time())


def _db(tmp_path, **state) -> Database:
    db = Database(str(tmp_path / "t.db"))
    for k, v in state.items():
        db.set_state(k, v)
    return db


def _poll_tick(db) -> dict:
    cfg = Config(kismet_url="http://x:2501", kismet_api_key="k")
    return _check_poller(db, cfg, now_ts=NOW)["poll_tick"]


# --- the two states that must keep their existing answers -------------------


def test_control_never_polled_is_still_known_and_not_stale(tmp_path):
    """A fresh install must NOT be flagged; that was a deliberate decision."""
    db = _db(tmp_path)
    try:
        t = _poll_tick(db)
        assert t["staleness_known"] is True
        assert t["is_stale"] is False
        assert t["counters_known"] is True, "nothing has run, so the zeros are real"
        assert t["completed_at"] is None
    finally:
        db.close()


def test_control_a_healthy_tick_is_unchanged(tmp_path):
    db = _db(
        tmp_path,
        last_tick_completed_at=str(NOW - 10),
        last_tick_admitted="42",
        last_tick_dropped_min_rssi="7",
    )
    try:
        t = _poll_tick(db)
        assert t["staleness_known"] is True and t["is_stale"] is False
        assert t["counters_known"] is True
        assert t["admitted"] == 42 and t["dropped_min_rssi"] == 7
    finally:
        db.close()


def test_control_a_dead_daemon_on_a_sane_clock_is_still_stale(tmp_path):
    db = _db(tmp_path, last_tick_completed_at=str(NOW - 3600))
    try:
        t = _poll_tick(db)
        assert t["staleness_known"] is True and t["is_stale"] is True
    finally:
        db.close()


# --- the defect ------------------------------------------------------------


def test_an_unreadable_timestamp_supports_no_liveness_verdict(tmp_path):
    db = _db(tmp_path, last_tick_completed_at="not-an-int")
    try:
        t = _poll_tick(db)
        assert t["staleness_known"] is False, (
            "asserted a known staleness for a timestamp it could not read"
        )
        # ⚠️ `is None`, not falsiness: `not None` is True and would score this
        # exactly as the defect it replaces.
        assert t["is_stale"] is None
    finally:
        db.close()


def test_an_unreadable_timestamp_is_distinguishable_from_never_polled(tmp_path):
    """The whole defect was these two collapsing into one return value."""
    never = _db(tmp_path / "a", )
    (tmp_path / "b").mkdir(parents=True, exist_ok=True)
    corrupt = _db(tmp_path / "b", last_tick_completed_at="not-an-int")
    try:
        assert _read_last_tick_stats(never) is None
        got = _read_last_tick_stats(corrupt)
        assert got is not None, "corrupt is still indistinguishable from never-polled"
        assert got["stamp_readable"] is False
    finally:
        never.close()
        corrupt.close()


def test_a_corrupt_timestamp_does_not_discard_the_readable_counters(tmp_path):
    """One bad timestamp used to zero the whole tick block."""
    db = _db(
        tmp_path,
        last_tick_completed_at="not-an-int",
        last_tick_admitted="42",
        last_tick_dropped_min_rssi="7",
    )
    try:
        t = _poll_tick(db)
        assert t["admitted"] == 42, "a readable counter was thrown away"
        assert t["dropped_min_rssi"] == 7
        assert t["counters_known"] is True, "the COUNTERS were fine; only the stamp was not"
    finally:
        db.close()


def test_an_unreadable_counter_is_flagged_rather_than_published_as_zero(tmp_path):
    db = _db(
        tmp_path,
        last_tick_completed_at=str(NOW - 10),
        last_tick_admitted="not-an-int",
    )
    try:
        t = _poll_tick(db)
        assert t["counters_known"] is False, (
            "published a number for a counter it could not read"
        )
        # The stamp was fine, so the liveness verdict is still available.
        assert t["staleness_known"] is True
    finally:
        db.close()


# --- the rendered surfaces --------------------------------------------------


def _render(tmp_path, path, **state):
    db = _db(tmp_path, **state)
    cfg = Config(kismet_url="http://x:2501", kismet_api_key="k")
    try:
        with TestClient(create_app(cfg, db), raise_server_exceptions=False) as c:
            r = c.get(path)
        return r
    finally:
        db.close()


@pytest.mark.webui
@pytest.mark.parametrize("path", ["/", "/healthz"])
def test_an_unreadable_stamp_does_not_500_the_page(tmp_path, path):
    """`completed_at` is None in that state; every surface renders it."""
    r = _render(tmp_path / path.strip("/") or tmp_path, path,
                last_tick_completed_at="not-an-int")
    assert r.status_code == 200, r.text[:300]


@pytest.mark.webui
def test_the_unreadable_message_does_not_blame_the_clock(tmp_path):
    """⛔ Two causes must not share one sentence.

    An unreadable stored value and an ahead-of-clock stamp both set
    `staleness_known: False`. If the unreadable case rendered "clock disagrees",
    the operator would check NTP, find nothing wrong, and dismiss the warning.
    """
    bad = _render(tmp_path / "bad", "/", last_tick_completed_at="not-an-int")
    assert "unreadable" in bad.text
    assert "clock disagrees" not in bad.text, (
        "an unreadable stored value was reported as a clock problem"
    )

    ahead = _render(tmp_path / "ahead", "/",
                    last_tick_completed_at=str(NOW + 86400))
    assert "clock disagrees" in ahead.text, "CONTROL: the clock case lost its message"
    assert "unreadable" not in ahead.text


@pytest.mark.webui
def test_unreadable_counters_are_not_rendered_as_zero(tmp_path):
    r = _render(tmp_path, "/", last_tick_completed_at=str(NOW - 10),
                last_tick_admitted="not-an-int")
    assert r.status_code == 200
    assert "unavailable" in r.text
    assert "admitted:</strong> 0" not in r.text, (
        "rendered a placeholder 0 as though nothing had been admitted"
    )
