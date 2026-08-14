"""Retention under a wall clock that is wrong.

Both retention paths derive their cutoff from the system clock:
``poller.py`` binds ``now_ts = int(time.time())`` once per tick and threads it
through ``poll_once`` into ``maybe_prune_sightings`` / ``maybe_prune_evidence``.
Every existing retention test passes an explicit, well-behaved ``now_ts``, so
nothing in the suite has ever exercised a clock that moves the wrong way.

These tests cover the persisted *rate-limiter anchor*. They are the companion
to ``test_clock_jump_anchor.py``, which covers the other half, and the split
matters because the two guards sit at different layers:

- ``poller.clock_is_trusted`` (PR #35) refuses to prune while a jump is fresh.
  It compares the wall clock against elapsed monotonic time, so it can only
  see a jump that happens *during* a process.
- These tests cover what survives that gate: the ``last_*_prune`` timestamp
  persisted in ``poller_state``. A daemon that boots with an already-wrong
  clock takes its anchor *from* that wrong clock -- PR #35's own note concedes
  "a step at boot happens before the anchor is taken" -- prunes, and records a
  timestamp that is in the future relative to true time. Once NTP corrects,
  the clock is trusted again but the stored anchor is still ahead, and
  ``now_ts - last`` is negative. Measured on main before this fix: pruning
  stalled at +0d/+30d/+200d/+364d and did not resume until **+366d**.

⚠️ Do NOT add a cutoff guard to ``retention.py`` itself. From inside that
module "the clock jumped forward" and "the table holds only old rows" are the
same observation, and
``test_sightings_retention.py::test_returns_none_oldest_when_table_is_emptied``
requires the second one to delete everything. That is why the forward-jump
guard lives in the poller and not here.
"""

import pytest

from lynceus.db import Database
from lynceus.evidence import (
    STATE_KEY_LAST_EVIDENCE_PRUNE,
    capture_evidence,
    maybe_prune_evidence,
)
from lynceus.retention import STATE_KEY_LAST_SIGHTINGS_PRUNE, maybe_prune_sightings

NOW = 1_700_000_000
DAY = 86_400


@pytest.fixture
def db(tmp_path):
    database = Database(str(tmp_path / "lynceus.db"))
    database.ensure_location("default", "Default")
    yield database
    database.close()


def seed_sightings(db, mac="aa:1", days=(0, 40, 50)):
    db.upsert_device(
        mac=mac, device_type="wifi", oui_vendor="Acme", is_randomized=0, now_ts=NOW
    )
    for d in days:
        db.insert_sighting(
            mac=mac, ts=NOW - d * DAY, rssi=-50, ssid="n", location_id="default"
        )


def seed_evidence(db, mac="aa:1", days=(0, 200, 400)):
    db.upsert_device(
        mac=mac, device_type="wifi", oui_vendor="Acme", is_randomized=0, now_ts=NOW
    )
    alert_id = db.add_alert(
        ts=NOW, rule_name="r", mac=mac, message="m", severity="high"
    )
    for d in days:
        capture_evidence(
            db,
            alert_id=alert_id,
            mac=mac,
            kismet_record={"d": d},
            now_ts=NOW - d * DAY,
        )


def sighting_rows(db):
    return db._conn.execute("SELECT COUNT(*) FROM sightings").fetchone()[0]


def evidence_rows(db):
    return db._conn.execute("SELECT COUNT(*) FROM evidence_snapshots").fetchone()[0]


# --- the rate limiter must still rate-limit -------------------------------
# Presence assertions. Without these, the "does not stall" tests below are
# satisfied by a limiter that never limits anything, which would be a worse
# defect than the one they guard.


def test_recent_prune_still_suppresses_a_second_sightings_run(db):
    seed_sightings(db)
    db.set_state(STATE_KEY_LAST_SIGHTINGS_PRUNE, str(NOW - 60))

    assert maybe_prune_sightings(db, 10, now_ts=NOW) is False
    assert sighting_rows(db) == 3


def test_recent_prune_still_suppresses_a_second_evidence_run(db):
    seed_evidence(db)
    db.set_state(STATE_KEY_LAST_EVIDENCE_PRUNE, str(NOW - 60))

    assert maybe_prune_evidence(db, 90, now_ts=NOW) is False
    assert evidence_rows(db) == 3


# --- a future anchor must not stall pruning -------------------------------


def test_future_sightings_anchor_does_not_stall_pruning(db):
    """A prune that ran while the clock was wrong-and-ahead records a future
    timestamp. ``now_ts - last`` is then negative, and a bare
    ``< interval_seconds`` check reads that as "too recent" -- so pruning
    stalls for the entire length of the excursion. Measured before the fix:
    a one-year excursion stopped the sightings table being pruned for a year.
    """
    seed_sightings(db)
    db.set_state(STATE_KEY_LAST_SIGHTINGS_PRUNE, str(NOW + 365 * DAY))

    assert maybe_prune_sightings(db, 10, now_ts=NOW) is True
    assert sighting_rows(db) == 1  # the 40d and 50d rows go; the fresh one stays


def test_future_evidence_anchor_does_not_stall_pruning(db):
    seed_evidence(db)
    db.set_state(STATE_KEY_LAST_EVIDENCE_PRUNE, str(NOW + 365 * DAY))

    assert maybe_prune_evidence(db, 90, now_ts=NOW) is True
    assert evidence_rows(db) == 1  # the 200d and 400d rows go


def test_future_anchor_is_replaced_with_a_sane_one(db):
    """The stall must self-heal, not merely be bypassed once: the run has to
    re-record the anchor from the good clock, so the NEXT call rate-limits
    normally instead of pruning on every tick forever."""
    seed_sightings(db)
    db.set_state(STATE_KEY_LAST_SIGHTINGS_PRUNE, str(NOW + 365 * DAY))

    assert maybe_prune_sightings(db, 10, now_ts=NOW) is True
    assert int(db.get_state(STATE_KEY_LAST_SIGHTINGS_PRUNE)) == NOW
    # Immediately after, the ordinary rate limit applies again.
    assert maybe_prune_sightings(db, 10, now_ts=NOW + 60) is False


def test_unparseable_anchor_still_prunes(db):
    """A corrupt anchor falls back to 0, which is in the past, so the run is
    due. Pinned because the fix touches the same branch."""
    seed_sightings(db)
    db.set_state(STATE_KEY_LAST_SIGHTINGS_PRUNE, "not-an-int")

    assert maybe_prune_sightings(db, 10, now_ts=NOW) is True
