"""Retention for the sightings table.

sightings has never been pruned and grows without bound -- the reason
co_observation.window_days exists. Pruning is DESTRUCTIVE and irreversible, so
these tests pin the boundary exactly and pin what the UI is allowed to claim
once rows are gone.
"""

import pytest

from lynceus.db import Database
from lynceus.retention import maybe_prune_sightings, prune_old_sightings

NOW = 1_700_000_000
DAY = 86_400


@pytest.fixture
def db(tmp_path):
    database = Database(str(tmp_path / "lynceus.db"))
    database.ensure_location("default", "Default")
    yield database
    database.close()


def seed_days(db, mac, days):
    db.upsert_device(mac=mac, device_type="wifi", oui_vendor="Acme", is_randomized=0, now_ts=NOW)
    for d in days:
        db.insert_sighting(mac=mac, ts=NOW - d * DAY, rssi=-50, ssid="n", location_id="default")


def rows(db, mac="aa:1"):
    return db._conn.execute("SELECT COUNT(*) FROM sightings WHERE mac=?", (mac,)).fetchone()[0]


def test_prunes_only_rows_older_than_retention(db):
    seed_days(db, "aa:1", [0, 1, 5, 9, 10, 11, 30])

    deleted, oldest, _ = prune_old_sightings(db, 10, now_ts=NOW)

    assert deleted == 2  # the 11-day and 30-day rows
    assert rows(db) == 5
    assert oldest == NOW - 10 * DAY


def test_boundary_is_inclusive_at_exactly_the_cutoff(db):
    """A row exactly at the cutoff is KEPT. Off by one here silently deletes a
    day of evidence every time the job runs."""
    seed_days(db, "aa:1", [10])

    deleted, _, _ = prune_old_sightings(db, 10, now_ts=NOW)

    assert deleted == 0
    assert rows(db) == 1


def test_returns_none_oldest_when_table_is_emptied(db):
    seed_days(db, "aa:1", [40, 50])

    deleted, oldest, _ = prune_old_sightings(db, 10, now_ts=NOW)

    assert deleted == 2
    assert oldest is None


def test_prune_is_a_no_op_when_retention_is_none(db):
    seed_days(db, "aa:1", [0, 100, 1000])

    deleted, _, _ = prune_old_sightings(db, None, now_ts=NOW)

    assert deleted == 0
    assert rows(db) == 3


@pytest.mark.parametrize("bad", [0, -1, True, 1.5, "10"])
def test_prune_rejects_an_invalid_retention(db, bad):
    with pytest.raises(ValueError):
        prune_old_sightings(db, bad, now_ts=NOW)


def test_maybe_prune_runs_once_per_interval(db):
    seed_days(db, "aa:1", [0, 40])

    assert maybe_prune_sightings(db, 10, now_ts=NOW) is True
    # Same day: must not run again.
    assert maybe_prune_sightings(db, 10, now_ts=NOW + 60) is False
    # A day later: runs.
    assert maybe_prune_sightings(db, 10, now_ts=NOW + DAY + 1) is True


def test_maybe_prune_does_nothing_when_retention_is_none(db):
    seed_days(db, "aa:1", [0, 500])

    assert maybe_prune_sightings(db, None, now_ts=NOW) is False
    assert rows(db) == 2


def test_prune_does_not_touch_other_tables(db):
    """Retention is for observation rows only. Alerts are the operator's record
    of what was decided and must outlive the sightings behind them."""
    seed_days(db, "aa:1", [40])
    db.add_alert(ts=NOW - 40 * DAY, rule_name="r", mac="aa:1", message="m", severity="low")

    prune_old_sightings(db, 10, now_ts=NOW)

    assert rows(db) == 0
    assert db._conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 1
    assert db._conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0] == 1


# --- wiring ------------------------------------------------------------
#
# A prune function nothing calls is the failure mode this codebase keeps
# meeting: complete, tested, and unreachable. maybe_prune_evidence had exactly
# that gap -- this comment used to record it as open -- and it is now closed by
# the take-effect pair plus throttle test at the foot of tests/test_evidence.py.


def test_poll_once_prunes_sightings_when_retention_is_configured(db, tmp_path):
    from lynceus.config import Config
    from lynceus.kismet import FakeKismetClient
    from lynceus.poller import poll_once

    fixture = tmp_path / "empty.json"
    fixture.write_text("[]", encoding="utf-8")
    config = Config(
        db_path=str(tmp_path / "unused.db"),
        kismet_fixture_path=str(fixture),
        sightings_retention_days=10,
    )
    seed_days(db, "aa:1", [0, 40])

    poll_once(FakeKismetClient(str(fixture)), db, config, now_ts=NOW)

    assert rows(db) == 1, "poll_once did not reach the sightings prune"


def test_poll_once_prunes_nothing_when_retention_is_unset(db, tmp_path):
    """The default must leave every row alone, on every tick, forever."""
    from lynceus.config import Config
    from lynceus.kismet import FakeKismetClient
    from lynceus.poller import poll_once

    fixture = tmp_path / "empty.json"
    fixture.write_text("[]", encoding="utf-8")
    config = Config(db_path=str(tmp_path / "unused.db"), kismet_fixture_path=str(fixture))
    seed_days(db, "aa:1", [0, 40, 4000])

    poll_once(FakeKismetClient(str(fixture)), db, config, now_ts=NOW)

    assert rows(db) == 3
