"""The disclosure rules. These are the tests that matter in this feature.

Every decision about what a case file may contain is made in
``query.py`` and nowhere else, so these tests are the specification of
that behaviour. Two of them are proven by planting the defect and
watching them go red, recorded in the PR: the bystander leak and the
silent ``do_not_publish`` drop.
"""

from __future__ import annotations

import pytest

from lynceus.casefile.query import build_case_file
from lynceus.db import Database

TARGET = "aa:bb:cc:dd:ee:01"
WATCHLISTED_NEIGHBOUR = "aa:bb:cc:dd:ee:02"
BYSTANDER = "de:ad:be:ef:00:99"

NOW = 1_700_100_000
START = NOW - 3 * 86400


def _seed(tmp_path, *, name="case.db", runs=3, sightings_per_run=1):
    """A target co-observed by one watchlisted device and one bystander.

    Both co-observers are seeded identically apart from the watchlist, so
    a guard that passes here is passing because of the watchlist rule and
    not because the fixture happened to omit one of them.
    """
    db = Database(str(tmp_path / name))
    db.ensure_location("loc-a", "Home")
    db.ensure_location("loc-b", "Work")
    for mac in (TARGET, WATCHLISTED_NEIGHBOUR, BYSTANDER):
        db.upsert_device(
            mac=mac,
            device_type="wifi",
            oui_vendor="Acme Surveillance",
            is_randomized=0,
            now_ts=START,
        )
    # Runs are a day apart, well past the 900s gap that separates one
    # visit from the next, so each day counts as its own shared run.
    for run in range(runs):
        base = START + run * 86400
        for step in range(sightings_per_run):
            offset = step * 60
            db.insert_sighting(TARGET, base + offset, -50, None, "loc-a")
            db.insert_sighting(WATCHLISTED_NEIGHBOUR, base + offset + 30, -60, None, "loc-a")
            db.insert_sighting(BYSTANDER, base + offset + 45, -70, None, "loc-a")
    db.insert_sighting(TARGET, START + 4000, -55, None, "loc-b")

    target_wid, _ = db.add_watchlist(
        pattern=TARGET, pattern_type="mac", severity="high", description="ALPR"
    )
    db.add_watchlist(
        pattern=WATCHLISTED_NEIGHBOUR,
        pattern_type="mac",
        severity="high",
        description="Body camera",
    )
    alert_id = db.add_alert(
        ts=START + 10,
        rule_name="watchlist-mac",
        mac=TARGET,
        message=f"Watchlisted device {TARGET} seen at loc-a",
        severity="high",
        matched_watchlist_id=target_wid,
        rule_type="watchlist_mac",
    )
    return db, alert_id


def _add_evidence(db, alert_id, mac, *, do_not_publish=0, captured_at=START + 11):
    """Insert an evidence row directly.

    ``do_not_publish`` has no producer anywhere in the product: migration
    009 added the column as forward-compat and ``evidence.py``'s INSERT
    never sets it. Seeding it by SQL is the only way to exercise the
    exclusion rule, and it is honest about that.
    """
    with db.transaction() as conn:
        conn.execute(
            "INSERT INTO evidence_snapshots("
            "alert_id, mac, captured_at, kismet_record_json, rssi_history_json, "
            "do_not_publish) VALUES (?, ?, ?, ?, ?, ?)",
            (alert_id, mac, captured_at, '{"k": "v"}', "[-50]", do_not_publish),
        )


@pytest.fixture
def casefile_db(tmp_path):
    db, alert_id = _seed(tmp_path)
    _add_evidence(db, alert_id, TARGET)
    return db


@pytest.fixture
def casefile_db_with_dnp(tmp_path):
    db, alert_id = _seed(tmp_path)
    _add_evidence(db, alert_id, TARGET)
    second = db.add_alert(
        ts=START + 20,
        rule_name="watchlist-mac",
        mac=TARGET,
        message="second sighting",
        severity="high",
        rule_type="watchlist_mac",
    )
    _add_evidence(db, second, TARGET, do_not_publish=1, captured_at=START + 21)
    return db


@pytest.fixture
def casefile_db_substring_trap(tmp_path):
    """An alert for a DIFFERENT device whose message contains our MAC.

    This is what a substring filter would wrongly pull in. It is the
    same defect class as #220: a pattern matched by the wrong operator.
    """
    db, _ = _seed(tmp_path)
    db.upsert_device(
        mac=BYSTANDER,
        device_type="wifi",
        oui_vendor="Other",
        is_randomized=0,
        now_ts=START,
    )
    db.add_alert(
        ts=START + 30,
        rule_name="proximity",
        mac=BYSTANDER,
        message=f"seen alongside {TARGET} at loc-a",
        severity="med",
        rule_type="watchlist_mac",
    )
    return db


@pytest.fixture
def casefile_db_empty(tmp_path):
    """A known device with every sighting pruned away."""
    db = Database(str(tmp_path / "empty.db"))
    db.upsert_device(
        mac=TARGET,
        device_type="wifi",
        oui_vendor="Acme Surveillance",
        is_randomized=0,
        now_ts=START,
    )
    return db


@pytest.fixture
def casefile_db_many_sightings(tmp_path):
    db, _ = _seed(tmp_path, name="many.db", runs=4, sightings_per_run=10)
    return db


def test_a_bystander_is_counted_but_never_named(casefile_db):
    """THE guard. An unwatchlisted co-observer must not appear anywhere."""
    cf = build_case_file(casefile_db, TARGET, now_ts=NOW)
    named = [c["mac"] for c in cf.co_observers_named]
    assert WATCHLISTED_NEIGHBOUR in named, "a watchlisted co-observer must be named"
    assert BYSTANDER not in named
    assert cf.co_observers_aggregate >= 1, "the bystander must still be COUNTED"
    assert BYSTANDER not in repr(cf), "the bystander leaked into the dataclass"


def test_do_not_publish_rows_are_excluded_and_counted(casefile_db_with_dnp):
    """BOTH halves. Excluding silently turns a privacy control into a hole
    the document does not admit to."""
    cf = build_case_file(casefile_db_with_dnp, TARGET, now_ts=NOW)
    assert cf.evidence, "the fixture must produce publishable evidence too"
    assert all(e["do_not_publish"] == 0 for e in cf.evidence)
    assert cf.excluded_counts["do_not_publish"] == 1


def test_named_co_observers_carry_their_underlying_pairs(casefile_db):
    """A count alone must be taken on trust; the pairs are real sighting rows."""
    cf = build_case_file(casefile_db, TARGET, now_ts=NOW)
    neighbour = next(c for c in cf.co_observers_named if c["mac"] == WATCHLISTED_NEIGHBOUR)
    assert neighbour["pairs"], "no drill-down rows"
    for pair in neighbour["pairs"]:
        assert "location_id" in pair


def test_parameters_are_recorded(casefile_db):
    """A co-observation count without its thresholds is unreproducible."""
    cf = build_case_file(casefile_db, TARGET, now_ts=NOW)
    assert cf.parameters["proximity_seconds"] == 300
    assert cf.parameters["gap_seconds"] == 900
    assert "schema_version" in cf.parameters


def test_alerts_are_matched_on_EXACT_mac(casefile_db_substring_trap):
    """An alert for another device whose MESSAGE contains our MAC must not
    appear. Substring matching here is a wrong-record bug."""
    cf = build_case_file(casefile_db_substring_trap, TARGET, now_ts=NOW)
    assert cf.alerts, "the fixture must produce alerts for the target too"
    assert all(a["mac"] == TARGET for a in cf.alerts)


def test_a_device_with_no_retained_sightings_still_builds(casefile_db_empty):
    """Spec section 7: the empty record is a correctness case, not an edge case."""
    cf = build_case_file(casefile_db_empty, TARGET, now_ts=NOW)
    assert cf.sightings == []
    assert cf.limits, "the limits must be present even when there is nothing else"


def test_an_unknown_device_is_refused_rather_than_invented(casefile_db):
    """A blank document for a MAC that was never seen would read as
    'it was not there', which is a stronger claim than the record supports."""
    with pytest.raises(LookupError):
        build_case_file(casefile_db, "11:22:33:44:55:66", now_ts=NOW)


def test_the_sighting_cap_is_recorded_when_it_bites(casefile_db_many_sightings):
    cf = build_case_file(casefile_db_many_sightings, TARGET, now_ts=NOW, sighting_limit=10)
    assert len(cf.sightings) == 10
    assert cf.excluded_counts["sightings_over_cap"] > 0


def test_the_mac_is_normalised_before_anything_touches_it(casefile_db):
    """Both entry points take the MAC from the user. Normalising first is
    what keeps a MAC-shaped path traversal out of the filename."""
    cf = build_case_file(casefile_db, TARGET.upper(), now_ts=NOW)
    assert cf.device["mac"] == TARGET


def test_retention_limits_are_conditioned_on_the_actual_config(casefile_db):
    """Limit 2 changes meaning when nothing is pruned, so it must not be
    boilerplate that says 'retention may have pruned' regardless."""
    cf = build_case_file(casefile_db, TARGET, now_ts=NOW)
    assert "sightings_retention_days" in cf.parameters
