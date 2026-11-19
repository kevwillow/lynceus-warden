"""Tests for the ``randomized_device_present`` rule type.

"Someone's phone is inside the house": a randomized-MAC Wi-Fi device sitting
close to the sensor (strong signal) for a sustained time, while people walking
past never dwell long enough. Every other rule type skips randomized MACs; this
one is the only rule type that looks at them, which is also why a hard ``mac``
allowlist entry still silences it (connected phones keep a stable per-network
randomized MAC; unconnected visitors rotate).

All MACs below are locally administered and synthetic (the IEEE U/L bit is set
in the first octet), and no SSIDs appear anywhere: the repo's
identifier-hygiene gate refuses real-looking device identifiers.
"""

from __future__ import annotations

import textwrap

import pytest
from pydantic import ValidationError

from lynceus.allowlist import load_allowlist
from lynceus.config import Config
from lynceus.db import Database
from lynceus.kismet import DeviceObservation
from lynceus.poller import process_observation
from lynceus.rules import Rule, Ruleset, evaluate

# Synthetic, locally administered (0x5a has the IEEE U/L bit set); never off a
# radio.
MAC = "5a:00:00:00:00:01"
MAC_OTHER = "5a:00:00:00:00:02"

NOW = 1_700_000_000


class _Recorder:
    def __init__(self):
        self.sent = []

    def send(self, *a, **k):
        self.sent.append((a, k))
        return True


@pytest.fixture()
def db(tmp_path):
    database = Database(str(tmp_path / "presence.db"))
    database.ensure_location("default", "Default")
    yield database
    database.close()


def _obs(
    mac: str = MAC, rssi: int = -45, last_seen: int = NOW, is_randomized: bool = True
) -> DeviceObservation:
    return DeviceObservation(
        mac=mac,
        device_type="wifi",
        first_seen=last_seen,
        last_seen=last_seen,
        rssi=rssi,
        ssid=None,
        oui_vendor=None,
        is_randomized=is_randomized,
    )


def _rule(**kw) -> Rule:
    base = dict(
        name="someone_inside",
        rule_type="randomized_device_present",
        severity="med",
        presence_min_rssi=-55,
        presence_min_dwell_seconds=600,
        presence_max_alerts_per_hour=6,
    )
    base.update(kw)
    return Rule(**base)


def _seed(db: Database, mac: str, ts_list: list[int], rssi: int) -> None:
    db.upsert_device(
        mac=mac,
        device_type="wifi",
        oui_vendor=None,
        is_randomized=1,
        now_ts=NOW,
    )
    for ts in ts_list:
        db.insert_sighting(mac=mac, ts=ts, rssi=rssi, ssid=None, location_id="default")


def _every_60s(minutes: int) -> list[int]:
    """``minutes`` minutes of sightings, one every 60s, ending at NOW."""
    return [NOW - (minutes * 60 - 60) + 60 * i for i in range(minutes)]


def test_strong_run_of_11_minutes_hits_with_exact_message(db):
    """The hit: 11 min of strong sightings at -45, dwell 600 -> one hit."""
    _seed(db, MAC, _every_60s(11), -45)
    hits = evaluate(
        Ruleset(rules=[_rule()]), _obs(), True, db=db
    )
    assert len(hits) == 1
    hit = hits[0]
    assert hit.message == f"Randomized device present: {MAC} at -45 dBm for at least 10 min"
    assert hit.severity == "med"
    assert hit.mac == MAC
    assert hit.rule_type == "randomized_device_present"
    assert hit.rule_name == "someone_inside"


def test_9_minute_run_is_under_dwell_and_misses(db):
    _seed(db, MAC, _every_60s(9), -45)
    hits = evaluate(Ruleset(rules=[_rule()]), _obs(), True, db=db)
    assert hits == []


def test_walk_past_two_sightings_30s_apart_misses(db):
    _seed(db, MAC, [NOW - 30, NOW], -45)
    hits = evaluate(Ruleset(rules=[_rule()]), _obs(), True, db=db)
    assert hits == []


def test_a_wide_gap_resets_the_run(db):
    """6+6 min with a >5-min gap in the middle is not a 12-min run."""
    # Run A spans 360s and ends 400s before run B starts (400 >
    # PRESENCE_MAX_GAP_SECONDS), so the latest run is B alone at 360s.
    run_a = [NOW - 1120 + 60 * i for i in range(7)]
    run_b = [NOW - 360 + 60 * i for i in range(7)]
    _seed(db, MAC, run_a + run_b, -45)
    hits = evaluate(Ruleset(rules=[_rule()]), _obs(), True, db=db)
    assert hits == []


def test_non_randomized_mac_never_hits(db):
    _seed(db, MAC, _every_60s(11), -45)
    hits = evaluate(
        Ruleset(rules=[_rule()]), _obs(is_randomized=False), True, db=db
    )
    assert hits == []


def test_rssi_zero_rows_never_count_as_strong(db):
    """rssi 0 is a bogus reading on wired/virtual MACs; 20 minutes of it must
    not assemble a run even though the current observation is strong."""
    _seed(db, MAC, _every_60s(20), 0)
    _seed(db, MAC, [NOW], -45)
    hits = evaluate(Ruleset(rules=[_rule()]), _obs(), True, db=db)
    assert hits == []


def test_current_obs_weaker_than_threshold_misses_even_with_strong_history(db):
    _seed(db, MAC, _every_60s(11), -45)
    hits = evaluate(Ruleset(rules=[_rule()]), _obs(rssi=-70), True, db=db)
    assert hits == []


def test_rate_cap_blocks_at_the_cap_and_allows_under_it(db):
    """cap=2: with 1 alert row in the trailing hour the rule fires; with 2 it
    is at the cap and does not."""
    _seed(db, MAC_OTHER, [], -45)
    db.add_alert(
        ts=NOW - 120,
        rule_name="someone_inside",
        mac=MAC_OTHER,
        message="earlier alert for this rule",
        severity="med",
        rule_type="randomized_device_present",
    )
    _seed(db, MAC, _every_60s(11), -45)
    hits = evaluate(Ruleset(rules=[_rule(presence_max_alerts_per_hour=2)]), _obs(), True, db=db)
    assert len(hits) == 1

    db.add_alert(
        ts=NOW - 60,
        rule_name="someone_inside",
        mac=MAC_OTHER,
        message="second alert for this rule",
        severity="med",
        rule_type="randomized_device_present",
    )
    hits = evaluate(Ruleset(rules=[_rule(presence_max_alerts_per_hour=2)]), _obs(), True, db=db)
    assert hits == []


def test_shadow_rule_returns_nothing_and_lands_in_the_sink(db):
    _seed(db, MAC, _every_60s(11), -45)
    sink: list = []
    hits = evaluate(
        Ruleset(rules=[_rule(shadow=True)]), _obs(), True, db=db, shadow_sink=sink
    )
    assert hits == []
    assert len(sink) == 1
    assert sink[0].message == f"Randomized device present: {MAC} at -45 dBm for at least 10 min"


def test_allowlisted_mac_through_the_poller_path_writes_no_alert(tmp_path):
    """The allowlist is checked BEFORE evaluate, so a hard `mac` entry
    silences this rule_type without any new code."""
    allowlist_yaml = tmp_path / "allowlist.yaml"
    allowlist_yaml.write_text(
        textwrap.dedent(
            f"""
            entries:
              - pattern: "{MAC}"
                pattern_type: mac
                note: operator's own phone
            """
        ),
        encoding="utf-8",
    )
    cfg = Config(
        db_path=str(tmp_path / "s.db"),
        allowlist_path=str(allowlist_yaml),
        evidence_capture_enabled=False,
        kismet_health_check_on_startup=False,
    )
    db = Database(cfg.db_path)
    db.ensure_location("default", "Default")
    _seed(db, MAC, _every_60s(11), -45)
    try:
        ruleset = Ruleset(rules=[_rule()])
        process_observation(
            _obs(),
            db,
            cfg,
            NOW,
            effective_location_id="default",
            effective_location_label="Default",
            ensured_locations=set(),
            processed_counter=[0],
            admitted_counter=[0],
            ruleset=ruleset,
            allowlist=load_allowlist(str(allowlist_yaml)),
            notifier=_Recorder(),
            clock_trusted=True,
        )
        alerts = db._conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        assert alerts == 0
    finally:
        db.close()


def test_the_poller_path_alerts_when_not_allowlisted(tmp_path):
    """Presence beside the silence above: the same qualifying observation
    without the allowlist entry raises exactly one alert row, so the silence
    test cannot pass on a rule that never fires."""
    allowlist_yaml = tmp_path / "allowlist.yaml"
    allowlist_yaml.write_text("entries: []\n", encoding="utf-8")
    cfg = Config(
        db_path=str(tmp_path / "s.db"),
        allowlist_path=str(allowlist_yaml),
        evidence_capture_enabled=False,
        kismet_health_check_on_startup=False,
    )
    db = Database(cfg.db_path)
    db.ensure_location("default", "Default")
    _seed(db, MAC, _every_60s(11), -45)
    try:
        process_observation(
            _obs(),
            db,
            cfg,
            NOW,
            effective_location_id="default",
            effective_location_label="Default",
            ensured_locations=set(),
            processed_counter=[0],
            admitted_counter=[0],
            ruleset=Ruleset(rules=[_rule()]),
            allowlist=load_allowlist(str(allowlist_yaml)),
            notifier=_Recorder(),
            clock_trusted=True,
        )
        rows = db._conn.execute(
            "SELECT rule_name, mac, rule_type FROM alerts"
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["rule_name"] == "someone_inside"
        assert rows[0]["mac"] == MAC
        assert rows[0]["rule_type"] == "randomized_device_present"
    finally:
        db.close()


# ------------------------------- validation ---------------------------------


def test_missing_presence_min_rssi_rejected():
    with pytest.raises(ValidationError):
        Rule(name="x", rule_type="randomized_device_present", severity="med")


@pytest.mark.parametrize("rssi", [0, 5, -101])
def test_out_of_range_presence_min_rssi_rejected(rssi):
    with pytest.raises(ValidationError):
        Rule(
            name="x",
            rule_type="randomized_device_present",
            severity="med",
            presence_min_rssi=rssi,
        )


@pytest.mark.parametrize("rssi", [-100, -1])
def test_inclusive_presence_min_rssi_bounds_accepted(rssi):
    rule = Rule(
        name="x",
        rule_type="randomized_device_present",
        severity="med",
        presence_min_rssi=rssi,
    )
    assert rule.presence_min_rssi == rssi


def test_dwell_below_60_rejected():
    with pytest.raises(ValidationError):
        Rule(
            name="x",
            rule_type="randomized_device_present",
            severity="med",
            presence_min_rssi=-55,
            presence_min_dwell_seconds=30,
        )


def test_alerts_per_hour_below_1_rejected():
    with pytest.raises(ValidationError):
        Rule(
            name="x",
            rule_type="randomized_device_present",
            severity="med",
            presence_min_rssi=-55,
            presence_max_alerts_per_hour=0,
        )


def test_non_empty_patterns_rejected():
    with pytest.raises(ValidationError):
        Rule(
            name="x",
            rule_type="randomized_device_present",
            severity="med",
            presence_min_rssi=-55,
            patterns=["5a:00:00:00:00:01"],
        )


def test_presence_fields_rejected_on_other_rule_types():
    with pytest.raises(ValidationError) as exc:
        Rule(
            name="x",
            rule_type="new_non_randomized_device",
            severity="med",
            presence_min_rssi=-55,
        )
    assert "presence_min_rssi" in str(exc.value)
    with pytest.raises(ValidationError):
        Rule(
            name="x",
            rule_type="watchlist_mac",
            severity="med",
            patterns=["5a:00:00:00:00:01"],
            presence_min_dwell_seconds=600,
        )


def test_defaults_applied():
    rule = Rule(
        name="x",
        rule_type="randomized_device_present",
        severity="med",
        presence_min_rssi=-55,
    )
    assert rule.presence_min_dwell_seconds == 600
    assert rule.presence_max_alerts_per_hour == 6


def test_db_none_is_no_hit_and_no_exception(db):
    _seed(db, MAC, _every_60s(11), -45)
    # The rule is capable of hitting with this exact DB, so a None db is the
    # only reason the call below returns [].
    with_db = evaluate(Ruleset(rules=[_rule()]), _obs(), True, db=db)
    assert len(with_db) == 1
    hits = evaluate(Ruleset(rules=[_rule()]), _obs(), True, db=None)
    assert hits == []
