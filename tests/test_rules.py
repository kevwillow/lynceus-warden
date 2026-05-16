"""Tests for the detection rules engine."""

import logging
from pathlib import Path

import pytest
from pydantic import ValidationError

from lynceus.db import Database
from lynceus.kismet import DeviceObservation
from lynceus.rules import Rule, RuleHit, Ruleset, evaluate, load_ruleset

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "rules_example.yaml"


def _obs(
    mac: str = "a4:83:e7:11:22:33",
    ssid: str | None = None,
    is_randomized: bool = False,
    oui_vendor: str | None = "Apple",
) -> DeviceObservation:
    return DeviceObservation(
        mac=mac,
        device_type="wifi",
        first_seen=1700000000,
        last_seen=1700000100,
        rssi=-50,
        ssid=ssid,
        oui_vendor=oui_vendor,
        is_randomized=is_randomized,
    )


# -------------------------------- load_ruleset -------------------------------


def test_load_empty_ruleset_file(tmp_path):
    p = tmp_path / "rules.yaml"
    p.write_text("", encoding="utf-8")
    rs = load_ruleset(str(p))
    assert isinstance(rs, Ruleset)
    assert rs.rules == []


def test_load_with_rules_from_fixture():
    rs = load_ruleset(str(FIXTURE_PATH))
    assert [r.name for r in rs.rules] == [
        "hak5_pineapple_oui",
        "known_bad_mac",
        "rogue_ssids",
        "new_device_alert",
        "temporarily_disabled",
    ]
    assert rs.rules[-1].enabled is False


# ------------------------------- rejected input ------------------------------


def test_invalid_rule_type_rejected():
    with pytest.raises(ValidationError):
        Rule(
            name="bogus",
            rule_type="watchlist_bssid",
            severity="low",
            patterns=["aa:bb:cc"],
        )


def test_watchlist_with_empty_patterns_rejected():
    with pytest.raises(ValidationError):
        Rule(name="empty", rule_type="watchlist_mac", severity="low", patterns=[])


def test_new_non_randomized_device_with_patterns_rejected():
    with pytest.raises(ValidationError):
        Rule(
            name="bad",
            rule_type="new_non_randomized_device",
            severity="low",
            patterns=["aa:bb:cc:dd:ee:ff"],
        )


def test_invalid_severity_rejected():
    with pytest.raises(ValidationError):
        Rule(
            name="severity",
            rule_type="watchlist_mac",
            severity="critical",
            patterns=["aa:bb:cc:dd:ee:ff"],
        )


def test_invalid_mac_pattern_rejected():
    with pytest.raises(ValidationError):
        Rule(
            name="bad_mac",
            rule_type="watchlist_mac",
            severity="low",
            patterns=["not-a-mac"],
        )


def test_invalid_oui_pattern_rejected():
    with pytest.raises(ValidationError):
        Rule(
            name="bad_oui",
            rule_type="watchlist_oui",
            severity="low",
            patterns=["aa:bb"],
        )


def test_duplicate_rule_names_rejected():
    r1 = Rule(name="dup", rule_type="watchlist_mac", severity="low", patterns=["aa:bb:cc:dd:ee:ff"])
    r2 = Rule(name="dup", rule_type="watchlist_mac", severity="low", patterns=["11:22:33:44:55:66"])
    with pytest.raises(ValidationError):
        Ruleset(rules=[r1, r2])


def test_extra_field_rejected():
    with pytest.raises(ValidationError):
        Rule(
            name="extra",
            rule_type="watchlist_mac",
            severity="low",
            patterns=["aa:bb:cc:dd:ee:ff"],
            color="red",
        )


# ---------------------------------- evaluate ---------------------------------


def test_disabled_rule_skipped_in_evaluate():
    rule = Rule(
        name="disabled",
        rule_type="watchlist_mac",
        severity="high",
        patterns=["a4:83:e7:11:22:33"],
        enabled=False,
    )
    rs = Ruleset(rules=[rule])
    assert evaluate(rs, _obs(mac="a4:83:e7:11:22:33"), is_new_device=False) == []


def test_evaluate_watchlist_mac_hit():
    rule = Rule(
        name="hit",
        rule_type="watchlist_mac",
        severity="high",
        patterns=["a4:83:e7:11:22:33"],
    )
    rs = Ruleset(rules=[rule])
    hits = evaluate(rs, _obs(mac="a4:83:e7:11:22:33"), is_new_device=False)
    assert len(hits) == 1
    assert hits[0].rule_name == "hit"
    assert hits[0].severity == "high"
    assert hits[0].mac == "a4:83:e7:11:22:33"


def test_evaluate_watchlist_mac_uppercase_pattern_normalized():
    rule = Rule(
        name="upper",
        rule_type="watchlist_mac",
        severity="high",
        patterns=["A4:83:E7:11:22:33"],
    )
    rs = Ruleset(rules=[rule])
    hits = evaluate(rs, _obs(mac="a4:83:e7:11:22:33"), is_new_device=False)
    assert len(hits) == 1


def test_evaluate_watchlist_mac_miss():
    rule = Rule(
        name="miss",
        rule_type="watchlist_mac",
        severity="high",
        patterns=["aa:bb:cc:dd:ee:ff"],
    )
    rs = Ruleset(rules=[rule])
    assert evaluate(rs, _obs(mac="11:22:33:44:55:66"), is_new_device=False) == []


def test_evaluate_watchlist_oui_hit():
    rule = Rule(
        name="oui",
        rule_type="watchlist_oui",
        severity="high",
        patterns=["00:13:37"],
    )
    rs = Ruleset(rules=[rule])
    hits = evaluate(rs, _obs(mac="00:13:37:aa:bb:cc"), is_new_device=False)
    assert len(hits) == 1
    assert hits[0].rule_name == "oui"


def test_evaluate_watchlist_oui_miss():
    rule = Rule(
        name="oui",
        rule_type="watchlist_oui",
        severity="high",
        patterns=["00:13:37"],
    )
    rs = Ruleset(rules=[rule])
    assert evaluate(rs, _obs(mac="00:13:38:aa:bb:cc"), is_new_device=False) == []


def test_evaluate_watchlist_ssid_hit():
    rule = Rule(
        name="ssid",
        rule_type="watchlist_ssid",
        severity="med",
        patterns=["FreeAirportWiFi"],
    )
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="aa:bb:cc:dd:ee:ff", ssid="FreeAirportWiFi"),
        is_new_device=False,
    )
    assert len(hits) == 1
    assert hits[0].rule_name == "ssid"


def test_evaluate_watchlist_ssid_miss_when_obs_ssid_none():
    rule = Rule(
        name="ssid",
        rule_type="watchlist_ssid",
        severity="med",
        patterns=["FreeAirportWiFi"],
    )
    rs = Ruleset(rules=[rule])
    assert evaluate(rs, _obs(mac="aa:bb:cc:dd:ee:ff", ssid=None), is_new_device=False) == []


def test_evaluate_new_non_randomized_device_hit():
    rule = Rule(name="new", rule_type="new_non_randomized_device", severity="low")
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="a4:83:e7:11:22:33", is_randomized=False),
        is_new_device=True,
    )
    assert len(hits) == 1
    assert hits[0].rule_name == "new"


def test_evaluate_new_non_randomized_device_no_hit_when_randomized():
    rule = Rule(name="new", rule_type="new_non_randomized_device", severity="low")
    rs = Ruleset(rules=[rule])
    assert (
        evaluate(
            rs,
            _obs(mac="02:11:22:33:44:55", is_randomized=True),
            is_new_device=True,
        )
        == []
    )


def test_evaluate_new_non_randomized_device_no_hit_when_not_new():
    rule = Rule(name="new", rule_type="new_non_randomized_device", severity="low")
    rs = Ruleset(rules=[rule])
    assert (
        evaluate(
            rs,
            _obs(mac="a4:83:e7:11:22:33", is_randomized=False),
            is_new_device=False,
        )
        == []
    )


def test_evaluate_multiple_hits_single_observation():
    mac_rule = Rule(
        name="mac_hit",
        rule_type="watchlist_mac",
        severity="high",
        patterns=["a4:83:e7:11:22:33"],
    )
    new_rule = Rule(
        name="new_dev",
        rule_type="new_non_randomized_device",
        severity="low",
    )
    rs = Ruleset(rules=[mac_rule, new_rule])
    hits = evaluate(
        rs,
        _obs(mac="a4:83:e7:11:22:33", is_randomized=False),
        is_new_device=True,
    )
    assert len(hits) == 2
    assert {h.rule_name for h in hits} == {"mac_hit", "new_dev"}
    assert all(isinstance(h, RuleHit) for h in hits)


def test_evaluate_message_format_includes_mac_and_description():
    rule = Rule(
        name="known_bad",
        rule_type="watchlist_mac",
        severity="high",
        patterns=["a4:83:e7:11:22:33"],
        description="Stolen laptop",
    )
    rs = Ruleset(rules=[rule])
    hits = evaluate(rs, _obs(mac="a4:83:e7:11:22:33"), is_new_device=False)
    assert hits[0].message == "MAC a4:83:e7:11:22:33 on watchlist: Stolen laptop"


def test_evaluate_returns_empty_list_when_no_matches():
    rule = Rule(
        name="never",
        rule_type="watchlist_mac",
        severity="high",
        patterns=["de:ad:be:ef:00:01"],
    )
    rs = Ruleset(rules=[rule])
    assert evaluate(rs, _obs(mac="11:22:33:44:55:66"), is_new_device=False) == []


# ---------------------------------- ble_uuid -------------------------------

_AIRTAG_UUID = "0000fd5a-0000-1000-8000-00805f9b34fb"
_TILE_UUID = "0000feed-0000-1000-8000-00805f9b34fb"


def _ble_obs(
    mac: str = "7a:bb:cc:dd:ee:ff",
    uuids: tuple[str, ...] = (),
) -> DeviceObservation:
    return DeviceObservation(
        mac=mac,
        device_type="ble",
        first_seen=1700000000,
        last_seen=1700000100,
        rssi=-80,
        ssid=None,
        oui_vendor="Apple",
        is_randomized=True,
        ble_service_uuids=uuids,
    )


def test_ble_uuid_rule_normalizes_pattern_uppercase():
    rule = Rule(
        name="airtag",
        rule_type="ble_uuid",
        severity="high",
        patterns=["0000FD5A-0000-1000-8000-00805F9B34FB"],
    )
    assert rule.patterns == [_AIRTAG_UUID]


def test_ble_uuid_rule_rejects_malformed_pattern():
    with pytest.raises(ValidationError):
        Rule(
            name="bad",
            rule_type="ble_uuid",
            severity="high",
            patterns=["fd5a"],
        )


def test_ble_uuid_rule_empty_patterns_rejected():
    with pytest.raises(ValidationError):
        Rule(name="empty", rule_type="ble_uuid", severity="high", patterns=[])


def test_evaluate_ble_uuid_hit():
    rule = Rule(
        name="airtag",
        rule_type="ble_uuid",
        severity="high",
        patterns=[_AIRTAG_UUID],
    )
    rs = Ruleset(rules=[rule])
    hits = evaluate(rs, _ble_obs(uuids=(_AIRTAG_UUID,)), is_new_device=False)
    assert len(hits) == 1
    assert hits[0].rule_name == "airtag"
    assert hits[0].severity == "high"


def test_evaluate_ble_uuid_miss():
    rule = Rule(
        name="airtag",
        rule_type="ble_uuid",
        severity="high",
        patterns=[_AIRTAG_UUID],
    )
    rs = Ruleset(rules=[rule])
    assert evaluate(rs, _ble_obs(uuids=(_TILE_UUID,)), is_new_device=False) == []


def test_evaluate_ble_uuid_message_format_includes_first_matched_uuid():
    rule = Rule(
        name="trackers",
        rule_type="ble_uuid",
        severity="high",
        patterns=[_AIRTAG_UUID, _TILE_UUID],
        description="Known trackers",
    )
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _ble_obs(mac="7a:bb:cc:dd:ee:ff", uuids=(_TILE_UUID, _AIRTAG_UUID)),
        is_new_device=False,
    )
    assert len(hits) == 1
    assert hits[0].message == (
        f"BLE service UUID {_AIRTAG_UUID} on watchlist: Known trackers (mac 7a:bb:cc:dd:ee:ff)"
    )


# -------------------- watchlist_mac_range (DB-delegated) --------------------
#
# The first DB-delegated rule_type in Lynceus. Two structural divergences
# from every other watchlist_* rule type, tested explicitly:
#
#   1. Patterns MUST be empty (validator carve-out). A single rule entry
#      enables alert-firing for every matching watchlist mac_range row.
#   2. Severity sources from the matched DB row, not from rule.severity.
#      The importer wrote per-row severity from device_category for a
#      reason; reading it back is the only path that respects that data.


@pytest.fixture
def db_with_mac_range(tmp_path):
    """Database fixture seeded with two mac_range rows (one /28 high,
    one /36 low) — covers severity-from-DB assertion and prefix-length
    coverage for the eval branch."""
    db_path = str(tmp_path / "rules_macrange.db")
    db = Database(db_path)
    with db._conn:
        db._conn.execute(
            "INSERT INTO watchlist("
            "pattern, pattern_type, severity, description, "
            "mac_range_prefix, mac_range_prefix_length) "
            "VALUES (?, 'mac_range', ?, NULL, ?, ?)",
            ("aa:bb:cc:d/28", "high", "aabbccd", 28),
        )
        db._conn.execute(
            "INSERT INTO watchlist("
            "pattern, pattern_type, severity, description, "
            "mac_range_prefix, mac_range_prefix_length) "
            "VALUES (?, 'mac_range', ?, NULL, ?, ?)",
            ("11:22:33:44:e/36", "low", "11223344e", 36),
        )
    yield db
    db.close()


def test_watchlist_mac_range_rule_rejects_non_empty_patterns():
    """Validator carve-out: patterns must be empty for this rule_type.
    The rules engine delegates matching to the watchlist DB; per-rule
    patterns have no semantics here."""
    with pytest.raises(ValidationError) as excinfo:
        Rule(
            name="bad_macrange",
            rule_type="watchlist_mac_range",
            severity="med",
            patterns=["aa:bb:cc:d/28"],
        )
    assert "patterns must be empty" in str(excinfo.value)


def test_watchlist_mac_range_rule_accepts_empty_patterns():
    """Empty patterns is the required idiom. severity in the rule is
    informational only — the consuming evaluate() branch sources
    severity from the matched watchlist row, not the rule."""
    rule = Rule(
        name="argus_mac_range",
        rule_type="watchlist_mac_range",
        severity="low",
        patterns=[],
    )
    assert rule.patterns == []
    assert rule.rule_type == "watchlist_mac_range"


def test_evaluate_watchlist_mac_range_28_hit_sources_severity_from_db(db_with_mac_range):
    """A MAC inside a watchlisted /28 (severity 'high' in the DB row)
    must produce a hit whose severity is 'high' — NOT the rule's
    severity. This is the explicit divergence from the other
    watchlist_* rule types and the central reason this rule_type
    exists."""
    rule = Rule(
        name="argus_mac_range",
        rule_type="watchlist_mac_range",
        severity="low",
        patterns=[],
    )
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="aa:bb:cc:d1:23:45"),
        is_new_device=False,
        db=db_with_mac_range,
    )
    assert len(hits) == 1
    assert hits[0].rule_name == "argus_mac_range"
    assert hits[0].severity == "high"
    assert hits[0].mac == "aa:bb:cc:d1:23:45"
    assert "watchlisted mac_range (/28" in hits[0].message


def test_evaluate_watchlist_mac_range_36_hit_sources_severity_from_db(db_with_mac_range):
    """The /36 fixture row has severity 'low'. The hit's severity must
    match it, regardless of the rule's severity field."""
    rule = Rule(
        name="argus_mac_range",
        rule_type="watchlist_mac_range",
        severity="high",
        patterns=[],
    )
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="11:22:33:44:e7:89"),
        is_new_device=False,
        db=db_with_mac_range,
    )
    assert len(hits) == 1
    assert hits[0].severity == "low"
    assert "watchlisted mac_range (/36" in hits[0].message


def test_evaluate_watchlist_mac_range_miss(db_with_mac_range):
    rule = Rule(
        name="argus_mac_range",
        rule_type="watchlist_mac_range",
        severity="low",
        patterns=[],
    )
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="ff:ee:dd:cc:bb:aa"),
        is_new_device=False,
        db=db_with_mac_range,
    )
    assert hits == []


def test_evaluate_watchlist_mac_range_without_db_logs_error(caplog):
    """Defensive: evaluate() with a watchlist_mac_range rule in the
    ruleset but db=None must log an ERROR and skip — silently
    dropping the hit would be worse than a loud failure. The error
    text names the rule and explains the contract."""
    rule = Rule(
        name="argus_mac_range",
        rule_type="watchlist_mac_range",
        severity="low",
        patterns=[],
    )
    rs = Ruleset(rules=[rule])
    with caplog.at_level(logging.ERROR, logger="lynceus.rules"):
        hits = evaluate(rs, _obs(mac="aa:bb:cc:d1:23:45"), is_new_device=False)
    assert hits == []
    errors = [
        r for r in caplog.records
        if r.levelno == logging.ERROR
        and "watchlist_mac_range" in r.getMessage()
        and "argus_mac_range" in r.getMessage()
    ]
    assert len(errors) == 1


def test_evaluate_existing_rule_types_unaffected_by_optional_db_kwarg():
    """Regression guard: the new optional db= kwarg must not break
    callers that don't pass it. Pre-Part-2 test_rules callsites
    (18 of them) all invoke evaluate(rs, obs, is_new_device=...)
    positionally and they must continue to pass. This test mirrors
    the canonical watchlist_mac hit shape — if the signature change
    introduced a regression it would surface here loudly."""
    rule = Rule(
        name="hit",
        rule_type="watchlist_mac",
        severity="high",
        patterns=["a4:83:e7:11:22:33"],
    )
    rs = Ruleset(rules=[rule])
    hits = evaluate(rs, _obs(mac="a4:83:e7:11:22:33"), is_new_device=False)
    assert len(hits) == 1
    assert hits[0].severity == "high"
