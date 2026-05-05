"""Tests for the detection rules engine."""

from pathlib import Path

import pytest
from pydantic import ValidationError

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
