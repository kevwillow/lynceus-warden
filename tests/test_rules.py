"""Tests for the detection rules engine."""

import logging
from pathlib import Path

import pytest
from pydantic import ValidationError

from lynceus.db import Database
from lynceus.kismet import DeviceObservation
from lynceus.rules import (
    Rule,
    RuleHit,
    Ruleset,
    RuntimeSeverityOverride,
    evaluate,
    load_ruleset,
)

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


def test_watchlist_mac_range_with_empty_patterns_required_carve_out():
    """The watchlist_mac_range carve-out: empty patterns is REQUIRED
    here (the rule_type has no in-memory match semantic — patterns
    are CIDR-shaped, not equality-shaped). Distinct from the four
    delegation-capable types (mac/oui/ssid/ble_uuid) which accept
    BOTH empty (delegate) and non-empty (in-memory) shapes."""
    rule = Rule(
        name="argus_mac_range",
        rule_type="watchlist_mac_range",
        severity="low",
        patterns=[],
    )
    assert rule.patterns == []


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


def test_ble_uuid_rule_empty_patterns_accepted_delegation_mode():
    """Updated semantic (formerly rejected): ble_uuid joins the four
    delegation-capable types — empty patterns is now valid and
    activates the DB-delegation path. Mirrors the validator carve-out
    structure exercised by the watchlist_{mac,oui,ssid} delegation
    tests below."""
    rule = Rule(name="empty", rule_type="ble_uuid", severity="high", patterns=[])
    assert rule.patterns == []
    assert rule.rule_type == "ble_uuid"


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


# ---- watchlist delegation extension ----------------------------------------
#
# Extends the empty-patterns-delegates-to-DB semantic established by
# watchlist_mac_range (Part 2) to watchlist_mac, watchlist_oui,
# watchlist_ssid, and ble_uuid. The four blocks below mirror each
# other deliberately — same validator-accepts-empty test, same
# delegation-hit test (severity-from-DB assertion), same in-memory
# regression test (severity-from-rule assertion preserves backward
# compat), same db-None error-log test.


@pytest.fixture
def db_with_delegation_rows(tmp_path):
    """Seed one watchlist row per delegation-capable pattern_type so
    each rule_type has something to match against. Severities chosen
    distinct from the rule severities below to make the
    severity-from-DB assertion unambiguous."""
    db_path = str(tmp_path / "rules_delegation.db")
    db = Database(db_path)
    with db._conn:
        # mac row at high severity (rule severity below is "low" so the
        # severity-from-DB contract is observable).
        db._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
            "VALUES (?, 'mac', 'high', 'delegated mac')",
            ("a4:83:e7:11:22:33",),
        )
        # oui row at med severity.
        db._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
            "VALUES (?, 'oui', 'med', 'delegated oui')",
            ("00:13:37",),
        )
        # ssid row at high severity.
        db._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
            "VALUES (?, 'ssid', 'high', 'delegated ssid')",
            ("FreeAirportWiFi",),
        )
        # ble_uuid row at med severity.
        db._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
            "VALUES (?, 'ble_uuid', 'med', 'delegated ble')",
            (_AIRTAG_UUID,),
        )
    yield db
    db.close()


# ---- watchlist_mac delegation ----


def test_watchlist_mac_with_empty_patterns_accepted_delegation_mode():
    """Validator: empty patterns is the delegation idiom. severity in
    the rule is informational only — the consuming evaluate() branch
    sources severity from the matched watchlist row."""
    rule = Rule(name="del_mac", rule_type="watchlist_mac", severity="low", patterns=[])
    assert rule.patterns == []
    assert rule.rule_type == "watchlist_mac"


def test_watchlist_mac_with_non_empty_patterns_accepted_in_memory_mode():
    """Validator regression: non-empty patterns continues to be
    accepted (the in-memory match path that pre-existing rules.yaml
    deployments rely on)."""
    rule = Rule(
        name="legacy_mac",
        rule_type="watchlist_mac",
        severity="high",
        patterns=["a4:83:e7:11:22:33"],
    )
    assert rule.patterns == ["a4:83:e7:11:22:33"]


def test_evaluate_watchlist_mac_delegation_hit_sources_severity_from_db(
    db_with_delegation_rows,
):
    """Empty patterns + a matching DB row → hit with severity FROM
    THE DB ROW (not from rule.severity, which is 'low' here). This is
    the central invariant of the delegation semantic."""
    rule = Rule(name="del_mac", rule_type="watchlist_mac", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="a4:83:e7:11:22:33"),
        is_new_device=False,
        db=db_with_delegation_rows,
    )
    assert len(hits) == 1
    assert hits[0].rule_name == "del_mac"
    assert hits[0].severity == "high"  # from DB, not "low"
    assert hits[0].mac == "a4:83:e7:11:22:33"


def test_evaluate_watchlist_mac_delegation_miss(db_with_delegation_rows):
    """Empty patterns + no matching DB row → no hit."""
    rule = Rule(name="del_mac", rule_type="watchlist_mac", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="ff:ee:dd:cc:bb:aa"),
        is_new_device=False,
        db=db_with_delegation_rows,
    )
    assert hits == []


def test_evaluate_watchlist_mac_in_memory_path_severity_from_rule_unchanged():
    """Backward compat regression: non-empty patterns continues to
    use the in-memory match path with severity sourced from the rule.
    No DB consulted, no behavior change for pre-existing deployments."""
    rule = Rule(
        name="legacy_mac",
        rule_type="watchlist_mac",
        severity="high",
        patterns=["a4:83:e7:11:22:33"],
    )
    rs = Ruleset(rules=[rule])
    hits = evaluate(rs, _obs(mac="a4:83:e7:11:22:33"), is_new_device=False)
    assert len(hits) == 1
    assert hits[0].severity == "high"  # from rule


def test_evaluate_watchlist_mac_delegation_without_db_logs_error(caplog):
    """Defensive: empty patterns + db=None must log ERROR and skip
    rather than silently dropping the hit."""
    rule = Rule(name="del_mac", rule_type="watchlist_mac", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    with caplog.at_level(logging.ERROR, logger="lynceus.rules"):
        hits = evaluate(rs, _obs(mac="a4:83:e7:11:22:33"), is_new_device=False)
    assert hits == []
    errors = [
        r for r in caplog.records
        if r.levelno == logging.ERROR
        and "watchlist_mac" in r.getMessage()
        and "del_mac" in r.getMessage()
    ]
    assert len(errors) == 1


# ---- watchlist_oui delegation ----


def test_watchlist_oui_with_empty_patterns_accepted_delegation_mode():
    rule = Rule(name="del_oui", rule_type="watchlist_oui", severity="low", patterns=[])
    assert rule.patterns == []


def test_watchlist_oui_with_non_empty_patterns_accepted_in_memory_mode():
    """Backward compat: existing patterns-based watchlist_oui rules
    continue to validate."""
    rule = Rule(
        name="legacy_oui",
        rule_type="watchlist_oui",
        severity="high",
        patterns=["00:13:37"],
    )
    assert rule.patterns == ["00:13:37"]


def test_evaluate_watchlist_oui_delegation_hit_sources_severity_from_db(
    db_with_delegation_rows,
):
    """Empty patterns + observation MAC whose OUI matches a DB row →
    hit with severity FROM THE DB ROW (the seeded oui row is 'med';
    rule severity is 'low')."""
    rule = Rule(name="del_oui", rule_type="watchlist_oui", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="00:13:37:aa:bb:cc"),
        is_new_device=False,
        db=db_with_delegation_rows,
    )
    assert len(hits) == 1
    assert hits[0].severity == "med"  # from DB
    assert hits[0].mac == "00:13:37:aa:bb:cc"


def test_evaluate_watchlist_oui_delegation_miss(db_with_delegation_rows):
    rule = Rule(name="del_oui", rule_type="watchlist_oui", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="ff:ee:dd:cc:bb:aa"),
        is_new_device=False,
        db=db_with_delegation_rows,
    )
    assert hits == []


def test_evaluate_watchlist_oui_in_memory_path_severity_from_rule_unchanged():
    """Backward compat: non-empty patterns → in-memory match,
    severity from rule."""
    rule = Rule(
        name="legacy_oui",
        rule_type="watchlist_oui",
        severity="high",
        patterns=["00:13:37"],
    )
    rs = Ruleset(rules=[rule])
    hits = evaluate(rs, _obs(mac="00:13:37:aa:bb:cc"), is_new_device=False)
    assert len(hits) == 1
    assert hits[0].severity == "high"


def test_evaluate_watchlist_oui_delegation_without_db_logs_error(caplog):
    rule = Rule(name="del_oui", rule_type="watchlist_oui", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    with caplog.at_level(logging.ERROR, logger="lynceus.rules"):
        hits = evaluate(rs, _obs(mac="00:13:37:aa:bb:cc"), is_new_device=False)
    assert hits == []
    errors = [
        r for r in caplog.records
        if r.levelno == logging.ERROR and "watchlist_oui" in r.getMessage()
    ]
    assert len(errors) == 1


# ---- watchlist_ssid delegation ----


def test_watchlist_ssid_with_empty_patterns_accepted_delegation_mode():
    rule = Rule(name="del_ssid", rule_type="watchlist_ssid", severity="low", patterns=[])
    assert rule.patterns == []


def test_watchlist_ssid_with_non_empty_patterns_accepted_in_memory_mode():
    rule = Rule(
        name="legacy_ssid",
        rule_type="watchlist_ssid",
        severity="med",
        patterns=["FreeAirportWiFi"],
    )
    assert rule.patterns == ["FreeAirportWiFi"]


def test_evaluate_watchlist_ssid_delegation_hit_sources_severity_from_db(
    db_with_delegation_rows,
):
    """Empty patterns + obs.ssid matching a DB row → hit with severity
    from the DB row ('high'; rule severity is 'low')."""
    rule = Rule(name="del_ssid", rule_type="watchlist_ssid", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="aa:bb:cc:dd:ee:ff", ssid="FreeAirportWiFi"),
        is_new_device=False,
        db=db_with_delegation_rows,
    )
    assert len(hits) == 1
    assert hits[0].severity == "high"


def test_evaluate_watchlist_ssid_delegation_miss(db_with_delegation_rows):
    rule = Rule(name="del_ssid", rule_type="watchlist_ssid", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="aa:bb:cc:dd:ee:ff", ssid="something_else"),
        is_new_device=False,
        db=db_with_delegation_rows,
    )
    assert hits == []


def test_evaluate_watchlist_ssid_delegation_no_ssid_no_hit(db_with_delegation_rows):
    """Observations without a captured SSID can't match a delegated
    watchlist_ssid rule — same shape as the in-memory branch's
    obs.ssid is None guard."""
    rule = Rule(name="del_ssid", rule_type="watchlist_ssid", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="aa:bb:cc:dd:ee:ff", ssid=None),
        is_new_device=False,
        db=db_with_delegation_rows,
    )
    assert hits == []


def test_evaluate_watchlist_ssid_in_memory_path_severity_from_rule_unchanged():
    rule = Rule(
        name="legacy_ssid",
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
    assert hits[0].severity == "med"


def test_evaluate_watchlist_ssid_delegation_without_db_logs_error(caplog):
    rule = Rule(name="del_ssid", rule_type="watchlist_ssid", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    with caplog.at_level(logging.ERROR, logger="lynceus.rules"):
        hits = evaluate(
            rs,
            _obs(mac="aa:bb:cc:dd:ee:ff", ssid="FreeAirportWiFi"),
            is_new_device=False,
        )
    assert hits == []
    errors = [
        r for r in caplog.records
        if r.levelno == logging.ERROR and "watchlist_ssid" in r.getMessage()
    ]
    assert len(errors) == 1


# ---- ble_uuid delegation ----


def test_ble_uuid_with_non_empty_patterns_accepted_in_memory_mode():
    rule = Rule(
        name="legacy_ble",
        rule_type="ble_uuid",
        severity="high",
        patterns=[_AIRTAG_UUID],
    )
    assert rule.patterns == [_AIRTAG_UUID]


def test_evaluate_ble_uuid_delegation_hit_sources_severity_from_db(
    db_with_delegation_rows,
):
    """Empty patterns + obs.ble_service_uuids containing a watchlisted
    UUID → hit with severity from the DB row ('med'; rule severity
    'low')."""
    rule = Rule(name="del_ble", rule_type="ble_uuid", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _ble_obs(uuids=(_AIRTAG_UUID,)),
        is_new_device=False,
        db=db_with_delegation_rows,
    )
    assert len(hits) == 1
    assert hits[0].severity == "med"


def test_evaluate_ble_uuid_delegation_miss(db_with_delegation_rows):
    rule = Rule(name="del_ble", rule_type="ble_uuid", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _ble_obs(uuids=(_TILE_UUID,)),
        is_new_device=False,
        db=db_with_delegation_rows,
    )
    assert hits == []


def test_evaluate_ble_uuid_delegation_no_uuids_no_hit(db_with_delegation_rows):
    """Observations without service UUIDs cannot match a delegated
    ble_uuid rule."""
    rule = Rule(name="del_ble", rule_type="ble_uuid", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _ble_obs(uuids=()),
        is_new_device=False,
        db=db_with_delegation_rows,
    )
    assert hits == []


def test_evaluate_ble_uuid_in_memory_path_severity_from_rule_unchanged():
    rule = Rule(
        name="legacy_ble",
        rule_type="ble_uuid",
        severity="high",
        patterns=[_AIRTAG_UUID],
    )
    rs = Ruleset(rules=[rule])
    hits = evaluate(rs, _ble_obs(uuids=(_AIRTAG_UUID,)), is_new_device=False)
    assert len(hits) == 1
    assert hits[0].severity == "high"


def test_evaluate_ble_uuid_delegation_without_db_logs_error(caplog):
    rule = Rule(name="del_ble", rule_type="ble_uuid", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    with caplog.at_level(logging.ERROR, logger="lynceus.rules"):
        hits = evaluate(rs, _ble_obs(uuids=(_AIRTAG_UUID,)), is_new_device=False)
    assert hits == []
    errors = [
        r for r in caplog.records
        if r.levelno == logging.ERROR and "ble_uuid" in r.getMessage()
    ]
    assert len(errors) == 1


# ---- runtime severity overrides --------------------------------------------
#
# Per-branch coverage that the runtime override layer applies at the
# correct eval branch and obeys the documented precedence
# (suppression wins over remap; pass-through when overrides is None,
# is_empty(), or match has no device_category). Mirrors the five
# delegation branches (mac_range + four extension types).


def _attach_category(db: Database, watchlist_id: int, category: str) -> None:
    """Attach a watchlist_metadata row with the given device_category.
    The matchers LEFT JOIN watchlist_metadata so the category
    surfaces on the resolved match for the runtime layer to key on."""
    db.upsert_metadata(
        watchlist_id,
        {"argus_record_id": f"argus-{watchlist_id}", "device_category": category},
    )


@pytest.fixture
def db_with_categorized_rows(tmp_path):
    """Same shape as db_with_delegation_rows but with
    watchlist_metadata rows attached so each match surfaces a
    device_category. Five rows, one per pattern_type + the
    mac_range row, each at a distinct category so the runtime
    transform per branch is observable."""
    db_path = str(tmp_path / "rules_overrides.db")
    db = Database(db_path)
    with db._conn:
        cur = db._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
            "VALUES ('a4:83:e7:11:22:33', 'mac', 'low', NULL)"
        )
        mac_id = int(cur.lastrowid)
        cur = db._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
            "VALUES ('00:13:37', 'oui', 'low', NULL)"
        )
        oui_id = int(cur.lastrowid)
        cur = db._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
            "VALUES ('FreeAirportWiFi', 'ssid', 'low', NULL)"
        )
        ssid_id = int(cur.lastrowid)
        cur = db._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
            f"VALUES ('{_AIRTAG_UUID}', 'ble_uuid', 'low', NULL)"
        )
        ble_id = int(cur.lastrowid)
        cur = db._conn.execute(
            "INSERT INTO watchlist("
            "pattern, pattern_type, severity, description, "
            "mac_range_prefix, mac_range_prefix_length) "
            "VALUES ('aa:bb:cc:d/28', 'mac_range', 'low', NULL, 'aabbccd', 28)"
        )
        mr_id = int(cur.lastrowid)
    _attach_category(db, mac_id, "alpr")
    _attach_category(db, oui_id, "hacking_tool")
    _attach_category(db, ssid_id, "drone")
    _attach_category(db, ble_id, "imsi_catcher")
    _attach_category(db, mr_id, "unknown")
    yield db
    db.close()


# ---- per-branch: pass-through when overrides is None / empty ----


def test_evaluate_runtime_overrides_none_passes_through_severity(db_with_categorized_rows):
    """Backward-compat fast path: severity_overrides=None →
    byte-identical to pre-override behavior. The DB severity ("low"
    for all seeded rows) flows directly onto the RuleHit."""
    rule = Rule(name="del_mac", rule_type="watchlist_mac", severity="high", patterns=[])
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="a4:83:e7:11:22:33"),
        is_new_device=False,
        db=db_with_categorized_rows,
    )
    assert len(hits) == 1
    assert hits[0].severity == "low"  # from DB; rule severity ignored


def test_evaluate_runtime_overrides_empty_config_passes_through(db_with_categorized_rows):
    """An empty RuntimeSeverityOverride (no remap, no suppress) is
    a load-bearing pass-through case — the wizard's starter file
    produces this state until operator uncomments something."""
    rule = Rule(name="del_mac", rule_type="watchlist_mac", severity="high", patterns=[])
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="a4:83:e7:11:22:33"),
        is_new_device=False,
        db=db_with_categorized_rows,
        severity_overrides=RuntimeSeverityOverride(),
    )
    assert len(hits) == 1
    assert hits[0].severity == "low"


def test_evaluate_runtime_overrides_no_category_on_match_passes_through(tmp_path):
    """A delegation match against a row with NO watchlist_metadata
    (e.g. the 63 bundled default_watchlist rows) surfaces
    device_category=None. The runtime layer pass-throughs on None
    category regardless of how rich the override config is."""
    db_path = str(tmp_path / "no_meta.db")
    db = Database(db_path)
    with db._conn:
        db._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
            "VALUES ('a4:83:e7:11:22:33', 'mac', 'low', NULL)"
        )
    try:
        rule = Rule(name="del_mac", rule_type="watchlist_mac", severity="high", patterns=[])
        rs = Ruleset(rules=[rule])
        hits = evaluate(
            rs,
            _obs(mac="a4:83:e7:11:22:33"),
            is_new_device=False,
            db=db,
            severity_overrides=RuntimeSeverityOverride(
                device_category_severity={"alpr": "high"},
                suppress_categories=frozenset({"drone"}),
            ),
        )
        assert len(hits) == 1
        assert hits[0].severity == "low"  # passes through; no category to key on
    finally:
        db.close()


# ---- per-branch: remap applies ----


def test_evaluate_runtime_remap_watchlist_mac(db_with_categorized_rows):
    """watchlist_mac delegation hit on category=alpr; remap alpr→high
    should override the row's baked severity ("low") at alert time."""
    overrides = RuntimeSeverityOverride(device_category_severity={"alpr": "high"})
    rule = Rule(name="del_mac", rule_type="watchlist_mac", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="a4:83:e7:11:22:33"),
        is_new_device=False,
        db=db_with_categorized_rows,
        severity_overrides=overrides,
    )
    assert len(hits) == 1
    assert hits[0].severity == "high"  # remapped from "low"


def test_evaluate_runtime_remap_watchlist_oui(db_with_categorized_rows):
    overrides = RuntimeSeverityOverride(device_category_severity={"hacking_tool": "med"})
    rule = Rule(name="del_oui", rule_type="watchlist_oui", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="00:13:37:aa:bb:cc"),
        is_new_device=False,
        db=db_with_categorized_rows,
        severity_overrides=overrides,
    )
    assert len(hits) == 1
    assert hits[0].severity == "med"


def test_evaluate_runtime_remap_watchlist_ssid(db_with_categorized_rows):
    overrides = RuntimeSeverityOverride(device_category_severity={"drone": "high"})
    rule = Rule(name="del_ssid", rule_type="watchlist_ssid", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="aa:bb:cc:dd:ee:ff", ssid="FreeAirportWiFi"),
        is_new_device=False,
        db=db_with_categorized_rows,
        severity_overrides=overrides,
    )
    assert len(hits) == 1
    assert hits[0].severity == "high"


def test_evaluate_runtime_remap_ble_uuid(db_with_categorized_rows):
    overrides = RuntimeSeverityOverride(device_category_severity={"imsi_catcher": "med"})
    rule = Rule(name="del_ble", rule_type="ble_uuid", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _ble_obs(uuids=(_AIRTAG_UUID,)),
        is_new_device=False,
        db=db_with_categorized_rows,
        severity_overrides=overrides,
    )
    assert len(hits) == 1
    assert hits[0].severity == "med"


def test_evaluate_runtime_remap_watchlist_mac_range(db_with_categorized_rows):
    """Mirror of Part 2's mac_range branch under the runtime layer.
    Remap unknown→med means the 17,786 IEEE-registry rows
    (device_category=unknown) fire at "med" instead of the baked
    "low" without re-importing."""
    overrides = RuntimeSeverityOverride(device_category_severity={"unknown": "med"})
    rule = Rule(name="argus_mr", rule_type="watchlist_mac_range", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="aa:bb:cc:d1:23:45"),
        is_new_device=False,
        db=db_with_categorized_rows,
        severity_overrides=overrides,
    )
    assert len(hits) == 1
    assert hits[0].severity == "med"


def test_evaluate_runtime_remap_other_categories_unaffected(db_with_categorized_rows):
    """A remap that doesn't cover the match's category is a no-op
    on this match (the remap dict is per-category; non-listed
    categories pass through)."""
    overrides = RuntimeSeverityOverride(
        device_category_severity={"some_other_category": "high"}
    )
    rule = Rule(name="del_mac", rule_type="watchlist_mac", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="a4:83:e7:11:22:33"),  # category=alpr
        is_new_device=False,
        db=db_with_categorized_rows,
        severity_overrides=overrides,
    )
    assert len(hits) == 1
    assert hits[0].severity == "low"  # alpr unaffected


# ---- per-branch: suppression ----


def test_evaluate_runtime_suppress_watchlist_mac(db_with_categorized_rows, caplog):
    """suppress_categories listing alpr → the watchlist_mac
    delegation match on category=alpr emits NO RuleHit. An INFO
    log line records the suppression so operators have a forensic
    trail."""
    overrides = RuntimeSeverityOverride(suppress_categories=frozenset({"alpr"}))
    rule = Rule(name="del_mac", rule_type="watchlist_mac", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    with caplog.at_level(logging.INFO, logger="lynceus.rules"):
        hits = evaluate(
            rs,
            _obs(mac="a4:83:e7:11:22:33"),
            is_new_device=False,
            db=db_with_categorized_rows,
            severity_overrides=overrides,
        )
    assert hits == []
    info = [
        r for r in caplog.records
        if r.levelno == logging.INFO
        and "suppressing category=alpr" in r.getMessage()
        and "del_mac" in r.getMessage()
    ]
    assert len(info) == 1


def test_evaluate_runtime_suppress_watchlist_oui(db_with_categorized_rows):
    overrides = RuntimeSeverityOverride(suppress_categories=frozenset({"hacking_tool"}))
    rule = Rule(name="del_oui", rule_type="watchlist_oui", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="00:13:37:aa:bb:cc"),
        is_new_device=False,
        db=db_with_categorized_rows,
        severity_overrides=overrides,
    )
    assert hits == []


def test_evaluate_runtime_suppress_watchlist_ssid(db_with_categorized_rows):
    overrides = RuntimeSeverityOverride(suppress_categories=frozenset({"drone"}))
    rule = Rule(name="del_ssid", rule_type="watchlist_ssid", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="aa:bb:cc:dd:ee:ff", ssid="FreeAirportWiFi"),
        is_new_device=False,
        db=db_with_categorized_rows,
        severity_overrides=overrides,
    )
    assert hits == []


def test_evaluate_runtime_suppress_ble_uuid(db_with_categorized_rows):
    overrides = RuntimeSeverityOverride(suppress_categories=frozenset({"imsi_catcher"}))
    rule = Rule(name="del_ble", rule_type="ble_uuid", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _ble_obs(uuids=(_AIRTAG_UUID,)),
        is_new_device=False,
        db=db_with_categorized_rows,
        severity_overrides=overrides,
    )
    assert hits == []


def test_evaluate_runtime_suppress_watchlist_mac_range(db_with_categorized_rows):
    """An operator who wants the 17,786 IEEE-registry rows in the
    DB for metadata enrichment but doesn't want alerts on them
    can suppress category=unknown at runtime. Rows stay in the
    watchlist; only alerts are silenced."""
    overrides = RuntimeSeverityOverride(suppress_categories=frozenset({"unknown"}))
    rule = Rule(name="argus_mr", rule_type="watchlist_mac_range", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="aa:bb:cc:d1:23:45"),
        is_new_device=False,
        db=db_with_categorized_rows,
        severity_overrides=overrides,
    )
    assert hits == []


# ---- precedence: suppression wins over remap ----


def test_evaluate_runtime_suppress_wins_over_remap(db_with_categorized_rows):
    """When a category has BOTH a remap and a suppress entry,
    suppression wins. The documented precedence: vendor (deferred) >
    suppress > remap > pass-through."""
    overrides = RuntimeSeverityOverride(
        device_category_severity={"alpr": "high"},  # would remap to high
        suppress_categories=frozenset({"alpr"}),  # but suppress wins
    )
    rule = Rule(name="del_mac", rule_type="watchlist_mac", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="a4:83:e7:11:22:33"),
        is_new_device=False,
        db=db_with_categorized_rows,
        severity_overrides=overrides,
    )
    assert hits == []  # suppressed, not remapped


# ---- in-memory pattern rules are unaffected ----


def test_evaluate_in_memory_pattern_rule_ignores_runtime_overrides(db_with_categorized_rows):
    """Critical invariant: rules with non-empty patterns continue
    to source severity from the rule. Runtime overrides apply only
    to DB-delegation matches. An in-memory watchlist_mac rule with
    pattern matching the same MAC must still fire at rule.severity
    regardless of the override config."""
    overrides = RuntimeSeverityOverride(
        device_category_severity={"alpr": "low"},  # would lower if applied
        suppress_categories=frozenset({"alpr"}),  # would suppress if applied
    )
    rule = Rule(
        name="legacy_mac",
        rule_type="watchlist_mac",
        severity="high",
        patterns=["a4:83:e7:11:22:33"],  # NON-empty = in-memory path
    )
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="a4:83:e7:11:22:33"),
        is_new_device=False,
        db=db_with_categorized_rows,
        severity_overrides=overrides,
    )
    assert len(hits) == 1
    assert hits[0].severity == "high"  # from rule, not from DB or override


# ---- suppress_vendors (runtime vendor suppression) -------------------------
#
# Vendor suppression keys on watchlist_metadata.vendor (projected as
# ``manufacturer`` on the resolved match). Per the documented
# precedence, the vendor check runs BEFORE the category-driven
# checks — vendor is the more specific axis. Match comparison is
# normalized lowercase + strip on both sides.


def _attach_vendor(db: Database, watchlist_id: int, vendor: str) -> None:
    """Set vendor on an already-attached metadata row. The fixture's
    _attach_category call creates the metadata row; this one fills
    in the vendor column the LEFT JOIN projects as manufacturer."""
    with db._conn:
        db._conn.execute(
            "UPDATE watchlist_metadata SET vendor = ? WHERE watchlist_id = ?",
            (vendor, watchlist_id),
        )


@pytest.fixture
def db_with_vendored_rows(db_with_categorized_rows):
    """Extends ``db_with_categorized_rows`` by attaching canonical
    vendor strings to each of the five seeded watchlist rows. Each
    row keeps its existing device_category so precedence tests
    (vendor vs category) can fire on the same row.

    Vendor strings are intentionally mixed-case + punctuated to
    exercise the load-time normalization (lowercase + strip) end-
    to-end."""
    db = db_with_categorized_rows
    rows = db._conn.execute(
        "SELECT id, pattern_type FROM watchlist"
    ).fetchall()
    vendor_by_pattern_type = {
        "mac": "Mitsubishi Electric US, Inc.",
        "oui": "Hak5 LLC",
        "ssid": "DJI Inc.",
        "ble_uuid": "Apple Inc.",
        "mac_range": "Acme Surveillance Corp",
    }
    for row in rows:
        _attach_vendor(db, int(row["id"]), vendor_by_pattern_type[row["pattern_type"]])
    return db


def _vendors(*names: str) -> frozenset[str]:
    """Build a suppress_vendors set in the normalized form (lowercase
    + strip) that load_runtime_severity_overrides would produce. Lets
    the per-branch tests construct overrides without re-implementing
    the parser's normalization."""
    return frozenset(n.strip().lower() for n in names)


def test_evaluate_runtime_suppress_vendor_watchlist_mac(db_with_vendored_rows, caplog):
    """Vendor-suppress on the watchlist_mac delegation branch. Match
    has manufacturer="Mitsubishi Electric US, Inc." (set by fixture);
    override suppresses that vendor → no RuleHit + INFO log."""
    overrides = RuntimeSeverityOverride(
        suppress_vendors=_vendors("Mitsubishi Electric US, Inc.")
    )
    rule = Rule(name="del_mac", rule_type="watchlist_mac", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    with caplog.at_level(logging.INFO, logger="lynceus.rules"):
        hits = evaluate(
            rs,
            _obs(mac="a4:83:e7:11:22:33"),
            is_new_device=False,
            db=db_with_vendored_rows,
            severity_overrides=overrides,
        )
    assert hits == []
    info = [
        r for r in caplog.records
        if r.levelno == logging.INFO
        and "suppressing manufacturer=" in r.getMessage()
        and "Mitsubishi Electric US, Inc." in r.getMessage()
        and "del_mac" in r.getMessage()
    ]
    assert len(info) == 1


def test_evaluate_runtime_suppress_vendor_watchlist_oui(db_with_vendored_rows):
    overrides = RuntimeSeverityOverride(suppress_vendors=_vendors("Hak5 LLC"))
    rule = Rule(name="del_oui", rule_type="watchlist_oui", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="00:13:37:aa:bb:cc"),
        is_new_device=False,
        db=db_with_vendored_rows,
        severity_overrides=overrides,
    )
    assert hits == []


def test_evaluate_runtime_suppress_vendor_watchlist_ssid(db_with_vendored_rows):
    overrides = RuntimeSeverityOverride(suppress_vendors=_vendors("DJI Inc."))
    rule = Rule(name="del_ssid", rule_type="watchlist_ssid", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="aa:bb:cc:dd:ee:ff", ssid="FreeAirportWiFi"),
        is_new_device=False,
        db=db_with_vendored_rows,
        severity_overrides=overrides,
    )
    assert hits == []


def test_evaluate_runtime_suppress_vendor_ble_uuid(db_with_vendored_rows):
    overrides = RuntimeSeverityOverride(suppress_vendors=_vendors("Apple Inc."))
    rule = Rule(name="del_ble", rule_type="ble_uuid", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _ble_obs(uuids=(_AIRTAG_UUID,)),
        is_new_device=False,
        db=db_with_vendored_rows,
        severity_overrides=overrides,
    )
    assert hits == []


def test_evaluate_runtime_suppress_vendor_watchlist_mac_range(db_with_vendored_rows):
    """The 17,786 IEEE-registry mac_range rows ship under a single
    Argus-registered manufacturer string. An operator wanting them
    in the DB for annotation but not for alerts can suppress that
    vendor at runtime without re-importing."""
    overrides = RuntimeSeverityOverride(
        suppress_vendors=_vendors("Acme Surveillance Corp")
    )
    rule = Rule(
        name="argus_mr", rule_type="watchlist_mac_range", severity="low", patterns=[]
    )
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="aa:bb:cc:d1:23:45"),
        is_new_device=False,
        db=db_with_vendored_rows,
        severity_overrides=overrides,
    )
    assert hits == []


def test_evaluate_runtime_suppress_vendor_case_insensitive(db_with_vendored_rows):
    """Match's manufacturer is stored on the row exactly as Argus
    exported it (mixed case + punctuation). The override entry is
    normalized at load time. The eval-time check normalizes the
    match the same way, so any case / whitespace variant of the same
    vendor string in the override file matches the row."""
    # Row carries "Mitsubishi Electric US, Inc." — override loaded
    # via _vendors() with assorted casing all collapses to the same
    # frozenset member.
    overrides = RuntimeSeverityOverride(
        suppress_vendors=_vendors("  MITSUBISHI electric us, INC.  ")
    )
    rule = Rule(name="del_mac", rule_type="watchlist_mac", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="a4:83:e7:11:22:33"),
        is_new_device=False,
        db=db_with_vendored_rows,
        severity_overrides=overrides,
    )
    assert hits == []


def test_evaluate_runtime_suppress_vendor_different_vendor_passes_through(
    db_with_vendored_rows,
):
    """Negative-match regression: an override listing a vendor OTHER
    than the row's manufacturer must NOT suppress the alert. The
    runtime layer falls through to the category-driven checks (or
    pass-through if those also don't apply)."""
    overrides = RuntimeSeverityOverride(suppress_vendors=_vendors("Pineapple Computing"))
    rule = Rule(name="del_mac", rule_type="watchlist_mac", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="a4:83:e7:11:22:33"),
        is_new_device=False,
        db=db_with_vendored_rows,
        severity_overrides=overrides,
    )
    assert len(hits) == 1
    assert hits[0].severity == "low"  # row severity, untouched


def test_evaluate_runtime_suppress_vendor_null_manufacturer_falls_through(
    db_with_categorized_rows,
):
    """A row with NO vendor on the metadata row (manufacturer=None)
    causes the suppress_vendors check to skip entirely and fall
    through to the category-driven checks. Here the category check
    is configured to remap, and that remap must apply."""
    # db_with_categorized_rows has metadata rows attached but no
    # vendor — manufacturer comes back as None.
    overrides = RuntimeSeverityOverride(
        suppress_vendors=_vendors("Mitsubishi Electric US, Inc."),
        device_category_severity={"alpr": "high"},
    )
    rule = Rule(name="del_mac", rule_type="watchlist_mac", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="a4:83:e7:11:22:33"),  # category=alpr, no vendor
        is_new_device=False,
        db=db_with_categorized_rows,
        severity_overrides=overrides,
    )
    # Vendor check skipped (manufacturer is None); category remap applies.
    assert len(hits) == 1
    assert hits[0].severity == "high"


def test_evaluate_runtime_suppress_vendor_wins_over_category_remap(
    db_with_vendored_rows,
):
    """Documented precedence: vendor suppress > category suppress >
    category remap. A row with both a vendor-suppress and a
    category-remap entry → suppressed (no RuleHit)."""
    overrides = RuntimeSeverityOverride(
        suppress_vendors=_vendors("Mitsubishi Electric US, Inc."),
        device_category_severity={"alpr": "high"},  # would remap if vendor didn't win
    )
    rule = Rule(name="del_mac", rule_type="watchlist_mac", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="a4:83:e7:11:22:33"),
        is_new_device=False,
        db=db_with_vendored_rows,
        severity_overrides=overrides,
    )
    assert hits == []


def test_evaluate_runtime_suppress_vendor_wins_over_category_suppress(
    db_with_vendored_rows, caplog
):
    """When both vendor and category would suppress the same match,
    the INFO log line names the VENDOR (the more specific axis)
    rather than the category — operators inspecting the log can
    tell which key drove the suppression. Forensic precision
    matters when an operator has both keys populated and wants to
    debug why an alert was dropped."""
    overrides = RuntimeSeverityOverride(
        suppress_vendors=_vendors("Mitsubishi Electric US, Inc."),
        suppress_categories=frozenset({"alpr"}),
    )
    rule = Rule(name="del_mac", rule_type="watchlist_mac", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    with caplog.at_level(logging.INFO, logger="lynceus.rules"):
        hits = evaluate(
            rs,
            _obs(mac="a4:83:e7:11:22:33"),
            is_new_device=False,
            db=db_with_vendored_rows,
            severity_overrides=overrides,
        )
    assert hits == []
    info = [r for r in caplog.records if r.levelno == logging.INFO]
    vendor_lines = [r for r in info if "suppressing manufacturer=" in r.getMessage()]
    category_lines = [r for r in info if "suppressing category=" in r.getMessage()]
    assert len(vendor_lines) == 1
    assert category_lines == []  # vendor check returned first; category never ran


# ---- pattern_overrides (runtime row-level remap) ---------------------------
#
# Row-level severity remap keyed by argus_record_id (the stable Argus
# identifier projected onto Resolved*Match via Touch 1's LEFT JOIN).
# Per the documented precedence, the row-level remap runs AFTER both
# suppression gates (vendor + category) and BEFORE the category-level
# remap (device_category_severity). The 16-hex format validation is a
# load-time concern (covered in test_severity_overrides.py); at
# eval-time the check is a simple dict-membership test on the
# already-normalized key.


# Per-pattern_type canonical argus_record_ids for the fixture rows.
# 16-hex strings to mirror the Argus production shape, but the
# eval-time check does not require this format — it just looks up
# match.argus_record_id in overrides.pattern_overrides. Using realistic
# shapes here documents the production contract for future readers.
_ARID_MAC = "a1b2c3d4e5f60001"
_ARID_OUI = "a1b2c3d4e5f60002"
_ARID_SSID = "a1b2c3d4e5f60003"
_ARID_BLE = "a1b2c3d4e5f60004"
_ARID_MAC_RANGE = "a1b2c3d4e5f60005"


@pytest.fixture
def db_with_argus_record_ids(db_with_categorized_rows):
    """Extends ``db_with_categorized_rows`` by rewriting
    ``argus_record_id`` on each of the five seeded watchlist rows to
    a real 16-hex value. The parent fixture's
    ``_attach_category`` writes a placeholder (``argus-<wid>``) which
    is fine for category-driven tests but not a realistic key for
    pattern_overrides. Each row keeps its existing device_category so
    precedence tests (pattern_override vs category remap) can fire on
    the same row."""
    db = db_with_categorized_rows
    rows = db._conn.execute("SELECT id, pattern_type FROM watchlist").fetchall()
    arid_by_pattern_type = {
        "mac": _ARID_MAC,
        "oui": _ARID_OUI,
        "ssid": _ARID_SSID,
        "ble_uuid": _ARID_BLE,
        "mac_range": _ARID_MAC_RANGE,
    }
    with db._conn:
        for row in rows:
            db._conn.execute(
                "UPDATE watchlist_metadata SET argus_record_id = ? "
                "WHERE watchlist_id = ?",
                (arid_by_pattern_type[row["pattern_type"]], int(row["id"])),
            )
    return db


def test_evaluate_runtime_pattern_overrides_watchlist_mac(db_with_argus_record_ids):
    """watchlist_mac delegation hit on argus_record_id=_ARID_MAC;
    pattern_overrides remap → row severity flips from baked "low" to
    "high" at alert time. Mirror of the category-remap branch but
    keyed on the more-specific row identifier."""
    overrides = RuntimeSeverityOverride(pattern_overrides={_ARID_MAC: "high"})
    rule = Rule(name="del_mac", rule_type="watchlist_mac", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="a4:83:e7:11:22:33"),
        is_new_device=False,
        db=db_with_argus_record_ids,
        severity_overrides=overrides,
    )
    assert len(hits) == 1
    assert hits[0].severity == "high"


def test_evaluate_runtime_pattern_overrides_watchlist_oui(db_with_argus_record_ids):
    overrides = RuntimeSeverityOverride(pattern_overrides={_ARID_OUI: "med"})
    rule = Rule(name="del_oui", rule_type="watchlist_oui", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="00:13:37:aa:bb:cc"),
        is_new_device=False,
        db=db_with_argus_record_ids,
        severity_overrides=overrides,
    )
    assert len(hits) == 1
    assert hits[0].severity == "med"


def test_evaluate_runtime_pattern_overrides_watchlist_ssid(db_with_argus_record_ids):
    overrides = RuntimeSeverityOverride(pattern_overrides={_ARID_SSID: "high"})
    rule = Rule(name="del_ssid", rule_type="watchlist_ssid", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="aa:bb:cc:dd:ee:ff", ssid="FreeAirportWiFi"),
        is_new_device=False,
        db=db_with_argus_record_ids,
        severity_overrides=overrides,
    )
    assert len(hits) == 1
    assert hits[0].severity == "high"


def test_evaluate_runtime_pattern_overrides_ble_uuid(db_with_argus_record_ids):
    overrides = RuntimeSeverityOverride(pattern_overrides={_ARID_BLE: "med"})
    rule = Rule(name="del_ble", rule_type="ble_uuid", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _ble_obs(uuids=(_AIRTAG_UUID,)),
        is_new_device=False,
        db=db_with_argus_record_ids,
        severity_overrides=overrides,
    )
    assert len(hits) == 1
    assert hits[0].severity == "med"


def test_evaluate_runtime_pattern_overrides_watchlist_mac_range(db_with_argus_record_ids):
    """An operator can carve a single MAC range out of the
    bulk-imported IEEE-registry corpus and tune just that one row's
    severity — exactly the use case the matrix is designed for."""
    overrides = RuntimeSeverityOverride(pattern_overrides={_ARID_MAC_RANGE: "high"})
    rule = Rule(
        name="argus_mr", rule_type="watchlist_mac_range", severity="low", patterns=[]
    )
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="aa:bb:cc:d1:23:45"),
        is_new_device=False,
        db=db_with_argus_record_ids,
        severity_overrides=overrides,
    )
    assert len(hits) == 1
    assert hits[0].severity == "high"


def test_evaluate_runtime_pattern_overrides_unknown_arid_passes_through(
    db_with_argus_record_ids,
):
    """Negative-match regression: an override targeting a different
    argus_record_id must NOT remap the row. The runtime layer falls
    through to the category remap (or pass-through if none). Stale
    pattern_overrides entries — a legitimate state per the load-time
    contract — must behave this way."""
    overrides = RuntimeSeverityOverride(
        pattern_overrides={"deadbeefcafef00d": "high"}  # not on any row
    )
    rule = Rule(name="del_mac", rule_type="watchlist_mac", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="a4:83:e7:11:22:33"),
        is_new_device=False,
        db=db_with_argus_record_ids,
        severity_overrides=overrides,
    )
    assert len(hits) == 1
    assert hits[0].severity == "low"  # row severity, untouched


def test_evaluate_runtime_pattern_overrides_null_arid_falls_through(tmp_path):
    """A watchlist row with no metadata row → argus_record_id=None
    on the match (LEFT JOIN). The pattern_overrides check skips
    entirely and the runtime layer falls through to the
    category-driven checks — which here also skip (no metadata =
    device_category also None), so the alert fires at the row's
    baked severity.

    Per migration 004, watchlist_metadata.argus_record_id is NOT
    NULL UNIQUE; the only way for argus_record_id to surface as
    None on a Resolved*Match is the LEFT-JOIN-against-missing-
    metadata path. So device_category and argus_record_id are
    always None together for non-Argus rows — the
    pattern_overrides skip and the category-layer skip are joined
    at the hip, by design. This is the limitation called out in
    the CHANGELOG: only Argus-imported rows are targetable from
    pattern_overrides."""
    db_path = str(tmp_path / "no_meta.db")
    db = Database(db_path)
    with db._conn:
        db._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
            "VALUES ('a4:83:e7:11:22:33', 'mac', 'low', NULL)"
        )
    try:
        overrides = RuntimeSeverityOverride(
            pattern_overrides={_ARID_MAC: "high"},
            device_category_severity={"alpr": "high"},
        )
        rule = Rule(name="del_mac", rule_type="watchlist_mac", severity="low", patterns=[])
        rs = Ruleset(rules=[rule])
        hits = evaluate(
            rs,
            _obs(mac="a4:83:e7:11:22:33"),
            is_new_device=False,
            db=db,
            severity_overrides=overrides,
        )
        assert len(hits) == 1
        assert hits[0].severity == "low"  # arid=None, category=None → pass-through
    finally:
        db.close()


def test_evaluate_runtime_pattern_overrides_wins_over_category_remap(
    db_with_argus_record_ids,
):
    """Documented precedence: pattern_overrides > device_category_
    severity. The row is in category=alpr; both the pattern_overrides
    entry (row → med) and the category remap (alpr → high) would
    apply, but the more-specific row-level remap wins."""
    overrides = RuntimeSeverityOverride(
        pattern_overrides={_ARID_MAC: "med"},
        device_category_severity={"alpr": "high"},
    )
    rule = Rule(name="del_mac", rule_type="watchlist_mac", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="a4:83:e7:11:22:33"),
        is_new_device=False,
        db=db_with_argus_record_ids,
        severity_overrides=overrides,
    )
    assert len(hits) == 1
    assert hits[0].severity == "med"  # pattern_overrides wins


def test_evaluate_runtime_pattern_overrides_loses_to_suppress_vendors(
    db_with_argus_record_ids,
):
    """Suppression always wins over remap — vendor suppress is a
    deliberate "no alert from this manufacturer" statement that
    pattern_overrides cannot override. Tests the load-bearing
    invariant from the prompt's "What NOT to do" list (per-row
    UNSUPPRESS is not a feature)."""
    # First attach a vendor to the fixture's mac row so the
    # suppress_vendors check has something to key on.
    db = db_with_argus_record_ids
    with db._conn:
        db._conn.execute(
            "UPDATE watchlist_metadata SET vendor = ? "
            "WHERE argus_record_id = ?",
            ("Mitsubishi Electric US, Inc.", _ARID_MAC),
        )
    overrides = RuntimeSeverityOverride(
        suppress_vendors=frozenset({"mitsubishi electric us, inc."}),
        pattern_overrides={_ARID_MAC: "high"},  # would remap if vendor didn't win
    )
    rule = Rule(name="del_mac", rule_type="watchlist_mac", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="a4:83:e7:11:22:33"),
        is_new_device=False,
        db=db,
        severity_overrides=overrides,
    )
    assert hits == []  # vendor suppression wins; no remap applied


def test_evaluate_runtime_pattern_overrides_loses_to_suppress_categories(
    db_with_argus_record_ids,
):
    """Symmetric to the vendor-suppress precedence test: category
    suppress also wins over a pattern_overrides remap on the same
    row. Suppression at either layer is a stronger statement than
    remap at the row layer."""
    overrides = RuntimeSeverityOverride(
        suppress_categories=frozenset({"alpr"}),
        pattern_overrides={_ARID_MAC: "high"},
    )
    rule = Rule(name="del_mac", rule_type="watchlist_mac", severity="low", patterns=[])
    rs = Ruleset(rules=[rule])
    hits = evaluate(
        rs,
        _obs(mac="a4:83:e7:11:22:33"),
        is_new_device=False,
        db=db_with_argus_record_ids,
        severity_overrides=overrides,
    )
    assert hits == []
