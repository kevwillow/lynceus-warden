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
