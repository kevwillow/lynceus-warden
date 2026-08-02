"""Local-only tests for the ble_device_class rule type.

tests/ is gitignored — these are NEVER committed (see project memory).
"""

from __future__ import annotations

import pytest

from lynceus.ble_continuity import CLASS_AIRPODS, CLASS_FIND_MY
from lynceus.kismet import DeviceObservation
from lynceus.rules import Rule, Ruleset, evaluate


def _obs(device_class):
    return DeviceObservation(
        device_type="ble",
        mac="aa:bb:cc:dd:ee:ff",
        first_seen=1,
        last_seen=2,
        rssi=-50,
        ssid=None,
        oui_vendor=None,
        is_randomized=False,
        ble_device_class=device_class,
    )


def _ruleset(patterns, severity="high"):
    return Ruleset(
        rules=[
            Rule(
                name="find_my_tracker",
                rule_type="ble_device_class",
                severity=severity,
                patterns=patterns,
                description="Find My tracker advertising nearby",
            )
        ]
    )


def test_matching_class_emits_hit():
    hits = evaluate(_ruleset([CLASS_FIND_MY]), _obs(CLASS_FIND_MY), is_new_device=True)
    assert len(hits) == 1
    assert hits[0].rule_type == "ble_device_class"
    assert hits[0].rule_name == "find_my_tracker"
    assert hits[0].severity == "high"
    assert hits[0].mac == "aa:bb:cc:dd:ee:ff"
    assert CLASS_FIND_MY in hits[0].message


def test_non_matching_class_emits_nothing():
    hits = evaluate(_ruleset([CLASS_FIND_MY]), _obs(CLASS_AIRPODS), is_new_device=True)
    assert hits == []


def test_none_class_emits_nothing():
    hits = evaluate(_ruleset([CLASS_FIND_MY]), _obs(None), is_new_device=True)
    assert hits == []


def test_multiple_patterns_any_match():
    ruleset = _ruleset([CLASS_FIND_MY, CLASS_AIRPODS])
    assert len(evaluate(ruleset, _obs(CLASS_AIRPODS), is_new_device=True)) == 1


def test_disabled_rule_emits_nothing():
    ruleset = Ruleset(
        rules=[
            Rule(
                name="off",
                rule_type="ble_device_class",
                severity="high",
                patterns=[CLASS_FIND_MY],
                enabled=False,
            )
        ]
    )
    assert evaluate(ruleset, _obs(CLASS_FIND_MY), is_new_device=True) == []


def test_evaluate_needs_no_db():
    """In-memory only — no watchlist backs this rule type, so evaluate must
    not require a db handle the way the delegating types do."""
    hits = evaluate(
        _ruleset([CLASS_FIND_MY]), _obs(CLASS_FIND_MY), is_new_device=False, db=None
    )
    assert len(hits) == 1


def test_empty_patterns_rejected():
    """No watchlist backs this rule type, so empty patterns cannot mean
    'delegate to the DB' the way they do for watchlist_* types."""
    with pytest.raises(ValueError, match="must have non-empty patterns"):
        Rule(
            name="bad",
            rule_type="ble_device_class",
            severity="high",
            patterns=[],
        )
