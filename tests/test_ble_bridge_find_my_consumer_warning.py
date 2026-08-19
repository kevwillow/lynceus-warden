"""The readiness warning nobody gets: a bridge that decodes and counts, but
no enabled rule ever consults what it decoded, so nothing alerts.

The plant in section 5 of PACKET.md is enforced in this file: each direction
is a separate test, both are keyed on real rule state (not substring matches
against prose), and the test that asserts presence is the one whose failure
proves the warning is wired up.
"""

from __future__ import annotations

from lynceus.ble_bridge_checks import (
    CHECK_NO_DECODED_CLASS_CONSUMER,
    check_bridge_readiness,
)


def _codes(*args, **kwargs) -> set[str]:
    return {w.code for w in check_bridge_readiness(*args, **kwargs)}


def test_no_consumer_warning_present_without_a_decoded_class_rule():
    """A bridge whose only enabled rule does NOT consume ble_device_class.

    Keyed on the constant code, not substring matching the prose -- so a
    rewrite of the summary text does not silently invalidate the test.
    """
    codes = _codes(
        adapter="hci1",
        kismet_sources=("ble:hci1",),
        # The shipped argus_mac rule is watchlist_mac, not ble_device_class.
        # Real rule state, not a contrived empty list.
        enabled_rule_types=("watchlist_mac", "watchlist_oui"),
    )
    assert CHECK_NO_DECODED_CLASS_CONSUMER in codes


def test_no_consumer_warning_absent_with_a_decoded_class_rule():
    """An operator who has enabled the apple_find_my rule is not warned."""
    codes = _codes(
        adapter="hci1",
        kismet_sources=("ble:hci1",),
        enabled_rule_types=("ble_device_class",),
    )
    assert CHECK_NO_DECODED_CLASS_CONSUMER not in codes


def test_no_consumer_warning_absent_with_mixed_rules_including_the_class():
    """The class rule co-exists with other rule_types -- still not warned."""
    codes = _codes(
        adapter="hci1",
        kismet_sources=("ble:hci1",),
        enabled_rule_types=(
            "watchlist_mac",
            "watchlist_oui",
            "ble_device_class",
        ),
    )
    assert CHECK_NO_DECODED_CLASS_CONSUMER not in codes


def test_no_consumer_warning_carries_an_actionable_remedy():
    """The remedy must name the file, the block, and what to do."""
    warnings = check_bridge_readiness(
        adapter="hci1",
        kismet_sources=("ble:hci1",),
        enabled_rule_types=("watchlist_mac",),
    )
    consumer_warnings = [w for w in warnings if w.code == CHECK_NO_DECODED_CLASS_CONSUMER]
    assert len(consumer_warnings) == 1
    remedy = consumer_warnings[0].remedy
    assert "config/rules.yaml" in remedy
    assert "apple_find_my" in remedy
    assert remedy  # not empty


def test_no_consumer_warning_is_a_config_gate_not_an_environment_check():
    """Pure config in, pure config out -- no adapter, no hardware probed.

    Mirrors the contract test for the bleak and bluez checks below in the
    existing suite. A clean config with no class rule still emits this one
    warning, which is the whole point.
    """
    warnings = check_bridge_readiness(
        adapter="hci1",
        kismet_sources=("ble:hci1",),
        enabled_rule_types=("watchlist_mac",),
    )
    codes = {w.code for w in warnings}
    assert codes == {CHECK_NO_DECODED_CLASS_CONSUMER}


def test_unknown_rule_state_is_silent_but_known_empty_warns():
    """`None` and `()` must NOT be collapsed, and this is the subtle one.

    ⛔ The obvious guard is `if rule_types and ...`, which reads fine and is
    wrong. `None` means the CALLER DOES NOT KNOW the rule state -- the setup
    wizard runs before any ruleset exists -- so warning there is a guess. An
    EMPTY tuple means the caller looked and found no enabled rules, which is
    the WORST case: nothing alerts at all.

    Collapsing them suppresses the warning exactly where it matters most,
    which is this check's own defect reappearing inside its own fix. This test
    exists because that guard was written the wrong way round once already.
    """
    unknown = check_bridge_readiness(
        adapter="hci1", kismet_sources=None, enabled_rule_types=None
    )
    assert CHECK_NO_DECODED_CLASS_CONSUMER not in {w.code for w in unknown}, (
        "warned about rule state the caller never claimed to know"
    )

    known_empty = check_bridge_readiness(
        adapter="hci1", kismet_sources=None, enabled_rule_types=()
    )
    assert CHECK_NO_DECODED_CLASS_CONSUMER in {w.code for w in known_empty}, (
        "a ruleset with NO enabled rules alerts on nothing at all, and that is "
        "the case the operator most needs told about -- do not collapse it "
        "with the unknown case"
    )
