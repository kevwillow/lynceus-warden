"""Pre-flight readiness checks for enabling the passive BLE bridge.

tests/ is gitignored — these are NEVER committed (see project memory).

These encode the three enablement gates that produce a silently useless or
noisy install (BACKLOG BLE-G1, BLE-G2, BLE-G6). All three are decidable from
config data alone — no adapter, no hardware — which is what lets the setup
wizard warn before an operator commits and lets the web UI explain a bridge
that is on but contributing nothing.
"""

from __future__ import annotations

from lynceus import ble_bridge_checks
from lynceus.ble_bridge_checks import (
    CHECK_ADAPTER_CONTENTION,
    CHECK_BLEAK_MISSING,
    CHECK_RAW_COMPANY_ID_RULE,
    CHECK_SOURCE_GATE,
    check_bridge_readiness,
)


def _codes(*args, **kwargs) -> set[str]:
    return {w.code for w in check_bridge_readiness(*args, **kwargs)}


def test_clean_config_produces_no_warnings():
    assert (
        check_bridge_readiness(
            adapter="hci1",
            kismet_sources=("wlan0", "ble:hci1"),
            enabled_rule_types=("ble_device_class",),
        )
        == ()
    )


def test_kismet_claiming_the_bridge_adapter_warns():
    """BLE-G6: Kismet holds the adapter, so the bridge can never scan."""
    codes = _codes(
        adapter="hci1",
        kismet_sources=("wlan0", "hci0", "hci1", "ble:hci1"),
        enabled_rule_types=(),
    )
    assert CHECK_ADAPTER_CONTENTION in codes


def test_source_gate_without_ble_provenance_warns():
    """BLE-G2: gate admits on seen_by_sources, bridge stamps 'ble:<adapter>'."""
    codes = _codes(
        adapter="hci1",
        kismet_sources=("wlan0",),
        enabled_rule_types=(),
    )
    assert CHECK_SOURCE_GATE in codes


def test_empty_kismet_sources_is_no_gate_at_all():
    """An unset source list means no filter — nothing to warn about."""
    codes = _codes(adapter="hci1", kismet_sources=(), enabled_rule_types=())
    assert CHECK_SOURCE_GATE not in codes
    assert CHECK_ADAPTER_CONTENTION not in codes


def test_raw_company_id_rule_warns_about_alert_storm():
    """BLE-G1: matches company id, not class — the decoder does not help."""
    codes = _codes(
        adapter="hci1",
        kismet_sources=("ble:hci1",),
        enabled_rule_types=("watchlist_ble_manufacturer_id",),
    )
    assert CHECK_RAW_COMPANY_ID_RULE in codes


def test_ble_device_class_rule_is_not_a_storm_risk():
    """The class-based rule is the curated path — it must not warn."""
    codes = _codes(
        adapter="hci1",
        kismet_sources=("ble:hci1",),
        enabled_rule_types=("ble_device_class",),
    )
    assert CHECK_RAW_COMPANY_ID_RULE not in codes


def test_contention_and_source_gate_are_independent_findings():
    """Same config can trip both; they have different remedies."""
    codes = _codes(
        adapter="hci1",
        kismet_sources=("hci1",),
        enabled_rule_types=(),
    )
    assert {CHECK_ADAPTER_CONTENTION, CHECK_SOURCE_GATE} <= codes


def test_every_warning_carries_a_remedy():
    """A warning the operator cannot act on is just noise."""
    warnings = check_bridge_readiness(
        adapter="hci1",
        kismet_sources=("hci1",),
        enabled_rule_types=("watchlist_ble_manufacturer_id",),
    )
    assert len(warnings) == 3
    for w in warnings:
        assert w.summary and w.remedy
        assert w.code in {
            CHECK_ADAPTER_CONTENTION,
            CHECK_SOURCE_GATE,
            CHECK_RAW_COMPANY_ID_RULE,
        }


def test_accepts_lists_not_just_tuples():
    """Callers pass config lists straight through; do not require tuples."""
    assert check_bridge_readiness(
        adapter="hci1",
        kismet_sources=["ble:hci1"],
        enabled_rule_types=["ble_device_class"],
    ) == ()


def test_none_kismet_sources_treated_as_no_gate():
    """config.kismet_sources is None when unset — must not crash."""
    assert (
        check_bridge_readiness(
            adapter="hci1",
            kismet_sources=None,
            enabled_rule_types=None,
        )
        == ()
    )


# --- BLE-G7: bleak absent from the interpreter -----------------------------
# The one readiness failure an operator reaches without misconfiguring
# anything: bleak is an optional extra, so a default install lacks it and an
# enabled bridge captures nothing while looking healthy.


def test_bleak_missing_warns_when_find_spec_returns_none(monkeypatch):
    """Package absent -> a warning carrying the install remedy."""
    monkeypatch.setattr(
        ble_bridge_checks.importlib.util, "find_spec", lambda name: None
    )
    warning = ble_bridge_checks.check_bleak_available()
    assert warning is not None
    assert warning.code == CHECK_BLEAK_MISSING
    assert warning.summary and warning.remedy
    # The remedy must name the extra, or the operator cannot act on it.
    assert "lynceus[ble]" in warning.remedy


def test_bleak_present_produces_no_warning(monkeypatch):
    """Present package stays silent -- it is not a claim that it works."""
    monkeypatch.setattr(
        ble_bridge_checks.importlib.util, "find_spec", lambda name: object()
    )
    assert ble_bridge_checks.check_bleak_available() is None


def test_broken_install_raising_is_treated_as_missing(monkeypatch):
    """A partially-removed install can raise; unusable either way."""

    def _boom(name):
        raise ValueError("no parent package")

    monkeypatch.setattr(ble_bridge_checks.importlib.util, "find_spec", _boom)
    warning = ble_bridge_checks.check_bleak_available()
    assert warning is not None
    assert warning.code == CHECK_BLEAK_MISSING


def test_bleak_check_stays_out_of_the_pure_config_check(monkeypatch):
    """check_bridge_readiness must not gain an environment dependency.

    Its contract is "decidable from configuration alone". Even with bleak
    absent, a clean config produces no config-layer warnings -- the two
    checks answer different questions and callers compose them.
    """
    monkeypatch.setattr(
        ble_bridge_checks.importlib.util, "find_spec", lambda name: None
    )
    assert (
        check_bridge_readiness(
            adapter="hci1",
            kismet_sources=("wlan0", "ble:hci1"),
            enabled_rule_types=("ble_device_class",),
        )
        == ()
    )
