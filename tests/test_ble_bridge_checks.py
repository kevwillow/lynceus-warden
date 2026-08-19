"""Pre-flight readiness checks for enabling the passive BLE bridge.

These encode the five enablement gates that produce a silently useless or
noisy install. Three (BACKLOG BLE-G1, BLE-G2, BLE-G6) are decidable from
config data alone — no adapter, no hardware — which is what lets the setup
wizard warn before an operator commits and lets the web UI explain a bridge
that is on but contributing nothing. Two (BLE-G7, BLE-G8) can only be
answered by probing the environment.
"""

from __future__ import annotations

import subprocess

from lynceus import ble_bridge_checks
from lynceus.ble_bridge_checks import (
    CHECK_ADAPTER_CONTENTION,
    CHECK_BLEAK_MISSING,
    CHECK_BLUEZ_NO_ADV_MONITOR,
    CHECK_NO_DECODED_CLASS_CONSUMER,
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
    # ⚠️ Was `len(warnings) == 3`. A bare count has to be bumped by hand every
    # time a check is added, and bumping it is a no-op edit that proves nothing
    # -- it passes for the wrong new warning just as readily as the right one.
    # Naming the expected SET fails on an unexpected addition AND on a silent
    # disappearance, which the count never caught.
    assert warnings, "no warnings produced -- the per-warning loop below would be vacuous"
    for w in warnings:
        assert w.summary and w.remedy
    assert {w.code for w in warnings} == {
        CHECK_ADAPTER_CONTENTION,
        CHECK_SOURCE_GATE,
        CHECK_RAW_COMPANY_ID_RULE,
        CHECK_NO_DECODED_CLASS_CONSUMER,
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


# --- BLE-G8: BlueZ not publishing AdvertisementMonitorManager1 -------------
# The failure mode that actually bit, and the one none of the four checks
# above can see. Measured on BlueZ 5.72 / kernel 7.0.0 -- both above the
# minimums the bridge's own error text quotes -- with bleak installed, the
# adapter free and the config clean: all four gates green, bridge captured
# nothing, because Experimental was commented out in main.conf.
#
# The three fixtures below are trimmed from real `busctl --system introspect`
# output on a two-adapter Linux host, including the empty-but-successful
# response for a path that does not exist.

_HEADER = "NAME TYPE SIGNATURE RESULT/VALUE FLAGS\n"

_ADAPTER_WITH_MONITOR = _HEADER + (
    "org.bluez.Adapter1                     interface - - -\n"
    "org.bluez.AdvertisementMonitorManager1 interface - - -\n"
    "org.bluez.GattManager1                 interface - - -\n"
    "org.bluez.LEAdvertisingManager1        interface - - -\n"
)

_ADAPTER_WITHOUT_MONITOR = _HEADER + (
    "org.bluez.Adapter1                     interface - - -\n"
    "org.bluez.GattManager1                 interface - - -\n"
    "org.bluez.LEAdvertisingManager1        interface - - -\n"
)

# busctl EXITS 0 for a path that does not exist and prints only the header.
_NO_SUCH_OBJECT = _HEADER


def _stub_busctl(monkeypatch, *, stdout: str, returncode: int = 0, on_path: bool = True):
    """Drive the check without a bus. Patches the module-owned seams only."""
    monkeypatch.setattr(ble_bridge_checks, "_is_linux", lambda: True)
    monkeypatch.setattr(
        ble_bridge_checks.shutil, "which", lambda name: "/usr/bin/busctl" if on_path else None
    )

    def _fake_run(cmd, **kwargs):
        return subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr="")

    monkeypatch.setattr(ble_bridge_checks.subprocess, "run", _fake_run)


def test_adapter_without_monitor_interface_warns(monkeypatch):
    """The control: a real adapter lacking the interface must be reported."""
    _stub_busctl(monkeypatch, stdout=_ADAPTER_WITHOUT_MONITOR)
    warning = ble_bridge_checks.check_bluez_advertisement_monitor("hci1")
    assert warning is not None
    assert warning.code == CHECK_BLUEZ_NO_ADV_MONITOR
    assert warning.summary and warning.remedy
    # The remedy must be actionable: name the setting and the restart.
    assert "Experimental" in warning.remedy
    assert "systemctl restart bluetooth" in warning.remedy
    # ...and name the adapter the operator actually asked about.
    assert "hci1" in warning.remedy


def test_adapter_with_monitor_interface_is_silent(monkeypatch):
    _stub_busctl(monkeypatch, stdout=_ADAPTER_WITH_MONITOR)
    assert ble_bridge_checks.check_bluez_advertisement_monitor("hci1") is None


def test_nonexistent_adapter_does_not_warn(monkeypatch):
    """busctl exits 0 with an empty body for a path that isn't there.

    Without an explicit Adapter1 check that is indistinguishable from a real
    adapter missing the monitor interface, and the operator gets a confident
    "enable experimental features" remedy for an adapter they never plugged
    in. Regression guard for exactly that.
    """
    _stub_busctl(monkeypatch, stdout=_NO_SUCH_OBJECT)
    assert ble_bridge_checks.check_bluez_advertisement_monitor("hci9") is None


def test_busctl_failure_is_silent(monkeypatch):
    """bluetoothd down / D-Bus policy refusal: not distinguishable, so quiet."""
    _stub_busctl(monkeypatch, stdout="", returncode=1)
    assert ble_bridge_checks.check_bluez_advertisement_monitor("hci1") is None


def test_busctl_absent_from_path_is_silent(monkeypatch):
    _stub_busctl(monkeypatch, stdout=_ADAPTER_WITHOUT_MONITOR, on_path=False)
    assert ble_bridge_checks.check_bluez_advertisement_monitor("hci1") is None


def test_non_linux_is_silent(monkeypatch):
    """The interface is BlueZ-specific; elsewhere the question is meaningless."""
    _stub_busctl(monkeypatch, stdout=_ADAPTER_WITHOUT_MONITOR)
    monkeypatch.setattr(ble_bridge_checks, "_is_linux", lambda: False)
    assert ble_bridge_checks.check_bluez_advertisement_monitor("hci1") is None


def test_wedged_bluetoothd_times_out_silently(monkeypatch):
    """A hung daemon must not hang the wizard, nor produce a false finding."""
    monkeypatch.setattr(ble_bridge_checks, "_is_linux", lambda: True)
    monkeypatch.setattr(ble_bridge_checks.shutil, "which", lambda name: "/usr/bin/busctl")

    def _hang(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, ble_bridge_checks._BUSCTL_TIMEOUT_SECONDS)

    monkeypatch.setattr(ble_bridge_checks.subprocess, "run", _hang)
    assert ble_bridge_checks.check_bluez_advertisement_monitor("hci1") is None


def test_busctl_is_invoked_with_the_requested_adapter(monkeypatch):
    """The object path must follow the adapter argument, not a hardcoded one."""
    seen: list[list[str]] = []
    monkeypatch.setattr(ble_bridge_checks, "_is_linux", lambda: True)
    monkeypatch.setattr(ble_bridge_checks.shutil, "which", lambda name: "/usr/bin/busctl")

    def _capture(cmd, **kwargs):
        seen.append(list(cmd))
        return subprocess.CompletedProcess(cmd, 0, stdout=_ADAPTER_WITH_MONITOR, stderr="")

    monkeypatch.setattr(ble_bridge_checks.subprocess, "run", _capture)
    # Deliberately NOT hci0 or hci1: an implementation that hardcoded either
    # of the two adapters this was developed against would pass a test that
    # asked for one of them. It did, until this used hci7.
    ble_bridge_checks.check_bluez_advertisement_monitor("hci7")
    assert seen == [["busctl", "--system", "introspect", "org.bluez", "/org/bluez/hci7"]]


def test_monitor_check_stays_out_of_the_pure_config_check(monkeypatch):
    """check_bridge_readiness must not gain a second environment dependency."""
    _stub_busctl(monkeypatch, stdout=_ADAPTER_WITHOUT_MONITOR)
    assert (
        check_bridge_readiness(
            adapter="hci1",
            kismet_sources=("wlan0", "ble:hci1"),
            enabled_rule_types=("ble_device_class",),
        )
        == ()
    )


def test_collect_reports_monitor_gate_upstream_of_contention(monkeypatch):
    """G8 sits above G6: contention presumes the adapter could be opened.

    An operator reading top-down must be told the bridge cannot scan at all
    before being told Kismet is holding the adapter.
    """
    _stub_busctl(monkeypatch, stdout=_ADAPTER_WITHOUT_MONITOR)
    monkeypatch.setattr(
        ble_bridge_checks.importlib.util, "find_spec", lambda name: object()
    )
    codes = [
        w.code
        for w in ble_bridge_checks.collect_bridge_warnings(
            adapter="hci1",
            kismet_sources=("hci1",),
            enabled_rule_types=(),
        )
    ]
    assert CHECK_BLUEZ_NO_ADV_MONITOR in codes
    assert CHECK_ADAPTER_CONTENTION in codes
    assert codes.index(CHECK_BLUEZ_NO_ADV_MONITOR) < codes.index(CHECK_ADAPTER_CONTENTION)


def test_collect_reports_bleak_above_the_monitor_gate(monkeypatch):
    """G7 stays first: with no scan library, the bus question is academic."""
    _stub_busctl(monkeypatch, stdout=_ADAPTER_WITHOUT_MONITOR)
    monkeypatch.setattr(ble_bridge_checks.importlib.util, "find_spec", lambda name: None)
    codes = [
        w.code
        for w in ble_bridge_checks.collect_bridge_warnings(
            adapter="hci1",
            kismet_sources=None,
            enabled_rule_types=None,
        )
    ]
    assert codes.index(CHECK_BLEAK_MISSING) < codes.index(CHECK_BLUEZ_NO_ADV_MONITOR)
