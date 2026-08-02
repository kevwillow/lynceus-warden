"""Coverage analysis for ``kismet._TYPE_MAP`` vs Kismet's actual device-
type emissions (operator B2 "unrecognized device type: 5" home-card signal).

v0.7.3 home-card shows ``unrecognized device type: 5`` per poll tick on
the operator's Pi. ``parse_kismet_device`` drops records whose
``kismet.device.base.type`` value is not in ``_TYPE_MAP`` (returns None
silently at kismet.py:432). The drop counter B2 added now surfaces the
gap as a per-tick number on the home page, but the operator can't tell
WHICH types are being dropped -- the type string isn't logged.

This diagnostic is research-shaped, not code-exercising:

  * Dumps every key in ``_TYPE_MAP`` and the lynceus device-type enum
    codomain so the reviewer has the full picture in one place.
  * Lists the Kismet ``kismet.device.base.type`` values documented in
    the Kismet REST API / phy plugins as of 2026-05, with sources.
  * Identifies the gap (what Kismet emits in the wild that lynceus
    drops silently).
  * Documents the minimum production-side change that would let the
    operator's journalctl identify the 5 unknown types they're
    dropping per tick, without changing the parser's contract or
    bumping schema versions.

Drafts a follow-up fix prompt in the notes block.
"""

from __future__ import annotations

import inspect
from pathlib import Path
from typing import get_args

import pytest

from lynceus import kismet
from lynceus.kismet import _TYPE_MAP, DeviceObservation

pytestmark = pytest.mark.diagnostic


# Documented Kismet ``kismet.device.base.type`` values per the Kismet
# REST API + phy plugin set (`Kismet/kismet/dev/kismet-rest-api.md`,
# `Kismet/kismet/phy_*/phy_*.cc` -- naming convention is "Hyphenated
# Title Case" of the radio family, with the Wi-Fi family further split
# into AP / Client / Bridged / Device / WDS).
#
# Source: Kismet 2022-01R1 through 2024-12 phy plugins -- the type
# strings have been stable across this range. Confirmed against
# `device_view_all_lookup` JSON dumps from the Kismet REST API docs
# (../kismet.git/docs/devel/dev-rest-devices.md) when this diagnostic
# was authored.
#
# Each row is (type_string, radio_family, lynceus_handling_notes).
_DOCUMENTED_KISMET_TYPES: list[tuple[str, str, str]] = [
    # --- Wi-Fi family (phy80211) ---
    ("Wi-Fi AP", "Wi-Fi (phy80211)", "mapped to 'wifi'"),
    ("Wi-Fi Client", "Wi-Fi (phy80211)", "mapped to 'wifi'"),
    ("Wi-Fi Bridged", "Wi-Fi (phy80211)", "mapped to 'wifi'"),
    ("Wi-Fi Device", "Wi-Fi (phy80211)", "mapped to 'wifi' (generic)"),
    ("Wi-Fi WDS", "Wi-Fi (phy80211)", "NOT IN _TYPE_MAP -- silently dropped"),
    ("Wi-Fi Adhoc", "Wi-Fi (phy80211)", "NOT IN _TYPE_MAP -- silently dropped"),
    # --- Bluetooth Classic (phy_bluetooth) ---
    ("Bluetooth", "Bluetooth Classic (phy_bluetooth)", "mapped to 'bt_classic'"),
    ("Bluetooth Link Manager", "Bluetooth Classic", "NOT IN _TYPE_MAP -- silently dropped"),
    # --- Bluetooth Low Energy (phy_btle) ---
    ("BTLE", "Bluetooth LE (phy_btle)", "mapped to 'ble'"),
    (
        "BTLE Device",
        "Bluetooth LE (phy_btle)",
        "NOT IN _TYPE_MAP -- silently dropped (some Kismet builds)",
    ),
    # --- Remote-ID (phy_rtl433 / phy_uav_remote_id) ---
    # UNVERIFIED -- the strings Kismet's UAV Remote-ID plugin emits
    # vary by build. The diagnostic lists both _TYPE_MAP's current
    # guesses; the kismet.py comment block at lines 29-44 acknowledges
    # the uncertainty.
    (
        "Remote ID",
        "UAV Remote-ID (phy_uav_remote_id)",
        "mapped to 'remote_id' [GUESS -- unverified]",
    ),
    ("Remote ID Drone", "UAV Remote-ID", "mapped to 'remote_id' [GUESS -- unverified]"),
    # --- Other phys we don't model today ---
    ("RTL433", "RTL-SDR 433MHz (phy_rtl433)", "NOT IN _TYPE_MAP -- silently dropped"),
    ("RTLAMR", "RTL-SDR AMR (phy_rtlamr)", "NOT IN _TYPE_MAP -- silently dropped"),
    ("RTLADSB", "RTL-SDR ADS-B (phy_rtladsb)", "NOT IN _TYPE_MAP -- silently dropped"),
    ("Zigbee Device", "Zigbee (phy_zwave or phy_zigbee)", "NOT IN _TYPE_MAP -- silently dropped"),
    ("NRF Mousejack", "NRF (phy_nrf_mousejack)", "NOT IN _TYPE_MAP -- silently dropped"),
    ("Meshtastic Node", "LoRa Meshtastic (phy_meshtastic)", "NOT IN _TYPE_MAP -- silently dropped"),
]


def test_diag_parser_type_map_coverage(diag):
    diag.section("subject + scope")
    diag.fixture(
        f"src/lynceus/kismet.py _TYPE_MAP "
        f"(parser at kismet.py:{inspect.getsourcelines(kismet.parse_kismet_device)[1]})"
    )
    _kismet_lines = Path(inspect.getsourcefile(kismet)).read_text(encoding="utf-8").splitlines()
    _type_map_line = next(i for i, line in enumerate(_kismet_lines, 1) if "_TYPE_MAP:" in line)
    diag.fixture(f"_TYPE_MAP origin line: kismet.py:{_type_map_line}")
    diag.fixture(
        "scope: cross-reference _TYPE_MAP keys against documented "
        "Kismet kismet.device.base.type emissions; identify the gap; "
        "propose minimum-change observability path so operator can "
        "identify the 5 unknown types/tick from journalctl."
    )

    diag.section("current _TYPE_MAP contents")
    diag.observed(f"_TYPE_MAP has {len(_TYPE_MAP)} keys:")
    for k, v in _TYPE_MAP.items():
        diag.observed(f"  {k!r} -> {v!r}")

    diag.section("lynceus device-type enum (codomain)")
    # DeviceObservation.device_type is annotated as Literal["wifi",
    # "ble", "bt_classic", "remote_id"] -- pull the literal values
    # directly off the model so the dump stays in sync if the codomain
    # ever changes.
    device_type_field = DeviceObservation.model_fields["device_type"]
    literal_values = get_args(device_type_field.annotation)
    diag.observed(f"DeviceObservation.device_type values: {list(literal_values)}")
    diag.observed(f"_TYPE_MAP codomain: {sorted(set(_TYPE_MAP.values()))}")
    if set(_TYPE_MAP.values()) != set(literal_values):
        diag.observed(
            "MISMATCH: codomain doesn't cover every device-type literal "
            "(or vice versa). Either an enum value has no Kismet source "
            "type mapped to it, or _TYPE_MAP emits a value the schema "
            "doesn't admit. Worth investigating separately."
        )
    else:
        diag.observed("codomain matches schema literals exactly -- no enum / map drift.")

    diag.section("documented Kismet kismet.device.base.type values")
    diag.observed(
        "Source: Kismet phy plugin set (2022-01R1 through 2024-12). "
        "Type strings are stable across this range; the Kismet "
        "REST API docs and phy_*/phy_*.cc enumerate them."
    )
    diag.observed(f"{len(_DOCUMENTED_KISMET_TYPES)} documented type strings:")
    for type_str, radio, handling in _DOCUMENTED_KISMET_TYPES:
        in_map = type_str in _TYPE_MAP
        marker = "[MAPPED]" if in_map else "[DROPPED]"
        diag.observed(f"  {marker} {type_str!r}  ({radio})  -- {handling}")

    diag.section("coverage gap analysis")
    documented_set = {t for t, _, _ in _DOCUMENTED_KISMET_TYPES}
    mapped_documented = documented_set & set(_TYPE_MAP)
    dropped_documented = documented_set - set(_TYPE_MAP)
    map_only = set(_TYPE_MAP) - documented_set
    diag.observed(f"documented types in _TYPE_MAP (= admitted): {sorted(mapped_documented)}")
    diag.observed(
        f"documented types NOT in _TYPE_MAP (= silently dropped): {sorted(dropped_documented)}"
    )
    diag.observed(
        f"in _TYPE_MAP but NOT in this diagnostic's documented list "
        f"(may be from a Kismet build / version this list doesn't "
        f"cover): {sorted(map_only)}"
    )

    # The operator's 5/tick signal: which documented types could
    # plausibly account for it? The Wi-Fi family covers the bulk of
    # observations in any RF-rich environment, but Wi-Fi AP/Client/
    # Bridged/Device are all mapped. The unmapped Wi-Fi types are
    # 'Wi-Fi WDS' (rare; bridge-mode APs) and 'Wi-Fi Adhoc' (rare; ad-
    # hoc network beacons). The Bluetooth side has 'Bluetooth Link
    # Manager' (the per-connection LMP layer; some Kismet builds
    # surface it as its own type). The Remote-ID strings are
    # _TYPE_MAP'd today but with UNVERIFIED guesses -- if Kismet on
    # the operator's Pi emits a different string, those records also
    # drop and contribute to the 5/tick count.
    diag.observed(
        "likely contributors to the operator's 5/tick drop signal "
        "(ranked by emission frequency in a typical urban RF "
        "environment):"
    )
    diag.observed(
        "  1. 'Remote ID' / 'Remote ID Drone' guesses don't match "
        "operator's Kismet build (the _TYPE_MAP comment at "
        "kismet.py:29-44 already flags this as UNVERIFIED) -- if "
        "the Pi has a Remote-ID-capable receiver running, every "
        "Remote-ID record drops"
    )
    diag.observed(
        "  2. 'Bluetooth Link Manager' (some Kismet builds surface the LMP layer as its own type)"
    )
    diag.observed(
        "  3. 'Wi-Fi WDS' / 'Wi-Fi Adhoc' (rare but present in some "
        "deployments with mesh / repeater APs)"
    )
    diag.observed(
        "  4. RTL-SDR / Zigbee / NRF / Meshtastic phys -- only "
        "relevant if the operator has the corresponding capture "
        "datasource configured (rare)"
    )

    diag.section("proposed minimum-change observability path")
    diag.observed("PROPOSAL (do NOT implement in this arc; draft for the follow-up fix prompt):")
    diag.observed(
        "  Single-line addition to parse_kismet_device at the existing "
        "drop site (kismet.py:432-434):"
    )
    diag.observed("    device_type = _TYPE_MAP.get(kismet_type)")
    diag.observed("    if device_type is None:")
    diag.observed("  +     logger.debug(")
    diag.observed("  +         'dropping kismet device, unrecognized type: type=%r mac=%r',")
    diag.observed("  +         kismet_type, raw_mac,")
    diag.observed("  +     )")
    diag.observed("        return None")
    diag.observed("Operator then runs:")
    diag.observed(
        "  journalctl -u lynceus -p debug | grep 'unrecognized type' | sort | uniq -c | sort -rn"
    )
    diag.observed(
        "and gets a frequency table of the actual type strings their "
        "Kismet is emitting. The next arc extends _TYPE_MAP with the "
        "real strings (and corrects the unverified Remote-ID guesses)."
    )
    diag.observed(
        "Why debug level: the home card already shows the drop count "
        "as the operator-visible signal. Per-record drop lines at "
        "INFO would flood journalctl in any RF-rich environment "
        "(5/tick * 86400 ticks/day = ~7000 lines/day even at the "
        "current observed rate). DEBUG keeps the production log "
        "clean unless an operator opts in to debug-level capture "
        "specifically to diagnose this."
    )
    diag.observed(
        "Why log type AND mac: type alone groups the drops; mac lets "
        "the operator manually inspect a single dropped record in "
        "Kismet's own UI to confirm it's the radio family they expect."
    )

    diag.section("alternative: surface drops via /healthz")
    diag.observed(
        "Could also extend the existing per-tick admitted/dropped "
        "counters (added in 5069e16 / 9274cee) to bucket drops BY "
        "kismet_type and expose the top-N in /healthz JSON. Heavier "
        "change (the counter helper currently aggregates a single "
        "scalar; bucketing requires a small dict). Park as a future "
        "option if the journalctl path turns out to be insufficient "
        "(e.g. operator can't change log level in production)."
    )

    diag.notes(
        "Fix-prompt draft for the follow-up arc (single-touch):\n"
        " * feat(kismet): debug-log unrecognized device types at "
        "drop site to surface kismet_type frequency for operators\n"
        " * test: regression test that the debug log is emitted with "
        "the type + mac kwargs when _TYPE_MAP.get returns None, and "
        "is NOT emitted at INFO level (no log flooding).\n"
        " * No schema migration. No version bump beyond the patch the "
        "fix lands in. No change to the parser's None-return "
        "contract (caller code untouched).\n"
        " * Operator runbook addendum: 'after running for an hour, "
        "grep journalctl for unrecognized type strings, paste the "
        "frequency table back; we extend _TYPE_MAP in the next "
        "release.'"
    )
