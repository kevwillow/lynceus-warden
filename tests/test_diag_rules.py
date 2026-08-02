"""Diagnostic dumps for the rules engine evaluation order + severity.

``rules.evaluate(ruleset, obs, is_new_device, db=, severity_overrides=)``
iterates ``ruleset.rules`` in YAML order; each rule emits zero or
more ``RuleHit``s based on its rule_type's matching logic. Two
distinct pattern_types coexist under the single ``watchlist_ssid``
rule_type: ``ssid`` (exact-equality) and ``ssid_pattern``
(case-insensitive substring), with exact consulted first
(rules.py:872-874).

These tests build observation + watchlist fixtures that hit multiple
branches simultaneously and dump:

- The emitted RuleHit list in order (rule_type, severity, message).
- The ``matched_watchlist_id`` resolved by
  ``Database.resolve_matched_watchlist_id`` (annotation path, distinct
  from evaluate's per-hit emit path).
- How ssid_exact vs ssid_pattern interact when both could match.
"""

from __future__ import annotations

import pytest

from lynceus.db import Database
from lynceus.kismet import DeviceObservation
from lynceus.rules import Rule, Ruleset, evaluate

pytestmark = pytest.mark.diagnostic


def _add_wl(
    db: Database,
    pattern: str,
    pattern_type: str,
    severity: str = "med",
    *,
    mac_range_prefix: str | None = None,
    mac_range_prefix_length: int | None = None,
    description: str | None = None,
) -> int:
    cur = db._conn.execute(
        "INSERT INTO watchlist("
        "pattern, pattern_type, severity, description, "
        "mac_range_prefix, mac_range_prefix_length) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (pattern, pattern_type, severity, description,
         mac_range_prefix, mac_range_prefix_length),
    )
    db._conn.commit()
    return int(cur.lastrowid)


def _format_hit(h) -> str:
    return (f"rule_name={h.rule_name!r} rule_type={h.rule_type!r} "
            f"severity={h.severity!r} mac={h.mac!r} message={h.message!r}")


# ---------------------------------------------------------------------------
# Test 1 — eval-order across every rule_type with a multi-match observation
# ---------------------------------------------------------------------------


def test_diag_rules_eval_order(diag, tmp_path):
    db = Database(str(tmp_path / "diag.db"))

    # Plant a watchlist row per pattern_type so each delegation path has
    # something to find.
    wl_mac = _add_wl(db, "aa:bb:cc:11:22:33", "mac", "high")
    wl_oui = _add_wl(db, "aa:bb:cc", "oui", "med")
    wl_ssid = _add_wl(db, "DiagExactSSID", "ssid", "med")
    wl_ssid_pat = _add_wl(db, "diag-pat", "ssid_pattern", "low")
    wl_mac_range = _add_wl(
        db, "aa:bb:cc:1/28", "mac_range", "high",
        mac_range_prefix="aabbcc1", mac_range_prefix_length=28,
    )
    wl_ble_uuid = _add_wl(
        db, "0000180a-0000-1000-8000-00805f9b34fb", "ble_uuid", "med",
    )
    wl_ble_mfg = _add_wl(db, "004c", "ble_manufacturer_id", "med")
    wl_drone = _add_wl(db, "DIAGDRONE", "drone_id_prefix", "high")
    diag.fixture(f"planted watchlist rows: mac={wl_mac} oui={wl_oui} "
                 f"ssid_exact={wl_ssid} ssid_pattern={wl_ssid_pat} "
                 f"mac_range={wl_mac_range} ble_uuid={wl_ble_uuid} "
                 f"ble_mfg={wl_ble_mfg} drone={wl_drone}")

    # Build a ruleset with delegation-mode (empty patterns) entries for
    # every supported rule_type.
    ruleset = Ruleset(rules=[
        Rule(name="rule-mac", rule_type="watchlist_mac", severity="med"),
        Rule(name="rule-oui", rule_type="watchlist_oui", severity="low"),
        Rule(name="rule-ssid", rule_type="watchlist_ssid", severity="high"),
        Rule(name="rule-mac-range", rule_type="watchlist_mac_range",
             severity="med"),
        Rule(name="rule-ble-uuid", rule_type="ble_uuid", severity="low"),
        Rule(name="rule-ble-mfg",
             rule_type="watchlist_ble_manufacturer_id", severity="med"),
        Rule(name="rule-drone",
             rule_type="watchlist_drone_id_prefix", severity="high"),
        Rule(name="rule-new-device",
             rule_type="new_non_randomized_device", severity="low"),
    ])
    diag.fixture(f"ruleset: {len(ruleset.rules)} rules, all in DB-delegation "
                 "(empty-patterns) mode")

    # Observation that fires every branch at once.
    obs = DeviceObservation(
        mac="aa:bb:cc:11:22:33",
        device_type="wifi",
        first_seen=1_700_000_000,
        last_seen=1_700_000_000,
        rssi=-50,
        ssid="DiagExactSSID",
        oui_vendor="DiagVendor",
        is_randomized=False,
        ble_service_uuids=("0000180a-0000-1000-8000-00805f9b34fb",),
        ble_manufacturer_id="004c",
        drone_id_prefix="DIAGDRONE",
    )
    diag.fixture(f"observation: mac={obs.mac} ssid={obs.ssid!r} "
                 f"ble_service_uuids={obs.ble_service_uuids} "
                 f"ble_manufacturer_id={obs.ble_manufacturer_id} "
                 f"drone_id_prefix={obs.drone_id_prefix} is_randomized=False")

    diag.exercise("evaluate(ruleset, obs, is_new_device=True, db=db)")
    hits = evaluate(ruleset, obs, is_new_device=True, db=db)
    diag.observed(f"hit count: {len(hits)}")
    diag.observed("--- emitted RuleHits in order ---")
    for h in hits:
        diag.observed(f"  {_format_hit(h)}")

    annotated = db.resolve_matched_watchlist_id(
        mac=obs.mac,
        ssid=obs.ssid,
        ble_service_uuids=obs.ble_service_uuids,
        ble_manufacturer_id=obs.ble_manufacturer_id,
        drone_id_prefix=obs.drone_id_prefix,
    )
    diag.observed(f"resolve_matched_watchlist_id annotation: {annotated}")
    diag.observed(f"  (matches wl_mac={wl_mac}? {annotated == wl_mac})")
    diag.observed(f"  (matches wl_mac_range={wl_mac_range}? "
                  f"{annotated == wl_mac_range})")

    diag.notes("evaluate emits one RuleHit per matching rule -- a multi-branch "
               "observation fires every branch independently. "
               "resolve_matched_watchlist_id is a SEPARATE walk used for "
               "the alert-row annotation; its walk order is the same as the "
               "rules engine but it returns a single id (the first match in "
               "walk order).")
    db.close()


# ---------------------------------------------------------------------------
# Test 2 — severity resolution under multiple matches
# ---------------------------------------------------------------------------


def test_diag_rules_severity_resolution(diag, tmp_path):
    db = Database(str(tmp_path / "diag.db"))

    # Two watchlist rows that BOTH match the same observation, with
    # divergent severities. Observation: MAC + OUI matches.
    wl_mac = _add_wl(db, "aa:bb:cc:11:22:33", "mac", "low")  # low severity
    wl_oui = _add_wl(db, "aa:bb:cc", "oui", "high")          # high severity
    diag.fixture(f"watchlist: mac={wl_mac} severity='low', oui={wl_oui} "
                 f"severity='high' -- both match aa:bb:cc:11:22:33")

    # Ruleset orders mac FIRST, oui SECOND -- evaluate walks rules in
    # ruleset.rules order. This dump shows whether the engine emits both
    # hits independently OR whether earlier matches short-circuit later
    # ones.
    ruleset = Ruleset(rules=[
        Rule(name="rule-mac", rule_type="watchlist_mac", severity="med"),
        Rule(name="rule-oui", rule_type="watchlist_oui", severity="med"),
    ])
    diag.fixture("ruleset order: rule-mac BEFORE rule-oui (both DB-delegation)")

    obs = DeviceObservation(
        mac="aa:bb:cc:11:22:33",
        device_type="wifi",
        first_seen=1_700_000_000,
        last_seen=1_700_000_000,
        rssi=-50, ssid=None, oui_vendor=None, is_randomized=False,
    )

    diag.exercise("evaluate() with overlapping mac+oui rules")
    hits = evaluate(ruleset, obs, is_new_device=False, db=db)
    diag.observed(f"hit count: {len(hits)}")
    for h in hits:
        diag.observed(f"  {_format_hit(h)}")

    # Confirm severity provenance: for DB-delegation matches, severity
    # is sourced from the matched watchlist row, NOT from rule.severity.
    diag.observed("severity expectation: each DB-delegation hit's severity "
                  "should equal the matched watchlist row's severity, NOT "
                  "the rule.severity (which is 'med' for both rules above).")
    diag.notes("Single-emit-vs-multi-emit determines whether the alert table "
               "lands with one or two rows for the same observation. If "
               "evaluate emits both, the dedup layer downstream collapses "
               "them; if evaluate emits one, the dedup choice is moot.")
    db.close()


# ---------------------------------------------------------------------------
# Test 3 — ssid_exact vs ssid_pattern when both could match
# ---------------------------------------------------------------------------


def test_diag_rules_ssid_pattern_vs_ssid_exact(diag, tmp_path):
    db = Database(str(tmp_path / "diag.db"))

    # Two watchlist rows that could BOTH match SSID 'AcmeRouter':
    # - exact: pattern_type 'ssid', pattern 'AcmeRouter'
    # - pattern: pattern_type 'ssid_pattern', pattern 'router'
    wl_exact = _add_wl(db, "AcmeRouter", "ssid", "high")
    wl_pattern = _add_wl(db, "router", "ssid_pattern", "low")
    diag.fixture(f"watchlist: ssid_exact={wl_exact} (pattern='AcmeRouter', "
                 f"severity='high'), ssid_pattern={wl_pattern} "
                 f"(pattern='router', severity='low')")

    ruleset = Ruleset(rules=[
        Rule(name="rule-ssid", rule_type="watchlist_ssid", severity="med"),
    ])
    diag.fixture("ruleset: single watchlist_ssid rule (delegation mode)")

    obs = DeviceObservation(
        mac="aa:bb:cc:11:22:33",
        device_type="wifi",
        first_seen=1_700_000_000,
        last_seen=1_700_000_000,
        rssi=-50, ssid="AcmeRouter", oui_vendor=None, is_randomized=False,
    )
    diag.fixture(f"observation ssid={obs.ssid!r} (would match BOTH rows)")

    diag.exercise("evaluate() with overlapping ssid_exact + ssid_pattern")
    hits = evaluate(ruleset, obs, is_new_device=False, db=db)
    diag.observed(f"hit count: {len(hits)}")
    for h in hits:
        diag.observed(f"  {_format_hit(h)}")
    if hits:
        # The hit's severity should be 'high' if exact won, 'low' if
        # pattern won.
        diag.observed(f"resolved severity: {hits[0].severity!r} -- "
                      f"{'EXACT won' if hits[0].severity == 'high' else 'PATTERN won'}")

    # Now try an observation that only the pattern row matches.
    obs_pat_only = DeviceObservation(
        mac="aa:bb:cc:11:22:44",
        device_type="wifi",
        first_seen=1_700_000_000, last_seen=1_700_000_000,
        rssi=-50, ssid="OurRouter", oui_vendor=None, is_randomized=False,
    )
    diag.exercise(f"evaluate() with ssid={obs_pat_only.ssid!r} "
                  "(pattern-only match)")
    hits2 = evaluate(ruleset, obs_pat_only, is_new_device=False, db=db)
    diag.observed(f"hit count: {len(hits2)}")
    for h in hits2:
        diag.observed(f"  {_format_hit(h)}")

    diag.notes("rules.py:872-874 consults resolve_matched_ssid_for_eval first; "
               "ssid_pattern is the FALLBACK only when exact misses. So with "
               "both rows present and an exact-matching ssid, exact wins and "
               "the severity from the high-severity exact row should be on "
               "the emitted RuleHit. Reviewer: confirm the resolved severity "
               "matches the expected winner.")
    db.close()
