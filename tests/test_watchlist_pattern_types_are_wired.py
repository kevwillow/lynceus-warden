"""Every watchlist pattern_type the operator can STORE, measured end to end:
does a perfectly matching device actually produce an alert?

``tests/test_watchlist_pattern_type_manifest.py`` already proves each type is
ADMITTED — that the tuple matches the live CHECK constraint. Nothing proved any
of them DOES anything. Measured against the shipped ``config/rules.yaml``, seven
of ten do not:

    mac / ssid / ssid_pattern                 -> ALERT
    oui / mac_range / ble_uuid /
    ble_local_name / ble_manufacturer_id /
    drone_id_prefix / imei_tac                -> *** NO ALERT ***

⚠️ This file does NOT assert that the dead types SHOULD fire. Enabling the
delegating rules changes what alerts for every existing deployment, and that is
the operator's call, not a test's. What it asserts is that the set is exactly
what we measured — so the gap cannot grow silently, and cannot be closed
silently either. Both directions fail:

  * a NEW pattern_type added without wiring        -> test_the_admitted_types_...
  * a dead type WIRED UP                           -> test_the_dead_types_...
  * a working type BROKEN                          -> test_the_wired_types_...

⭐ Two distinct causes are deliberately kept apart, because the fixes differ:

  DEAD_BY_CONFIG   the rule exists and is commented out in config/rules.yaml.
                   Uncommenting it revives the type. A deployment decision.
  DEAD_BY_MODEL    ``imei_tac`` has NO field on DeviceObservation at all, so
                   there is nothing to compare a stored pattern against. No
                   ruleset change can revive it; it needs capture-side work
                   first. Admitted by migration 021 and by add_watchlist.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

import pytest

from lynceus.db import Database
from lynceus.kismet import DeviceObservation
from lynceus.rules import evaluate, load_ruleset

REPO_ROOT = Path(__file__).resolve().parents[1]
SHIPPED_RULES = REPO_ROOT / "config" / "rules.yaml"

# Measured 2026-08-15 against the shipped ruleset. See the module docstring.
WIRED_TYPES = frozenset({"mac", "ssid", "ssid_pattern"})
DEAD_BY_CONFIG = frozenset(
    {"oui", "ble_uuid", "ble_local_name", "ble_manufacturer_id", "drone_id_prefix"}
)
# mac_range is DEAD_BY_CONFIG too -- its rule ships commented out like the rest.
# It gets its own name only because it was ALSO dead for a second, independent
# reason (the write surface left the matched columns NULL), fixed in this change.
DEAD_BY_CONFIG_MAC_RANGE = frozenset({"mac_range"})
DEAD_BY_MODEL = frozenset({"imei_tac"})
DEAD_TYPES = DEAD_BY_CONFIG | DEAD_BY_CONFIG_MAC_RANGE | DEAD_BY_MODEL

# pattern_type -> (stored pattern, observation kwargs that match it EXACTLY).
# None kwargs means "no observation field exists to carry this" (DEAD_BY_MODEL).
CASES: dict[str, tuple[str, dict | None]] = {
    "mac": ("3c:5a:b4:dd:ee:01", {"mac": "3c:5a:b4:dd:ee:01"}),
    "oui": ("3c:5a:b4", {"mac": "3c:5a:b4:11:22:33"}),
    # /24 is rejected on purpose (that shape is identifier_type=oui by IEEE
    # design); only /28 and /36 parse. A /24 here reads exactly like the type
    # being dead and is not.
    "mac_range": ("3c:5a:b4:d/28", {"mac": "3c:5a:b4:dd:ee:07"}),
    "ssid": ("MyTargetNet", {"mac": "3c:5a:b4:dd:ee:02", "ssid": "MyTargetNet"}),
    # ⚠️ ssid_pattern is a SUBSTRING needle, not a glob -- the SQL wraps it as
    # ``? LIKE '%' || pattern || '%'``. A '*' here is a literal asterisk and
    # matches nothing, which reads exactly like the type being dead. It is not.
    "ssid_pattern": ("MyTarget", {"mac": "3c:5a:b4:dd:ee:03", "ssid": "MyTargetNet"}),
    "ble_uuid": (
        "0000fd5a-0000-1000-8000-00805f9b34fb",
        {
            "mac": "3c:5a:b4:dd:ee:04",
            "device_type": "ble",
            "ble_service_uuids": ("0000fd5a-0000-1000-8000-00805f9b34fb",),
        },
    ),
    "ble_local_name": (
        "TrackerTag",
        {"mac": "3c:5a:b4:dd:ee:05", "device_type": "ble", "ble_local_name": "TrackerTag"},
    ),
    "ble_manufacturer_id": (
        "004c",
        {"mac": "3c:5a:b4:dd:ee:06", "device_type": "ble", "ble_manufacturer_id": "004c"},
    ),
    "drone_id_prefix": ("1581F", {"mac": "3c:5a:b4:dd:ee:08", "drone_id_prefix": "1581FABC"}),
    "imei_tac": ("35291612", None),
}


def _observation(**kw) -> DeviceObservation:
    base = {
        "mac": "00:00:00:00:00:00",
        "device_type": kw.pop("device_type", "wifi"),
        "first_seen": 1786800000,
        "last_seen": 1786800000,
        "rssi": -40,
        "ssid": None,
        "oui_vendor": None,
        "is_randomized": False,
    }
    base.update(kw)
    return DeviceObservation(**base)


def _alerts_for(pattern_type: str, tmp_path: Path) -> list[str]:
    """Store a watchlist entry of this type, observe a matching device, return
    the names of the rules that fired."""
    pattern, obs_kwargs = CASES[pattern_type]
    assert obs_kwargs is not None, f"{pattern_type} has no observation field; use the model test"
    db = Database(str(tmp_path / f"{pattern_type}.db"))
    # The sanctioned write surface -- the same call the web UI's "add to
    # watchlist" action uses. If this raises, the type is not operator-reachable
    # and the whole question is moot, so it is an assertion, not a skip.
    db.add_watchlist(
        pattern=pattern,
        pattern_type=pattern_type,
        severity="high",
        description=f"operator watchlist entry ({pattern_type})",
    )
    ruleset = load_ruleset(SHIPPED_RULES)
    hits = evaluate(ruleset, _observation(**obs_kwargs), False, db=db)
    return [h.rule_name for h in hits]


def _admitted_pattern_types(tmp_path: Path) -> set[str]:
    """Parse the live CHECK constraint rather than reading the Python tuple, so
    the two sides of the assertion have independent sources."""
    Database(str(tmp_path / "schema.db"))
    conn = sqlite3.connect(str(tmp_path / "schema.db"))
    try:
        sql = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='watchlist'"
        ).fetchone()[0]
    finally:
        conn.close()
    match = re.search(r"pattern_type\s+TEXT[^,]*?CHECK\s*\(\s*pattern_type\s+IN\s*\(([^)]*)\)",
                      sql, re.IGNORECASE | re.DOTALL)
    assert match, f"could not find the pattern_type CHECK constraint in:\n{sql}"
    return set(re.findall(r"'([^']+)'", match.group(1)))


def test_the_admitted_types_are_exactly_the_ones_we_have_classified(tmp_path):
    """A new pattern_type must be classified as wired or dead, not just admitted.

    Fails when a migration adds a type and nobody says whether it does anything.
    """
    admitted = _admitted_pattern_types(tmp_path)
    # Presence floor: a regex that matched nothing would make every set
    # comparison below vacuously true.
    assert len(admitted) >= 10, f"parsed too few pattern types, instrument is broken: {admitted}"
    classified = WIRED_TYPES | DEAD_TYPES
    assert admitted == classified, (
        f"unclassified pattern types: {sorted(admitted - classified)}; "
        f"classified but no longer admitted: {sorted(classified - admitted)}. "
        "Measure whether each new type actually alerts, then add it to "
        "WIRED_TYPES or DEAD_BY_CONFIG/DEAD_BY_MODEL."
    )


@pytest.mark.parametrize("pattern_type", sorted(WIRED_TYPES))
def test_the_wired_types_do_alert_on_an_exact_match(pattern_type, tmp_path):
    """The presence assertion. Without it, the absence test below is satisfied
    by a ruleset that alerts on nothing at all."""
    fired = _alerts_for(pattern_type, tmp_path)
    assert fired, (
        f"watchlist pattern_type {pattern_type!r} no longer alerts on an exact match. "
        "A delegating rule in config/rules.yaml was removed, disabled, or given a "
        "non-empty patterns list (non-empty patterns disable DB delegation for that "
        "rule_type entirely)."
    )


@pytest.mark.parametrize("pattern_type", sorted(DEAD_BY_CONFIG))
def test_the_dead_types_still_produce_no_alert(pattern_type, tmp_path):
    """The absence assertion, and the one that fires when someone FIXES this.

    ⚠️ Not a claim that this is correct behaviour -- it is a claim that the set
    has not moved without the register moving with it. If you wired one of these
    up, that is good: move it to WIRED_TYPES and update the register.
    """
    fired = _alerts_for(pattern_type, tmp_path)
    assert not fired, (
        f"watchlist pattern_type {pattern_type!r} now alerts (rules: {fired}). "
        "If that was intended, move it from DEAD_BY_CONFIG to WIRED_TYPES and "
        "update docs/AUDIT_REGISTER.md -- this test is the record of the gap."
    )


def test_imei_tac_cannot_be_revived_by_configuration_alone():
    """The distinct sub-class: no observation field exists to match against.

    ``imei_tac`` is admitted by migration 021 and accepted by ``add_watchlist``,
    but ``DeviceObservation`` has no ``imei_tac`` attribute, so no rule -- enabled
    or not -- has anything to compare a stored pattern to. Uncommenting rules
    cannot fix this one; it needs capture-side work first.
    """
    assert "imei_tac" not in DeviceObservation.model_fields, (
        "DeviceObservation now carries imei_tac -- the capture side landed. "
        "Re-measure whether a matching device alerts and reclassify the type; "
        "it may now belong in DEAD_BY_CONFIG or WIRED_TYPES."
    )
    # Presence beside absence: the field the manifest DOES carry, so a rename of
    # model_fields cannot make the assertion above vacuously true.
    assert "ble_local_name" in DeviceObservation.model_fields


def test_the_store_accepts_every_dead_type_which_is_why_this_matters(tmp_path):
    """The reachability half. A dead type is only a defect because the operator
    can store one and be told nothing."""
    db = Database(str(tmp_path / "reach.db"))
    stored = []
    for pattern_type in sorted(DEAD_TYPES):
        pattern, _ = CASES[pattern_type]
        watchlist_id, inserted = db.add_watchlist(
            pattern=pattern, pattern_type=pattern_type, severity="high", description=None
        )
        assert inserted, f"{pattern_type} was not stored"
        stored.append(watchlist_id)
    assert len(stored) == len(DEAD_TYPES) >= 7, (
        "every dead pattern_type is accepted by the sanctioned write surface "
        "with no warning, which is what makes the gap invisible to the operator"
    )


# --------------------------------------------------------------------------
# mac_range was dead TWICE, and the second cause is a write-surface defect
# rather than a deployment choice. Measured 2026-08-15, with the delegating
# rule ENABLED so the ruleset is not the variable:
#
#   add_watchlist("3c:5a:b4:d/28")            prefix=None  -> *** NO ALERT ***
#   same row + derived columns populated      prefix=3c5ab4d -> ALERT
#
# `_lookup_mac_range_matches` reads the migration-011 index on
# (mac_range_prefix_length, mac_range_prefix), never `pattern`. Only the Argus
# importer populated them, so every UI-created and hand-seeded mac_range row
# was inert while being reported as "inserted".
# --------------------------------------------------------------------------

DELEGATING_MAC_RANGE_RULESET = """
rules:
  - name: test_mac_range
    rule_type: watchlist_mac_range
    severity: low
    patterns: []
    description: "enabled so the ruleset is not the variable under test"
"""


def _mac_range_ruleset(tmp_path: Path):
    path = tmp_path / "mac_range_rules.yaml"
    path.write_text(DELEGATING_MAC_RANGE_RULESET)
    return load_ruleset(path)


def test_add_watchlist_populates_the_columns_the_lookup_actually_reads(tmp_path):
    db = Database(str(tmp_path / "w.db"))
    wid, inserted = db.add_watchlist(
        pattern="3c:5a:b4:d/28", pattern_type="mac_range", severity="high", description=None
    )
    assert inserted
    conn = sqlite3.connect(str(tmp_path / "w.db"))
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT mac_range_prefix, mac_range_prefix_length FROM watchlist WHERE id=?",
            (wid,),
        ).fetchone()
        # Presence beside absence: a non-mac_range row must still leave them
        # NULL, or an INSERT that filled every row with junk would pass above.
        mac_id, _ = db.add_watchlist(
            pattern="3c:5a:b4:dd:ee:01", pattern_type="mac", severity="high", description=None
        )
        mac_row = conn.execute(
            "SELECT mac_range_prefix, mac_range_prefix_length FROM watchlist WHERE id=?",
            (mac_id,),
        ).fetchone()
    finally:
        conn.close()
    assert row["mac_range_prefix"] == "3c5ab4d"
    assert row["mac_range_prefix_length"] == 28
    assert mac_row["mac_range_prefix"] is None
    assert mac_row["mac_range_prefix_length"] is None


def test_a_mac_range_row_written_by_add_watchlist_actually_fires(tmp_path):
    """The behaviour, not the column. This is the assertion that would have
    caught the defect; the column check above only explains it."""
    db = Database(str(tmp_path / "fire.db"))
    db.add_watchlist(
        pattern="3c:5a:b4:d/28", pattern_type="mac_range", severity="high", description=None
    )
    ruleset = _mac_range_ruleset(tmp_path)
    inside = evaluate(ruleset, _observation(mac="3c:5a:b4:dd:ee:07"), False, db=db)
    outside = evaluate(ruleset, _observation(mac="3c:5a:b4:11:22:33"), False, db=db)
    assert [h.rule_name for h in inside] == ["test_mac_range"], (
        "a mac_range row written through the sanctioned write surface still does "
        "not match a device inside the range"
    )
    # The range must still be a range -- a fix that matched everything would
    # satisfy the assertion above.
    assert outside == [], "a device outside the /28 must not match"


def test_add_watchlist_refuses_a_mac_range_it_could_never_match(tmp_path):
    """Fail closed. /24 is rejected by design (that shape is an OUI), and
    storing it would produce a row the operator believes is watching."""
    db = Database(str(tmp_path / "refuse.db"))
    with pytest.raises(ValueError, match="could never fire"):
        db.add_watchlist(
            pattern="3c:5a:b4:dd:ee:00/24",
            pattern_type="mac_range",
            severity="high",
            description=None,
        )
    # Presence beside absence: the valid shape is still accepted.
    _, inserted = db.add_watchlist(
        pattern="3c:5a:b4:d/28", pattern_type="mac_range", severity="high", description=None
    )
    assert inserted


def test_the_yaml_seeder_writes_a_row_that_matches(tmp_path):
    """The seeder had its own duplicate INSERT and drifted from add_watchlist.
    Driving the real entry point proves the two are one path now."""
    from lynceus.cli.seed_watchlist import seed_from_yaml

    yaml_path = tmp_path / "seed.yaml"
    yaml_path.write_text(
        'entries:\n'
        '  - pattern: "3c:5a:b4:d/28"\n'
        "    pattern_type: mac_range\n"
        "    severity: high\n"
        '    description: "operator hand-seeded mac_range"\n'
    )
    db = Database(str(tmp_path / "seeded.db"))
    inserted, _skipped = seed_from_yaml(db, str(yaml_path))
    assert inserted == 1, "the seeder did not insert the entry at all"
    hits = evaluate(
        _mac_range_ruleset(tmp_path), _observation(mac="3c:5a:b4:dd:ee:07"), False, db=db
    )
    assert [h.rule_name for h in hits] == ["test_mac_range"], (
        "the seeder reported the row as inserted and it still cannot match -- "
        "which is exactly what it did before this fix"
    )
