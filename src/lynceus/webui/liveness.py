"""Which watchlist pattern_types can actually fire, given the loaded ruleset.

An operator adds a watchlist entry, the UI accepts it, ``/settings`` counts it
and ``/healthz.json`` reports it — and for seven of the ten storable
pattern_types nothing will ever fire (Finding 32, ``docs/AUDIT_REGISTER.md``).
Six are dead because the delegating rule ships **commented out** in
``config/rules.yaml``; ``imei_tac`` is dead because no ``DeviceObservation``
field exists to compare a stored pattern against.

⭐ **This is statically knowable the moment the entry is written.** The ruleset
is loadable, so "does any enabled rule delegate to this pattern_type?" is
answerable without waiting for a device to walk past. That is the whole content
of this module.

⛔ **Nothing here decides whether the dead rules SHOULD be enabled.** That
changes what alerts for every existing deployment and is the operator's call
(reserved for Kev, Finding 32). This module only makes the current answer
visible.

## Why a map, and why it is not a hardcoded list of dead types

The verdict is computed from the ruleset that is loaded at request time, so
uncommenting ``watchlist_oui`` in ``rules.yaml`` flips ``oui`` to live with **no
code change here**. What is written down is only the structural wiring —
which ``rule_type``'s delegation branch consults which ``pattern_type`` — a
fact of ``rules.evaluate`` that changes only when a new rule_type is added.

🪤 A predecessor (#67) warned about ``ble_manufacturer_id`` with a literal
``{% if %}`` in ``settings.html``. It was right about that one type and could
never be right about a second, and it would keep warning after Kev enabled the
rule. This supersedes it. Its two hard-won lessons are kept: use ``dim``
(there is no ``warn`` class in ``lynceus.css``), and collapse whitespace before
asserting on rendered prose.

⚠️ The map is guarded, not trusted. ``tests/test_webui_liveness.py`` compares
every verdict here against what ``rules.evaluate`` actually does with a real
observation, under **two different rulesets** — so the two sides read genuinely
different things, and a map that drifts from the delegation branches fails.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from lynceus import rules as rules_mod

if TYPE_CHECKING:  # pragma: no cover - typing only
    from lynceus.config import Config
    from lynceus.rules import Ruleset

logger = logging.getLogger(__name__)

# rule_type -> the watchlist pattern_types its DB-delegation branch consults.
#
# ⚠️ ``watchlist_ssid`` dispatches TWO pattern_types under one rule_type:
# ``ssid`` (exact) is tried first and ``ssid_pattern`` (case-insensitive
# substring) is the fallback. Operators see one rule_type; the split is
# invisible from the rules.yaml surface. Reading this map as one-to-one is the
# mistake it exists to prevent.
RULE_TYPE_DELEGATES_TO: dict[str, tuple[str, ...]] = {
    "watchlist_mac": ("mac",),
    "watchlist_oui": ("oui",),
    "watchlist_ssid": ("ssid", "ssid_pattern"),
    "watchlist_mac_range": ("mac_range",),
    "ble_uuid": ("ble_uuid",),
    "watchlist_ble_manufacturer_id": ("ble_manufacturer_id",),
    "watchlist_drone_id_prefix": ("drone_id_prefix",),
    "watchlist_ble_local_name": ("ble_local_name",),
}

# rule_types that exist but consult no watchlist row at all. Listed explicitly
# so that adding a rule_type to rules.RuleType and forgetting it here FAILS
# rather than silently defaulting to "delegates to nothing".
NON_DELEGATING_RULE_TYPES: frozenset[str] = frozenset(
    {"new_non_randomized_device", "watchful_recurrence", "ble_device_class"}
)

# ⛔ Storable, and no rule_type can ever serve it: there is no field on
# DeviceObservation to compare the stored pattern against. No ruleset change
# revives this one — it needs capture-side work first (Finding 32). Kept
# separate from "the rule is commented out" because the FIX differs, and an
# operator told "enable the rule" for imei_tac would be sent somewhere with
# nothing to find.
DEAD_BY_MODEL: frozenset[str] = frozenset({"imei_tac"})


def live_pattern_types(ruleset: Ruleset) -> frozenset[str]:
    """The pattern_types a watchlist entry could fire under, for this ruleset.

    A rule contributes only when it is **enabled** and its ``patterns`` list is
    **empty**. A non-empty list is not a stricter version of delegation — it
    turns delegation off for that rule entirely and matches in-memory against
    the listed patterns instead. That is precisely why ``watchlist_oui`` *looks*
    wired in the shipped ruleset: ``hak5_pineapple_oui`` carries an inline
    ``patterns: ["00:13:37"]``, so the operator's OUI rows are never consulted.
    """
    live: set[str] = set()
    for rule in ruleset.rules:
        if not rule.enabled:
            continue
        if rule.patterns:
            continue
        live.update(RULE_TYPE_DELEGATES_TO.get(rule.rule_type, ()))
    return frozenset(live)


def watchlist_liveness(config: Config, pattern_type_counts: dict[str, int]) -> dict:
    """The operator-facing liveness summary for a watchlist.

    ``pattern_type_counts`` is the live per-type breakdown that ``/settings``
    and ``/healthz.json`` already compute — passed in rather than re-queried so
    the number the operator reads and the number graded here cannot disagree.

    Returns a dict with a deliberate **three-state** ``known`` flag:

    ``known=True``   the ruleset loaded; ``live`` / ``inert`` are trustworthy.
    ``known=False``  no ``rules_path`` is configured, or the file failed to
                     load. ``inert`` is empty and ``reason`` says why.

    ⛔ The third state is not decoration. Reporting "all your entries are
    inert" because the rules file has a typo would be a worse lie than the
    silence this module exists to fix — an operator would go and delete rows
    that were fine. Unknown must read as unknown.
    """
    total = sum(int(v) for v in pattern_type_counts.values())
    unknown = {
        "known": False,
        "total": total,
        "live_count": total,
        "inert_count": 0,
        "live_types": (),
        "inert_types": (),
        "dead_by_model_types": (),
        "reason": None,
    }

    if not config.rules_path:
        return {**unknown, "reason": "no rules_path is configured"}
    try:
        ruleset = rules_mod.load_ruleset(config.rules_path)
    except Exception as exc:  # noqa: BLE001 — configured-but-broken is observable
        logger.warning(
            "watchlist liveness: rules_path=%r failed to load (%s); "
            "reporting liveness as unknown rather than as dead",
            config.rules_path,
            exc,
        )
        return {**unknown, "reason": f"the rules file could not be read ({exc})"}

    live_types = live_pattern_types(ruleset)
    # Only types the operator ACTUALLY HAS are reported. A warning about a type
    # nobody stored is noise, and a caution shown on every install is one an
    # operator learns to scroll past.
    stored = {pt for pt, n in pattern_type_counts.items() if int(n) > 0}
    inert = stored - live_types
    live_count = sum(int(pattern_type_counts[pt]) for pt in stored & live_types)
    inert_count = sum(int(pattern_type_counts[pt]) for pt in inert)
    return {
        "known": True,
        "total": total,
        "live_count": live_count,
        "inert_count": inert_count,
        "live_types": tuple(sorted(stored & live_types)),
        "inert_types": tuple(sorted(inert)),
        "dead_by_model_types": tuple(sorted(inert & DEAD_BY_MODEL)),
        "reason": None,
    }


def is_pattern_type_live(pattern_type: str, liveness: dict) -> bool:
    """Whether a single entry's type can fire, for per-row rendering.

    Unknown liveness renders as live: an entry marked "cannot fire" on the
    strength of an unreadable rules file is the false alarm this whole change
    is supposed to avoid.
    """
    if not liveness.get("known"):
        return True
    return pattern_type not in liveness["inert_types"]
