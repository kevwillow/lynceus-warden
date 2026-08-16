"""Which watchlist pattern_types can actually fire, given the loaded ruleset.

⛔ **KNOWN LIMITS — read these before treating anything here as "will alert".**
There are FIVE mechanisms that stop a stored entry producing an alert. This
module reports three of them, and the other two are stated rather than
half-answered:

===========================  ==========  ==================================
mechanism                    reported?   why / why not
===========================  ==========  ==================================
no delegating rule (inert)   yes         per pattern_type, from the ruleset
rule_type snoozed            yes         per pattern_type, from the DB
severity override            yes         per ROW, from watchlist_metadata
allowlist match              **no**      suppresses by DEVICE, not by row --
                                         one watchlist row can match many
                                         devices, so there is no honest
                                         per-row answer to render
clock-disagreement at write  **no**      `webui/clock.py` is a WRITE-TIME
                                         guard, not a row state: nothing
                                         records that an existing
                                         suppression was written under a
                                         bad clock, so it cannot be
                                         attributed to a row afterwards
===========================  ==========  ==================================

⇒ Inert / snoozed / override are **independent flags and can co-occur**; each
carries its own remediation and reporting only one offers a next step that does
not restore alerting. The two unreported ones mean **no count here is a promise
that a row will alert** — see ``watchlist_liveness``.

⭐ **One more mechanism sits OUTSIDE that table, because it silences nothing: a
severity REMAP** (``pattern_overrides`` / ``vendor_severity`` /
``device_category_severity``). It does not stop the alert; it changes what the
alert says — so it is not a sixth row above, and counting it as one would
overstate what that table is about. Every watchlist surface rendered
``watchlist.severity``, which the runtime layer then re-decides at alert time: a
row stored ``high`` alerting ``low``, on the severity column an operator sorts
and filters by. That is Finding 42, and ``effective_severity`` answers it.

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
import sqlite3
from typing import TYPE_CHECKING

from lynceus import rules as rules_mod
from lynceus.rules import _is_reserved_oui_mac

if TYPE_CHECKING:  # pragma: no cover - typing only
    from lynceus.config import Config
    from lynceus.db import Database
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


def oui_prefix_never_matches(pattern_type: str, pattern: str | None) -> str | None:
    """Reason this row can never match regardless of the ruleset, or None.

    Applies only to pattern_type == "oui". Returns the human reason string from
    rules._is_reserved_oui_mac, or None when the row can match.
    """
    if pattern_type != "oui" or not pattern:
        return None
    is_reserved, reason = _is_reserved_oui_mac(pattern)
    if not is_reserved:
        return None
    # ⚠️ The VERDICT decides, never the reason's truthiness. `return reason if
    # is_reserved else None` couples them, so a future `(True, None)` or
    # `(True, "")` would silently answer "this row can match" -- a guard that
    # reports "no" when it cannot describe its own finding. Unreachable today
    # (every True branch of _is_reserved_oui_mac carries a non-empty string),
    # and pinned by a test so it stays that way.
    return reason or "reserved or locally-administered prefix"


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


def snoozed_pattern_types(db: Database, now_ts: int) -> dict[str, int]:
    """``{pattern_type: snooze expiry}`` for every type an active rule_type
    snooze is currently silencing.

    ⭐ A snooze is a SECOND way a stored entry produces no alert, and it is a
    completely different thing from being inert. The rule fires normally — the
    poller drops the alert at emit time (``poller.py``'s
    ``is_rule_type_snoozed`` gate). So the entry is not dead: it is silenced,
    deliberately, by the operator, until a time they chose.

    ⛔ Which is exactly why it must NOT be folded into ``inert_types``. Telling
    someone "no enabled rule delegates to this type" about a type they snoozed
    themselves last week sends them into ``rules.yaml`` to fix a file that is
    already correct. The cause is different, the fix is different, and the
    honest report says which one it is.

    ⚠️ The web UI can set one of these itself (``POST /rules/{rule_type}/snooze``),
    so this is reachable without ever touching a config file.
    """
    by_rule_type: dict[str, int] = {}
    try:
        for snooze in db.list_active_rule_type_snoozes(now_ts):
            by_rule_type[snooze.rule_type] = int(snooze.expires_at)
    except sqlite3.Error as exc:
        # A legacy install predating the rule_type_snoozes table must not 500
        # the watchlist pages. No snoozes readable = report none, which is the
        # same answer the pre-snooze releases gave.
        logger.warning("watchlist liveness: rule_type snoozes unreadable (%s)", exc)
        return {}

    out: dict[str, int] = {}
    for rule_type, expires_at in by_rule_type.items():
        for pattern_type in RULE_TYPE_DELEGATES_TO.get(rule_type, ()):
            # ⚠️ This marks the type suppressed when ANY serving rule_type is
            # snoozed, and takes the latest expiry.
            #
            # 🪤 The comment here used to claim the opposite -- "silenced only
            # while EVERY one is snoozed" -- which `max()` does not establish
            # and the code never did. Dormant today (no pattern_type has two
            # delegators), so nothing exercised the difference; it would have
            # OVER-reported suppression the moment the map gained that shape.
            # A cold read caught it. If such a type is ever added, decide the
            # semantics deliberately and test it, rather than inheriting this.
            out[pattern_type] = max(out.get(pattern_type, 0), expires_at)
    return out


def watchlist_liveness(
    config: Config,
    pattern_type_counts: dict[str, int],
    *,
    db: Database | None = None,
    now_ts: int | None = None,
) -> dict:
    """The operator-facing liveness summary for a watchlist.

    ``pattern_type_counts`` is the live per-type breakdown that ``/settings``
    and ``/healthz.json`` already compute — passed in rather than re-queried so
    the number the operator reads and the number graded here cannot disagree.

    ``db`` / ``now_ts`` are optional so a caller that only wants the ruleset
    verdict need not supply them; omitting them reports **no** snoozes, which
    is what every release before them reported.

    Returns a dict with a deliberate **three-state** ``known`` flag:

    ``known=True``   the ruleset loaded; ``live`` / ``inert`` are trustworthy.
    ``known=False``  no ``rules_path`` is configured, or the file failed to
                     load. ``inert`` is empty and ``reason`` says why.

    ⛔ The third state is not decoration. Reporting "all your entries are
    inert" because the rules file has a typo would be a worse lie than the
    silence this module exists to fix — an operator would go and delete rows
    that were fine. Unknown must read as unknown.

    ⛔ **These are INDEPENDENT FLAGS, not a partition — an earlier version of
    this docstring said "partition" and the code enforced it, which was the
    defect.** A type can be inert AND snoozed; both are reported, because
    fixing either one alone does not restore alerting.

    ⚠️ **Which means the counts OVERLAP and must not be summed.** A type in
    ``both_types`` is counted in ``inert_count`` and in ``suppressed_count``,
    so ``live + inert + suppressed`` can exceed ``total``. That is the correct
    behaviour for independent flags and the wrong behaviour for anything
    treating them as a partition — ``/healthz.json`` exports the two type LISTS
    beside the counts precisely so a consumer can intersect them rather than
    infer a partition that does not exist.

    ⚠️ **``live_count`` is not "rows that will alert."** It counts rows whose
    TYPE is delegated and unsnoozed. Two further mechanisms silence individual
    rows and neither is visible here:

      * a ``suppress_vendors`` / ``suppress_categories`` severity override —
        per row, reported by ``override_suppression_axes`` and marked on
        ``/watchlist``, but NOT subtracted from this count (doing so needs a
        full-table scan; see ``runtime_suppressions``);
      * an **allowlist** match — which suppresses by DEVICE, not by watchlist
        row, so it has no clean per-row rendering at all. Stated as a known
        limit rather than half-answered.

    ⇒ Read ``live_count`` as *delegated and unsnoozed*, never as a promise.
    """
    total = sum(int(v) for v in pattern_type_counts.values())
    # ⛔ `None`, not `total`. This said `live_count: total` and it was a
    # CONTRADICTION shipped as a reassurance: `/healthz.json` returned
    # `liveness_known: false` beside `live_rows: <every row you have>`, and a
    # monitoring tool that graphs live_rows without gating on the boolean reads
    # a clean bill off an unreadable rules file. Unknown means no row is KNOWN
    # live; the only honest count is no count.
    #
    # 🪤 My own guard missed this. The unknown-state test asserted `inert_rows`
    # and did not assert `live_rows` — an absence assertion with no presence
    # assertion beside it. Both are asserted now.
    unknown = {
        "known": False,
        "total": total,
        "live_count": None,
        "inert_count": None,
        "suppressed_count": None,
        "live_types": (),
        "inert_types": (),
        "suppressed_types": (),
        "both_types": (),
        "suppressed_until": {},
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

    snoozed_until: dict[str, int] = {}
    if db is not None and now_ts is not None:
        # ⛔ Applied to everything STORED, not intersected with `live_types`.
        #
        # 🪤 It was intersected, on the reasoning that "unsnoozing an inert type
        # changes nothing, so inert wins". That reasoning has an exact inverse
        # which is just as true: **fixing the delegation changes nothing either,
        # because the snooze is still there.** Collapsing to one cause offers a
        # remediation that does not restore alerting, whichever one you pick.
        #
        # ⇒ They are INDEPENDENT FLAGS, not states in a partition. A type can be
        # both, and both have to be said, because the operator has to do both.
        # I had a planted defect asserting the old behaviour was correct -- a
        # plant certifies the model the test encodes, so it happily pinned this.
        snoozed_until = {
            pt: exp
            for pt, exp in snoozed_pattern_types(db, now_ts).items()
            if pt in stored
        }
    suppressed = set(snoozed_until)
    # "Firing" means nothing known to THIS function silences it: the type is
    # delegated AND not snoozed. ⚠️ It still cannot account for the per-row
    # causes (a severity override, an allowlist match) -- see the docstring.
    firing = (stored & live_types) - suppressed

    return {
        "known": True,
        "total": total,
        "live_count": sum(int(pattern_type_counts[pt]) for pt in firing),
        "inert_count": sum(int(pattern_type_counts[pt]) for pt in inert),
        "suppressed_count": sum(int(pattern_type_counts[pt]) for pt in suppressed),
        "live_types": tuple(sorted(firing)),
        "inert_types": tuple(sorted(inert)),
        "suppressed_types": tuple(sorted(suppressed)),
        # ⭐ The intersection, DERIVED here once rather than recomputed in each
        # template that needs it. #116 made these two independent flags in this
        # module and left every surface rendering them as an `{% elif %}` chain,
        # so a type that is both was reported as one cause on the list page and
        # as the OTHER on the detail page — contradictory diagnoses one click
        # apart, each naming a fix that alone restores nothing. Exposing the
        # intersection is what lets a surface say "both" instead of choosing.
        "both_types": tuple(sorted(inert & suppressed)),
        "suppressed_until": dict(sorted(snoozed_until.items())),
        "dead_by_model_types": tuple(sorted(inert & DEAD_BY_MODEL)),
        "reason": None,
    }


def load_overrides(config: Config):
    """The parsed runtime override layer, or ``None`` when there is none.

    Split out of ``runtime_suppressions`` so a caller that needs BOTH the
    suppression axes and the severity remap reads the file once. Every failure
    mode is benign and returns ``None`` — a page must not 500 because the
    operator's overrides file has a typo, and reporting "no overrides" is the
    same answer every release before this one gave.
    """
    path = getattr(config, "severity_overrides_path", None)
    if not path:
        return None
    try:
        return rules_mod.load_runtime_severity_overrides(path)
    except Exception as exc:  # noqa: BLE001 — the loader is documented as benign
        logger.warning("runtime suppressions: overrides unreadable (%s)", exc)
        return None


def suppression_axes_of(overrides) -> dict:
    """``runtime_suppressions``' return value, from an already-loaded object."""
    if overrides is None:
        return {"configured": False, "vendors": (), "categories": ()}
    return {
        "configured": True,
        "vendors": tuple(sorted(overrides.suppress_vendors)),
        "categories": tuple(sorted(overrides.suppress_categories)),
    }


def effective_severity(
    stored_severity: str,
    vendor: str | None,
    device_category: str | None,
    argus_record_id: str | None,
    suppressions: dict,
    overrides,
) -> str | None:
    """The severity an alert for this row would ACTUALLY carry — or ``None``
    when a suppression axis means there is no alert to carry one.

    ⭐ **Finding 42.** ``watchlist.severity`` is what the importer baked in;
    ``_apply_runtime_overrides`` re-applies the override file at ALERT time, on
    top of it. Three axes remap (``pattern_overrides`` by argus_record_id,
    ``vendor_severity`` by manufacturer, ``device_category_severity`` by
    category), so a row stored ``high`` can alert ``low`` — measured on all
    three. Every watchlist surface rendered the stored column, which is the one
    number the operator will never receive.

    ⛔ **Delegates to the engine's own function rather than reimplementing the
    precedence.** A local copy of "row beats vendor beats category" is a second
    manifest that can drift from the first, which is the defect behind Findings
    32, 34 and 37. ``_is_reserved_oui_mac`` is imported for the same reason.

    ⚠️ **The suppression check runs FIRST, and that ordering is load-bearing
    for a reason that is not about correctness.** Both of
    ``_apply_runtime_overrides``' suppression branches emit an INFO log naming a
    rule and a watchlist_id. Those describe an alert being dropped at poll time.
    Reaching them from a page render would write that line once per suppressed
    row per page load — a log entry asserting an event that did not happen.
    Returning early on the suppressed rows means the engine call is only ever
    reached on the branch where neither log statement can execute, which is a
    structural guarantee rather than a comment asking for care. Pinned by
    ``test_rendering_a_suppressed_row_writes_no_alert_log``.

    ⚠️ Returns ``None`` for suppressed rows rather than a severity, because a
    suppressed row HAS no effective severity — reporting the remapped value
    beside "this row's alerts are discarded" would invite the operator to read
    it as what they will receive.
    """
    if override_suppression_axes(vendor, device_category, suppressions):
        return None
    return rules_mod._apply_runtime_overrides(
        match_severity=stored_severity,
        match_device_category=device_category,
        match_manufacturer=vendor,
        match_argus_record_id=argus_record_id,
        # Only ever used in the two INFO log messages, which this function is
        # structurally unable to reach. Named honestly anyway: if a future
        # refactor did reach them, the line would say where it came from
        # instead of naming a rule that never ran.
        match_watchlist_id=-1,
        rule_name="webui:watchlist-render",
        overrides=overrides,
    )


def severity_remap_axis(
    vendor: str | None,
    device_category: str | None,
    argus_record_id: str | None,
    overrides,
) -> tuple[str, str] | None:
    """``(axis, key)`` naming WHICH override entry remaps this row, or None.

    ⚠️ Exactly ONE axis, unlike ``override_suppression_axes``, and the
    difference is not an inconsistency. Suppression axes are independent — a row
    listed under both ``suppress_vendors`` and ``suppress_categories`` needs
    both removed, so naming one would offer a next step that does not restore
    alerting. The remaps are a PRECEDENCE: exactly one wins, and removing the
    winner hands the row to the next tier rather than to its stored value. So
    the honest answer here is the one that is actually in force.

    ⛔ Both this and ``matching_remap_axes`` read ONE list, so "which axis won"
    and "how many matched" cannot drift apart. The list's order is the engine's
    documented precedence, and
    ``test_the_named_axis_is_the_one_the_engine_actually_used`` grades it
    against ``evaluate`` rather than against this file.
    """
    matched = matching_remap_axes(vendor, device_category, argus_record_id, overrides)
    return matched[0] if matched else None


def matching_remap_axes(
    vendor: str | None,
    device_category: str | None,
    argus_record_id: str | None,
    overrides,
) -> tuple[tuple[str, str], ...]:
    """Every ``(axis, key)`` whose selector matches this row, most specific
    first — the engine's own precedence order.

    ⚠️ Normalisation mirrors ``_apply_runtime_overrides`` exactly: vendor is
    ``strip().lower()`` (the loader stores keys in that form), category is
    compared RAW, and ``argus_record_id`` is compared raw against keys the
    loader lowercased. Using different rules here would name an axis the engine
    did not use, which is worse than naming none.
    """
    if overrides is None:
        return ()
    matched: list[tuple[str, str]] = []
    if argus_record_id is not None and argus_record_id in overrides.pattern_overrides:
        matched.append(("pattern_overrides", argus_record_id))
    if vendor is not None:
        key = vendor.strip().lower()
        if key in overrides.vendor_severity:
            matched.append(("vendor_severity", key))
    if (
        device_category is not None
        and device_category in overrides.device_category_severity
    ):
        matched.append(("device_category_severity", device_category))
    return tuple(matched)


def severity_remap(
    stored_severity: str,
    vendor: str | None,
    device_category: str | None,
    argus_record_id: str | None,
    suppressions: dict,
    overrides,
) -> dict | None:
    """What a surface needs to render this row honestly, or ``None`` when the
    stored severity IS the severity the operator will receive.

    ⭐ **The rendering decision this encodes, written down because it is a
    decision and not a mechanical fix.** The stored value is real: the importer
    computed it, ``/watchlist.csv`` has always exported it and the severity
    filter is SQL over that column. The remap is equally real and sits on top of
    it. So neither value alone is the truth —

      * rendering only the stored value is Finding 42, the number the operator
        will never receive;
      * rendering only the effective value hides that the row's own column says
        something else, and silently disagrees with the severity filter, which
        cannot be made remap-aware without the full-table scan #111 refused.

    ⇒ Surfaces show **both**: the effective severity as the value, the stored
    one marked superseded beside it, and the axis and key that did it so the
    next step is actionable.

    ⚠️ ``None`` when a remap axis matches but maps to the severity already
    stored. Nothing is being hidden in that case and a "superseded" marker
    would be noise claiming a change that did not happen.
    """
    effective = effective_severity(
        stored_severity,
        vendor,
        device_category,
        argus_record_id,
        suppressions,
        overrides,
    )
    if effective is None or effective == stored_severity:
        return None
    axis = severity_remap_axis(vendor, device_category, argus_record_id, overrides)
    if axis is None:
        # The engine remapped and this module cannot say which entry did it —
        # the two have drifted. Rendering "superseded" without the cause is
        # still strictly better than rendering the stored value as though it
        # were what arrives, so degrade rather than hide it, and say so loudly
        # in the log. `test_every_engine_remap_can_be_attributed_to_an_axis`
        # is what keeps this unreachable.
        logger.warning(
            "severity remap: the engine remapped %s -> %s but no override axis "
            "matched (vendor=%r category=%r argus_record_id=%r) — "
            "severity_remap_axis has drifted from _apply_runtime_overrides",
            stored_severity,
            effective,
            vendor,
            device_category,
            argus_record_id,
        )
    return {
        "stored": stored_severity,
        "effective": effective,
        "axis": axis[0] if axis else None,
        "key": axis[1] if axis else None,
        # ⚠️ Whether the winning axis is the ONLY one that matches this row.
        #
        # 🪤 The first draft of the detail page said "removing that entry from
        # the overrides file restores <stored>". That is a claim the code had
        # not established: with two axes matching, removing the winner hands the
        # row to the NEXT TIER, not to its stored value -- so an operator
        # following the advice would edit the file and see the severity change
        # to a third value. Same shape as the error message that asserted a
        # cause it never established (#106). Cheap to answer properly, so the
        # page states a fact instead of an expectation.
        "sole_axis": len(
            matching_remap_axes(vendor, device_category, argus_record_id, overrides)
        )
        == 1,
    }




def has_configured_remap(overrides) -> bool:
    """Whether ANY of the three remap axes is populated.

    ⚠️ A property of the FILE, not of the rows — it says a remap selector
    exists, never that a stored row matches one. The distinction is the same one
    ``/settings`` makes for the suppression lists, and it is what stops "you
    have overrides" being read as "your rows are affected".
    """
    axes = configured_remap_axes(overrides)
    return bool(axes["categories"] or axes["vendors"] or axes["rows"])


def configured_remap_axes(overrides) -> dict:
    """The remap selectors the operator has configured, for ``/settings``.

    ⛔ Selectors, never a row count — the same refusal ``runtime_suppressions``
    documents. Counting affected rows means scanning the whole watchlist (17k+
    rows on an Argus install) on every page load with no index to do it
    cheaply. The rows are marked where they are already loaded instead, which
    also answers WHICH.
    """
    if overrides is None:
        return {"configured": False, "categories": {}, "vendors": {}, "rows": {}}
    return {
        "configured": True,
        "categories": dict(sorted(overrides.device_category_severity.items())),
        "vendors": dict(sorted(overrides.vendor_severity.items())),
        "rows": dict(sorted(overrides.pattern_overrides.items())),
    }


def runtime_suppressions(config: Config) -> dict:
    """The vendors and device categories the severity overrides silence.

    ⭐ A THIRD way a stored watchlist entry produces no alert, and unlike the
    other two it is **per row**, not per pattern_type. ``rules``'s
    ``_apply_runtime_overrides`` returns ``None`` for a match whose manufacturer
    is in ``suppress_vendors`` or whose category is in ``suppress_categories``,
    and every delegation branch then emits nothing.

    Measured, one `mac` entry with vendor "AcmeCorp" / category "tracker",
    matching device observed:

        no overrides file                  -> 1 alert
        suppress_vendors: [acmecorp]       -> 0 alerts
        suppress_categories: [tracker]     -> 0 alerts

    ...and the liveness report said ``live_count=1`` in all three. That is
    Finding 39, and it is live on any install using overrides today.

    ⚠️ Vendor comparison is ``strip().lower()`` because that is exactly what
    ``_apply_runtime_overrides`` does. Category comparison is NOT normalised,
    for the same reason — it compares the raw value. Matching the engine's
    normalisation is the whole point: a marker that used different rules would
    flag rows the engine does not suppress and miss rows it does, which is worse
    than saying nothing.

    ⛔ Returns the LISTS, never a row count. Counting suppressed rows would mean
    scanning the whole watchlist (17k+ rows on an Argus install) on every
    ``/settings`` and ``/healthz.json`` hit, and there is no indexed vendor
    filter to do it cheaply. Rows are marked where they are already loaded
    instead — which is also the more useful answer, because it says WHICH.

    ⚠️ Kept as a ``config``-taking wrapper over ``load_overrides`` +
    ``suppression_axes_of`` so its callers and its tests are unchanged. A route
    that also needs the severity remap calls those two directly and reads the
    file once instead of twice.
    """
    return suppression_axes_of(load_overrides(config))


def override_suppression_axes(
    vendor: str | None, device_category: str | None, suppressions: dict
) -> tuple[str, ...]:
    """EVERY axis that silences this entry — ``("vendor",)``, ``("category",)``,
    both, or empty.

    ⛔ A TUPLE, not a single reason. The first version returned on the first
    match, so a row listed under BOTH ``suppress_vendors`` and
    ``suppress_categories`` was described as vendor-suppressed only — and
    removing the vendor entry, the next step the page offered, would not have
    restored alerting. Independent causes need independent flags; picking one
    to report is the same defect as collapsing them.

    ⚠️ Returns the REASON, not a bool, because the UI has to name the axis that
    actually matched. Printing every populated metadata field as though it
    matched tells an operator to go and remove a category suppression that had
    nothing to do with it.

    ⚠️ Takes the two VALUES, not a row. An earlier version took "a row" and read
    it with ``row.get(...)`` behind a ``hasattr(row, "get")`` guard — and the two
    call sites hand over two different shapes (``WatchlistRow`` NamedTuple vs
    dict). The NamedTuple has no ``.get``, so the guard turned a type mismatch
    into a silent "not suppressed": one page marked rows correctly, the other
    marked nothing, and nothing raised. A guard that converts "I cannot read
    this" into "the answer is no" is indistinguishable from a correct negative.

    ⚠️ ``is not None``, not truthiness, because that is exactly what
    ``_apply_runtime_overrides`` tests. Measured: the loader admits ``""`` into
    ``suppress_categories``, and the engine suppresses a row whose category is
    ``""`` — a truthiness check here would skip it and mark the row live while
    every alert it produces is discarded. Vendor is still ``strip().lower()``;
    category is still compared raw. Matching the engine's exact semantics is the
    whole job.
    """
    if not suppressions.get("configured"):
        return ()
    axes: list[str] = []
    if vendor is not None and vendor.strip().lower() in suppressions["vendors"]:
        axes.append("vendor")
    if device_category is not None and device_category in suppressions["categories"]:
        axes.append("category")
    return tuple(axes)


def is_row_suppressed_by_overrides(
    vendor: str | None, device_category: str | None, suppressions: dict
) -> bool:
    """Whether this entry's alerts are dropped by a severity override."""
    return bool(override_suppression_axes(vendor, device_category, suppressions))


def is_pattern_type_live(pattern_type: str, liveness: dict) -> bool:
    """Whether a single entry's type can fire, for per-row rendering.

    Unknown liveness renders as live: an entry marked "cannot fire" on the
    strength of an unreadable rules file is the false alarm this whole change
    is supposed to avoid.

    ⚠️ A SNOOZED type is live by this predicate, deliberately. The rule does
    consult it; an alert is being dropped downstream for a reason the operator
    chose and can reverse. ``is_pattern_type_snoozed`` reports that separately
    — collapsing the two would label a deliberate, temporary silence with the
    permanent cause's explanation.
    """
    if not liveness.get("known"):
        return True
    return pattern_type not in liveness["inert_types"]


def is_pattern_type_snoozed(pattern_type: str, liveness: dict) -> bool:
    """Whether this entry's type is currently silenced by a rule_type snooze."""
    if not liveness.get("known"):
        return False
    return pattern_type in liveness["suppressed_types"]
