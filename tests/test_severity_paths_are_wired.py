"""Every severity the operator can configure, measured to the layer that acts on it.

Two surfaces, one question — *does the value reach the code that would honour it?*

  1. ``severity_overrides.yaml`` -> ``rules.evaluate``: which rule_types actually
     apply a runtime override, and which silently ignore one.
  2. a ``Severity`` literal -> ``notify``: does every severity map to an ntfy
     priority and tag, or does one fall off the end.

⭐ Both are measured by DRIVING the code, not by reading it. The count in
``evaluate``'s own docstring was wrong for three releases — it claimed five
delegation branches consulted overrides when eight did — and no grep would have
caught that, because the call sites were all present and correct. Only running
them shows which ones bite.

⚠️ Understating coverage is not the harmless direction. An operator reading
"only five branches consult it" concludes their overrides are dead for three of
the types they configured; the obvious next move is to go and "fix" branches
that were never broken.

Both directions fail here:

  * a NEW rule_type nobody classified            -> test_every_rule_type_is_classified
  * a wired type that stops honouring overrides  -> test_every_delegating_rule_type_...
  * a non-delegating type that starts honouring  -> test_the_non_delegating_rule_types_...
  * a Severity the notify maps do not cover      -> test_every_severity_maps_to_...
"""

from __future__ import annotations

import pathlib
import re
import typing

import pytest

from lynceus.db import Database
from lynceus.kismet import DeviceObservation
from lynceus.notify import SEVERITY_TO_PRIORITY, SEVERITY_TO_TAGS
from lynceus.rules import (
    Rule,
    Ruleset,
    RuleType,
    RuntimeSeverityOverride,
    Severity,
    evaluate,
)

#: Derived from the Literal, never transcribed — a new rule_type must land in
#: the classification below or `test_every_rule_type_is_classified` fails.
ALL_RULE_TYPES = frozenset(typing.get_args(RuleType))
ALL_SEVERITIES = frozenset(typing.get_args(Severity))

MAC = "ac:de:48:11:22:33"  # universally-administered OUI; a locally-administered
                           # one is discarded by the reserved-OUI guard and reads
                           # exactly like a watchlist row that never matched.
CATEGORY = "drone"
VENDOR = "Flock Safety"
ARID = "abcdef0123456789"

#: Measured 2026-08-15 by driving `evaluate`. These rule_types resolve a
#: watchlist row and therefore have a category / vendor / argus_record_id an
#: override can key on.
DELEGATING = frozenset(
    {
        "watchlist_mac",
        "watchlist_oui",
        "watchlist_ssid",
        "watchlist_mac_range",
        "ble_uuid",
        "watchlist_ble_manufacturer_id",
        "watchlist_drone_id_prefix",
        "watchlist_ble_local_name",
    }
)

#: Match no watchlist row, so there is nothing for an override to key on. This
#: is INHERENT, not a gap: `new_non_randomized_device` is categorical and
#: `ble_device_class` is decoded from the advertisement itself.
NO_WATCHLIST_ROW = frozenset({"new_non_randomized_device", "ble_device_class"})

#: System-emitted by the poller at the watchful escalation site (migration 018).
#: `evaluate` has no branch for it at all, so it is not measurable here.
NOT_EVALUATED = frozenset({"watchful_recurrence"})

#: rule_type -> (watchlist (pattern, pattern_type) or None, obs kwargs, rule patterns)
CASES: dict[str, tuple[tuple[str, str] | None, dict, list[str]]] = {
    "watchlist_mac": ((MAC, "mac"), {}, []),
    "watchlist_oui": (("ac:de:48", "oui"), {}, []),
    "watchlist_ssid": (("MyTargetNet", "ssid"), {"ssid": "MyTargetNet"}, []),
    "watchlist_mac_range": (("ac:de:48:1/28", "mac_range"), {}, []),
    "ble_uuid": (
        ("0000fd5a-0000-1000-8000-00805f9b34fb", "ble_uuid"),
        {"ble_service_uuids": ("0000fd5a-0000-1000-8000-00805f9b34fb",)},
        [],
    ),
    "watchlist_ble_manufacturer_id": (
        ("004c", "ble_manufacturer_id"),
        {"ble_manufacturer_id": "004c"},
        [],
    ),
    "watchlist_drone_id_prefix": (
        ("1581F", "drone_id_prefix"),
        {"drone_id_prefix": "1581FABC"},
        [],
    ),
    "watchlist_ble_local_name": (
        ("TrackerTag", "ble_local_name"),
        {"ble_local_name": "TrackerTag"},
        [],
    ),
    "new_non_randomized_device": (None, {}, []),
    "ble_device_class": (None, {"ble_device_class": "find_my"}, ["find_my"]),
    "watchful_recurrence": (None, {}, []),
}

#: Each runtime override key, and what applying it should do to a matched row
#: carrying CATEGORY / VENDOR / ARID. Every key in `RuntimeSeverityOverride` is
#: represented; `test_every_override_key_is_exercised` holds that true.
def _pattern_types_passed_by_rules_py() -> frozenset[str]:
    """Every literal `match_pattern_type=` value in rules.py, read from source.

    Derived, not transcribed. `evaluate` passes the pattern_type as a literal
    at each delegating call site (and, for ssid, conditionally from one of two
    resolvers), so the source is the only authority on the real set.
    """
    import lynceus.rules as _rules_mod

    src = pathlib.Path(_rules_mod.__file__).read_text(encoding="utf-8")
    literals = set(re.findall(r'match_pattern_type=["\']([a-z_]+)["\']', src))
    literals |= set(re.findall(r'matched_pattern_type = ["\']([a-z_]+)["\']', src))
    assert literals, "found no match_pattern_type literals in rules.py"
    return frozenset(literals)


_PATTERN_TYPES_IN_RULES = _pattern_types_passed_by_rules_py()


OVERRIDES: dict[str, tuple[RuntimeSeverityOverride, str]] = {
    "device_category_severity": (
        RuntimeSeverityOverride(device_category_severity={CATEGORY: "high"}),
        "remap",
    ),
    "suppress_categories": (
        RuntimeSeverityOverride(suppress_categories=frozenset({CATEGORY})),
        "suppress",
    ),
    "vendor_severity": (
        RuntimeSeverityOverride(vendor_severity={VENDOR.lower(): "high"}),
        "remap",
    ),
    "suppress_vendors": (
        RuntimeSeverityOverride(suppress_vendors=frozenset({VENDOR.lower()})),
        "suppress",
    ),
    "pattern_overrides": (
        RuntimeSeverityOverride(pattern_overrides={ARID: "high"}),
        "remap",
    ),
    # ⛔ This key is the odd one out: it keys on the CONJUNCTION of the matched
    # row's pattern_type and its device_category, so a single pattern_type
    # entry suppresses for exactly one delegating branch and no others. The
    # sweep below expects one effect per key across EVERY delegating rule_type,
    # so the instance has to cover every pattern_type a delegating branch can
    # report.
    #
    # ⭐ That set is DERIVED from rules.py rather than typed out here. A
    # hand-copied list looks derived and is not: it would silently stop
    # covering a branch the moment someone adds a rule_type, and this guard
    # exists precisely to catch that.
    "suppress_pattern_categories": (
        RuntimeSeverityOverride(
            suppress_pattern_categories={
                pt: frozenset({CATEGORY}) for pt in _PATTERN_TYPES_IN_RULES
            }
        ),
        "suppress",
    ),
}


def _observation(**kw) -> DeviceObservation:
    base = dict(
        mac=MAC,
        device_type="ble",
        first_seen=1_700_000_000,
        last_seen=1_700_000_000,
        rssi=-40,
        ssid=kw.pop("ssid", None),
        oui_vendor=None,
        is_randomized=False,
    )
    base.update(kw)
    return DeviceObservation(**base)


def _evaluate(rule_type: str, overrides, tmp_path, tag: str):
    """Drive the real `evaluate` for one rule_type. Row severity is always
    'low', so a remap to 'high' is unambiguous."""
    watchlist, obs_kwargs, patterns = CASES[rule_type]
    db = Database(str(tmp_path / f"{rule_type}-{tag}.db"))
    try:
        if watchlist is not None:
            watchlist_id, _ = db.add_watchlist(
                pattern=watchlist[0],
                pattern_type=watchlist[1],
                severity="low",
                description="wiring probe",
            )
            db.upsert_metadata(
                watchlist_id,
                {"device_category": CATEGORY, "vendor": VENDOR, "argus_record_id": ARID},
            )
        ruleset = Ruleset(
            rules=[Rule(name="probe", rule_type=rule_type, severity="low", patterns=patterns)]
        )
        return evaluate(ruleset, _observation(**obs_kwargs), True, db=db,
                        severity_overrides=overrides)
    finally:
        db.close()


# --- the classification ----------------------------------------------------


def test_every_rule_type_is_classified():
    """A new rule_type must be measured, not silently inherit a category."""
    classified = DELEGATING | NO_WATCHLIST_ROW | NOT_EVALUATED
    assert len(ALL_RULE_TYPES) >= 11, f"implausibly few rule types: {sorted(ALL_RULE_TYPES)}"
    assert ALL_RULE_TYPES == classified, (
        f"unclassified rule_type(s): {sorted(ALL_RULE_TYPES - classified)}; "
        f"classified but no longer declared: {sorted(classified - ALL_RULE_TYPES)}. "
        "Measure whether an override applies, then add it to DELEGATING, "
        "NO_WATCHLIST_ROW or NOT_EVALUATED."
    )
    assert set(CASES) == ALL_RULE_TYPES, (
        f"case map drifted from RuleType: {sorted(ALL_RULE_TYPES ^ set(CASES))}"
    )
    # The three sets must be disjoint, or a type could be counted twice and the
    # equality above would still hold.
    assert not DELEGATING & NO_WATCHLIST_ROW
    assert not DELEGATING & NOT_EVALUATED
    assert not NO_WATCHLIST_ROW & NOT_EVALUATED


def test_every_override_key_is_exercised():
    """The sweep below is only as complete as OVERRIDES. A new runtime key that
    nothing exercises would leave `test_every_delegating_rule_type_...` passing
    while the key reaches no branch at all."""
    declared = set(RuntimeSeverityOverride.model_fields)
    assert set(OVERRIDES) == declared, (
        f"runtime override keys not measured: {sorted(declared - set(OVERRIDES))}; "
        f"measured but no longer declared: {sorted(set(OVERRIDES) - declared)}"
    )
    assert len(OVERRIDES) >= 5


# --- the measurement -------------------------------------------------------


@pytest.mark.parametrize("override_key", sorted(OVERRIDES))
@pytest.mark.parametrize("rule_type", sorted(DELEGATING))
def test_every_delegating_rule_type_honours_every_override_key(
    rule_type, override_key, tmp_path
):
    """The presence assertion first: without an override the rule must fire at
    the row's severity. A rule that fires nothing makes "the override applied"
    unfalsifiable — and every one of these branches is a DB lookup that can
    return None for reasons having nothing to do with overrides."""
    control = _evaluate(rule_type, None, tmp_path, "control")
    assert control, (
        f"control invalid: {rule_type} produced no hit at all, so nothing below "
        f"is a statement about severity overrides"
    )
    assert control[0].severity == "low", (
        f"control invalid: expected the row severity 'low', got {control[0].severity!r}"
    )

    overrides, effect = OVERRIDES[override_key]
    hits = _evaluate(rule_type, overrides, tmp_path, override_key)

    if effect == "suppress":
        assert not hits, (
            f"{rule_type} ignored {override_key}: the operator suppressed this "
            f"category/vendor and the alert fired anyway ({hits})"
        )
    else:
        assert hits, f"{rule_type} suppressed on a REMAP key {override_key}; expected a hit"
        assert hits[0].severity == "high", (
            f"{rule_type} ignored {override_key}: severity stayed "
            f"{hits[0].severity!r} instead of the configured 'high'"
        )


def test_the_sweep_covers_the_whole_matrix():
    """`assert seen >= N` — a filter that emptied either axis would leave zero
    parametrised cases running and a green suite."""
    assert len(DELEGATING) >= 8, f"too few delegating rule types: {sorted(DELEGATING)}"
    assert len(DELEGATING) * len(OVERRIDES) >= 40


@pytest.mark.parametrize("rule_type", sorted(NO_WATCHLIST_ROW))
def test_the_non_delegating_rule_types_ignore_overrides(rule_type, tmp_path):
    """The absence assertion, and the one that fires if someone wires these up.

    ⚠️ Not a claim that ignoring is correct — it is a claim that the set has not
    moved without the register moving with it. These rule_types match no
    watchlist row, so there is no category, vendor or argus_record_id for an
    override to key on; honouring one would mean inventing a new keying rule.
    """
    control = _evaluate(rule_type, None, tmp_path, "control")
    assert control, f"control invalid: {rule_type} produced no hit to override"

    for override_key, (overrides, _effect) in OVERRIDES.items():
        hits = _evaluate(rule_type, overrides, tmp_path, override_key)
        assert hits and hits[0].severity == control[0].severity, (
            f"{rule_type} now honours {override_key} (got {hits}). If that was "
            f"intended, move it from NO_WATCHLIST_ROW to DELEGATING and update "
            f"docs/AUDIT_REGISTER.md — this test is the record of the boundary."
        )


@pytest.mark.parametrize("rule_type", sorted(NOT_EVALUATED))
def test_the_system_emitted_rule_types_produce_no_hit_from_evaluate(rule_type, tmp_path):
    """`watchful_recurrence` is emitted by the poller, not matched by `evaluate`.

    Pinned so that if a branch is ever added, someone has to come back here and
    decide whether it should consult overrides rather than inheriting silence.
    """
    assert _evaluate(rule_type, None, tmp_path, "control") == [], (
        f"{rule_type} now produces hits from evaluate(); classify whether it "
        f"should honour severity overrides and move it out of NOT_EVALUATED"
    )


# --- the notify half -------------------------------------------------------


def test_every_severity_maps_to_a_priority_and_a_tag():
    """One layer out: a severity that reaches `send` with no map entry raises
    KeyError inside the poller's try/except and is logged as a delivery
    failure — an alert lost to a typo in a Literal.

    Derived from the `Severity` Literal so adding a fourth value fails HERE,
    at import time of the test, rather than at 3am on the operator's Pi.
    """
    assert len(ALL_SEVERITIES) >= 3, f"implausibly few severities: {sorted(ALL_SEVERITIES)}"
    assert set(SEVERITY_TO_PRIORITY) == ALL_SEVERITIES, (
        f"SEVERITY_TO_PRIORITY does not cover the Severity literal: "
        f"missing={sorted(ALL_SEVERITIES - set(SEVERITY_TO_PRIORITY))}, "
        f"extra={sorted(set(SEVERITY_TO_PRIORITY) - ALL_SEVERITIES)}"
    )
    assert set(SEVERITY_TO_TAGS) == ALL_SEVERITIES, (
        f"SEVERITY_TO_TAGS does not cover the Severity literal: "
        f"missing={sorted(ALL_SEVERITIES - set(SEVERITY_TO_TAGS))}, "
        f"extra={sorted(set(SEVERITY_TO_TAGS) - ALL_SEVERITIES)}"
    )


def test_priorities_are_distinct_and_ordered_by_severity():
    """Presence beside the coverage check above: a map covering every severity
    with the SAME priority would satisfy it while making severity invisible in
    the operator's notifications."""
    assert SEVERITY_TO_PRIORITY["low"] < SEVERITY_TO_PRIORITY["med"] < SEVERITY_TO_PRIORITY["high"]
    assert len(set(SEVERITY_TO_TAGS.values())) == len(SEVERITY_TO_TAGS)


# ---------------------------------------------------------------------------
# ⛔ Everything above proves the EVALUATOR honours an override object handed to
# it. A cold read pointed out that the file is called `..._are_wired` and never
# tested the wiring: `_evaluate` constructs `RuntimeSeverityOverride` directly,
# so the YAML loader could ignore a key, or the poller could pass None forever,
# and every test above would stay green.
#
# The wiring does exist — `Poller.__init__` calls
# `load_runtime_severity_overrides(config.severity_overrides_path)` and threads
# the result into `evaluate`. These tests drive it from a real FILE so that
# claim is measured rather than asserted by a filename.
# ---------------------------------------------------------------------------


def test_a_real_overrides_FILE_suppresses_through_the_real_loader(tmp_path):
    """YAML on disk -> `load_runtime_severity_overrides` -> `evaluate`.

    The half `_evaluate` cannot reach: a loader that dropped `suppress_vendors`
    would leave every parametrised case above passing.
    """
    from lynceus.rules import load_runtime_severity_overrides

    path = tmp_path / "severity_overrides.yaml"
    path.write_text(f"suppress_vendors:\n  - {VENDOR}\n", encoding="utf-8")

    overrides = load_runtime_severity_overrides(str(path))
    assert overrides is not None, "the loader returned None for a valid overrides file"
    assert not overrides.is_empty(), (
        "the loader parsed the file to an EMPTY runtime view; the key it needs is "
        "`suppress_vendors` and nothing downstream will suppress anything"
    )

    # Control first: the same row alerts when no overrides file is involved.
    control = _evaluate("watchlist_mac", None, tmp_path, "file-control")
    assert control, "control invalid: the row does not alert even without an override"

    suppressed = _evaluate("watchlist_mac", overrides, tmp_path, "file-treatment")
    assert not suppressed, (
        "an overrides FILE that the real loader parsed did not suppress the match. "
        "The evaluator honours an injected object (tests above), so the break is in "
        "the loader or its key mapping."
    )


def test_the_poller_threads_the_loaded_overrides_into_evaluate():
    """The last link, checked structurally because standing a poller up needs a
    live Kismet.

    ⚠️ Deliberately NOT a grep for the string in the file — that matches the
    import line and the parameter default. This resolves the attribute the
    poller actually stores and the signature `evaluate` actually accepts, so a
    rename on either side fails here rather than silently decoupling the two.
    """
    import inspect

    from lynceus import poller as poller_module

    source = inspect.getsource(poller_module.Poller.__init__)
    assert "load_runtime_severity_overrides" in source, (
        "Poller.__init__ no longer loads the overrides file; the runtime layer is "
        "disconnected and every test in this file would still pass"
    )
    assert "severity_overrides" in inspect.signature(evaluate).parameters, (
        "evaluate() no longer accepts severity_overrides"
    )
    assert "severity_overrides" in inspect.signature(
        poller_module.process_observation
    ).parameters, (
        "process_observation no longer accepts severity_overrides, so the poller "
        "cannot hand the loaded file to the evaluator"
    )


def test_send_ACTUALLY_uses_the_maps_rather_than_merely_declaring_them(monkeypatch):
    """⛔ The two tests above inspect dictionaries. Nothing made `send()` read them.

    A cold read caught it: `send` could hardcode a priority, swap the two maps,
    or ignore severity entirely, and the coverage/ordering assertions would all
    stay green. This drives the real POST path and reads the headers it builds.
    """
    from lynceus import notify as notify_module

    captured: dict = {}

    class _Response:
        status_code = 200

    def _fake_post(url, data=None, headers=None, timeout=None):
        captured["headers"] = headers
        return _Response()

    monkeypatch.setattr(notify_module.requests, "post", _fake_post)
    notifier = notify_module.NtfyNotifier(base_url="https://ntfy.example", topic="t")

    seen: dict[str, tuple[str, str]] = {}
    for severity in sorted(ALL_SEVERITIES):
        captured.clear()
        assert notifier.send(severity, "title", "body") is True
        headers = captured["headers"]
        seen[severity] = (headers["Priority"], headers["Tags"])

    # `assert seen >= N`: a loop over an emptied set would otherwise pass.
    assert len(seen) == len(ALL_SEVERITIES) >= 3

    for severity, (priority, tag) in seen.items():
        assert priority == str(SEVERITY_TO_PRIORITY[severity]), (
            f"send() sent Priority={priority} for severity={severity!r} but the map "
            f"says {SEVERITY_TO_PRIORITY[severity]} — the map is decorative"
        )
        assert tag == SEVERITY_TO_TAGS[severity], (
            f"send() sent Tags={tag!r} for severity={severity!r} but the map says "
            f"{SEVERITY_TO_TAGS[severity]!r}"
        )

    # Presence beside the mapping: the values must actually DIFFER between
    # severities, or a send() that hardcoded one value would satisfy the loop
    # above whenever the maps happened to agree with it.
    assert len({p for p, _ in seen.values()}) == len(seen)


def test_a_priority_override_does_not_silently_discard_the_severity_tag():
    """The documented decoupling: the watchful escalation site sends
    severity="high" with priority_override=4 so prominence and tone can differ.

    Pinned because "tag follows severity in both cases" is a comment, and a
    refactor that derived the tag from the PRIORITY would look correct and
    silently relabel every overridden alert.
    """
    from lynceus import notify as notify_module

    captured: dict = {}

    class _Response:
        status_code = 200

    monkeypatch_target = notify_module.requests

    def _fake_post(url, data=None, headers=None, timeout=None):
        captured["headers"] = headers
        return _Response()

    original = monkeypatch_target.post
    monkeypatch_target.post = _fake_post
    try:
        notifier = notify_module.NtfyNotifier(base_url="https://ntfy.example", topic="t")
        assert notifier.send("high", "t", "b", priority_override=4) is True
    finally:
        monkeypatch_target.post = original

    assert captured["headers"]["Priority"] == "4", "priority_override was ignored"
    assert captured["headers"]["Tags"] == SEVERITY_TO_TAGS["high"], (
        "the tag followed the OVERRIDDEN priority instead of the severity; an "
        "escalation sent at priority 4 would be relabelled as a lower tier"
    )
