"""The settings page must report `suppress_pattern_categories` suppression.

`liveness.override_suppression_axes` tells an operator every reason a watchlist
row's alerts are being discarded. #242 added a fifth suppression mechanism to
the engine, `suppress_pattern_categories`, keyed on the conjunction of the
matched row's `pattern_type` and its `device_category`. The liveness module was
not taught about it in that PR: it is a different caller of
`_apply_runtime_overrides`, outside `rules.evaluate` and outside that packet's
write set.

⛔ The failure that matters is one-directional. A UI that reports a row as LIVE
while the engine silently discards every alert it produces is worse than no
report at all: the operator reads "this will alert", it does not, and nothing
anywhere says why. That is the exact defect this module's own docstrings
describe having shipped before, with `override_suppression_axes` returning the
first matching reason instead of all of them.

So the load-bearing test here is not "the axis appears". It is `test_liveness_
agrees_with_the_engine_on_every_case`: whatever the engine decides, liveness
must decide the same.
"""

from __future__ import annotations

import pytest

from lynceus import rules as rules_mod
from lynceus.rules import RuntimeSeverityOverride
from lynceus.webui.liveness import (
    is_row_suppressed_by_overrides,
    override_suppression_axes,
    suppression_axes_of,
)

CATEGORY = "unknown"
PATTERN_TYPE = "ble_manufacturer_id"
OTHER_PATTERN_TYPE = "mac_range"
OTHER_CATEGORY = "cctv_camera"


def _suppressions(**kw):
    return suppression_axes_of(RuntimeSeverityOverride(**kw))


def _engine_suppresses(overrides, *, pattern_type, device_category) -> bool:
    """Ask the ENGINE, through the same entry point `rules.evaluate` uses."""
    return (
        rules_mod._apply_runtime_overrides(
            match_severity="high",
            match_pattern_type=pattern_type,
            match_device_category=device_category,
            match_manufacturer=None,
            match_argus_record_id=None,
            match_watchlist_id=1,
            rule_name="test",
            overrides=overrides,
        )
        is None
    )


def test_both_halves_matching_reports_the_axis():
    s = _suppressions(suppress_pattern_categories={PATTERN_TYPE: frozenset({CATEGORY})})
    axes = override_suppression_axes(None, CATEGORY, s, PATTERN_TYPE)
    assert "pattern_category" in axes, (
        "the settings page did not name the mechanism that is silencing this row; "
        f"got {axes}"
    )


@pytest.mark.parametrize(
    "pattern_type,device_category,why",
    [
        (OTHER_PATTERN_TYPE, CATEGORY, "category matches but pattern_type does not"),
        (PATTERN_TYPE, OTHER_CATEGORY, "pattern_type matches but category does not"),
        (None, CATEGORY, "no pattern_type in scope at all"),
    ],
)
def test_neither_half_alone_reports_the_axis(pattern_type, device_category, why):
    """⚠️ Over-reporting is its own defect: it sends the operator to delete a
    suppression entry that was never silencing this row."""
    s = _suppressions(suppress_pattern_categories={PATTERN_TYPE: frozenset({CATEGORY})})
    axes = override_suppression_axes(None, device_category, s, pattern_type)
    assert "pattern_category" not in axes, f"reported the axis when {why}: {axes}"


def test_an_unconfigured_file_reports_nothing():
    s = _suppressions()
    assert override_suppression_axes(None, CATEGORY, s, PATTERN_TYPE) == ()


def test_the_axis_is_additive_not_exclusive():
    """This module already shipped the bug of reporting one reason and stopping.
    Removing only the named entry would then not restore alerting."""
    s = _suppressions(
        suppress_categories=frozenset({CATEGORY}),
        suppress_pattern_categories={PATTERN_TYPE: frozenset({CATEGORY})},
    )
    axes = override_suppression_axes(None, CATEGORY, s, PATTERN_TYPE)
    assert "category" in axes and "pattern_category" in axes, (
        f"both mechanisms silence this row; only these were named: {axes}"
    )


@pytest.mark.parametrize(
    "pattern_type",
    [PATTERN_TYPE, OTHER_PATTERN_TYPE, "oui", "ssid", "ssid_pattern", None],
)
@pytest.mark.parametrize("device_category", [CATEGORY, OTHER_CATEGORY, "", None])
def test_liveness_agrees_with_the_engine_on_every_case(pattern_type, device_category):
    """⛔ The load-bearing test. Liveness must never say LIVE where the engine
    suppresses, across the whole cross product.

    Runs the real `_apply_runtime_overrides` rather than reimplementing its
    rules, because a test that restates the logic it is checking agrees with
    itself by construction and would not have caught the omission this file
    exists to fix.

    ⚠️ `pattern_type=None` is included deliberately. It is the shape every
    caller had before this change, and the engine passes such a row through, so
    liveness reporting "not suppressed" there is agreement rather than a miss.
    """
    overrides = RuntimeSeverityOverride(
        suppress_pattern_categories={PATTERN_TYPE: frozenset({CATEGORY})}
    )
    s = suppression_axes_of(overrides)

    engine = _engine_suppresses(
        overrides, pattern_type=pattern_type, device_category=device_category
    )
    ui = is_row_suppressed_by_overrides(None, device_category, s, pattern_type)

    assert ui == engine, (
        f"liveness and the engine disagree for pattern_type={pattern_type!r} "
        f"device_category={device_category!r}: engine suppresses={engine}, "
        f"UI reports suppressed={ui}. A row the engine silences that the UI "
        f"calls live is the failure this module exists to prevent."
    )


def test_normalisation_matches_the_engine():
    """Both halves are normalised by the engine, so both must be here.

    A raw comparison would mark a row live while every alert it produces is
    discarded, which is the asymmetry `override_suppression_axes`' own
    docstring warns about for the vendor axis.
    """
    overrides = RuntimeSeverityOverride(
        suppress_pattern_categories={PATTERN_TYPE: frozenset({CATEGORY})}
    )
    s = suppression_axes_of(overrides)
    for pt, cat in ((PATTERN_TYPE.upper(), CATEGORY), (f"  {PATTERN_TYPE} ", CATEGORY)):
        engine = _engine_suppresses(overrides, pattern_type=pt, device_category=cat)
        ui = is_row_suppressed_by_overrides(None, cat, s, pt)
        assert ui == engine, (
            f"normalisation disagreement for pattern_type={pt!r}: "
            f"engine={engine}, UI={ui}"
        )
