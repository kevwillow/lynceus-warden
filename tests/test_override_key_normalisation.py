"""Operator-config lookups normalise BOTH sides, at every site.

⛔ THE CLASS, not the instance. A lookup where the key side and the value side
are normalised differently silently ignores what the operator configured. The
register for this round is `internal/rig-reports/REGISTER_2026-08-22_POST_MERGE_HUNT.md`;
the enumeration that found the sites was:

    grep -rnE '\\b(in|\\[)\\s*(overrides)\\.[a-z_]+' src/lynceus --include=*.py

Three sites were already correct (`suppress_vendors` and `vendor_severity` in
`rules.py`, `vendor_severity` in `liveness.py`): key lowercased at load, value
`.strip().lower()` at lookup. Six were not, across three files.

🪤 THE TRAP THIS FILE EXISTS TO PIN. Fixing only the KEY side is a REGRESSION,
not a partial fix. An operator whose rows genuinely carry `ALPR` and who wrote
`ALPR` in YAML matched before and would stop matching after, because the lookup
still compares the raw row value. Both halves have to move together, which is
why `normalize_override_key` is one function that both sides call rather than
two `.strip().lower()` calls that can drift.

⚠️ Measured premise: all 41,508 rows of the bundled `default_watchlist.csv`
carry lowercase `device_category`. So the live defect bites the operator who
capitalises in YAML, and the regression above would bite one importing a custom
CSV that capitalises.
"""

from __future__ import annotations

import pathlib

import pytest

from lynceus.cli.import_argus import (
    DEFAULT_CATEGORY_SEVERITIES,
    OverrideConfig,
    load_override_config,
    resolve_severity,
)
from lynceus.rules import load_runtime_severity_overrides, normalize_override_key

# ---------------------------------------------------------------------------
# The shared normaliser
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("ALPR", "alpr"),
        ("  Drone  ", "drone"),
        ("alpr", "alpr"),
        ("", None),
        ("   ", None),
        (None, None),
        (17, None),
    ],
)
def test_normalize_override_key(raw, expected):
    assert normalize_override_key(raw) == expected


def test_both_sides_of_a_lookup_use_the_same_function():
    """⛔ Not two `.strip().lower()` calls. One function.

    The BLE UUID defect this repo already shipped was two normalisations that
    disagreed: the watchlist side expanded 16-bit UUIDs to the 128-bit base
    form, the observation side did not, and every advertisement of a
    watchlisted tracker was dropped with a DEBUG line. Its fix was to make both
    sides call one function. This asserts the same shape here, so a later edit
    cannot reintroduce a second private normalisation.
    """
    for module in ("rules.py", "webui/liveness.py", "cli/import_argus.py"):
        root = pathlib.Path(__file__).resolve().parent.parent / "src" / "lynceus"
        src = (root / module).read_text()
        assert "normalize_override_key" in src, (
            f"{module} no longer calls the shared normaliser; if the lookup moved, "
            f"move this assertion with it rather than deleting it"
        )


# ---------------------------------------------------------------------------
# rules.py — the runtime override path
# ---------------------------------------------------------------------------


def _write_overrides(tmp_path, text):
    p = tmp_path / "severity_overrides.yaml"
    p.write_text(text)
    return str(p)


@pytest.mark.parametrize("yaml_key", ["ALPR", "alpr", "  Alpr  "])
@pytest.mark.parametrize("row_value", ["alpr", "ALPR", " Alpr "])
def test_category_severity_matches_in_every_case_combination(tmp_path, yaml_key, row_value):
    """The grid is the point: 3 spellings in YAML x 3 in the row, all match.

    Before the fix, only the exact-string diagonal matched. Fixing the key side
    alone would move which cells pass without making the grid pass.
    """
    from lynceus.rules import _apply_runtime_overrides

    ov = load_runtime_severity_overrides(
        _write_overrides(tmp_path, f"device_category_severity:\n  {yaml_key}: low\n")
    )
    assert ov is not None
    assert _apply_runtime_overrides(
        overrides=ov,
        match_severity="high",
        match_manufacturer=None,
        match_device_category=row_value,
        match_argus_record_id=None,
        match_watchlist_id=1,
        rule_name="watchlist_oui",
    ) == "low", f"YAML {yaml_key!r} did not remap a row carrying {row_value!r}"


@pytest.mark.parametrize("yaml_entry", ["ALPR", "alpr", "  Alpr  "])
@pytest.mark.parametrize("row_value", ["alpr", "ALPR", " Alpr "])
def test_suppress_categories_suppresses_in_every_case_combination(tmp_path, yaml_entry, row_value):
    from lynceus.rules import _apply_runtime_overrides

    ov = load_runtime_severity_overrides(
        _write_overrides(tmp_path, f"suppress_categories:\n  - {yaml_entry}\n")
    )
    assert ov is not None
    assert _apply_runtime_overrides(
        overrides=ov,
        match_severity="high",
        match_manufacturer=None,
        match_device_category=row_value,
        match_argus_record_id=None,
        match_watchlist_id=1,
        rule_name="watchlist_oui",
    ) is None, f"YAML {yaml_entry!r} did not suppress a row carrying {row_value!r}"


def test_a_category_the_operator_did_not_list_is_still_untouched(tmp_path):
    """⛔ The control. Normalising must not make everything match everything."""
    from lynceus.rules import _apply_runtime_overrides

    ov = load_runtime_severity_overrides(
        _write_overrides(tmp_path, "device_category_severity:\n  alpr: low\n")
    )
    assert _apply_runtime_overrides(
        overrides=ov,
        match_severity="high",
        match_manufacturer=None,
        match_device_category="drone",
        match_argus_record_id=None,
        match_watchlist_id=1,
        rule_name="watchlist_oui",
    ) == "high"


# ---------------------------------------------------------------------------
# liveness.py — what the settings page TELLS the operator is matching
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("row_value", ["alpr", "ALPR", " Alpr "])
def test_the_settings_page_reports_the_same_match_the_rules_engine_makes(tmp_path, row_value):
    """⛔ If these two disagreed, the page would confidently report the wrong
    answer, which is worse than reporting none."""
    from lynceus.webui.liveness import matching_remap_axes

    ov = load_runtime_severity_overrides(
        _write_overrides(tmp_path, "device_category_severity:\n  ALPR: low\n")
    )
    axes = matching_remap_axes(
        vendor=None, device_category=row_value, argus_record_id=None, overrides=ov
    )
    assert any(name == "device_category_severity" for name, _ in axes), (
        f"the settings page does not report a match for a row carrying {row_value!r}, "
        f"but the rules engine does"
    )


# ---------------------------------------------------------------------------
# cli/import_argus.py — its OWN loader and its OWN lookup
# ---------------------------------------------------------------------------


def test_the_importer_default_category_table_is_case_insensitive():
    """⛔ `DEFAULT_CATEGORY_SEVERITIES`' keys are lowercase literals, so this
    arm was one-sided: an Argus export carrying `ALPR` fell past it to the
    "low" default instead of the built-in "high"."""
    assert "alpr" in DEFAULT_CATEGORY_SEVERITIES
    assert resolve_severity(
        manufacturer=None, device_category="ALPR", confidence=None, overrides=OverrideConfig()
    ) == DEFAULT_CATEGORY_SEVERITIES["alpr"]


@pytest.mark.parametrize("row_value", ["alpr", "ALPR"])
def test_the_importer_category_override_matches_in_either_case(tmp_path, row_value):
    p = tmp_path / "ov.yaml"
    p.write_text("device_category_severity:\n  ALPR: med\n")
    ov = load_override_config(str(p))
    assert resolve_severity(
        manufacturer=None, device_category=row_value, confidence=None, overrides=ov
    ) == "med"


@pytest.mark.parametrize("row_value", ["axon enterprise", "Axon Enterprise", " AXON ENTERPRISE "])
def test_the_importer_vendor_override_matches_in_either_case(tmp_path, row_value):
    """⚠️ The vendor half is normalised correctly on BOTH sides in `rules.py`
    and was raw on both sides here. Same key, same product, two files, opposite
    behaviour -- which is why the round swept the class rather than the site."""
    p = tmp_path / "ov.yaml"
    p.write_text("vendor_overrides:\n  Axon Enterprise: high\n")
    ov = load_override_config(str(p))
    assert resolve_severity(
        manufacturer=row_value, device_category="unknown", confidence=None, overrides=ov
    ) == "high"
