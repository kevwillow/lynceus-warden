"""Tests for the runtime severity-overrides parser layer.

Backs ``rules.RuntimeSeverityOverride`` /
``rules.load_runtime_severity_overrides``. The runtime layer reads
the same file (``severity_overrides.yaml``) that
``lynceus-import-argus --override-file`` consumes, but exposes only
the runtime-relevant subset (``device_category_severity`` +
``suppress_categories``). Failure modes are all benign — the
poller must never crash because the operator edited their override
file into a malformed state.
"""

from __future__ import annotations

import logging

import pytest

from lynceus.rules import (
    RuntimeSeverityOverride,
    load_runtime_severity_overrides,
)

# ---- RuntimeSeverityOverride model ----------------------------------------


def test_empty_runtime_override_is_empty():
    """The pass-through fast-path's load-bearing predicate."""
    cfg = RuntimeSeverityOverride()
    assert cfg.is_empty()


def test_remap_only_is_not_empty():
    cfg = RuntimeSeverityOverride(device_category_severity={"unknown": "med"})
    assert not cfg.is_empty()
    assert cfg.device_category_severity == {"unknown": "med"}


def test_suppress_only_is_not_empty():
    cfg = RuntimeSeverityOverride(suppress_categories=frozenset({"drone"}))
    assert not cfg.is_empty()
    assert "drone" in cfg.suppress_categories


def test_suppress_vendors_only_is_not_empty():
    """is_empty() must include suppress_vendors in its definition;
    otherwise a file populated only with vendor suppressions would
    short-circuit to the pass-through fast-path in
    ``_apply_runtime_overrides`` and never apply."""
    cfg = RuntimeSeverityOverride(
        suppress_vendors=frozenset({"mitsubishi electric us, inc."})
    )
    assert not cfg.is_empty()
    assert "mitsubishi electric us, inc." in cfg.suppress_vendors


def test_combined_remap_and_suppress():
    cfg = RuntimeSeverityOverride(
        device_category_severity={"unknown": "med", "alpr": "high"},
        suppress_categories=frozenset({"drone"}),
        suppress_vendors=frozenset({"acme corp"}),
    )
    assert not cfg.is_empty()
    assert cfg.device_category_severity["alpr"] == "high"
    assert "drone" in cfg.suppress_categories
    assert "acme corp" in cfg.suppress_vendors


def test_remap_rejects_invalid_severity():
    """Severity values must be in (low, med, high). Any other string
    is a validation error rather than a silent pass-through — the
    parser's load function downgrades validation errors to None +
    WARNING (tested below)."""
    with pytest.raises(ValueError):
        RuntimeSeverityOverride(device_category_severity={"unknown": "critical"})


def test_frozen_immutable():
    """Model is frozen; an operator can't mutate the loaded config
    at runtime. Reload requires daemon restart, by design.

    Pydantic v2 raises ValidationError on assignment to a frozen
    model; we accept either ValidationError or the underlying
    pydantic-core variant.
    """
    from pydantic import ValidationError as _VE

    cfg = RuntimeSeverityOverride(device_category_severity={"unknown": "med"})
    with pytest.raises(_VE):
        cfg.device_category_severity = {"alpr": "high"}  # type: ignore[misc]


# ---- load_runtime_severity_overrides --------------------------------------


def test_load_none_path_returns_none_logs_info(caplog):
    """Caller (poller) treats None as 'runtime layer disabled'. The
    config field severity_overrides_path defaults to None and is
    opt-in; this guard backs that default. The INFO line names the
    config field by exact name so an operator can grep for it in
    journalctl and find the actionable hint."""
    with caplog.at_level(logging.INFO, logger="lynceus.rules"):
        assert load_runtime_severity_overrides(None) is None
    info = [
        r for r in caplog.records
        if r.levelno == logging.INFO
        and "severity_overrides_path" in r.getMessage()
        and "lynceus.yaml" in r.getMessage()
    ]
    assert len(info) == 1


def test_load_missing_file_returns_none_logs_info(tmp_path, caplog):
    """Absence is normal — the operator may not have run the wizard
    or may have removed the file deliberately. INFO log, not WARNING."""
    p = tmp_path / "missing.yaml"
    with caplog.at_level(logging.INFO, logger="lynceus.rules"):
        result = load_runtime_severity_overrides(p)
    assert result is None
    info = [
        r for r in caplog.records
        if r.levelno == logging.INFO and "not found" in r.getMessage()
    ]
    assert len(info) == 1


def test_load_empty_yaml_returns_empty_config_logs_info(tmp_path, caplog):
    """Empty file parses to an empty config — pass-through at eval
    time. Distinct from None: the file exists, just contains no
    runtime keys (the wizard's starter file is in this state until
    operator uncomments something). INFO line distinguishes this
    from the active-keys case so an operator grepping the startup
    log can tell at a glance whether the file is doing something."""
    p = tmp_path / "empty.yaml"
    p.write_text("", encoding="utf-8")
    with caplog.at_level(logging.INFO, logger="lynceus.rules"):
        cfg = load_runtime_severity_overrides(p)
    assert cfg is not None
    assert cfg.is_empty()
    info = [
        r for r in caplog.records
        if r.levelno == logging.INFO
        and "loaded from" in r.getMessage()
        and "no active runtime keys" in r.getMessage()
        and str(p) in r.getMessage()
    ]
    assert len(info) == 1


def test_load_active_keys_logs_info_with_counts(tmp_path, caplog):
    """The 'layer is active' confirmation. The operator running the
    live smoke greps for this line at daemon startup to verify the
    file is being read. Counts (remap entries + suppressed
    categories + suppressed vendors + pattern overrides) make the
    log self-describing — an operator who expected 3 remaps but
    sees 1 knows the file's parsing is selective."""
    p = tmp_path / "active.yaml"
    p.write_text(
        "device_category_severity:\n"
        "  unknown: med\n"
        "  alpr: high\n"
        "suppress_categories:\n"
        "  - drone\n"
        "suppress_vendors:\n"
        "  - \"Mitsubishi Electric US, Inc.\"\n"
        "  - \"Acme Corp\"\n"
        "pattern_overrides:\n"
        "  \"a1b2c3d4e5f60001\": high\n",
        encoding="utf-8",
    )
    with caplog.at_level(logging.INFO, logger="lynceus.rules"):
        cfg = load_runtime_severity_overrides(p)
    assert cfg is not None
    assert not cfg.is_empty()
    info = [
        r for r in caplog.records
        if r.levelno == logging.INFO
        and "loaded from" in r.getMessage()
        and "2 category remap" in r.getMessage()
        and "1 suppressed category" in r.getMessage()
        and "2 suppressed vendor" in r.getMessage()
        and "1 pattern override" in r.getMessage()
    ]
    assert len(info) == 1


def test_load_import_only_keys_returns_empty_runtime_view(tmp_path):
    """A file populated entirely with import-time keys
    (vendor_overrides, geographic_filter, confidence_downgrade_
    threshold) parses without error and yields an empty runtime
    view. This is the wizard's default starter state — the load
    must not crash on it."""
    p = tmp_path / "import_only.yaml"
    p.write_text(
        "vendor_overrides:\n"
        "  \"Acme\": high\n"
        "geographic_filter:\n"
        "  - US\n"
        "confidence_downgrade_threshold: 70\n",
        encoding="utf-8",
    )
    cfg = load_runtime_severity_overrides(p)
    assert cfg is not None
    assert cfg.is_empty()


def test_load_runtime_keys_only(tmp_path):
    p = tmp_path / "runtime.yaml"
    p.write_text(
        "device_category_severity:\n"
        "  unknown: med\n"
        "  alpr: high\n"
        "suppress_categories:\n"
        "  - drone\n"
        "  - body_cam\n",
        encoding="utf-8",
    )
    cfg = load_runtime_severity_overrides(p)
    assert cfg is not None
    assert cfg.device_category_severity == {"unknown": "med", "alpr": "high"}
    assert cfg.suppress_categories == frozenset({"drone", "body_cam"})


def test_load_combined_layers_runtime_view_filters_correctly(tmp_path):
    """A file mixing both layers' keys: the runtime view contains
    only the two runtime keys; the import-time keys are silently
    dropped from the view (extra='ignore'). The import-time consumer
    in import_argus.py reads them via its own code path; nothing
    drifts."""
    p = tmp_path / "combined.yaml"
    p.write_text(
        "vendor_overrides:\n"
        "  \"Acme\": high\n"
        "device_category_severity:\n"
        "  unknown: med\n"
        "suppress_categories:\n"
        "  - drone\n"
        "geographic_filter:\n"
        "  - US\n"
        "confidence_downgrade_threshold: 70\n",
        encoding="utf-8",
    )
    cfg = load_runtime_severity_overrides(p)
    assert cfg is not None
    assert cfg.device_category_severity == {"unknown": "med"}
    assert cfg.suppress_categories == frozenset({"drone"})
    # The view does not surface import-time keys at all — pydantic
    # extra='ignore' on RuntimeSeverityOverride drops them. The
    # importer reads them via its own OverrideConfig.
    assert not hasattr(cfg, "vendor_overrides")


def test_load_malformed_yaml_returns_none_logs_warning(tmp_path, caplog):
    """A YAML parse error must NOT crash the poller. WARNING + None;
    daemon continues with pass-through semantics. The import-time
    consumer in lynceus-import-argus has separate error handling
    (raises RuntimeError) and is unaffected."""
    p = tmp_path / "malformed.yaml"
    p.write_text("device_category_severity:\n  unknown:\n    : oops\n", encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger="lynceus.rules"):
        result = load_runtime_severity_overrides(p)
    assert result is None
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) >= 1
    assert str(p) in warnings[0].getMessage()


def test_load_invalid_severity_value_returns_none_logs_warning(tmp_path, caplog):
    """device_category_severity with an out-of-set value (e.g.
    "critical") fails pydantic validation. The loader downgrades to
    None + WARNING — never crash the poller."""
    p = tmp_path / "bad_sev.yaml"
    p.write_text(
        "device_category_severity:\n"
        "  unknown: critical\n",  # not a valid severity literal
        encoding="utf-8",
    )
    with caplog.at_level(logging.WARNING, logger="lynceus.rules"):
        result = load_runtime_severity_overrides(p)
    assert result is None
    warnings = [
        r for r in caplog.records
        if r.levelno == logging.WARNING and "validation" in r.getMessage().lower()
    ]
    assert len(warnings) == 1


def test_load_non_mapping_yaml_returns_none_logs_warning(tmp_path, caplog):
    """YAML that parses to a list / scalar (not a mapping) is
    technically valid YAML but not the expected shape — distinguished
    from parse errors so the WARNING can name the actual type."""
    p = tmp_path / "list.yaml"
    p.write_text("- not a mapping\n- nope\n", encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger="lynceus.rules"):
        result = load_runtime_severity_overrides(p)
    assert result is None


def test_load_suppress_categories_non_list_is_ignored(tmp_path):
    """The loader is tolerant — if suppress_categories is set to a
    non-list (operator typo: ``suppress_categories: drone`` instead
    of a YAML list), the loader silently drops the key rather than
    crashing. The eval layer pass-throughs uncovered categories
    anyway, so a dropped suppress key just means 'no suppression
    applied' which is the conservative behavior."""
    p = tmp_path / "scalar_suppress.yaml"
    p.write_text(
        "device_category_severity:\n"
        "  unknown: med\n"
        "suppress_categories: drone\n",  # operator typo — should be a list
        encoding="utf-8",
    )
    cfg = load_runtime_severity_overrides(p)
    assert cfg is not None
    assert cfg.device_category_severity == {"unknown": "med"}
    assert cfg.suppress_categories == frozenset()


def test_load_accepts_path_or_string(tmp_path):
    """API ergonomics: callers should be able to pass either a Path
    or a str. The poller passes a str from config; tests pass a
    Path."""
    p = tmp_path / "as_str.yaml"
    p.write_text("device_category_severity:\n  unknown: med\n", encoding="utf-8")
    via_path = load_runtime_severity_overrides(p)
    via_str = load_runtime_severity_overrides(str(p))
    assert via_path is not None
    assert via_str is not None
    assert via_path.device_category_severity == via_str.device_category_severity


def test_load_unreadable_file_returns_none_logs_warning(tmp_path, caplog):
    """If the file is a directory (or otherwise unreadable as YAML
    text), the loader logs WARNING and returns None rather than
    propagating an OSError up into the poller startup path."""
    # A directory at the override-file path: opens but fails to read.
    p = tmp_path / "is_a_dir.yaml"
    p.mkdir()
    with caplog.at_level(logging.WARNING, logger="lynceus.rules"):
        result = load_runtime_severity_overrides(p)
    # On Windows opening a directory raises PermissionError; on POSIX
    # IsADirectoryError. Both should downgrade cleanly.
    assert result is None


# ---- suppress_vendors parsing & normalization -----------------------------


def test_load_suppress_vendors_only(tmp_path):
    """A file with only suppress_vendors parses to a non-empty
    runtime view. The other two runtime keys remain at their
    defaults."""
    p = tmp_path / "vendors.yaml"
    p.write_text(
        "suppress_vendors:\n"
        "  - \"Mitsubishi Electric US, Inc.\"\n",
        encoding="utf-8",
    )
    cfg = load_runtime_severity_overrides(p)
    assert cfg is not None
    assert not cfg.is_empty()
    assert cfg.suppress_vendors == frozenset({"mitsubishi electric us, inc."})
    assert cfg.device_category_severity == {}
    assert cfg.suppress_categories == frozenset()


def test_load_suppress_vendors_normalizes_case_and_whitespace(tmp_path):
    """Entries are normalized at load time (lowercase + strip)
    so the eval-time comparison is a single frozenset lookup. An
    operator-typed ``"  Acme CORP  "`` lands in the dataclass as
    ``"acme corp"``."""
    p = tmp_path / "mixed_case.yaml"
    p.write_text(
        "suppress_vendors:\n"
        "  - \"  Acme CORP  \"\n"
        "  - \"DJI Inc.\"\n",
        encoding="utf-8",
    )
    cfg = load_runtime_severity_overrides(p)
    assert cfg is not None
    assert cfg.suppress_vendors == frozenset({"acme corp", "dji inc."})


def test_load_suppress_vendors_dedupes_after_normalization(tmp_path):
    """Two entries that differ only in case / whitespace collapse to
    one entry in the frozenset. Operator can't break the
    runtime-layer count budget by listing the same vendor twice
    with different casing."""
    p = tmp_path / "dupes.yaml"
    p.write_text(
        "suppress_vendors:\n"
        "  - \"Acme Corp\"\n"
        "  - \"acme corp\"\n"
        "  - \"  ACME CORP\"\n",
        encoding="utf-8",
    )
    cfg = load_runtime_severity_overrides(p)
    assert cfg is not None
    assert cfg.suppress_vendors == frozenset({"acme corp"})


def test_load_suppress_vendors_drops_empty_and_non_string_with_warning(tmp_path, caplog):
    """Per-entry validation: non-string and empty-after-strip
    entries get WARNING-logged and dropped; the rest of the list
    still parses. The whole layer must not be disabled by a single
    malformed entry."""
    p = tmp_path / "malformed_entries.yaml"
    p.write_text(
        "suppress_vendors:\n"
        "  - \"Acme Corp\"\n"
        "  - \"\"\n"          # empty string
        "  - \"   \"\n"        # whitespace only — empty after strip
        "  - 42\n"             # non-string
        "  - \"DJI Inc.\"\n",
        encoding="utf-8",
    )
    with caplog.at_level(logging.WARNING, logger="lynceus.rules"):
        cfg = load_runtime_severity_overrides(p)
    assert cfg is not None
    assert cfg.suppress_vendors == frozenset({"acme corp", "dji inc."})
    warnings = [
        r for r in caplog.records
        if r.levelno == logging.WARNING and "suppress_vendors" in r.getMessage()
    ]
    # One WARN per dropped entry: "" + "   " + 42 → 3.
    assert len(warnings) == 3


def test_load_suppress_vendors_non_list_is_ignored(tmp_path):
    """Tolerant of operator typos: a scalar ``suppress_vendors:
    "Acme"`` (rather than a YAML list) is silently dropped — the
    eval layer pass-throughs uncovered vendors, so a dropped key
    just means 'no vendor suppression' (the conservative default)."""
    p = tmp_path / "scalar.yaml"
    p.write_text(
        "device_category_severity:\n"
        "  unknown: med\n"
        "suppress_vendors: \"Acme Corp\"\n",  # operator typo
        encoding="utf-8",
    )
    cfg = load_runtime_severity_overrides(p)
    assert cfg is not None
    assert cfg.device_category_severity == {"unknown": "med"}
    assert cfg.suppress_vendors == frozenset()


def test_load_all_three_runtime_keys_combined(tmp_path):
    """A file mixing every runtime key. Each lands in its own
    field; counts in the INFO log line up across three categories."""
    p = tmp_path / "all_three.yaml"
    p.write_text(
        "device_category_severity:\n"
        "  unknown: med\n"
        "  alpr: high\n"
        "suppress_categories:\n"
        "  - drone\n"
        "suppress_vendors:\n"
        "  - \"Mitsubishi Electric US, Inc.\"\n",
        encoding="utf-8",
    )
    cfg = load_runtime_severity_overrides(p)
    assert cfg is not None
    assert cfg.device_category_severity == {"unknown": "med", "alpr": "high"}
    assert cfg.suppress_categories == frozenset({"drone"})
    assert cfg.suppress_vendors == frozenset({"mitsubishi electric us, inc."})


# ---- pattern_overrides parsing & normalization ----------------------------
#
# Row-level severity remap keyed by argus_record_id (16-hex SHA-256
# prefix per the Argus contract). Load-time validation drops malformed
# keys/values with a WARNING; whether the argus_record_id corresponds
# to an actual row in the DB is NOT checked here (stale entries are a
# legitimate state — the row may have been removed and will be
# re-added on next import).


def test_pattern_overrides_only_is_not_empty():
    """is_empty() must include pattern_overrides in its definition;
    otherwise a file populated only with row-level remaps would
    short-circuit to the pass-through fast-path in
    ``_apply_runtime_overrides`` and never apply."""
    cfg = RuntimeSeverityOverride(
        pattern_overrides={"a1b2c3d4e5f60001": "high"}
    )
    assert not cfg.is_empty()
    assert cfg.pattern_overrides == {"a1b2c3d4e5f60001": "high"}


def test_pattern_overrides_rejects_invalid_severity():
    """Severity values must be in (low, med, high) — same constraint
    as device_category_severity. The dataclass-level validator
    rejects out-of-band literals; the loader's per-entry validation
    is a separate layer (tolerant: WARN + drop)."""
    with pytest.raises(ValueError):
        RuntimeSeverityOverride(
            pattern_overrides={"a1b2c3d4e5f60001": "critical"}
        )


def test_load_pattern_overrides_only(tmp_path):
    """A file with only pattern_overrides parses to a non-empty
    runtime view. The other three runtime keys remain at their
    defaults."""
    p = tmp_path / "patterns.yaml"
    p.write_text(
        "pattern_overrides:\n"
        "  \"a1b2c3d4e5f60001\": high\n",
        encoding="utf-8",
    )
    cfg = load_runtime_severity_overrides(p)
    assert cfg is not None
    assert not cfg.is_empty()
    assert cfg.pattern_overrides == {"a1b2c3d4e5f60001": "high"}
    assert cfg.device_category_severity == {}
    assert cfg.suppress_categories == frozenset()
    assert cfg.suppress_vendors == frozenset()


def test_load_pattern_overrides_normalizes_case(tmp_path):
    """Argus emits argus_record_id as a lowercase 16-hex SHA-256
    prefix, but an operator copy-pasting from a different surface
    (e.g. the web UI which renders the value verbatim) could end up
    with mixed casing. Load-time normalization makes the eval-time
    lookup case-insensitive without paying the cost of a normalize
    at every match."""
    p = tmp_path / "mixed_case.yaml"
    p.write_text(
        "pattern_overrides:\n"
        "  \"A1B2C3D4E5F60001\": high\n"
        "  \"  fedcba9876543210  \": med\n",
        encoding="utf-8",
    )
    cfg = load_runtime_severity_overrides(p)
    assert cfg is not None
    assert cfg.pattern_overrides == {
        "a1b2c3d4e5f60001": "high",
        "fedcba9876543210": "med",
    }


def test_load_pattern_overrides_drops_malformed_key_format_with_warning(
    tmp_path, caplog
):
    """A key that isn't 16 hex chars after normalization is dropped
    with a WARNING; the rest of the dict still parses. One bad key
    must not disable the whole layer."""
    p = tmp_path / "malformed_keys.yaml"
    p.write_text(
        "pattern_overrides:\n"
        "  \"a1b2c3d4e5f60001\": high\n"           # valid
        "  \"a1b2\": med\n"                          # too short
        "  \"a1b2c3d4e5f60001abcdef\": med\n"        # too long
        "  \"g1b2c3d4e5f60001\": med\n"              # non-hex char
        "  \"fedcba9876543210\": low\n",             # valid
        encoding="utf-8",
    )
    with caplog.at_level(logging.WARNING, logger="lynceus.rules"):
        cfg = load_runtime_severity_overrides(p)
    assert cfg is not None
    assert cfg.pattern_overrides == {
        "a1b2c3d4e5f60001": "high",
        "fedcba9876543210": "low",
    }
    warnings = [
        r for r in caplog.records
        if r.levelno == logging.WARNING and "pattern_overrides" in r.getMessage()
    ]
    # One WARN per malformed key: too-short + too-long + non-hex → 3.
    assert len(warnings) == 3


def test_load_pattern_overrides_drops_invalid_severity_with_warning(
    tmp_path, caplog
):
    """A valid 16-hex key paired with a non-severity value is dropped
    with a WARNING — the entry would crash the dataclass validator
    if it slipped through, so per-entry drop is the only way to keep
    the layer alive in the presence of an operator typo."""
    p = tmp_path / "bad_severity.yaml"
    p.write_text(
        "pattern_overrides:\n"
        "  \"a1b2c3d4e5f60001\": high\n"
        "  \"fedcba9876543210\": critical\n"   # not a valid severity
        "  \"1111222233334444\": 5\n",          # not a string
        encoding="utf-8",
    )
    with caplog.at_level(logging.WARNING, logger="lynceus.rules"):
        cfg = load_runtime_severity_overrides(p)
    assert cfg is not None
    assert cfg.pattern_overrides == {"a1b2c3d4e5f60001": "high"}
    warnings = [
        r for r in caplog.records
        if r.levelno == logging.WARNING and "pattern_overrides" in r.getMessage()
    ]
    assert len(warnings) == 2


def test_load_pattern_overrides_drops_non_string_keys_with_warning(
    tmp_path, caplog
):
    """A non-string key (e.g. YAML auto-converted an unquoted bare
    word to an integer) is dropped with a WARNING. Per-entry
    tolerance: the surrounding dict still parses normally."""
    p = tmp_path / "non_string_keys.yaml"
    # YAML auto-converts ``42`` to an int when unquoted; the loader
    # must defend against that even though the operator probably
    # meant something else.
    p.write_text(
        "pattern_overrides:\n"
        "  42: high\n"
        "  \"a1b2c3d4e5f60001\": med\n",
        encoding="utf-8",
    )
    with caplog.at_level(logging.WARNING, logger="lynceus.rules"):
        cfg = load_runtime_severity_overrides(p)
    assert cfg is not None
    assert cfg.pattern_overrides == {"a1b2c3d4e5f60001": "med"}
    warnings = [
        r for r in caplog.records
        if r.levelno == logging.WARNING and "pattern_overrides" in r.getMessage()
    ]
    assert len(warnings) == 1


def test_load_pattern_overrides_empty_dict_pass_through(tmp_path):
    """An empty ``pattern_overrides: {}`` (the wizard starter's
    default) parses without error and leaves the field at its
    default empty dict. is_empty() returns True when this is the
    only key present — the runtime layer fast-paths through."""
    p = tmp_path / "empty_patterns.yaml"
    p.write_text("pattern_overrides: {}\n", encoding="utf-8")
    cfg = load_runtime_severity_overrides(p)
    assert cfg is not None
    assert cfg.pattern_overrides == {}
    assert cfg.is_empty()


def test_load_pattern_overrides_non_dict_is_ignored(tmp_path):
    """Tolerant of operator typos: a list-shaped value (rather than
    a dict) is silently dropped — same defensive shape as the
    suppress_* loaders. The eval layer pass-throughs uncovered keys,
    so a dropped key just means 'no pattern overrides' (the
    conservative default)."""
    p = tmp_path / "list_shape.yaml"
    p.write_text(
        "device_category_severity:\n"
        "  unknown: med\n"
        "pattern_overrides:\n"
        "  - \"a1b2c3d4e5f60001\"\n",  # operator typo: list, not dict
        encoding="utf-8",
    )
    cfg = load_runtime_severity_overrides(p)
    assert cfg is not None
    assert cfg.device_category_severity == {"unknown": "med"}
    assert cfg.pattern_overrides == {}


def test_load_all_four_runtime_keys_combined(tmp_path):
    """A file mixing every runtime key. Each lands in its own field;
    counts in the INFO log line up across all four categories."""
    p = tmp_path / "all_four.yaml"
    p.write_text(
        "device_category_severity:\n"
        "  unknown: med\n"
        "  alpr: high\n"
        "suppress_categories:\n"
        "  - drone\n"
        "suppress_vendors:\n"
        "  - \"Mitsubishi Electric US, Inc.\"\n"
        "pattern_overrides:\n"
        "  \"a1b2c3d4e5f60001\": high\n"
        "  \"fedcba9876543210\": low\n",
        encoding="utf-8",
    )
    cfg = load_runtime_severity_overrides(p)
    assert cfg is not None
    assert cfg.device_category_severity == {"unknown": "med", "alpr": "high"}
    assert cfg.suppress_categories == frozenset({"drone"})
    assert cfg.suppress_vendors == frozenset({"mitsubishi electric us, inc."})
    assert cfg.pattern_overrides == {
        "a1b2c3d4e5f60001": "high",
        "fedcba9876543210": "low",
    }
