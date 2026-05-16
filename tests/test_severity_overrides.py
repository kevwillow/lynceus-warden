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


def test_combined_remap_and_suppress():
    cfg = RuntimeSeverityOverride(
        device_category_severity={"unknown": "med", "alpr": "high"},
        suppress_categories=frozenset({"drone"}),
    )
    assert not cfg.is_empty()
    assert cfg.device_category_severity["alpr"] == "high"
    assert "drone" in cfg.suppress_categories


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
    categories) make the log self-describing — an operator who
    expected 3 remaps but sees 1 knows the file's parsing is
    selective."""
    p = tmp_path / "active.yaml"
    p.write_text(
        "device_category_severity:\n"
        "  unknown: med\n"
        "  alpr: high\n"
        "suppress_categories:\n"
        "  - drone\n",
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
