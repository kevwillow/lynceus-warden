"""Tests for lynceus.setup.models — type vocabulary for the apply_config core."""

from __future__ import annotations

import dataclasses

import pytest

from lynceus.setup import (
    STEP_NAMES,
    ApplyReport,
    ApplyStep,
    ProgressSink,
)


# ---- ApplyStep -------------------------------------------------------------


def test_apply_step_is_frozen():
    step = ApplyStep(name="write_config", status="ok", message="wrote it")
    with pytest.raises(dataclasses.FrozenInstanceError):
        step.message = "no rebinding allowed"  # type: ignore[misc]


def test_apply_step_equality_by_value():
    a = ApplyStep(name="write_config", status="ok", message="m", detail={"k": 1})
    b = ApplyStep(name="write_config", status="ok", message="m", detail={"k": 1})
    assert a == b
    # detail differing → not equal
    c = ApplyStep(name="write_config", status="ok", message="m", detail={"k": 2})
    assert a != c


def test_apply_step_detail_defaults_to_none():
    step = ApplyStep(name="write_config", status="ok", message="wrote it")
    assert step.detail is None


# ---- ApplyReport.overall_status -------------------------------------------


def test_overall_status_ok_when_all_steps_ok():
    report = ApplyReport(
        steps=(
            ApplyStep(name="write_config", status="ok", message="m"),
            ApplyStep(name="scaffold_severity_overrides", status="ok", message="m"),
        )
    )
    assert report.overall_status == "ok"


def test_overall_status_ok_when_some_skipped_no_failures():
    # "skipped" is not a failure — a step that doesn't apply (chown
    # under --user, bundled-import disabled) is still a success shape.
    report = ApplyReport(
        steps=(
            ApplyStep(name="write_config", status="ok", message="m"),
            ApplyStep(name="chown_db_files", status="skipped", message="--user"),
        )
    )
    assert report.overall_status == "ok"


def test_overall_status_failed_when_any_step_failed():
    report = ApplyReport(
        steps=(
            ApplyStep(name="write_config", status="ok", message="m"),
            ApplyStep(name="import_bundled_watchlist", status="failed", message="boom"),
            ApplyStep(name="write_rules", status="ok", message="m"),
        )
    )
    assert report.overall_status == "failed"


def test_overall_status_ok_when_a_step_warns():
    # "warning" is a non-blocking outcome (Arc B Kismet source-name
    # cross-check semantics): the step ran, found something the
    # operator needs to know about, but the apply pipeline still
    # completed successfully. overall_status must NOT flip to
    # "failed" — only an actual "failed" step does that.
    report = ApplyReport(
        steps=(
            ApplyStep(name="write_config", status="ok", message="m"),
            ApplyStep(
                name="verify_kismet_sources",
                status="warning",
                message="mismatched source names: ['wlan0']",
            ),
        )
    )
    assert report.overall_status == "ok"


def test_overall_status_ok_for_empty_report():
    # An apply_config that no-ops (e.g. dry-run flag, future) still
    # returns a structurally valid report.
    report = ApplyReport(steps=())
    assert report.overall_status == "ok"


# ---- ProgressSink Protocol ------------------------------------------------


def test_progress_sink_runtime_checkable():
    class Recorder:
        def __init__(self) -> None:
            self.calls: list[ApplyStep] = []

        def record(self, step: ApplyStep) -> None:
            self.calls.append(step)

    rec = Recorder()
    assert isinstance(rec, ProgressSink)


def test_progress_sink_rejects_objects_without_record():
    class NotASink:
        pass

    assert not isinstance(NotASink(), ProgressSink)


# ---- STEP_NAMES constants -------------------------------------------------


def test_step_names_tuple_is_exhaustive():
    # Pinning the canonical set so Touch 2's apply_config can't silently
    # drop a step. If a new step is intentionally added, this test gets
    # updated in the same commit as the core change.
    assert STEP_NAMES == (
        "write_config",
        "scaffold_severity_overrides",
        "scaffold_allowlist",
        "create_data_dir",
        "create_log_dir",
        "import_bundled_watchlist",
        "chown_db_files",
        "write_rules",
        "verify_kismet_sources",
    )


def test_step_names_are_unique():
    assert len(STEP_NAMES) == len(set(STEP_NAMES))
