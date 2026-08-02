"""Tests for the CLI ProgressSink used by ``run_wizard``."""

from __future__ import annotations

from lynceus.cli import setup as wiz
from lynceus.setup.models import STEP_NAMES, ApplyStep, ProgressSink


def test_cli_progress_sink_satisfies_protocol():
    sink = wiz.CLIProgressSink()
    assert isinstance(sink, ProgressSink)


def test_cli_progress_sink_starts_empty():
    sink = wiz.CLIProgressSink()
    assert sink.steps == []


def test_cli_progress_sink_records_one_step():
    sink = wiz.CLIProgressSink()
    step = ApplyStep(name="write_config", status="ok", message="wrote it")
    sink.record(step)
    assert sink.steps == [step]


def test_cli_progress_sink_preserves_record_order():
    sink = wiz.CLIProgressSink()
    a = ApplyStep(name="write_config", status="ok", message="m1")
    b = ApplyStep(name="scaffold_severity_overrides", status="ok", message="m2")
    c = ApplyStep(name="import_bundled_watchlist", status="failed", message="m3")
    for step in (a, b, c):
        sink.record(step)
    assert sink.steps == [a, b, c]


def test_cli_progress_sink_is_silent(capsys):
    """Phase 1 contract: the CLI sink does NOT print per step.

    ``run_wizard`` reads from the returned ``ApplyReport`` after
    ``apply_config`` completes and reconstructs the legacy per-phase
    prints (summary block, bundled-import message, group-ownership
    summary) in the byte-for-byte order the pre-refactor wizard
    emitted them. If the sink started printing, it would inject
    output INTO the apply_config call window — between the prompts
    and the summary block — and tests that grep specific summary
    strings at specific positions would shift.
    """
    sink = wiz.CLIProgressSink()
    for step_name in STEP_NAMES:
        sink.record(ApplyStep(name=step_name, status="ok", message="x"))
    out = capsys.readouterr()
    assert out.out == ""
    assert out.err == ""


def test_cli_progress_sink_collects_full_canonical_step_sequence_via_apply_config(
    tmp_path, monkeypatch
):
    """End-to-end smoke: apply_config wired with a CLIProgressSink
    records every step in STEP_NAMES order — same contract Touch 2's
    test_apply_report_step_order_matches_canonical_sequence pins, but
    routed through the CLI sink to confirm record() is hooked up."""
    from lynceus import paths as paths_mod
    from lynceus.config import CaptureConfig, Config
    from lynceus.setup.core import apply_config

    monkeypatch.setattr(wiz, "_is_windows", lambda: False)
    monkeypatch.setattr(paths_mod, "default_data_dir", lambda scope: tmp_path / "data")
    monkeypatch.setattr(paths_mod, "default_log_dir", lambda scope: tmp_path / "log")
    monkeypatch.setattr(
        paths_mod,
        "default_db_path",
        lambda scope: tmp_path / "data" / "lynceus.db",
    )
    monkeypatch.setattr(
        wiz,
        "import_bundled_watchlist",
        lambda db_path, override_file: (False, "no bundled watchlist"),
    )

    sink = wiz.CLIProgressSink()
    config = Config(
        kismet_url="http://127.0.0.1:2501",
        kismet_api_key="t",
        kismet_sources=["wlan0"],
        capture=CaptureConfig(probe_ssids=False, ble_friendly_names=True),
        ntfy_url=None,
        ntfy_topic=None,
        min_rssi=-70,
    )
    report = apply_config(
        config,
        scope="user",
        target_path=tmp_path / "lynceus.yaml",
        severity_overrides_path=tmp_path / "severity_overrides.yaml",
        allowlist_path=tmp_path / "allowlist.yaml",
        enabled_rule_types=None,
        progress=sink,
    )

    sink_names = tuple(s.name for s in sink.steps)
    assert sink_names == STEP_NAMES
    assert tuple(sink.steps) == report.steps
