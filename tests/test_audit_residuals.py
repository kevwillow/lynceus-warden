"""Structural tests for ``scripts/audit_residuals.py``.

The audit script's primary deliverable is the analysis output itself
(``docs/ARGUS_RESIDUALS.md``) — not a behavior contract that needs
to be locked down. These tests cover the framing the operator
relies on: counts match the input fixture, recommendation logic
honors the documented decision table, the markdown table is
well-formed, and the default-path resolver falls back gracefully
when no CSV is at the expected locations.
"""

from __future__ import annotations

import importlib.util
import sys
from collections import Counter
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
AUDIT_PATH = REPO_ROOT / "scripts" / "audit_residuals.py"


def _load_audit_module():
    """Load ``scripts/audit_residuals.py`` as a module.

    Lives in ``scripts/`` (not under ``src/``) and is not installed
    via ``[project.scripts]`` — a fresh ``spec_from_file_location``
    load is the cleanest way to expose its symbols to the tests
    without polluting the package surface.
    """
    spec = importlib.util.spec_from_file_location(
        "audit_residuals", AUDIT_PATH
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["audit_residuals"] = module
    spec.loader.exec_module(module)
    return module


audit = _load_audit_module()


META_LINE = (
    "# meta: schema_version=21, exported_at=2026-05-17T15:53:27Z, "
    "record_count=10, confidence_threshold=0\n"
)
HEADER_LINE = (
    "argus_record_id,id,identifier,identifier_type,device_category,"
    "manufacturer,model,confidence,source_type,source_url,"
    "source_excerpt,geographic_scope,description,first_seen,"
    "last_verified,notes\n"
)


def _row(rid: str, identifier: str, itype: str) -> str:
    """Build one fixture CSV row.

    Most columns are not what the audit cares about; they just need
    to be present and parseable. Sets confidence=80, geographic
    scope=global, and trivial source fields so the importer-style
    parser is happy.
    """
    return (
        f"{rid},argus-{rid},{identifier},{itype},surveillance,"
        f"acme,model-x,80,research,https://example.org/x,"
        f"excerpt,global,desc,2026-05-01T00:00:00Z,"
        f"2026-05-10T00:00:00Z,notes\n"
    )


def _write_fixture(tmp_path: Path, rows: list[str]) -> Path:
    """Write a minimal Argus-shaped CSV under ``tmp_path``."""
    p = tmp_path / "argus.csv"
    with open(p, "w", encoding="utf-8", newline="") as f:
        f.write(META_LINE)
        f.write(HEADER_LINE)
        for r in rows:
            f.write(r)
    return p


# --- collect_residuals --------------------------------------------------


def test_collect_residuals_counts_admitted_vs_dropped(tmp_path):
    """Two admitted (``mac``, ``oui``), three dropped across two types."""
    rows = [
        _row("r1", "aa:bb:cc:dd:ee:ff", "mac"),
        _row("r2", "aa:bb:cc", "oui"),
        _row("r3", "APQ8009", "chipset_codename"),
        _row("r4", "APQ8016", "chipset_codename"),
        _row("r5", "0x4C", "ble_company_id"),
    ]
    p = _write_fixture(tmp_path, rows)
    samples, admitted, total, counts = audit.collect_residuals(p)
    assert total == 5
    assert admitted == 2
    assert counts == Counter(
        {"chipset_codename": 2, "ble_company_id": 1}
    )
    assert samples["chipset_codename"] == ["APQ8009", "APQ8016"]
    assert samples["ble_company_id"] == ["0x4C"]


def test_collect_residuals_keeps_first_five_distinct_samples(tmp_path):
    """``samples`` caps at five distinct values per residual type.

    Six rows of the same residual type with distinct identifiers ->
    only the first five are retained; the sixth is dropped from the
    sample list but still counted.
    """
    rows = [
        _row(f"r{i}", f"value-{i}", "chipset_codename") for i in range(6)
    ]
    p = _write_fixture(tmp_path, rows)
    samples, admitted, total, counts = audit.collect_residuals(p)
    assert counts["chipset_codename"] == 6
    assert samples["chipset_codename"] == [
        "value-0",
        "value-1",
        "value-2",
        "value-3",
        "value-4",
    ]


def test_collect_residuals_dedupes_identical_identifiers(tmp_path):
    """A residual type with two rows carrying the same identifier
    yields ``count=2`` but ``samples=[identifier]`` (deduped)."""
    rows = [
        _row("r1", "APQ8009", "chipset_codename"),
        _row("r2", "APQ8009", "chipset_codename"),
    ]
    p = _write_fixture(tmp_path, rows)
    samples, _, _, counts = audit.collect_residuals(p)
    assert counts["chipset_codename"] == 2
    assert samples["chipset_codename"] == ["APQ8009"]


def test_collect_residuals_uppercase_type_treated_as_admitted(tmp_path):
    """The importer lowercases ``identifier_type`` before lookup,
    so ``BLE_SERVICE`` is admitted not dropped. Audit must mirror."""
    rows = [
        _row("r1", "0000180d-0000-1000-8000-00805f9b34fb", "BLE_SERVICE"),
    ]
    p = _write_fixture(tmp_path, rows)
    _, admitted, total, counts = audit.collect_residuals(p)
    assert admitted == 1
    assert total == 1
    assert counts == Counter()


# --- classify_recommendation -------------------------------------------


@pytest.mark.parametrize(
    "surface, yield_count, expected",
    [
        # Normalization variant wins over yield: ``admit-via-normalization``
        # regardless of count.
        ("normalization-variant", 1, "admit-via-normalization"),
        ("normalization-variant", 50, "admit-via-normalization"),
        # No surface always drops.
        ("no-observation-surface", 1, "drop-entirely"),
        ("no-observation-surface", 999, "drop-entirely"),
        # Plausible / verified surface + small yield drops.
        ("plausible-needs-smoke", 4, "drop-entirely"),
        ("verified-lynceus", 4, "drop-entirely"),
        ("verified-kismet-docs", 4, "drop-entirely"),
        # Plausible / kismet-docs at threshold defers.
        ("plausible-needs-smoke", 5, "defer-pending-smoke"),
        ("verified-kismet-docs", 5, "defer-pending-smoke"),
        # Verified-lynceus at threshold = admit (high-value).
        ("verified-lynceus", 5, "admit"),
        ("verified-lynceus", 100, "admit"),
        # Unknown surface signals an audit table refresh.
        ("unknown-needs-classification", 999, "needs-classification"),
    ],
)
def test_classify_recommendation(surface, yield_count, expected):
    assert audit.classify_recommendation(surface, yield_count) == expected


# --- render_report ------------------------------------------------------


def test_render_report_table_has_correct_column_count(tmp_path):
    """Every data row in the per-type breakdown table has the same
    column count as the header (five separator pipes, six cells).
    Regression guard against an ``identifier`` that includes a pipe
    breaking row shape."""
    rows = [
        _row("r1", "with | pipe", "chipset_codename"),
        _row("r2", "no pipe", "ble_company_id"),
    ]
    p = _write_fixture(tmp_path, rows)
    samples, admitted, total, counts = audit.collect_residuals(p)
    report = audit.render_report(
        csv_path=p,
        samples=samples,
        counts=counts,
        admitted=admitted,
        total=total,
        meta={"schema_version": "21", "record_count": 2},
    )
    # Find the breakdown table block; data rows are after the
    # separator row, until the next blank line.
    lines = report.splitlines()
    header_index = next(
        i for i, line in enumerate(lines)
        if line.startswith("| Type | Argus rows")
    )
    separator_line = lines[header_index + 1]
    assert separator_line.startswith("|---")
    expected_pipes = lines[header_index].count("|")
    for body_line in lines[header_index + 2:]:
        if not body_line.startswith("|"):
            break
        # Count unescaped pipes only — a literal '|' in a sample
        # value is escaped as '\|' which must NOT count as a
        # column separator.
        unescaped = body_line.replace("\\|", "")
        assert unescaped.count("|") == expected_pipes, (
            f"row has wrong column count: {body_line!r}"
        )


def test_render_report_summary_counts_match_per_type_rows(tmp_path):
    """High-yield + no-surface => ``drop-entirely``; high-yield +
    normalization-variant => ``admit-via-normalization``; high-yield
    + plausible => ``defer-pending-smoke``. The Summary section must
    aggregate the per-type rows correctly."""
    # Build a fixture where each non-trivial recommendation bucket
    # gets exactly one type with yield 6 (above the threshold).
    rows: list[str] = []
    rows += [_row(f"a{i}", f"APQ80{i:02d}", "chipset_codename") for i in range(6)]
    rows += [_row(f"b{i}", f"0x{i:04x}", "ble_company_id") for i in range(6)]
    rows += [
        _row(f"c{i}", f"DJI device_type={i}", "device_class_id") for i in range(6)
    ]
    rows += [_row(f"d{i}", f"name-{i}", "ble_local_name") for i in range(6)]
    p = _write_fixture(tmp_path, rows)
    samples, admitted, total, counts = audit.collect_residuals(p)
    report = audit.render_report(
        csv_path=p,
        samples=samples,
        counts=counts,
        admitted=admitted,
        total=total,
        meta={},
    )
    assert "- **admit**: 1 type(s), 6 row(s)" in report
    assert (
        "- **admit-via-normalization**: 1 type(s), 6 row(s)"
        in report
    )
    assert "- **defer-pending-smoke**: 1 type(s), 6 row(s)" in report
    assert "- **drop-entirely**: 1 type(s), 6 row(s)" in report
    assert (
        "- **needs-classification**: 0 type(s), 0 row(s)" in report
    )


def test_render_report_flags_unknown_type_as_needs_classification(tmp_path):
    """A residual type not in ``RESIDUAL_SURFACE_TABLE`` shows
    ``needs-classification`` in the recommendation column instead of
    a fabricated verdict."""
    rows = [
        _row(f"r{i}", f"value-{i}", "newly_added_argus_type")
        for i in range(10)
    ]
    p = _write_fixture(tmp_path, rows)
    samples, admitted, total, counts = audit.collect_residuals(p)
    report = audit.render_report(
        csv_path=p,
        samples=samples,
        counts=counts,
        admitted=admitted,
        total=total,
        meta={},
    )
    assert "needs-classification" in report
    assert "newly_added_argus_type" in report


def test_render_report_escapes_pipes_in_sample_cells(tmp_path):
    """A literal ``|`` in an Argus identifier must be backslash-
    escaped in the markdown cell so the table still renders."""
    rows = [
        _row("r1", "pipe|inside|value", "chipset_codename"),
    ]
    p = _write_fixture(tmp_path, rows)
    samples, admitted, total, counts = audit.collect_residuals(p)
    report = audit.render_report(
        csv_path=p,
        samples=samples,
        counts=counts,
        admitted=admitted,
        total=total,
        meta={},
    )
    assert "`pipe\\|inside\\|value`" in report


# --- main + default path resolution -------------------------------------


def test_main_writes_report_to_output_path(tmp_path, capsys):
    """End-to-end: ``main`` parses, classifies, renders, and writes
    the report to ``--output``. The default path fallback is not
    exercised here — that's the resolver test below."""
    rows = [_row("r1", "APQ8009", "chipset_codename")]
    csv_path = _write_fixture(tmp_path, rows)
    output_path = tmp_path / "report.md"
    rc = audit.main(["--csv", str(csv_path), "--output", str(output_path)])
    assert rc == 0
    body = output_path.read_text(encoding="utf-8")
    assert "# Argus Residual Types Audit" in body
    assert "chipset_codename" in body
    # stderr carries the structured summary line for re-runs.
    captured = capsys.readouterr()
    assert "audit_residuals: total=1" in captured.err


def test_resolve_default_csv_falls_back_to_argus_cache(
    tmp_path, monkeypatch
):
    """When the dev-box snapshot path is absent, the resolver picks
    the newest ``*.csv`` from the user-scope argus-cache directory."""
    missing = tmp_path / "nonexistent" / "argus_export.csv"
    monkeypatch.setattr(audit, "DEV_BOX_SNAPSHOT", missing)
    cache_dir = tmp_path / "data" / "argus-cache"
    cache_dir.mkdir(parents=True)
    older = cache_dir / "old.csv"
    newer = cache_dir / "new.csv"
    older.write_text("# meta: older\n", encoding="utf-8")
    newer.write_text("# meta: newer\n", encoding="utf-8")
    # Force a clear mtime ordering even on filesystems with low
    # mtime resolution (FAT, some network mounts).
    import os
    os.utime(older, (1_000, 1_000))
    os.utime(newer, (2_000, 2_000))

    from lynceus import paths
    monkeypatch.setattr(paths, "default_data_dir", lambda scope: tmp_path / "data")

    resolved = audit.resolve_default_csv()
    assert resolved == newer


def test_resolve_default_csv_returns_none_when_no_sources(
    tmp_path, monkeypatch
):
    """Both default sources absent => resolver returns None; main
    then surfaces a clear argparse error instead of crashing."""
    monkeypatch.setattr(
        audit, "DEV_BOX_SNAPSHOT", tmp_path / "missing.csv"
    )
    from lynceus import paths
    monkeypatch.setattr(
        paths, "default_data_dir", lambda scope: tmp_path / "nope"
    )
    assert audit.resolve_default_csv() is None

    with pytest.raises(SystemExit):
        audit.main([])
