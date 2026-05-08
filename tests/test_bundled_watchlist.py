"""Tests for the bundled default watchlist shipped under ``lynceus.data``.

Covers the package-data wiring (``pyproject.toml`` → wheel → importlib.resources),
the NOTICE.md provenance metadata, and a non-mocked sanity check that
``import_bundled_watchlist`` from ``lynceus.cli.setup`` actually locates the
real CSV resource.
"""

from __future__ import annotations

import csv
import datetime as _dt
import importlib.resources
import io
import re
from unittest.mock import MagicMock

from lynceus.cli import setup as wiz
from lynceus.cli.import_argus import EXPECTED_HEADER

DATA_PACKAGE = "lynceus.data"
CSV_RESOURCE = "default_watchlist.csv"
NOTICE_RESOURCE = "NOTICE.md"


def _read_resource_text(name: str) -> str:
    return importlib.resources.files(DATA_PACKAGE).joinpath(name).read_text(encoding="utf-8")


def test_bundled_csv_present_at_resource_path():
    resource = importlib.resources.files(DATA_PACKAGE).joinpath(CSV_RESOURCE)
    assert resource.is_file(), f"expected {DATA_PACKAGE}/{CSV_RESOURCE} to be packaged"


def test_bundled_csv_has_cp11_header():
    text = _read_resource_text(CSV_RESOURCE)
    lines = text.splitlines()
    # Skip the leading "# meta:" line; the second line is the CP11 header.
    assert lines[0].startswith("# meta:"), "expected leading meta line"
    reader = csv.reader(io.StringIO("\n".join(lines[1:])))
    header = next(reader)
    assert header == EXPECTED_HEADER, f"bundled CSV header does not match CP11 schema; got {header}"
    assert len(header) == 16


def test_bundled_csv_has_at_least_one_data_row():
    text = _read_resource_text(CSV_RESOURCE)
    lines = text.splitlines()
    reader = csv.DictReader(io.StringIO("\n".join(lines[1:])))
    rows = list(reader)
    assert len(rows) >= 1, "bundled CSV is empty (no data rows after header)"


def test_notice_present_at_resource_path():
    resource = importlib.resources.files(DATA_PACKAGE).joinpath(NOTICE_RESOURCE)
    assert resource.is_file(), f"expected {DATA_PACKAGE}/{NOTICE_RESOURCE} to be packaged"


def test_notice_credits_argus():
    text = _read_resource_text(NOTICE_RESOURCE)
    assert "Argus" in text, "NOTICE.md must mention Argus as the data source"


def test_notice_includes_iso8601_snapshot_timestamp():
    """The NOTICE must cite the snapshot's ``exported_at`` so operators know
    how stale the bundled data is. Format must be ISO 8601 (Z-suffixed UTC)."""
    text = _read_resource_text(NOTICE_RESOURCE)
    match = re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", text)
    assert match is not None, "NOTICE.md does not contain an ISO 8601 timestamp"
    # Round-trip parse to be sure it's a valid timestamp, not just shape-matched.
    _dt.datetime.strptime(match.group(0), "%Y-%m-%dT%H:%M:%SZ")


def test_notice_timestamp_matches_csv_meta_line():
    """Sanity: the timestamp the NOTICE advertises should match the CSV's own
    ``# meta: exported_at=...`` line. If they drift, the NOTICE is lying."""
    csv_text = _read_resource_text(CSV_RESOURCE)
    notice_text = _read_resource_text(NOTICE_RESOURCE)
    csv_match = re.search(r"exported_at=(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)", csv_text)
    assert csv_match is not None, "bundled CSV missing exported_at in meta line"
    assert csv_match.group(1) in notice_text, (
        f"NOTICE does not reference the CSV's exported_at={csv_match.group(1)}"
    )


def test_import_bundled_watchlist_locates_real_resource(monkeypatch):
    """End-to-end sanity that the package-data wiring works: with no
    importlib.resources patching, ``import_bundled_watchlist`` must reach the
    subprocess invocation rather than short-circuiting on
    ``no bundled watchlist``. We stub ``subprocess.Popen`` so the test stays
    offline-deterministic and doesn't depend on ``lynceus-import-argus`` being
    on PATH inside the test runner."""
    captured = {}

    def fake_popen(args, **kwargs):
        captured["args"] = list(args)
        proc = MagicMock()
        proc.communicate.return_value = ("imported 63 records, updated 0, dropped 0\n", "")
        proc.returncode = 0
        return proc

    monkeypatch.setattr(wiz.subprocess, "Popen", fake_popen)
    ok, msg = wiz.import_bundled_watchlist(db_path="/tmp/lynceus-test.db", override_file=None)
    assert ok is True, f"expected bundled import to succeed, got: {msg}"
    assert "imported 63 records" in msg
    # The subprocess must have been invoked with the bundled CSV path.
    assert captured["args"][0] == "lynceus-import-argus"
    input_idx = captured["args"].index("--input")
    csv_path = captured["args"][input_idx + 1]
    assert csv_path.endswith("default_watchlist.csv"), (
        f"expected --input to point at default_watchlist.csv, got {csv_path}"
    )
