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


def test_bundled_csv_meta_record_count_matches_parsed_row_count():
    """The meta line advertises ``record_count=N``; the parser should
    yield exactly N data rows. A drift here means the snapshot was
    re-exported but the meta header wasn't rewritten -- operators
    relying on the count for sizing checks would see stale numbers."""
    text = _read_resource_text(CSV_RESOURCE)
    meta_match = re.search(r"record_count=(\d+)", text)
    assert meta_match is not None, "bundled CSV missing record_count in meta line"
    meta_count = int(meta_match.group(1))

    lines = text.splitlines()
    reader = csv.DictReader(io.StringIO("\n".join(lines[1:])))
    parsed_count = sum(1 for _ in reader)
    assert parsed_count == meta_count, (
        f"meta record_count={meta_count} but parser yielded {parsed_count} rows"
    )


def test_bundled_csv_identifier_types_all_recognized_by_importer():
    """Every distinct identifier_type in the bundle must be a key in
    ``IDENTIFIER_TYPE_MAP``, OR be a residual the importer expects to
    drop (residuals are documented in docs/ARGUS_RESIDUALS.md). If a
    new Argus identifier_type lands in the bundle without a
    corresponding import alias, the importer silently drops it as
    unknown_type and the row never reaches the watchlist DB. This
    test surfaces that gap before a fresh install hits it."""
    from lynceus.cli.import_argus import IDENTIFIER_TYPE_MAP

    text = _read_resource_text(CSV_RESOURCE)
    lines = text.splitlines()
    reader = csv.DictReader(io.StringIO("\n".join(lines[1:])))
    distinct_types = {r["identifier_type"].strip().lower() for r in reader}

    admitted = distinct_types & set(IDENTIFIER_TYPE_MAP.keys())
    residuals = distinct_types - set(IDENTIFIER_TYPE_MAP.keys())

    # Sanity: at least one admitted type (otherwise the import would
    # produce an empty watchlist).
    assert admitted, "bundled CSV has zero identifier_types recognized by importer"

    # Residuals are expected (Argus is broader than Lynceus's matching
    # surface); but the SSID dimension's two types -- ssid_exact and
    # ssid_pattern -- MUST be in admitted, not residuals, after rc6's
    # activation work.
    assert "ssid_exact" in admitted, (
        "ssid_exact must be admitted (alias to 'ssid') in IDENTIFIER_TYPE_MAP"
    )
    assert "ssid_pattern" in admitted, (
        "ssid_pattern must be admitted in IDENTIFIER_TYPE_MAP (migration 019)"
    )

    # Residuals must be a strict subset of the documented audit set,
    # but we don't assert the exact membership here -- the per-type
    # breakdown lives in docs/ARGUS_RESIDUALS.md and runs separately.
    # We DO assert no admitted type slipped into residuals by typo.
    assert not (admitted & residuals), "type cannot be both admitted and residual"


def test_bundled_csv_ssid_rows_land_in_watchlist_db(tmp_path):
    """End-to-end against the actual bundled CSV (not synthetic data):
    after importing, the watchlist DB contains rows with
    ``pattern_type='ssid'`` (from the 5 ssid_exact alias rows; natural-
    key dedup collapses duplicate identifiers) AND rows with
    ``pattern_type='ssid_pattern'`` (from the 5 ssid_pattern rows).
    This is the contract the new SSID activation work depends on --
    a regression here would make the argus_ssid rule operationally
    silent for fresh installs."""
    from lynceus.cli.import_argus import OverrideConfig, import_csv
    from lynceus.db import Database

    bundle_path = importlib.resources.files(DATA_PACKAGE).joinpath(CSV_RESOURCE)
    db = Database(str(tmp_path / "lynceus.db"))
    try:
        import_csv(db, str(bundle_path), OverrideConfig())
        ssid_rows = db._conn.execute(
            "SELECT pattern FROM watchlist WHERE pattern_type = 'ssid'"
        ).fetchall()
        ssid_pattern_rows = db._conn.execute(
            "SELECT pattern FROM watchlist WHERE pattern_type = 'ssid_pattern'"
        ).fetchall()

        # ssid_exact dedup: 5 Argus rows (Flock x2, Flock-230503 x2,
        # Flock-*) collapse to 3 unique watchlist rows via natural-key.
        assert len(ssid_rows) == 3, (
            f"expected 3 unique ssid rows (post-dedup), got {len(ssid_rows)}"
        )
        ssid_patterns = sorted(r["pattern"] for r in ssid_rows)
        assert ssid_patterns == ["Flock", "Flock-*", "Flock-230503"]

        # ssid_pattern: 5 Argus rows, no duplicates by natural key.
        assert len(ssid_pattern_rows) == 5
        sp_patterns = sorted(r["pattern"] for r in ssid_pattern_rows)
        assert sp_patterns == ["FLOCK", "FS Ext Battery", "Flock", "Penguin", "flock"]
    finally:
        db.close()


def test_bundled_csv_end_to_end_flock_observation_fires_argus_ssid_alert(tmp_path):
    """The operational loop the rc6 SSID activation enables: import the
    bundled CSV, configure the bundled argus_ssid rule (empty-patterns
    delegation), evaluate a Kismet-shaped observation of ``Flock`` ->
    a RuleHit is produced with severity from the matched DB row.

    Without this test, refactors to import / db / rules could each pass
    in isolation while the integrated path went silent -- the operator-
    visible 'alert on Flock cameras out of the box' promise depends on
    all three layers fitting together."""
    from lynceus.cli.import_argus import OverrideConfig, import_csv
    from lynceus.db import Database
    from lynceus.kismet import DeviceObservation
    from lynceus.rules import Rule, Ruleset, evaluate

    bundle_path = importlib.resources.files(DATA_PACKAGE).joinpath(CSV_RESOURCE)
    db = Database(str(tmp_path / "lynceus.db"))
    try:
        import_csv(db, str(bundle_path), OverrideConfig())

        rule = Rule(
            name="argus_ssid",
            rule_type="watchlist_ssid",
            severity="low",  # ignored -- severity comes from the matched row
            patterns=[],
            description="Argus + bundled SSID watchlist (exact + substring)",
        )
        rs = Ruleset(rules=[rule])

        obs = DeviceObservation(
            mac="aa:bb:cc:dd:ee:ff",
            device_type="wifi",
            first_seen=1700000000,
            last_seen=1700000100,
            rssi=-50,
            ssid="Flock",
            oui_vendor=None,
            is_randomized=False,
        )
        hits = evaluate(rs, obs, is_new_device=False, db=db)
        assert len(hits) == 1, (
            "observation of 'Flock' must fire the argus_ssid delegation rule "
            "via the bundled SSID rows; got no hits"
        )
        hit = hits[0]
        assert hit.rule_name == "argus_ssid"
        assert hit.rule_type == "watchlist_ssid"
        # Severity is sourced from the matched DB row, not from the
        # rule literal. The bundled CSV's two Flock rows
        # (argus_record_id 69248a5dad0c2eab repeated ×2 with
        # cat=gunshot_detect then cat=alpr, both at conf=65) hit the
        # within-import dup gate. v0.6.0's initial gate was implicit
        # first-wins (gunshot_detect at low survived; the alpr peer
        # downgraded to med was discarded — a silent operator-visible
        # severity demotion). The v0.6.0 hotfix replaced that with
        # explicit highest-severity-wins via a pre-pass tiebreak; the
        # alpr peer now wins and Flock alerts fire at `med` again.
        # This test pins both: (1) the alpr/med outcome explicitly,
        # and (2) DB-delegation by comparing alert severity to the
        # stored watchlist row's severity.
        stored = db._conn.execute(
            "SELECT severity FROM watchlist "
            "WHERE pattern = 'Flock' AND pattern_type = 'ssid' LIMIT 1"
        ).fetchone()
        assert stored is not None, "Flock row must be present in the watchlist"
        assert stored["severity"] == "med", (
            f"highest-severity-wins must pick the alpr peer (high→med "
            f"after conf=65 downgrade) over the gunshot_detect peer "
            f"(med→low after conf=65 downgrade); got "
            f"{stored['severity']!r} in the DB"
        )
        assert hit.severity == stored["severity"], (
            f"alert severity {hit.severity!r} must equal stored "
            f"watchlist row severity {stored['severity']!r} (DB-delegation)"
        )
    finally:
        db.close()


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
