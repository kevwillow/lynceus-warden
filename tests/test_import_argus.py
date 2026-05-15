"""Tests for the v0.3 lynceus-import-argus CLI."""

from __future__ import annotations

import csv
import io
from pathlib import Path

import pytest
import yaml

from lynceus.cli import import_argus
from lynceus.cli.import_argus import (
    DEFAULT_CONFIDENCE_DOWNGRADE_THRESHOLD,
    EXPECTED_HEADER,
    OverrideConfig,
    import_csv,
    load_override_config,
    main,
    parse_argus_csv,
    resolve_severity,
)
from lynceus.db import Database

META_LINE = "# meta: argus_export v3 (CP11)\n"


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "lynceus.db")


@pytest.fixture
def db(db_path):
    d = Database(db_path)
    yield d
    d.close()


def _write_csv(path: Path, rows: list[dict[str, str]], header: list[str] | None = None) -> str:
    header = header if header is not None else EXPECTED_HEADER
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(META_LINE)
        writer = csv.writer(f)
        writer.writerow(header)
        for row in rows:
            writer.writerow([row.get(c, "") for c in header])
    return str(path)


def _row(**kwargs) -> dict[str, str]:
    """Return a row dict with sensible defaults for required Argus columns."""
    base = {
        "argus_record_id": "argus-default",
        "id": "1",
        "identifier": "aa:bb:cc:dd:ee:ff",
        "identifier_type": "mac",
        "device_category": "alpr",
        "manufacturer": "Acme",
        "model": "",
        "confidence": "85",
        "source_type": "manufacturer_doc",
        "source_url": "https://example.com/doc",
        "source_excerpt": "excerpt",
        "geographic_scope": "us",
        "description": "test record",
        "first_seen": "2026-05-06 00:30:28",
        "last_verified": "2026-05-06 00:30:28",
        "notes": "",
    }
    base.update(kwargs)
    return base


def _wl_count(db: Database) -> int:
    return int(db._conn.execute("SELECT COUNT(*) FROM watchlist").fetchone()[0])


def _md_count(db: Database) -> int:
    return int(db._conn.execute("SELECT COUNT(*) FROM watchlist_metadata").fetchone()[0])


# ---------------------------------------------------------------------------
# Header validation and meta-line handling.
# ---------------------------------------------------------------------------


def test_valid_header_parses_cleanly(tmp_path):
    path = _write_csv(tmp_path / "good.csv", [_row(argus_record_id="x")])
    rows = parse_argus_csv(path)
    assert len(rows) == 1
    assert rows[0]["argus_record_id"] == "x"


def test_missing_column_rejected_with_clear_error(tmp_path):
    bad_header = [c for c in EXPECTED_HEADER if c != "confidence"]
    path = _write_csv(tmp_path / "bad.csv", [], header=bad_header)
    with pytest.raises(ValueError, match="confidence"):
        parse_argus_csv(path)


def test_extra_column_rejected_with_clear_error(tmp_path):
    bad_header = [*EXPECTED_HEADER, "extra_col"]
    path = _write_csv(tmp_path / "bad.csv", [], header=bad_header)
    with pytest.raises(ValueError, match="extra_col"):
        parse_argus_csv(path)


def test_wrong_order_rejected_with_clear_error(tmp_path):
    bad_header = list(EXPECTED_HEADER)
    bad_header[0], bad_header[1] = bad_header[1], bad_header[0]
    path = _write_csv(tmp_path / "bad.csv", [], header=bad_header)
    with pytest.raises(ValueError, match="order"):
        parse_argus_csv(path)


def test_meta_comment_line_skipped(tmp_path):
    path = _write_csv(tmp_path / "ok.csv", [_row(argus_record_id="x")])
    rows = parse_argus_csv(path)
    assert len(rows) == 1


def test_missing_meta_line_raises_clear_error(tmp_path):
    p = tmp_path / "no_meta.csv"
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(EXPECTED_HEADER)
    writer.writerow(["argus-x"] + ["x"] * (len(EXPECTED_HEADER) - 1))
    p.write_text(buf.getvalue(), encoding="utf-8")
    with pytest.raises(ValueError, match="# meta:"):
        parse_argus_csv(str(p))


# ---------------------------------------------------------------------------
# Identifier-type mapping.
# ---------------------------------------------------------------------------


def test_mac_identifier_type_imports_as_mac(tmp_path, db):
    path = _write_csv(
        tmp_path / "wl.csv",
        [_row(argus_record_id="m1", identifier_type="mac", identifier="aa:bb:cc:dd:ee:ff")],
    )
    import_csv(db, path, OverrideConfig())
    row = db._conn.execute("SELECT pattern_type FROM watchlist").fetchone()
    assert row["pattern_type"] == "mac"


def test_oui_identifier_type_imports_as_oui(tmp_path, db):
    path = _write_csv(
        tmp_path / "wl.csv",
        [_row(argus_record_id="o1", identifier_type="oui", identifier="aa:bb:cc")],
    )
    import_csv(db, path, OverrideConfig())
    row = db._conn.execute("SELECT pattern_type FROM watchlist").fetchone()
    assert row["pattern_type"] == "oui"


def test_ssid_exact_identifier_type_imports_as_ssid(tmp_path, db):
    path = _write_csv(
        tmp_path / "wl.csv",
        [_row(argus_record_id="s1", identifier_type="ssid_exact", identifier="VanWifi")],
    )
    import_csv(db, path, OverrideConfig())
    row = db._conn.execute("SELECT pattern_type FROM watchlist").fetchone()
    assert row["pattern_type"] == "ssid"


def test_ble_uuid_identifier_type_imports_as_ble_uuid(tmp_path, db):
    # Full 128-bit UUID — short forms are rejected by normalize_pattern
    # (L-RULES-1) since the poller only matches against the 128-bit
    # observation UUIDs from Kismet.
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(
                argus_record_id="b1",
                identifier_type="ble_uuid",
                identifier="0000fd5a-0000-1000-8000-00805f9b34fb",
            )
        ],
    )
    import_csv(db, path, OverrideConfig())
    row = db._conn.execute("SELECT pattern_type FROM watchlist").fetchone()
    assert row["pattern_type"] == "ble_uuid"


def test_ble_service_identifier_type_imports_as_ble_uuid(tmp_path, db):
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(
                argus_record_id="b2",
                identifier_type="ble_service",
                identifier="0000fd6f-0000-1000-8000-00805f9b34fb",
            )
        ],
    )
    import_csv(db, path, OverrideConfig())
    row = db._conn.execute("SELECT pattern_type FROM watchlist").fetchone()
    assert row["pattern_type"] == "ble_uuid"


def test_uppercase_identifier_type_normalized_to_lowercase_allowlist(tmp_path, db):
    """Argus may emit identifier_type as uppercase (``BLE_SERVICE``). The
    allowlist keys in ``IDENTIFIER_TYPE_MAP`` are lowercase, so without
    case-normalization the row silently lands in ``dropped_unknown_type``
    and the Argus metadata enrichment chain is lost — symmetrical with
    the 19aabf6 pattern-value normalization fix. Pre-fix this asserts
    ``imported_new == 1`` and fails (it would be ``dropped_unknown_type == 1``)."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(
                argus_record_id="b-upper-type",
                identifier_type="BLE_SERVICE",
                identifier="0000fd6f-0000-1000-8000-00805f9b34fb",
            )
        ],
    )
    report = import_csv(db, path, OverrideConfig())
    assert report.imported_new == 1
    assert report.dropped_unknown_type == 0
    row = db._conn.execute("SELECT pattern_type FROM watchlist").fetchone()
    assert row["pattern_type"] == "ble_uuid"


def test_mac_range_identifier_type_dropped_increments_counter(tmp_path, db):
    path = _write_csv(
        tmp_path / "wl.csv",
        [_row(argus_record_id="r1", identifier_type="mac_range")],
    )
    report = import_csv(db, path, OverrideConfig())
    assert report.dropped_mac_range == 1
    assert _wl_count(db) == 0
    assert _md_count(db) == 0


def test_unknown_identifier_type_dropped_increments_counter(tmp_path, db):
    path = _write_csv(
        tmp_path / "wl.csv",
        [_row(argus_record_id="u1", identifier_type="fcc_id")],
    )
    report = import_csv(db, path, OverrideConfig())
    assert report.dropped_unknown_type == 1
    assert _wl_count(db) == 0


# ---------------------------------------------------------------------------
# Drop-bucket per-row logging (audit-3).
# Counter-only drops left operators with no forensic trail; each drop
# now emits one INFO log line carrying argus_record_id, the raw
# identifier_type from the CSV (so it's grep-able), and a stable
# reason token (mac_range_unsupported / unknown_identifier_type).
# INFO not WARNING — expected drops per Argus §4.4, not anomalies.
# ---------------------------------------------------------------------------

import logging as _logging  # local alias for caplog tests below


def _drop_log_records(caplog, argus_record_id: str, reason: str) -> list:
    return [
        r
        for r in caplog.records
        if r.levelno == _logging.INFO
        and r.name == "lynceus.cli.import_argus"
        and argus_record_id in r.getMessage()
        and reason in r.getMessage()
    ]


def test_mac_range_drop_emits_info_log(tmp_path, db, caplog):
    path = _write_csv(
        tmp_path / "wl.csv",
        [_row(argus_record_id="mr-logged", identifier_type="mac_range")],
    )
    with caplog.at_level(_logging.INFO, logger="lynceus.cli.import_argus"):
        import_csv(db, path, OverrideConfig())
    matches = _drop_log_records(caplog, "mr-logged", "mac_range_unsupported")
    assert len(matches) == 1
    assert "'mac_range'" in matches[0].getMessage()  # identifier_type=%r


def test_ble_characteristic_drop_emits_info_log(tmp_path, db, caplog):
    """ble_characteristic is a known Argus type that Wave G may emit but
    Lynceus does not yet support; falls through to unknown_identifier_type."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [_row(argus_record_id="bc-logged", identifier_type="ble_characteristic")],
    )
    with caplog.at_level(_logging.INFO, logger="lynceus.cli.import_argus"):
        import_csv(db, path, OverrideConfig())
    matches = _drop_log_records(caplog, "bc-logged", "unknown_identifier_type")
    assert len(matches) == 1
    assert "'ble_characteristic'" in matches[0].getMessage()


def test_garbage_identifier_type_drop_emits_info_log(tmp_path, db, caplog):
    """Defensive case: a future Argus identifier_type Lynceus has never
    seen must produce a log line so operators can trace why imports
    shrunk after a Wave-X+N push."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [_row(argus_record_id="gt-logged", identifier_type="garbage_type_42")],
    )
    with caplog.at_level(_logging.INFO, logger="lynceus.cli.import_argus"):
        import_csv(db, path, OverrideConfig())
    matches = _drop_log_records(caplog, "gt-logged", "unknown_identifier_type")
    assert len(matches) == 1
    assert "'garbage_type_42'" in matches[0].getMessage()


def test_drop_log_preserves_raw_identifier_type_case(tmp_path, db, caplog):
    """audit-1 case-normalized identifier_type for the allowlist lookup,
    but the log must surface the RAW CSV value (case preserved) so an
    operator's `grep argus_export.csv` finds the source row."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [_row(argus_record_id="case-logged", identifier_type="GARBAGE_TYPE_42")],
    )
    with caplog.at_level(_logging.INFO, logger="lynceus.cli.import_argus"):
        import_csv(db, path, OverrideConfig())
    matches = _drop_log_records(caplog, "case-logged", "unknown_identifier_type")
    assert len(matches) == 1
    assert "'GARBAGE_TYPE_42'" in matches[0].getMessage()


def test_kept_row_emits_no_drop_log(tmp_path, db, caplog):
    """Guard: rows that successfully import must NOT emit a drop log line
    (catches the regression where someone accidentally logs every row)."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [_row(argus_record_id="kept", identifier_type="mac")],
    )
    with caplog.at_level(_logging.INFO, logger="lynceus.cli.import_argus"):
        import_csv(db, path, OverrideConfig())
    drop_messages = [
        r for r in caplog.records
        if "skipping row" in r.getMessage()
    ]
    assert drop_messages == []


# ---------------------------------------------------------------------------
# L-RULES-1: write-time pattern normalization.
# ---------------------------------------------------------------------------


def test_import_argus_normalizes_uppercase_mac_at_write(tmp_path, db):
    """Argus exports may carry uppercase MACs; the poller normalizes its
    observation MAC to lowercase before the watchlist equality lookup,
    so a row stored uppercase silently never links. THIS MUST FAIL
    PRE-FIX (the import would store the MAC verbatim)."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(
                argus_record_id="m-upper",
                identifier_type="mac",
                identifier="AA:BB:CC:DD:EE:FF",
            )
        ],
    )
    import_csv(db, path, OverrideConfig())
    row = db._conn.execute("SELECT pattern FROM watchlist").fetchone()
    assert row["pattern"] == "aa:bb:cc:dd:ee:ff"


def test_import_argus_normalizes_uppercase_ble_service(tmp_path, db):
    """The Wave G push will exercise the ``ble_service`` identifier_type
    specifically; ensure uppercase 128-bit UUIDs land in canonical
    lowercase hyphen-separated form."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(
                argus_record_id="b-upper",
                identifier_type="ble_service",
                identifier="0000FD6F-0000-1000-8000-00805F9B34FB",
            )
        ],
    )
    import_csv(db, path, OverrideConfig())
    row = db._conn.execute("SELECT pattern, pattern_type FROM watchlist").fetchone()
    assert row["pattern_type"] == "ble_uuid"
    assert row["pattern"] == "0000fd6f-0000-1000-8000-00805f9b34fb"


def test_import_argus_normalizes_dehyphenated_ble_service(tmp_path, db):
    """Dehyphenated 32-hex UUID inputs are reinserted with canonical
    hyphens; the poller's ``normalize_uuid`` produces hyphenated form."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(
                argus_record_id="b-flat",
                identifier_type="ble_service",
                identifier="0000fd6f00001000800000805f9b34fb",
            )
        ],
    )
    import_csv(db, path, OverrideConfig())
    row = db._conn.execute("SELECT pattern FROM watchlist").fetchone()
    assert row["pattern"] == "0000fd6f-0000-1000-8000-00805f9b34fb"


def test_import_argus_rejects_malformed_pattern_increments_counter(tmp_path, db):
    """A row with an identifier that cannot be normalized (here: 2-octet
    string declared as a full MAC) must be skipped without aborting the
    whole import, and surface as ``normalization_failed`` on the
    report — not as a generic ``errors`` bucket entry."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(
                argus_record_id="bad-mac",
                identifier_type="mac",
                identifier="AA:BB",
            ),
            _row(
                argus_record_id="good-mac",
                identifier_type="mac",
                identifier="aa:bb:cc:dd:ee:ff",
            ),
        ],
    )
    report = import_csv(db, path, OverrideConfig())
    assert report.normalization_failed == 1
    assert report.imported_new == 1  # the good row still landed
    assert report.errors == 0  # not surfaced as a generic error
    rows = db._conn.execute("SELECT pattern FROM watchlist ORDER BY id").fetchall()
    assert [r["pattern"] for r in rows] == ["aa:bb:cc:dd:ee:ff"]


def test_import_argus_render_includes_normalization_failed(tmp_path, db):
    """Operator-facing report must surface the new counter so silent
    drops are visible at the end of the import run."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(
                argus_record_id="bad-mac",
                identifier_type="mac",
                identifier="AA:BB",
            )
        ],
    )
    report = import_csv(db, path, OverrideConfig())
    rendered = report.render()
    assert "normalization_failed" in rendered
    assert "Dropped (normalization_failed): 1" in rendered


# ---------------------------------------------------------------------------
# Severity defaults — one per spec-defined category.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "category,expected",
    [
        ("imsi_catcher", "high"),
        ("alpr", "high"),
        ("body_cam", "med"),
        ("drone", "med"),
        ("gunshot_detect", "med"),
        ("hacking_tool", "high"),
        ("in_vehicle_router", "med"),
        ("unknown", "low"),
    ],
)
def test_default_severity_per_category(category, expected):
    sev = resolve_severity(
        manufacturer=None,
        device_category=category,
        confidence=99,
        overrides=OverrideConfig(),
    )
    assert sev == expected


def test_unrecognized_category_defaults_to_low():
    sev = resolve_severity(
        manufacturer=None,
        device_category="something_new_we_havent_seen",
        confidence=99,
        overrides=OverrideConfig(),
    )
    assert sev == "low"


# ---------------------------------------------------------------------------
# Override precedence.
# ---------------------------------------------------------------------------


def test_vendor_override_applied():
    sev = resolve_severity(
        manufacturer="VendorA",
        device_category="unknown",
        confidence=99,
        overrides=OverrideConfig(vendor_overrides={"VendorA": "high"}),
    )
    assert sev == "high"


def test_vendor_override_beats_category_override():
    sev = resolve_severity(
        manufacturer="VendorA",
        device_category="alpr",
        confidence=99,
        overrides=OverrideConfig(
            vendor_overrides={"VendorA": "low"},
            device_category_severity={"alpr": "med"},
        ),
    )
    assert sev == "low"


def test_category_override_beats_builtin_default():
    sev = resolve_severity(
        manufacturer=None,
        device_category="alpr",
        confidence=99,
        overrides=OverrideConfig(device_category_severity={"alpr": "low"}),
    )
    assert sev == "low"


# ---------------------------------------------------------------------------
# severity = "drop".
# ---------------------------------------------------------------------------


def test_severity_drop_skips_record_and_increments_counter(tmp_path, db):
    path = _write_csv(
        tmp_path / "wl.csv",
        [_row(argus_record_id="d1", manufacturer="Skipme")],
    )
    overrides = OverrideConfig(vendor_overrides={"Skipme": "drop"})
    report = import_csv(db, path, overrides)
    assert report.dropped_severity_drop == 1
    assert _wl_count(db) == 0


# ---------------------------------------------------------------------------
# Confidence downgrade.
# ---------------------------------------------------------------------------


def test_confidence_below_threshold_downgrades_high_to_med():
    sev = resolve_severity(
        manufacturer=None,
        device_category="alpr",
        confidence=50,
        overrides=OverrideConfig(),
    )
    assert sev == "med"


def test_confidence_below_threshold_downgrades_med_to_low():
    sev = resolve_severity(
        manufacturer=None,
        device_category="drone",
        confidence=50,
        overrides=OverrideConfig(),
    )
    assert sev == "low"


def test_confidence_below_threshold_low_floors_at_low():
    sev = resolve_severity(
        manufacturer=None,
        device_category="unknown",
        confidence=10,
        overrides=OverrideConfig(),
    )
    assert sev == "low"


def test_confidence_at_threshold_does_not_downgrade():
    sev = resolve_severity(
        manufacturer=None,
        device_category="alpr",
        confidence=DEFAULT_CONFIDENCE_DOWNGRADE_THRESHOLD,
        overrides=OverrideConfig(),
    )
    assert sev == "high"


def test_confidence_threshold_zero_disables_downgrade():
    sev = resolve_severity(
        manufacturer=None,
        device_category="alpr",
        confidence=10,
        overrides=OverrideConfig(confidence_downgrade_threshold=0),
    )
    assert sev == "high"


# ---------------------------------------------------------------------------
# --min-confidence row-skip (audit-2).
# Distinct from confidence_downgrade_threshold above: --min-confidence hard
# skips the row pre-DB; the threshold downgrades severity but imports.
# ---------------------------------------------------------------------------


def test_min_confidence_below_threshold_row_skipped(tmp_path, db):
    """confidence=79 with min_confidence=80 → skipped, counted in
    dropped_low_confidence, no DB write."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [_row(argus_record_id="lc1", confidence="79")],
    )
    report = import_csv(db, path, OverrideConfig(), min_confidence=80)
    assert report.dropped_low_confidence == 1
    assert report.imported_new == 0
    assert _wl_count(db) == 0
    assert _md_count(db) == 0


def test_min_confidence_at_threshold_row_kept(tmp_path, db):
    """confidence=80 with min_confidence=80 → kept (boundary is inclusive)."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [_row(argus_record_id="lc2", confidence="80")],
    )
    report = import_csv(db, path, OverrideConfig(), min_confidence=80)
    assert report.dropped_low_confidence == 0
    assert report.imported_new == 1
    assert _wl_count(db) == 1


def test_min_confidence_above_threshold_row_kept(tmp_path, db):
    """confidence=81 with min_confidence=80 → kept."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [_row(argus_record_id="lc3", confidence="81")],
    )
    report = import_csv(db, path, OverrideConfig(), min_confidence=80)
    assert report.dropped_low_confidence == 0
    assert report.imported_new == 1


def test_min_confidence_unset_imports_all_confidences(tmp_path, db):
    """Default behavior (no --min-confidence) must not skip any row;
    guards against accidental "always-on" filtering regressions."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(argus_record_id="u1", identifier="aa:bb:cc:dd:ee:01", confidence="10"),
            _row(argus_record_id="u2", identifier="aa:bb:cc:dd:ee:02", confidence="99"),
        ],
    )
    report = import_csv(db, path, OverrideConfig())
    assert report.dropped_low_confidence == 0
    assert report.imported_new == 2


def test_min_confidence_does_not_downgrade_kept_severity(tmp_path, db):
    """A row at min_confidence=80 with default downgrade threshold=70 is
    NOT downgraded — confirms --min-confidence and confidence_downgrade_threshold
    operate independently (kept row's severity should reflect the downgrade
    rule alone, here: confidence=80 ≥ 70 so no downgrade)."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [_row(argus_record_id="lc4", confidence="80", device_category="alpr")],
    )
    import_csv(db, path, OverrideConfig(), min_confidence=80)
    row = db._conn.execute("SELECT severity FROM watchlist").fetchone()
    assert row["severity"] == "high"


def test_min_confidence_cli_flag_threads_through_to_importer(tmp_path, db_path, capsys):
    """End-to-end argparse plumbing: --min-confidence on the CLI must reach
    import_csv as the keyword arg. Pre-fix this raises SystemExit at
    parse_args time because the flag does not exist."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(argus_record_id="cli-a", identifier="aa:bb:cc:dd:ee:01", confidence="50"),
            _row(argus_record_id="cli-b", identifier="aa:bb:cc:dd:ee:02", confidence="90"),
        ],
    )
    rc = main(
        [
            "--db",
            db_path,
            "--input",
            path,
            "--override-file",
            str(tmp_path / "missing.yaml"),
            "--min-confidence",
            "80",
        ]
    )
    assert rc == 0
    captured = capsys.readouterr()
    assert "Dropped (low_confidence): 1" in captured.out
    assert "Imported (new): 1" in captured.out


def test_min_confidence_skip_logs_argus_record_id_and_confidence(tmp_path, db, caplog):
    """Per-row INFO log line on each skip must include argus_record_id and
    confidence so operators can debug ambiguous post-import counts."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [_row(argus_record_id="lc-logged", confidence="42")],
    )
    import logging as _logging

    with caplog.at_level(_logging.INFO, logger="lynceus.cli.import_argus"):
        import_csv(db, path, OverrideConfig(), min_confidence=80)
    assert any("lc-logged" in r.message and "42" in r.message for r in caplog.records)


def test_min_confidence_render_includes_counter(tmp_path, db):
    """Operator-facing summary must surface dropped_low_confidence on
    both the per-bucket line and the trailing summary line."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [_row(argus_record_id="lc-render", confidence="10")],
    )
    report = import_csv(db, path, OverrideConfig(), min_confidence=80)
    text = report.render()
    assert "Dropped (low_confidence): 1" in text
    assert "1 low_confidence" in text


# ---------------------------------------------------------------------------
# Geographic filter.
# ---------------------------------------------------------------------------


def test_geographic_filter_matching_scope_passes(tmp_path, db):
    path = _write_csv(
        tmp_path / "wl.csv",
        [_row(argus_record_id="g1", geographic_scope="us")],
    )
    report = import_csv(db, path, OverrideConfig(geographic_filter=["us", "eu"]))
    assert report.imported_new == 1
    assert report.dropped_geographic_filter == 0


def test_geographic_filter_non_matching_scope_dropped(tmp_path, db):
    path = _write_csv(
        tmp_path / "wl.csv",
        [_row(argus_record_id="g2", geographic_scope="apac")],
    )
    report = import_csv(db, path, OverrideConfig(geographic_filter=["us"]))
    assert report.dropped_geographic_filter == 1
    assert _wl_count(db) == 0


def test_geographic_filter_global_scope_always_passes(tmp_path, db):
    path = _write_csv(
        tmp_path / "wl.csv",
        [_row(argus_record_id="g3", geographic_scope="global")],
    )
    report = import_csv(db, path, OverrideConfig(geographic_filter=["us"]))
    assert report.imported_new == 1


def test_geographic_filter_empty_scope_dropped_when_filter_set(tmp_path, db):
    path = _write_csv(
        tmp_path / "wl.csv",
        [_row(argus_record_id="g4", geographic_scope="")],
    )
    report = import_csv(db, path, OverrideConfig(geographic_filter=["us"]))
    assert report.dropped_geographic_filter == 1


def test_geographic_filter_unset_imports_all_scopes(tmp_path, db):
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(argus_record_id="g5a", geographic_scope="apac"),
            _row(argus_record_id="g5b", geographic_scope=""),
            _row(argus_record_id="g5c", geographic_scope="global"),
        ],
    )
    report = import_csv(db, path, OverrideConfig())
    assert report.imported_new == 3
    assert report.dropped_geographic_filter == 0


# ---------------------------------------------------------------------------
# Date parsing.
# ---------------------------------------------------------------------------


def test_first_seen_parsed_to_unix_epoch(tmp_path, db):
    path = _write_csv(
        tmp_path / "wl.csv",
        [_row(argus_record_id="d1", first_seen="2026-05-06 00:30:28")],
    )
    import_csv(db, path, OverrideConfig())
    row = db._conn.execute("SELECT first_seen FROM watchlist_metadata").fetchone()
    # 2026-05-06 00:30:28 UTC -> deterministic epoch
    import datetime as _dt

    expected = int(_dt.datetime(2026, 5, 6, 0, 30, 28, tzinfo=_dt.UTC).timestamp())
    assert row["first_seen"] == expected


def test_empty_date_stored_as_null(tmp_path, db):
    path = _write_csv(
        tmp_path / "wl.csv",
        [_row(argus_record_id="d2", first_seen="", last_verified="")],
    )
    import_csv(db, path, OverrideConfig())
    row = db._conn.execute("SELECT first_seen, last_verified FROM watchlist_metadata").fetchone()
    assert row["first_seen"] is None
    assert row["last_verified"] is None


def test_malformed_date_logged_as_row_error(tmp_path, db):
    path = _write_csv(
        tmp_path / "wl.csv",
        [_row(argus_record_id="d3", first_seen="not-a-date")],
    )
    report = import_csv(db, path, OverrideConfig())
    assert report.errors == 1
    assert any("not-a-date" in msg or "first_seen" in msg for msg in report.error_log)
    assert _wl_count(db) == 0


# ---------------------------------------------------------------------------
# `_parse_date` multi-format tolerance.
#
# Argus codified canonical emission as ISO-8601 UTC `Z` form at seconds
# precision on 2026-05-14 (CP22). Archived exports may predate that and
# carry any of: ISO with offset, space-separated, or date-only. Lynceus
# tolerates all four for backward compat.
# ---------------------------------------------------------------------------


def test_parse_date_iso_with_z(tmp_path, db):
    """Canonical Argus emission shape — must parse cleanly."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [_row(argus_record_id="dz", first_seen="2026-05-11T18:21:50Z")],
    )
    report = import_csv(db, path, OverrideConfig())
    assert report.errors == 0
    assert report.imported_new == 1
    row = db._conn.execute("SELECT first_seen FROM watchlist_metadata").fetchone()
    import datetime as _dt

    expected = int(_dt.datetime(2026, 5, 11, 18, 21, 50, tzinfo=_dt.UTC).timestamp())
    assert row["first_seen"] == expected


def test_parse_date_iso_with_microseconds_offset(tmp_path, db):
    """Pre-canonicalization dominant shape (~99% of pre-CP22 last_verified rows)."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [_row(argus_record_id="dm", first_seen="2026-05-14T06:13:42.204792+00:00")],
    )
    report = import_csv(db, path, OverrideConfig())
    assert report.errors == 0
    assert report.imported_new == 1
    row = db._conn.execute("SELECT first_seen FROM watchlist_metadata").fetchone()
    import datetime as _dt

    expected = int(
        _dt.datetime(2026, 5, 14, 6, 13, 42, 204792, tzinfo=_dt.UTC).timestamp()
    )
    assert row["first_seen"] == expected


def test_parse_date_iso_with_nonzero_offset_coerces_to_utc(tmp_path, db):
    """Non-zero offset: 2026-05-14T08:13:42-04:00 → 2026-05-14T12:13:42 UTC."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [_row(argus_record_id="do", first_seen="2026-05-14T08:13:42-04:00")],
    )
    report = import_csv(db, path, OverrideConfig())
    assert report.errors == 0
    row = db._conn.execute("SELECT first_seen FROM watchlist_metadata").fetchone()
    import datetime as _dt

    expected = int(_dt.datetime(2026, 5, 14, 12, 13, 42, tzinfo=_dt.UTC).timestamp())
    assert row["first_seen"] == expected


def test_parse_date_date_only_emits_midnight_utc(tmp_path, db):
    """Date-only row preserves only day signal; treat as midnight UTC."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [_row(argus_record_id="dd", first_seen="2026-05-10")],
    )
    report = import_csv(db, path, OverrideConfig())
    assert report.errors == 0
    row = db._conn.execute("SELECT first_seen FROM watchlist_metadata").fetchone()
    import datetime as _dt

    expected = int(_dt.datetime(2026, 5, 10, 0, 0, 0, tzinfo=_dt.UTC).timestamp())
    assert row["first_seen"] == expected


def test_parse_date_space_separated_still_works(tmp_path, db):
    """Backward compat: archived pre-CP22 Argus exports."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [_row(argus_record_id="ds", first_seen="2026-05-06 00:30:28")],
    )
    report = import_csv(db, path, OverrideConfig())
    assert report.errors == 0
    row = db._conn.execute("SELECT first_seen FROM watchlist_metadata").fetchone()
    import datetime as _dt

    expected = int(_dt.datetime(2026, 5, 6, 0, 30, 28, tzinfo=_dt.UTC).timestamp())
    assert row["first_seen"] == expected


# ---------------------------------------------------------------------------
# Empty optional fields and confidence validation.
# ---------------------------------------------------------------------------


def test_empty_optional_fields_become_null_in_metadata(tmp_path, db):
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(
                argus_record_id="e1",
                source_url="",
                source_excerpt="",
                notes="",
            )
        ],
    )
    import_csv(db, path, OverrideConfig())
    row = db._conn.execute(
        "SELECT source_url, source_excerpt, notes FROM watchlist_metadata"
    ).fetchone()
    assert row["source_url"] is None
    assert row["source_excerpt"] is None
    assert row["notes"] is None


def test_empty_confidence_logged_as_row_error(tmp_path, db):
    path = _write_csv(
        tmp_path / "wl.csv",
        [_row(argus_record_id="c1", confidence="")],
    )
    report = import_csv(db, path, OverrideConfig())
    assert report.errors == 1
    assert any("confidence" in msg for msg in report.error_log)


def test_non_int_confidence_logged_as_row_error(tmp_path, db):
    path = _write_csv(
        tmp_path / "wl.csv",
        [_row(argus_record_id="c2", confidence="high")],
    )
    report = import_csv(db, path, OverrideConfig())
    assert report.errors == 1
    assert any("confidence" in msg for msg in report.error_log)


# ---------------------------------------------------------------------------
# Idempotency and update behavior.
# ---------------------------------------------------------------------------


def test_reimport_same_csv_reports_zero_new_zero_updated_n_unchanged(tmp_path, db):
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(argus_record_id="i1", identifier="aa:bb:cc:dd:ee:01"),
            _row(argus_record_id="i2", identifier="aa:bb:cc:dd:ee:02"),
        ],
    )
    r1 = import_csv(db, path, OverrideConfig())
    assert r1.imported_new == 2

    r2 = import_csv(db, path, OverrideConfig())
    assert r2.imported_new == 0
    assert r2.updated == 0
    assert r2.unchanged == 2
    assert _wl_count(db) == 2
    assert _md_count(db) == 2


def test_reimport_unchanged_does_not_refresh_updated_at(tmp_path, db):
    path = _write_csv(
        tmp_path / "wl.csv",
        [_row(argus_record_id="i1")],
    )
    import_csv(db, path, OverrideConfig())
    first = db.get_metadata_by_argus_record_id("i1")
    import_csv(db, path, OverrideConfig())
    second = db.get_metadata_by_argus_record_id("i1")
    assert first["updated_at"] == second["updated_at"]
    assert first["created_at"] == second["created_at"]


def test_reimport_changed_confidence_updates_and_refreshes_updated_at(tmp_path, db, monkeypatch):
    times = iter([1_700_000_000, 1_700_000_500])
    monkeypatch.setattr("lynceus.db.time.time", lambda: next(times))

    path1 = _write_csv(
        tmp_path / "wl1.csv",
        [_row(argus_record_id="i1", confidence="95")],
    )
    import_csv(db, path1, OverrideConfig())
    first = db.get_metadata_by_argus_record_id("i1")

    path2 = _write_csv(
        tmp_path / "wl2.csv",
        [_row(argus_record_id="i1", confidence="80")],
    )
    report = import_csv(db, path2, OverrideConfig())
    second = db.get_metadata_by_argus_record_id("i1")

    assert report.updated == 1
    assert second["confidence"] == 80
    assert second["created_at"] == first["created_at"]
    assert second["updated_at"] > first["updated_at"]


def test_reimport_changed_description_updates_watchlist_row(tmp_path, db):
    path1 = _write_csv(
        tmp_path / "wl1.csv",
        [_row(argus_record_id="i1", description="original")],
    )
    import_csv(db, path1, OverrideConfig())

    path2 = _write_csv(
        tmp_path / "wl2.csv",
        [_row(argus_record_id="i1", description="updated text")],
    )
    report = import_csv(db, path2, OverrideConfig())
    assert report.updated == 1
    row = db._conn.execute("SELECT description FROM watchlist").fetchone()
    assert row["description"] == "updated text"


def test_reimport_changed_severity_updates_watchlist_row(tmp_path, db):
    path = _write_csv(
        tmp_path / "wl.csv",
        [_row(argus_record_id="i1", device_category="alpr")],
    )
    import_csv(db, path, OverrideConfig())
    row = db._conn.execute("SELECT severity FROM watchlist").fetchone()
    assert row["severity"] == "high"

    overrides = OverrideConfig(device_category_severity={"alpr": "low"})
    report = import_csv(db, path, overrides)
    assert report.updated == 1
    row = db._conn.execute("SELECT severity FROM watchlist").fetchone()
    assert row["severity"] == "low"


def test_argus_record_id_is_upsert_key_even_if_identifier_changes(tmp_path, db):
    path1 = _write_csv(
        tmp_path / "wl1.csv",
        [_row(argus_record_id="i1", identifier="aa:bb:cc:dd:ee:01")],
    )
    import_csv(db, path1, OverrideConfig())
    assert _md_count(db) == 1

    path2 = _write_csv(
        tmp_path / "wl2.csv",
        [_row(argus_record_id="i1", identifier="ff:ee:dd:cc:bb:aa")],
    )
    report = import_csv(db, path2, OverrideConfig())
    assert _md_count(db) == 1
    md = db.get_metadata_by_argus_record_id("i1")
    assert md is not None
    assert report.imported_new == 0


# ---------------------------------------------------------------------------
# Backward compatibility with seed-watchlist YAML.
# ---------------------------------------------------------------------------


def test_yaml_seed_and_argus_import_coexist(tmp_path, db):
    from lynceus.cli.seed_watchlist import seed_from_yaml

    yaml_path = tmp_path / "seed.yaml"
    yaml_path.write_text(
        yaml.safe_dump(
            {
                "entries": [
                    {
                        "pattern": "11:22:33:44:55:66",
                        "pattern_type": "mac",
                        "severity": "high",
                        "description": "yaml-seeded",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    seed_from_yaml(db, str(yaml_path))
    assert _wl_count(db) == 1

    csv_path = _write_csv(
        tmp_path / "wl.csv",
        [_row(argus_record_id="argus1", identifier="aa:bb:cc:dd:ee:01")],
    )
    report = import_csv(db, csv_path, OverrideConfig())
    assert report.imported_new == 1
    assert _wl_count(db) == 2
    assert _md_count(db) == 1


# ---------------------------------------------------------------------------
# CLI / main() — dry-run, override-file resolution, report output.
# ---------------------------------------------------------------------------


def test_dry_run_writes_nothing_to_db(tmp_path, db_path, capsys):
    path = _write_csv(
        tmp_path / "wl.csv",
        [_row(argus_record_id="d1", identifier="aa:bb:cc:dd:ee:01")],
    )
    rc = main(
        [
            "--db",
            db_path,
            "--input",
            path,
            "--override-file",
            str(tmp_path / "missing.yaml"),
            "--dry-run",
        ]
    )
    assert rc == 0
    captured = capsys.readouterr()
    assert "[DRY RUN]" in captured.out
    assert "Imported (new): 1" in captured.out

    db = Database(db_path)
    try:
        assert _wl_count(db) == 0
        assert _md_count(db) == 0
    finally:
        db.close()


def test_override_file_missing_falls_back_to_defaults(tmp_path, db):
    cfg = load_override_config(str(tmp_path / "does-not-exist.yaml"))
    assert cfg.vendor_overrides == {}
    assert cfg.device_category_severity == {}
    assert cfg.geographic_filter == []
    assert cfg.confidence_downgrade_threshold == DEFAULT_CONFIDENCE_DOWNGRADE_THRESHOLD


def test_override_file_loads_yaml_contents(tmp_path):
    p = tmp_path / "overrides.yaml"
    p.write_text(
        yaml.safe_dump(
            {
                "vendor_overrides": {"VendorA": "drop"},
                "device_category_severity": {"alpr": "low"},
                "geographic_filter": ["us"],
                "confidence_downgrade_threshold": 50,
            }
        ),
        encoding="utf-8",
    )
    cfg = load_override_config(str(p))
    assert cfg.vendor_overrides == {"VendorA": "drop"}
    assert cfg.device_category_severity == {"alpr": "low"}
    assert cfg.geographic_filter == ["us"]
    assert cfg.confidence_downgrade_threshold == 50


def test_main_returns_zero_on_success(tmp_path, db_path, capsys):
    path = _write_csv(
        tmp_path / "wl.csv",
        [_row(argus_record_id="m1")],
    )
    rc = main(
        [
            "--db",
            db_path,
            "--input",
            path,
            "--override-file",
            str(tmp_path / "missing.yaml"),
        ]
    )
    assert rc == 0
    captured = capsys.readouterr()
    assert "Total rows in CSV: 1" in captured.out
    assert "imported 1 records" in captured.out


def test_main_exposed_as_entry_point():
    # Make sure the module exports a `main` callable for console_scripts.
    assert callable(import_argus.main)


# ---------------------------------------------------------------------------
# --from-github fetch flow.
# ---------------------------------------------------------------------------


def test_resolve_ref_returns_explicit_ref_without_api_call(monkeypatch):
    """If the operator passed --ref X, _resolve_ref must return X
    verbatim and never touch the network. The latest-release lookup is
    only for the default-ref path."""

    def _no_network_get(*args, **kwargs):
        raise AssertionError(f"requests.get must not be called, got {args!r}")

    monkeypatch.setattr(import_argus.requests, "get", _no_network_get)
    assert import_argus._resolve_ref("kevwillow/argus-db", "v1.2.3") == "v1.2.3"
    assert import_argus._resolve_ref("kevwillow/argus-db", "main") == "main"


def test_resolve_ref_queries_releases_latest_when_ref_is_none(monkeypatch):
    """Default --ref behavior: hit /releases/latest and return tag_name.
    NOT the tip of main — see the docstring rationale."""
    captured = {}

    class _FakeResp:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return {"tag_name": "v0.9.7", "name": "Argus v0.9.7"}

    def _fake_get(url, timeout=None):
        captured["url"] = url
        captured["timeout"] = timeout
        return _FakeResp()

    monkeypatch.setattr(import_argus.requests, "get", _fake_get)
    tag = import_argus._resolve_ref("kevwillow/argus-db", None)
    assert tag == "v0.9.7"
    assert captured["url"] == "https://api.github.com/repos/kevwillow/argus-db/releases/latest"
    # Sanity: timeout must be set so a hung GitHub request can't wedge
    # the CLI indefinitely.
    assert captured["timeout"] is not None and captured["timeout"] > 0


def test_resolve_ref_raises_when_payload_lacks_tag_name(monkeypatch):
    """A 200 from GitHub with no tag_name (unusual, but not impossible
    on a freshly-created repo with no releases) must surface as a
    RuntimeError naming the repo, not a silent KeyError."""

    class _FakeResp:
        def raise_for_status(self):
            return None

        def json(self):
            return {"name": "no-tag-here"}

    monkeypatch.setattr(import_argus.requests, "get", lambda *a, **kw: _FakeResp())
    with pytest.raises(RuntimeError, match="kevwillow/argus-db"):
        import_argus._resolve_ref("kevwillow/argus-db", None)


def test_fetch_argus_export_writes_cache_file_with_resolved_ref(tmp_path, monkeypatch):
    """fetch_argus_export must call raw.githubusercontent.com at the
    resolved ref/path, write the bytes into cache_dir, and return the
    cache path. The filename embeds the ref so multiple pulled artifacts
    coexist."""
    payload = b"# meta: argus_export v3 (test)\nheader,row\n"

    class _FakeResp:
        content = payload

        def raise_for_status(self):
            return None

    captured = {}

    def _fake_get(url, timeout=None):
        captured["url"] = url
        captured["timeout"] = timeout
        return _FakeResp()

    monkeypatch.setattr(import_argus.requests, "get", _fake_get)
    cache = tmp_path / "argus-cache"
    out = import_argus.fetch_argus_export("kevwillow/argus-db", "v1.2.3", cache)
    assert out == cache / "v1.2.3__argus_export.csv"
    assert out.read_bytes() == payload
    # raw.githubusercontent.com URL with the resolved ref + the
    # repo-internal export path.
    assert captured["url"] == (
        "https://raw.githubusercontent.com/kevwillow/argus-db/v1.2.3/"
        "exports/argus_export.csv"
    )
    assert captured["timeout"] is not None and captured["timeout"] > 0


def test_fetch_argus_export_sanitizes_slash_in_ref(tmp_path, monkeypatch):
    """A ref like 'release/v1.2' must not escape the cache_dir into a
    subdirectory the test never mkdir'd. Sanitize the slash."""

    class _FakeResp:
        content = b"x"

        def raise_for_status(self):
            return None

    monkeypatch.setattr(import_argus.requests, "get", lambda *a, **kw: _FakeResp())
    cache = tmp_path / "argus-cache"
    out = import_argus.fetch_argus_export("kevwillow/argus-db", "release/v1.2", cache)
    # Filename has the slash collapsed; no surprise subdirectory created.
    assert out.parent == cache
    assert "release_v1.2" in out.name


def test_main_from_github_and_input_are_mutually_exclusive(tmp_path, db_path):
    """Passing both --from-github and --input must error. argparse parse
    errors raise SystemExit(2) — that's the contract."""
    path = _write_csv(tmp_path / "wl.csv", [_row(argus_record_id="x")])
    with pytest.raises(SystemExit) as excinfo:
        main(["--db", db_path, "--input", path, "--from-github"])
    assert excinfo.value.code == 2


def test_main_neither_input_nor_from_github_is_error(db_path):
    """Pre-change --input was required; the new dispatch must keep that
    strictness — passing neither flag is a parse error, not a silent
    no-op."""
    with pytest.raises(SystemExit) as excinfo:
        main(["--db", db_path])
    assert excinfo.value.code == 2


def test_main_ref_without_from_github_is_error(tmp_path, db_path):
    """--ref only makes sense when fetching; passing it alongside
    --input is a config bug worth surfacing rather than silently
    ignoring."""
    path = _write_csv(tmp_path / "wl.csv", [_row(argus_record_id="r1")])
    with pytest.raises(SystemExit) as excinfo:
        main(["--db", db_path, "--input", path, "--ref", "main"])
    assert excinfo.value.code == 2


def test_main_from_github_invokes_fetch_and_imports(tmp_path, db_path, monkeypatch, capsys):
    """End-to-end: --from-github must call fetch_argus_export with the
    parsed --repo / --ref, then run the existing import on the returned
    file. We stub fetch_argus_export to point at a local fixture so the
    test stays offline."""
    fixture = _write_csv(
        tmp_path / "fetched.csv",
        [_row(argus_record_id="gh-1", identifier="aa:bb:cc:dd:ee:01")],
    )
    captured = {}

    def _fake_fetch(repo, ref, cache_dir):
        captured["repo"] = repo
        captured["ref"] = ref
        captured["cache_dir"] = cache_dir
        return Path(fixture)

    monkeypatch.setattr(import_argus, "fetch_argus_export", _fake_fetch)
    rc = main(
        [
            "--db",
            db_path,
            "--from-github",
            "--repo",
            "someone/argus-fork",
            "--ref",
            "v9.9.9",
            "--override-file",
            str(tmp_path / "missing.yaml"),
        ]
    )
    assert rc == 0
    assert captured["repo"] == "someone/argus-fork"
    assert captured["ref"] == "v9.9.9"
    # Cache path lives under data_dir/argus-cache. We can't pin the
    # exact path without spoofing scope -> data_dir, so just assert the
    # tail.
    assert captured["cache_dir"].name == "argus-cache"
    out = capsys.readouterr().out
    assert "Imported (new): 1" in out


# ---------------------------------------------------------------------------
# Default --db resolution against paths.default_db_path.
# ---------------------------------------------------------------------------


def test_main_default_db_resolves_to_user_default(tmp_path, monkeypatch, capsys):
    """When --db is omitted, the importer must write to
    paths.default_db_path(--scope). Spoofing the helper proves the
    plumbing without reaching the actual XDG dir."""
    spoofed_db = tmp_path / "spoofed-user.db"
    captured = {}

    def _fake_default_db_path(scope):
        captured["scope"] = scope
        return spoofed_db

    monkeypatch.setattr(import_argus.paths, "default_db_path", _fake_default_db_path)

    csv_path = _write_csv(tmp_path / "wl.csv", [_row(argus_record_id="def-u")])
    rc = main(
        [
            "--input",
            csv_path,
            "--scope",
            "user",
            "--override-file",
            str(tmp_path / "missing.yaml"),
        ]
    )
    assert rc == 0
    assert captured["scope"] == "user"
    # The DB file should now exist at the spoofed path.
    assert spoofed_db.exists()


def test_main_default_db_resolves_to_system_default(tmp_path, monkeypatch):
    """Same as the user case but for --scope system, which on macOS /
    Windows would otherwise raise NotImplementedError. We monkeypatch
    so the assertion holds cross-platform."""
    spoofed_db = tmp_path / "spoofed-system.db"
    captured = {}

    def _fake_default_db_path(scope):
        captured["scope"] = scope
        return spoofed_db

    monkeypatch.setattr(import_argus.paths, "default_db_path", _fake_default_db_path)

    csv_path = _write_csv(tmp_path / "wl.csv", [_row(argus_record_id="def-s")])
    rc = main(
        [
            "--input",
            csv_path,
            "--scope",
            "system",
            "--override-file",
            str(tmp_path / "missing.yaml"),
        ]
    )
    assert rc == 0
    assert captured["scope"] == "system"
    assert spoofed_db.exists()


def test_main_explicit_db_does_not_invoke_default_helper(tmp_path, monkeypatch):
    """When --db is given, paths.default_db_path must not be called
    (avoids surprising NotImplementedError on macOS --scope=system
    when the operator isn't even relying on the default)."""

    def _explode(scope):
        raise AssertionError(
            f"paths.default_db_path should not be called when --db is given (scope={scope})"
        )

    monkeypatch.setattr(import_argus.paths, "default_db_path", _explode)
    explicit_db = tmp_path / "explicit.db"
    csv_path = _write_csv(tmp_path / "wl.csv", [_row(argus_record_id="e1")])
    rc = main(
        [
            "--db",
            str(explicit_db),
            "--input",
            csv_path,
            "--override-file",
            str(tmp_path / "missing.yaml"),
        ]
    )
    assert rc == 0
    assert explicit_db.exists()


# ---------------------------------------------------------------------------
# End-to-end smoke: heterogeneous fixture exercising every branch.
# ---------------------------------------------------------------------------


def _e2e_rows() -> list[dict[str, str]]:
    """Build a fixture covering every code path the importer cares about."""
    return [
        # 5 keepers spanning all five identifier types and every default severity tier.
        _row(
            argus_record_id="k1",
            identifier_type="mac",
            identifier="aa:bb:cc:dd:ee:01",
            device_category="alpr",
            confidence="90",
            geographic_scope="us",
        ),
        _row(
            argus_record_id="k2",
            identifier_type="oui",
            identifier="aa:bb:cc",
            device_category="drone",
            confidence="90",
            geographic_scope="global",
        ),
        _row(
            argus_record_id="k3",
            identifier_type="ssid_exact",
            identifier="VanWifi-Foo",
            device_category="hacking_tool",
            confidence="90",
            geographic_scope="us",
        ),
        _row(
            argus_record_id="k4",
            identifier_type="ble_uuid",
            # Full 128-bit UUID — short forms are rejected by L-RULES-1
            # normalization (Kismet observations carry the full 128-bit
            # form so a short pattern would never match anyway).
            identifier="0000fd5a-0000-1000-8000-00805f9b34fb",
            device_category="body_cam",
            confidence="90",
            geographic_scope="",
        ),
        _row(
            argus_record_id="k5",
            identifier_type="ble_service",
            identifier="0000fd6f-0000-1000-8000-00805f9b34fb",
            device_category="unknown",
            confidence="90",
            geographic_scope="us",
        ),
        # Drops:
        _row(argus_record_id="d1", identifier_type="mac_range", identifier="aa:bb:cc:dd:00:00"),
        _row(argus_record_id="d2", identifier_type="mac_range", identifier="11:22:33:44:00:00"),
        _row(argus_record_id="u1", identifier_type="fcc_id", identifier="A2B-XYZ123"),
        # Downgrade target: high default for alpr but low confidence -> med.
        _row(
            argus_record_id="g1",
            identifier_type="mac",
            identifier="aa:bb:cc:dd:ee:91",
            device_category="alpr",
            confidence="50",
        ),
    ]


def test_end_to_end_smoke_counts_match(tmp_path, db):
    path = _write_csv(tmp_path / "wl.csv", _e2e_rows())
    report = import_csv(db, path, OverrideConfig())
    assert report.total_rows == 9
    assert report.imported_new == 6
    assert report.dropped_mac_range == 2
    assert report.dropped_unknown_type == 1
    assert report.dropped_geographic_filter == 0
    assert report.dropped_severity_drop == 0
    assert report.errors == 0
    assert _wl_count(db) == 6
    assert _md_count(db) == 6


def test_end_to_end_smoke_severity_tiers_correct(tmp_path, db):
    path = _write_csv(tmp_path / "wl.csv", _e2e_rows())
    import_csv(db, path, OverrideConfig())
    rows = {
        r["argus_record_id"]: r["severity"]
        for r in db._conn.execute(
            "SELECT m.argus_record_id, w.severity "
            "FROM watchlist_metadata m JOIN watchlist w ON w.id = m.watchlist_id"
        ).fetchall()
    }
    assert rows["k1"] == "high"  # alpr
    assert rows["k2"] == "med"  # drone
    assert rows["k3"] == "high"  # hacking_tool
    assert rows["k4"] == "med"  # body_cam
    assert rows["k5"] == "low"  # unknown
    assert rows["g1"] == "med"  # alpr (high) downgraded by confidence=50


def test_end_to_end_smoke_idempotent(tmp_path, db):
    path = _write_csv(tmp_path / "wl.csv", _e2e_rows())
    import_csv(db, path, OverrideConfig())
    report = import_csv(db, path, OverrideConfig())
    assert report.imported_new == 0
    assert report.updated == 0
    assert report.unchanged == 6


def test_run_summary_line_formatted_correctly(tmp_path, db):
    path = _write_csv(tmp_path / "wl.csv", _e2e_rows())
    report = import_csv(db, path, OverrideConfig())
    text = report.render()
    assert "imported 6 records, updated 0, dropped 3" in text
    assert "2 mac_range" in text
    assert "0 geographic_filter" in text
    assert "0 severity_drop" in text
    assert "1 unknown_type" in text


# ---------------------------------------------------------------------------
# Cross-repo contract smoke against a live Argus CSV export.
#
# Argus and Lynceus live in separate repos. This test verifies the end-to-end
# contract: a real `argus_export.csv` produced by the Argus export pipeline
# imports into Lynceus without parse errors. Skipped when the sibling Argus
# checkout is not present (e.g. CI), opportunistic when both repos coexist.
#
# Searched paths (first hit wins):
# - $LYNCEUS_ARGUS_CSV (env var override)
# - <repo_root>/../argus-db-main/exports/argus_export.csv
# - <repo_root>/../argus/exports/argus_export.csv
# ---------------------------------------------------------------------------


def _find_live_argus_csv() -> Path | None:
    import os

    override = os.environ.get("LYNCEUS_ARGUS_CSV")
    if override:
        p = Path(override)
        return p if p.is_file() else None
    repo_root = Path(__file__).resolve().parents[1]
    for candidate in (
        repo_root.parent / "argus-db-main" / "exports" / "argus_export.csv",
        repo_root.parent / "argus" / "exports" / "argus_export.csv",
    ):
        if candidate.is_file():
            return candidate
    return None


def test_cross_repo_live_argus_csv_imports_without_errors(tmp_path, db):
    """Real Argus CSV → Lynceus import: zero timestamp / row errors.

    The bedrock contract claim: whatever shapes the current Argus export
    pipeline emits for `first_seen` / `last_verified`, Lynceus's
    `_parse_date` tolerates them. Counts are reconciled rather than
    hard-pinned so the test does not drift as the Argus dataset grows.
    """
    csv_path = _find_live_argus_csv()
    if csv_path is None:
        pytest.skip(
            "live Argus CSV not found — set LYNCEUS_ARGUS_CSV or place "
            "the sibling argus-db-main repo next to lynceus"
        )

    report = import_csv(db, str(csv_path), OverrideConfig(), dry_run=True)

    assert report.errors == 0, (
        f"live Argus CSV produced {report.errors} row errors; "
        f"first 3: {report.error_log[:3]}"
    )
    assert report.imported_new > 0, "live Argus CSV imported zero rows"
    total_classified = (
        report.imported_new
        + report.updated
        + report.unchanged
        + report.dropped_mac_range
        + report.dropped_severity_drop
        + report.dropped_geographic_filter
        + report.dropped_unknown_type
        + report.dropped_low_confidence
        + report.normalization_failed
        + report.errors
    )
    assert total_classified == report.total_rows, (
        f"row reconciliation mismatch: {total_classified} classified vs "
        f"{report.total_rows} total"
    )
