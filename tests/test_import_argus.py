"""Tests for the v0.3 lynceus-import-argus CLI."""

from __future__ import annotations

import csv
import io
from pathlib import Path

import pytest
import yaml

from lynceus.cli import import_argus
from lynceus.cli.import_argus import (
    DEFAULT_ARGUS_SCHEMA_VERSION_ACCEPT_LIST,
    DEFAULT_CONFIDENCE_DOWNGRADE_THRESHOLD,
    EXPECTED_HEADER,
    OverrideConfig,
    import_csv,
    load_override_config,
    main,
    parse_argus_csv,
    parse_argus_meta,
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


def test_ssid_exact_argus_sample_rows_all_land_as_ssid(tmp_path, db):
    """Mirrors the actual Argus export contents at the 2026-05-17 snapshot:
    5 ssid_exact rows (``Flock`` x2, ``Flock-230503`` x2, ``Flock-*``).
    The two pairs of duplicates differ in argus_record_id only and
    collide on the same (pattern, pattern_type) natural key. First
    occurrence per pattern wins; the second peer in each pair lands
    in ``dropped_peer_collision`` (the per-Argus-record dedup rework,
    v0.6.0). 3 unique watchlist rows + 3 metadata rows; 3 imported_new
    + 2 dropped_peer_collision. Asserts all counts so a regression to
    the dedup, alias, or peer-collide gate is loud."""
    samples = [
        ("s-flock-1", "Flock"),
        ("s-flock-2", "Flock"),
        ("s-flock-230503-1", "Flock-230503"),
        ("s-flock-230503-2", "Flock-230503"),
        ("s-flock-wildcard", "Flock-*"),
    ]
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(argus_record_id=arid, identifier_type="ssid_exact", identifier=val)
            for arid, val in samples
        ],
    )
    report = import_csv(db, path, OverrideConfig())

    types = {
        r["pattern_type"]
        for r in db._conn.execute("SELECT pattern_type FROM watchlist").fetchall()
    }
    assert types == {"ssid"}

    patterns = sorted(
        r["pattern"]
        for r in db._conn.execute("SELECT pattern FROM watchlist").fetchall()
    )
    assert patterns == ["Flock", "Flock-*", "Flock-230503"]

    assert _wl_count(db) == 3
    assert _md_count(db) == 3
    assert report.imported_new == 3
    assert report.dropped_peer_collision == 2


def test_ssid_exact_wildcard_logs_warning_and_imports_anyway(tmp_path, db, caplog):
    """``Flock-*`` typed as ssid_exact is almost certainly Argus-side
    miscategorization (should be ssid_pattern). Per kev's call: warn
    loudly at import time but import the row anyway — the literal ``*``
    never matches a real WiFi observation, so the row sits dormant
    until Argus fixes it upstream. Asserts the warning is emitted, the
    counter increments, AND the row lands in the watchlist."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(
                argus_record_id="s-wild",
                identifier_type="ssid_exact",
                identifier="Flock-*",
            )
        ],
    )
    with caplog.at_level(_logging.WARNING, logger="lynceus.cli.import_argus"):
        report = import_csv(db, path, OverrideConfig())

    warnings = [
        r
        for r in caplog.records
        if r.levelno == _logging.WARNING
        and r.name == "lynceus.cli.import_argus"
        and "ssid_exact" in r.getMessage()
        and "Flock-*" in r.getMessage()
    ]
    assert len(warnings) == 1
    assert "argus_record_id=s-wild" in warnings[0].getMessage()
    assert "ssid_pattern" in warnings[0].getMessage(), (
        "warning should hint the operator that the row likely belongs as ssid_pattern"
    )

    assert report.ssid_exact_wildcard_warn == 1
    assert report.imported_new == 1

    row = db._conn.execute(
        "SELECT pattern, pattern_type FROM watchlist"
    ).fetchone()
    assert row["pattern"] == "Flock-*"
    assert row["pattern_type"] == "ssid"


def test_ssid_exact_without_wildcard_emits_no_warning(tmp_path, db, caplog):
    """Guard: ordinary ssid_exact rows must NOT trip the wildcard warning
    path. Catches accidental over-broadening of the trigger (e.g. if
    someone widens the char set to include `-` or normal punctuation)."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(
                argus_record_id="s-clean",
                identifier_type="ssid_exact",
                identifier="Flock-230503",
            )
        ],
    )
    with caplog.at_level(_logging.WARNING, logger="lynceus.cli.import_argus"):
        report = import_csv(db, path, OverrideConfig())

    wildcard_warnings = [
        r
        for r in caplog.records
        if r.levelno == _logging.WARNING
        and r.name == "lynceus.cli.import_argus"
        and "ssid_exact" in r.getMessage()
    ]
    assert wildcard_warnings == []
    assert report.ssid_exact_wildcard_warn == 0
    assert report.imported_new == 1


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


def test_mac_range_canonical_28_imports_with_prefix_columns(tmp_path, db):
    """Canonical /28 mac_range row lands in the watchlist with the
    nibble-precision prefix metadata populated. Previously dropped via
    dropped_mac_range; restored under the Argus 2026-05-14T22:34:07Z
    wire contract."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(
                argus_record_id="mr-28",
                identifier_type="mac_range",
                identifier="aa:bb:cc:d/28",
            )
        ],
    )
    report = import_csv(db, path, OverrideConfig())
    assert report.imported_new == 1
    assert report.dropped_mac_range == 0
    assert report.normalization_failed == 0
    row = db._conn.execute(
        "SELECT pattern, pattern_type, mac_range_prefix, mac_range_prefix_length "
        "FROM watchlist"
    ).fetchone()
    assert row["pattern_type"] == "mac_range"
    assert row["pattern"] == "aa:bb:cc:d/28"
    assert row["mac_range_prefix"] == "aabbccd"
    assert row["mac_range_prefix_length"] == 28


def test_mac_range_canonical_36_imports_with_prefix_columns(tmp_path, db):
    """Canonical /36 mac_range row lands with 9-hex prefix metadata."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(
                argus_record_id="mr-36",
                identifier_type="mac_range",
                identifier="aa:bb:cc:dd:e/36",
            )
        ],
    )
    report = import_csv(db, path, OverrideConfig())
    assert report.imported_new == 1
    row = db._conn.execute(
        "SELECT pattern, mac_range_prefix, mac_range_prefix_length FROM watchlist"
    ).fetchone()
    assert row["pattern"] == "aa:bb:cc:dd:e/36"
    assert row["mac_range_prefix"] == "aabbccdde"
    assert row["mac_range_prefix_length"] == 36


def test_mac_range_legacy_bare_prefix_canonicalized_on_disk(tmp_path, db):
    """Legacy bare-prefix shape ('aa:bb:cc:d', 5-group 'aa:bb:cc:dd:e')
    is accepted dual-shape per the Argus-engineer handoff. On disk, the
    pattern column is uniformly canonicalized to CIDR form so the
    watchlist UI shows uniform shape regardless of input."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(
                argus_record_id="mr-legacy-28",
                identifier_type="mac_range",
                identifier="aa:bb:cc:d",
            ),
            _row(
                argus_record_id="mr-legacy-36",
                identifier_type="mac_range",
                identifier="aa:bb:cc:dd:e",
            ),
        ],
    )
    report = import_csv(db, path, OverrideConfig())
    assert report.imported_new == 2
    rows = db._conn.execute(
        "SELECT pattern, mac_range_prefix_length FROM watchlist ORDER BY id"
    ).fetchall()
    assert [r["pattern"] for r in rows] == ["aa:bb:cc:d/28", "aa:bb:cc:dd:e/36"]
    assert [r["mac_range_prefix_length"] for r in rows] == [28, 36]


def test_mac_range_malformed_pattern_routes_to_normalization_failed(tmp_path, db):
    """A row whose mac_range pattern cannot be parsed (here: a full 6-byte
    MAC declared as a range) lands in normalization_failed, not in a
    generic errors bucket — same disposition as malformed MACs in the
    L-RULES-1 path. The good row in the same import still lands."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(
                argus_record_id="bad-range",
                identifier_type="mac_range",
                identifier="aa:bb:cc:dd:ee:ff",
            ),
            _row(
                argus_record_id="good-range",
                identifier_type="mac_range",
                identifier="aa:bb:cc:d/28",
            ),
        ],
    )
    report = import_csv(db, path, OverrideConfig())
    assert report.normalization_failed == 1
    assert report.imported_new == 1
    assert report.errors == 0
    rows = db._conn.execute("SELECT pattern FROM watchlist").fetchall()
    assert [r["pattern"] for r in rows] == ["aa:bb:cc:d/28"]


def test_unknown_identifier_type_dropped_increments_counter(tmp_path, db):
    path = _write_csv(
        tmp_path / "wl.csv",
        [_row(argus_record_id="u1", identifier_type="fcc_id")],
    )
    report = import_csv(db, path, OverrideConfig())
    assert report.dropped_unknown_type == 1
    assert _wl_count(db) == 0


def test_ble_manufacturer_id_identifier_type_imports_canonicalized(tmp_path, db):
    """Argus emits '0xNNNN'; the importer canonicalizes to bare lowercase
    hex via patterns.normalize_pattern so the runtime equality lookup
    against the kismet observation field works without per-call
    normalization."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(
                argus_record_id="blm1",
                identifier_type="ble_manufacturer_id",
                identifier="0x004C",
            )
        ],
    )
    report = import_csv(db, path, OverrideConfig())
    assert report.imported_new == 1
    assert report.dropped_unknown_type == 0
    row = db._conn.execute(
        "SELECT pattern, pattern_type FROM watchlist"
    ).fetchone()
    assert row["pattern_type"] == "ble_manufacturer_id"
    assert row["pattern"] == "004c"


def test_drone_id_prefix_identifier_type_imports_uppercase_canonical(tmp_path, db):
    """Argus emits uppercase ASCII alphanumeric; canonical persistent
    form is also uppercase (ANSI/CTA-2063-A serials are case-sensitive
    by spec)."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(
                argus_record_id="dr1",
                identifier_type="drone_id_prefix",
                identifier="21239ESA2",
            )
        ],
    )
    report = import_csv(db, path, OverrideConfig())
    assert report.imported_new == 1
    assert report.dropped_unknown_type == 0
    row = db._conn.execute(
        "SELECT pattern, pattern_type FROM watchlist"
    ).fetchone()
    assert row["pattern_type"] == "drone_id_prefix"
    assert row["pattern"] == "21239ESA2"


def test_ble_manufacturer_id_no_longer_falls_to_unknown_type(tmp_path, db):
    """Regression: pre-rc5 these rows hit dropped_unknown_type. Confirm
    a mixed CSV with both new types lands them as imported, not dropped."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(
                argus_record_id="blm-mix",
                identifier_type="ble_manufacturer_id",
                identifier="0x09C8",
            ),
            _row(
                argus_record_id="dr-mix",
                identifier_type="drone_id_prefix",
                identifier="2137FDE1",
            ),
            _row(
                argus_record_id="still-unknown",
                identifier_type="rf_channel",
            ),
        ],
    )
    report = import_csv(db, path, OverrideConfig())
    assert report.imported_new == 2
    assert report.dropped_unknown_type == 1  # rf_channel still dropped


def test_ble_company_id_aliased_to_ble_manufacturer_id(tmp_path, db):
    """Argus emits a small tail (7 rows in the rc5 snapshot) of rows with
    identifier_type=``ble_company_id`` carrying canonical-shape values
    like ``0x4C`` / ``0x004C`` / ``0x010C``. The semantic surface is the
    same as the admitted ``ble_manufacturer_id`` type — Bluetooth SIG
    16-bit Company Identifier — and the importer aliases the Argus type
    to the Lynceus pattern_type. Canonical persistent form is unchanged
    (``004c`` lowercase 4-hex). Closes the rc5 residuals
    admit-via-normalization gap (docs/ARGUS_RESIDUALS.md)."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(
                argus_record_id="bci-1",
                identifier_type="ble_company_id",
                identifier="0x4C",
            ),
            _row(
                argus_record_id="bci-2",
                identifier_type="ble_company_id",
                identifier="0x010C",
            ),
        ],
    )
    report = import_csv(db, path, OverrideConfig())
    assert report.imported_new == 2
    assert report.dropped_unknown_type == 0
    rows = db._conn.execute(
        "SELECT pattern, pattern_type FROM watchlist ORDER BY pattern"
    ).fetchall()
    assert [r["pattern_type"] for r in rows] == [
        "ble_manufacturer_id",
        "ble_manufacturer_id",
    ]
    assert [r["pattern"] for r in rows] == ["004c", "010c"]


def test_ble_service_uuid_aliased_to_ble_uuid_short_forms_expand(tmp_path, db):
    """Argus emits ``ble_service_uuid`` in three shapes: 16-bit short
    (``fd44``), 32-bit short (``7dfc9000``), and full 128-bit
    (``74278bda-...``). The importer aliases the type to ``ble_uuid``
    and the canonicalizer expands short forms against the Bluetooth
    base UUID. Closes the rc5 residuals admit-via-normalization gap."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(
                argus_record_id="bsu-16bit",
                identifier_type="ble_service_uuid",
                identifier="fd44",
            ),
            _row(
                argus_record_id="bsu-32bit",
                identifier_type="ble_service_uuid",
                identifier="7dfc9000",
            ),
            _row(
                argus_record_id="bsu-128bit",
                identifier_type="ble_service_uuid",
                identifier="74278bda-b644-4520-8f0c-720eaf059935",
            ),
        ],
    )
    report = import_csv(db, path, OverrideConfig())
    assert report.imported_new == 3
    assert report.dropped_unknown_type == 0
    rows = db._conn.execute(
        "SELECT pattern, pattern_type FROM watchlist ORDER BY pattern"
    ).fetchall()
    assert [r["pattern_type"] for r in rows] == ["ble_uuid"] * 3
    assert [r["pattern"] for r in rows] == [
        "0000fd44-0000-1000-8000-00805f9b34fb",
        "74278bda-b644-4520-8f0c-720eaf059935",
        "7dfc9000-0000-1000-8000-00805f9b34fb",
    ]


def test_ble_service_uuid_dual_form_takes_uuid_segment(tmp_path, db):
    """Argus emits ~2 rows in the rc5 snapshot with dual-form values
    like ``"fd5a / 0x0075"`` — 16-bit UUID + paired company id in a
    single identifier cell. The importer takes the UUID segment for
    the ``ble_uuid`` admission; the company-id half is admitted
    separately as ``ble_manufacturer_id`` when Argus types it that
    way."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(
                argus_record_id="bsu-dual-1",
                identifier_type="ble_service_uuid",
                identifier="fd5a / 0x0075",
            ),
            _row(
                argus_record_id="bsu-dual-2",
                identifier_type="ble_service_uuid",
                identifier="fdcd / 0x02d0",
            ),
        ],
    )
    report = import_csv(db, path, OverrideConfig())
    assert report.imported_new == 2
    assert report.dropped_unknown_type == 0
    assert report.normalization_failed == 0
    rows = db._conn.execute(
        "SELECT pattern, pattern_type FROM watchlist ORDER BY pattern"
    ).fetchall()
    assert [r["pattern_type"] for r in rows] == ["ble_uuid", "ble_uuid"]
    assert [r["pattern"] for r in rows] == [
        "0000fd5a-0000-1000-8000-00805f9b34fb",
        "0000fdcd-0000-1000-8000-00805f9b34fb",
    ]


def test_ble_service_uuid_short_and_padded_dedup_via_natural_key(tmp_path, db):
    """``fd44`` (16-bit short) and ``0000fd44`` (32-bit zero-padded
    rendering of the same SIG-assigned 16-bit UUID) both canonicalize
    to ``0000fd44-...-00805f9b34fb``. The importer's natural-key
    lookup (pattern, pattern_type) collapses them onto a single
    watchlist row; the peer-collide gate (v0.6.0) drops the second
    Argus row to avoid the prior last-write-wins overwrite of the
    metadata. First Argus row imports (imported_new=1); second is
    counted in ``dropped_peer_collision``. Single watchlist row +
    single metadata row, bound to the first argus_record_id."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(
                argus_record_id="bsu-fd44-short",
                identifier_type="ble_service_uuid",
                identifier="fd44",
            ),
            _row(
                argus_record_id="bsu-fd44-padded",
                identifier_type="ble_service_uuid",
                identifier="0000fd44",
            ),
        ],
    )
    report = import_csv(db, path, OverrideConfig())
    assert report.imported_new == 1  # first row admitted
    assert report.dropped_peer_collision == 1  # second row gated
    assert report.dropped_unknown_type == 0
    assert _wl_count(db) == 1  # one watchlist row (dedup)


def test_ble_manufacturer_id_malformed_lands_in_normalization_failed(tmp_path, db):
    """Defensive: a malformed ble_manufacturer_id value (>4 hex chars)
    routes through normalization_failed, not unknown_type — matches
    the mac_range malformed-row counter convention."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(
                argus_record_id="blm-bad",
                identifier_type="ble_manufacturer_id",
                identifier="0x12345",
            ),
        ],
    )
    report = import_csv(db, path, OverrideConfig())
    assert report.normalization_failed == 1
    assert report.imported_new == 0


def test_drone_id_prefix_too_short_lands_in_normalization_failed(tmp_path, db):
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(
                argus_record_id="dr-bad",
                identifier_type="drone_id_prefix",
                identifier="AB",
            ),
        ],
    )
    report = import_csv(db, path, OverrideConfig())
    assert report.normalization_failed == 1
    assert report.imported_new == 0


# ---------------------------------------------------------------------------
# Per-Argus-record dedup gates (v0.6.0).
#
# Two upstream-emitted dup shapes in the bundled Argus CSV produced
# counter inflation + watchlist_metadata thrash on no-op re-import
# before the v0.6.0 rework. Both are gated at per-row dispatch in
# `import_csv`; see docs/ARGUS_DEDUP_SHAPES.md for the bucket
# inventory.
# ---------------------------------------------------------------------------


def test_peer_collide_gate_drops_second_natural_key_collision(tmp_path, db):
    """Two Argus rows with distinct argus_record_ids that canonicalize
    to the same (pattern, pattern_type) — the dominant shape behind
    Bucket A (mac_range legacy bare-prefix vs CIDR, ble_manufacturer_id
    case variants, ble_uuid short-form). With both rows at identical
    severity and confidence (default `alpr` cat, conf=85), the
    tiebreak chain falls through to "earliest CSV index wins":
    ``pc-bare`` is the Phase B winner, ``pc-cidr`` lands in
    ``dropped_peer_collision``; the loser's metadata never reaches
    `upsert_metadata` so the winner's ``watchlist_metadata`` row is
    not overwritten."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(
                argus_record_id="pc-bare",
                identifier_type="mac_range",
                identifier="10:63:a3:1",   # legacy bare prefix
                manufacturer="Jacobs",
            ),
            _row(
                argus_record_id="pc-cidr",
                identifier_type="mac_range",
                identifier="10:63:a3:1/28",  # canonical CIDR; same pattern
                manufacturer="Jacobs Technology, Inc.",
            ),
        ],
    )
    report = import_csv(db, path, OverrideConfig())
    assert report.imported_new == 1
    assert report.dropped_peer_collision == 1
    assert _wl_count(db) == 1
    assert _md_count(db) == 1
    md = db._conn.execute(
        "SELECT argus_record_id, vendor FROM watchlist_metadata"
    ).fetchone()
    assert md["argus_record_id"] == "pc-bare"  # earliest CSV index tiebreak
    assert md["vendor"] == "Jacobs"


def test_peer_collide_gate_attaches_to_seeded_watchlist_row_without_md(tmp_path, db):
    """A YAML-seeded watchlist row exists with no metadata side. The
    first Argus row matching that natural key MUST attach metadata
    normally — the peer-collide gate only fires when the existing
    watchlist row ALREADY has metadata bound to a different
    argus_record_id. Without this case, seeded rows would be locked
    out of the Argus side entirely."""
    # Seed a watchlist row without metadata.
    with db._conn:
        db._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
            "VALUES (?, ?, ?, ?)",
            ("aa:bb:cc:dd:ee:ff", "mac", "low", "yaml-seeded"),
        )
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(argus_record_id="argus-first-attach", identifier="aa:bb:cc:dd:ee:ff"),
        ],
    )
    report = import_csv(db, path, OverrideConfig())
    assert report.imported_new == 1
    assert report.dropped_peer_collision == 0
    assert _wl_count(db) == 1  # same row, not duplicated
    assert _md_count(db) == 1
    md = db._conn.execute(
        "SELECT argus_record_id FROM watchlist_metadata"
    ).fetchone()
    assert md["argus_record_id"] == "argus-first-attach"


def test_in_import_dup_gate_drops_second_argus_record_id_occurrence(tmp_path, db):
    """The same argus_record_id appearing twice in one CSV with
    content drift — the dominant Bucket B shape (primary_registry vs
    crowdsourced OUI overlay). The primary_registry row resolves to
    severity=med (cat=drone at conf=80, no downgrade) while the
    crowdsourced row resolves to severity=low (cat=drone at conf=65,
    downgraded). Highest-severity-wins picks the primary_registry
    row; the crowdsourced peer lands in ``dropped_in_import_dup``."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(
                argus_record_id="dup-record-1",
                identifier_type="oui",
                identifier="48:1c:b9",
                device_category="drone",
                manufacturer="DJI",
                source_type="primary_registry",
                confidence="80",
            ),
            _row(
                argus_record_id="dup-record-1",   # SAME id, different fields
                identifier_type="oui",
                identifier="48:1c:b9",
                device_category="drone",
                manufacturer="",                  # crowdsourced overlay shape
                source_type="crowdsourced",
                confidence="65",
            ),
        ],
    )
    report = import_csv(db, path, OverrideConfig())
    assert report.imported_new == 1
    assert report.dropped_in_import_dup == 1
    md = db._conn.execute(
        "SELECT vendor, source, confidence FROM watchlist_metadata"
    ).fetchone()
    # First occurrence's fields survived; not overwritten by occ 2.
    assert md["vendor"] == "DJI"
    assert md["source"] == "primary_registry"
    assert md["confidence"] == 80


def test_in_import_dup_gate_independent_of_peer_collide_gate(tmp_path, db):
    """A CSV that exercises BOTH gates in one run — argus_record_id
    `X` appears once and is admitted; argus_record_id `Y` appears
    twice (dropped_in_import_dup increments once for the second);
    and argus_record_id `Z` shares X's canonical pattern
    (dropped_peer_collision increments once). Verifies the two
    gates do not interfere — distinct counters and clean counter
    invariant."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(argus_record_id="X", identifier="aa:bb:cc:11:22:33"),
            _row(argus_record_id="Y", identifier="aa:bb:cc:44:55:66"),
            _row(argus_record_id="Y", identifier="aa:bb:cc:44:55:66"),  # in-import dup
            _row(argus_record_id="Z", identifier="aa:bb:cc:11:22:33"),  # peer-collide of X
        ],
    )
    report = import_csv(db, path, OverrideConfig())
    assert report.imported_new == 2  # X and Y
    assert report.dropped_in_import_dup == 1  # second Y
    assert report.dropped_peer_collision == 1  # Z collides with X
    assert (
        report.imported_new
        + report.updated
        + report.unchanged
        + report.dropped_in_import_dup
        + report.dropped_peer_collision
        + report.dropped_unknown_type
        + report.dropped_geographic_filter
        + report.dropped_severity_drop
        + report.dropped_low_confidence
        + report.normalization_failed
        + report.errors
    ) == report.total_rows == 4


# ---------------------------------------------------------------------------
# Tiebreak policy for peer-collide and within-import-dup pre-pass
# (v0.6.0 hotfix). The pre-pass adjudicates among admitted candidates
# using a three-tier chain:
#   1. highest severity rank (high > med > low per _SEVERITY_RANK)
#   2. highest confidence
#   3. earliest CSV index
# Each tier breaks ties from the previous tier. The tests below pin
# each tier individually and the determinism contract across the
# composed chain.
# ---------------------------------------------------------------------------


def test_tiebreak_highest_severity_wins_within_import_dup(tmp_path, db):
    """Three CSV rows share the same argus_record_id with severities
    low / high / med (deliberately not in descending or ascending
    order). Highest-severity-wins picks the `high` row regardless of
    its CSV position; the low and med rows land in
    ``dropped_in_import_dup``. Without this policy, first-occurrence-
    wins would have picked the `low` row and silently demoted the
    operator-visible alert severity."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(
                argus_record_id="sev-dup",
                identifier="aa:bb:cc:11:22:33",
                # alpr@conf=85 → high (no downgrade). But override
                # forces the severity into a known place.
                device_category="alpr",
                manufacturer="LowVendor",
                confidence="85",
            ),
            _row(
                argus_record_id="sev-dup",
                identifier="aa:bb:cc:11:22:33",
                device_category="alpr",
                manufacturer="HighVendor",
                confidence="85",
            ),
            _row(
                argus_record_id="sev-dup",
                identifier="aa:bb:cc:11:22:33",
                device_category="alpr",
                manufacturer="MedVendor",
                confidence="85",
            ),
        ],
    )
    ov = OverrideConfig(
        vendor_overrides={
            "LowVendor": "low",
            "HighVendor": "high",
            "MedVendor": "med",
        }
    )
    report = import_csv(db, path, ov)
    assert report.imported_new == 1
    assert report.dropped_in_import_dup == 2
    md = db._conn.execute(
        "SELECT vendor FROM watchlist_metadata"
    ).fetchone()
    assert md["vendor"] == "HighVendor", (
        f"highest-severity-wins must pick the 'high' row regardless "
        f"of CSV position; got vendor={md['vendor']!r}"
    )
    wl = db._conn.execute(
        "SELECT severity FROM watchlist"
    ).fetchone()
    assert wl["severity"] == "high"


def test_tiebreak_highest_severity_wins_peer_collide(tmp_path, db):
    """Two Argus rows with distinct argus_record_ids that
    canonicalize to the same (pattern, pattern_type). The first row
    resolves to low severity, the second to high. Highest-severity-
    wins picks the second row; the first lands in
    ``dropped_peer_collision``."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(
                argus_record_id="pc-low",
                identifier_type="ble_manufacturer_id",
                identifier="0x004C",
                manufacturer="LowVendor",
                confidence="85",
            ),
            _row(
                argus_record_id="pc-high",
                identifier_type="ble_manufacturer_id",
                # Same canonical pattern after normalization.
                identifier="0x4C",
                manufacturer="HighVendor",
                confidence="85",
            ),
        ],
    )
    ov = OverrideConfig(
        vendor_overrides={"LowVendor": "low", "HighVendor": "high"}
    )
    report = import_csv(db, path, ov)
    assert report.imported_new == 1
    assert report.dropped_peer_collision == 1
    md = db._conn.execute(
        "SELECT argus_record_id, vendor FROM watchlist_metadata"
    ).fetchone()
    assert md["argus_record_id"] == "pc-high"
    assert md["vendor"] == "HighVendor"


def test_tiebreak_confidence_breaks_severity_tie_within_import_dup(tmp_path, db):
    """Both occurrences of the same argus_record_id resolve to the
    same severity. Tiebreak falls through to highest confidence: the
    conf=90 row wins over conf=70 regardless of CSV order."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(
                argus_record_id="conf-tie",
                identifier="aa:bb:cc:11:22:33",
                manufacturer="LowConf",
                confidence="70",
            ),
            _row(
                argus_record_id="conf-tie",
                identifier="aa:bb:cc:11:22:33",
                manufacturer="HighConf",
                confidence="90",
            ),
        ],
    )
    report = import_csv(db, path, OverrideConfig())
    assert report.imported_new == 1
    assert report.dropped_in_import_dup == 1
    md = db._conn.execute(
        "SELECT vendor, confidence FROM watchlist_metadata"
    ).fetchone()
    assert md["vendor"] == "HighConf"
    assert md["confidence"] == 90


def test_tiebreak_csv_order_breaks_severity_and_confidence_tie(tmp_path, db):
    """Both occurrences of the same argus_record_id resolve to the
    same severity AND the same confidence. Tiebreak falls through to
    earliest CSV index: the first row wins."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(
                argus_record_id="csv-tie",
                identifier="aa:bb:cc:11:22:33",
                manufacturer="FirstVendor",
                confidence="85",
            ),
            _row(
                argus_record_id="csv-tie",
                identifier="aa:bb:cc:11:22:33",
                manufacturer="SecondVendor",
                confidence="85",
            ),
        ],
    )
    report = import_csv(db, path, OverrideConfig())
    assert report.imported_new == 1
    assert report.dropped_in_import_dup == 1
    md = db._conn.execute(
        "SELECT vendor FROM watchlist_metadata"
    ).fetchone()
    assert md["vendor"] == "FirstVendor"


def test_tiebreak_is_deterministic_across_repeated_imports(tmp_path):
    """Identical input CSV must produce identical winners across
    independent runs. Re-running ``import_csv`` against a fresh DB
    with the same CSV bytes must yield the same surviving
    argus_record_ids in the same watchlist row order — the
    deterministic tiebreak ensures the rework's idempotency carries
    across operator re-runs, not just within a single import."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(
                argus_record_id="det-1",
                identifier_type="ble_manufacturer_id",
                identifier="0x004C",
                manufacturer="VendorA",
                confidence="85",
            ),
            _row(
                argus_record_id="det-2",
                identifier_type="ble_manufacturer_id",
                identifier="0x4C",            # canonicalizes same
                manufacturer="VendorB",
                confidence="85",
            ),
            _row(
                argus_record_id="det-3",
                identifier="aa:bb:cc:99:88:77",
                manufacturer="VendorC",
                confidence="85",
            ),
            _row(
                argus_record_id="det-3",     # in-import dup
                identifier="aa:bb:cc:99:88:77",
                manufacturer="VendorD",
                confidence="85",
            ),
        ],
    )

    def _import_fresh():
        db = Database(str(tmp_path / "fresh.db"))
        try:
            import_csv(db, path, OverrideConfig())
            md_rows = db._conn.execute(
                "SELECT argus_record_id, vendor FROM watchlist_metadata "
                "ORDER BY id"
            ).fetchall()
            return [(r["argus_record_id"], r["vendor"]) for r in md_rows]
        finally:
            db.close()
            (tmp_path / "fresh.db").unlink()

    run1 = _import_fresh()
    run2 = _import_fresh()
    run3 = _import_fresh()
    assert run1 == run2 == run3, (
        f"tiebreak must be deterministic; got: "
        f"run1={run1} run2={run2} run3={run3}"
    )


def test_no_op_reimport_produces_zero_mutating_writes_to_watchlist_tables(
    tmp_path, db
):
    """Re-importing the same CSV against a populated DB must produce
    zero `watchlist` and `watchlist_metadata` UPDATE/INSERT statements
    — the importer is idempotent on unchanged content. The
    `import_runs` INSERT still fires (the staleness signal records
    each import attempt); only writes to the dedup-relevant tables
    are pinned to zero here."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(argus_record_id="r1", identifier="aa:bb:cc:11:22:33"),
            _row(argus_record_id="r2", identifier="aa:bb:cc:44:55:66"),
            _row(argus_record_id="r3", identifier_type="oui", identifier="de:ad:be"),
        ],
    )
    # Populate.
    r1 = import_csv(db, path, OverrideConfig())
    assert r1.imported_new == 3

    # Capture mutating SQL on the re-import.
    mutations_to_dedup_tables: list[str] = []

    def cap(sql: str) -> None:
        upper = sql.upper().lstrip()
        if not upper.startswith(("INSERT", "UPDATE", "DELETE", "REPLACE")):
            return
        # Strip whitespace for matching.
        s = " ".join(sql.split()).lower()
        if (
            "watchlist_metadata" in s
            or s.startswith(("insert into watchlist(", "update watchlist "))
        ):
            mutations_to_dedup_tables.append(sql.strip())

    db._conn.set_trace_callback(cap)
    try:
        r2 = import_csv(db, path, OverrideConfig())
    finally:
        db._conn.set_trace_callback(None)

    assert r2.imported_new == 0
    assert r2.updated == 0
    assert r2.unchanged == 3
    assert mutations_to_dedup_tables == [], (
        f"no-op re-import must not write to watchlist or "
        f"watchlist_metadata; got: {mutations_to_dedup_tables}"
    )


def test_upsert_metadata_short_circuits_when_fields_match(tmp_path):
    """Direct unit test of the inner content-equality short-circuit
    in `Database.upsert_metadata`. Calling the function twice with
    identical fields against an existing row must NOT fire an
    UPDATE — `updated_at` is unchanged across the second call. This
    is layered defense behind the import-side gates; it makes the
    function idempotent for any caller that reaches the UPDATE
    branch."""
    import time as _time

    db = Database(str(tmp_path / "uxm.db"))
    try:
        with db._conn:
            cur = db._conn.execute(
                "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
                "VALUES (?, ?, ?, ?)",
                ("aa:bb:cc:dd:ee:ff", "mac", "low", "uxm test"),
            )
            watchlist_id = int(cur.lastrowid)
        fields = {
            "argus_record_id": "uxm-1",
            "device_category": "alpr",
            "vendor": "Acme",
            "source": "manufacturer_doc",
            "confidence": 85,
        }
        db.upsert_metadata(watchlist_id, fields)
        pre = db._conn.execute(
            "SELECT updated_at FROM watchlist_metadata WHERE watchlist_id = ?",
            (watchlist_id,),
        ).fetchone()

        # Second call — must short-circuit.
        # Sleep > 1s so a clock-based UPDATE would be visible if it fired.
        _time.sleep(1.1)
        captured: list[str] = []

        def cap(sql: str) -> None:
            upper = sql.upper().lstrip()
            if upper.startswith(("UPDATE", "INSERT")):
                captured.append(sql.strip())

        db._conn.set_trace_callback(cap)
        try:
            db.upsert_metadata(watchlist_id, fields)
        finally:
            db._conn.set_trace_callback(None)
        post = db._conn.execute(
            "SELECT updated_at FROM watchlist_metadata WHERE watchlist_id = ?",
            (watchlist_id,),
        ).fetchone()
        assert post["updated_at"] == pre["updated_at"], (
            "updated_at must not bump when fields are content-equal"
        )
        update_stmts = [s for s in captured if s.upper().lstrip().startswith("UPDATE")]
        assert update_stmts == [], (
            f"short-circuit must skip the UPDATE; got: {update_stmts}"
        )
    finally:
        db.close()


def test_upsert_metadata_still_updates_when_fields_differ(tmp_path):
    """Inverse of the short-circuit test: when ANY caller-provided
    field actually differs from the stored row, the UPDATE must
    fire (and `updated_at` bumps). The short-circuit must not mask
    legitimate writes."""
    import time as _time

    db = Database(str(tmp_path / "uxm2.db"))
    try:
        with db._conn:
            cur = db._conn.execute(
                "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
                "VALUES (?, ?, ?, ?)",
                ("aa:bb:cc:dd:ee:ff", "mac", "low", "uxm test"),
            )
            watchlist_id = int(cur.lastrowid)
        db.upsert_metadata(
            watchlist_id,
            {
                "argus_record_id": "uxm-2",
                "device_category": "alpr",
                "vendor": "Acme",
                "confidence": 85,
            },
        )
        pre = db._conn.execute(
            "SELECT updated_at, vendor FROM watchlist_metadata "
            "WHERE watchlist_id = ?",
            (watchlist_id,),
        ).fetchone()
        _time.sleep(1.1)
        db.upsert_metadata(
            watchlist_id,
            {
                "argus_record_id": "uxm-2",
                "device_category": "alpr",
                "vendor": "Acme Corp.",  # changed
                "confidence": 85,
            },
        )
        post = db._conn.execute(
            "SELECT updated_at, vendor FROM watchlist_metadata "
            "WHERE watchlist_id = ?",
            (watchlist_id,),
        ).fetchone()
        assert post["vendor"] == "Acme Corp."
        assert post["updated_at"] > pre["updated_at"], (
            "updated_at must bump when a field actually changes"
        )
    finally:
        db.close()



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


def test_mac_range_legacy_bare_prefix_emits_canonicalization_info_log(
    tmp_path, db, caplog
):
    """Legacy bare-prefix mac_range rows are accepted but log a per-row
    INFO line carrying the raw input, the canonicalized form, and the
    argus_record_id. Operators grep for this to watch the legacy count
    drop to zero once Argus canonicalizes upstream."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(
                argus_record_id="mr-legacy-logged",
                identifier_type="mac_range",
                identifier="aa:bb:cc:d",
            )
        ],
    )
    with caplog.at_level(_logging.INFO, logger="lynceus.cli.import_argus"):
        import_csv(db, path, OverrideConfig())
    matches = [
        r
        for r in caplog.records
        if r.levelno == _logging.INFO
        and r.name == "lynceus.cli.import_argus"
        and "mr-legacy-logged" in r.getMessage()
        and "legacy bare-prefix" in r.getMessage()
    ]
    assert len(matches) == 1
    msg = matches[0].getMessage()
    assert "'aa:bb:cc:d'" in msg  # raw shape, repr-quoted
    assert "'aa:bb:cc:d/28'" in msg  # canonical shape


def test_mac_range_canonical_emits_no_canonicalization_log(tmp_path, db, caplog):
    """Guard: canonical CIDR rows must NOT emit the legacy-canonicalization
    INFO line — that line is the only signal operators have for tracking
    how many legacy rows remain in Argus's emission."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(
                argus_record_id="mr-canon-noLog",
                identifier_type="mac_range",
                identifier="aa:bb:cc:d/28",
            )
        ],
    )
    with caplog.at_level(_logging.INFO, logger="lynceus.cli.import_argus"):
        import_csv(db, path, OverrideConfig())
    bare_prefix_msgs = [
        r for r in caplog.records if "legacy bare-prefix" in r.getMessage()
    ]
    assert bare_prefix_msgs == []


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
    """Three rows all share the default identifier (same canonical
    pattern); without geographic filtering they all pass that gate,
    but the peer-collide gate (v0.6.0) drops the second and third
    onto the same watchlist row. ``dropped_geographic_filter`` remains
    zero (the geographic gate didn't fire); the peer-collide gate
    accounts for the dedup of identical-pattern rows."""
    path = _write_csv(
        tmp_path / "wl.csv",
        [
            _row(argus_record_id="g5a", geographic_scope="apac"),
            _row(argus_record_id="g5b", geographic_scope=""),
            _row(argus_record_id="g5c", geographic_scope="global"),
        ],
    )
    report = import_csv(db, path, OverrideConfig())
    assert report.imported_new == 1
    assert report.dropped_peer_collision == 2
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


def test_load_override_config_permission_error_raises_useful_message(tmp_path, monkeypatch):
    """A PermissionError on the is_file() probe must surface as a
    RuntimeError naming the offending path. The bare PermissionError
    traceback isn't actionable for an operator. This is what crashes
    unprivileged --user invocations when the default points at
    /etc/lynceus/severity_overrides.yaml (0750 root:lynceus)."""
    blocked = tmp_path / "blocked.yaml"
    blocked.touch()

    PathCls = type(blocked)
    real_is_file = PathCls.is_file

    def _raise(self):
        if str(self) == str(blocked):
            raise PermissionError(13, "Permission denied")
        return real_is_file(self)

    monkeypatch.setattr(PathCls, "is_file", _raise)
    with pytest.raises(RuntimeError, match="cannot probe override file"):
        load_override_config(str(blocked))


# ---------------------------------------------------------------------------
# Scope-strict --override-file resolution.
#
# Bug from the rc4 live smoke: argparse defaulted --override-file to a
# hardcoded /etc/lynceus/severity_overrides.yaml regardless of --scope.
# On a host with a parallel --system install (where that dir is 0750
# root:lynceus), an unprivileged --scope user run blew up with a bare
# PermissionError instead of using the user-scope override path. Fix:
# omitted --override-file derives from paths.default_overrides_path(scope),
# and never probes the opposite scope.
# ---------------------------------------------------------------------------


def test_main_scope_user_does_not_probe_system_override(tmp_path, db_path, monkeypatch):
    """With --scope user and no --override-file, the importer must
    probe the user-scope path and ONLY the user-scope path. The
    system-scope path must not be touched even when the user file is
    absent (the bug was: hardcoded /etc/ default; user-scope hosts
    without permission crashed)."""
    user_override = tmp_path / "user-overrides.yaml"
    system_override = tmp_path / "system-overrides.yaml"
    # Neither file exists — this exercises the absent-file fallback,
    # which is the exact path that used to leak into /etc/.

    scope_calls = []

    def _fake_overrides_path(scope):
        scope_calls.append(scope)
        return {"user": user_override, "system": system_override}[scope]

    monkeypatch.setattr(import_argus.paths, "default_overrides_path", _fake_overrides_path)

    PathCls = type(user_override)
    real_is_file = PathCls.is_file
    probed_paths = []

    def _probe(self):
        probed_paths.append(str(self))
        return real_is_file(self)

    monkeypatch.setattr(PathCls, "is_file", _probe)

    csv_path = _write_csv(tmp_path / "wl.csv", [_row(argus_record_id="s1")])
    rc = main(["--db", db_path, "--input", csv_path, "--scope", "user"])

    assert rc == 0
    assert scope_calls == ["user"], (
        f"default_overrides_path should be called exactly once with 'user'; "
        f"got {scope_calls}"
    )
    assert str(user_override) in probed_paths
    assert str(system_override) not in probed_paths, (
        f"system override path probed despite --scope user: {probed_paths}"
    )


def test_main_scope_system_does_not_probe_user_override(tmp_path, db_path, monkeypatch):
    """Inverse: --scope system must not probe the user-scope path.
    The symmetry matters: if a system-scope batch job ran on a
    multi-user box, the user-scope default would change behavior
    based on whose home dir the daemon happens to be invoked from."""
    user_override = tmp_path / "user-overrides.yaml"
    system_override = tmp_path / "system-overrides.yaml"

    def _fake_overrides_path(scope):
        return {"user": user_override, "system": system_override}[scope]

    monkeypatch.setattr(import_argus.paths, "default_overrides_path", _fake_overrides_path)
    # default_db_path under --scope system raises NotImplementedError
    # on macOS/Windows; spoof it so the test holds cross-platform.
    monkeypatch.setattr(import_argus.paths, "default_db_path", lambda scope: Path(db_path))

    PathCls = type(user_override)
    real_is_file = PathCls.is_file
    probed_paths = []

    def _probe(self):
        probed_paths.append(str(self))
        return real_is_file(self)

    monkeypatch.setattr(PathCls, "is_file", _probe)

    csv_path = _write_csv(tmp_path / "wl.csv", [_row(argus_record_id="s2")])
    rc = main(["--input", csv_path, "--scope", "system"])

    assert rc == 0
    assert str(system_override) in probed_paths
    assert str(user_override) not in probed_paths, (
        f"user override path probed despite --scope system: {probed_paths}"
    )


def test_main_explicit_override_file_ignores_scope_default(tmp_path, db_path, monkeypatch):
    """When --override-file is passed explicitly, paths.default_overrides_path
    must NOT be called — explicit beats scope-derived. The operator's
    chosen path is used verbatim regardless of --scope."""
    explicit = tmp_path / "explicit-overrides.yaml"
    # File doesn't exist — load_override_config falls back to defaults,
    # but the resolution itself proves the scope-default helper was
    # never consulted.

    def _explode(scope):
        raise AssertionError(
            f"paths.default_overrides_path must not be called when "
            f"--override-file is given explicitly (scope={scope})"
        )

    monkeypatch.setattr(import_argus.paths, "default_overrides_path", _explode)

    csv_path = _write_csv(tmp_path / "wl.csv", [_row(argus_record_id="ex1")])
    rc = main(
        [
            "--db",
            db_path,
            "--input",
            csv_path,
            "--scope",
            "user",
            "--override-file",
            str(explicit),
        ]
    )
    assert rc == 0


def test_main_user_scope_permission_error_surfaces_clean_message(
    tmp_path, db_path, monkeypatch, caplog
):
    """Direct repro of the rc4 live-smoke crash: --scope user, override
    path resolves to a location whose is_file() probe raises
    PermissionError. The importer must return non-zero AND the log must
    include the offending path so the operator can see *what* is wrong
    without staring at a bare PermissionError traceback."""
    blocked = tmp_path / "blocked-overrides.yaml"
    blocked.touch()

    monkeypatch.setattr(
        import_argus.paths,
        "default_overrides_path",
        lambda scope: blocked,
    )

    PathCls = type(blocked)
    real_is_file = PathCls.is_file

    def _raise(self):
        if str(self) == str(blocked):
            raise PermissionError(13, "Permission denied")
        return real_is_file(self)

    monkeypatch.setattr(PathCls, "is_file", _raise)

    csv_path = _write_csv(tmp_path / "wl.csv", [_row(argus_record_id="p1")])
    with caplog.at_level("ERROR"):
        rc = main(["--db", db_path, "--input", csv_path, "--scope", "user"])

    assert rc == 1
    assert str(blocked) in caplog.text, (
        f"error output should name the offending override path; got: {caplog.text!r}"
    )


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
    """A 200 from GitHub with no tag_name must surface as a RuntimeError
    naming the repo, not a silent KeyError. (Distinct from the 404 path
    — GitHub returns 404 for "no releases published"; a 200 with no
    tag_name is malformed.)"""

    class _FakeResp:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return {"name": "no-tag-here"}

    monkeypatch.setattr(import_argus.requests, "get", lambda *a, **kw: _FakeResp())
    with pytest.raises(RuntimeError, match="kevwillow/argus-db"):
        import_argus._resolve_ref("kevwillow/argus-db", None)


def test_resolve_ref_falls_back_to_main_on_404(monkeypatch, caplog):
    """When /releases/latest 404s (repo has no published GitHub Release
    objects — e.g. kevwillow/argus-db ships its CSV on every commit but
    doesn't cut formal Releases), _resolve_ref must fall back to 'main'
    and emit a WARNING. The warning is load-bearing: it's the only
    signal operators get that they didn't pin a tag."""
    import requests as _requests

    class _FakeResp:
        status_code = 404

        def raise_for_status(self):
            raise _requests.HTTPError("404 Client Error: Not Found")

        def json(self):
            return {"message": "Not Found"}

    monkeypatch.setattr(import_argus.requests, "get", lambda *a, **kw: _FakeResp())
    with caplog.at_level("WARNING", logger="lynceus.cli.import_argus"):
        ref = import_argus._resolve_ref("kevwillow/argus-db", None)
    assert ref == "main"
    matching = [
        r
        for r in caplog.records
        if r.levelname == "WARNING" and "No published releases" in r.getMessage()
    ]
    assert matching, (
        f"expected a WARNING-level log mentioning 'No published releases'; "
        f"got {[(r.levelname, r.getMessage()) for r in caplog.records]}"
    )
    assert "kevwillow/argus-db" in matching[0].getMessage()
    assert "--ref" in matching[0].getMessage()


def test_resolve_ref_raises_on_non_404_http_error(monkeypatch):
    """A 500 from /releases/latest must propagate — only 404 ("no
    releases published") gets the main-fallback. A 500 is GitHub
    saying "try later", not "no releases"; silently importing from
    main would mask transient outages."""
    import requests as _requests

    class _FakeResp:
        status_code = 500

        def raise_for_status(self):
            raise _requests.HTTPError("500 Server Error")

        def json(self):
            return {}

    monkeypatch.setattr(import_argus.requests, "get", lambda *a, **kw: _FakeResp())
    with pytest.raises(_requests.HTTPError):
        import_argus._resolve_ref("kevwillow/argus-db", None)


def test_resolve_ref_raises_on_403_http_error(monkeypatch):
    """403 (rate-limited or auth-required) must also propagate — same
    reasoning as 500."""
    import requests as _requests

    class _FakeResp:
        status_code = 403

        def raise_for_status(self):
            raise _requests.HTTPError("403 Forbidden")

        def json(self):
            return {}

    monkeypatch.setattr(import_argus.requests, "get", lambda *a, **kw: _FakeResp())
    with pytest.raises(_requests.HTTPError):
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
    out, resolved = import_argus.fetch_argus_export(
        "kevwillow/argus-db", "v1.2.3", cache
    )
    assert out == cache / "v1.2.3__argus_export.csv"
    assert out.read_bytes() == payload
    # Caller-passed ref propagates back as the resolved value so
    # main() can use it for the import_runs.source forensic field
    # without re-calling _resolve_ref.
    assert resolved == "v1.2.3"
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
    out, _resolved = import_argus.fetch_argus_export(
        "kevwillow/argus-db", "release/v1.2", cache
    )
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
        # Return tuple matches the post-refactor contract: caller
        # uses the resolved-ref string for the import_runs.source
        # forensic field, avoiding a duplicate _resolve_ref call.
        return Path(fixture), ref or "main"

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
        # Two additional keepers — mac_range /28 (canonical CIDR) and
        # mac_range /36 (legacy bare-prefix, canonicalized on disk).
        # Pre-mac_range plumbing these were dropped via dropped_mac_range
        # (full 6-byte MACs were used as drop fixtures because mac_range
        # parsing did not yet exist); both now land in the watchlist.
        _row(
            argus_record_id="k6",
            identifier_type="mac_range",
            identifier="aa:bb:cc:d/28",
            device_category="alpr",
            confidence="90",
            geographic_scope="us",
        ),
        _row(
            argus_record_id="k7",
            identifier_type="mac_range",
            identifier="11:22:33:44:e",
            device_category="drone",
            confidence="90",
            geographic_scope="us",
        ),
        # Drops:
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
    assert report.imported_new == 8
    assert report.dropped_mac_range == 0
    assert report.dropped_unknown_type == 1
    assert report.dropped_geographic_filter == 0
    assert report.dropped_severity_drop == 0
    assert report.errors == 0
    assert _wl_count(db) == 8
    assert _md_count(db) == 8


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
    assert report.unchanged == 8


def test_run_summary_line_formatted_correctly(tmp_path, db):
    path = _write_csv(tmp_path / "wl.csv", _e2e_rows())
    report = import_csv(db, path, OverrideConfig())
    text = report.render()
    assert "imported 8 records, updated 0, dropped 1" in text
    # mac_range rows no longer drop — they land in the watchlist.
    # The counter line still renders so the bucket is visible at 0.
    assert "0 mac_range" in text
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
        + report.dropped_peer_collision
        + report.dropped_in_import_dup
        + report.normalization_failed
        + report.errors
    )
    # mac_range rows land in the watchlist as of the 011 migration.
    # Argus's 2026-05-14T22:34:07Z snapshot carried ~17,798 mac_range
    # rows (~64% /28 + ~35% /36 + ~12 legacy bare-prefix); the exact
    # count drifts as Argus grows and as legacy rows are canonicalized
    # upstream, so assert "substantially nonzero" rather than a fixed
    # number. This is a dry_run import so we count via the report;
    # the actual DB write path is covered by the per-row tests above.
    assert report.imported_new > 1000, (
        f"live Argus CSV imported only {report.imported_new} rows "
        f"(<1000) — likely a regression in mac_range admission or a "
        f"dramatic shrinkage in the upstream dataset"
    )
    assert report.dropped_mac_range == 0, (
        f"live Argus CSV produced {report.dropped_mac_range} "
        f"dropped_mac_range rows; with the 011 mac_range schema this "
        f"counter should be 0 (rows now import). A nonzero value means "
        f"the importer is still rejecting them somewhere."
    )

    assert total_classified == report.total_rows, (
        f"row reconciliation mismatch: {total_classified} classified vs "
        f"{report.total_rows} total"
    )


# ---------------------------------------------------------------------------
# parse_argus_meta — # meta: line key=value parser for the staleness signal.
# ---------------------------------------------------------------------------
#
# Canonical Argus shape today (from src/lynceus/data/default_watchlist.csv):
#   # meta: schema_version=8, exported_at=2026-05-07T20:17:59Z, \
#           record_count=63, confidence_threshold=0
# Parser is tolerant of additions / omissions per the Argus contract —
# upstream may add keys without coordinating a Lynceus release.


def _write_csv_with_meta(path: Path, meta_line: str, rows: list[dict[str, str]]) -> str:
    """Like _write_csv, but with an operator-supplied # meta: line so
    parse_argus_meta tests can exercise specific shapes."""
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(meta_line if meta_line.endswith("\n") else meta_line + "\n")
        writer = csv.writer(f)
        writer.writerow(EXPECTED_HEADER)
        for row in rows:
            writer.writerow([row.get(c, "") for c in EXPECTED_HEADER])
    return str(path)


def test_parse_argus_meta_canonical_shape(tmp_path):
    """The shape Argus ships in production. All four keys extract;
    exported_at parses through _parse_date to a Unix epoch int."""
    path = _write_csv_with_meta(
        tmp_path / "canonical.csv",
        "# meta: schema_version=8, exported_at=2026-05-07T20:17:59Z, "
        "record_count=63, confidence_threshold=0",
        [],
    )
    meta = parse_argus_meta(path)
    assert meta["schema_version"] == "8"
    # 2026-05-07T20:17:59Z → confirmed via _parse_date; the exact int
    # is the contract, not just "non-None".
    import datetime as _dt
    expected = int(
        _dt.datetime(2026, 5, 7, 20, 17, 59, tzinfo=_dt.UTC).timestamp()
    )
    assert meta["exported_at"] == expected
    assert meta["record_count"] == 63
    assert meta["confidence_threshold"] == 0


def test_parse_argus_meta_missing_keys_land_as_none(tmp_path):
    """Tolerant of upstream removing keys (or shipping a free-form
    meta line — the rc2-era META_LINE shape ``# meta: argus_export v3
    (CP11)`` parses to all-Nones cleanly)."""
    path = _write_csv_with_meta(
        tmp_path / "free_form.csv",
        "# meta: argus_export v3 (CP11)",
        [],
    )
    meta = parse_argus_meta(path)
    assert meta == {
        "exported_at": None,
        "record_count": None,
        "schema_version": None,
        "confidence_threshold": None,
    }


def test_parse_argus_meta_unknown_keys_are_ignored(tmp_path):
    """Tolerant of upstream ADDING keys — the parser must not crash
    on `new_field=value` it doesn't recognize. Lynceus releases can
    lag Argus releases."""
    path = _write_csv_with_meta(
        tmp_path / "with_unknown.csv",
        "# meta: schema_version=9, exported_at=2026-05-07T20:17:59Z, "
        "new_field_argus_will_add=42, record_count=63",
        [],
    )
    meta = parse_argus_meta(path)
    assert meta["schema_version"] == "9"
    assert meta["exported_at"] is not None
    assert meta["record_count"] == 63
    # No surprise key on the returned dict.
    assert set(meta.keys()) == {
        "exported_at",
        "record_count",
        "schema_version",
        "confidence_threshold",
    }


def test_parse_argus_meta_unparseable_exported_at_falls_through_to_none(tmp_path):
    """Malformed exported_at (e.g. a corrupted timestamp) → None for
    just that field, not a crash for the whole parser. The staleness
    layer treats None as 'no Argus-side freshness signal' and falls
    back to imported_at."""
    path = _write_csv_with_meta(
        tmp_path / "bad_ts.csv",
        "# meta: exported_at=not-a-timestamp, record_count=63",
        [],
    )
    meta = parse_argus_meta(path)
    assert meta["exported_at"] is None
    assert meta["record_count"] == 63


def test_parse_argus_meta_malformed_record_count_falls_through_to_none(tmp_path):
    """Per-field tolerance: a bad record_count doesn't lose the
    exported_at signal we did manage to parse."""
    path = _write_csv_with_meta(
        tmp_path / "bad_count.csv",
        "# meta: exported_at=2026-05-07T20:17:59Z, record_count=not-an-int",
        [],
    )
    meta = parse_argus_meta(path)
    assert meta["exported_at"] is not None
    assert meta["record_count"] is None


def test_parse_argus_meta_missing_prefix_returns_all_nones(tmp_path):
    """parse_argus_meta is defensive — a file whose first line lacks
    the `# meta:` prefix returns all-Nones (and parse_argus_csv
    separately raises a clear ValueError for the same condition).
    Splitting the two responsibilities means parse_argus_meta is safe
    to call alongside parse_argus_csv without re-validating."""
    p = tmp_path / "no_meta.csv"
    p.write_text("header,row\n", encoding="utf-8")
    meta = parse_argus_meta(str(p))
    assert meta == {
        "exported_at": None,
        "record_count": None,
        "schema_version": None,
        "confidence_threshold": None,
    }


# ---------------------------------------------------------------------------
# import_csv writes import_runs rows (the staleness signal's source).
# ---------------------------------------------------------------------------


def test_import_csv_writes_import_runs_row_with_meta_fields(tmp_path, db):
    """A successful import writes one row to import_runs carrying the
    parsed exported_at, the operator-supplied source string, and the
    record_count from the CSV's `# meta:` line. The staleness signal
    reads from here at startup + /settings."""
    path = _write_csv_with_meta(
        tmp_path / "with_meta.csv",
        "# meta: schema_version=8, exported_at=2026-05-07T20:17:59Z, "
        "record_count=1, confidence_threshold=0",
        [_row(argus_record_id="x1", identifier="aa:bb:cc:dd:ee:01")],
    )
    overrides = OverrideConfig()
    report = import_csv(
        db, path, overrides, source="kevwillow/argus-db@v9.9.9"
    )
    assert report.imported_new == 1
    latest = db.get_latest_import_run()
    assert latest is not None
    assert latest["source"] == "kevwillow/argus-db@v9.9.9"
    assert latest["record_count"] == 1
    import datetime as _dt
    expected = int(
        _dt.datetime(2026, 5, 7, 20, 17, 59, tzinfo=_dt.UTC).timestamp()
    )
    assert latest["exported_at"] == expected
    # imported_at is the local-clock write moment; assert it's recent
    # (within an hour, generous for slow CI runners) rather than
    # pinning a specific value.
    import time
    assert abs(latest["imported_at"] - int(time.time())) < 3600


def test_import_csv_dry_run_does_not_write_import_runs_row(tmp_path, db):
    """--dry-run wrote nothing to watchlist/watchlist_metadata, so it
    must not write to import_runs either — otherwise the staleness
    card would claim a recent refresh that never landed."""
    path = _write_csv(tmp_path / "wl.csv", [_row(argus_record_id="dr-1")])
    overrides = OverrideConfig()
    import_csv(db, path, overrides, dry_run=True, source="/path/to/wl.csv")
    assert db.get_latest_import_run() is None


def test_import_csv_legacy_free_form_meta_records_null_exported_at(tmp_path, db):
    """A CSV with the rc2-era free-form meta line still imports
    cleanly and writes an import_runs row — just with exported_at as
    None. The startup log line then falls back to imported_at for
    the age calculation."""
    # The default _write_csv helper writes "# meta: argus_export v3 (CP11)"
    # — free-form, no key=value pairs.
    path = _write_csv(tmp_path / "legacy.csv", [_row(argus_record_id="leg-1")])
    overrides = OverrideConfig()
    import_csv(db, path, overrides, source="/legacy.csv")
    latest = db.get_latest_import_run()
    assert latest is not None
    assert latest["exported_at"] is None
    assert latest["record_count"] is None
    assert latest["source"] == "/legacy.csv"


def test_main_input_records_absolute_source_path(tmp_path, db_path):
    """--input writes the absolute CSV path to import_runs.source so
    /settings can render where the import came from."""
    csv_path = _write_csv(tmp_path / "wl.csv", [_row(argus_record_id="abs-1")])
    rc = main(
        [
            "--db",
            db_path,
            "--input",
            csv_path,
            "--override-file",
            str(tmp_path / "missing.yaml"),
        ]
    )
    assert rc == 0
    db = Database(db_path)
    try:
        latest = db.get_latest_import_run()
        assert latest is not None
        # source must be an absolute path, regardless of how the
        # operator-typed --input value was shaped.
        assert Path(latest["source"]).is_absolute()
        assert latest["source"].endswith("wl.csv")
    finally:
        db.close()


def test_main_from_github_records_owner_repo_at_ref_source(
    tmp_path, db_path, monkeypatch
):
    """--from-github writes ``owner/repo@ref`` to import_runs.source
    — the operator-facing identifier the /settings card renders.
    Ref is the RESOLVED value (not args.ref pre-resolution), so a
    --from-github without --ref still gets a concrete tag/branch."""
    fixture = _write_csv(
        tmp_path / "fetched.csv",
        [_row(argus_record_id="gh-src-1", identifier="aa:bb:cc:dd:ee:01")],
    )

    def _fake_fetch(repo, ref, cache_dir):
        # Mimic fetch_argus_export's resolved-ref return: if the
        # caller passes a ref, return it verbatim; otherwise resolve
        # to a tag (we stub to "v2.0.0" for the test).
        resolved = ref or "v2.0.0"
        return Path(fixture), resolved

    monkeypatch.setattr(import_argus, "fetch_argus_export", _fake_fetch)
    rc = main(
        [
            "--db",
            db_path,
            "--from-github",
            "--repo",
            "someone/argus-fork",
            "--override-file",
            str(tmp_path / "missing.yaml"),
        ]
    )
    assert rc == 0
    db = Database(db_path)
    try:
        latest = db.get_latest_import_run()
        assert latest is not None
        assert latest["source"] == "someone/argus-fork@v2.0.0"
    finally:
        db.close()


# ---------------------------------------------------------------------------
# # meta: schema_version accept-list ingress check.
# ---------------------------------------------------------------------------
#
# Defensive ingress hygiene per the Argus engineer §F.2. The importer
# accepts a configurable allow-list of schema_version values (default
# ["25", "26"] for the v1.4.1 transition window) and WARNs without
# aborting on anything outside it. Missing schema_version (older
# `# meta: argus_export v3 (CP11)` shapes) skips the check silently —
# warning-on-absent would regress archived-export imports.


def _warnings_for_schema_version(caplog) -> list:
    return [
        r
        for r in caplog.records
        if r.levelno == _logging.WARNING
        and r.name == "lynceus.cli.import_argus"
        and "schema_version" in r.getMessage()
    ]


def test_argus_schema_version_25_accepted_silently(tmp_path, db, caplog):
    """schema_version=25 (pre-Phase-1 regen anchor) is in the default
    accept-list — no warning, row imports."""
    path = _write_csv_with_meta(
        tmp_path / "v25.csv",
        "# meta: schema_version=25, exported_at=2026-05-07T20:17:59Z, record_count=1",
        [_row(argus_record_id="v25-1")],
    )
    with caplog.at_level(_logging.WARNING, logger="lynceus.cli.import_argus"):
        report = import_csv(db, path, OverrideConfig())
    assert _warnings_for_schema_version(caplog) == []
    assert report.imported_new == 1


def test_argus_schema_version_26_accepted_silently(tmp_path, db, caplog):
    """schema_version=26 (v1.4.1 cutover) is in the default accept-list
    — no warning, row imports."""
    path = _write_csv_with_meta(
        tmp_path / "v26.csv",
        "# meta: schema_version=26, exported_at=2026-05-07T20:17:59Z, record_count=1",
        [_row(argus_record_id="v26-1")],
    )
    with caplog.at_level(_logging.WARNING, logger="lynceus.cli.import_argus"):
        report = import_csv(db, path, OverrideConfig())
    assert _warnings_for_schema_version(caplog) == []
    assert report.imported_new == 1


def test_argus_schema_version_unknown_warns_imports_anyway(tmp_path, db, caplog):
    """schema_version outside the accept-list (here ``"99"``) trips a
    WARNING with the configured accept-list and the override key, but
    does NOT abort — defensive posture preserves backward compat with
    operators on older Argus exports."""
    path = _write_csv_with_meta(
        tmp_path / "v99.csv",
        "# meta: schema_version=99, exported_at=2026-05-07T20:17:59Z, record_count=1",
        [_row(argus_record_id="v99-1")],
    )
    with caplog.at_level(_logging.WARNING, logger="lynceus.cli.import_argus"):
        report = import_csv(db, path, OverrideConfig())
    warnings = _warnings_for_schema_version(caplog)
    assert len(warnings) == 1
    msg = warnings[0].getMessage()
    assert "'99'" in msg
    assert "argus_schema_version_accept_list" in msg, (
        "warning should hint the override key so an operator can tune"
    )
    assert report.imported_new == 1


def test_argus_schema_version_custom_accept_list_via_overrides(tmp_path, db, caplog):
    """Operator-supplied accept-list narrows the accepted set; values
    no longer in the list start warning."""
    path = _write_csv_with_meta(
        tmp_path / "v25_narrowed.csv",
        "# meta: schema_version=25, exported_at=2026-05-07T20:17:59Z, record_count=1",
        [_row(argus_record_id="narr-1")],
    )
    overrides = OverrideConfig(argus_schema_version_accept_list=["27"])
    with caplog.at_level(_logging.WARNING, logger="lynceus.cli.import_argus"):
        report = import_csv(db, path, overrides)
    warnings = _warnings_for_schema_version(caplog)
    assert len(warnings) == 1
    assert "'25'" in warnings[0].getMessage()
    assert report.imported_new == 1


def test_argus_schema_version_missing_key_silent(tmp_path, db, caplog):
    """rc2-era ``# meta: argus_export v3 (CP11)`` shape has no
    schema_version key. Established codebase convention is silent
    tolerance for missing meta fields; warning here would be a noisy
    regression for archived-export imports."""
    path = _write_csv_with_meta(
        tmp_path / "free_form.csv",
        "# meta: argus_export v3 (CP11)",
        [_row(argus_record_id="ff-1")],
    )
    with caplog.at_level(_logging.WARNING, logger="lynceus.cli.import_argus"):
        report = import_csv(db, path, OverrideConfig())
    assert _warnings_for_schema_version(caplog) == []
    assert report.imported_new == 1


def test_argus_schema_version_accept_list_none_disables_check(tmp_path, db, caplog):
    """Explicit None on the accept-list is the operator opt-out: even
    a schema_version that would otherwise warn passes silently."""
    path = _write_csv_with_meta(
        tmp_path / "v99_disabled.csv",
        "# meta: schema_version=99, exported_at=2026-05-07T20:17:59Z, record_count=1",
        [_row(argus_record_id="dis-1")],
    )
    overrides = OverrideConfig(argus_schema_version_accept_list=None)
    with caplog.at_level(_logging.WARNING, logger="lynceus.cli.import_argus"):
        report = import_csv(db, path, overrides)
    assert _warnings_for_schema_version(caplog) == []
    assert report.imported_new == 1


def test_argus_schema_version_accept_list_empty_disables_check(tmp_path, db, caplog):
    """Empty list is treated the same as None — operator opt-out."""
    path = _write_csv_with_meta(
        tmp_path / "v99_empty.csv",
        "# meta: schema_version=99, exported_at=2026-05-07T20:17:59Z, record_count=1",
        [_row(argus_record_id="emp-1")],
    )
    overrides = OverrideConfig(argus_schema_version_accept_list=[])
    with caplog.at_level(_logging.WARNING, logger="lynceus.cli.import_argus"):
        report = import_csv(db, path, overrides)
    assert _warnings_for_schema_version(caplog) == []
    assert report.imported_new == 1


def test_load_override_config_argus_schema_version_default(tmp_path):
    """YAML without the key falls back to the built-in default
    ["25", "26"]."""
    p = tmp_path / "overrides.yaml"
    p.write_text(yaml.safe_dump({}), encoding="utf-8")
    cfg = load_override_config(str(p))
    assert cfg.argus_schema_version_accept_list == list(
        DEFAULT_ARGUS_SCHEMA_VERSION_ACCEPT_LIST
    )


def test_load_override_config_argus_schema_version_explicit_null(tmp_path):
    """Explicit ``argus_schema_version_accept_list: null`` disables
    the check. Distinct from key-absent (which uses the default)."""
    p = tmp_path / "overrides.yaml"
    p.write_text(
        yaml.safe_dump({"argus_schema_version_accept_list": None}),
        encoding="utf-8",
    )
    cfg = load_override_config(str(p))
    assert cfg.argus_schema_version_accept_list is None


def test_load_override_config_argus_schema_version_explicit_list(tmp_path):
    """Operator-supplied list lands as-is, coerced to list[str] (YAML
    ints get stringified so the comparison against schema_version
    raw string values stays type-safe)."""
    p = tmp_path / "overrides.yaml"
    p.write_text(
        yaml.safe_dump({"argus_schema_version_accept_list": [26, "27", 28]}),
        encoding="utf-8",
    )
    cfg = load_override_config(str(p))
    assert cfg.argus_schema_version_accept_list == ["26", "27", "28"]
