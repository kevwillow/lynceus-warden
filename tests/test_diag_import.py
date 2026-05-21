"""Diagnostic dumps for ``lynceus-import-argus`` accounting.

The pre-smoke dry-exercise quantified the counter lies: re-importing
the bundled CSV produced 31 false-new + 21 false-updated counters
and 25 ``watchlist_metadata`` rows where ``updated_at`` was bumped
despite no content change. These tests reproduce the surface at a
unit-test scale with deterministic synthetic CSVs so the reviewer
can verify behavior against intent without needing live timing of
the bundled 22k-row import.
"""

from __future__ import annotations

import csv
import time

import pytest

from lynceus.cli.import_argus import (
    EXPECTED_HEADER,
    OverrideConfig,
    import_csv,
)
from lynceus.db import Database

pytestmark = pytest.mark.diagnostic


META_LINE = "# meta: schema_version=21, exported_at=2026-05-17T15:53:27Z, record_count=4, confidence_threshold=0\n"


def _row(**overrides) -> dict[str, str]:
    base = {
        "argus_record_id": "diag-rec-1",
        "id": "1",
        "identifier": "aa:bb:cc:11:22:33",
        "identifier_type": "mac",
        "device_category": "alpr",
        "manufacturer": "DiagVendor",
        "model": "DiagModel",
        "confidence": "85",
        "source_type": "manufacturer_doc",
        "source_url": "https://example.com/diag",
        "source_excerpt": "diag excerpt",
        "geographic_scope": "US",
        "description": "diag record",
        "first_seen": "2026-05-06T00:30:28Z",
        "last_verified": "2026-05-06T00:30:28Z",
        "notes": "",
    }
    base.update(overrides)
    return base


def _write_csv(path, rows, *, header=None):
    header = header if header is not None else EXPECTED_HEADER
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(META_LINE)
        w = csv.writer(f)
        w.writerow(header)
        for r in rows:
            w.writerow([r.get(c, "") for c in header])
    return str(path)


def _metadata_snapshot(db: Database) -> list[dict]:
    rows = db._conn.execute(
        "SELECT id, argus_record_id, watchlist_id, updated_at, created_at, vendor "
        "FROM watchlist_metadata ORDER BY id"
    ).fetchall()
    return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Test 1 — SQL trace of a no-op re-import
# ---------------------------------------------------------------------------


def test_diag_import_argus_no_op_sql_trace(diag, tmp_path):
    csv_path = _write_csv(
        tmp_path / "diag.csv",
        [
            _row(argus_record_id="rec-mac-1", identifier="aa:bb:cc:11:22:33"),
            _row(argus_record_id="rec-mac-2", identifier="aa:bb:cc:11:22:44"),
            _row(argus_record_id="rec-oui-1", identifier_type="oui",
                 identifier="de:ad:be", manufacturer="OUIVendor"),
            _row(argus_record_id="rec-ssid-1", identifier_type="ssid_exact",
                 identifier="DiagSSID", manufacturer="SSIDVendor"),
        ],
    )

    db = Database(str(tmp_path / "diag.db"))

    diag.fixture("4-row CSV: 2 mac, 1 oui, 1 ssid_exact")

    diag.exercise("import_csv() first run -- populates DB")
    r1 = import_csv(db, csv_path, OverrideConfig())
    diag.observed(f"first run report: new={r1.imported_new} "
                  f"updated={r1.updated} unchanged={r1.unchanged} "
                  f"dropped={r1.dropped_severity_drop + r1.dropped_unknown_type + r1.dropped_geographic_filter + r1.dropped_mac_range + r1.dropped_low_confidence}")

    # Install SQL trace BEFORE the second run; capture only mutating
    # statements so noisy SELECT chatter doesn't dilute the dump.
    mutations: list[str] = []
    selects = {"count": 0}

    def capture(sql: str) -> None:
        upper = sql.upper().lstrip()
        if upper.startswith(("INSERT", "UPDATE", "DELETE", "REPLACE")):
            mutations.append(sql.strip())
        elif upper.startswith("SELECT"):
            selects["count"] += 1

    db._conn.set_trace_callback(capture)

    diag.exercise("import_csv() second run -- SAME CSV, no field changes")
    r2 = import_csv(db, csv_path, OverrideConfig())
    diag.observed(f"second run report: new={r2.imported_new} "
                  f"updated={r2.updated} unchanged={r2.unchanged}")
    diag.observed(f"second-run SELECT count (read-side traffic): "
                  f"{selects['count']}")
    diag.observed(f"second-run mutating-statement count: {len(mutations)}")
    diag.observed("--- second-run mutating statements (target table + verb) ---")
    for stmt in mutations:
        verb = stmt.split(None, 1)[0].upper()
        head = " ".join(stmt.split()[:6])
        diag.observed(f"  {verb}: {head}")

    diag.notes("Expected on an honest no-op: new=0, updated=0, "
               "unchanged=<total_rows>, mutating-statement count=1 "
               "(just the import_runs row that records the import "
               "happened). Any additional UPDATEs against "
               "watchlist_metadata or watchlist are the import "
               "thrashing the row needlessly.")
    db.close()


# ---------------------------------------------------------------------------
# Test 2 — argus_metadata row updated_at diff after no-op re-import
# ---------------------------------------------------------------------------


def test_diag_import_argus_metadata_thrash(diag, tmp_path):
    csv_path = _write_csv(
        tmp_path / "diag.csv",
        [
            _row(argus_record_id="rec-1"),
            _row(argus_record_id="rec-2", identifier="aa:bb:cc:dd:ee:01"),
            _row(argus_record_id="rec-3", identifier="aa:bb:cc:dd:ee:02"),
            _row(argus_record_id="rec-4", identifier_type="oui",
                 identifier="de:ad:be"),
        ],
    )
    db = Database(str(tmp_path / "diag.db"))

    diag.exercise("import_csv() first run")
    import_csv(db, csv_path, OverrideConfig())
    pre = _metadata_snapshot(db)
    diag.fixture(f"first-run watchlist_metadata snapshot ({len(pre)} rows):")
    for row in pre:
        diag.fixture(f"  {row}")

    # Sleep 1s so the upsert_metadata wall-clock now_ts differs if it
    # writes -- the diff is then unambiguous.
    time.sleep(1.1)

    diag.exercise("import_csv() second run -- identical CSV")
    import_csv(db, csv_path, OverrideConfig())
    post = _metadata_snapshot(db)
    diag.observed(f"second-run watchlist_metadata snapshot ({len(post)} rows):")
    for row in post:
        diag.observed(f"  {row}")

    diag.observed("--- per-row updated_at delta ---")
    pre_map = {r["id"]: r for r in pre}
    bumped = 0
    for row in post:
        pre_row = pre_map.get(row["id"], {})
        delta = row["updated_at"] - (pre_row.get("updated_at") or 0)
        marker = " <-- THRASHED" if delta > 0 else ""
        diag.observed(
            f"  id={row['id']} argus_record_id={row['argus_record_id']} "
            f"updated_at_delta={delta}{marker}"
        )
        if delta > 0:
            bumped += 1
    diag.observed(f"rows with updated_at bumped despite no content change: {bumped}")

    diag.notes("Synthetic fixture has no peer-collide or in-import-dup "
               "rows, so neither the v0.6.0 import-side gates nor the "
               "inner upsert_metadata short-circuit are exercised here "
               "— a no-bump observation holds on the synthetic CSV both "
               "before and after the rework, for different reasons. The "
               "bundled-CSV equivalent (which carries 25 thrashed rows "
               "before the rework and 0 after) is "
               "test_diag_import_argus_bundled_csv_dedup_shapes below.")
    db.close()


# ---------------------------------------------------------------------------
# Test 3 — per-type admit-vs-drop accounting
# ---------------------------------------------------------------------------


def test_diag_import_argus_admit_vs_drop(diag, tmp_path):
    rows = [
        # Supported identifier_types per IDENTIFIER_TYPE_MAP (import_argus.py:61):
        _row(argus_record_id="ok-mac", identifier_type="mac",
             identifier="aa:bb:cc:11:22:33"),
        _row(argus_record_id="ok-oui", identifier_type="oui",
             identifier="de:ad:be"),
        _row(argus_record_id="ok-ssid", identifier_type="ssid_exact",
             identifier="ExactSSID"),
        _row(argus_record_id="ok-ssidpat", identifier_type="ssid_pattern",
             identifier="*-pattern"),
        _row(argus_record_id="ok-ble", identifier_type="ble_uuid",
             identifier="0000180a-0000-1000-8000-00805f9b34fb"),
        _row(argus_record_id="ok-bleservice", identifier_type="ble_service",
             identifier="0000180f-0000-1000-8000-00805f9b34fb"),
        _row(argus_record_id="ok-blemfg", identifier_type="ble_manufacturer_id",
             identifier="0x004c"),
        _row(argus_record_id="ok-blecompany", identifier_type="ble_company_id",
             identifier="0x09c8"),
        _row(argus_record_id="ok-drone", identifier_type="drone_id_prefix",
             identifier="DIAG-DRONE-PREFIX"),
        _row(argus_record_id="ok-macrange", identifier_type="mac_range",
             identifier="aa:bb:cc:1/28"),
        # Unsupported types (should be dropped as unknown):
        _row(argus_record_id="bad-typo", identifier_type="ssid",
             identifier="LegacyTypeSSID"),
        _row(argus_record_id="bad-empty", identifier_type="",
             identifier="EmptyType"),
        _row(argus_record_id="bad-unknown", identifier_type="not_a_type",
             identifier="UnknownTypeIdent"),
        # Severity drop (severity_overrides config could downgrade to 'drop',
        # but default config admits all -- so this is here as a baseline).
        _row(argus_record_id="lowconf", identifier_type="mac",
             identifier="aa:bb:cc:99:99:99", confidence="10"),
        # Empty identifier:
        _row(argus_record_id="bad-empty-ident", identifier_type="mac",
             identifier=""),
    ]
    csv_path = _write_csv(tmp_path / "diag.csv", rows)
    db = Database(str(tmp_path / "diag.db"))

    diag.fixture(f"CSV total rows: {len(rows)} "
                 f"(10 supported types + 3 unsupported + 1 low-confidence "
                 f"baseline + 1 empty-identifier error)")
    diag.exercise("import_csv() with default OverrideConfig "
                  "(no geographic filter, no severity downgrade)")
    report = import_csv(db, csv_path, OverrideConfig(), min_confidence=70)
    diag.observed(f"report: total_rows={report.total_rows} "
                  f"imported_new={report.imported_new} "
                  f"updated={report.updated} unchanged={report.unchanged}")
    diag.observed(f"  dropped_unknown_type={report.dropped_unknown_type}")
    diag.observed(f"  dropped_severity_drop={report.dropped_severity_drop}")
    diag.observed(f"  dropped_geographic_filter={report.dropped_geographic_filter}")
    diag.observed(f"  dropped_mac_range={report.dropped_mac_range}")
    diag.observed(f"  dropped_low_confidence={report.dropped_low_confidence}")
    diag.observed(f"  normalization_failed={report.normalization_failed}")
    diag.observed(f"  errors={report.errors}")
    diag.observed(f"  error_log: {report.error_log}")

    # Cross-check by reading the DB directly.
    wl_rows = db._conn.execute(
        "SELECT pattern_type, COUNT(*) FROM watchlist GROUP BY pattern_type"
    ).fetchall()
    diag.observed(f"watchlist rows by pattern_type: "
                  f"{[(r[0], r[1]) for r in wl_rows]}")
    md_count = db._conn.execute(
        "SELECT COUNT(*) FROM watchlist_metadata"
    ).fetchone()[0]
    diag.observed(f"watchlist_metadata row count: {md_count}")

    diag.notes("Reviewer cross-check: imported_new + sum(dropped_*) + "
               "normalization_failed + errors + updated + unchanged "
               "SHOULD equal total_rows. Any shortfall indicates rows "
               "silently disappearing. The v0.6.0 dedup rework added "
               "two `dropped_*` counters (dropped_peer_collision and "
               "dropped_in_import_dup) — both must be in the sum for "
               "the invariant to hold. The ssid_exact vs ssid_pattern "
               "split lands in watchlist as pattern_type 'ssid' (for "
               "ssid_exact) and 'ssid_pattern'.")
    db.close()


# ---------------------------------------------------------------------------
# Test 4 — bundled-CSV per-Argus-record dedup shapes (v0.6.0 rework)
#
# The synthetic-CSV diag tests above (no_op_sql_trace, metadata_thrash)
# don't reproduce the upstream-emitted dup shapes that drove the pre-
# rework bundled-CSV counter inflation (31 false-new, 21 false-updated,
# 25 metadata `updated_at` bumps; 99 mutating statements per re-import).
# This test exercises the actual bundled CSV end-to-end and pins:
# - second-run mutation count = 1 (only the import_runs INSERT)
# - dropped_peer_collision / dropped_in_import_dup hit their expected
#   values, derived from an independent CSV parse pass (not from
#   re-running the importer's own counters)
# - the counter math invariant balances both on first import and on
#   no-op re-import
# - a breakdown of the bucket A (peer-collide) and bucket B (in-import-
#   dup) shapes lands in the diagnostic log so reviewers can cross-
#   check the upstream-emission inventory documented in
#   docs/ARGUS_DEDUP_SHAPES.md
# ---------------------------------------------------------------------------


def test_diag_import_argus_bundled_csv_dedup_shapes(diag, tmp_path):
    import collections
    import importlib.resources

    from lynceus.cli.import_argus import (
        IDENTIFIER_TYPE_MAP,
        _SEVERITY_RANK,
        OverrideConfig as _OvCfg,
        parse_argus_csv,
        resolve_severity,
    )
    from lynceus.patterns import (
        canonicalize_mac_range_pattern,
        normalize_pattern,
        parse_mac_range_pattern,
    )

    def _resolved_sev(r: dict) -> str | None:
        """Reproduce the importer's severity resolution for a CSV row
        (default OverrideConfig) so the diag log can annotate winners
        and losers per the highest-severity-wins tiebreak."""
        try:
            conf = int(r.get("confidence", "") or "0")
        except ValueError:
            return None
        sev = resolve_severity(
            manufacturer=r.get("manufacturer") or None,
            device_category=r.get("device_category") or None,
            confidence=conf,
            overrides=_OvCfg(),
        )
        return sev if sev != "drop" else None

    def _tiebreak_winner(members: list[dict], csv_indices: list[int]) -> int:
        """Return the csv_index of the highest-severity-wins winner
        among ``members``. Tiebreak chain mirrors
        ``import_argus._select_winners``: severity rank → confidence
        → earliest csv_index. ``members[i]`` corresponds to
        ``csv_indices[i]`` 1-to-1."""
        best_idx = -1
        best_key: tuple[int, int, int] | None = None
        for m, ci in zip(members, csv_indices, strict=True):
            sev = _resolved_sev(m)
            if sev is None:
                continue
            try:
                conf = int(m["confidence"])
            except (KeyError, ValueError):
                conf = 0
            key = (_SEVERITY_RANK[sev], conf, -ci)
            if best_key is None or key > best_key:
                best_key = key
                best_idx = ci
        return best_idx

    bundle_path = str(
        importlib.resources.files("lynceus.data").joinpath("default_watchlist.csv")
    )
    diag.fixture(f"bundled Argus CSV: {bundle_path}")

    # ---- Independent CSV parse: derive ground-truth bucket inventory.
    rows = parse_argus_csv(bundle_path)
    diag.fixture(f"parsed {len(rows)} data rows")

    argus_id_count = collections.Counter(r["argus_record_id"] for r in rows)
    dup_argus_ids = {k: v for k, v in argus_id_count.items() if v > 1}

    # Each pattern_groups entry carries (csv_index, argus_id, raw_row)
    # tuples so the diag log can annotate winner/loser per
    # ``_select_winners``'s tiebreak chain. Diag analysis is parallel
    # to (not via) the importer's own counter path so the audit
    # cross-checks the production code rather than re-asserting it.
    pattern_groups: dict[tuple[str, str], list[tuple[int, str, dict]]] = {}
    for csv_idx, raw in enumerate(rows):
        argus_type = (raw["identifier_type"] or "").strip().lower()
        if argus_type not in IDENTIFIER_TYPE_MAP:
            continue
        ptype = IDENTIFIER_TYPE_MAP[argus_type]
        try:
            if ptype == "mac_range":
                pfx, plen = parse_mac_range_pattern(raw["identifier"])
                canon = canonicalize_mac_range_pattern(pfx, plen)
            else:
                canon = normalize_pattern(ptype, raw["identifier"])
        except Exception:
            continue
        pattern_groups.setdefault((canon, ptype), []).append(
            (csv_idx, raw["argus_record_id"], raw)
        )
    nk_collide_groups = {
        k: v
        for k, v in pattern_groups.items()
        if len({a for _, a, _ in v}) > 1
    }

    diag.fixture(
        f"bucket B (in-import-dup): {len(dup_argus_ids)} distinct "
        f"argus_record_ids appear >1 time, sum count "
        f"{sum(dup_argus_ids.values())}"
    )
    diag.fixture(
        f"bucket A (peer-collide): {len(nk_collide_groups)} (pattern, "
        f"pattern_type) groups have >1 distinct argus_record_id, sum "
        f"members {sum(len(v) for v in nk_collide_groups.values())}"
    )

    # Sample shape breakdown by canonical pattern_type
    by_ptype: dict[str, int] = collections.Counter()
    for (_, ptype), members in nk_collide_groups.items():
        by_ptype[ptype] += 1
    diag.fixture(f"bucket A breakdown by pattern_type: {dict(by_ptype)}")

    # Sample concrete groups with winner/loser annotation per the
    # highest-severity-wins tiebreak chain.
    diag.fixture("--- bucket A representative groups (first 5) with tiebreak winners ---")
    for (canon, ptype), members in list(nk_collide_groups.items())[:5]:
        idxs = [m[0] for m in members]
        rows_for_tb = [m[2] for m in members]
        winner_idx = _tiebreak_winner(rows_for_tb, idxs)
        diag.fixture(f"  pattern={canon!r} type={ptype}")
        for csv_idx, argus_id, raw in members:
            marker = "WINS" if csv_idx == winner_idx else "loses"
            diag.fixture(
                f"    [{marker}] csv_idx={csv_idx} argus={argus_id} "
                f"ident={raw.get('identifier')!r} "
                f"mfg={raw.get('manufacturer')!r} "
                f"sev={_resolved_sev(raw)} conf={raw.get('confidence')}"
            )
    diag.fixture("--- bucket B representative sets (first 5) with tiebreak winners ---")
    for argus_id, count in list(dup_argus_ids.items())[:5]:
        member_pairs = [(i, r) for i, r in enumerate(rows) if r["argus_record_id"] == argus_id]
        idxs = [p[0] for p in member_pairs]
        rows_for_tb = [p[1] for p in member_pairs]
        winner_idx = _tiebreak_winner(rows_for_tb, idxs)
        diag.fixture(f"  argus={argus_id} count={count}")
        for csv_idx, raw in member_pairs:
            marker = "WINS" if csv_idx == winner_idx else "loses"
            diag.fixture(
                f"    [{marker}] csv_idx={csv_idx} "
                f"ident={raw.get('identifier')!r} "
                f"cat={raw.get('device_category')!r} "
                f"mfg={raw.get('manufacturer')!r} "
                f"src={raw.get('source_type')!r} "
                f"sev={_resolved_sev(raw)} conf={raw.get('confidence')}"
            )

    # Count severity-drift sets (where tiebreak actually re-binds vs
    # passive first-wins). Useful as the audit summary number in the
    # diag log even when winners happen to coincide with first-in-CSV.
    bucket_a_drift = 0
    for (canon, ptype), members in nk_collide_groups.items():
        sevs = {_resolved_sev(m[2]) for m in members} - {None}
        if len(sevs) > 1:
            bucket_a_drift += 1
    bucket_b_drift = 0
    for argus_id in dup_argus_ids:
        member_rows = [r for r in rows if r["argus_record_id"] == argus_id]
        sevs = {_resolved_sev(r) for r in member_rows} - {None}
        if len(sevs) > 1:
            bucket_b_drift += 1
    diag.fixture(
        f"severity-drift groups (where tiebreak rebinds the winner "
        f"away from first-in-CSV-order): bucket_A={bucket_a_drift} of "
        f"{len(nk_collide_groups)}, bucket_B={bucket_b_drift} of "
        f"{len(dup_argus_ids)}"
    )

    # ---- Exercise: two-pass import against a fresh DB.
    db = Database(str(tmp_path / "bundled_diag.db"))

    diag.exercise("import_csv() first run -- populates DB from bundled CSV")
    r1 = import_csv(db, bundle_path, OverrideConfig())
    diag.observed(
        f"r1: total={r1.total_rows} new={r1.imported_new} "
        f"updated={r1.updated} unchanged={r1.unchanged} "
        f"dropped_peer_collision={r1.dropped_peer_collision} "
        f"dropped_in_import_dup={r1.dropped_in_import_dup} "
        f"dropped_unknown_type={r1.dropped_unknown_type} "
        f"errors={r1.errors}"
    )
    inv1 = (
        r1.imported_new + r1.updated + r1.unchanged
        + r1.dropped_unknown_type + r1.dropped_geographic_filter
        + r1.dropped_severity_drop + r1.dropped_mac_range
        + r1.dropped_low_confidence + r1.dropped_peer_collision
        + r1.dropped_in_import_dup + r1.normalization_failed + r1.errors
    )
    diag.observed(
        f"r1 invariant sum={inv1} total_rows={r1.total_rows} "
        f"match={inv1 == r1.total_rows}"
    )

    # ---- Exercise: no-op re-import, trace mutating SQL.
    mutations: list[str] = []

    def cap(sql: str) -> None:
        upper = sql.upper().lstrip()
        if upper.startswith(("INSERT", "UPDATE", "DELETE", "REPLACE")):
            mutations.append(sql.strip())

    db._conn.set_trace_callback(cap)
    diag.exercise("import_csv() second run -- SAME CSV, no field changes")
    r2 = import_csv(db, bundle_path, OverrideConfig())
    db._conn.set_trace_callback(None)
    diag.observed(
        f"r2: total={r2.total_rows} new={r2.imported_new} "
        f"updated={r2.updated} unchanged={r2.unchanged} "
        f"dropped_peer_collision={r2.dropped_peer_collision} "
        f"dropped_in_import_dup={r2.dropped_in_import_dup}"
    )
    inv2 = (
        r2.imported_new + r2.updated + r2.unchanged
        + r2.dropped_unknown_type + r2.dropped_geographic_filter
        + r2.dropped_severity_drop + r2.dropped_mac_range
        + r2.dropped_low_confidence + r2.dropped_peer_collision
        + r2.dropped_in_import_dup + r2.normalization_failed + r2.errors
    )
    diag.observed(
        f"r2 invariant sum={inv2} total_rows={r2.total_rows} "
        f"match={inv2 == r2.total_rows}"
    )
    diag.observed(
        f"second-run mutating-statement count: {len(mutations)}"
    )
    verbs: dict[str, int] = collections.Counter()
    for s in mutations:
        head = " ".join(s.split()[:3])
        verbs[head] += 1
    for head, count in verbs.most_common():
        diag.observed(f"  {count:5d} × {head}")

    # ---- Pinned assertions: numbers that should be stable across runs.
    # First import: dropped counters derive directly from the bucket
    # inventories above. The peer-collide count = sum(members-1) per
    # nk-collide group (the loser of each collide). The in-import-dup
    # count = sum(c-1) per dup-argus set, BUT only for sets where the
    # first occurrence passed validation (a small number may be lower
    # if the first occurrence was dropped for other reasons).
    expected_peer_collide = sum(len(v) - 1 for v in nk_collide_groups.values())
    expected_in_import_dup_upper = sum(c - 1 for c in dup_argus_ids.values())
    diag.notes(
        f"Pinned: dropped_peer_collision == sum(members-1) per "
        f"nk-collide group = {expected_peer_collide}. "
        f"dropped_in_import_dup <= sum(c-1) per dup-argus set = "
        f"{expected_in_import_dup_upper}; the actual count can be "
        f"lower if the first occurrence of a dup-argus set was "
        f"dropped for an upstream reason (unknown_type, "
        f"normalization_failed, etc.). 2nd-run mutation count must "
        f"be exactly 1 (import_runs INSERT)."
    )
    assert r1.dropped_peer_collision == expected_peer_collide, (
        f"first-run dropped_peer_collision={r1.dropped_peer_collision} "
        f"expected {expected_peer_collide}"
    )
    assert r1.dropped_in_import_dup <= expected_in_import_dup_upper, (
        f"first-run dropped_in_import_dup={r1.dropped_in_import_dup} "
        f"exceeds upper bound {expected_in_import_dup_upper}"
    )
    assert inv1 == r1.total_rows
    assert inv2 == r2.total_rows
    assert r2.imported_new == 0
    assert r2.updated == 0
    assert r2.unchanged == r1.imported_new, (
        f"all r1.imported_new rows must be unchanged on re-import; "
        f"r2.unchanged={r2.unchanged} vs r1.imported_new={r1.imported_new}"
    )
    assert len(mutations) == 1, (
        f"second-run mutating-statement count must be exactly 1 "
        f"(import_runs INSERT); got {len(mutations)}: "
        f"{[m.split()[:3] for m in mutations]}"
    )
    db.close()
