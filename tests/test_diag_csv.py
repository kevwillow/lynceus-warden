"""Diagnostic dumps for /alerts.csv (and /watchlist.csv) export shape.

CSV exports stream rows via ``Database.iter_alerts_with_match`` (cursor-
iterating, lazy). Header is 21 columns (``app.py:1444``). NULL handling
across columns is per-field at the writer site
(``app.py:1509-1532``). These tests dump:

- The actual CSV bytes emitted for rows with assorted NULL columns.
- Row-count + action_taken parity between HTML /alerts and CSV
  /alerts.csv under identical filters.
- The ISO datetime format used per column for ts inputs at year
  boundaries and DST edges.

Observation-only; reviewer reads the .log files for divergence from
intent.
"""

from __future__ import annotations

import csv
import io

import pytest
from fastapi.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import create_app

pytestmark = pytest.mark.diagnostic


def _seed_device(db: Database, mac: str, *, ts: int) -> None:
    db.ensure_location("diagloc", "Diagnostic")
    db.upsert_device(
        mac=mac, device_type="wifi", oui_vendor="DiagVendor",
        is_randomized=0, now_ts=ts,
    )


def _seed_alert(
    db: Database, *, mac: str | None, ts: int,
    rule_name: str = "diag-rule", severity: str = "med",
    note: str | None = None,
    note_updated_at: int | None = None,
    matched_watchlist_id: int | None = None,
    rule_type: str | None = "watchlist_mac",
    message: str = "diag alert",
) -> int:
    if mac is not None:
        _seed_device(db, mac, ts=ts)
    aid = db.add_alert(
        ts=ts, rule_name=rule_name, mac=mac, message=message,
        severity=severity, matched_watchlist_id=matched_watchlist_id,
        rule_type=rule_type,
    )
    if note is not None:
        # note + note_updated_at land via a separate UPDATE in production;
        # the diag goes straight to SQL to set both atomically.
        db._conn.execute(
            "UPDATE alerts SET note = ?, note_updated_at = ? WHERE id = ?",
            (note, note_updated_at, aid),
        )
        db._conn.commit()
    return aid


def _parse_csv(text: str) -> tuple[list[str], list[list[str]]]:
    rdr = csv.reader(io.StringIO(text))
    rows = list(rdr)
    return rows[0], rows[1:]


# ---------------------------------------------------------------------------
# Test 1 — NULL column rendering across the 21-column row
# ---------------------------------------------------------------------------


def test_diag_csv_alerts_nulls(diag, tmp_path):
    config = Config(db_path=str(tmp_path / "diag.db"))
    db = Database(config.db_path)

    # Row A: minimal alert -- many NULL columns by default.
    a_min = _seed_alert(
        db, mac="aa:aa:aa:aa:aa:aa", ts=1_700_000_000,
        rule_name="bare", severity="low",
    )
    # Row B: NULL mac, NULL rule_type.
    a_null_mac = _seed_alert(
        db, mac=None, ts=1_700_001_000,
        rule_name="no-mac", severity="med", rule_type=None,
    )
    # Row C: note set, note_updated_at NULL (allowed schema-wise).
    a_note_no_ts = _seed_alert(
        db, mac="bb:bb:bb:bb:bb:bb", ts=1_700_002_000,
        rule_name="note-only", severity="high",
        note="operator note", note_updated_at=None,
    )
    # Row D: note + note_updated_at set.
    a_note_full = _seed_alert(
        db, mac="cc:cc:cc:cc:cc:cc", ts=1_700_003_000,
        rule_name="note-full", severity="high",
        note="annotated", note_updated_at=1_700_003_500,
    )
    diag.fixture("seeded 4 alerts spanning NULL-column combinations")

    app = create_app(config, db)
    with TestClient(app) as client:
        diag.exercise("GET /alerts.csv")
        r = client.get("/alerts.csv")
    diag.observed(f"status: {r.status_code}")
    diag.observed(f"Content-Disposition: {r.headers.get('content-disposition')}")

    header, data = _parse_csv(r.text)
    diag.observed(f"header ({len(header)} cols): {header}")
    diag.observed(f"data row count: {len(data)}")
    for row in data:
        named = dict(zip(header, row, strict=True))
        diag.observed(f"--- row id={named['id']} rule_name={named['rule_name']!r} ---")
        for col, val in named.items():
            diag.observed(f"  {col}: {val!r}")
    diag.notes("Empty string is the writer's NULL stand-in (app.py:1509). "
               "ts_iso_utc empty string would indicate ts itself was NULL; "
               "alerts.ts is NOT NULL in the schema, so that column should "
               "always populate.")
    db.close()


# ---------------------------------------------------------------------------
# Test 2 — HTML /alerts vs CSV /alerts.csv parity under identical filters
# ---------------------------------------------------------------------------


def test_diag_csv_filter_parity(diag, tmp_path):
    config = Config(db_path=str(tmp_path / "diag.db"))
    db = Database(config.db_path)

    # Seed: 12 alerts spread across severities and timestamps.
    ids = []
    base_ts = 1_700_000_000
    for i in range(12):
        sev = ("low", "med", "high")[i % 3]
        ids.append(_seed_alert(
            db, mac=f"aa:aa:aa:aa:aa:{i:02x}", ts=base_ts + i * 60,
            rule_name=f"diag-{i}", severity=sev,
        ))
    diag.fixture(f"seeded {len(ids)} alerts; severities cycle low/med/high")

    app = create_app(config, db)
    filters = {"severity": "high"}
    with TestClient(app) as client:
        diag.exercise(f"GET /alerts {filters!r} and /alerts.csv {filters!r}")
        html = client.get("/alerts", params=filters)
        csv_resp = client.get("/alerts.csv", params=filters)

    diag.observed(f"HTML status: {html.status_code}")
    diag.observed(f"CSV status: {csv_resp.status_code}")

    # Pull alert ids out of the HTML by scanning for /alerts/<id> links.
    import re
    html_ids = sorted(
        int(m.group(1)) for m in re.finditer(r'/alerts/(\d+)', html.text)
    )
    diag.observed(f"HTML alert link ids (deduped+sorted): "
                  f"{sorted(set(html_ids))}")

    header, data = _parse_csv(csv_resp.text)
    csv_ids = sorted(int(row[0]) for row in data)
    diag.observed(f"CSV row ids (sorted): {csv_ids}")

    in_html_only = sorted(set(html_ids) - set(csv_ids))
    in_csv_only = sorted(set(csv_ids) - set(html_ids))
    diag.observed(f"in HTML only: {in_html_only}")
    diag.observed(f"in CSV only: {in_csv_only}")
    diag.observed("action_taken column values per CSV row:")
    for row in data:
        diag.observed(f"  id={row[0]} action_taken={row[-1]!r}")

    diag.notes("HTML route paginates (per_page default applies); CSV streams "
               "every matching row. ID drift between the two surfaces is "
               "expected for filtered sets larger than one page. The "
               "alert-detail page link IDs in HTML come from BOTH the visible "
               "rows AND any 'related alerts' references on the templated "
               "page -- so HTML id set may be a superset of the per-page "
               "list. Action_taken should be 'false' across the board since "
               "no allowlist file is configured.")
    db.close()


# ---------------------------------------------------------------------------
# Test 3 — datetime format consistency at boundary timestamps
# ---------------------------------------------------------------------------


def test_diag_csv_datetime_formats(diag, tmp_path):
    config = Config(db_path=str(tmp_path / "diag.db"))
    db = Database(config.db_path)

    # Boundary timestamps -- offline reviewer compares the CSV's chosen
    # rendering against the documented contract.
    test_ts = [
        ("epoch", 0),
        ("y2k_midnight_utc", 946_684_800),   # 2000-01-01T00:00:00Z
        ("northern_dst_spring_2026", 1_741_672_800),  # 2026-03-11T02:00:00Z (US DST start)
        ("northern_dst_fall_2026", 1_762_232_400),    # 2026-11-01T01:00:00Z (US DST end)
        ("pre_y2038_window", 2_147_483_640),
        ("post_y2038_window", 2_147_483_700),  # crosses 32-bit boundary
    ]
    seeded_map: dict[int, str] = {}
    for label, ts in test_ts:
        aid = _seed_alert(
            db, mac=f"de:ad:be:ef:00:{(ts % 256):02x}", ts=ts,
            rule_name=label, severity="low",
        )
        seeded_map[aid] = label
    diag.fixture(f"seeded {len(test_ts)} alerts at boundary timestamps "
                 f"(epoch, Y2K, US DST edges, Y2038 boundary)")

    app = create_app(config, db)
    with TestClient(app) as client:
        diag.exercise("GET /alerts.csv (full unfiltered export)")
        r = client.get("/alerts.csv")
    diag.observed(f"status: {r.status_code}")

    header, data = _parse_csv(r.text)
    by_id = {int(row[0]): row for row in data}
    diag.observed("CSV ts_iso_utc + ts_unix per seeded alert:")
    for aid in sorted(seeded_map):
        row = by_id.get(aid)
        if row is None:
            diag.observed(f"  id={aid} ({seeded_map[aid]}) -- MISSING FROM CSV")
            continue
        named = dict(zip(header, row, strict=True))
        diag.observed(f"  id={aid} ({seeded_map[aid]}): "
                      f"ts_iso_utc={named['ts_iso_utc']!r} "
                      f"ts_unix={named['ts_unix']!r} "
                      f"note_updated_at_iso_utc={named['note_updated_at_iso_utc']!r}")

    diag.notes("CSV writer at app.py:1486 formats via "
               "datetime.fromtimestamp(ts, tz=UTC).strftime('%Y-%m-%dT%H:%M:%SZ'). "
               "Reviewer: confirm output uses UTC (no local-tz drift), the "
               "'Z' suffix is present, and Y2038-boundary timestamps render "
               "without overflow on the target platform.")
    db.close()
