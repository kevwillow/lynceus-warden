"""Diagnostic trace for the daemon Kismet polling chain (smoke finding #5).

Smoke v0.7.2: the dashboard /devices list is empty despite Kismet
actively seeing devices. Determines whether the issue is daemon-level
(poller never persists), parse-level (Kismet record shape not
admitted), filter-level (source_allowlist / min_rssi silently drops),
or UI-level (devices route renders nothing despite populated DB).

The "highest-priority diagnostic" per the prompt — it disambiguates
which layer is at fault.

Two halves:

  Half A — happy path against a recorded fixture
      tests/fixtures/kismet_devices.json (6 records covering wifi,
      ble, bt_classic, RTL433 [parser-rejected], from 3 distinct
      Kismet sources). Run one poll_once tick against a fresh DB
      with default Config; trace every SQL statement; dump device /
      sighting counts before + after.

  Half B — edge cases via hand-built records
      Empty list. Records missing required fields. Records with a
      device type not in kismet._TYPE_MAP. Each fed through the real
      parse_kismet_device + poll_once pipeline; dump what gets
      swallowed, what surfaces, what raises.

ALSO instrument the two daemon-side silent-drop gates the wizard's
step-4 warning calls out:

  - source_allowlist: kismet_sources != obs.seen_by_sources
  - min_rssi: obs.rssi < config.min_rssi

These are the most likely root causes for "devices empty" if the
fixture-fed happy path succeeds — the operator's lynceus.yaml
kismet_sources value mismatches Kismet's source name (silent drop)
or the floor is set too aggressively.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import lynceus.poller as poller_mod
from lynceus.config import Config
from lynceus.db import Database
from lynceus.kismet import _TYPE_MAP, parse_kismet_device
from lynceus.poller import poll_once

pytestmark = pytest.mark.diagnostic


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "kismet_devices.json"


def _row_count(db: Database, table: str) -> int:
    return int(db._conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


def _trace_sql(db: Database, captured: list[str]) -> None:
    """Capture every SQL statement the poller's DB connection executes.
    Re-registering trace_callback is allowed; the lambda just appends."""
    db._conn.set_trace_callback(captured.append)


def _config_for(tmp_path: Path, **overrides) -> Config:
    """Build a Config that points at FakeKismetClient via
    kismet_fixture_path so build_kismet_client returns the fake. All
    other fields default; tests pass kwargs to override the silent-
    drop gates explicitly."""
    kwargs = dict(
        kismet_fixture_path=str(FIXTURE_PATH),
        db_path=str(tmp_path / "diag.db"),
        kismet_health_check_on_startup=False,
        evidence_capture_enabled=False,
    )
    kwargs.update(overrides)
    return Config(**kwargs)


# ---------------------------------------------------------------------------
# Single test, multi-section. One log artifact at
# tests/diagnostic_output/test_diag_daemon_kismet_polling.log
# ---------------------------------------------------------------------------


def test_diag_daemon_kismet_polling(diag, tmp_path, monkeypatch):
    # -----------------------------------------------------------------
    # Section 1 — code-path map
    # -----------------------------------------------------------------
    diag.section("code path: where poll_once writes")
    diag.fixture("entry point: src/lynceus/poller.py:136 poll_once")
    diag.fixture(
        "kismet client: src/lynceus/poller.py:126 build_kismet_client — "
        "returns FakeKismetClient when config.kismet_fixture_path is set"
    )
    diag.fixture(
        "observation parse: src/lynceus/kismet.py:416 parse_kismet_device — "
        "returns None on missing required fields, unknown device type, "
        "or malformed MAC. Silently swallowed by the caller."
    )
    diag.fixture(
        "silent-drop gate 1 (source_allowlist): poller.py:185-198 — "
        "every observation whose seen_by_sources has NO entry in "
        "source_allowlist is skipped via `continue` with one DEBUG line; "
        "no row written to any table."
    )
    diag.fixture(
        "silent-drop gate 2 (min_rssi): poller.py:199-206 — "
        "observations below config.min_rssi are skipped via `continue` "
        "with one DEBUG line."
    )
    diag.fixture(
        "happy-path writes per surviving observation: "
        "db.ensure_location, db.get_device (read), db.upsert_device, "
        "db.merge_device_probe_ssids (gated on capture.probe_ssids + "
        "obs.probe_ssids), db.update_device_ble_name (gated on "
        "capture.ble_friendly_names + obs.ble_local_name), "
        "db.insert_sighting. Then allowlist + rules + alerts."
    )

    # -----------------------------------------------------------------
    # Section 2 — happy path: fixture, default Config, empty DB
    # -----------------------------------------------------------------
    diag.section("happy path: FakeKismetClient + kismet_devices.json")
    config = _config_for(tmp_path)
    db = Database(config.db_path)
    client = poller_mod.build_kismet_client(config)
    diag.fixture(f"fixture path: {FIXTURE_PATH}")
    diag.fixture(f"fixture record count: {len(client._fixture)}")
    for i, raw in enumerate(client._fixture):
        # Real Kismet shape: the source name is nested in
        # kismet.common.seenby.source — a dict of kismet.datasource.*
        # keys. Walk the nested dict; on legacy bare-string sources
        # use the string directly.
        seenby = []
        for s in raw.get("kismet.device.base.seenby", []):
            source = s.get("kismet.common.seenby.source")
            if isinstance(source, dict):
                seenby.append(source.get("kismet.datasource.name"))
            elif isinstance(source, str):
                seenby.append(source)
            else:
                seenby.append(None)
        diag.fixture(
            f"  raw[{i}] mac={raw.get('kismet.device.base.macaddr')!r} "
            f"type={raw.get('kismet.device.base.type')!r} "
            f"seenby={seenby}"
        )

    # Pre-flight: how many fixture records would parse_kismet_device
    # admit at all (independent of poller filters)?
    admit = []
    drop = []
    for raw in client._fixture:
        obs = parse_kismet_device(raw)
        if obs is None:
            drop.append(raw.get("kismet.device.base.macaddr"))
        else:
            admit.append(
                f"mac={obs.mac} type={obs.device_type} rssi={obs.rssi} "
                f"seen_by_sources={list(obs.seen_by_sources)}"
            )
    diag.observed(f"parse_kismet_device admits: {len(admit)} of {len(client._fixture)}")
    for line in admit:
        diag.observed(f"  ADMIT {line}")
    diag.observed(f"parse_kismet_device drops: {drop}")
    diag.observed(
        "  (Drops are silent — parse returns None for unknown device "
        "type, e.g. RTL433. _TYPE_MAP keys today: "
        f"{sorted(_TYPE_MAP.keys())})"
    )

    devices_before = _row_count(db, "devices")
    sightings_before = _row_count(db, "sightings")
    diag.observed(
        f"DB rows BEFORE poll_once: devices={devices_before} "
        f"sightings={sightings_before}"
    )

    captured: list[str] = []
    _trace_sql(db, captured)
    processed = poll_once(client, db, config, now_ts=1_700_001_000)
    devices_after = _row_count(db, "devices")
    sightings_after = _row_count(db, "sightings")
    diag.observed(f"poll_once returned processed={processed}")
    diag.observed(
        f"DB rows AFTER poll_once:  devices={devices_after} "
        f"sightings={sightings_after}"
    )
    # The fixture has 6 records; RTL433 is parser-rejected so 5 admit;
    # all 5 carry rssi well above the default (no min_rssi); source_
    # allowlist is None (no filter). Expected: 5 devices, 5 sightings.
    insert_sqls = [s for s in captured if s.strip().upper().startswith(("INSERT", "UPDATE"))]
    diag.observed(f"INSERT/UPDATE statements emitted: {len(insert_sqls)}")
    for s in insert_sqls[:30]:
        diag.observed(f"  {s.strip()[:200]}")

    # Dump every persisted device so the reviewer can see the schema +
    # values without re-running a query themselves.
    diag.observed("--- persisted devices (post-tick) ---")
    for row in db._conn.execute(
        "SELECT mac, device_type, first_seen, last_seen, sighting_count, "
        "oui_vendor, is_randomized, ble_name, probe_ssids FROM devices"
    ):
        diag.observed(f"  {dict(row)}")
    diag.observed("--- persisted sightings (post-tick) ---")
    for row in db._conn.execute(
        "SELECT mac, ts, rssi, ssid, location_id FROM sightings"
    ):
        diag.observed(f"  {dict(row)}")
    db.close()

    # -----------------------------------------------------------------
    # Section 3 — silent drop via source_allowlist (smoke finding #5
    # most-likely root cause).
    # -----------------------------------------------------------------
    diag.section("silent drop: source_allowlist mismatches every record")
    diag.fixture(
        "source_allowlist=frozenset({'NONEXISTENT-SOURCE'}) — no fixture "
        "record's seen_by_sources contains this string. Mirrors the "
        "production failure mode where the operator's lynceus.yaml "
        "kismet_sources lists 'external_wifi' but Kismet's source "
        "config has `source=wlan1:name=external` (no _wifi)."
    )
    config2 = _config_for(tmp_path / "case2")
    db2 = Database(config2.db_path)
    client2 = poller_mod.build_kismet_client(config2)
    processed2 = poll_once(
        client2,
        db2,
        config2,
        now_ts=1_700_001_000,
        source_allowlist=frozenset({"NONEXISTENT-SOURCE"}),
    )
    diag.observed(f"poll_once returned processed={processed2}")
    diag.observed(
        f"DB rows AFTER: devices={_row_count(db2, 'devices')} "
        f"sightings={_row_count(db2, 'sightings')}"
    )
    diag.observed(
        "  -> EVERY record dropped silently at poller.py:192 with one "
        "DEBUG line per drop ('obs %s sources %r not in allowlist'). "
        "The dashboard /devices page sees an empty devices table and "
        "renders 'No devices match the current filter.' even though "
        "Kismet was actively returning records."
    )
    db2.close()

    # -----------------------------------------------------------------
    # Section 4 — silent drop via min_rssi
    # -----------------------------------------------------------------
    diag.section("silent drop: min_rssi above every record's signal")
    config3 = _config_for(tmp_path / "case3", min_rssi=0)
    db3 = Database(config3.db_path)
    client3 = poller_mod.build_kismet_client(config3)
    diag.fixture(
        "min_rssi=0 (every Kismet RSSI is negative dBm, so every "
        "obs.rssi < 0 < min_rssi). Mirrors the operator typo where "
        "the wizard slider was set to +0 instead of -75."
    )
    processed3 = poll_once(client3, db3, config3, now_ts=1_700_001_000)
    diag.observed(f"poll_once returned processed={processed3}")
    diag.observed(
        f"DB rows AFTER: devices={_row_count(db3, 'devices')} "
        f"sightings={_row_count(db3, 'sightings')}"
    )
    diag.observed(
        "  -> EVERY record dropped silently at poller.py:199 with one "
        "DEBUG line per drop ('obs %s rssi=%s below min_rssi=%s'). "
        "Operationally indistinguishable from the source_allowlist "
        "drop above without DEBUG logging enabled."
    )
    db3.close()

    # -----------------------------------------------------------------
    # Section 5 — empty response handling
    # -----------------------------------------------------------------
    diag.section("edge: empty kismet response")
    config4 = _config_for(tmp_path / "case4")
    db4 = Database(config4.db_path)
    # Stub get_devices_since to return []. The fake client's normal
    # path uses the fixture; we patch the instance method here so the
    # real poller code sees an empty observation list.
    client4 = poller_mod.build_kismet_client(config4)
    monkeypatch.setattr(
        client4,
        "get_devices_since",
        lambda *a, **kw: [],
    )
    processed4 = poll_once(client4, db4, config4, now_ts=1_700_001_000)
    diag.observed(f"poll_once with empty list returned processed={processed4}")
    diag.observed(
        f"DB rows AFTER: devices={_row_count(db4, 'devices')} "
        f"sightings={_row_count(db4, 'sightings')}"
    )
    # state.last_poll_ts should still be written even with zero
    # observations — this guards the next tick's since cursor.
    last_poll = db4.get_state("last_poll_ts")
    diag.observed(f"state.last_poll_ts after empty tick: {last_poll!r}")
    db4.close()

    # -----------------------------------------------------------------
    # Section 6 — malformed records (missing fields, bad MAC,
    # unknown device type)
    # -----------------------------------------------------------------
    diag.section("edge: malformed and unknown-type records")
    bad_records = [
        # Missing kismet.device.base.macaddr -> parse returns None.
        {
            "kismet.device.base.type": "Wi-Fi AP",
            "kismet.device.base.first_time": 1_700_000_000,
            "kismet.device.base.last_time": 1_700_000_100,
        },
        # Missing kismet.device.base.type.
        {
            "kismet.device.base.macaddr": "aa:bb:cc:dd:ee:ff",
            "kismet.device.base.first_time": 1_700_000_000,
            "kismet.device.base.last_time": 1_700_000_100,
        },
        # Malformed MAC (parse_kismet_device drops via normalize_mac
        # ValueError).
        {
            "kismet.device.base.macaddr": "not-a-mac",
            "kismet.device.base.type": "Wi-Fi AP",
            "kismet.device.base.first_time": 1_700_000_000,
            "kismet.device.base.last_time": 1_700_000_100,
        },
        # Unknown kismet device type — parse silently returns None
        # (this is exactly how RTL433 drops out today).
        {
            "kismet.device.base.macaddr": "11:22:33:44:55:66",
            "kismet.device.base.type": "Some Future Radio Family",
            "kismet.device.base.first_time": 1_700_000_000,
            "kismet.device.base.last_time": 1_700_000_100,
        },
        # New-shape record: previously-known type but no
        # kismet.device.base.signal block (Kismet builds without
        # signal-strength channels). Parse admits it with rssi=None.
        # Poll_once accepts it; the sighting row has rssi=NULL.
        {
            "kismet.device.base.macaddr": "aa:00:11:22:33:44",
            "kismet.device.base.type": "Bluetooth",
            "kismet.device.base.first_time": 1_700_000_000,
            "kismet.device.base.last_time": 1_700_000_100,
            "kismet.device.base.manuf": "DiagVendor",
            # NOTE: no kismet.device.base.signal at all.
        },
    ]
    for i, rec in enumerate(bad_records):
        obs = parse_kismet_device(rec)
        diag.observed(
            f"  bad_record[{i}]: parse_kismet_device returned "
            f"{type(obs).__name__ if obs is not None else 'None'}"
        )
        if obs is not None:
            diag.observed(
                f"    admitted: mac={obs.mac} type={obs.device_type} "
                f"rssi={obs.rssi}"
            )

    config5 = _config_for(tmp_path / "case5")
    db5 = Database(config5.db_path)
    client5 = poller_mod.build_kismet_client(config5)
    monkeypatch.setattr(
        client5,
        "get_devices_since",
        lambda *a, **kw: [
            obs for obs in (parse_kismet_device(r) for r in bad_records) if obs is not None
        ],
    )
    processed5 = poll_once(client5, db5, config5, now_ts=1_700_001_000)
    diag.observed(f"poll_once with mixed bad records returned processed={processed5}")
    diag.observed(
        f"DB rows AFTER: devices={_row_count(db5, 'devices')} "
        f"sightings={_row_count(db5, 'sightings')}"
    )
    for row in db5._conn.execute(
        "SELECT mac, device_type, oui_vendor FROM devices"
    ):
        diag.observed(f"  persisted: {dict(row)}")
    db5.close()

    # -----------------------------------------------------------------
    # Section 7 — what get_devices_since against a real (non-fake)
    # client emits. Document the HTTP shape so a future fix prompt
    # can correlate fixture content with live Kismet behavior.
    # -----------------------------------------------------------------
    diag.section("HTTP shape: real KismetClient.get_devices_since")
    diag.observed(
        "src/lynceus/kismet.py:554 KismetClient.get_devices_since issues "
        "a single GET against "
        "'{base_url}/devices/last-time/{since_ts}/devices.json' with "
        "header Cookie: KISMET=<api_key>. Response must be a JSON list; "
        "non-list raises ValueError. Per-record errors do NOT surface — "
        "parse_kismet_device returns None and the record is dropped."
    )
    diag.observed(
        "Failure modes that DO surface to poller.py:824 (via the "
        "outer try/except in run_forever): requests.RequestException "
        "(network), requests.HTTPError (non-2xx from "
        "raise_for_status), ValueError (non-list payload). Each "
        "aborts the tick but the loop continues — observable as one "
        "ERROR line per failed tick in journalctl."
    )

    diag.notes(
        "Working hypothesis for smoke #5 (dashboard /devices empty "
        "despite Kismet seeing devices), in order of likelihood:\n"
        "(a) source_allowlist mismatch — see Section 3. The wizard "
        "step-4 silent-drop warning already calls this out as the "
        "operator-error vector. Check operator's lynceus.yaml "
        "kismet_sources values against Kismet's `source=...:name=...` "
        "lines on the host.\n"
        "(b) min_rssi above signal floor — see Section 4. Less likely "
        "unless wizard slider was misconfigured.\n"
        "(c) parser drops — Section 2 shows RTL433 silently drops via "
        "_TYPE_MAP miss. If the host's Kismet emits a device type not "
        "in _TYPE_MAP (e.g. a new Bluetooth subclass), records vanish "
        "without a log line.\n"
        "(d) Kismet REST shape change — Section 7 documents the "
        "endpoint; if Kismet rev'd, the ValueError 'expected list' "
        "would show up in journalctl.\n"
        "Next-step verification: enable DEBUG logging on the operator's "
        "host and look for 'sources %r not in allowlist' OR 'rssi=%s "
        "below min_rssi'. Presence narrows to (a) or (b) immediately."
    )
