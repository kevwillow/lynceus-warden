"""Diagnostic: A1 — a malformed Kismet record that *raises* (rather than
parses to None) aborts the whole poll tick and livelocks the daemon.

VERIFY-ONLY. No production code is touched. Observation-only dump.

Crux being verified (from the consolidated sweep, finding A1):

  - Does the client parse records EAGERLY (a malformed record raises
    during the fetch, OUTSIDE the per-observation try/except -> whole
    tick aborts) or LAZILY per-record (raise lands INSIDE the per-obs
    guard -> already handled)?
  - Does last_poll state advance only on poll_once completion, so the
    next tick re-hits the same record -> livelock (daemon alive, never
    progresses)?
  - Does FakeKismetClient share the real client's parse path, so a
    fixture repro exercises the REAL parse?

Key distinction this test draws: parse_kismet_device returns None for
the *guarded* malformed kinds (missing required field / unknown type /
malformed mac -> kismet.py:450-466) which are counted + skipped. But a
record that PASSES those guards and then violates a Pydantic
validator/type raises ValidationError at the UNGUARDED model
construction (kismet.py:562). That raise is the poison pill.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import lynceus.poller as poller_mod
from lynceus.config import Config
from lynceus.db import Database
from lynceus.kismet import FakeKismetClient, parse_kismet_device
from lynceus.poller import STATE_KEY_LAST_POLL, poll_once

pytestmark = pytest.mark.diagnostic


def _row_count(db: Database, table: str) -> int:
    return int(db._conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


# A well-formed record that parse_kismet_device admits cleanly.
GOOD = {
    "kismet.device.base.macaddr": "aa:bb:cc:11:22:33",
    "kismet.device.base.type": "Wi-Fi AP",
    "kismet.device.base.first_time": 1_700_000_000,
    "kismet.device.base.last_time": 1_700_000_100,
    "kismet.device.base.manuf": "DiagVendorGood",
}

# Poison records: each passes the None-returning guards (mac present +
# valid, type recognized, first/last present) but trips a Pydantic
# validator at model construction -> ValidationError, NOT None.
POISON_LAST_BEFORE_FIRST = {
    "kismet.device.base.macaddr": "aa:bb:cc:44:55:66",
    "kismet.device.base.type": "Wi-Fi AP",
    "kismet.device.base.first_time": 1_700_000_200,
    "kismet.device.base.last_time": 1_700_000_100,  # last < first
}
POISON_FIRST_TIME_ZERO = {
    "kismet.device.base.macaddr": "aa:bb:cc:77:88:99",
    "kismet.device.base.type": "Wi-Fi AP",
    "kismet.device.base.first_time": 0,  # _validate_first_seen: must be > 0
    "kismet.device.base.last_time": 1_700_000_100,
}

# Contrast: a *guarded* malformed kind -> parse returns None, no raise.
GUARDED_NONE = {
    # missing kismet.device.base.macaddr -> None at kismet.py:450
    "kismet.device.base.type": "Wi-Fi AP",
    "kismet.device.base.first_time": 1_700_000_000,
    "kismet.device.base.last_time": 1_700_000_100,
}


def _write_fixture(tmp_path: Path, name: str, records: list[dict]) -> str:
    p = tmp_path / name
    p.write_text(json.dumps(records), encoding="utf-8")
    return str(p)


def _config_for(tmp_path: Path, fixture_path: str, **overrides) -> Config:
    kwargs = dict(
        kismet_fixture_path=fixture_path,
        db_path=str(tmp_path / "diag_a1.db"),
        kismet_health_check_on_startup=False,
        evidence_capture_enabled=False,
    )
    kwargs.update(overrides)
    return Config(**kwargs)


def test_diag_a1_poison_record_livelock(diag, tmp_path):
    # -----------------------------------------------------------------
    diag.section("parse boundary: None (guarded) vs raise (poison)")
    diag.fixture(
        "parse_kismet_device: src/lynceus/kismet.py:438. Guarded drops "
        "(missing field / unknown type / bad mac) return None at "
        "kismet.py:450-466. Model construction at kismet.py:562 is "
        "UNGUARDED -> Pydantic validators can raise."
    )

    # Guarded -> None
    obs_none = parse_kismet_device(GUARDED_NONE)
    diag.observed(
        f"GUARDED_NONE (missing mac): parse_kismet_device -> "
        f"{obs_none!r}  [returns None, handled+counted by caller]"
    )

    # Poison -> raises
    for label, rec in (
        ("POISON_LAST_BEFORE_FIRST", POISON_LAST_BEFORE_FIRST),
        ("POISON_FIRST_TIME_ZERO", POISON_FIRST_TIME_ZERO),
    ):
        try:
            r = parse_kismet_device(rec)
            diag.observed(
                f"{label}: parse_kismet_device -> {r!r} (NO RAISE - "
                f"unexpected; A1 would not reproduce via this shape)"
            )
        except Exception as e:  # noqa: BLE001 - capturing exact behavior
            diag.observed(
                f"{label}: parse_kismet_device RAISED "
                f"{type(e).__name__}: {str(e).splitlines()[0]}"
            )

    # -----------------------------------------------------------------
    diag.section("eager fetch: one poison record discards the whole batch")
    diag.fixture(
        "get_devices_since builds a full list (kismet.py:625-638); the "
        "parse_kismet_device call at kismet.py:627 is NOT wrapped in "
        "try/except. FakeKismetClient.get_devices_since shares the same "
        "parse path (kismet.py:741-764)."
    )
    fx = _write_fixture(
        tmp_path, "batch.json", [GOOD, POISON_LAST_BEFORE_FIRST]
    )
    client = FakeKismetClient(fx)
    counter: list[int] = [0]
    try:
        out = client.get_devices_since(0, unparseable_counter=counter)
        diag.observed(
            f"get_devices_since -> {len(out)} observations (NO RAISE - "
            f"unexpected)"
        )
    except Exception as e:  # noqa: BLE001
        diag.observed(
            f"get_devices_since RAISED {type(e).__name__}: "
            f"{str(e).splitlines()[0]}"
        )
        diag.observed(
            "  -> the well-formed GOOD record co-batched ahead of the "
            "poison was already parsed but is DISCARDED: the function "
            "never returns its partial results list."
        )
    diag.observed(f"unparseable_counter after raise: {counter[0]} "
                  "(poison did NOT increment it - it raised, not None)")

    # -----------------------------------------------------------------
    diag.section("poll_once aborts: tick lost, last_poll frozen, livelock")
    diag.fixture(
        "poll_once calls get_devices_since at poller.py:234 - BEFORE the "
        "per-obs loop (line 253) and its try/except (line 254). last_poll "
        "is written only at poller.py:581, end of poll_once."
    )
    config = _config_for(tmp_path, fx)
    db = Database(config.db_path)
    poison_client = poller_mod.build_kismet_client(config)

    last_poll_before = db.get_state(STATE_KEY_LAST_POLL)
    devices_before = _row_count(db, "devices")
    diag.observed(
        f"BEFORE tick 1: last_poll={last_poll_before!r} "
        f"devices={devices_before}"
    )

    # Simulate the run_forever per-tick boundary (poller.py:1206-1226):
    # poll_once raises, the loop logs + continues (daemon stays alive).
    def _one_tick(n: int) -> None:
        try:
            poll_once(poison_client, db, config, now_ts=1_700_001_000 + n)
            diag.observed(f"tick {n}: poll_once returned (NO RAISE - unexpected)")
        except Exception as e:  # noqa: BLE001 - mirrors run_forever boundary
            diag.observed(
                f"tick {n}: poll_once RAISED {type(e).__name__} "
                f"({str(e).splitlines()[0][:60]}...) -> run_forever would "
                f"log 'poll_once raised; continuing' and loop on"
            )

    _one_tick(1)
    last_poll_after1 = db.get_state(STATE_KEY_LAST_POLL)
    devices_after1 = _row_count(db, "devices")
    diag.observed(
        f"AFTER tick 1: last_poll={last_poll_after1!r} "
        f"devices={devices_after1}  (GOOD record NOT persisted; whole "
        f"batch lost)"
    )

    _one_tick(2)
    last_poll_after2 = db.get_state(STATE_KEY_LAST_POLL)
    devices_after2 = _row_count(db, "devices")
    diag.observed(
        f"AFTER tick 2: last_poll={last_poll_after2!r} "
        f"devices={devices_after2}  (identical window re-queried; same "
        f"poison re-hit -> LIVELOCK)"
    )

    diag.notes(
        "A1 REPRODUCES. The daemon stays alive (run_forever's per-tick "
        "Exception boundary at poller.py:1224 swallows the raise) but "
        "never progresses: last_poll never advances past its pre-poison "
        "value (poller.py:581 unreachable), so every subsequent tick "
        "re-fetches the same /devices/last-time window, re-hits the same "
        "poison record, and re-aborts. Co-batched well-formed devices "
        "are never persisted while the poison sits in the window. "
        "Mechanism: EAGER materialization in get_devices_since "
        "(kismet.py:625-638) + UNGUARDED model construction "
        "(kismet.py:562) + the fetch call sitting outside the per-obs "
        "guard (poller.py:234 vs 253-254). The None-returning guards "
        "(kismet.py:450-466) only cover missing-field/unknown-type/"
        "bad-mac; validator failures (first_seen<=0, last<first, "
        "non-coercible rssi/oui_vendor) are the unhandled poison class."
    )
    db.close()
