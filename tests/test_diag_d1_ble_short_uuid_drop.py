"""Diagnostic: D1 — BLE short-form (16/32-bit) service UUIDs are dropped
at observation parse, so a watchlist ble_uuid (AirTag/Tile) never fires.

VERIFY-ONLY. No production code is touched. Observation-only dump.
SOFTWARE MATCHER HALF ONLY (live Kismet field-path is rig-required).

Asymmetry under scrutiny:
  - Watchlist side (storage): patterns._normalize_ble_uuid (patterns.py:103-138)
    ACCEPTS 4-hex (16-bit) and 8-hex (32-bit) short forms and FOLDS them into
    the 128-bit base UUID per BT Core Spec §3.2.1.
  - Observation side (parse): kismet.normalize_uuid (kismet.py:202-206) requires
    an already-full 8-4-4-4-12 128-bit UUID (_UUID_RE, kismet.py:18) and does
    NO base folding. parse_kismet_device (kismet.py:478-491) drops any service
    uuid that fails normalize_uuid.
  - Match (db.py:1086-1103, resolve_matched_ble_uuid_for_eval) is exact-equality
    on the 128-bit string.

Net: a watchlist 16-bit UUID is stored base-expanded, but if Kismet emits the
short form the observation drops it before folding -> the equality match has
nothing to compare -> the rule never fires.
"""

from __future__ import annotations

import pytest

from lynceus.cli.import_argus import OverrideConfig  # noqa: F401 (parity import)
from lynceus.db import Database
from lynceus.kismet import normalize_uuid, parse_kismet_device
from lynceus.patterns import normalize_pattern

pytestmark = pytest.mark.diagnostic

# AirTag/FindMy assigned 16-bit service UUID (illustrative synthetic use of
# the 16-bit slot; exact assigned numbers are not the point — the FORM is).
SHORT_16 = "fd5a"
SHORT_32 = "0000fd5a"


def _ble_record(uuids: list[str]) -> dict:
    return {
        "kismet.device.base.macaddr": "aa:bb:cc:dd:ee:01",
        "kismet.device.base.type": "BTLE",
        "kismet.device.base.first_time": 1_700_000_000,
        "kismet.device.base.last_time": 1_700_000_100,
        "kismet.device.base.service_uuids": uuids,
    }


def test_diag_d1_ble_short_uuid_drop(diag, tmp_path):
    # ---- 1. normalizer asymmetry --------------------------------------
    diag.section("normalizer asymmetry: watchlist folds, obs rejects")
    folded_16 = normalize_pattern("ble_uuid", SHORT_16)
    folded_32 = normalize_pattern("ble_uuid", SHORT_32)
    diag.observed(
        f"watchlist normalize_pattern('ble_uuid','{SHORT_16}') -> {folded_16!r}"
    )
    diag.observed(
        f"watchlist normalize_pattern('ble_uuid','{SHORT_32}') -> {folded_32!r}"
    )
    for form in (SHORT_16, SHORT_32, "0x" + SHORT_16):
        try:
            r = normalize_uuid(form)
            diag.observed(f"obs normalize_uuid({form!r}) -> {r!r} (accepted)")
        except ValueError as e:
            diag.observed(f"obs normalize_uuid({form!r}) RAISED ValueError: {e}")
    # The folded full-128 form IS accepted by the obs normalizer.
    diag.observed(
        f"obs normalize_uuid({folded_16!r}) -> "
        f"{normalize_uuid(folded_16)!r} (full-128 accepted)"
    )

    # ---- 2. parse drops short forms -----------------------------------
    diag.section("parse_kismet_device drops short-form service uuids")
    obs_mixed = parse_kismet_device(
        _ble_record([SHORT_16, SHORT_32, folded_16])
    )
    diag.observed(
        f"record service_uuids=['{SHORT_16}','{SHORT_32}','{folded_16}'] -> "
        f"obs.ble_service_uuids={list(obs_mixed.ble_service_uuids)}"
    )
    diag.observed(
        "  -> only the already-full-128 form survives; both short forms dropped"
    )

    # ---- 3. match outcome ---------------------------------------------
    diag.section("match: short-form emission -> rule never fires")
    db = Database(str(tmp_path / "d1.db"))
    with db._conn:
        db._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
            "VALUES (?, 'ble_uuid', 'high', 'watch: AirTag/Tile 16-bit UUID')",
            (folded_16,),
        )
    diag.fixture(f"watchlist ble_uuid stored as {folded_16!r}")

    # Case A: Kismet emits SHORT form (16-bit on the wire).
    obs_short = parse_kismet_device(_ble_record([SHORT_16]))
    match_short = db.resolve_matched_ble_uuid_for_eval(obs_short.ble_service_uuids)
    diag.observed(
        f"Kismet emits short '{SHORT_16}': obs uuids="
        f"{list(obs_short.ble_service_uuids)} -> match="
        f"{match_short.watchlist_id if match_short else None}  (MISS)"
    )

    # Case B: Kismet emits the base-expanded 128-bit form.
    obs_full = parse_kismet_device(_ble_record([folded_16]))
    match_full = db.resolve_matched_ble_uuid_for_eval(obs_full.ble_service_uuids)
    diag.observed(
        f"Kismet emits full-128 '{folded_16}': obs uuids="
        f"{list(obs_full.ble_service_uuids)} -> match="
        f"{match_full.watchlist_id if match_full else None}  (HIT)"
    )
    db.close()

    diag.notes(
        "D1 REPRODUCES at the software-matcher level. The watchlist stores a "
        "16/32-bit ble_uuid in base-expanded 128-bit form; the observation "
        "parser (kismet.normalize_uuid) rejects anything that is not already "
        "a full 128-bit UUID and does NOT perform the base-UUID folding, so a "
        "short-form service UUID is dropped at parse (kismet.py:489-490) "
        "before it can be folded or matched. The equality matcher "
        "(db.py:1100) then has nothing to compare and the rule never fires. "
        "The miss/hit hinges entirely on which FORM Kismet emits in "
        "kismet.device.base.service_uuids. "
        "LIVE PATH UNVERIFIED -- needs rig (Kismet field-path confirmation)."
    )
