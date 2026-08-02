"""Diagnostic: D2 — drone_id_prefix is matched by whole-string EQUALITY,
not by prefix, so a watchlist 'DJI' never matches an observed 'DJIABC123'.

VERIFY-ONLY. No production code is touched. Observation-only dump.
SOFTWARE MATCHER HALF ONLY (live Kismet field-path is rig-required).

Path under scrutiny:
  - Match (db.py:1145-1168, resolve_matched_drone_id_prefix_for_eval) delegates
    to _lookup_simple_watchlist_match('drone_id_prefix', drone_id) ==
    `WHERE pattern_type=? AND pattern=?` -- EXACT equality. The docstring
    states it outright: "Matching is exact-equality on the prefix string ...
    startswith-style matching against a longer observed serial number would
    need a separate range/prefix matcher -- that is future work."
  - Allowlist mirror (allowlist.py:161-165) is also equality:
    `obs.drone_id_prefix == entry.pattern`.
  - Obs coercion (kismet._coerce_drone_id_prefix, kismet.py:405-419) uppercases
    and requires isalnum, so a hyphenated serial is dropped entirely.
"""

from __future__ import annotations

import pytest

from lynceus.db import Database
from lynceus.kismet import _coerce_drone_id_prefix
from lynceus.patterns import normalize_pattern

pytestmark = pytest.mark.diagnostic


def test_diag_d2_drone_prefix_equality(diag, tmp_path):
    # ---- 1. store + coerce forms --------------------------------------
    diag.section("watchlist store form + observation coercion")
    stored = normalize_pattern("drone_id_prefix", "DJI")
    diag.observed(f"watchlist normalize_pattern('drone_id_prefix','DJI') -> {stored!r}")
    for raw in ("DJIABC123", "DJI-ABC123", "dji", "DJI"):
        coerced = _coerce_drone_id_prefix(raw)
        diag.observed(f"obs _coerce_drone_id_prefix({raw!r}) -> {coerced!r}")
    diag.observed(
        "  -> note 'DJI-ABC123' coerces to None (hyphen fails isalnum) and "
        "never reaches the matcher at all"
    )

    # ---- 2. match: equality, not prefix -------------------------------
    diag.section("match: 'DJI' watch vs longer observed serial")
    db = Database(str(tmp_path / "d2.db"))
    with db._conn:
        db._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
            "VALUES (?, 'drone_id_prefix', 'high', 'watch: DJI drones')",
            (stored,),
        )
    diag.fixture(f"watchlist drone_id_prefix stored as {stored!r}")

    obs_long = _coerce_drone_id_prefix("DJIABC123")  # starts with DJI
    m_long = db.resolve_matched_drone_id_prefix_for_eval(obs_long)
    diag.observed(
        f"observed serial {obs_long!r} (starts with 'DJI') -> match="
        f"{m_long.watchlist_id if m_long else None}  (MISS -- prefix "
        f"semantics do NOT hold)"
    )

    obs_exact = _coerce_drone_id_prefix("DJI")  # exactly the stored value
    m_exact = db.resolve_matched_drone_id_prefix_for_eval(obs_exact)
    diag.observed(
        f"observed serial {obs_exact!r} (exactly 'DJI') -> match="
        f"{m_exact.watchlist_id if m_exact else None}  (HIT -- equality only)"
    )
    db.close()

    diag.notes(
        "D2 REPRODUCES at the software-matcher level. Despite the pattern_type "
        "being named 'drone_id_prefix', the matcher is whole-string equality "
        "(db.py:1168 via _lookup_simple_watchlist_match) -- confirmed by its "
        "own docstring, which defers startswith matching to 'future work'. A "
        "watchlist entry 'DJI' fires only on an observed serial that is "
        "EXACTLY 'DJI', not on 'DJIABC123'. Whether real Remote-ID serials "
        "arrive as a bare manufacturer prefix ('DJI') or a full serial "
        "('DJIABC123...') determines whether this matters operationally -- and "
        "that is the rig question. The allowlist mirror (allowlist.py:161-165) "
        "has the same equality semantics, so suppression and alerting agree "
        "(neither does prefix matching). "
        "LIVE PATH UNVERIFIED -- needs rig (Kismet field-path confirmation)."
    )
