"""Regression: D2 — drone Remote-ID serials match by LEADING-SUBSTRING
(prefix), not equality, and a separator-bearing captured serial is
STRIPPED rather than rejected (Argus MAC-357).

Guards the fix in fix(rules): match drone_id_prefix by leading-substring
and strip separators on captured serials. Exercises every drone match
site that changed — the obs coercion (kismet._coerce_drone_id_prefix),
the DB eval + annotation resolvers (db._lookup_drone_id_prefix_match),
the in-memory rule path (rules.evaluate), and the allowlist mirror
(allowlist._entry_matches) — plus a negative guard that the shared
equality matcher for every OTHER pattern_type is untouched.

Sample serials are Argus-provided real Remote-ID forms:
  1787F03BM23030002222  (Commaris, 20 chars)
  1748FEV3HMA1114680    (Autel,    18 chars)
  1581F836              (DJI prefix; a real DJI wire serial extends it)
"""

from __future__ import annotations

import pytest

from lynceus.allowlist import Allowlist, AllowlistEntry
from lynceus.db import Database
from lynceus.kismet import DeviceObservation, _coerce_drone_id_prefix
from lynceus.patterns import normalize_pattern
from lynceus.rules import Rule, Ruleset, evaluate

COMMARIS = "1787F03BM23030002222"
AUTEL = "1748FEV3HMA1114680"
DJI_PREFIX = "1581F836"
DJI_WIRE_SERIAL = "1581F836BM2303000222"  # a real serial that extends DJI_PREFIX


@pytest.fixture
def db(tmp_path):
    d = Database(str(tmp_path / "d2.db"))
    yield d
    d.close()


def _add_drone(db: Database, pattern: str, severity: str = "high") -> int:
    with db._conn:
        cur = db._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
            "VALUES (?, 'drone_id_prefix', ?, NULL)",
            (pattern, severity),
        )
    return int(cur.lastrowid)


def _drone_obs(drone_id_prefix: str | None) -> DeviceObservation:
    return DeviceObservation(
        mac="aa:bb:cc:dd:ee:ff",
        device_type="remote_id",
        first_seen=1700000000,
        last_seen=1700000100,
        rssi=-50,
        ssid=None,
        oui_vendor=None,
        is_randomized=False,
        drone_id_prefix=drone_id_prefix,
    )


# ---- coercion: strip-not-reject -------------------------------------------


def test_coerce_strips_hyphens_then_keeps_serial():
    # The reject-on-non-alnum bug dropped this to None before any match.
    assert _coerce_drone_id_prefix("1581F836-0001-2222") == "1581F83600012222"


def test_coerce_strips_surrounding_whitespace():
    assert _coerce_drone_id_prefix(f"  {AUTEL}  ") == AUTEL


def test_coerce_strips_nul_padding():
    # Fixed-width wire fields pad with NUL; strip it, don't reject.
    assert _coerce_drone_id_prefix(f"{COMMARIS}\x00\x00") == COMMARIS


def test_coerce_uppercases_after_strip():
    assert _coerce_drone_id_prefix("1581f836-bm2303") == "1581F836BM2303"


def test_coerce_genuine_garbage_still_rejected():
    # '*' and '#' are not in the separator set, so they survive the strip
    # and the result is still not clean alnum -> rejected.
    assert _coerce_drone_id_prefix("15*81F#836") is None
    # All-separator / empty-after-strip -> too short -> rejected.
    assert _coerce_drone_id_prefix("----") is None
    # Non-ASCII alphanumerics are rejected (isascii guard).
    assert _coerce_drone_id_prefix("café-drone") is None


# ---- DB eval resolver: prefix + longest-match -----------------------------


def test_eval_real_serial_extending_prefix_hits(db):
    wid = _add_drone(db, DJI_PREFIX)
    match = db.resolve_matched_drone_id_prefix_for_eval(DJI_WIRE_SERIAL)
    assert match is not None, "a wire serial extending the stored prefix must HIT"
    assert match.watchlist_id == wid


def test_eval_exact_prefix_still_hits(db):
    # A serial equal to the stored prefix is a degenerate leading substring.
    wid = _add_drone(db, DJI_PREFIX)
    match = db.resolve_matched_drone_id_prefix_for_eval(DJI_PREFIX)
    assert match is not None
    assert match.watchlist_id == wid


def test_eval_non_leading_serial_misses(db):
    _add_drone(db, DJI_PREFIX)
    # Shares no leading substring -> no match.
    assert db.resolve_matched_drone_id_prefix_for_eval(AUTEL) is None


def test_eval_longest_prefix_wins_attribution(db):
    short = _add_drone(db, "1581F", severity="med")  # manufacturer-level
    long = _add_drone(db, "1581F836", severity="high")  # model-level
    db.upsert_metadata(long, {"device_category": "drone", "argus_record_id": "argus-long"})

    # A serial leading with BOTH prefixes attributes to the LONGER row.
    match = db.resolve_matched_drone_id_prefix_for_eval(DJI_WIRE_SERIAL)
    assert match is not None
    assert match.watchlist_id == long
    assert match.severity == "high"
    assert match.device_category == "drone"

    # A serial leading with only the shorter prefix falls back to it.
    only_short = db.resolve_matched_drone_id_prefix_for_eval("1581FZZZ9999")
    assert only_short is not None
    assert only_short.watchlist_id == short
    assert only_short.severity == "med"


def test_eval_remains_case_sensitive(db):
    # substr(...) = pattern uses binary collation; a lowercased serial
    # must NOT match (the caller canonicalizes via _coerce_drone_id_prefix).
    _add_drone(db, DJI_PREFIX)
    assert db.resolve_matched_drone_id_prefix_for_eval(DJI_WIRE_SERIAL.lower()) is None


# ---- DB annotation path: prefix + longest-match ---------------------------


def test_annotation_path_prefix_hit_returns_longest_row(db):
    _add_drone(db, "1581F", severity="med")
    long = _add_drone(db, "1581F836", severity="high")
    rid = db.resolve_matched_watchlist_id(mac=None, drone_id_prefix=DJI_WIRE_SERIAL)
    assert rid == long, "annotation must agree with the row that fires the rule"


# ---- in-memory rule path: prefix ------------------------------------------


def test_in_memory_rule_prefix_hit():
    rule = Rule(
        name="dji_inline",
        rule_type="watchlist_drone_id_prefix",
        severity="high",
        patterns=[DJI_PREFIX],
    )
    hits = evaluate(
        Ruleset(rules=[rule]),
        _drone_obs(DJI_WIRE_SERIAL),
        is_new_device=False,
    )
    assert len(hits) == 1
    assert hits[0].rule_name == "dji_inline"
    assert hits[0].severity == "high"


def test_in_memory_rule_non_leading_miss():
    rule = Rule(
        name="dji_inline",
        rule_type="watchlist_drone_id_prefix",
        severity="high",
        patterns=[DJI_PREFIX],
    )
    hits = evaluate(
        Ruleset(rules=[rule]),
        _drone_obs(AUTEL),
        is_new_device=False,
    )
    assert hits == []


# ---- delegation rule path (DB-backed): prefix -----------------------------


def test_delegation_rule_prefix_hit_sources_severity_from_db(db):
    _add_drone(db, DJI_PREFIX, severity="high")
    rule = Rule(
        name="dji_del",
        rule_type="watchlist_drone_id_prefix",
        severity="low",
        patterns=[],
    )
    hits = evaluate(
        Ruleset(rules=[rule]),
        _drone_obs(DJI_WIRE_SERIAL),
        is_new_device=False,
        db=db,
    )
    assert len(hits) == 1
    assert hits[0].severity == "high"  # from the DB row, not the rule


# ---- allowlist mirror: prefix suppression ---------------------------------


def test_allowlist_prefix_suppresses_extending_serial():
    entry = AllowlistEntry(pattern=DJI_PREFIX, pattern_type="drone_id_prefix")
    al = Allowlist(entries=[entry])
    matched = al.is_allowed(_drone_obs(DJI_WIRE_SERIAL))
    assert matched is not None, "a prefix-allowlisted drone must be suppressed"
    assert matched.pattern == DJI_PREFIX


def test_allowlist_prefix_does_not_suppress_unrelated_serial():
    al = Allowlist(
        entries=[AllowlistEntry(pattern=DJI_PREFIX, pattern_type="drone_id_prefix")]
    )
    assert al.is_allowed(_drone_obs(AUTEL)) is None


# ---- negative guard: non-drone pattern types stay EQUALITY -----------------


def test_non_drone_pattern_types_unaffected_by_prefix_change(db):
    """The prefix matcher is drone-only; the shared equality matcher for
    every other pattern_type must NOT have become leading-substring."""
    with db._conn:
        db._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
            "VALUES ('HomeNet', 'ssid', 'high', NULL)"
        )
    # Exact ssid still hits.
    assert db.resolve_matched_ssid_for_eval("HomeNet") is not None
    # A longer ssid that merely STARTS WITH the stored value must MISS —
    # proves ssid stayed equality and didn't inherit prefix semantics.
    assert db.resolve_matched_ssid_for_eval("HomeNetExtended") is None
