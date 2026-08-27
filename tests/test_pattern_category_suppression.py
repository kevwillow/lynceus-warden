"""Pattern-type × device-category conjunction suppression.

Closes BLE-G1: ``suppress_categories: [unknown]`` is too blunt because
80.3% of the shipped corpus is ``device_category=unknown`` — including
the ``mac_range`` and hostname rows that carry the detection that works.
The new ``suppress_pattern_categories`` runtime key lets an operator
carve ``unknown`` away from ONE pattern_type without removing it from
the product's backbone. Both halves must match — pattern_type alone
suppresses nothing, category alone does the same.

The shape deliberately mirrors ``suppress_categories`` /
``suppress_vendors`` (frozenset-style value, normalisation at load
time, INFO log on suppression, is_empty() participation) so the
operator who already knows those keys has nothing new to learn.

⛔ THE PLANT TEST at the bottom is the load-bearing one. It is written
to FAIL with the new check removed from `_apply_runtime_overrides` —
proving the test actually exercises the code it claims to cover. A
test that passes before the change is testing nothing.
"""

from __future__ import annotations

import logging

import pytest

from lynceus.db import Database
from lynceus.kismet import DeviceObservation
from lynceus.rules import (
    Rule,
    Ruleset,
    RuntimeSeverityOverride,
    _apply_runtime_overrides,
    evaluate,
    load_runtime_severity_overrides,
)

# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

# Universally-administered OUI; the reserved-OUI guard discards locally-
# administered prefixes.
# MAC's first 7 hex digits ("acde480") match the /28 prefix below.
MAC = "ac:de:48:01:00:00"
MAC_RANGE_PREFIX = "ac:de:48:0/28"  # /28 covers 16 addrs incl. MAC above
CATEGORY = "unknown"


def _ble_manuf_obs(ble_manufacturer_id: str | None = "004c") -> DeviceObservation:
    return DeviceObservation(
        mac="aa:bb:cc:dd:ee:ff",
        device_type="ble",
        first_seen=1_700_000_000,
        last_seen=1_700_000_000,
        rssi=-60,
        ssid=None,
        oui_vendor=None,
        is_randomized=False,
        ble_manufacturer_id=ble_manufacturer_id,
    )


def _mac_range_obs(mac: str = MAC) -> DeviceObservation:
    """A wifi observation carrying a MAC inside the seeded /28 prefix."""
    return DeviceObservation(
        mac=mac,
        device_type="wifi",
        first_seen=1_700_000_000,
        last_seen=1_700_000_000,
        rssi=-50,
        ssid=None,
        oui_vendor="TestCorp",
        is_randomized=False,
    )


@pytest.fixture
def db_with_mac_range_row(tmp_path):
    """One /28 mac_range row at severity 'high' with category=unknown."""
    db = Database(str(tmp_path / "pkt_suppress.db"))
    with db._conn:
        db._conn.execute(
            "INSERT INTO watchlist("
            "pattern, pattern_type, severity, description, "
            "mac_range_prefix, mac_range_prefix_length) "
            "VALUES (?, 'mac_range', ?, ?, ?, ?)",
            ("ac:de:48:0/28", "high", "test row", "acde480", 28),
        )
        wid = db._conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        db.upsert_metadata(
            wid,
            {
                "argus_record_id": "abcdef0123456789",
                "device_category": CATEGORY,
            },
        )
    yield db
    db.close()


@pytest.fixture
def db_with_ble_manuf_row(tmp_path):
    """One ble_manufacturer_id row at severity 'high' with category=unknown."""
    db = Database(str(tmp_path / "pkt_suppress_blm.db"))
    with db._conn:
        db._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
            "VALUES ('004c', 'ble_manufacturer_id', 'high', 'apple manuf')"
        )
        wid = db._conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        db.upsert_metadata(
            wid,
            {
                "argus_record_id": "deadbeefcafebabe",
                "device_category": CATEGORY,
            },
        )
    yield db
    db.close()


@pytest.fixture
def db_with_ble_manuf_row_no_metadata(tmp_path):
    """One ble_manufacturer_id row at severity 'high' with NO metadata row.

    Lets us exercise the ``match_device_category is None`` pass-through:
    a row without metadata has nothing to key the conjunction on.
    """
    db = Database(str(tmp_path / "pkt_suppress_blm_nometa.db"))
    with db._conn:
        db._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
            "VALUES ('004c', 'ble_manufacturer_id', 'high', 'apple manuf')"
        )
    yield db
    db.close()


@pytest.fixture
def db_with_ble_manuf_row_cctv_category(tmp_path):
    """One ble_manufacturer_id row with category=cctv_camera (not unknown)."""
    db = Database(str(tmp_path / "pkt_suppress_blm_cctv.db"))
    with db._conn:
        db._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
            "VALUES ('004c', 'ble_manufacturer_id', 'high', 'apple manuf')"
        )
        wid = db._conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        db.upsert_metadata(
            wid,
            {
                "argus_record_id": "f00dface11223344",
                "device_category": "cctv_camera",
            },
        )
    yield db
    db.close()


def _mac_range_rule() -> Ruleset:
    return Ruleset(
        rules=[
            Rule(
                name="argus_mac_range",
                rule_type="watchlist_mac_range",
                severity="low",
                patterns=[],
            )
        ]
    )


def _ble_manuf_rule() -> Ruleset:
    return Ruleset(
        rules=[
            Rule(
                name="del_blm",
                rule_type="watchlist_ble_manufacturer_id",
                severity="low",
                patterns=[],
            )
        ]
    )


# ---------------------------------------------------------------------------
# The model — RuntimeSeverityOverride
# ---------------------------------------------------------------------------


def test_suppress_pattern_categories_default_is_empty_dict():
    """Default field is an empty dict, mirroring the other dict-valued
    runtime keys (device_category_severity, vendor_severity, etc.)."""
    cfg = RuntimeSeverityOverride()
    assert cfg.suppress_pattern_categories == {}


def test_suppress_pattern_categories_only_is_not_empty():
    """⛔ is_empty() must include the new field. Forgetting this is the
    single most likely way to ship this broken: a file containing only
    ``suppress_pattern_categories`` would take the pass-through fast
    path and the feature would silently do nothing.
    """
    cfg = RuntimeSeverityOverride(
        suppress_pattern_categories={"mac_range": frozenset({"unknown"})}
    )
    assert not cfg.is_empty(), (
        "is_empty() ignored suppress_pattern_categories; a file with only "
        "this key would short-circuit to pass-through and never suppress"
    )


def test_suppress_pattern_categories_normalizes_keys_in_model_validator():
    """⛔ Normalisation in the MODEL, not in the loader. Keys AND set
    members both run through the shared ``normalize_override_key`` so a
    directly-constructed instance (e.g. from tests) and a YAML-loaded
    instance agree on what counts as a match.
    """
    cfg = RuntimeSeverityOverride(
        suppress_pattern_categories={"MAC_RANGE": ["Unknown", "  ALPR  ", ""]}
    )
    assert cfg.suppress_pattern_categories == {
        "mac_range": frozenset({"unknown", "alpr"})
    }


def test_suppress_pattern_categories_drops_empty_keys_in_model_validator():
    """A YAML key that normalises to None is silently dropped rather than
    crashing the model."""
    cfg = RuntimeSeverityOverride(
        suppress_pattern_categories={"": ["unknown"], "   ": ["alpr"], "mac_range": []}
    )
    assert cfg.suppress_pattern_categories == {"mac_range": frozenset()}


def test_suppress_pattern_categories_rejects_non_dict_value_silently():
    """A value that isn't a list/tuple/set/frozenset is silently dropped
    rather than crashing. The loader drops with a WARNING; the model
    silently coerces (matching the existing ``_normalize_keys`` policy
    on its neighbouring fields)."""
    cfg = RuntimeSeverityOverride(
        suppress_pattern_categories={"mac_range": "not-a-list"}
    )
    assert cfg.suppress_pattern_categories == {}


def test_combined_with_other_keys_is_not_empty():
    """The new field coexists with the existing fields."""
    cfg = RuntimeSeverityOverride(
        device_category_severity={"unknown": "med"},
        suppress_pattern_categories={"mac_range": frozenset({"unknown"})},
    )
    assert not cfg.is_empty()
    assert cfg.device_category_severity == {"unknown": "med"}
    assert cfg.suppress_pattern_categories == {"mac_range": frozenset({"unknown"})}


# ---------------------------------------------------------------------------
# _apply_runtime_overrides — the conjunction
# ---------------------------------------------------------------------------


def test_both_halves_match_suppresses():
    """Both pattern_type AND device_category match → return None."""
    cfg = RuntimeSeverityOverride(
        suppress_pattern_categories={"mac_range": frozenset({CATEGORY})}
    )
    assert (
        _apply_runtime_overrides(
            match_severity="high",
            match_pattern_type="mac_range",
            match_device_category=CATEGORY,
            match_manufacturer=None,
            match_argus_record_id=None,
            match_watchlist_id=1,
            rule_name="watchlist_mac_range",
            overrides=cfg,
        )
        is None
    )


def test_pattern_type_match_alone_does_NOT_suppress():
    """⛔ Neither half alone suppresses. The whole point of the new key:
    an entry keyed on ``ble_manufacturer_id`` must not eat a
    ``mac_range`` row even if the row's category is the one the
    operator listed under a different key.
    """
    cfg = RuntimeSeverityOverride(
        suppress_pattern_categories={"ble_manufacturer_id": frozenset({CATEGORY})}
    )
    assert (
        _apply_runtime_overrides(
            match_severity="high",
            match_pattern_type="mac_range",  # different pattern_type
            match_device_category=CATEGORY,
            match_manufacturer=None,
            match_argus_record_id=None,
            match_watchlist_id=1,
            rule_name="watchlist_mac_range",
            overrides=cfg,
        )
        == "high"
    ), "mac_range row was suppressed by a ble_manufacturer_id-keyed entry"


def test_category_match_alone_does_NOT_suppress():
    """The opposite half: a row whose category is in the list but whose
    pattern_type is not the listed key must pass through.
    """
    cfg = RuntimeSeverityOverride(
        suppress_pattern_categories={"mac_range": frozenset({CATEGORY})}
    )
    assert (
        _apply_runtime_overrides(
            match_severity="high",
            match_pattern_type="ble_manufacturer_id",  # different pattern_type
            match_device_category=CATEGORY,
            match_manufacturer=None,
            match_argus_record_id=None,
            match_watchlist_id=1,
            rule_name="watchlist_ble_manufacturer_id",
            overrides=cfg,
        )
        == "high"
    ), "ble_manufacturer_id row was suppressed by a mac_range-keyed entry"


def test_none_pattern_type_does_not_suppress():
    """Caller didn't pass a pattern_type → the conjunction has nothing
    to key on and must pass through."""
    cfg = RuntimeSeverityOverride(
        suppress_pattern_categories={"mac_range": frozenset({CATEGORY})}
    )
    assert (
        _apply_runtime_overrides(
            match_severity="high",
            match_pattern_type=None,
            match_device_category=CATEGORY,
            match_manufacturer=None,
            match_argus_record_id=None,
            match_watchlist_id=1,
            rule_name="watchlist_mac_range",
            overrides=cfg,
        )
        == "high"
    )


def test_none_device_category_does_not_match():
    """⛔ A row with no category metadata has nothing to key the
    conjunction on. Pass-through, exactly as the existing
    category-driven checks do."""
    cfg = RuntimeSeverityOverride(
        suppress_pattern_categories={"mac_range": frozenset({CATEGORY})}
    )
    assert (
        _apply_runtime_overrides(
            match_severity="high",
            match_pattern_type="mac_range",
            match_device_category=None,
            match_manufacturer=None,
            match_argus_record_id=None,
            match_watchlist_id=1,
            rule_name="watchlist_mac_range",
            overrides=cfg,
        )
        == "high"
    )


def test_suppression_logs_info_with_pattern_type_and_category(caplog):
    """The INFO log line names all four fields the operator needs to
    triage a surprise suppression: rule_name, pattern_type, category,
    watchlist_id. Same shape as the existing suppress_categories line
    (rule_name + category + watchlist_id) extended with pattern_type."""
    cfg = RuntimeSeverityOverride(
        suppress_pattern_categories={"mac_range": frozenset({CATEGORY})}
    )
    with caplog.at_level(logging.INFO, logger="lynceus.rules"):
        _apply_runtime_overrides(
            match_severity="high",
            match_pattern_type="mac_range",
            match_device_category=CATEGORY,
            match_manufacturer=None,
            match_argus_record_id=None,
            match_watchlist_id=42,
            rule_name="argus_mac_range",
            overrides=cfg,
        )
    info = [
        r
        for r in caplog.records
        if r.levelno == logging.INFO
        and "mac_range" in r.getMessage()
        and CATEGORY in r.getMessage()
        and "watchlist_id=42" in r.getMessage()
        and "argus_mac_range" in r.getMessage()
    ]
    assert len(info) == 1


def test_unmatched_pattern_type_does_not_log(caplog):
    """No suppression → no log line. Pinned so a future refactor cannot
    quietly start emitting noise on every match."""
    cfg = RuntimeSeverityOverride(
        suppress_pattern_categories={"mac_range": frozenset({CATEGORY})}
    )
    with caplog.at_level(logging.INFO, logger="lynceus.rules"):
        _apply_runtime_overrides(
            match_severity="high",
            match_pattern_type="ble_manufacturer_id",
            match_device_category=CATEGORY,
            match_manufacturer=None,
            match_argus_record_id=None,
            match_watchlist_id=1,
            rule_name="del_blm",
            overrides=cfg,
        )
    assert not [r for r in caplog.records if r.levelno == logging.INFO]


def test_normalization_applies_on_both_sides():
    """Operator can write the key / categories in any case and still match
    a row that stores them in lowercase (or vice versa). Both halves
    go through the same normaliser that ``suppress_categories`` uses.
    """
    cfg = RuntimeSeverityOverride(
        suppress_pattern_categories={"MAC_RANGE": frozenset({"Unknown"})}
    )
    assert (
        _apply_runtime_overrides(
            match_severity="high",
            match_pattern_type="mac_range",
            match_device_category="unknown",
            match_manufacturer=None,
            match_argus_record_id=None,
            match_watchlist_id=1,
            rule_name="watchlist_mac_range",
            overrides=cfg,
        )
        is None
    )


def test_pass_through_when_overrides_is_empty():
    """No active runtime keys → fast-path return match_severity."""
    cfg = RuntimeSeverityOverride(
        suppress_pattern_categories={"mac_range": frozenset({CATEGORY})}
    )
    assert cfg.is_empty() is False
    # Make a different (empty) overrides object — fast path.
    assert (
        _apply_runtime_overrides(
            match_severity="high",
            match_pattern_type="mac_range",
            match_device_category=CATEGORY,
            match_manufacturer=None,
            match_argus_record_id=None,
            match_watchlist_id=1,
            rule_name="watchlist_mac_range",
            overrides=RuntimeSeverityOverride(),
        )
        == "high"
    )


def test_pass_through_when_overrides_is_none():
    """No overrides file loaded → fast-path."""
    assert (
        _apply_runtime_overrides(
            match_severity="high",
            match_pattern_type="mac_range",
            match_device_category=CATEGORY,
            match_manufacturer=None,
            match_argus_record_id=None,
            match_watchlist_id=1,
            rule_name="watchlist_mac_range",
            overrides=None,
        )
        == "high"
    )


# ---------------------------------------------------------------------------
# evaluate() — the end-to-end behaviour the operator observes
# ---------------------------------------------------------------------------


def test_evaluate_passes_through_when_no_overrides(db_with_mac_range_row):
    """No overrides file → the hit fires at the row's severity. Same
    as before the feature existed (byte-identical pass-through)."""
    hits = evaluate(
        _mac_range_rule(), _mac_range_obs(),
        is_new_device=True, db=db_with_mac_range_row,
    )
    assert len(hits) == 1
    assert hits[0].severity == "high"


def test_evaluate_passes_through_when_overrides_empty(db_with_mac_range_row):
    """An empty overrides file → fast-path → hit fires. The pass-through
    must stay byte-identical to the pre-feature behavior."""
    from lynceus.rules import RuntimeSeverityOverride

    empty = RuntimeSeverityOverride()
    hits = evaluate(
        _mac_range_rule(),
        _mac_range_obs(),
        is_new_device=True,
        db=db_with_mac_range_row,
        severity_overrides=empty,
    )
    assert len(hits) == 1
    assert hits[0].severity == "high"


def test_evaluate_suppresses_when_both_halves_match(db_with_mac_range_row):
    """mac_range row + category=unknown + config ``mac_range: [unknown]``
    → no hit."""
    overrides = RuntimeSeverityOverride(
        suppress_pattern_categories={"mac_range": frozenset({CATEGORY})}
    )
    hits = evaluate(
        _mac_range_rule(),
        _mac_range_obs(),
        is_new_device=True,
        db=db_with_mac_range_row,
        severity_overrides=overrides,
    )
    assert hits == [], (
        f"mac_range row with category=unknown was NOT suppressed by "
        f"suppress_pattern_categories={{'mac_range': ['unknown']}}: {hits}"
    )


def test_evaluate_does_not_suppress_when_only_pattern_type_matches(
    db_with_ble_manuf_row_cctv_category,
):
    """Config ``ble_manufacturer_id: [unknown]`` + a ble_manufacturer_id
    row whose category is ``cctv_camera`` (not in the list) → hit fires."""
    overrides = RuntimeSeverityOverride(
        suppress_pattern_categories={"ble_manufacturer_id": frozenset({CATEGORY})}
    )
    hits = evaluate(
        _ble_manuf_rule(),
        _ble_manuf_obs(),
        is_new_device=True,
        db=db_with_ble_manuf_row_cctv_category,
        severity_overrides=overrides,
    )
    assert len(hits) == 1, (
        "ble_manufacturer_id row with category=cctv_camera was suppressed by "
        "a config entry that only listed category=unknown"
    )


def test_evaluate_does_not_suppress_when_category_is_none(
    db_with_ble_manuf_row_no_metadata,
):
    """A row without metadata has no category to key on. Pass-through."""
    overrides = RuntimeSeverityOverride(
        suppress_pattern_categories={"ble_manufacturer_id": frozenset({CATEGORY})}
    )
    hits = evaluate(
        _ble_manuf_rule(),
        _ble_manuf_obs(),
        is_new_device=True,
        db=db_with_ble_manuf_row_no_metadata,
        severity_overrides=overrides,
    )
    assert len(hits) == 1, (
        "ble_manufacturer_id row with no metadata (category=None) was suppressed "
        "by a config entry keyed on a category it has no value for"
    )


def test_evaluate_mac_range_with_unknown_category_suppressed(
    db_with_mac_range_row,
):
    """The motivating example from the design doc: 80.3% of the shipped
    corpus is category=unknown, but the operator only wants to suppress
    it for the mac_range pattern_type, not globally. The conjunction
    is the whole point — ``suppress_categories`` alone would
    over-suppress."""
    overrides = RuntimeSeverityOverride(
        suppress_pattern_categories={"mac_range": frozenset({CATEGORY})}
    )
    assert evaluate(
        _mac_range_rule(),
        _mac_range_obs(),
        is_new_device=True,
        db=db_with_mac_range_row,
        severity_overrides=overrides,
    ) == []


# ---------------------------------------------------------------------------
# The loader — load_runtime_severity_overrides
# ---------------------------------------------------------------------------


def _write(tmp_path, text):
    p = tmp_path / "severity_overrides.yaml"
    p.write_text(text, encoding="utf-8")
    return str(p)


def test_loader_parses_suppress_pattern_categories(tmp_path):
    """YAML round-trip: ``suppress_pattern_categories`` lands as a
    ``dict[str, frozenset[str]]`` on the model, both sides normalised."""
    cfg = load_runtime_severity_overrides(
        _write(
            tmp_path,
            "suppress_pattern_categories:\n"
            "  mac_range: [unknown]\n"
            "  ble_manufacturer_id: [cctv_camera, drone]\n",
        )
    )
    assert cfg is not None
    assert cfg.suppress_pattern_categories == {
        "mac_range": frozenset({"unknown"}),
        "ble_manufacturer_id": frozenset({"cctv_camera", "drone"}),
    }


def test_loader_normalises_keys_and_set_members(tmp_path):
    """Operator can write the key and categories in any case / with
    surrounding whitespace and still get a normalised match."""
    cfg = load_runtime_severity_overrides(
        _write(
            tmp_path,
            "suppress_pattern_categories:\n"
            "  MAC_RANGE: ['  Unknown  ', 'ALPR']\n",
        )
    )
    assert cfg is not None
    assert cfg.suppress_pattern_categories == {
        "mac_range": frozenset({"unknown", "alpr"})
    }


def test_loader_drops_malformed_value_list_with_warning(tmp_path, caplog):
    """A value that isn't a list is dropped with a WARNING; the rest of
    the dict still parses. One malformed entry must not disable the
    layer."""
    cfg = load_runtime_severity_overrides(
        _write(
            tmp_path,
            "suppress_pattern_categories:\n"
            "  mac_range: 'not-a-list'\n"
            "  ble_manufacturer_id: [unknown]\n",
        )
    )
    assert cfg is not None
    assert cfg.suppress_pattern_categories == {
        "ble_manufacturer_id": frozenset({"unknown"})
    }
    warnings = [
        r
        for r in caplog.records
        if r.levelno == logging.WARNING and "suppress_pattern_categories" in r.getMessage()
    ]
    assert len(warnings) == 1


def test_loader_drops_non_string_entries_with_warning(tmp_path, caplog):
    """Per-entry validation: non-string / empty-after-strip entries are
    dropped with a WARNING; the rest still applies."""
    cfg = load_runtime_severity_overrides(
        _write(
            tmp_path,
            "suppress_pattern_categories:\n"
            "  mac_range:\n"
            "    - unknown\n"
            "    - 42\n"  # non-string
            "    - ''\n"  # empty
            "    - '   '\n"  # whitespace-only
            "    - alpr\n",
        )
    )
    assert cfg is not None
    assert cfg.suppress_pattern_categories == {
        "mac_range": frozenset({"unknown", "alpr"})
    }
    warnings = [
        r
        for r in caplog.records
        if r.levelno == logging.WARNING and "suppress_pattern_categories" in r.getMessage()
    ]
    # 42 + '' + '   ' → 3 warnings (one per dropped entry).
    assert len(warnings) == 3


def test_loader_drops_empty_string_key_with_warning(tmp_path, caplog):
    cfg = load_runtime_severity_overrides(
        _write(
            tmp_path,
            "suppress_pattern_categories:\n"
            "  '': [unknown]\n"
            "  mac_range: [alpr]\n",
        )
    )
    assert cfg is not None
    assert cfg.suppress_pattern_categories == {
        "mac_range": frozenset({"alpr"})
    }
    warnings = [
        r
        for r in caplog.records
        if r.levelno == logging.WARNING and "suppress_pattern_categories" in r.getMessage()
    ]
    assert len(warnings) == 1


def test_loader_drops_non_string_key_with_warning(tmp_path, caplog):
    cfg = load_runtime_severity_overrides(
        _write(
            tmp_path,
            "suppress_pattern_categories:\n"
            "  42: [unknown]\n"
            "  mac_range: [alpr]\n",
        )
    )
    assert cfg is not None
    assert cfg.suppress_pattern_categories == {
        "mac_range": frozenset({"alpr"})
    }
    warnings = [
        r
        for r in caplog.records
        if r.levelno == logging.WARNING and "suppress_pattern_categories" in r.getMessage()
    ]
    assert len(warnings) == 1


def test_loader_ignores_non_dict_top_level_shape(tmp_path):
    """scalar / list at the top of ``suppress_pattern_categories`` is
    silently dropped (the eval layer pass-throughs uncovered
    categories anyway)."""
    cfg = load_runtime_severity_overrides(
        _write(
            tmp_path,
            "suppress_pattern_categories: 'not-a-dict'\n",
        )
    )
    assert cfg is not None
    assert cfg.suppress_pattern_categories == {}


def test_loader_empty_suppress_pattern_categories_still_activates_file(tmp_path):
    """The dict is allowed to parse to {} (e.g. operator temporarily
    commented every entry). The file is still 'loaded' but with an
    empty new field — ``is_empty()`` correctly accounts for this."""
    cfg = load_runtime_severity_overrides(
        _write(
            tmp_path,
            "device_category_severity:\n"
            "  unknown: med\n"
            "suppress_pattern_categories: {}\n",
        )
    )
    assert cfg is not None
    assert not cfg.is_empty()
    assert cfg.suppress_pattern_categories == {}


def test_loader_only_suppress_pattern_categories_activates(tmp_path):
    """A file with ONLY the new key — no other runtime keys — is parsed
    to a non-empty runtime view. (The is_empty() check would short-circuit
    the feature if forgotten — pinned here.)"""
    cfg = load_runtime_severity_overrides(
        _write(
            tmp_path,
            "suppress_pattern_categories:\n"
            "  mac_range: [unknown]\n",
        )
    )
    assert cfg is not None
    assert not cfg.is_empty(), (
        "a file with only suppress_pattern_categories parsed to an empty "
        "runtime view; is_empty() must include the new field"
    )
    assert cfg.suppress_pattern_categories == {
        "mac_range": frozenset({"unknown"})
    }


def test_loader_summary_log_names_new_field(tmp_path, caplog):
    """The 'active runtime keys' INFO line names every field with a
    count, so an operator reading startup output knows the file did
    something."""
    with caplog.at_level(logging.INFO, logger="lynceus.rules"):
        cfg = load_runtime_severity_overrides(
            _write(
                tmp_path,
                "suppress_pattern_categories:\n"
                "  mac_range: [unknown]\n"
                "  ble_manufacturer_id: [cctv_camera]\n",
            )
        )
    assert cfg is not None
    info = [
        r
        for r in caplog.records
        if r.levelno == logging.INFO and "loaded from" in r.getMessage()
    ]
    assert len(info) == 1
    msg = info[0].getMessage()
    assert "suppressed pattern_category" in msg
    assert "2 suppressed pattern_category" in msg


def test_loader_dedupes_after_normalisation(tmp_path):
    """Two entries that normalise to the same value collapse to one
    frozenset member."""
    cfg = load_runtime_severity_overrides(
        _write(
            tmp_path,
            "suppress_pattern_categories:\n"
            "  mac_range:\n"
            "    - unknown\n"
            "    - Unknown\n"
            "    - '  unknown  '\n",
        )
    )
    assert cfg is not None
    assert cfg.suppress_pattern_categories == {
        "mac_range": frozenset({"unknown"})
    }


# ---------------------------------------------------------------------------
# The plant test — the load-bearing one
# ---------------------------------------------------------------------------
#
# ⛔ This test is the one that proves the guard works. It must be
# observed to FAIL with the new check removed from
# `_apply_runtime_overrides` (the conjunction block — look for
# `suppress_pattern_categories.get(normalized_pattern_type)` and
# temporarily comment it out, then re-run this test, then put it back).
# A test that passed before the feature shipped is testing nothing.


def test_plant_suppress_pattern_categories_suppresses_when_both_halves_match(
    db_with_mac_range_row,
):
    """The plant. With the conjunction in ``_apply_runtime_overrides``:
    a mac_range row whose category is the one the operator listed
    under ``mac_range`` in ``suppress_pattern_categories`` produces
    ZERO RuleHits.

    Without the conjunction (i.e. the new check is removed/commented):
    the same configuration produces one RuleHit at the row's
    severity. That is the FAIL shape the plant depends on.
    """
    overrides = RuntimeSeverityOverride(
        suppress_pattern_categories={"mac_range": frozenset({CATEGORY})}
    )
    hits = evaluate(
        _mac_range_rule(),
        _mac_range_obs(),
        is_new_device=True,
        db=db_with_mac_range_row,
        severity_overrides=overrides,
    )
    assert hits == [], (
        f"the conjunction is supposed to suppress this row, but it fired: {hits}"
    )
