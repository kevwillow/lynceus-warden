"""`/healthz.json` makes overlapping liveness counts explicit to consumers."""

from __future__ import annotations

from pathlib import Path

from starlette.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import create_app
from lynceus.webui.csrf import CSRF_COOKIE_NAME, CSRF_FORM_FIELD

REPO_ROOT = Path(__file__).resolve().parents[1]
SHIPPED_RULES = REPO_ROOT / "config" / "rules.yaml"

BLE_UUID_ROWS = (
    "0000fd5a-0000-1000-8000-00805f9b34fb",
    "0000fd6f-0000-1000-8000-00805f9b34fb",
)
MAC_ROW = "aa:bb:cc:dd:ee:ff"


def test_this_suite_is_testing_the_tree_it_lives_in():
    import lynceus.webui.app as under_test

    assert Path(under_test.__file__).resolve().is_relative_to(REPO_ROOT)


def _build_app(tmp_path, *, rules_path: str | None = str(SHIPPED_RULES)):
    config = Config(db_path=str(tmp_path / "healthz.db"), rules_path=rules_path)
    db = Database(config.db_path)
    db.ensure_location("default", "Default")
    for pattern in BLE_UUID_ROWS:
        db.add_watchlist(pattern=pattern, pattern_type="ble_uuid", severity="high")
    db.add_watchlist(pattern=MAC_ROW, pattern_type="mac", severity="high")
    return db, create_app(config, db)


def _snooze_via_route(client: TestClient, rule_type: str) -> None:
    client.get("/")
    token = client.cookies.get(CSRF_COOKIE_NAME)
    assert token, "GET / did not establish a CSRF token"
    response = client.post(
        f"/rules/{rule_type}/snooze",
        data={"duration_seconds": "86400", CSRF_FORM_FIELD: token},
        follow_redirects=False,
    )
    assert response.status_code == 303, response.text[:200]


def _watchlist_check(client: TestClient) -> dict:
    response = client.get("/healthz.json")
    assert response.status_code == 200
    return response.json()["checks"]["watchlist"]


def test_the_invariant_holds_when_a_type_is_both_inert_and_snoozed(tmp_path):
    db, app = _build_app(tmp_path)
    try:
        with TestClient(app) as client:
            _snooze_via_route(client, "ble_uuid")
            watchlist = _watchlist_check(client)
        assert (
            watchlist["live_rows"]
            + watchlist["inert_rows"]
            + watchlist["snoozed_rows"]
            - watchlist["double_counted_rows"]
            == watchlist["total_rows"]
        )
        assert watchlist["double_counted_rows"] == 2
        assert watchlist["both_inert_and_snoozed_pattern_types"] == ["ble_uuid"]
    finally:
        db.close()


def test_the_invariant_holds_with_no_snooze_at_all(tmp_path):
    db, app = _build_app(tmp_path)
    try:
        with TestClient(app) as client:
            watchlist = _watchlist_check(client)
        assert (
            watchlist["live_rows"]
            + watchlist["inert_rows"]
            + watchlist["snoozed_rows"]
            - watchlist["double_counted_rows"]
            == watchlist["total_rows"]
        )
        assert watchlist["double_counted_rows"] == 0
    finally:
        db.close()


def test_a_snoozed_live_type_does_not_double_count(tmp_path):
    db, app = _build_app(tmp_path)
    try:
        with TestClient(app) as client:
            _snooze_via_route(client, "watchlist_mac")
            watchlist = _watchlist_check(client)
        assert watchlist["double_counted_rows"] == 0
        assert watchlist["live_rows"] == 0
    finally:
        db.close()


def test_the_exported_list_is_the_intersection_and_not_the_inert_set(tmp_path):
    """⭐ Added because a planted defect SURVIVED the four tests above.

    Swapping the exported `both_types` for `inert_types` changed no assertion:
    every fixture here had exactly one inert type, so the intersection and the
    inert set were the same list. A second inert type that is NOT snoozed is
    what makes the two distinguishable -- and it is the difference an operator
    reading this key actually depends on.
    """
    db, app = _build_app(tmp_path)
    # `ble_local_name` is inert against the shipped ruleset too, and is left
    # UNSNOOZED, so it belongs to inert_pattern_types and not to the overlap.
    db.add_watchlist(pattern="tile", pattern_type="ble_local_name", severity="high")
    try:
        with TestClient(app) as client:
            _snooze_via_route(client, "ble_uuid")
            watchlist = _watchlist_check(client)
        assert "ble_local_name" in watchlist["inert_pattern_types"]
        assert watchlist["both_inert_and_snoozed_pattern_types"] == ["ble_uuid"], (
            "the exported overlap is reporting the inert set, not the intersection"
        )
        # ...and the number must follow the same set, not the inert one.
        assert watchlist["double_counted_rows"] == 2
        assert (
            watchlist["live_rows"]
            + watchlist["inert_rows"]
            + watchlist["snoozed_rows"]
            - watchlist["double_counted_rows"]
            == watchlist["total_rows"]
        )
    finally:
        db.close()


def test_the_overlap_is_null_not_zero_when_liveness_is_unknown(tmp_path):
    db, app = _build_app(tmp_path, rules_path=None)
    try:
        with TestClient(app) as client:
            watchlist = _watchlist_check(client)
        assert watchlist["liveness_known"] is False
        assert watchlist["double_counted_rows"] is None
    finally:
        db.close()


def test_the_overlap_is_null_when_the_ruleset_cannot_be_read(tmp_path):
    bad_rules = tmp_path / "bad.yaml"
    bad_rules.write_text("rules: [[[not yaml", encoding="utf-8")
    db, app = _build_app(tmp_path, rules_path=str(bad_rules))
    try:
        with TestClient(app) as client:
            watchlist = _watchlist_check(client)
        assert watchlist["double_counted_rows"] is None
        assert watchlist["both_inert_and_snoozed_pattern_types"] == []
    finally:
        db.close()


def test_the_overlap_is_null_when_the_snooze_table_cannot_be_read(tmp_path):
    """⛔ Caught before this PR landed: the fix for "a failed snooze read is a
    verified zero" left `double_counted_rows: 0` sitting beside
    `snoozed_rows: null` — this entry's own defect one field along.

    The overlap is the INTERSECTION of the inert set with the snoozed set, so
    it is unknown if EITHER side is.
    """
    import sqlite3

    db, app = _build_app(tmp_path)

    def boom(now_ts):
        raise sqlite3.OperationalError("database is locked")

    db.list_active_rule_type_snoozes = boom
    try:
        with TestClient(app) as client:
            watchlist = _watchlist_check(client)
        assert watchlist["snoozes_known"] is False
        assert watchlist["snoozed_rows"] is None
        assert watchlist["double_counted_rows"] is None, (
            "the overlap reports a number while the snooze half of it is unknown"
        )
        # ...and the RULESET is still known: the two failures are separate.
        assert watchlist["liveness_known"] is True
    finally:
        db.close()
