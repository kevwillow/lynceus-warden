"""One damaged `import_runs` row must not take down the pages that read it.

`_watchlist_freshness`, the home summary builder and `_check_watchlist` each did
a bare `int()` on a stored column. Measured on a database carrying ONE
`import_runs.imported_at` of `"not-an-int"`:

    route            before      after
    /                HTTP 500    200, watchlist "unknown"
    /settings        HTTP 500    200
    /healthz.json    503         200 with stale=null, staleness_known=false

⭐ The home page is the operator's primary surface and, on a default install
with the heartbeat off, their liveness signal. #161 isolated the `/healthz.json`
checks so a raise there is reported rather than fatal — but that is containment
of ONE surface. The mechanism was untouched on the other two, which is
[[a-fix-can-close-the-surface-not-the-finding]] in one file.

⚠️ The `/healthz.json` change from 503 to 200 is deliberate and is NOT a silent
downgrade: the 503 was a crashed check being reported as an error, and what
replaces it is the state described precisely — `stale: null` beside
`staleness_known: false`, the same idiom this file already uses for an
undecidable liveness verdict, which by existing convention does not flip the
overall status. #161's isolation stays as the backstop for a genuine raise.
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import (
    _watchlist_freshness_card,
    _watchlist_freshness_summary,
    create_app,
    stored_int,
)

NOW = int(time.time())
ROUTES = ["/", "/settings", "/healthz", "/healthz.json"]


def _client(tmp_path, rows):
    db = Database(str(tmp_path / "t.db"))
    for r in rows:
        db._conn.execute(
            "INSERT INTO import_runs (imported_at, exported_at, record_count) "
            "VALUES (?, ?, ?)",
            r,
        )
    db._conn.commit()
    cfg = Config(kismet_url="http://x:2501", kismet_api_key="k")
    return create_app(cfg, db), db


# --- the helper -------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        (None, None),
        ("not-an-int", None),
        ("", None),
        ("12345", 12345),
        (12345, 12345),
        (0, 0),  # ⚠️ epoch 0 is a VALUE, not an absence
    ],
)
def test_stored_int_reports_unreadable_as_none_and_keeps_zero(raw, expected):
    assert stored_int(raw) == expected


def test_stored_int_never_substitutes_zero_for_unreadable():
    """0 would render as "imported in 1970" — a confident wrong answer."""
    assert stored_int("not-an-int") is not 0  # noqa: F632
    assert stored_int("not-an-int") is None


# --- the routes -------------------------------------------------------------


@pytest.mark.webui
@pytest.mark.parametrize("route", ROUTES)
def test_control_a_healthy_import_still_renders(tmp_path, route):
    app, db = _client(tmp_path, [(NOW - 3600, NOW - 7200, 5)])
    try:
        with TestClient(app, raise_server_exceptions=False) as c:
            assert c.get(route).status_code == 200
    finally:
        db.close()


@pytest.mark.webui
@pytest.mark.parametrize("route", ROUTES)
@pytest.mark.parametrize(
    "row",
    [
        ("not-an-int", None, 5),
        (NOW - 3600, "not-an-int", 5),
        (NOW - 3600, None, "not-an-int"),
    ],
    ids=["bad-imported_at", "bad-exported_at", "bad-record_count"],
)
def test_one_damaged_row_does_not_take_a_page_down(tmp_path, route, row):
    app, db = _client(tmp_path, [row])
    try:
        with TestClient(app, raise_server_exceptions=False) as c:
            r = c.get(route)
        assert r.status_code == 200, (
            f"{route} returned {r.status_code} for a single damaged stored value: "
            f"{r.text[:200]}"
        )
    finally:
        db.close()


@pytest.mark.webui
def test_an_unreadable_import_time_is_reported_as_unknown_not_as_fresh(tmp_path):
    """The point of not crashing is to say something TRUE instead."""
    app, db = _client(tmp_path, [("not-an-int", None, 5)])
    try:
        with TestClient(app, raise_server_exceptions=False) as c:
            body = c.get("/healthz.json").json()["checks"]["watchlist"]
        assert body["staleness_known"] is False, "claimed to know the staleness"
        assert body["stale"] is None, "asserted a staleness verdict it cannot support"
        assert body["days_since_import"] is None
        assert body["last_imported_at"] is None
    finally:
        db.close()


@pytest.mark.webui
def test_control_a_healthy_import_still_reports_a_known_staleness(tmp_path):
    """Without this, the test above would pass against code that knows nothing."""
    app, db = _client(tmp_path, [(NOW - 3600, None, 5)])
    try:
        with TestClient(app, raise_server_exceptions=False) as c:
            body = c.get("/healthz.json").json()["checks"]["watchlist"]
        assert body["staleness_known"] is True
        assert body["stale"] is False
        assert body["days_since_import"] == 0
    finally:
        db.close()


def test_an_export_stamped_at_epoch_zero_is_used_not_skipped(tmp_path):
    """⚠️ `exported_at or imported_at` treated epoch 0 as absent and fell through
    to the IMPORT time — the same shape as the heartbeat delivered at epoch 0
    that read as never delivered. 0 is a value, not an absence.

    Driven on both builders: the reference is what decides fresh/stale, so
    silently swapping which timestamp it is changes the verdict the operator
    sees.
    """
    _, db = _client(tmp_path, [(NOW - 86400, 0, 5)])
    try:
        card = _watchlist_freshness_card(db, warn_days=30, now_ts=NOW)
        summary = _watchlist_freshness_summary(db, warn_days=30, now_ts=NOW)
        assert card["exported_at"] == 0, "an epoch-0 export was dropped by the card"
        assert summary["exported_at"] == 0, "...and by the summary"
        # The reference is the EXPORT (epoch 0), so this is ancient, not 1 day old.
        assert card["age_days"] is not None and card["age_days"] > 10000, (
            f"the epoch-0 export was skipped and the import time used instead: "
            f"age_days={card['age_days']}"
        )
        assert card["status"] == "stale"
    finally:
        db.close()


@pytest.mark.webui
def test_control_a_normal_export_is_still_the_reference(tmp_path):
    """Without this, the epoch-0 test would pass against code that ignores
    exported_at entirely."""
    _, db = _client(tmp_path, [(NOW - 86400, NOW - 86400 * 40, 5)])
    try:
        card = _watchlist_freshness_card(db, warn_days=30, now_ts=NOW)
        assert card["age_days"] == 40, "the export is no longer the reference"
        assert card["status"] == "stale"
    finally:
        db.close()
