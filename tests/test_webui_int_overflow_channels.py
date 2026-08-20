"""A caller-supplied integer must not reach a SQLite bind parameter unbounded —
through ANY channel, not just a path parameter.

⛔ **This file exists because the previous fix closed a SURFACE, not the
mechanism.** `RowId = Annotated[int, Path(le=SQLITE_MAX_ROWID)]` bounded the 15
routes that take a row id in the URL. Within the hour, a cross-model sweep found
the identical `OverflowError: Python int too large to convert to SQLite INTEGER`
reachable through three other channels, all reproduced before being believed:

    POST /alerts/bulk-ack        alert_ids=2**63     -> 500   Form list[int]
    POST /alerts/ack-all-visible rendered_at=2**63   -> 500   Form str, hand-parsed
    GET  /watchlist              page=2**63          -> 500   Query str via parse_pagination

⭐ **And the third one's bound is NOT `SQLITE_MAX_ROWID`.** Callers compute
`offset = (page - 1) * per_page`, so the ceiling on `page` is the rowid ceiling
DIVIDED BY `per_page`. Measured before fixing:

    per_page=25   largest working page = 368934881474191033
    per_page=200  largest working page =  46116860184273880

A bound of `2**63 - 1` on `page` would have left the defect fully reachable at
every per_page. **That was found by the CONTROL** — `page = 2**63 - 1`, one below
the rowid ceiling, also returned 500 — not by the reported trigger. Testing only
what the report said would have shipped a fix that fixed nothing.

⚠️ Severity is LOW and stays LOW: unhandled `OverflowError` → 500, no info leak
(Starlette's plain "Internal Server Error"), the daemon keeps serving, and the
bulk-ack transaction rolls back when the `with self._conn` block exits by
exception. This is a wrong status code on hostile input.
"""

from __future__ import annotations

import warnings

import pytest
from starlette.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import SQLITE_MAX_ROWID, create_app
from lynceus.webui.csrf import CSRF_COOKIE_NAME, CSRF_FORM_FIELD
from lynceus.webui.pagination import MAX_SQLITE_INT

BIG = SQLITE_MAX_ROWID + 1
JUST_UNDER = SQLITE_MAX_ROWID


@pytest.fixture()
def client(tmp_path):
    warnings.filterwarnings("ignore")
    (tmp_path / "allowlist.yaml").write_text("entries: []\n")
    db = Database(str(tmp_path / "lynceus.db"))
    app = create_app(
        Config(db_path=str(tmp_path / "lynceus.db"),
               allowlist_path=str(tmp_path / "allowlist.yaml")),
        db,
    )
    try:
        with TestClient(app, raise_server_exceptions=False) as c:
            yield c
    finally:
        db.close()


def _tok(client):
    client.get("/alerts")
    return client.cookies.get(CSRF_COOKIE_NAME)


# --------------------------------------------------------------------------
# Channel 1 — a Form list[int]
# --------------------------------------------------------------------------
def test_bulk_ack_rejects_an_id_above_the_sqlite_ceiling(client):
    r = client.post(
        "/alerts/bulk-ack",
        data={CSRF_FORM_FIELD: _tok(client), "alert_ids": str(BIG)},
        follow_redirects=False,
    )
    assert r.status_code == 400, r.status_code


def test_bulk_ack_still_accepts_the_largest_valid_id(client):
    """⛔ The other half. Rejecting everything satisfies the test above."""
    r = client.post(
        "/alerts/bulk-ack",
        data={CSRF_FORM_FIELD: _tok(client), "alert_ids": str(JUST_UNDER)},
        follow_redirects=False,
    )
    assert r.status_code == 200, r.status_code


def test_bulk_ack_still_rejects_a_non_positive_id(client):
    """The pre-existing lower bound must survive the new upper one."""
    r = client.post(
        "/alerts/bulk-ack",
        data={CSRF_FORM_FIELD: _tok(client), "alert_ids": "0"},
        follow_redirects=False,
    )
    assert r.status_code == 400


# --------------------------------------------------------------------------
# Channel 2 — a Form str parsed to int by hand
# --------------------------------------------------------------------------
def test_ack_all_visible_survives_an_out_of_range_rendered_at(client):
    """Treated as unset, matching how that parse already handles every other
    unusable value — not rejected, because `rendered_at` is a rendering hint and
    a stale tab should not become a 4xx."""
    r = client.post(
        "/alerts/ack-all-visible",
        data={CSRF_FORM_FIELD: _tok(client), "rendered_at": str(BIG)},
        follow_redirects=False,
    )
    assert r.status_code == 200, r.status_code


def test_ack_all_visible_still_honours_a_valid_rendered_at(tmp_path):
    """⛔ **This test asserted only a 200 and a planted defect walked straight
    through it.** Making the branch `if False:` — i.e. ignoring `rendered_at`
    entirely — kept every status code identical, so the guard was checking
    nothing. `rendered_at` is what bounds the bulk write to the alerts that were
    actually ON THE PAGE; without it, an alert that arrives between the render
    and the click is acknowledged unseen, which this route's own comment calls
    "the worst class of bug for an operation that writes silently in bulk".

    So the assertion is now behavioural: an alert stamped AFTER `rendered_at`
    must survive the bulk ack.
    """
    warnings.filterwarnings("ignore")
    (tmp_path / "allowlist.yaml").write_text("entries: []\n")
    db = Database(str(tmp_path / "lynceus.db"))
    app = create_app(
        Config(db_path=str(tmp_path / "lynceus.db"),
               allowlist_path=str(tmp_path / "allowlist.yaml")),
        db,
    )
    rendered_at = 1_700_000_000
    db.upsert_device("aa:bb:cc:dd:ee:01", "wifi", "V", 0, rendered_at)
    on_page = db.add_alert(ts=rendered_at - 60, rule_name="r",
                           mac="aa:bb:cc:dd:ee:01", message="was shown",
                           severity="high")
    arrived_after = db.add_alert(ts=rendered_at + 60, rule_name="r",
                                 mac="aa:bb:cc:dd:ee:01", message="arrived later",
                                 severity="high")
    try:
        with TestClient(app, raise_server_exceptions=False) as c:
            c.get("/alerts")
            r = c.post(
                "/alerts/ack-all-visible",
                data={CSRF_FORM_FIELD: c.cookies.get(CSRF_COOKIE_NAME),
                      "rendered_at": str(rendered_at)},
                follow_redirects=False,
            )
            assert r.status_code == 200, r.status_code
        rows = {
            int(x[0]): int(x[1])
            for x in db._conn.execute(
                "SELECT id, acknowledged FROM alerts"
            ).fetchall()
        }
    finally:
        db.close()

    assert rows[on_page] == 1, "the alert that WAS on the page should be acked"
    assert rows[arrived_after] == 0, (
        "an alert stamped after rendered_at was acknowledged unseen — "
        "rendered_at is being ignored"
    )


# --------------------------------------------------------------------------
# Channel 3 — a Query str through the shared pagination helper
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "path",
    ["/watchlist", "/alerts", "/devices", "/probes", "/watchful", "/allowlist"],
)
def test_no_list_route_500s_on_an_enormous_page(client, path):
    """⭐ Swept across every list route rather than fixed on the one that was
    reported. `/watchlist` was the only one that 500'd — it is the only route
    that queries with the raw requested page before `build_pagination` clamps it
    — but the fix lives in `parse_pagination`, so the guard is the sweep."""
    assert client.get(f"{path}?page={BIG}").status_code != 500


@pytest.mark.parametrize("per_page", [25, 50, 100, 200])
def test_watchlist_survives_a_page_below_the_rowid_ceiling(client, per_page):
    """⛔ **The control that found the real bound.** `page = 2**63 - 1` is a
    legal rowid, so a `le=SQLITE_MAX_ROWID` bound would let it through — and
    `(page - 1) * per_page` then overflows anyway. This fails against a fix that
    bounds `page` by the rowid ceiling instead of by the ceiling over per_page.
    """
    r = client.get(f"/watchlist?page={JUST_UNDER}&page_size={per_page}")
    assert r.status_code != 500, (per_page, r.status_code)


def test_the_pagination_ceiling_divides_by_per_page(client):
    """The property, stated directly rather than only through a route: the
    clamp must scale with per_page, or the largest allowed page still overflows
    the offset multiplication."""
    from lynceus.webui.pagination import parse_pagination

    allowed = (25, 50, 100, 200)
    page, per = parse_pagination(
        str(2**70), None, allowed_per_page=allowed, default_per_page=50
    )
    assert page * max(allowed) <= MAX_SQLITE_INT, (
        f"page={page} still overflows the offset multiplication at "
        f"per_page={max(allowed)}"
    )


def test_the_two_int_ceilings_stay_equal():
    """`webui.app` imports `webui.pagination`, not the reverse, so the constant
    is defined twice on purpose. Two components disagreeing about the ceiling is
    how one of them gets fixed and the other does not."""
    assert MAX_SQLITE_INT == SQLITE_MAX_ROWID
