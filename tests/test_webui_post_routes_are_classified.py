"""Every web-UI POST route must be classified against the open auth decision.

⭐ Why this exists. Web UI authentication is reserved for Kev (register item 5)
and the evidence is complete: **22 of the 23 POST routes change persistent state
for a caller with no credential of any kind.** A decision that large stays open
for a while, and the risk while it does is not that someone implements the wrong
thing — it is that the surface **grows** in the meantime and nobody notices,
because adding a route is a one-line change that no existing test objects to.

So this pins the surface, not the verdict. Adding a POST route fails here until
someone names it, at which point they are looking at the auth decision.

⚠️ Deliberately NOT asserting "22 of 23 must keep mutating". That would make
implementing auth fail the suite, which is backwards. What it asserts is that the
SET is known, plus one behavioural anchor so the register cannot quietly become
wrong in the reassuring direction either.

Both directions fail:

  * a NEW POST route nobody classified       -> test_every_post_route_is_classified
  * a classified route disappears            -> test_every_post_route_is_classified
  * auth lands and the register goes stale   -> test_the_register_claim_is_still_true
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import create_app
from lynceus.webui.csrf import CSRF_COOKIE_NAME, CSRF_FORM_FIELD

REPO_ROOT = Path(__file__).resolve().parents[1]

#: Measured 2026-08-15 on `1e0fdef` by issuing every POST with no credential and
#: diffing every row of every table plus both allowlist files. See
#: docs/AUDIT_REGISTER.md, "Reserved for Kev" item 5.
#:
#: ⛔ These are not "routes that should be unauthenticated". They are the record
#: of what an unauthenticated caller can currently do, so the list cannot grow
#: without someone reading that sentence.
MUTATES_WITHOUT_CREDENTIALS = frozenset(
    {
        "/alerts/ack-all-visible",
        "/alerts/bulk-ack",
        "/alerts/{alert_id}/ack",
        "/alerts/{alert_id}/allowlist",
        "/alerts/{alert_id}/allowlist/remove",
        "/alerts/{alert_id}/note",
        "/alerts/{alert_id}/snooze",
        "/alerts/{alert_id}/unack",
        "/alerts/{alert_id}/watch",
        "/allowlist/add",
        "/allowlist/bulk_remove",
        "/devices/{mac:path}/allowlist",
        "/devices/{mac:path}/allowlist/remove",
        "/devices/{mac:path}/snooze",
        "/devices/{mac:path}/watchlist",
        "/rules/{rule_type}/snooze",
        "/rules/{rule_type}/unsnooze",
        "/watchful/{entry_id}/confirm-safe",
        "/watchful/{entry_id}/dismiss",
        "/watchful/{entry_id}/investigate",
        "/watchful/{entry_id}/promote",
        "/watchful/{entry_id}/reset",
    }
)

#: ⚠️ Refuses on a DOMAIN precondition ("no alert for this MAC; watchful tracking
#: starts from an alert"), NOT on access control. Give it a MAC that has an alert
#: and it works too. Listed separately so nobody reads it as a route that is
#: protected -- that misreading is exactly how a 22/23 becomes a reported 21/23.
REFUSES_ON_DOMAIN_PRECONDITION = frozenset({"/devices/{mac:path}/watch"})

CLASSIFIED = MUTATES_WITHOUT_CREDENTIALS | REFUSES_ON_DOMAIN_PRECONDITION


@pytest.fixture()
def app():
    td = tempfile.mkdtemp()
    allowlist = Path(td) / "allowlist.yaml"
    allowlist.write_text("entries: []\n", encoding="utf-8")
    cfg = Config(
        db_path=td + "/s.db",
        rules_path=str(REPO_ROOT / "config" / "rules.yaml"),
        allowlist_path=str(allowlist),
    )
    db = Database(cfg.db_path)
    db.ensure_location("default", "Default")
    try:
        yield create_app(cfg, db)
    finally:
        db.close()


def _post_routes(app) -> set[str]:
    """Derived from the LIVE app, never from a copy of this file's own list.

    🪤 The original probe carried a hardcoded list of 23. Four merges landed
    between the two measurements of this surface; a route added by any of them
    would have been silently missed. Deriving is what makes "complete coverage"
    a measurement instead of an assumption.
    """
    return {
        route.path
        for route in app.routes
        if "POST" in (getattr(route, "methods", None) or set())
    }


def test_every_post_route_is_classified(app):
    """The guard. A new POST route must be measured against the auth decision,
    not merely added."""
    live = _post_routes(app)
    # Presence floor: an app that failed to register its routes would make the
    # set comparison below vacuously true.
    assert len(live) >= 23, (
        f"only {len(live)} POST routes found; the app did not build its routing "
        f"table properly and this guard is measuring nothing: {sorted(live)}"
    )
    assert live == CLASSIFIED, (
        f"unclassified POST route(s): {sorted(live - CLASSIFIED)}; "
        f"classified but no longer present: {sorted(CLASSIFIED - live)}.\n"
        "Web UI authentication is an OPEN decision (docs/AUDIT_REGISTER.md, "
        "'Reserved for Kev' item 5) and 22 of 23 POST routes currently change "
        "persistent state for a caller with no credential. Measure the new route "
        "the same way, add it to the right set here, and update the count in the "
        "register — do not just append it."
    )


def test_the_two_classes_do_not_overlap():
    """A route counted in both sets would let the totals in the register be
    satisfied by a list that is internally inconsistent."""
    assert not (MUTATES_WITHOUT_CREDENTIALS & REFUSES_ON_DOMAIN_PRECONDITION)
    assert len(MUTATES_WITHOUT_CREDENTIALS) == 22, (
        f"the register records 22 mutating routes, this list has "
        f"{len(MUTATES_WITHOUT_CREDENTIALS)}"
    )
    assert len(CLASSIFIED) == 23


def test_the_register_claim_is_still_true(app):
    """The behavioural anchor, and the direction the structural check misses.

    ⚠️ If authentication lands, this fails — and that is the point. The register
    would otherwise keep asserting an exposure that no longer exists, which is
    the same rot as asserting one that does. One representative route is enough;
    the full 23-route sweep lives in the probe.
    """
    from starlette.testclient import TestClient

    client = TestClient(app, follow_redirects=False)
    # The only preliminary a browser -- or anyone who can reach the port -- does:
    # GET a page to collect the CSRF cookie. That is not a credential.
    client.get("/")
    # ⚠️ Field name taken from the constant, not typed as a literal. The first
    # draft of this test guessed "csrf_token", got a 403, and for a moment looked
    # exactly like "authentication has landed" -- a wrong instrument imitating
    # the very finding it was checking for.
    response = client.post(
        "/rules/watchlist_mac/snooze",
        data={"duration_seconds": "86400", CSRF_FORM_FIELD: _csrf(client)},
    )
    assert response.status_code in (200, 303), (
        f"POST /rules/watchlist_mac/snooze returned {response.status_code} for an "
        "unauthenticated caller. If authentication was implemented, the register's "
        "'22 of 23' evidence is now stale — update item 5 rather than deleting this."
    )


def _csrf(client) -> str:
    token = client.cookies.get(CSRF_COOKIE_NAME)
    assert token, (
        f"no {CSRF_COOKIE_NAME} cookie after a GET; the CSRF control changed and "
        "this test can no longer distinguish 'refused for lack of auth' from "
        "'refused for lack of a token'"
    )
    return token


def test_csrf_refuses_a_tokenless_request_and_is_not_authentication(app):
    """The control that stops the anchor above being misread.

    Without this, someone could conclude the POST succeeded because nothing
    guards it at all. CSRF *does* refuse — it just is not authentication, because
    the token is self-issued to anyone who can GET a page.
    """
    from starlette.testclient import TestClient

    client = TestClient(app, follow_redirects=False)
    client.get("/")
    refused = client.post(
        "/rules/watchlist_mac/snooze", data={"duration_seconds": "86400"}
    )
    assert refused.status_code == 403, (
        f"a tokenless POST returned {refused.status_code}, expected 403 — the CSRF "
        "control changed, and the register's 'CSRF works and is not auth' line "
        "needs re-measuring"
    )
