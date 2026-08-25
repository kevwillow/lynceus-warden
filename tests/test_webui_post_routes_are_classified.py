"""Every web-UI POST route must be classified against the auth decision.

⭐ **UPDATED 2026-08-25: the decision is no longer open.** Kev chose shape (b),
single-operator password + session (register item 5). ``webui/auth.py`` ships
it. What this file measures therefore changed, and the change is deliberate
rather than a relaxation:

  * **With NO credentials file** — the default loopback install — the surface is
    exactly what it was: 23 POST routes, 22 of which change persistent state for
    a caller with no credential. That is still true, still measured here, and
    still the shipped default. Authentication is opt-in on loopback and
    MANDATORY off it (``webui/server.remote_bind_refusal``).
  * **With a credentials file**, the same POST is refused 401 and changes
    nothing, and the surface gains exactly ``/login`` and ``/logout``.

⚠️ The original framing of this file said "auth lands and the register goes
stale -> test_the_register_claim_is_still_true". That fired as designed: the
register's evidence needed rewriting the moment auth existed. It has been, and
the anchor below now pins BOTH configurations so the register cannot rot in
either direction — neither by asserting an exposure that is gone, nor by
implying a protection the default install does not have.

Both directions fail:

  * a NEW POST route nobody classified       -> test_every_post_route_is_classified
  * a classified route disappears            -> test_every_post_route_is_classified
  * auth stops refusing the same POST        -> test_a_configured_password_refuses_the_same_post
  * auth starts applying with no password    -> test_the_register_claim_is_still_true
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
def app_and_db():
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
        yield create_app(cfg, db), db
    finally:
        db.close()


@pytest.fixture()
def app(app_and_db):
    return app_and_db[0]


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


def test_the_register_claim_is_still_true(app_and_db):
    """The behavioural anchor for the DEFAULT install, with no password set.

    ⚠️ This used to read "if authentication lands, this fails — and that is the
    point". It fired, the register was rewritten, and what it pins now is the
    narrower and still-true claim: with no credentials file, an unauthenticated
    caller changes persistent state. Its counterpart,
    ``test_a_configured_password_refuses_the_same_post``, pins the other
    configuration, and the pair is what stops the register rotting in either
    direction.

    ⛔ It asserts a PERSISTENT MUTATION, not a status code. An earlier version
    accepted 200-or-303, and a cold read caught that **a login redirect is a
    303** — so the single test whose job was to notice authentication landing
    would have passed once it did. Worse, 200/303 is also satisfied by a
    validation bounce or a swallowed failure, so it could not distinguish "the
    caller changed the system" from "the caller was politely turned away".

    ⚠️ Coverage stated plainly: ONE of the 22 routes is exercised here. The full
    23-route sweep with a whole-database fingerprint lives in
    `internal/session2-harnesses/auth_probe.py`, which is **gitignored** — so
    in-repo, this anchor is the only behavioural evidence and the other 21 rest
    on the classification list above.
    """
    from starlette.testclient import TestClient

    app, db = app_and_db

    def _snoozed() -> int:
        return db._conn.execute("SELECT COUNT(*) FROM rule_type_snoozes").fetchone()[0]

    before = _snoozed()
    assert before == 0, "fixture is not clean; a pre-existing snooze would mask the result"

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
    assert _snoozed() == before + 1, (
        f"POST /rules/watchlist_mac/snooze (status {response.status_code}) did not "
        f"create a rule_type_snoozes row for an unauthenticated caller. If "
        f"authentication was implemented — note a login redirect is also a 303, "
        f"which is why this asserts the row and not the status — the register's "
        f"'22 of 23' evidence is now stale. Update item 5 rather than deleting this."
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


# --- The other configuration: a password IS set -------------------------------
#
# ⭐ Added 2026-08-25 with the auth feature. The tests above measure the default
# install and would go on passing untouched if the middleware were deleted
# tomorrow, because nothing in them ever builds an app that has a credential.
# These are the half that notices.


@pytest.fixture()
def authed_app_and_db():
    """The same fixture, plus a credentials file, so auth is switched on."""
    from lynceus.webui.auth import hash_password
    from lynceus.webui.credentials import write_credentials

    td = tempfile.mkdtemp()
    allowlist = Path(td) / "allowlist.yaml"
    allowlist.write_text("entries: []\n", encoding="utf-8")
    cfg = Config(
        db_path=td + "/s.db",
        rules_path=str(REPO_ROOT / "config" / "rules.yaml"),
        allowlist_path=str(allowlist),
    )
    write_credentials(cfg.resolved_ui_auth_path(), hash_password("a-long-enough-password"))
    db = Database(cfg.db_path)
    db.ensure_location("default", "Default")
    try:
        yield create_app(cfg, db), db
    finally:
        db.close()


def test_a_configured_password_refuses_the_same_post(authed_app_and_db):
    """The mirror of ``test_the_register_claim_is_still_true``.

    ⛔ Asserts the ABSENCE of a persistent mutation, not merely a status code —
    the same reasoning that made the original anchor stop accepting 200-or-303.
    A refusal that still wrote the row would be the worst of both.
    """
    from starlette.testclient import TestClient

    app, db = authed_app_and_db

    def _snoozed() -> int:
        return db._conn.execute("SELECT COUNT(*) FROM rule_type_snoozes").fetchone()[0]

    before = _snoozed()
    assert before == 0, "fixture is not clean"

    client = TestClient(app, follow_redirects=False)
    response = client.post(
        "/rules/watchlist_mac/snooze",
        data={"duration_seconds": "86400"},
        headers={"accept": "*/*"},
    )
    assert response.status_code == 401, (
        f"POST with no session returned {response.status_code}, not 401"
    )
    assert _snoozed() == before, (
        "an unauthenticated POST created a rule_type_snoozes row even though a "
        "password is configured — the middleware is not in the path"
    )


def test_the_post_surface_gains_exactly_login_and_logout_when_auth_is_on(
    app_and_db, authed_app_and_db
):
    """Derived from both live apps, so the delta is measured, not asserted.

    ⚠️ The point is that enabling auth adds the credential routes and NOTHING
    else. A middleware that also registered, say, a password-reset endpoint
    would be a new unauthenticated surface nobody classified.
    """
    open_routes = _post_routes(app_and_db[0])
    authed_routes = _post_routes(authed_app_and_db[0])
    assert open_routes == CLASSIFIED, "the no-credential surface drifted"
    assert authed_routes - open_routes == {"/login", "/logout"}, (
        f"enabling auth changed the POST surface by "
        f"{sorted(authed_routes - open_routes)}, expected exactly /login and /logout"
    )
    assert not (open_routes - authed_routes), (
        f"enabling auth REMOVED POST routes: {sorted(open_routes - authed_routes)}"
    )
