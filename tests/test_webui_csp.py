"""Content-Security-Policy: the header, the nonce, and the inline scripts.

⭐ The UI shipped with NO CSP while several internal documents asserted that
"a strict CSP applies" -- a claim docs/AUDIT_REGISTER.md records as false.
Escaping was the only barrier between an operator-controlled MAC, SSID or
location name and script execution.

These tests exist because a CSP is the kind of control that fails silently in
both directions: a missing header protects nothing and looks fine, and a
nonce that does not reach a template blocks that page's script and looks fine
too, until the pre-paint theme flash or the table-state jump comes back.
"""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import create_app
from lynceus.webui.csp import build_policy, generate_nonce


@pytest.fixture
def client(tmp_path):
    config = Config(db_path=str(tmp_path / "csp.db"))
    db = Database(config.db_path)
    app = create_app(config, db)
    with TestClient(app) as c:
        yield c
    db.close()


def _policy(response):
    return response.headers.get("content-security-policy", "")


def _directives(policy: str) -> dict[str, list[str]]:
    """Parse a CSP into ``{name: [sources]}``.

    ⚠️ Why this exists. Every directive here used to be asserted with
    ``assert "object-src 'none'" in policy``, and a CSP directive is a
    SPACE-SEPARATED SOURCE LIST — so ``object-src 'none' https://evil.example``
    contains that substring and satisfied the assertion. Appending an attacker
    source to any directive left both CSP guards green.

    That is the same defect as the URL-substring guards fixed in #26, on the
    security control that matters most: the whole point of ``'none'`` is that
    it is the ENTIRE list, and only comparing the parsed list can say so.
    """
    out: dict[str, list[str]] = {}
    for chunk in policy.split(";"):
        parts = chunk.split()
        if parts:
            out[parts[0]] = parts[1:]
    return out


def _nonce_of(response):
    m = re.search(r"'nonce-([A-Za-z0-9_-]+)'", _policy(response))
    return m.group(1) if m else None


# ⚠️ Every `<script>` scan below is case-INSENSITIVE, and that is not
# defensive tidiness. CodeQL flagged the original patterns as high severity
# (py/bad-tag-filter): HTML tag names are case-insensitive, so `<SCRIPT>` is a
# perfectly valid inline script that `r"<script"` does not match.
#
# For a guard whose entire job is "EVERY inline script carries the nonce",
# that is a hole of exactly the shape this file exists to close -- the scan
# would report zero offenders while an unnonced script sat on the page. The
# templates are ours and lowercase today; the guard must not depend on that
# staying true. Found by CI on its first run against this branch.


# --- the header itself ---------------------------------------------------


def test_every_html_route_sends_a_policy(client):
    """⭐ Routes are enumerated from the app, never hardcoded.

    A hardcoded list stops covering a newly added route silently, which is a
    failure mode this project has already hit three times -- the AGPL footer
    guard exists for the same reason.
    """
    app = client.app
    paths = sorted(
        r.path
        for r in app.routes
        if getattr(r, "path", "").startswith("/")
        and "{" not in getattr(r, "path", "")
        and "GET" in (getattr(r, "methods", None) or set())
        and not r.path.startswith("/static")
        and not r.path.endswith(".csv")
    )
    assert paths, "route enumeration found nothing; the test would prove nothing"
    missing = []
    for path in paths:
        r = client.get(path)
        if r.status_code >= 500:
            continue
        if "content-security-policy" not in r.headers:
            missing.append((path, r.status_code))
    assert not missing, f"routes served without a CSP: {missing}"


def test_policy_locks_down_script_src_and_the_usual_suspects(client):
    policy = _policy(client.get("/"))
    assert "script-src 'self' 'nonce-" in policy
    assert "'unsafe-inline'" not in policy.split("script-src")[1].split(";")[0], (
        "script-src must not allow inline; the nonce is the whole point"
    )
    # EQUALITY on the parsed source list, not substring containment. An
    # attacker source appended to any of these leaves the substring intact.
    directives = _directives(policy)
    for name, expected_sources in (
        ("default-src", ["'self'"]),
        ("object-src", ["'none'"]),
        ("base-uri", ["'none'"]),
        ("frame-ancestors", ["'none'"]),
        ("form-action", ["'self'"]),
    ):
        assert name in directives, f"missing {name!r} entirely"
        assert directives[name] == expected_sources, (
            f"{name} must be exactly {expected_sources}, got {directives[name]} — "
            f"an extra source here silently widens the policy while every "
            f"substring check still passes"
        )
    # Presence beside equality: a parser that returned {} would satisfy nothing
    # above, but a policy that lost directives entirely should also be loud.
    assert len(directives) >= 10, f"implausibly few directives: {sorted(directives)}"


def test_style_src_inline_is_allowed_and_that_is_deliberate(client):
    """Nine style= attributes remain across five templates and CSP nonces do
    not apply to style attributes. Pinned so the compromise is a decision on
    the record rather than an accident, and so removing those attributes later
    is a visible change here."""
    policy = _policy(client.get("/"))
    style = policy.split("style-src")[1].split(";")[0]
    assert "'unsafe-inline'" in style


# --- the nonce -----------------------------------------------------------


def test_nonce_differs_on_every_request(client):
    """⚠️ A nonce reused across responses is worth no more than
    'unsafe-inline': an attacker who reads one page learns the value and can
    author script any later page will execute."""
    seen = {_nonce_of(client.get("/")) for _ in range(8)}
    assert None not in seen
    assert len(seen) == 8, f"nonce repeated across requests: {seen}"


def test_every_inline_script_carries_the_current_nonce(client):
    """The header and the markup must agree. A nonce that does not reach a
    template renders as an empty attribute, the browser refuses that script,
    and nothing errors -- the page just silently loses the behaviour."""
    r = client.get("/")
    nonce = _nonce_of(r)
    assert nonce
    inline = re.findall(r"<script(?![^>]*\ssrc=)([^>]*)>", r.text, re.I)
    assert inline, "no inline script found on the homepage; the test proves nothing"
    for attrs in inline:
        assert f'nonce="{nonce}"' in attrs, (
            f"inline script without the current nonce: <script{attrs}>"
        )


def test_the_table_macro_script_gets_the_nonce_through_the_import(client):
    """⭐ The macro is imported into each page, and a Jinja macro cannot see
    the caller's context unless the import says `with context`. Without it
    request.state.csp_nonce renders EMPTY inside the macro, the browser blocks
    the pre-paint applier, and the default->persisted column jump returns with
    no error anywhere. This is that regression's tripwire."""
    # The macro only renders inside `{% if devices %}`, so an empty database
    # would silently give this test nothing to look at.
    client.app.state.db.upsert_device("aa:bb:cc:dd:ee:01", "wifi", "Acme", 0, 1700000000)
    r = client.get("/devices")
    assert r.status_code == 200
    nonce = _nonce_of(r)
    assert nonce
    assert "__lynTableApply" in r.text, "no table macro script on /devices; fixture is wrong"
    macro_scripts = re.findall(r"<script([^>]*)>window\.__lynTableApply", r.text, re.I)
    assert macro_scripts, "table applier script not found"
    for attrs in macro_scripts:
        assert f'nonce="{nonce}"' in attrs, (
            "the data_table macro emitted a script without the nonce -- the "
            "'with context' on its import is missing"
        )
    assert 'nonce=""' not in r.text, "an empty nonce rendered somewhere"


def test_csp_header_is_present_even_on_a_csrf_rejection(client):
    """Middleware order is load-bearing. Starlette applies middleware in
    reverse registration order, so CSPMiddleware is registered AFTER
    CSRFMiddleware in order to wrap it. Registered the other way round, a
    request CSRFMiddleware rejects would come back with no policy at all."""
    r = client.post("/alerts/1/ack", data={}, headers={"cookie": ""})
    assert r.status_code in (403, 404, 422), f"unexpected status {r.status_code}"
    assert "content-security-policy" in r.headers, (
        "a rejected request was served without a policy; CSP is inside CSRF"
    )


# --- inline event handlers -----------------------------------------------
#
# ⛔ These exist because the nonce tests above CANNOT catch this class. They
# inspect <script> tags, and a CSP nonce authorises <script> ELEMENTS only --
# never inline on*= attributes, which need 'unsafe-inline'/'unsafe-hashes'.
# The whole suite stayed green while eleven onsubmit="return confirm(...)"
# guards were silently blocked in the browser. Worse: a blocked onsubmit
# never returns false, so the form submitted with NO confirmation, turning
# "Permanently silence this device" into a one-click unconfirmed mutation.
#
# A guard that only checks the mechanism you implemented will not notice the
# mechanism you forgot.


_EVENT_ATTR = re.compile(r"\son[a-z]+\s*=", re.I)
_MAC = "aa:bb:cc:dd:ee:02"

#: Action suffixes that suppress alerting or change watch state. `/ack` and a
#: note SAVE are deliberately absent -- they are not destructive and have never
#: prompted.
_DESTRUCTIVE = ("/allowlist", "/watchlist", "/snooze", "/watch")


@pytest.fixture
def rich_client(tmp_path):
    """⚠️ A default-config client renders ONE of these forms. The silence
    section is gated on `allowlist_configured`, and the watchful/alert forms
    need an alert to exist -- so a naive fixture leaves most of the surface
    unrendered and the assertions below vacuously true. This was measured:
    with the inline handler planted back, the first version of these tests
    passed 12/12 because the form carrying the defect never rendered."""
    allowlist = tmp_path / "allow.yaml"
    allowlist.write_text("entries: []\n")
    config = Config(db_path=str(tmp_path / "csp2.db"), allowlist_path=str(allowlist))
    db = Database(config.db_path)
    db.upsert_device(_MAC, "wifi", "Acme", 0, 1700000000)
    alert_id = db.add_alert(
        ts=1700000000,
        rule_name="r1",
        mac=_MAC,
        message="m",
        severity="high",
        matched_watchlist_id=None,
        rule_type="watchlist_mac",
    )
    app = create_app(config, db)
    with TestClient(app) as c:
        c.alert_id = alert_id
        yield c
    db.close()


def _action_pages(client):
    return [f"/devices/{_MAC}", f"/alerts/{client.alert_id}", "/devices", "/alerts", "/rules"]


def test_no_inline_event_handlers_survive_anywhere(rich_client):
    """The regression tripwire for the confirm-dialog breakage.

    Any `on*=` attribute is dead code under this policy: the browser refuses
    it and the page silently loses whatever it did."""
    offenders = []
    for path in _action_pages(rich_client):
        r = rich_client.get(path)
        if r.status_code != 200:
            continue
        for m in _EVENT_ATTR.finditer(r.text):
            start = max(0, m.start() - 90)
            offenders.append(f"{path}: ...{r.text[start:m.end() + 40]}...")
    assert not offenders, "inline event handlers are blocked by the CSP:\n" + "\n".join(offenders)


def test_no_javascript_scheme_urls(rich_client):
    """`javascript:` navigations are blocked by the same directive, and
    hashes do not apply to them either."""
    for path in _action_pages(rich_client):
        r = rich_client.get(path)
        if r.status_code == 200:
            assert "javascript:" not in r.text.lower(), f"javascript: URL on {path}"


def test_every_destructive_form_still_carries_a_confirmation(rich_client):
    """⭐ The half that actually matters. Stripping the inline handlers and
    replacing them with NOTHING passes both tests above, while leaving every
    destructive action unguarded -- which is precisely the state the CSP
    shipped in. This pins that each one still asks first."""
    seen = 0
    missing = []
    for path in (f"/devices/{_MAC}", f"/alerts/{rich_client.alert_id}"):
        r = rich_client.get(path)
        assert r.status_code == 200, path
        for form in re.findall(r"<form\b[^>]*>", r.text):
            action = re.search(r'action="([^"]*)"', form)
            if not action or not any(action.group(1).endswith(d) for d in _DESTRUCTIVE):
                continue
            seen += 1
            if "data-confirm=" not in form:
                missing.append(f"{path}: {action.group(1)}")
    # Guard the guard: if the fixture stops rendering these, the loop above
    # would pass while proving nothing at all.
    assert seen >= 6, f"only {seen} destructive forms rendered; fixture is too thin"
    assert not missing, "destructive form with no confirmation:\n" + "\n".join(missing)


# --- unit level ----------------------------------------------------------


def test_build_policy_embeds_the_nonce():
    assert "'nonce-abc123'" in build_policy("abc123")


def test_generate_nonce_is_unpredictable():
    nonces = {generate_nonce() for _ in range(200)}
    assert len(nonces) == 200
    assert all(len(n) >= 16 for n in nonces)
