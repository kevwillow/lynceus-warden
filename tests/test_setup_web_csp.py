"""Content-Security-Policy on the setup wizard app.

⭐ The wizard shipped with NO CSP while the dashboard had one. That was an
omission, not a decision, and it was the wrong way round: the wizard is the
MORE sensitive of the two apps. It holds the Kismet API key and the ntfy topic
in flight, it renders operator-supplied values back into its own forms, and in
system scope it runs as root. See docs/AUDIT_REGISTER.md, Wave 5, Finding 14.

These mirror tests/test_webui_csp.py deliberately. The two apps are separate
FastAPI instances with separate middleware stacks, so a guard on one proves
nothing about the other -- which is exactly how the gap arose.
"""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from lynceus.setup.web.app import create_wizard_app

_TOKEN = "test-setup-token"

#: Any inline event attribute is dead code under this policy: the browser
#: refuses it and the page silently loses whatever it did. Measured in
#: Chromium: "Executing inline event handler violates the following Content
#: Security Policy directive ... The action has been blocked."
#:
#: ⚠️ ``re.I`` here and on the ``<script>`` scan below is load-bearing. HTML
#: tag and attribute names are case-insensitive, so ``<SCRIPT>`` and
#: ``ONCLICK=`` are valid and a case-sensitive pattern reports zero offenders
#: while they sit on the page. CodeQL flagged the original as high severity
#: (py/bad-tag-filter) on this workflow's first run -- a real hole in a guard
#: whose whole job is completeness.
_EVENT_ATTR = re.compile(r"\son[a-z]+\s*=", re.I)


@pytest.fixture
def client(tmp_path):
    app = create_wizard_app(
        setup_token=_TOKEN,
        scope="user",
        target_path=tmp_path / "lynceus.yaml",
        skip_probes=True,
    )
    with TestClient(app) as c:
        yield c


def _get(client, path):
    return client.get(path, headers={"X-Setup-Token": _TOKEN})


def _policy(response):
    return response.headers.get("content-security-policy", "")


def _nonce_of(response):
    m = re.search(r"'nonce-([A-Za-z0-9_-]+)'", _policy(response))
    return m.group(1) if m else None


def test_every_wizard_route_sends_a_policy(client):
    """Routes are enumerated from the app, never hardcoded, so a step added
    later cannot quietly opt out."""
    app = client.app
    paths = sorted(
        r.path
        for r in app.routes
        if getattr(r, "path", "").startswith("/")
        and "{" not in getattr(r, "path", "")
        and "GET" in (getattr(r, "methods", None) or set())
        and not r.path.startswith("/static")
    )
    assert paths, "route enumeration found nothing; the test would prove nothing"
    missing = []
    for path in paths:
        r = _get(client, path)
        if r.status_code >= 500:
            continue
        if "content-security-policy" not in r.headers:
            missing.append((path, r.status_code))
    assert not missing, f"wizard routes served without a CSP: {missing}"


def test_policy_is_present_on_a_token_rejection(client):
    """⭐ Middleware order is load-bearing and easy to get backwards.
    CSPMiddleware is registered LAST so it wraps SetupTokenMiddleware; the
    other way round, the 403 an unauthenticated request gets would carry no
    policy at all -- and that is the response an attacker sees most."""
    r = client.get("/")  # no token
    assert r.status_code == 403, f"expected a token rejection, got {r.status_code}"
    assert "content-security-policy" in r.headers, (
        "the token rejection was served without a policy; CSP is inside the token gate"
    )


def _directives(policy: str) -> dict[str, list[str]]:
    """Parse a CSP into ``{name: [sources]}`` — see the twin in test_webui_csp.

    A directive is a space-separated source list, so substring checks cannot
    distinguish ``object-src 'none'`` from ``object-src 'none' https://evil``.
    """
    out: dict[str, list[str]] = {}
    for chunk in policy.split(";"):
        parts = chunk.split()
        if parts:
            out[parts[0]] = parts[1:]
    return out


def test_script_src_is_strict(client):
    policy = _policy(_get(client, "/"))
    directives = _directives(policy)
    script_src = directives.get("script-src", [])
    assert script_src and script_src[0] == "'self'", f"script-src: {script_src}"
    assert any(s.startswith("'nonce-") for s in script_src), (
        f"script-src carries no nonce: {script_src}"
    )
    assert "'unsafe-inline'" not in script_src, "the nonce is the whole point"
    # Exactly self + one nonce, nothing appended. The substring form of this
    # assertion passed with an attacker source on the end.
    assert len(script_src) == 2, (
        f"script-src must be exactly ['self', nonce], got {script_src}"
    )


def test_the_locked_down_directives_are_exactly_locked_down(client):
    """Sibling of test_webui_csp's equality check — the wizard holds the
    Kismet API key and the ntfy topic in flight, so its policy matters at
    least as much as the dashboard's."""
    directives = _directives(_policy(_get(client, "/")))
    for name, expected in (
        ("default-src", ["'self'"]),
        ("object-src", ["'none'"]),
        ("base-uri", ["'none'"]),
        ("frame-ancestors", ["'none'"]),
        ("form-action", ["'self'"]),
    ):
        assert name in directives, f"missing {name!r} entirely"
        assert directives[name] == expected, (
            f"{name} must be exactly {expected}, got {directives[name]}"
        )
    assert len(directives) >= 10, f"implausibly few directives: {sorted(directives)}"


def test_nonce_differs_on_every_request(client):
    seen = {_nonce_of(_get(client, "/")) for _ in range(8)}
    assert None not in seen
    assert len(seen) == 8, f"nonce repeated across requests: {seen}"


def test_every_inline_script_carries_the_current_nonce(client):
    """A nonce that does not reach a template renders as an empty attribute,
    the browser refuses that script, and nothing errors -- the wizard just
    silently loses its theme bootstrap or its apply-progress stream."""
    r = _get(client, "/")
    nonce = _nonce_of(r)
    assert nonce
    inline = re.findall(r"<script(?![^>]*\ssrc=)([^>]*)>", r.text, re.I)
    assert inline, "no inline script on the landing page; the test proves nothing"
    for attrs in inline:
        assert f'nonce="{nonce}"' in attrs, f"inline script without the nonce: <script{attrs}>"
    assert 'nonce=""' not in r.text, "an empty nonce rendered somewhere"


def test_no_inline_event_handlers_on_any_wizard_step(client):
    """⛔ The regression tripwire. The wizard carried five of these: two
    double-submit guards on /apply and /done, the live RSSI readout, and the
    select-all-rule-types toggle. Each fails SILENTLY under the policy -- the
    slider stops tracking, "select all" ticks and does nothing, and /apply
    becomes double-clickable on the step that writes config and, in system
    scope, chowns files."""
    offenders = []
    paths = ["/"] + [f"/step/{n}" for n in range(1, 14)] + ["/review"]
    checked = 0
    for path in paths:
        r = _get(client, path)
        if r.status_code != 200:
            continue
        checked += 1
        for m in _EVENT_ATTR.finditer(r.text):
            start = max(0, m.start() - 90)
            offenders.append(f"{path}: ...{r.text[start:m.end() + 40]}...")
    assert checked >= 5, f"only {checked} wizard pages rendered; the sweep is too thin"
    assert not offenders, "inline event handlers are blocked by the CSP:\n" + "\n".join(offenders)


#: Each converted handler: the page it lives on, and a fragment of the
#: replacement listener that must actually reach the browser.
_REPLACEMENTS = [
    ("/step/10", 'getElementById("min_rssi_slider")', "RSSI live readout"),
    ("/step/12", 'getElementById("select-all-rule-types")', "select-all rule types"),
    ("/review", 'form.getAttribute("data-disable-on-submit")', "double-submit guard"),
]


@pytest.mark.parametrize("path,fragment,label", _REPLACEMENTS)
def test_each_converted_handler_has_a_live_replacement(client, path, fragment, label):
    """⭐ The other half of the pair, and it caught a real mistake.

    Deleting an inline handler satisfies the absence test above while leaving
    the behaviour gone -- which is strictly worse than the CSP breakage it was
    meant to fix, because it fails on every browser rather than just modern
    ones. This is not hypothetical: the RSSI and select-all replacements were
    first appended AFTER `{% endblock %}` in their templates, where Jinja
    inheritance silently discards them. Both rendered nothing, the absence
    test still passed, and only a pre-existing wizard test noticed.

    ⇒ An absence assertion needs a presence assertion beside it."""
    r = _get(client, path)
    assert r.status_code == 200, f"{path} did not render ({r.status_code})"
    assert fragment in r.text, (
        f"{label}: replacement listener missing from {path} -- the behaviour is gone. "
        "Check it is inside {% block content %}, not after {% endblock %}."
    )
