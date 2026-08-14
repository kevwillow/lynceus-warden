"""Content-Security-Policy, with a per-request nonce for the inline scripts.

⭐ Why this exists. The UI had **no CSP at all** — measured; only
``CSRFMiddleware`` was installed — while several internal documents asserted
that "a strict CSP applies". `docs/AUDIT_REGISTER.md` records that claim as
false. Escaping was the only barrier between an operator-controlled MAC, SSID
or location name and script execution, and a single overlooked raw render
anywhere would have run unopposed.

**Why a nonce rather than hashes.** The pages carry several inline scripts, and
one of them is *generated*: the ``data_table`` macro emits
``__lynTableApply('<table id>')`` per opted-in table, so its body differs per
table and a static hash list could never cover it. A nonce covers generated and
static inline script alike.

**Why ``style-src`` still allows inline.** Nine ``style="..."`` attributes
remain across five templates, and CSP nonces do not apply to style
*attributes*. Inline style is a far weaker vector than inline script, so the
compromise is confined to styles and ``script-src`` stays strict. Removing it
means moving those attributes into the stylesheet first — ``_alerts_chart.html``
computes some of them, so that is not a mechanical change.

**Why no ``report-uri``.** This is an offline, localhost-bound tool. There is no
collector to report to, so a Report-Only rollout would have provided no
protection and sent violations nowhere.
"""

from __future__ import annotations

import secrets

#: Directives that never vary. ``script-src`` is completed per request with the
#: nonce. ``object-src``/``base-uri``/``frame-ancestors`` are the three that
#: cost nothing here and close off plugin embedding, ``<base>`` hijacking and
#: clickjacking respectively.
_STATIC_DIRECTIVES = (
    "default-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
    "form-action 'self'",
)


def build_policy(nonce: str) -> str:
    """The full policy string for one request."""
    directives = [f"script-src 'self' 'nonce-{nonce}'", *_STATIC_DIRECTIVES]
    return "; ".join(directives)


def generate_nonce() -> str:
    """A fresh nonce per request.

    ⚠️ Per REQUEST, never per process. A nonce reused across responses is worth
    no more than ``'unsafe-inline'``: an attacker who can read one page learns
    the value and can then author script that any later page will execute.
    """
    return secrets.token_urlsafe(16)


class CSPMiddleware:
    """ASGI middleware: mint a nonce, publish it, set the header.

    The nonce is published on ``scope["state"]`` so templates can read it as
    ``request.state.csp_nonce``. That is deliberately not a Jinja environment
    global: globals are per-application and this value must differ per request.
    """

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        nonce = generate_nonce()
        # Starlette reads Request.state from scope["state"], so copy rather
        # than mutate: the caller's scope may be reused.
        state = dict(scope.get("state") or {})
        state["csp_nonce"] = nonce
        new_scope = {**scope, "state": state}
        policy = build_policy(nonce).encode("latin-1")

        async def send_wrapper(message):
            if message.get("type") == "http.response.start":
                headers = list(message.get("headers") or [])
                # Replace rather than append, so a policy set further down the
                # stack cannot end up duplicated -- browsers intersect repeated
                # CSP headers, and two policies is a confusing way to debug.
                headers = [
                    (n, v)
                    for n, v in headers
                    if n.decode("latin-1").lower() != "content-security-policy"
                ]
                headers.append((b"content-security-policy", policy))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(new_scope, receive, send_wrapper)
