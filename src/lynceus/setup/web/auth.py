"""Setup-token gate for the lynceus-setup web wizard.

The wizard is bound to loopback by default but still requires a
per-run secret in either ``?token=<token>`` (query string) or an
``X-Setup-Token`` header. Bare requests get 403. This stops drive-by
access from any other process or browser tab that happens to know the
loopback port.

Comparison is constant-time via ``secrets.compare_digest``; equal
lengths matter, so we early-return False on length mismatch instead of
letting ``compare_digest`` raise.

Exempt paths skip the check entirely. ``/healthz`` is exempt for
liveness probes; ``/static/`` is exempt so the operator's browser can
fetch CSS without re-attaching the token to every asset URL. Exempt
paths are matched by exact-equal OR child-of (``path == p`` or
``path.startswith(p + "/")``) so ``/static`` covers ``/static/x.css``
without accidentally exempting ``/staticthing``.
"""

from __future__ import annotations

from collections.abc import Iterable
from secrets import compare_digest
from urllib.parse import parse_qs


class SetupTokenMiddleware:
    """ASGI middleware enforcing the setup token on every non-exempt route."""

    def __init__(
        self,
        app,
        *,
        setup_token: str,
        exempt_paths: Iterable[str] = (),
    ) -> None:
        self.app = app
        self.setup_token = setup_token
        self.exempt_paths = tuple(exempt_paths)

    def _is_exempt(self, path: str) -> bool:
        for exempt in self.exempt_paths:
            if path == exempt or path.startswith(exempt + "/"):
                return True
        return False

    def _extract_token(self, scope) -> str | None:
        headers = scope.get("headers") or []
        for name, value in headers:
            if name.decode("latin-1").lower() == "x-setup-token":
                return value.decode("latin-1")
        qs = scope.get("query_string") or b""
        if not qs:
            return None
        try:
            params = parse_qs(qs.decode("latin-1"), keep_blank_values=True)
        except UnicodeDecodeError:
            return None
        values = params.get("token")
        if not values:
            return None
        return values[0]

    def _token_valid(self, provided: str | None) -> bool:
        if not provided:
            return False
        if len(provided) != len(self.setup_token):
            return False
        return compare_digest(provided, self.setup_token)

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if self._is_exempt(path):
            await self.app(scope, receive, send)
            return
        provided = self._extract_token(scope)
        if not self._token_valid(provided):
            await _send_403(send)
            return
        await self.app(scope, receive, send)


async def _send_403(send) -> None:
    body = b"setup token required"
    await send(
        {
            "type": "http.response.start",
            "status": 403,
            "headers": [
                (b"content-type", b"text/plain; charset=utf-8"),
                (b"content-length", str(len(body)).encode("latin-1")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body, "more_body": False})
