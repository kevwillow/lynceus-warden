"""CSRF protection via the double-submit cookie pattern.

Lightweight ASGI middleware. State-changing requests (POST/PUT/PATCH/DELETE)
must present a CSRF token in either an X-CSRF-Token header or a `_csrf` form
field; the value is compared in constant time to the talos_csrf cookie.

Even when the UI is bound to localhost only, CSRF still matters: any other
browser tab the user has open can fire requests at `http://127.0.0.1:...`,
so binding to loopback is not by itself a defence. The cookie+token check is.
"""

from __future__ import annotations

import secrets
from urllib.parse import parse_qs

CSRF_COOKIE_NAME = "talos_csrf"
CSRF_HEADER_NAME = "X-CSRF-Token"
CSRF_FORM_FIELD = "_csrf"
CSRF_COOKIE_MAX_AGE = 60 * 60 * 8

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def generate_token() -> str:
    return secrets.token_urlsafe(32)


def constant_time_compare(a: str, b: str) -> bool:
    if not isinstance(a, str) or not isinstance(b, str):
        return False
    if len(a) != len(b):
        return False
    return secrets.compare_digest(a, b)


def get_csrf_token(request) -> str:
    return request.cookies.get(CSRF_COOKIE_NAME, "")


def _parse_cookie_header(header: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in header.split(";"):
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def _parse_form_token(body: bytes) -> str | None:
    try:
        decoded = body.decode("utf-8")
    except UnicodeDecodeError:
        return None
    parsed = parse_qs(decoded, keep_blank_values=True)
    values = parsed.get(CSRF_FORM_FIELD)
    if not values:
        return None
    return values[0]


# --- Body read-and-replay -----------------------------------------------------
# The request body can only be read once: the ASGI `receive` callable hands out
# each chunk a single time and then it's gone. To validate the CSRF token from
# the form body AND still let the route handler read the same body via
# FastAPI's `Form()` / Starlette's `request.form()`, we read the body once
# here, then hand the route a fresh `receive` callable that replays the bytes
# we captured.
#
# Do not remove the replay wrapper. Without it, the route's form parser will
# wait forever on a stream that's already been drained — the failure shows up
# as a hang, not an exception, so a regression test would just time out and
# get killed by CI rather than fail loudly. Verified empirically.
#
# ASGI receive is single-shot. To validate the CSRF token from the request
# body (form field) AND let the downstream route also read the body via
# FastAPI Form() / Starlette request.form(), we read the body once here
# and replay it via a fresh receive callable. Removing this replay will
# cause downstream form parsing to hang indefinitely waiting on an
# exhausted stream. Verified empirically; do not "simplify" without
# re-validating with a manual hang test.
async def _read_body(receive) -> bytes:
    chunks: list[bytes] = []
    while True:
        msg = await receive()
        msg_type = msg.get("type")
        if msg_type == "http.request":
            chunks.append(msg.get("body", b"") or b"")
            if not msg.get("more_body", False):
                break
        elif msg_type == "http.disconnect":
            break
    return b"".join(chunks)


def _replay_receive(body: bytes):
    sent = False

    async def receive():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    return receive


async def _send_403(send) -> None:
    body = b"CSRF token mismatch"
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


class CSRFMiddleware:
    """ASGI middleware enforcing CSRF on state-changing requests."""

    def __init__(self, app, *, cookie_secure: bool = False) -> None:
        self.app = app
        self.cookie_secure = cookie_secure

    def _build_cookie_value(self, token: str) -> str:
        parts = [
            f"{CSRF_COOKIE_NAME}={token}",
            f"Max-Age={CSRF_COOKIE_MAX_AGE}",
            "Path=/",
            "SameSite=Strict",
        ]
        if self.cookie_secure:
            parts.append("Secure")
        return "; ".join(parts)

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "GET").upper()
        headers = scope.get("headers") or []
        cookie_header = ""
        content_type = ""
        header_token = ""
        for name, value in headers:
            lname = name.decode("latin-1").lower()
            if lname == "cookie":
                cookie_header += (";" if cookie_header else "") + value.decode("latin-1")
            elif lname == "content-type":
                content_type = value.decode("latin-1").lower()
            elif lname == "x-csrf-token":
                header_token = value.decode("latin-1")

        cookies = _parse_cookie_header(cookie_header)
        cookie_value = cookies.get(CSRF_COOKIE_NAME)

        if method in _SAFE_METHODS:
            if cookie_value is None:
                token_to_set = generate_token()
                cookie_str = self._build_cookie_value(token_to_set).encode("latin-1")
                injected_headers: list[tuple[bytes, bytes]] = []
                cookie_seen = False
                for name, value in headers:
                    if name.decode("latin-1").lower() == "cookie":
                        merged = value.decode("latin-1") + f"; {CSRF_COOKIE_NAME}={token_to_set}"
                        injected_headers.append((name, merged.encode("latin-1")))
                        cookie_seen = True
                    else:
                        injected_headers.append((name, value))
                if not cookie_seen:
                    injected_headers.append(
                        (b"cookie", f"{CSRF_COOKIE_NAME}={token_to_set}".encode("latin-1"))
                    )
                new_scope = {**scope, "headers": injected_headers}

                async def send_wrapper(message):
                    if message.get("type") == "http.response.start":
                        new_headers = list(message.get("headers") or [])
                        new_headers.append((b"set-cookie", cookie_str))
                        message = {**message, "headers": new_headers}
                    await send(message)

                await self.app(new_scope, receive, send_wrapper)
            else:
                await self.app(scope, receive, send)
            return

        if cookie_value is None:
            await _send_403(send)
            return

        if header_token and constant_time_compare(cookie_value, header_token):
            await self.app(scope, receive, send)
            return

        if content_type.startswith("application/x-www-form-urlencoded"):
            body = await _read_body(receive)
            form_token = _parse_form_token(body)
            if form_token and constant_time_compare(cookie_value, form_token):
                await self.app(scope, _replay_receive(body), send)
                return

        await _send_403(send)
