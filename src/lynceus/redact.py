"""Shared redaction helpers for ntfy topic / URL surfaces.

The ntfy topic functions as a shared-secret URL path component on public
brokers: anyone who knows it can both subscribe to alerts and inject false
alerts. Any log line, terminal print, or rendered template that echoes the
raw topic leaks that secret. Centralizing the redaction shape here keeps
every leak surface consistent — the webui rendering, the notifier's failure
logs, and the setup wizard's summary / probe-error prints all defer to the
same helpers.

The format ``prefix•••suffix`` is borrowed verbatim from the existing
webui helper so operators see one recognizable shape across all surfaces.
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit


def redact_ntfy_topic(topic: str | None) -> str:
    """Return a length-preserving-ish redaction of an ntfy topic.

    Topics of 6+ characters render as first 4 + ``•••`` + last 2; shorter
    topics collapse to ``•••``; ``None`` and empty input return ``""``.
    Mirrors the original ``_redact_ntfy_topic`` from ``webui/app.py``.
    """
    if topic is None:
        return ""
    if len(topic) < 6:
        return "•••" if topic else ""
    return topic[:4] + "•••" + topic[-2:]


def redact_topic_in_url(url: str | None) -> str:
    """Replace the final path segment of a URL with the redacted topic form.

    URLs with no path (``https://ntfy.sh``) or a bare-root path
    (``https://ntfy.sh/``) are returned unchanged — there is no topic to
    redact. Query strings and fragments are preserved. Trailing slashes
    on the topic segment are preserved. Inputs that ``urlsplit`` rejects
    are returned unchanged so this helper is safe to wrap around any log
    string without risking a new exception class on the failure path.
    """
    if not url:
        return url or ""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    path = parts.path
    if not path or path == "/":
        return url
    trailing_slash = path.endswith("/")
    stripped = path.rstrip("/")
    if not stripped:
        return url
    head, sep, tail = stripped.rpartition("/")
    if not tail:
        return url
    redacted_tail = redact_ntfy_topic(tail)
    new_path = (head + sep if sep else "") + redacted_tail + ("/" if trailing_slash else "")
    return urlunsplit((parts.scheme, parts.netloc, new_path, parts.query, parts.fragment))
