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

import re
from pathlib import Path
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


# --- YAML config redaction (for lynceus-export-config) ---------------------

# Top-level scalar fields in lynceus.yaml whose values are credentials and
# must be scrubbed before sharing an exported config. The set mirrors the
# secret-bearing fields of ``config.Config``: kismet_api_key (Kismet REST
# token), ntfy_auth_token (broker bearer), and ntfy_topic (functions as a
# shared secret on public brokers — see this module's header comment).
# Keep in sync with config.Config: a new credential field added there
# without a matching entry here would silently round-trip raw in exports.
_SECRET_FIELDS: tuple[str, ...] = (
    "kismet_api_key",
    "ntfy_auth_token",
    "ntfy_topic",
)

# Sentinel value the redactor writes in place of secrets. Operators
# restoring an export replace this verbatim with the real credential
# before restarting the daemon.
REDACTED_PLACEHOLDER = "<REDACTED>"

# YAML value forms that mean "no secret present" — these pass through
# unchanged so the redactor doesn't disguise an unset field as a redacted
# one. The wizard never writes these forms when a credential is supplied,
# so seeing one means the operator intentionally cleared the field.
_EMPTY_VALUE_TOKENS = frozenset({"", "null", "Null", "NULL", "~", "''", '""'})

_SECRET_LINE_RE = re.compile(
    r"^(?P<key>" + "|".join(_SECRET_FIELDS) + r")(?P<sep>\s*:\s*)(?P<val>.*)$"
)

_NTFY_URL_LINE_RE = re.compile(
    r"^(?P<key>ntfy_url)(?P<sep>\s*:\s*)(?P<val>.*)$"
)


def _strip_url_userinfo(raw: str) -> str | None:
    """Strip ``user:pass@`` from a URL value. Return None if no userinfo.

    Preserves YAML quoting (single or double) so the rewritten line stays
    a valid YAML scalar. Returns None for empty / null-token inputs and
    for URLs that don't actually carry userinfo, so callers know to leave
    the original line untouched.
    """
    if raw in _EMPTY_VALUE_TOKENS:
        return None
    quote = ""
    inner = raw
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in ('"', "'"):
        quote = raw[0]
        inner = raw[1:-1]
    try:
        parts = urlsplit(inner)
    except ValueError:
        return None
    if "@" not in parts.netloc:
        return None
    new_netloc = parts.netloc.split("@", 1)[1]
    new_url = urlunsplit(
        (parts.scheme, new_netloc, parts.path, parts.query, parts.fragment)
    )
    return f"{quote}{new_url}{quote}"


def redact_yaml_config(filename: str, content: str) -> tuple[str, list[str]]:
    """Return ``(redacted_content, redacted_field_names)`` for a config file.

    Only ``lynceus.yaml`` carries credentials in the current schema (see
    ``config.Config``). Other Lynceus config files — ``rules.yaml``,
    ``severity_overrides.yaml``, ``allowlist.yaml``, ``allowlist_ui.yaml`` —
    have no secret-bearing fields and pass through unchanged with an empty
    field list. Callers record the empty list in the export manifest so the
    receiver can see that those files were considered and found clean,
    rather than skipped.

    The implementation is intentionally line-based — not YAML round-trip —
    so operator comments, key ordering, and whitespace survive. Trade-off:
    secrets written as block scalars (``key: |``) or folded scalars
    (``key: >``) are not recognized and would round-trip raw. The wizard
    never produces those forms for credential fields, but an operator who
    hand-edits to a block scalar is responsible for that choice.

    Redacted shapes:
    - ``kismet_api_key: TOKEN``       -> ``kismet_api_key: <REDACTED>``
    - ``ntfy_auth_token: TOKEN``      -> ``ntfy_auth_token: <REDACTED>``
    - ``ntfy_topic: TOKEN``           -> ``ntfy_topic: <REDACTED>``
    - ``ntfy_url: https://u:p@h/...`` -> ``ntfy_url: https://h/...``
      (only when userinfo is present; otherwise unchanged)

    Returns the field names that were actually changed. For ``ntfy_url``
    the entry is ``"ntfy_url:userinfo"`` to distinguish "URL credential
    stripped" from "secret value masked".
    """
    if Path(filename).name != "lynceus.yaml":
        return content, []

    redacted_fields: list[str] = []
    out_chunks: list[str] = []

    for line in content.splitlines(keepends=True):
        # Split body from trailing newline so the regex matches without
        # the EOL eating into the value group.
        stripped = line.rstrip("\r\n")
        eol = line[len(stripped):]

        m = _SECRET_LINE_RE.match(stripped)
        if m:
            value_token = m.group("val").strip()
            if value_token in _EMPTY_VALUE_TOKENS:
                out_chunks.append(line)
                continue
            out_chunks.append(
                f"{m.group('key')}{m.group('sep')}{REDACTED_PLACEHOLDER}{eol}"
            )
            redacted_fields.append(m.group("key"))
            continue

        m = _NTFY_URL_LINE_RE.match(stripped)
        if m:
            stripped_url = _strip_url_userinfo(m.group("val").strip())
            if stripped_url is not None:
                out_chunks.append(
                    f"{m.group('key')}{m.group('sep')}{stripped_url}{eol}"
                )
                redacted_fields.append("ntfy_url:userinfo")
                continue

        out_chunks.append(line)

    return "".join(out_chunks), redacted_fields
