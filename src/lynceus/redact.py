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

import yaml


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


class RedactionFailure(RuntimeError):
    """Raised when a config file cannot be proven free of secrets.

    Deliberately an exception rather than a warning. Every other outcome in
    this module ends with a file inside a shareable archive, so a failure that
    merely logs would be a failure that ships.
    """

# YAML value forms that mean "no secret present" — these pass through
# unchanged so the redactor doesn't disguise an unset field as a redacted
# one. The wizard never writes these forms when a credential is supplied,
# so seeing one means the operator intentionally cleared the field.
_EMPTY_VALUE_TOKENS = frozenset({"", "null", "Null", "NULL", "~", "''", '""'})

_SECRET_LINE_RE = re.compile(
    r"^(?P<key>" + "|".join(_SECRET_FIELDS) + r")(?P<sep>\s*:\s*)(?P<val>.*)$"
)

# ⚠️ kismet_url was NOT inspected at all, only ntfy_url. Both accept
# `scheme://user:pass@host/...`, and the Kismet one guards the capture API.
_URL_FIELDS: tuple[str, ...] = ("ntfy_url", "kismet_url")

_URL_LINE_RE = re.compile(
    r"^(?P<key>" + "|".join(_URL_FIELDS) + r")(?P<sep>\s*:\s*)(?P<val>.*)$"
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
    # ⛔ Split the YAML inline comment off FIRST. `urlsplit` reads `#` as the
    # start of a fragment, so `kismet_url: http://h:2501  # broker` parsed as a
    # URL with fragment " broker" -- and dropping "the fragment" silently ate
    # the operator's comment. YAML requires whitespace before an inline `#`,
    # which is exactly what distinguishes it from a genuine URL fragment.
    comment = ""
    for marker in ("  #", " #"):
        idx = raw.find(marker)
        if idx != -1:
            comment = raw[idx:]
            raw = raw[:idx]
            break
    raw = raw.rstrip()
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
    has_userinfo = "@" in parts.netloc
    # ⚠️ A token rides in `?token=` as often as in userinfo, and returning None
    # for "no @" meant a query-string credential was never touched at all.
    if not has_userinfo and not parts.query and not parts.fragment:
        return None
    # ⛔ rsplit, not split. The userinfo delimiter is the LAST '@' -- a
    # password containing '@' ("alice:p@ss@host") left "ss@host" as the new
    # netloc, i.e. part of the credential surviving as apparent userinfo.
    new_netloc = parts.netloc.rsplit("@", 1)[1] if has_userinfo else parts.netloc
    # ⛔ query and fragment are dropped, not preserved. `ntfy_topic` is treated
    # as a shared secret by this module's own header, and a topic or bearer
    # token rides in `?token=` just as often as in userinfo. Keeping them was
    # stripping the lock and leaving the key under the mat.
    new_url = urlunsplit((parts.scheme, new_netloc, parts.path, "", ""))
    if f"{quote}{new_url}{quote}" == f"{quote}{inner}{quote}":
        return None  # nothing actually changed; leave the line alone
    return f"{quote}{new_url}{quote}{comment}"


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
    # ⛔ Learned by PARSING THE ORIGINAL, not by scraping the lines we rewrote.
    # An anchor parks the credential under an innocent key and leaves only a
    # reference where the secret name is (`cred: &c TOKEN` / `kismet_api_key:
    # *c`). Scraping the matched line records the string `*c` and never learns
    # the token, so the masked LINE looked like success while the value sat
    # three lines up. Resolving through the loader is what makes an alias give
    # up what it points at.
    seen_secret_values: list[str] = _secret_values_in(content)

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

        m = _URL_LINE_RE.match(stripped)
        if m:
            stripped_url = _strip_url_userinfo(m.group("val").strip())
            if stripped_url is not None:
                out_chunks.append(
                    f"{m.group('key')}{m.group('sep')}{stripped_url}{eol}"
                )
                redacted_fields.append(f"{m.group('key')}:userinfo")
                continue

        out_chunks.append(line)

    rewritten = "".join(out_chunks)

    # ⛔ VERIFY, then claim. Everything above is a syntax-recognising rewriter,
    # and the caller turns its return value into `redaction_applied: true` in a
    # manifest an operator hands to a stranger. Ten of eleven spellings of the
    # same credential survived that rewriter, four of them while being REPORTED
    # as redacted. So the rewriter no longer gets the last word: the result is
    # parsed and checked, and if a secret is still in there the formatting-
    # preserving output is thrown away for one that is actually clean.
    # ⚠️ An original that does not parse cannot be verified either way, and
    # refusing it would regress a documented capability: the exporter
    # deliberately supports backing up a BROKEN config. So the line-based
    # result still ships, marked plainly as unverified rather than claimed as
    # clean. Only a file that parsed BEFORE and is still dirty AFTER is a
    # failure this module caused and must refuse.
    if _secret_values_surviving(content) == ["<unparseable>"]:
        return rewritten, redacted_fields + ["<unverified: file does not parse>"]

    survivors = _secret_values_surviving(rewritten)
    escaped = [v for v in seen_secret_values if v in rewritten]
    if not survivors and not escaped:
        return rewritten, redacted_fields
    survivors = survivors + [f"<value escaped elsewhere: {v[:4]}...>" for v in escaped]

    fallback = _redact_semantically(content, seen_secret_values)
    if fallback is not None:
        dumped, changed = fallback
        if not _secret_values_surviving(dumped) and not any(
            v in dumped for v in seen_secret_values
        ):
            # Comments and key order are gone; the credential is too.
            return dumped, sorted(set(redacted_fields) | set(changed))

    # Neither path could prove the file clean. Refuse to emit it rather than
    # ship a live credential under a manifest that says otherwise -- the caller
    # records the failure and the receiver sees the file is missing, which is a
    # far better outcome than a token they can use.
    raise RedactionFailure(
        f"could not redact {filename}: secret-bearing keys still present after "
        f"redaction ({', '.join(survivors)}). The file was NOT included."
    )


def _secret_values_surviving(text: str) -> list[str]:
    """Secret-bearing keys whose value is still a real value after redaction.

    ⛔ This exists because the line rewriter REPORTED SUCCESS on forms it
    cannot handle. Measured on the shipped implementation, ten of eleven YAML
    spellings of the same credential survived, and four of them --- block
    scalar, folded scalar, an anchor holding the value, a commented-out copy
    --- were reported in ``redacted_fields`` as though they had been removed.
    The docstring above discloses the block-scalar limitation honestly; what it
    did not disclose is that the limitation is announced as a SUCCESS. A
    manifest saying ``redaction_applied: true`` over a live Kismet token is
    worse than one saying nothing, because the operator hands the archive to a
    stranger on the strength of it.

    Parsing is what makes this syntax-independent: after ``safe_load`` there is
    no difference between an indented key, a quoted key, a flow mapping, a
    block scalar or an alias --- there is just a value. Returns the dotted key
    paths that still hold something other than the placeholder or an empty
    token.
    """
    try:
        docs = list(yaml.safe_load_all(text))
    except yaml.YAMLError:
        # Unparseable after rewriting: we cannot prove anything about it.
        return ["<unparseable>"]

    survivors: list[str] = []

    def walk(node: object, path: str) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                child = f"{path}.{key}" if path else str(key)
                if str(key) in _SECRET_FIELDS and not isinstance(value, (dict, list)):
                    rendered = "" if value is None else str(value)
                    if (
                        rendered != REDACTED_PLACEHOLDER
                        and rendered.strip() not in _EMPTY_VALUE_TOKENS
                    ):
                        survivors.append(child)
                walk(value, child)
        elif isinstance(node, list):
            for i, item in enumerate(node):
                walk(item, f"{path}[{i}]")

    for doc in docs:
        walk(doc, "")
    return survivors


def _redact_semantically(
    content: str, known_values: list[str] | None = None
) -> tuple[str, list[str]] | None:
    """Parse, replace every secret value, re-dump. Loses comments; keeps truth.

    The fallback for a file the line rewriter could not clean. Comments and key
    order are sacrificed deliberately: an export that preserves the operator's
    formatting and their live credential is not a trade-off worth having.
    """
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError:
        return None
    if not isinstance(data, dict):
        return None
    changed: list[str] = []
    known = set(known_values or ())

    def scrub(node: object) -> None:
        if isinstance(node, dict):
            for key in list(node):
                value = node[key]
                # Scrubbed by VALUE as well as by key name, so a credential
                # parked under an innocent key via a YAML anchor goes too.
                if not isinstance(value, (dict, list)) and str(value) in known:
                    node[key] = REDACTED_PLACEHOLDER
                    changed.append(str(key))
                elif str(key) in _SECRET_FIELDS and not isinstance(value, (dict, list)):
                    rendered = "" if value is None else str(value)
                    if rendered.strip() not in _EMPTY_VALUE_TOKENS:
                        node[key] = REDACTED_PLACEHOLDER
                        changed.append(str(key))
                else:
                    scrub(value)
        elif isinstance(node, list):
            for item in node:
                scrub(item)

    scrub(data)
    return yaml.safe_dump(data, sort_keys=False), changed


def _secret_values_in(text: str) -> list[str]:
    """Every RESOLVED value held under a secret-bearing key, at any depth.

    Resolved, so a YAML alias yields the credential it points at rather than
    the reference. Short values are dropped: a two-character value cannot be
    searched for in a config file without matching everything.
    """
    try:
        docs = list(yaml.safe_load_all(text))
    except yaml.YAMLError:
        return []
    found: list[str] = []

    def walk(node: object) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if str(key) in _SECRET_FIELDS and not isinstance(value, (dict, list)):
                    rendered = "" if value is None else str(value)
                    if (
                        rendered.strip() not in _EMPTY_VALUE_TOKENS
                        and rendered != REDACTED_PLACEHOLDER
                        and len(rendered) >= 6
                    ):
                        found.append(rendered)
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    for doc in docs:
        walk(doc)
    return found
