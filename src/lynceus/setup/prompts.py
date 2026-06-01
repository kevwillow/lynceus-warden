"""Interactive prompt helpers extracted from ``lynceus.cli.setup``.

Moved here in F6 Phase 1 Touch 4 to draw a bright line between
"collect input from a terminal" (this module) and "apply that input
to disk" (``lynceus.setup.core``). The Phase 2 web wizard will NOT
use these prompts — it'll have its own form-validation layer driven
by FastAPI — so isolating them in a CLI-only module keeps the core
free of stdin/stdout concerns.

All helpers preserved verbatim from the pre-refactor module. The
re-import shim in ``lynceus.cli.setup`` keeps the legacy
``wiz.prompt_default`` / ``wiz._looks_like_path`` / etc. test seams
working without 200 test-import edits.
"""

from __future__ import annotations

import getpass
import re
from urllib.parse import urlsplit


# --- Free-form prompts -----------------------------------------------------


def prompt_default(
    question: str,
    default: str | None = None,
    *,
    required: bool = False,
    input_fn=None,
) -> str:
    """Prompt for a string. If ``default`` is given, empty input returns it.
    If ``required`` and no default, empty input re-prompts."""
    in_fn = input_fn or input
    while True:
        if default is not None:
            # Show the default AND the cue that Enter accepts it, so the
            # bracket reads as "press Enter to keep this" rather than just
            # "here's a value". Matches the "(Enter to ...)" cue the
            # default=None prompts (ntfy URL/topic) already carry, so every
            # wizard prompt signals its Enter behaviour the same way.
            value = in_fn(f"{question} [{default}] (Enter to keep default): ").strip()
            if value == "":
                return default
            return value
        value = in_fn(f"{question}: ").strip()
        if value:
            return value
        if required:
            print("Value required; please enter a non-empty value.")
            continue
        return value


def prompt_secret(question: str, *, getpass_fn=None) -> str:
    gp = getpass_fn or getpass.getpass
    while True:
        value = gp(f"{question}: ").strip()
        if value:
            return value
        print("Value required; please enter a non-empty value.")


# --- URL prompt with re-try cap --------------------------------------------

URL_PROMPT_MAX_ATTEMPTS = 4


class _URLPromptAborted(Exception):
    """Raised by ``prompt_url`` after too many invalid attempts.

    Signals to ``run_wizard`` to abort with a non-zero return code rather
    than letting the operator loop indefinitely on a fat-fingered input.
    """


def _is_valid_url(value: str) -> bool:
    """Return True iff ``value`` parses as an http(s) URL with a non-empty host.

    Mirrors the config-layer validator in ``lynceus.config``. The wizard
    runs this BEFORE any probe so that ``probe_kismet`` / ``probe_ntfy`` —
    which would otherwise feed scheme-less inputs straight into
    ``requests.get`` and surface a cryptic ``MissingSchema`` traceback —
    never see an invalid URL. Belt; the config-layer validator is suspenders.
    """
    parts = urlsplit(value)
    return parts.scheme in ("http", "https") and bool(parts.netloc)


def prompt_url(
    question: str,
    *,
    default: str | None,
    required: bool,
    input_fn=None,
    max_attempts: int = URL_PROMPT_MAX_ATTEMPTS,
) -> str:
    """Prompt for a URL with scheme validation and a hard re-try cap.

    Empty input is allowed only when ``required`` is False (returns ``""``).
    Otherwise the input must parse with a scheme of ``http`` or ``https`` and
    a non-empty host. After ``max_attempts`` invalid entries the function
    raises ``_URLPromptAborted`` so the wizard can return a non-zero exit
    code with a "re-run lynceus-setup" hint.
    """
    in_fn = input_fn or input
    for _ in range(max_attempts):
        value = prompt_default(question, default=default, required=required, input_fn=in_fn)
        if not value and not required:
            return value
        if _is_valid_url(value):
            return value
        print(f"✗ URL must include a scheme (http:// or https://). You typed: {value}")
    raise _URLPromptAborted()


# --- Yes/no + numbered choice ---------------------------------------------


def prompt_yes_no(question: str, *, default: bool, input_fn=None) -> bool:
    in_fn = input_fn or input
    suffix = "[Y/n]" if default else "[y/N]"
    while True:
        raw = in_fn(f"{question} {suffix} ").strip().lower()
        if raw == "":
            return default
        if raw in ("y", "yes"):
            return True
        if raw in ("n", "no"):
            return False
        print("Please answer y or n.")


def prompt_numbered_choice(question: str, options: list[str], *, input_fn=None) -> str:
    in_fn = input_fn or input
    print(question)
    for i, opt in enumerate(options, 1):
        print(f"  {i}) {opt}")
    while True:
        raw = in_fn(f"Pick a number (1-{len(options)}): ").strip()
        try:
            n = int(raw)
        except ValueError:
            print(f"Enter a number between 1 and {len(options)}.")
            continue
        if 1 <= n <= len(options):
            return options[n - 1]
        print(f"Choice out of range; enter a number between 1 and {len(options)}.")


# --- Section headers + context blocks --------------------------------------


def _print_section(title: str) -> None:
    """Print a wizard section header with a ``═`` underline.

    Used to break the Kismet and ntfy wizard sections out visually so a
    first-time operator can tell where one ask ends and the next begins.
    The underline is plain box-drawing — no emoji, no ANSI color, no new
    dependency — so the output still looks fine when tee'd into a log.
    """
    print()
    print(title)
    print("═" * len(title))
    print()


def _print_context(text: str) -> None:
    """Print a multi-line context block above a prompt.

    Leading / trailing whitespace is stripped from ``text`` so the
    caller can use a triple-quoted literal without worrying about the
    indentation of the first line, then a single trailing blank line
    separates the block from the prompt that follows.
    """
    for line in text.strip().split("\n"):
        print(line)
    print()


# --- ntfy topic + path validators -----------------------------------------

_NTFY_TOPIC_RE = re.compile(r"^[A-Za-z0-9_-]{6,64}$")
_NTFY_TOPIC_DENY_LIST = frozenset({"na", "n/a", "none", "skip", "no", "null", "nil", "abort"})
NTFY_TOPIC_MAX_ATTEMPTS = 4


def _looks_like_ntfy_topic(value: str) -> bool:
    """Return True iff ``value`` is a plausible ntfy topic name.

    ntfy.sh's actual constraint is broader (any non-empty string), but
    accepting "na", "skip", or a fat-fingered three-letter typo as a
    topic routes alerts to a topic the operator never subscribed to —
    a worse failure mode than a re-prompt. The regex tightens to
    ``[A-Za-z0-9_-]{6,64}`` so bare cancellation words and
    accidentally-pasted secrets that are too short or too long both
    fail closed. The deny-list catches the cases that DO match the
    regex (e.g. ``skip`` is 4 chars, but ``aborted`` would match
    length-wise) and that operators commonly type meaning "I want to
    skip this prompt"; the validator points them at the empty-input
    skip path instead.
    """
    if not value:
        return False
    if value.lower() in _NTFY_TOPIC_DENY_LIST:
        return False
    return bool(_NTFY_TOPIC_RE.match(value))


def _looks_like_path(value: str) -> bool:
    """Heuristic for accepting a config-file path entered at a prompt.

    Accepts inputs that contain a path separator OR end with a recognised
    config-file extension. Rejects bare alphabetic words like ``na``,
    ``skip``, ``none`` so a fat-fingered "just give me the default" doesn't
    silently land in the wrong file.
    """
    if not value:
        return False
    if "/" in value or "\\" in value:
        return True
    if value.lower().endswith((".yaml", ".yml")):
        return True
    return False
