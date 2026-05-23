"""lynceus-setup — interactive first-run configuration wizard.

Generates a working lynceus.yaml from a guided flow, probes Kismet and ntfy
for connectivity, and optionally invokes lynceus-import-argus at the end.
Cross-platform (Linux/macOS/Windows) for path resolution and privilege checks;
read-only on existing state — refuses to clobber a config without
``--reconfigure``.

No TUI library — plain ``input()``/``getpass()``/``print()`` so the wizard
runs in any terminal that can run Python.
"""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import os
import secrets
import sys
from pathlib import Path

import requests

from .. import __version__, paths
from ..config import DEFAULT_KISMET_URL, CaptureConfig, Config
from ..kismet import KismetClient
from ..redact import redact_ntfy_topic, redact_topic_in_url
from ..setup.models import ApplyStep

# Re-exports from setup.core so existing test imports survive the Touch 2
# move. The 200 setup-wizard tests reach for ``wiz._atomic_write``,
# ``wiz.subprocess.Popen``, ``wiz.SetupError``, etc. via this module's
# namespace; pulling the same names back here keeps every test seam
# pointing at the same objects without editing 200 test imports.
from ..setup.core import (  # noqa: F401  (test-namespace re-exports)
    BUNDLED_ABSENT_MESSAGE,
    BUNDLED_IMPORT_TIMEOUT_SECONDS,
    BUNDLED_WATCHLIST_PACKAGE,
    BUNDLED_WATCHLIST_RESOURCE,
    DEFAULT_UI_PORT,
    DELEGATION_RULES,
    SEVERITY_OVERRIDES_TEMPLATE,
    SetupError,
    _apply_system_perms_to_dir,
    _apply_system_perms_to_file,
    _atomic_write,
    _is_windows,
    _yaml_bool,
    _yaml_str,
    append_rules_path_to_config,
    apply_config,
    count_watchlist_by_pattern_type,
    import_bundled_watchlist,
    importlib,
    render_config_yaml,
    render_rules_yaml,
    scaffold_severity_overrides,
    subprocess,
    write_config,
)
from ..setup.prompts import (  # noqa: F401  (test-namespace re-exports)
    NTFY_TOPIC_MAX_ATTEMPTS,
    URL_PROMPT_MAX_ATTEMPTS,
    _NTFY_TOPIC_DENY_LIST,
    _NTFY_TOPIC_RE,
    _is_valid_url,
    _looks_like_ntfy_topic,
    _looks_like_path,
    _print_context,
    _print_section,
    _URLPromptAborted,
    prompt_default,
    prompt_numbered_choice,
    prompt_secret,
    prompt_url,
    prompt_yes_no,
)


# --- CLI progress sink ------------------------------------------------------


class CLIProgressSink:
    """Synchronous ``ProgressSink`` implementation for the CLI wizard.

    Phase 1 records steps without printing. ``run_wizard`` reads the
    returned ``ApplyReport`` after ``apply_config`` completes and
    reconstructs the legacy output (summary block, bundled-import
    message, group-ownership summary) in the exact order the
    pre-refactor wizard printed it. Keeping the sink silent here
    preserves stdout byte-for-byte against the 200-test baseline; the
    Phase 2 web wizard will plug in an SSE-streaming sink instead.
    """

    def __init__(self) -> None:
        self.steps: list[ApplyStep] = []

    def record(self, step: ApplyStep) -> None:
        self.steps.append(step)

logger = logging.getLogger(__name__)


# --- Defaults ---------------------------------------------------------------

# DEFAULT_KISMET_URL re-exported from lynceus.config so the wizard, the loaded
# config, and the fixture-vs-url warning compare against a single source of
# truth.
DEFAULT_NTFY_BROKER = "https://ntfy.sh"
DEFAULT_RSSI_THRESHOLD = -70
PROBE_TIMEOUT_SECONDS = 5.0

SEVERITY_OVERRIDES_EXPLANATION = """\
Severity overrides let you customize how Lynceus rates threats. By
default, each Argus device category (drone, alpr, hacking_tool, etc.)
maps to a fixed severity (low/med/high). The overrides file lets you
reassign severities, filter out categories you don't care about, or
add vendor-specific rules.

Two layers read this file:
  - IMPORT-TIME (vendor_overrides, geographic_filter, confidence_
    downgrade_threshold): applied by lynceus-import-argus when data
    is brought in. Edits take effect after the next re-import.
  - RUNTIME (device_category_severity, suppress_categories,
    suppress_vendors, pattern_overrides, vendor_severity): applied
    by the poller at alert time. Edits take effect on daemon
    restart — no re-import required.

A starter file with explanatory comments will be created at the path
below. You can edit it any time. Press Enter to accept the default.
"""

# --- Path resolution --------------------------------------------------------


def user_config_dir() -> Path:
    """Per-user config directory.

    Linux/macOS: ``$XDG_CONFIG_HOME/lynceus`` or ``~/.config/lynceus``.
    Windows: ``%APPDATA%\\Lynceus``.
    """
    if _is_windows():
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "Lynceus"
        return Path.home() / "AppData" / "Roaming" / "Lynceus"
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg) / "lynceus"
    return Path.home() / ".config" / "lynceus"


def system_config_dir() -> Path:
    """System-wide config directory.

    Linux/macOS: ``/etc/lynceus``.
    Windows: ``%ProgramData%\\Lynceus``.
    """
    if _is_windows():
        programdata = os.environ.get("ProgramData") or os.environ.get("PROGRAMDATA")
        if programdata:
            return Path(programdata) / "Lynceus"
        return Path(r"C:\ProgramData\Lynceus")
    return Path("/etc/lynceus")


def resolve_config_path(scope: str, output: str | None) -> Path:
    if output:
        return Path(output)
    if scope == "system":
        return system_config_dir() / "lynceus.yaml"
    return user_config_dir() / "lynceus.yaml"


# --- Privilege / pre-flight -------------------------------------------------


def _euid() -> int | None:
    """Return effective UID on POSIX, or None on Windows."""
    if hasattr(os, "geteuid"):
        return os.geteuid()
    return None


def is_writable_system_path(path: Path) -> bool:
    """Walk up to the first existing ancestor and report whether it's writable.

    Used on Windows where there's no euid check; if we can write to the parent
    directory (or its first existing ancestor), the system-scope write will
    likely succeed.
    """
    p = path
    while not p.exists():
        parent = p.parent
        if parent == p:
            return False
        p = parent
    return os.access(p, os.W_OK)


def determine_scope(args: argparse.Namespace) -> str:
    if getattr(args, "system", False):
        return "system"
    return "user"


def preflight_existing(target: Path, reconfigure: bool) -> str | None:
    if target.exists() and not reconfigure:
        return (
            f"Config already exists at {target}. "
            "Use --reconfigure to overwrite, or edit it manually."
        )
    return None


def preflight_scope(scope: str, target: Path) -> str | None:
    if scope != "system":
        return None
    if not _is_windows():
        if _euid() != 0:
            return "Use sudo for --system, or use --user for a per-user config."
        return None
    if not is_writable_system_path(target):
        return (
            f"Insufficient privileges to write system config at {target}. "
            "Run as Administrator, or use --user."
        )
    return None


# Prompt helpers (prompt_default/secret/url/yes_no/numbered_choice,
# _print_section/_print_context, _URLPromptAborted, _is_valid_url,
# _looks_like_ntfy_topic, _looks_like_path) moved to
# ``lynceus.setup.prompts`` in F6 Phase 1 Touch 4 and re-exported at
# the top of this module so the legacy wiz.* test seams keep working.


# --- Kismet datasource label rendering -------------------------------------


def _format_source_label(source: dict) -> str:
    """Render a Kismet datasource for the numbered-selection prompt.

    Format: ``"<name>  (interface: <iface>, capture: <capture_iface>)"``.
    The parenthetical clarifies what the source is actually capturing on
    so the operator can distinguish e.g. ``external_wifi`` mapped to
    ``wlan1`` from ``external_wifi`` mapped to a different radio. Empty
    sub-fields are dropped from the parenthetical so it doesn't render
    half-empty.
    """
    name = source.get("name") or ""
    parts: list[str] = []
    iface = source.get("interface") or ""
    capture = source.get("capture_interface") or ""
    if iface:
        parts.append(f"interface: {iface}")
    if capture:
        parts.append(f"capture: {capture}")
    if parts:
        return f"{name}  ({', '.join(parts)})"
    return name


# --- Kismet API key auto-locate --------------------------------------------
#
# Kismet persists its API keys to ``~/.kismet/session.db`` — despite the
# ``.db`` extension this is a JSON array of objects shaped like
# ``{"token", "name", "role", "created", "accessed", "expires"}``. There is
# no system-wide token file; ``/etc/kismet/kismet_httpd.conf`` only ever
# carries the ``httpd_session_db=`` *pointer*. Storage scheme has been
# stable since the 2022-08 Boost.Beast HTTP-server rewrite (see
# kis_net_beast_httpd.cc::store_auth / kis_net_beast_auth::as_json).
#
# Lynceus only needs read access to device endpoints, so when multiple
# keys exist we prefer (in order): a key named "lynceus", a "readonly"
# role key, an "admin" role key, or the first non-empty token.
#
# Auto-locate is best-effort and additive: every failure mode — missing
# file, unreadable file, malformed JSON, no usable entry — silently falls
# through to the manual entry path. Operator-visible output is limited
# to "found a key" / "no existing key found"; permission denials, parse
# errors, and path details never reach the operator.


_KISMET_KEY_PREFERRED_NAME = "lynceus"
_KISMET_KEY_PREFERRED_ROLES = ("readonly", "admin")


def _kismet_api_key_candidate_paths(scope: str) -> list[Path]:
    """Return ordered candidate file paths for Kismet's session.db, scope-aware.

    Most-specific first. ``user`` scope checks the current operator's
    ``~/.kismet/session.db``. ``system`` scope (typically reached via
    ``sudo lynceus-setup --system``) prefers the invoking operator's
    ``~/.kismet/`` over root's, because Kismet is most often launched as
    the operator's own user rather than as root.

    Returns an empty list on Windows — Kismet is Linux/macOS-first and
    no canonical Windows install layout exists for the wizard to
    inspect.
    """
    if _is_windows():
        return []
    candidates: list[Path] = []
    seen: set[Path] = set()

    def _add(p: Path) -> None:
        if p not in seen:
            seen.add(p)
            candidates.append(p)

    if scope == "system":
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user:
            try:
                import pwd

                home = Path(pwd.getpwnam(sudo_user).pw_dir)
                _add(home / ".kismet" / "session.db")
            except (KeyError, ImportError):
                pass
        _add(Path("/root") / ".kismet" / "session.db")
        _add(Path.home() / ".kismet" / "session.db")
    else:
        _add(Path.home() / ".kismet" / "session.db")
    return candidates


def _read_kismet_api_key(path: Path) -> tuple[str, str] | None:
    """Read a usable API key from a Kismet session.db file.

    Returns ``(token, name)`` on success, ``None`` on any failure
    (missing file, unreadable, malformed JSON, no usable entry). The
    caller treats ``None`` as "fall through to manual entry"; we never
    raise.

    Selection priority when multiple entries exist:
      1. entry whose ``name`` equals ``"lynceus"``
      2. entry whose ``role`` is ``"readonly"``
      3. entry whose ``role`` is ``"admin"``
      4. first entry with a non-empty ``token``

    Lynceus only needs read access to device endpoints, so ``readonly``
    is preferred over ``admin`` when both exist — the principle-of-
    least-privilege fallback. A ``lynceus``-named key created by the
    operator takes precedence over either default.
    """
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        entries = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return None
    if not isinstance(entries, list):
        return None

    def _token_of(entry: object) -> tuple[str, str] | None:
        if not isinstance(entry, dict):
            return None
        token = entry.get("token")
        if not isinstance(token, str) or not token.strip():
            return None
        name = entry.get("name") if isinstance(entry.get("name"), str) else ""
        return token, name

    by_name = None
    by_role: dict[str, tuple[str, str]] = {}
    first = None
    for entry in entries:
        result = _token_of(entry)
        if result is None:
            continue
        if first is None:
            first = result
        if isinstance(entry, dict):
            name = entry.get("name")
            role = entry.get("role")
            if by_name is None and isinstance(name, str) and name == _KISMET_KEY_PREFERRED_NAME:
                by_name = result
            if isinstance(role, str) and role not in by_role:
                by_role[role] = result

    if by_name is not None:
        return by_name
    for role in _KISMET_KEY_PREFERRED_ROLES:
        if role in by_role:
            return by_role[role]
    return first


def _redact_kismet_api_key(key: str) -> str:
    """Render a Kismet API key as a short head/tail preview.

    Format: ``"abc1...wxyz"`` — 4 chars head, ellipsis, 4 chars tail.
    Keys shorter than ~12 chars (unusual for Kismet) are collapsed to a
    fully-redacted placeholder so the preview never approximates the
    full key.
    """
    s = key.strip()
    if len(s) < 12:
        return "***"
    return f"{s[:4]}...{s[-4:]}"


# --- Wireless interface enumeration ----------------------------------------


def enumerate_wireless_interfaces() -> list[str] | None:
    """Return a sorted list of wireless interface names, or None when the OS
    doesn't expose them in a way we recognise (operator falls back to typing
    the name in directly)."""
    if os.name == "posix":
        sys_class_net = Path("/sys/class/net")
        if not sys_class_net.is_dir():
            return None
        interfaces: list[str] = []
        try:
            for entry in sorted(sys_class_net.iterdir()):
                if (entry / "wireless").is_dir():
                    interfaces.append(entry.name)
        except OSError:
            return None
        return interfaces or None
    return None


# --- Bluetooth adapter enumeration -----------------------------------------


def enumerate_bluetooth_adapters() -> list[str] | None:
    """Return Bluetooth controller names (``hciN``), or None when the platform
    isn't supported.

    Linux: read ``/sys/class/bluetooth/`` for ``hci*`` entries. Returns ``[]``
    when the directory is absent or empty (kernel without BT subsystem, or no
    adapter plugged in).

    macOS / Windows: returns ``None`` (sentinel for "not implemented") so the
    wizard can print an informational note and let the operator configure
    Kismet's BT source manually.
    """
    if os.name != "posix":
        return None
    if sys.platform == "darwin":
        return None
    sys_class_bt = Path("/sys/class/bluetooth")
    if not sys_class_bt.is_dir():
        return []
    try:
        adapters = sorted(
            entry.name for entry in sys_class_bt.iterdir() if entry.name.startswith("hci")
        )
    except OSError:
        return []
    return adapters


# --- Probes -----------------------------------------------------------------


def probe_kismet(
    url: str, token: str, timeout: float = PROBE_TIMEOUT_SECONDS
) -> tuple[bool, str | None, str | None]:
    """Return ``(reachable, version, error)`` from Kismet's
    ``/system/status.json`` endpoint."""
    client = KismetClient(base_url=url, api_key=token, timeout=timeout)
    result = client.health_check()
    return bool(result.get("reachable")), result.get("version"), result.get("error")


def probe_kismet_sources(
    url: str, token: str, timeout: float = PROBE_TIMEOUT_SECONDS
) -> list[dict] | None:
    """Query Kismet for its configured datasource list.

    Returns the normalized source list on success, ``None`` on any failure
    (network, HTTP, malformed JSON, timeout). Caller falls back to OS
    enumeration with a clear warning when this returns ``None``.

    The wizard relies on this so the operator picks Kismet *source names*
    (e.g. ``external_wifi``) — what the poller actually filters on — rather
    than kernel interface names (e.g. ``wlan1``) which silently mismatch
    when the operator's Kismet config maps them to a different name.
    """
    try:
        client = KismetClient(base_url=url, api_key=token, timeout=timeout)
        return client.list_sources()
    except Exception as e:
        logger.warning("Kismet list_sources probe failed: %s", e)
        return None


def probe_ntfy(
    url: str, topic: str, timeout: float = PROBE_TIMEOUT_SECONDS
) -> tuple[bool, str | None]:
    """POST a one-line message to the ntfy topic. Return ``(ok, error)``.

    The error string never carries the raw topic. ``requests`` exceptions'
    ``__str__()`` typically embeds the full URL (with topic) — instead of
    forwarding that to the wizard's terminal output we return only the
    exception type name plus a topic-redacted URL. Full exception detail
    is logged at DEBUG for operators who need it.
    """
    full_url = f"{url.rstrip('/')}/{topic}"
    safe_url = redact_topic_in_url(full_url)
    try:
        response = requests.post(full_url, data=b"Lynceus setup test", timeout=timeout)
    except requests.exceptions.RequestException as e:
        logger.debug("ntfy probe exception detail", exc_info=True)
        return False, f"{type(e).__name__} ({safe_url})"
    if 200 <= response.status_code < 300:
        return True, None
    return False, f"HTTP {response.status_code}"


# --- Enable-alerting flow ---------------------------------------------------
#
# The wizard's closing arc — between the bundled-watchlist auto-import and
# the "Setup complete" hint block — runs a guarded flow that lets the
# operator opt in to Argus-backed alerting. Without this flow the
# operator's only path from `lynceus-setup` to alerts-firing is to
# manually copy config/rules.yaml, uncomment the right delegation
# entries, and edit lynceus.yaml's rules_path. The flow lands the same
# three artefacts (a rules.yaml at the scope-appropriate path, the
# selected delegation entries active, rules_path wired into
# lynceus.yaml) interactively. Default is NO at every prompt to match
# Lynceus's privacy-conservative posture: alerts are opt-in.
#
# The data-shape constants (``DELEGATION_RULES``) and the writers
# (``count_watchlist_by_pattern_type``, ``render_rules_yaml``,
# ``append_rules_path_to_config``) moved to ``lynceus.setup.core`` in
# F6 Phase 1. They are re-exported at the top of this module so the
# orchestration below — which is interactive and stays in the CLI —
# can keep its existing names.


def run_enable_alerting_flow(
    scope: str,
    db_path: str,
    *,
    input_fn=None,
) -> tuple[Path | None, bool]:
    """Gate + per-type prompts + rules.yaml write.

    Returns ``(rules_path_to_wire, wrote_file)``:
    - ``rules_path_to_wire`` is the Path to wire in via lynceus.yaml's
      ``rules_path``, or ``None`` when nothing should be wired (operator
      declined the gate, declined every per-type prompt, or there was
      no watchlist data to alert on).
    - ``wrote_file`` is True iff this function actually wrote (or
      overwrote) the rules.yaml file. The caller uses that flag to
      decide whether to apply system-mode ownership to the new file.
    """
    in_fn = input_fn or input
    print()
    print("Argus-backed alerting (opt-in):")
    print("  Lynceus can fire alerts on devices matching the imported")
    print("  watchlist. Each rule_type can be enabled independently;")
    print("  all are disabled by default.")
    if not prompt_yes_no(
        "Enable Argus-backed alerting?",
        default=False,
        input_fn=in_fn,
    ):
        return (None, False)

    counts = count_watchlist_by_pattern_type(db_path)
    enabled_rule_types: set[str] = set()
    for (_name, rule_type, pattern_type, label, _desc) in DELEGATION_RULES:
        count = counts.get(pattern_type, 0)
        if count <= 0:
            # No data of this type in the watchlist DB — skip the prompt.
            # An operator opting into a delegation rule for an empty
            # pattern_type would never see an alert anyway, and the empty
            # rule would noise up rules.yaml.
            continue
        if prompt_yes_no(
            f"Enable {rule_type} ({count:,} {label})?",
            default=False,
            input_fn=in_fn,
        ):
            enabled_rule_types.add(rule_type)

    if not enabled_rule_types:
        # Gate Y + every per-type N (or every type had zero rows). No
        # rules.yaml to write, no rules_path to wire — the operator
        # answered no to alert-firing in practice, so end the flow as if
        # they had answered no at the top-level gate.
        print("No rule_types enabled; skipping rules.yaml generation.")
        return (None, False)

    rules_target = paths.default_config_dir(scope) / "rules.yaml"
    if rules_target.exists():
        # --reconfigure alone is NOT authorization to overwrite an
        # operator's hand-edited rules.yaml. The explicit overwrite
        # confirmation is separate; default is NO.
        print(
            f"rules.yaml already exists at {rules_target}. "
            "Overwriting would replace any manual edits."
        )
        if not prompt_yes_no(
            "Overwrite?",
            default=False,
            input_fn=in_fn,
        ):
            # Leave the file alone, but still wire rules_path on the
            # caller side — operator may have copied the file by hand
            # without ever setting rules_path in lynceus.yaml. This
            # closes the "manually copied, never wired" gap.
            print(f"Leaving {rules_target} untouched.")
            return (rules_target, False)

    rules_target.parent.mkdir(parents=True, exist_ok=True)
    content = render_rules_yaml(enabled_rule_types)
    _atomic_write(rules_target, content)
    active_names = sorted(
        rt for (_n, rt, _pt, _l, _d) in DELEGATION_RULES if rt in enabled_rule_types
    )
    print(
        f"Wrote rules.yaml to {rules_target} with "
        f"{len(active_names)} active rule(s): {', '.join(active_names)}."
    )
    return (rules_target, True)


# --- Wizard orchestration ---------------------------------------------------


def _prompt_ntfy_topic(*, input_fn=None) -> str:
    """Prompt the operator for an ntfy topic with validation.

    Returns the validated topic string. By the time we reach this prompt
    the operator has already committed to ntfy by entering a non-empty
    URL — blank input here is *accept the suggested random topic*, not
    a back-out. The skip-ntfy path is the URL prompt; clearing ``ntfy_url``
    after the operator typed it would silently turn an opt-in into an
    opt-out, which is the exact misrouting Bug 7 set out to prevent.

    Raises ``SetupError`` after ``NTFY_TOPIC_MAX_ATTEMPTS`` invalid
    non-empty entries so the operator hits a clear failure boundary
    instead of an infinite re-prompt loop. rc1 accepted any non-empty
    string here, which let "na" / "skip" / fat-fingered typos through
    and silently routed alerts to a topic the operator never subscribed
    to.
    """
    suggested = f"lynceus-{secrets.token_hex(4)}"
    print(f"  Suggested random topic (unguessable): {suggested}")
    invalid_count = 0
    while True:
        entered = prompt_default(
            "ntfy topic name (Enter to accept the suggested topic above)",
            default=None,
            required=False,
            input_fn=input_fn,
        )
        if not entered:
            return suggested
        if _looks_like_ntfy_topic(entered):
            return entered
        invalid_count += 1
        print(
            f"✗ Topic must be 6-64 alphanumeric/underscore/hyphen "
            f"characters (got: {entered}). Press Enter to accept the suggested "
            "topic, or re-run lynceus-setup with a blank URL to skip ntfy."
        )
        if invalid_count >= NTFY_TOPIC_MAX_ATTEMPTS:
            raise SetupError(
                f"Could not produce a valid ntfy topic after "
                f"{NTFY_TOPIC_MAX_ATTEMPTS} attempts. Re-run lynceus-setup "
                "and leave the URL prompt blank to disable ntfy entirely."
            )


def run_wizard(
    args: argparse.Namespace,
    *,
    input_fn=None,
    getpass_fn=None,
) -> int:
    in_fn = input_fn or input
    gp_fn = getpass_fn or getpass.getpass

    scope = determine_scope(args)
    target = resolve_config_path(scope, args.output)

    err = preflight_existing(target, args.reconfigure)
    if err:
        print(err, file=sys.stderr)
        return 2

    err = preflight_scope(scope, target)
    if err:
        print(err, file=sys.stderr)
        return 2

    print(f"Lynceus setup wizard — writing to {target}")
    print()

    answers: dict = {}

    # (a) Kismet URL — validated for scheme + host before any probe touches it.
    _print_section("Kismet Connection")
    _print_context(
        """
Lynceus reads device observations from Kismet via its REST API.
You'll need two things:
  - The Kismet web UI URL (default below works for a local Kismet)
  - An API key (set up in the next prompt)

If Kismet isn't installed or running yet, you can still complete
this wizard — the probe will fail soft and you can re-run
`lynceus-setup --reconfigure` after Kismet is up. Two ways to
get Kismet ready on Debian/Ubuntu/Kali:
  - Install + configure: sudo lynceus-bootstrap-kismet
  - Or install Kismet manually per your distro's instructions.
"""
    )
    try:
        answers["kismet_url"] = prompt_url(
            "Kismet API URL",
            default=DEFAULT_KISMET_URL,
            required=True,
            input_fn=in_fn,
        )
    except _URLPromptAborted:
        print(
            f"Too many invalid URL entries (>{URL_PROMPT_MAX_ATTEMPTS - 1}). "
            "Re-run lynceus-setup to retry.",
            file=sys.stderr,
        )
        return 1
    # (b) Kismet token — auto-locate from Kismet's session.db first, then
    # fall through to the walkthrough + manual prompt on miss / decline.
    print()
    print("Kismet API Key")
    print("─" * len("Kismet API Key"))
    print()
    print("Searching for an existing API key on disk...")
    located: tuple[str, str, Path] | None = None
    for candidate in _kismet_api_key_candidate_paths(scope):
        found = _read_kismet_api_key(candidate)
        if found is not None:
            token, _name = found
            located = (token, _name, candidate)
            break

    use_located = False
    if located is not None:
        token, name, path = located
        preview = _redact_kismet_api_key(token)
        print(f"Found a key in {path}.")
        if name:
            print(f"Preview: {preview}  (name: {name})")
        else:
            print(f"Preview: {preview}")
        print()
        use_located = prompt_yes_no("Use this key?", default=True, input_fn=in_fn)

    if use_located and located is not None:
        answers["kismet_api_key"] = located[0]
    else:
        if located is None:
            print("no existing key found.")
        print()
        _print_context(
            """
Where to find your API key (one-time setup in Kismet):
  1. Open the Kismet web UI in your browser (the URL above).
  2. Log in. On first launch Kismet prompts you to set a password.
  3. Open the menu (top-right) → Settings → Login Configuration.
  4. Under "API Keys", create a new key:
       Name:  lynceus
       Role:  readonly
  5. Copy the generated key and paste it below. Input is hidden.

If you don't have a key yet, you can press Ctrl-C, set one up,
and re-run lynceus-setup. The wizard will not store the key
anywhere except your generated lynceus.yaml.
"""
        )
        answers["kismet_api_key"] = prompt_secret(
            "Kismet API token (input hidden)", getpass_fn=gp_fn
        )

    # (c) Kismet probe — also queries the configured datasource list when
    # reachable, so we can offer the operator the actual source NAMES the
    # poller filters on (rather than kernel interface names which silently
    # mismatch — the rc1 silent-drop bug).
    sources_list: list[dict] | None = None
    fallback_warning_needed = False
    if not args.skip_probes:
        ok, version, error = probe_kismet(answers["kismet_url"], answers["kismet_api_key"])
        if ok:
            print(f"✓ Kismet reachable, version {version or 'unknown'}")
            sources_list = probe_kismet_sources(answers["kismet_url"], answers["kismet_api_key"])
            if sources_list is None:
                fallback_warning_needed = True
        else:
            print(f"✗ Kismet probe failed: {error}")
            if not prompt_yes_no("Continue anyway?", default=False, input_fn=in_fn):
                print("Aborted.", file=sys.stderr)
                return 1
            fallback_warning_needed = True

    wifi_sources: list[dict] = []
    bt_sources: list[dict] = []
    if sources_list is not None:
        wifi_sources = [s for s in sources_list if s.get("driver") == "linuxwifi"]
        bt_sources = [s for s in sources_list if s.get("driver") == "linuxbluetooth"]

    if fallback_warning_needed and sources_list is None:
        print(
            "WARNING: Could not query Kismet for datasource names. "
            "Falling back to OS interface enumeration."
        )
        print(
            "Verify the value you pick matches the `name=` in your Kismet source "
            "line (e.g. `source=wlan1:name=external_wifi` → pick `external_wifi`)."
        )
        print("If they don't match, the poller will silently drop every observation.")

    # (d) Capture source selection (WiFi)
    kismet_sources: list[str] = []
    if sources_list is not None:
        if not wifi_sources:
            print(
                "Kismet is reachable but has no Wi-Fi datasource configured. "
                "Add one to your Kismet config (typically /etc/kismet/kismet_site.conf):"
            )
            print("    source=wlan1:name=external_wifi")
            print("Then restart Kismet and re-run lynceus-setup.")
            return 1
        wifi_labels = [_format_source_label(s) for s in wifi_sources]
        picked_wifi = prompt_numbered_choice(
            "Select Kismet Wi-Fi datasource:", wifi_labels, input_fn=in_fn
        )
        wifi_idx = wifi_labels.index(picked_wifi)
        kismet_sources.append(wifi_sources[wifi_idx]["name"])
    else:
        interfaces = enumerate_wireless_interfaces()
        if interfaces:
            wifi = prompt_numbered_choice("Select capture interface:", interfaces, input_fn=in_fn)
        else:
            wifi = prompt_default(
                "Capture interface name (e.g. wlan0)",
                default=None,
                required=True,
                input_fn=in_fn,
            )
        kismet_sources.append(wifi)

    # (d2) Bluetooth capture source
    if sources_list is not None:
        if not bt_sources:
            print("Kismet has no Bluetooth datasource configured. To enable BLE captures later:")
            print("    Add: source=hci0:type=linuxbluetooth,name=local_bt")
            print("    Restart Kismet, then re-run lynceus-setup --reconfigure.")
            print("Continuing without BT capture.")
        elif prompt_yes_no(
            "Add a Bluetooth capture source? Tier 1 BLE enrichment requires "
            "Kismet to have a BT source configured.",
            default=True,
            input_fn=in_fn,
        ):
            bt_labels = [_format_source_label(s) for s in bt_sources]
            picked_bt = prompt_numbered_choice(
                "Select Kismet Bluetooth datasource:", bt_labels, input_fn=in_fn
            )
            bt_idx = bt_labels.index(picked_bt)
            kismet_sources.append(bt_sources[bt_idx]["name"])
    else:
        bt_adapters = enumerate_bluetooth_adapters()
        if bt_adapters is None:
            print(
                "Bluetooth adapter selection not implemented on this platform; "
                "configure Kismet's BT source manually if needed."
            )
        elif len(bt_adapters) == 0:
            print(
                "No Bluetooth adapter detected. Skipping BT source. "
                "Configure Kismet's bluetooth source manually if you want BLE captures."
            )
        else:
            if prompt_yes_no(
                "Add a Bluetooth capture source? Tier 1 BLE enrichment requires "
                "Kismet to have a BT source configured.",
                default=True,
                input_fn=in_fn,
            ):
                bt_choice = prompt_numbered_choice(
                    "Select Bluetooth adapter:", bt_adapters, input_fn=in_fn
                )
                kismet_sources.append(bt_choice)

    answers["kismet_sources"] = kismet_sources

    # (e) probe_ssids
    answers["probe_ssids"] = prompt_yes_no(
        "Capture probe SSIDs from observed devices? Reveals device WiFi history. "
        "Lynceus default is OFF for this reason.",
        default=False,
        input_fn=in_fn,
    )
    # (f) ble_friendly_names
    answers["ble_friendly_names"] = prompt_yes_no(
        "Capture BLE advertised names? Less sensitive (broadcast publicly with intent).",
        default=True,
        input_fn=in_fn,
    )

    # (g) ntfy URL — empty input skips ntfy entirely. When non-empty, the same
    # scheme-and-host validation runs before any probe.
    _print_section("Push Notifications (ntfy)")
    _print_context(
        f"""
ntfy is a free push notification service (https://ntfy.sh).
Lynceus publishes alerts to a 'topic' you choose; you subscribe to
that topic from your phone (ntfy mobile app) or desktop browser.

Two prompts follow:
  1. ntfy broker URL — the default ({DEFAULT_NTFY_BROKER}) is the
     public service. Set this to your own URL if you self-host.
  2. ntfy topic — a name you pick. Anyone who knows the topic can
     read AND publish to it, so treat it like a password.

To skip ntfy entirely (no push notifications), press Enter at the
URL prompt below. You can wire it up later with
`lynceus-setup --reconfigure`.
"""
    )
    try:
        ntfy_url_input = prompt_url(
            f"ntfy broker URL (Enter to skip, e.g. {DEFAULT_NTFY_BROKER})",
            default=None,
            required=False,
            input_fn=in_fn,
        )
    except _URLPromptAborted:
        print(
            f"Too many invalid URL entries (>{URL_PROMPT_MAX_ATTEMPTS - 1}). "
            "Re-run lynceus-setup to retry.",
            file=sys.stderr,
        )
        return 1
    if not ntfy_url_input:
        print(
            "Skipping ntfy. Notifications will not be sent. "
            "To enable later, edit lynceus.yaml or run lynceus-setup --reconfigure."
        )
        answers["ntfy_url"] = ""
        answers["ntfy_topic"] = ""
    else:
        answers["ntfy_url"] = ntfy_url_input
        # (h) ntfy topic — validated. Blank input here is *accept the
        # suggested random topic*, not skip; the skip-ntfy path is the URL
        # prompt above. Invalid input re-prompts up to NTFY_TOPIC_MAX_ATTEMPTS
        # times before SetupError aborts.
        print()
        print("ntfy Topic")
        print("─" * len("ntfy Topic"))
        print()
        _print_context(
            """
Pick a topic name that's hard to guess. The topic IS the shared
secret — anyone who knows it can see your alerts and impersonate
the publisher.

A random suggested topic is shown at the prompt below; press Enter
to accept it, or type your own (6-64 chars, letters/digits/_/-).
To subscribe on your phone: install the ntfy app, tap the + button,
and enter the topic exactly as written.
"""
        )
        try:
            answers["ntfy_topic"] = _prompt_ntfy_topic(input_fn=in_fn)
        except SetupError as exc:
            print(f"Setup failed: {exc}", file=sys.stderr)
            return 1
        # (i) ntfy probe
        if not args.skip_probes:
            ok, error = probe_ntfy(answers["ntfy_url"], answers["ntfy_topic"])
            if ok:
                print("✓ ntfy publish OK, check your subscriber for the test message")
            else:
                print(f"✗ ntfy publish failed: {error}")
                if not prompt_yes_no("Continue anyway?", default=False, input_fn=in_fn):
                    print("Aborted.", file=sys.stderr)
                    return 1

    # (j) RSSI threshold
    rssi_str = prompt_default(
        "RSSI threshold (dBm). Devices weaker than this are ignored. "
        "-70 is a reasonable default for indoor sweeps; -85 is more permissive.",
        default=str(DEFAULT_RSSI_THRESHOLD),
        input_fn=in_fn,
    )
    try:
        answers["min_rssi"] = int(rssi_str)
    except ValueError:
        print(f"Invalid RSSI {rssi_str!r}; using default {DEFAULT_RSSI_THRESHOLD}.")
        answers["min_rssi"] = DEFAULT_RSSI_THRESHOLD

    # (k) Severity overrides scaffold — explain, then prompt with validation.
    print(SEVERITY_OVERRIDES_EXPLANATION)
    sev_default = str(target.parent / "severity_overrides.yaml")
    while True:
        sev_path_str = prompt_default(
            "Severity overrides file path",
            default=sev_default,
            input_fn=in_fn,
        )
        if _looks_like_path(sev_path_str):
            break
        print(
            "That doesn't look like a file path. "
            "Please enter a full path or press Enter for the default."
        )
    sev_path = Path(sev_path_str)

    # Drive the deterministic file-write + bundled-import + chown chain
    # through ``apply_config``. The CLI sink records each ApplyStep
    # silently; the legacy per-phase prints (summary block, bundled
    # message, group-ownership summary) are reconstructed below from
    # the returned ApplyReport so the wizard's stdout stays byte-for-
    # byte identical to v0.6.3. ``enabled_rule_types=None`` keeps the
    # alerting flow OUT of apply_config — it stays here in the CLI
    # frontend so per-type prompts can still show post-import row
    # counts (the legacy UX).
    config = Config(
        kismet_url=answers["kismet_url"],
        kismet_api_key=answers["kismet_api_key"],
        kismet_sources=answers["kismet_sources"],
        capture=CaptureConfig(
            probe_ssids=answers["probe_ssids"],
            ble_friendly_names=answers["ble_friendly_names"],
        ),
        ntfy_url=answers["ntfy_url"] or None,
        ntfy_topic=answers["ntfy_topic"] or None,
        min_rssi=answers["min_rssi"],
    )
    cli_sink = CLIProgressSink()
    try:
        report = apply_config(
            config,
            scope=scope,
            target_path=target,
            severity_overrides_path=sev_path,
            enabled_rule_types=None,
            run_bundled_import=True,
            progress=cli_sink,
        )
    except SetupError as exc:
        print(f"Setup failed: {exc}", file=sys.stderr)
        return 1

    # Extract per-step results so the legacy prints below can carry the
    # same data they used to read from local variables.
    scaffold_step = next(s for s in report.steps if s.name == "scaffold_severity_overrides")
    sev_created = bool(scaffold_step.detail and scaffold_step.detail.get("scaffolded"))
    import_step = next(s for s in report.steps if s.name == "import_bundled_watchlist")
    bundled_ok = import_step.status == "ok"
    bundled_msg = import_step.message
    chown_step = next(s for s in report.steps if s.name == "chown_db_files")
    chowned_db_files: list[Path] = (
        [Path(p) for p in chown_step.detail["files"]]
        if chown_step.detail and "files" in chown_step.detail
        else []
    )

    # Summary
    print()
    print(f"Config written to: {target}")
    print(f"  kismet_url:        {answers['kismet_url']}")
    print(f"  kismet_api_key:    (set, {len(answers['kismet_api_key'])} chars)")
    print(f"  kismet_sources:    {', '.join(answers['kismet_sources'])}")
    print(f"  probe_ssids:       {answers['probe_ssids']}")
    print(f"  ble_friendly_names:{answers['ble_friendly_names']}")
    print(f"  ntfy_url:          {answers['ntfy_url'] or '(skipped)'}")
    # Redact the topic in the wizard summary — terminal scrollback and any
    # tee'd install log otherwise capture the shared-secret value. The
    # full topic remains in the config file at ``target`` for the daemon.
    ntfy_topic_summary = redact_ntfy_topic(answers["ntfy_topic"]) or "(skipped)"
    print(f"  ntfy_topic:        {ntfy_topic_summary}")
    print(f"  min_rssi:          {answers['min_rssi']}")
    if sev_created:
        print(f"  severity overrides: {sev_path} (scaffolded)")
    else:
        print(f"  severity overrides: {sev_path} (existing, not modified)")

    # Bundled-import message — apply_config already ran the import.
    # Resolve the same db_path string the alerting flow below queries
    # against (the canonical default_db_path for this scope).
    db_path_str = str(paths.default_db_path(scope))
    print()
    if import_step.status == "ok":
        print(f"Imported bundled threat data: {bundled_msg}.")
    elif import_step.status == "failed":
        print(
            f"Bundled threat-data import failed: {bundled_msg}. "
            "You can retry later with lynceus-import-argus."
        )
    # status == "skipped" (BUNDLED_ABSENT_MESSAGE): silent, same as legacy.

    # Enable-alerting flow (opt-in). Runs after the bundled-watchlist
    # import so the per-type prompts can show real row counts, and
    # after DB ownership has been settled so a fresh rules.yaml written
    # under --system inherits the same root:lynceus 0640 contract as
    # the config it points at.
    try:
        rules_target, rules_written = run_enable_alerting_flow(
            scope, db_path_str, input_fn=in_fn
        )
    except SetupError as exc:
        print(f"Setup failed: {exc}", file=sys.stderr)
        return 1

    chowned_rules: Path | None = None
    if rules_target is not None and rules_written and scope == "system":
        try:
            _apply_system_perms_to_file(rules_target)
            chowned_rules = rules_target
        except SetupError as exc:
            print(f"Setup failed: {exc}", file=sys.stderr)
            return 1

    if rules_target is not None:
        # Wire rules_path into lynceus.yaml. We re-read instead of
        # blindly appending so an unexpected pre-existing rules_path
        # (operator hand-edit since the wizard wrote the file) doesn't
        # produce a duplicate key. The wizard's own render_config_yaml
        # never emits rules_path, so on a clean run "rules_path:" is
        # always absent and the append happens.
        try:
            existing_text = target.read_text(encoding="utf-8")
        except OSError:
            existing_text = ""
        if "rules_path:" not in existing_text:
            append_rules_path_to_config(target, rules_target)
            print(f"Wired rules_path → {rules_target} in {target}.")

    if scope == "system":
        touched: list[str] = [str(target), str(sev_path)]
        touched.extend(str(p) for p in chowned_db_files)
        if chowned_rules is not None:
            touched.append(str(chowned_rules))
        print(f"Applied lynceus group ownership: {', '.join(touched)}")

    print()
    print(f"Setup complete. Config at {target}.")
    # Scope-aware refresh hint. Mirrors the install.sh "Watchlist data:"
    # block so an operator who saw both surfaces recognizes them as the
    # same hint. Hint only — the wizard makes no network call here; the
    # bundled default_watchlist.csv auto-import above is the default,
    # --from-github is opt-in for the next refresh.
    print("Watchlist refresh (run later, optional):")
    if scope == "system":
        print("  sudo lynceus-import-argus --scope system --from-github         # network")
        print("  sudo lynceus-import-argus --scope system --input <path-to-csv> # air-gapped")
        # Auto-refresh hint is system-scope only. The lynceus-refresh
        # units only ship via install.sh --system; a --user install has
        # no systemd integration and the operator would hit a
        # "Failed to enable unit" if we suggested the command here.
        print("  sudo systemctl enable --now lynceus-refresh.timer              # weekly auto-refresh")
    else:
        print("  lynceus-import-argus --from-github            # latest from GitHub")
        print("  lynceus-import-argus --input <path-to-csv>    # air-gapped")
    print(
        "To start Lynceus: `lynceus-quickstart` for dev/demo, "
        "or enable the systemd service for production."
    )
    print(f"UI will be available at http://127.0.0.1:{DEFAULT_UI_PORT}")
    # Explicit end-of-wizard marker. Without this the shell prompt
    # returns mixed with the last hint line and operators perceive
    # --system as hanging silently after completion — there's no
    # visible "the wizard is done, you're back in the shell now"
    # signal. The flush ensures the marker hits the terminal before
    # control returns regardless of how sys.stdout.reconfigure in
    # main() left the buffering policy.
    print()
    print("─" * 60)
    print(f"Setup complete — exiting. Config at {target}.")
    print("─" * 60)
    sys.stdout.flush()
    return 0


# --- CLI entry point --------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lynceus-setup",
        description=(
            "Interactive first-run wizard. Generates a working lynceus.yaml, "
            "probes Kismet and ntfy, and optionally imports Argus threat data."
        ),
    )
    scope = p.add_mutually_exclusive_group()
    scope.add_argument(
        "--user",
        action="store_true",
        help="Write config to per-user path (default if not running as root).",
    )
    scope.add_argument(
        "--system",
        action="store_true",
        help="Write config to system-scope path (requires elevated privileges).",
    )
    p.add_argument(
        "--reconfigure",
        action="store_true",
        help="Overwrite an existing config file. Without this flag the wizard refuses.",
    )
    p.add_argument(
        "--output",
        default=None,
        help="Explicit output file path (overrides --user / --system).",
    )
    p.add_argument(
        "--skip-probes",
        action="store_true",
        help="Skip Kismet and ntfy connectivity tests (e.g. configuring offline).",
    )
    # --- Web wizard flags (F6 Phase 2a) -------------------------------------
    # The CLI flow is the default; --web swaps the interactive terminal
    # prompts for a browser-driven multi-page form. Apply pipeline still
    # lands in Phase 2b — Phase 2a only validates and previews.
    p.add_argument(
        "--web",
        action="store_true",
        help="Run the wizard as a local web app instead of the interactive CLI flow.",
    )
    p.add_argument(
        "--port",
        type=int,
        default=None,
        help=(
            "Port for --web (default: 8766, one above the lynceus-ui default 8765). "
            "Ignored without --web."
        ),
    )
    p.add_argument(
        "--bind",
        default=None,
        help=(
            "Bind host for --web (default: 127.0.0.1). Pass 0.0.0.0 to opt into "
            "remote access. Ignored without --web."
        ),
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"lynceus-setup {__version__}",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    # Windows consoles default to cp1252/cp437, which can't encode the
    # box-drawing chars _print_section uses (UnicodeEncodeError on print).
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    args = _build_parser().parse_args(argv)
    # Refuse sudo-without-system. The wizard derives scope from --system
    # alone (not euid), so `sudo lynceus-setup --reconfigure` would
    # silently write to /root/.config/lynceus/lynceus.yaml — a path the
    # system daemon (which reads /etc/lynceus/lynceus.yaml) never sees.
    # The operator's last touch surface must NEVER silently switch
    # scopes: a misplaced config is worse than a refusal, because it
    # creates divergence between what the operator believes they
    # configured and what the daemon actually loads. Refuse with both
    # correct invocations shown side-by-side so the recovery move is
    # obvious. The _euid() wrapper returns None on Windows, so this
    # check is a no-op there (Windows has no sudo trap to fall into).
    if _euid() == 0 and not args.system:
        print(
            "Refusing to run as root without --system.\n\n"
            "Running as root with --user scope would write to\n"
            "  /root/.config/lynceus/lynceus.yaml\n"
            "which is not the path the system daemon reads. Did you mean one of:\n\n"
            "  sudo lynceus-setup --system [--reconfigure]   # system-wide\n"
            "  lynceus-setup [--reconfigure]                 # user-scope, no sudo\n",
            file=sys.stderr,
        )
        return 2
    if getattr(args, "web", False):
        return _run_web_wizard(args)
    return run_wizard(args)


def _run_web_wizard(args: argparse.Namespace) -> int:
    """Dispatch ``--web`` to the FastAPI wizard sub-app.

    Resolves scope and target path the same way the CLI flow does,
    then hands off to ``run_wizard_server``. Defaults for ``--port``
    and ``--bind`` come from ``lynceus.setup.web.server`` so the
    operator-visible defaults live next to the code that consumes
    them.
    """
    from ..setup.web.server import (
        DEFAULT_WIZARD_BIND,
        DEFAULT_WIZARD_PORT,
        run_wizard_server,
    )

    scope = determine_scope(args)
    target_path = resolve_config_path(scope, args.output)
    host = args.bind if args.bind is not None else DEFAULT_WIZARD_BIND
    port = args.port if args.port is not None else DEFAULT_WIZARD_PORT
    return run_wizard_server(
        host=host,
        port=port,
        scope=scope,
        target_path=target_path,
        reconfigure=args.reconfigure,
        skip_probes=args.skip_probes,
    )


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
