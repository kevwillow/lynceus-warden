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
import importlib.resources
import logging
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit

import requests

from .. import __version__, paths
from ..config import DEFAULT_KISMET_URL
from ..kismet import KismetClient
from ..redact import redact_ntfy_topic, redact_topic_in_url

logger = logging.getLogger(__name__)


# --- Errors -----------------------------------------------------------------


class SetupError(Exception):
    """Raised by the wizard helpers for operator-actionable failures.

    Caught at the ``run_wizard`` boundary and rendered to stderr with a
    non-zero exit code. Distinguished from ad-hoc ``RuntimeError`` so a
    test can assert exactly which failure mode it's exercising.
    """


# --- Atomic writes + system-mode permissions --------------------------------
#
# rc1 had three independent footguns in the way it laid down state under
# ``--system`` mode:
#
#   * Bug 6: config written 0600 root:root → ``User=lynceus`` daemon could
#     not read it → unit failed on first start.
#   * S1:    data_dir + lynceus.db owned by root → daemon could not write
#     → first poll failed with "attempt to write a readonly database".
#   * S2:    secrets-bearing config briefly world-readable between
#     ``write_text`` and the follow-up ``chmod`` (race window in BOTH user
#     and system mode).
#
# The fix is a coordinated change: ``_atomic_write`` collapses the S2
# race by setting the target mode at fd-creation time, and the
# ``_apply_system_perms_*`` helpers give system mode a clean ownership
# story (``root:lynceus 0640`` for files, ``lynceus:lynceus 0750`` for
# directories the daemon must write to). User mode behaviour is
# unchanged — the helpers are wired in only when ``scope == "system"``.


def _atomic_write(path: Path, content: str, *, mode: int = 0o600) -> None:
    """Write ``content`` to ``path`` with ``mode`` set at creation time.

    Closes the S2 race: the legacy "write the file then chmod" two-step
    leaves a window in which the file exists with umask-derived bits
    (typically world-readable ``0o644``) before the chmod lands. Anyone
    reading the file in that interval sees the secret-bearing config
    in the clear. Setting the mode in the ``os.open`` flags eliminates
    the window — the file never exists on disk with permissions broader
    than requested.

    On Windows the POSIX mode bits are meaningless, so we fall back to
    ``path.write_text`` to match the chmod-skip pattern used elsewhere.
    """
    if _is_windows():
        path.write_text(content, encoding="utf-8")
        return
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(content)


def _apply_system_perms_to_file(path: Path, *, group: str = "lynceus", mode: int = 0o640) -> None:
    """Set ``root:<group>`` ownership and ``mode`` on a system-mode file.

    Used for ``/etc/lynceus/lynceus.yaml`` and the severity-overrides
    file: the config is owned by root (so a compromised daemon cannot
    rewrite its own config) but readable by the lynceus group (so the
    ``User=lynceus`` daemon can actually load it).
    """
    if _is_windows():
        return
    if sys.platform == "darwin":
        raise SetupError("--system mode is Linux-only with systemd; not supported on macOS.")
    import grp

    try:
        gid = grp.getgrnam(group).gr_gid
    except KeyError as exc:
        raise SetupError(
            f"Group '{group}' does not exist. "
            "Run `sudo ./install.sh --system` first to create the system user/group."
        ) from exc
    os.chown(str(path), 0, gid)
    os.chmod(str(path), mode)


def _apply_system_perms_to_dir(
    path: Path,
    *,
    owner: str = "lynceus",
    group: str = "lynceus",
    mode: int = 0o750,
) -> None:
    """Set ``<owner>:<group>`` ownership and ``mode`` on a system-mode dir.

    Used for ``/var/lib/lynceus`` and ``/var/log/lynceus``: the daemon
    needs to create files in these directories, so they must be owned
    by the lynceus user, not root. Same shape as
    ``_apply_system_perms_to_file`` but resolves a UID too.
    """
    if _is_windows():
        return
    if sys.platform == "darwin":
        raise SetupError("--system mode is Linux-only with systemd; not supported on macOS.")
    import grp
    import pwd

    try:
        uid = pwd.getpwnam(owner).pw_uid
    except KeyError as exc:
        raise SetupError(
            f"User '{owner}' does not exist. "
            "Run `sudo ./install.sh --system` first to create the system user/group."
        ) from exc
    try:
        gid = grp.getgrnam(group).gr_gid
    except KeyError as exc:
        raise SetupError(
            f"Group '{group}' does not exist. "
            "Run `sudo ./install.sh --system` first to create the system user/group."
        ) from exc
    os.chown(str(path), uid, gid)
    os.chmod(str(path), mode)


# --- Defaults ---------------------------------------------------------------

# DEFAULT_KISMET_URL re-exported from lynceus.config so the wizard, the loaded
# config, and the fixture-vs-url warning compare against a single source of
# truth.
DEFAULT_NTFY_BROKER = "https://ntfy.sh"
DEFAULT_RSSI_THRESHOLD = -70
DEFAULT_UI_PORT = 8765
PROBE_TIMEOUT_SECONDS = 5.0

SEVERITY_OVERRIDES_EXPLANATION = """\
Severity overrides let you customize how Lynceus rates threats. By
default, each Argus device category (drone, alpr, hacking_tool, etc.)
maps to a fixed severity (low/med/high). The overrides file lets you
reassign severities, filter out categories you don't care about, or
add vendor-specific rules.

A starter file with explanatory comments will be created at the path
below. You can edit it any time. Press Enter to accept the default.
"""

SEVERITY_OVERRIDES_TEMPLATE = """\
# Lynceus severity overrides — consumed by `lynceus-import-argus --override-file`.
#
# Each section is optional. Uncomment and edit only what you want to change.
# First match wins: vendor_overrides > device_category_severity > built-in.

# vendor_overrides:
#   # Force a specific severity for any record from this manufacturer.
#   # Use the literal string "drop" to skip records from a vendor entirely.
#   "ACME Surveillance Inc": high
#   "Hobbyist Drone Co":     drop

# device_category_severity:
#   # Override the built-in severity for an Argus device_category.
#   # Built-ins: imsi_catcher=high, alpr=high, body_cam=med, drone=med,
#   # gunshot_detect=med, hacking_tool=high, in_vehicle_router=med, unknown=low.
#   imsi_catcher: high
#   drone: low

# geographic_filter:
#   # Only import records whose geographic_scope matches one of these values
#   # (records with scope "global" are always kept). Empty/unset = no filter.
#   - US
#   - global

# Argus records below this confidence (0-100) get their severity downgraded
# one notch (high -> med, med -> low). Set to 0 to disable.
# confidence_downgrade_threshold: 70
"""


# --- Path resolution --------------------------------------------------------


def _is_windows() -> bool:
    """Indirection point for tests — monkeypatch this rather than ``os.name``,
    which would also flip pathlib's native Path subclass at runtime."""
    return os.name == "nt"


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


# --- Prompt helpers ---------------------------------------------------------


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
            value = in_fn(f"{question} [{default}]: ").strip()
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


# --- Path-input validation -------------------------------------------------


# --- ntfy topic validation -------------------------------------------------

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


# --- Config write -----------------------------------------------------------


def render_config_yaml(answers: dict) -> str:
    """Build the lynceus.yaml content with section comments. Hand-rolled so
    the operator gets explanatory comments, not a bare yaml.safe_dump."""
    sources_lines = ["kismet_sources:"]
    for src in answers["kismet_sources"]:
        sources_lines.append(f"  - {src}")
    lines = [
        "# Lynceus configuration — generated by lynceus-setup.",
        "# Edit this file directly, or re-run `lynceus-setup --reconfigure`.",
        "",
        "# --- Kismet source ---",
        "# REST API endpoint and the cookie token used to authenticate.",
        f"kismet_url: {answers['kismet_url']}",
        f"kismet_api_key: {_yaml_str(answers['kismet_api_key'])}",
        "",
        "# --- Capture sources ---",
        "# Inclusive filter on Kismet source (adapter) names. Only observations",
        "# from listed sources are processed; others are silently dropped.",
        *sources_lines,
        "",
        "# --- Tier 1 passive metadata capture ---",
        "# Privacy-sensitive toggles. probe_ssids reveals device WiFi history",
        "# (off by default). ble_friendly_names captures BLE GAP advertisement",
        "# names — broadcast publicly with intent (on by default).",
        "capture:",
        f"  probe_ssids: {_yaml_bool(answers['probe_ssids'])}",
        f"  ble_friendly_names: {_yaml_bool(answers['ble_friendly_names'])}",
        "",
        "# --- Notifications (ntfy) ---",
        "# Topic acts as the shared secret — anyone who knows it can publish",
        "# AND subscribe. Pick something unguessable. Empty strings disable ntfy.",
        f"ntfy_url: {_yaml_str(answers['ntfy_url'])}",
        f"ntfy_topic: {_yaml_str(answers['ntfy_topic'])}",
        "",
        "# --- RSSI floor ---",
        "# Drop observations weaker than this RSSI in dBm. -70 is reasonable",
        "# indoors; -85 is more permissive.",
        f"min_rssi: {int(answers['min_rssi'])}",
        "",
        "# --- Web UI ---",
        f"ui_bind_port: {DEFAULT_UI_PORT}",
        "",
    ]
    return "\n".join(lines)


def _yaml_str(value: str) -> str:
    """Quote a string for safe inclusion in a single-line YAML value."""
    if value is None:
        return "null"
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _yaml_bool(value: bool) -> str:
    return "true" if value else "false"


def write_config(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(path, content)


def scaffold_severity_overrides(path: Path) -> bool:
    """Create the default override file if it doesn't already exist.
    Returns True when newly created, False when an existing file was kept."""
    if path.exists():
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(path, SEVERITY_OVERRIDES_TEMPLATE)
    return True


# --- Argus import -----------------------------------------------------------


BUNDLED_WATCHLIST_PACKAGE = "lynceus.data"
BUNDLED_WATCHLIST_RESOURCE = "default_watchlist.csv"
BUNDLED_ABSENT_MESSAGE = "no bundled watchlist"


def import_bundled_watchlist(db_path: str, override_file: str | None) -> tuple[bool, str]:
    """Auto-import the bundled default_watchlist.csv when shipped in
    ``lynceus.data``. Returns ``(success, message)``.

    Silently returns ``(False, "no bundled watchlist")`` when the data
    package or CSV resource is missing — that is the expected case for
    source builds without bundled threat data, not an error. On subprocess
    failure returns ``(False, "import failed: <reason>")`` with stderr (or
    stdout) captured in the reason. On success returns ``(True, <summary>)``
    where the summary is the import_argus summary line if recognisable.
    """
    try:
        resource = importlib.resources.files(BUNDLED_WATCHLIST_PACKAGE).joinpath(
            BUNDLED_WATCHLIST_RESOURCE
        )
    except (ModuleNotFoundError, FileNotFoundError):
        return False, BUNDLED_ABSENT_MESSAGE
    try:
        present = resource.is_file()
    except (FileNotFoundError, OSError):
        return False, BUNDLED_ABSENT_MESSAGE
    if not present:
        return False, BUNDLED_ABSENT_MESSAGE

    try:
        with importlib.resources.as_file(resource) as csv_path:
            cmd = [
                "lynceus-import-argus",
                "--input",
                str(csv_path),
                "--db",
                db_path,
            ]
            if override_file:
                cmd += ["--override-file", override_file]
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
            except FileNotFoundError:
                return False, "import failed: lynceus-import-argus not found on PATH"
            stdout, stderr = proc.communicate()
            rc = proc.returncode
    except (FileNotFoundError, OSError) as e:
        return False, f"import failed: {e}"

    if rc != 0:
        detail = (stderr or stdout or f"exit code {rc}").strip().splitlines()
        reason = detail[-1] if detail else f"exit code {rc}"
        return False, f"import failed: {reason}"

    summary = next(
        (line for line in stdout.splitlines() if line.lstrip().startswith("imported")),
        "imported successfully",
    )
    return True, summary


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
    # (b) Kismet token
    answers["kismet_api_key"] = prompt_secret("Kismet API token (input hidden)", getpass_fn=gp_fn)

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
    try:
        ntfy_url_input = prompt_url(
            f"ntfy broker URL (Enter to skip notifications, e.g. {DEFAULT_NTFY_BROKER})",
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

    # Write config
    content = render_config_yaml(answers)
    try:
        write_config(target, content)
        if scope == "system":
            _apply_system_perms_to_file(target)

        sev_created = scaffold_severity_overrides(sev_path)
        if scope == "system":
            # Apply on every system run, not just when newly scaffolded:
            # an existing file inherited from a botched rc1 install may
            # still be 0600 root:root and unreadable by the daemon.
            _apply_system_perms_to_file(sev_path)

        # Defensive: ensure data + log directories exist before we hand off
        # to lynceus-import-argus. On a fresh box neither exists, and
        # sqlite refuses to open ``<missing>/lynceus.db`` with "unable to
        # open database file". Under --system the daemon (User=lynceus)
        # also needs to OWN these directories, otherwise the first poll
        # fails with "attempt to write a readonly database".
        data_dir = paths.default_data_dir(scope)
        log_dir = paths.default_log_dir(scope)
        data_dir.mkdir(parents=True, exist_ok=True)
        log_dir.mkdir(parents=True, exist_ok=True)
        if scope == "system":
            _apply_system_perms_to_dir(data_dir)
            _apply_system_perms_to_dir(log_dir)
    except SetupError as exc:
        print(f"Setup failed: {exc}", file=sys.stderr)
        return 1

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

    # Auto-import bundled threat data when shipped. Silent skip when absent.
    # Resolve DB path via the canonical paths helper so the bundled threat
    # data lands where the daemon will actually read from
    # (``/var/lib/lynceus/lynceus.db`` under --system, the per-user XDG
    # data dir under --user) instead of the operator's CWD.
    db_path_str = str(paths.default_db_path(scope))
    print()
    bundled_ok, bundled_msg = import_bundled_watchlist(
        db_path=db_path_str,
        override_file=str(sev_path),
    )
    if bundled_msg != BUNDLED_ABSENT_MESSAGE:
        if bundled_ok:
            print(f"Imported bundled threat data: {bundled_msg}.")
        else:
            print(
                f"Bundled threat-data import failed: {bundled_msg}. "
                "You can retry later with lynceus-import-argus."
            )

    # System-mode ownership for the freshly written DB and any sqlite
    # sidecars (lynceus.db-wal, lynceus.db-shm). The DB must be OWNED
    # by lynceus (not just group-readable) so the daemon can write to
    # it — root:lynceus 0640 would let the first poll fail with "attempt
    # to write a readonly database". We reuse the dir helper because it
    # already does the ``lynceus:lynceus`` lookup; mode is overridden to
    # 0o640 to keep DB files non-executable.
    chowned_db_files: list[Path] = []
    if scope == "system" and bundled_ok:
        try:
            db_path = Path(db_path_str)
            for candidate in sorted(db_path.parent.glob(db_path.name + "*")):
                if candidate.is_file():
                    _apply_system_perms_to_dir(candidate, mode=0o640)
                    chowned_db_files.append(candidate)
        except SetupError as exc:
            print(f"Setup failed: {exc}", file=sys.stderr)
            return 1

    if scope == "system":
        touched: list[str] = [str(target), str(sev_path)]
        touched.extend(str(p) for p in chowned_db_files)
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
    else:
        print("  lynceus-import-argus --from-github            # latest from GitHub")
        print("  lynceus-import-argus --input <path-to-csv>    # air-gapped")
    print(
        "To start Lynceus: `lynceus-quickstart` for dev/demo, "
        "or enable the systemd service for production."
    )
    print(f"UI will be available at http://127.0.0.1:{DEFAULT_UI_PORT}")
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
    p.add_argument(
        "--version",
        action="version",
        version=f"lynceus-setup {__version__}",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    return run_wizard(args)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
