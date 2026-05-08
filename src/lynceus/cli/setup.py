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
import os
import secrets
import subprocess
import sys
from pathlib import Path

import requests

from .. import __version__
from ..kismet import KismetClient

# --- Defaults ---------------------------------------------------------------

DEFAULT_KISMET_URL = "http://127.0.0.1:2501"
DEFAULT_NTFY_BROKER = "https://ntfy.sh"
DEFAULT_RSSI_THRESHOLD = -70
DEFAULT_UI_PORT = 8765
DEFAULT_DB_PATH = "lynceus.db"
PROBE_TIMEOUT_SECONDS = 5.0

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


# --- Probes -----------------------------------------------------------------


def probe_kismet(
    url: str, token: str, timeout: float = PROBE_TIMEOUT_SECONDS
) -> tuple[bool, str | None, str | None]:
    """Return ``(reachable, version, error)`` from Kismet's
    ``/system/status.json`` endpoint."""
    client = KismetClient(base_url=url, api_key=token, timeout=timeout)
    result = client.health_check()
    return bool(result.get("reachable")), result.get("version"), result.get("error")


def probe_ntfy(
    url: str, topic: str, timeout: float = PROBE_TIMEOUT_SECONDS
) -> tuple[bool, str | None]:
    """POST a one-line message to the ntfy topic. Return ``(ok, error)``."""
    full_url = f"{url.rstrip('/')}/{topic}"
    try:
        response = requests.post(full_url, data=b"Lynceus setup test", timeout=timeout)
    except requests.exceptions.RequestException as e:
        return False, str(e)
    if 200 <= response.status_code < 300:
        return True, None
    return False, f"HTTP {response.status_code}"


# --- Config write -----------------------------------------------------------


def render_config_yaml(answers: dict) -> str:
    """Build the lynceus.yaml content with section comments. Hand-rolled so
    the operator gets explanatory comments, not a bare yaml.safe_dump."""
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
        "kismet_sources:",
        f"  - {answers['interface']}",
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
        "# AND subscribe. Pick something unguessable.",
        f"ntfy_url: {answers['ntfy_url']}",
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
    path.write_text(content, encoding="utf-8")
    if not _is_windows():
        os.chmod(path, 0o600)


def scaffold_severity_overrides(path: Path) -> bool:
    """Create the default override file if it doesn't already exist.
    Returns True when newly created, False when an existing file was kept."""
    if path.exists():
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(SEVERITY_OVERRIDES_TEMPLATE, encoding="utf-8")
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


def maybe_import_argus(
    *,
    db_path: str,
    severity_path: str,
    input_fn=None,
    bundled_succeeded: bool = False,
) -> None:
    in_fn = input_fn or input
    prompt = (
        "Import an additional Argus CSV with newer data?"
        if bundled_succeeded
        else "Would you like to import Argus threat data now? Requires an Argus CSV export file."
    )
    if not prompt_yes_no(prompt, default=False, input_fn=in_fn):
        print(
            "Skipping import. Run `lynceus-import-argus --input <path-to-csv>` "
            "when you have an Argus export."
        )
        return
    while True:
        path = prompt_default(
            "Path to Argus CSV export",
            default=None,
            required=True,
            input_fn=in_fn,
        )
        if Path(path).is_file():
            break
        print(f"File not found: {path}")
    cmd = [
        "lynceus-import-argus",
        "--input",
        path,
        "--db",
        db_path,
        "--override-file",
        severity_path,
    ]
    try:
        proc = subprocess.Popen(cmd, stdout=sys.stdout, stderr=sys.stderr)
        rc = proc.wait()
    except FileNotFoundError:
        print(f"Import failed; you can retry later with `lynceus-import-argus --input {path}`.")
        return
    if rc != 0:
        print(f"Import failed; you can retry later with `lynceus-import-argus --input {path}`.")


# --- Wizard orchestration ---------------------------------------------------


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

    # (a) Kismet URL
    answers["kismet_url"] = prompt_default(
        "Kismet API URL", default=DEFAULT_KISMET_URL, input_fn=in_fn
    )
    # (b) Kismet token
    answers["kismet_api_key"] = prompt_secret("Kismet API token (input hidden)", getpass_fn=gp_fn)

    # (c) Kismet probe
    if not args.skip_probes:
        ok, version, error = probe_kismet(answers["kismet_url"], answers["kismet_api_key"])
        if ok:
            print(f"✓ Kismet reachable, version {version or 'unknown'}")
        else:
            print(f"✗ Kismet probe failed: {error}")
            if not prompt_yes_no("Continue anyway?", default=False, input_fn=in_fn):
                print("Aborted.", file=sys.stderr)
                return 1

    # (d) Capture interface
    interfaces = enumerate_wireless_interfaces()
    if interfaces:
        answers["interface"] = prompt_numbered_choice(
            "Select capture interface:", interfaces, input_fn=in_fn
        )
    else:
        answers["interface"] = prompt_default(
            "Capture interface name (e.g. wlan0)",
            default=None,
            required=True,
            input_fn=in_fn,
        )

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

    # (g) ntfy URL
    answers["ntfy_url"] = prompt_default(
        "ntfy broker URL", default=DEFAULT_NTFY_BROKER, input_fn=in_fn
    )
    # (h) ntfy topic
    suggested = f"lynceus-{secrets.token_hex(4)}"
    print(f"  Suggested random topic (unguessable): {suggested}")
    answers["ntfy_topic"] = prompt_default(
        "ntfy topic name",
        default=None,
        required=True,
        input_fn=in_fn,
    )

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

    # (k) Severity overrides scaffold
    sev_default = str(target.parent / "severity_overrides.yaml")
    sev_path_str = prompt_default(
        "Severity overrides file path",
        default=sev_default,
        input_fn=in_fn,
    )
    sev_path = Path(sev_path_str)

    # Write config
    content = render_config_yaml(answers)
    write_config(target, content)

    sev_created = scaffold_severity_overrides(sev_path)

    # Summary
    print()
    print(f"Config written to: {target}")
    print(f"  kismet_url:        {answers['kismet_url']}")
    print(f"  kismet_api_key:    (set, {len(answers['kismet_api_key'])} chars)")
    print(f"  capture interface: {answers['interface']}")
    print(f"  probe_ssids:       {answers['probe_ssids']}")
    print(f"  ble_friendly_names:{answers['ble_friendly_names']}")
    print(f"  ntfy_url:          {answers['ntfy_url']}")
    print(f"  ntfy_topic:        {answers['ntfy_topic']}")
    print(f"  min_rssi:          {answers['min_rssi']}")
    if sev_created:
        print(f"  severity overrides: {sev_path} (scaffolded)")
    else:
        print(f"  severity overrides: {sev_path} (existing, not modified)")

    # Auto-import bundled threat data when shipped. Silent skip when absent.
    print()
    bundled_ok, bundled_msg = import_bundled_watchlist(
        db_path=DEFAULT_DB_PATH,
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

    # Optional additional Argus import (final prompt)
    print()
    maybe_import_argus(
        db_path=DEFAULT_DB_PATH,
        severity_path=str(sev_path),
        input_fn=in_fn,
        bundled_succeeded=bundled_ok,
    )

    print()
    print(f"Setup complete. Config at {target}.")
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
