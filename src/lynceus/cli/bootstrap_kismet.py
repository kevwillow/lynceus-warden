"""lynceus-bootstrap-kismet -- install + configure Kismet on Debian/Ubuntu/Kali.

Walks a fresh host from "no Kismet installed" to "Kismet installed,
configured for the operator's interfaces, kismet group set up, ready
for the operator to launch the web UI, set the admin password, and
generate an API key." Closes the "what do I do before running
lynceus-setup?" gap for new operators.

Contrast with ``install.sh``: install.sh is OFFLINE by design (its
threat-model invariant — codified in its header comment). This script
IS allowed network calls — it adds the Kismet apt repo, runs apt
update, and installs the kismet package.

Operator flow:

  1. git clone + ./install.sh                (Lynceus, offline)
  2. sudo lynceus-bootstrap-kismet           (Kismet, network)
  3. open http://localhost:2501              (set password)
  4. Settings -> API Keys -> Create          (operator does this)
  5. sudo lynceus-setup                      (configure Lynceus)

This script does steps 2 only. Step 4 requires a running Kismet web UI
and cannot be automated -- the operator does the web ceremony.

Non-destructive + idempotent. Re-runnable from any state:

  * already-installed kismet?           skip the install step
  * already-configured apt source?      skip add-source
  * pre-existing kismet_site.conf?      append-only, never overwrite
  * operator already in kismet group?   skip usermod

Bounded to Debian/Ubuntu/Kali in v1. Other distros get a clear
"manual install required" pointer to https://www.kismetwireless.net/packages/
and a clean exit 0 -- they aren't broken, they just need to install
Kismet by hand.

Exit codes:
  0 -- success, OR unsupported distro (operator action: install manually)
  1 -- recoverable failure (operator action: fix + re-run)
  2 -- tool-level failure (run not root, etc.)
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, Iterable

from .. import __version__

# --- Constants -------------------------------------------------------------
#
# All literals verified against https://www.kismetwireless.net/packages/
# during the rc5 investigation. If Kismet changes any of these (key URL,
# keyring path, sources.list location, codename mapping), update here
# and bump the touch.

KISMET_GPG_KEY_URL = "https://www.kismetwireless.net/repos/kismet-release.gpg.key"
KISMET_KEYRING_PATH = Path("/usr/share/keyrings/kismet-archive-keyring.gpg")
KISMET_SOURCES_LIST_PATH = Path("/etc/apt/sources.list.d/kismet.list")
KISMET_PACKAGE = "kismet"
KISMET_GROUP = "kismet"
KISMET_SITE_CONF_PATH = Path("/etc/kismet/kismet_site.conf")
KISMET_WEB_UI_URL = "http://localhost:2501"

UNSUPPORTED_POINTER_URL = "https://www.kismetwireless.net/packages/"

# Distro ID -> set of supported VERSION_CODENAMEs the Kismet apt repo
# carries. Kali rolling reports VERSION_CODENAME=kali-rolling but the
# repo path is just `kali` -- handled as a special case below.
SUPPORTED_DEBIAN_CODENAMES: tuple[str, ...] = ("bookworm", "trixie")
SUPPORTED_UBUNTU_CODENAMES: tuple[str, ...] = ("focal", "jammy", "noble", "plucky")


# --- Errors -----------------------------------------------------------------


class BootstrapError(Exception):
    """Operator-actionable failure. Caught at the main() boundary and
    rendered to stderr; exits 1. Distinguished from RuntimeError so
    tests can assert which failure mode they're exercising.
    """


# --- Subprocess + IO helpers ------------------------------------------------


def _print(msg: str = "") -> None:
    """Plain stdout. Wrapped so tests can monkeypatch easily."""
    print(msg)


def _err(msg: str) -> None:
    print(msg, file=sys.stderr)


def _run(
    cmd: list[str],
    *,
    dry_run: bool,
    check: bool = True,
    capture: bool = False,
    input_bytes: bytes | None = None,
) -> subprocess.CompletedProcess[bytes] | None:
    """Run ``cmd`` (list, never shell=True). In dry-run, print the
    rendered command and return None. On real runs, returns the
    CompletedProcess. ``check=True`` (default) raises BootstrapError
    with the stderr tail on non-zero exit so the caller never has to
    handle CalledProcessError directly.
    """
    rendered = " ".join(_shell_quote(arg) for arg in cmd)
    if dry_run:
        _print(f"DRY-RUN: {rendered}")
        return None

    try:
        result = subprocess.run(
            cmd,
            input=input_bytes,
            capture_output=capture or check,
            check=False,
        )
    except FileNotFoundError as exc:
        raise BootstrapError(
            f"command not found: {cmd[0]} -- {exc}. Install it (e.g. "
            f"sudo apt install <package>) and re-run."
        ) from exc

    if check and result.returncode != 0:
        tail = (result.stderr or b"").decode("utf-8", errors="replace").strip()
        if not tail:
            tail = (result.stdout or b"").decode("utf-8", errors="replace").strip()
        raise BootstrapError(
            f"command failed (exit {result.returncode}): {rendered}\n  {tail}"
        )
    return result


def _shell_quote(arg: str) -> str:
    """Render an argument for the dry-run preview. Not used to actually
    invoke the command (which always goes through ``subprocess.run``
    with the list form).
    """
    if not arg or any(c in arg for c in ' \t"\'\\$`'):
        return "'" + arg.replace("'", "'\\''") + "'"
    return arg


# --- Privilege + environment checks ----------------------------------------


def _is_root() -> bool:
    """True iff effective uid is 0. Linux/POSIX only."""
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _real_operator_user() -> str | None:
    """The real operator behind ``sudo``. SUDO_USER when set + non-root;
    otherwise None (we won't add ``root`` to the kismet group --
    capabilities are the point of the group, and root already has them).
    """
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != "root":
        return sudo_user
    return None


# --- /etc/os-release parsing + distro gate ---------------------------------


def parse_os_release(content: str) -> dict[str, str]:
    """Parse /etc/os-release content into a dict.

    /etc/os-release is shell-syntax KEY=VALUE pairs; values may be
    quoted. We do NOT shell out -- this is a pure-Python parser so
    distro detection works on any host the script's tests can import
    on (including non-Linux dev machines).
    """
    result: dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if (
            len(value) >= 2
            and value[0] == value[-1]
            and value[0] in ('"', "'")
        ):
            value = value[1:-1]
        result[key] = value
    return result


def detect_distro(
    os_release_path: Path = Path("/etc/os-release"),
) -> tuple[str | None, str | None]:
    """Return ``(distro_id, repo_codename)``.

    - On Kali: ``("kali", "kali")`` -- the Kismet repo uses the literal
      ``kali`` codename, not the ``kali-rolling`` value
      /etc/os-release reports.
    - On supported Debian: ``("debian", "<bookworm|trixie>")``.
    - On supported Ubuntu: ``("ubuntu", "<focal|jammy|noble|plucky>")``.
    - On unsupported distros (Fedora, Arch, etc.) OR on supported
      distro at an unsupported version: ``(None, None)``.

    Returning a 2-tuple lets the caller distinguish "wrong distro"
    from "right distro, wrong version" if needed in future; v1 treats
    both as the same "manual install" case.
    """
    try:
        content = os_release_path.read_text(encoding="utf-8")
    except OSError:
        return None, None
    fields = parse_os_release(content)
    distro_id = fields.get("ID", "").lower()
    codename = fields.get("VERSION_CODENAME", "").lower()

    if distro_id == "kali":
        return "kali", "kali"
    if distro_id == "debian":
        if codename in SUPPORTED_DEBIAN_CODENAMES:
            return "debian", codename
        return None, None
    if distro_id == "ubuntu":
        if codename in SUPPORTED_UBUNTU_CODENAMES:
            return "ubuntu", codename
        return None, None
    return None, None


# --- State probes ----------------------------------------------------------


def _kismet_installed() -> bool:
    """``which kismet`` -- a Kismet binary on PATH is good enough; we
    don't care which version. The post-install probe goes deeper.
    """
    return shutil.which("kismet") is not None


def _apt_source_configured() -> bool:
    """True iff our sources.list.d file already exists. Exact match on
    KISMET_SOURCES_LIST_PATH; a hand-rolled source list at a different
    filename will look "missing" to us and trigger an add -- by design,
    so we always own a known-good copy.
    """
    return KISMET_SOURCES_LIST_PATH.exists()


def _group_exists(group: str) -> bool:
    """Best-effort grep of /etc/group. If the file is unreadable (very
    unusual), assume the group doesn't exist so the operator gets a
    clear error rather than a silent skip.
    """
    try:
        with open("/etc/group", encoding="utf-8") as fh:
            for line in fh:
                name, _, _rest = line.partition(":")
                if name == group:
                    return True
    except OSError:
        return False
    return False


def _user_in_group(user: str, group: str) -> bool:
    """True iff ``user`` appears in ``group``'s member list in
    /etc/group. Does NOT check primary GID -- in practice the kismet
    group is supplementary on every install path we support.
    """
    try:
        with open("/etc/group", encoding="utf-8") as fh:
            for line in fh:
                parts = line.rstrip("\n").split(":")
                if len(parts) >= 4 and parts[0] == group:
                    members = [m for m in parts[3].split(",") if m]
                    return user in members
    except OSError:
        return False
    return False


# --- Kismet apt repo install -----------------------------------------------


def _download_kismet_gpg_key(url: str = KISMET_GPG_KEY_URL) -> bytes:
    """Fetch the ASCII-armored key body. Uses urllib (stdlib) to avoid
    a hard dep on wget being installed on a minimal host.
    """
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            return resp.read()
    except urllib.error.URLError as exc:
        raise BootstrapError(
            f"failed to download Kismet GPG key from {url}: {exc}.\n"
            f"  Action: check network connectivity and re-run, or use "
            f"--no-network if Kismet is already installed."
        ) from exc


def install_kismet_apt_repo(codename: str, *, dry_run: bool) -> None:
    """Register the Kismet apt repo for ``codename``. Idempotent: if
    the sources.list file is already present we leave it alone, on
    the assumption that an existing one was either dropped by us on
    a prior run or hand-rolled by the operator. Either way, we don't
    silently overwrite -- it would clobber a deliberate edit.

    Writes:
      - /usr/share/keyrings/kismet-archive-keyring.gpg  (dearmored key)
      - /etc/apt/sources.list.d/kismet.list             (deb line)
    Runs:
      - apt update

    Order matters: key first, then sources file, then update. Putting
    apt update before either causes a "NO_PUBKEY" hiccup that confuses
    operators reading the log.
    """
    if _apt_source_configured():
        _print(
            f"Kismet apt source already at {KISMET_SOURCES_LIST_PATH}; "
            f"skipping add-source."
        )
    else:
        _print(f"Downloading Kismet GPG key from {KISMET_GPG_KEY_URL}")
        if dry_run:
            _print(f"DRY-RUN: download {KISMET_GPG_KEY_URL}")
            armored = b""
        else:
            armored = _download_kismet_gpg_key()

        if not shutil.which("gpg") and not dry_run:
            raise BootstrapError(
                "gpg not found on PATH. Install it first: "
                "sudo apt install gnupg"
            )

        _print(f"Dearmoring + writing keyring to {KISMET_KEYRING_PATH}")
        if dry_run:
            _print(
                f"DRY-RUN: gpg --dearmor > {KISMET_KEYRING_PATH}"
            )
        else:
            KISMET_KEYRING_PATH.parent.mkdir(parents=True, exist_ok=True)
            # Use subprocess directly here because we need to stream
            # bytes in and capture bytes out -- _run is shaped for the
            # simpler invoke-and-check case.
            try:
                result = subprocess.run(
                    ["gpg", "--dearmor"],
                    input=armored,
                    capture_output=True,
                    check=True,
                )
            except subprocess.CalledProcessError as exc:
                tail = (exc.stderr or b"").decode("utf-8", errors="replace")
                raise BootstrapError(
                    f"gpg --dearmor failed: {tail.strip()}"
                ) from exc
            _atomic_write_bytes(KISMET_KEYRING_PATH, result.stdout, mode=0o644)

        deb_line = (
            f"deb [signed-by={KISMET_KEYRING_PATH}] "
            f"https://www.kismetwireless.net/repos/apt/release/{codename} "
            f"{codename} main\n"
        )
        _print(f"Writing apt source to {KISMET_SOURCES_LIST_PATH}")
        if dry_run:
            _print(f"DRY-RUN: write {KISMET_SOURCES_LIST_PATH}")
            _print(f"DRY-RUN: {deb_line.strip()}")
        else:
            KISMET_SOURCES_LIST_PATH.parent.mkdir(parents=True, exist_ok=True)
            _atomic_write_text(KISMET_SOURCES_LIST_PATH, deb_line, mode=0o644)

    _print("Running apt update")
    _run(["apt-get", "update"], dry_run=dry_run, check=True)


def install_kismet_package(*, dry_run: bool) -> None:
    """``apt-get install -y kismet``. Idempotent at the apt layer --
    re-running on an already-installed system is a no-op.
    """
    _print(f"Installing {KISMET_PACKAGE} package (apt-get install -y {KISMET_PACKAGE})")
    env_args: list[str] = []
    # DEBIAN_FRONTEND=noninteractive so apt doesn't try to throw a
    # debconf prompt at a non-tty operator -- Kismet's postinst asks
    # "Install kismet with suid root?" by default.
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    if dry_run:
        _print(
            f"DRY-RUN: DEBIAN_FRONTEND=noninteractive apt-get install -y "
            f"{KISMET_PACKAGE}"
        )
        return
    try:
        result = subprocess.run(
            ["apt-get", "install", "-y", KISMET_PACKAGE],
            env=env,
            capture_output=True,
            check=False,
        )
    except FileNotFoundError as exc:
        raise BootstrapError(
            f"apt-get not found -- this script requires Debian/Ubuntu/Kali: {exc}"
        ) from exc
    if result.returncode != 0:
        tail = (result.stderr or b"").decode("utf-8", errors="replace").strip()
        raise BootstrapError(
            f"apt-get install failed (exit {result.returncode}): {tail or '(no stderr)'}"
        )


# --- Wi-Fi + Bluetooth interface detection ---------------------------------


def parse_iw_dev(output: str) -> list[tuple[str, str]]:
    """Parse `iw dev` output into ``[(phy, iface), ...]``.

    `iw dev` format:

        phy#0
            Interface wlan0
                ifindex 3
                ...
        phy#1
            Interface wlan1
                ...

    A single phy may carry multiple Interface entries; we record each.
    Phy lines look like ``phy#N``; we re-emit them as ``phyN`` to
    match what ``iw phy <name> info`` expects.
    """
    pairs: list[tuple[str, str]] = []
    current_phy: str | None = None
    phy_re = re.compile(r"^phy#(\d+)$")
    iface_re = re.compile(r"^\s*Interface\s+(\S+)\s*$")
    for line in output.splitlines():
        m = phy_re.match(line.strip())
        if m:
            current_phy = f"phy{m.group(1)}"
            continue
        m = iface_re.match(line)
        if m and current_phy is not None:
            pairs.append((current_phy, m.group(1)))
    return pairs


def parse_iw_phy_info_supports_monitor(output: str) -> bool:
    """True iff `iw phy <phy> info` output advertises monitor mode in
    the "Supported interface modes:" section.

    Section shape:

        Supported interface modes:
             * IBSS
             * managed
             * AP
             * AP/VLAN
             * monitor
             * mesh point

    We scan until the first non-``\\s*\\* `` line after the header,
    or end-of-output.
    """
    in_section = False
    bullet_re = re.compile(r"^\s*\*\s*(.+?)\s*$")
    for line in output.splitlines():
        if "Supported interface modes" in line:
            in_section = True
            continue
        if in_section:
            m = bullet_re.match(line)
            if not m:
                # End of bullet list; section over.
                break
            if m.group(1).strip().lower() == "monitor":
                return True
    return False


def detect_wifi_monitor_capable() -> list[str]:
    """Return interface names that support monitor mode.

    Runs `iw dev` to enumerate (phy, iface) pairs, then probes each
    phy via `iw phy <phy> info`. If `iw` is missing on PATH we return
    an empty list rather than raising -- the operator on a minimal
    install can still proceed with --interface explicitly, or skip
    Wi-Fi entirely.
    """
    if shutil.which("iw") is None:
        return []
    try:
        dev_result = subprocess.run(
            ["iw", "dev"], capture_output=True, text=True, check=False
        )
    except OSError:
        return []
    if dev_result.returncode != 0:
        return []
    pairs = parse_iw_dev(dev_result.stdout)
    capable: list[str] = []
    for phy, iface in pairs:
        try:
            info = subprocess.run(
                ["iw", "phy", phy, "info"],
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError:
            continue
        if info.returncode == 0 and parse_iw_phy_info_supports_monitor(info.stdout):
            capable.append(iface)
    return capable


def detect_bluetooth_interfaces(
    sys_class_path: Path = Path("/sys/class/bluetooth"),
) -> list[str]:
    """Enumerate hci* devices via sysfs.

    Sysfs is the canonical source -- ``/sys/class/bluetooth/hci*`` is
    populated by the kernel for every controller, regardless of
    whether ``bluetoothctl`` is installed or the bluetooth.service is
    running. ``bluetoothctl list`` and ``hciconfig`` both rely on
    additional userspace plumbing that may or may not be present on
    a fresh host. sysfs has none of those failure modes.
    """
    if not sys_class_path.is_dir():
        return []
    names = []
    try:
        for entry in sorted(sys_class_path.iterdir()):
            if entry.name.startswith("hci") and entry.name[3:].isdigit():
                names.append(entry.name)
    except OSError:
        return []
    return names


# --- kismet_site.conf patching ---------------------------------------------


_SOURCE_LINE_RE = re.compile(r"^\s*source\s*=\s*([^:\s]+)")


def existing_source_interfaces(content: str) -> set[str]:
    """Return the set of interface names already present as the head
    of a ``source=<iface>...`` line in ``content``. Comments and blank
    lines are ignored. Used by the patcher to enforce idempotency
    without textually-exact-matching the whole line (the operator may
    have added their own ``:name=foo`` suffix, which we preserve).
    """
    out: set[str] = set()
    for line in content.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        m = _SOURCE_LINE_RE.match(line)
        if m:
            out.add(m.group(1))
    return out


def build_source_line(iface: str, kind: str) -> str:
    """Render a single ``source=`` line. ``kind`` is ``"wifi"`` or
    ``"bt"``. We always emit the explicit ``type=`` form so the
    operator and Kismet agree on the driver -- the auto-detect form
    works but is harder to debug when an interface gets misclassified.
    """
    if kind == "wifi":
        return f"source={iface}:type=linuxwifi"
    if kind == "bt":
        return f"source={iface}:type=linuxbluetooth"
    raise ValueError(f"unknown source kind: {kind!r}")


def kismet_site_conf_additions(
    existing_content: str,
    wifi_ifaces: Iterable[str],
    bt_ifaces: Iterable[str],
) -> list[str]:
    """Compute the list of source= lines that need appending.

    Idempotency invariant: for any iface already present as the head
    of an existing source= line, we skip -- regardless of whatever
    suffix the operator has tacked on. This preserves operator
    customisations (``:name=foo``, ``:channel_list=...``) instead of
    silently rewriting them.
    """
    present = existing_source_interfaces(existing_content)
    additions: list[str] = []
    for iface in wifi_ifaces:
        if iface not in present:
            additions.append(build_source_line(iface, "wifi"))
    for iface in bt_ifaces:
        if iface not in present:
            additions.append(build_source_line(iface, "bt"))
    return additions


def _atomic_write_bytes(path: Path, content: bytes, *, mode: int = 0o644) -> None:
    """Write ``content`` atomically: tmpfile in same dir, fsync, replace.
    Prevents a partially-written file being read by Kismet if the
    daemon is already running with the file open.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmpname = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=str(path.parent)
    )
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmpname, mode)
        os.replace(tmpname, path)
    except OSError:
        try:
            os.unlink(tmpname)
        except OSError:
            pass
        raise


def _atomic_write_text(path: Path, content: str, *, mode: int = 0o644) -> None:
    _atomic_write_bytes(path, content.encode("utf-8"), mode=mode)


def patch_kismet_site_conf(
    path: Path,
    wifi_ifaces: Iterable[str],
    bt_ifaces: Iterable[str],
    *,
    dry_run: bool,
) -> list[str]:
    """Add missing source= lines for the selected interfaces. Returns
    the list of lines that were added (or would have been, in
    dry-run). The caller surfaces them to the operator as the "diff".

    File creation: if the file is absent we lay down a minimal header
    comment + the source lines. Pre-existing content is appended to,
    never replaced -- the patcher reads, computes the diff, and
    re-writes the full body via _atomic_write_text. Operator
    customisations (any non-source line, any source= for an iface we
    weren't asked to touch) are preserved verbatim.
    """
    try:
        existing = path.read_text(encoding="utf-8") if path.exists() else ""
    except OSError as exc:
        raise BootstrapError(
            f"could not read {path}: {exc}. Action: check that the "
            f"directory exists and the script is running as root."
        ) from exc

    additions = kismet_site_conf_additions(existing, wifi_ifaces, bt_ifaces)
    if not additions:
        _print(f"{path}: no changes needed (all selected interfaces already configured)")
        return []

    if existing == "":
        body = (
            "# kismet_site.conf -- operator overrides.\n"
            "# Managed (append-only) by lynceus-bootstrap-kismet.\n"
            "# Hand-edits below are preserved on re-run.\n"
            "\n"
            "# Capture sources:\n"
            + "\n".join(additions)
            + "\n"
        )
    else:
        sep = "" if existing.endswith("\n") else "\n"
        body = (
            existing
            + sep
            + "\n# Added by lynceus-bootstrap-kismet:\n"
            + "\n".join(additions)
            + "\n"
        )

    _print(f"{path}: adding {len(additions)} line(s):")
    for line in additions:
        _print(f"  + {line}")

    if dry_run:
        _print(f"DRY-RUN: would write {path}")
        return additions

    _atomic_write_text(path, body, mode=0o644)
    return additions


# --- Group membership ------------------------------------------------------


def add_user_to_kismet_group(user: str, *, dry_run: bool) -> None:
    """``usermod -aG kismet <user>``. The caller has already verified
    the group exists and the user is not yet a member.
    """
    _print(f"Adding {user} to the {KISMET_GROUP} group")
    _run(["usermod", "-aG", KISMET_GROUP, user], dry_run=dry_run, check=True)


# --- Interactive prompts ---------------------------------------------------


def _prompt_yes_no(
    question: str,
    *,
    default: bool = True,
    input_fn: Callable[[str], str] = input,
) -> bool:
    """Y/n (default Y) or y/N (default N) prompt. EOFError on stdin
    closed -> use default. Repeats on invalid input until we get a
    parseable answer. Behaves the same as the setup-wizard prompts
    so operators get a consistent UX.
    """
    suffix = " [Y/n] " if default else " [y/N] "
    while True:
        try:
            raw = input_fn(question + suffix).strip().lower()
        except EOFError:
            return default
        if not raw:
            return default
        if raw in ("y", "yes"):
            return True
        if raw in ("n", "no"):
            return False
        _print("  Please answer 'y' or 'n'.")


# --- Closing pointer -------------------------------------------------------


_CLOSING_RULE = "=" * 60


def print_closing_pointer(operator: str | None) -> None:
    """The "what now?" block. Always the last thing printed on a
    success path. Mentions the kismet group log-out caveat even when
    the operator was already in the group -- it's harmless and
    avoids a "did I miss a step?" moment.
    """
    relog_target = operator if operator else "your operator user"
    _print("")
    _print(_CLOSING_RULE)
    _print("Kismet bootstrap complete.")
    _print("")
    _print("Next steps:")
    _print(
        f"  1. Log out and log back in as {relog_target} so the kismet"
    )
    _print("     group takes effect (current shells don't pick up new groups).")
    _print("  2. Start Kismet:")
    _print("       sudo systemctl start kismet")
    _print("     OR (foreground, for first-launch password setup):")
    _print("       kismet")
    _print(f"  3. Open the web UI:    {KISMET_WEB_UI_URL}")
    _print("  4. Set your password (Kismet prompts on first launch).")
    _print("  5. Generate an API key:")
    _print("       Settings -> API Keys -> Create")
    _print("       Name: lynceus  |  Role: readonly")
    _print("  6. Run: sudo lynceus-setup")
    _print("     (lynceus-setup auto-locates the API key from disk;")
    _print("      you typically won't need to copy-paste it.)")
    _print(_CLOSING_RULE)


def print_unsupported_pointer(distro_id: str | None) -> None:
    """Unsupported-distro message. Clean exit 0 -- the operator isn't
    broken, they just need to install Kismet manually.
    """
    label = distro_id or "unknown"
    _print("")
    _print(_CLOSING_RULE)
    _print(f"Distro '{label}' is not supported by the Kismet apt repo.")
    _print("")
    _print("lynceus-bootstrap-kismet handles Debian, Ubuntu, and Kali only")
    _print("in v1. On any other distro, install Kismet manually following")
    _print("the official packaging instructions:")
    _print("")
    _print(f"  {UNSUPPORTED_POINTER_URL}")
    _print("")
    _print("Then re-run lynceus-bootstrap-kismet with --skip-install to")
    _print("get the interface configuration + permissions steps, or skip")
    _print("straight to: sudo lynceus-setup")
    _print(_CLOSING_RULE)


# --- CLI argparse ----------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lynceus-bootstrap-kismet",
        description=(
            "Install + configure Kismet on Debian/Ubuntu/Kali, then point "
            "the operator at the web-UI ceremony (set password, create "
            "API key) that lynceus-setup picks up afterward. Idempotent: "
            "safe to re-run. Requires root (apt, setcap, /etc/kismet "
            "ownership). install.sh remains offline; this script is the "
            "one Lynceus CLI that uses the network beyond "
            "lynceus-import-argus."
        ),
    )
    p.add_argument(
        "--skip-install",
        action="store_true",
        help=(
            "Skip the apt repo + package install; Kismet is already "
            "present. Useful on hosts where Kismet was installed by a "
            "different mechanism (manual build, custom package) but the "
            "kismet_site.conf + group setup still needs running."
        ),
    )
    p.add_argument(
        "--interface",
        action="append",
        default=[],
        metavar="NAME",
        help=(
            "Add this interface to kismet_site.conf without auto-detection. "
            "May be given multiple times. Pairs with --interface-type to "
            "force a kind; defaults to 'wifi'."
        ),
    )
    p.add_argument(
        "--interface-type",
        choices=("wifi", "bt"),
        default="wifi",
        help=(
            "Kind for --interface entries when used. Default: %(default)s."
        ),
    )
    p.add_argument(
        "--no-network",
        action="store_true",
        help=(
            "Refuse any apt / network operation. Implies --skip-install. "
            "Useful for offline operators who installed Kismet manually."
        ),
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Print every command + file write that would happen, without "
            "executing. Operator-facing prompts still appear, so the "
            "preview reflects the real interactive choices."
        ),
    )
    p.add_argument(
        "--yes",
        action="store_true",
        help=(
            "Accept every Y/n prompt with its default (Y). Useful for "
            "scripted bootstrap; the script still emits the same output."
        ),
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"lynceus-bootstrap-kismet {__version__}",
    )
    return p


# --- Orchestrator ----------------------------------------------------------


def _select_interfaces(
    args: argparse.Namespace,
    input_fn: Callable[[str], str],
) -> tuple[list[str], list[str]]:
    """Return ``(wifi_to_configure, bt_to_configure)``.

    Operator flow:
      * --interface flags: bypass detection entirely (categorised by
        --interface-type).
      * Otherwise: enumerate, show, ask Y per interface.

    "No interfaces" is not an error -- the operator may have a remote
    capture rig they'll configure manually, or only one kind of radio.
    We log a note and continue.
    """
    if args.interface:
        if args.interface_type == "wifi":
            return list(args.interface), []
        return [], list(args.interface)

    yes_default = args.yes
    yes_fn = (lambda q, default=True: True) if yes_default else (
        lambda q, default=True: _prompt_yes_no(
            q, default=default, input_fn=input_fn
        )
    )

    _print("")
    _print("Detecting capture interfaces...")
    wifi_candidates = detect_wifi_monitor_capable()
    bt_candidates = detect_bluetooth_interfaces()

    if not wifi_candidates:
        _print("  No Wi-Fi monitor-capable interfaces found.")
    if not bt_candidates:
        _print("  No Bluetooth controllers found.")

    wifi_selected: list[str] = []
    for iface in wifi_candidates:
        if yes_fn(f"Use Wi-Fi interface {iface} for Kismet capture?", True):
            wifi_selected.append(iface)

    bt_selected: list[str] = []
    for iface in bt_candidates:
        if yes_fn(f"Use Bluetooth controller {iface} for Kismet capture?", True):
            bt_selected.append(iface)

    return wifi_selected, bt_selected


def run(args: argparse.Namespace, *, input_fn: Callable[[str], str] = input) -> int:
    """Main flow. Returns an exit code; main() forwards it to sys.exit."""

    # Root gate -- needed for apt, setcap, /etc/kismet ownership,
    # usermod. --dry-run is also gated so the preview reflects what an
    # operator would actually have to run.
    if not _is_root():
        _err(
            "lynceus-bootstrap-kismet: must run as root. "
            "Re-run with sudo: sudo lynceus-bootstrap-kismet"
        )
        return 2

    # Linux gate -- everything below assumes apt + /etc/os-release.
    if sys.platform != "linux":
        _err(
            f"lynceus-bootstrap-kismet: Linux only "
            f"(detected platform: {sys.platform}). On other platforms, "
            f"install Kismet manually and run lynceus-setup."
        )
        return 2

    distro_id, codename = detect_distro()
    if distro_id is None:
        print_unsupported_pointer(distro_id)
        return 0

    _print(
        f"Detected distro: {distro_id} (codename: {codename}). "
        f"Proceeding with Kismet bootstrap."
    )

    # Install path -- gated by --skip-install and --no-network.
    if args.no_network and not args.skip_install:
        _print("--no-network implies --skip-install; will not run apt operations.")
    skip_install = args.skip_install or args.no_network

    if not skip_install:
        if _kismet_installed():
            _print("kismet binary already on PATH.")
            if args.yes:
                # --yes accepts every Y/n prompt with its default. This
                # one defaults to N, so --yes skips re-install.
                proceed_install = False
            else:
                proceed_install = _prompt_yes_no(
                    "Re-run apt-get install kismet anyway?",
                    default=False,
                    input_fn=input_fn,
                )
            if proceed_install:
                install_kismet_apt_repo(codename or "", dry_run=args.dry_run)
                install_kismet_package(dry_run=args.dry_run)
            else:
                _print("Skipping apt install (kismet already present).")
        else:
            install_kismet_apt_repo(codename or "", dry_run=args.dry_run)
            install_kismet_package(dry_run=args.dry_run)
            if not args.dry_run and not _kismet_installed():
                raise BootstrapError(
                    "apt-get install succeeded but the 'kismet' binary "
                    "is not on PATH. Investigate before re-running."
                )

    # Interface selection -- always run (configures even on
    # --skip-install / --no-network).
    wifi_selected, bt_selected = _select_interfaces(args, input_fn)

    if not wifi_selected and not bt_selected:
        _print(
            "\nNo interfaces selected for kismet_site.conf. Skipping "
            "config patch."
        )
    else:
        patch_kismet_site_conf(
            KISMET_SITE_CONF_PATH,
            wifi_selected,
            bt_selected,
            dry_run=args.dry_run,
        )

    # Group membership -- the .deb postinst creates the group + sets
    # capabilities; we only need to add the operator to it.
    operator = _real_operator_user()
    if operator is None:
        _print(
            "\nNote: SUDO_USER not set or runs as root. Skipping kismet "
            "group membership step -- the user that will run Kismet "
            "should be added manually:"
        )
        _print(f"  sudo usermod -aG {KISMET_GROUP} <user>")
    else:
        if not _group_exists(KISMET_GROUP):
            # Don't paper over a missing group -- that's a signal that
            # the package install didn't behave as expected and the
            # operator needs to investigate before adding capabilities
            # via some other path.
            _err(
                f"\nERROR: {KISMET_GROUP!r} group does not exist. The Kismet "
                f".deb is expected to create it during postinst; if it "
                f"isn't there, the package install didn't complete "
                f"cleanly. Check `dpkg -l kismet` and the install log."
            )
            return 1
        if _user_in_group(operator, KISMET_GROUP):
            _print(f"\n{operator} is already in the {KISMET_GROUP} group; skipping usermod.")
        else:
            add_user_to_kismet_group(operator, dry_run=args.dry_run)

    print_closing_pointer(operator)
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        return run(args)
    except BootstrapError as exc:
        _err(f"lynceus-bootstrap-kismet: {exc}")
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
