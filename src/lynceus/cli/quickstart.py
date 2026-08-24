"""lynceus-quickstart — dev/demo launcher that starts the daemon + UI.

Foreground-only: Ctrl+C shuts everything down. Production deployment uses
systemd; quickstart is for hacking and demos. The launcher only orchestrates
the existing entry points (lynceus, lynceus-ui) — it does not re-implement
either daemon or UI.
"""

from __future__ import annotations

import argparse
import collections
import csv
import ctypes
import logging
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import webbrowser
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

import yaml

from .. import __version__, paths
from ..yaml_duplicates import warn_duplicate_keys

logger = logging.getLogger(__name__)

DEFAULT_UI_PORT = 8765
DAEMON_GRACE_SECONDS = 2.0
UI_HEALTH_TIMEOUT_SECONDS = 10.0
SHUTDOWN_GRACE_SECONDS = 10.0
SUPERVISE_POLL_INTERVAL = 0.5
TAIL_LINES_ON_CRASH = 20


# --- Platform indirection ---------------------------------------------------
#
# Mirrors paths._platform() and setup.core._is_windows(). Patch THESE in
# tests, never os.name or sys.platform.
#
# `quickstart.os` is not a copy of the os module, it is the interpreter-wide
# singleton, so monkeypatching os.name here changes it for every caller in the
# process, pytest included. pathlib picks its concrete Path subclass off
# os.name at call time, so under a "nt" patch on POSIX, pytest's own
# _repr_failure_py builds a WindowsPath and raises NotImplementedError while
# it is rendering a traceback. monkeypatch teardown runs AFTER the report is
# built, so the patch is still live when that happens. pytest reports it as
# INTERNALERROR and aborts the entire session: not one failure, every
# remaining test silently unrun. Measured on the first Linux run of this
# suite, which died at 42%.


def _is_windows() -> bool:
    """True on Windows. Test seam: patch this, not ``os.name``."""
    return os.name == "nt"


def _is_linux() -> bool:
    """True on Linux. Test seam: patch this, not ``sys.platform``."""
    return sys.platform.startswith("linux")


BANNER = """\
===============================================
LYNCEUS QUICKSTART — DEV/DEMO LAUNCHER
This is not a production deployment.
For production use systemd: see install.sh
==============================================="""


# --- Pre-flight checks --------------------------------------------------------


def check_not_root() -> str | None:
    """Refuse to run as root on POSIX. No-op when os.geteuid is unavailable
    (Windows)."""
    if not hasattr(os, "geteuid"):
        return None
    if os.geteuid() == 0:
        return (
            "lynceus-quickstart should not run as root. Use a regular user. "
            "For systemd deployment, see install.sh."
        )
    return None


SYSTEMD_UNITS = ("lynceus.service", "lynceus-ui.service")


def check_no_systemd() -> str | None:
    """Refuse to run if any Lynceus systemd unit is active. Probes both the
    daemon (``lynceus.service``) and the UI (``lynceus-ui.service``) under
    user-scope and system-scope. No-op on Windows or when systemctl is not
    available on PATH."""
    if _is_windows():
        return None
    probes: list[list[str]] = []
    for unit in SYSTEMD_UNITS:
        probes.append(["systemctl", "--user", "is-active", unit])
        probes.append(["systemctl", "is-active", unit])
    for cmd in probes:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=False)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        except OSError:
            continue
        if (r.stdout or "").strip() == "active":
            return (
                "Lynceus is already running under systemd. "
                "Stop the service first or use the production deployment."
            )
    return None


def check_config_exists(path: str) -> str | None:
    if not Path(path).exists():
        return f"Config file not found at {path}. Run lynceus-setup first."
    return None


def check_port_free(port: int, host: str = "127.0.0.1") -> str | None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        try:
            s.bind((host, port))
        except OSError:
            return f"Port {port} is already in use. Stop whatever is bound there or pass --port-ui."
    finally:
        s.close()
    return None


# --- Banner -------------------------------------------------------------------


def print_banner(port: int, file=None) -> None:
    out = file if file is not None else sys.stdout
    print(BANNER, file=out)
    print("Starting daemon...", file=out)
    print(f"Starting UI on http://127.0.0.1:{port}...", file=out)
    print("Opening browser...", file=out)
    print("===============================================", file=out)
    out.flush()


# --- Subprocess management ----------------------------------------------------


# Linux parent-death-signal wiring. Resolved once in the parent process so
# the post-fork preexec_fn (which runs in a fragile async-signal context)
# does no importing or symbol lookup. ``_prctl`` is None off Linux.
_PR_SET_PDEATHSIG = 1
try:
    _prctl = ctypes.CDLL(None, use_errno=True).prctl if sys.platform.startswith("linux") else None
except Exception:  # pragma: no cover - defensive: missing/odd libc
    _prctl = None


def _set_pdeathsig() -> None:
    """Linux child preexec: ask the kernel to SIGTERM this child when
    quickstart (its parent) dies — including abnormal exits (terminal closed,
    ``kill -9``) where neither the Ctrl+C handler nor supervise() runs.

    Without it each child runs in its own session (``start_new_session``) and
    would be orphaned on an abnormal parent death, leaving uvicorn holding
    port 8765 → "address already in use" on the next launch. Best-effort:
    no-ops where prctl is unavailable, and never aborts the child's exec."""
    if _prctl is None:
        return
    try:
        _prctl(_PR_SET_PDEATHSIG, int(signal.SIGTERM), 0, 0, 0)
        # Close the fork→prctl race: if quickstart already exited in that
        # window, the signal won't arrive — self-terminate instead of
        # lingering as the very orphan this guards against.
        if os.getppid() == 1:
            os._exit(1)
    except Exception:
        pass


def _popen_kwargs() -> dict:
    """Cross-platform kwargs to isolate subprocesses into their own session
    (POSIX) or process group (Windows), so a Ctrl+C in the parent terminal
    does not also race the children. On Linux, additionally register a
    parent-death signal so an abnormal quickstart exit can't orphan them."""
    if _is_windows():
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    kwargs: dict = {"start_new_session": True}
    if _is_linux():
        kwargs["preexec_fn"] = _set_pdeathsig
    return kwargs


def _resolve_entry_point(name: str) -> list[str]:
    """Resolve an installed console-script next to sys.executable; fall back
    to a bare PATH lookup if the script is not co-located (developer setups,
    PEP 660 editable installs on some distros).
    """
    bin_dir = Path(sys.executable).parent
    candidates: list[Path] = []
    if _is_windows():
        candidates.append(bin_dir / f"{name}.exe")
        candidates.append(bin_dir / "Scripts" / f"{name}.exe")
    else:
        candidates.append(bin_dir / name)
    for c in candidates:
        if c.exists():
            return [str(c)]
    return [name]


def start_daemon(config_path: str) -> subprocess.Popen:
    cmd = _resolve_entry_point("lynceus") + ["--config", config_path]
    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        **_popen_kwargs(),
    )


def start_ui(config_path: str) -> subprocess.Popen:
    cmd = _resolve_entry_point("lynceus-ui") + ["--config", config_path]
    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        **_popen_kwargs(),
    )


# --- Output teeing ------------------------------------------------------------


class TeeSupervisor:
    """Streams a subprocess's stdout/stderr to the parent terminal with a name
    prefix and retains the last N lines for crash reporting."""

    def __init__(
        self,
        name: str,
        proc: subprocess.Popen,
        maxlen: int = TAIL_LINES_ON_CRASH,
    ) -> None:
        self.name = name
        self.proc = proc
        self.tail_lines: collections.deque[str] = collections.deque(maxlen=maxlen)
        self._lock = threading.Lock()
        self._threads: list[threading.Thread] = []
        if proc.stdout is not None:
            self._spawn(proc.stdout, sys.stdout)
        if proc.stderr is not None:
            self._spawn(proc.stderr, sys.stderr)

    def _spawn(self, src, dst) -> None:
        t = threading.Thread(target=self._pump, args=(src, dst), daemon=True)
        t.start()
        self._threads.append(t)

    def _pump(self, src, dst) -> None:
        prefix = f"[{self.name}] "
        try:
            for line in src:
                with self._lock:
                    self.tail_lines.append(line)
                try:
                    dst.write(prefix + line)
                    dst.flush()
                except Exception:
                    pass
        except Exception:
            pass

    def tail(self) -> list[str]:
        with self._lock:
            return list(self.tail_lines)


# --- Health check -------------------------------------------------------------


def _urlopen_get(url: str, timeout: float):
    return urlopen(url, timeout=timeout)


def wait_for_ui_ready(port: int, timeout: float = UI_HEALTH_TIMEOUT_SECONDS) -> bool:
    deadline = time.monotonic() + timeout
    url = f"http://127.0.0.1:{port}/healthz"
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with _urlopen_get(url, timeout=1.0) as resp:
                if 200 <= resp.getcode() < 300:
                    return True
        except (URLError, OSError) as e:
            last_err = e
        time.sleep(0.2)
    if last_err is not None:
        logger.debug("UI health check final error: %s", last_err)
    return False


# --- Browser ------------------------------------------------------------------


def launch_browser(port: int, no_browser: bool = False, file=None) -> None:
    if no_browser:
        return
    out = file if file is not None else sys.stdout
    url = f"http://127.0.0.1:{port}"
    if not webbrowser.open(url):
        print(f"No browser available; visit {url} manually.", file=out)
        out.flush()


# --- Shutdown -----------------------------------------------------------------


def shutdown(procs, grace: float = SHUTDOWN_GRACE_SECONDS) -> None:
    """SIGTERM each process; SIGKILL any that do not exit within `grace`."""
    for p in procs:
        try:
            if p.poll() is None:
                p.terminate()
        except Exception as e:
            logger.warning("terminate failed: %s", e)
    for p in procs:
        try:
            p.wait(timeout=grace)
        except subprocess.TimeoutExpired:
            try:
                p.kill()
            except Exception as e:
                logger.warning("kill failed: %s", e)
            try:
                p.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                pass
        except Exception:
            pass


def _make_sigint_handler(procs):
    def _handler(signum, frame):
        print(
            "\nShutdown requested. Stopping subprocesses...",
            file=sys.stderr,
        )
        shutdown(procs)
        print("Shutdown complete.", file=sys.stderr)
        sys.exit(0)

    return _handler


# --- Supervision loop ---------------------------------------------------------


def _extract_daemon_error(tail_lines: list[str]) -> str | None:
    """Pull the daemon's actionable error out of its captured output so it can
    be surfaced prominently instead of buried in the tail dump.

    Prefers the ``RuntimeError`` message the poller raises (the actionable
    health-check guidance — stale-key vs Kismet-down, naming the config file);
    falls back to a Kismet health-check line. Returns None when nothing
    recognisable is present, in which case the caller just shows the raw tail.
    """
    for line in reversed(tail_lines):
        stripped = line.strip()
        if stripped.startswith("RuntimeError:"):
            return stripped[len("RuntimeError:") :].strip()
    for line in reversed(tail_lines):
        stripped = line.strip()
        if "Kismet" not in stripped:
            continue
        if "rejected the API key" in stripped or "unreachable" in stripped:
            return stripped
    return None


def supervise(
    daemon,
    ui,
    daemon_tee=None,
    ui_tee=None,
    poll_interval: float = SUPERVISE_POLL_INTERVAL,
) -> int:
    """Block until one of the subprocesses dies. Returns 1 on unexpected exit."""
    while True:
        d_rc = daemon.poll()
        if d_rc is not None:
            print(
                f"\nDaemon exited unexpectedly with code {d_rc}.",
                file=sys.stderr,
            )
            if daemon_tee is not None:
                tail = daemon_tee.tail()
                if tail:
                    print("--- last daemon output ---", file=sys.stderr)
                    sys.stderr.writelines(tail)
                    print("--------------------------", file=sys.stderr)
                    actionable = _extract_daemon_error(tail)
                    if actionable:
                        print(f"\n>>> daemon error: {actionable}", file=sys.stderr)
            shutdown([ui])
            return 1
        u_rc = ui.poll()
        if u_rc is not None:
            print(
                f"\nUI exited unexpectedly with code {u_rc}.",
                file=sys.stderr,
            )
            if ui_tee is not None:
                tail = ui_tee.tail()
                if tail:
                    print("--- last ui output ---", file=sys.stderr)
                    sys.stderr.writelines(tail)
                    print("----------------------", file=sys.stderr)
            shutdown([daemon])
            return 1
        time.sleep(poll_interval)


# --- Config helpers -----------------------------------------------------------


def _read_ui_port_from_config(config_path: str) -> int:
    """Read ``ui_bind_port`` from the OPERATOR'S config file.

    ⛔ This reads the operator's hand-edited ``lynceus.yaml``, not a
    machine-written file. It was exempted from the duplicate-key coverage guard
    on the reasoning that it parses a "machine-written port override" -- which
    described the wrong file: the machine-written override is what
    ``_write_port_override_config`` RETURNS. Measured on a config carrying a
    duplicate ``ui_bind_port:``, this silently returned the LAST one with
    nothing logged at any level.
    """
    try:
        with open(config_path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except OSError:
        return DEFAULT_UI_PORT
    # ⚠️ Deliberately OUTSIDE the `try` above. A diagnostic that can be caught
    # by the caller's error handling is how a valid allowlist once loaded as
    # zero entries; `warn_duplicate_keys` never raises, and it is placed where
    # it could not matter if it did.
    warn_duplicate_keys(Path(config_path), logger=logger, subject="config file")
    return int(data.get("ui_bind_port", DEFAULT_UI_PORT))


def _write_port_override_config(config_path: str, port: int) -> str:
    """Write a temp YAML copy of the config with ui_bind_port overridden.
    Returns the temp file path; caller is responsible for cleanup.

    ⛔ The temp copy is handed to the UI process, and ``yaml.safe_dump`` writes
    back only the surviving value of any duplicate key. Measured: a config with
    ``heartbeat_enabled:`` twice produced a temp config keeping only the loser,
    with the operator's other value gone and nothing reported -- the daemon
    doing the laundering, which is the shape #138 named. The warning below is
    emitted against the SOURCE file, before the collapse, because after
    ``safe_dump`` the evidence no longer exists.
    """
    with open(config_path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    warn_duplicate_keys(Path(config_path), logger=logger, subject="config file")
    data["ui_bind_port"] = port
    fd, tmp = tempfile.mkstemp(suffix=".yaml", prefix="lynceus-quickstart-")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f)
    return tmp


def _demo_watchlist_candidates(fixture_path: Path) -> tuple[set[str], set[str]]:
    """Derive the (macs, ssid-ish names) the demo fixture can ever match
    against, straight from the fixture JSON -- not a hardcoded literal.

    Mirrors the two fields the real match path actually reads: ``kismet.
    device.base.macaddr`` (exact, case-insensitive) and ``kismet.device.
    base.name`` (substring haystack for ``ssid``/``ssid_pattern``, see
    ``kismet.py``'s ``ssid = raw.get("kismet.device.base.name")`` and
    ``db.py``'s ``_lookup_substring_watchlist_match``). Kept in lockstep
    with the fixture on purpose: whatever devices Task 2 curates in, this
    derives the right filter with no second place to update.
    """
    import json

    records = json.loads(fixture_path.read_text(encoding="utf-8"))
    macs = {
        r["kismet.device.base.macaddr"].lower()
        for r in records
        if r.get("kismet.device.base.macaddr")
    }
    names = {
        r["kismet.device.base.name"]
        for r in records
        if r.get("kismet.device.base.name")
    }
    return macs, names


def _filter_watchlist_csv_for_demo(
    src_csv: Path, fixture_path: Path, out_csv: Path
) -> bool:
    """Write ``out_csv`` containing only the bundled-watchlist rows the demo
    fixture can actually match, and report whether any survived.

    ⛔ Importing the full bundled CSV works -- measured, it fires the real
    Flock-SSID alert -- but ``import_csv`` does per-row DB validation and
    writes, and at the bundled corpus's real size (41,518 rows) that
    measured 4m27s from launch to the UI's first response. That defeats a
    "no hardware, watch it run" demo: someone evaluating the product
    watches a blank terminal for four and a half minutes. Filtering here
    costs one read of the full CSV (~0.25s, measured, pure ``csv`` parsing,
    no DB) and hands ``import_csv`` only the handful of rows that were ever
    going to survive contact with a 9-device fixture, so the DB-write cost
    scales with the demo, not with the corpus.

    identifier_type coverage matches the two delegation rule_types
    ``build_demo_config`` enables (``watchlist_mac``, ``watchlist_ssid``):
    ``mac`` rows need an exact (case-insensitive) hit against a fixture
    MAC; ``ssid`` / ``ssid_pattern`` rows need the identifier to be a
    case-insensitive substring of a fixture device name -- the same
    direction ``_lookup_substring_watchlist_match`` tests in the real
    matcher (needle=identifier, haystack=observed name).
    """
    from ..cli.import_argus import EXPECTED_HEADER, parse_argus_csv

    macs, names = _demo_watchlist_candidates(fixture_path)
    rows = parse_argus_csv(str(src_csv))
    kept = []
    for row in rows:
        identifier = row["identifier"]
        # ⛔ These are the RAW Argus identifier_type values (what's actually in
        # the CSV column), not the mapped watchlist.pattern_type -- import_csv
        # applies IDENTIFIER_TYPE_MAP downstream of this filter (ssid_exact ->
        # "ssid"). Testing against "ssid" here instead of "ssid_exact" silently
        # dropped every ssid_exact row (6 of 41 SSID rows in the bundled CSV):
        # "ssid" never occurs as a raw identifier_type. Do not "helpfully"
        # normalize these to the mapped names.
        id_type = row["identifier_type"]
        if id_type == "mac":
            if identifier.lower() in macs:
                kept.append(row)
        elif id_type in ("ssid_exact", "ssid_pattern"):
            needle = identifier.lower()
            if needle and any(needle in name.lower() for name in names):
                kept.append(row)

    with src_csv.open(encoding="utf-8") as f:
        meta_line = f.readline()
    # ⛔ record_count in the meta line becomes import_runs.record_count, which
    # the dashboard's "watchlist" freshness figure reads verbatim (app.py's
    # watchlist_records = watchlist_freshness["record_count"]) -- it is NOT a
    # re-COUNT(*) of the watchlist table. Copying the original corpus's
    # record_count (41,518) through unchanged would make the demo dashboard
    # claim a full corpus while only `len(kept)` rows actually exist: honest
    # about the row count is the entire point of filtering, so the count in
    # the meta line has to track what this function actually kept.
    meta_line = re.sub(r"record_count=\d+", f"record_count={len(kept)}", meta_line)
    with out_csv.open("w", encoding="utf-8", newline="") as f:
        f.write(meta_line)
        writer = csv.writer(f)
        writer.writerow(EXPECTED_HEADER)
        for row in kept:
            writer.writerow([row[col] for col in EXPECTED_HEADER])
    return bool(kept)


def _seed_demo_watchlist(db_path: Path, state_dir: Path) -> Path | None:
    """Import the demo-relevant slice of the bundled Argus watchlist into
    the demo DB, and render a rules.yaml enabling the two delegation
    rule_types the demo actually has watchlist rows for.

    ``lynceus-setup`` normally does both of these -- via ``import_bundled_
    watchlist`` and the interactive enable-alerting wizard in
    ``lynceus.setup.core`` -- but the demo path exists specifically so a
    stranger never has to run the wizard. Without this, the demo db has 0
    watchlist rows and no ``rules_path``: the daemon logs "ruleset is empty",
    and the curated fixture's Flock-style AP (matched via a bundled
    ssid_pattern stem -- see BACKLOG's SHIPPED entry and tests/test_demo_
    mode.py) never alerts. That is the exact "tests pass, dashboard shows
    nothing real" gap this task exists to catch, so this reproduces the two
    non-interactive halves of the wizard's closing arc directly, in-process
    (not via the ``lynceus-import-argus`` console script -- that would need
    PATH resolution the daemon/UI subprocesses get from ``_resolve_entry_
    point`` and this call site has no equivalent for) -- and against a CSV
    already filtered down to what the demo can match, not the full corpus
    (see ``_filter_watchlist_csv_for_demo``).

    Returns the rules.yaml path to wire into the config, or None if the
    bundled watchlist CSV is not present (source builds without bundled
    threat data), nothing in it matches the demo fixture, or the import
    failed for any reason -- either way the demo still runs, just without
    alerts, rather than crashing.
    """
    import importlib.resources

    from ..cli.import_argus import import_csv, load_override_config
    from ..db import Database
    from ..demo import DEMO_FIXTURE_PATH
    from ..setup.core import render_rules_yaml

    try:
        resource = importlib.resources.files("lynceus.data").joinpath(
            "default_watchlist.csv"
        )
        if not resource.is_file():
            return None
    except (ModuleNotFoundError, FileNotFoundError, OSError):
        return None

    try:
        with importlib.resources.as_file(resource) as csv_path:
            filtered_csv = state_dir / "demo_watchlist.csv"
            if not _filter_watchlist_csv_for_demo(
                Path(csv_path), DEMO_FIXTURE_PATH, filtered_csv
            ):
                return None
            db = Database(str(db_path))
            try:
                import_csv(
                    db,
                    str(filtered_csv),
                    load_override_config(None),
                    source="lynceus-quickstart --demo (bundled watchlist, filtered to fixture)",
                )
            finally:
                db.close()
    except Exception:
        logger.warning("demo: bundled watchlist import failed", exc_info=True)
        return None

    rules_path = state_dir / "rules.yaml"
    rules_path.write_text(
        render_rules_yaml({"watchlist_mac", "watchlist_ssid"}), encoding="utf-8"
    )
    return rules_path


def build_demo_config(state_dir: Path) -> Path:
    """Write a self-contained demo config into ``state_dir`` and return its path.

    ⛔ Everything lives under ``state_dir``, which the caller creates fresh. The
    demo must never point at, migrate, or prune a database the operator cares
    about: someone evaluating the product for the first time should not be able
    to damage an install they do not yet have.
    """
    from ..demo import DEMO_FIXTURE_PATH

    db_path = state_dir / "demo.db"
    rules_path = _seed_demo_watchlist(db_path, state_dir)

    config = {
        "db_path": str(db_path),
        "kismet_fixture_path": str(DEMO_FIXTURE_PATH),
        "kismet_fixture_shift_to_now": True,
        "poll_interval_seconds": 5,
        "ui_bind_host": "127.0.0.1",
    }
    if rules_path is not None:
        config["rules_path"] = str(rules_path)
    path = state_dir / "lynceus-demo.yaml"
    path.write_text(yaml.safe_dump(config, sort_keys=True), encoding="utf-8")
    return path


# --- CLI entry point ----------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lynceus-quickstart",
        description=(
            "Dev/demo launcher: starts the lynceus daemon and UI as "
            "subprocesses, opens the dashboard in a browser, and shuts both "
            "down on Ctrl+C. Production deployments should use systemd."
        ),
    )
    parser.add_argument(
        "--port-ui",
        type=int,
        default=None,
        help=(
            f"UI bind port (default: {DEFAULT_UI_PORT}, or whatever "
            "ui_bind_port is set to in the config)."
        ),
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Start daemon + UI but do not launch a browser.",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help=(
            "Run the bundled demo: no Kismet, no adapter and no config needed. "
            "Seeds a throwaway database in a temp directory and replays a "
            "curated fixture with its clocks shifted to now."
        ),
    )
    # Resolve at parse time so --help shows the path that will actually be used
    # — the user-mode XDG file under ``--user`` installs, the system-mode file
    # otherwise, or a clear "(none found)" sentinel that mirrors what main()
    # will report when the operator forgets to run lynceus-setup first.
    resolved_default = paths.resolve_existing_config()
    config_default = str(resolved_default) if resolved_default is not None else None
    config_default_help = config_default if config_default else "(none found)"
    # --config and --system are mutually exclusive: --config names an
    # explicit path; --system forces the system (/etc) scope. Both at once
    # is contradictory, so let argparse reject the combination.
    scope_group = parser.add_mutually_exclusive_group()
    scope_group.add_argument(
        "--config",
        default=config_default,
        help=f"Path to lynceus.yaml (default: {config_default_help}).",
    )
    scope_group.add_argument(
        "--system",
        action="store_true",
        help=(
            "Resolve and launch against the system-scope config (under "
            "/etc/lynceus) instead of the default user-scope-first "
            "resolution. Does NOT change resolution precedence — it points "
            "quickstart explicitly at the system scope so it matches a "
            "`sudo lynceus-setup --system` install."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"lynceus-quickstart {__version__}",
    )
    return parser


def _no_config_error() -> str:
    """Build an error message listing both probed config paths.

    On macOS / Windows the system path is unsupported and is reported as
    "(unsupported)" so the operator isn't pointed at a path Lynceus refuses
    to use.
    """
    user_path = paths.default_config_path("user")
    try:
        system_path: Path | None = paths.default_config_path("system")
    except NotImplementedError:
        system_path = None
    lines = [
        "no lynceus config found. Looked at:",
        f"  user:   {user_path}",
        f"  system: {system_path if system_path is not None else '(unsupported on this platform)'}",
        "Run lynceus-setup to create one.",
    ]
    return "\n".join(lines)


def _cleanup_demo_dir(demo_dir: Path | None) -> None:
    """Remove a ``--demo``-created temp directory. No-op if None (--demo
    was not used) or already gone.

    Called from every early-return in ``main()`` between the point ``--demo``
    creates the directory and the daemon/UI ``try/finally`` that would
    otherwise be the only cleanup path -- ``check_not_root``,
    ``check_no_systemd``, and ``check_port_free`` can all still fail (return
    2) before that ``try`` is even entered, e.g. re-running ``--demo`` while
    a previous demo instance still holds the port. Without this, that
    ordinary "ran it twice" mistake leaks a ~16 MB throwaway database per
    attempt, contradicting the README's "throwaway" / "touches no config of
    yours" claims for a demo whose whole point is leaving no trace.
    """
    if demo_dir is not None:
        shutil.rmtree(demo_dir, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    demo_dir: Path | None = None
    if args.demo:
        demo_dir = Path(tempfile.mkdtemp(prefix="lynceus-demo-"))
        args.config = str(build_demo_config(demo_dir))
        print(f"demo: throwaway database and config under {demo_dir}")
    if args.system:
        # Explicit system-scope: point quickstart at /etc regardless of the
        # user-scope-first default. This is an explicit override, not a
        # change to resolve_existing_config()'s precedence. The existence
        # check below catches a missing /etc config with the standard
        # "Run lynceus-setup first" guidance.
        try:
            resolved = paths.default_config_path("system")
        except NotImplementedError:
            print(
                "error: --system config scope is not supported on this platform.",
                file=sys.stderr,
            )
            _cleanup_demo_dir(demo_dir)
            return 2
        config_path = str(resolved)
    elif args.config is None:
        # _build_parser already attempted resolution at parse time; re-resolve
        # here so tests that monkeypatch paths.resolve_existing_config after
        # parser construction still work and so the error message lists the
        # actual paths probed.
        resolved = paths.resolve_existing_config()
        if resolved is None:
            print(f"error: {_no_config_error()}", file=sys.stderr)
            return 2
        config_path = str(resolved)
    else:
        config_path = args.config

    for err in (
        check_not_root(),
        check_no_systemd(),
        check_config_exists(config_path),
    ):
        if err:
            print(f"error: {err}", file=sys.stderr)
            _cleanup_demo_dir(demo_dir)
            return 2

    config_port = _read_ui_port_from_config(config_path)
    effective_port = args.port_ui if args.port_ui is not None else config_port

    port_err = check_port_free(effective_port)
    if port_err:
        print(f"error: {port_err}", file=sys.stderr)
        _cleanup_demo_dir(demo_dir)
        return 2

    ui_config_path = config_path
    tmp_config: str | None = None
    if args.port_ui is not None and args.port_ui != config_port:
        tmp_config = _write_port_override_config(config_path, args.port_ui)
        ui_config_path = tmp_config

    # Name the resolved config + scope before launching, so a scope mismatch
    # (quickstart resolves user-scope-first; the operator may have edited the
    # system file) is visible up front rather than only inferred from a
    # downstream daemon failure.
    scope = paths.classify_config_scope(config_path)
    scope_label = f"{scope} scope" if scope else "custom path"
    print(f"Using config: {config_path} ({scope_label})")
    # If a config also exists in the other canonical scope, the one we
    # resolved is shadowing it — the exact "I configured /etc but quickstart
    # read ~/.config" trap. Surface it loudly before launching.
    shadow = paths.describe_shadowing(config_path)
    if shadow:
        print(f"warning: {shadow}", file=sys.stderr)
    print_banner(effective_port)

    daemon: subprocess.Popen | None = None
    ui: subprocess.Popen | None = None
    daemon_tee: TeeSupervisor | None = None
    ui_tee: TeeSupervisor | None = None
    try:
        daemon = start_daemon(config_path)
        daemon_tee = TeeSupervisor("daemon", daemon)
        time.sleep(DAEMON_GRACE_SECONDS)
        if daemon.poll() is not None:
            print(
                f"error: daemon failed to start (exit code {daemon.returncode}).",
                file=sys.stderr,
            )
            tail = daemon_tee.tail()
            for line in tail:
                sys.stderr.write(line)
            actionable = _extract_daemon_error(tail)
            if actionable:
                print(f"\n>>> daemon error: {actionable}", file=sys.stderr)
            return 1

        ui = start_ui(ui_config_path)
        ui_tee = TeeSupervisor("ui", ui)

        if not wait_for_ui_ready(effective_port):
            print(
                f"error: UI did not become healthy within {UI_HEALTH_TIMEOUT_SECONDS:.0f}s.",
                file=sys.stderr,
            )
            for line in ui_tee.tail():
                sys.stderr.write(line)
            shutdown([daemon, ui])
            return 1

        launch_browser(effective_port, no_browser=args.no_browser)

        try:
            signal.signal(signal.SIGINT, _make_sigint_handler([daemon, ui]))
        except (ValueError, OSError):
            pass
        if hasattr(signal, "SIGTERM"):
            try:
                signal.signal(signal.SIGTERM, _make_sigint_handler([daemon, ui]))
            except (ValueError, OSError):
                pass

        return supervise(daemon, ui, daemon_tee, ui_tee)
    except KeyboardInterrupt:
        if daemon is not None or ui is not None:
            shutdown([p for p in (daemon, ui) if p is not None])
        return 0
    finally:
        if tmp_config is not None:
            try:
                os.unlink(tmp_config)
            except OSError:
                pass
        _cleanup_demo_dir(demo_dir)


if __name__ == "__main__":
    sys.exit(main())
