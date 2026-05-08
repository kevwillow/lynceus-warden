"""lynceus-quickstart — dev/demo launcher that starts the daemon + UI.

Foreground-only: Ctrl+C shuts everything down. Production deployment uses
systemd; quickstart is for hacking and demos. The launcher only orchestrates
the existing entry points (lynceus, lynceus-ui) — it does not re-implement
either daemon or UI.
"""

from __future__ import annotations

import argparse
import collections
import logging
import os
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

from .. import __version__

logger = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = "/etc/lynceus/lynceus.yaml"
DEFAULT_UI_PORT = 8765
DAEMON_GRACE_SECONDS = 2.0
UI_HEALTH_TIMEOUT_SECONDS = 10.0
SHUTDOWN_GRACE_SECONDS = 10.0
SUPERVISE_POLL_INTERVAL = 0.5
TAIL_LINES_ON_CRASH = 20

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
    if os.name != "posix":
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


def _popen_kwargs() -> dict:
    """Cross-platform kwargs to isolate subprocesses into their own
    process group (POSIX) or process group (Windows), so a Ctrl+C in
    the parent terminal does not also race the children."""
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def _resolve_entry_point(name: str) -> list[str]:
    """Resolve an installed console-script next to sys.executable; fall back
    to a bare PATH lookup if the script is not co-located (developer setups,
    PEP 660 editable installs on some distros).
    """
    bin_dir = Path(sys.executable).parent
    candidates: list[Path] = []
    if os.name == "nt":
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
    try:
        with open(config_path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except OSError:
        return DEFAULT_UI_PORT
    return int(data.get("ui_bind_port", DEFAULT_UI_PORT))


def _write_port_override_config(config_path: str, port: int) -> str:
    """Write a temp YAML copy of the config with ui_bind_port overridden.
    Returns the temp file path; caller is responsible for cleanup."""
    with open(config_path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    data["ui_bind_port"] = port
    fd, tmp = tempfile.mkstemp(suffix=".yaml", prefix="lynceus-quickstart-")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        yaml.safe_dump(data, f)
    return tmp


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
        "--config",
        default=None,
        help=f"Path to lynceus.yaml (default: {DEFAULT_CONFIG_PATH}).",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"lynceus-quickstart {__version__}",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    config_path = args.config or DEFAULT_CONFIG_PATH

    for err in (
        check_not_root(),
        check_no_systemd(),
        check_config_exists(config_path),
    ):
        if err:
            print(f"error: {err}", file=sys.stderr)
            return 2

    config_port = _read_ui_port_from_config(config_path)
    effective_port = args.port_ui if args.port_ui is not None else config_port

    port_err = check_port_free(effective_port)
    if port_err:
        print(f"error: {port_err}", file=sys.stderr)
        return 2

    ui_config_path = config_path
    tmp_config: str | None = None
    if args.port_ui is not None and args.port_ui != config_port:
        tmp_config = _write_port_override_config(config_path, args.port_ui)
        ui_config_path = tmp_config

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
            for line in daemon_tee.tail():
                sys.stderr.write(line)
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


if __name__ == "__main__":
    sys.exit(main())
