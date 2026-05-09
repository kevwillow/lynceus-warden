"""Tests for lynceus.cli.quickstart — the dev/demo launcher."""

from __future__ import annotations

import io
import os
import signal
import socket
import subprocess
from unittest.mock import MagicMock
from urllib.error import URLError

import pytest
import yaml

from lynceus import paths
from lynceus.cli import quickstart


@pytest.fixture
def cfg_file(tmp_path):
    p = tmp_path / "lynceus.yaml"
    p.write_text(yaml.safe_dump({"db_path": str(tmp_path / "t.db"), "ui_bind_port": 8765}))
    return p


# ---- Pre-flight: root check ---------------------------------------------------


def test_root_check_refuses_when_euid_zero(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 0, raising=False)
    err = quickstart.check_not_root()
    assert err is not None
    assert "should not run as root" in err
    assert "install.sh" in err


def test_root_check_skipped_when_geteuid_absent(monkeypatch):
    # Simulate Windows: os.geteuid simply does not exist on win32.
    monkeypatch.delattr(os, "geteuid", raising=False)
    assert quickstart.check_not_root() is None


# ---- Pre-flight: systemd check ------------------------------------------------


def test_systemd_check_refuses_when_lynceus_service_active(monkeypatch):
    def fake_run(cmd, **kw):
        active = "lynceus.service" in cmd and "--user" in cmd
        return MagicMock(stdout="active\n" if active else "inactive\n")

    monkeypatch.setattr(quickstart.subprocess, "run", fake_run)
    monkeypatch.setattr(quickstart.os, "name", "posix")
    err = quickstart.check_no_systemd()
    assert err is not None
    assert "already running under systemd" in err


def test_systemd_check_refuses_when_lynceus_ui_service_active(monkeypatch):
    def fake_run(cmd, **kw):
        return MagicMock(stdout="active\n" if "lynceus-ui.service" in cmd else "inactive\n")

    monkeypatch.setattr(quickstart.subprocess, "run", fake_run)
    monkeypatch.setattr(quickstart.os, "name", "posix")
    err = quickstart.check_no_systemd()
    assert err is not None
    assert "already running under systemd" in err


def test_systemd_check_probes_both_units_under_both_scopes(monkeypatch):
    """The check must look at both ``lynceus.service`` and
    ``lynceus-ui.service`` under both ``--user`` and system scope so that
    quickstart never collides with a partial production deployment."""
    seen: list[list[str]] = []

    def fake_run(cmd, **kw):
        seen.append(list(cmd))
        return MagicMock(stdout="inactive\n")

    monkeypatch.setattr(quickstart.subprocess, "run", fake_run)
    monkeypatch.setattr(quickstart.os, "name", "posix")
    assert quickstart.check_no_systemd() is None

    flat = [tuple(c) for c in seen]
    assert any("--user" in c and "lynceus.service" in c for c in flat)
    assert any("--user" in c and "lynceus-ui.service" in c for c in flat)
    assert any("--user" not in c and "lynceus.service" in c for c in flat)
    assert any("--user" not in c and "lynceus-ui.service" in c for c in flat)
    # Importantly, the legacy "lynceus-daemon.service" name is no longer probed.
    assert not any("lynceus-daemon.service" in c for c in flat)


def test_systemd_check_passes_when_all_inactive(monkeypatch):
    monkeypatch.setattr(
        quickstart.subprocess,
        "run",
        lambda cmd, **kw: MagicMock(stdout="inactive\n"),
    )
    monkeypatch.setattr(quickstart.os, "name", "posix")
    assert quickstart.check_no_systemd() is None


def test_systemd_check_skipped_on_windows(monkeypatch):
    called = []

    def fake_run(cmd, **kw):
        called.append(cmd)
        return MagicMock(stdout="active\n")

    monkeypatch.setattr(quickstart.subprocess, "run", fake_run)
    monkeypatch.setattr(quickstart.os, "name", "nt")
    assert quickstart.check_no_systemd() is None
    assert called == [], "subprocess.run must not be invoked on Windows"


# ---- Pre-flight: config + port ------------------------------------------------


def test_config_check_refuses_missing(tmp_path):
    err = quickstart.check_config_exists(str(tmp_path / "nope.yaml"))
    assert err is not None
    assert "Config file not found" in err
    assert "lynceus-setup" in err


def test_port_check_refuses_when_occupied():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    s.listen(1)
    try:
        port = s.getsockname()[1]
        err = quickstart.check_port_free(port)
        assert err is not None
        assert f"Port {port} is already in use" in err
        assert "--port-ui" in err
    finally:
        s.close()


# ---- Banner -------------------------------------------------------------------


def test_banner_contains_dev_demo_and_systemd():
    buf = io.StringIO()
    quickstart.print_banner(8765, file=buf)
    out = buf.getvalue()
    assert "DEV/DEMO" in out
    assert "systemd" in out


# ---- Subprocess startup -------------------------------------------------------


def test_start_daemon_invokes_popen_with_config(monkeypatch):
    captured = {}

    def fake_popen(args, **kwargs):
        captured["args"] = args
        return MagicMock()

    monkeypatch.setattr(quickstart.subprocess, "Popen", fake_popen)
    quickstart.start_daemon("/path/to/cfg.yaml")
    assert captured["args"][-2:] == ["--config", "/path/to/cfg.yaml"]


def test_start_ui_invokes_popen_with_config(monkeypatch):
    captured = {}

    def fake_popen(args, **kwargs):
        captured["args"] = args
        return MagicMock()

    monkeypatch.setattr(quickstart.subprocess, "Popen", fake_popen)
    quickstart.start_ui("/path/to/cfg.yaml")
    assert captured["args"][-2:] == ["--config", "/path/to/cfg.yaml"]


# ---- Health check -------------------------------------------------------------


def test_wait_for_ui_ready_returns_true_on_200(monkeypatch):
    class FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def getcode(self):
            return 200

    monkeypatch.setattr(quickstart, "_urlopen_get", lambda url, timeout: FakeResp())
    assert quickstart.wait_for_ui_ready(8765, timeout=2.0) is True


def test_wait_for_ui_ready_returns_false_on_timeout(monkeypatch):
    def always_fail(url, timeout):
        raise URLError("nope")

    monkeypatch.setattr(quickstart, "_urlopen_get", always_fail)
    monkeypatch.setattr(quickstart.time, "sleep", lambda s: None)
    assert quickstart.wait_for_ui_ready(8765, timeout=0.05) is False


# ---- Browser launch -----------------------------------------------------------


def test_launch_browser_calls_open_with_url(monkeypatch):
    captured = []
    monkeypatch.setattr(quickstart.webbrowser, "open", lambda url: captured.append(url) or True)
    quickstart.launch_browser(8765, no_browser=False)
    assert captured == ["http://127.0.0.1:8765"]


def test_launch_browser_skipped_with_no_browser_flag(monkeypatch):
    captured = []
    monkeypatch.setattr(quickstart.webbrowser, "open", lambda url: captured.append(url) or True)
    quickstart.launch_browser(8765, no_browser=True)
    assert captured == []


def test_launch_browser_prints_fallback_when_open_returns_false(monkeypatch):
    monkeypatch.setattr(quickstart.webbrowser, "open", lambda url: False)
    buf = io.StringIO()
    quickstart.launch_browser(8765, no_browser=False, file=buf)
    out = buf.getvalue()
    assert "No browser available" in out
    assert "http://127.0.0.1:8765" in out


# ---- Shutdown ----------------------------------------------------------------


def test_shutdown_sends_sigterm_and_returns_cleanly():
    proc = MagicMock()
    proc.poll.return_value = None  # alive when shutdown checks
    proc.wait.return_value = 0  # exits before grace expires
    quickstart.shutdown([proc], grace=0.1)
    proc.terminate.assert_called_once()
    proc.kill.assert_not_called()


def test_shutdown_kills_processes_that_dont_exit():
    proc = MagicMock()
    proc.poll.return_value = None
    # First wait raises TimeoutExpired, second wait (after kill) returns 0.
    proc.wait.side_effect = [
        subprocess.TimeoutExpired(cmd="x", timeout=0.1),
        0,
    ]
    quickstart.shutdown([proc], grace=0.05)
    proc.terminate.assert_called_once()
    proc.kill.assert_called_once()


def test_sigint_handler_triggers_shutdown_on_both(monkeypatch):
    captured = []

    def fake_shutdown(procs, grace=quickstart.SHUTDOWN_GRACE_SECONDS):
        captured.append(list(procs))

    monkeypatch.setattr(quickstart, "shutdown", fake_shutdown)
    daemon = MagicMock()
    ui = MagicMock()
    handler = quickstart._make_sigint_handler([daemon, ui])
    with pytest.raises(SystemExit) as exc_info:
        handler(signal.SIGINT, None)
    assert exc_info.value.code == 0
    assert captured == [[daemon, ui]]


# ---- Crash survival ----------------------------------------------------------


def test_supervise_returns_1_when_daemon_dies(monkeypatch):
    # Avoid real shutdown during test.
    shutdown_calls = []
    monkeypatch.setattr(
        quickstart,
        "shutdown",
        lambda procs, grace=quickstart.SHUTDOWN_GRACE_SECONDS: shutdown_calls.append(list(procs)),
    )
    monkeypatch.setattr(quickstart.time, "sleep", lambda s: None)

    daemon = MagicMock()
    daemon.poll = MagicMock(side_effect=[None, 1])
    daemon.returncode = 1
    ui = MagicMock()
    ui.poll = MagicMock(return_value=None)
    daemon_tee = MagicMock()
    daemon_tee.tail = MagicMock(return_value=["err1\n", "err2\n"])
    ui_tee = MagicMock()
    ui_tee.tail = MagicMock(return_value=[])

    rc = quickstart.supervise(daemon, ui, daemon_tee, ui_tee, poll_interval=0.0)
    assert rc == 1
    # Survivor (ui) was shut down.
    assert shutdown_calls == [[ui]]


# ---- G3 regression: --config defaulting via paths.resolve_existing_config ---
#
# rc1 hardcoded ``DEFAULT_CONFIG_PATH = "/etc/lynceus/lynceus.yaml"``. Operators
# who ran ``lynceus-setup --user`` got their config in
# ``~/.config/lynceus/lynceus.yaml`` and then ``lynceus-quickstart`` errored
# with "Config file not found at /etc/lynceus/lynceus.yaml" — the wizard wrote
# it elsewhere and quickstart never looked there. The pre-fix tests called
# ``main`` with explicit ``--config`` paths and never exercised the default.


@pytest.fixture
def _stub_config_paths(monkeypatch, tmp_path):
    """Redirect ``paths.default_config_path`` to ``tmp_path``-relative files
    so tests can pre-create user/system configs without touching real
    ``~/.config`` or ``/etc/lynceus``."""
    user_path = tmp_path / "user" / "lynceus.yaml"
    system_path = tmp_path / "system" / "lynceus.yaml"

    def fake_default_config_path(scope):
        if scope == "user":
            return user_path
        if scope == "system":
            return system_path
        raise ValueError(scope)

    monkeypatch.setattr(paths, "default_config_path", fake_default_config_path)
    return user_path, system_path


def test_main_finds_user_config_when_only_user_exists(monkeypatch, tmp_path, _stub_config_paths):
    """G3 regression: this is the test that would have caught the rc1 bug.

    Only the user-mode config exists; quickstart with no ``--config`` must
    discover it via ``paths.resolve_existing_config()``. Pre-fix this
    errored out because quickstart looked only at
    ``/etc/lynceus/lynceus.yaml``.
    """
    user_path, _ = _stub_config_paths
    user_path.parent.mkdir(parents=True)
    user_path.write_text(yaml.safe_dump({"ui_bind_port": 8765}))

    started_with: list[str] = []

    def fake_start_daemon(cfg):
        started_with.append(("daemon", cfg))
        proc = MagicMock()
        proc.poll = MagicMock(return_value=None)
        return proc

    def fake_start_ui(cfg):
        started_with.append(("ui", cfg))
        proc = MagicMock()
        proc.poll = MagicMock(return_value=None)
        return proc

    # Mock everything heavy so we exercise only the path-resolution code.
    monkeypatch.setattr(quickstart, "check_not_root", lambda: None)
    monkeypatch.setattr(quickstart, "check_no_systemd", lambda: None)
    monkeypatch.setattr(quickstart, "check_port_free", lambda port, host="127.0.0.1": None)
    monkeypatch.setattr(quickstart, "start_daemon", fake_start_daemon)
    monkeypatch.setattr(quickstart, "start_ui", fake_start_ui)
    monkeypatch.setattr(quickstart, "TeeSupervisor", lambda *a, **k: MagicMock(tail=lambda: []))
    monkeypatch.setattr(quickstart, "wait_for_ui_ready", lambda port, timeout=10.0: True)
    monkeypatch.setattr(quickstart, "launch_browser", lambda *a, **k: None)
    monkeypatch.setattr(quickstart.time, "sleep", lambda s: None)

    sentinel: list[int] = []

    def fake_supervise(*a, **k):
        sentinel.append(1)
        return 0

    monkeypatch.setattr(quickstart, "supervise", fake_supervise)
    monkeypatch.setattr(quickstart.signal, "signal", lambda *a, **k: None)

    rc = quickstart.main([])
    assert rc == 0
    assert sentinel == [1], "supervise was not reached — earlier preflight failed"
    assert ("daemon", str(user_path)) in started_with


def test_main_finds_system_config_when_only_system_exists(
    monkeypatch, tmp_path, _stub_config_paths
):
    _, system_path = _stub_config_paths
    system_path.parent.mkdir(parents=True)
    system_path.write_text(yaml.safe_dump({"ui_bind_port": 8765}))

    monkeypatch.setattr(quickstart, "check_not_root", lambda: None)
    monkeypatch.setattr(quickstart, "check_no_systemd", lambda: None)
    monkeypatch.setattr(quickstart, "check_port_free", lambda port, host="127.0.0.1": None)

    daemon_calls: list[str] = []

    def fake_start_daemon(cfg):
        daemon_calls.append(cfg)
        proc = MagicMock()
        proc.poll = MagicMock(return_value=None)
        return proc

    monkeypatch.setattr(quickstart, "start_daemon", fake_start_daemon)
    monkeypatch.setattr(quickstart, "start_ui", lambda cfg: MagicMock(poll=lambda: None))
    monkeypatch.setattr(quickstart, "TeeSupervisor", lambda *a, **k: MagicMock(tail=lambda: []))
    monkeypatch.setattr(quickstart, "wait_for_ui_ready", lambda port, timeout=10.0: True)
    monkeypatch.setattr(quickstart, "launch_browser", lambda *a, **k: None)
    monkeypatch.setattr(quickstart, "supervise", lambda *a, **k: 0)
    monkeypatch.setattr(quickstart.signal, "signal", lambda *a, **k: None)
    monkeypatch.setattr(quickstart.time, "sleep", lambda s: None)

    rc = quickstart.main([])
    assert rc == 0
    assert daemon_calls == [str(system_path)]


def test_main_prefers_user_config_when_both_exist(monkeypatch, tmp_path, _stub_config_paths):
    user_path, system_path = _stub_config_paths
    user_path.parent.mkdir(parents=True)
    system_path.parent.mkdir(parents=True)
    user_path.write_text(yaml.safe_dump({"ui_bind_port": 8765}))
    system_path.write_text(yaml.safe_dump({"ui_bind_port": 8766}))

    monkeypatch.setattr(quickstart, "check_not_root", lambda: None)
    monkeypatch.setattr(quickstart, "check_no_systemd", lambda: None)
    monkeypatch.setattr(quickstart, "check_port_free", lambda port, host="127.0.0.1": None)

    daemon_calls: list[str] = []

    def fake_start_daemon(cfg):
        daemon_calls.append(cfg)
        proc = MagicMock()
        proc.poll = MagicMock(return_value=None)
        return proc

    monkeypatch.setattr(quickstart, "start_daemon", fake_start_daemon)
    monkeypatch.setattr(quickstart, "start_ui", lambda cfg: MagicMock(poll=lambda: None))
    monkeypatch.setattr(quickstart, "TeeSupervisor", lambda *a, **k: MagicMock(tail=lambda: []))
    monkeypatch.setattr(quickstart, "wait_for_ui_ready", lambda port, timeout=10.0: True)
    monkeypatch.setattr(quickstart, "launch_browser", lambda *a, **k: None)
    monkeypatch.setattr(quickstart, "supervise", lambda *a, **k: 0)
    monkeypatch.setattr(quickstart.signal, "signal", lambda *a, **k: None)
    monkeypatch.setattr(quickstart.time, "sleep", lambda s: None)

    rc = quickstart.main([])
    assert rc == 0
    assert daemon_calls == [str(user_path)]


def test_main_errors_with_both_paths_when_neither_exists(monkeypatch, capsys, _stub_config_paths):
    user_path, system_path = _stub_config_paths
    # Neither path is created — both are absent.
    monkeypatch.setattr(quickstart, "check_not_root", lambda: None)
    monkeypatch.setattr(quickstart, "check_no_systemd", lambda: None)

    rc = quickstart.main([])
    err = capsys.readouterr().err
    assert rc == 2
    assert str(user_path) in err
    assert str(system_path) in err
    assert "lynceus-setup" in err


def test_help_shows_resolved_path_not_static(monkeypatch, capsys, _stub_config_paths):
    """S3 fix bundled with G3: ``--help`` should display the actually-resolved
    default path, not a hardcoded ``/etc/lynceus/lynceus.yaml`` literal."""
    user_path, _ = _stub_config_paths
    user_path.parent.mkdir(parents=True)
    user_path.write_text("ui_bind_port: 8765\n")

    # Force a wide terminal so argparse doesn't wrap the help text and split
    # the path across lines — we're testing content, not formatting.
    monkeypatch.setenv("COLUMNS", "500")

    with pytest.raises(SystemExit):
        quickstart.main(["--help"])
    out = capsys.readouterr().out
    assert str(user_path) in out
    assert "/etc/lynceus/lynceus.yaml" not in out


def test_help_shows_none_found_sentinel_when_no_config(monkeypatch, capsys, _stub_config_paths):
    """When neither config exists, --help must not advertise a static path
    that does not exist."""
    monkeypatch.setenv("COLUMNS", "500")
    with pytest.raises(SystemExit):
        quickstart.main(["--help"])
    out = capsys.readouterr().out
    assert "/etc/lynceus/lynceus.yaml" not in out
