"""Tests for the top-level install.sh shipped with the v0.3 release.

Linux-only — install.sh is opinionated about systemd integration and
refuses to run on macOS or Windows. Operators on those platforms use
``pip install -e .`` from a clone instead.

These tests exercise install.sh through ``--dry-run`` to avoid touching
the real system. The dry run must:

  * still complete pre-flight (Python / pip / systemctl detection),
  * print every command it would have executed,
  * NOT invoke pip, useradd, systemctl, or chown.

When the dry run is exercised under ``--user`` we point ``$HOME`` at a
``tmp_path`` sandbox so the directory-creation step lands somewhere
disposable instead of the test runner's real home.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
INSTALL_SH = REPO_ROOT / "install.sh"
SYSTEMD_DIR = REPO_ROOT / "systemd"

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="install.sh is Linux-only; skipping installer tests on non-Linux platforms.",
)


def _run(args, *, env_extra=None, cwd=None, check=False, timeout=30):
    """Invoke install.sh via bash with the given args. Returns CompletedProcess."""
    bash = shutil.which("bash")
    if bash is None:  # pragma: no cover - bash is required everywhere we'd run
        pytest.skip("bash not on PATH")
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    cmd = [bash, str(INSTALL_SH), *args]
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env=env,
        cwd=str(cwd) if cwd is not None else None,
        check=check,
        timeout=timeout,
    )


# ---- presence + syntax ----------------------------------------------------


def test_install_sh_exists_and_is_executable():
    assert INSTALL_SH.exists(), f"missing installer at {INSTALL_SH}"
    mode = INSTALL_SH.stat().st_mode
    assert mode & 0o111, "install.sh must be executable"


def test_install_sh_passes_bash_syntax_check():
    bash = shutil.which("bash")
    if bash is None:  # pragma: no cover
        pytest.skip("bash not on PATH")
    r = subprocess.run(
        [bash, "-n", str(INSTALL_SH)],
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert r.returncode == 0, f"bash -n failed:\nstderr:\n{r.stderr}"


# ---- --help ---------------------------------------------------------------


def test_install_sh_help_exits_zero_with_usage():
    r = _run(["--help"])
    assert r.returncode == 0, f"stderr:\n{r.stderr}"
    out = r.stdout + r.stderr
    assert "Usage" in out or "usage" in out
    # Modes must be discoverable from --help.
    assert "--user" in out
    assert "--system" in out


# ---- non-Linux refusal ----------------------------------------------------


def test_install_sh_refuses_on_non_linux_uname(tmp_path):
    """A stub ``uname`` earlier on PATH simulates running on macOS. install.sh
    must detect this and exit non-zero with a clear "Linux only" message."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_uname = fake_bin / "uname"
    fake_uname.write_text("#!/usr/bin/env bash\necho Darwin\n")
    fake_uname.chmod(0o755)

    env_path = f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}"
    r = _run(["--user", "--dry-run"], env_extra={"PATH": env_path})
    assert r.returncode != 0
    combined = r.stdout + r.stderr
    assert "Linux only" in combined or "Linux-only" in combined


# ---- --system without root -----------------------------------------------


def test_install_sh_system_without_root_refuses():
    """Tests run as a regular user. ``--system`` must reject with a clear
    ``Use sudo`` hint instead of attempting the install."""
    if os.geteuid() == 0:
        pytest.skip("test runner is root; cannot exercise the non-root rejection path")
    r = _run(["--system", "--dry-run"])
    assert r.returncode != 0
    combined = r.stdout + r.stderr
    assert "sudo" in combined.lower()


# ---- --user dry-run -------------------------------------------------------


def test_install_sh_user_dry_run_prints_pip_command(tmp_path):
    """``--user --dry-run`` must report the pip install it *would* have run
    and must not actually invoke pip."""
    sandbox_home = tmp_path / "home"
    sandbox_home.mkdir()
    # Strip VIRTUAL_ENV so the dry-run reflects the --user code path, not
    # the venv branch that elides "--user" from pip.
    env = {"HOME": str(sandbox_home)}
    if "VIRTUAL_ENV" in os.environ:
        env["VIRTUAL_ENV"] = ""
    r = _run(["--user", "--dry-run"], env_extra=env)
    assert r.returncode == 0, f"stderr:\n{r.stderr}\nstdout:\n{r.stdout}"
    out = r.stdout + r.stderr
    # The dry-run should reveal both the pip command and the directory plan.
    assert "pip install" in out
    assert "--user" in out or "VIRTUAL_ENV" in out
    # Standard XDG-style targets should be referenced for the user scope.
    assert ".config/lynceus" in out
    assert ".local/share/lynceus" in out


def test_install_sh_user_dry_run_does_not_invoke_pip(tmp_path):
    """A stub pip on PATH that touches a tripwire file proves dry-run did
    NOT actually call pip."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    tripwire = tmp_path / "pip-was-called"
    fake_pip = fake_bin / "pip"
    fake_pip.write_text(f'#!/usr/bin/env bash\necho "fake-pip invoked" > {tripwire}\nexit 0\n')
    fake_pip.chmod(0o755)

    sandbox_home = tmp_path / "home"
    sandbox_home.mkdir()
    env_path = f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}"
    env = {"HOME": str(sandbox_home), "PATH": env_path}
    if "VIRTUAL_ENV" in os.environ:
        env["VIRTUAL_ENV"] = ""
    r = _run(["--user", "--dry-run"], env_extra=env)
    assert r.returncode == 0, f"stderr:\n{r.stderr}\nstdout:\n{r.stdout}"
    assert not tripwire.exists(), "dry-run must not invoke pip"


# ---- systemd unit files ---------------------------------------------------


@pytest.mark.parametrize("unit_name", ["lynceus.service", "lynceus-ui.service"])
def test_systemd_unit_has_required_sections(unit_name):
    unit_path = SYSTEMD_DIR / unit_name
    assert unit_path.exists(), f"missing unit file: {unit_path}"
    content = unit_path.read_text()
    for section in ("[Unit]", "[Service]", "[Install]"):
        assert section in content, f"{unit_name} missing {section}"


def test_systemd_unit_lynceus_execstart_invokes_lynceus_with_config():
    content = (SYSTEMD_DIR / "lynceus.service").read_text()
    assert "ExecStart=" in content
    # Daemon reads the DB path from the config file; ExecStart should not
    # bolt on a --db flag that lynceus does not accept.
    assert "/usr/local/bin/lynceus" in content
    assert "--config /etc/lynceus/lynceus.yaml" in content


def test_systemd_unit_lynceus_ui_execstart_invokes_lynceus_ui():
    content = (SYSTEMD_DIR / "lynceus-ui.service").read_text()
    assert "/usr/local/bin/lynceus-ui" in content
    assert "--config /etc/lynceus/lynceus.yaml" in content


def test_systemd_units_run_as_lynceus_user():
    for name in ("lynceus.service", "lynceus-ui.service"):
        content = (SYSTEMD_DIR / name).read_text()
        assert "User=lynceus" in content, f"{name} must run as lynceus user"
        assert "Group=lynceus" in content, f"{name} must run in lynceus group"


def test_systemd_units_have_hardening_directives():
    """Spot-check that the units pick up the hardening the prompt
    enumerated, so a future careless edit cannot quietly drop them."""
    for name in ("lynceus.service", "lynceus-ui.service"):
        content = (SYSTEMD_DIR / name).read_text()
        assert "NoNewPrivileges=true" in content, f"{name} missing NoNewPrivileges"
        assert "ProtectSystem=strict" in content, f"{name} missing ProtectSystem"
        assert "ProtectHome=true" in content, f"{name} missing ProtectHome"
        assert "PrivateTmp=true" in content, f"{name} missing PrivateTmp"
        # ReadWritePaths must include both the data and log directories or
        # the daemon cannot persist anything under ProtectSystem=strict.
        assert "/var/lib/lynceus" in content
        assert "/var/log/lynceus" in content


def test_systemd_unit_lynceus_ui_orders_after_daemon():
    content = (SYSTEMD_DIR / "lynceus-ui.service").read_text()
    # Look at the [Unit] section to make sure the UI starts after the daemon.
    unit_block = content.split("[Service]", 1)[0]
    assert "lynceus.service" in unit_block, (
        "lynceus-ui must declare After=/Wants= on lynceus.service in [Unit]"
    )
