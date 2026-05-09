"""Tests for the top-level install.sh shipped with the v0.3 release.

Linux-only — install.sh is opinionated about systemd integration and
refuses to run on macOS or Windows. Operators on those platforms use
``pip install -e .`` from a clone instead.

install.sh installs Lynceus into a dedicated Python venv (PEP 668
compliance: recent Debian/Ubuntu/Kali ship an externally-managed
system Python and reject ``pip install`` against it). The lynceus-*
console scripts are exposed via symlinks from the venv's ``bin/``
into a directory on PATH (``~/.local/bin`` for ``--user``,
``/usr/local/bin`` for ``--system``).

These tests exercise install.sh through ``--dry-run`` to avoid touching
the real system. The dry run must:

  * still complete pre-flight (Python / venv module / systemctl detection),
  * print every command it would have executed (venv creation,
    pip-install-into-venv, symlink commands),
  * NOT invoke pip, python -m venv, useradd, systemctl, ln, or chown.

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

# Tests that need to *run* install.sh under bash use this marker; tests
# that only inspect file contents (grep-based perm assertions, systemd
# unit content checks) do not, so they execute on Windows/macOS too.
_NEEDS_BASH = pytest.mark.skipif(
    sys.platform != "linux",
    reason="install.sh is Linux-only; skipping bash-driven tests on non-Linux platforms.",
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


def test_install_sh_exists():
    """Cross-platform existence check; the executable-bit assertion lives
    on the Linux-only test below since Windows doesn't model that bit."""
    assert INSTALL_SH.exists(), f"missing installer at {INSTALL_SH}"


@_NEEDS_BASH
def test_install_sh_is_executable():
    mode = INSTALL_SH.stat().st_mode
    assert mode & 0o111, "install.sh must be executable"


@_NEEDS_BASH
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


@_NEEDS_BASH
def test_install_sh_help_exits_zero_with_usage():
    r = _run(["--help"])
    assert r.returncode == 0, f"stderr:\n{r.stderr}"
    out = r.stdout + r.stderr
    assert "Usage" in out or "usage" in out
    # Modes must be discoverable from --help.
    assert "--user" in out
    assert "--system" in out


# ---- non-Linux refusal ----------------------------------------------------


@_NEEDS_BASH
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


@_NEEDS_BASH
def test_install_sh_system_without_root_refuses():
    """Tests run as a regular user. A real ``--system`` install must
    reject with a clear ``Use sudo`` hint instead of attempting the
    install. (``--system --dry-run`` is intentionally allowed without
    root so operators can preview the install plan; that path is
    covered separately below.)"""
    if os.geteuid() == 0:
        pytest.skip("test runner is root; cannot exercise the non-root rejection path")
    r = _run(["--system"])
    assert r.returncode != 0
    combined = r.stdout + r.stderr
    assert "sudo" in combined.lower()


# ---- --user dry-run -------------------------------------------------------


@_NEEDS_BASH
def test_install_sh_user_dry_run_prints_venv_and_pip_commands(tmp_path):
    """``--user --dry-run`` must report the venv creation and pip-in-venv
    install it *would* have run, and must not actually invoke either."""
    sandbox_home = tmp_path / "home"
    sandbox_home.mkdir()
    env = {"HOME": str(sandbox_home)}
    if "VIRTUAL_ENV" in os.environ:
        env["VIRTUAL_ENV"] = ""
    r = _run(["--user", "--dry-run"], env_extra=env)
    assert r.returncode == 0, f"stderr:\n{r.stderr}\nstdout:\n{r.stdout}"
    out = r.stdout + r.stderr
    # Dry-run must reveal both the venv creation and a pip-in-venv install.
    assert "python3 -m venv" in out
    assert "pip install" in out
    # PEP 668 compliance: install.sh must NOT bypass the system policy.
    assert "--break-system-packages" not in out
    # User install creates a venv under ~/.local/share/lynceus/.venv.
    assert ".local/share/lynceus/.venv" in out
    # Symlinks for the console scripts go into ~/.local/bin.
    assert ".local/bin" in out
    # Standard XDG-style targets are still referenced for config/data/log.
    assert ".config/lynceus" in out
    assert ".local/share/lynceus" in out


@_NEEDS_BASH
def test_install_sh_user_dry_run_lists_console_script_symlinks(tmp_path):
    """Each entry-point command shipped in pyproject.toml must show up
    in the dry-run plan as a symlink target."""
    sandbox_home = tmp_path / "home"
    sandbox_home.mkdir()
    env = {"HOME": str(sandbox_home)}
    if "VIRTUAL_ENV" in os.environ:
        env["VIRTUAL_ENV"] = ""
    r = _run(["--user", "--dry-run"], env_extra=env)
    assert r.returncode == 0, f"stderr:\n{r.stderr}\nstdout:\n{r.stdout}"
    out = r.stdout + r.stderr
    for script in (
        "lynceus",
        "lynceus-ui",
        "lynceus-quickstart",
        "lynceus-setup",
        "lynceus-seed-watchlist",
        "lynceus-import-argus",
    ):
        assert script in out, f"console script {script!r} missing from dry-run output"


@_NEEDS_BASH
def test_install_sh_user_dry_run_does_not_invoke_pip(tmp_path):
    """A stub pip on PATH that touches a tripwire file proves dry-run did
    NOT actually call pip — neither the (now-irrelevant) system pip, nor
    the venv pip we create."""
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


# ---- --system dry-run -----------------------------------------------------


@_NEEDS_BASH
def test_install_sh_system_dry_run_mentions_venv_path():
    """``--system --dry-run`` (no root needed for preview) must reference
    the dedicated /opt/lynceus/.venv path and a pip-in-venv install."""
    if shutil.which("systemctl") is None:
        pytest.skip("systemctl not on PATH; --system pre-flight would fail")
    r = _run(["--system", "--dry-run"])
    assert r.returncode == 0, f"stderr:\n{r.stderr}\nstdout:\n{r.stdout}"
    out = r.stdout + r.stderr
    assert "/opt/lynceus/.venv" in out
    assert "python3 -m venv" in out
    assert "pip install" in out
    assert "--break-system-packages" not in out
    # Symlinks land in /usr/local/bin under --system.
    assert "/usr/local/bin" in out
    # Ownership is set to the lynceus system user.
    assert "chown" in out
    assert "lynceus:lynceus" in out


# ---- --uninstall dry-run --------------------------------------------------


@_NEEDS_BASH
def test_install_sh_uninstall_dry_run_lists_symlinks_and_venv():
    """``--uninstall --dry-run`` must list both the venv that would be
    removed and the console-script symlinks that would be unlinked."""
    if shutil.which("systemctl") is None:
        pytest.skip("systemctl not on PATH; --uninstall pre-flight would fail")
    r = _run(["--uninstall", "--dry-run"])
    assert r.returncode == 0, f"stderr:\n{r.stderr}\nstdout:\n{r.stdout}"
    out = r.stdout + r.stderr
    assert "/opt/lynceus/.venv" in out
    assert "/usr/local/bin" in out
    # Each console script must show up so the operator can audit the plan.
    for script in (
        "lynceus-ui",
        "lynceus-quickstart",
        "lynceus-setup",
        "lynceus-seed-watchlist",
        "lynceus-import-argus",
    ):
        assert script in out, f"console script {script!r} missing from uninstall dry-run"


# ---- python3-venv module missing -----------------------------------------


@_NEEDS_BASH
def test_install_sh_aborts_when_python3_venv_unavailable(tmp_path):
    """Some minimal Debian/Ubuntu images ship python3 without the venv
    module. install.sh must detect this in pre-flight and exit with a
    pointer to ``apt install python3-venv`` rather than crashing midway
    through the install."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    fake_python3 = fake_bin / "python3"
    fake_python3.write_text(
        "#!/usr/bin/env bash\n"
        "# Stub python3: passes through to the real interpreter for everything\n"
        "# except 'python3 -m venv ...', which exits non-zero to simulate a\n"
        "# system that's missing the python3-venv apt package.\n"
        'if [[ "${1:-}" == "-m" && "${2:-}" == "venv" ]]; then\n'
        "    echo 'Error: No module named venv' >&2\n"
        "    exit 1\n"
        "fi\n"
        "for cand in /usr/bin/python3 /usr/local/bin/python3 /bin/python3; do\n"
        '    if [[ -x "$cand" ]]; then exec "$cand" "$@"; fi\n'
        "done\n"
        "echo 'no real python3 available for stub passthrough' >&2\n"
        "exit 127\n"
    )
    fake_python3.chmod(0o755)

    sandbox_home = tmp_path / "home"
    sandbox_home.mkdir()
    env_path = f"{fake_bin}{os.pathsep}{os.environ.get('PATH', '')}"
    env = {"HOME": str(sandbox_home), "PATH": env_path}
    if "VIRTUAL_ENV" in os.environ:
        env["VIRTUAL_ENV"] = ""
    r = _run(["--user", "--dry-run"], env_extra=env)
    assert r.returncode != 0, f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    combined = r.stdout + r.stderr
    assert "python3-venv" in combined
    assert "apt install python3-venv" in combined


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
    # ExecStart points at the venv binary directly so the daemon does
    # not depend on whatever happens to be on the systemd PATH and so a
    # PEP-668-managed system Python is irrelevant at runtime.
    assert "/opt/lynceus/.venv/bin/lynceus" in content
    assert "--config /etc/lynceus/lynceus.yaml" in content


def test_systemd_unit_lynceus_ui_execstart_invokes_lynceus_ui():
    content = (SYSTEMD_DIR / "lynceus-ui.service").read_text()
    assert "/opt/lynceus/.venv/bin/lynceus-ui" in content
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


# ---- S5 regression: /etc/lynceus directory ownership ----------------------
#
# rc1's install.sh created /etc/lynceus root:root 0755 and only chowned
# /var/lib/lynceus and /var/log/lynceus to lynceus:lynceus. The lynceus
# group could enter /etc/lynceus through the world-execute bit, but a
# defence-in-depth posture (or future tightening) requires that the
# directory itself grant traversal explicitly to the daemon's group.
# The fix grants ``root:lynceus 0750``: file-level perms (0640) on
# lynceus.yaml are then sufficient because the daemon can traverse
# /etc/lynceus on the strength of being in the lynceus group, and
# nothing else on the box can (mode 0750 = no other-traverse).
#
# These tests are grep-based on install.sh content, so they don't need
# bash and run on every platform.


def test_install_sh_grants_lynceus_group_traversal_on_etc_lynceus():
    """The install.sh /etc/lynceus mkdir must be followed by an explicit
    ``chown root:lynceus`` and ``chmod 0750`` so the daemon can traverse
    the directory to reach lynceus.yaml. Without this S5 fix, file-level
    perms on the config don't matter — the daemon is denied at the
    directory boundary."""
    content = INSTALL_SH.read_text()
    assert "chown root:lynceus /etc/lynceus" in content, (
        "missing chown root:lynceus on /etc/lynceus — file-level perms "
        "on lynceus.yaml are useless without dir-level traversal grant"
    )
    assert "chmod 0750 /etc/lynceus" in content, (
        "missing chmod 0750 on /etc/lynceus — leaves the dir world-traversable"
    )


def test_install_sh_etc_lynceus_chown_lives_inside_install_system():
    """The /etc/lynceus chown must live inside install_system(), not
    install_user() or uninstall_system() — otherwise --user installs
    would try to chown a directory that doesn't apply, and --uninstall
    would re-chown a directory we may be about to remove."""
    content = INSTALL_SH.read_text()
    install_system_block = content.split("install_system()", 1)[1].split("uninstall_system()", 1)[0]
    assert "chown root:lynceus /etc/lynceus" in install_system_block, (
        "/etc/lynceus chown must be inside install_system()"
    )
    assert "chmod 0750 /etc/lynceus" in install_system_block, (
        "/etc/lynceus chmod must be inside install_system()"
    )


def test_install_sh_existing_var_chowns_preserved():
    """Defensive: the new /etc/lynceus chown additions must not have
    broken the pre-existing chowns of /var/lib/lynceus and
    /var/log/lynceus. The daemon needs both to write."""
    content = INSTALL_SH.read_text()
    assert "chown -R lynceus:lynceus /var/lib/lynceus /var/log/lynceus" in content, (
        "the original /var/lib + /var/log chown was lost; daemon would "
        "fail with EACCES on first write"
    )


def test_install_sh_etc_lynceus_chown_runs_after_mkdir():
    """The chown lines must come after the mkdir, otherwise we'd be
    chowning a path that doesn't exist yet."""
    content = INSTALL_SH.read_text()
    install_system_block = content.split("install_system()", 1)[1].split("uninstall_system()", 1)[0]
    mkdir_idx = install_system_block.find("mkdir -p /etc/lynceus")
    chown_idx = install_system_block.find("chown root:lynceus /etc/lynceus")
    chmod_idx = install_system_block.find("chmod 0750 /etc/lynceus")
    assert mkdir_idx >= 0, "expected /etc/lynceus mkdir in install_system()"
    assert chown_idx > mkdir_idx, "chown root:lynceus must run AFTER mkdir"
    assert chmod_idx > mkdir_idx, "chmod 0750 must run AFTER mkdir"
