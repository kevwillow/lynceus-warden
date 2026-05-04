"""Wheel-install regression: ensure migrations ship as package data."""

import shutil
import sqlite3
import subprocess
import sys
import venv
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.slow
def test_wheel_install_finds_migrations(tmp_path):
    """Build a wheel, install it into a fresh venv, run a Database() init, assert tables exist."""
    if shutil.which("python") is None:
        pytest.skip("python not on PATH")
    try:
        import build  # noqa: F401
    except ImportError:
        pytest.skip("build module not installed; run `pip install build` to enable")

    dist_dir = tmp_path / "dist"
    result = subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(dist_dir), str(REPO_ROOT)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, f"build failed:\n{result.stderr}"

    wheels = list(dist_dir.glob("talos-*.whl"))
    assert len(wheels) == 1, f"expected one wheel, got {wheels}"

    venv_dir = tmp_path / "venv"
    venv.create(venv_dir, with_pip=True)
    if sys.platform == "win32":
        venv_python = venv_dir / "Scripts" / "python.exe"
    else:
        venv_python = venv_dir / "bin" / "python"

    install = subprocess.run(
        [str(venv_python), "-m", "pip", "install", str(wheels[0])],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert install.returncode == 0, f"pip install failed:\n{install.stderr}"

    db_path = tmp_path / "wheel-test.db"
    driver = (
        "from talos.db import Database; "
        f"db = Database(r'{db_path}'); db.close()"
    )
    drive = subprocess.run(
        [str(venv_python), "-c", driver],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert drive.returncode == 0, f"Database() init failed in wheel venv:\n{drive.stderr}"
    assert db_path.exists()

    con = sqlite3.connect(db_path)
    try:
        tables = {
            row[0]
            for row in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    finally:
        con.close()
    for required in {
        "devices",
        "sightings",
        "alerts",
        "watchlist",
        "locations",
        "poller_state",
        "schema_migrations",
    }:
        assert required in tables, f"missing {required} after wheel install"
