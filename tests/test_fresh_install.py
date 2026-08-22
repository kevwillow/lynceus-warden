"""The path a NEW USER takes, run as a test rather than as a thing to remember.

CI proves the wheel installs and that every console script answers `--help`.
Nothing in `tests/` proved that a person who runs `lynceus-setup` ends up with a
working system, and that is the only path a first-time user ever takes.

`scripts/audit/repro_fresh_install.py` drives the whole of it: build the wheel,
install it into a clean venv with no dev extras, run the wizard with answers on
stdin, validate the config the wizard wrote, start the UI and fetch a route.
Every step runs under a redirected HOME, and it refuses to start if that home
resolves inside the real one.

⛔ **Deselected by default.** It needs a machine with at least one capture
interface, because the wizard enumerates them and the answers pick one by
number. A stock CI runner has none. Run it explicitly:

    pytest -m install

⚠️ The wheel is rebuilt from the tree under test on every run, so a defect
planted in `src/` reaches the installed artifact. That is what makes this a test
of the product rather than a test of the script.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.install

REPO = Path(__file__).resolve().parents[1]
GATE = REPO / "scripts" / "audit" / "repro_fresh_install.py"

#: The script's exit codes are its finding, so they are named here rather than
#: collapsed into "it failed". Each one says which step of the new-user path
#: broke, which is the difference between a bug report and a shrug.
EXIT_MEANING = {
    2: "the wizard completed but the config it wrote does not validate",
    3: "the wizard did not complete, or the wheel did not build or install",
    4: "the UI did not serve",
    124: "the run timed out",
}

#: Long enough for a wheel build, a venv, a pip install, the wizard and the UI.
#: Measured 2026-08-22 on a developer box: 18 seconds end to end.
TIMEOUT_SECONDS = 900


def test_a_new_user_gets_a_working_system():
    assert GATE.is_file(), f"{GATE} is missing, so nothing below measured anything"
    proc = subprocess.run(
        [sys.executable, str(GATE)],
        capture_output=True,
        text=True,
        timeout=TIMEOUT_SECONDS,
        cwd=REPO,
    )
    transcript = (proc.stdout + proc.stderr).strip()

    # ⛔ Fail closed on an empty transcript. A script that produced no output at
    # all did not run the path, whatever it exited with, and asserting only the
    # return code would call that a pass.
    assert transcript, "the gate produced no output, so it did not run"
    assert "[1/5] building the wheel" in transcript, (
        f"the gate did not reach its first step, so its exit code says nothing:\n{transcript}"
    )

    if proc.returncode != 0:
        why = EXIT_MEANING.get(proc.returncode, "it failed in a way it has no code for")
        pytest.fail(
            f"the fresh-install path is broken: {why} (exit {proc.returncode}).\n"
            f"{transcript}"
        )

    # The success line is part of the contract. An exit 0 with a different tail
    # means the script changed shape and this test stopped covering what it says.
    assert "FRESH INSTALL WORKS" in transcript, (
        f"the gate exited 0 without reporting success:\n{transcript}"
    )
