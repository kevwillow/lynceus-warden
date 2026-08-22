"""The gates that prove a release, promoted from a script a human had to remember to run.

Two things were measured green before v1.0.0 and then left as loose scripts:
the fresh-install path (`scripts/audit/repro_fresh_install.py`) and the browser
crawl. A gate nobody runs is not a gate, so they live here now, behind the
``release_gate`` marker.

Run them explicitly::

    pytest -m release_gate

``addopts`` in ``pyproject.toml`` deselects the marker, so the default suite and
CI never touch these. That is deliberate and not laziness: the fresh-install
gate builds a wheel and needs a host with at least one capture interface, and
the browser crawl needs Chromium. A hosted runner has neither.

⛔ **Nothing here skips.** A marker is already an opt-in, so a second escape
hatch inside it would mean ``pytest -m release_gate`` could print all-green
having run nothing, which is the failure this file exists to end. If the host
cannot support a gate, it fails with the transcript of what went wrong.

⭐ The unmarked tests DO run in stock CI. They exist because a deselected test
rots silently and nothing else would ever notice. Between them they cover the
three ways this file can quietly stop being a gate: the module stops importing,
the marker stops selecting it, and the script it drives stops offering the API
the gate calls.

⚠️ ``--collect-only`` imports THIS module and nothing else. The audit script is
loaded inside the test body, so collection alone would not notice it breaking.
That is why the contract test below imports it for real.
"""

from __future__ import annotations

import ast
import importlib.util
import os
import pwd
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

import lynceus

REPO_ROOT = Path(__file__).resolve().parents[1]
AUDIT = REPO_ROOT / "scripts" / "audit"


def _load_audit_script(stem: str):
    """Import a script out of ``scripts/audit/`` by path.

    ``scripts/`` is not a package and is not on ``pythonpath``, so this cannot
    be a plain import. Loading by path also means a rename or a move of the
    shipped script fails here rather than silently leaving the gate untested.
    """
    path = AUDIT / f"{stem}.py"
    assert path.is_file(), f"{path} is missing; the gate has no script to drive"
    name = f"_audit_{stem}"
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    # ⛔ Register BEFORE executing. The script uses `from __future__ import
    # annotations`, so @dataclass resolves its field types lazily through
    # `sys.modules[cls.__module__]`. Skipping this line makes the class body
    # raise AttributeError on None, which reads like a defect in the script.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _operators_config_dir() -> Path:
    """The real ``~/.config/lynceus``, read from the passwd database.

    ⛔ NOT from ``$HOME`` and not from ``Path.home()``. ``conftest`` monkeypatches
    ``HOME`` for every test, so both of those resolve to a per-test sandbox, and
    a guard built on either would be asserting that a temporary directory it
    just created is untouched. ``pwd`` reads the account, which no fixture can
    redirect. ⇒ [[a-guard-that-matches-one-rendering]]
    """
    return Path(pwd.getpwuid(os.getuid()).pw_dir) / ".config" / "lynceus"


def _declared_console_scripts() -> list[str]:
    """Every name under ``[project.scripts]``, read from the shipped pyproject."""
    with (REPO_ROOT / "pyproject.toml").open("rb") as fh:
        return sorted(tomllib.load(fh)["project"]["scripts"])


def _snapshot(directory: Path) -> dict[str, tuple[int, int]] | None:
    """Name to (size, mtime_ns) for everything in a directory, or None if absent.

    ⛔ None rather than ``{}``. An absent directory and an empty one have to be
    distinguishable, or the guard cannot see a run that CREATED the operator's
    config directory and left it empty: both snapshots would be ``{}`` and the
    equality would hold. On a clean machine, absent is the normal case, so that
    is precisely where the hole would be.
    """
    if not directory.is_dir():
        return None
    return {p.name: (p.stat().st_size, p.stat().st_mtime_ns) for p in sorted(directory.iterdir())}


@pytest.mark.release_gate
def test_fresh_install_path_works():
    """Wheel to clean venv to wizard to validate to a UI serving /healthz.json.

    The script returns its evidence rather than only an exit code, because an
    exit code of 0 cannot tell a working install apart from a run that quietly
    did nothing. Every assertion below is on something the run OBSERVED.
    """
    script = _load_audit_script("repro_fresh_install")

    before = _snapshot(_operators_config_dir())
    result = script.run_fresh_install()
    after = _snapshot(_operators_config_dir())

    # The hermeticity claim first, because it is the one that damages a person
    # rather than a build. The suite has written into a real ~/.config/lynceus
    # before, and it went unnoticed for the worst reason: on a clean home the
    # write SUCCEEDS. This runs the shipped wizard as a subprocess, which is the
    # single most likely thing in the suite to do it again.
    assert after == before, (
        f"the run modified the operator's real config dir "
        f"{_operators_config_dir()}: {before} -> {after}"
    )

    assert result.code == 0, f"fresh install failed with code {result.code}: {result.failure}"

    # Derived, never transcribed. A version bump must not need an edit here.
    expected_wheel = f"lynceus-{lynceus.__version__}-py3-none-any.whl"
    assert result.wheel == expected_wheel

    # Every entry point the project declares must exist in the venv's bin.
    # Read out of pyproject rather than listed here, so a script added to the
    # project is covered by this gate without anyone remembering to add it.
    # ⇒ [[iterate-the-derived-set-dont-transcribe-it]]
    declared = _declared_console_scripts()
    assert declared, "pyproject declares no [project.scripts]; this assertion would be vacuous"
    missing = sorted(set(declared) - set(result.console_scripts))
    assert not missing, f"the install produced no {missing}; it has {result.console_scripts}"

    # The wizard writing nothing, or writing only some of what it promises, is
    # the defect this gate exists for. `lynceus.yaml` is the file everything
    # else reads; the other two are what the wizard's own summary claims.
    assert "lynceus.yaml" in result.config_files
    assert "allowlist.yaml" in result.config_files
    assert "severity_overrides.yaml" in result.config_files

    assert result.validate_summary is not None
    assert "0 errors" in result.validate_summary, result.validate_summary

    assert result.healthz_status == 200
    assert '"status"' in result.healthz_body, result.healthz_body

    # A UI that answers 200 having created no database is serving a shell.
    assert result.db_bytes > 0, "the UI served but created no database"


def _attributes_the_gate_reads() -> list[str]:
    """Every ``result.<name>`` the gate test touches, read out of its own source.

    Listing them by hand would make this agree with a list rather than with the
    test, so a new assertion added to the gate would go uncovered. Reading the
    AST means the contract check grows whenever the gate does.
    ⇒ [[iterate-the-derived-set-dont-transcribe-it]]
    """
    tree = ast.parse(Path(__file__).read_text())
    gate = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "test_fresh_install_path_works"
    )
    return sorted(
        {
            node.attr
            for node in ast.walk(gate)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "result"
        }
    )


def test_fresh_install_script_still_offers_what_the_gate_calls():
    """Import the audit script for real and check the surface the gate uses.

    This is the rot the collection check cannot see. The script lives outside
    ``tests/`` and outside the package, nothing else imports it, and the one
    test that does is deselected by default. Renaming a field on ``FreshInstall``
    would break the gate and turn up in no run anywhere.

    Importing it is cheap: the module defines a dataclass and some functions and
    does no work at import time.
    """
    script = _load_audit_script("repro_fresh_install")

    assert callable(script.run_fresh_install)
    assert callable(script.main)
    assert script.ANSWERS, "the wizard answers are empty; the gate cannot drive setup"

    reads = _attributes_the_gate_reads()
    assert reads, "derived no attributes from the gate; this check would be vacuous"
    evidence = script.FreshInstall()
    missing = [name for name in reads if not hasattr(evidence, name)]
    assert not missing, (
        f"the gate reads {missing} off FreshInstall and the script no longer has them"
    )


def test_operators_config_dir_escapes_the_home_fixture():
    """The hermeticity guard must look at the real account, not the sandbox.

    ``test_fresh_install_path_works`` asserts the operator's ``~/.config/lynceus``
    is untouched. That assertion is worth nothing if the path it checks is the
    per-test HOME ``conftest`` just created, because then it compares an empty
    temporary directory against itself and passes no matter what the run did.
    This is the guard on that guard, and it runs in stock CI.
    """
    sandbox = Path(os.environ["HOME"]).resolve()
    real = _operators_config_dir().resolve()

    assert real != sandbox / ".config" / "lynceus"
    assert sandbox not in real.parents, (
        f"_operators_config_dir() resolved to {real}, which is inside the test "
        f"sandbox {sandbox}. The hermeticity assertion would be vacuous."
    )


def test_snapshot_detects_a_change():
    """`_snapshot` must actually discriminate.

    The hermeticity assertion is ``after == before``. If ``_snapshot`` returned
    something constant, that comparison would hold across any amount of damage.
    Planting the change here is cheaper and safer than planting it in the gate,
    where proving the point means letting a wizard loose on a real home.
    """
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        directory = Path(td) / "lynceus"
        assert _snapshot(directory) is None, "a missing directory must be distinguishable"

        directory.mkdir()
        empty = _snapshot(directory)
        assert empty == {}
        # The case the None exists for: creating the directory is itself a change.
        assert empty != _snapshot(directory.parent / "never-created")

        (directory / "rules.yaml").write_text("a")
        created = _snapshot(directory)
        assert created != empty, "a new file must change the snapshot"

        (directory / "rules.yaml").write_text("bb")
        assert _snapshot(directory) != created, "an edited file must change the snapshot"


def _release_gate_test_names() -> list[str]:
    """The marked tests in this module, derived from the module itself.

    Transcribing the names would make the two guards below agree with a list
    rather than with the file, and a gate added later would be silently
    unprotected. ⇒ [[iterate-the-derived-set-dont-transcribe-it]]
    """
    module = sys.modules[__name__]
    return sorted(
        name
        for name, obj in vars(module).items()
        if name.startswith("test_")
        and any(m.name == "release_gate" for m in getattr(obj, "pytestmark", []))
    )


def _collect(*args: str) -> subprocess.CompletedProcess:
    """Run pytest's collector in a subprocess against this file only.

    ``--collect-only`` imports the module and stops, so this costs an import
    and proves the gate is still reachable without paying for a wheel build.
    """
    env = dict(os.environ, PYTHONPATH=str(REPO_ROOT / "src"))
    return subprocess.run(
        [
            sys.executable, "-m", "pytest", "--collect-only", "-q",
            "-p", "no:cacheprovider", "-p", "no:randomly",
            "tests/test_release_gates.py", *args,
        ],
        cwd=REPO_ROOT, capture_output=True, text=True, env=env, timeout=300,
    )


def test_release_gates_are_still_collectible():
    """`pytest -m release_gate` must find every gate in this file.

    This is the whole reason the unmarked tests exist. A deselected test that
    stopped importing would never fail anywhere, so the suite would go on
    reporting green while the release gates quietly became unrunnable.
    """
    names = _release_gate_test_names()
    assert names, "no test in this module carries the release_gate marker"

    result = _collect("-m", "release_gate")
    assert result.returncode == 0, result.stdout + result.stderr
    for name in names:
        assert f"::{name}" in result.stdout, (
            f"{name} carries the release_gate marker but `-m release_gate` did not "
            f"collect it:\n{result.stdout}"
        )


def test_release_gates_are_deselected_by_default():
    """The default suite must not pick these up.

    The other direction of the same guard. Without it, a change to ``addopts``
    could start a wheel build inside every CI leg, and the first sign would be
    a job that takes minutes longer for no stated reason.
    """
    names = _release_gate_test_names()
    assert names, "no test in this module carries the release_gate marker"

    result = _collect()
    assert result.returncode == 0, result.stdout + result.stderr
    for name in names:
        assert f"::{name}" not in result.stdout, (
            f"{name} is marked release_gate but the DEFAULT collection includes it. "
            f"Check the -m expression in [tool.pytest.ini_options] addopts:\n{result.stdout}"
        )
    # And the guard is not passing because collection found nothing at all.
    assert "::test_release_gates_are_deselected_by_default" in result.stdout, result.stdout
