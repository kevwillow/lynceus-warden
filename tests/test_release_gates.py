"""Guards that the host-only gates have not quietly stopped being gates.

Two gates need a real machine rather than a CI runner, so `addopts` deselects
both and neither ever runs in Actions:

    tests/test_fresh_install.py   `install`   needs a capture interface
    tests/test_browser_ui.py      `browser`   needs Chromium and playwright

⛔ **A deselected test rots and nothing notices.** It cannot fail, so an import
error, a renamed API in the script it drives, or a marker expression that stops
selecting it are all invisible until somebody runs the gate by hand, which is
months later and usually the day of a release.

Everything in this file is UNMARKED and therefore DOES run in stock CI. Nothing
here executes a gate. Between them these cover the ways a gate stops being one:

  - its module stops importing
  - the marker stops SELECTING it, so `pytest -m install` runs nothing
  - the marker stops DESELECTING it, so a wheel build lands in every CI leg
  - the script it drives stops offering the API the gate calls
  - the hermeticity guard ends up pointed at the sandbox rather than the operator
  - a gate stops recording that it ran, so `make release-gates` cannot tell a
    real pass from a run that executed nothing

⚠️ ``--collect-only`` imports a module and stops. A gate's helper script is
loaded inside the test body, so collection alone would not notice it breaking.
That is why the contract test below imports it for real.

⛔ **Do not write a count of these here.** An earlier version of this paragraph
said "four" and was wrong within the hour, which is the exact rot it warns about.
"""

from __future__ import annotations

import ast
import importlib.util
import os
import subprocess
import sys
from pathlib import Path

from tests.conftest import HOST_ONLY_MARKERS, record_gate_ran

REPO_ROOT = Path(__file__).resolve().parents[1]


def _collect(*args: str) -> subprocess.CompletedProcess:
    """Run pytest's collector in a subprocess over the WHOLE test tree.

    ``--collect-only`` imports the modules and stops, so this costs imports and
    proves the gates are still reachable without paying for a wheel build or a
    browser.

    ⛔ The whole tree, never one file. Scoped to a single file these guards would
    say nothing about a gate added anywhere else, which is how the two existing
    gates ended up in two different files in the first place.

    ⛔ `PYTEST_ADDOPTS` is cleared for the same reason the release target clears
    it: ambient options can turn any pytest run into one that collects or
    executes nothing, and these guards would then be measuring that.
    """
    env = dict(os.environ, PYTHONPATH=str(REPO_ROOT / "src"))
    env.pop("PYTEST_ADDOPTS", None)
    return subprocess.run(
        [
            sys.executable, "-m", "pytest", "--collect-only", "-q",
            "-p", "no:cacheprovider", "-p", "no:randomly", *args,
        ],
        cwd=REPO_ROOT, capture_output=True, text=True, env=env, timeout=600,
    )


def _node_ids(result: subprocess.CompletedProcess) -> set[str]:
    """Every ``path::test`` line in a ``--collect-only -q`` result."""
    return {line.strip() for line in result.stdout.splitlines() if "::" in line}


def _marker_expression() -> str:
    """`(install or browser)`, built from the shared set rather than typed out."""
    return "(" + " or ".join(sorted(HOST_ONLY_MARKERS)) + ")"


def test_every_host_only_marker_is_registered():
    """`--strict-markers` only catches markers that are USED, never the expression.

    A marker dropped from ``pyproject.toml`` while a test still carries it is
    caught by pytest itself. The dangerous direction is the other one: a marker
    that stays registered but falls out of the ``-m`` expression in ``addopts``.
    Nothing in pytest checks that, which is why the two tests after this exist.
    """
    import tomllib

    with (REPO_ROOT / "pyproject.toml").open("rb") as fh:
        config = tomllib.load(fh)["tool"]["pytest"]["ini_options"]

    registered = {entry.split(":", 1)[0] for entry in config["markers"]}
    missing = sorted(HOST_ONLY_MARKERS - registered)
    assert not missing, f"{missing} are treated as host-only but not registered as markers"


def test_host_only_gates_are_still_collectible():
    """`pytest -m "install or browser"` must find gates.

    This is the whole reason the unmarked tests exist. A deselected test that
    stopped importing would never fail anywhere, so the suite would go on
    reporting green while the release gates quietly became unrunnable.
    """
    result = _collect("-m", _marker_expression())
    assert result.returncode == 0, result.stdout + result.stderr

    collected = _node_ids(result)
    assert collected, (
        f"`-m {_marker_expression()}` collected nothing across tests/. Either both "
        f"gates were deleted or the markers stopped being applied:\n{result.stdout}"
    )

    # Every marker must contribute at least one gate. Without this, `browser`
    # could vanish entirely and the union above would still be non-empty.
    for marker in sorted(HOST_ONLY_MARKERS):
        per_marker = _node_ids(_collect("-m", marker))
        assert per_marker, f"no test anywhere carries the `{marker}` marker any more"


def test_host_only_gates_are_deselected_by_default():
    """The default suite and CI must not pick these up.

    The other direction of the same guard. Without it a change to ``addopts``
    could start a wheel build, or a Chromium launch, inside every CI leg, and the
    first sign would be a job that takes minutes longer for no stated reason.
    """
    marked = _node_ids(_collect("-m", _marker_expression()))
    assert marked, "collected no host-only gates; this guard would be vacuous"

    default = _collect()
    assert default.returncode == 0, default.stdout + default.stderr
    default_ids = _node_ids(default)

    # And the guard is not passing because collection found nothing at all.
    assert any(
        node.endswith("::test_host_only_gates_are_deselected_by_default")
        for node in default_ids
    ), default.stdout

    leaked = sorted(marked & default_ids)
    assert not leaked, (
        f"{len(leaked)} host-only gates are in the DEFAULT collection: {leaked}. "
        f"Check the -m expression in [tool.pytest.ini_options] addopts."
    )


def test_fresh_install_script_still_offers_what_the_gate_calls():
    """Import the audit script for real and check the surface the gate uses.

    This is the rot the collection check cannot see. The script lives outside
    ``tests/`` and outside the package, nothing else imports it, and the one test
    that does is deselected by default. Renaming a field on ``FreshInstall``
    would break the gate and turn up in no run anywhere.

    Importing it is cheap: the module defines a dataclass and some functions and
    does no work at import time.
    """
    path = REPO_ROOT / "scripts" / "audit" / "repro_fresh_install.py"
    assert path.is_file(), f"{path} is missing; the install gate has no script to drive"
    spec = importlib.util.spec_from_file_location("_contract_repro_fresh_install", path)
    script = importlib.util.module_from_spec(spec)
    sys.modules["_contract_repro_fresh_install"] = script
    spec.loader.exec_module(script)

    assert callable(script.run_fresh_install)
    assert callable(script.main)
    assert callable(script.sandbox_path)
    assert script.ANSWERS, "the wizard answers are empty; the gate cannot drive setup"

    reads = _attributes_the_gate_reads()
    assert reads, "derived no attributes from the gate; this check would be vacuous"
    evidence = script.FreshInstall()
    missing = [name for name in reads if not hasattr(evidence, name)]
    assert not missing, (
        f"the gate reads {missing} off FreshInstall and the script no longer has them"
    )


def _attributes_the_gate_reads() -> list[str]:
    """Every ``result.<name>`` the install gate touches, read out of its source.

    Listing them by hand would make this agree with a list rather than with the
    test, so a new assertion added to the gate would go uncovered. Reading the
    AST means the contract check grows whenever the gate does.
    """
    source = (REPO_ROOT / "tests" / "test_fresh_install.py").read_text()
    gate = next(
        node
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.FunctionDef)
        and node.name == "test_a_new_user_gets_a_working_system"
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


def test_the_hermeticity_guard_escapes_the_home_fixture():
    """The install gate's real-home guard must look at the account, not the sandbox.

    ``test_a_new_user_gets_a_working_system`` asserts the operator's config trees
    are untouched. That assertion is worth nothing if the paths it checks are the
    per-test HOME ``conftest`` just created, because then it compares empty
    temporary directories against themselves and passes no matter what the run
    did. This is the guard on that guard, and it runs in stock CI.
    """
    from tests.test_fresh_install import operator_config_dirs

    sandbox = Path(os.environ["HOME"]).resolve()
    roots = operator_config_dirs()
    assert roots, "no operator config directories derived at all"

    for root in roots:
        real = root.resolve()
        assert real != (sandbox / ".config" / "lynceus").resolve()
        assert sandbox not in real.parents, (
            f"operator_config_dirs() produced {real}, which is inside the test sandbox "
            f"{sandbox}. The hermeticity assertion would be vacuous."
        )


def test_the_hermeticity_snapshot_detects_a_change(tmp_path):
    """`snapshot` must actually discriminate.

    The hermeticity assertion is ``after == before``. If ``snapshot`` returned
    something constant, that comparison would hold across any amount of damage.
    Planting the change here is cheaper and safer than planting it in the gate,
    where proving the point means letting a wizard loose on a real home.
    """
    from tests.test_fresh_install import snapshot

    directory = tmp_path / "lynceus"
    assert snapshot(directory) is None, "a missing directory must be distinguishable"

    directory.mkdir()
    empty = snapshot(directory)
    assert empty == {}
    assert empty != snapshot(tmp_path / "never-created")

    (directory / "rules.yaml").write_text("a")
    created = snapshot(directory)
    assert created != empty, "a new file must change the snapshot"

    (directory / "rules.yaml").write_text("bb")
    grown = snapshot(directory)
    assert grown != created, "an edited file must change the snapshot"

    # The three a size-and-mtime snapshot could not see.
    stat = (directory / "rules.yaml").stat()
    (directory / "rules.yaml").write_text("cc")
    os.utime(directory / "rules.yaml", ns=(stat.st_atime_ns, stat.st_mtime_ns))
    rewritten = snapshot(directory)
    assert rewritten != grown, "a same-length rewrite with the mtime put back must be visible"

    (directory / "rules.yaml").chmod(0o600)
    moded = snapshot(directory)
    assert moded != rewritten, "a mode change must be visible"

    nested = directory / "conf.d"
    nested.mkdir()
    (nested / "extra.yaml").write_text("x")
    assert snapshot(directory) != moded, "a file below a subdirectory must be visible"


def test_sandbox_path_removes_every_other_lynceus(tmp_path):
    """`sandbox_path()` must put the new venv first and drop rival installs.

    The take-effect pair. A function returning only the venv's bin would pass a
    "no other lynceus" check and break every child process that needs `PATH`, so
    this proves both halves. No single fixed answer satisfies both.

    ⛔ Measured 2026-08-22: the wizard shells out to `lynceus-import-argus` BY
    NAME. With a lynceus venv on the ambient `PATH` it resolved out of the
    developer's venv, and with none it was unresolvable and the bundled
    threat-data import was skipped entirely while the gate reported success.
    """
    path = REPO_ROOT / "scripts" / "audit" / "repro_fresh_install.py"
    spec = importlib.util.spec_from_file_location("_pathcheck_repro_fresh_install", path)
    script = importlib.util.module_from_spec(spec)
    sys.modules["_pathcheck_repro_fresh_install"] = script
    spec.loader.exec_module(script)

    rival = tmp_path / "other-venv" / "bin"
    rival.mkdir(parents=True)
    (rival / "lynceus-import-argus").write_text("#!/bin/sh\n")
    innocent = tmp_path / "ordinary" / "bin"
    innocent.mkdir(parents=True)
    (innocent / "grep").write_text("#!/bin/sh\n")
    venv_bin = tmp_path / "fresh" / "bin"
    venv_bin.mkdir(parents=True)

    original = os.environ.get("PATH", "")
    os.environ["PATH"] = os.pathsep.join([str(rival), str(innocent)])
    try:
        result = script.sandbox_path(venv_bin).split(os.pathsep)
    finally:
        os.environ["PATH"] = original

    assert result[0] == str(venv_bin), "the fresh venv must win the lookup"
    assert str(rival) not in result, "the rival lynceus install is still reachable"
    assert str(innocent) in result, "an unrelated PATH entry must survive"


def test_the_gate_waits_longer_than_the_wizard_waits_on_itself():
    """The harness must not give up before the thing it is driving does.

    ``lynceus-setup`` runs the bundled watchlist import as a subprocess and waits
    up to ``BUNDLED_IMPORT_TIMEOUT_SECONDS`` for it. If the gate's own timeout is
    the smaller of the two, a wedged import gets reported as "the wizard did not
    complete" and the reader goes looking at the prompt sequence for a failure
    that has nothing to do with it.

    Both numbers are read from the code, so raising either one turns this red in
    CI rather than quietly inverting the order.
    """
    from lynceus.setup.core import BUNDLED_IMPORT_TIMEOUT_SECONDS

    path = REPO_ROOT / "scripts" / "audit" / "repro_fresh_install.py"
    spec = importlib.util.spec_from_file_location("_timeout_repro_fresh_install", path)
    script = importlib.util.module_from_spec(spec)
    sys.modules["_timeout_repro_fresh_install"] = script
    spec.loader.exec_module(script)

    assert script.WIZARD_TIMEOUT_SECONDS > BUNDLED_IMPORT_TIMEOUT_SECONDS, (
        f"the gate gives the wizard {script.WIZARD_TIMEOUT_SECONDS}s but the wizard gives "
        f"its own import {BUNDLED_IMPORT_TIMEOUT_SECONDS}s. The harness would time out "
        f"first and misattribute the failure."
    )


def test_record_gate_ran_is_a_real_signal(tmp_path, monkeypatch):
    """`make release-gates` believes the sentinel, so it has to mean something.

    The take-effect pair. A ``record_gate_ran`` that always wrote would make the
    Makefile's check pass for a run that executed nothing, and one that never
    wrote would make the target fail for a run that worked.

    ⇒ Measured 2026-08-22: `PYTEST_ADDOPTS=--collect-only make release-gates`
    exited 0 having printed "1/4626 tests collected" and run no test body. The
    Makefile clears `PYTEST_ADDOPTS` and then asserts this file is non-empty,
    because pytest's exit code cannot tell that run from a real pass.
    """
    sentinel = tmp_path / "ran"

    monkeypatch.delenv("LYNCEUS_GATE_SENTINEL", raising=False)
    record_gate_ran("some_gate")
    assert not sentinel.exists()

    monkeypatch.setenv("LYNCEUS_GATE_SENTINEL", str(sentinel))
    record_gate_ran("first_gate")
    record_gate_ran("second_gate")
    assert sentinel.read_text().split() == ["first_gate", "second_gate"]

    # ⛔ The write must FOLLOW the variable, because the Makefile sets it to a
    # path of its own choosing and then reads that exact file.
    moved = tmp_path / "elsewhere"
    monkeypatch.setenv("LYNCEUS_GATE_SENTINEL", str(moved))
    record_gate_ran("third_gate")
    assert moved.read_text().split() == ["third_gate"]
    assert sentinel.read_text().split() == ["first_gate", "second_gate"], (
        "writing to the new path must not also touch the old one"
    )


def test_the_sentinel_fixture_records_a_marked_test_and_ignores_the_rest(tmp_path):
    """The autouse fixture must fire for host-only gates and for nothing else.

    ⭐ Proven by running pytest for real on a throwaway file, because the fixture
    is what `make release-gates` depends on and asserting the helper alone would
    leave the wiring untested. The generated tests are trivial, so this costs an
    interpreter start rather than a wheel build.
    """
    marker = sorted(HOST_ONLY_MARKERS)[0]
    sentinel = tmp_path / "ran"
    module = tmp_path / "test_generated_gate.py"
    module.write_text(
        "import pytest\n"
        f"@pytest.mark.{marker}\n"
        "def test_marked():\n"
        "    pass\n"
        "def test_unmarked():\n"
        "    pass\n"
    )
    # The fixture lives in tests/conftest.py, so the throwaway file has to be
    # collected under it. Point rootdir at the repo and hand pytest the path.
    target = REPO_ROOT / "tests" / module.name
    target.write_text(module.read_text())
    try:
        env = dict(
            os.environ,
            PYTHONPATH=str(REPO_ROOT / "src"),
            LYNCEUS_GATE_SENTINEL=str(sentinel),
        )
        env.pop("PYTEST_ADDOPTS", None)
        result = subprocess.run(
            [
                sys.executable, "-m", "pytest", "-q",
                "-p", "no:cacheprovider", "-p", "no:randomly",
                f"tests/{module.name}", "-m", marker,
            ],
            cwd=REPO_ROOT, capture_output=True, text=True, env=env, timeout=300,
        )
    finally:
        target.unlink(missing_ok=True)

    assert result.returncode == 0, result.stdout + result.stderr
    recorded = sentinel.read_text().split() if sentinel.exists() else []
    assert any("test_marked" in line for line in recorded), (
        f"the fixture did not record a `{marker}` test that ran: {recorded}\n{result.stdout}"
    )
    assert not any("test_unmarked" in line for line in recorded), (
        f"the fixture recorded an unmarked test: {recorded}"
    )
