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
ways this file can quietly stop being a gate: the module stops importing, the
marker stops selecting it, the marker stops DEselecting it, the script it drives
stops offering the API the gate calls, and the hermeticity guard ends up pointed
at the sandbox instead of the operator.

⚠️ ``--collect-only`` imports a module and stops. The audit script is loaded
inside the test body, so collection alone would not notice it breaking. That is
why the contract test below imports it for real.

⛔ **Do not write a count of them here.** An earlier version of this paragraph
said "four" and was wrong within the hour, which is the exact rot it is warning
about. ⇒ [[date-every-number-you-publish]]
"""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import os
import pwd
import re
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


#: The operator's environment as it was BEFORE ``conftest`` redirected it.
#:
#: ⛔ Captured at module import, which pytest does during collection, before any
#: fixture body runs. The autouse ``_isolate_user_config_dirs`` overwrites these
#: for every test, so by the time a test executes the real values are gone and
#: cannot be recovered. There is exactly one moment to read them and this is it.
_REAL_ENV = {key: os.environ.get(key) for key in ("HOME", "XDG_CONFIG_HOME", "SUDO_USER")}


def _operator_config_dirs() -> list[Path]:
    """Every directory a real ``lynceus`` config could be sitting in.

    A single path is not enough, and a path derived from ``$HOME`` at test time
    is worse than useless. Three things have to be covered:

    - ``conftest`` monkeypatches ``HOME`` for every test, so ``Path.home()``
      during a test is a per-test sandbox. A guard built on it compares an empty
      temporary directory against itself and passes no matter what the run did.
      ⇒ [[a-guard-that-matches-one-rendering]]
    - ``XDG_CONFIG_HOME`` moves the config root somewhere that is not
      ``~/.config`` at all, so the passwd home alone can watch the wrong place.
    - Under ``sudo``, the passwd home is root's and the operator's is not.

    So watch the union: the account's home from ``pwd``, the pre-fixture ``HOME``,
    the pre-fixture ``XDG_CONFIG_HOME``, and the invoking user's home when
    ``SUDO_USER`` says there is one. Duplicates collapse.
    """
    roots: set[Path] = set()

    account_home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    roots.add(account_home / ".config" / "lynceus")

    if _REAL_ENV["HOME"]:
        roots.add(Path(_REAL_ENV["HOME"]) / ".config" / "lynceus")
    if _REAL_ENV["XDG_CONFIG_HOME"]:
        roots.add(Path(_REAL_ENV["XDG_CONFIG_HOME"]) / "lynceus")
    if _REAL_ENV["SUDO_USER"]:
        try:
            roots.add(Path(pwd.getpwnam(_REAL_ENV["SUDO_USER"]).pw_dir) / ".config" / "lynceus")
        except KeyError:
            pass

    return sorted(roots)


def record_gate_ran(name: str) -> None:
    """Append proof that a gate BODY executed, if the caller asked for it.

    ⛔ This is what makes `make release-gates` honest. pytest exits 0 for a run
    that collected and executed nothing, and no exit code distinguishes that
    from a real pass. Measured 2026-08-22: `PYTEST_ADDOPTS=--collect-only make
    release-gates` printed "1/4626 tests collected" and exited 0.

    Only writes when ``LYNCEUS_GATE_SENTINEL`` names a path, so a plain
    `pytest -m release_gate` stays side-effect free. Every host-only gate must
    call this, including the browser one.
    """
    target = os.environ.get("LYNCEUS_GATE_SENTINEL")
    if not target:
        return
    with open(target, "a", encoding="utf-8") as fh:
        fh.write(f"{name}\n")


def _declared_console_scripts() -> list[str]:
    """Every name under ``[project.scripts]``, read from the shipped pyproject."""
    with (REPO_ROOT / "pyproject.toml").open("rb") as fh:
        return sorted(tomllib.load(fh)["project"]["scripts"])


def _snapshot(directory: Path) -> dict[str, tuple] | None:
    """Recursive fingerprint of a directory, or None if it is absent.

    ⛔ None rather than ``{}``. An absent directory and an empty one have to be
    distinguishable, or the guard cannot see a run that CREATED the operator's
    config directory and left it empty: both snapshots would be ``{}`` and the
    equality would hold. On a clean machine absent is the normal case, so that is
    precisely where the hole would be.

    ⛔ Recursive, and it records **mode and a content digest**, not just size and
    mtime. Size plus mtime misses a `chmod`, misses anything below a
    subdirectory whose own stat did not change, and misses a same-length rewrite
    with the mtime put back. The digest costs nothing here: a lynceus config
    directory holds a handful of small YAML files.

    ⚠️ What it still cannot see: ownership and ACL changes, damage anywhere else
    in the home, and anything created and removed between the two calls. The
    claim this supports is "the run did not change these config trees", never
    "the run touched nothing".
    """
    if not directory.is_dir():
        return None

    out: dict[str, tuple] = {}
    for path in sorted(directory.rglob("*")):
        rel = str(path.relative_to(directory))
        stat = path.lstat()
        if path.is_symlink():
            out[rel] = ("link", stat.st_mode, os.readlink(path))
        elif path.is_dir():
            out[rel] = ("dir", stat.st_mode)
        else:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            out[rel] = ("file", stat.st_mode, stat.st_size, digest)
    return out


@pytest.mark.release_gate
def test_fresh_install_path_works():
    """Wheel to clean venv to wizard to validate to a UI serving /healthz.json.

    The script returns its evidence rather than only an exit code, because an
    exit code of 0 cannot tell a working install apart from a run that quietly
    did nothing. Every assertion below is on something the run OBSERVED.
    """
    record_gate_ran("test_fresh_install_path_works")
    script = _load_audit_script("repro_fresh_install")

    roots = _operator_config_dirs()
    assert roots, "derived no operator config directories; the guard below would be vacuous"
    before = {root: _snapshot(root) for root in roots}
    result = script.run_fresh_install()
    after = {root: _snapshot(root) for root in roots}

    # The hermeticity claim first, because it is the one that damages a person
    # rather than a build. The suite has written into a real ~/.config/lynceus
    # before, and it went unnoticed for the worst reason: on a clean home the
    # write SUCCEEDS. This runs the shipped wizard as a subprocess, which is the
    # single most likely thing in the suite to do it again.
    #
    # ⚠️ If this fails, rule out an innocent writer before believing the gate did
    # it. The run takes ~20s, and an editor, a sync tool or a live lynceus daemon
    # touching the same tree in that window looks identical from here.
    changed = [root for root in roots if before[root] != after[root]]
    assert not changed, (
        f"the run changed {len(changed)} of {len(roots)} operator config trees. "
        + "; ".join(f"{root}: {before[root]} -> {after[root]}" for root in changed)
    )

    assert result.code == 0, f"fresh install failed with code {result.code}: {result.failure}"

    # It has to have tested THIS tree. The shared .venv pins the primary
    # checkout's src absolutely, so a harness run from a worktree can silently
    # grade a different checkout, and this repo has had that happen.
    # ⇒ [[verify-which-tree-you-are-actually-testing]]
    assert result.repo == REPO_ROOT, f"the gate built {result.repo}, not {REPO_ROOT}"

    # And it has to have done it somewhere that is not an operator config tree.
    assert result.sandbox_home is not None
    sandbox = Path(result.sandbox_home).resolve()
    for root in roots:
        assert root not in sandbox.parents and root != sandbox, (
            f"the sandbox {sandbox} was inside the operator tree {root}"
        )

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

    # ⛔ Anchored, not a substring. `"0 errors" in summary` is satisfied by
    # "10 errors", which is the exact shape of the failure it is meant to catch.
    assert result.validate_summary is not None
    assert re.search(r"(?<!\d)0 errors\b", result.validate_summary), result.validate_summary

    # ⛔ The PARSED status, not a substring of the body. `'"status"' in body`
    # accepts {"status":"unhealthy"}, accepts malformed JSON containing the
    # token, and accepts an unrelated server that won the port.
    assert result.healthz_status == 200
    assert result.healthz_status_field == "ok", (
        f"/healthz.json reported {result.healthz_status_field!r}: {result.healthz_body}"
    )

    # A UI that answers 200 having created no database is serving a shell, and a
    # non-empty file at the right path is not a database. A failed migration
    # leaves a valid SQLite file with no tables in it.
    assert result.db_bytes > 0, "the UI served but created no database"
    assert result.db_tables > 0, (
        f"the database is {result.db_bytes} bytes with {result.db_tables} tables"
    )

    # ⛔ The bundled threat-data import, checked by its EFFECT. The wizard prints
    # "Bundled threat-data import failed ... you can retry later" and then EXITS
    # 0, so its return code is silent about the one step that makes a fresh
    # install useful. Counting rows survives any rewording of that message, and
    # it is the assertion that fails if the import times out under load.
    assert result.watchlist_rows > 0, (
        f"the wizard finished with {result.watchlist_rows} watchlist rows. The bundled "
        f"threat-data import did not land, and the wizard exits 0 when that happens."
    )

    # ⛔ The run must have been driving the venv it built, not whatever lynceus
    # happened to be on the caller's PATH. This is the assertion that would have
    # caught the gate quietly skipping the bundled watchlist import for a day:
    # `lynceus-import-argus` was unreachable, the wizard took its
    # FileNotFoundError branch, and the gate still said the install worked.
    assert result.sandbox_path, "the run recorded no PATH; it cannot have been sandboxed"
    entries = result.sandbox_path.split(os.pathsep)
    assert entries[0].endswith("/bin"), entries[0]
    for entry in entries[1:]:
        candidate = Path(entry)
        if not candidate.is_dir():
            continue
        rival = sorted(p.name for p in candidate.iterdir() if p.name.startswith("lynceus"))
        assert not rival, f"{entry} on the gate's PATH still offers {rival}"


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


def test_record_gate_ran_is_a_real_signal(tmp_path, monkeypatch):
    """`make release-gates` believes this file, so it has to mean something.

    The take-effect pair. A ``record_gate_ran`` that always wrote would make the
    Makefile's check pass for a run that executed nothing, and one that never
    wrote would make the target fail for a run that worked. Neither half alone
    proves it; a fixed answer cannot satisfy both.

    ⇒ Measured 2026-08-22: `PYTEST_ADDOPTS=--collect-only make release-gates`
    exited 0 having printed "1/4626 tests collected" and run no test body. The
    Makefile clears `PYTEST_ADDOPTS` and then asserts this file is non-empty,
    because pytest's exit code cannot tell that run from a real pass.
    """
    sentinel = tmp_path / "ran"

    # Unset: silent, so a plain `pytest -m release_gate` has no side effects.
    monkeypatch.delenv("LYNCEUS_GATE_SENTINEL", raising=False)
    record_gate_ran("some_gate")
    assert not sentinel.exists()

    # Set: the name of every gate that executed, appended.
    monkeypatch.setenv("LYNCEUS_GATE_SENTINEL", str(sentinel))
    record_gate_ran("first_gate")
    record_gate_ran("second_gate")
    assert sentinel.read_text().split() == ["first_gate", "second_gate"]

    # ⛔ The write must FOLLOW the variable, because the Makefile sets it to a
    # path of its own choosing and then reads that exact file. A version writing
    # to a fixed location would leave the Makefile's file absent and the target
    # would fail every time, which is loud, but this pins the contract anyway.
    moved = tmp_path / "elsewhere"
    monkeypatch.setenv("LYNCEUS_GATE_SENTINEL", str(moved))
    record_gate_ran("third_gate")
    assert moved.read_text().split() == ["third_gate"]
    assert sentinel.read_text().split() == ["first_gate", "second_gate"], (
        "writing to the new path must not also touch the old one"
    )


def test_every_release_gate_records_that_it_ran():
    """A gate that forgets the sentinel makes the Makefile's check a lie.

    Derived from the marked tests rather than from a list, so a gate added later
    is covered without anyone remembering this exists. That includes the browser
    gate when it lands.
    """
    names = _release_gate_test_names()
    assert names, "no test in this module carries the release_gate marker"

    source = Path(__file__).read_text()
    tree = ast.parse(source)
    for name in names:
        fn = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == name
        )
        calls = {
            node.func.id
            for node in ast.walk(fn)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        assert "record_gate_ran" in calls, (
            f"{name} is a release_gate but never calls record_gate_ran(), so "
            f"`make release-gates` cannot tell whether its body executed."
        )


def test_gate_waits_longer_than_the_wizard_waits_on_itself():
    """The harness must not give up before the thing it is driving does.

    ``lynceus-setup`` runs the bundled watchlist import as a subprocess and
    waits up to ``BUNDLED_IMPORT_TIMEOUT_SECONDS`` for it. If the gate's own
    timeout is the smaller of the two, a wedged import gets reported as "the
    wizard did not complete" and the reader goes looking at the prompt sequence
    for a failure that has nothing to do with it. Let the wizard's own bound
    fire and print its own diagnosis.

    Both numbers are read from the code, so raising either one turns this red
    in CI rather than quietly inverting the order.
    ⇒ [[find-the-threshold-before-inventing-one]]
    """
    from lynceus.setup.core import BUNDLED_IMPORT_TIMEOUT_SECONDS

    script = _load_audit_script("repro_fresh_install")
    assert script.WIZARD_TIMEOUT_SECONDS > BUNDLED_IMPORT_TIMEOUT_SECONDS, (
        f"the gate gives the wizard {script.WIZARD_TIMEOUT_SECONDS}s but the wizard "
        f"gives its own import {BUNDLED_IMPORT_TIMEOUT_SECONDS}s. The harness would "
        f"time out first and misattribute the failure."
    )


def test_sandbox_path_removes_every_other_lynceus(tmp_path):
    """`sandbox_path()` must put the new venv first and drop rival installs.

    The take-effect pair. A function that returned only the venv's bin would
    pass a "no other lynceus" check and break every child process that needs
    `PATH`, so this proves both halves: the rival is gone AND the innocent
    entry survives.
    """
    script = _load_audit_script("repro_fresh_install")

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


def test_operators_config_dir_escapes_the_home_fixture():
    """The hermeticity guard must look at the real account, not the sandbox.

    ``test_fresh_install_path_works`` asserts the operator's ``~/.config/lynceus``
    is untouched. That assertion is worth nothing if the path it checks is the
    per-test HOME ``conftest`` just created, because then it compares an empty
    temporary directory against itself and passes no matter what the run did.
    This is the guard on that guard, and it runs in stock CI.
    """
    sandbox = Path(os.environ["HOME"]).resolve()
    roots = _operator_config_dirs()
    assert roots, "no operator config directories derived at all"

    for root in roots:
        real = root.resolve()
        assert real != (sandbox / ".config" / "lynceus").resolve()
        assert sandbox not in real.parents, (
            f"_operator_config_dirs() produced {real}, which is inside the test "
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
        grown = _snapshot(directory)
        assert grown != created, "an edited file must change the snapshot"

        # The three the old size-and-mtime version could not see.
        stat = (directory / "rules.yaml").stat()
        (directory / "rules.yaml").write_text("cc")
        os.utime(directory / "rules.yaml", ns=(stat.st_atime_ns, stat.st_mtime_ns))
        assert _snapshot(directory) != grown, (
            "a same-length rewrite with the mtime put back must still be visible"
        )

        rewritten = _snapshot(directory)
        (directory / "rules.yaml").chmod(0o600)
        assert _snapshot(directory) != rewritten, "a mode change must be visible"

        moded = _snapshot(directory)
        nested = directory / "conf.d"
        nested.mkdir()
        (nested / "extra.yaml").write_text("x")
        assert _snapshot(directory) != moded, "a file below a subdirectory must be visible"


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
    """Run pytest's collector in a subprocess over the WHOLE test tree.

    ``--collect-only`` imports the modules and stops, so this costs imports and
    proves the gates are still reachable without paying for a wheel build.

    ⛔ The whole tree, not this file. Scoped to one file, these guards would say
    nothing about a ``release_gate`` test added anywhere else, and the browser
    gate is landing in ``tests/test_browser_ui.py``. A guard that only protects
    the file it lives in is the narrowest possible reading of its own job.

    ⛔ `PYTEST_ADDOPTS` is cleared for the same reason the release target clears
    it: ambient options can turn any pytest run into something that collects or
    executes nothing, and these guards would then be measuring that instead.
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
    collected = _node_ids(result)
    assert collected, f"`-m release_gate` collected nothing across tests/:\n{result.stdout}"
    for name in names:
        assert any(node.endswith(f"::{name}") for node in collected), (
            f"{name} carries the release_gate marker but `-m release_gate` did not "
            f"collect it:\n{result.stdout}"
        )


def test_release_gates_are_deselected_by_default():
    """The default suite must not pick these up.

    The other direction of the same guard. Without it, a change to ``addopts``
    could start a wheel build inside every CI leg, and the first sign would be
    a job that takes minutes longer for no stated reason.
    """
    marked = _node_ids(_collect("-m", "release_gate"))
    assert marked, "`-m release_gate` collected nothing; this guard would be vacuous"

    default = _collect()
    assert default.returncode == 0, default.stdout + default.stderr
    default_ids = _node_ids(default)

    # And the guard is not passing because collection found nothing at all.
    assert any(
        node.endswith("::test_release_gates_are_deselected_by_default") for node in default_ids
    ), default.stdout

    leaked = sorted(marked & default_ids)
    assert not leaked, (
        f"{len(leaked)} release_gate tests are in the DEFAULT collection: {leaked}. "
        f"Check the -m expression in [tool.pytest.ini_options] addopts."
    )
