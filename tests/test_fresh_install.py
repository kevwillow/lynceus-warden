"""The path a NEW USER takes, run as a test rather than as a thing to remember.

CI proves the wheel installs and that every console script answers `--help`.
Nothing in `tests/` proved that a person who runs `lynceus-setup` ends up with a
working system, and that is the only path a first-time user ever takes.

`scripts/audit/repro_fresh_install.py` drives the whole of it: build the wheel,
install it into a clean venv with no dev extras, run the wizard with answers on
stdin, validate the config the wizard wrote, start the UI and fetch a route.
Every subprocess runs under a redirected HOME, and it refuses to start if that
home resolves inside the real one.

⛔ **Deselected by default.** It needs a machine with at least one capture
interface, because the wizard enumerates them and the answers pick one by
number. A stock CI runner has none. Run it explicitly::

    pytest -m install

⚠️ The wheel is rebuilt from the tree under test on every run, so a defect
planted in `src/` reaches the installed artifact. That is what makes this a test
of the product rather than a test of the script.

⏱️ **It takes about nine minutes, and that is the correct duration.** An earlier
version of this file recorded "18 seconds end to end". Measured 2026-08-22, those
18 seconds were the gate SKIPPING the bundled threat-data import: the wizard
shells out to `lynceus-import-argus` by name, the harness left the ambient `PATH`
alone, so the binary was unresolvable from the clean venv and
`import_bundled_watchlist` took its `FileNotFoundError` branch. The wizard prints
"Bundled threat-data import failed" and **exits 0**, so nothing noticed. With
`PATH` sandboxed the same run takes 8m40s and lands 23,441 watchlist rows
(measured 2026-08-22). Re-measured 2026-08-24 at `750d2b3`, load ~11:
**3m29s, 23,430 rows, 16 tables, 16.1 MB**. The row count moved because #220
re-cut the bundled signatures AND widened the importer's metacharacter check to
drop identifiers that are still regex-shaped, which is the count becoming
honest rather than data going missing. ⇒ Both figures are dated measurements,
not contracts; the assertion below is `> 0` deliberately.

⇒ **Every assertion below is on evidence the run OBSERVED, never on its exit code
and never on a line it printed.** Exit 0 cannot tell a working install from a run
that quietly did nothing, and the wizard's own exit code is silent about the one
step that makes a fresh install useful.
"""

from __future__ import annotations

import importlib.util
import os
import pwd
import re
import sys
import tomllib
from pathlib import Path

import pytest

import lynceus
from tests.conftest import REAL_ENV

pytestmark = pytest.mark.install

REPO = Path(__file__).resolve().parents[1]
GATE = REPO / "scripts" / "audit" / "repro_fresh_install.py"




def _load_gate():
    """Import the audit script by path.

    ``scripts/`` is not a package and is not on ``pythonpath``, so this cannot be
    a plain import. Loading by path also means a rename or a move of the shipped
    script fails here rather than silently leaving the gate untested.
    """
    assert GATE.is_file(), f"{GATE} is missing, so nothing below measures anything"
    name = "_audit_repro_fresh_install"
    spec = importlib.util.spec_from_file_location(name, GATE)
    module = importlib.util.module_from_spec(spec)
    # ⛔ Register BEFORE executing. The script uses `from __future__ import
    # annotations`, so @dataclass resolves its field types lazily through
    # `sys.modules[cls.__module__]`. Skipping this line makes the class body
    # raise AttributeError on None, which reads like a defect in the script.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def operator_config_dirs() -> list[Path]:
    """Every directory a real ``lynceus`` config could be sitting in.

    A single path is not enough, and a path derived from ``$HOME`` at test time
    is worse than useless. Three things have to be covered:

    - ``conftest`` monkeypatches ``HOME`` for every test, so ``Path.home()``
      during a test is a per-test sandbox. A guard built on it compares an empty
      temporary directory against itself and passes no matter what the run did.
    - ``XDG_CONFIG_HOME`` moves the config root somewhere that is not
      ``~/.config`` at all, so the passwd home alone can watch the wrong place.
    - Under ``sudo``, the passwd home is root's and the operator's is not.

    So watch the union. Duplicates collapse.
    """
    roots: set[Path] = set()
    roots.add(Path(pwd.getpwuid(os.getuid()).pw_dir) / ".config" / "lynceus")
    if REAL_ENV["HOME"]:
        roots.add(Path(REAL_ENV["HOME"]) / ".config" / "lynceus")
    if REAL_ENV["XDG_CONFIG_HOME"]:
        roots.add(Path(REAL_ENV["XDG_CONFIG_HOME"]) / "lynceus")
    if REAL_ENV["SUDO_USER"]:
        try:
            roots.add(Path(pwd.getpwnam(REAL_ENV["SUDO_USER"]).pw_dir) / ".config" / "lynceus")
        except KeyError:
            pass
    return sorted(roots)


def snapshot(directory: Path) -> dict[str, tuple] | None:
    """Recursive fingerprint of a directory, or None if it is absent.

    ⛔ None rather than ``{}``. An absent directory and an empty one have to be
    distinguishable, or the guard cannot see a run that CREATED the operator's
    config directory and left it empty. On a clean machine absent is the normal
    case, so that is precisely where the hole would be.

    ⛔ Recursive, and it records mode and a content digest, not size and mtime.
    Size plus mtime misses a `chmod`, misses anything below a subdirectory whose
    own stat did not change, and misses a same-length rewrite with the mtime put
    back. The digest costs nothing: a lynceus config directory is a few small
    YAML files.

    ⚠️ What it still cannot see: ownership and ACL changes, damage anywhere else
    in the home, and anything created and removed between the two calls. The
    claim it supports is "the run did not change these config trees", never "the
    run touched nothing".
    """
    import hashlib

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
            out[rel] = ("file", stat.st_mode, stat.st_size,
                        hashlib.sha256(path.read_bytes()).hexdigest())
    return out


def declared_console_scripts() -> list[str]:
    """Every name under ``[project.scripts]``, read from the shipped pyproject."""
    with (REPO / "pyproject.toml").open("rb") as fh:
        return sorted(tomllib.load(fh)["project"]["scripts"])


def test_a_new_user_gets_a_working_system():
    """Wheel to clean venv to wizard to validate to a UI serving /healthz.json."""
    script = _load_gate()

    roots = operator_config_dirs()
    assert roots, "derived no operator config directories; the guard below would be vacuous"
    before = {root: snapshot(root) for root in roots}
    result = script.run_fresh_install()
    after = {root: snapshot(root) for root in roots}

    # The hermeticity claim first, because it is the one that damages a person
    # rather than a build. The suite has written into a real ~/.config/lynceus
    # before, and it went unnoticed for the worst reason: on a clean home the
    # write SUCCEEDS. This runs the shipped wizard as a subprocess, which is the
    # single most likely thing in the suite to do it again.
    #
    # ⚠️ If this fails, rule out an innocent writer before believing the gate did
    # it. The run takes minutes, and an editor, a sync tool or a live lynceus
    # daemon touching the same tree in that window looks identical from here.
    changed = [root for root in roots if before[root] != after[root]]
    assert not changed, (
        f"the run changed {len(changed)} of {len(roots)} operator config trees. "
        + "; ".join(f"{root}: {before[root]} -> {after[root]}" for root in changed)
    )

    assert result.code == 0, f"fresh install failed with code {result.code}: {result.failure}"

    # It has to have tested THIS tree. The shared .venv is editable-installed
    # against the PRIMARY checkout, so a harness run from a worktree can silently
    # grade a different tree, and this repo has had that happen.
    assert result.repo == REPO, f"the gate built {result.repo}, not {REPO}"

    assert result.sandbox_home is not None
    sandbox = Path(result.sandbox_home).resolve()
    for root in roots:
        assert root not in sandbox.parents and root != sandbox, (
            f"the sandbox {sandbox} was inside the operator tree {root}"
        )

    # Derived, never transcribed. A version bump must not need an edit here.
    assert result.wheel == f"lynceus-{lynceus.__version__}-py3-none-any.whl"

    # Every entry point the project declares, read out of pyproject rather than
    # listed here, so a script added to the project is covered by this gate
    # without anyone remembering to add it.
    declared = declared_console_scripts()
    assert declared, "pyproject declares no [project.scripts]; this assertion would be vacuous"
    missing = sorted(set(declared) - set(result.console_scripts))
    assert not missing, f"the install produced no {missing}; it has {result.console_scripts}"

    # ⛔ The run must have driven the venv it built, not whatever lynceus was on
    # the caller's PATH. This is the assertion that would have caught the gate
    # quietly skipping the bundled watchlist import.
    assert result.sandbox_path, "the run recorded no PATH; it cannot have been sandboxed"
    entries = result.sandbox_path.split(os.pathsep)
    assert entries[0].endswith("/bin"), entries[0]
    for entry in entries[1:]:
        candidate = Path(entry)
        if not candidate.is_dir():
            continue
        rival = sorted(p.name for p in candidate.iterdir() if p.name.startswith("lynceus"))
        assert not rival, f"{entry} on the gate's PATH still offers {rival}"

    # The wizard writing nothing, or only some of what it promises, is the defect
    # this gate exists for.
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
    # it is the assertion that fails if the import loses its race with the
    # wizard's own 600-second kill bound on slower hardware.
    assert result.watchlist_rows > 0, (
        f"the wizard finished with {result.watchlist_rows} watchlist rows. The bundled "
        f"threat-data import did not land, and the wizard exits 0 when that happens."
    )
