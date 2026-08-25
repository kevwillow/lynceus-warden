"""``install.sh``'s symlink list must match ``[project.scripts]`` exactly.

⭐ **Why this exists, and it is not hypothetical.** ``install.sh`` carried the
comment *"Any new entry point added there must be appended here so the symlink
layer keeps it on PATH"* — and that comment was the entire control. Measured
2026-08-25 on ``79517f0``: ``lynceus-export-case`` shipped in v1.1.1 (PR #229)
and was never appended, so on a ``--system`` install it was the one console
script that never reached ``/usr/local/bin``. An operator following
``docs/DEPLOYMENT.md`` got a command-not-found for the feature that release was
built around.

⛔ **Both sides are DERIVED**, never transcribed. A copy of either list living
in this file would go stale the same way the one in ``install.sh`` did — and it
would go stale silently, because a test that agrees with its own copy always
passes. That failure is recorded in this repo twice over
(``tests/test_webui_post_routes_are_classified.py`` derives its route set from
the live app for exactly this reason).

Both directions fail:

  * a script in pyproject, absent from install.sh  -> it never lands on PATH
  * a script in install.sh, absent from pyproject  -> a dangling symlink
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = REPO_ROOT / "pyproject.toml"
INSTALL_SH = REPO_ROOT / "install.sh"


def declared_in_pyproject() -> set[str]:
    with PYPROJECT.open("rb") as fh:
        data = tomllib.load(fh)
    return set(data.get("project", {}).get("scripts", {}))


def declared_in_install_sh() -> set[str]:
    """Parse the ``CONSOLE_SCRIPTS=( ... )`` array out of the shell script.

    ⚠️ Anchored on the assignment and terminated on the closing paren at column
    zero, rather than grepping the whole file for ``lynceus-*``. The file names
    console scripts in log lines and usage text too, and a loose grep would
    absorb those and report a parity that does not exist.
    """
    text = INSTALL_SH.read_text(encoding="utf-8")
    match = re.search(r"^CONSOLE_SCRIPTS=\((.*?)^\)", text, re.MULTILINE | re.DOTALL)
    assert match, "could not find the CONSOLE_SCRIPTS=( ... ) array in install.sh"
    body = match.group(1)
    names = set()
    for raw in body.splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            names.update(line.split())
    return names


def test_install_sh_symlinks_every_declared_console_script():
    pyproject = declared_in_pyproject()
    install = declared_in_install_sh()

    # Presence floors. Two empty sets are equal, and a parse that silently
    # returned nothing would make the comparison below vacuously true — the
    # exact shape of guard failure this repo has hit before.
    assert len(pyproject) >= 10, (
        f"only {len(pyproject)} scripts parsed from pyproject; the parse is "
        f"broken and this test is measuring nothing: {sorted(pyproject)}"
    )
    assert len(install) >= 10, (
        f"only {len(install)} scripts parsed from install.sh; the parse is "
        f"broken and this test is measuring nothing: {sorted(install)}"
    )

    missing_from_install = sorted(pyproject - install)
    assert not missing_from_install, (
        f"{missing_from_install} are declared in pyproject's [project.scripts] "
        f"but absent from CONSOLE_SCRIPTS in install.sh. On a --system install "
        f"they are never symlinked into /usr/local/bin, so the operator gets "
        f"command-not-found. Append them to install.sh."
    )

    dangling = sorted(install - pyproject)
    assert not dangling, (
        f"{dangling} are listed in install.sh's CONSOLE_SCRIPTS but are not "
        f"declared in pyproject's [project.scripts]. The installer would create "
        f"a symlink pointing at a file pip never wrote."
    )


def test_the_two_parsers_do_not_both_read_the_same_file():
    """The control. A parity test whose two halves read one source is vacuous.

    Cheap to state and it removes the one way this file could pass forever
    without checking anything.
    """
    assert PYPROJECT != INSTALL_SH
    assert PYPROJECT.exists() and INSTALL_SH.exists()
    # And the parsers genuinely disagree in shape: one is TOML keys, the other
    # a shell array. If someone "simplified" both to the same helper, this
    # catches it.
    assert "CONSOLE_SCRIPTS" in INSTALL_SH.read_text(encoding="utf-8")
    assert "[project.scripts]" in PYPROJECT.read_text(encoding="utf-8")
