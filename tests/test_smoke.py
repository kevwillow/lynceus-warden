"""Smoke test: every module imports and version is pinned."""

import tomllib
from pathlib import Path

import lynceus
from lynceus import allowlist, db, kismet, main, notify, poller, rules


def test_version():
    assert lynceus.__version__ == "0.6.2"


def test_version_matches_pyproject():
    # __init__.py is the runtime answer (CLI --version, webui nav strap);
    # pyproject.toml is what pip installs as. Two literals = drift hazard
    # (rc6 ship caught one). Parse pyproject and assert they agree.
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    assert lynceus.__version__ == data["project"]["version"]


def test_modules_importable():
    for module in (db, kismet, poller, rules, notify, allowlist, main):
        assert module is not None
