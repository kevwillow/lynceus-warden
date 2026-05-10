"""Smoke test: every module imports and version is pinned."""

import lynceus
from lynceus import allowlist, db, kismet, main, notify, poller, rules


def test_version():
    assert lynceus.__version__ == "0.4.0rc1"


def test_modules_importable():
    for module in (db, kismet, poller, rules, notify, allowlist, main):
        assert module is not None
