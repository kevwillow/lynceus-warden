"""Smoke test: every module imports and version is pinned."""

import talos
from talos import allowlist, db, kismet, main, notify, poller, rules


def test_version():
    assert talos.__version__ == "0.1.0"


def test_modules_importable():
    for module in (db, kismet, poller, rules, notify, allowlist, main):
        assert module is not None
