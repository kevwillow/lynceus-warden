"""The conftest HOME-isolation fixture is a guard that nothing asserted.

⛔ WHY THIS FILE EXISTS. `_isolate_user_config_dirs` (tests/conftest.py) stops
the suite writing into the real ``~/.config/lynceus`` of whoever runs it. It
was added after seven tests were measured doing exactly that.

🪤 **The tests it protects PASS WITH IT DISARMED.** Measured by A/B/A on
2026-08-20: setting ``autouse=False`` made ``allowlist.yaml`` reappear in a
fake home while every test still went green. So nothing in the suite would
fail if a future refactor dropped the fixture — the pollution would silently
come back and CI would stay green, exactly as it did before anyone noticed.

⇒ A guard whose removal breaks no test is not enforced, it is merely present.
These tests fail loudly if the isolation stops working, which is the whole job.
[[guards-can-be-silently-disarmed]]
"""

from __future__ import annotations

import os
from pathlib import Path

from lynceus import paths

# The one directory the suite must never touch. Deliberately derived from the
# INVOKING user's real environment at import time, before any fixture has had a
# chance to redirect it — comparing against a value the fixture itself produced
# would be circular and could not fail.
_REAL_HOME_AT_IMPORT = Path(os.path.expanduser("~")).resolve()


def test_config_dir_is_not_the_real_user_home():
    """The load-bearing assertion: config paths resolve away from the real home."""
    resolved = paths.default_config_dir("user").resolve()
    assert _REAL_HOME_AT_IMPORT not in resolved.parents and resolved != _REAL_HOME_AT_IMPORT, (
        f"config dir {resolved} is under the real home {_REAL_HOME_AT_IMPORT}. "
        "The HOME-isolation fixture is not in effect, so this suite can write "
        "into the operator's actual ~/.config/lynceus."
    )


def test_every_config_sidecar_is_redirected_too():
    """Not just the directory — each file derived from it.

    ⛔ Asserting only ``default_config_dir`` would pass if a future path helper
    stopped deriving from it. Each of these is a separate write target the
    wizard actually uses, and the original defect was precisely that one of
    them (rules.yaml) was not covered by an isolation that looked complete.
    """
    for name, fn in (
        ("config", paths.default_config_path),
        ("allowlist", paths.default_allowlist_path),
        ("overrides", paths.default_overrides_path),
    ):
        resolved = fn("user").resolve()
        assert _REAL_HOME_AT_IMPORT not in resolved.parents, (
            f"{name} path {resolved} is under the real home {_REAL_HOME_AT_IMPORT}"
        )


def test_home_and_xdg_agree_with_each_other():
    """HOME and XDG_CONFIG_HOME must point at the SAME redirected tree.

    Redirecting one and not the other is the silent-partial-isolation failure:
    helpers that consult ``XDG_CONFIG_HOME`` land in the sandbox while helpers
    falling back to ``Path.home()`` land in the real home, and the suite looks
    isolated while half of it is not.
    """
    home = Path(os.environ["HOME"]).resolve()
    xdg = Path(os.environ["XDG_CONFIG_HOME"]).resolve()
    assert home in xdg.parents or xdg == home, (
        f"XDG_CONFIG_HOME {xdg} is not inside HOME {home}; isolation is partial"
    )
    assert Path.home().resolve() == home, (
        "Path.home() disagrees with $HOME, so helpers that use it are unisolated"
    )


def test_each_test_gets_a_distinct_home(tmp_path):
    """Per-test, not per-session — one test's leftovers must not reach the next.

    Recorded rather than assumed: the fixture is deliberately function-scoped.
    A session-scoped version would still keep the real home safe while letting
    a file written by one test change what a later one observes.
    """
    home = Path(os.environ["HOME"]).resolve()

    # ⛔ REFUSE TO WRITE unless the sandbox is confirmed first. Measured
    # 2026-08-20: without this, disarming the fixture made THIS test write
    # `seen-by-a-previous-test` into the real home — the exact defect the file
    # exists to catch, committed by the guard itself. It went unnoticed because
    # the test still PASSED: the marker was absent, so the assertion held, and
    # the write was pure collateral. Found only by planting the defect.
    # ⇒ A guard that performs a side effect must prove it is safe to perform it
    # BEFORE performing it, not assert about it afterwards.
    assert _REAL_HOME_AT_IMPORT not in home.parents and home != _REAL_HOME_AT_IMPORT, (
        f"refusing to write a marker: HOME is {home}, inside the real home "
        f"{_REAL_HOME_AT_IMPORT}. Isolation is off — fix that, not this test."
    )

    marker = home / "seen-by-a-previous-test"
    assert not marker.exists(), (
        "a previous test's HOME leaked into this one; the isolation fixture is "
        "session-scoped when it must be function-scoped"
    )
    marker.write_text("x", encoding="utf-8")
