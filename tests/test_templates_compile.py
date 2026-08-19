"""Every shipped template must actually COMPILE, against the app's own filters.

⚠️ **The gap this closes.** The template suite is large and none of it compiles
a template. `test_dashboard_classes_are_defined.py` reads templates as text and
regexes out class names; the `webui`-marked tests exercise the handful of routes
a test client visits. A template that no test renders — `error.html`,
`not_found.html`, `bulk_ack_result.html`, the wizard's `cancelled.html` — can
carry a malformed tag or a filter nobody registered, pass the entire suite, and
raise a 500 the first time an operator hits the path that renders it. The
templates that render on the *error* paths are exactly the ones least likely to
be covered by a happy-path route test, and the worst ones to have broken.

⭐ **Why it uses the real app environments rather than a bare `Environment`.**
Jinja resolves filter names at COMPILE time, not at render time. A bare
environment therefore rejects eight of these templates for using `unix_to_iso`,
`device_label` and `unix_to_utc_human` — filters `create_app` registers at
startup. Compiling against the app's own env is both the honest check and a
strictly stronger one: it fails if a template uses a filter the app does *not*
register, which a bare environment could never distinguish from the eight
false alarms.

🪤 **What this CANNOT see, 1: rendering.** Compiling is not rendering. A
template that compiles can still raise on a missing context key, or on
`{{ x.y }}` where `x` is None — `test_webui_future_timestamps.py` and friends
are what cover that, route by route.

🪤 **What this CANNOT see, 2: markup outside a block.** Measured while proving
this guard: a `{{ 1 | no_such_filter }}` appended to `error.html` *survives*,
because the template `{% extends %}` a base and Jinja never compiles child
content that sits outside a `{% block %}`. Moved inside the block, the same
plant fails the test. So this guard sees a template's blocks, not every byte of
it — which is fine, since markup outside a block never renders either.

Read a green run as "no template is syntactically broken and no template uses
an unregistered filter", nothing more.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest
from jinja2 import TemplateSyntaxError

from lynceus.config import Config
from lynceus.db import Database
from lynceus.setup.web.app import create_wizard_app
from lynceus.webui.app import create_app

_ROOT = Path(__file__).resolve().parents[1]

#: Template roots, paired with the factory that builds the environment able to
#: compile them. The two apps register different filters and globals, so a
#: wizard template compiled against the dashboard env (or vice versa) would
#: report a filter error that says nothing about either app.
_ROOTS = (
    "src/lynceus/webui/templates",
    "src/lynceus/setup/web/templates",
)


def _tracked_templates(root: str) -> list[Path]:
    """Templates under ``root``, as git sees them.

    ⛔ Derived from `git ls-files`, never globbed off disk. A glob picks up
    stray untracked scratch templates on a developer's box and — the direction
    that actually matters — keeps reporting success if the directory is renamed
    and the glob quietly matches nothing.
    """
    out = subprocess.run(
        ["git", "ls-files", f"{root}/*.html"],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    return [_ROOT / p for p in out]


def _webui_env(tmp_path):
    config = Config(db_path=str(tmp_path / "compile.db"))
    db = Database(config.db_path)
    app = create_app(config, db)
    return app.state.templates.env, db


def _wizard_env():
    app = create_wizard_app(
        setup_token="compile-check-token-0000000000000000",
        scope="user",
        target_path=Path("/tmp/compile-check-lynceus.yaml"),
    )
    return app.state.templates.env


@pytest.mark.webui
def test_the_template_set_is_not_empty():
    """⛔ Guards every other test in this file.

    If both roots stopped matching, each compile test below would iterate an
    empty list and pass. An empty check list scoring as green is the failure
    mode this repo has been bitten by more than once.
    """
    counts = {root: len(_tracked_templates(root)) for root in _ROOTS}
    for root, n in counts.items():
        assert n > 0, f"no tracked templates under {root}; the compile checks would be vacuous"
    total = sum(counts.values())
    assert total >= 40, (
        f"only {total} templates found ({counts}); the shipped set is ~49. "
        "Either templates were deleted or the paths moved."
    )


@pytest.mark.webui
def test_every_dashboard_template_compiles(tmp_path):
    env, db = _webui_env(tmp_path)
    try:
        failures = _compile_all(env, _tracked_templates(_ROOTS[0]))
    finally:
        db.close()
    assert not failures, "templates failed to compile:\n  " + "\n  ".join(failures)


@pytest.mark.webui
def test_every_wizard_template_compiles():
    env = _wizard_env()
    failures = _compile_all(env, _tracked_templates(_ROOTS[1]))
    assert not failures, "templates failed to compile:\n  " + "\n  ".join(failures)


def _compile_all(env, templates: list[Path]) -> list[str]:
    failures: list[str] = []
    for path in templates:
        try:
            env.get_template(path.name)
        except TemplateSyntaxError as exc:
            failures.append(f"{path.relative_to(_ROOT)}:{exc.lineno}: {exc.message}")
        except Exception as exc:  # noqa: BLE001 - report, don't mask
            failures.append(f"{path.relative_to(_ROOT)}: {type(exc).__name__}: {exc}")
    return failures
