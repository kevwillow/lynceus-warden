"""Shared pytest fixtures for the Lynceus test suite."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

#: The operator's environment as it was BEFORE anything in this file redirected it.
#:
#: ⛔ Captured here, at conftest import, and NOT in the test module that uses it.
#: pytest loads conftest before it imports any test module and before any fixture
#: body runs, so this is the one moment the real values still exist.
#:
#: 🪤 Measured 2026-08-22. This lived in `tests/test_fresh_install.py` and was
#: correct only while that module was collected. Running a different file that
#: imported it INSIDE a test body captured the per-test sandbox HOME instead, and
#: the hermeticity guard built on it then compared an empty temporary directory
#: against itself. A module-level capture is only as early as its first importer.
REAL_ENV = {key: os.environ.get(key) for key in ("HOME", "XDG_CONFIG_HOME", "SUDO_USER")}

_DIAGNOSTIC_OUTPUT_DIR = Path(__file__).parent / "diagnostic_output"


class DiagnosticDump:
    """Accumulator + writer for diagnostic-test structured output.

    The diagnostic suite (``pytest -m diagnostic``) dumps actual
    behavior to per-test ``.log`` files for offline reviewer scrutiny.
    Tests append to four labeled buckets:

        diag.fixture("MAC aa:bb:cc:11:22:33 inserted into allowlist")
        diag.exercise("Invoked poll_once() with a synthetic observation")
        diag.observed("watchful sighting_count: 1 -> 1 (unchanged)")
        diag.notes("Allowlist precedence wins; watchful gate unreachable")

    Buckets support multi-line content; ``section()`` opens a
    sub-divider when a single test exercises multiple scenarios. The
    final file is written at fixture teardown.
    """

    def __init__(self, test_name: str) -> None:
        self.test_name = test_name
        self._sections: list[dict] = []
        self._current: dict = {
            "name": test_name,
            "fixture": [],
            "exercise": [],
            "observed": [],
            "notes": [],
        }
        self._sections.append(self._current)

    def section(self, name: str) -> None:
        """Open a new sub-section. Subsequent fixture/exercise/observed/
        notes calls write into this section until ``section()`` is
        called again. Use for tests that exercise multiple scenarios.
        """
        self._current = {
            "name": name,
            "fixture": [],
            "exercise": [],
            "observed": [],
            "notes": [],
        }
        self._sections.append(self._current)

    def fixture(self, text: str) -> None:
        self._current["fixture"].append(str(text))

    def exercise(self, text: str) -> None:
        self._current["exercise"].append(str(text))

    def observed(self, text: str) -> None:
        self._current["observed"].append(str(text))

    def notes(self, text: str) -> None:
        self._current["notes"].append(str(text))

    def render(self) -> str:
        out: list[str] = []
        for s in self._sections:
            header_bar = "=" * (60 - min(60, len(s["name"]) + 1))
            out.append(f"{header_bar} {s['name']}")
            for label in ("fixture", "exercise", "observed", "notes"):
                lines = s[label]
                if not lines:
                    continue
                out.append(f"{label.upper()}:")
                for line in lines:
                    for sub in str(line).splitlines() or [""]:
                        out.append(f"  * {sub}" if sub else "  *")
            out.append("")
        return "\n".join(out)

    def write(self, out_dir: Path) -> Path:
        out_dir.mkdir(parents=True, exist_ok=True)
        target = out_dir / f"{self.test_name}.log"
        target.write_text(self.render(), encoding="utf-8")
        return target


@pytest.fixture
def diag(request):
    """Diagnostic-dump fixture; writes per-test ``.log`` at teardown.

    Output lands in ``tests/diagnostic_output/<test_name>.log`` (the
    directory is created on demand and is gitignored). The dump is
    written even if the test raises, so a crashed diagnostic still
    leaves its partial observations on disk for review.
    """
    dump = DiagnosticDump(request.node.name)
    try:
        yield dump
    finally:
        dump.write(_DIAGNOSTIC_OUTPUT_DIR)


@pytest.fixture(autouse=True)
def _kismet_no_runtime_retry(monkeypatch):
    """Make urllib3's ``Retry`` mechanism a no-op at runtime during tests.

    The H5 fix mounts a urllib3 ``Retry`` on ``KismetClient``'s session so a
    transient Kismet 5xx or connection error transparently retries 3 times
    with ``backoff_factor=0.5``. In production the recovery is the point.
    In tests, the webui suite alone constructs ~120 apps that each fire one
    Kismet status probe at a closed loopback port; on Windows each refused-
    connection attempt costs ~2s, so 4 attempts × 120 tests adds minutes of
    wall-clock for an outcome the tests already know.

    Patching ``Retry.increment`` to raise ``MaxRetryError`` immediately
    short-circuits the retry loop after the first failure — without
    altering the *configured* attributes (``total``, ``backoff_factor``,
    ``status_forcelist``, ``allowed_methods``). The structural
    ``test_h5_session_retry_mounted_for_*`` tests inspect those attributes
    on the mounted adapter and still pass.
    """
    from urllib3.exceptions import MaxRetryError
    from urllib3.util.retry import Retry

    def raise_immediately(
        self,
        method=None,
        url=None,
        response=None,
        error=None,
        _pool=None,
        _stacktrace=None,
    ):
        raise MaxRetryError(_pool, url, error or "test-mode no-retry")

    monkeypatch.setattr(Retry, "increment", raise_immediately)


@pytest.fixture(autouse=True)
def _isolate_user_config_dirs(tmp_path_factory, monkeypatch):
    """Give every test its own HOME, so the suite cannot write into the
    real ``~/.config/lynceus`` of whoever runs it.

    ⛔ This is a hermeticity guard, not a convenience. Measured 2026-08-20 on
    `416bad5`: running the suite created ``rules.yaml`` and ``allowlist.yaml``
    in the developer's actual config directory. Seven tests reached a wizard
    write whose target is ``paths.default_config_dir(scope) / "<name>"`` while
    stubbing only ``resolve_config_path``, which covers ``lynceus.yaml`` and
    nothing else.

    ⚠️ It stayed invisible for the worst possible reason: **it only fails when
    the file already exists.** On a clean home -- every CI runner -- the write
    SUCCEEDS and the test PASSES, so green CI was being bought by writing
    outside the sandbox. It surfaced only on a box that had run
    ``lynceus-setup``, where #182's overwrite confirmation consumed a scripted
    answer and the test died on StopIteration, reading like a broken test
    rather than a test escaping its sandbox.

    ⭐ Isolating the ENVIRONMENT rather than stubbing ``default_config_dir``
    is deliberate: ``test_paths.py`` asserts what that function derives, so
    stubbing the function would gut the tests that cover path resolution
    itself. Redirecting HOME leaves the derivation under test and only moves
    where it lands. Evidence it is safe: the full suite was run under a
    redirected HOME before this was added -- 4446 passed, 0 failed.

    Per-test rather than per-session, so a file one test leaves behind cannot
    change what the next one observes. ⇒ [[a-fixture-can-contaminate-the-next-case]]
    """
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(home / ".local" / "share"))
    monkeypatch.setenv("XDG_STATE_HOME", str(home / ".local" / "state"))
    return home


#: Markers for gates that need a real machine rather than a CI runner.
#: ``addopts`` deselects each of these, so they only ever run when somebody asks
#: for them by name. Keep in step with the ``markers`` list in ``pyproject.toml``.
HOST_ONLY_MARKERS = frozenset({"install", "browser"})


def record_gate_ran(name: str) -> None:
    """Append proof that a host-only gate BODY executed, if asked to.

    ⛔ This is what makes `make release-gates` honest. pytest exits 0 for a run
    that collected and executed nothing, and no exit code tells that apart from
    a real pass. Measured 2026-08-22: `PYTEST_ADDOPTS=--collect-only make
    release-gates` printed "1/4626 tests collected" and exited 0, having run no
    test body at all. The Makefile clears `PYTEST_ADDOPTS` and then reads this
    file, because it cannot trust the exit code alone.

    Writes only when ``LYNCEUS_GATE_SENTINEL`` names a path, so an ordinary
    `pytest` run has no side effects.
    """
    target = os.environ.get("LYNCEUS_GATE_SENTINEL")
    if not target:
        return
    with open(target, "a", encoding="utf-8") as fh:
        fh.write(f"{name}\n")


@pytest.fixture(autouse=True)
def _record_host_only_gate_ran(request):
    """Record every host-only gate that actually runs.

    ⭐ A fixture rather than a call inside each gate, so a gate added later is
    covered without anyone remembering. The browser gate got this for free.

    Records AFTER the body, so it means "this executed", not "this was about to".
    A failing gate still records, which is correct: it ran, and pytest's exit
    code is what carries pass or fail.
    """
    yield
    if HOST_ONLY_MARKERS & {m.name for m in request.node.iter_markers()}:
        record_gate_ran(request.node.nodeid)
