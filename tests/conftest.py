"""Shared pytest fixtures for the Lynceus test suite."""

from __future__ import annotations

from pathlib import Path

import pytest

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
