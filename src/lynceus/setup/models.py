"""Type vocabulary for the config-application core.

``ApplyStep`` is one structured record per side-effect the core
performs. ``ApplyReport`` is the ordered list returned at the end.
``ProgressSink`` is the callback the core invokes after each step,
so a non-CLI frontend (the Phase 2 web wizard) can stream progress
without parsing stdout.

The CLI frontend plugs in a "print one line per step" sink; the web
frontend will plug in a "push to SSE queue" sink. Keeping the sink
synchronous (one method, no async) sidesteps async/await ratholes —
the web side can hand each step to an async queue from inside its
sink implementation if it wants to.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

ApplyStepStatus = Literal["ok", "skipped", "failed", "warning"]
ApplyOverallStatus = Literal["ok", "failed"]
ArgusLoadMode = Literal["skip", "bundled", "github", "file"]


@dataclass(frozen=True)
class ArgusChoice:
    """Operator-driven choice for how to load the Argus watchlist.

    The web wizard's argus step captures this and passes it to
    ``apply_config``. Replaces the legacy auto-bundled-import default
    so Lynceus stays a working product when the operator picks Skip
    (rules-based detection continues; existing watchlist data is
    preserved).

    ``mode``:
      * ``"skip"`` — apply emits a skipped import step; the watchlist
        is left exactly as it was (no clear, no import).
      * ``"bundled"`` — import the snapshot shipped in the wheel.
      * ``"github"`` — fetch the latest snapshot from a GitHub repo
        (default: ``kevwillow/argus-db``). Network required.
      * ``"file"`` — import a local CSV the operator points at.

    ``file_path`` is required when ``mode == "file"`` and ignored
    otherwise. ``github_repo`` / ``github_ref`` are used when
    ``mode == "github"``; ``github_ref`` of ``None`` lets the
    importer resolve to the latest release with a ``main`` fallback.
    """

    mode: ArgusLoadMode
    file_path: str | None = None
    github_repo: str = "kevwillow/argus-db"
    github_ref: str | None = None
# "warning" is a non-blocking outcome: the step ran, found a real
# problem worth telling the operator about, but does not flip
# overall_status (the apply pipeline still completes). The Arc B
# Kismet source-name cross-check uses it for "you wrote a source name
# Kismet doesn't expose — observations from that source will silently
# drop". Adding new "warning" emitters is fine; just make sure the
# operator-facing message names the specific surface and the recovery
# path.


# Every step name ``apply_config`` may emit, in the canonical order
# they fire when every branch is taken. Tests pin step ordering
# against this tuple so Touch 2's refactor can't silently reorder the
# --system permissions sequence (mkdir → chown(dirs) → bundled-import
# → chown(.db files)) — the ordering IS the fix for rc1 bugs S1, S2,
# and Bug 6, per the inline comments at cli/setup.py:1746-1878.
STEP_NAMES: tuple[str, ...] = (
    "write_config",
    "scaffold_severity_overrides",
    "scaffold_allowlist",
    "create_data_dir",
    "create_log_dir",
    "import_bundled_watchlist",
    "chown_db_files",
    "write_rules",
    "verify_kismet_sources",
)


@dataclass(frozen=True)
class ApplyStep:
    """One structured record of a side-effect the core performed.

    ``name`` is one of ``STEP_NAMES``. ``status`` is "ok" when the
    step did its work, "skipped" when the step was not applicable
    (e.g. ``chown_db_files`` under ``--user``), and "failed" when the
    step's work raised. ``message`` is an operator-readable one-liner.
    ``detail`` carries structured context for failures or non-default
    behavior — e.g. the path written, the count imported.
    """

    name: str
    status: ApplyStepStatus
    message: str
    detail: dict[str, object] | None = None


@dataclass(frozen=True)
class ApplyReport:
    """The ordered transcript of an ``apply_config`` invocation."""

    steps: tuple[ApplyStep, ...]

    @property
    def overall_status(self) -> ApplyOverallStatus:
        """``"failed"`` if any step failed, else ``"ok"``.

        "skipped" is not a failure — a step that doesn't apply (chown
        under --user, bundled-import disabled) is the same shape of
        success as a step that did its work.
        """
        if any(step.status == "failed" for step in self.steps):
            return "failed"
        return "ok"


@runtime_checkable
class ProgressSink(Protocol):
    """Callback shape for streaming ``ApplyStep`` records.

    Implementations call back synchronously inside ``apply_config``'s
    step loop. The CLI frontend's implementation prints one line per
    step; the Phase 2 web wizard's implementation pushes each step
    onto an SSE queue.
    """

    def record(self, step: ApplyStep) -> None: ...
