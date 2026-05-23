"""Config-application core extracted from ``lynceus.cli.setup``.

The CLI wizard (``lynceus-setup``) and the eventual run-once web wizard
(Phase 2) share the same side-effect chain: write ``lynceus.yaml``,
scaffold severity overrides, create data/log dirs, import the bundled
watchlist, optionally write ``rules.yaml``. This package holds that
chain as a pure-Python function that consumes a validated ``Config``
and emits a structured ``ApplyReport`` so neither frontend has to
parse stdout to know what happened.
"""

from __future__ import annotations

from lynceus.setup.models import (
    STEP_NAMES,
    ApplyOverallStatus,
    ApplyReport,
    ApplyStep,
    ApplyStepStatus,
    ProgressSink,
)

__all__ = [
    "STEP_NAMES",
    "ApplyOverallStatus",
    "ApplyReport",
    "ApplyStep",
    "ApplyStepStatus",
    "ProgressSink",
]
