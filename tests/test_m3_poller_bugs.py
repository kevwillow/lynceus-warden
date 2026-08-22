"""Real bugs found in ``src/lynceus/poller.py``.

Each test pins ONE defect observed against the unmodified code. Every test
below was watched FAIL before the corresponding fix and PASSED after; both
outputs are in the commit message.

The def-defects-found-here shape:

  Bug A — ``poll_once`` logs ``"UI allowlist snooze repair failed"`` on EVERY
          tick when ``config.allowlist_path`` is None (the default for any
          install that did not run the wizard with an allowlist configured).

This file is the only test artifact for these fixes; the suite is read by
``make lint`` and by the per-module pytest selections and otherwise gitignored.
"""

from __future__ import annotations

import logging

from lynceus.allowlist import Allowlist
from lynceus.config import Config
from lynceus.db import Database
from lynceus.kismet import FakeKismetClient
from lynceus.notify import RecordingNotifier
from lynceus.poller import poll_once
from lynceus.rules import Ruleset

# ---------------------------------------------------------------------------
# Bug A — the UI-allowlist snooze repair crashes when no allowlist is set
# ---------------------------------------------------------------------------


def test_poll_once_does_not_log_a_ui_allowlist_repair_warning_when_no_allowlist_is_configured(
    tmp_path, caplog
):
    """The defect: ``poll_once`` unconditionally calls
    ``Path(config.allowlist_path)`` inside its per-tick repair sweep. On a
    default install — i.e. one that never wrote an ``allowlist_path`` into
    ``lynceus.yaml`` — ``config.allowlist_path`` is None and ``Path(None)``
    raises ``TypeError``. The repair code is wrapped in ``try/except``, but
    the wrong thing is caught: the code reports the failure ("UI allowlist
    snooze repair failed") as if a real repair had been attempted and lost,
    when in fact there is no allowlist to repair.

    Measured against the unmodified code: ONE ``WARNING`` line per poll tick.
    At the default 60-second tick the operator's ``journalctl -u
    lynceus.service`` sees ~1440 lines/day whose message is wrong AND whose
    WARNING level trains them to ignore the line that actually matters.

    The Poller's ``__init__`` already guards on this with
    ``Path(config.allowlist_path) if config.allowlist_path else None`` —
    the same shape is needed here. The fix is a one-line skip when no
    allowlist is configured; the regression test is the assertion below.
    """
    fixture = tmp_path / "empty.json"
    fixture.write_text("[]", encoding="utf-8")
    cfg = Config(
        db_path=str(tmp_path / "ui.db"),
        kismet_fixture_path=str(fixture),
        # The default in Config is None; pin it for clarity.
        allowlist_path=None,
    )
    db = Database(cfg.db_path)
    db.ensure_location("default", "Default")
    try:
        client = FakeKismetClient(str(fixture))
        with caplog.at_level(logging.WARNING, logger="lynceus.poller"):
            poll_once(
                client,
                db,
                cfg,
                1_700_000_000,
                ruleset=Ruleset(),
                allowlist=Allowlist(),
                notifier=RecordingNotifier(),
            )
        offenders = [
            r.getMessage()
            for r in caplog.records
            if "UI allowlist snooze repair failed" in r.getMessage()
        ]
        assert offenders == [], (
            "poll_once logged the UI-allowlist snooze repair WARNING even "
            "though no allowlist is configured (allowlist_path=None). The "
            "default install runs this on every tick; at the default 60s "
            "interval that is ~1440 misleading WARNINGS/day whose text is "
            "also wrong ('repair failed' implies a real repair was attempted)."
            f" Offending records: {offenders}"
        )
    finally:
        db.close()
