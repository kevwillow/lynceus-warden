"""No notification channel is the most consequential state on /settings.

Without ntfy, nothing reaches the operator's phone: alerts land in the web UI
and nowhere else. For a tool whose purpose is warning someone while they are
moving, that is the difference between the product working and not.

⚠️ It used to render as a plain italic sentence — "ntfy is not configured." —
with no badge, directly below a heartbeat-off case that gets
`badge-status-error` and a sentence naming what it costs. Severity should
track consequence, not how easy the state is to describe. This is the same
shape as the audit register's Finding 0, where a home tile showed "no ruleset
configured" in NEUTRAL styling while a merely-stale watchlist got a warning.

🪤 The tempting fix is to make `NullNotifier.send()` return False so the
alerts show as undelivered. That is wrong, and these tests pin why: a
web-UI-only install is a legitimate choice, and marking its alerts undelivered
forever would make /settings and the heartbeat report a permanent fault. A
warning shown always is one an operator learns to scroll past — the same trap
as flagging a BLE bridge nobody enabled.
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.notify import NullNotifier, build_notifier
from lynceus.webui.app import create_app


def _prose(html: str) -> str:
    """Collapse whitespace: template text wraps across source lines."""
    return " ".join(html.split())


def _client(tmp_path, **cfg_kwargs):
    cfg = Config(db_path=str(tmp_path / "s.db"), **cfg_kwargs)
    db = Database(cfg.db_path)
    db.ensure_location("default", "Default")
    app = create_app(cfg, db)
    c = TestClient(app)
    c.db = db
    return c, db


def test_an_unconfigured_channel_is_marked_as_an_error_not_a_note(tmp_path):
    c, db = _client(tmp_path)
    try:
        prose = _prose(c.get("/settings").text)
        # 🪤 Scoped to the CONTIGUOUS fragment. Asserting `"badge-status-error"
        # in body` passed with the defect planted, because the heartbeat-off
        # card on the same page also carries that class — the assertion was
        # satisfied by markup it was not testing.
        assert '<span class="badge-status-error">not configured</span>' in prose
    finally:
        db.close()


def test_it_says_what_is_actually_lost(tmp_path):
    """A status with no consequence attached is a status an operator skims.
    The point is not "a setting is unset", it is "you are not being warned"."""
    c, db = _client(tmp_path)
    try:
        prose = _prose(c.get("/settings").text)
        assert "no alert reaches your phone" in prose
        assert "you are not currently being warned" in prose
    finally:
        db.close()


def test_a_configured_channel_carries_no_such_warning(tmp_path):
    """Presence assertion. Without it, every test above is satisfied by a page
    that shows the alarm unconditionally — which is the failure mode that
    trains operators to ignore this card."""
    c, db = _client(
        tmp_path, ntfy_url="https://ntfy.example", ntfy_topic="a-topic-value"
    )
    try:
        prose = _prose(c.get("/settings").text)
        assert "no alert reaches your phone" not in prose
    finally:
        db.close()


# --- the fix that would have been wrong ------------------------------------


def test_null_notifier_still_reports_success(tmp_path):
    """⛔ Pins the rejected fix. Making NullNotifier return False would mark
    every alert on a web-UI-only install undelivered forever, so /settings and
    the heartbeat would report a permanent fault that no action can clear.

    If someone changes this, they must also decide what `notified_at` means on
    an install with no channel — and this test should fail loudly first.
    """
    assert NullNotifier().send("high", "t", "m") is True


def test_no_channel_selects_the_null_notifier(tmp_path):
    """The presence half of the above: the branch under test is reachable."""
    cfg = Config(db_path=str(tmp_path / "n.db"))
    assert isinstance(build_notifier(cfg), NullNotifier)
