"""A jumped clock must not poison the poll cursor.

The cursor half of the wall-clock defect class. #35 gated the *retention*
prunes; this is the other side, and it is the worse of the two.

A skipped prune costs one day of deferred housekeeping. A watermark written
from a jumped clock is **persistent**: `last_poll_ts` is read back on the next
tick as `since=<the future>`, Kismet returns nothing, and the daemon is blind
for the whole excursion. Re-anchoring the clock does not undo it, because the
poisoned value is already in the database.

⚠️ And the failure is invisible in exactly the way this product cannot afford:
30 days of "no devices seen" looks identical to a quiet environment. Same
"silence is ambiguous" family as the heartbeat, arriving through the cursor.

🪤 The subtle half is the interaction with `POLL_WATERMARK_HOLDS`. That
counter's budget belongs to PERSIST failures (PR #24). If a clock hold spent
it, an operator with a jumped clock AND a failing disk would silently lose the
persist-retry protection — one bug quietly disarming another's guard.
`test_a_clock_hold_does_not_spend_the_persist_retry_budget` pins that.
"""

from __future__ import annotations

import pytest

from lynceus.config import Config
from lynceus.db import Database
from lynceus.kismet import FakeKismetClient
from lynceus.poller import (
    POLL_WATERMARK_MAX_HOLDS,
    STATE_KEY_LAST_POLL,
    STATE_KEY_WATERMARK_HOLDS,
    poll_once,
)

NOW = 1_700_000_000
JUMPED = NOW + 30 * 86_400


@pytest.fixture()
def env(tmp_path):
    fixture = tmp_path / "empty.json"
    fixture.write_text("[]", encoding="utf-8")
    cfg = Config(db_path=str(tmp_path / "wm.db"), kismet_fixture_path=str(fixture))
    db = Database(cfg.db_path)
    db.ensure_location("default", "Default")
    client = FakeKismetClient(str(fixture))
    yield client, db, cfg
    db.close()


def _watermark(db) -> str | None:
    return db.get_state(STATE_KEY_LAST_POLL)


def test_a_trusted_clock_advances_the_watermark(env):
    """The presence assertion. A test that only proved the watermark is held
    would pass against code that never advances it -- which is the A1
    poison-record livelock PR #24 exists to prevent."""
    client, db, cfg = env
    poll_once(client, db, cfg, NOW, clock_trusted=True)
    assert _watermark(db) == str(NOW)


def test_an_untrusted_clock_does_not_advance_the_watermark(env):
    """The defect: `since=<the future>` on every later tick."""
    client, db, cfg = env
    poll_once(client, db, cfg, NOW, clock_trusted=True)
    assert _watermark(db) == str(NOW)

    poll_once(client, db, cfg, JUMPED, clock_trusted=False)
    assert _watermark(db) == str(NOW), (
        "the poll cursor was moved 30 days into the future; every later tick "
        "asks Kismet for devices since then and gets nothing"
    )


def test_the_watermark_is_not_poisoned_even_on_the_very_first_tick(env):
    """No prior value to fall back on is the nastier case: a first tick on a
    jumped clock would otherwise establish the poisoned cursor from scratch."""
    client, db, cfg = env
    poll_once(client, db, cfg, JUMPED, clock_trusted=False)
    assert _watermark(db) is None, (
        f"a first tick on an untrusted clock established a poisoned cursor: "
        f"{_watermark(db)}"
    )


def test_normal_advance_resumes_once_the_clock_is_trusted_again(env):
    """The hold is bounded by the anchor's own re-anchoring, so this must not
    become a permanent freeze -- the other broken extreme."""
    client, db, cfg = env
    poll_once(client, db, cfg, NOW, clock_trusted=True)
    poll_once(client, db, cfg, JUMPED, clock_trusted=False)
    assert _watermark(db) == str(NOW)

    poll_once(client, db, cfg, NOW + 60, clock_trusted=True)
    assert _watermark(db) == str(NOW + 60), "the watermark stayed frozen"


def test_a_clock_hold_does_not_spend_the_persist_retry_budget(env, monkeypatch):
    """🪤 One bug must not disarm another's guard.

    `POLL_WATERMARK_HOLDS` is the budget for retrying observations that failed
    to PERSIST. If a clock hold consumed it, an operator hitting both problems
    at once would lose the protection PR #24 added, silently.
    """
    client, db, cfg = env
    db.set_state(STATE_KEY_WATERMARK_HOLDS, "1")

    poll_once(client, db, cfg, JUMPED, clock_trusted=False)

    assert db.get_state(STATE_KEY_WATERMARK_HOLDS) == "1", (
        "a clock hold spent part of the persist-retry budget"
    )


def test_an_untrusted_clock_does_not_reset_the_persist_retry_budget(env):
    """The other direction of the same interaction: the untrusted branch must
    not clear the counter either, or a clock blip would hand a genuinely
    poisonous record a fresh set of retries every time it occurred."""
    client, db, cfg = env
    db.set_state(STATE_KEY_WATERMARK_HOLDS, str(POLL_WATERMARK_MAX_HOLDS))

    poll_once(client, db, cfg, JUMPED, clock_trusted=False)

    assert db.get_state(STATE_KEY_WATERMARK_HOLDS) == str(POLL_WATERMARK_MAX_HOLDS)
