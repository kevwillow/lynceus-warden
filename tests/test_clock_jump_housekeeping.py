"""A jumped clock must not delete operator intent either.

The third half of the wall-clock defect class. #35 gated the retention prunes,
#40 gated the poll cursor, and both are keyed on capture DATA. These two
housekeeping calls sit BETWEEN those gates in ``poll_once`` and were left
running on the same untrusted ``now_ts``:

- ``db.cleanup_expired_rule_type_snoozes(now_ts)`` — a physical
  ``DELETE FROM rule_type_snoozes WHERE expires_at <= ?``. Measured before this
  fix: a snooze the operator set to last until ``NOW+7d`` is **deleted at clock
  +8d**, and correcting the clock does not bring it back.
- ``db.auto_archive_watchful_recurrence(now_ts)`` — retires entries on a 90-day
  quiet stretch measured against the same clock.

⚠️ This one destroys OPERATOR INTENT rather than capture data, which makes it
different in kind from the prunes. "I have seen this rule type, stop telling me
about it for a week" is a decision the operator made; losing it means the tool
starts shouting about something they deliberately silenced, and they have no
way to know why.

🪤 The comment that guarded this call argued it was safe: *"a missed cleanup
never affects correctness, only steady-state row count, because the gate's
``expires_at > now_ts`` filter already ignores expired rows."* That is sound
for a cleanup that does NOT RUN — which is precisely what this gate now
arranges. It was never an argument that running it with a wrong clock is safe,
and the read-side filter cannot restore a deleted row.
"""

from __future__ import annotations

import pytest

from lynceus.config import Config
from lynceus.db import Database
from lynceus.kismet import FakeKismetClient
from lynceus.poller import poll_once

NOW = 1_700_000_000
DAY = 86_400
JUMPED = NOW + 8 * DAY


@pytest.fixture()
def env(tmp_path):
    fixture = tmp_path / "empty.json"
    fixture.write_text("[]", encoding="utf-8")
    cfg = Config(db_path=str(tmp_path / "hk.db"), kismet_fixture_path=str(fixture))
    db = Database(cfg.db_path)
    db.ensure_location("default", "Default")
    client = FakeKismetClient(str(fixture))
    yield client, db, cfg
    db.close()


def _snoozes(db) -> int:
    return db._conn.execute("SELECT COUNT(*) FROM rule_type_snoozes").fetchone()[0]


def _seed_live_snooze(db, *, expires_at=NOW + 7 * DAY):
    """A snooze the operator set, still live at NOW."""
    db.add_rule_type_snooze(
        rule_type="watchlist_mac", expires_at=expires_at, added_at=NOW
    )


# --- presence assertions -------------------------------------------------
# Without these, "the snooze survived" is equally satisfied by a poll_once that
# purges nothing ever, which would be a different defect wearing the same
# passing test.


def test_a_trusted_clock_still_purges_a_genuinely_expired_snooze(env):
    client, db, cfg = env
    _seed_live_snooze(db, expires_at=NOW - 1)  # already expired at NOW
    assert _snoozes(db) == 1

    poll_once(client, db, cfg, NOW, clock_trusted=True)

    assert _snoozes(db) == 0, "a trusted clock must still do the housekeeping"


def test_a_trusted_clock_keeps_a_snooze_that_has_not_expired(env):
    client, db, cfg = env
    _seed_live_snooze(db)

    poll_once(client, db, cfg, NOW, clock_trusted=True)

    assert _snoozes(db) == 1


# --- the guard -----------------------------------------------------------


def test_an_untrusted_clock_does_not_delete_a_live_snooze(env):
    """The measured defect: at clock +8d a 7-day snooze is gone."""
    client, db, cfg = env
    _seed_live_snooze(db)

    poll_once(client, db, cfg, JUMPED, clock_trusted=False)

    assert _snoozes(db) == 1, (
        "a snooze the operator set for 7 days was deleted by a poll tick whose "
        "clock had jumped 8 days forward — and no clock correction restores it"
    )


def test_the_snooze_survives_the_whole_excursion_not_just_one_tick(env):
    """A daemon polls every 60s, so the jumped clock is not seen once — it is
    seen for every tick until NTP corrects. A guard that held for a single tick
    and then let the next one through would look identical in a one-shot test.
    """
    client, db, cfg = env
    _seed_live_snooze(db)

    for _ in range(5):
        poll_once(client, db, cfg, JUMPED, clock_trusted=False)

    assert _snoozes(db) == 1


def test_housekeeping_resumes_once_the_clock_is_trusted_again(env):
    """⛔ The other extreme. Refusing forever protects the snooze and loses the
    table to unbounded growth — the same "both extremes are broken" shape as
    POLL_WATERMARK_MAX_HOLDS. Once the clock is trusted, expired rows must go.
    """
    client, db, cfg = env
    _seed_live_snooze(db, expires_at=NOW + 7 * DAY)

    poll_once(client, db, cfg, JUMPED, clock_trusted=False)
    assert _snoozes(db) == 1

    # Clock corrects, and real time has genuinely passed the expiry.
    poll_once(client, db, cfg, NOW + 8 * DAY, clock_trusted=True)
    assert _snoozes(db) == 0, "housekeeping must resume, not be disabled forever"
