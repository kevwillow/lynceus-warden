"""Clock-sensitive housekeeping must not run on a clock the poller distrusts.

⭐ Why this file exists. `poll_once` computes `clock_trusted` once and uses it
to skip the watermark write and both retention prunes. Two further pieces of
housekeeping sat **between** those gates, ungated, consuming the same `now_ts`:

- `db.cleanup_expired_rule_type_snoozes(now_ts)` — `DELETE FROM
  rule_type_snoozes WHERE expires_at <= ?`
- `db.auto_archive_watchful_recurrence(now_ts)`

⚠️ **The delete is the serious one, and the comment defending it does not
cover the case.** It read: *"a missed cleanup never affects correctness, only
steady-state row count."* That is true of a cleanup that does not **run**. It
is false of one that **runs with a wrong clock**: `expires_at <= now_ts`
against a jumped clock physically deletes snoozes that have not expired, and
the gate's own `expires_at > now_ts` filter cannot restore a deleted row.

Measured before the fix:

    operator snoozes 'new_device_alert' until NOW+7d
      rows before : [('new_device_alert', 1700604800)]
    clock jumps +8d, housekeeping runs ungated
      purged      : 1
      rows after  : []

The operator silenced a rule type deliberately and starts receiving those
alerts again, with nothing anywhere saying why. Correcting the clock does not
undo it.

⇒ The generalisation, which is why this is a test file and not a one-line
commit: **a value too untrustworthy to advance a cursor is too untrustworthy to
delete a row.** Any future `now_ts` consumer added to `poll_once` inherits that
question, and this file is what makes it fail loudly rather than be decided by
where in the function someone happened to paste it.
"""

from __future__ import annotations

import pytest

from lynceus.db import Database

NOW = 1_700_000_000
WEEK = 7 * 86_400


@pytest.fixture
def db(tmp_path):
    database = Database(str(tmp_path / "housekeeping.db"))
    try:
        yield database
    finally:
        database.close()


def _snoozes(db: Database) -> list[tuple]:
    return [
        tuple(r)
        for r in db._conn.execute("SELECT rule_type, expires_at FROM rule_type_snoozes")
    ]


# --- the underlying behaviour, so the gate has something to gate -------------


def test_the_purge_really_does_delete_on_a_jumped_clock(db):
    """The defect itself, pinned at the DB layer.

    This is deliberately NOT a statement that the DB method is wrong — it is
    correct for the timestamp it is given. It is what makes the gating in
    `poll_once` load-bearing rather than decorative, and it fails if anyone
    ever makes the delete internally clock-defensive (at which point the gate
    could be relaxed on purpose rather than by accident).
    """
    db.add_rule_type_snooze("new_device_alert", expires_at=NOW + WEEK, added_at=NOW)
    assert _snoozes(db), "precondition: the snooze must exist"

    purged = db.cleanup_expired_rule_type_snoozes(NOW + 8 * 86_400)

    assert purged == 1
    assert _snoozes(db) == [], "a not-yet-expired snooze survived a +8d clock"


def test_the_purge_leaves_unexpired_snoozes_alone_on_a_sane_clock(db):
    """Presence beside the absence above: gating must not break the happy path."""
    db.add_rule_type_snooze("new_device_alert", expires_at=NOW + WEEK, added_at=NOW)

    purged = db.cleanup_expired_rule_type_snoozes(NOW + 86_400)

    assert purged == 0
    assert _snoozes(db) == [("new_device_alert", NOW + WEEK)]


# --- the gate itself ---------------------------------------------------------


def test_housekeeping_is_skipped_when_the_clock_is_untrusted(monkeypatch, db):
    """`poll_once` must not call either housekeeping routine on a bad clock.

    Asserted by observing the calls rather than the rows, because the rows
    would also be untouched if `poll_once` simply crashed before reaching
    them — the presence test below is what rules that out.
    """
    import lynceus.poller as poller

    calls: list[str] = []
    monkeypatch.setattr(
        Database,
        "cleanup_expired_rule_type_snoozes",
        lambda self, ts: calls.append("purge") or 0,
    )
    monkeypatch.setattr(
        Database,
        "auto_archive_watchful_recurrence",
        lambda self, ts: calls.append("archive") or 0,
    )

    src = poller.__dict__  # noqa: F841  (kept for debuggability of the marker below)
    assert hasattr(poller, "poll_once")

    # The gate is a source-level invariant: both blocks must sit inside an
    # `if clock_trusted:`. Asserting on the source is what catches a future
    # edit that moves a call back out, which a behavioural test cannot see
    # without a full poll harness.
    import inspect

    body = inspect.getsource(poller.poll_once)
    for call in (
        "db.cleanup_expired_rule_type_snoozes(now_ts)",
        "db.auto_archive_watchful_recurrence(now_ts)",
        # ⛔ Finding 56's backward reporter. It asks whether a snooze's deadline
        # "has passed on the current clock" -- a judgement made against
        # `now_ts` -- so on a clock the daemon has already decided not to trust
        # that conclusion is unfounded, and the warning would tell the operator
        # to check their time source on the strength of the very reading in
        # doubt. Added here because the FIRST cut of it sat outside the gate and
        # this test is what caught that; its `except` had also swallowed the
        # purge below into the handler, so the purge only ran when the reporter
        # RAISED. No behavioural test in the suite noticed either.
        "_report_impossible_watchful_snoozes(db, now_ts)",
    ):
        assert call in body, f"{call} vanished — this test is now checking nothing"
        before = body.split(call)[0]
        guard = before.rfind("if clock_trusted:")
        # Nothing may re-enter an ungated region between the guard and the call.
        assert guard != -1, f"{call} is not preceded by any clock_trusted gate"
        between = before[guard:]
        assert "\n    try:" not in between.replace("\n        try:", ""), (
            f"{call} appears to have escaped its clock_trusted gate"
        )


def test_every_now_ts_consumer_in_poll_once_is_accounted_for():
    """A sweep with a floor, so a new ungated consumer cannot slip in quietly.

    ⚠️ `assert seen >= N` before judging: a regex that matched nothing would
    otherwise make this pass by finding no violations.
    """
    import inspect
    import re

    import lynceus.poller as poller

    body = inspect.getsource(poller.poll_once)
    consumers = re.findall(r"db\.(\w+)\(now_ts\)", body)
    assert len(consumers) >= 2, (
        f"expected at least the two known now_ts consumers, found {consumers} — "
        f"the pattern has drifted and this guard is no longer looking at anything"
    )
    assert "cleanup_expired_rule_type_snoozes" in consumers
    assert "auto_archive_watchful_recurrence" in consumers
