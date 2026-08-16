"""Is this process's clock behind events the system has already recorded?

⛔ **The web UI is a separate process from the poller and has no ``ClockAnchor``.**
It computes ``expires_at = int(time.time()) + duration`` and persists that
absolute deadline, so an operator clicking "snooze 24h" while the host clock is
wrong stores a deadline that is wrong by the same amount.

The FORWARD case is already handled: ``repair_future_dated_rule_type_snoozes``,
``repair_future_dated_ui_entries`` and their siblings re-base rows whose
``added_at`` lies in the future, and the poller calls all of them under
``clock_trusted``. Measured at +91 days: the 24-hour snooze is re-based to
exactly 24 hours.

⭐ **The BACKWARD case is not, and this module exists for it.** Every one of
those repairs keys on ``added_at > now_ts``. A clock that was *behind* at write
time leaves ``added_at`` in the past and ``expires_at`` already elapsed, so no
repair matches — and ``cleanup_expired_*`` then deletes the row as expired.

    Measured, clock 6 years behind at write, then corrected:
        operator asked for : 24h of silence
        repaired by poller : []
        purged by cleanup  : 1
        got                : 0h

    Control, clock +91 days at write:  repaired to exactly 24.0h. ✅
    Sanity, clock correct:             24.0h. ✅

An RTC-less Raspberry Pi — this project's target hardware — boots with a stale
clock and syncs later, so "behind at write" is its normal state, not an exotic
one.

## Why refuse the write rather than warn about it

When the clock really is behind, the deadline is already past: the snooze is
inert from the moment it is stored and is then purged. Accepting silently gives
the operator a suppression they believe in and never get -- the same call this
codebase made for reserved OUIs (#86), **reject at write rather than accepting
and ignoring at detection time.**

⚠️ It is a TRADE, not a free win, and ``clock_behind_recorded_history`` spells
out why: the check cannot distinguish "the clock is wrong now" from "a past
fast clock stamped that row", so it refuses some writes that would have worked.
That is accepted because the refusal is recoverable and visible, while the
failure it prevents is neither.

⚠️ Only DURATION-bearing writes are refused. A permanent allowlist entry carries
no deadline, so a wrong clock cannot spoil it, and blocking it would stop an
operator suppressing a device during exactly the incident that made them look.
"""

from __future__ import annotations

import logging
import sqlite3
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from lynceus.db import Database

logger = logging.getLogger(__name__)

#: Matches ``poller.CLOCK_JUMP_TOLERANCE_SECONDS``. Deliberately the same
#: magnitude: two components disagreeing about what counts as a clock problem
#: is how an operator gets told the clock is fine on one page and broken on
#: another. Not imported, because ``webui`` does not otherwise depend on
#: ``poller`` and one constant is not worth the coupling — the test asserts
#: they stay equal instead.
CLOCK_BEHIND_TOLERANCE_SECONDS = 300


def clock_behind_recorded_history(db: Database, now_ts: int) -> dict:
    """Is ``now_ts`` earlier than something this system already recorded?

    Returns ``{"behind": bool, "newest_ts": int|None, "behind_by": int,
    "source": str|None}``.

    ⭐ What it actually detects, stated precisely: **the clock now reads earlier
    than it did when these rows were written.** The web UI and the poller
    normally share a host and therefore a clock, so this is not two components
    disagreeing — it is one clock having jumped BACKWARD at some point since
    those rows were stamped. No anchor, no new state, no second process.

    ⛔ **It cannot tell which side is correct, and nothing local can.** Two
    situations produce byte-identical database state:

        A. the clock is wrong NOW; the rows were stamped correctly
           → a deadline computed here is already past. Refusing is right.
        B. the clock is right NOW; the rows were stamped by a past fast clock
           → the deadline would be fine. Refusing is a FALSE POSITIVE.

    Both are refused. That is a deliberate trade, not an oversight: the refusal
    is recoverable (the message says what to check, permanent allowlist entries
    still work, and it clears when the stale rows age out of retention), whereas
    case A accepted silently is a suppression the operator believes in and never
    gets. Pinned by ``test_a_future_stamped_record_also_refuses``.

    ⚠️ **Known blind spot, equally deliberate to state:** an install where EVERY
    row was written by the same behind clock has no ahead-row to compare
    against, so this does not fire and the snooze still dies when the clock is
    corrected. This narrows the window; it does not close it. Pinned by
    ``test_an_install_with_no_ahead_rows_is_a_known_blind_spot``.

    ⚠️ Compared only against timestamps written by the poller **on this host**
    (alerts, delivered heartbeats). The poll watermark is deliberately EXCLUDED:
    it carries Kismet's ``last_seen``, i.e. a *different machine's* clock, so a
    Kismet host running fast would make a perfectly correct local clock look
    behind and refuse writes that were fine.

    ⚠️ Tolerance, not zero. Small negative deltas are ordinary NTP slew and
    round-off; only a gap larger than ``CLOCK_BEHIND_TOLERANCE_SECONDS``
    counts. A false "your clock is wrong, refusing to snooze" would be worse
    than the defect this prevents.
    """
    candidates: list[tuple[int, str]] = []
    try:
        alert_ts = db.latest_alert_ts()
        if alert_ts is not None:
            candidates.append((int(alert_ts), "the most recent alert"))
        hb_ts = db.latest_delivered_heartbeat_ts()
        if hb_ts is not None:
            candidates.append((int(hb_ts), "the last delivered heartbeat"))
    except sqlite3.Error as exc:
        # A legacy install missing a table must not 500 a page or block a
        # write. Unreadable history = no evidence the clock is wrong, which is
        # the same answer every release before this one gave.
        logger.warning("clock check: history unreadable (%s); not blocking", exc)
        return {"behind": False, "newest_ts": None, "behind_by": 0, "source": None}

    if not candidates:
        # A fresh install has recorded nothing, so there is nothing to be
        # behind. ⛔ Not an error and not a refusal: on day one every write is
        # allowed, which is correct — there is no evidence either way.
        return {"behind": False, "newest_ts": None, "behind_by": 0, "source": None}

    newest_ts, source = max(candidates, key=lambda c: c[0])
    behind_by = newest_ts - int(now_ts)
    return {
        "behind": behind_by > CLOCK_BEHIND_TOLERANCE_SECONDS,
        "newest_ts": newest_ts,
        "behind_by": max(0, behind_by),
        "source": source,
    }


def refuse_if_clock_behind(
    db: Database, now_ts: int, duration_seconds: int | None = None
) -> str | None:
    """Message explaining why a duration-bearing write must not proceed, or
    ``None`` when it may.

    ⭐ ``duration_seconds`` makes the refusal PRECISE, and its absence was an
    overclaim. The deadline is ``now + duration`` on the *writing* clock, so it
    is in the future for that clock and the suppression does work — until the
    clock is corrected. What happens then depends on a comparison this function
    could not previously make:

        duration >  behind_by   the suppression SURVIVES correction, shortened
                                by roughly `behind_by`. Allowed.
        duration <= behind_by   the deadline lands on the far side of the gap:
                                it expires the moment the clock is fixed and is
                                then purged. Refused.

    Without the duration this refused both cases and told the operator the
    suppression "would never take effect" — false for the first, and the kind
    of error message that sends someone to fix the wrong thing. Omitting the
    argument keeps the old conservative behaviour (refuse whenever the clock
    disagrees), which is why it defaults to None rather than being required.

    Callers raise ``HTTPException(400, detail=...)``; the message names the
    delta, the evidence and the fix.
    """
    state = clock_behind_recorded_history(db, now_ts)
    if not state["behind"]:
        return None
    behind_by = state["behind_by"]
    if duration_seconds is not None and duration_seconds > behind_by:
        # Survives the correction with time to spare -- refusing would block a
        # write that works.
        return None
    hours = behind_by / 3600.0
    # ⚠️ Phrased as a DISAGREEMENT, not "your clock is wrong": the check cannot
    # tell whether this clock is behind or that record was stamped ahead, and an
    # error asserting more than the code knows sends an operator to fix the
    # wrong thing.
    scope = (
        f"a {duration_seconds // 3600}-hour suppression set now"
        if duration_seconds
        else "a suppression set now"
    )
    return (
        f"This machine's clock reads {hours:.1f} hours EARLIER than "
        f"{state['source']}, so the two disagree about what time it is. "
        f"{scope} would be stored with a deadline on the near side of that "
        f"gap: it would expire the moment the clock is corrected, and then be "
        f"deleted as expired. Refusing rather than accepting a setting that "
        f"will not survive. Check the clock (NTP / `timedatectl`); if it is "
        f"correct, the stale record clears as it ages out of retention. A "
        f"longer duration than the gap would survive, and permanent allowlist "
        f"entries are unaffected — they carry no deadline."
    )
