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


#: The consequence clause is chosen by the CALLER, because the consequence is
#: not the same for every write this gate protects. A snooze stores a deadline
#: that expires early; a watchful reset stamps a lifecycle clock and quietly
#: buys less tracking than the operator asked for. ⛔ **One sentence covering
#: both would name the wrong cause for one of them**, and a warning naming the
#: wrong cause gets followed, gets nowhere, and gets dismissed next time.
_ACTIONS = ("suppression", "watchful_reset")


def refuse_if_clock_behind(
    db: Database,
    now_ts: int,
    duration_seconds: int | None = None,
    *,
    action: str = "suppression",
) -> str | None:
    """Message explaining why a clock-stamped write must not proceed, or
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

    ⛔ **``action="watchful_reset"`` deliberately passes NO duration, and that is
    a measurement, not an oversight.** A reset stamps ``last_seen_at = MAX(
    last_seen_at, now)`` and the entry is auto-archived a fixed quiet period
    after that column, so what the operator loses is
    ``min(entry_staleness, behind_by)`` -- it depends on the ROW, not only on
    the clock, and no single ``duration_seconds`` can express it. Measured
    through the real POST route on the tree without this gate (gitignored:
    `internal/session2-harnesses/f51_route_verify.py`; its db-layer twin is
    `f51_reset_gate_probe.py`) — days of tracking granted for a click meaning
    "I am still watching this device", with the page reporting success in every
    row:

        correct clock, 89d stale     90.0d      <- control
        behind  30d,   89d stale     60.0d      a 90d duration would ALLOW this
        behind 100d,   89d stale      1.0d
        behind 100d,   95d stale     ARCHIVED   the entry is dropped outright
        behind 100d,    1d stale     89.0d      the cost of refusing: harmless

    So this refuses the whole class rather than the cases a duration argument
    happens to catch. The last row is the price and it is accepted for the same
    reason the rest of the module accepts its false positives: the refusal is
    recoverable and visible.

    ⛔ **"Recoverable" is not "free", and the first version of this message said
    it was.** It told the operator the entry *"stays escalated and tracked
    meanwhile, so nothing is lost by waiting"*. Measured, with a control, on the
    tree that shipped it:

        entry 89d stale, clock behind 100d   refused -> clock fixed -> retry 303
        entry 95d stale, clock behind 100d   refused -> clock fixed -> retry 400,
                                             ARCHIVED by the poller in between

    An entry already past the quiet window is archived by ordinary housekeeping
    while the operator goes to fix the clock, and an archived entry cannot be
    reset at all — so the reassurance was false for exactly the entries most at
    risk, which is the population this gate exists for. The message now names
    that instead of promising against it. ⇒ Do not restore the shorter sentence.

    Callers raise ``HTTPException(400, detail=...)``; the message names the
    delta, the evidence and the fix.
    """
    if action not in _ACTIONS:
        # ⛔ Not a silent fallback to the suppression wording. An unknown action
        # would then be explained to the operator in terms of a deadline that
        # write never had -- the exact failure this parameter exists to prevent.
        raise ValueError(f"action must be one of {_ACTIONS}, got {action!r}")
    state = clock_behind_recorded_history(db, now_ts)
    if not state["behind"]:
        return None
    behind_by = state["behind_by"]
    if duration_seconds is not None and duration_seconds > behind_by:
        # Survives the correction with time to spare -- refusing would block a
        # write that works.
        return None
    hours = behind_by / 3600.0
    # ⚠️ Phrased as a DISAGREEMENT for both actions: the check cannot tell
    # whether this clock is behind or that record was stamped ahead.
    disagreement = (
        f"This machine's clock reads {hours:.1f} hours EARLIER than "
        f"{state['source']}, so the two disagree about what time it is. "
    )
    remedy = (
        "Check the clock (NTP / `timedatectl`); if it is correct, the stale "
        "record clears as it ages out of retention. "
    )
    if action == "watchful_reset":
        quiet_days = db.WATCHFUL_RECURRENCE_ARCHIVE_QUIET_SECONDS // 86400
        return (
            f"{disagreement}A reset stamps this entry as last seen NOW, and an "
            f"entry is auto-archived {quiet_days} days after that timestamp. "
            f"Written against the earlier clock the reset therefore grants up "
            f"to {hours:.1f} hours less continued tracking than it appears to, "
            f"and an entry already close to that limit is archived outright — "
            f"the opposite of what this button means. Refusing rather than "
            f"quietly watching for less time than you asked for. {remedy}The "
            f"entry is not dismissed and nothing is deleted — it stays "
            f"escalated meanwhile. But an entry already at the end of its "
            f"{quiet_days}-day window can still be archived while the clock is "
            f"wrong, and an archived entry cannot be reset, so fix the clock "
            f"rather than waiting for it."
        )
    scope = (
        f"a {duration_seconds // 3600}-hour suppression set now"
        if duration_seconds
        else "a suppression set now"
    )
    return (
        f"{disagreement}{scope} would be stored with a deadline on the near "
        f"side of that gap: it would expire the moment the clock is corrected, "
        f"and then be deleted as expired. Refusing rather than accepting a "
        f"setting that will not survive. {remedy}A longer duration than the gap "
        f"would survive, and permanent allowlist entries are unaffected — they "
        f"carry no deadline."
    )
