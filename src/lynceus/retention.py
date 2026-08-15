"""Retention for the ``sightings`` table.

``sightings`` has never had a retention policy. At a 60-second poll interval a
single continuously-present device contributes ~1,440 rows a day, so the table
grows without bound and eventually fills a Pi. It is also the reason
``co_observation.window_days`` exists: an unbounded table needs the query to
supply the horizon the schema does not.

⛔ **This deletes evidence, and the deletion is irreversible.** It is therefore
off by default (``sightings_retention_days: null``), which is exactly what
every existing install already does. An upgrade must never silently discard an
operator's observation history.

Mirrors ``evidence.prune_old_evidence`` / ``maybe_prune_evidence`` deliberately,
including the once-a-day rate limit recorded in ``poller_state``, so there is
one retention idiom in this codebase rather than two.
"""

from __future__ import annotations

import logging

from lynceus.db import Database

logger = logging.getLogger(__name__)

STATE_KEY_LAST_SIGHTINGS_PRUNE = "last_sightings_prune"


def _validate_retention(retention_days: int | None) -> None:
    if retention_days is None:
        return
    if not isinstance(retention_days, int) or isinstance(retention_days, bool):
        raise ValueError("retention_days must be int or None")
    if retention_days < 1:
        raise ValueError("retention_days must be >= 1")


def prune_old_sightings(
    db: Database,
    retention_days: int | None,
    *,
    now_ts: int,
) -> tuple[int, int | None]:
    """Delete sightings older than ``retention_days``.

    Returns ``(rows_deleted, oldest_remaining_ts)``; the second element is None
    when no sightings remain. ``retention_days=None`` is a no-op returning
    ``(0, ...)``, because "no policy" is a valid and default configuration
    rather than an error.

    ⚠️ The cutoff is **exclusive**: a row exactly at ``now - retention_days``
    is KEPT. Off by one here quietly deletes an extra day of evidence on every
    run, and nothing downstream would report it.

    Touches ``sightings`` only. Alerts are the operator's record of what was
    decided and must outlive the observations behind them; devices carry
    identity that stays meaningful after its rows age out.

    ⛔ ``now_ts`` is REQUIRED. It has no wall-clock default on purpose.

    This deletes rows on a time comparison, and the decision about whether the
    clock can be trusted is made by the caller -- ``poll_once`` gates every
    call on ``clock_trusted`` after a monotonic-anchor check (#35/#40/#58).
    A ``now_ts=None`` default silently substituted ``int(time.time())``, so a
    single call that omitted the argument would have bypassed that gate
    entirely and deleted against a raw, possibly-jumped clock. Nothing in the
    signature said so, and it would not have failed -- it would have deleted.

    ⇒ The gate is now structural rather than a matter of caller discipline:
    omitting the argument is a TypeError at the call site.
    """
    _validate_retention(retention_days)
    if retention_days is None:
        oldest_row = db._conn.execute("SELECT MIN(ts) FROM sightings").fetchone()
        oldest = int(oldest_row[0]) if oldest_row and oldest_row[0] is not None else None
        return 0, oldest

    cutoff = now_ts - retention_days * 86_400
    with db._conn:
        cur = db._conn.execute("DELETE FROM sightings WHERE ts < ?", (cutoff,))
        deleted = cur.rowcount
        oldest_row = db._conn.execute("SELECT MIN(ts) FROM sightings").fetchone()
    oldest = int(oldest_row[0]) if oldest_row and oldest_row[0] is not None else None
    logger.info(
        "Pruned %d sightings older than %d days (oldest remaining: %s)",
        deleted,
        retention_days,
        oldest,
    )
    return deleted, oldest


def maybe_prune_sightings(
    db: Database,
    retention_days: int | None,
    *,
    now_ts: int,
    interval_seconds: int = 86_400,
) -> bool:
    """Run :func:`prune_old_sightings` at most once per ``interval_seconds``.

    Returns True only when a prune actually executed. A ``retention_days`` of
    None returns False without recording a run, so enabling retention later
    prunes immediately instead of waiting out an interval it never served.

    ⛔ ``now_ts`` is REQUIRED. It has no wall-clock default on purpose.

    This deletes rows on a time comparison, and the decision about whether the
    clock can be trusted is made by the caller -- ``poll_once`` gates every
    call on ``clock_trusted`` after a monotonic-anchor check (#35/#40/#58).
    A ``now_ts=None`` default silently substituted ``int(time.time())``, so a
    single call that omitted the argument would have bypassed that gate
    entirely and deleted against a raw, possibly-jumped clock. Nothing in the
    signature said so, and it would not have failed -- it would have deleted.

    ⇒ The gate is now structural rather than a matter of caller discipline:
    omitting the argument is a TypeError at the call site.
    """
    _validate_retention(retention_days)
    if retention_days is None:
        return False
    last_raw = db.get_state(STATE_KEY_LAST_SIGHTINGS_PRUNE)
    if last_raw is not None:
        try:
            last = int(last_raw)
        except (TypeError, ValueError):
            last = 0
        elapsed = now_ts - last
        # ``elapsed < 0`` means the recorded anchor sits in the FUTURE, which
        # no sane clock produces: it is what a prune that ran while the clock
        # was wrong-and-ahead leaves behind. Treating that as "too recent"
        # (which a bare ``elapsed < interval_seconds`` does, negatives being
        # less than any positive interval) stalls pruning until real time
        # overtakes the bad value -- measured at a full year of no pruning for
        # a one-year excursion, on a table whose whole purpose is to stop an
        # unbounded one filling a Pi. An impossible anchor is treated as due,
        # so the run below re-records a sane value and the stall self-heals.
        if 0 <= elapsed < interval_seconds:
            return False
    prune_old_sightings(db, retention_days, now_ts=now_ts)
    db.set_state(STATE_KEY_LAST_SIGHTINGS_PRUNE, str(now_ts))
    return True
