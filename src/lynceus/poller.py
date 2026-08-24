"""Poll loop: fetch from Kismet on an interval, persist, and trigger rule eval."""

from __future__ import annotations

import argparse
import asyncio
import datetime as _dt
import json
import logging
import signal
import sys
import threading
import time
from pathlib import Path

from . import __version__, paths
from .allowlist import (
    Allowlist,
    AllowlistParseError,
    _load_allowlist_with_counts,
    is_soft_attribute,
    repair_future_dated_ui_entries,
)
from .config import Config, load_config
from .db import Database, WatchfulRecurrence
from .evidence import capture_evidence, maybe_prune_evidence
from .kismet import FakeKismetClient, KismetClient
from .notify import (
    Notifier,
    NullNotifier,
    build_metadata_suffix,
    build_notifier,
    build_type_suffix,
)
from .retention import maybe_prune_sightings
from .rules import (
    Ruleset,
    RuntimeSeverityOverride,
    evaluate,
    load_ruleset,
    load_runtime_severity_overrides,
)

STATE_KEY_LAST_POLL = "last_poll_ts"

#: How many consecutive ticks the poll watermark may be held back to retry
#: observations that failed to persist. See the write site at the end of
#: ``poll_once`` for the full reasoning; the short version is that this number
#: is the whole design, because BOTH extremes are broken:
#:
#:   0 (always advance)  -> a device whose persist fails is PERMANENTLY LOST.
#:                          Measured: watermark jumps to the tick time, past
#:                          the device's last_seen, and Kismet is never asked
#:                          for that window again. A car with an ALPR that
#:                          drives past once during a disk hiccup leaves no
#:                          alert, no row, and one WARNING line.
#:   ∞ (never advance)   -> a record that fails EVERY time freezes the
#:                          watermark and the daemon re-fetches the same
#:                          window forever. Alive, and permanently blind.
#:                          That is the A1 poison-record livelock.
#:
#: 3 matches RUNTIME_KISMET_LOSS_THRESHOLD's tolerance and covers roughly three
#: minutes of transient failure at the default interval, which is the shape of
#: a locked DB or a full disk being cleared. A failure that outlives it is not
#: transient, so the watermark advances and the loss is logged at ERROR.
POLL_WATERMARK_MAX_HOLDS = 3

#: How far the wall clock may drift from elapsed monotonic time within one
#: process before this tick's clock is treated as untrustworthy.
#:
#: 300s is far above any legitimate correction -- NTP slews rather than steps
#: once running, and a step at boot happens before the anchor is taken -- and
#: far below the smallest excursion that does damage (a retention window is
#: measured in days). It does not need to be tight: the cost of a false
#: positive is one skipped prune, and the prunes are already once-a-day no-ops.
CLOCK_JUMP_TOLERANCE_SECONDS = 300

#: Consecutive untrusted ticks before the daemon accepts the new clock as truth,
#: re-anchors, and resumes pruning.
#:
#: 🪤 Same shape and same reasoning as POLL_WATERMARK_MAX_HOLDS, because BOTH
#: extremes are broken. Holding forever protects capture data but loses the
#: table to unbounded growth on a machine whose clock is permanently wrong --
#: an RTC-less Pi that never reaches NTP is exactly this project's target. So
#: the bound IS the design: refuse to prune while the jump is fresh, then log
#: loudly, re-anchor, and let retention resume against the clock the machine
#: actually has.
CLOCK_JUMP_MAX_HOLDS = 3

#: Consecutive ticks the watermark has been held. Reset on any clean tick.
STATE_KEY_WATERMARK_HOLDS = "watermark_holds"

# Per-tick counters surfaced on the home page, in /healthz, and as the
# INFO heartbeat in journalctl. Each key is overwritten in place on
# every poll tick (last-tick semantics, not cumulative) so the
# poller_state table stays bounded. The three drop reasons mirror the
# silent-drop sites the diagnostic identified: source_allowlist /
# min_rssi gates inside poll_once and the parser-None bucket counted
# inside KismetClient.get_devices_since via the unparseable_counter
# kwarg.
#: Liveness of the opt-in BLE bridge, as observed by the poll loop each tick.
#: One of "running" / "failed" / "stopped".
#:
#: ⚠️ ABSENT means the bridge has never been enabled on this install, which is
#: the default. That is NOT a problem and the heartbeat must stay silent about
#: it — a dead-man's switch that complains about a feature nobody turned on
#: trains the operator to ignore it, which costs more than the warning is worth.
#:
#: ⛔ Written only by the main poll loop, never by the bridge thread. The thread
#: owns a separate database connection, and a second writer for one status
#: string buys nothing while adding a cross-thread write to the state table.
STATE_KEY_BLE_BRIDGE_STATUS = "ble_bridge_status"
BLE_BRIDGE_RUNNING = "running"
BLE_BRIDGE_FAILED = "failed"
BLE_BRIDGE_STOPPED = "stopped"
# Alive, but not scanning. Distinct from "failed" because the two have
# different causes and different remedies, and one sentence covering both sends
# the operator to check whether the process is up — which, here, it is.
BLE_BRIDGE_STALLED = "stalled"
# Wall-clock second at which the bridge last had a scan session genuinely
# turning. Written by the bridge's own tick, read by _observe_ble_bridge.
STATE_KEY_BLE_BRIDGE_SCAN_TS = "ble_bridge_scan_alive_ts"

#: Entry ids whose impossible watchful snooze has already been reported, as a
#: JSON list. ⛔ Durable, and that is the point: `find_impossible_watchful_
#: snoozes` has no purge behind it, so without a memory the same warning would
#: be re-emitted on EVERY poll cycle forever. #139 already had to fix exactly
#: that shape ([1,1,1,1] per cycle) on the rule_type reporter -- there the bound
#: comes free from the row being deleted immediately afterwards; watchful
#: entries are never deleted.
STATE_KEY_IMPOSSIBLE_WATCHFUL_REPORTED = "impossible_watchful_reported"

#: How many reported entry ids to remember. Far above any plausible count (each
#: one needs its own clock incident). ⚠️ If it is ever exceeded the oldest are
#: forgotten and may be reported again -- a repeated warning, which is the safe
#: direction; the alternative is a state row that grows without limit.
IMPOSSIBLE_WATCHFUL_REPORT_MEMORY = 256

STATE_KEY_LAST_TICK_COMPLETED_AT = "last_tick_completed_at"
STATE_KEY_LAST_TICK_ADMITTED = "last_tick_admitted"
STATE_KEY_LAST_TICK_DROPPED_SOURCE_ALLOWLIST = "last_tick_dropped_source_allowlist"
STATE_KEY_LAST_TICK_DROPPED_MIN_RSSI = "last_tick_dropped_min_rssi"
STATE_KEY_LAST_TICK_DROPPED_UNPARSEABLE = "last_tick_dropped_unparseable"

# Cadence for the per-rule_type snooze suppression summary log. The
# Poller flushes accumulated counts to a single INFO line at this
# interval (default ~1h) so operators grepping journalctl see what
# the active snoozes are actually catching without one log line per
# suppressed emit drowning the rest of the daemon output. Tests
# shorten this to verify the flush behavior without sleeping.
SUPPRESSION_LOG_INTERVAL_SECONDS = 3600

# Backoff schedule for the startup Kismet health check, in seconds.
# Three attempts with 2s/4s waits between them — covers the window where
# Kismet is still coming up under systemd's After=network.target without
# letting an actually-broken Kismet hold up daemon start indefinitely.
# Tests override to ``[0.0, 0.0, 0.0]`` to skip the sleeps.
HEALTH_CHECK_RETRY_BACKOFF: list[float] = [2.0, 4.0, 8.0]

# Runtime Kismet-loss alerting (0.9.1). The poll loop has no retry of its own
# — each tick is a single attempt, poll_interval_seconds apart — so a RUNTIME
# loss of Kismet is treated as "really gone" only after this many CONSECUTIVE
# failed ticks, mirroring the startup check's len(HEALTH_CHECK_RETRY_BACKOFF)
# tolerance. A single transient failed poll stays below it and never pages the
# operator; at the default 60s interval the one-shot "down" alert needs roughly
# three minutes of sustained loss. This governs the RUNTIME path ONLY — the
# startup check above owns the fail-fast/crash-loop behavior and never reaches
# this alert.
RUNTIME_KISMET_LOSS_THRESHOLD = 3

# How many delivery attempts one alert gets before the poller stops retrying
# it. Wave 5 Finding 12: an alert row used to be committed before the send was
# attempted, and dedup keyed on the row, so a failed send suppressed its own
# retry for the whole dedup window (3600s by default). Delivery is now the
# dedup key, which makes a retry possible -- and therefore makes a BOUND
# necessary, because each attempt costs a blocking HTTP timeout on the poll
# path and an unbounded loop would retry a dead server on every tick.
#
# 4 attempts at the default 60s interval covers roughly three minutes of
# outage, which matches RUNTIME_KISMET_LOSS_THRESHOLD's tolerance above and is
# comfortably longer than the mobile-data blips this exists to survive. When
# they are spent the row stays notified_at=NULL, so it is still counted as
# undelivered on /settings rather than quietly forgotten.
NOTIFY_MAX_ATTEMPTS = 4

#: Base spacing for watchful-escalation retries. The retry driver is "we saw the
#: device again", which on a short poll interval fires every few minutes, so
#: without spacing all NOTIFY_MAX_ATTEMPTS are spent inside one outage. Tripling
#: puts attempts 2/3/4 at roughly +5min/+15min/+45min from the escalation, which
#: is the timescale on which a moving operator regains signal.
WATCHFUL_RETRY_BASE_SECONDS = 300

# How long run_forever waits for the BLE bridge thread to drain its buffer and
# close its own Database after stop() before logging that it overran. Generous
# relative to a flush tick so a mid-flush shutdown completes cleanly.
BLE_BRIDGE_JOIN_TIMEOUT_SECONDS = 10.0

logger = logging.getLogger(__name__)


# Distinguishes "this generation has not escalated" (None) from "the ledger
# could not be read" (this sentinel). Collapsing the two let a failed read fall
# into the SNOOZE-consumption branch, which stamps `now_ts` without consulting
# the ledger -- stranding an already-pending alert behind the retry's
# `ts >= escalated_at` filter, permanently. Measured in f44_coldread_probe.py.
_LEDGER_UNREADABLE = object()


def _watchful_generation_escalated_at(
    db: Database, entry_id: int, generation: int, mac: str
):
    """When this entry generation emitted its escalation alert, if it did.

    Returns the emit instant, ``None`` if this generation has not escalated, or
    ``_LEDGER_UNREADABLE`` if the lookup failed.

    ⚠️ A failure degrades to the ordinary emit path -- never the snooze
    branch -- on purpose.
    The real dedup guard is the UNIQUE constraint inside
    ``Database.add_watchful_escalation_alert``, so a failed read here costs a
    redundant emit ATTEMPT that the constraint then turns into a no-op, and
    never a duplicate alert row. Raising instead would abandon every remaining
    hit on this device for the sake of a lookup that correctness does not rest
    on, which is the trade this whole finding exists to avoid making.
    """
    try:
        return db.watchful_generation_escalated_at(entry_id, generation)
    except Exception as e:
        logger.warning(
            "Could not read the watchful escalation ledger for %s: %s -- "
            "falling through to the ordinary emit path, where the UNIQUE "
            "constraint still prevents a duplicate.",
            mac,
            e,
        )
        return _LEDGER_UNREADABLE


def _emit_watchful_escalation(
    db: Database,
    notifier: Notifier,
    entry: WatchfulRecurrence,
    now_ts: int,
) -> int | None:
    """Emit the synthetic ``watchful_recurrence`` escalation alert.

    ⛔ Returns the instant the caller must stamp into ``escalated_at``, or
    ``None`` if the write failed -- in which case the entry stays unescalated
    and the next sighting retries. Deliberately NOT keyed on delivery: once the
    row exists, ``_retry_watchful_escalation`` can find it and re-send, which
    is exactly what #74 built it for.

    ⭐ It returns a TIMESTAMP rather than a bool because the value differs
    between its two success cases, and getting that wrong loses the escalation
    permanently. The row was written now (stamp ``now_ts``), or it was written
    by an EARLIER crossing whose stamp failed (stamp that earlier instant, read
    back from the ledger). ``_retry_watchful_escalation`` passes
    ``escalated_at`` to ``get_recent_alert_for_rule_and_mac`` as ``since_ts``,
    which filters ``ts >= since_ts``, so stamping ``now_ts`` over an older
    alert row makes that row invisible to the retry for good.

    ⛔ Both mean the escalation was RECORDED once. They do NOT mean the
    operator was told -- an earlier draft of this docstring said they did, and
    row existence and successful delivery are different states, which is the
    exact conflation #74 exists to prevent. Delivery is tracked on the alert
    row (``notified_at`` / ``notify_attempts``) and re-driven by
    ``_retry_watchful_escalation``, which the recovery path invokes as soon as
    it has restored the stamp.

    The generation is the entry's ``reset_count``, so a RESET entry is a
    generation with no row and escalates normally -- the half that a "skip if
    an alert row exists for this MAC" dedup would have broken, by silencing a
    device the operator deliberately restarted watching.

    Called at the first threshold-cross for an entry (the caller's
    ``escalated_at is None`` test is the "fire once per escalation"
    guard). Independent of the entry's own
    ``snooze_expires_at``: per OQ-3 that field gates the original
    alert pipeline only, not the escalation alert. Subject to the
    per-rule_type snooze on ``watchful_recurrence``, which the
    caller checks before invoking this helper -- watchful detection
    state transitions still happen even when the rule_type snooze
    is suppressing emit.

    Severity is "high" -- consistent with the operator's intent
    that the recurrence matters and so /alerts and /rules render
    the high-severity badge. ntfy priority is 4 via the
    ``priority_override`` knob added to ``Notifier.send`` in this
    rc cycle. The severity / priority decoupling is intentional
    per the scare-factor mitigation locked decision: priority-4 is
    one above the default-3 (med) and one below the urgent-5
    reserved for severity=high watchlist hits the operator opted
    into. It is NOT a default-mapping oversight.
    """
    first_watched_iso = _dt.datetime.fromtimestamp(
        entry.first_seen_at, tz=_dt.UTC
    ).strftime("%Y-%m-%d")
    message = (
        f"Device {entry.mac} seen {entry.sighting_count} times "
        f"since first watch on {first_watched_iso}. "
        "Recurrence threshold reached."
    )
    try:
        alert_id = db.add_watchful_escalation_alert(
            entry.id,
            entry.reset_count,
            ts=now_ts,
            mac=entry.mac,
            message=message,
            severity="high",
            matched_watchlist_id=entry.matched_watchlist_id,
        )
    except Exception as e:
        logger.warning(
            "Failed to write watchful escalation alert for %s: %s -- the entry "
            "stays unescalated so the next sighting retries this write. It is "
            "NOT recorded as escalated, because an entry marked escalated with "
            "no alert row is a lost escalation nothing re-drives.",
            entry.mac,
            e,
        )
        return None
    if alert_id is None:
        # ⭐ This generation already emitted an escalation and the stamp is
        # what did not land (Finding 44). Write nothing and send nothing --
        # the returned instant is what gets `escalated_at` stamped, and the
        # stamp is the precondition `_retry_watchful_escalation` needs before
        # it will re-drive DELIVERY of the row that already exists. Delivering
        # here instead would re-send the same escalation without the attempt
        # accounting that path keeps.
        #
        # ⚠️ Only reachable when the caller's pre-check was UNAVAILABLE, since
        # a working pre-check handles this case before we are called. The
        # timestamp must still come from the ledger: `now_ts` would be the
        # permanent-loss bug described above, reached by the degraded path
        # instead of the ordinary one.
        ledger = _watchful_generation_escalated_at(
            db, entry.id, entry.reset_count, entry.mac
        )
        emitted_at = None if ledger is _LEDGER_UNREADABLE else ledger
        if emitted_at is None:
            # The constraint says the row exists but the ledger cannot be read
            # to say when. Refuse to stamp rather than stamp a value known to
            # be wrong: the entry stays unescalated, nothing is emitted (the
            # constraint sees to that), and the next sighting recovers properly
            # once the database is readable again. Fail-open and self-healing,
            # against a stamp that would silently make the alert undeliverable.
            logger.warning(
                "Watchful escalation for %s is already recorded for "
                "generation %d but its ledger row could not be read; leaving "
                "the entry unescalated so the next sighting can recover it.",
                entry.mac,
                entry.reset_count,
            )
            return None
        logger.info(
            "Watchful escalation for %s was already emitted for generation %d; "
            "recovering the escalated stamp instead of emitting a duplicate.",
            entry.mac,
            entry.reset_count,
        )
        return emitted_at
    # Display-only at-a-glance device type for the escalation ntfy, mirroring
    # the main alert path (85eb163). Unlike that path there is no observation
    # in scope here, so device_type is read off the persisted devices row and
    # device_category off the matched watchlist metadata (the same md path the
    # main alert uses). Both lookups are guarded: a missing device/metadata row
    # -- or a DB error -- renders an em-dash placeholder rather than breaking
    # escalation. matched_watchlist_id is None for non-Argus watchful entries,
    # which is a legitimate absent category. No inference.
    device_type = None
    device_category = None
    try:
        device_row = db.get_device(entry.mac)
        if device_row is not None:
            device_type = device_row.get("device_type")
        if entry.matched_watchlist_id is not None:
            md = db.get_metadata_by_watchlist_id(entry.matched_watchlist_id)
            device_category = md.get("device_category") if md else None
    except Exception:
        device_type = None
        device_category = None
    type_suffix = build_type_suffix(device_type, device_category)
    _deliver_watchful_escalation(
        db,
        notifier,
        alert_id=alert_id,
        mac=entry.mac,
        body=message + type_suffix,
        now_ts=now_ts,
        # ⛔ REQUIRED, not defaulted, and 0 is a claim rather than a fallback.
        # `add_watchful_escalation_alert` returns an id ONLY for a row it just
        # inserted (an existing reservation returns None and never reaches
        # here), so `notify_attempts` is 0 by construction. A default would let
        # a future call site inherit a CAS keyed on zero SILENTLY -- and unlike
        # `record_alert_notify_attempt`, whose omitted `expected_attempts`
        # means "no CAS at all", omitting it here would mean "CAS against 0",
        # which is the opposite. Two defaults of different KINDS, one calling
        # the other, is the trap; making it explicit removes it.
        expected_attempts=0,
    )
    # The ROW exists, which is what the caller's stamp is a claim about. A
    # failed SEND is the retry path's business, not a reason to leave the entry
    # unescalated and re-emit a duplicate row on the next sighting.
    #
    # `now_ts` is the alert row's own `ts`, so the stamp and the row agree and
    # the retry's `ts >= escalated_at` lookup matches it.
    return now_ts


def _deliver_watchful_escalation(
    db: Database,
    notifier: Notifier,
    *,
    alert_id: int,
    mac: str,
    body: str,
    now_ts: int,
    expected_attempts: int,
) -> bool:
    """Send one watchful escalation and RECORD whether it actually arrived.

    ⛔ This used to be a bare ``notifier.send`` whose result was logged and
    discarded — the fire-and-forget shape PR #19 removed from the main alert
    path and that the heartbeat was deliberately built to avoid. The escalation
    kept it, and it is the worst place in the product to keep it: measured with
    ntfy down at the moment the threshold was crossed, across eight further days
    of the device continuing to follow the operator —

        alert row : notified_at=None, notify_attempts=0
        notifier  : called ONCE, never again
        heartbeat : "1 alert written but never delivered", permanently

    ⚠️ `escalate_watchful_recurrence` is idempotent by design ("fire once per
    escalation"), so nothing re-drove it. One transient network blip at exactly
    the wrong moment permanently lost the single most important message this
    product sends — that someone appears to be following you — and the operator
    was never told it had been lost.

    Uses the DB-backed counters rather than in-memory ones (the shape #62 uses
    for the Kismet-down notice, which has no alert row) precisely because this
    one does have a row: the retry then survives a daemon restart, and losing
    the escalation across a restart is exactly as bad as losing it to a blip.
    """
    # Bookkeeping must never cost a notification — same reasoning as the main
    # alert path: losing the counter costs at worst one extra retry, losing the
    # send means the operator is never told.
    #
    # ⛔ The attempt is also the CLAIM -- same mechanism as the main alert
    # path. `_retry_watchful_escalation` decides to re-send from a READ of the
    # row (`notified_at IS NULL`, attempts left) and two writers can pass that
    # read together. The first-crossing race is closed by migration 026's
    # UNIQUE(entry_id, generation) reservation, but that is taken when the row
    # is WRITTEN and says nothing about how many times an existing row is
    # DELIVERED. Measured: two writers, one escalation row, TWO "this device
    # appears to be following you" notifications.
    claim_lost = False
    try:
        attempts = db.record_alert_notify_attempt(
            alert_id, expected_attempts=expected_attempts
        )
        if attempts is None:
            claim_lost = True
    except Exception as e:
        logger.warning(
            "Failed to record notify attempt for watchful escalation %s "
            "(sending anyway): %s",
            alert_id,
            e,
        )
        attempts = 0
    if claim_lost:
        # A definite loss, not an error: another writer is delivering this
        # escalation, or it already arrived. Returning False is honest -- THIS
        # call did not deliver it -- and no caller treats that as a reason to
        # re-emit a row.
        logger.debug(
            "watchful escalation %s for %s: a concurrent writer claimed this "
            "delivery",
            alert_id,
            mac,
        )
        return False
    try:
        ok = notifier.send(
            severity="high",
            title="lynceus: watchful escalation",
            message=body,
            priority_override=4,
        )
    except Exception as e:
        logger.warning(
            "Notifier raised for watchful escalation %s: %s", mac, e
        )
        return False
    if not ok:
        logger.warning(
            "Watchful escalation for %s NOT delivered (attempt %d/%d)%s",
            mac,
            attempts,
            NOTIFY_MAX_ATTEMPTS,
            ""
            if attempts < NOTIFY_MAX_ATTEMPTS
            else " -- giving up; the operator has NOT been told this device "
            "keeps recurring",
        )
        return False
    try:
        db.mark_alert_notified(alert_id, now_ts=now_ts)
    except Exception as e:
        logger.warning(
            "Delivered watchful escalation %s but failed to stamp it "
            "(it may be re-sent once): %s",
            alert_id,
            e,
        )
    return True


def _retry_watchful_escalation(
    db: Database,
    notifier: Notifier,
    entry,
    now_ts: int,
) -> None:
    """Re-send an escalation the operator was never actually told about.

    ⭐ The main alert path gets its retry for free: the rule fires again next
    tick and the dedup lookup finds the undelivered row. The escalation has no
    such driver, because `escalate_watchful_recurrence` fires exactly once per
    entry. So the retry has to be driven by the thing that is still happening —
    seeing the device again.

    Bounded by the same NOTIFY_MAX_ATTEMPTS as everything else, and gated on the
    rule_type snooze: if the operator has silenced `watchful_recurrence`,
    retrying is still notifying.
    """
    escalated_at = getattr(entry, "escalated_at", None)
    if escalated_at is None:
        return
    try:
        # `since` is the escalation instant itself, so this finds that exact
        # alert without depending on a window constant that could age out.
        row = db.get_recent_alert_for_rule_and_mac(
            "watchful_recurrence", entry.mac, int(escalated_at)
        )
    except Exception as e:
        logger.warning("watchful escalation retry lookup failed for %s: %s", entry.mac, e)
        return
    if row is None or row.get("notified_at") is not None:
        return
    if row.get("notify_abandoned_at") is not None:
        # ⛔ ABANDONED means the operator RESET this entry while looking at
        # this escalation (`reset_watchful_recurrence`, Finding 50). The reset
        # stops the retry by clearing `escalated_at` -- "clearing escalated_at
        # is what removes the retry path" -- so anything still holding a
        # pre-reset copy of the entry can drive one send the reset was meant
        # to prevent. Checking the mark closes that regardless of who is
        # holding a stale entry, which the caller-side fix alone does not.
        return
    attempts = int(row.get("notify_attempts") or 0)
    if attempts >= NOTIFY_MAX_ATTEMPTS:
        return

    # ⭐ SPACE the attempts out. The retry driver is "we saw the device again",
    # which on a 5-minute poll fires every 5 minutes, so an unspaced retry burns
    # all four attempts inside twenty minutes -- against a phone that is out of
    # signal, which #62 notes is likeliest precisely while the operator is
    # moving. Four attempts covering one outage is a coin flip; four attempts
    # covering an hour is a retry.
    #
    # Derived from `notify_attempts` and the alert's own `ts` so it needs no
    # `last_attempt_at` column and therefore no migration: attempt 2 at +5min,
    # 3 at +15min, 4 at +45min from the escalation.
    #
    # ⛔ Finding 65. This arithmetic is only meaningful while the clock has not
    # moved BACKWARDS since the row was written. A Pi with no RTC -- this
    # project's stated target -- can boot days AHEAD, stamp the escalation with
    # that clock, and then be corrected by NTP. `since_alert` is negative from
    # then on, which is below every `required_wait`, so this gate returns on
    # every tick for as long as the original skew lasted. Measured with a 7-day
    # skew, against an identical un-skewed install:
    #
    #     CONTROL   no skew         escalation re-sends = 1
    #     TREATMENT clock corrected  escalation re-sends = 0   (~7 days)
    #
    # ⭐ A future `ts` relative to the CURRENT clock means precisely "the clock
    # moved backwards since the write" -- if it were merely running ahead, both
    # values would be ahead together and the spacing would work. So in this
    # state the elapsed-time reasoning is not slightly wrong, it is void, and
    # suppressing on it is asserting a wait that was never measured.
    #
    # Delivering is the conservative direction HERE, which is the opposite of
    # the watchful COUNTING gate a few hundred lines up -- and deliberately so.
    # There, a bad clock FABRICATES evidence, so skipping is safe. Here the row
    # already exists and the operator has already not been told; the only thing
    # at stake is whether the most serious message this product sends is
    # delivered or silently held for days.
    #
    # ⚠️ Bounded, not fail-open: NOTIFY_MAX_ATTEMPTS still caps the retries, so
    # a persistently backwards clock costs at worst the remaining attempts
    # spent sooner rather than an unbounded resend loop.
    row_ts = int(row["ts"])
    since_alert = now_ts - row_ts
    required_wait = WATCHFUL_RETRY_BASE_SECONDS * (3 ** (attempts - 1))
    if row_ts <= now_ts and attempts >= 1 and since_alert < required_wait:
        return

    if db.is_rule_type_snoozed("watchful_recurrence", now_ts) is not None:
        return
    logger.info(
        "retrying undelivered watchful escalation for %s (alert %s)",
        entry.mac,
        row["id"],
    )
    _deliver_watchful_escalation(
        db,
        notifier,
        alert_id=int(row["id"]),
        mac=entry.mac,
        body=str(row["message"]),
        now_ts=now_ts,
        # The claim must be keyed on the value THIS retry decided from, so a
        # second writer that read the same row loses it.
        expected_attempts=attempts,
    )


def build_kismet_client(config: Config) -> KismetClient:
    if config.kismet_fixture_path:
        return FakeKismetClient(config.kismet_fixture_path)
    return KismetClient(
        config.kismet_url,
        api_key=config.kismet_api_key,
        timeout=config.kismet_timeout_seconds,
    )


def process_observation(
    obs,
    db,
    config,
    now_ts,
    *,
    effective_location_id,
    effective_location_label,
    ensured_locations,
    processed_counter,
    admitted_counter,
    ruleset,
    allowlist,
    notifier,
    clock_trusted: bool,
    severity_overrides=None,
    rule_type_suppression_counter=None,
) -> None:
    """Persist one observation and run its alert pipeline.

    Extracted from poll_once; accumulators are mutated in place.

    ``clock_trusted`` is REQUIRED and deliberately has no default. Watchful
    recurrence counting is arithmetic on wall-clock differences, so a caller
    that has not thought about clock trust must not be able to inherit a
    permissive one by omission -- the same structural-gate reasoning that made
    ``now_ts`` required for retention and evidence pruning.
    """
    existing_device = db.get_device(obs.mac)
    is_new = existing_device is None
    if effective_location_id not in ensured_locations:
        db.ensure_location(effective_location_id, effective_location_label)
        ensured_locations.add(effective_location_id)
    db.upsert_device(
        mac=obs.mac,
        device_type=obs.device_type,
        oui_vendor=obs.oui_vendor,
        is_randomized=int(obs.is_randomized),
        now_ts=now_ts,
        ble_device_class=obs.ble_device_class,
    )
    if config.capture.probe_ssids and obs.probe_ssids:
        stored, truncated = db.merge_device_probe_ssids(obs.mac, obs.probe_ssids)
        if truncated:
            logger.warning(
                "probe_ssids cap reached for %s: stored=%d cap=%d",
                obs.mac,
                stored,
                db.PROBE_SSIDS_PER_DEVICE_CAP,
            )
    if config.capture.ble_friendly_names and obs.ble_local_name:
        db.update_device_ble_name(obs.mac, obs.ble_local_name)
    # ⛔ `obs.last_seen` is bounded BELOW at parse (`first_seen` has a `> 0`
    # validator and `last_seen` inherits the same floor) and NOT ABOVE, so a
    # capture source with a corrupt clock can hand us any future timestamp.
    # Measured with `last_time = 4102444800` (year 2100), which the parser
    # accepts:
    #
    #   stored          : [1693088000, 4102444800]
    #   30-day prune    : deleted=1, remaining=[4102444800]
    #   seen last 24h   : 1
    #
    # ⚠️ The prune deleted the LEGITIMATE 40-day-old row and kept the bogus
    # one. A future `ts` is immune to retention forever AND satisfies every
    # recent-window query, so it also contaminates the co-observation corpus.
    #
    # ⭐ CLAMP rather than reject. The device really was seen -- only the
    # source's opinion of when is wrong -- and for a stalking-detection tool,
    # discarding a real detection is the worse error. `now_ts` is the honest
    # answer to "when did we observe this": it is the reading the rest of this
    # tick already uses. The tolerance matches the clock-jump one so the two
    # notions of "close enough to now" cannot drift apart.
    observed_at = obs.last_seen
    if observed_at > now_ts + CLOCK_JUMP_TOLERANCE_SECONDS:
        logger.warning(
            "capture source reported %s seen at %d, which is %ds in the "
            "future (clock skew on the source?); recording it as %d instead. "
            "A future timestamp would never be pruned and would count as "
            "'seen recently' forever.",
            obs.mac,
            observed_at,
            observed_at - now_ts,
            now_ts,
        )
        observed_at = now_ts
    db.insert_sighting(
        mac=obs.mac,
        ts=observed_at,
        rssi=obs.rssi,
        ssid=obs.ssid,
        location_id=effective_location_id,
    )
    processed_counter[0] += 1
    admitted_counter[0] += 1
    matched_allowlist_entry = allowlist.is_allowed(obs, now_ts=now_ts)
    if matched_allowlist_entry is not None:
        logger.debug("allowlisted, suppressing alerts: %s", obs.mac)
        # Audit pass: re-evaluate rules ONLY to record any watchlist
        # hits the allowlist just suppressed. Operators with write
        # access to the allowlist can otherwise silently disable a
        # watchlist rule by adding the matching device — this INFO
        # line gives them a journalctl trail. Cost is bounded by
        # the allowlist size (operator-curated, typically small).
        suppressed_hits = evaluate(
            ruleset,
            obs,
            is_new_device=is_new,
            db=db,
            severity_overrides=severity_overrides,
        )
        # Snooze entries carry an ``expires_at`` so the audit line
        # makes it obvious in journalctl which suppressions are
        # temporary vs permanent. Operators grepping for the
        # existing "Allowlist suppressed watchlist hit:" prefix
        # still get a match — the suffix appends after severity.
        expires_suffix = ""
        if matched_allowlist_entry.expires_at is not None:
            expires_iso = _dt.datetime.fromtimestamp(
                matched_allowlist_entry.expires_at, tz=_dt.UTC
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
            expires_suffix = f" (expires {expires_iso})"
        # ⛔ A SOFT allowlist match may not silence an EXPLICIT watchlist hit.
        #
        # The pattern types split by who controls the matched value
        # (`allowlist.HARD_ALLOWLIST_PATTERN_TYPES`): a MAC/OUI/mac_range is a
        # property of the radio, while a local name, SSID, service UUID or
        # manufacturer id is FREE TEXT the device puts in its own
        # advertisement. Suppressing on the latter means "ignore anything that
        # SAYS it is X" -- and anything can say it is X.
        #
        # 🪤 Measured before this gate existed. Operator allowlists their own
        # headphones by name, which is the documented use of `ble_local_name`:
        #
        #     the real headphones                mac=aa:...:01  suppressed=YES
        #     AN ATTACKER broadcasting that name mac=de:...:99  suppressed=YES
        #     the same attacker, not spoofing    mac=de:...:99  suppressed=no
        #
        # An attacker only had to name themselves after something the operator
        # allowlisted, and the operator's own HIGH-severity watchlist entry for
        # that MAC went silent. In a tool whose job is noticing who is
        # following you, that is detection evasion rather than noise control.
        #
        # ⭐ This code already computed the answer and threw it away. The audit
        # pass below re-evaluates the rules purely to LOG the watchlist hits the
        # allowlist just silenced -- an INFO line that exists precisely because
        # someone judged those events to matter. Turning that log line into a
        # decision is the whole change.
        #
        # ⛔ Deliberately NOT "ignore soft entries entirely": a soft match still
        # suppresses ambient noise (`new_non_randomized_device`), which is the
        # legitimate everyday use. Only an explicit watchlist hit overrides it.
        soft_match = is_soft_attribute(matched_allowlist_entry.pattern_type)
        watchlist_hits = [
            sh for sh in suppressed_hits
            if sh.rule_type != "new_non_randomized_device"
        ]
        if soft_match and watchlist_hits:
            logger.warning(
                "Allowlist entry matched a SPOOFABLE attribute (%s=%r) on a "
                "device with %d watchlist hit(s); NOT suppressing them. A "
                "device chooses this value itself, so it cannot silence an "
                "explicit watchlist entry. mac=%s",
                matched_allowlist_entry.pattern_type,
                matched_allowlist_entry.pattern,
                len(watchlist_hits),
                obs.mac,
            )
        else:
            for sh in watchlist_hits:
                logger.info(
                    "Allowlist suppressed watchlist hit: rule=%s mac=%s severity=%s%s",
                    sh.rule_name,
                    obs.mac,
                    sh.severity,
                    expires_suffix,
                )
            return
    # Watchful tracking gate (migration 018). Per the locked
    # gate-ordering decision -- allowlist -> watchful tracking
    # -> rule eval -> per-rule_type snooze -> per-alert snooze
    # -> emit -- watchful runs only for non-allowlisted
    # observations (the allowlist branch above continues on
    # match, so this code is unreachable for allowlisted
    # MACs). Operator semantic: allowlist precedence wins,
    # an allowlisted MAC under watchful snooze sees no
    # sighting_count increment and no escalation.
    #
    # Fast-path skip: the get_active_watchful_recurrence_by_mac
    # lookup is a single indexed point query and returns None
    # immediately when the table is empty (typical steady
    # state). Backward-compat: poll cycles with no tracking
    # entries are byte-identical to pre-rc6 behavior.
    #
    # ⛔ GATED on `clock_trusted`. Recurrence is a claim about ELAPSED TIME --
    # `record_watchful_sighting` counts an observation only when
    # `now_ts - last_seen_at >= 24h` -- so an untrustworthy clock cannot
    # produce a trustworthy count. Measured on an ungated build:
    #
    #   +24h jump  -> sighting_count 1->2, counted=True   (a recurrence that
    #                 never happened; four of these cross the escalation
    #                 threshold and tell the operator they are being followed)
    #   +91d jump  -> last_seen_at written 91 days AHEAD, after which real
    #                 sightings counted again only from day 92
    #
    # ⚠️ Three harms, and the second is the one that matters most for this
    # product: fabricated evidence, ~92 days of SILENCE while a device that
    # genuinely is following the operator goes uncounted, and a permanent
    # `escalated_at` that does not heal when the clock is corrected.
    #
    # ⭐ Round 7's sweep sanctioned "destructive operations" -- DELETEs and
    # archives -- and missed this because it is a state-ADVANCING write.
    # Writing a wrong value is as damaging as deleting a right one.
    #
    # Skipping is the conservative direction here, unlike the heartbeat's
    # deliberate fail-toward-sending. But be honest about what it costs, because
    # the first draft of this comment was not:
    #
    # ⚠️ A skipped count is NOT simply "recoverable on the next sighting". There
    # may be no next sighting; a later call adds one count, it does not
    # reconstruct the ones that were skipped; and if the entry sat at 3, a
    # genuine threshold-crossing sighting produces no warning at the moment the
    # operator most needs it. The trade is a DELAYED-or-LOST true escalation
    # against a FABRICATED one, and it is chosen only because a false "you are
    # being followed" alert is unrecoverable -- `escalated_at` is permanent, and
    # the operator's trust in the tool is more so.
    #
    # ⛔ RESIDUAL, not fixed here: `ClockAnchor` re-anchors after
    # CLOCK_JUMP_MAX_HOLDS consecutive divergent ticks and then reports the
    # jumped clock as trusted. A clock that stays wrong therefore resumes
    # poisoning recurrence state from the 4th tick onward. That fail-open is a
    # deliberate system-wide decision (an unbounded hold is the other broken
    # extreme) and cannot be undone from here -- the honest fix is to measure
    # recurrence gaps monotonically rather than from the wall clock, which
    # `last_seen_at` being persisted across restarts makes non-trivial. This
    # gate removes the transient-jump case, which is the common one; it does
    # not make recurrence counting clock-proof.
    watchful_entry = None
    if clock_trusted:
        watchful_entry = db.get_active_watchful_recurrence_by_mac(obs.mac)
    if watchful_entry is not None:
        outcome = db.record_watchful_sighting(watchful_entry.id, now_ts)
        if outcome is not None:
            # Threshold detection.
            #
            # ⛔ `escalated_at` is STAMPED ONLY ONCE THE ALERT ROW EXISTS, and
            # the ordering is the whole fix. It used to be stamped first, with
            # `escalate_watchful_recurrence`'s idempotency standing in for a
            # first-crossing guard -- so a `db.add_alert` that raised (sqlite
            # "database is locked" is reachable here: the web UI is a separate
            # process writing this same file) left the entry marked escalated
            # with no alert row. `escalate_watchful_recurrence` fires once per
            # entry, and `_retry_watchful_escalation` returns early when it
            # cannot find the row, so NOTHING re-drove it. Measured, on a
            # FOREVER watchful snooze where the escalation is the only signal
            # that can arrive, across 8 further days of daily sightings:
            #
            #   healthy DB          esc rows 1  delivered 1  heartbeat: healthy
            #   DELIVERY fails(#74) esc rows 1  delivered 0  heartbeat: UNHEALTHY
            #   the WRITE fails     esc rows 0  delivered 0  heartbeat: healthy
            #
            # ⚠️ The last row is the defect: it is byte-identical to the healthy
            # install on the operator's only health channel. #74's failure mode
            # leaves an undelivered ROW, which `count_undelivered_alerts` sees;
            # this one leaves nothing to count. The single most important
            # message this product sends -- that someone appears to be
            # following you -- was lost silently and permanently.
            #
            # ⭐ Same principle the main alert path already applies one gate
            # down ("dedup on DELIVERY, not on row existence") and that #74
            # applied to the stamp: do not record the state that suppresses the
            # retry until the thing it claims happened actually happened.
            #
            # ⚠️ `outcome.counted` is deliberately NOT part of this condition.
            # Counting is debounced to once per 24h; the escalation is due
            # whenever the count has reached the threshold and the entry has not
            # escalated yet. Requiring `counted` made the earliest possible
            # recovery the next COUNTED sighting, i.e. up to 24h away, when the
            # device is in front of the sensor every poll. `escalated_at is
            # None` is the guard that keeps this firing once.
            if (
                outcome.entry.sighting_count
                >= Database.WATCHFUL_RECURRENCE_ESCALATION_THRESHOLD
                and outcome.entry.escalated_at is None
            ):
                # ⭐ Finding 44: `escalated_at IS NULL` alone cannot tell "this
                # generation has never escalated" from "it escalated and the
                # stamp did not land". Migration 026's ledger can, so ask it
                # BEFORE consulting the snooze -- a recovery is not a
                # suppression, and counting it as one would put the
                # highest-severity thing this product sends into the hourly
                # snooze summary for an escalation the snooze never touched.
                generation = outcome.entry.reset_count
                ledger = _watchful_generation_escalated_at(
                    db, watchful_entry.id, generation, obs.mac
                )
                emitted_at = None if ledger is _LEDGER_UNREADABLE else ledger
                # Only a genuine first crossing consults the snooze. Reading it
                # on the recovery path would be a wasted query whose answer is
                # never used.
                #
                # ⛔ An UNREADABLE ledger must also skip it, and this is a
                # correctness requirement rather than an optimisation. The
                # snooze branch stamps `now_ts` without consulting the ledger,
                # so if a row is already pending at an earlier `ts` the retry's
                # `ts >= escalated_at` filter can never find it again -- the
                # permanent-undeliverability bug, reached through the degraded
                # path instead of the ordinary one. Falling through to the emit
                # path instead puts the UNIQUE constraint back in authority.
                rt_snooze = (
                    db.is_rule_type_snoozed("watchful_recurrence", now_ts)
                    if (emitted_at is None and ledger is not _LEDGER_UNREADABLE)
                    else None
                )
                if emitted_at is not None:
                    # Recovery: the alert row exists, nothing new is emitted,
                    # and the stamp is what re-enables the delivery retry path.
                    #
                    # ⛔ Stamped with the ORIGINAL escalation instant, never
                    # `now_ts`, and this is the difference between a recovered
                    # escalation and a permanently lost one. The retry path
                    # feeds `escalated_at` to `get_recent_alert_for_rule_and_mac`
                    # as `since_ts`, which filters `ts >= since_ts`. A stamp
                    # written at recovery time sits DAYS after the alert row's
                    # own `ts`, so the lookup would never match that row again
                    # and the escalation could never be delivered -- with the
                    # entry looking fully escalated on every surface.
                    #
                    # ⭐ And the retry is driven HERE, in the same observation,
                    # rather than left to the next sighting. The branch below
                    # is an `elif`, so without this call a crash between the
                    # committed write and the send costs an extra sighting
                    # before the operator is told -- and if the device is never
                    # seen again, they are not told at all. Pre-fix that case
                    # re-emitted a duplicate, which was noisy but reached them.
                    try:
                        recovered = db.escalate_watchful_recurrence(
                            watchful_entry.id,
                            emitted_at,
                            expected_reset_count=generation,
                        )
                    except Exception as e:
                        recovered = None
                        logger.warning(
                            "Could not recover the escalated stamp for %s "
                            "(the escalation itself was already emitted and "
                            "is not re-sent): %s",
                            obs.mac,
                            e,
                        )
                    if recovered is not None:
                        _retry_watchful_escalation(
                            db, notifier, recovered, now_ts
                        )
                elif rt_snooze is None:
                    # First crossing, and not suppressed. Subject only to the
                    # per-rule_type snooze on watchful_recurrence (per design
                    # doc: detection runs; notification doesn't, while the
                    # snooze is active).
                    # Stamp only if the row was written. A None here means the
                    # write failed, so the entry stays unescalated and the next
                    # sighting retries the whole emit. The value is the instant
                    # to stamp -- `now_ts` for a fresh write, the ORIGINAL
                    # escalation instant when the constraint caught a repeat
                    # that the pre-check was unavailable to spot.
                    stamp_at = _emit_watchful_escalation(
                        db, notifier, outcome.entry, now_ts
                    )
                    if stamp_at is not None:
                        # ⭐ Finding 44 is CLOSED here, and this comment used to
                        # say the opposite. The row write and this stamp are
                        # still two transactions and a failure BETWEEN them
                        # still leaves a row with no stamp -- what changed is
                        # that the row write now also reserves
                        # (entry_id, reset_count) in `watchful_escalations`, in
                        # the SAME transaction. So the next sighting re-takes
                        # this branch, finds the reservation, and recovers the
                        # stamp instead of emitting a second "this device
                        # appears to be following you". Cost is zero duplicates,
                        # not the one this used to be bounded at.
                        #
                        # ⛔ Still guarded, and the reason is unchanged:
                        # bookkeeping must not cost the rest of the observation,
                        # the same rule the notify counter and the notified
                        # stamp already follow on the main path. An unguarded
                        # raise here abandons every remaining hit on this
                        # device, and the alert has ALREADY been delivered by
                        # this point. What the guard now costs is a delayed
                        # stamp rather than a duplicate alert.
                        try:
                            stamped = db.escalate_watchful_recurrence(
                                watchful_entry.id,
                                stamp_at,
                                expected_reset_count=generation,
                            )
                        except Exception as e:
                            stamped = None
                            logger.warning(
                                "Delivered the watchful escalation for %s but "
                                "failed to stamp the entry as escalated (the "
                                "next sighting recovers the stamp): %s",
                                obs.mac,
                                e,
                            )
                        # A no-op on a fresh emit -- the row was just marked
                        # delivered, so the retry returns on its first check.
                        # It matters when `stamp_at` came from the ledger: that
                        # row may never have been sent, and this is what tells
                        # the operator without waiting for another sighting.
                        if stamped is not None:
                            _retry_watchful_escalation(
                                db, notifier, stamped, now_ts
                            )
                else:
                    # ⛔ The snooze CONSUMES the escalation -- stamp it, per
                    # the design doc's "detection runs, notification does
                    # not". That stamp is also what keeps "no alert row"
                    # unambiguous: without it, a snoozed escalation and a
                    # failed write are indistinguishable afterwards, and
                    # any recovery built on "escalated but no row" would
                    # resurrect the alert the operator deliberately
                    # silenced the moment their snooze expired.
                    db.escalate_watchful_recurrence(
                        watchful_entry.id,
                        now_ts,
                        expected_reset_count=generation,
                    )
                    logger.debug(
                        "watchful escalation suppressed by "
                        "rule_type snooze: mac=%s",
                        obs.mac,
                    )
                    # ⛔ Count it. The ordinary rule_type-snooze branch
                    # increments this counter and the escalation branch did
                    # not, so the hourly suppression summary — the line an
                    # operator greps to see what their snoozes are actually
                    # catching — silently omitted the highest-severity
                    # suppression the product can make. Measured: an
                    # escalation reached and suppressed, summary reports {}.
                    if rule_type_suppression_counter is not None:
                        rule_type_suppression_counter["watchful_recurrence"] = (
                            rule_type_suppression_counter.get(
                                "watchful_recurrence", 0
                            )
                            + 1
                        )
            elif outcome.entry.escalated_at is not None:
                # ⛔ `outcome.entry`, NOT the `watchful_entry` read above. The
                # `if` decides from the row as it is INSIDE
                # `record_watchful_sighting`'s transaction and this `elif`
                # decided from the row as it was BEFORE it -- two sources, one
                # decision. An operator RESET landing between them is where
                # they disagree: reset clears `escalated_at` exactly so this
                # retry stops, and the stale copy drove it anyway. Measured on
                # a reset applied at the seam, against a control that resets
                # first: control 0 sends, treatment 1 -- an escalation the
                # operator had just cleared, re-sent from the row the reset had
                # marked abandoned.
                #
                # ⭐ Already escalated, meaning the alert ROW EXISTS (the branch
                # above stamps only after a successful write). If that
                # escalation never actually REACHED the operator, this is the
                # only thing that will drive a re-send -- the first-crossing
                # branch above is guarded on `escalated_at is None` and so is
                # gone for good once stamped.
                #
                # ⚠️ A FAILED WRITE is the other case and it does NOT come here:
                # it leaves `escalated_at` NULL, so the branch above retries the
                # write itself. Keeping those two recoveries separate is what
                # stops a snoozed escalation -- also stamped, also without a row
                # until the snooze is checked -- from being resurrected here.
                #
                # Deliberately outside the `outcome.counted` test: counting is
                # debounced to once per 24h, and a bounded four attempts spread
                # a day apart is not a retry, it is a coin flip. Driven instead
                # by the thing that is still happening -- seeing the device.
                # No-ops immediately (one indexed lookup) once the alert is
                # stamped delivered, which is the steady state.
                _retry_watchful_escalation(
                    db, notifier, outcome.entry, now_ts
                )
            # snooze_expires_at on the watchful entry gates
            # the ORIGINAL alert pipeline for this MAC (per
            # OQ-3). The escalation alert above is
            # independent of this gate -- the operator's
            # whole point is "tell me if it keeps showing
            # up", which the escalation answers regardless
            # of the snooze window.
            snooze_expires_at = outcome.entry.snooze_expires_at
            snooze_active = (
                snooze_expires_at is None
                or snooze_expires_at > now_ts
            )
            if snooze_active:
                logger.debug(
                    "watchful snooze suppressing original alerts: mac=%s",
                    obs.mac,
                )
                return
    hits = evaluate(
        ruleset,
        obs,
        is_new_device=is_new,
        db=db,
        severity_overrides=severity_overrides,
    )
    matched_watchlist_id: int | None = None
    if any(h.rule_type != "new_non_randomized_device" for h in hits):
        matched_watchlist_id = db.resolve_matched_watchlist_id(
            mac=obs.mac,
            ssid=obs.ssid,
            ble_service_uuids=obs.ble_service_uuids,
            ble_manufacturer_id=obs.ble_manufacturer_id,
            drone_id_prefix=obs.drone_id_prefix,
            ble_local_name=obs.ble_local_name,
        )
    for hit in hits:
        # Rule_type snooze gate. Sequenced BEFORE dedup because
        # snooze is the wider / stronger statement: "no emits
        # from this rule_type at all". Skipping dedup avoids
        # writing a recent-alert lookup we'd discard anyway.
        # The RuleHit is intentionally still produced upstream
        # (rule.evaluate ran, /rules statistics see the rule
        # firing in the sense it would have); only the alert
        # row + evidence capture + notifier hop are gated. The
        # in-process counter accumulates per rule_type so the
        # Poller's periodic INFO summary can break suppression
        # activity down — operators grepping journalctl see
        # which rule_types the snooze is actually catching.
        snooze = db.is_rule_type_snoozed(hit.rule_type, now_ts)
        if snooze is not None:
            logger.debug(
                "rule_type snooze suppressed emit: rule=%s rule_type=%s mac=%s",
                hit.rule_name,
                hit.rule_type,
                hit.mac,
            )
            if rule_type_suppression_counter is not None:
                rule_type_suppression_counter[hit.rule_type] = (
                    rule_type_suppression_counter.get(hit.rule_type, 0) + 1
                )
            continue
        # ⭐ Dedup on DELIVERY, not on row existence. Wave 5 Finding 12: the
        # row was committed before the send was attempted and this gate keyed
        # on the row, so a send that failed suppressed its own retry for the
        # whole window -- at the default 3600s, one transient blip cost an
        # hour of alerting for this device+rule.
        #
        # Three states, and collapsing any two of them reintroduces a defect:
        #   delivered in-window        -> suppress; the operator knows.
        #   undelivered, attempts left -> RETRY THE EXISTING ROW. Emitting a
        #                                 new one instead would fill /alerts
        #                                 with duplicates of one detection
        #                                 every time ntfy was briefly down.
        #   undelivered, attempts spent-> suppress the retry, but leave
        #                                 notified_at NULL so /settings can
        #                                 still report it as undelivered.
        retry_alert: dict | None = None
        if config.alert_dedup_window_seconds > 0:
            since = now_ts - config.alert_dedup_window_seconds
            recent = db.get_recent_alert_for_rule_and_mac(hit.rule_name, hit.mac, since)
            if recent is not None:
                if recent.get("notified_at") is not None:
                    logger.debug("dedup-skip %s/%s", hit.rule_name, hit.mac)
                    continue
                if int(recent.get("notify_attempts") or 0) >= NOTIFY_MAX_ATTEMPTS:
                    logger.debug(
                        "dedup-skip %s/%s (undelivered, %d attempts spent)",
                        hit.rule_name,
                        hit.mac,
                        NOTIFY_MAX_ATTEMPTS,
                    )
                    continue
                retry_alert = recent
                logger.info(
                    "retrying undelivered notification for %s/%s (alert %s, attempt %d)",
                    hit.rule_name,
                    hit.mac,
                    recent["id"],
                    int(recent.get("notify_attempts") or 0) + 1,
                )
        hit_match_id = (
            matched_watchlist_id if hit.rule_type != "new_non_randomized_device" else None
        )
        if retry_alert is not None:
            # Reuse the row; do NOT re-capture evidence, which is keyed to the
            # original alert id and already stored.
            new_alert_id = int(retry_alert["id"])
        else:
            try:
                if config.alert_dedup_window_seconds > 0:
                    # ⛔ Finding 58. The dedup above is a READ; this is the
                    # WRITE, and the read is not true any more by the time we
                    # get here if another writer inserted in between.
                    # `process_observation` runs in the poll loop AND in the
                    # `ble-bridge` thread, which holds its own `Database` on
                    # its own connection, so the per-instance lock does not
                    # serialise them. Measured, one detection to both writers:
                    # sequential 1 alert / 1 send, interleaved 2 alerts /
                    # 2 sends. The conditional insert re-asserts "nothing
                    # recent" inside the INSERT itself.
                    #
                    # ⚠️ Only THIS arm. The retry arm above reuses the existing
                    # row deliberately; routing it through here would turn a
                    # re-send into a silent skip and reinstate Wave 5
                    # Finding 12.
                    new_alert_id = db.add_alert_if_none_since(
                        ts=now_ts,
                        rule_name=hit.rule_name,
                        mac=hit.mac,
                        message=hit.message,
                        severity=hit.severity,
                        matched_watchlist_id=hit_match_id,
                        rule_type=hit.rule_type,
                        since_ts=now_ts - config.alert_dedup_window_seconds,
                    )
                    if new_alert_id is None:
                        # Another writer alerted for this rule+mac inside the
                        # window while we were deciding. It notifies; we must
                        # not, or the operator hears about one detection twice.
                        logger.debug(
                            "dedup-skip %s/%s (a concurrent writer alerted "
                            "first)",
                            hit.rule_name,
                            hit.mac,
                        )
                        continue
                else:
                    new_alert_id = db.add_alert(
                        ts=now_ts,
                        rule_name=hit.rule_name,
                        mac=hit.mac,
                        message=hit.message,
                        severity=hit.severity,
                        matched_watchlist_id=hit_match_id,
                        rule_type=hit.rule_type,
                    )
            except Exception as e:
                # ⛔ Do NOT swallow this. The rule has already MATCHED: a
                # watchlisted device is in range and the operator has not been
                # told. Logging a warning and moving on discards a confirmed
                # hit, and because the device and sighting rows were written
                # just above (upsert_device, insert_sighting), the tick looks
                # entirely normal afterwards.
                #
                # Measured before this change, with add_alert raising sqlite's
                # "database is locked" on a real fixture device:
                #
                #     healthy : 5 devices, 5 sightings, 1 alert, 1 notification
                #     failing : 5 devices, 5 sightings, 0 alerts, 0 notifications
                #               watermark holds = 0, watermark ADVANCED
                #
                # Holds staying at 0 is the part that makes it permanent: the
                # watermark moves past the window, so Kismet is never asked for
                # it again and the hit cannot come back on a later tick.
                #
                # Raising instead hands this to the persist-failure path the
                # caller already has (see `failed_last_seen` in poll_once),
                # which holds the watermark and retries the window — bounded by
                # POLL_WATERMARK_MAX_HOLDS, so a genuinely poisonous record
                # still cannot livelock the daemon.
                #
                # ⚠️ The cost: the retry re-inserts a sighting for a device
                # whose sighting already landed, because the sighting write
                # precedes the alert write. That duplicate is already the
                # accepted behaviour for every OTHER post-sighting failure on
                # this path; this change makes alert-write failures consistent
                # with it rather than introducing it. A duplicated sighting row
                # is a far cheaper error than a silently dropped alert.
                raise RuntimeError(
                    f"failed to write alert {hit.rule_name} for {hit.mac}: {e}"
                ) from e
        if (
            retry_alert is None
            and config.evidence_capture_enabled
            and obs.raw_record is not None
        ):
            capture_evidence(
                db,
                new_alert_id,
                hit.mac,
                obs.raw_record,
                now_ts=now_ts,
                capture=config.capture,
                store_gps=config.evidence_store_gps,
            )
        title = f"lynceus: {hit.severity.upper()} alert"
        suffix = ""
        device_category = None
        if hit_match_id is not None:
            try:
                md = db.get_metadata_by_watchlist_id(hit_match_id)
                suffix = build_metadata_suffix(md, oui_vendor=obs.oui_vendor)
                device_category = md.get("device_category") if md else None
            except Exception:
                suffix = ""
                device_category = None
        # Display-only at-a-glance device type, always appended: radio
        # category off the observation + Argus device_category off the
        # match (em-dash placeholder when absent, no inference).
        type_suffix = build_type_suffix(obs.device_type, device_category)
        # Count the attempt BEFORE making it. A send that hangs and is killed,
        # or one that raises in a way the except below cannot see, must still
        # burn an attempt -- otherwise the bound is not a bound and a wedged
        # notifier is retried on every tick forever.
        #
        # ⛔ But bookkeeping must NEVER cost a notification. This whole function
        # runs inside a per-observation try/except in poll_once, so an
        # unguarded raise here would abandon the observation entirely: no
        # notification for this hit, and none for any remaining hit on the same
        # device. Losing the counter costs at worst one extra retry later;
        # losing the send means the operator is never told, which is the exact
        # failure Finding 12 exists to close.
        #
        # ⛔ And the attempt is a CLAIM, which is what makes it safe to send.
        # The dedup decision above is a READ; on the retry arm nothing
        # re-asserted it at the send, so both writers could read one
        # undelivered row and both notify. Finding 58 closed that shape on the
        # INSERT arm only -- deliberately, since a conditional insert would
        # turn a re-send into a silent skip (Wave 5 Finding 12). The CAS is
        # the other half: the loser skips this instant, the WINNER is sending
        # right now, and a failed send leaves `notified_at` NULL so the next
        # tick retries. Nothing is swallowed for the window.
        #
        # `expected_attempts` is what the dedup read saw -- 0 on the fresh arm,
        # where `add_alert_if_none_since` has already made us the only writer
        # and the column is `NOT NULL DEFAULT 0` (migration 024).
        expected_attempts = (
            int(retry_alert.get("notify_attempts") or 0)
            if retry_alert is not None
            else 0
        )
        claim_lost = False
        try:
            attempts = db.record_alert_notify_attempt(
                new_alert_id, expected_attempts=expected_attempts
            )
            if attempts is None:
                claim_lost = True
        except Exception as e:
            logger.warning(
                "Failed to record notify attempt for alert %s (sending anyway): %s",
                new_alert_id,
                e,
            )
            attempts = 0
        if claim_lost:
            # ⚠️ A LOST CLAIM, never an error -- the two are deliberately
            # distinguishable, because a raise must still send.
            logger.debug(
                "send-skip %s/%s (alert %s: a concurrent writer claimed this "
                "delivery)",
                hit.rule_name,
                hit.mac,
                new_alert_id,
            )
            continue
        try:
            ok = notifier.send(
                severity=hit.severity,
                title=title,
                message=hit.message + suffix + type_suffix,
            )
            if ok:
                # ⭐ Only NOW is this alert deduplicatable. Until this row is
                # stamped, the next poll retries it rather than assuming the
                # operator was told (Wave 5 Finding 12).
                #
                # Guarded for the same reason as the counter above: this runs
                # inside poll_once's per-observation try/except. If the stamp
                # fails the delivery still happened, and the worst case is one
                # duplicate notification on the next poll -- strictly better
                # than abandoning the rest of this observation's hits.
                try:
                    db.mark_alert_notified(new_alert_id, now_ts=now_ts)
                except Exception as e:
                    logger.warning(
                        "Delivered alert %s but failed to stamp it as notified "
                        "(it may be re-sent once): %s",
                        new_alert_id,
                        e,
                    )
            else:
                logger.warning(
                    "Notifier returned False for %s/%s (alert %s, attempt %d/%d)%s",
                    hit.rule_name,
                    hit.mac,
                    new_alert_id,
                    attempts,
                    NOTIFY_MAX_ATTEMPTS,
                    "" if attempts < NOTIFY_MAX_ATTEMPTS else " -- giving up, alert UNDELIVERED",
                )
        except Exception as e:
            logger.warning(
                "Notifier raised for %s/%s (alert %s, attempt %d/%d): %s",
                hit.rule_name,
                hit.mac,
                new_alert_id,
                attempts,
                NOTIFY_MAX_ATTEMPTS,
                e,
            )


def effective_ble_flush_interval(config: Config) -> int:
    """Seconds between BLE bridge tick flushes, as the bridge will actually run.

    ⚠️ ONE derivation, deliberately. `_start_ble_bridge` passes this to the
    bridge and `_observe_ble_bridge` sizes the stall window from it; two copies
    of the same `or poll_interval_seconds` fallback would drift the moment one
    of them changed, and the failure would be a false "stalled" verdict on a
    healthy bridge — which is worse than the defect this window exists to catch.
    """
    configured = config.ble_bridge.flush_interval
    return int(configured if configured is not None else config.poll_interval_seconds)


def _compose_heartbeat(db: Database, config: Config, *, now_ts: int) -> tuple[bool, str]:
    """Build the heartbeat's (healthy, message) from MEASURED state.

    ⛔ The one invariant that matters: **this must never claim health it has
    not verified.** A heartbeat that says "all good" while ingest is dead is
    strictly worse than no heartbeat at all -- it converts an operator's vague
    unease into false confidence, on the one channel they rely on to be told
    that something is near them. Every clause below is derived from a value
    read out of the database on this tick; none of them defaults to healthy.

    🪤 "No devices seen" is deliberately NOT unhealthy. A quiet RF environment
    is the normal case for this tool and flagging it would train the operator
    to ignore the warning that matters. The signals that separate "nothing is
    out there" from "we stopped looking" are the tick clock and the persist
    watermark, so those -- not the device count -- decide `healthy`.
    """
    problems: list[str] = []

    # 1. Is the daemon actually completing poll ticks? Same 2x-interval
    #    convention as the /healthz.json poll check, so the two surfaces
    #    cannot disagree about what "stale" means.
    last_tick_raw = db.get_state(STATE_KEY_LAST_TICK_COMPLETED_AT)
    if last_tick_raw is None:
        problems.append("no poll tick has ever completed")
    else:
        age = now_ts - int(last_tick_raw)
        # ⛔ A NEGATIVE age means the recorded tick time sits in the FUTURE,
        # which no sane clock produces -- it is what a tick completed while the
        # clock was wrong-and-ahead leaves behind. A bare `age > threshold`
        # reads that as "extremely recent" and reports HEALTHY, so the staleness
        # check is disabled for the whole length of the excursion. Measured with
        # a +91d anchor and a poll loop that had stopped completing ticks for an
        # hour: healthy=True, "Still watching".
        #
        # ⚠️ That is the one thing this clause exists to catch. `retention.py`
        # and `evidence.py` both already guard the identical shape with
        # `0 <= elapsed`; this clause did not, and three siblings disagreeing
        # about the same impossible value is how it survived.
        if age < 0:
            problems.append(
                f"the last completed poll tick is recorded {-age}s in the "
                f"FUTURE (clock jump?); tick staleness cannot be judged"
            )
        elif age > 2 * config.poll_interval_seconds:
            problems.append(
                f"no poll tick for {age}s (expected every {config.poll_interval_seconds}s)"
            )

    # 2. Are observations actually reaching the database? A watermark held at
    #    the bound means persists are failing and capture data is being lost --
    #    the "silent pipeline death" case, where the process is alive, ingest
    #    has stopped, and today the only symptom is one ERROR line in a log
    #    nobody is tailing.
    holds = int(db.get_state(STATE_KEY_WATERMARK_HOLDS) or 0)
    if holds >= POLL_WATERMARK_MAX_HOLDS:
        problems.append(
            f"observations are failing to persist (watermark held {holds}x, "
            f"capture data is being lost)"
        )
    elif holds > 0:
        problems.append(f"{holds} observation(s) failed to persist since the last tick")

    # 3. Undelivered alerts mean the operator has already missed something.
    undelivered = db.count_undelivered_alerts()
    if undelivered:
        problems.append(f"{undelivered} alert(s) written but never delivered")

    # 4. Is the BLE bridge still alive? Clauses 1-3 all watch the KISMET path,
    #    so a dead bridge left this function reporting "still watching" while
    #    BLE-only devices -- the trackers and tags this tool exists to find --
    #    were not being seen at all, and stayed unseen until someone restarted
    #    the daemon. That is exactly the claim-health-you-have-not-verified
    #    failure the docstring above forbids, arriving through the one capture
    #    path none of the other clauses observe.
    #
    #    ⚠️ ABSENT means the bridge has never been enabled, which is the default
    #    and is NOT a fault; "stopped" is a clean shutdown and likewise is not.
    #    Only enabled-then-dead is a problem. The poll loop is the sole writer
    #    and only writes when the bridge is enabled.
    #
    #    ⚠️ "failed" and "stalled" get SEPARATE sentences. They have different
    #    causes and different remedies: "not running" tells the operator to
    #    check whether the bridge is up, and for a stalled bridge it IS up —
    #    they would find nothing wrong and learn to discount the warning. The
    #    stalled wording names the adapter instead, which is where to look.
    bridge_status = db.get_state(STATE_KEY_BLE_BRIDGE_STATUS)
    if bridge_status == BLE_BRIDGE_FAILED:
        problems.append(
            "the BLE bridge is not running (BLE-only devices, including "
            "trackers, are not being seen; Kismet capture is unaffected)"
        )
    elif bridge_status == BLE_BRIDGE_STALLED:
        problems.append(
            "the BLE bridge is up but has completed no scan for longer than "
            "expected — the adapter has most likely gone away (BLE-only "
            "devices, including trackers, are not being seen; Kismet capture "
            "is unaffected)"
        )

    # 5. Kismet reported devices and we admitted NONE of them.
    #
    # ⭐ Clause 4 above watches the BLE path; this one watches the KISMET path,
    # and they are the same failure arriving through the two different capture
    # routes: the daemon is up, the pipeline is not carrying anything, and
    # nothing else in this function can tell.
    #
    # ⛔ This closes the gap between this function's stated invariant and what
    # it did. Measured on main: a tick with 412 devices dropped by the source
    # allowlist and 0 admitted produced healthy=True and the message "Still
    # watching. 0 device sighting(s) in the last 24h" -- BYTE-IDENTICAL to what
    # an operator in a genuinely quiet area receives. So the one thing the
    # heartbeat exists to disambiguate, it did not.
    #
    # ⭐ "admitted == 0" alone stays HEALTHY, deliberately: a quiet RF
    # environment is not a fault, and alerting on it trains the operator to
    # ignore the channel. The signal is not silence, it is CONTRADICTION --
    # Kismet handed us devices and every one was discarded. That cannot be a
    # quiet site by construction, whatever the drop reason.
    #
    # ⚠️ Deliberately does not fire when admitted > 0. A config that drops most
    # devices but admits some is doing its job; second-guessing the operator's
    # own filter thresholds is not this function's business.
    def _tick_count(key: str) -> int:
        try:
            return int(db.get_state(key) or 0)
        except (TypeError, ValueError):
            # A malformed counter must not take the heartbeat down with it --
            # this function is what reports faults, so it has to survive them.
            return 0

    admitted = _tick_count(STATE_KEY_LAST_TICK_ADMITTED)
    discarded = {
        "source allowlist": _tick_count(
            STATE_KEY_LAST_TICK_DROPPED_SOURCE_ALLOWLIST
        ),
        "min_rssi": _tick_count(STATE_KEY_LAST_TICK_DROPPED_MIN_RSSI),
        "unparseable": _tick_count(STATE_KEY_LAST_TICK_DROPPED_UNPARSEABLE),
    }
    total_discarded = sum(discarded.values())
    if last_tick_raw is not None and admitted == 0 and total_discarded > 0:
        # Name the reason: "not watching" without a cause sends the operator
        # to the hardware, and the fault is almost always in their config.
        why = ", ".join(
            f"{n} by {reason}" for reason, n in discarded.items() if n
        )
        problems.append(
            f"every device Kismet reported was discarded ({why}); "
            f"lynceus is not watching anything"
        )

    healthy = not problems

    since_ts = now_ts - config.heartbeat_interval_hours * 3600
    seen = db.count_sightings_since(since_ts)
    window = f"{config.heartbeat_interval_hours}h"
    last_alert_ts = db.latest_alert_ts()
    if last_alert_ts is None:
        last_alert = "no alerts yet"
    else:
        hours = max(0, (now_ts - int(last_alert_ts)) // 3600)
        last_alert = f"last alert {hours}h ago"

    if healthy:
        return True, (
            f"Still watching. {seen} device sighting(s) in the last {window}, {last_alert}."
        )
    return False, (
        "NOT FULLY WATCHING — lynceus is running but: "
        + "; ".join(problems)
        + f". ({seen} sighting(s) in the last {window}, {last_alert}.)"
    )


def maybe_emit_heartbeat(
    db: Database,
    config: Config,
    notifier: Notifier | None,
    *,
    now_ts: int,
) -> bool:
    """Send the periodic proof-of-life if one is due, or retry an undelivered one.

    Returns True if a heartbeat was delivered on this call.

    ⭐ The interval clock runs from **delivery**, not from composition, and the
    retry rides the same three-state gate as alerts (024). A heartbeat built on
    the fire-and-forget path would inherit exactly the defect PR #19 fixed --
    and here it would be worse than it was for alerts, because a *missing*
    heartbeat is read as "the daemon is dead". An operator would go looking at
    hardware when the real fault was one transient ntfy blip.

    Called from ``poll_once`` on every tick; a no-op except once per interval,
    so it is cheap.
    """
    if not config.heartbeat_enabled or notifier is None:
        return False

    # ⛔ Bounded for the same reason as both scheduling lookups below: a
    # future-dated row must not shadow the newest real one in retry selection.
    latest = db.latest_heartbeat(not_after=now_ts)

    # An undelivered heartbeat with attempts left is retried before any new one
    # is composed -- the operator is owed the message that was already written,
    # and composing a second would leave the first stranded as undelivered
    # forever while saying the same thing.
    if latest is not None and latest.get("notified_at") is None:
        if int(latest.get("notify_attempts") or 0) >= NOTIFY_MAX_ATTEMPTS:
            # Attempts spent. Leave it undelivered so /settings still counts it,
            # and fall through to the interval check: if the next window has
            # come round, a fresh attempt with fresh state is more useful than
            # re-sending a stale one.
            logger.warning(
                "heartbeat %s undelivered after %d attempts; the operator has NOT "
                "been told the daemon is alive",
                latest["id"],
                NOTIFY_MAX_ATTEMPTS,
            )
        else:
            return _send_heartbeat(
                db, notifier, latest["id"], bool(latest["healthy"]),
                latest["message"], now_ts=now_ts, retry=True,
            )

    # ⛔ `not_after=now_ts` is load-bearing, not defensive tidiness. See the
    # future-anchor trap below.
    last_delivered = db.latest_delivered_heartbeat_ts(not_after=now_ts)
    interval = config.heartbeat_interval_hours * 3600

    # What the interval is measured from. Delivery is the honest reference --
    # a heartbeat nobody received has proved nothing -- but it cannot be the
    # ONLY one.
    #
    # 🪤 Caught by `test_retries_are_bounded`: with delivery as the sole
    # reference, a topic that is down when the very first heartbeat is composed
    # leaves `last_delivered` permanently None. Every subsequent tick then sees
    # "never delivered, interval trivially elapsed", composes a BRAND NEW row
    # and burns another four attempts -- a row and four blocking HTTP timeouts
    # per poll tick, forever. The bounded-retry logic above is defeated by
    # simply making a new thing to retry.
    #
    # 🪤 THE FUTURE-ANCHOR TRAP. Both lookups are clamped to `now_ts` because a
    # forward clock jump writes a heartbeat row stamped in the future, and
    # `latest_heartbeat` orders by `ts DESC` while `latest_delivered_...` takes
    # `MAX(notified_at)` -- so once the clock is corrected, that future row wins
    # every subsequent comparison. `elapsed` is then negative on EVERY tick,
    # which the `0 <= elapsed` test below deliberately treats as "send", and
    # nothing a normal-time tick writes can ever supersede it.
    #
    # ⭐ The comment below used to say a spurious heartbeat "costs one
    # notification". That reasoned about a transient BACKWARD jump and was
    # wrong about the case that actually happens: a FORWARD jump leaves a
    # permanent future anchor. Measured on a fixture before this clamp existed:
    # 300 corrected 60s ticks produced 300 sends -- one per tick, not one total
    # -- extrapolating to ~131,040 over a 91-day excursion. Clamping restores
    # the documented tradeoff: the future row is ignored for scheduling, so at
    # most one extra heartbeat is sent and normal cadence resumes immediately.
    # The row is still shown verbatim in the web UI, which reads unclamped
    # because an operator inspecting health should see the bad timestamp.
    reference = last_delivered
    if reference is None and latest is not None:
        # ⚠️ Leaving this as None is NOT a safe simplification: None means
        # "never sent one, send promptly", which composes a brand-new row on
        # every tick and defeats the bounded retry. Measured: 200 corrected
        # ticks, 200 new rows.
        #
        # This is safe only because `latest` was fetched with `not_after=now_ts`
        # above. Unbounded, it would be the future row itself.
        reference = int(latest["ts"])

    if reference is not None:
        elapsed = now_ts - reference
        # 🪤 `elapsed < interval` alone would stall the switch for the WHOLE
        # excursion if the wall clock jumped backward -- the dead-man's switch
        # going quiet is precisely the failure it exists to remove, and the
        # operator would read the silence as "the daemon is dead". Session 3
        # measured the same shape in retention.py:118 / evidence.py:324, where
        # a future anchor stalled pruning for 366 days.
        #
        # ⭐ Note the direction differs by subsystem, and that is the point:
        # an untrustworthy clock means "do NOT prune" for retention (fail
        # toward keeping data) but "DO send" here (fail toward noise). A
        # dead-man's switch must fail toward sending; a spurious heartbeat
        # costs one notification, a suppressed one costs the whole guarantee.
        if 0 <= elapsed < interval:
            return False
    # Never delivered one: send promptly rather than waiting a full interval.
    # This is the operator's confirmation that the switch is actually armed --
    # deferring it means a misconfigured ntfy topic is discovered a day later,
    # or never. A restart loop cannot spam the topic, because delivery stamps
    # `notified_at` and the interval gate above then applies across restarts.

    healthy, message = _compose_heartbeat(db, config, now_ts=now_ts)
    try:
        heartbeat_id = db.insert_heartbeat(ts=now_ts, healthy=healthy, message=message)
    except Exception as e:
        logger.warning("Failed to record heartbeat (not sending): %s", e)
        return False
    return _send_heartbeat(
        db, notifier, heartbeat_id, healthy, message, now_ts=now_ts, retry=False
    )


def _send_heartbeat(
    db: Database,
    notifier: Notifier,
    heartbeat_id: int,
    healthy: bool,
    message: str,
    *,
    now_ts: int,
    retry: bool,
) -> bool:
    """Attempt delivery of one heartbeat row, tracking the attempt either way.

    The attempt is counted BEFORE the send for the same reason as alerts: a
    hung or unkillable notifier must still burn one, or the bound is not a
    bound.
    """
    try:
        attempts = db.record_heartbeat_notify_attempt(heartbeat_id)
    except Exception as e:
        logger.warning(
            "Failed to record heartbeat attempt for %s (sending anyway): %s",
            heartbeat_id, e,
        )
        attempts = 0
    try:
        ok = notifier.send(
            # An unhealthy heartbeat is a real problem report, not an FYI, so
            # it does NOT ride the low-priority path the healthy one uses.
            severity="med" if not healthy else "low",
            title="lynceus: still watching" if healthy else "lynceus: NOT fully watching",
            message=message,
        )
    except Exception as e:
        logger.warning(
            "Notifier raised sending heartbeat %s (attempt %d/%d): %s",
            heartbeat_id, attempts, NOTIFY_MAX_ATTEMPTS, e,
        )
        return False
    if ok:
        try:
            db.mark_heartbeat_notified(heartbeat_id, now_ts=now_ts)
        except Exception as e:
            logger.warning(
                "Delivered heartbeat %s but failed to stamp it (it may be re-sent "
                "once): %s",
                heartbeat_id, e,
            )
        logger.info(
            "heartbeat %s delivered (%s)%s",
            heartbeat_id,
            "healthy" if healthy else "UNHEALTHY",
            " [retry]" if retry else "",
        )
        return True
    logger.warning(
        "Notifier returned False for heartbeat %s (attempt %d/%d)%s",
        heartbeat_id, attempts, NOTIFY_MAX_ATTEMPTS,
        "" if attempts < NOTIFY_MAX_ATTEMPTS else " -- giving up, heartbeat UNDELIVERED",
    )
    return False


def _report_impossible_watchful_snoozes(db: Database, now_ts: int) -> None:
    """Tell the operator about a watchful snooze that silently did nothing.

    ⛔ Reports each entry AT MOST ONCE, and the memory is durable. The sibling
    rule_type reporter gets that bound for free because the purge deletes the
    row immediately afterwards; watchful entries are never purged, so a naive
    port of it would re-emit the same warning on every poll cycle forever --
    which is the unbounded-repetition defect #139 already had to fix once, and
    which trains the operator to ignore the channel.

    ⛔ Phrased as a DISAGREEMENT, never as a verdict about which clock was
    wrong. `applied_at` is stamped by the same host clock, so a database
    migrated while the clock read AHEAD puts the floor above legitimate later
    writes. It also does NOT claim the snooze suppressed nothing: it may have
    been in force for the whole period before the clock was corrected.

    ⚠️ Never raises, and never changes state the operator can see. In
    particular it does NOT clear `snooze_expires_at`: NULL there means snoozed
    **FOREVER**, so "tidying up" an expired snooze would make it permanent.
    """
    try:
        found = db.find_impossible_watchful_snoozes(now_ts)
    except Exception as e:  # pragma: no cover -- the helper already swallows
        logger.warning("watchful snooze impossibility lookup failed: %s", e)
        return
    if not found:
        return
    try:
        raw = db.get_state(STATE_KEY_IMPOSSIBLE_WATCHFUL_REPORTED)
        reported = list(json.loads(raw)) if raw else []
    except Exception:
        # An unreadable or corrupt memory must not silence the warning; the
        # safe direction is to report again.
        reported = []
    seen = {int(x) for x in reported if isinstance(x, int | str) and str(x).isdigit()}

    fresh = [row for row in found if row.entry_id not in seen]
    if not fresh:
        return
    for row in fresh:
        # Per-row try: one unrenderable `created_at` (an out-of-range epoch from
        # a wildly wrong clock) must not raise out of the loop and take every
        # REMAINING warning with it. #139 fixed exactly that on the sibling.
        try:
            stamped = _dt.datetime.fromtimestamp(
                row.created_at, tz=_dt.UTC
            ).isoformat()
        except (OverflowError, OSError, ValueError):
            stamped = f"an unrenderable epoch value ({row.created_at})"
        logger.warning(
            "the %ds watchful snooze for %s may have run short: the entry is "
            "stamped %s, earlier than this database's own first migration, so "
            "the row and the schema history disagree about when it was written "
            "and at least one of the two clocks was wrong. Its deadline has "
            "passed on the current clock. Set it again if you still want it, "
            "and check this host's time source.",
            row.duration_seconds,
            row.mac,
            stamped,
        )
    try:
        remembered = (reported + [r.entry_id for r in fresh])[
            -IMPOSSIBLE_WATCHFUL_REPORT_MEMORY:
        ]
        db.set_state(
            STATE_KEY_IMPOSSIBLE_WATCHFUL_REPORTED, json.dumps(remembered)
        )
    except Exception as e:
        # The warning is already out. Failing to remember costs a repeat next
        # cycle, which is the safe direction.
        logger.warning(
            "could not record which impossible watchful snoozes were "
            "reported (they may be reported again): %s",
            e,
        )


def poll_once(
    client: KismetClient,
    db: Database,
    config: Config,
    now_ts: int,
    *,
    ruleset: Ruleset | None = None,
    allowlist: Allowlist | None = None,
    notifier: Notifier | None = None,
    source_allowlist: frozenset[str] | None = None,
    source_locations: dict[str, str] | None = None,
    severity_overrides: RuntimeSeverityOverride | None = None,
    rule_type_suppression_counter: dict[str, int] | None = None,
    clock_trusted: bool = True,
) -> int:
    """Run one poll tick: fetch from Kismet, persist sightings, evaluate rules.

    Allowlist precedence: a device matching a **HARD** allowlist entry (``mac``,
    ``mac_range``, ``oui`` -- properties of the radio itself) is suppressed
    regardless of any watchlist rules it would have matched. ⛔ A **SOFT** entry
    (``ble_local_name``, ``ssid``, uuid, manufacturer id -- free text the device
    chooses for itself) does **not** silence an explicit watchlist hit, because
    an attacker could otherwise suppress themselves by broadcasting a name the
    operator had allowlisted. See ``allowlist.HARD_ALLOWLIST_PATTERN_TYPES`` and
    the carve-out in ``process_observation``.

    ⚠️ This sentence used to read *"a device matching ANY allowlist entry is
    suppressed, regardless of any watchlist rules"*. That was true when written
    and stopped being true at #82, which introduced the hard/soft split -- the
    single most repeated defect shape on this project, and it survived here for
    the length of the whole hard/soft rollout.

    When suppression hides what would have been a watchlist hit, an INFO-level audit line is
    emitted so operators can review whether the allowlist is too permissive —
    silently disabling a watchlist rule by allowlisting the matching device
    is exactly the kind of misconfiguration the audit log is meant to surface.

    ``rule_type_suppression_counter`` accumulates per-rule_type
    suppression counts for the rule_type-snooze layer. The Poller
    instance owns the counter across poll cycles so the periodic
    INFO-summary log spans more than a single tick; tests pass an
    empty dict to inspect accumulation directly. ``None`` (the
    default, used by ad-hoc callers) means no accumulation — the
    gate still suppresses correctly; only the breakdown is dropped.
    """
    if ruleset is None:
        ruleset = Ruleset()
    if allowlist is None:
        allowlist = Allowlist()
    if notifier is None:
        notifier = NullNotifier()
    last_poll_str = db.get_state(STATE_KEY_LAST_POLL)
    last_poll_ts = int(last_poll_str) if last_poll_str else 0
    db.ensure_location(config.location_id, config.location_label)
    # ensure_location is a write transaction (INSERT ... ON CONFLICT DO
    # UPDATE) on every call. Track the location ids already ensured this
    # tick so the per-observation call below fires only for a genuinely-new
    # source_locations-remapped location -- not once per observation for the
    # common single-location case, which would re-commit the same row N
    # times a tick. Seeded with the default just ensured above.
    ensured_locations: set[str] = {config.location_id}
    # unparseable_counter is the only out-of-band signal the client
    # surfaces: parse_kismet_device returns None inside the client
    # (unknown device type, malformed mac, missing required field),
    # so the poller never sees the dropped raw record. Pass a mutable
    # single-element list so the count survives the call boundary.
    unparseable_counter: list[int] = [0]
    observations = client.get_devices_since(
        last_poll_ts,
        capture_probe_ssids=config.capture.probe_ssids,
        capture_ble_name=config.capture.ble_friendly_names,
        evidence_capture_enabled=config.evidence_capture_enabled,
        unparseable_counter=unparseable_counter,
    )
    processed = [0]
    admitted = [0]
    # last_seen of every observation that failed to persist this tick. Drives
    # the watermark decision at the end of poll_once.
    failed_last_seen: list[int] = []
    dropped_source_allowlist = 0
    dropped_min_rssi = 0
    # Per-tick aggregation of the source names that actually appeared on
    # dropped records. Lets the end-of-tick INFO line tell operators the
    # specific names Kismet is reporting so they can align kismet_site.conf
    # with lynceus.yaml without digging through DEBUG logs. Records with no
    # source attribution contribute nothing here (the empty-seenby branch
    # bumps dropped_source_allowlist on its own — the count is enough to
    # surface that case; there's no name to aggregate).
    dropped_sources_seen: set[str] = set()
    for obs in observations:
        try:
            if source_allowlist is not None:
                if not obs.seen_by_sources:
                    logger.debug(
                        "obs %s has no source attribution, dropping under source_allowlist",
                        obs.mac,
                    )
                    dropped_source_allowlist += 1
                    continue
                if not any(s in source_allowlist for s in obs.seen_by_sources):
                    logger.debug(
                        "obs %s sources %r not in allowlist, dropping",
                        obs.mac,
                        obs.seen_by_sources,
                    )
                    dropped_source_allowlist += 1
                    dropped_sources_seen.update(obs.seen_by_sources)
                    continue
            if config.min_rssi is not None and obs.rssi is not None and obs.rssi < config.min_rssi:
                logger.debug(
                    "obs %s rssi=%s below min_rssi=%s, dropping",
                    obs.mac,
                    obs.rssi,
                    config.min_rssi,
                )
                dropped_min_rssi += 1
                continue

            effective_location_id = config.location_id
            effective_location_label = config.location_label
            if source_locations is not None:
                for src in obs.seen_by_sources:
                    if src in source_locations:
                        effective_location_id = source_locations[src]
                        if effective_location_id != config.location_id:
                            effective_location_label = effective_location_id
                        break

            process_observation(
                obs,
                db,
                config,
                now_ts,
                effective_location_id=effective_location_id,
                effective_location_label=effective_location_label,
                ensured_locations=ensured_locations,
                processed_counter=processed,
                admitted_counter=admitted,
                ruleset=ruleset,
                allowlist=allowlist,
                notifier=notifier,
                clock_trusted=clock_trusted,
                severity_overrides=severity_overrides,
                rule_type_suppression_counter=rule_type_suppression_counter,
            )
        except Exception as e:
            # ⭐ Record WHEN this device was last seen, not just that it failed.
            # The watermark decision at the end of the tick needs the oldest
            # such timestamp: advancing past it is what loses the device for
            # good, because Kismet is never asked for that window again.
            failed_last_seen.append(obs.last_seen)
            logger.warning("Failed to persist observation %s: %s", obs.mac, e)
            continue
    dropped_unparseable = unparseable_counter[0]
    dropped_total = (
        dropped_source_allowlist + dropped_min_rssi + dropped_unparseable
    )
    # Self-documenting source_allowlist mismatch: when records dropped
    # under the gate this tick AND we collected at least one actual
    # source name from them, emit a single INFO line naming what
    # Kismet is reporting vs. what lynceus expects. The per-record
    # DEBUG line above (line ~218) still captures every drop for
    # forensic grepping at debug level; this is the operator-facing
    # signal that surfaces the mismatch at default log level. Bounded
    # to one INFO line per tick regardless of record count.
    if dropped_source_allowlist > 0 and dropped_sources_seen:
        allowlist_repr = (
            sorted(source_allowlist) if source_allowlist is not None else []
        )
        logger.info(
            "source_allowlist mismatch on tick: %d records seen by sources=%s "
            "not in allowlist=%s",
            dropped_source_allowlist,
            sorted(dropped_sources_seen),
            allowlist_repr,
        )
    # Heartbeat: emitted every tick regardless of values so a silent
    # daemon (Kismet down, all observations dropped at a single
    # threshold) is visible in journalctl. The three drop reasons map
    # one-to-one with the silent-drop sites — operators grepping for
    # "poll tick:" get the breakdown without needing DEBUG level.
    logger.info(
        "poll tick: %d admitted, %d dropped "
        "(source_allowlist=%d, min_rssi=%d, unparseable=%d)",
        admitted[0],
        dropped_total,
        dropped_source_allowlist,
        dropped_min_rssi,
        dropped_unparseable,
    )
    db.set_state(STATE_KEY_LAST_TICK_ADMITTED, str(admitted[0]))
    db.set_state(
        STATE_KEY_LAST_TICK_DROPPED_SOURCE_ALLOWLIST,
        str(dropped_source_allowlist),
    )
    db.set_state(STATE_KEY_LAST_TICK_DROPPED_MIN_RSSI, str(dropped_min_rssi))
    db.set_state(
        STATE_KEY_LAST_TICK_DROPPED_UNPARSEABLE, str(dropped_unparseable)
    )
    db.set_state(STATE_KEY_LAST_TICK_COMPLETED_AT, str(now_ts))

    # ⭐ The watermark. Advancing it unconditionally -- which is what this did
    # -- silently and PERMANENTLY loses any observation that failed to persist.
    #
    # Measured, with the device last seen five seconds before the tick that
    # processed it (the normal case: Kismet reports devices seen *during* the
    # window, and the watermark is set to the window's END):
    #
    #     device last seen at 1699999995; tick ran at 1700000000
    #     after poll 1: persisted=['01']  watermark=1700000000
    #     after poll 2: asked Kismet since=1700000000 -> returned NOTHING
    #     DOOMED recovered: False
    #
    # A device that appears once -- a car with an ALPR driving past -- during a
    # transient DB failure is gone. No alert, no row, no trace but a WARNING.
    # For a tool whose entire job is to notice that device, that is the worst
    # failure it can have, and it is invisible.
    #
    # ⛔ But "hold the watermark until everything persists" is NOT the fix: a
    # record that fails every time then freezes it forever and the daemon
    # re-fetches the same window indefinitely -- alive, and permanently blind.
    # That is the A1 poison-record livelock, and the unconditional advance
    # above was the defence against it.
    #
    # So: hold, but BOUNDED. Retry the failed window for up to
    # POLL_WATERMARK_MAX_HOLDS consecutive ticks, then give up loudly and move
    # on. Transient failures recover; a genuinely poisonous record costs three
    # ticks instead of the daemon's remaining lifetime.
    holds = 0
    try:
        holds = int(db.get_state(STATE_KEY_WATERMARK_HOLDS) or 0)
    except (TypeError, ValueError):
        holds = 0
    watermark: int | None
    if not clock_trusted:
        # ⛔ The cursor half of the clock-jump class, and it is WORSE than the
        # retention half that #35 gated. A skipped prune costs one day of
        # deferred housekeeping. A watermark written from a jumped clock is
        # PERSISTENT: `last_poll_ts` is read back next tick as
        # `since=<the future>`, Kismet returns nothing, and the daemon is blind
        # for the whole excursion -- 30 days of "no devices seen" that looks
        # exactly like a quiet environment. Re-anchoring does not undo it,
        # because the poisoned value is already in the database.
        #
        # So: leave the stored watermark exactly where it is. The cost is
        # re-querying a window we may already have processed, which is an
        # idempotent re-upsert of devices already stored -- the same trade the
        # `- 1` below makes deliberately.
        #
        # ⚠️ This deliberately skips the WATERMARK_HOLDS bookkeeping too. That
        # counter's budget belongs to PERSIST failures; letting a clock jump
        # spend it would mean an operator with both problems at once silently
        # loses the persist-retry protection that PR #24 exists to provide.
        #
        # Not unbounded: `Poller.clock_is_trusted` re-anchors after
        # CLOCK_JUMP_MAX_HOLDS consecutive ticks, so this holds for at most
        # that many ticks and then normal advance resumes.
        watermark = None
        logger.error(
            "clock is untrusted this tick; NOT advancing the poll watermark "
            "(leaving it at %s). Writing a watermark from a jumped clock would "
            "ask Kismet for devices 'since the future' on every later tick.",
            db.get_state(STATE_KEY_LAST_POLL),
        )
    elif failed_last_seen and holds < POLL_WATERMARK_MAX_HOLDS:
        # ``- 1`` so the retry window is inclusive of the failed device
        # regardless of whether Kismet's /devices/last-time boundary is
        # strictly-greater or greater-or-equal. That is not settled here, and
        # a one-second overlap costs an idempotent re-upsert of devices already
        # stored, while getting it wrong the other way loses the device.
        watermark = min(now_ts, min(failed_last_seen) - 1)
        db.set_state(STATE_KEY_WATERMARK_HOLDS, str(holds + 1))
        logger.warning(
            "holding poll watermark at %d to retry %d observation(s) that failed "
            "to persist (hold %d/%d)",
            watermark,
            len(failed_last_seen),
            holds + 1,
            POLL_WATERMARK_MAX_HOLDS,
        )
    else:
        watermark = now_ts
        if failed_last_seen:
            # Out of retries. This is a real, permanent loss of capture data,
            # so it is ERROR rather than WARNING -- the operator's detection
            # coverage has a hole in it and nothing else will say so.
            logger.error(
                "giving up on %d observation(s) that failed to persist across %d "
                "ticks; advancing the poll watermark past them -- THESE DEVICES "
                "ARE LOST and will not be re-fetched",
                len(failed_last_seen),
                POLL_WATERMARK_MAX_HOLDS,
            )
        if holds:
            db.set_state(STATE_KEY_WATERMARK_HOLDS, "0")
    if watermark is not None:
        db.set_state(STATE_KEY_LAST_POLL, str(watermark))
    # Per-poll housekeeping for the rule_type_snoozes table: physically
    # delete rows whose expires_at has passed. Cheap (table is tiny;
    # indexed on expires_at) and defensive — the gate's
    # ``expires_at > now_ts`` filter already ignores expired rows, so a
    # missed cleanup never affects correctness, only steady-state row
    # count. Wrapped defensively for the same reason as the evidence
    # prune below: a housekeeping failure must not abort the poll loop.
    #
    # ⛔ GATED on `clock_trusted`, like both prunes below and for a stronger
    # reason. The comment above defends this as "a missed cleanup never affects
    # correctness, only steady-state row count" -- true of a cleanup that does
    # not RUN, and false of one that runs with a wrong clock. `expires_at <=
    # now_ts` on a jumped clock physically deletes snoozes that have not
    # expired, and the gate's own `expires_at > now_ts` filter cannot restore a
    # deleted row. Measured: a snooze set to NOW+7d is deleted at clock +8d,
    # purged=1, and correcting the clock does not bring it back -- the operator
    # simply starts receiving alerts they deliberately silenced.
    if clock_trusted:
        # ⛔ REPAIR BEFORE PURGE, and the order is load-bearing. The web UI is a
        # separate process with no ClockAnchor: it computes
        # `expires_at = time.time() + duration` and persists that absolute
        # deadline, so a snooze created while the host clock was wrong is wrong
        # by the same amount. Measured at +91 days: a "24 hour" snooze stayed
        # active for 92 DAYS after NTP corrected the clock.
        #
        # ⭐ Nothing here can prevent that write — it happens in another process
        # that this gate cannot reach. So this is a REPAIR, the same shape as
        # the suppression anchor's self-heal and for the same reason: where the
        # bad state is written somewhere a gate cannot see, the state has to be
        # fixable after the fact.
        #
        # ⚠️ Running it after the purge would let this tick delete a row it was
        # about to re-base -- `cleanup` keys on `expires_at <= now_ts`, and a
        # snooze written on a BACKWARD-jumped clock has exactly that shape.
        try:
            for rule_type, duration in db.repair_future_dated_rule_type_snoozes(now_ts):
                # ⚠️ "for the Nds the operator asked for" was an overclaim and is
                # now stated precisely. The re-base restarts the window from NOW,
                # so if real time already elapsed under the wrong clock the total
                # suppression EXCEEDS what was asked (24h written on a +91d clock,
                # corrected 12h later => 36h of silence). Nothing stored can fix
                # that: both timestamps came from the wrong clock, so the elapsed
                # real time is not recoverable. Saying "runs for Nds FROM NOW" is
                # the strongest true statement available. See AUDIT_REGISTER.
                logger.warning(
                    "rule_type snooze for %s was created on a clock that read "
                    "ahead of this one; re-based to run for %ds FROM NOW rather "
                    "than until the wrong deadline. If time already passed under "
                    "the wrong clock the total silence will exceed what you asked "
                    "for -- lift it manually if that matters",
                    rule_type,
                    duration,
                )
        except Exception as e:
            logger.warning("rule_type_snoozes repair failed: %s", e)
        # ⭐ The SAME defect lives in the other storage backend. `_write_ui_allowlist`
        # persists per-device and per-alert snoozes to the UI YAML with the same
        # `expires_at = time.time() + seconds` shape. Measured at +91 days: a
        # 24-hour snooze on one suspicious device suppressed it for 92 DAYS.
        #
        # ⚠️ I found the rule_type instance by grepping for `db.<method>(now_ts=...)`,
        # which structurally could not see this one -- it writes a file, not a row.
        # Both are repaired here so the two backends cannot drift apart again.
        #
        # ⛔ Guard the None case the way ``Poller.__init__`` already does for
        # the same field. ``Path(None)`` raises ``TypeError``; the ``except``
        # below would then catch it and log "UI allowlist snooze repair
        # failed" once per tick for every install without an allowlist
        # configured -- a default install -- polluting ``journalctl`` at the
        # WARNING level that operators are trained to watch. Skipping is the
        # honest direction: with no allowlist, there is nothing in the UI
        # backend to repair, so the call site must no-op.
        if config.allowlist_path is not None:
            try:
                for pattern, duration in repair_future_dated_ui_entries(
                    config.resolved_ui_allowlist_path(), now_ts
                ):
                    logger.warning(
                        "UI suppression for %s was created on a clock that read "
                        "ahead of this one; re-based so it runs for the %ds the "
                        "operator chose, not until the wrong deadline",
                        pattern,
                        duration,
                    )
            except Exception as e:
                logger.warning("UI allowlist snooze repair failed: %s", e)
        # ⚠️ THIRD instance of the same defect, and the most harmful of the
        # three: `snooze_expires_at` gates the ORIGINAL alert pipeline for that
        # MAC (OQ-3), not just the recurrence escalation. Measured with the web
        # clock +91d, on a device the operator had explicitly watchlisted as
        # HIGH severity: zero notifications at day 1, 30 and 60. A "snooze this
        # device's alerts for 24 hours" silenced their own stalker alert for 92
        # days.
        #
        # ⛔ I shipped the first two repairs believing that was the whole class.
        # Three storage sites, three separate discoveries, one shape. Any new
        # `x_expires_at = clock + duration` write belongs on this list.
        try:
            for mac, duration in db.repair_future_dated_watchful_snoozes(now_ts):
                logger.warning(
                    "watchful snooze for %s was created on a clock that read "
                    "ahead of this one; re-based so its alerts resume after the "
                    "%ds the operator chose",
                    mac,
                    duration,
                )
        except Exception as e:
            logger.warning("watchful snooze repair failed: %s", e)
        # ⚠️ FOURTH site, and this one is not a deadline -- it is a BASELINE.
        # `last_seen_at` drives the 24h recurrence debounce, so #69 gated the
        # poller's write to it; `reset_watchful_recurrence` writes the same
        # column from the web process, which has no anchor. Measured: reset on a
        # +91d clock froze recurrence counting until day 92, i.e. exactly the
        # harm #69 fixed, arriving through the other process.
        #
        # ⛔ ORDER: after the snooze repair, never before. That one keys on
        # `created_at > now_ts` to recognise a jumped write; this one must not
        # erase the row's future-dated provenance before it has been read.
        try:
            for mac, ahead in db.repair_future_dated_watchful_baselines(now_ts):
                logger.warning(
                    "watchful baseline for %s was %ds in the future (a reset on "
                    "a jumped clock?); clamped to now so recurrence counting "
                    "resumes instead of stalling for that long",
                    mac,
                    ahead,
                )
        except Exception as e:
            logger.warning("watchful baseline repair failed: %s", e)
        # ⛔ BEFORE the purge, and that order is the whole point: the purge is
        # what destroys the evidence. Finding 41's backward case -- a snooze
        # written while the clock read behind, then NTP corrects it -- arrives
        # here with `expires_at` already in the past, so `cleanup` deletes it
        # and the operator's "24 hours" was ZERO. The repair above cannot see
        # it: that one keys on `added_at > now_ts`, the FORWARD shape.
        #
        # ⭐ We do not resurrect the row, and that is deliberate. A snooze
        # SUPPRESSES alerting, so the safe direction is the one it already
        # fails in -- the device keeps alerting. Re-basing would silently start
        # suppressing a rule type on the strength of a row whose real age is
        # unknowable. What was actually wrong is that it happened SILENTLY;
        # that is the half fixed here. Pinned by
        # `test_an_impossible_snooze_is_reported_but_NOT_resurrected`.
        # ⚠️ Phrased as a DISAGREEMENT, and every word of that is load-bearing.
        # An earlier version of this message asserted three things the code had
        # not established: that the clock "was wrong" (the schema stamp comes
        # from the same clock, so either side may be the wrong one), that the
        # snooze suppressed NOTHING (it is in force for the whole period before
        # the clock is corrected), and that the row was expired at all (the
        # query had no expiry condition, so rows still in force were reported
        # as discarded). All three were found by a cold read of the merged
        # change. An error string asserting a cause the code never established
        # is the same defect class as prose promising a guard that does not
        # exist -- see AUDIT_REGISTER's rule on checks that cannot distinguish
        # two causes.
        # ⚠️ Field access, not positional unpacking. Swapping two names here
        # rendered a 1970 timestamp to the operator while every test passed.
        # ⚠️ And the formatting is per-row inside its own try: a single
        # unrenderable `added_at` (an out-of-range epoch from a corrupted or
        # wildly wrong clock) used to raise out of the whole loop, so every
        # REMAINING impossible snooze was purged with no warning at all.
        try:
            for snooze in db.find_impossible_rule_type_snoozes(now_ts):
                try:
                    stamped = _dt.datetime.fromtimestamp(
                        snooze.added_at, tz=_dt.UTC
                    ).isoformat()
                except (OverflowError, OSError, ValueError):
                    stamped = f"an unrenderable epoch value ({snooze.added_at})"
                logger.warning(
                    "the %ds snooze for %s is being discarded: it is stamped %s, "
                    "earlier than this database's own first migration, so the "
                    "row and the schema history disagree about when it was "
                    "written and at least one of the two clocks was wrong. Its "
                    "deadline has passed on the current clock. Set it again if "
                    "you still want it, and check this host's time source.",
                    snooze.duration_seconds,
                    snooze.rule_type,
                    stamped,
                )
        except Exception as e:  # pragma: no cover -- the helper already swallows
            logger.warning("rule_type_snoozes impossibility check failed: %s", e)
        try:
            purged = db.cleanup_expired_rule_type_snoozes(now_ts)
            if purged > 0:
                logger.debug(
                    "rule_type_snoozes: purged %d expired row(s) on poll cycle",
                    purged,
                )
        except Exception as e:
            logger.warning("rule_type_snoozes cleanup failed: %s", e)
        # The same BACKWARD check for the WATCHFUL snooze backend (Finding 56).
        #
        # ⛔ INSIDE the `clock_trusted` gate, with its siblings, and that is a
        # correctness requirement rather than tidiness. The check asks whether a
        # snooze's deadline "has passed on the current clock" -- a judgement
        # made against `now_ts`. On a clock the daemon has already decided not
        # to trust, that judgement is unfounded, and the warning it prints tells
        # the operator to go and check a time source over a conclusion drawn
        # from the very reading that is in doubt.
        try:
            _report_impossible_watchful_snoozes(db, now_ts)
        except Exception as e:  # pragma: no cover -- the helper already swallows
            logger.warning(
                "watchful snooze impossibility check failed: %s", e
            )
    # Per-poll housekeeping for watchful_recurrence: archive entries
    # whose last_seen_at is >= 90 days stale. Per OQ-3 this is the
    # SOLE lifecycle clock for unactioned watchful entries --
    # snooze_expires_at does not drive any housekeeping action.
    # Idempotent and cheap (indexed on archived_at; bounded by the
    # watchful table's small steady-state size). Wrapped defensively
    # for the same reason as the surrounding housekeeping blocks: a
    # failure here must not abort the poll loop.
    #
    # ⛔ Also gated. Milder than the snooze purge -- archiving is reversible
    # where a delete is not -- but it is the same shape: a forward jump
    # archives entries whose 90-day quiet stretch has not actually elapsed,
    # and this is the SOLE lifecycle clock for unactioned watchful entries.
    if clock_trusted:
        try:
            archived = db.auto_archive_watchful_recurrence(now_ts)
            if archived > 0:
                logger.info(
                    "watchful_recurrence: archived %d entries (90d quiet-stretch reached)",
                    archived,
                )
        except Exception as e:
            logger.warning("watchful_recurrence auto-archive failed: %s", e)
    # Daily housekeeping: prune evidence rows past the retention window. The
    # helper is a no-op except once per ~24h, so this is cheap to call from
    # every poll tick. Wrapped defensively because a prune failure must not
    # crash the poll loop.
    #
    # ⛔ Both prunes are gated on `clock_trusted`. A retention cutoff is
    # `now_ts - retention_days * 86400`, so a wall clock that has jumped
    # FORWARD deletes rows that are inside the window and does it silently.
    # Measured by session 3 on 30 daily sightings with retention_days=30:
    #
    #     clock   deleted   should have deleted
    #     +7d     6         0
    #     +30d    29        0
    #     +365d   30        0
    #
    # ⚠️ This cannot be fixed inside retention.py, and that is the whole reason
    # the gate lives here. From inside that module "the clock jumped forward"
    # and "the table holds only old rows" are the SAME observation, and the
    # second is required behaviour -- test_sightings_retention.py::
    # test_returns_none_oldest_when_table_is_emptied asserts a wholly-stale
    # table is fully deleted. Any "elapsed since last prune" bound is computed
    # from the same corrupt clock, so it is circular.
    # ⭐ The prune deadline is DERIVED from the staleness threshold it exists to
    # protect, never invented. The UI and `_check_poller` both call this daemon
    # stale at 2 * poll_interval_seconds; a prune runs INSIDE this tick, so
    # spending one whole interval on it leaves the other for the poll work and
    # keeps the tick clear of that threshold. Nothing here needs to know how
    # fast the storage is, which is what made a hardcoded N unjustifiable.
    prune_deadline = float(max(1, config.poll_interval_seconds))
    if clock_trusted:
        try:
            maybe_prune_evidence(
                db,
                config.evidence_retention_days,
                now_ts=now_ts,
                max_seconds=prune_deadline,
            )
        except Exception as e:
            logger.warning("Evidence prune failed: %s", e)
    # The dead-man's switch. Placed AFTER the tick counters and the watermark
    # bookkeeping above are written, so it reads this tick's state rather than
    # the previous one -- a heartbeat composed from stale state could report
    # health that had already stopped being true. No-op except once per
    # heartbeat_interval_hours, and disabled by default.
    #
    # Wrapped defensively for the same reason as the prunes: this exists to
    # report that the pipeline is broken, so it must never be the thing that
    # breaks it.
    try:
        maybe_emit_heartbeat(db, config, notifier, now_ts=now_ts)
    except Exception as e:
        logger.warning("Heartbeat emit failed: %s", e)
    # Same daily cadence for sightings, and a no-op unless the operator has
    # opted in -- sightings_retention_days defaults to None, meaning never
    # prune, which is what every install has always done. Wrapped defensively
    # for the same reason: a prune failure must not stop the poll loop.
    if clock_trusted:
        try:
            maybe_prune_sightings(
                db,
                config.sightings_retention_days,
                now_ts=now_ts,
                max_seconds=prune_deadline,
            )
        except Exception as e:
            logger.warning("Sightings prune failed: %s", e)
    else:
        # ERROR, not WARNING: skipping a prune trades unbounded table growth
        # for not destroying capture data, which is the right trade but is not
        # a state to sit in quietly. `Poller` bounds how long this can last --
        # see CLOCK_JUMP_MAX_HOLDS.
        logger.error(
            "clock is untrusted this tick; SKIPPING both retention prunes "
            "(evidence + sightings) to avoid deleting data inside the window"
        )
    return processed[0]


def log_watchlist_staleness(
    db: Database, warn_days: int, *, now_ts: int
) -> None:
    """Log a single startup line describing the watchlist's age.

    Three outcomes, mirroring the three states the operator can be in:

    - Imports recorded AND most-recent import is within ``warn_days``:
      one INFO line with row count + days-since + exported date.
    - Imports recorded AND most-recent import is older than
      ``warn_days``: one WARNING line, same fields plus a refresh hint
      naming ``lynceus-import-argus --from-github``. The WARNING is
      the load-bearing signal — an operator running ``journalctl -u
      lynceus.service`` can spot it without grepping for a specific
      pattern.
    - No imports recorded (fresh install, never ran the importer): one
      INFO line stating so. Deliberately NOT a WARNING — a fresh
      install where the operator hasn't run lynceus-import-argus yet
      is the expected state right after lynceus-setup; warning would
      be noise.

    Age is computed against ``exported_at`` when present (Argus-side
    timestamp on the CSV's ``# meta:`` line), falling back to
    ``imported_at`` (local clock at write time). Falling back rather
    than logging "unknown age" keeps a useful signal for the
    pre-meta-parsing imports that ship NULL exported_at — the local
    clock is a strict lower bound on the data's age (data can be
    older than imported_at but never newer).

    ⚠️ That fallback is about a MISSING ``exported_at``. A *present*
    one that is dated ahead of this clock is a different case and is
    reported as an unknown age at WARNING — see the comment at the
    age arithmetic. Kept in lockstep with ``/settings`` by
    ``tests/test_watchlist_age_lockstep.py``.

    Failures (db error, sqlite contention) downgrade to a single
    WARNING line; the poller continues. Observability-only by
    design — a broken staleness signal must NOT block startup.
    """
    try:
        row_count = int(
            db._conn.execute("SELECT COUNT(*) AS c FROM watchlist").fetchone()["c"]
        )
        latest = db.get_latest_import_run()
    except Exception as exc:
        logger.warning(
            "watchlist: staleness check failed (%s); continuing without "
            "freshness signal at startup. /settings will surface the "
            "same data if the DB recovers.",
            exc,
        )
        return

    if latest is None:
        logger.info(
            "watchlist: %d rows total, no Argus import metadata recorded "
            "(no lynceus-import-argus run yet, or runs predate the import_runs "
            "table from migration 012)",
            row_count,
        )
        return

    # Prefer Argus-side exported_at; fall back to imported_at when the
    # meta line was unparseable.
    #
    # ⛔ **This used to clamp a negative age to zero**, with the reasoning that
    # the raw timestamp was still printed for forensic clarity. That reasoning
    # is replaced, not extended: `exported_at` carries the ARGUS host's clock,
    # so a future-dated export needs no local clock fault -- and clamping made a
    # watchlist a YEAR old log `most recent Argus import 0 days ago` at **INFO**,
    # i.e. no warning at all, with the honest number nowhere in the line an
    # operator greps for. The printed timestamp does not help someone scanning
    # journalctl for WARNINGs.
    #
    # ⚠️ It is also a LOCKSTEP requirement, and that is why this changed here.
    # `_watchlist_freshness_card`'s docstring says this log line and /settings
    # are "deliberately kept in lockstep so an operator who sees a WARNING in
    # journalctl can open /settings and see the same numbers without
    # reconciling". /settings stopped clamping; if this did not, the two would
    # say `0 days / fresh` and `cannot tell` about the same watchlist.
    # `tests/test_watchlist_age_lockstep.py` now checks that agreement.
    #
    # Tolerance, not zero: `exported_at` legitimately sits seconds ahead when
    # the two hosts' clocks differ normally. `CLOCK_JUMP_TOLERANCE_SECONDS` is
    # this module's existing notion of "close enough to now".
    reference_ts = latest["exported_at"] or latest["imported_at"]
    ahead_by = int(reference_ts) - now_ts
    age_days = (
        None
        if ahead_by > CLOCK_JUMP_TOLERANCE_SECONDS
        else max(0, now_ts - int(reference_ts)) // 86400
    )
    exported_at = latest["exported_at"]
    exported_iso = (
        _dt.datetime.fromtimestamp(int(exported_at), tz=_dt.UTC).strftime("%Y-%m-%d")
        if exported_at is not None
        else "unknown"
    )

    if age_days is None:
        # ⛔ WARNING, not INFO. The staleness signal is the thing that has
        # failed, and an operator scanning for WARNINGs must not scroll past a
        # watchlist whose age nothing has established.
        logger.warning(
            "watchlist: %d rows total, but the age of the most recent Argus "
            "import cannot be established: it is dated %s, which is ahead of "
            "this machine's clock. Argus stamps that field with ITS clock, so "
            "compare the two hosts. Until they agree, treat the watchlist as "
            "of unknown age rather than fresh.",
            row_count,
            exported_iso,
        )
    elif age_days > warn_days:
        logger.warning(
            "watchlist: %d rows total, most recent Argus import %d days "
            "ago (exported %s); consider 'lynceus-import-argus "
            "--from-github' to refresh",
            row_count,
            age_days,
            exported_iso,
        )
    else:
        logger.info(
            "watchlist: %d rows total, most recent Argus import %d days "
            "ago (exported %s)",
            row_count,
            age_days,
            exported_iso,
        )


class ClockAnchor:
    """Tracks whether the wall clock has moved independently of elapsed time.

    Extracted from ``Poller`` so the BLE bridge can reach the same judgement.
    The bridge flushes observations straight into ``process_observation`` off
    its own ``int(time.time())`` reading, so before this existed it had no way
    to form an opinion about its clock at all -- a second, unguarded door into
    the watchful-recurrence arithmetic that ``poll_once`` gates.

    ⚠️ ``is_trusted`` mutates hold state, so call it exactly once per tick.
    """

    def __init__(self) -> None:
        self._anchor: tuple[float, float] = (time.time(), time.monotonic())
        self._holds = 0

    def is_trusted(self, now_ts: int) -> bool:
        """Has the wall clock moved independently of elapsed real time?

        Compares the wall clock against what it *should* read given how much
        monotonic time has passed since the anchor. A divergence beyond
        CLOCK_JUMP_TOLERANCE_SECONDS means the clock itself moved -- NTP
        stepping, a manual set, an RTC-less board finally syncing -- rather
        than time simply passing.

        Returns False while a jump is fresh, so the caller can decline to do
        anything the wall clock would get wrong. After CLOCK_JUMP_MAX_HOLDS
        consecutive holds it re-anchors and returns True again: see that
        constant for why an unbounded hold is the other broken extreme.
        """
        wall, mono = self._anchor
        expected = wall + (time.monotonic() - mono)
        drift = abs(now_ts - expected)
        if drift <= CLOCK_JUMP_TOLERANCE_SECONDS:
            if self._holds:
                logger.info(
                    "wall clock agrees with elapsed time again (drift %.1fs); "
                    "resuming normal operation",
                    drift,
                )
            self._holds = 0
            return True

        self._holds += 1
        if self._holds >= CLOCK_JUMP_MAX_HOLDS:
            logger.error(
                "wall clock has diverged from elapsed time by %.0fs for %d "
                "consecutive ticks; ACCEPTING the new clock and re-anchoring. "
                "Retention pruning resumes against it -- if this clock is wrong, "
                "data inside the retention window may now be deleted.",
                drift,
                self._holds,
            )
            # ⚠️ Re-anchor to `now_ts`, NOT to a fresh `time.time()`. `now_ts`
            # is the reading the rest of this tick will actually use, and the
            # anchor has to describe that same clock -- a second reading can
            # differ, and then the very next tick measures drift against a
            # value nothing else in the system saw. Caught by
            # test_the_hold_is_bounded_and_then_re_anchors, which held the
            # jumped clock steady and watched the drift reappear from nowhere.
            self._anchor = (float(now_ts), time.monotonic())
            self._holds = 0
            return True

        logger.error(
            "wall clock jumped: reads %ds, expected ~%ds from elapsed time "
            "(drift %.0fs). Holding %d/%d -- time-dependent housekeeping is "
            "suspended this tick.",
            now_ts,
            int(expected),
            drift,
            self._holds,
            CLOCK_JUMP_MAX_HOLDS,
        )
        return False


class Poller:
    def __init__(self, config: Config, config_path: str | None = None) -> None:
        self.config = config
        # The resolved YAML path the daemon was launched with (``--config``),
        # plumbed through so the startup health-check failure can name the
        # exact file a rejected key came from. ``None`` for in-process callers
        # (tests, embedded use) that build a Poller from a Config object with
        # no backing file.
        self.config_path = config_path
        # ⭐ The clock anchor. You CANNOT detect a wall-clock jump using only
        # the wall clock -- from inside any single reading, "the clock moved"
        # and "time passed" are indistinguishable. Pairing it with a monotonic
        # reading taken at the same instant makes a jump *during this process*
        # unambiguous, while a restart after genuine downtime is correctly not
        # flagged (a new process takes a new anchor).
        self._clock = ClockAnchor()
        self.db = Database(config.db_path)
        self.client = build_kismet_client(config)
        if config.kismet_health_check_on_startup:
            self._startup_health_check()
        self._source_allowlist: frozenset[str] | None = (
            frozenset(config.kismet_sources) if config.kismet_sources else None
        )
        # Alias map: configured-name → frozenset of stamped names Kismet
        # may credit observations to. Populated lazily from
        # KismetClient.list_sources() on the first tick that needs it, and
        # cleared on any tick that drops records under the source_allowlist
        # gate (so a Kismet reconfiguration mid-run is picked up without
        # restarting lynceus). Stays None while no allowlist is configured —
        # the resolution path short-circuits before any API call.
        #
        # The v0.7.7 smoke probe surfaced the bug this exists to fix:
        # Kismet's linux_wifi capture path auto-creates a monitor VIF
        # (`kismon0`) on the parent adapter and stamps observations with
        # the VIF's name, while the operator configures the parent name
        # (`wlx00c0ca112233`) in lynceus.yaml. The two appear in
        # /datasource/all_sources.json as two rows sharing one UUID;
        # grouping by UUID gives the alias set.
        self._source_alias_map: dict[str, frozenset[str]] | None = None
        # Startup robustness (BT capture-source arc): after the health
        # check, surface any allowlisted source Kismet isn't currently
        # capturing from, so an unplugged dongle / hciN index reorder /
        # wizard mis-pick is LOUD at boot instead of a silent per-tick drop.
        self._warn_absent_allowlisted_sources()
        if config.rules_path:
            self.ruleset = load_ruleset(config.rules_path)
            active = sum(1 for r in self.ruleset.rules if r.enabled)
            total = len(self.ruleset.rules)
            if active == total:
                logger.info(
                    "loaded ruleset from %s: %d active rules",
                    config.rules_path,
                    active,
                )
            else:
                logger.info(
                    "loaded ruleset from %s: %d active rules (%d disabled)",
                    config.rules_path,
                    active,
                    total - active,
                )
        else:
            self.ruleset = Ruleset()
            logger.info(
                "no rules_path configured; ruleset is empty — no alerts will fire"
            )
        # Allowlist load + mtime cache for the per-tick reload watch.
        # Both files (operator-curated primary + daemon-managed UI sibling)
        # are stat()ed at every poll and reloaded when either has moved;
        # missing files map to sentinel mtime 0.0 so a file appearing or
        # disappearing both count as changes that trigger a reload.
        self._allowlist_primary_path: Path | None = (
            Path(config.allowlist_path) if config.allowlist_path else None
        )
        self._allowlist_ui_path: Path | None = (
            self.config.resolved_ui_allowlist_path()
            if self._allowlist_primary_path is not None
            else None
        )
        # ⚠️ The pre-move location is WATCHED as well as read. During the
        # migration window it is the live file, and an operator hand-editing
        # it there would otherwise never trip a reload -- the daemon would keep
        # serving a merge from a file that had changed underneath it. Costs one
        # extra stat per tick, and is None once the two resolve to the same
        # directory (a user-scope install, or any test).
        self._allowlist_legacy_ui_path: Path | None = (
            self.config.legacy_ui_allowlist_path()
            if self._allowlist_primary_path is not None
            else None
        )
        self._allowlist_mtimes: dict[Path, float] = {}
        # Set when the primary allowlist is corrupt at startup; the
        # operator ntfy is deferred until build_notifier runs below,
        # because the allowlist loads before the notifier exists.
        self._allowlist_startup_degraded: str | None = None
        if self._allowlist_primary_path is not None:
            try:
                merged, _primary_count, _ui_count = _load_allowlist_with_counts(
                    str(self._allowlist_primary_path),
                    raise_on_parse_error=True,
                    ui_path=self._allowlist_ui_path,
                    legacy_path=self.config.legacy_ui_allowlist_path(),
                )
            except AllowlistParseError as exc:
                # Corrupt-but-present primary at startup. There is no
                # last-good to retain (this IS the first load), so start
                # with empty suppression to keep detection running — but
                # make the degraded state un-missable: a CRITICAL log now
                # plus an operator ntfy once the notifier exists (below).
                # FileNotFoundError is deliberately NOT caught here: a
                # missing primary is a config error that must crash the
                # daemon rather than silently disable suppression.
                self.allowlist = Allowlist()
                self._allowlist_startup_degraded = str(exc)
                logger.critical(
                    "allowlist primary file %s failed to load at startup "
                    "(%s); SUPPRESSION DISABLED — every allowlisted device "
                    "can now alert until the file is fixed and reloaded",
                    self._allowlist_primary_path,
                    exc.__cause__,
                )
            else:
                self.allowlist = merged
            self._allowlist_mtimes = self._current_allowlist_mtimes()
        else:
            self.allowlist = Allowlist()
        # severity_overrides.yaml: runtime view (device_category_severity
        # + suppress_categories). Failures (missing / unreadable /
        # malformed) downgrade to None at the loader, never raise — the
        # poller must not crash because the operator edited their
        # override file into a malformed state. The import-time consumer
        # in lynceus-import-argus is a separate code path with its own
        # error handling and is unaffected by this load.
        self.severity_overrides = load_runtime_severity_overrides(
            config.severity_overrides_path
        )
        log_watchlist_staleness(
            self.db, config.watchlist_staleness_warn_days, now_ts=int(time.time())
        )
        self.notifier: Notifier = build_notifier(config)
        if self._allowlist_startup_degraded is not None:
            # Deferred from the startup allowlist load above — the notifier
            # did not yet exist there. NullNotifier (no ntfy configured) makes
            # this a no-op, in which case the CRITICAL log above is the only
            # signal — the accepted fallback. priority_override=4 mirrors the
            # Kismet-loss operator alerts (below the 5 reserved for watchlist
            # hits), so it does not pose as an opted-in device alert.
            self.notifier.send(
                "high",
                "Lynceus: allowlist failed to load — suppression DISABLED",
                f"The primary allowlist {self._allowlist_primary_path} could "
                f"not be parsed at startup; Lynceus started with ZERO "
                f"suppression. Every previously allowlisted device can raise "
                f"alerts until the file is fixed and the daemon reloads it.",
                priority_override=4,
            )
        self._stop_flag = False
        # Runtime Kismet-loss alert state (0.9.1). In-memory by design: the
        # alert is for a daemon that STAYS UP while Kismet disappears mid-run,
        # so the state only needs to live as long as the loop. A restart can't
        # strand a stale "down" — the startup health check gates re-entry to
        # run_forever, so if Kismet is still gone the process crash-loops before
        # the loop runs, and if it recovered the state starts fresh. The
        # transition/de-dup logic lives in _note_kismet_poll_result.
        self._consecutive_poll_failures = 0
        self._kismet_down_alerted = False
        #: Last BLE-bridge status written by this process. The per-tick check
        #: writes only on CHANGE, so a healthy bridge costs one write at
        #: startup rather than one per poll for the daemon's lifetime.
        self._ble_bridge_last_status: str | None = None
        self._ble_bridge_started_at: int | None = None
        #: Whether the "Kismet unreachable" notification was actually DELIVERED,
        #: as distinct from attempted. The recovery edge keys on this so it
        #: cannot announce the end of an outage the operator never heard about.
        self._kismet_down_delivered = False
        self._kismet_down_attempts = 0
        # Rule_type snooze suppression accumulator. Cumulative across
        # poll cycles; flushed to an INFO summary every
        # SUPPRESSION_LOG_INTERVAL_SECONDS. Initialized to "log on the
        # first tick that produces a non-empty counter past the
        # interval boundary" — anchoring to instance-creation time so
        # restarts don't produce a phantom summary on the first tick.
        self._rule_type_suppression_counter: dict[str, int] = {}
        self._last_suppression_log_ts: int = int(time.time())

    def _build_source_alias_map(self) -> dict[str, frozenset[str]]:
        """Query Kismet's source list and group names by UUID.

        Returns a dict mapping each name Kismet might stamp on an
        observation to the frozenset of all names sharing the same source
        UUID. A failure to fetch (auth, network, transient 5xx) is logged
        at WARNING and the caller gets an empty dict — the allowlist gate
        then falls back to literal matching, which is the pre-fix
        behavior. Operators see the WARNING and know to investigate
        without the poller crashing.
        """
        try:
            sources = self.client.list_sources()
        except Exception as e:
            logger.warning(
                "could not fetch Kismet source list for alias resolution "
                "(%s); falling back to literal source_allowlist matching",
                e,
            )
            return {}
        by_uuid: dict[str, set[str]] = {}
        for src in sources:
            uuid = src.get("uuid") or ""
            if not uuid:
                continue
            names = by_uuid.setdefault(uuid, set())
            name = src.get("name") or ""
            interface = src.get("interface") or ""
            if name:
                names.add(name)
            if interface:
                names.add(interface)
        aliases: dict[str, frozenset[str]] = {}
        for names in by_uuid.values():
            frozen = frozenset(names)
            for n in names:
                aliases[n] = frozen
        logger.debug(
            "source alias map built: %s",
            {k: sorted(v) for k, v in aliases.items()},
        )
        return aliases

    def _warn_absent_allowlisted_sources(self) -> None:
        """Warn (don't block) when a configured ``kismet_sources`` entry
        isn't among Kismet's live sources at startup.

        Premise-independent robustness for the source_allowlist gate: an
        allowlisted name Kismet isn't currently capturing from admits zero
        observations, which otherwise surfaces only as silent
        ``dropped_source_allowlist`` ticks. This catches an unplugged USB
        adapter at boot, an hciN index reorder, and any wizard mis-pick.
        One aggregated WARNING line (the v0.7.5 INFO-aggregation style)
        names the missing source(s) and lists the live sources for
        contrast.

        No-op when no allowlist is configured (the gate is bypassed
        anyway). A presence match is conservative — name OR interface OR
        capture_interface — so a config that legitimately targets a VIF's
        capture_interface (e.g. ``kismon0``) doesn't false-warn. A fetch
        failure (auth, network, 5xx) is logged at WARNING and swallowed so
        startup never dies on it. Deliberately does NOT populate
        ``self._source_alias_map``: that stays lazily built on the first
        tick, so a transient failure here can't cache an empty map and
        defeat the alias expansion."""
        if self._source_allowlist is None:
            return
        try:
            sources = self.client.list_sources()
        except Exception as e:
            logger.warning(
                "could not enumerate Kismet live sources at startup for the "
                "allowlist presence check (%s); skipping — per-tick drop "
                "logging still covers source mismatches",
                e,
            )
            return
        live: set[str] = set()
        for src in sources:
            for key in ("name", "interface", "capture_interface"):
                val = (src.get(key) or "").strip()
                if val:
                    live.add(val)
        missing = sorted(s for s in self._source_allowlist if s not in live)
        if not missing:
            return
        live_names = sorted(
            name
            for src in sources
            if (name := (src.get("name") or "").strip())
        )
        logger.warning(
            "allowlisted source(s) %s not present in Kismet's live sources "
            "%s; their observations will be dropped — check the adapter is "
            "connected and the names match setup",
            missing,
            live_names,
        )

    def _resolve_source_allowlist(self) -> frozenset[str] | None:
        """Expand the configured allowlist through the alias map.

        Operator config of `kismet_sources: [wlx00c0ca112233, hci1]` plus
        an alias map `{wlx00c0ca112233: {wlx00c0ca112233, kismon0}, ...}`
        yields `{wlx00c0ca112233, kismon0, hci1}`. Names not present in
        the map fall back to themselves, so a typo or an adapter Kismet
        isn't reporting still gates correctly (configured name always
        matches itself — operators can't lose admit-ability via mapping
        logic). Returns ``None`` when no allowlist is configured, which
        bypasses the gate entirely just as before.
        """
        if self._source_allowlist is None:
            return None
        if self._source_alias_map is None:
            self._source_alias_map = self._build_source_alias_map()
        expanded: set[str] = set()
        for name in self._source_allowlist:
            expanded.update(
                self._source_alias_map.get(name, frozenset({name}))
            )
        return frozenset(expanded)

    def _maybe_clear_source_alias_map_on_drops(self) -> None:
        """Clear the alias map when the last tick dropped records.

        Reads the per-tick drop counter poll_once just wrote. If > 0,
        the next tick will rebuild the map from Kismet — handles
        operators reconfiguring Kismet mid-run without forcing a refresh
        on every healthy tick. Steady-state misconfig keeps rebuilding
        each tick, accepted because the cost is one HTTP call and the
        alternative (silent drops continuing forever after a Kismet
        restart) is worse.
        """
        raw = self.db.get_state(STATE_KEY_LAST_TICK_DROPPED_SOURCE_ALLOWLIST)
        if raw and int(raw) > 0:
            self._source_alias_map = None

    def _maybe_flush_suppression_summary(self, *, now_ts: int) -> None:
        """Emit the periodic per-rule_type suppression breakdown line.

        Cadence is SUPPRESSION_LOG_INTERVAL_SECONDS (default 1h). On
        each poll-loop iteration we check elapsed time since the last
        flush; when it exceeds the interval AND at least one
        suppression has accumulated, one INFO line goes out with the
        per-rule_type breakdown and the counter resets. An empty
        counter is silently skipped — no point logging "0 suppressed
        in last hour" when no snooze is active.

        Operators grepping journalctl for a single string get the
        full audit shape: "rule_type snooze suppressed <total>
        alert(s) in last ~<interval>: <breakdown>" — the prefix is
        stable so a watcher script can match without parsing the
        rest. The interval is approximate because poll ticks don't
        align to the hour boundary; the line surfaces what was
        accumulated, not what was expected.
        """
        elapsed = now_ts - self._last_suppression_log_ts

        # ⛔ A future anchor freezes this audit line for the length of the jump.
        # Measured with SUPPRESSION_LOG_INTERVAL_SECONDS=3600 and a +8 day jump:
        # the counter was cleared and `_last_suppression_log_ts` stamped 8 days
        # ahead, after which no summary flushed until day 8 -- roughly 8 days of
        # lost audit cadence, from one bad tick.
        #
        # Self-healing rather than gated on `clock_trusted`, deliberately. The
        # anchor can be stamped from a jumped clock even when this method is
        # never called on an untrusted tick, because ClockAnchor re-anchors
        # after CLOCK_JUMP_MAX_HOLDS and reports the jumped clock as trusted --
        # so a gate alone would not prevent the state this repairs.
        if elapsed < 0:
            logger.warning(
                "suppression-summary anchor is %ds in the future (clock jump?); "
                "re-anchoring to now so the audit line is not suppressed until "
                "wall time catches up",
                -elapsed,
            )
            self._last_suppression_log_ts = now_ts
            return

        if elapsed < SUPPRESSION_LOG_INTERVAL_SECONDS:
            return
        if not self._rule_type_suppression_counter:
            # Keep the cadence anchor moving so a sustained-empty
            # period doesn't burst-log the moment a single suppression
            # accumulates after a long idle stretch.
            self._last_suppression_log_ts = now_ts
            return
        total = sum(self._rule_type_suppression_counter.values())
        breakdown = ", ".join(
            f"{rt}={count}"
            for rt, count in sorted(self._rule_type_suppression_counter.items())
        )
        logger.info(
            "rule_type snooze suppressed %d alert(s) in last ~%ds: %s",
            total,
            elapsed,
            breakdown,
        )
        self._rule_type_suppression_counter.clear()
        self._last_suppression_log_ts = now_ts

    def _current_allowlist_mtimes(self) -> dict[Path, float]:
        """Return current mtimes for both allowlist files, sentinel 0.0 if absent.

        A missing file maps to 0.0 deliberately: the same sentinel for
        "doesn't exist yet" and "deleted by the operator", so the first
        appearance of a UI sibling (its mtime moving from 0.0 to a real
        timestamp) and the disappearance of either file (real timestamp
        moving to 0.0) both register as changes that trip a reload.
        """
        result: dict[Path, float] = {}
        for p in (
            self._allowlist_primary_path,
            self._allowlist_ui_path,
            self._allowlist_legacy_ui_path,
        ):
            if p is None:
                continue
            try:
                result[p] = p.stat().st_mtime if p.exists() else 0.0
            except OSError:
                result[p] = 0.0
        return result

    def _maybe_reload_allowlist(self) -> None:
        """Reload the allowlist if either file's mtime has moved.

        Called before every poll tick. The stat() pair is cheap; the
        merged-load only runs on mtime change. Without this, the daemon
        would need a restart for every operator edit to allowlist.yaml
        and every UI button click that writes to allowlist_ui.yaml —
        precisely the operator-comfort outcome this prompt closes.
        """
        if self._allowlist_primary_path is None:
            return
        current = self._current_allowlist_mtimes()
        if current == self._allowlist_mtimes:
            return
        try:
            merged, primary_count, ui_count = _load_allowlist_with_counts(
                str(self._allowlist_primary_path),
                raise_on_parse_error=True,
                ui_path=self._allowlist_ui_path,
                legacy_path=self.config.legacy_ui_allowlist_path(),
            )
        except FileNotFoundError:
            # Operator deleted the primary file mid-run. Hold the
            # last-known good allowlist rather than emptying it — a
            # half-typed config move shouldn't blow open every
            # suppression at once. Update the mtime cache so the next
            # tick re-checks; the file reappearing trips a reload.
            logger.warning(
                "allowlist primary file %s vanished; retaining last-known entries",
                self._allowlist_primary_path,
            )
            self._allowlist_mtimes = current
            return
        except AllowlistParseError as exc:
            # Operator saved a corrupt edit mid-run (a YAML slip or a bad
            # field). Same fail-SAFE stance as the deleted-file path above:
            # retain the last-known good allowlist instead of swapping in an
            # empty one, which would drop every suppression at once and
            # storm ntfy (A2). Update the mtime cache so we don't re-attempt
            # the failing load every tick; fixing the file moves the mtime
            # and trips a clean reload.
            logger.warning(
                "allowlist primary file %s could not be parsed (%s); "
                "retaining last-known entries",
                self._allowlist_primary_path,
                exc.__cause__,
            )
            self._allowlist_mtimes = current
            return
        self.allowlist = merged
        self._allowlist_mtimes = current
        logger.info(
            "allowlist reloaded: %d operator entries + %d UI entries",
            primary_count,
            ui_count,
        )

    def _startup_health_check(self) -> None:
        """Probe Kismet at startup, retrying transient failures with backoff.

        Under systemd's ``After=network.target`` the Kismet REST endpoint may
        not be ready when the lynceus unit starts — a single 5xx, DNS hiccup,
        or transient connection refused was enough on rc1 to crash the
        daemon. The retry loop tolerates ``len(HEALTH_CHECK_RETRY_BACKOFF)``
        attempts; only after all of them fail do we raise (fail-fast — running
        blind against an unreachable/unauthorized Kismet is wrong). The
        failure *message* is actionable: it distinguishes an auth rejection
        (a stale/wrong-scope key) from an unreachable Kismet and names the
        config file the key came from. When and how often it fails is
        unchanged — only the wording is.
        """
        backoff = HEALTH_CHECK_RETRY_BACKOFF
        total = len(backoff)
        last_err: str = "unknown error"
        last_status: int | None = None
        for attempt in range(1, total + 1):
            health = self.client.health_check()
            if health.get("reachable"):
                return
            last_err = health.get("error") or "unknown error"
            last_status = health.get("status_code")
            if attempt < total:
                wait = backoff[attempt - 1]
                logger.info(
                    "Kismet health check failed (attempt %d/%d), retrying in %.1fs...",
                    attempt,
                    total,
                    wait,
                )
                time.sleep(wait)
        logger.error("Kismet health check failed at startup: %s", last_err)
        raise RuntimeError(self._build_health_check_failure_message(last_status, last_err))

    def _build_health_check_failure_message(self, status_code: int | None, error: str) -> str:
        """Compose the actionable startup health-check failure message.

        An auth rejection (Kismet answered 401/403) is a key problem retrying
        can't fix — name the config file the rejected key came from (when
        known) and point at lynceus-setup. Anything else (no HTTP response —
        connection refused / timeout) is treated as Kismet being unreachable
        and names the URL. Both keep the ``kismet_health_check_on_startup=false``
        escape hatch.
        """
        hatch = "Set kismet_health_check_on_startup=false to skip this check."
        if status_code in (401, 403):
            origin = f" from {self.config_path}" if self.config_path else ""
            return (
                f"Kismet rejected the API key{origin} (HTTP {status_code}): {error}. "
                "The key may be stale, revoked, or from the wrong config scope — "
                f"re-run lynceus-setup or check kismet_api_key. {hatch}"
            )
        return (
            f"Kismet unreachable at {self.config.kismet_url}: {error}. "
            f"Is Kismet running and reachable? {hatch}"
        )

    def _on_signal(self, signum: int, frame: object) -> None:
        self._stop_flag = True

    def _interruptible_sleep(self, seconds: int) -> None:
        for _ in range(seconds):
            if self._stop_flag:
                return
            time.sleep(1)

    def _note_kismet_poll_result(self, poll_failed: bool) -> None:
        """Drive the runtime Kismet-loss paired alert state machine for one tick.

        Paired + de-duped: exactly one "Kismet unreachable" infra alert once
        ``RUNTIME_KISMET_LOSS_THRESHOLD`` consecutive failed ticks confirm
        Kismet is genuinely gone, and exactly one paired "reachable again"
        alert on the next good tick — but only if a "down" was sent. Never
        repeats while down.

        Called ONLY from ``run_forever``, never from ``_startup_health_check``
        or ``run_once``, so it cannot fire on the startup / crash-loop path
        (the 189-spam regression this whole feature is gated against).

        The ``health_check()`` confirmation on the down edge keeps this an
        INFRASTRUCTURE signal: a poll tick can fail for reasons that are not
        Kismet being unreachable (a DB write error, a malformed-device
        ValidationError), and those must not masquerade as a Kismet-down page.
        A successful poll is itself proof of reachability, so the recovery edge
        needs no probe. It is fired straight through the notifier, bypassing
        the device-alert pipeline (allowlist / rules / snooze / severity
        overrides) entirely, and carries ``priority_override=4`` so it stays
        out of the priority-5 reserved for opted-in watchlist hits.
        """
        if not poll_failed:
            # ⛔ Pair the recovery with a down the operator ACTUALLY received.
            # Keyed on `_kismet_down_delivered`, not `_kismet_down_alerted`:
            # announcing "reachable again" for an outage that was never
            # announced is worse than silence, because it retroactively tells
            # the operator there was a gap in capture they were never warned
            # about, and gives them no way to learn how long it lasted.
            if self._kismet_down_delivered:
                self.notifier.send(
                    "high",
                    "Lynceus: Kismet reachable again",
                    "Kismet is reachable again — RF capture resumed.",
                    priority_override=4,
                )
                logger.info("Kismet reachable again; sent recovery notification")
            self._kismet_down_alerted = False
            self._kismet_down_delivered = False
            self._kismet_down_attempts = 0
            self._consecutive_poll_failures = 0
            return
        self._consecutive_poll_failures += 1
        if self._kismet_down_alerted:
            return
        if self._consecutive_poll_failures < RUNTIME_KISMET_LOSS_THRESHOLD:
            return
        health = self.client.health_check()
        if health.get("reachable"):
            return
        error = health.get("error") or "no response"
        # ⛔ The send's result IS the state transition. It used to be discarded,
        # so a False return still logged "sent down notification" and latched
        # `_kismet_down_alerted = True`, which the guard above then used to
        # suppress every retry for the rest of the outage. Measured with a
        # failing notifier: 1 attempt, 0 delivered, no retry across 7 ticks --
        # RF capture had stopped and the operator was never told.
        #
        # This is Wave 5 Finding 12 (see NOTIFY_MAX_ATTEMPTS above) on the INFRA
        # alert path, which bypasses the device-alert pipeline and so never
        # inherited that fix. It is the worse of the two instances: a missed
        # device alert loses one sighting; a missed "Kismet unreachable" means
        # every subsequent sighting is lost and nothing says so.
        delivered = self.notifier.send(
            "high",
            "Lynceus: Kismet unreachable",
            f"Kismet at {self.config.kismet_url} is unreachable — "
            f"RF capture stopped. Last error: {error}",
            priority_override=4,
        )
        self._kismet_down_attempts += 1
        if delivered:
            logger.warning(
                "Kismet unreachable for %d consecutive polls; sent down notification",
                self._consecutive_poll_failures,
            )
            self._kismet_down_alerted = True
            self._kismet_down_delivered = True
            return
        # 🪤 Bounded, for the same reason NOTIFY_MAX_ATTEMPTS is: each attempt
        # costs a blocking HTTP timeout on the poll path, so retrying a dead
        # notifier every tick for the length of the outage would slow the
        # capture loop exactly when it matters. Retry while attempts remain,
        # then latch to stop retrying -- but leave `_kismet_down_delivered`
        # False, so the recovery edge stays honest about what was actually said.
        if self._kismet_down_attempts >= NOTIFY_MAX_ATTEMPTS:
            logger.error(
                "Kismet unreachable for %d consecutive polls and the down "
                "notification FAILED all %d delivery attempts — the operator "
                "has NOT been told that RF capture stopped",
                self._consecutive_poll_failures,
                self._kismet_down_attempts,
            )
            self._kismet_down_alerted = True
            return
        logger.warning(
            "Kismet unreachable for %d consecutive polls; down notification "
            "delivery failed (attempt %d of %d) — will retry next tick",
            self._consecutive_poll_failures,
            self._kismet_down_attempts,
            NOTIFY_MAX_ATTEMPTS,
        )

    def clock_is_trusted(self, now_ts: int) -> bool:
        """Delegates to `ClockAnchor.is_trusted`; see it for the reasoning.

        Kept as a method because it is the daemon's per-tick entry point and
        several tests drive it through a Poller.

        ⚠️ Mutates hold state, so call it exactly once per tick.
        """
        return self._clock.is_trusted(now_ts)

    def run_forever(self) -> None:
        try:
            signal.signal(signal.SIGTERM, self._on_signal)
            signal.signal(signal.SIGINT, self._on_signal)
        except ValueError:
            pass
        # Additive, flag-gated BLE bridge. OFF by default => bridge stays None
        # and the poll loop below is byte-identical to before. A start failure
        # must never take down Kismet polling, so it is caught and logged.
        bridge = None
        bridge_thread = None
        if self.config.ble_bridge.enabled:
            try:
                # ⛔ Clear BEFORE starting. A stamp left by the previous run
                # is already older than the stall window, so inheriting it
                # would grade a legitimately warming-up bridge as stalled on
                # every daemon start. Absent routes through the bounded
                # warm-up grace instead, which is what start means.
                self.db.set_state(STATE_KEY_BLE_BRIDGE_SCAN_TS, "")
                self._ble_bridge_started_at = int(time.time())
                bridge, bridge_thread = self._start_ble_bridge()
                self.db.set_state(STATE_KEY_BLE_BRIDGE_STATUS, BLE_BRIDGE_RUNNING)
            except Exception:
                logger.error("BLE bridge failed to start; continuing without it", exc_info=True)
                bridge, bridge_thread = None, None
                # ⛔ Record it. Continuing without the bridge is the right call
                # for Kismet polling, but until now it was also INVISIBLE: the
                # heartbeat reported "still watching" while BLE-only devices —
                # the trackers this tool exists to find — were not being seen
                # at all, and stayed unseen until someone restarted the daemon.
                self.db.set_state(STATE_KEY_BLE_BRIDGE_STATUS, BLE_BRIDGE_FAILED)
        try:
            while not self._stop_flag:
                # Per-iteration exception boundary. A single transient failure
                # (Kismet 5xx, DNS hiccup, malformed device record raising
                # ValidationError mid-poll) used to escape the loop and exit
                # the daemon. Catching here keeps the poll loop alive and
                # logs the traceback so journalctl shows what happened.
                # KeyboardInterrupt and SystemExit (BaseException, not
                # Exception) propagate so Ctrl+C / ``systemctl stop`` still
                # work cleanly — the outer ``finally`` still runs and closes
                # the DB before the signal is re-raised.
                poll_failed = False
                try:
                    self._maybe_reload_allowlist()
                    now_ts = int(time.time())
                    # ⛔ Observe the bridge BEFORE composing the heartbeat, so
                    # the heartbeat inside poll_once reads this tick's truth
                    # rather than the previous one. A thread can die without its
                    # own except handler running — killed, or an error escaping
                    # the callback — so liveness is checked here rather than
                    # trusted to the crash path to report itself.
                    self._observe_ble_bridge(bridge_thread)
                    # Exactly once per tick: it advances the hold counter.
                    clock_trusted = self.clock_is_trusted(now_ts)
                    poll_once(
                        self.client,
                        self.db,
                        self.config,
                        now_ts,
                        clock_trusted=clock_trusted,
                        ruleset=self.ruleset,
                        allowlist=self.allowlist,
                        notifier=self.notifier,
                        source_allowlist=self._resolve_source_allowlist(),
                        source_locations=self.config.kismet_source_locations,
                        severity_overrides=self.severity_overrides,
                        rule_type_suppression_counter=self._rule_type_suppression_counter,
                    )
                    self._maybe_clear_source_alias_map_on_drops()
                    self._maybe_flush_suppression_summary(now_ts=now_ts)
                except Exception:
                    logger.error("poll_once raised; continuing", exc_info=True)
                    poll_failed = True
                # Runtime Kismet-loss paired alert (0.9.1). Guarded separately
                # so a misbehaving notifier can't kill the poll loop — the same
                # loop-survival invariant the poll_once boundary above protects.
                try:
                    self._note_kismet_poll_result(poll_failed)
                except Exception:
                    logger.error(
                        "Kismet-loss alert handling raised; continuing",
                        exc_info=True,
                    )
                self._interruptible_sleep(self.config.poll_interval_seconds)
        finally:
            if bridge is not None:
                self._stop_ble_bridge(bridge, bridge_thread)
                # A clean shutdown is not a fault. Without this the last thing
                # written would be "running" or "failed", and the next start
                # would inherit a stale verdict about a process that has ended.
                self.db.set_state(STATE_KEY_BLE_BRIDGE_STATUS, BLE_BRIDGE_STOPPED)
            self.db.close()

    def _observe_ble_bridge(self, thread) -> None:
        """Record whether the BLE bridge is still alive, once per tick.

        ⚠️ Only ever writes when the bridge is ENABLED. On the default install
        the key stays absent, and `_compose_heartbeat` treats absent as "not in
        use" rather than as a fault — a dead-man's switch that complains about a
        feature nobody turned on is one the operator learns to ignore.

        Wrapped defensively like the rest of the per-tick housekeeping: failing
        to record bridge health must not abort the poll loop, because Kismet
        capture is still running and is the more important of the two.
        """
        if not self.config.ble_bridge.enabled:
            return
        try:
            if thread is None or not thread.is_alive():
                status = BLE_BRIDGE_FAILED
            else:
                status = self._grade_ble_scan_liveness()
            if status != self._ble_bridge_last_status:
                if status == BLE_BRIDGE_FAILED:
                    logger.error(
                        "BLE bridge is not running; BLE-only devices are not "
                        "being seen. Kismet capture is unaffected."
                    )
                elif status == BLE_BRIDGE_STALLED:
                    logger.error(
                        "BLE bridge thread is alive but has completed no scan "
                        "for over %ss; BLE-only devices are not being seen. "
                        "Kismet capture is unaffected.",
                        2 * effective_ble_flush_interval(self.config),
                    )
                self.db.set_state(STATE_KEY_BLE_BRIDGE_STATUS, status)
                self._ble_bridge_last_status = status
        except Exception as e:
            logger.warning("could not record BLE bridge status: %s", e)

    def _grade_ble_scan_liveness(self) -> str:
        """RUNNING or STALLED for a bridge thread that is confirmed alive.

        ⛔ `thread.is_alive()` is a liveness test for the THREAD, not for the
        capture. `BleBridge.run` deliberately catches every bleak/BlueZ failure
        and restarts the scan after a backoff — correct, because an adapter that
        comes back should be picked up without a daemon restart, but it means an
        adapter that never comes back leaves a thread that is alive forever and
        scanning never. This reads the stamp the scan loop itself writes.

        ⚠️ A QUIET room must stay RUNNING. The stamp comes from the tick flush,
        which turns whether or not any advert was buffered, so zero devices seen
        is not evidence of a fault — and grading on device count would report a
        stalled bridge for most operators most of the time.

        ⚠️ `0 <= age`, not `age <= window` alone. A stamp dated in the FUTURE is
        what a clock excursion leaves behind, and a bare upper bound reads that
        as "extremely recent" and reports healthy for the whole excursion —
        the defect `_compose_heartbeat` clause 1 already carries a guard for,
        and which retention.py and evidence.py bound the same way.
        """
        window = 2 * effective_ble_flush_interval(self.config)
        now_ts = int(time.time())
        stamp: int | None = None
        raw = self.db.get_state(STATE_KEY_BLE_BRIDGE_SCAN_TS)
        if raw:
            try:
                stamp = int(raw)
            except (TypeError, ValueError):
                stamp = None
        if stamp is None:
            # No scan has stamped since this bridge was started. That is normal
            # until the first tick lands, and a fault after that: without the
            # grace period every daemon start would report a stalled bridge.
            started = self._ble_bridge_started_at
            if started is None or 0 <= now_ts - started <= window:
                return BLE_BRIDGE_RUNNING
            return BLE_BRIDGE_STALLED
        age = now_ts - stamp
        return BLE_BRIDGE_RUNNING if 0 <= age <= window else BLE_BRIDGE_STALLED

    def _start_ble_bridge(self):
        """Construct + start the passive BLE bridge in a daemon thread.

        The bridge gets the Poller's shared deps (ruleset, notifier, config,
        severity_overrides) and a LIVE allowlist provider — ``lambda:
        self.allowlist`` reads the attribute on each flush, so the hot-reloaded
        allowlist (reassigned atomically in _maybe_reload_allowlist) reaches the
        bridge. It opens its OWN Database on the same path (WAL second writer);
        the poller's connection is never shared.
        """
        # Local import breaks the poller <-> bridges.ble import cycle
        # (bridges.ble imports process_observation from this module).
        from .bridges.ble import BleBridge

        cfg = self.config.ble_bridge
        flush_interval = effective_ble_flush_interval(self.config)
        bridge = BleBridge(
            db=Database(self.config.db_path),
            config=self.config,
            ruleset=self.ruleset,
            allowlist_provider=lambda: self.allowlist,
            notifier=self.notifier,
            severity_overrides=self.severity_overrides,
            location_id=self.config.location_id,
            location_label=self.config.location_label,
            adapter=cfg.adapter,
            flush_interval=flush_interval,
        )

        def _thread_main() -> None:
            try:
                asyncio.run(bridge.run())
            except Exception:
                logger.error("BLE bridge thread crashed", exc_info=True)

        thread = threading.Thread(target=_thread_main, name="ble-bridge", daemon=True)
        thread.start()
        logger.info(
            "BLE bridge started (adapter=%s, flush_interval=%ss)", cfg.adapter, flush_interval
        )
        return bridge, thread

    def _stop_ble_bridge(self, bridge, thread) -> None:
        """Stop the bridge and join its thread; run()'s finally closes its DB."""
        try:
            bridge.stop()
        except Exception:
            logger.error("BLE bridge stop() raised", exc_info=True)
        if thread is not None:
            thread.join(timeout=BLE_BRIDGE_JOIN_TIMEOUT_SECONDS)
            if thread.is_alive():
                logger.warning(
                    "BLE bridge thread did not stop within %ss",
                    BLE_BRIDGE_JOIN_TIMEOUT_SECONDS,
                )
        logger.info("BLE bridge stopped")

    def run_once(self) -> int:
        try:
            self._maybe_reload_allowlist()
            now_ts = int(time.time())
            processed = poll_once(
                self.client,
                self.db,
                self.config,
                now_ts,
                ruleset=self.ruleset,
                allowlist=self.allowlist,
                notifier=self.notifier,
                source_allowlist=self._resolve_source_allowlist(),
                source_locations=self.config.kismet_source_locations,
                severity_overrides=self.severity_overrides,
                rule_type_suppression_counter=self._rule_type_suppression_counter,
            )
            self._maybe_clear_source_alias_map_on_drops()
            self._maybe_flush_suppression_summary(now_ts=now_ts)
            return processed
        finally:
            self.db.close()


# --- TTY-gated startup banner ----------------------------------------------
#
# Shown only when stdout is a TTY: direct invocation like
# ``lynceus --config foo.yaml`` from a terminal. Suppressed under
# ``lynceus-quickstart`` (which pipes stdout to TeeSupervisor) and under
# systemd (which captures stdout to journalctl) because ASCII art is
# noise in both cases. Service-mode startup logs a single INFO line
# ``Lynceus daemon started, N rules active, watching M interfaces``
# instead — operators grepping ``journalctl -u lynceus.service`` get a
# clear start marker without the box-drawing garbage.

_STARTUP_BANNER = r""" _
| |   _   _ _ __   ___ ___ _   _ ___
| |  | | | | '_ \ / __/ _ \ | | / __|
| |__| |_| | | | | (_|  __/ |_| \__ \
|_____\__, |_| |_|\___\___|\__,_|___/
      |___/   - the watcher daemon -"""


def emit_startup_banner(
    *,
    active_rules: int,
    source_count: int,
    file=None,
    is_tty: bool | None = None,
) -> None:
    """Emit the startup announcement.

    TTY: ASCII banner plus a dynamic subtitle naming version,
    rule-count, and interface count. Service mode (no TTY): one INFO
    log line carrying the same counts. ``is_tty`` defaults to
    ``file.isatty()`` (or ``sys.stdout.isatty()`` when ``file`` is
    None) — overridable so unit tests can exercise both branches
    without needing a real pty.

    A failure to flush stdout is swallowed: the banner is a courtesy,
    not load-bearing, and a closed-stdout scenario must not crash
    daemon startup.
    """
    out = file if file is not None else sys.stdout
    if is_tty is None:
        is_tty = out.isatty() if hasattr(out, "isatty") else False

    if is_tty:
        subtitle = (
            f"v{__version__}  •  watching {active_rules} rules across "
            f"{source_count} interfaces  •  ctrl-c to stop"
        )
        print(_STARTUP_BANNER, file=out)
        print(subtitle, file=out)
        print(file=out)
        try:
            out.flush()
        except Exception:
            pass
    else:
        logger.info(
            "Lynceus daemon started, %d rules active, watching %d interfaces",
            active_rules,
            source_count,
        )


def _count_active_rules(poller: Poller) -> int:
    """Total rules with ``enabled`` truthy; mirrors the existing INFO
    line emitted by Poller.__init__ so the banner agrees with what
    operators already see in their logs."""
    return sum(1 for r in poller.ruleset.rules if r.enabled)


def _count_kismet_sources(config: Config) -> int:
    """0 when ``kismet_sources`` is unset (treated as no filter); the
    banner-side count matches the operator's lynceus.yaml literally so
    a wrong banner number always points to a wrong config rather than
    a wrong derivation."""
    return len(config.kismet_sources) if config.kismet_sources else 0


def _log_config_provenance(config_path: str) -> None:
    """Emit the startup config-provenance lines (v0.7.5 aggregation style).

    One INFO names the config file the daemon loaded and its scope, so a
    scope mismatch ("I edited /etc but the daemon read ~/.config") is visible
    at a glance in ``journalctl`` instead of inferred from a downstream
    stale-key failure. When a config ALSO exists in the OTHER canonical scope,
    one additional WARNING names both files, says which is in use, and flags
    which is newer — turning a silent shadow into a loud startup line.
    Observability only — never blocks startup."""
    scope = paths.classify_config_scope(config_path)
    scope_label = f"{scope} scope" if scope else "custom path"
    logger.info("config: using %s (%s)", config_path, scope_label)
    shadow = paths.describe_shadowing(config_path)
    if shadow:
        logger.warning(shadow)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="lynceus")
    parser.add_argument("--config", required=True)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)

    try:
        config = load_config(args.config)
        logging.basicConfig(level=config.log_level)
        _log_config_provenance(args.config)
        poller = Poller(config, config_path=args.config)
        emit_startup_banner(
            active_rules=_count_active_rules(poller),
            source_count=_count_kismet_sources(config),
        )
        if args.once:
            poller.run_once()
        else:
            poller.run_forever()
        return 0
    except Exception:
        logger.exception("fatal error in main")
        return 1
