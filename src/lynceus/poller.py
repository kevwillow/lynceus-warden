"""Poll loop: fetch from Kismet on an interval, persist, and trigger rule eval."""

from __future__ import annotations

import argparse
import datetime as _dt
import logging
import signal
import sys
import time
from pathlib import Path

from . import __version__, paths
from .allowlist import (
    Allowlist,
    _load_allowlist_with_counts,
    derive_ui_path,
    load_allowlist,
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
from .rules import (
    Ruleset,
    RuntimeSeverityOverride,
    evaluate,
    load_ruleset,
    load_runtime_severity_overrides,
)

STATE_KEY_LAST_POLL = "last_poll_ts"

# Per-tick counters surfaced on the home page, in /healthz, and as the
# INFO heartbeat in journalctl. Each key is overwritten in place on
# every poll tick (last-tick semantics, not cumulative) so the
# poller_state table stays bounded. The three drop reasons mirror the
# silent-drop sites the diagnostic identified: source_allowlist /
# min_rssi gates inside poll_once and the parser-None bucket counted
# inside KismetClient.get_devices_since via the unparseable_counter
# kwarg.
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

logger = logging.getLogger(__name__)


def _emit_watchful_escalation(
    db: Database,
    notifier: Notifier,
    entry: WatchfulRecurrence,
    now_ts: int,
) -> None:
    """Emit the synthetic ``watchful_recurrence`` escalation alert.

    Called once at the first threshold-cross for an entry (the
    ``db.escalate_watchful_recurrence`` idempotency guard ensures
    "fire once per escalation"). Independent of the entry's own
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
        db.add_alert(
            ts=now_ts,
            rule_name="watchful_recurrence",
            mac=entry.mac,
            message=message,
            severity="high",
            matched_watchlist_id=entry.matched_watchlist_id,
            rule_type="watchful_recurrence",
        )
    except Exception as e:
        logger.warning(
            "Failed to write watchful escalation alert for %s: %s",
            entry.mac,
            e,
        )
        return
    try:
        ok = notifier.send(
            severity="high",
            title="lynceus: watchful escalation",
            message=message,
            priority_override=4,
        )
        if not ok:
            logger.warning(
                "Notifier returned False for watchful escalation %s",
                entry.mac,
            )
    except Exception as e:
        logger.warning(
            "Notifier raised for watchful escalation %s: %s",
            entry.mac,
            e,
        )


def build_kismet_client(config: Config) -> KismetClient:
    if config.kismet_fixture_path:
        return FakeKismetClient(config.kismet_fixture_path)
    return KismetClient(
        config.kismet_url,
        api_key=config.kismet_api_key,
        timeout=config.kismet_timeout_seconds,
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
) -> int:
    """Run one poll tick: fetch from Kismet, persist sightings, evaluate rules.

    Allowlist precedence: a device matching any allowlist entry is suppressed,
    regardless of any watchlist rules it would have matched. When suppression
    hides what would have been a watchlist hit, an INFO-level audit line is
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
    processed = 0
    admitted = 0
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

            existing_device = db.get_device(obs.mac)
            is_new = existing_device is None
            db.ensure_location(effective_location_id, effective_location_label)
            db.upsert_device(
                mac=obs.mac,
                device_type=obs.device_type,
                oui_vendor=obs.oui_vendor,
                is_randomized=int(obs.is_randomized),
                now_ts=now_ts,
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
            db.insert_sighting(
                mac=obs.mac,
                ts=obs.last_seen,
                rssi=obs.rssi,
                ssid=obs.ssid,
                location_id=effective_location_id,
            )
            processed += 1
            admitted += 1
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
                for sh in suppressed_hits:
                    if sh.rule_type == "new_non_randomized_device":
                        continue
                    logger.info(
                        "Allowlist suppressed watchlist hit: rule=%s mac=%s severity=%s%s",
                        sh.rule_name,
                        obs.mac,
                        sh.severity,
                        expires_suffix,
                    )
                continue
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
            watchful_entry = db.get_active_watchful_recurrence_by_mac(obs.mac)
            if watchful_entry is not None:
                outcome = db.record_watchful_sighting(watchful_entry.id, now_ts)
                if outcome is not None:
                    # Threshold detection. escalate_watchful_recurrence
                    # is idempotent (no-op if escalated_at already
                    # set), which drives the design doc's "fire once
                    # per escalation" rule without a separate
                    # first-crossing guard here.
                    if (
                        outcome.counted
                        and outcome.entry.sighting_count
                        >= Database.WATCHFUL_RECURRENCE_ESCALATION_THRESHOLD
                    ):
                        escalated = db.escalate_watchful_recurrence(
                            watchful_entry.id, now_ts
                        )
                        if escalated is not None:
                            # First crossing. Subject only to the
                            # per-rule_type snooze on watchful_recurrence
                            # (per design doc: detection runs;
                            # notification doesn't, while the snooze
                            # is active).
                            rt_snooze = db.is_rule_type_snoozed(
                                "watchful_recurrence", now_ts
                            )
                            if rt_snooze is None:
                                _emit_watchful_escalation(
                                    db, notifier, escalated, now_ts
                                )
                            else:
                                logger.debug(
                                    "watchful escalation suppressed by "
                                    "rule_type snooze: mac=%s",
                                    obs.mac,
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
                        continue
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
                if config.alert_dedup_window_seconds > 0:
                    since = now_ts - config.alert_dedup_window_seconds
                    if (
                        db.get_recent_alert_for_rule_and_mac(hit.rule_name, hit.mac, since)
                        is not None
                    ):
                        logger.debug("dedup-skip %s/%s", hit.rule_name, hit.mac)
                        continue
                hit_match_id = (
                    matched_watchlist_id if hit.rule_type != "new_non_randomized_device" else None
                )
                try:
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
                    logger.warning("Failed to write alert %s for %s: %s", hit.rule_name, hit.mac, e)
                    continue
                if config.evidence_capture_enabled and obs.raw_record is not None:
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
                try:
                    ok = notifier.send(
                        severity=hit.severity,
                        title=title,
                        message=hit.message + suffix + type_suffix,
                    )
                    if not ok:
                        logger.warning("Notifier returned False for %s/%s", hit.rule_name, hit.mac)
                except Exception as e:
                    logger.warning("Notifier raised for %s/%s: %s", hit.rule_name, hit.mac, e)
        except Exception as e:
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
        admitted,
        dropped_total,
        dropped_source_allowlist,
        dropped_min_rssi,
        dropped_unparseable,
    )
    db.set_state(STATE_KEY_LAST_TICK_ADMITTED, str(admitted))
    db.set_state(
        STATE_KEY_LAST_TICK_DROPPED_SOURCE_ALLOWLIST,
        str(dropped_source_allowlist),
    )
    db.set_state(STATE_KEY_LAST_TICK_DROPPED_MIN_RSSI, str(dropped_min_rssi))
    db.set_state(
        STATE_KEY_LAST_TICK_DROPPED_UNPARSEABLE, str(dropped_unparseable)
    )
    db.set_state(STATE_KEY_LAST_TICK_COMPLETED_AT, str(now_ts))
    db.set_state(STATE_KEY_LAST_POLL, str(now_ts))
    # Per-poll housekeeping for the rule_type_snoozes table: physically
    # delete rows whose expires_at has passed. Cheap (table is tiny;
    # indexed on expires_at) and defensive — the gate's
    # ``expires_at > now_ts`` filter already ignores expired rows, so a
    # missed cleanup never affects correctness, only steady-state row
    # count. Wrapped defensively for the same reason as the evidence
    # prune below: a housekeeping failure must not abort the poll loop.
    try:
        purged = db.cleanup_expired_rule_type_snoozes(now_ts)
        if purged > 0:
            logger.debug(
                "rule_type_snoozes: purged %d expired row(s) on poll cycle",
                purged,
            )
    except Exception as e:
        logger.warning("rule_type_snoozes cleanup failed: %s", e)
    # Per-poll housekeeping for watchful_recurrence: archive entries
    # whose last_seen_at is >= 90 days stale. Per OQ-3 this is the
    # SOLE lifecycle clock for unactioned watchful entries --
    # snooze_expires_at does not drive any housekeeping action.
    # Idempotent and cheap (indexed on archived_at; bounded by the
    # watchful table's small steady-state size). Wrapped defensively
    # for the same reason as the surrounding housekeeping blocks: a
    # failure here must not abort the poll loop.
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
    try:
        maybe_prune_evidence(db, config.evidence_retention_days, now_ts=now_ts)
    except Exception as e:
        logger.warning("Evidence prune failed: %s", e)
    return processed


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
    # meta line was unparseable. ``age_seconds`` ≥ 0 in practice; a
    # negative value would mean the timestamp is in the future
    # (clock skew). We clamp to >= 0 for the days arithmetic but
    # surface the raw timestamp for forensic clarity.
    reference_ts = latest["exported_at"] or latest["imported_at"]
    age_seconds = max(0, now_ts - int(reference_ts))
    age_days = age_seconds // 86400
    exported_at = latest["exported_at"]
    exported_iso = (
        _dt.datetime.fromtimestamp(int(exported_at), tz=_dt.UTC).strftime("%Y-%m-%d")
        if exported_at is not None
        else "unknown"
    )

    if age_days > warn_days:
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


class Poller:
    def __init__(self, config: Config, config_path: str | None = None) -> None:
        self.config = config
        # The resolved YAML path the daemon was launched with (``--config``),
        # plumbed through so the startup health-check failure can name the
        # exact file a rejected key came from. ``None`` for in-process callers
        # (tests, embedded use) that build a Poller from a Config object with
        # no backing file.
        self.config_path = config_path
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
        # (`wlx00c0cab966f8`) in lynceus.yaml. The two appear in
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
            derive_ui_path(self._allowlist_primary_path)
            if self._allowlist_primary_path is not None
            else None
        )
        self._allowlist_mtimes: dict[Path, float] = {}
        if self._allowlist_primary_path is not None:
            self.allowlist = load_allowlist(str(self._allowlist_primary_path))
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

        Operator config of `kismet_sources: [wlx00c0cab966f8, hci1]` plus
        an alias map `{wlx00c0cab966f8: {wlx00c0cab966f8, kismon0}, ...}`
        yields `{wlx00c0cab966f8, kismon0, hci1}`. Names not present in
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
        for p in (self._allowlist_primary_path, self._allowlist_ui_path):
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
                str(self._allowlist_primary_path)
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
            if self._kismet_down_alerted:
                self.notifier.send(
                    "high",
                    "Lynceus: Kismet reachable again",
                    "Kismet is reachable again — RF capture resumed.",
                    priority_override=4,
                )
                logger.info("Kismet reachable again; sent recovery notification")
                self._kismet_down_alerted = False
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
        self.notifier.send(
            "high",
            "Lynceus: Kismet unreachable",
            f"Kismet at {self.config.kismet_url} is unreachable — "
            f"RF capture stopped. Last error: {error}",
            priority_override=4,
        )
        logger.warning(
            "Kismet unreachable for %d consecutive polls; sent down notification",
            self._consecutive_poll_failures,
        )
        self._kismet_down_alerted = True

    def run_forever(self) -> None:
        try:
            signal.signal(signal.SIGTERM, self._on_signal)
            signal.signal(signal.SIGINT, self._on_signal)
        except ValueError:
            pass
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
                    poll_once(
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
            self.db.close()

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
