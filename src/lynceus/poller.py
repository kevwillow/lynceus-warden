"""Poll loop: fetch from Kismet on an interval, persist, and trigger rule eval."""

from __future__ import annotations

import argparse
import datetime as _dt
import logging
import signal
import time
from pathlib import Path

from . import __version__
from .allowlist import (
    Allowlist,
    _load_allowlist_with_counts,
    derive_ui_path,
    load_allowlist,
)
from .config import Config, load_config
from .db import Database
from .evidence import capture_evidence, maybe_prune_evidence
from .kismet import FakeKismetClient, KismetClient
from .notify import Notifier, NullNotifier, build_metadata_suffix, build_notifier
from .rules import (
    Ruleset,
    RuntimeSeverityOverride,
    evaluate,
    load_ruleset,
    load_runtime_severity_overrides,
)

STATE_KEY_LAST_POLL = "last_poll_ts"

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

logger = logging.getLogger(__name__)


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
    observations = client.get_devices_since(
        last_poll_ts,
        capture_probe_ssids=config.capture.probe_ssids,
        capture_ble_name=config.capture.ble_friendly_names,
        evidence_capture_enabled=config.evidence_capture_enabled,
    )
    processed = 0
    for obs in observations:
        try:
            if source_allowlist is not None:
                if not obs.seen_by_sources:
                    logger.debug(
                        "obs %s has no source attribution, dropping under source_allowlist",
                        obs.mac,
                    )
                    continue
                if not any(s in source_allowlist for s in obs.seen_by_sources):
                    logger.debug(
                        "obs %s sources %r not in allowlist, dropping",
                        obs.mac,
                        obs.seen_by_sources,
                    )
                    continue
            if config.min_rssi is not None and obs.rssi is not None and obs.rssi < config.min_rssi:
                logger.debug(
                    "obs %s rssi=%s below min_rssi=%s, dropping",
                    obs.mac,
                    obs.rssi,
                    config.min_rssi,
                )
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
            if config.capture.ble_friendly_names and obs.ble_name:
                db.update_device_ble_name(obs.mac, obs.ble_name)
            db.insert_sighting(
                mac=obs.mac,
                ts=obs.last_seen,
                rssi=obs.rssi,
                ssid=obs.ssid,
                location_id=effective_location_id,
            )
            processed += 1
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
                if hit_match_id is not None:
                    try:
                        md = db.get_metadata_by_watchlist_id(hit_match_id)
                        suffix = build_metadata_suffix(md)
                    except Exception:
                        suffix = ""
                try:
                    ok = notifier.send(
                        severity=hit.severity,
                        title=title,
                        message=hit.message + suffix,
                    )
                    if not ok:
                        logger.warning("Notifier returned False for %s/%s", hit.rule_name, hit.mac)
                except Exception as e:
                    logger.warning("Notifier raised for %s/%s: %s", hit.rule_name, hit.mac, e)
        except Exception as e:
            logger.warning("Failed to persist observation %s: %s", obs.mac, e)
            continue
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
    def __init__(self, config: Config) -> None:
        self.config = config
        self.db = Database(config.db_path)
        self.client = build_kismet_client(config)
        if config.kismet_health_check_on_startup:
            self._startup_health_check()
        self._source_allowlist: frozenset[str] | None = (
            frozenset(config.kismet_sources) if config.kismet_sources else None
        )
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
        # Rule_type snooze suppression accumulator. Cumulative across
        # poll cycles; flushed to an INFO summary every
        # SUPPRESSION_LOG_INTERVAL_SECONDS. Initialized to "log on the
        # first tick that produces a non-empty counter past the
        # interval boundary" — anchoring to instance-creation time so
        # restarts don't produce a phantom summary on the first tick.
        self._rule_type_suppression_counter: dict[str, int] = {}
        self._last_suppression_log_ts: int = int(time.time())

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
        attempts; only after all of them fail do we surface the same
        ``RuntimeError`` callers have always seen, so behaviour at the
        ``main()`` boundary is unchanged.
        """
        backoff = HEALTH_CHECK_RETRY_BACKOFF
        total = len(backoff)
        last_err: str = "unknown error"
        for attempt in range(1, total + 1):
            health = self.client.health_check()
            if health.get("reachable"):
                return
            last_err = health.get("error") or "unknown error"
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
        raise RuntimeError(
            f"Kismet unreachable at startup: {last_err}. "
            "Set kismet_health_check_on_startup=false to skip this check."
        )

    def _on_signal(self, signum: int, frame: object) -> None:
        self._stop_flag = True

    def _interruptible_sleep(self, seconds: int) -> None:
        for _ in range(seconds):
            if self._stop_flag:
                return
            time.sleep(1)

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
                        source_allowlist=self._source_allowlist,
                        source_locations=self.config.kismet_source_locations,
                        severity_overrides=self.severity_overrides,
                        rule_type_suppression_counter=self._rule_type_suppression_counter,
                    )
                    self._maybe_flush_suppression_summary(now_ts=now_ts)
                except Exception:
                    logger.error("poll_once raised; continuing", exc_info=True)
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
                source_allowlist=self._source_allowlist,
                source_locations=self.config.kismet_source_locations,
                severity_overrides=self.severity_overrides,
                rule_type_suppression_counter=self._rule_type_suppression_counter,
            )
            self._maybe_flush_suppression_summary(now_ts=now_ts)
            return processed
        finally:
            self.db.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="lynceus")
    parser.add_argument("--config", required=True)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)

    try:
        config = load_config(args.config)
        logging.basicConfig(level=config.log_level)
        poller = Poller(config)
        if args.once:
            poller.run_once()
        else:
            poller.run_forever()
        return 0
    except Exception:
        logger.exception("fatal error in main")
        return 1
