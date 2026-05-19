"""SQLite persistence layer: schema, migrations, and connection helpers."""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import sys
import time
from pathlib import Path
from types import TracebackType
from typing import NamedTuple

logger = logging.getLogger(__name__)


class ResolvedMacRangeMatch(NamedTuple):
    """A watchlist mac_range row that matched an observed MAC.

    Returned by ``Database.resolve_matched_mac_range``. Carries the
    watchlist row id (for ``alerts.matched_watchlist_id`` stamping),
    the row's severity (sourced from the matched row, NOT from any
    rules.yaml entry — see ``rules.evaluate`` for the
    severity-from-DB rationale), the matched prefix length (28 or 36,
    for downstream display / logging), and the matched row's
    ``device_category`` from ``watchlist_metadata`` if present (NULL
    for rows without a metadata row, e.g. the 63 bundled
    default_watchlist rows that ship without device_category).

    ``device_category`` powers the runtime severity-overrides layer
    (``rules.RuntimeSeverityOverride``): the eval branch uses it to
    look up per-category remap and suppression entries from
    severity_overrides.yaml at alert time, on top of whatever
    severity was baked at import time. NULL category means the row
    has no metadata to key on; the runtime layer passes through.

    ``manufacturer`` is the matched row's ``watchlist_metadata.vendor``
    column (named ``manufacturer`` on the Python side to mirror the
    Argus CSV column it ultimately sources from; see
    ``import_argus.py``'s mapping of CSV ``manufacturer`` → DB
    ``vendor``). Powers the runtime ``suppress_vendors`` key on the
    same RuntimeSeverityOverride: vendor-level suppression at alert
    time, case-insensitive exact match. NULL manufacturer (no
    metadata row, or a metadata row with NULL vendor) means the
    runtime layer's vendor check passes through.

    ``argus_record_id`` is the matched row's
    ``watchlist_metadata.argus_record_id`` column — the stable
    16-hex SHA-256 prefix Argus emits as its consumer-facing
    identifier. Powers the runtime ``pattern_overrides`` key:
    row-level severity remap by exact argus_record_id match. NULL
    (no metadata row, e.g. the 63 bundled default_watchlist rows or
    operator-seeded rows via ``lynceus-seed-watchlist``) means the
    pattern_overrides check skips entirely — falls through to the
    category-level layer.
    """

    watchlist_id: int
    severity: str
    prefix_length: int
    device_category: str | None
    manufacturer: str | None
    argus_record_id: str | None


class ResolvedWatchlistMatch(NamedTuple):
    """A watchlist row matched by a DB-delegated rule_type.

    Returned by ``Database.resolve_matched_{mac,oui,ssid,ble_uuid}_for_eval``
    — the eval-time matchers that back the empty-patterns delegation
    semantic established in lockstep with ``ResolvedMacRangeMatch``.
    Same severity-from-row contract: the consuming rules.evaluate
    branches stamp the emitted RuleHit with this severity, NOT the
    rule's severity, so that imported per-row severities (e.g. the
    Argus device_category-derived defaults) survive into alerts.

    ``device_category`` is the matched row's ``watchlist_metadata.
    device_category`` (or None when no metadata row exists), and
    powers the runtime severity-overrides layer the same way
    ``ResolvedMacRangeMatch.device_category`` does — see that
    NamedTuple's docstring for the full rationale. NULL category
    means the row has no metadata to key on; the runtime layer
    passes through.

    ``manufacturer`` mirrors ``ResolvedMacRangeMatch.manufacturer``:
    sourced from ``watchlist_metadata.vendor``, Python-side name
    matches the Argus CSV column, powers ``suppress_vendors``.

    ``argus_record_id`` mirrors
    ``ResolvedMacRangeMatch.argus_record_id``: sourced directly from
    ``watchlist_metadata.argus_record_id`` (no rename), powers the
    runtime ``pattern_overrides`` row-level remap. NULL for rows
    without a metadata row.
    """

    watchlist_id: int
    severity: str
    device_category: str | None
    manufacturer: str | None
    argus_record_id: str | None


class WatchlistRow(NamedTuple):
    """A single watchlist row projected for the /watchlist list page.

    Returned by ``Database.list_watchlist_filtered`` as the row side
    of the ``(rows, total)`` tuple. The shape carries every column
    the list template renders -- pattern + pattern_type + severity +
    description from ``watchlist``, plus the small subset of
    ``watchlist_metadata`` columns the list view actually shows
    (vendor, confidence, device_category, argus_record_id). The
    detail page still reads the full metadata row via
    ``list_watchlist_with_metadata`` -- the projection here keeps
    each list query at one SELECT per page render rather than
    materializing 20+ unused columns for 22k rows.

    ``vendor`` / ``device_category`` / ``argus_record_id`` /
    ``confidence`` are NULL when the row has no
    ``watchlist_metadata`` JOIN partner (i.e. yaml-seeded or bundled
    rows without an Argus side-table entry). The template renders
    each as an empty string in that case; the filter helper exposes
    ``device_category=__none__`` as the explicit "uncategorized"
    selector.
    """

    id: int
    pattern: str
    pattern_type: str
    severity: str
    description: str | None
    mac_range_prefix: str | None
    mac_range_prefix_length: int | None
    vendor: str | None
    confidence: int | None
    device_category: str | None
    argus_record_id: str | None


class RuleStats(NamedTuple):
    """Per-rule fire counts + last-fired timestamp for a time window.

    Returned by ``Database.count_alerts_grouped_by_rule_name`` as the
    value side of the ``{rule_name: RuleStats}`` dict. ``count`` is
    the number of alerts with the given ``rule_name`` whose ``ts``
    falls in the requested window; ``last_fired_ts`` is the
    ``MAX(ts)`` for that same set. Both come from a single
    aggregation query — caller pays for one round-trip regardless of
    how many rules.yaml entries exist.

    Rules that never fired in the window are absent from the dict
    entirely; the /rules handler defaults missing entries to
    ``RuleStats(count=0, last_fired_ts=None)`` so the template can
    iterate the ruleset and render "—" for inactive rules without
    branching on dict membership.
    """

    count: int
    last_fired_ts: int | None


class RuleTypeSnooze(NamedTuple):
    """One row of ``rule_type_snoozes``: an active temporary suppression.

    Mirrors the table schema from migration 017 — ``rule_type`` is the
    primary key (the ``rules.RuleType`` literal whose alerts are
    suppressed); ``expires_at`` is the absolute epoch-seconds bound at
    which the snooze stops gating (rows with ``expires_at <= now_ts``
    are filtered at gate-check time and physically deleted on the
    poller cleanup pass); ``added_at`` is when the snooze was written
    (operator audit trail / UI sort key); ``note`` is the optional
    free-text reason supplied at snooze time.

    The gate at the poller emit boundary consumes a single instance
    (``is_rule_type_snoozed`` returns ``RuleTypeSnooze | None``); the
    /rules render consumes the full active set
    (``list_active_rule_type_snoozes``). Both call sites work off the
    same shape so the template can render expiry / note consistently
    whichever helper produced the row.
    """

    rule_type: str
    expires_at: int
    added_at: int
    note: str | None


class WatchfulRecurrence(NamedTuple):
    """One row of ``watchful_recurrence``: the daemon's tracking state
    for a MAC under watchful snooze.

    Lifecycle is timestamp-derived, not stored in a `state` enum::

        escalated_at IS NULL,     archived_at IS NULL  -> tracking
        escalated_at IS NOT NULL, archived_at IS NULL  -> escalated
        archived_at IS NOT NULL                        -> archived

    ``sighting_count`` starts at 1 (the alert that prompted the
    watch is the first sighting); escalation fires when a counted
    recurrence brings the count to 4 while ``escalated_at`` is
    NULL.

    ``snooze_expires_at`` gates ALERTS ONLY: it has no effect on
    the row's lifecycle. The 90-day no-observation auto-archive is
    the sole lifecycle clock for unactioned entries.

    ``last_seen_at`` updates only on counted sightings (>=24h
    gap), not on intra-debounce observations. See migration 018
    header for the v1 recurrence model's documented consequence
    (continuously-nearby devices accumulate one sighting per
    ~24h rather than one total).

    The Phase 2 dormant columns -- ``confirmed_safe``,
    ``flagged_for_investigation``, ``operator_note``,
    ``reset_count`` -- are present on the row but are not read or
    written by Phase 1 code paths. They ship now to avoid a
    migration 019 when the operator UI lands.
    """

    id: int
    mac: str
    created_at: int
    first_seen_at: int
    last_seen_at: int
    sighting_count: int
    snooze_expires_at: int | None
    escalated_at: int | None
    archived_at: int | None
    source_alert_id: int | None
    matched_watchlist_id: int | None
    confirmed_safe: int
    flagged_for_investigation: int
    operator_note: str | None
    reset_count: int


class WatchfulSightingOutcome(NamedTuple):
    """Result of recording an observation against a watchful entry.

    ``counted`` is True when the observation was at >=24h from the
    entry's ``last_seen_at`` and incremented ``sighting_count``;
    False when the observation was under-debounce (the ambient
    case, no DB change). ``entry`` is the post-update row state in
    either case so the caller can drive escalation decisions
    (``counted AND entry.sighting_count >= 4 AND
    entry.escalated_at IS NULL`` => threshold cross) without a
    second round-trip.

    Same-cycle dedup is handled organically: the first counted
    observation in a cycle updates ``last_seen_at`` to the cycle's
    ``now_ts``; any subsequent observation in the same cycle has
    ``gap == 0 < 86400`` and is treated as under-debounce.
    """

    counted: bool
    entry: WatchfulRecurrence


def _row_to_watchful_recurrence(row: sqlite3.Row) -> WatchfulRecurrence:
    """Construct a ``WatchfulRecurrence`` from a SELECT * row.

    Factored out because the 15-column shape recurs across four
    helpers (get_active, record_sighting, escalate, and the
    re-fetch after record_sighting's UPDATE); inlining the
    NamedTuple construction at each call site would add ~60 lines
    of indistinguishable boilerplate and tempt drift between
    sites. Column order in callers' SELECT statements MUST match
    the field order here.
    """
    return WatchfulRecurrence(
        id=int(row["id"]),
        mac=str(row["mac"]),
        created_at=int(row["created_at"]),
        first_seen_at=int(row["first_seen_at"]),
        last_seen_at=int(row["last_seen_at"]),
        sighting_count=int(row["sighting_count"]),
        snooze_expires_at=(
            int(row["snooze_expires_at"])
            if row["snooze_expires_at"] is not None
            else None
        ),
        escalated_at=(
            int(row["escalated_at"]) if row["escalated_at"] is not None else None
        ),
        archived_at=(
            int(row["archived_at"]) if row["archived_at"] is not None else None
        ),
        source_alert_id=(
            int(row["source_alert_id"])
            if row["source_alert_id"] is not None
            else None
        ),
        matched_watchlist_id=(
            int(row["matched_watchlist_id"])
            if row["matched_watchlist_id"] is not None
            else None
        ),
        confirmed_safe=int(row["confirmed_safe"]),
        flagged_for_investigation=int(row["flagged_for_investigation"]),
        operator_note=row["operator_note"],
        reset_count=int(row["reset_count"]),
    )


def _find_migrations_dir() -> Path:
    try:
        from importlib.resources import files

        pkg_migrations = files("lynceus.migrations")
        as_path = Path(str(pkg_migrations))
        if as_path.is_dir() and any(as_path.glob("*.sql")):
            return as_path
    except (ModuleNotFoundError, TypeError, OSError):
        pass

    repo_relative = Path(__file__).resolve().parent.parent.parent / "migrations"
    if repo_relative.is_dir() and any(repo_relative.glob("*.sql")):
        return repo_relative

    raise FileNotFoundError(
        "Could not locate lynceus migrations directory. "
        "Expected either lynceus.migrations package data or a repo-relative migrations/ folder."
    )


class Database:
    def __init__(self, path: str) -> None:
        # sqlite3.connect with a nested non-existent path fails with the
        # opaque "unable to open database file" error. The wizard creates
        # the canonical data dir up front, but anything constructing a
        # Database() directly (tests, ad-hoc scripts, third-party callers)
        # would have hit that. ``:memory:`` has no parent to create.
        is_fresh = False
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            is_fresh = not Path(path).exists()
        self._conn = sqlite3.connect(
            path,
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
            check_same_thread=False,
        )
        # On POSIX, freshly-created user-mode DBs land at the process
        # umask (typically 0644 — world-readable). Evidence rows can
        # contain operator GPS and probe SSIDs; the system-mode install
        # already chmods to 0640 root:lynceus, but user-mode left the
        # default. Force 0600 on first creation so user-mode installs
        # don't ship a world-readable DB. Don't touch existing files —
        # operator-set modes (e.g. the 0640 from systemd install) must
        # be preserved on subsequent opens.
        if is_fresh and path != ":memory:" and sys.platform != "win32":
            try:
                os.chmod(path, 0o600)
            except OSError as exc:
                logger.warning("could not chmod 0600 on fresh database %s: %s", path, exc)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._migrations_dir = _find_migrations_dir()
        self._apply_migrations()

    def _apply_migrations(self) -> None:
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations("
            "version INTEGER PRIMARY KEY, "
            "applied_at INTEGER NOT NULL)"
        )
        self._conn.commit()
        applied = {row[0] for row in self._conn.execute("SELECT version FROM schema_migrations")}
        for sql_path in sorted(self._migrations_dir.glob("*.sql")):
            version = int(sql_path.name.split("_", 1)[0])
            if version in applied:
                continue
            sql = sql_path.read_text(encoding="utf-8")
            self._conn.executescript(sql)
            self._conn.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
                (version, int(time.time())),
            )
            self._conn.commit()

    def upsert_device(
        self,
        mac: str,
        device_type: str,
        oui_vendor: str | None,
        is_randomized: int,
        now_ts: int,
    ) -> None:
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO devices(
                    mac, device_type, first_seen, last_seen,
                    sighting_count, oui_vendor, is_randomized
                )
                VALUES (?, ?, ?, ?, 1, ?, ?)
                ON CONFLICT(mac) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    sighting_count = devices.sighting_count + 1
                """,
                (mac, device_type, now_ts, now_ts, oui_vendor, is_randomized),
            )

    PROBE_SSIDS_PER_DEVICE_CAP = 50

    def merge_device_probe_ssids(
        self,
        mac: str,
        new_ssids: list[str] | tuple[str, ...],
        *,
        cap: int = PROBE_SSIDS_PER_DEVICE_CAP,
    ) -> tuple[int, bool]:
        """Merge new probe SSIDs into the device's stored JSON list.

        The merge is order-preserving and de-duplicating: existing
        SSIDs come first, then any new strings not already present, in
        the order observed. The resulting list is truncated to ``cap``
        entries; the second tuple element indicates whether truncation
        actually happened so the caller can emit a warning.

        Returns ``(stored_count, truncated)``.
        """
        with self._conn:
            row = self._conn.execute(
                "SELECT probe_ssids FROM devices WHERE mac = ?", (mac,)
            ).fetchone()
            if row is None:
                return (0, False)
            raw = row["probe_ssids"]
            existing: list[str] = []
            if raw:
                try:
                    decoded = json.loads(raw)
                    if isinstance(decoded, list):
                        existing = [s for s in decoded if isinstance(s, str)]
                except (json.JSONDecodeError, TypeError, ValueError):
                    existing = []
            merged: list[str] = list(existing)
            seen: set[str] = set(existing)
            for ssid in new_ssids:
                if not isinstance(ssid, str) or not ssid:
                    continue
                if ssid in seen:
                    continue
                seen.add(ssid)
                merged.append(ssid)
            truncated = len(merged) > cap
            if truncated:
                merged = merged[:cap]
            payload = json.dumps(merged) if merged else None
            self._conn.execute(
                "UPDATE devices SET probe_ssids = ? WHERE mac = ?",
                (payload, mac),
            )
            return (len(merged), truncated)

    def update_device_ble_name(self, mac: str, ble_name: str) -> None:
        """Set the device's BLE friendly name. Latest write wins."""
        with self._conn:
            self._conn.execute(
                "UPDATE devices SET ble_name = ? WHERE mac = ?",
                (ble_name, mac),
            )

    def insert_sighting(
        self,
        mac: str,
        ts: int,
        rssi: int | None,
        ssid: str | None,
        location_id: str,
    ) -> int:
        with self._conn:
            cur = self._conn.execute(
                "INSERT INTO sightings(mac, ts, rssi, ssid, location_id) VALUES (?, ?, ?, ?, ?)",
                (mac, ts, rssi, ssid, location_id),
            )
            return cur.lastrowid

    def ensure_location(self, location_id: str, label: str) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO locations(id, label) VALUES (?, ?) "
                "ON CONFLICT(id) DO UPDATE SET label = excluded.label",
                (location_id, label),
            )

    def get_device(self, mac: str) -> dict | None:
        row = self._conn.execute("SELECT * FROM devices WHERE mac = ?", (mac,)).fetchone()
        return dict(row) if row else None

    def list_recent_sightings(self, since_ts: int) -> list[dict]:
        rows = self._conn.execute(
            "SELECT * FROM sightings WHERE ts >= ? ORDER BY ts ASC", (since_ts,)
        ).fetchall()
        return [dict(r) for r in rows]

    def add_alert(
        self,
        ts: int,
        rule_name: str,
        mac: str | None,
        message: str,
        severity: str,
        matched_watchlist_id: int | None = None,
        rule_type: str | None = None,
    ) -> int:
        # rule_type is the categorical RuleHit.rule_type literal
        # ('watchlist_mac', 'watchlist_oui', ...). Migration 015
        # added the column NULL-able; rows written pre-rc5 carry
        # NULL, which is honest about their unknown rule_type --
        # the rule_name -> rule_type mapping requires the loaded
        # ruleset and isn't recoverable retroactively. Always
        # passed from poller.py for new alerts.
        with self._conn:
            cur = self._conn.execute(
                "INSERT INTO alerts(ts, rule_name, mac, message, severity, "
                "matched_watchlist_id, rule_type) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    ts,
                    rule_name,
                    mac,
                    message,
                    severity,
                    matched_watchlist_id,
                    rule_type,
                ),
            )
            return cur.lastrowid

    def _lookup_simple_watchlist_match(
        self, pattern_type: str, pattern: str
    ) -> ResolvedWatchlistMatch | None:
        """Single shared SELECT for the four pattern-equality rule_types.

        Backs both ``resolve_matched_watchlist_id`` (annotation path,
        which only needs the row id) and the four
        ``resolve_matched_*_for_eval`` matchers (the DB-delegated
        eval path, which needs id + severity + device_category).
        Sharing the SQL keeps the two callers from drifting — adding
        a column projection here flows to both at once.

        The LEFT JOIN onto ``watchlist_metadata`` surfaces
        ``device_category``, ``vendor`` (projected as
        ``manufacturer``), and ``argus_record_id`` for the runtime
        overrides layer. The JOIN is single-row indexed on
        ``watchlist_id`` (FK target carries an automatic index in
        SQLite); cost is negligible vs the primary equality lookup
        on (pattern_type, pattern). All three are NULL for rows
        lacking a metadata row (the 63 bundled default_watchlist
        rows that pre-date the Argus metadata schema), which the
        runtime layer treats as pass-through.

        Returns None for falsy ``pattern`` so callers can pass through
        unfiltered observation fields without pre-checking.
        """
        if not pattern:
            return None
        row = self._conn.execute(
            "SELECT w.id AS id, w.severity AS severity, "
            "m.device_category AS device_category, "
            "m.vendor AS manufacturer, "
            "m.argus_record_id AS argus_record_id "
            "FROM watchlist w "
            "LEFT JOIN watchlist_metadata m ON m.watchlist_id = w.id "
            "WHERE w.pattern_type = ? AND w.pattern = ? LIMIT 1",
            (pattern_type, pattern),
        ).fetchone()
        if row is None:
            return None
        return ResolvedWatchlistMatch(
            watchlist_id=int(row["id"]),
            severity=str(row["severity"]),
            device_category=(
                str(row["device_category"]) if row["device_category"] is not None else None
            ),
            manufacturer=(
                str(row["manufacturer"]) if row["manufacturer"] is not None else None
            ),
            argus_record_id=(
                str(row["argus_record_id"]) if row["argus_record_id"] is not None else None
            ),
        )

    def resolve_matched_watchlist_id(
        self,
        *,
        mac: str | None,
        ssid: str | None = None,
        ble_service_uuids: tuple[str, ...] = (),
        ble_manufacturer_id: str | None = None,
        drone_id_prefix: str | None = None,
    ) -> int | None:
        """Pick the most-specific watchlist row matching this observation.

        Tiebreaker order:
          mac > oui > ble_manufacturer_id > mac_range >
          drone_id_prefix > ssid > ble_uuid

        Returns the watchlist row id, or None when no row matches.

        mac_range falls after oui so an operator-curated oui rule still
        takes precedence over a bulk-imported Argus mac_range covering
        the same OUI — the IEEE design forbids the two overlapping for
        the same MAC, so in practice oui and mac_range are disjoint,
        but the ordering is conservative.

        ble_manufacturer_id slots between oui and mac_range — same
        "vendor-level identifier" specificity tier as oui (the BLE
        Company Identifier is the BLE-side analogue of the IEEE OUI,
        16-bit instead of 24-bit), and only meaningful on BLE
        observations where the upstream extractor populated it. A
        mac/oui hit always wins because both are stronger evidence
        for *this specific device* than a vendor-wide BLE company id.

        drone_id_prefix slots between mac_range and ssid — a device
        serial prefix is more identifier-specific than a free-form
        SSID but less so than a covered MAC range; falling after
        mac_range mirrors the oui-before-mac_range pattern (a
        curated mac_range catching the device's MAC takes
        precedence over a Remote-ID serial that may have been
        spoofed). Both new branches are no-op when the observation
        carries None for the corresponding field, which is the
        default for every code path that doesn't go through
        kismet.parse_kismet_device's extraction layer.
        """
        if mac is not None:
            match = self._lookup_simple_watchlist_match("mac", mac)
            if match is not None:
                return match.watchlist_id
            match = self._lookup_simple_watchlist_match("oui", mac[:8])
            if match is not None:
                return match.watchlist_id
        if ble_manufacturer_id:
            match = self._lookup_simple_watchlist_match(
                "ble_manufacturer_id", ble_manufacturer_id
            )
            if match is not None:
                return match.watchlist_id
        if mac is not None:
            # mac_range annotation: call the private helper directly
            # rather than the public resolve_matched_mac_range so the
            # WARNING-on-overlap is not emitted twice when the rules
            # engine has already logged it for the same observation.
            mac_range_matches = self._lookup_mac_range_matches(mac)
            if mac_range_matches:
                return mac_range_matches[0].watchlist_id
        if drone_id_prefix:
            match = self._lookup_simple_watchlist_match(
                "drone_id_prefix", drone_id_prefix
            )
            if match is not None:
                return match.watchlist_id
        if ssid:
            match = self._lookup_simple_watchlist_match("ssid", ssid)
            if match is not None:
                return match.watchlist_id
        for uuid in ble_service_uuids:
            match = self._lookup_simple_watchlist_match("ble_uuid", uuid)
            if match is not None:
                return match.watchlist_id
        return None

    def _lookup_mac_range_matches(self, mac: str | None) -> list[ResolvedMacRangeMatch]:
        """Private indexed lookup for watchlisted mac_range rows covering ``mac``.

        Hits the partial index from migration 011
        (idx_watchlist_mac_range_prefix on
        (mac_range_prefix_length, mac_range_prefix) WHERE
        pattern_type='mac_range'), so each prefix-length query is
        O(log n). Two queries worst case — /36 first, /28 second —
        so the more-specific match sorts ahead of the less-specific
        one in the returned list.

        Returns an empty list for falsy ``mac`` (None / empty string).
        Returns one match in the normal case (IEEE design makes /28
        and /36 ranges disjoint for the same MAC); two matches
        indicates an Argus contract violation, surfaced by the public
        callers via WARNING rather than here so the noise stays one
        log line per observation.
        """
        if not mac:
            return []
        normalized = mac.replace(":", "").lower()
        matches: list[ResolvedMacRangeMatch] = []
        for length in (36, 28):
            hex_chars = length // 4
            candidate = normalized[:hex_chars]
            row = self._conn.execute(
                "SELECT w.id AS id, w.severity AS severity, "
                "m.device_category AS device_category, "
                "m.vendor AS manufacturer, "
                "m.argus_record_id AS argus_record_id "
                "FROM watchlist w "
                "LEFT JOIN watchlist_metadata m ON m.watchlist_id = w.id "
                "WHERE w.pattern_type = 'mac_range' "
                "AND w.mac_range_prefix_length = ? "
                "AND w.mac_range_prefix = ? LIMIT 1",
                (length, candidate),
            ).fetchone()
            if row is not None:
                matches.append(
                    ResolvedMacRangeMatch(
                        watchlist_id=int(row["id"]),
                        severity=str(row["severity"]),
                        prefix_length=length,
                        device_category=(
                            str(row["device_category"])
                            if row["device_category"] is not None
                            else None
                        ),
                        manufacturer=(
                            str(row["manufacturer"])
                            if row["manufacturer"] is not None
                            else None
                        ),
                        argus_record_id=(
                            str(row["argus_record_id"])
                            if row["argus_record_id"] is not None
                            else None
                        ),
                    )
                )
        return matches

    def resolve_matched_mac_range(self, mac: str | None) -> ResolvedMacRangeMatch | None:
        """Return the watchlist mac_range row matching ``mac``, or None.

        Severity is sourced from the matched row, NOT from any
        rules.yaml entry — the importer wrote per-row severity for a
        reason (device_category-derived for Argus rows) and the
        watchlist_mac_range rule_type in rules.evaluate uses this
        severity directly for the emitted RuleHit. This is the first
        DB-delegated rule_type in Lynceus and the first divergence
        from the rule-sourced-severity convention; see the
        watchlist_mac_range branch in ``rules.evaluate`` for the
        consuming side.

        /28 and /36 ranges are disjoint for any given MAC by IEEE
        design. Overlap indicates an Argus contract violation; when
        it surfaces, a WARNING is logged carrying both watchlist_ids
        and the more-specific /36 row wins.
        """
        matches = self._lookup_mac_range_matches(mac)
        if len(matches) > 1:
            logger.warning(
                "watchlist mac_range overlap for %s — watchlist_ids %s; "
                "preferring /%d (most specific). /28 and /36 ranges "
                "covering the same MAC should never coexist by IEEE "
                "design; this indicates an Argus-side contract "
                "violation worth raising upstream.",
                mac,
                [m.watchlist_id for m in matches],
                matches[0].prefix_length,
            )
        return matches[0] if matches else None

    # ---- DB-delegated eval matchers ---------------------------------
    #
    # The four matchers below back the empty-patterns delegation
    # semantic for watchlist_mac, watchlist_oui, watchlist_ssid, and
    # ble_uuid. They mirror the role of resolve_matched_mac_range from
    # Part 2: each is consulted from the corresponding rules.evaluate
    # branch when rule.patterns is empty, and each returns severity
    # alongside watchlist_id so the consuming branch can stamp the
    # emitted RuleHit with the matched DB row's severity (NOT the
    # rule's severity — see the rationale in ResolvedMacRangeMatch
    # and the rules.evaluate branches).
    #
    # All four delegate to _lookup_simple_watchlist_match so the SQL
    # cannot drift from the annotation path that resolve_matched_
    # watchlist_id walks for matched_watchlist_id stamping.

    def resolve_matched_mac_for_eval(
        self, mac: str | None
    ) -> ResolvedWatchlistMatch | None:
        """Watchlist row for an exact MAC match, or None.

        Used by rules.evaluate's watchlist_mac branch when rule.patterns
        is empty (delegation mode). Falsy ``mac`` short-circuits to None.
        """
        if not mac:
            return None
        return self._lookup_simple_watchlist_match("mac", mac)

    def resolve_matched_oui_for_eval(
        self, mac: str | None
    ) -> ResolvedWatchlistMatch | None:
        """Watchlist row for the OUI prefix of ``mac``, or None.

        OUI is the first 8 chars of the MAC (e.g. ``"aa:bb:cc"`` from
        ``"aa:bb:cc:dd:ee:ff"``). Used by rules.evaluate's
        watchlist_oui branch when rule.patterns is empty (delegation
        mode). Falsy ``mac`` short-circuits to None.
        """
        if not mac:
            return None
        return self._lookup_simple_watchlist_match("oui", mac[:8])

    def resolve_matched_ssid_for_eval(
        self, ssid: str | None
    ) -> ResolvedWatchlistMatch | None:
        """Watchlist row for an exact SSID match, or None.

        Used by rules.evaluate's watchlist_ssid branch when
        rule.patterns is empty (delegation mode). Falsy ``ssid``
        short-circuits to None — observations without a captured SSID
        cannot match a watchlist_ssid row.
        """
        if not ssid:
            return None
        return self._lookup_simple_watchlist_match("ssid", ssid)

    def resolve_matched_ssid_pattern_for_eval(
        self, ssid: str | None
    ) -> ResolvedWatchlistMatch | None:
        """Watchlist row for a case-insensitive substring SSID match, or None.

        Sibling to ``resolve_matched_ssid_for_eval`` for the
        ``ssid_pattern`` pattern_type (Argus's identifier_type by the
        same name; aliased one-to-one at import). The observation's
        SSID is the haystack; the watchlist row's ``pattern`` column
        is the substring needle. ``COLLATE NOCASE`` provides the
        ASCII-insensitive matching SQLite documents for LIKE (and
        makes the intent self-documenting in case
        ``PRAGMA case_sensitive_like`` is ever flipped elsewhere).

        Defensive ``pattern != ''`` filter: an empty needle would
        match every observation. Belt-and-suspenders alongside the
        Python-side falsy short-circuit (the empty pattern still
        survives the importer's ``not raw_pattern`` check only if
        somehow injected later — guard against the hypothetical).

        Used by rules.evaluate's watchlist_ssid branch as a fallback
        after the exact ssid lookup misses. Severity is sourced from
        the matched row (same convention as the exact path).

        LIKE wildcard chars (``%``, ``_``) in stored patterns: not
        escaped. SSIDs containing those chars as literals are
        vanishingly rare in practice, and any false-positive widening
        is bounded by the existing watchlist row set (operator-curated
        or Argus-imported). If this surfaces as a real problem, the
        fix is at write time (escape on insert) rather than read
        time.
        """
        if not ssid:
            return None
        row = self._conn.execute(
            "SELECT w.id AS id, w.severity AS severity, "
            "m.device_category AS device_category, "
            "m.vendor AS manufacturer, "
            "m.argus_record_id AS argus_record_id "
            "FROM watchlist w "
            "LEFT JOIN watchlist_metadata m ON m.watchlist_id = w.id "
            "WHERE w.pattern_type = 'ssid_pattern' "
            "AND w.pattern != '' "
            "AND ? LIKE '%' || w.pattern || '%' COLLATE NOCASE "
            "LIMIT 1",
            (ssid,),
        ).fetchone()
        if row is None:
            return None
        return ResolvedWatchlistMatch(
            watchlist_id=int(row["id"]),
            severity=str(row["severity"]),
            device_category=(
                str(row["device_category"]) if row["device_category"] is not None else None
            ),
            manufacturer=(
                str(row["manufacturer"]) if row["manufacturer"] is not None else None
            ),
            argus_record_id=(
                str(row["argus_record_id"]) if row["argus_record_id"] is not None else None
            ),
        )

    def resolve_matched_ble_uuid_for_eval(
        self, uuids: tuple[str, ...] | list[str]
    ) -> ResolvedWatchlistMatch | None:
        """Watchlist row for the first watchlisted UUID in ``uuids``.

        Iterates ``uuids`` in order and returns the first watchlist
        row found, mirroring the existing in-memory ble_uuid branch
        which also returns on the first match. Used by rules.evaluate's
        ble_uuid branch when rule.patterns is empty (delegation mode).
        Empty ``uuids`` short-circuits to None.
        """
        if not uuids:
            return None
        for uuid in uuids:
            match = self._lookup_simple_watchlist_match("ble_uuid", uuid)
            if match is not None:
                return match
        return None

    def resolve_matched_ble_manufacturer_id_for_eval(
        self, company_id: str | None
    ) -> ResolvedWatchlistMatch | None:
        """Watchlist row for an exact BLE manufacturer (company) ID match, or None.

        ``company_id`` is the Bluetooth SIG 16-bit Company Identifier
        in the canonical persistent form (lowercase 4-hex-char, no
        '0x' prefix — see patterns._normalize_ble_manufacturer_id).
        Callers passing an observation field should normalize it
        through normalize_pattern('ble_manufacturer_id', value)
        before calling — same write-time-canonical contract the
        other equality-shaped matchers rely on. Used by
        rules.evaluate's watchlist_ble_manufacturer_id branch when
        rule.patterns is empty (delegation mode). Falsy
        ``company_id`` short-circuits to None.
        """
        if not company_id:
            return None
        return self._lookup_simple_watchlist_match("ble_manufacturer_id", company_id)

    def resolve_matched_drone_id_prefix_for_eval(
        self, drone_id: str | None
    ) -> ResolvedWatchlistMatch | None:
        """Watchlist row for an exact drone Remote-ID prefix match, or None.

        ``drone_id`` is the ANSI/CTA-2063-A serial-number prefix in
        the canonical persistent form (uppercase ASCII alphanumeric —
        see patterns._normalize_drone_id_prefix). Callers passing an
        observation field should normalize through
        normalize_pattern('drone_id_prefix', value) first.

        Matching is exact-equality on the prefix string. The Argus
        rows are themselves prefixes (3-20 chars in the
        2026-05-14 snapshot), so an operator who wants
        startswith-style matching against a longer observed serial
        number would need a separate range/prefix matcher — that is
        future work, not in scope for this commit. Used by
        rules.evaluate's watchlist_drone_id_prefix branch when
        rule.patterns is empty (delegation mode). Falsy
        ``drone_id`` short-circuits to None.
        """
        if not drone_id:
            return None
        return self._lookup_simple_watchlist_match("drone_id_prefix", drone_id)

    def get_recent_alert_for_rule_and_mac(
        self,
        rule_name: str,
        mac: str | None,
        since_ts: int,
    ) -> dict | None:
        row = self._conn.execute(
            """
            SELECT id, ts, rule_name, mac, message, severity, acknowledged
            FROM alerts
            WHERE rule_name = ?
              AND ts >= ?
              AND ((? IS NOT NULL AND mac = ?) OR (? IS NULL AND mac IS NULL))
            ORDER BY ts DESC
            LIMIT 1
            """,
            (rule_name, since_ts, mac, mac, mac),
        ).fetchone()
        return dict(row) if row else None

    # ---- import_runs (per-import freshness metadata) ----------------

    def record_import_run(
        self,
        *,
        imported_at: int,
        exported_at: int | None,
        source: str | None,
        record_count: int | None,
    ) -> int:
        """Persist one row to ``import_runs`` for a successful import.

        Powers the staleness signal — the startup log line + the
        /settings card both read the most-recent row from this table.
        Called by ``lynceus-import-argus`` after a successful write
        (NOT on --dry-run; nothing wrote, so nothing to record).

        ``exported_at`` is the Argus-side timestamp parsed from the
        CSV's ``# meta:`` line; ``None`` when the meta line is
        absent or unparseable. ``imported_at`` is the local-clock
        moment of write — always set; the integer Unix epoch matches
        the rest of the schema's timestamp convention.
        """
        with self._conn:
            cur = self._conn.execute(
                "INSERT INTO import_runs(imported_at, exported_at, source, record_count) "
                "VALUES (?, ?, ?, ?)",
                (imported_at, exported_at, source, record_count),
            )
            return int(cur.lastrowid)

    def get_latest_import_run(self) -> dict | None:
        """Return the most-recent ``import_runs`` row, or ``None``
        when no imports have been recorded.

        Selection is by descending ``imported_at`` (the local clock
        moment of write), NOT by ``exported_at`` — an operator who
        re-imports an older CSV on top of a newer one is
        deliberately reverting to the older corpus, and the
        "freshness" indicator should reflect the active import. The
        index ``idx_import_runs_imported_at`` from migration 012
        makes this a single-row lookup.
        """
        row = self._conn.execute(
            "SELECT id, imported_at, exported_at, source, record_count "
            "FROM import_runs ORDER BY imported_at DESC, id DESC LIMIT 1"
        ).fetchone()
        return dict(row) if row else None

    def watchlist_pattern_type_counts(self) -> dict[str, int]:
        """Return ``{pattern_type: count}`` for all rows in
        ``watchlist``. Every pattern_type the schema admits appears
        as a key (zero when no rows of that type exist) so callers
        can render a stable layout without per-type presence
        checks."""
        counts = {pt: 0 for pt in self._WATCHLIST_PATTERN_TYPES}
        rows = self._conn.execute(
            "SELECT pattern_type, COUNT(*) AS c FROM watchlist GROUP BY pattern_type"
        ).fetchall()
        for row in rows:
            pt = row["pattern_type"]
            if pt in counts:
                counts[pt] = int(row["c"])
        return counts

    def get_state(self, key: str) -> str | None:
        row = self._conn.execute("SELECT value FROM poller_state WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def set_state(self, key: str, value: str) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO poller_state(key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    def healthcheck(self) -> dict:
        """Return a small dict useful for the /healthz endpoint."""
        cur = self._conn.cursor()
        cur.execute("SELECT COALESCE(MAX(version), 0) FROM schema_migrations")
        schema_version = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM devices")
        device_count = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM alerts")
        alert_count = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged = 0")
        unacked_alert_count = cur.fetchone()[0]
        return {
            "schema_version": int(schema_version),
            "device_count": int(device_count),
            "alert_count": int(alert_count),
            "unacked_alert_count": int(unacked_alert_count),
        }

    # --- Read-only queries for the web UI ---------------------------------
    #
    # All methods below are read-only, parameterized, and validate their
    # arguments before they hit SQL. They return plain dicts (or lists of
    # dicts) rather than sqlite3.Row objects so the templating layer doesn't
    # have to know about the row factory.

    _ALERT_SEVERITIES = ("low", "med", "high")
    _DEVICE_TYPES = ("wifi", "ble", "bt_classic", "remote_id")
    # Cap for the per-alert triage note (alerts.note). 4096 chars
    # accommodates multi-paragraph triage rationale without inviting
    # the column to become an unbounded text dump -- a longer write-up
    # belongs in an external system (operator notebook, ticket).
    # Enforced server-side; the template textarea sets the same cap
    # via maxlength but the server is the source of truth.
    _ALERT_NOTE_MAX_CHARS = 4096

    @staticmethod
    def _validate_pagination(limit: int, offset: int, *, max_limit: int = 1000) -> None:
        if not isinstance(limit, int) or isinstance(limit, bool):
            raise ValueError("limit must be int")
        if not isinstance(offset, int) or isinstance(offset, bool):
            raise ValueError("offset must be int")
        if limit < 1 or limit > max_limit:
            raise ValueError(f"limit must be in [1, {max_limit}]")
        if offset < 0:
            raise ValueError("offset must be >= 0")

    def list_alerts(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        severity: str | None = None,
        acknowledged: bool | None = None,
        since_ts: int | None = None,
        until_ts: int | None = None,
        search: str | None = None,
        rule_type: str | None = None,
        q: str | None = None,
        has_note: str | None = None,
        has_action: str | None = None,
        actioned_macs: tuple[str, ...] = (),
        actioned_oui_prefixes: tuple[str, ...] = (),
    ) -> list[dict]:
        self._validate_pagination(limit, offset)
        if severity is not None and severity not in self._ALERT_SEVERITIES:
            raise ValueError(f"severity must be one of {self._ALERT_SEVERITIES}")

        # list_alerts is the lighter sibling of list_alerts_with_match
        # (no watchlist join columns in the result). Filter shape stays
        # identical so /alerts ack-all-visible can mirror the page's
        # filter set exactly -- "ack all matching" must not diverge
        # from "I can see these on the page."
        clauses, params = self._alert_filter_clauses(
            severity=severity,
            acknowledged=acknowledged,
            since_ts=since_ts,
            until_ts=until_ts,
            search=search,
            rule_type=rule_type,
            q=q,
            has_note=has_note,
            has_action=has_action,
            actioned_macs=actioned_macs,
            actioned_oui_prefixes=actioned_oui_prefixes,
            alias="a",
        )
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = (
            "SELECT a.id, a.ts, a.rule_name, a.rule_type, a.mac, a.message, "
            f"a.severity, a.acknowledged {self._ALERTS_FROM_FOR_FILTERS} "
            f"{where} ORDER BY a.ts DESC, a.id DESC LIMIT ? OFFSET ?"
        )
        params.extend([limit, offset])
        rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def count_alerts(
        self,
        *,
        severity: str | None = None,
        acknowledged: bool | None = None,
        since_ts: int | None = None,
        until_ts: int | None = None,
        search: str | None = None,
        rule_type: str | None = None,
        q: str | None = None,
        has_note: str | None = None,
        has_action: str | None = None,
        actioned_macs: tuple[str, ...] = (),
        actioned_oui_prefixes: tuple[str, ...] = (),
    ) -> int:
        # COUNT and the page query (list_alerts_with_match) must
        # apply the same filters or "K total" is a lie and the
        # pagination math breaks. Both call _alert_filter_clauses
        # with alias="a" and use the same _ALERTS_FROM_FOR_FILTERS
        # FROM clause -- single source of truth.
        if severity is not None and severity not in self._ALERT_SEVERITIES:
            raise ValueError(f"severity must be one of {self._ALERT_SEVERITIES}")
        clauses, params = self._alert_filter_clauses(
            severity=severity,
            acknowledged=acknowledged,
            since_ts=since_ts,
            until_ts=until_ts,
            search=search,
            rule_type=rule_type,
            q=q,
            has_note=has_note,
            has_action=has_action,
            actioned_macs=actioned_macs,
            actioned_oui_prefixes=actioned_oui_prefixes,
            alias="a",
        )
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT COUNT(*) {self._ALERTS_FROM_FOR_FILTERS} {where}"
        return int(self._conn.execute(sql, params).fetchone()[0])

    # Shared FROM clause for count_alerts + list_alerts_with_match.
    # The LEFT JOINs are unconditional because the q-substring
    # filter touches m.vendor; even when q is unset the JOINs cost
    # one indexed lookup per matched row (negligible at our scale)
    # and the cost of an inconsistent COUNT-vs-page filter shape
    # would be much worse (pagination math becomes a lie).
    _ALERTS_FROM_FOR_FILTERS = (
        "FROM alerts a "
        "LEFT JOIN watchlist w ON w.id = a.matched_watchlist_id "
        "LEFT JOIN watchlist_metadata m ON m.watchlist_id = w.id"
    )

    # has_note accepted values. "all" / None / unrecognized -> no
    # clause; the handler clamps invalid input to None before
    # reaching here. Kept narrow on purpose -- expanding to fuzzy
    # forms (e.g. note_contains=X) would conflate the indicator-on-
    # list workflow with full-text search.
    _ALERT_HAS_NOTE_VALUES = ("with_note", "without_note")

    # has_action accepted values. Same clamp posture as has_note --
    # any other value (including None / "all" / typo) becomes the
    # no-op default. The handler resolves the YAML-side allowlist
    # signal into actioned_macs / actioned_oui_prefixes before
    # calling here; this layer never reads files.
    _ALERT_HAS_ACTION_VALUES = ("with_action", "without_action")

    @staticmethod
    def _alert_filter_clauses(
        *,
        severity: str | None,
        acknowledged: bool | None,
        since_ts: int | None,
        until_ts: int | None,
        search: str | None,
        rule_type: str | None = None,
        q: str | None = None,
        has_note: str | None = None,
        has_action: str | None = None,
        actioned_macs: tuple[str, ...] = (),
        actioned_oui_prefixes: tuple[str, ...] = (),
        alias: str = "",
    ) -> tuple[list[str], list]:
        prefix = f"{alias}." if alias else ""
        clauses: list[str] = []
        params: list = []
        if severity is not None:
            clauses.append(f"{prefix}severity = ?")
            params.append(severity)
        if acknowledged is not None:
            clauses.append(f"{prefix}acknowledged = ?")
            params.append(1 if acknowledged else 0)
        if since_ts is not None:
            clauses.append(f"{prefix}ts >= ?")
            params.append(since_ts)
        if until_ts is not None:
            clauses.append(f"{prefix}ts <= ?")
            params.append(until_ts)
        if search is not None and search != "":
            like = f"%{search.lower()}%"
            clauses.append(
                f"(LOWER({prefix}message) LIKE ? OR LOWER({prefix}rule_name) LIKE ?)"
            )
            params.extend([like, like])
        if rule_type is not None and rule_type != "":
            # NULL-rule_type rows (alerts written pre-migration-015)
            # are excluded from any rule_type=<specific> filter -- the
            # honest answer for "we don't know what type this was."
            clauses.append(f"{prefix}rule_type = ?")
            params.append(rule_type)
        if q is not None and q != "":
            # q matches MAC + message (catches SSID for ssid-typed
            # rules whose message embeds the SSID) + manufacturer
            # (via the watchlist_metadata JOIN, alias m).
            qlike = f"%{q.lower()}%"
            clauses.append(
                f"(LOWER(COALESCE({prefix}mac, '')) LIKE ? "
                f"OR LOWER({prefix}message) LIKE ? "
                "OR LOWER(COALESCE(m.vendor, '')) LIKE ?)"
            )
            params.extend([qlike, qlike, qlike])
        if has_note == "with_note":
            clauses.append(f"{prefix}note IS NOT NULL")
        elif has_note == "without_note":
            clauses.append(f"{prefix}note IS NULL")
        if has_action in ("with_action", "without_action"):
            # Three OR'd signals: per-alert snooze (allowlist_ui.yaml
            # mac/oui match), permanent allowlist (allowlist.yaml
            # mac/oui match), and watchful tracking (mac-scoped
            # transitive: every alert from a MAC under an active
            # watchful_recurrence row inherits the action status,
            # because that's the suppression effect the operator
            # opted into). Snooze and allowlist signals are pre-
            # resolved into actioned_macs / actioned_oui_prefixes
            # by the handler (which loads the YAML files) -- this
            # layer never reads files. Rule_type_snoozes (migration
            # 017) intentionally excluded: a system-wide setting,
            # not a per-alert engagement.
            action_clauses: list[str] = []
            action_params: list = []
            if actioned_macs:
                placeholders = ",".join("?" for _ in actioned_macs)
                action_clauses.append(f"{prefix}mac IN ({placeholders})")
                action_params.extend(actioned_macs)
            for oui in actioned_oui_prefixes:
                action_clauses.append(f"{prefix}mac LIKE ?")
                action_params.append(f"{oui}:%")
            action_clauses.append(
                "EXISTS (SELECT 1 FROM watchful_recurrence wr "
                f"WHERE wr.mac = {prefix}mac "
                "AND wr.archived_at IS NULL)"
            )
            combined = "(" + " OR ".join(action_clauses) + ")"
            if has_action == "with_action":
                clauses.append(combined)
            else:
                # NULL-mac alerts can't match any mac-keyed signal;
                # the OR collapses to NULL there and NOT NULL stays
                # NULL, silently dropping NULL-mac rows from BOTH
                # with_action and without_action result sets. Add
                # an explicit mac-is-null branch so without_action
                # behaves as "no action signal applies" rather than
                # "has mac and no signal applies."
                clauses.append(f"({prefix}mac IS NULL OR NOT {combined})")
            params.extend(action_params)
        # Any other value (including None / "all" / typo) is the
        # no-op default -- same silent-fallback semantic as rule_type
        # and window.
        return clauses, params

    def get_alert(self, alert_id: int) -> dict | None:
        row = self._conn.execute(
            "SELECT id, ts, rule_name, rule_type, mac, message, severity, "
            "acknowledged, note, note_updated_at FROM alerts WHERE id = ?",
            (alert_id,),
        ).fetchone()
        if row is None:
            return None
        alert = dict(row)
        if alert["mac"]:
            dev_row = self._conn.execute(
                "SELECT * FROM devices WHERE mac = ?", (alert["mac"],)
            ).fetchone()
            alert["device"] = dict(dev_row) if dev_row else None
        else:
            alert["device"] = None
        return alert

    _ALERT_WITH_MATCH_FILTER_KEYS = (
        "limit",
        "offset",
        "severity",
        "acknowledged",
        "since_ts",
        "until_ts",
        "search",
        "rule_type",
        "q",
        "has_note",
        "has_action",
        "actioned_macs",
        "actioned_oui_prefixes",
    )

    _ALERT_WITH_MATCH_SELECT = (
        "SELECT "
        "a.id AS id, a.ts AS ts, a.rule_name AS rule_name, "
        "a.rule_type AS rule_type, a.mac AS mac, "
        "a.message AS message, a.severity AS severity, "
        "a.acknowledged AS acknowledged, "
        "a.matched_watchlist_id AS matched_watchlist_id, "
        "a.note AS note, a.note_updated_at AS note_updated_at, "
        "w.id AS w_id, w.pattern AS w_pattern, "
        "w.pattern_type AS w_pattern_type, w.severity AS w_severity, "
        "w.description AS w_description, "
        "m.id AS m_id, m.argus_record_id AS m_argus_record_id, "
        "m.device_category AS m_device_category, m.confidence AS m_confidence, "
        "m.vendor AS m_vendor, m.source AS m_source, "
        "m.source_url AS m_source_url, m.source_excerpt AS m_source_excerpt, "
        "m.fcc_id AS m_fcc_id, m.geographic_scope AS m_geographic_scope, "
        "m.first_seen AS m_first_seen, m.last_verified AS m_last_verified, "
        "m.notes AS m_notes, m.created_at AS m_created_at, "
        "m.updated_at AS m_updated_at "
        "FROM alerts a "
        "LEFT JOIN watchlist w ON w.id = a.matched_watchlist_id "
        "LEFT JOIN watchlist_metadata m ON m.watchlist_id = w.id"
    )

    @staticmethod
    def _alert_match_row_to_dict(row) -> dict:
        alert = {
            "id": row["id"],
            "ts": row["ts"],
            "rule_name": row["rule_name"],
            "rule_type": row["rule_type"],
            "mac": row["mac"],
            "message": row["message"],
            "severity": row["severity"],
            "acknowledged": row["acknowledged"],
            "matched_watchlist_id": row["matched_watchlist_id"],
            "note": row["note"],
            "note_updated_at": row["note_updated_at"],
        }
        if row["w_id"] is not None:
            alert["watchlist"] = {
                "id": row["w_id"],
                "pattern": row["w_pattern"],
                "pattern_type": row["w_pattern_type"],
                "severity": row["w_severity"],
                "description": row["w_description"],
            }
        else:
            alert["watchlist"] = None
        if row["m_id"] is not None:
            alert["watchlist_metadata"] = {
                "id": row["m_id"],
                "argus_record_id": row["m_argus_record_id"],
                "device_category": row["m_device_category"],
                "confidence": row["m_confidence"],
                "vendor": row["m_vendor"],
                "source": row["m_source"],
                "source_url": row["m_source_url"],
                "source_excerpt": row["m_source_excerpt"],
                "fcc_id": row["m_fcc_id"],
                "geographic_scope": row["m_geographic_scope"],
                "first_seen": row["m_first_seen"],
                "last_verified": row["m_last_verified"],
                "notes": row["m_notes"],
                "created_at": row["m_created_at"],
                "updated_at": row["m_updated_at"],
            }
        else:
            alert["watchlist_metadata"] = None
        return alert

    def get_alert_with_match(self, alert_id: int) -> dict | None:
        self._validate_alert_id(alert_id)
        row = self._conn.execute(
            f"{self._ALERT_WITH_MATCH_SELECT} WHERE a.id = ?",
            (alert_id,),
        ).fetchone()
        if row is None:
            return None
        return self._alert_match_row_to_dict(row)

    def get_evidence_for_alert(self, alert_id: int) -> dict | None:
        """Return the evidence snapshot for an alert, or None when absent.

        ``kismet_record`` and ``rssi_history`` come back already JSON-decoded
        so the caller (and the templating layer) does not need to know about
        the on-disk JSON columns. A malformed JSON column is reported via the
        ``kismet_record_corrupt`` / ``rssi_history_corrupt`` flags rather than
        raising — defense-in-depth so a single bad row cannot crash the
        alert detail page. The web handler is responsible for logging the
        warning when it sees a corrupt flag.
        """
        self._validate_alert_id(alert_id)
        row = self._conn.execute(
            "SELECT id, alert_id, mac, captured_at, kismet_record_json, "
            "rssi_history_json, gps_lat, gps_lon, gps_alt, gps_captured_at, "
            "do_not_publish "
            "FROM evidence_snapshots WHERE alert_id = ? ORDER BY id ASC LIMIT 1",
            (alert_id,),
        ).fetchone()
        if row is None:
            return None
        kismet_record: dict | None
        kismet_corrupt = False
        raw_kismet = row["kismet_record_json"]
        try:
            decoded = json.loads(raw_kismet) if raw_kismet else None
            kismet_record = decoded if isinstance(decoded, dict) else None
            if raw_kismet and kismet_record is None:
                kismet_corrupt = True
        except (json.JSONDecodeError, TypeError, ValueError):
            kismet_record = None
            kismet_corrupt = True
        rssi_history: list | None
        rssi_corrupt = False
        raw_rssi = row["rssi_history_json"]
        try:
            decoded = json.loads(raw_rssi) if raw_rssi else None
            rssi_history = decoded if isinstance(decoded, list) else None
            if raw_rssi and rssi_history is None:
                rssi_corrupt = True
        except (json.JSONDecodeError, TypeError, ValueError):
            rssi_history = None
            rssi_corrupt = True
        return {
            "id": row["id"],
            "alert_id": row["alert_id"],
            "mac": row["mac"],
            "captured_at": row["captured_at"],
            "kismet_record": kismet_record,
            "kismet_record_corrupt": kismet_corrupt,
            "rssi_history": rssi_history,
            "rssi_history_corrupt": rssi_corrupt,
            "gps_lat": row["gps_lat"],
            "gps_lon": row["gps_lon"],
            "gps_alt": row["gps_alt"],
            "gps_captured_at": row["gps_captured_at"],
            # do_not_publish is a v0.5.0 forward-compat column — no
            # producers in v0.4.0. Surfaced in the dict so future
            # consumers (public-feed export) can read it without a
            # second query.
            "do_not_publish": row["do_not_publish"],
        }

    def list_alerts_with_match(self, filters: dict | None = None) -> list[dict]:
        filters = filters or {}
        unknown = set(filters) - set(self._ALERT_WITH_MATCH_FILTER_KEYS)
        if unknown:
            raise ValueError(f"unknown filter keys: {sorted(unknown)}")

        limit = filters.get("limit", 100)
        offset = filters.get("offset", 0)
        self._validate_pagination(limit, offset)
        severity = filters.get("severity")
        if severity is not None and severity not in self._ALERT_SEVERITIES:
            raise ValueError(f"severity must be one of {self._ALERT_SEVERITIES}")

        clauses, params = self._alert_filter_clauses(
            severity=severity,
            acknowledged=filters.get("acknowledged"),
            since_ts=filters.get("since_ts"),
            until_ts=filters.get("until_ts"),
            search=filters.get("search"),
            rule_type=filters.get("rule_type"),
            q=filters.get("q"),
            has_note=filters.get("has_note"),
            has_action=filters.get("has_action"),
            actioned_macs=filters.get("actioned_macs", ()),
            actioned_oui_prefixes=filters.get("actioned_oui_prefixes", ()),
            alias="a",
        )
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = (
            f"{self._ALERT_WITH_MATCH_SELECT} {where} "
            "ORDER BY a.ts DESC, a.id DESC LIMIT ? OFFSET ?"
        )
        params.extend([limit, offset])
        rows = self._conn.execute(sql, params).fetchall()
        return [self._alert_match_row_to_dict(r) for r in rows]

    def list_devices(
        self,
        *,
        limit: int = 200,
        offset: int = 0,
        device_type: str | None = None,
        randomized: bool | None = None,
    ) -> list[dict]:
        self._validate_pagination(limit, offset)
        if device_type is not None and device_type not in self._DEVICE_TYPES:
            raise ValueError(f"device_type must be one of {self._DEVICE_TYPES}")

        clauses: list[str] = []
        params: list = []
        if device_type is not None:
            clauses.append("device_type = ?")
            params.append(device_type)
        if randomized is not None:
            clauses.append("is_randomized = ?")
            params.append(1 if randomized else 0)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = (
            "SELECT mac, device_type, first_seen, last_seen, sighting_count, "
            "oui_vendor, is_randomized, notes "
            f"FROM devices {where} ORDER BY last_seen DESC, mac LIMIT ? OFFSET ?"
        )
        params.extend([limit, offset])
        rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def count_devices(
        self,
        *,
        device_type: str | None = None,
        randomized: bool | None = None,
    ) -> int:
        if device_type is not None and device_type not in self._DEVICE_TYPES:
            raise ValueError(f"device_type must be one of {self._DEVICE_TYPES}")
        clauses: list[str] = []
        params: list = []
        if device_type is not None:
            clauses.append("device_type = ?")
            params.append(device_type)
        if randomized is not None:
            clauses.append("is_randomized = ?")
            params.append(1 if randomized else 0)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT COUNT(*) FROM devices {where}"
        return int(self._conn.execute(sql, params).fetchone()[0])

    def get_device_with_sightings(self, mac: str, *, sighting_limit: int = 100) -> dict | None:
        if not isinstance(sighting_limit, int) or isinstance(sighting_limit, bool):
            raise ValueError("sighting_limit must be int")
        if sighting_limit < 1 or sighting_limit > 1000:
            raise ValueError("sighting_limit must be in [1, 1000]")
        dev_row = self._conn.execute(
            "SELECT mac, device_type, first_seen, last_seen, sighting_count, "
            "oui_vendor, is_randomized, notes FROM devices WHERE mac = ?",
            (mac,),
        ).fetchone()
        if dev_row is None:
            return None
        sight_rows = self._conn.execute(
            "SELECT id, ts, rssi, ssid, location_id FROM sightings "
            "WHERE mac = ? ORDER BY ts DESC, id DESC LIMIT ?",
            (mac, sighting_limit),
        ).fetchall()
        return {
            "device": dict(dev_row),
            "sightings": [dict(r) for r in sight_rows],
        }

    def list_watchlist(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT id, pattern, pattern_type, severity, description "
            "FROM watchlist ORDER BY pattern_type, pattern"
        ).fetchall()
        return [dict(r) for r in rows]

    # --- watchlist_metadata (Argus side table) ----------------------------

    _WATCHLIST_PATTERN_TYPES = (
        "mac",
        "oui",
        "ssid",
        "ble_uuid",
        "mac_range",
        "ble_manufacturer_id",
        "drone_id_prefix",
    )
    _METADATA_OPTIONAL_FIELDS = (
        "confidence",
        "vendor",
        "source",
        "source_url",
        "source_excerpt",
        "fcc_id",
        "geographic_scope",
        "first_seen",
        "last_verified",
        "notes",
    )
    _METADATA_ALLOWED_FIELDS = (
        "argus_record_id",
        "device_category",
        *_METADATA_OPTIONAL_FIELDS,
    )

    def upsert_metadata(self, watchlist_id: int, fields: dict) -> int:
        if not isinstance(watchlist_id, int) or isinstance(watchlist_id, bool):
            raise ValueError("watchlist_id must be int")
        if not isinstance(fields, dict):
            raise ValueError("fields must be a dict")
        if not fields.get("argus_record_id"):
            raise ValueError("fields['argus_record_id'] is required")
        if not fields.get("device_category"):
            raise ValueError("fields['device_category'] is required")
        unknown = set(fields) - set(self._METADATA_ALLOWED_FIELDS)
        if unknown:
            raise ValueError(f"unknown metadata fields: {sorted(unknown)}")

        now_ts = int(time.time())
        with self._conn:
            existing = self._conn.execute(
                "SELECT id FROM watchlist_metadata WHERE watchlist_id = ?",
                (watchlist_id,),
            ).fetchone()
            if existing is None:
                cols = ["watchlist_id", *fields.keys(), "created_at", "updated_at"]
                values = [watchlist_id, *fields.values(), now_ts, now_ts]
                placeholders = ", ".join("?" for _ in cols)
                cur = self._conn.execute(
                    f"INSERT INTO watchlist_metadata({', '.join(cols)}) VALUES ({placeholders})",
                    values,
                )
                return int(cur.lastrowid)
            set_clause = ", ".join(f"{k} = ?" for k in fields)
            values = [*fields.values(), now_ts, watchlist_id]
            self._conn.execute(
                f"UPDATE watchlist_metadata SET {set_clause}, updated_at = ? "
                f"WHERE watchlist_id = ?",
                values,
            )
            return int(existing["id"])

    def get_metadata_by_watchlist_id(self, watchlist_id: int) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM watchlist_metadata WHERE watchlist_id = ?",
            (watchlist_id,),
        ).fetchone()
        return dict(row) if row else None

    def get_metadata_by_argus_record_id(self, argus_record_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT * FROM watchlist_metadata WHERE argus_record_id = ?",
            (argus_record_id,),
        ).fetchone()
        return dict(row) if row else None

    def get_watchlist_with_metadata(self, watchlist_id: int) -> dict | None:
        # Single-row sibling of ``list_watchlist_with_metadata``: same
        # column projection, but indexed by ``w.id`` so the /watchlist/<id>
        # detail route does not have to load every row (the full Argus
        # import lands ~22k rows; ``list_watchlist_with_metadata`` returns
        # all of them and the route would then filter in Python).
        # ``metadata_id`` is the alias the route uses to detect a present
        # JOIN partner.
        row = self._conn.execute(
            "SELECT "
            "w.id AS id, w.pattern, w.pattern_type, w.severity, w.description, "
            "w.mac_range_prefix, w.mac_range_prefix_length, "
            "m.id AS metadata_id, m.argus_record_id, m.device_category, "
            "m.confidence, m.vendor, m.source, m.source_url, m.source_excerpt, "
            "m.fcc_id, m.geographic_scope, m.first_seen, m.last_verified, "
            "m.notes, m.created_at, m.updated_at "
            "FROM watchlist w "
            "LEFT JOIN watchlist_metadata m ON m.watchlist_id = w.id "
            "WHERE w.id = ? LIMIT 1",
            (watchlist_id,),
        ).fetchone()
        return dict(row) if row else None

    def list_watchlist_with_metadata(
        self,
        filters: dict | None = None,
    ) -> list[dict]:
        filters = filters or {}
        unknown = set(filters) - {"pattern_type", "severity", "device_category"}
        if unknown:
            raise ValueError(f"unknown filter keys: {sorted(unknown)}")
        pattern_type = filters.get("pattern_type")
        severity = filters.get("severity")
        device_category = filters.get("device_category")
        if pattern_type is not None and pattern_type not in self._WATCHLIST_PATTERN_TYPES:
            raise ValueError(f"pattern_type must be one of {self._WATCHLIST_PATTERN_TYPES}")
        if severity is not None and severity not in self._ALERT_SEVERITIES:
            raise ValueError(f"severity must be one of {self._ALERT_SEVERITIES}")

        clauses: list[str] = []
        params: list = []
        if pattern_type is not None:
            clauses.append("w.pattern_type = ?")
            params.append(pattern_type)
        if severity is not None:
            clauses.append("w.severity = ?")
            params.append(severity)
        if device_category is not None:
            clauses.append("m.device_category = ?")
            params.append(device_category)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = (
            "SELECT "
            "w.id AS id, w.pattern, w.pattern_type, w.severity, w.description, "
            "w.mac_range_prefix, w.mac_range_prefix_length, "
            "m.id AS metadata_id, m.argus_record_id, m.device_category, "
            "m.confidence, m.vendor, m.source, m.source_url, m.source_excerpt, "
            "m.fcc_id, m.geographic_scope, m.first_seen, m.last_verified, "
            "m.notes, m.created_at, m.updated_at "
            "FROM watchlist w "
            "LEFT JOIN watchlist_metadata m ON m.watchlist_id = w.id "
            f"{where} "
            "ORDER BY w.pattern_type, w.pattern"
        )
        rows = self._conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    # --- Filtered + paginated watchlist for /watchlist list page ----------
    #
    # The full Argus import lands ~22k rows in ``watchlist``. The
    # pre-rc5 ``list_watchlist_with_metadata`` returns every row to
    # Python and sorts there; that does not scale past a few thousand
    # rows. ``list_watchlist_filtered`` is the paginated sibling: a
    # COUNT query for the footer and a LIMIT/OFFSET'd SELECT for the
    # page, both sharing ``_build_watchlist_filter_clauses`` so the
    # two never diverge (same invariant /alerts ack-all-visible
    # depends on). The ``device_category=__none__`` sentinel selects
    # rows with no metadata JOIN partner -- the "uncategorized"
    # bucket for yaml-seeded / bundled rows the operator may want
    # to triage separately from Argus-imported rows.

    _WATCHLIST_UNCATEGORIZED_SENTINEL = "__none__"

    @staticmethod
    def _build_watchlist_filter_clauses(
        *,
        q: str | None,
        pattern_type: str | None,
        severity: str | None,
        device_category: str | None,
    ) -> tuple[list[str], list]:
        """Build the shared WHERE clauses + bind params for
        list_watchlist_filtered's COUNT and SELECT halves.

        Treats empty strings as "absent" (the route layer passes
        "" through for unset form fields). The ``q`` clause matches
        case-insensitively against pattern, vendor (the "manufacturer"
        column in the prompt's vocabulary), argus_record_id, and
        device_category -- the four columns an operator is likely to
        type into the search box. COALESCE collapses NULLs to "" so
        a NULL vendor on a yaml-seeded row doesn't blow the predicate.
        """
        clauses: list[str] = []
        params: list = []
        if pattern_type is not None and pattern_type != "":
            clauses.append("w.pattern_type = ?")
            params.append(pattern_type)
        if severity is not None and severity != "":
            clauses.append("w.severity = ?")
            params.append(severity)
        if device_category is not None and device_category != "":
            if device_category == Database._WATCHLIST_UNCATEGORIZED_SENTINEL:
                clauses.append("m.device_category IS NULL")
            else:
                clauses.append("m.device_category = ?")
                params.append(device_category)
        if q is not None and q != "":
            qlike = f"%{q.lower()}%"
            clauses.append(
                "("
                "LOWER(w.pattern) LIKE ? "
                "OR LOWER(COALESCE(m.vendor, '')) LIKE ? "
                "OR LOWER(COALESCE(m.argus_record_id, '')) LIKE ? "
                "OR LOWER(COALESCE(m.device_category, '')) LIKE ?"
                ")"
            )
            params.extend([qlike, qlike, qlike, qlike])
        return clauses, params

    _WATCHLIST_FROM_FOR_FILTERS = (
        "FROM watchlist w "
        "LEFT JOIN watchlist_metadata m ON m.watchlist_id = w.id"
    )

    # The sort key matches the pre-rc5 Python-side
    # ``_watchlist_sort_key`` (severity desc by importance then pattern
    # alphabetical). ``w.id`` is the deterministic tiebreaker so two
    # rows with identical (severity, pattern) do not flicker between
    # pages on repeat renders. SQLite returns the same row order for
    # COUNT-clamped LIMIT/OFFSET pagination only when ORDER BY is
    # total; the id tiebreaker makes it so.
    _WATCHLIST_ORDER_BY = (
        "ORDER BY CASE w.severity "
        "WHEN 'high' THEN 0 WHEN 'med' THEN 1 WHEN 'low' THEN 2 ELSE 3 END, "
        "w.pattern, w.id"
    )

    def list_watchlist_filtered(
        self,
        *,
        q: str | None = None,
        pattern_type: str | None = None,
        severity: str | None = None,
        device_category: str | None = None,
        page: int = 1,
        per_page: int = 50,
    ) -> tuple[list[WatchlistRow], int]:
        """Return ``(rows for page, total matching count)``.

        The COUNT query and the page SELECT share
        ``_build_watchlist_filter_clauses`` and
        ``_WATCHLIST_FROM_FOR_FILTERS`` -- single filter-builder
        invariant, mirroring /alerts. ``page`` is 1-indexed and is
        floored at 1 here; out-of-range clamping against the total
        is the caller's job (the route uses the shared
        ``build_pagination`` helper for that).
        """
        if pattern_type is not None and pattern_type != "" and pattern_type not in self._WATCHLIST_PATTERN_TYPES:
            raise ValueError(f"pattern_type must be one of {self._WATCHLIST_PATTERN_TYPES}")
        if severity is not None and severity != "" and severity not in self._ALERT_SEVERITIES:
            raise ValueError(f"severity must be one of {self._ALERT_SEVERITIES}")
        if not isinstance(page, int) or isinstance(page, bool) or page < 1:
            raise ValueError("page must be a positive int")
        if not isinstance(per_page, int) or isinstance(per_page, bool) or per_page < 1:
            raise ValueError("per_page must be a positive int")

        clauses, params = self._build_watchlist_filter_clauses(
            q=q,
            pattern_type=pattern_type,
            severity=severity,
            device_category=device_category,
        )
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        count_sql = f"SELECT COUNT(*) {self._WATCHLIST_FROM_FOR_FILTERS} {where}"
        total = int(self._conn.execute(count_sql, params).fetchone()[0])

        offset = (page - 1) * per_page
        page_sql = (
            "SELECT "
            "w.id AS id, w.pattern, w.pattern_type, w.severity, w.description, "
            "w.mac_range_prefix, w.mac_range_prefix_length, "
            "m.vendor, m.confidence, m.device_category, m.argus_record_id "
            f"{self._WATCHLIST_FROM_FOR_FILTERS} "
            f"{where} {self._WATCHLIST_ORDER_BY} LIMIT ? OFFSET ?"
        )
        page_params = [*params, per_page, offset]
        rows = self._conn.execute(page_sql, page_params).fetchall()
        return [
            WatchlistRow(
                id=int(r["id"]),
                pattern=r["pattern"],
                pattern_type=r["pattern_type"],
                severity=r["severity"],
                description=r["description"],
                mac_range_prefix=r["mac_range_prefix"],
                mac_range_prefix_length=r["mac_range_prefix_length"],
                vendor=r["vendor"],
                confidence=r["confidence"],
                device_category=r["device_category"],
                argus_record_id=r["argus_record_id"],
            )
            for r in rows
        ], total

    def distinct_watchlist_device_categories(self) -> list[str]:
        """Return the sorted distinct non-NULL ``device_category``
        values in ``watchlist_metadata``, for the filter-bar
        dropdown on /watchlist.

        Live query is acceptable at current scale (22k rows, a
        SELECT DISTINCT on a non-indexed column completes in
        single-digit milliseconds on SQLite). If the cardinality
        becomes pathological for any reason, a cached snapshot at
        import time is the obvious follow-up. NULL is excluded
        from the result set because the route exposes "no
        category" via the ``__none__`` sentinel option instead.
        """
        rows = self._conn.execute(
            "SELECT DISTINCT device_category FROM watchlist_metadata "
            "WHERE device_category IS NOT NULL "
            "ORDER BY device_category"
        ).fetchall()
        return [r["device_category"] for r in rows]

    # --- Alert acknowledgement actions and stats --------------------------

    @staticmethod
    def _validate_alert_id(alert_id: int) -> None:
        if not isinstance(alert_id, int) or isinstance(alert_id, bool):
            raise ValueError("alert_id must be a positive int")
        if alert_id < 1:
            raise ValueError("alert_id must be a positive int")

    @staticmethod
    def _validate_actor_and_note(actor: str, note: str | None) -> str:
        if not isinstance(actor, str):
            raise ValueError("actor must be a non-empty string")
        cleaned = actor.strip()
        if not cleaned:
            raise ValueError("actor must be a non-empty string")
        if note is not None:
            if not isinstance(note, str):
                raise ValueError("note must be a string")
            if len(note) > 500:
                raise ValueError("note must be <= 500 chars")
        return cleaned

    def update_alert_note(
        self,
        alert_id: int,
        note_text: str,
        *,
        now_ts: int | None = None,
    ) -> bool:
        """Set or clear the operator triage note for an alert.

        ``note_text`` is plain text. Empty / whitespace-only input
        CLEARS the note (sets both columns to NULL); a non-empty
        value writes the stripped text plus an updated_at timestamp.
        ``now_ts`` defaults to ``int(time.time())`` -- server-side
        clock is the single source of truth for the timestamp.

        Returns True if the alert existed and was updated, False if
        ``alert_id`` did not match a row. Length-validation
        (``_ALERT_NOTE_MAX_CHARS``) raises ``ValueError`` before any
        DB write so an over-cap submission cannot partially apply.

        Distinct from ``alert_actions.note`` (the per-ack/unack
        action-history note) and from ``watchlist_metadata.notes``
        (Argus-imported metadata). This column is one persistent
        triage conclusion per alert; the action history continues
        to record per-event notes orthogonally.
        """
        self._validate_alert_id(alert_id)
        if not isinstance(note_text, str):
            raise ValueError("note_text must be a string")
        if len(note_text) > self._ALERT_NOTE_MAX_CHARS:
            raise ValueError(
                f"note_text must be <= {self._ALERT_NOTE_MAX_CHARS} chars "
                f"(got {len(note_text)})"
            )
        stripped = note_text.strip()
        if not stripped:
            persist: str | None = None
            ts_value: int | None = None
        else:
            persist = stripped
            ts_value = now_ts if now_ts is not None else int(time.time())
        with self._conn:
            cur = self._conn.execute(
                "UPDATE alerts SET note = ?, note_updated_at = ? WHERE id = ?",
                (persist, ts_value, alert_id),
            )
            return cur.rowcount > 0

    def _set_alert_ack(
        self,
        alert_id: int,
        *,
        action: str,
        actor: str,
        note: str | None,
        ts: int,
    ) -> bool:
        self._validate_alert_id(alert_id)
        actor_clean = self._validate_actor_and_note(actor, note)
        target_flag = 1 if action == "ack" else 0
        with self._conn:
            row = self._conn.execute(
                "SELECT acknowledged FROM alerts WHERE id = ?", (alert_id,)
            ).fetchone()
            if row is None:
                return False
            self._conn.execute(
                "UPDATE alerts SET acknowledged = ? WHERE id = ?",
                (target_flag, alert_id),
            )
            self._conn.execute(
                "INSERT INTO alert_actions(alert_id, action, ts, actor, note) "
                "VALUES (?, ?, ?, ?, ?)",
                (alert_id, action, ts, actor_clean, note),
            )
            return True

    def acknowledge_alert(
        self,
        alert_id: int,
        *,
        actor: str,
        note: str | None = None,
        ts: int,
    ) -> bool:
        return self._set_alert_ack(alert_id, action="ack", actor=actor, note=note, ts=ts)

    def unacknowledge_alert(
        self,
        alert_id: int,
        *,
        actor: str,
        note: str | None = None,
        ts: int,
    ) -> bool:
        return self._set_alert_ack(alert_id, action="unack", actor=actor, note=note, ts=ts)

    def bulk_acknowledge_alerts(
        self,
        alert_ids: list[int],
        *,
        actor: str,
        note: str | None = None,
        ts: int,
    ) -> dict:
        if not isinstance(alert_ids, list):
            raise ValueError("alert_ids must be a list of ints")
        if len(alert_ids) == 0:
            raise ValueError("alert_ids must be non-empty")
        if len(alert_ids) > 1000:
            raise ValueError("alert_ids must contain at most 1000 ids")
        for aid in alert_ids:
            self._validate_alert_id(aid)
        actor_clean = self._validate_actor_and_note(actor, note)

        requested = len(alert_ids)
        unique_ids = list(dict.fromkeys(alert_ids))
        acknowledged = 0
        already_acked = 0
        missing = 0
        action_rows = 0
        with self._conn:
            for aid in unique_ids:
                row = self._conn.execute(
                    "SELECT acknowledged FROM alerts WHERE id = ?", (aid,)
                ).fetchone()
                if row is None:
                    missing += 1
                    continue
                if row["acknowledged"] == 1:
                    already_acked += 1
                else:
                    self._conn.execute(
                        "UPDATE alerts SET acknowledged = 1 WHERE id = ?",
                        (aid,),
                    )
                    acknowledged += 1
                self._conn.execute(
                    "INSERT INTO alert_actions(alert_id, action, ts, actor, note) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (aid, "ack", ts, actor_clean, note),
                )
                action_rows += 1
        return {
            "requested": requested,
            "acknowledged": acknowledged,
            "already_acked": already_acked,
            "missing": missing,
            "action_rows_written": action_rows,
        }

    def list_alert_actions(self, alert_id: int, *, limit: int = 50) -> list[dict]:
        self._validate_alert_id(alert_id)
        if not isinstance(limit, int) or isinstance(limit, bool):
            raise ValueError("limit must be int")
        if limit < 1 or limit > 1000:
            raise ValueError("limit must be in [1, 1000]")
        rows = self._conn.execute(
            "SELECT id, action, ts, actor, note FROM alert_actions "
            "WHERE alert_id = ? ORDER BY ts DESC, id DESC LIMIT ?",
            (alert_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def alert_severity_counts(self, *, since_ts: int | None = None) -> dict:
        counts = {"low": 0, "med": 0, "high": 0}
        if since_ts is None:
            sql = "SELECT severity, COUNT(*) FROM alerts GROUP BY severity"
            params: tuple = ()
        else:
            sql = "SELECT severity, COUNT(*) FROM alerts WHERE ts >= ? GROUP BY severity"
            params = (since_ts,)
        for sev, count in self._conn.execute(sql, params).fetchall():
            if sev in counts:
                counts[sev] = int(count)
        return counts

    def count_alerts_grouped_by_rule_name(
        self, *, since_ts: int | None = None
    ) -> dict[str, RuleStats]:
        """Return ``{rule_name: RuleStats}`` for alerts in the time window.

        Single aggregation query — one round-trip regardless of how
        many distinct ``rule_name`` values exist. ``since_ts`` is an
        epoch-seconds lower bound (inclusive, matches the
        ``alerts.ts >= ?`` shape used elsewhere); ``None`` means
        all-time aggregation. Rules that never fired in the window
        are absent from the dict — callers default missing entries
        to ``RuleStats(count=0, last_fired_ts=None)`` rather than
        filling them in here (keeps the dict small and the rendering
        loop branch-free at the call site).

        ``rule_name`` is the operator-visible identifier from
        rules.yaml — the same string that lands in
        ``alerts.rule_name`` at write time. Pre-migration-015 rows
        with NULL ``rule_type`` still count toward their
        ``rule_name`` aggregate; this helper deliberately ignores
        ``rule_type`` so the count reflects the operator's
        rules.yaml view, not the post-rc5 type-axis subset.

        Backed by the ``idx_alerts_ts`` index for the ``ts >= ?``
        clause; the ``GROUP BY rule_name`` is unindexed but
        operates over the already-filtered range. At current scale
        (rules.yaml typically dozens of entries, alerts table small
        enough that filtered aggregates are sub-100ms) live-querying
        on every /rules render is cheaper than any caching scheme.
        """
        if since_ts is None:
            sql = (
                "SELECT rule_name, COUNT(*), MAX(ts) "
                "FROM alerts GROUP BY rule_name"
            )
            params: tuple = ()
        else:
            sql = (
                "SELECT rule_name, COUNT(*), MAX(ts) "
                "FROM alerts WHERE ts >= ? GROUP BY rule_name"
            )
            params = (since_ts,)
        out: dict[str, RuleStats] = {}
        for rule_name, count, max_ts in self._conn.execute(sql, params).fetchall():
            if rule_name is None:
                # Defensive: alerts.rule_name is NOT NULL in the
                # schema, but a hand-edited DB or a future column
                # relaxation should not crash the /rules page.
                continue
            out[str(rule_name)] = RuleStats(
                count=int(count),
                last_fired_ts=int(max_ts) if max_ts is not None else None,
            )
        return out

    def add_rule_type_snooze(
        self,
        rule_type: str,
        expires_at: int,
        added_at: int,
        note: str | None = None,
    ) -> bool:
        """Insert (or replace) the rule_type snooze row.

        INSERT OR REPLACE semantic: re-snoozing a rule_type that
        already has an active snooze overwrites ``expires_at`` /
        ``added_at`` / ``note`` rather than failing — the operator
        clicking "snooze 24h" on an already-snoozed rule_type wants
        the new window applied, not an error. Returns True on success.

        Caller computes ``expires_at = now_ts + duration_seconds`` so
        the duration-whitelist enforcement lives at the POST-route
        layer; this helper trusts the value passed in.

        Validates ``rule_type`` is a non-empty string. The webui-side
        validates against the ``rules.RuleType`` literal set; this
        helper rejects only the trivially-invalid case so a direct
        caller (e.g. a future CLI surface) doesn't accidentally insert
        an empty string as a primary key.
        """
        if not isinstance(rule_type, str) or not rule_type:
            raise ValueError("rule_type must be a non-empty string")
        if not isinstance(expires_at, int) or isinstance(expires_at, bool):
            raise ValueError("expires_at must be an int (epoch seconds)")
        if not isinstance(added_at, int) or isinstance(added_at, bool):
            raise ValueError("added_at must be an int (epoch seconds)")
        with self._conn:
            self._conn.execute(
                "INSERT OR REPLACE INTO rule_type_snoozes("
                "rule_type, expires_at, added_at, note) VALUES (?, ?, ?, ?)",
                (rule_type, expires_at, added_at, note),
            )
        return True

    def remove_rule_type_snooze(self, rule_type: str) -> bool:
        """Delete the snooze row for ``rule_type``.

        Returns True if a row existed and was deleted, False if no
        snooze existed. The webui "unsnooze" POST handler is idempotent
        — operators double-clicking the button get a 303 either way
        and the template re-renders against current state.
        """
        if not isinstance(rule_type, str) or not rule_type:
            raise ValueError("rule_type must be a non-empty string")
        with self._conn:
            cur = self._conn.execute(
                "DELETE FROM rule_type_snoozes WHERE rule_type = ?",
                (rule_type,),
            )
        return cur.rowcount > 0

    def list_active_rule_type_snoozes(self, now_ts: int) -> list[RuleTypeSnooze]:
        """Return all snoozes whose ``expires_at > now_ts``.

        Expired-but-not-yet-deleted rows are filtered here (the
        cleanup_expired_rule_type_snoozes physical delete runs on
        poller cycle, so between cycles a stale row may briefly exist
        in the table without gating any alerts). The /rules render
        consumes this list and shows the rendered badge / unsnooze
        button only for active rows.

        Sorted by ``rule_type ASC`` for deterministic render order;
        the /rules page iterates rules.yaml entries against this list
        via a dict membership test, so the sort order is for tests
        that read the full active set.
        """
        if not isinstance(now_ts, int) or isinstance(now_ts, bool):
            raise ValueError("now_ts must be an int (epoch seconds)")
        rows = self._conn.execute(
            "SELECT rule_type, expires_at, added_at, note "
            "FROM rule_type_snoozes WHERE expires_at > ? "
            "ORDER BY rule_type ASC",
            (now_ts,),
        ).fetchall()
        return [
            RuleTypeSnooze(
                rule_type=str(r["rule_type"]),
                expires_at=int(r["expires_at"]),
                added_at=int(r["added_at"]),
                note=r["note"],
            )
            for r in rows
        ]

    def cleanup_expired_rule_type_snoozes(self, now_ts: int) -> int:
        """Physically delete snoozes whose ``expires_at <= now_ts``.

        Called from the poller cycle. Between cycles, the gate-time
        ``is_rule_type_snoozed`` filter on ``expires_at > now_ts``
        already ignores expired rows — this is housekeeping, not
        correctness. Returns the count of rows deleted (caller can
        log if non-zero).
        """
        if not isinstance(now_ts, int) or isinstance(now_ts, bool):
            raise ValueError("now_ts must be an int (epoch seconds)")
        with self._conn:
            cur = self._conn.execute(
                "DELETE FROM rule_type_snoozes WHERE expires_at <= ?",
                (now_ts,),
            )
        return cur.rowcount

    def is_rule_type_snoozed(
        self, rule_type: str, now_ts: int
    ) -> RuleTypeSnooze | None:
        """Single-row lookup for the alert-emit gate.

        Returns the live ``RuleTypeSnooze`` when one exists with
        ``expires_at > now_ts``; returns ``None`` for any of:
        - no row exists for this rule_type (the common case — no
          snooze applies)
        - a row exists but has expired (``expires_at <= now_ts``;
          gate gracefully ignores until cleanup runs)

        The gate calls this on every emitted RuleHit. The PK lookup
        is sub-millisecond; checking ``expires_at`` inline in SQL
        means a single round-trip without a follow-up filter.
        """
        if not isinstance(rule_type, str) or not rule_type:
            return None
        if not isinstance(now_ts, int) or isinstance(now_ts, bool):
            raise ValueError("now_ts must be an int (epoch seconds)")
        row = self._conn.execute(
            "SELECT rule_type, expires_at, added_at, note "
            "FROM rule_type_snoozes WHERE rule_type = ? AND expires_at > ?",
            (rule_type, now_ts),
        ).fetchone()
        if row is None:
            return None
        return RuleTypeSnooze(
            rule_type=str(row["rule_type"]),
            expires_at=int(row["expires_at"]),
            added_at=int(row["added_at"]),
            note=row["note"],
        )

    # ------------------------------------------------------------------
    # watchful_recurrence helpers (migration 018)
    #
    # Four operations: lookup-active-by-mac, record-sighting,
    # escalate, auto-archive. Phase 1 entries are created via
    # direct INSERT in tests; Phase 2's operator UI will add a
    # create helper. None of the helpers below assume "escalated
    # is terminal" -- a Phase 2 reset-from-escalated transition
    # (clears escalated_at, resets sighting_count) interoperates
    # cleanly with all four (record_watchful_sighting keeps
    # counting; escalate_watchful_recurrence will fire again on a
    # second threshold cross; auto-archive applies regardless of
    # prior escalation state).
    # ------------------------------------------------------------------

    WATCHFUL_RECURRENCE_DEBOUNCE_SECONDS = 86400
    WATCHFUL_RECURRENCE_ARCHIVE_QUIET_SECONDS = 86400 * 90
    WATCHFUL_RECURRENCE_ESCALATION_THRESHOLD = 4

    def get_active_watchful_recurrence_by_mac(
        self, mac: str
    ) -> WatchfulRecurrence | None:
        """Resolve the active watchful entry for ``mac``, or None.

        "Active" means ``archived_at IS NULL``. Archived rows are
        retained in the table for audit but are not surfaced to
        the gate. The caller (poller) checks ``snooze_expires_at``
        independently when deciding whether the escalation alert
        should be suppressed by the snooze; the row's lifecycle
        does not depend on ``snooze_expires_at`` (per OQ-3).

        Returns the first matching row by ``id`` ASC. The
        application layer enforces at most one active row per MAC
        (no partial-unique index in migration 018 -- see header).
        If multiple active rows somehow exist, the oldest wins,
        which is the safer default for a tracking-style surface.
        """
        if not isinstance(mac, str) or not mac:
            return None
        row = self._conn.execute(
            "SELECT id, mac, created_at, first_seen_at, last_seen_at, "
            "sighting_count, snooze_expires_at, escalated_at, archived_at, "
            "source_alert_id, matched_watchlist_id, confirmed_safe, "
            "flagged_for_investigation, operator_note, reset_count "
            "FROM watchful_recurrence "
            "WHERE mac = ? AND archived_at IS NULL "
            "ORDER BY id ASC LIMIT 1",
            (mac,),
        ).fetchone()
        if row is None:
            return None
        return _row_to_watchful_recurrence(row)

    def record_watchful_sighting(
        self, entry_id: int, observed_at: int
    ) -> WatchfulSightingOutcome | None:
        """Record an observation against a watchful entry.

        Returns ``None`` if the entry doesn't exist or has been
        archived between the gate's lookup and this call (the
        concurrent-archive race documented in the design doc). On
        success returns a ``WatchfulSightingOutcome`` whose
        ``counted`` field is True when the observation triggered a
        count increment (gap >= 24h) and False otherwise.

        The 24-hour debounce boundary is inclusive: an observation
        exactly 86400 seconds after ``last_seen_at`` counts. This
        matches the OQ-3 resolution's inclusive-boundary phrasing
        and differs from the design doc's strict-greater-than
        framing.

        Under-debounce observations are TRUE no-ops at the DB
        layer (``last_seen_at`` is not bumped). This is what makes
        same-cycle dedup organic: the first counted observation in
        a cycle updates ``last_seen_at = now_ts``; any subsequent
        observation in the same cycle has ``gap == 0`` and is
        rejected as under-debounce.

        Independent of ``escalated_at``: the count keeps
        incrementing after escalation so the /watchful UI (Phase
        2) can show the climbing count, and so a Phase 2
        reset-from-escalated transition (clears escalated_at,
        resets sighting_count) can drive a fresh fourth-sighting
        cross without helper changes.
        """
        if not isinstance(entry_id, int) or isinstance(entry_id, bool):
            raise ValueError("entry_id must be an int")
        if not isinstance(observed_at, int) or isinstance(observed_at, bool):
            raise ValueError("observed_at must be an int (epoch seconds)")
        with self._conn:
            row = self._conn.execute(
                "SELECT id, mac, created_at, first_seen_at, last_seen_at, "
                "sighting_count, snooze_expires_at, escalated_at, archived_at, "
                "source_alert_id, matched_watchlist_id, confirmed_safe, "
                "flagged_for_investigation, operator_note, reset_count "
                "FROM watchful_recurrence "
                "WHERE id = ? AND archived_at IS NULL",
                (entry_id,),
            ).fetchone()
            if row is None:
                return None
            gap = observed_at - int(row["last_seen_at"])
            if gap < self.WATCHFUL_RECURRENCE_DEBOUNCE_SECONDS:
                return WatchfulSightingOutcome(
                    counted=False,
                    entry=_row_to_watchful_recurrence(row),
                )
            self._conn.execute(
                "UPDATE watchful_recurrence "
                "SET last_seen_at = ?, sighting_count = sighting_count + 1 "
                "WHERE id = ?",
                (observed_at, entry_id),
            )
            new_row = self._conn.execute(
                "SELECT id, mac, created_at, first_seen_at, last_seen_at, "
                "sighting_count, snooze_expires_at, escalated_at, archived_at, "
                "source_alert_id, matched_watchlist_id, confirmed_safe, "
                "flagged_for_investigation, operator_note, reset_count "
                "FROM watchful_recurrence WHERE id = ?",
                (entry_id,),
            ).fetchone()
        return WatchfulSightingOutcome(
            counted=True,
            entry=_row_to_watchful_recurrence(new_row),
        )

    def escalate_watchful_recurrence(
        self, entry_id: int, escalated_at: int
    ) -> WatchfulRecurrence | None:
        """Set ``escalated_at`` on the entry if currently NULL.

        Returns the post-update row when the transition fired (the
        caller emits the escalation alert in that case), or
        ``None`` when the entry was already escalated, has been
        archived, or doesn't exist. The WHERE-clause guard makes
        this idempotent: a second call for the same entry-id is a
        no-op, which is what drives the design doc's
        "fire once per escalation" rule.

        Phase 2 reset-from-escalated clears ``escalated_at`` back
        to NULL; the next threshold-cross will then call this
        helper again and the WHERE-clause guard will accept the
        new write. No special "re-escalate" path is needed.
        """
        if not isinstance(entry_id, int) or isinstance(entry_id, bool):
            raise ValueError("entry_id must be an int")
        if not isinstance(escalated_at, int) or isinstance(escalated_at, bool):
            raise ValueError("escalated_at must be an int (epoch seconds)")
        with self._conn:
            cur = self._conn.execute(
                "UPDATE watchful_recurrence SET escalated_at = ? "
                "WHERE id = ? "
                "AND escalated_at IS NULL "
                "AND archived_at IS NULL",
                (escalated_at, entry_id),
            )
            if cur.rowcount == 0:
                return None
            row = self._conn.execute(
                "SELECT id, mac, created_at, first_seen_at, last_seen_at, "
                "sighting_count, snooze_expires_at, escalated_at, archived_at, "
                "source_alert_id, matched_watchlist_id, confirmed_safe, "
                "flagged_for_investigation, operator_note, reset_count "
                "FROM watchful_recurrence WHERE id = ?",
                (entry_id,),
            ).fetchone()
        return _row_to_watchful_recurrence(row) if row is not None else None

    def auto_archive_watchful_recurrence(self, now_ts: int) -> int:
        """Archive watchful entries that haven't been counted in 90d.

        The boundary is inclusive: an entry whose
        ``last_seen_at + 90d == now_ts`` is archived. Returns the
        count of rows transitioned.

        Per OQ-3 this is the SOLE lifecycle clock for unactioned
        entries -- ``snooze_expires_at`` is not consulted. An
        entry whose 30-day snooze expired without any recurrence
        therefore continues to occupy a row until 90 days of
        silence accumulate, which the operator sees as a single
        archive transition at day 90 rather than a snooze-driven
        dismiss at day 30 plus an archive at day 90.

        Applies regardless of ``escalated_at``: an escalated entry
        that ages out hits ``archived``. The audit predicate
        ``escalated_at IS NOT NULL AND archived_at IS NOT NULL``
        distinguishes "escalated then aged out unaddressed" from
        "never escalated, archived after 90d quiet" (per OQ-7).

        Idempotent and cheap: indexed on ``archived_at`` (sweep
        target), bounded by the watchful table's small steady-
        state size.
        """
        if not isinstance(now_ts, int) or isinstance(now_ts, bool):
            raise ValueError("now_ts must be an int (epoch seconds)")
        cutoff = now_ts - self.WATCHFUL_RECURRENCE_ARCHIVE_QUIET_SECONDS
        with self._conn:
            cur = self._conn.execute(
                "UPDATE watchful_recurrence SET archived_at = ? "
                "WHERE archived_at IS NULL AND last_seen_at <= ?",
                (now_ts, cutoff),
            )
        return cur.rowcount

    # ------------------------------------------------------------------
    # Phase 2 operator-action helpers (migration 018 dormant columns)
    #
    # Six surfaces wire into Phase 2a's POST routes:
    #
    #   dismiss               -> archived_at = now (idempotent)
    #   promote               -> allowlist write + archived_at = now
    #   reset                 -> escalated_at NULL, count=1, reset_count++
    #   flag-for-investigate  -> flag + note, NO archive
    #   confirmed-safe        -> flag + note + archive
    #   create-from-alert     -> new row from an alerts.id
    #
    # The auto-archive sweep (above) and these operator writes coexist
    # cleanly: the sweep's `WHERE archived_at IS NULL` filter renders
    # operator-archived rows invisible. No housekeeping change needed.
    # ------------------------------------------------------------------

    def dismiss_watchful_recurrence(self, entry_id: int, now_ts: int) -> bool:
        """Operator dismiss: archive the entry, no other state change.

        Idempotent on already-archived (per Phase 2a spec): a second
        call returns False without raising. The DB UPDATE's
        ``archived_at IS NULL`` guard makes the second call a no-op
        and the rowcount tells us which case we hit.

        Returns True if this call performed the archive, False if the
        row was already archived. Caller distinguishes "not found"
        via a separate existence check (the route layer renders 404
        before invoking this helper).
        """
        if not isinstance(entry_id, int) or isinstance(entry_id, bool):
            raise ValueError("entry_id must be an int")
        if not isinstance(now_ts, int) or isinstance(now_ts, bool):
            raise ValueError("now_ts must be an int (epoch seconds)")
        with self._conn:
            cur = self._conn.execute(
                "UPDATE watchful_recurrence SET archived_at = ? "
                "WHERE id = ? AND archived_at IS NULL",
                (now_ts, entry_id),
            )
        return cur.rowcount == 1

    def promote_watchful_to_allowlist(
        self,
        entry_id: int,
        *,
        allowlist_path,
        pattern: str,
        pattern_type: str,
        note: str | None,
        expires_at: int | None,
        now_ts: int,
    ) -> bool:
        """Operator promote: allowlist write + watchful archive, atomic.

        Two effects must happen together: the allowlist file gains an
        entry (so the MAC stops alerting permanently) and the
        watchful row's ``archived_at`` is set (so the operator UI
        stops listing it). The "atomic" intent: the operator never
        sees a half-done state -- both happen, or neither.

        Achieving this against a yaml file + sqlite row is a
        best-effort coupling, not a true distributed transaction.
        Ordering:

          1. Precondition check: the row exists and is active. If
             archived or missing, raise before any side effect so
             the caller gets a clean failure with no yaml write.
          2. Allowlist write. If this raises, the DB row is
             untouched (we have not yet started the transaction).
          3. DB UPDATE under ``WHERE archived_at IS NULL``. If a
             concurrent archive snuck in between (1) and (3), the
             rowcount will be 0; we best-effort remove the yaml
             entry we just wrote and raise.

        The allowlist module is imported inside the function rather
        than at the top of db.py so the foundation module retains no
        compile-time dependency on the operator-UI layer. (db.py is
        a leaf; allowlist.py builds on it conceptually even if it
        does not import it today.)

        Returns True on success. Raises ``ValueError`` if the entry
        is already archived or does not exist; raises
        ``RuntimeError`` if the row was concurrently archived
        between the precondition check and the DB write.
        """
        if not isinstance(entry_id, int) or isinstance(entry_id, bool):
            raise ValueError("entry_id must be an int")
        if not isinstance(now_ts, int) or isinstance(now_ts, bool):
            raise ValueError("now_ts must be an int (epoch seconds)")
        if not isinstance(pattern, str) or not pattern:
            raise ValueError("pattern must be a non-empty string")
        if not isinstance(pattern_type, str) or not pattern_type:
            raise ValueError("pattern_type must be a non-empty string")

        from lynceus.allowlist import AllowlistEntry, add_ui_entry, remove_ui_entry

        row = self._conn.execute(
            "SELECT archived_at FROM watchful_recurrence WHERE id = ?",
            (entry_id,),
        ).fetchone()
        if row is None:
            raise ValueError(f"watchful entry {entry_id} does not exist")
        if row["archived_at"] is not None:
            raise ValueError(f"watchful entry {entry_id} is already archived")

        entry = AllowlistEntry(
            pattern=pattern,
            pattern_type=pattern_type,
            note=note,
            added_at=now_ts,
            expires_at=expires_at,
        )
        add_ui_entry(allowlist_path, entry)
        # Pattern stored is post-normalization; keep it for the rollback path.
        stored_pattern = entry.pattern
        stored_pattern_type = entry.pattern_type

        with self._conn:
            cur = self._conn.execute(
                "UPDATE watchful_recurrence SET archived_at = ? "
                "WHERE id = ? AND archived_at IS NULL",
                (now_ts, entry_id),
            )
            if cur.rowcount == 0:
                # Concurrent archive between our precondition check
                # and the UPDATE. Best-effort rollback of the yaml write.
                try:
                    remove_ui_entry(allowlist_path, stored_pattern, stored_pattern_type)
                except Exception:
                    pass
                raise RuntimeError(
                    f"watchful entry {entry_id} was concurrently archived during promote"
                )
        return True

    def reset_watchful_recurrence(
        self, entry_id: int, now_ts: int
    ) -> WatchfulRecurrence | None:
        """Operator reset-from-escalated: walk the entry back to tracking.

        Per OQ-8 the only state reset is meaningful from is
        ``escalated`` -- the operator saw the escalation alert,
        decided it was a known-benign pattern, and wants the count
        cleared so the next ~4 sightings won't re-escalate
        immediately. Resetting from ``tracking`` would be a no-op
        operator action (count already low); resetting from
        ``archived`` would resurrect a closed entry behind the
        operator's back. Both are rejected via ``ValueError``.

        On success the row becomes::

            escalated_at    -> NULL
            sighting_count  -> 1
            last_seen_at    -> now_ts
            reset_count     -> reset_count + 1

        Returns the post-update ``WatchfulRecurrence`` or raises
        ``ValueError`` if the entry does not exist or is not
        currently escalated. The next time the device is observed,
        the existing Phase 1 escalation machinery (record-sighting
        debounce + escalate guard) takes over with no special
        re-escalation path required.
        """
        if not isinstance(entry_id, int) or isinstance(entry_id, bool):
            raise ValueError("entry_id must be an int")
        if not isinstance(now_ts, int) or isinstance(now_ts, bool):
            raise ValueError("now_ts must be an int (epoch seconds)")
        with self._conn:
            cur = self._conn.execute(
                "UPDATE watchful_recurrence SET "
                "escalated_at = NULL, sighting_count = 1, "
                "last_seen_at = ?, reset_count = reset_count + 1 "
                "WHERE id = ? "
                "AND escalated_at IS NOT NULL "
                "AND archived_at IS NULL",
                (now_ts, entry_id),
            )
            if cur.rowcount == 0:
                raise ValueError(
                    f"watchful entry {entry_id} is not in the escalated state"
                )
            row = self._conn.execute(
                "SELECT id, mac, created_at, first_seen_at, last_seen_at, "
                "sighting_count, snooze_expires_at, escalated_at, archived_at, "
                "source_alert_id, matched_watchlist_id, confirmed_safe, "
                "flagged_for_investigation, operator_note, reset_count "
                "FROM watchful_recurrence WHERE id = ?",
                (entry_id,),
            ).fetchone()
        return _row_to_watchful_recurrence(row) if row is not None else None

    def flag_watchful_for_investigation(
        self, entry_id: int, note: str | None, now_ts: int
    ) -> bool:
        """Operator: mark the entry as 'under investigation', keep tracking.

        Distinct from confirmed-safe and dismiss: the operator wants
        to keep watching but flag the entry visibly for later. The
        row stays active (``archived_at`` unchanged) so future
        sightings continue to count and escalate per Phase 1
        behavior. Sets ``flagged_for_investigation = 1`` and
        replaces ``operator_note``.

        ``now_ts`` is accepted for API symmetry with the other
        operator-action helpers; this surface does not currently
        stamp it anywhere (the v1 row has no
        ``flagged_at`` column). Future-compat: if a per-action
        timestamp column lands, the signature is already shaped to
        carry it.

        Returns True on success. Raises ``ValueError`` if the entry
        is archived or does not exist -- a flag on a closed entry
        would be invisible in the UI and is rejected to avoid
        silent no-ops.
        """
        if not isinstance(entry_id, int) or isinstance(entry_id, bool):
            raise ValueError("entry_id must be an int")
        if not isinstance(now_ts, int) or isinstance(now_ts, bool):
            raise ValueError("now_ts must be an int (epoch seconds)")
        if note is not None and not isinstance(note, str):
            raise ValueError("note must be a string or None")
        with self._conn:
            cur = self._conn.execute(
                "UPDATE watchful_recurrence SET "
                "flagged_for_investigation = 1, operator_note = ? "
                "WHERE id = ? AND archived_at IS NULL",
                (note, entry_id),
            )
            if cur.rowcount == 0:
                raise ValueError(
                    f"watchful entry {entry_id} does not exist or is archived"
                )
        return True

    def mark_watchful_confirmed_safe(
        self, entry_id: int, note: str | None, now_ts: int
    ) -> bool:
        """Operator: mark the entry as confirmed-not-suspicious and close it.

        Distinct from ``promote_watchful_to_allowlist``: the
        operator's signal here is "this specific entry is benign",
        not "never alert me on this MAC again". No allowlist entry
        is created -- the same MAC appearing tomorrow can still
        raise a watchlist hit and a new watchful entry. Confirmed-
        safe is a per-entry annotation plus an archive, nothing
        more.

        Sets ``confirmed_safe = 1``, replaces ``operator_note``,
        and sets ``archived_at = now_ts``. Returns True on success.
        Raises ``ValueError`` if the entry is already archived or
        does not exist.
        """
        if not isinstance(entry_id, int) or isinstance(entry_id, bool):
            raise ValueError("entry_id must be an int")
        if not isinstance(now_ts, int) or isinstance(now_ts, bool):
            raise ValueError("now_ts must be an int (epoch seconds)")
        if note is not None and not isinstance(note, str):
            raise ValueError("note must be a string or None")
        with self._conn:
            cur = self._conn.execute(
                "UPDATE watchful_recurrence SET "
                "confirmed_safe = 1, operator_note = ?, archived_at = ? "
                "WHERE id = ? AND archived_at IS NULL",
                (note, now_ts, entry_id),
            )
            if cur.rowcount == 0:
                raise ValueError(
                    f"watchful entry {entry_id} does not exist or is archived"
                )
        return True

    def create_watchful_from_alert(
        self,
        alert_id: int,
        snooze_duration_seconds: int | None,
        now_ts: int,
    ) -> int | None:
        """Operator triage from /alerts: create a watchful entry.

        Reads ``mac`` and ``matched_watchlist_id`` from the source
        alert (the get_alert path does not include
        matched_watchlist_id, so the SELECT is local). Refuses to
        create if the source alert has no MAC -- watchful tracking
        is MAC-keyed.

        ``snooze_duration_seconds`` is the operator-chosen alert
        suppression window: e.g. 86400 for 24h, 604800 for 7d,
        2592000 for 30d, or ``None`` for forever. This populates
        ``snooze_expires_at`` (alert-gating only -- per OQ-3 it
        does not drive the row's lifecycle clock). The
        forever-snooze case is ``NULL`` in the column, which the
        existing poll-time gate already treats as "no expiry".

        Returns the new row's id. Returns ``None`` if the source
        alert does not exist. Raises ``ValueError`` if the alert
        has no MAC or if an active watchful entry already exists
        for the MAC (application-layer enforcement of the
        "at most one active row per MAC" invariant documented in
        migration 018).
        """
        if not isinstance(alert_id, int) or isinstance(alert_id, bool):
            raise ValueError("alert_id must be an int")
        if not isinstance(now_ts, int) or isinstance(now_ts, bool):
            raise ValueError("now_ts must be an int (epoch seconds)")
        if snooze_duration_seconds is not None:
            if (
                not isinstance(snooze_duration_seconds, int)
                or isinstance(snooze_duration_seconds, bool)
                or snooze_duration_seconds <= 0
            ):
                raise ValueError(
                    "snooze_duration_seconds must be a positive int or None"
                )
        alert_row = self._conn.execute(
            "SELECT mac, matched_watchlist_id FROM alerts WHERE id = ?",
            (alert_id,),
        ).fetchone()
        if alert_row is None:
            return None
        mac = alert_row["mac"]
        if not mac:
            raise ValueError(
                f"alert {alert_id} has no MAC; watchful tracking is MAC-keyed"
            )
        existing = self.get_active_watchful_recurrence_by_mac(mac)
        if existing is not None:
            raise ValueError(
                f"MAC {mac} already has active watchful entry {existing.id}"
            )
        snooze_expires_at = (
            now_ts + snooze_duration_seconds
            if snooze_duration_seconds is not None
            else None
        )
        with self._conn:
            cur = self._conn.execute(
                "INSERT INTO watchful_recurrence("
                "mac, created_at, first_seen_at, last_seen_at, sighting_count, "
                "snooze_expires_at, source_alert_id, matched_watchlist_id) "
                "VALUES (?, ?, ?, ?, 1, ?, ?, ?)",
                (
                    mac,
                    now_ts,
                    now_ts,
                    now_ts,
                    snooze_expires_at,
                    alert_id,
                    alert_row["matched_watchlist_id"],
                ),
            )
        return cur.lastrowid

    def get_watchful_recurrence(
        self, entry_id: int
    ) -> WatchfulRecurrence | None:
        """Fetch a watchful entry by id, active or archived.

        Used by the Phase 2a route layer to render 404 before
        invoking action helpers, and by tests to assert post-action
        state. Distinct from ``get_active_watchful_recurrence_by_mac``
        which filters to active rows by MAC.
        """
        if not isinstance(entry_id, int) or isinstance(entry_id, bool):
            raise ValueError("entry_id must be an int")
        row = self._conn.execute(
            "SELECT id, mac, created_at, first_seen_at, last_seen_at, "
            "sighting_count, snooze_expires_at, escalated_at, archived_at, "
            "source_alert_id, matched_watchlist_id, confirmed_safe, "
            "flagged_for_investigation, operator_note, reset_count "
            "FROM watchful_recurrence WHERE id = ?",
            (entry_id,),
        ).fetchone()
        return _row_to_watchful_recurrence(row) if row is not None else None

    # ------------------------------------------------------------------
    # /watchful page read helpers (Phase 2b)
    #
    # Listing + counting + escalation digest. Mirrors the
    # ``list_alerts_with_match`` + ``count_alerts`` shape used by /alerts
    # so the route's filter/pagination wiring matches the established
    # pattern. Filter semantics (silent fallback on unknown values) live
    # in the route; these helpers accept already-validated tokens.
    # ------------------------------------------------------------------

    _WATCHFUL_LIST_STATUS = frozenset({"active", "archived", "all"})
    _WATCHFUL_LIST_STATE = frozenset({"tracking", "escalated", "all"})

    def _build_watchful_filter_clauses(
        self,
        *,
        status: str,
        state: str,
        since_ts: int | None,
        q: str | None,
    ) -> tuple[str, list]:
        """Compose the WHERE clause + params for list + count.

        Sharing one builder keeps the COUNT and SELECT in lockstep so
        the operator never sees ``pagination.total = 12`` over an
        eight-row page (the bug class the /alerts shared builder
        documents and prevents). The two callers pass identical
        ``status / state / since_ts / q`` and get the same row set.
        """
        clauses: list[str] = []
        params: list = []
        if status == "active":
            clauses.append("archived_at IS NULL")
        elif status == "archived":
            clauses.append("archived_at IS NOT NULL")
        if state == "tracking":
            clauses.append("escalated_at IS NULL")
        elif state == "escalated":
            clauses.append("escalated_at IS NOT NULL")
        if since_ts is not None:
            clauses.append("last_seen_at >= ?")
            params.append(since_ts)
        if q:
            clauses.append("mac LIKE ?")
            params.append(f"%{q}%")
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        return where, params

    def count_watchful_recurrence(
        self,
        *,
        status: str = "active",
        state: str = "all",
        since_ts: int | None = None,
        q: str | None = None,
    ) -> int:
        """Count watchful rows matching the /watchful filter set.

        ``status`` selects on ``archived_at``: ``active`` (NULL),
        ``archived`` (NOT NULL), or ``all``. ``state`` selects on
        ``escalated_at`` and is only meaningful when status=active.
        ``since_ts`` clamps ``last_seen_at >= since_ts`` for the
        recency window. ``q`` is a MAC substring (case-sensitive --
        MACs are stored normalized lowercase).
        """
        if status not in self._WATCHFUL_LIST_STATUS:
            raise ValueError(f"status must be one of {sorted(self._WATCHFUL_LIST_STATUS)}")
        if state not in self._WATCHFUL_LIST_STATE:
            raise ValueError(f"state must be one of {sorted(self._WATCHFUL_LIST_STATE)}")
        where, params = self._build_watchful_filter_clauses(
            status=status, state=state, since_ts=since_ts, q=q,
        )
        row = self._conn.execute(
            f"SELECT COUNT(*) AS c FROM watchful_recurrence{where}",
            params,
        ).fetchone()
        return int(row["c"])

    def list_watchful_recurrence(
        self,
        *,
        status: str = "active",
        state: str = "all",
        since_ts: int | None = None,
        q: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[WatchfulRecurrence]:
        """List watchful rows under the filter set, newest-first.

        Ordering: ``last_seen_at DESC, id DESC``. Most recently active
        rows surface to the top of /watchful, which is the operator's
        triage-first view; the secondary id-DESC tiebreak keeps the
        ordering stable across renders when many rows share a
        last_seen_at (e.g. seed/test data).
        """
        if status not in self._WATCHFUL_LIST_STATUS:
            raise ValueError(f"status must be one of {sorted(self._WATCHFUL_LIST_STATUS)}")
        if state not in self._WATCHFUL_LIST_STATE:
            raise ValueError(f"state must be one of {sorted(self._WATCHFUL_LIST_STATE)}")
        if not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive int")
        if not isinstance(offset, int) or offset < 0:
            raise ValueError("offset must be a non-negative int")
        where, params = self._build_watchful_filter_clauses(
            status=status, state=state, since_ts=since_ts, q=q,
        )
        rows = self._conn.execute(
            "SELECT id, mac, created_at, first_seen_at, last_seen_at, "
            "sighting_count, snooze_expires_at, escalated_at, archived_at, "
            "source_alert_id, matched_watchlist_id, confirmed_safe, "
            "flagged_for_investigation, operator_note, reset_count "
            f"FROM watchful_recurrence{where} "
            "ORDER BY last_seen_at DESC, id DESC "
            "LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()
        return [_row_to_watchful_recurrence(r) for r in rows]

    def list_recent_watchful_escalations(
        self, *, since_ts: int
    ) -> list[WatchfulRecurrence]:
        """Watchful rows whose ``escalated_at`` falls in [since_ts, now].

        Powers the /watchful weekly-digest section. Returns rows
        regardless of current archived state so the digest reflects
        escalations that happened in the window even if the operator
        subsequently archived the entry. Ordered by escalated_at DESC
        so the route can group-by-week in a single pass.
        """
        if not isinstance(since_ts, int) or isinstance(since_ts, bool):
            raise ValueError("since_ts must be an int (epoch seconds)")
        rows = self._conn.execute(
            "SELECT id, mac, created_at, first_seen_at, last_seen_at, "
            "sighting_count, snooze_expires_at, escalated_at, archived_at, "
            "source_alert_id, matched_watchlist_id, confirmed_safe, "
            "flagged_for_investigation, operator_note, reset_count "
            "FROM watchful_recurrence "
            "WHERE escalated_at IS NOT NULL AND escalated_at >= ? "
            "ORDER BY escalated_at DESC",
            (since_ts,),
        ).fetchall()
        return [_row_to_watchful_recurrence(r) for r in rows]

    def alerts_per_day(self, *, days: int = 30, now_ts: int) -> list[dict]:
        if not isinstance(days, int) or isinstance(days, bool):
            raise ValueError("days must be int")
        if days < 1 or days > 365:
            raise ValueError("days must be in [1, 365]")
        if not isinstance(now_ts, int) or isinstance(now_ts, bool):
            raise ValueError("now_ts must be int")

        rows = self._conn.execute(
            "SELECT date(ts, 'unixepoch') AS day, COUNT(*) AS c "
            "FROM alerts WHERE ts >= ? AND ts <= ? GROUP BY day",
            (now_ts - (days - 1) * 86400, now_ts + 86400),
        ).fetchall()
        counts: dict[str, int] = {row["day"]: int(row["c"]) for row in rows if row["day"]}

        import datetime as _dt

        end_day = _dt.datetime.fromtimestamp(now_ts, tz=_dt.UTC).date()
        result: list[dict] = []
        for i in range(days - 1, -1, -1):
            day = end_day - _dt.timedelta(days=i)
            key = day.isoformat()
            result.append({"date": key, "count": counts.get(key, 0)})
        return result

    def device_seen_counts(self, *, now_ts: int) -> dict:
        """Return distinct-device counts in three rolling windows ending at now_ts.

        Returns ``{"day": int, "week": int, "month": int}``. A device counts
        when at least one sighting has ``ts >= now_ts - window_seconds``
        (inclusive lower bound; consistent across all three buckets).
        """
        if not isinstance(now_ts, int) or isinstance(now_ts, bool):
            raise ValueError("now_ts must be int")
        if now_ts <= 0:
            raise ValueError("now_ts must be > 0")
        windows = {
            "day": now_ts - 86400,
            "week": now_ts - 7 * 86400,
            "month": now_ts - 30 * 86400,
        }
        out: dict = {}
        for key, since in windows.items():
            row = self._conn.execute(
                "SELECT COUNT(DISTINCT mac) FROM sightings WHERE ts >= ?",
                (since,),
            ).fetchone()
            out[key] = int(row[0])
        return out

    def latest_poll_ts(self) -> int | None:
        """Return the int value of poller_state['last_poll_ts'] or None if unset.

        Raises ``ValueError`` if the stored value is present but not an int —
        silent fallback would mask DB corruption.
        """
        raw = self.get_state("last_poll_ts")
        if raw is None:
            return None
        try:
            return int(raw)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"poller_state.last_poll_ts is not an int: {raw!r}") from exc

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> Database:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()
