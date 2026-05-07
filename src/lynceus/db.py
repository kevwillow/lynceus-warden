"""SQLite persistence layer: schema, migrations, and connection helpers."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from types import TracebackType


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
        self._conn = sqlite3.connect(
            path,
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
            check_same_thread=False,
        )
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
    ) -> int:
        with self._conn:
            cur = self._conn.execute(
                "INSERT INTO alerts(ts, rule_name, mac, message, severity) VALUES (?, ?, ?, ?, ?)",
                (ts, rule_name, mac, message, severity),
            )
            return cur.lastrowid

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
    _DEVICE_TYPES = ("wifi", "ble", "bt_classic")

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
    ) -> list[dict]:
        self._validate_pagination(limit, offset)
        if severity is not None and severity not in self._ALERT_SEVERITIES:
            raise ValueError(f"severity must be one of {self._ALERT_SEVERITIES}")

        clauses, params = self._alert_filter_clauses(
            severity=severity,
            acknowledged=acknowledged,
            since_ts=since_ts,
            until_ts=until_ts,
            search=search,
        )
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = (
            "SELECT id, ts, rule_name, mac, message, severity, acknowledged "
            f"FROM alerts {where} ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?"
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
    ) -> int:
        if severity is not None and severity not in self._ALERT_SEVERITIES:
            raise ValueError(f"severity must be one of {self._ALERT_SEVERITIES}")
        clauses, params = self._alert_filter_clauses(
            severity=severity,
            acknowledged=acknowledged,
            since_ts=since_ts,
            until_ts=until_ts,
            search=search,
        )
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT COUNT(*) FROM alerts {where}"
        return int(self._conn.execute(sql, params).fetchone()[0])

    @staticmethod
    def _alert_filter_clauses(
        *,
        severity: str | None,
        acknowledged: bool | None,
        since_ts: int | None,
        until_ts: int | None,
        search: str | None,
    ) -> tuple[list[str], list]:
        clauses: list[str] = []
        params: list = []
        if severity is not None:
            clauses.append("severity = ?")
            params.append(severity)
        if acknowledged is not None:
            clauses.append("acknowledged = ?")
            params.append(1 if acknowledged else 0)
        if since_ts is not None:
            clauses.append("ts >= ?")
            params.append(since_ts)
        if until_ts is not None:
            clauses.append("ts <= ?")
            params.append(until_ts)
        if search is not None and search != "":
            like = f"%{search.lower()}%"
            clauses.append("(LOWER(message) LIKE ? OR LOWER(rule_name) LIKE ?)")
            params.extend([like, like])
        return clauses, params

    def get_alert(self, alert_id: int) -> dict | None:
        row = self._conn.execute(
            "SELECT id, ts, rule_name, mac, message, severity, acknowledged "
            "FROM alerts WHERE id = ?",
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

    _WATCHLIST_PATTERN_TYPES = ("mac", "oui", "ssid", "ble_uuid")
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
