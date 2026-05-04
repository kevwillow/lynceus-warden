"""SQLite persistence layer: schema, migrations, and connection helpers."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from types import TracebackType


def _find_migrations_dir() -> Path:
    try:
        from importlib.resources import files

        pkg_migrations = files("talos.migrations")
        as_path = Path(str(pkg_migrations))
        if as_path.is_dir() and any(as_path.glob("*.sql")):
            return as_path
    except (ModuleNotFoundError, TypeError, OSError):
        pass

    repo_relative = Path(__file__).resolve().parent.parent.parent / "migrations"
    if repo_relative.is_dir() and any(repo_relative.glob("*.sql")):
        return repo_relative

    raise FileNotFoundError(
        "Could not locate talos migrations directory. "
        "Expected either talos.migrations package data or a repo-relative migrations/ folder."
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
    ) -> list[dict]:
        self._validate_pagination(limit, offset)
        if severity is not None and severity not in self._ALERT_SEVERITIES:
            raise ValueError(f"severity must be one of {self._ALERT_SEVERITIES}")

        clauses: list[str] = []
        params: list = []
        if severity is not None:
            clauses.append("severity = ?")
            params.append(severity)
        if acknowledged is not None:
            clauses.append("acknowledged = ?")
            params.append(1 if acknowledged else 0)
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
    ) -> int:
        if severity is not None and severity not in self._ALERT_SEVERITIES:
            raise ValueError(f"severity must be one of {self._ALERT_SEVERITIES}")
        clauses: list[str] = []
        params: list = []
        if severity is not None:
            clauses.append("severity = ?")
            params.append(severity)
        if acknowledged is not None:
            clauses.append("acknowledged = ?")
            params.append(1 if acknowledged else 0)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT COUNT(*) FROM alerts {where}"
        return int(self._conn.execute(sql, params).fetchone()[0])

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
