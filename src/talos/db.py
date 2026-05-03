"""SQLite persistence layer: schema, migrations, and connection helpers."""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from types import TracebackType

_MIGRATIONS_DIR = Path(__file__).resolve().parent.parent.parent / "migrations"


class Database:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(
            path,
            detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._apply_migrations()

    def _apply_migrations(self) -> None:
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations("
            "version INTEGER PRIMARY KEY, "
            "applied_at INTEGER NOT NULL)"
        )
        self._conn.commit()
        applied = {row[0] for row in self._conn.execute("SELECT version FROM schema_migrations")}
        for sql_path in sorted(_MIGRATIONS_DIR.glob("*.sql")):
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
