"""CLI tool to seed the talos watchlist table.

Sources entries from built-in threat lists or YAML files. Idempotent — safe to
re-run.
"""

from __future__ import annotations

import argparse
import logging
import sys

import yaml

from ..db import Database
from ..seeds.threat_ouis import THREAT_OUIS

VALID_PATTERN_TYPES = {"mac", "oui", "ssid", "ble_uuid"}
VALID_SEVERITIES = {"low", "med", "high"}

logger = logging.getLogger(__name__)


def _entry_already_present(db: Database, pattern: str, pattern_type: str) -> bool:
    row = db._conn.execute(
        "SELECT 1 FROM watchlist WHERE pattern = ? AND pattern_type = ? LIMIT 1",
        (pattern, pattern_type),
    ).fetchone()
    return row is not None


def _insert_entry(
    db: Database,
    pattern: str,
    pattern_type: str,
    severity: str,
    description: str | None,
) -> None:
    with db._conn:
        db._conn.execute(
            "INSERT INTO watchlist (pattern, pattern_type, severity, description) "
            "VALUES (?, ?, ?, ?)",
            (pattern, pattern_type, severity, description),
        )


def seed_threat_ouis(db: Database) -> tuple[int, int]:
    """Returns (inserted, skipped) counts. Idempotent."""
    inserted = 0
    skipped = 0
    for entry in THREAT_OUIS:
        pattern = entry["pattern"]
        if _entry_already_present(db, pattern, "oui"):
            logger.debug("skipping existing OUI %s", pattern)
            skipped += 1
            continue
        _insert_entry(db, pattern, "oui", entry["severity"], entry["description"])
        logger.info("inserted threat OUI %s (%s)", pattern, entry["severity"])
        inserted += 1
    return inserted, skipped


def seed_from_yaml(db: Database, yaml_path: str) -> tuple[int, int]:
    """Load a YAML file and seed entries.

    Expected shape: {entries: [{pattern, pattern_type, severity, description}]}.
    """
    with open(yaml_path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    entries = data.get("entries", []) or []

    inserted = 0
    skipped = 0
    for raw in entries:
        pattern = raw.get("pattern")
        pattern_type = raw.get("pattern_type")
        severity = raw.get("severity")
        description = raw.get("description")

        if not isinstance(pattern, str) or not pattern.strip():
            logger.warning("skipping entry with empty/invalid pattern: %r", raw)
            skipped += 1
            continue
        if pattern_type not in VALID_PATTERN_TYPES:
            logger.warning(
                "skipping entry with invalid pattern_type %r: %r", pattern_type, raw
            )
            skipped += 1
            continue
        if severity not in VALID_SEVERITIES:
            logger.warning("skipping entry with invalid severity %r: %r", severity, raw)
            skipped += 1
            continue

        if _entry_already_present(db, pattern, pattern_type):
            logger.debug("skipping existing entry %s/%s", pattern_type, pattern)
            skipped += 1
            continue

        _insert_entry(db, pattern, pattern_type, severity, description)
        logger.info("inserted %s/%s (%s)", pattern_type, pattern, severity)
        inserted += 1
    return inserted, skipped


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="talos-seed-watchlist")
    parser.add_argument("--db", required=True, help="path to talos sqlite database")
    parser.add_argument(
        "--threat-ouis",
        action="store_true",
        help="seed the built-in threat OUI list",
    )
    parser.add_argument("--yaml", help="path to a YAML file with watchlist entries")
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    args = parser.parse_args(argv)

    if not args.threat_ouis and not args.yaml:
        print(
            "error: at least one of --threat-ouis or --yaml is required",
            file=sys.stderr,
        )
        return 2

    logging.basicConfig(level=args.log_level)

    try:
        db = Database(args.db)
        try:
            total_inserted = 0
            total_skipped = 0
            if args.threat_ouis:
                ins, skp = seed_threat_ouis(db)
                total_inserted += ins
                total_skipped += skp
            if args.yaml:
                ins, skp = seed_from_yaml(db, args.yaml)
                total_inserted += ins
                total_skipped += skp
        finally:
            db.close()
    except Exception:
        logger.exception("seed failed")
        return 1

    logger.info("Seed complete: %d inserted, %d skipped", total_inserted, total_skipped)
    return 0
