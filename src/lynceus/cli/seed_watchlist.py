"""CLI tool to seed the lynceus watchlist table.

Sources entries from built-in threat lists or YAML files. Idempotent — safe to
re-run.
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import sys

import yaml

from ..db import Database
from ..seeds.ble_uuids import TRACKER_UUIDS
from ..seeds.threat_ouis import THREAT_OUIS

VALID_PATTERN_TYPES = {"mac", "oui", "ssid", "ble_uuid"}
VALID_SEVERITIES = {"low", "med", "high"}

# Metadata block — mirrors the watchlist_metadata table's allowed columns.
# argus_record_id is optional in YAML (synthetic ID generated when absent);
# device_category is the only required field when a metadata block is present.
METADATA_REQUIRED_FIELDS = frozenset({"device_category"})
METADATA_OPTIONAL_FIELDS = frozenset(
    {
        "argus_record_id",
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
    }
)
METADATA_ALLOWED_FIELDS = METADATA_REQUIRED_FIELDS | METADATA_OPTIONAL_FIELDS

logger = logging.getLogger(__name__)


def _synthetic_argus_record_id(pattern: str, pattern_type: str) -> str:
    """Stable synthetic ID for hand-seeded YAML entries lacking an explicit one.

    Same (pattern, pattern_type) always yields the same ID, so re-seeding the
    same YAML stays idempotent. The ``yaml-`` prefix visually distinguishes
    these from Argus-imported records.
    """
    digest = hashlib.sha256(f"{pattern}:{pattern_type}".encode()).hexdigest()
    return f"yaml-{digest[:16]}"


def _validate_metadata(metadata: object) -> str | None:
    """Returns an error string if metadata is invalid, or None if valid."""
    if not isinstance(metadata, dict):
        return f"metadata must be a mapping, got {type(metadata).__name__}"
    unknown = set(metadata) - METADATA_ALLOWED_FIELDS
    if unknown:
        return f"unknown metadata keys (typo?): {sorted(unknown)}"
    if not metadata.get("device_category"):
        return "metadata block requires device_category"
    confidence = metadata.get("confidence")
    if confidence is not None:
        if isinstance(confidence, bool) or not isinstance(confidence, int):
            return f"metadata.confidence must be int 0..100, got {confidence!r}"
        if confidence < 0 or confidence > 100:
            return f"metadata.confidence must be in [0, 100], got {confidence}"
    return None


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


def _get_or_insert_watchlist_id(
    db: Database,
    pattern: str,
    pattern_type: str,
    severity: str,
    description: str | None,
) -> tuple[int, bool]:
    """Return (watchlist_id, was_inserted). Inserts only when row absent."""
    row = db._conn.execute(
        "SELECT id FROM watchlist WHERE pattern = ? AND pattern_type = ? LIMIT 1",
        (pattern, pattern_type),
    ).fetchone()
    if row is not None:
        return int(row[0]), False
    with db._conn:
        cur = db._conn.execute(
            "INSERT INTO watchlist (pattern, pattern_type, severity, description) "
            "VALUES (?, ?, ?, ?)",
            (pattern, pattern_type, severity, description),
        )
        return int(cur.lastrowid), True


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


def seed_ble_uuids(db: Database) -> tuple[int, int]:
    """Returns (inserted, skipped) counts. Idempotent."""
    inserted = 0
    skipped = 0
    for entry in TRACKER_UUIDS:
        pattern = entry["pattern"]
        if _entry_already_present(db, pattern, "ble_uuid"):
            logger.debug("skipping existing BLE UUID %s", pattern)
            skipped += 1
            continue
        _insert_entry(db, pattern, "ble_uuid", entry["severity"], entry["description"])
        logger.info("inserted BLE UUID %s (%s)", pattern, entry["severity"])
        inserted += 1
    return inserted, skipped


def seed_from_yaml(db: Database, yaml_path: str) -> tuple[int, int]:
    """Load a YAML file and seed entries.

    Top-level shape: ``{entries: [{pattern, pattern_type, severity, description,
    metadata?}]}``. The optional ``metadata`` block routes to the
    ``watchlist_metadata`` side table; entries without it remain v0.2-shaped.
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
        metadata = raw.get("metadata")

        if not isinstance(pattern, str) or not pattern.strip():
            logger.warning("skipping entry with empty/invalid pattern: %r", raw)
            skipped += 1
            continue
        if pattern_type not in VALID_PATTERN_TYPES:
            logger.warning("skipping entry with invalid pattern_type %r: %r", pattern_type, raw)
            skipped += 1
            continue
        if severity not in VALID_SEVERITIES:
            logger.warning("skipping entry with invalid severity %r: %r", severity, raw)
            skipped += 1
            continue

        if metadata is not None:
            err = _validate_metadata(metadata)
            if err is not None:
                logger.warning("skipping entry %s/%s: %s", pattern_type, pattern, err)
                skipped += 1
                continue

        watchlist_id, was_inserted = _get_or_insert_watchlist_id(
            db, pattern, pattern_type, severity, description
        )
        if was_inserted:
            logger.info("inserted %s/%s (%s)", pattern_type, pattern, severity)
            inserted += 1
        else:
            logger.debug("skipping existing entry %s/%s", pattern_type, pattern)
            skipped += 1

        if metadata is not None:
            md_fields = {k: v for k, v in metadata.items() if k in METADATA_ALLOWED_FIELDS}
            if not md_fields.get("argus_record_id"):
                md_fields["argus_record_id"] = _synthetic_argus_record_id(pattern, pattern_type)
            db.upsert_metadata(watchlist_id, md_fields)
            logger.info(
                "upserted metadata for %s/%s (argus_record_id=%s)",
                pattern_type,
                pattern,
                md_fields["argus_record_id"],
            )

    return inserted, skipped


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="lynceus-seed-watchlist")
    parser.add_argument("--db", required=True, help="path to lynceus sqlite database")
    parser.add_argument(
        "--threat-ouis",
        action="store_true",
        help="seed the built-in threat OUI list",
    )
    parser.add_argument(
        "--ble-uuids",
        action="store_true",
        help="seed the built-in BLE tracker UUID list",
    )
    parser.add_argument("--yaml", help="path to a YAML file with watchlist entries")
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    args = parser.parse_args(argv)

    if not args.threat_ouis and not args.ble_uuids and not args.yaml:
        print(
            "error: at least one of --threat-ouis, --ble-uuids, or --yaml is required",
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
            if args.ble_uuids:
                ins, skp = seed_ble_uuids(db)
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
