"""CLI tool to import Argus surveillance-equipment CSV exports into the
v0.3 watchlist + watchlist_metadata side table.

Idempotent on ``argus_record_id``. Supports operator overrides for vendor
and category severity, geographic filtering, and a confidence-based severity
downgrade. ``--dry-run`` parses + reports without writing.
"""

from __future__ import annotations

import argparse
import csv
import datetime as _dt
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests
import yaml

from .. import paths
from ..db import Database
from ..patterns import normalize_pattern

logger = logging.getLogger(__name__)

EXPECTED_HEADER: list[str] = [
    "argus_record_id",
    "id",
    "identifier",
    "identifier_type",
    "device_category",
    "manufacturer",
    "model",
    "confidence",
    "source_type",
    "source_url",
    "source_excerpt",
    "geographic_scope",
    "description",
    "first_seen",
    "last_verified",
    "notes",
]

# Argus identifier_type -> Lynceus watchlist.pattern_type.
IDENTIFIER_TYPE_MAP: dict[str, str] = {
    "mac": "mac",
    "oui": "oui",
    "ssid_exact": "ssid",
    "ble_uuid": "ble_uuid",
    "ble_service": "ble_uuid",
}

# Per-spec built-in severity defaults. Categories not listed default to "low".
DEFAULT_CATEGORY_SEVERITIES: dict[str, str] = {
    "imsi_catcher": "high",
    "alpr": "high",
    "body_cam": "med",
    "drone": "med",
    "gunshot_detect": "med",
    "hacking_tool": "high",
    "in_vehicle_router": "med",
    "unknown": "low",
}

VALID_SEVERITIES = ("high", "med", "low")
DEFAULT_OVERRIDE_PATH = "/etc/lynceus/severity_overrides.yaml"
DEFAULT_CONFIDENCE_DOWNGRADE_THRESHOLD = 70

# GitHub-fetch defaults for `--from-github`. Argus publishes its
# canonical CSV at exports/argus_export.csv on the kevlattice/argus
# repository; the path is fixed by the Argus side of the contract.
DEFAULT_GITHUB_REPO = "kevlattice/argus"
ARGUS_EXPORT_PATH_IN_REPO = "exports/argus_export.csv"
GITHUB_API_TIMEOUT_SECONDS = 15
GITHUB_RAW_TIMEOUT_SECONDS = 30

# Argus CSV `first_seen` / `last_verified` accepted timestamp shapes.
#
# Argus codified the canonical emission as ISO-8601 UTC with `Z` suffix at
# seconds precision (e.g. ``"2026-05-14T06:13:42Z"``) on 2026-05-14. Live
# archived exports may predate that landing and carry any of:
#
# - canonical Z form              (``"2026-05-14T06:13:42Z"``)
# - ISO with explicit UTC offset  (``"2026-05-14T06:13:42.204792+00:00"``)
# - space-separated, treated UTC  (``"2026-05-06 00:30:28"``)
# - date-only, midnight UTC       (``"2026-05-10"``)
#
# `_parse_date` tries each in order; returns int Unix UTC timestamp.
_DATE_FORMATS: tuple[str, ...] = (
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
)


@dataclass
class OverrideConfig:
    vendor_overrides: dict[str, str] = field(default_factory=dict)
    device_category_severity: dict[str, str] = field(default_factory=dict)
    geographic_filter: list[str] = field(default_factory=list)
    confidence_downgrade_threshold: int = DEFAULT_CONFIDENCE_DOWNGRADE_THRESHOLD


def load_override_config(path: str | None) -> OverrideConfig:
    """Load operator overrides from YAML; absent file yields built-in defaults."""
    if path is None:
        return OverrideConfig()
    p = Path(path)
    if not p.is_file():
        logger.info("override file %s not found, using built-in defaults", path)
        return OverrideConfig()
    with open(p, encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    return OverrideConfig(
        vendor_overrides=dict(raw.get("vendor_overrides") or {}),
        device_category_severity=dict(raw.get("device_category_severity") or {}),
        geographic_filter=list(raw.get("geographic_filter") or []),
        confidence_downgrade_threshold=int(
            raw.get("confidence_downgrade_threshold", DEFAULT_CONFIDENCE_DOWNGRADE_THRESHOLD)
        ),
    )


def _downgrade(severity: str) -> str:
    if severity == "high":
        return "med"
    if severity == "med":
        return "low"
    return "low"


def resolve_severity(
    *,
    manufacturer: str | None,
    device_category: str | None,
    confidence: int,
    overrides: OverrideConfig,
) -> str:
    """First match wins: vendor override > category override > built-in default.

    Returns one of ``"high"``, ``"med"``, ``"low"``, or the literal ``"drop"``
    when an override demands the record be skipped.
    """
    if manufacturer and manufacturer in overrides.vendor_overrides:
        sev = overrides.vendor_overrides[manufacturer]
    elif device_category and device_category in overrides.device_category_severity:
        sev = overrides.device_category_severity[device_category]
    elif device_category in DEFAULT_CATEGORY_SEVERITIES:
        sev = DEFAULT_CATEGORY_SEVERITIES[device_category]
    else:
        sev = "low"
    if sev == "drop":
        return "drop"
    if sev not in VALID_SEVERITIES:
        raise ValueError(f"invalid severity {sev!r} (expected one of {VALID_SEVERITIES} or 'drop')")
    threshold = overrides.confidence_downgrade_threshold
    if threshold > 0 and confidence < threshold:
        sev = _downgrade(sev)
    return sev


def _passes_geographic_filter(scope: str | None, filter_list: list[str]) -> bool:
    if not filter_list:
        return True
    if scope is None or scope == "":
        return False
    if scope == "global":
        return True
    return scope in filter_list


def _parse_date(value: str | None) -> int | None:
    """Parse an Argus CSV `first_seen` / `last_verified` value to Unix UTC.

    Tolerant of all four shapes historically emitted by Argus. Canonical
    emission is ISO-8601 UTC `Z` form at seconds precision; the older
    shapes remain supported for backward compat with archived exports.
    """
    if value is None or value == "":
        return None
    raw = value.strip()
    # ISO-8601 with `Z` suffix or explicit offset — `fromisoformat`
    # (Python 3.11+) handles both. Try this first: it's the canonical
    # shape and the dominant pre-canonicalization shape.
    if "T" in raw:
        normalized = raw[:-1] + "+00:00" if raw.endswith("Z") else raw
        try:
            dt = _dt.datetime.fromisoformat(normalized)
        except ValueError:
            pass
        else:
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=_dt.UTC)
            else:
                dt = dt.astimezone(_dt.UTC)
            return int(dt.timestamp())
    for fmt in _DATE_FORMATS:
        try:
            dt = _dt.datetime.strptime(raw, fmt).replace(tzinfo=_dt.UTC)
        except ValueError:
            continue
        return int(dt.timestamp())
    raise ValueError(
        f"unparseable Argus timestamp {value!r} — expected ISO-8601 with Z "
        f"or offset, space-separated `YYYY-MM-DD HH:MM:SS`, "
        f"or date-only `YYYY-MM-DD`"
    )


def _empty_to_none(value: str | None) -> str | None:
    if value is None or value == "":
        return None
    return value


@dataclass
class ImportReport:
    total_rows: int = 0
    imported_new: int = 0
    updated: int = 0
    unchanged: int = 0
    dropped_mac_range: int = 0
    dropped_severity_drop: int = 0
    dropped_geographic_filter: int = 0
    dropped_unknown_type: int = 0
    dropped_low_confidence: int = 0
    normalization_failed: int = 0
    errors: int = 0
    error_log: list[str] = field(default_factory=list)
    dry_run: bool = False

    def render(self) -> str:
        prefix = "[DRY RUN] " if self.dry_run else ""
        lines = [
            f"{prefix}Total rows in CSV: {self.total_rows}",
            f"{prefix}Imported (new): {self.imported_new}",
            f"{prefix}Updated (existing): {self.updated}",
            f"{prefix}Unchanged (no field deltas): {self.unchanged}",
            f"{prefix}Dropped (mac_range): {self.dropped_mac_range}",
            f"{prefix}Dropped (severity_drop): {self.dropped_severity_drop}",
            f"{prefix}Dropped (geographic_filter): {self.dropped_geographic_filter}",
            f"{prefix}Dropped (unknown_type): {self.dropped_unknown_type}",
            f"{prefix}Dropped (low_confidence): {self.dropped_low_confidence}",
            f"{prefix}Dropped (normalization_failed): {self.normalization_failed}",
            f"{prefix}Errors: {self.errors}",
        ]
        if self.error_log:
            lines.append(f"{prefix}--- Error log ---")
            lines.extend(f"{prefix}  {msg}" for msg in self.error_log)
        total_dropped = (
            self.dropped_mac_range
            + self.dropped_severity_drop
            + self.dropped_geographic_filter
            + self.dropped_unknown_type
            + self.dropped_low_confidence
            + self.normalization_failed
        )
        lines.append(
            f"{prefix}imported {self.imported_new} records, "
            f"updated {self.updated}, "
            f"dropped {total_dropped} "
            f"({self.dropped_mac_range} mac_range, "
            f"{self.dropped_geographic_filter} geographic_filter, "
            f"{self.dropped_severity_drop} severity_drop, "
            f"{self.dropped_unknown_type} unknown_type, "
            f"{self.dropped_low_confidence} low_confidence, "
            f"{self.normalization_failed} normalization_failed)"
        )
        return "\n".join(lines)


def _validate_header(header: list[str]) -> None:
    if header == EXPECTED_HEADER:
        return
    missing = [c for c in EXPECTED_HEADER if c not in header]
    extra = [c for c in header if c not in EXPECTED_HEADER]
    issues = []
    if missing:
        issues.append(f"missing column(s): {missing}")
    if extra:
        issues.append(f"unexpected column(s): {extra}")
    if not missing and not extra:
        issues.append(f"columns out of order: got {header}, expected {EXPECTED_HEADER}")
    raise ValueError("argus CSV header invalid — " + "; ".join(issues))


def parse_argus_csv(path: str) -> list[dict[str, str]]:
    """Read an Argus CSV. Skips the leading ``# meta:`` comment line, validates
    the header, and returns rows as dicts keyed by Argus column name.
    """
    with open(path, encoding="utf-8", newline="") as f:
        first = f.readline()
        if not first.startswith("# meta:"):
            raise ValueError(
                f"argus CSV {path}: expected first line to start with '# meta:', got {first!r}"
            )
        reader = csv.reader(f)
        try:
            header = next(reader)
        except StopIteration as exc:
            raise ValueError(f"argus CSV {path}: missing header row") from exc
        _validate_header(header)
        rows: list[dict[str, str]] = []
        for raw_row in reader:
            if len(raw_row) != len(EXPECTED_HEADER):
                raise ValueError(
                    f"argus CSV row has {len(raw_row)} columns, expected "
                    f"{len(EXPECTED_HEADER)}: {raw_row!r}"
                )
            rows.append(dict(zip(EXPECTED_HEADER, raw_row, strict=True)))
        return rows


def _build_metadata_fields(row: dict[str, str], confidence: int) -> dict[str, Any]:
    return {
        "argus_record_id": row["argus_record_id"],
        "device_category": _empty_to_none(row["device_category"]),
        "vendor": _empty_to_none(row["manufacturer"]),
        "source": _empty_to_none(row["source_type"]),
        "source_url": _empty_to_none(row["source_url"]),
        "source_excerpt": _empty_to_none(row["source_excerpt"]),
        "geographic_scope": _empty_to_none(row["geographic_scope"]),
        "notes": _empty_to_none(row["notes"]),
        "confidence": confidence,
        "first_seen": _parse_date(row["first_seen"]),
        "last_verified": _parse_date(row["last_verified"]),
    }


def _watchlist_row_for(db: Database, watchlist_id: int) -> dict | None:
    row = db._conn.execute(
        "SELECT id, pattern, pattern_type, severity, description FROM watchlist WHERE id = ?",
        (watchlist_id,),
    ).fetchone()
    return dict(row) if row is not None else None


def _watchlist_row_by_natural_key(db: Database, pattern: str, pattern_type: str) -> dict | None:
    row = db._conn.execute(
        "SELECT id, pattern, pattern_type, severity, description "
        "FROM watchlist WHERE pattern = ? AND pattern_type = ? LIMIT 1",
        (pattern, pattern_type),
    ).fetchone()
    return dict(row) if row is not None else None


def import_csv(
    db: Database,
    csv_path: str,
    overrides: OverrideConfig,
    *,
    dry_run: bool = False,
    min_confidence: int | None = None,
) -> ImportReport:
    rows = parse_argus_csv(csv_path)
    report = ImportReport(total_rows=len(rows), dry_run=dry_run)

    for row in rows:
        try:
            argus_id = row["argus_record_id"]
            if not argus_id:
                raise ValueError("row is missing argus_record_id")

            # Argus may emit identifier_type in any case (e.g. BLE_SERVICE).
            # Allowlist keys are lowercase; normalize before the lookup so
            # uppercase rows aren't silently swallowed as dropped_unknown_type.
            argus_type = (row["identifier_type"] or "").strip().lower()
            if argus_type == "mac_range":
                report.dropped_mac_range += 1
                # INFO not WARNING: these are expected drops per the
                # Argus §4.4 contract, not anomalies. Operators who want
                # silence can lift to WARN; the row-level forensic trail
                # is for diagnosing Wave-G-style surprises without
                # grepping the original CSV.
                logger.info(
                    "argus import: skipping row argus_record_id=%s "
                    "identifier_type=%r reason=%s",
                    argus_id,
                    row["identifier_type"],
                    "mac_range_unsupported",
                )
                continue
            if argus_type not in IDENTIFIER_TYPE_MAP:
                report.dropped_unknown_type += 1
                logger.info(
                    "argus import: skipping row argus_record_id=%s "
                    "identifier_type=%r reason=%s",
                    argus_id,
                    row["identifier_type"],
                    "unknown_identifier_type",
                )
                continue
            pattern_type = IDENTIFIER_TYPE_MAP[argus_type]

            scope = _empty_to_none(row["geographic_scope"])
            if not _passes_geographic_filter(scope, overrides.geographic_filter):
                report.dropped_geographic_filter += 1
                continue

            conf_str = row["confidence"]
            if conf_str is None or conf_str == "":
                raise ValueError("confidence is required")
            try:
                confidence = int(conf_str)
            except ValueError as exc:
                raise ValueError(f"confidence must be int, got {conf_str!r}") from exc

            # Hard skip for --min-confidence. Distinct from
            # overrides.confidence_downgrade_threshold, which downgrades
            # severity but still imports the row.
            if min_confidence is not None and confidence < min_confidence:
                report.dropped_low_confidence += 1
                logger.info(
                    "row argus_record_id=%r: skipped "
                    "(confidence=%d below --min-confidence=%d)",
                    argus_id,
                    confidence,
                    min_confidence,
                )
                continue

            severity = resolve_severity(
                manufacturer=_empty_to_none(row["manufacturer"]),
                device_category=_empty_to_none(row["device_category"]),
                confidence=confidence,
                overrides=overrides,
            )
            if severity == "drop":
                report.dropped_severity_drop += 1
                continue

            pattern = row["identifier"]
            if not pattern:
                raise ValueError("identifier is empty")
            # Normalize at write time (L-RULES-1). The poller normalizes its
            # observation MAC/UUID before the equality lookup against the
            # watchlist table; a row stored in non-canonical form silently
            # never matches and the alert loses its Argus metadata link.
            try:
                pattern = normalize_pattern(pattern_type, pattern)
            except ValueError as exc:
                report.normalization_failed += 1
                logger.warning(
                    "row argus_record_id=%r: rejected for normalization: %s",
                    argus_id,
                    exc,
                )
                continue
            description = _empty_to_none(row["description"])
            new_metadata = _build_metadata_fields(row, confidence)

            existing_md = db.get_metadata_by_argus_record_id(argus_id)
            existing_wl = (
                _watchlist_row_for(db, existing_md["watchlist_id"])
                if existing_md is not None
                else None
            )

            wl_changed = existing_wl is not None and (
                existing_wl["severity"] != severity
                or (existing_wl["description"] or None) != (description or None)
            )
            md_changed = existing_md is None or any(
                existing_md.get(k) != v for k, v in new_metadata.items()
            )

            if dry_run:
                if existing_md is None:
                    report.imported_new += 1
                elif wl_changed or md_changed:
                    report.updated += 1
                else:
                    report.unchanged += 1
                continue

            if existing_md is None:
                # Argus side has no record: insert (or attach to an existing
                # YAML-seeded watchlist row) and create the metadata side.
                wl_row = _watchlist_row_by_natural_key(db, pattern, pattern_type)
                if wl_row is None:
                    with db._conn:
                        cur = db._conn.execute(
                            "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
                            "VALUES (?, ?, ?, ?)",
                            (pattern, pattern_type, severity, description),
                        )
                        watchlist_id = int(cur.lastrowid)
                else:
                    watchlist_id = int(wl_row["id"])
                    if wl_row["severity"] != severity or (wl_row["description"] or None) != (
                        description or None
                    ):
                        with db._conn:
                            db._conn.execute(
                                "UPDATE watchlist SET severity = ?, description = ? WHERE id = ?",
                                (severity, description, watchlist_id),
                            )
                db.upsert_metadata(watchlist_id, new_metadata)
                report.imported_new += 1
            else:
                watchlist_id = int(existing_md["watchlist_id"])
                if wl_changed:
                    with db._conn:
                        db._conn.execute(
                            "UPDATE watchlist SET severity = ?, description = ? WHERE id = ?",
                            (severity, description, watchlist_id),
                        )
                if md_changed:
                    db.upsert_metadata(watchlist_id, new_metadata)
                if wl_changed or md_changed:
                    report.updated += 1
                else:
                    report.unchanged += 1
        except Exception as exc:
            report.errors += 1
            report.error_log.append(
                f"row argus_record_id={row.get('argus_record_id', '?')!r}: {exc}"
            )

    return report


def _resolve_ref(repo: str, ref: str | None) -> str:
    """Resolve which Argus repo ref to fetch the export from.

    With ``ref`` set, return it verbatim — operators who explicitly ask
    for ``main`` or a specific commit get exactly that, no API call.

    With ``ref is None``, query the GitHub Releases API for the latest
    *tagged release* (NOT the tip of main). A single bad push to main
    must not poison every operator who refreshes via ``--from-github``;
    pulling tagged releases by default keeps refresh on the slower,
    operator-curated cadence the Argus side uses for cuts.
    """
    if ref:
        return ref
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    r = requests.get(url, timeout=GITHUB_API_TIMEOUT_SECONDS)
    r.raise_for_status()
    payload = r.json()
    tag = payload.get("tag_name")
    if not tag:
        raise RuntimeError(
            f"GitHub API returned no tag_name for {repo} latest release: {payload!r}"
        )
    return tag


def fetch_argus_export(repo: str, ref: str | None, cache_dir: Path) -> Path:
    """Download an Argus CSV export from GitHub at ``ref`` (or latest tag).

    The file lands in ``cache_dir`` named ``<resolved-ref>__argus_export.csv``
    so each pulled artifact is preserved alongside the ref it came from
    — useful for forensic re-runs and for distinguishing two refreshes
    that landed on the same day. Re-fetching the same ref overwrites the
    cached copy; we don't try to be clever about ETags.
    """
    resolved = _resolve_ref(repo, ref)
    url = (
        f"https://raw.githubusercontent.com/{repo}/{resolved}/"
        f"{ARGUS_EXPORT_PATH_IN_REPO}"
    )
    cache_dir.mkdir(parents=True, exist_ok=True)
    # Sanitize the ref into the filename so a slash-bearing ref
    # (e.g. ``release/v1.2``) doesn't escape into a subdirectory.
    safe_ref = resolved.replace("/", "_").replace("\\", "_")
    dest = cache_dir / f"{safe_ref}__argus_export.csv"
    logger.info("Fetching Argus export %s@%s from %s", repo, resolved, url)
    # verify=True is the requests default; do NOT disable it. The
    # threat-model rationale for --from-github relies on TLS + GitHub's
    # serving infrastructure to authenticate the artifact.
    resp = requests.get(url, timeout=GITHUB_RAW_TIMEOUT_SECONDS)
    resp.raise_for_status()
    dest.write_bytes(resp.content)
    logger.info("Cached %d bytes at %s", len(resp.content), dest)
    return dest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="lynceus-import-argus")
    parser.add_argument(
        "--db",
        type=Path,
        default=None,
        help=(
            "path to lynceus sqlite database (default: "
            "paths.default_db_path(--scope), e.g. "
            "~/.local/share/lynceus/lynceus.db for --scope user, "
            "/var/lib/lynceus/lynceus.db for --scope system)"
        ),
    )
    parser.add_argument(
        "--scope",
        choices=("user", "system"),
        default="user",
        help=(
            "scope used to derive default --db and --from-github cache "
            "directory (default: %(default)s). Ignored when --db is "
            "passed explicitly AND --from-github is not used."
        ),
    )
    # --input and --from-github are alternatives. Mutual exclusion is
    # enforced after parse_args() so the error message can name both
    # flags clearly; argparse's add_mutually_exclusive_group() emits a
    # less-actionable "not allowed with" message and would not let us
    # require *exactly* one without bolting on the same post-parse
    # check anyway. --input stays available for air-gapped operators.
    parser.add_argument(
        "--input",
        default=None,
        help="path to a local Argus CSV export (alternative to --from-github)",
    )
    parser.add_argument(
        "--from-github",
        action="store_true",
        help=(
            "fetch the Argus CSV export from GitHub before importing. "
            "Default ref is the latest tagged release of --repo; pass "
            "--ref to pin to a specific tag, branch, or commit."
        ),
    )
    parser.add_argument(
        "--ref",
        default=None,
        help=(
            "git ref (tag / branch / commit) to fetch from --repo when "
            "--from-github is set. Default: latest tagged release. "
            "Explicit --ref main is allowed but not recommended."
        ),
    )
    parser.add_argument(
        "--repo",
        default=DEFAULT_GITHUB_REPO,
        metavar="OWNER/NAME",
        help="GitHub OWNER/NAME of the Argus repo (default: %(default)s)",
    )
    parser.add_argument(
        "--override-file",
        default=DEFAULT_OVERRIDE_PATH,
        help="path to severity overrides YAML (default: %(default)s)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="parse, validate, and print the report without writing to DB",
    )
    parser.add_argument(
        "--min-confidence",
        type=int,
        default=None,
        metavar="N",
        help=(
            "hard-skip rows with confidence < N (0-100). Rows below the "
            "threshold land in the dropped_low_confidence counter and never "
            "touch the DB. Distinct from the YAML "
            "confidence_downgrade_threshold (which downgrades severity but "
            "still imports the row)."
        ),
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    args = parser.parse_args(argv)

    logging.basicConfig(level=args.log_level)

    # Mutex on input source. "Exactly one" — neither is also an error,
    # because there is no sensible default behavior here: previously
    # --input was required, so we keep the strictness, just split across
    # two flags.
    if args.from_github and args.input:
        parser.error("--from-github and --input are mutually exclusive; pass exactly one")
    if not args.from_github and not args.input:
        parser.error("one of --from-github or --input is required")
    if args.ref and not args.from_github:
        parser.error("--ref is only meaningful with --from-github")

    db_path = args.db if args.db is not None else paths.default_db_path(args.scope)

    overrides = load_override_config(args.override_file)
    try:
        if args.from_github:
            cache_dir = paths.default_data_dir(args.scope) / "argus-cache"
            input_path = str(fetch_argus_export(args.repo, args.ref, cache_dir))
        else:
            input_path = args.input

        db = Database(str(db_path))
        try:
            report = import_csv(
                db,
                input_path,
                overrides,
                dry_run=args.dry_run,
                min_confidence=args.min_confidence,
            )
        finally:
            db.close()
    except Exception:
        logger.exception("argus import failed")
        return 1

    print(report.render())
    return 0


if __name__ == "__main__":
    sys.exit(main())
