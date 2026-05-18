"""Argus residuals audit — per-type yield + Kismet-observation-surface
analysis of rows the importer currently drops as ``unknown_type``.

Diagnostic tool, not an importer change: read-only, no DB writes,
no Kismet queries, no schema migrations. Re-runnable after each
Argus snapshot refresh for a fresh picture of the residual surface
the F1/F2 implementation prompt is sized against.

Usage::

    python scripts/audit_residuals.py [--csv PATH] [--output PATH]

Default ``--csv``: the dev-box snapshot at
``C:/Claude/argus-db-main/exports/argus_export.csv``, falling back to
``paths.default_data_dir("user") / "argus-cache" / "*.csv"`` for
systems where the dev snapshot path is absent. Default ``--output``:
``docs/ARGUS_RESIDUALS.md`` relative to the repo root.

The Kismet-observation-surface verdict for each residual type is
desk research baked into ``RESIDUAL_SURFACE_TABLE`` below — informed
by Lynceus's existing verified Kismet paths in ``src/lynceus/kismet.py``
plus public Kismet schema documentation. The audit does NOT contact
a live Kismet instance.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from lynceus.cli.import_argus import (  # noqa: E402
    IDENTIFIER_TYPE_MAP,
    parse_argus_csv,
    parse_argus_meta,
)

# Desk-research table: residual identifier_type -> (surface, detail).
#
# ``surface`` is one of:
#   - "normalization-variant": the residual is the same underlying
#     concept as an admitted pattern_type, separated only by a
#     normalization gap (case, hex prefix, dual-form rendering).
#     Recommendation is admit-via-normalization — change the
#     importer's pre-lookup normalization, not the pattern_type set.
#   - "verified-lynceus": Lynceus's ``src/lynceus/kismet.py`` already
#     extracts the underlying Kismet field for another purpose, so
#     the observation path is confirmed.
#   - "verified-kismet-docs": the field is in Kismet's documented
#     device schema with a clear path, though Lynceus has no current
#     consumer.
#   - "plausible-needs-smoke": likely observable based on the
#     Kismet device data model, but not in Lynceus's verified paths
#     and not pinned to a specific documented schema field — needs
#     a live capture to confirm.
#   - "no-observation-surface": the residual is static manufacturer
#     metadata, taxonomy descriptors, or spec values that Kismet
#     does not emit at runtime on a per-device basis.
#
# When the Argus side adds a new identifier_type the audit doesn't
# know about, it surfaces as ``unknown-needs-classification`` and
# becomes a prompt for an audit refresh — the table is the place
# to update, not the script logic.
RESIDUAL_SURFACE_TABLE: dict[str, tuple[str, str]] = {
    "ble_company_id": (
        "normalization-variant",
        "Bluetooth SIG 16-bit Company Identifier — same underlying "
        "concept as admitted pattern_type ``ble_manufacturer_id``. "
        "Residual values like ``0x4C`` / ``0x004C`` differ only in "
        "hex shape from the canonical lowercase 4-hex form Lynceus "
        "already stores (``004c``).",
    ),
    "ble_service_uuid": (
        "normalization-variant",
        "16-bit assigned BLE service UUID — same surface as admitted "
        "pattern_type ``ble_uuid``. Argus emits dual-form values "
        "(e.g. ``fd5a / 0x0075``) which the existing UUID normalizer "
        "rejects as malformed; the canonical 36-char form is stored.",
    ),
    "ble_local_name": (
        "verified-lynceus",
        "Kismet emits the BLE friendly name at "
        "``kismet.device.base.name`` — already harvested in "
        "``src/lynceus/kismet.py`` (``_BLE_NAME_FIELD``) when "
        "``capture.ble_friendly_names`` is enabled.",
    ),
    "device_class_id": (
        "no-observation-surface",
        "DJI ``device_type`` decoder enum (``DJI device_type=1`` ... "
        "``=70`` mapping to model names like Inspire 1 via the "
        "``DRONEID_DRONE_TYPES`` table in the RUB-SysSec/DroneSecurity "
        "decoder). The byte IS in the DJI DroneID broadcast, but the "
        "Argus values are model-class enum codes from a decoder "
        "catalog rather than per-device identifiers — admitting them "
        "as watchlist patterns would alert on every drone of that "
        "model class in range, mirroring the unbounded-fanout posture "
        "the audit already records for ``rf_channel``. Per-device "
        "Remote-ID coverage is via ``drone_id_prefix`` (ANSI/CTA-"
        "2063-A serial number prefix, the UAS-ID field), already "
        "admitted and observed via ``_DRONE_ID_PATHS`` in "
        "``src/lynceus/kismet.py``. Lynceus has no current probe for "
        "the device-type byte and adding one would require a new "
        "pattern_type + schema migration + observation surface for a "
        "match semantic the watchlist primitive does not fit. Verdict "
        "from the rc5 device_class_id archaeology pass (see CHANGELOG).",
    ),
    "ble_protocol_byte_table": (
        "plausible-needs-smoke",
        "First-byte protocol indicator inside the BLE manufacturer "
        "advertisement payload. Observable in principle via "
        "``kismet.device.base.advdata`` but the byte-table view "
        "needs a live emission sample to pin the exact field.",
    ),
    "ssid_pattern": (
        "plausible-needs-smoke",
        "Case-insensitive / substring SSID match — Kismet emits "
        "SSIDs in standard fields and Lynceus already extracts "
        "them, but watchlist match semantics differ from the "
        "existing exact-match ``ssid`` pattern_type and would "
        "require a new matcher in ``rules.py``.",
    ),
    "ble_protocol_byte": (
        "plausible-needs-smoke",
        "Single BLE protocol byte — same observation surface as "
        "``ble_protocol_byte_table``, smaller value cardinality.",
    ),
    "ble_characteristic": (
        "plausible-needs-smoke",
        "BLE GATT characteristic UUID. Kismet does not enumerate "
        "GATT services in its default device emission (only "
        "advertised service UUIDs); confirming requires a live "
        "capture against a connected device.",
    ),
    "chipset_codename": (
        "no-observation-surface",
        "Silicon vendor part number (e.g. ``APQ8009``, ``BCM43xx``) "
        "— static manufacturer metadata, not present in Kismet "
        "runtime device emissions.",
    ),
    "product_family_codename": (
        "no-observation-surface",
        "Vendor-internal product family designation (``AVICORE``, "
        "``CONDOR``) — static spec metadata, never advertised.",
    ),
    "rf_channel": (
        "no-observation-surface",
        "RF center frequency in MHz. Kismet emits "
        "``kismet.device.base.frequency`` per device, but watchlist "
        "semantics — alert on every device on a given frequency — "
        "have unbounded fanout and no real detection value.",
    ),
    "asdstan_enum_value": (
        "no-observation-surface",
        "ASD-STAN F3411 enum descriptor (e.g. "
        "``asdstan_id_type_values.0=None``) — Remote-ID taxonomy "
        "spec value, not a runtime field.",
    ),
    "alpr_model": (
        "no-observation-surface",
        "Argus-internal ALPR model identifier (``builtin-flock``, "
        "``builtin-motorola``) — taxonomy metadata; no equivalent "
        "in Kismet emissions.",
    ),
    "asdstan_message_type": (
        "no-observation-surface",
        "ASD-STAN F3411 message-type descriptor — Remote-ID "
        "spec taxonomy, not a runtime field.",
    ),
    "frequency_band": (
        "no-observation-surface",
        "Cellular band label (``GSM900``, ``DCS1800``) — Kismet "
        "does not emit a band-label field; closest is per-device "
        "frequency in MHz, which carries different semantics.",
    ),
    "firmware_sha256_hash": (
        "no-observation-surface",
        "Firmware binary hash — static spec metadata from "
        "image inspection, never broadcast.",
    ),
    "rf_protocol_constant": (
        "no-observation-surface",
        "PHY-layer protocol constants (Zadoff-Chu seeds, gold "
        "polynomials, CRC init/poly) — static spec values, not "
        "per-device emissions.",
    ),
    "operator_profile": (
        "no-observation-surface",
        "Argus-internal operator profile (``builtin-lowes``, "
        "``builtin-home-depot``) — taxonomy metadata.",
    ),
    "x509_cert_sha256_prefix": (
        "no-observation-surface",
        "X.509 certificate hash prefix — TLS handshake artifact, "
        "not in Kismet's device emission surface.",
    ),
    "gpt_partition_uuid": (
        "no-observation-surface",
        "GPT partition UUID from firmware image inspection — "
        "static metadata, never broadcast.",
    ),
    "ble_adv_interval": (
        "no-observation-surface",
        "BLE advertising interval in seconds — Kismet does not "
        "expose this as a per-device watchlist-shaped value.",
    ),
    "dji_protocol_struct_format": (
        "no-observation-surface",
        "DJI binary struct-pack format string — spec descriptor "
        "for payload layout, not a runtime emission.",
    ),
    "firmware_build_string": (
        "no-observation-surface",
        "Firmware build identifier (``BOOT.BF.3.3-00163``) from "
        "manufacturer specs — static metadata.",
    ),
    "ble_payload_offset": (
        "no-observation-surface",
        "Byte offset descriptor inside a BLE adv payload — spec "
        "metadata, not a per-device runtime field.",
    ),
    "network_endpoint": (
        "no-observation-surface",
        "URL (CRL / OCSP endpoint) — TLS-layer artifact discovered "
        "in firmware inspection, not in Kismet emissions.",
    ),
    "firmware_image_variant": (
        "no-observation-surface",
        "Firmware image variant tag — static manufacturer metadata.",
    ),
    "qualcomm_chip_format_id": (
        "no-observation-surface",
        "Qualcomm chip format identifier — static spec metadata.",
    ),
    "firmware_branded_string": (
        "no-observation-surface",
        "Firmware-branded marker (e.g. ``usb:force_eDL``) — static "
        "spec string, never advertised.",
    ),
    "bandwidth_mhz": (
        "no-observation-surface",
        "Channel bandwidth in MHz — Kismet may expose channel "
        "width but watchlist semantics are not meaningful.",
    ),
    "rf_burst_duration": (
        "no-observation-surface",
        "RF burst duration in seconds — spec metadata, not a "
        "per-device emission.",
    ),
    "firmware_build_uuid": (
        "no-observation-surface",
        "Firmware build UUID from manufacturer specs — static "
        "metadata, never broadcast.",
    ),
}

# Yield threshold separating "admit / defer" from "drop-entirely
# for negligible yield". Set to 5 to align with the prompt's
# explicit ``<5`` floor and with the count of distinct samples
# captured per type.
NEGLIGIBLE_YIELD_THRESHOLD = 5

DEV_BOX_SNAPSHOT = Path("C:/Claude/argus-db-main/exports/argus_export.csv")
DEFAULT_OUTPUT_REL = Path("docs/ARGUS_RESIDUALS.md")


def classify_recommendation(surface: str, yield_count: int) -> str:
    """Map (surface, yield) -> operator recommendation string.

    Decision order:
      1. ``unknown-needs-classification`` -> ``needs-classification``
         (the table needs a new entry; we don't fabricate a verdict)
      2. ``normalization-variant`` -> ``admit-via-normalization``
         (recommend a normalization fix in the importer, NOT a
         new pattern_type / new Kismet surface)
      3. ``no-observation-surface`` -> ``drop-entirely``
         (regardless of yield: no surface = no detection value)
      4. yield < NEGLIGIBLE_YIELD_THRESHOLD -> ``drop-entirely``
         (small-tail residuals do not justify a new code path)
      5. ``verified-lynceus`` -> ``admit``
         (high-value: Lynceus already extracts the field)
      6. ``verified-kismet-docs`` / ``plausible-needs-smoke``
         -> ``defer-pending-smoke``
    """
    if surface == "unknown-needs-classification":
        return "needs-classification"
    if surface == "normalization-variant":
        return "admit-via-normalization"
    if surface == "no-observation-surface":
        return "drop-entirely"
    if yield_count < NEGLIGIBLE_YIELD_THRESHOLD:
        return "drop-entirely"
    if surface == "verified-lynceus":
        return "admit"
    return "defer-pending-smoke"


def collect_residuals(
    csv_path: Path,
) -> tuple[dict[str, list[str]], int, int, Counter[str]]:
    """Walk an Argus CSV, return ``(samples, admitted_count,
    total_count, counts)``.

    ``samples`` maps each residual type to up to 5 distinct
    ``identifier`` strings (first-seen order). ``counts`` carries
    the full row count per residual type; ``admitted_count`` is the
    number of rows whose ``identifier_type`` is in
    ``IDENTIFIER_TYPE_MAP`` (and thus would survive the importer's
    type-layer gate); ``total_count`` is every CSV row.
    """
    rows = parse_argus_csv(str(csv_path))
    counts: Counter[str] = Counter()
    samples: dict[str, list[str]] = defaultdict(list)
    admitted = 0
    for row in rows:
        argus_type = (row.get("identifier_type") or "").strip().lower()
        if argus_type in IDENTIFIER_TYPE_MAP:
            admitted += 1
            continue
        counts[argus_type] += 1
        identifier = row.get("identifier") or ""
        bucket = samples[argus_type]
        if len(bucket) < 5 and identifier and identifier not in bucket:
            bucket.append(identifier)
    return dict(samples), admitted, len(rows), counts


def _md_escape(value: str) -> str:
    """Escape pipe + backtick for markdown-table cells.

    The Argus identifier strings include shapes like ``fd5a / 0x0075``
    that survive a bare table cell, but raw ``|`` in a sample would
    break the row. Sample values are also wrapped in backticks for
    readability; escape any literal backticks inside the value first.
    """
    return value.replace("|", "\\|").replace("`", "\\`")


def _ts_utc() -> str:
    return _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _mtime_utc(path: Path) -> str:
    return (
        _dt.datetime.fromtimestamp(path.stat().st_mtime, tz=_dt.UTC)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )


def render_report(
    *,
    csv_path: Path,
    samples: dict[str, list[str]],
    counts: Counter[str],
    admitted: int,
    total: int,
    meta: dict[str, object],
) -> str:
    """Build the markdown report body."""
    dropped = sum(counts.values())
    admitted_pct = (admitted / total * 100.0) if total else 0.0
    dropped_pct = (dropped / total * 100.0) if total else 0.0
    schema_version = meta.get("schema_version")
    schema_line = f"{schema_version}" if schema_version else "(missing)"
    record_count = meta.get("record_count")
    record_line = f"{record_count}" if record_count is not None else "(missing)"

    lines: list[str] = []
    lines.append("# Argus Residual Types Audit")
    lines.append("")
    lines.append(f"Generated: {_ts_utc()}")
    # Normalize to POSIX-style separators so the rendered path
    # reads cleanly in markdown viewers (backticks + backslashes
    # combine awkwardly). Both forward- and back-slash paths
    # resolve the same on Windows Python file APIs.
    lines.append(f"Argus snapshot: `{Path(csv_path).as_posix()}`")
    lines.append(f"Snapshot mtime: {_mtime_utc(csv_path)}")
    lines.append(f"Argus schema_version: {schema_line}")
    lines.append(f"Argus record_count (meta): {record_line}")
    lines.append(f"Total CSV rows: {total}")
    lines.append(
        f"Currently admitted: {admitted} ({admitted_pct:.1f}%)"
    )
    lines.append(
        f"Currently dropped (unknown_type): {dropped} "
        f"({dropped_pct:.1f}%) across {len(counts)} distinct residual types"
    )
    lines.append("")
    lines.append("## Per-type breakdown")
    lines.append("")
    lines.append(
        "| Type | Argus rows | Sample values | "
        "Surface verification | Recommendation |"
    )
    lines.append(
        "|------|-----------|---------------|"
        "----------------------|----------------|"
    )

    # Stable sort: descending yield first, then alphabetical type
    # so two snapshots with the same counts diff cleanly. Stable
    # ordering also makes the test fixture's expected output
    # exact rather than set-equal.
    ordered_types = sorted(
        counts.keys(), key=lambda t: (-counts[t], t)
    )

    summary_buckets: Counter[str] = Counter()
    summary_yields: Counter[str] = Counter()

    for rtype in ordered_types:
        yield_count = counts[rtype]
        surface_classification, _surface_detail = RESIDUAL_SURFACE_TABLE.get(
            rtype, ("unknown-needs-classification", "")
        )
        recommendation = classify_recommendation(
            surface_classification, yield_count
        )
        sample_cells = ", ".join(
            f"`{_md_escape(s)}`" for s in samples.get(rtype, [])[:5]
        ) or "(none)"
        lines.append(
            f"| `{_md_escape(rtype)}` | {yield_count} | {sample_cells} "
            f"| {surface_classification} | {recommendation} |"
        )
        summary_buckets[recommendation] += 1
        summary_yields[recommendation] += yield_count

    lines.append("")
    lines.append("## Per-type surface detail")
    lines.append("")
    lines.append(
        "Detailed surface rationale for each residual type. The "
        "table above shows the classification label; the prose below "
        "shows why."
    )
    lines.append("")
    for rtype in ordered_types:
        surface_classification, surface_detail = RESIDUAL_SURFACE_TABLE.get(
            rtype, ("unknown-needs-classification", "")
        )
        detail = surface_detail or (
            "Not in ``RESIDUAL_SURFACE_TABLE`` — likely added by a "
            "recent Argus update. Audit table needs a new entry."
        )
        lines.append(
            f"- **`{rtype}`** ({surface_classification}): {detail}"
        )
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    for rec in (
        "admit",
        "admit-via-normalization",
        "defer-pending-smoke",
        "drop-entirely",
        "needs-classification",
    ):
        bucket_types = summary_buckets.get(rec, 0)
        bucket_yield = summary_yields.get(rec, 0)
        lines.append(
            f"- **{rec}**: {bucket_types} type(s), "
            f"{bucket_yield} row(s)"
        )
    lines.append("")

    lines.append("## Methodology")
    lines.append("")
    lines.append(
        "Row counts are derived by parsing the Argus CSV with the "
        "importer's ``parse_argus_csv`` helper, then grouping rows "
        "whose lowercased ``identifier_type`` is not a key in "
        "``IDENTIFIER_TYPE_MAP`` (the same set the importer uses "
        "to decide admission). Sample values are the first five "
        "distinct ``identifier`` strings seen per group; small-"
        "cardinality residuals show all of them."
    )
    lines.append("")
    lines.append(
        "Surface verification is desk research, not live capture. "
        "Each residual type maps to a classification in "
        "``RESIDUAL_SURFACE_TABLE`` in "
        "``scripts/audit_residuals.py``:"
    )
    lines.append("")
    lines.append(
        "- ``normalization-variant`` — the residual is the same "
        "underlying concept as an admitted ``pattern_type``, "
        "blocked only by case / hex-shape / dual-form rendering. "
        "Fix is in the importer's normalization layer, not a new "
        "Kismet surface."
    )
    lines.append(
        "- ``verified-lynceus`` — Lynceus's ``src/lynceus/kismet.py`` "
        "already extracts the underlying Kismet field for some "
        "purpose, so the observation path is confirmed by the "
        "existing code rather than speculative."
    )
    lines.append(
        "- ``verified-kismet-docs`` — the field appears in Kismet's "
        "documented device schema with a clear path; Lynceus has "
        "no current consumer but the surface is known."
    )
    lines.append(
        "- ``plausible-needs-smoke`` — likely observable based on "
        "the Kismet device data model, but not pinned to a "
        "specific documented field. A live capture against "
        "representative hardware is needed before committing to "
        "an admit path."
    )
    lines.append(
        "- ``no-observation-surface`` — the residual is static "
        "manufacturer metadata, taxonomy descriptors, or "
        "PHY-spec constants that Kismet does not emit at runtime."
    )
    lines.append("")
    lines.append(
        "Recommendation logic (see ``classify_recommendation``):"
    )
    lines.append("")
    lines.append(
        "- ``admit-via-normalization`` if surface is "
        "``normalization-variant``."
    )
    lines.append(
        "- ``drop-entirely`` if surface is ``no-observation-surface``, "
        "OR if yield is below "
        f"``NEGLIGIBLE_YIELD_THRESHOLD = {NEGLIGIBLE_YIELD_THRESHOLD}`` "
        "(small-tail residuals don't justify a new code path)."
    )
    lines.append(
        "- ``admit`` if surface is ``verified-lynceus`` and yield "
        "clears the threshold."
    )
    lines.append(
        "- ``defer-pending-smoke`` for the remainder "
        "(``verified-kismet-docs`` / ``plausible-needs-smoke`` with "
        "yield above the threshold)."
    )
    lines.append(
        "- ``needs-classification`` if the residual type is not in "
        "``RESIDUAL_SURFACE_TABLE`` at all — the audit refuses to "
        "fabricate a verdict for an unknown type and surfaces it "
        "for a table refresh."
    )
    lines.append("")

    lines.append("## Re-running")
    lines.append("")
    lines.append(
        "    python scripts/audit_residuals.py [--csv PATH] [--output PATH]"
    )
    lines.append("")
    lines.append(
        "Re-run after each Argus snapshot refresh; the report "
        "regenerates against the new CSV. If a new residual type "
        "lands in ``identifier_type`` that is not in "
        "``RESIDUAL_SURFACE_TABLE``, the recommendation column "
        "shows ``needs-classification`` and the table needs an "
        "entry before the next F1/F2 sizing pass."
    )
    lines.append("")
    return "\n".join(lines)


def resolve_default_csv() -> Path | None:
    """Pick a default --csv when the operator didn't pass one.

    Preference order:
      1. The dev-box snapshot at ``C:/Claude/argus-db-main/exports/
         argus_export.csv`` — the path the operator actually keeps
         the working copy at on this machine, per the project memo.
      2. The newest ``*.csv`` inside the user-scope argus-cache
         (``paths.default_data_dir("user") / "argus-cache"``) — what
         ``lynceus-import-argus --from-github`` writes on system
         installs.

    Returns None if neither is present; main() raises with a clear
    error rather than crashing on a missing default.
    """
    if DEV_BOX_SNAPSHOT.is_file():
        return DEV_BOX_SNAPSHOT
    try:
        from lynceus import paths  # local import: paths needs src on sys.path
    except ModuleNotFoundError:
        return None
    cache_dir = paths.default_data_dir("user") / "argus-cache"
    if not cache_dir.is_dir():
        return None
    csvs = sorted(
        cache_dir.glob("*.csv"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return csvs[0] if csvs else None


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="audit_residuals")
    parser.add_argument(
        "--csv",
        type=Path,
        default=None,
        help=(
            "path to an Argus CSV export (default: dev-box "
            "snapshot at C:/Claude/argus-db-main/exports/"
            "argus_export.csv, falling back to the newest CSV in "
            "the user-scope argus-cache directory)"
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help=(
            f"where to write the markdown report (default: "
            f"{DEFAULT_OUTPUT_REL} relative to the repo root)"
        ),
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    csv_path = args.csv or resolve_default_csv()
    if csv_path is None:
        parser.error(
            "no Argus CSV found at the default locations; pass "
            "--csv PATH explicitly. Looked for: "
            f"{DEV_BOX_SNAPSHOT} and the user-scope argus-cache."
        )
    if not csv_path.is_file():
        parser.error(f"--csv path is not a file: {csv_path}")

    samples, admitted, total, counts = collect_residuals(csv_path)
    meta = parse_argus_meta(str(csv_path))
    report = render_report(
        csv_path=csv_path,
        samples=samples,
        counts=counts,
        admitted=admitted,
        total=total,
        meta=meta,
    )

    output_path = args.output or (REPO_ROOT / DEFAULT_OUTPUT_REL)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report, encoding="utf-8")

    dropped = sum(counts.values())
    sys.stderr.write(
        f"audit_residuals: total={total} admitted={admitted} "
        f"dropped={dropped} residual_types={len(counts)} "
        f"output={output_path}\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
