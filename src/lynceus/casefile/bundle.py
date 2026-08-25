"""One set of artifacts, written as a directory or streamed as a zip.

⛔ Both surfaces build from the SAME ``build_artifacts`` dict, so the CLI
and the web UI cannot ship different bundles. They are two entry points
to one product, and a recipient comparing two exports of the same record
has to get the same answer.

The manifest is computed over exactly the bytes that are written. A
manifest computed over anything else would be worse than having none: it
would certify a bundle it never saw.
"""

from __future__ import annotations

import csv
import io
import json
import zipfile
from pathlib import Path

from .manifest import build_manifest
from .render import render_html

HTML_NAME = "case-file.html"
MANIFEST_NAME = "manifest.json"
README_NAME = "README.txt"

#: A fixed timestamp for every zip entry. Two exports of the same record
#: must produce the same bytes, and a wall-clock mtime would make the zip
#: differ from itself for no reason a recipient could check.
_ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)

#: Ceiling for an export the web UI will build in memory. Past it the
#: route refuses and names the CLI, which streams to disk and has no such
#: bound. A refusal that names the alternative beats an OOM on the box
#: that is supposed to be doing the watching.
#:
#: ⭐ MEASURED, not chosen for roundness. See .claude/gates.md for the
#: run, its date and its SHA. Everything reaching this point is already
#: bounded by the caps in query.py, so this is a backstop for evidence
#: blobs, which are the one unbounded input.
MAX_STREAMED_BYTES = 64 * 1024 * 1024


class ExportTooLarge(Exception):
    """The bundle is too big to build in memory on this machine.

    Carries the uncompressed size so the caller can tell the operator how
    far past the line they are rather than only that they are past it.
    """

    def __init__(self, total_bytes: int, limit_bytes: int) -> None:
        super().__init__(f"case file is {total_bytes} bytes, over the {limit_bytes} byte limit")
        self.total_bytes = total_bytes
        self.limit_bytes = limit_bytes


def _csv_bytes(header: list[str], rows) -> bytes:
    buf = io.StringIO(newline="")
    writer = csv.writer(buf, lineterminator="\n")
    writer.writerow(header)
    for row in rows:
        writer.writerow(row)
    return buf.getvalue().encode("utf-8")


def _sightings_csv(case) -> bytes:
    return _csv_bytes(
        ["mac", "ts", "location_id", "rssi", "ssid"],
        (
            [
                case.device.get("mac"),
                s.get("ts"),
                s.get("location_id"),
                s.get("rssi"),
                s.get("ssid"),
            ]
            for s in case.sightings
        ),
    )


def _alerts_csv(case) -> bytes:
    return _csv_bytes(
        [
            "id",
            "ts",
            "rule_name",
            "rule_type",
            "severity",
            "mac",
            "matched_watchlist_id",
            "message",
        ],
        (
            [
                a.get("id"),
                a.get("ts"),
                a.get("rule_name"),
                a.get("rule_type"),
                a.get("severity"),
                a.get("mac"),
                a.get("matched_watchlist_id"),
                a.get("message"),
            ]
            for a in case.alerts
        ),
    )


def _co_observation_csv(case) -> bytes:
    rows = []
    for observer in case.co_observers_named:
        for loc in observer.get("locations", []):
            rows.append(
                [
                    observer["mac"],
                    loc.get("location_id"),
                    loc.get("shared_anchor_runs"),
                    loc.get("shared_days"),
                    loc.get("delta_min"),
                    loc.get("delta_median"),
                    loc.get("delta_max"),
                    loc.get("first_shared_ts"),
                    loc.get("last_shared_ts"),
                ]
            )
    return _csv_bytes(
        [
            "mac",
            "location_id",
            "shared_visits",
            "shared_days",
            "delta_min_seconds",
            "delta_median_seconds",
            "delta_max_seconds",
            "first_shared_ts",
            "last_shared_ts",
        ],
        rows,
    )


def _co_observation_pairs_csv(case) -> bytes:
    """The individual sighting pairs behind every count above.

    Not in the original layout sketch, and included because a count with
    no way to check it is exactly what the co-observation work went out
    of its way to avoid: every row here is two real logged sightings and
    the true interval between them.
    """
    rows = []
    for observer in case.co_observers_named:
        for pair in observer.get("pairs", []):
            rows.append(
                [
                    observer["mac"],
                    pair.get("location_id"),
                    pair.get("anchor_ts"),
                    pair.get("candidate_ts"),
                    pair.get("delta_seconds"),
                ]
            )
    return _csv_bytes(
        ["mac", "location_id", "this_device_ts", "that_device_ts", "interval_seconds"],
        rows,
    )


def _readme(case) -> bytes:
    device = case.device.get("mac", "unknown")
    named = len(case.co_observers_named)
    aggregate = case.co_observers_aggregate
    withheld = case.excluded_counts.get("do_not_publish", 0)
    over_cap = case.excluded_counts.get("sightings_over_cap", 0)

    lines = [
        "LYNCEUS CASE FILE",
        "=================",
        "",
        f"This bundle is the recorded history of one device, {device}, as held by",
        "one Lynceus installation.",
        "",
        "WHAT IS IN HERE",
        "",
        f"  {HTML_NAME}          the document. Open it in any browser. It works offline.",
        f"  {MANIFEST_NAME}            a SHA-256 for every other file in this bundle.",
        "  data/                    the underlying rows as CSV, so the document can be",
        "                           checked rather than taken on trust.",
        "  evidence/                the captured record for each alert, as JSON.",
        "",
        "THIS BUNDLE IS SENSITIVE",
        "",
        "It records where the person operating the sensor has been and what was",
        "near them. The location history in here is theirs as much as it is the",
        "observed device's. Treat it accordingly.",
        "",
        "WHAT THE HASHES DO AND DO NOT SHOW",
        "",
        f"  {MANIFEST_NAME} shows these files are unchanged since the export ran.",
        "  It does not prove the observations are accurate, and it is not a third",
        "  party attestation: the operator's own installation produced this bundle,",
        "  and the operator controls the database it came from.",
        "",
        "WHAT WAS DELIBERATELY LEFT OUT",
        "",
        f"  {named} device(s) seen alongside this one are named in the document, because",
        "  they matched the watchlist of known surveillance equipment.",
        f"  {aggregate} further device(s) were seen alongside it and are NOT named. On this",
        "  record they are members of the public, and this product will not put",
        "  their addresses in a document that may be handed to a third party.",
    ]
    if withheld:
        lines += [
            "",
            f"  {withheld} evidence snapshot(s) were withheld: the operator marked them",
            "  do not publish. They are counted here rather than silently dropped.",
        ]
    if over_cap:
        lines += [
            "",
            f"  {over_cap} sighting(s) are in the database but not listed, because this",
            f"  export was capped at {case.parameters.get('sighting_limit')} rows.",
        ]
    lines += [
        "",
        "BEFORE YOU RELY ON ANY OF IT",
        "",
        "  Read the 'Limits of this record' section at the end of the document.",
        "  Every point in it is a limit of the method, not a caution added for",
        "  form. In particular: this record is keyed on MAC address, and a gap in",
        "  it is not evidence of absence.",
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def build_artifacts(case) -> dict[str, bytes]:
    """Every file in the bundle, keyed by its path inside the bundle.

    The manifest is added last and covers everything else, which is why
    it cannot cover itself: a digest of a file that contains that digest
    has no fixed point.
    """
    artifacts: dict[str, bytes] = {
        HTML_NAME: render_html(case).encode("utf-8"),
        README_NAME: _readme(case),
        "data/sightings.csv": _sightings_csv(case),
        "data/alerts.csv": _alerts_csv(case),
        "data/co-observation.csv": _co_observation_csv(case),
        "data/co-observation-pairs.csv": _co_observation_pairs_csv(case),
    }
    for snapshot in case.evidence:
        artifacts[f"evidence/{snapshot['alert_id']}.json"] = json.dumps(
            snapshot, indent=2, sort_keys=True, default=str
        ).encode("utf-8")

    artifacts[MANIFEST_NAME] = json.dumps(
        build_manifest(artifacts), indent=2, sort_keys=True
    ).encode("utf-8")
    return artifacts


def bundle_name(case) -> str:
    """``case-<mac with no separators>-<YYYY-MM-DD>``.

    Derived from the NORMALISED MAC, which ``normalize_mac`` has already
    matched against a strict pattern, so nothing path-shaped survives to
    reach the filesystem. The stripping below is belt and braces on top
    of that, not the primary defence.
    """
    mac = str(case.device.get("mac", "")).replace(":", "").replace("-", "")
    mac = "".join(ch for ch in mac if ch.isalnum()) or "unknown"
    from .render import _format_date

    stamp = _format_date(case.parameters.get("generated_at_ts"))
    return f"case-{mac}-{stamp}"


def write_directory(case, out_dir) -> Path:
    """Write the bundle under ``out_dir`` and return the directory made."""
    root = Path(out_dir) / bundle_name(case)
    root.mkdir(parents=True, exist_ok=True)
    for name, payload in build_artifacts(case).items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    return root


def build_zip_bytes(case) -> bytes:
    """The same artifacts, in memory, never touching the filesystem.

    ⛔ The daemon must not write an export to disk. On a --system install
    the units grant ReadWritePaths=/var/lib/lynceus /var/log/lynceus and
    writing outside that is the 500 that #218 fixed for allowlist_ui.yaml.
    It also means the download lands on the laptop the operator is
    browsing from rather than on a headless Pi they would then have to
    copy it off, and nothing is left behind on that Pi afterwards.
    """
    artifacts = build_artifacts(case)

    # Checked BEFORE the zip is written, so the refusal costs one copy
    # rather than two. Deciding after compression would mean the machine
    # had already paid the memory this exists to protect.
    total = sum(len(v) for v in artifacts.values())
    if total > MAX_STREAMED_BYTES:
        raise ExportTooLarge(total, MAX_STREAMED_BYTES)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, payload in sorted(artifacts.items()):
            info = zipfile.ZipInfo(filename=name, date_time=_ZIP_EPOCH)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, payload)
    return buf.getvalue()
