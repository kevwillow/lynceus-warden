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
import re
import zipfile
from pathlib import Path

from ..csv_safety import csv_safe_cell
from .manifest import build_manifest
from .render import render_html

#: Any MAC-shaped run of text, in either of the two spellings this
#: product writes. Deliberately loose: this is a net, not a parser.
_MAC_SHAPED = re.compile(
    r"\b(?:[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}|[0-9a-fA-F]{12})\b"
)

#: What replaces an address the document is not allowed to disclose.
REDACTED_ADDRESS = "[address withheld]"


HTML_NAME = "case-file.html"
MANIFEST_NAME = "manifest.json"
README_NAME = "README.txt"

#: A fixed timestamp for every zip entry. Two exports of the same record
#: must produce the same bytes, and a wall-clock mtime would make the zip
#: differ from itself for no reason a recipient could check.
_ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)

#: Ceiling for an export the web UI will build in memory. Past it the
#: route refuses and names the CLI, which writes straight to disk and has
#: no such bound. A refusal that names the alternative beats an OOM on
#: the box that is supposed to be doing the watching.
#:
#: ⭐ DERIVED FROM A MEASUREMENT, not picked for roundness. At the caps on
#: 2026-08-24 the bundle was 4.78 MB of artifacts and peak allocation was
#: 26.3 MB, and across the whole sweep peak allocation ran at roughly
#: 5.5x the uncompressed artifact size. 32 MB of artifacts therefore
#: implies around 175 MB of peak allocation, which is what a 2 GB Pi
#: already running the daemon can absorb. See .claude/gates.md.
#:
#: ⚠️ This is a backstop for EVIDENCE, which is the one unbounded input:
#: everything else is bounded by the caps in query.py, and at those caps
#: the total is 4.78 MB, nowhere near this. A stored Kismet record has no
#: size limit, so 200 large snapshots is the way a real export gets here.
MAX_STREAMED_BYTES = 32 * 1024 * 1024


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
        # ⛔ Through the shared helper, not raw. A cell starting =, +, -
        # or @ is RUN AS A FORMULA by Excel, Sheets and Calc on open, and
        # SSIDs and watchlist descriptions are externally controlled. The
        # web UI's exports have been neutralised since the CSP work; this
        # is the second exporter and it must not be the weak one.
        writer.writerow([csv_safe_cell(cell) for cell in row])
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
        "  they matched a rule in the operator's watchlist. ⚠️ That is a rule match,",
        "  not an identification: a watchlist rule can cover a whole manufacturer",
        "  prefix or address range, so a named device is one the watchlist SELECTED",
        "  and not one that has been individually verified.",
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
    fields_withheld = case.excluded_counts.get("evidence_fields_withheld", 0)
    if fields_withheld:
        lines += [
            "",
            f"  {fields_withheld} field(s) were withheld from the evidence records. The",
            "  captured record describes the observed device, but it also carries the",
            "  addresses of other devices associated with it, and those belong to",
            "  members of the public. Only fields describing the observed device",
            "  itself are published.",
        ]
    if over_cap:
        lines += [
            "",
            f"  {over_cap} sighting(s) are in the database but not listed, because this",
            f"  export was capped at {case.parameters.get('sighting_limit')} rows.",
        ]
    # ⛔ Every cap that bit, reported. A cap nobody is told about reads as
    # completeness, which is the one thing this document must never imply.
    alerts_over = case.excluded_counts.get("alerts_over_cap", 0)
    if alerts_over:
        lines += [
            "",
            f"  {alerts_over} alert(s) matched but are not listed, because this export was",
            "  capped. Their evidence is not here either, so the withheld-snapshot",
            "  count above describes only the alerts that ARE listed.",
        ]
    co_over = case.excluded_counts.get("co_observers_over_cap", 0)
    if co_over:
        lines += [
            "",
            f"  {co_over} further co-observed device(s) were not analysed at all, because",
            "  the co-observation scan was capped. They are counted in neither the",
            "  named list nor the aggregate above.",
        ]
    redacted = case.excluded_counts.get("unapproved_addresses_redacted", 0)
    if redacted:
        lines += [
            "",
            f"  {redacted} address(es) were replaced with \"{REDACTED_ADDRESS}\" because they",
            "  appeared in free text and belong to neither this device nor any named",
            "  co-observer.",
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


def _redact_unapproved_addresses(payload: bytes, approved: set[str]) -> tuple[bytes, int]:
    """Replace every MAC-shaped string that is not approved for disclosure.

    ⛔ The last line of defence, and the reason it exists: the disclosure
    rule was written as "aggregate unwatchlisted co-observers", and twice
    an address reached an output by a route that rule did not cover. The
    first was a co-observer; the second sat nested inside the target's own
    stored Kismet record and was found only by auditing, after the guards
    for the first were already written and green.

    ⇒ Enforcing "no unapproved address leaves" as a property of the BYTES
    is the only version of this contract that does not depend on somebody
    having thought of every field. Free text is the open-ended part: an
    SSID and a watchlist description are externally controlled, and a
    future rule message could quote a second device.

    Redacts and COUNTS, never silently, matching every other exclusion in
    this feature.
    """
    if not payload:
        return payload, 0
    count = 0

    def _sub(match):
        nonlocal count
        found = match.group(0).lower()
        canonical = found if ":" in found else ":".join(
            found[i : i + 2] for i in range(0, 12, 2)
        )
        if canonical in approved:
            return match.group(0)
        count += 1
        return REDACTED_ADDRESS

    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return payload, 0
    return _MAC_SHAPED.sub(_sub, text).encode("utf-8"), count


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
        # int(), so the value can never become a path component. It is a
        # FK to an INTEGER PRIMARY KEY today; coercing costs nothing and
        # removes the question from the traversal argument entirely.
        artifacts[f"evidence/{int(snapshot['alert_id'])}.json"] = json.dumps(
            snapshot, indent=2, sort_keys=True, default=str
        ).encode("utf-8")

    # ⛔ Swept BEFORE the manifest is computed, so the digests cover the
    # bytes that actually ship. Hashing first and redacting afterwards
    # would produce a manifest that certifies a bundle nobody has.
    approved = case.approved_addresses()
    redacted_total = 0
    for name in list(artifacts):
        artifacts[name], n = _redact_unapproved_addresses(artifacts[name], approved)
        redacted_total += n
    if redacted_total:
        case.excluded_counts["unapproved_addresses_redacted"] = redacted_total
        # Rebuilt so the note below is itself inside the hashed bytes.
        artifacts[README_NAME] = _readme(case)
        artifacts[HTML_NAME], _ = _redact_unapproved_addresses(
            render_html(case).encode("utf-8"), approved
        )

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


class BundleExists(Exception):
    """A bundle directory of this name is already there."""

    def __init__(self, root: Path) -> None:
        super().__init__(f"{root} already exists")
        self.root = root


def write_directory(case, out_dir, *, overwrite: bool = False) -> Path:
    """Write the bundle under ``out_dir`` and return the directory made.

    ⛔ Refuses an existing bundle directory rather than writing over it.
    The name is derived from the MAC and the date, so a second export of
    the same device on the same day collides, and merging into it leaves
    files from the FIRST export in place. That is not untidiness: an
    evidence snapshot the operator has since marked do_not_publish would
    still be sitting in the directory they hand over, while the new
    manifest and the new document both say it was withheld. The bundle
    would then contain a file the manifest does not cover, which also
    falsifies README.txt's claim to hash every file in it.
    """
    root = Path(out_dir) / bundle_name(case)
    if root.exists() and any(root.iterdir()):
        if not overwrite:
            raise BundleExists(root)
        # Only ever removes files inside a directory this function named
        # and that looks like one of its own bundles.
        if not (root / MANIFEST_NAME).exists():
            raise BundleExists(root)
        for existing in sorted(root.rglob("*"), key=lambda q: len(q.parts), reverse=True):
            if existing.is_file():
                existing.unlink()
            elif existing.is_dir():
                existing.rmdir()
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
