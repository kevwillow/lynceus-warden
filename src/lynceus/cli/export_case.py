"""lynceus-export-case: the recorded history of one device, as a bundle.

The record Lynceus keeps is only an advantage over a keychain detector
if it can be handed to somebody. This is the command that produces the
thing you hand over: an HTML document, the underlying rows as CSV, the
captured evidence, and a hash manifest, in one directory.

⛔ This command makes no disclosure decision of its own. It parses
arguments, calls ``casefile.query.build_case_file`` and writes what comes
back. The web UI route does the same. That is deliberate: if either
entry point decided anything, the two would drift and one of them would
start disclosing something the other withholds.

Runs as the operator, reads the database and writes only under the
directory the operator named. No network of any kind.
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from .. import paths
from ..casefile.bundle import BundleExists, build_artifacts, write_directory
from ..casefile.manifest import build_manifest
from ..casefile.query import MAX_SIGHTINGS, build_case_file
from ..config import load_config
from ..db import Database

PROG = "lynceus-export-case"


def _parse_date(value: str, *, end_of_day: bool = False) -> int:
    """A YYYY-MM-DD boundary, read as UTC.

    Dates rather than timestamps because the operator is thinking in
    days, and UTC rather than local time because the document records UTC
    and a window meaning something other than the rows it selects would
    be a quiet lie.

    ⛔ ``--until`` resolves to the END of the named day. Midnight at the
    START of it would exclude almost the whole day the operator asked
    for, and they would have no way to tell from the output: the document
    would print their date and then show none of it.
    """
    try:
        moment = datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=UTC)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"expected YYYY-MM-DD, got {value!r}") from exc
    return int(moment.timestamp()) + (86399 if end_of_day else 0)


def _parse_until(value: str) -> int:
    return _parse_date(value, end_of_day=True)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=PROG,
        description=(
            "Export the recorded history of one device as a case file bundle: "
            "an HTML document, the underlying rows as CSV, the captured "
            "evidence, and a SHA-256 manifest."
        ),
        epilog=(
            "The bundle records where this installation has been and what was "
            "near it. Read the limits section in the document before relying "
            "on any of it."
        ),
    )
    p.add_argument("mac", help="the device to export, for example aa:bb:cc:dd:ee:01")
    p.add_argument(
        "--out",
        type=Path,
        default=None,
        help="directory to write the bundle into (default: the current directory)",
    )
    p.add_argument(
        "--db",
        default=None,
        help="path to the lynceus database (default: resolved from --scope)",
    )
    p.add_argument(
        "--scope",
        choices=("user", "system"),
        default="user",
        help="which installation's default database path to use (default: user)",
    )
    p.add_argument(
        "--config",
        default=None,
        help=(
            "path to lynceus.yaml. Read only for the retention settings, which "
            "the document needs in order to say whether earlier sightings may "
            "have been deleted. Without it the document says the setting was "
            "not available rather than implying retention was off."
        ),
    )
    p.add_argument("--since", type=_parse_date, default=None, metavar="YYYY-MM-DD")
    p.add_argument(
        "--until",
        type=_parse_until,
        default=None,
        metavar="YYYY-MM-DD",
        help="inclusive: the whole of the named day, UTC",
    )
    p.add_argument(
        "--force",
        action="store_true",
        help=(
            "replace an existing bundle for this device and date. Without it "
            "an existing directory is refused rather than merged into, "
            "because leftover files from the earlier export would still be "
            "handed over while the new manifest disclaims them."
        ),
    )
    p.add_argument(
        "--sighting-limit",
        type=int,
        default=MAX_SIGHTINGS,
        help=f"maximum sightings to list, 1 to {MAX_SIGHTINGS} (default: {MAX_SIGHTINGS})",
    )
    return p


def _fail(message: str) -> int:
    print(f"{PROG}: {message}", file=sys.stderr)
    return 1


def _resolve_db_path(args) -> tuple[str | None, int | None]:
    if args.db is not None:
        return args.db, None
    try:
        return str(paths.default_db_path(args.scope)), None
    except (NotImplementedError, ValueError) as exc:
        return None, _fail(f"cannot resolve the default database path: {exc}")


def _load_retention_config(config_arg):
    """Best effort, and silent about it on purpose.

    A missing or unreadable config is not a reason to refuse an export.
    The document already distinguishes "retention is off" from "the
    setting was not available", so returning None here produces an
    honest document rather than a wrong one.
    """
    path = config_arg
    if path is None:
        resolved = paths.resolve_existing_config()
        if resolved is None:
            return None
        path = str(resolved)
    try:
        return load_config(str(path))
    except Exception:
        return None


def _summarise(case, root: Path, digest: str) -> None:
    device = case.device
    vendor = device.get("oui_vendor") or "unknown vendor"
    print()
    print(f"  device   {device.get('mac')}  ({vendor})")

    until = case.window.get("until_ts")
    since = case.window.get("since_ts")
    if since:
        span_days = max(0, (int(until) - int(since)) // 86400)
        print(
            f"  window   {_day(since)} .. {_day(until)}  ({span_days} days, "
            f"{case.window.get('reason')})"
        )
    else:
        print(f"  window   all retained history, up to {_day(until)}")

    print(
        f"  {len(case.locations)} locations, {len(case.sightings)} sightings, "
        f"{len(case.alerts)} alerts, {len(case.evidence)} evidence snapshots"
    )
    print(
        f"  {len(case.co_observers_named)} watchlisted co-observers named, "
        f"{case.co_observers_aggregate} aggregated"
    )

    withheld = case.excluded_counts.get("do_not_publish", 0)
    if withheld:
        print(f"  {withheld} evidence row(s) excluded (do_not_publish)")
    over_cap = case.excluded_counts.get("sightings_over_cap", 0)
    if over_cap:
        cap = case.parameters["sighting_limit"]
        print(f"  {over_cap} sighting(s) not listed (export capped at {cap})")
    for key, label in (
        ("alerts_over_cap", "alert(s) not listed (export capped)"),
        ("co_observers_over_cap", "co-observed device(s) not analysed (scan capped)"),
        ("evidence_fields_withheld", "evidence field(s) withheld (not about this device)"),
        ("unapproved_addresses_redacted", "address(es) redacted from free text"),
    ):
        n = case.excluded_counts.get(key, 0)
        if n:
            print(f"  {n} {label}")
    print()
    print(f"  wrote {root}/")
    print(f"  manifest sha256:{digest}")
    print()


def _day(ts) -> str:
    if not ts:
        return "unknown"
    return datetime.fromtimestamp(int(ts), tz=UTC).strftime("%Y-%m-%d")


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    db_path, err = _resolve_db_path(args)
    if err is not None:
        return err

    # ⛔ Checked before opening. sqlite3 CREATES a database for a path
    # that does not exist, so a typo would otherwise produce an empty
    # database, an empty case file and an exit code of zero: the exact
    # shape of failure this product keeps finding and refusing.
    if not Path(db_path).exists():
        return _fail(f"database not found: {db_path}")

    if args.sighting_limit < 1 or args.sighting_limit > MAX_SIGHTINGS:
        return _fail(f"--sighting-limit must be between 1 and {MAX_SIGHTINGS}")
    if args.since is not None and args.until is not None and args.since > args.until:
        return _fail("--since is after --until")

    out_dir = (args.out or Path.cwd()).expanduser()
    config = _load_retention_config(args.config)

    db = Database(db_path)
    try:
        try:
            case = build_case_file(
                db,
                args.mac,
                now_ts=int(time.time()),
                since_ts=args.since,
                until_ts=args.until,
                sighting_limit=args.sighting_limit,
                config=config,
            )
        except ValueError as exc:
            # normalize_mac refused it. Nothing has been written.
            return _fail(f"{exc}")
        except LookupError:
            return _fail(
                f"no device in this database for {args.mac}. "
                "Nothing was written: an empty case file would read as "
                "'it was not there', which this record cannot support."
            )

        try:
            root = write_directory(case, out_dir, overwrite=args.force)
        except BundleExists as exc:
            return _fail(
                f"{exc.root} already exists. Nothing was written. Merging into it "
                "would leave files from the earlier export in a bundle whose "
                "manifest no longer covers them, including evidence that has "
                "since been marked do_not_publish. Use --force to replace it, "
                "or --out to write somewhere else."
            )
        except OSError as exc:
            return _fail(f"could not write the bundle under {out_dir}: {exc}")

        payload = {k: v for k, v in build_artifacts(case).items() if k != "manifest.json"}
        digest = build_manifest(payload)["manifest_sha256"]
    finally:
        db.close()

    _summarise(case, root, digest)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
