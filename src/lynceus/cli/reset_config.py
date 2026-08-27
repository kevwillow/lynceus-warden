"""lynceus-reset-config — recover from a broken config an operator can't read.

The backstop for a hand-edited ``lynceus.yaml`` or ``severity_overrides.yaml``
that the daemon now refuses to load. The recovery path this exists for:

  1. An operator broke ``lynceus.yaml`` and ``lynceus`` will not start.
  2. The daemon's own CLI cannot help, because the daemon is the thing that
     imports the config. So THIS CLI deliberately does NOT import the daemon,
     the rules engine, the database, or the web UI. It only imports
     ``lynceus.paths`` (for canonical path resolution) and the stdlib.
  3. By default it PREVIEWS — names each file it would move, with size, so
     the operator can see what they're losing before they lose it.
  4. With ``--yes`` it moves each target aside to ``<name>.bak-<UTC>`` rather
     than deleting it. A reset is recoverable.
  5. A non-interactive shell without ``--yes`` is refused outright — better
     than printing a prompt into the void.

The contract is intentionally narrow:

    lynceus-reset-config [--scope user|system] [--what tuning|all]
                         [--config PATH] [--yes] [--dry-run]

Exit codes (also: §3 of ``docs/UI_CONFIGURATION_DESIGN.md``):
    0  preview or successful reset
    1  refused: missing ``--yes`` on a non-tty, or nothing to reset
    2  real error: unwritable directory, etc.

This file does not import ``lynceus.config`` either — the whole point is to
work when that module would crash on the operator's broken config. Path
resolution goes through ``lynceus.paths``, which only inspects locations and
never parses files.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path

from .. import paths as lynceus_paths


# Distinct from the export-config timestamp only by intent: same format so an
# operator who knows one reads the other without thinking. ``Z`` suffix is
# UTC and is the unambiguous thing to grep for when sorting backups.
def _utc_timestamp() -> str:
    """Sortable UTC stamp: ``20260517T143022Z``."""
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _fmt_size(n: int) -> str:
    """Human-friendly byte size — bytes / KB / MB. Two decimal places."""
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.2f} KB"
    return f"{n / (1024 * 1024):.2f} MB"


def _resolve_targets(
    scope: str,
    what: str,
    config_override: Path | None,
) -> list[Path]:
    """Map the (scope, what, override) triple to the list of files to act on.

    ``--config PATH`` makes the target list exactly that one path. Without
    ``--config``, ``--what tuning`` targets the severity-overrides file and
    ``--what all`` also includes the main config.
    """
    if config_override is not None:
        return [config_override.expanduser()]
    targets: list[Path] = [lynceus_paths.default_overrides_path(scope)]
    if what == "all":
        targets.append(lynceus_paths.default_config_path(scope))
        # ⛔ Also target the config actually IN EFFECT, which is not always the
        # default path for the scope. A recovery command that resets a file
        # nobody loads, and leaves the broken one the daemon actually reads,
        # has done nothing while reporting success. Deduped and order-stable so
        # the preview reads the same way twice.
        try:
            live = lynceus_paths.resolve_existing_config()
        except OSError:
            live = None
        if live is not None and live not in targets:
            targets.append(live)
    return targets


def _describe_targets(targets: list[Path]) -> list[str]:
    """For each target, report whether it exists and how big it is."""
    lines: list[str] = []
    for path in targets:
        try:
            present = path.exists()
        except OSError as exc:
            lines.append(f"  {path}  (unreadable: {type(exc).__name__}: {exc})")
            continue
        if not present:
            lines.append(f"  {path}  (missing, nothing to reset)")
            continue
        try:
            size = path.stat().st_size
        except OSError as exc:
            lines.append(f"  {path}  (stat failed: {type(exc).__name__}: {exc})")
            continue
        lines.append(f"  {path}  ({_fmt_size(size)})")
    return lines


def _backup_path(target: Path, timestamp: str) -> Path:
    """Sibling backup filename: ``<name>.bak-<UTC>``."""
    return target.with_name(f"{target.name}.bak-{timestamp}")


def _do_reset(targets: list[Path]) -> list[Path]:
    """Move each present target aside to ``<name>.bak-<timestamp>``.

    Returns the list of backups actually created (one entry per moved file).
    A target that doesn't exist is skipped — "nothing to do" is not an error.

    An existing backup is never overwritten: a same-second collision gets a
    numeric suffix instead, so running this twice cannot destroy the first
    backup.
    """
    timestamp = _utc_timestamp()
    backups: list[Path] = []
    for target in targets:
        if not target.exists():
            continue
        backup = _backup_path(target, timestamp)
        # ⛔ shutil.move REPLACES an existing destination file on POSIX, so a
        # second reset inside the same UTC second would silently destroy the
        # first backup -- the one thing this command exists to preserve. Walk
        # to a free name instead. (An earlier docstring here claimed the
        # existing backup was left alone. It was not; it was overwritten.)
        if backup.exists():
            for n in range(2, 1000):
                candidate = backup.with_name(f"{backup.name}.{n}")
                if not candidate.exists():
                    backup = candidate
                    break
            else:
                raise OSError(f"could not find a free backup name beside {target}")
        # shutil.move handles cross-device moves (it falls back to copy+unlink
        # across filesystems) but in practice config files always live on the
        # same fs as their backups. Move is atomic on the same filesystem.
        shutil.move(str(target), str(backup))
        backups.append(backup)
    return backups


# --- argument parser -------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lynceus-reset-config",
        description=(
            "Reset Lynceus config files by moving them aside to timestamped "
            "backups. The recovery path for a hand-edited lynceus.yaml or "
            "severity_overrides.yaml the daemon will no longer load. By "
            "default, prints what would happen and changes nothing. Pass "
            "--yes to actually perform the reset."
        ),
    )
    p.add_argument(
        "--scope",
        choices=("user", "system"),
        default="user",
        help=(
            "which scope's config to target when --config is not set "
            "(default: %(default)s)"
        ),
    )
    p.add_argument(
        "--what",
        choices=("tuning", "all"),
        default="tuning",
        help=(
            "what to reset: 'tuning' resets only severity_overrides.yaml "
            "(default); 'all' also resets the main lynceus.yaml. Ignored "
            "when --config is set."
        ),
    )
    p.add_argument(
        "--config",
        type=Path,
        default=None,
        help=(
            "reset this specific file instead of the canonical paths "
            "resolved from --scope/--what"
        ),
    )
    p.add_argument(
        "--yes",
        action="store_true",
        help="perform the reset (default: preview only)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="alias for the default preview behaviour; never writes",
    )
    return p


# --- main ------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    # Refuse to prompt into the void. The contract is: with no TTY and no
    # --yes, this CLI is read-only. The alternative — an interactive
    # confirmation — is exactly the shape that fails when an operator SSH'd
    # in with a here-doc, because getpass on a non-tty just returns empty
    # and the reset would silently happen.
    if not args.yes and not args.dry_run and not sys.stdin.isatty():
        print(
            "lynceus-reset-config: stdin is not a terminal, refusing to "
            "prompt. Pass --yes to confirm the reset, or --dry-run to "
            "preview without changing anything.",
            file=sys.stderr,
        )
        return 1

    try:
        targets = _resolve_targets(args.scope, args.what, args.config)
    except NotImplementedError as exc:
        # --scope system on macOS / Windows.
        print(f"lynceus-reset-config: {exc}", file=sys.stderr)
        return 2

    if args.dry_run or not args.yes:
        # Preview. Always list the targets so the operator can see what would
        # be moved. Even when --yes is set we still print the inventory above
        # the action, so the operator has one more look at what they're losing.
        print("Reset preview (no changes made):")
        print(f"Scope: {args.scope}")
        if args.config is not None:
            print(f"Target: {args.config}")
        else:
            print(f"Targets ({args.what}):")
        for line in _describe_targets(targets):
            print(line)
        if any(_probe(p) == "unreadable" for p in targets):
            print(
                "One or more targets could not be accessed (see above). "
                "This is not the same as having nothing to reset.",
                file=sys.stderr,
            )
            return 2
        if not any(_path_exists(p) for p in targets):
            print("Nothing to reset.")
            return 1
        if not args.yes:
            print("Pass --yes to perform the reset.")
        return 0

    # --yes path. Inventory first (one more look), then move.
    unreadable = [p for p in targets if _probe(p) == "unreadable"]
    if unreadable:
        # ⛔ NOT "nothing to reset". A target we cannot even stat is a real
        # error (exit 2); reporting it as an empty inventory tells the operator
        # their config is already clean when it may be the broken file itself.
        for path in unreadable:
            print(
                f"lynceus-reset-config: cannot access {path}; refusing to "
                f"report the reset as complete.",
                file=sys.stderr,
            )
        return 2
    present_targets = [p for p in targets if _path_exists(p)]
    if not present_targets:
        print("lynceus-reset-config: nothing to reset.", file=sys.stderr)
        for line in _describe_targets(targets):
            print(line)
        return 1

    print("Resetting:")
    for line in _describe_targets(present_targets):
        print(line)

    try:
        backups = _do_reset(present_targets)
    except OSError as exc:
        print(
            f"lynceus-reset-config: failed to move files: "
            f"{type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 2

    for backup in backups:
        print(f"Moved to {backup}")
    if backups:
        print(
            "Restart lynceus (and lynceus-ui) so they pick up the cleared "
            "config."
        )
    return 0


def _probe(p: Path) -> str:
    """Three-state probe: ``present``, ``absent`` or ``unreadable``.

    ⛔ The two-state version could not tell "the file is not there" from "I was
    not allowed to look", and the caller reported both as nothing to reset.
    """
    try:
        return "present" if p.exists() else "absent"
    except OSError:
        return "unreadable"


def _path_exists(p: Path) -> bool:
    """Exists probe that swallows OSError — an unreadable directory must not
    crash a recovery command. Matches the contract in lynceus.paths: this
    CLI never propagates a PermissionError from a probe."""
    try:
        return p.exists()
    except OSError:
        return False


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
