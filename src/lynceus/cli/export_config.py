"""lynceus-export-config — bundle config + optional state into a portable archive.

Operator-facing surface for the four "save / share / backup my config"
use cases the rest of the CLI suite did not cover:

  (1) backup before an upgrade,
  (2) machine-to-machine migration,
  (3) sharing a sanitized snapshot with the maintainer for support,
  (4) template-sharing with another operator.

Safe by default. The bare invocation produces a config-only archive with
credentials redacted (kismet_api_key, ntfy_auth_token, ntfy_topic, and
``user:pass@`` userinfo in ntfy_url) so an operator who copy-pastes the
file into a chat does not leak secrets. The two opt-outs are explicit:

  --include-secrets  do not redact (personal backup, full restore)
  --include-state    include the SQLite DB + WAL sidecars

The archive is self-describing — a ``README.txt`` and a ``manifest.json``
live alongside the bundled files so the receiver does not need access
to Lynceus documentation to understand what they got. The manifest
records the lynceus version, export timestamp, scope, the originating
exporter command, which files were included, their SHA256 hashes, and
which fields (if any) were redacted.

Read-only end to end. The CLI never mutates any source file and never
writes outside the operator-chosen ``--output`` path. No network calls.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import io
import json
import os
import sys
import tarfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

import yaml

from .. import __version__, paths
from ..allowlist import derive_ui_path
from ..config import Config
from ..redact import REDACTED_PLACEHOLDER, redact_yaml_config

# Scope choices. ``auto`` resolves via paths.resolve_existing_config(),
# matching the auto-detection lynceus-quickstart already uses. The
# explicit two-value form is kept for parity with lynceus-validate /
# lynceus-import-argus.
ScopeArg = Literal["user", "system", "auto"]
ResolvedScope = Literal["user", "system"]

# Names of the four operator-maintainable config files Lynceus knows
# about. The ``allowlist_ui.yaml`` sibling is daemon-managed but is
# bundled too so a restore reproduces the full allowlist surface
# (UI-side entries would otherwise be silently dropped).
_CONFIG_FILENAMES = (
    "lynceus.yaml",
    "rules.yaml",
    "severity_overrides.yaml",
    "allowlist.yaml",
    "allowlist_ui.yaml",
)

# State files included only with --include-state. The DB's WAL sidecars
# carry recent writes that have not yet been checkpointed back into the
# main file; excluding them on a hot copy would lose alerts that were
# committed but not yet flushed. WAL files are absent when the DB is
# closed cleanly — that's not an error.
_STATE_DB_SIBLINGS = ("-shm", "-wal")


# --- data shapes -----------------------------------------------------------


@dataclass(frozen=True)
class FileEntry:
    """One file slated for the archive. ``arcname`` is the POSIX-style
    path inside the tarball; ``source`` is the absolute path on disk."""

    arcname: str
    source: Path
    # Bytes that will actually go into the archive (post-redaction for
    # configs; raw for state). ``None`` when the file is missing or
    # unreadable — see ``error`` / ``missing``.
    payload: bytes | None
    size_bytes: int
    sha256: str
    redacted: bool
    redacted_fields: tuple[str, ...] = ()
    missing: bool = False
    error: str | None = None


@dataclass
class ExportPlan:
    """Resolved input for an export run: scope, paths, archive metadata."""

    scope: ResolvedScope
    config_files: list[FileEntry] = field(default_factory=list)
    state_files: list[FileEntry] = field(default_factory=list)
    include_state: bool = False
    include_secrets: bool = False
    inner_dir: str = ""  # archive root directory name
    timestamp_utc: str = ""  # ISO-ish, sortable: 20260517T143022Z


# --- helpers ---------------------------------------------------------------


def _utc_timestamp() -> str:
    """Sortable, unambiguous UTC stamp: ``20260517T143022Z``."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _lynceus_version() -> str:
    """Resolve the installed lynceus version, falling back to the package
    constant when the package metadata is unavailable (source checkout
    without ``pip install -e .``). Mirrors ``webui/app.py``'s pattern."""
    try:
        return importlib.metadata.version("lynceus")
    except importlib.metadata.PackageNotFoundError:
        return __version__


def _resolve_scope(scope_arg: ScopeArg) -> ResolvedScope:
    """Map ``--scope`` to a concrete ``user``/``system`` value.

    ``auto`` checks the canonical user path first, then system; on macOS
    / Windows the system probe is skipped (paths.py raises
    ``NotImplementedError`` for system scope on those platforms). If
    neither path has a config, ``auto`` defaults to ``user``.
    """
    if scope_arg in ("user", "system"):
        return scope_arg  # type: ignore[return-value]
    user_path = paths.default_config_path("user")
    if user_path.exists():
        return "user"
    try:
        system_path = paths.default_config_path("system")
    except NotImplementedError:
        return "user"
    if system_path.exists():
        return "system"
    return "user"


def _resolved_config_paths(
    scope: ResolvedScope,
) -> dict[str, Path]:
    """Compute the canonical on-disk paths for each config filename.

    When ``lynceus.yaml`` parses cleanly its ``rules_path`` /
    ``allowlist_path`` / ``severity_overrides_path`` settings are
    followed; otherwise we fall back to ``<config_dir>/<name>.yaml``.
    The ``allowlist_ui.yaml`` sibling is derived from the (resolved)
    allowlist path via ``derive_ui_path``.

    Parse failures are non-fatal here — the operator may have a broken
    config and still want a backup. The caller records the parse error
    separately when reading ``lynceus.yaml`` for the archive.
    """
    config_dir = paths.default_config_dir(scope)
    lynceus_yaml = config_dir / "lynceus.yaml"
    rules = config_dir / "rules.yaml"
    overrides = paths.default_overrides_path(scope)
    allowlist = config_dir / "allowlist.yaml"

    if lynceus_yaml.exists():
        try:
            data = yaml.safe_load(lynceus_yaml.read_text(encoding="utf-8")) or {}
            cfg = Config(**data)
            if cfg.rules_path:
                rules = Path(cfg.rules_path)
            if cfg.severity_overrides_path:
                overrides = Path(cfg.severity_overrides_path)
            if cfg.allowlist_path:
                allowlist = Path(cfg.allowlist_path)
        except Exception:
            # Malformed lynceus.yaml — fall through with canonical defaults.
            # The reader records the malformed content as raw bytes (still
            # redacted line-by-line) so the operator can see what's broken
            # in the restored copy.
            pass

    return {
        "lynceus.yaml": lynceus_yaml,
        "rules.yaml": rules,
        "severity_overrides.yaml": overrides,
        "allowlist.yaml": allowlist,
        "allowlist_ui.yaml": derive_ui_path(allowlist),
    }


def _resolved_state_paths(scope: ResolvedScope) -> list[Path]:
    """Return the SQLite DB + any present WAL sidecars.

    DB path comes from ``lynceus.yaml.db_path`` when set, else
    ``paths.default_db_path(scope)``. WAL sidecars (``-shm``, ``-wal``)
    are included only when they actually exist on disk — they're
    transient and frequently absent on a cleanly-shut-down daemon.
    """
    db_path = paths.default_db_path(scope)
    lynceus_yaml = paths.default_config_path(scope)
    if lynceus_yaml.exists():
        try:
            data = yaml.safe_load(lynceus_yaml.read_text(encoding="utf-8")) or {}
            cfg = Config(**data)
            if cfg.db_path and cfg.db_path != "lynceus.db":
                # Honor the operator-configured DB path. The "lynceus.db"
                # default is a pydantic placeholder, not a real location,
                # so we only override when the operator set something else.
                db_path = Path(cfg.db_path)
        except Exception:
            pass

    results = [db_path]
    for suffix in _STATE_DB_SIBLINGS:
        sibling = db_path.with_name(db_path.name + suffix)
        if sibling.exists():
            results.append(sibling)
    return results


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_config_entry(
    filename: str,
    source: Path,
    redact: bool,
) -> FileEntry:
    """Read a config file and produce its archive entry.

    Missing files round-trip as ``missing=True`` with no payload.
    Permission / read errors round-trip as ``error="..."``; the export
    still succeeds but with a non-zero exit code so an operator notices
    the gap rather than ships a half-bundle silently.

    Redaction applies per-file via ``redact_yaml_config``, which is a
    no-op for everything except ``lynceus.yaml``.
    """
    arcname = f"config/{filename}"
    if not source.exists():
        return FileEntry(
            arcname=arcname,
            source=source,
            payload=None,
            size_bytes=0,
            sha256="",
            redacted=False,
            missing=True,
        )
    try:
        raw_text = source.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return FileEntry(
            arcname=arcname,
            source=source,
            payload=None,
            size_bytes=0,
            sha256="",
            redacted=False,
            error=f"{type(exc).__name__}: {exc}",
        )

    if redact:
        new_text, redacted_fields = redact_yaml_config(filename, raw_text)
    else:
        new_text, redacted_fields = raw_text, []
    payload = new_text.encode("utf-8")
    return FileEntry(
        arcname=arcname,
        source=source,
        payload=payload,
        size_bytes=len(payload),
        sha256=_sha256(payload),
        # ``redacted`` is True iff this file was both eligible AND
        # actually scrubbed. A file that ran through the redactor but
        # contained no secret fields reports redacted=False so the
        # receiver can tell "considered and clean" apart from "masked".
        redacted=bool(redacted_fields),
        redacted_fields=tuple(redacted_fields),
    )


def _read_state_entry(source: Path) -> FileEntry:
    """Read a state file as raw bytes — never redact observational data."""
    arcname = f"state/{source.name}"
    if not source.exists():
        return FileEntry(
            arcname=arcname,
            source=source,
            payload=None,
            size_bytes=0,
            sha256="",
            redacted=False,
            missing=True,
        )
    try:
        payload = source.read_bytes()
    except OSError as exc:
        return FileEntry(
            arcname=arcname,
            source=source,
            payload=None,
            size_bytes=0,
            sha256="",
            redacted=False,
            error=f"{type(exc).__name__}: {exc}",
        )
    return FileEntry(
        arcname=arcname,
        source=source,
        payload=payload,
        size_bytes=len(payload),
        sha256=_sha256(payload),
        redacted=False,
    )


def _build_manifest(plan: ExportPlan, argv: list[str]) -> dict:
    """Construct the machine-readable manifest dict."""
    redacted_fields_flat: list[str] = []
    files_block: list[dict] = []
    missing_block: list[str] = []
    errored_block: list[dict] = []

    for entry in (*plan.config_files, *plan.state_files):
        if entry.missing:
            missing_block.append(entry.arcname)
            continue
        if entry.error is not None:
            errored_block.append({"path": entry.arcname, "error": entry.error})
            continue
        files_block.append(
            {
                "path": entry.arcname,
                "size_bytes": entry.size_bytes,
                "sha256": entry.sha256,
                "redacted": entry.redacted,
            }
        )
        for fld in entry.redacted_fields:
            redacted_fields_flat.append(f"{entry.arcname}:{fld}")

    return {
        "lynceus_version": _lynceus_version(),
        "export_timestamp_utc": plan.timestamp_utc,
        "scope": plan.scope,
        "exporter_command": [Path(sys.argv[0]).name, *argv],
        "include_state": plan.include_state,
        "redaction_applied": not plan.include_secrets,
        "redacted_fields": redacted_fields_flat,
        "files": files_block,
        "missing": missing_block,
        "errored": errored_block,
    }


def _build_readme(plan: ExportPlan, manifest: dict) -> str:
    """Human-readable layout + restore guide bundled inside the archive."""
    lines: list[str] = []
    lines.append("Lynceus configuration export")
    lines.append("=" * 28)
    lines.append("")
    lines.append(f"Lynceus version : {manifest['lynceus_version']}")
    lines.append(f"Exported (UTC)  : {manifest['export_timestamp_utc']}")
    lines.append(f"Scope           : {manifest['scope']}")
    lines.append(f"Includes state  : {'yes' if plan.include_state else 'no'}")
    lines.append(
        f"Redaction       : {'enabled' if not plan.include_secrets else 'DISABLED — archive contains raw secrets'}"
    )
    lines.append("")
    lines.append("Contents")
    lines.append("--------")
    lines.append("  README.txt        this file")
    lines.append("  manifest.json     machine-readable inventory + hashes")
    lines.append("  config/           operator-maintained YAML config files")
    if plan.include_state:
        lines.append("  state/            SQLite database (+ WAL sidecars when present)")
    lines.append("")
    if manifest["missing"]:
        lines.append("Missing on source host (not bundled)")
        lines.append("-" * 36)
        for path in manifest["missing"]:
            lines.append(f"  - {path}")
        lines.append("")
    if manifest["errored"]:
        lines.append("Unreadable on source host (not bundled)")
        lines.append("-" * 39)
        for row in manifest["errored"]:
            lines.append(f"  - {row['path']}: {row['error']}")
        lines.append("")
    lines.append("Restoring")
    lines.append("---------")
    lines.append(
        "  1. Copy each config/<name>.yaml to the matching path on the"
    )
    lines.append(
        "     target system. The canonical Linux locations are:"
    )
    lines.append(
        "       user scope   : ~/.config/lynceus/<name>.yaml"
    )
    lines.append(
        "       system scope : /etc/lynceus/<name>.yaml"
    )
    lines.append("     Use ``lynceus-quickstart`` or ``lynceus-validate`` to")
    lines.append("     confirm the daemon picks them up.")
    if not plan.include_secrets:
        lines.append("")
        lines.append(
            f"  2. Search bundled YAML for ``{REDACTED_PLACEHOLDER}`` and replace"
        )
        lines.append(
            "     each occurrence with the real credential before the next"
        )
        lines.append(
            "     daemon restart. Redacted fields are listed in manifest.json"
        )
        lines.append("     under ``redacted_fields``.")
    if plan.include_state:
        lines.append("")
        idx = 3 if not plan.include_secrets else 2
        lines.append(
            f"  {idx}. Copy state/lynceus.db (and the -shm / -wal sidecars when"
        )
        lines.append(
            "     present) to the canonical data dir on the target:"
        )
        lines.append(
            "       user scope   : ~/.local/share/lynceus/lynceus.db"
        )
        lines.append(
            "       system scope : /var/lib/lynceus/lynceus.db"
        )
        lines.append(
            "     Stop the daemon before overwriting an existing DB."
        )
    lines.append("")
    lines.append("Verifying integrity")
    lines.append("-------------------")
    lines.append(
        "  manifest.json lists each file's SHA256. Re-hash on restore and"
    )
    lines.append("  compare against the manifest entry to detect transport damage.")
    lines.append("")
    return "\n".join(lines) + "\n"


def _add_bytes_to_archive(
    tar: tarfile.TarFile,
    arcname: str,
    payload: bytes,
    mtime: int,
) -> None:
    """Add an in-memory blob to the open archive as a regular file."""
    info = tarfile.TarInfo(name=arcname)
    info.size = len(payload)
    info.mtime = mtime
    info.mode = 0o644
    info.type = tarfile.REGTYPE
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    tar.addfile(info, io.BytesIO(payload))


def _add_directory_to_archive(
    tar: tarfile.TarFile,
    arcname: str,
    mtime: int,
) -> None:
    """Add an explicit directory entry. Some extractors expect them."""
    info = tarfile.TarInfo(name=arcname)
    info.type = tarfile.DIRTYPE
    info.mode = 0o755
    info.mtime = mtime
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    tar.addfile(info)


def _write_archive(plan: ExportPlan, output_path: Path, manifest: dict) -> None:
    """Materialize the planned archive at ``output_path``.

    Caller has already validated that ``output_path`` is writable and
    is not an existing file (or that --force was set).
    """
    mtime = int(datetime.now(timezone.utc).timestamp())
    manifest_bytes = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
    readme_bytes = _build_readme(plan, manifest).encode("utf-8")

    with tarfile.open(output_path, "w:gz") as tar:
        _add_directory_to_archive(tar, plan.inner_dir, mtime)
        _add_bytes_to_archive(
            tar, f"{plan.inner_dir}/README.txt", readme_bytes, mtime
        )
        _add_bytes_to_archive(
            tar, f"{plan.inner_dir}/manifest.json", manifest_bytes, mtime
        )
        _add_directory_to_archive(tar, f"{plan.inner_dir}/config", mtime)
        for entry in plan.config_files:
            if entry.payload is None:
                continue
            _add_bytes_to_archive(
                tar,
                f"{plan.inner_dir}/{entry.arcname}",
                entry.payload,
                mtime,
            )
        if plan.include_state:
            _add_directory_to_archive(tar, f"{plan.inner_dir}/state", mtime)
            for entry in plan.state_files:
                if entry.payload is None:
                    continue
                _add_bytes_to_archive(
                    tar,
                    f"{plan.inner_dir}/{entry.arcname}",
                    entry.payload,
                    mtime,
                )


# --- dry-run rendering -----------------------------------------------------


def _fmt_size(n: int) -> str:
    """Human-friendly byte size — bytes / KB / MB. Two decimal places."""
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.2f} KB"
    return f"{n / (1024 * 1024):.2f} MB"


def _render_dry_run(plan: ExportPlan, output_path: Path) -> str:
    """Inventory the planned archive without producing it."""
    lines: list[str] = []
    lines.append(f"Would export to: {output_path}")
    lines.append(f"Scope: {plan.scope}")
    redacted_fields_listed = sorted(
        {f for entry in plan.config_files for f in entry.redacted_fields}
    )
    if plan.include_secrets:
        lines.append("Redaction: DISABLED (--include-secrets)")
    else:
        if redacted_fields_listed:
            lines.append(
                "Redaction: enabled (" + ", ".join(redacted_fields_listed) + ")"
            )
        else:
            lines.append("Redaction: enabled (no secret fields found in inputs)")
    lines.append("")
    lines.append("Config files:")
    total = 0
    file_count = 0
    for entry in plan.config_files:
        if entry.missing:
            lines.append(f"  {entry.source}  (missing — skipped)")
        elif entry.error is not None:
            lines.append(f"  {entry.source}  (unreadable: {entry.error})")
        else:
            lines.append(f"  {entry.source}  ({_fmt_size(entry.size_bytes)})")
            total += entry.size_bytes
            file_count += 1
    lines.append("")
    if plan.include_state:
        lines.append("State files:")
        for entry in plan.state_files:
            if entry.missing:
                lines.append(f"  {entry.source}  (missing — skipped)")
            elif entry.error is not None:
                lines.append(f"  {entry.source}  (unreadable: {entry.error})")
            else:
                lines.append(f"  {entry.source}  ({_fmt_size(entry.size_bytes)})")
                total += entry.size_bytes
                file_count += 1
    else:
        lines.append("State files: not included (use --include-state)")
    lines.append("")
    lines.append(f"Total: {file_count} files, ~{_fmt_size(total)}")
    return "\n".join(lines) + "\n"


# --- output path validation ------------------------------------------------


def _validate_output_path(
    output: Path, force: bool
) -> tuple[bool, str]:
    """Return ``(ok, error_message)`` for the proposed --output path."""
    if output.is_dir():
        return False, (
            f"--output {output} is a directory; pass a file path "
            "(e.g. {output}/lynceus-export.tar.gz)"
        )
    parent = output.parent if str(output.parent) else Path(".")
    # Path("foo.tar.gz").parent is Path(".") which always exists.
    if not parent.exists():
        return False, (
            f"--output parent directory does not exist: {parent}"
        )
    if not os.access(parent, os.W_OK):
        return False, (
            f"--output parent directory is not writable: {parent}"
        )
    if output.exists() and not force:
        return False, (
            f"refusing to overwrite existing file {output} — pass --force "
            "to clobber, or choose a different --output path"
        )
    return True, ""


# --- argument parser -------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lynceus-export-config",
        description=(
            "Bundle Lynceus config (and optionally state) into a portable "
            "tar.gz archive. Safe by default: credentials are redacted "
            "unless --include-secrets is passed; the SQLite database is "
            "omitted unless --include-state is passed. The archive carries "
            "a README.txt and a manifest.json describing its contents."
        ),
    )
    p.add_argument(
        "--output",
        type=Path,
        default=None,
        help=(
            "output archive path (default: "
            "./lynceus-export-<scope>-<UTC-timestamp>.tar.gz in CWD)"
        ),
    )
    p.add_argument(
        "--scope",
        choices=("user", "system", "auto"),
        default="auto",
        help=(
            "which scope's config / state paths to read (default: "
            "%(default)s — picks the scope whose lynceus.yaml exists, "
            "falling back to user)"
        ),
    )
    p.add_argument(
        "--include-state",
        action="store_true",
        help=(
            "include the SQLite database and any WAL sidecars under "
            "state/ in the archive (off by default — DB can be large and "
            "carries observed MAC addresses)"
        ),
    )
    p.add_argument(
        "--include-secrets",
        action="store_true",
        help=(
            "do NOT redact secrets (kismet_api_key, ntfy_auth_token, "
            "ntfy_topic, ntfy_url userinfo). Use for personal backups "
            "where you intend a full restore; never use for an archive "
            "you'll share."
        ),
    )
    p.add_argument(
        "--force",
        action="store_true",
        help="overwrite --output if it already exists",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="list what would be exported; do not write an archive",
    )
    p.add_argument(
        "--no-color",
        action="store_true",
        help="no-op in v1 (output is always plain text); reserved for future",
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"lynceus-export-config {__version__}",
    )
    return p


def _plan_export(
    scope: ResolvedScope,
    include_state: bool,
    include_secrets: bool,
    timestamp_utc: str,
) -> ExportPlan:
    """Build the ExportPlan: resolve paths, read inputs, hash for manifest."""
    plan = ExportPlan(
        scope=scope,
        include_state=include_state,
        include_secrets=include_secrets,
        inner_dir=f"lynceus-export-{scope}-{timestamp_utc}",
        timestamp_utc=_iso_timestamp(timestamp_utc),
    )
    resolved = _resolved_config_paths(scope)
    for filename in _CONFIG_FILENAMES:
        plan.config_files.append(
            _read_config_entry(
                filename,
                resolved[filename],
                redact=not include_secrets,
            )
        )
    if include_state:
        for source in _resolved_state_paths(scope):
            plan.state_files.append(_read_state_entry(source))
    return plan


def _iso_timestamp(compact: str) -> str:
    """Expand the compact ``20260517T143022Z`` stamp into an ISO-8601 form
    for the manifest's ``export_timestamp_utc`` field. Two formats serve
    different consumers: the compact form sorts cleanly as a filename
    component; the expanded form is what JSON tooling expects to parse."""
    # compact is fixed-width: YYYYMMDDTHHMMSSZ
    dt = datetime.strptime(compact, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# --- main ------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    raw_argv = list(argv) if argv is not None else sys.argv[1:]

    try:
        scope = _resolve_scope(args.scope)
    except NotImplementedError as exc:
        # --scope system on macOS / Windows.
        print(f"lynceus-export-config: {exc}", file=sys.stderr)
        return 1

    timestamp = _utc_timestamp()
    plan = _plan_export(
        scope=scope,
        include_state=args.include_state,
        include_secrets=args.include_secrets,
        timestamp_utc=timestamp,
    )

    if args.output is None:
        output_path = Path.cwd() / f"lynceus-export-{scope}-{timestamp}.tar.gz"
    else:
        output_path = args.output.expanduser()

    if args.dry_run:
        # Resolve to absolute so the operator sees the same path the
        # real run would create. Skip the existence check — the point
        # of dry-run is to preview before any filesystem effect.
        try:
            shown_path = output_path.resolve()
        except OSError:
            shown_path = output_path
        sys.stdout.write(_render_dry_run(plan, shown_path))
        # Dry-run exit code follows the same rule as the real run: 2 if
        # any input was unreadable (operator should fix permissions
        # before exporting for real), 0 otherwise.
        return _exit_code_for_errors(plan)

    ok, err = _validate_output_path(output_path, args.force)
    if not ok:
        print(f"lynceus-export-config: {err}", file=sys.stderr)
        return 1

    manifest = _build_manifest(plan, raw_argv)
    try:
        _write_archive(plan, output_path, manifest)
    except OSError as exc:
        print(
            f"lynceus-export-config: failed to write archive {output_path}: {exc}",
            file=sys.stderr,
        )
        return 1

    print(f"Wrote {output_path}")
    if manifest["redacted_fields"]:
        print(
            f"Redacted {len(manifest['redacted_fields'])} field(s); "
            "see manifest.json for the list."
        )
    if manifest["missing"]:
        print(
            f"{len(manifest['missing'])} expected file(s) absent on source: "
            + ", ".join(manifest["missing"])
        )
    if manifest["errored"]:
        for row in manifest["errored"]:
            print(
                f"WARNING: could not read {row['path']}: {row['error']}",
                file=sys.stderr,
            )
    return _exit_code_for_errors(plan)


def _exit_code_for_errors(plan: ExportPlan) -> int:
    """Non-zero if any input was unreadable. Missing inputs are not
    errors — they're an expected state on partially-configured hosts."""
    for entry in (*plan.config_files, *plan.state_files):
        if entry.error is not None:
            return 2
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
