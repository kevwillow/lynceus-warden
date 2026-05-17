"""lynceus-validate — read-only configuration validator.

Reads (but never modifies) the four lynceus YAML files an operator may
maintain — ``lynceus.yaml``, ``rules.yaml``, ``severity_overrides.yaml``,
and ``allowlist.yaml`` (plus its daemon-managed ``allowlist_ui.yaml``
sibling) — and reports schema errors, unknown keys, malformed values,
and missing referenced paths. Wraps the existing loaders rather than
re-implementing them so the diagnoses match what the daemon would hit
at startup.

Exit codes are stable for CI / pre-commit hook use:
- 0: no errors (warnings may exist)
- 1: errors found
- 2: tool-level failure (config dir unreachable, etc.)

Output is plain ASCII, no ANSI color, no emoji — parseable for grep /
awk by operators in scripts. Where the daemon is lenient at runtime
(``severity_overrides.yaml``: malformed -> WARNING + pass-through;
``allowlist.yaml``: malformed primary -> ERROR + empty), the validator
is louder so the typo surfaces at edit time instead of as a confused
silence at the next restart.
"""

from __future__ import annotations

import argparse
import logging
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import ValidationError

from .. import __version__, paths
from ..allowlist import Allowlist, derive_ui_path, load_allowlist
from ..cli.import_argus import DEFAULT_CATEGORY_SEVERITIES
from ..config import Config, load_config
from ..rules import (
    RuntimeSeverityOverride,
    load_ruleset,
    load_runtime_severity_overrides,
)

# Known top-level keys in severity_overrides.yaml. Includes BOTH the
# import-time set (vendor_overrides, geographic_filter,
# confidence_downgrade_threshold) and the runtime set
# (device_category_severity, suppress_categories, suppress_vendors,
# pattern_overrides) — the file is consumed by two layers and the
# operator may legitimately maintain either subset.
SEVERITY_OVERRIDES_KNOWN_KEYS: tuple[str, ...] = (
    "vendor_overrides",
    "device_category_severity",
    "geographic_filter",
    "confidence_downgrade_threshold",
    "suppress_categories",
    "suppress_vendors",
    "pattern_overrides",
)

VALID_SEVERITIES: tuple[str, ...] = ("low", "med", "high")


Severity = Literal["error", "warning"]


@dataclass(frozen=True)
class Issue:
    """One validator finding. ``file`` is None for cross-file issues."""

    severity: Severity
    message: str
    file: Path | None = None
    line: int | None = None
    hint: str | None = None


@dataclass(frozen=True)
class FileReport:
    """Aggregated validator output for a single config file."""

    file: Path
    exists: bool
    valid: bool
    summary: str
    issues: tuple[Issue, ...] = field(default_factory=tuple)


# --- helpers ----------------------------------------------------------------


def _levenshtein(a: str, b: str) -> int:
    """Plain Levenshtein edit distance. Small inputs only — known-key set."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(
                min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + (0 if ca == cb else 1))
            )
        prev = curr
    return prev[-1]


def _closest(value: str, candidates: tuple[str, ...], *, max_distance: int = 3) -> str | None:
    """Closest candidate within ``max_distance`` edits, or None."""
    if not candidates:
        return None
    best = min(candidates, key=lambda c: _levenshtein(value, c))
    return best if _levenshtein(value, best) <= max_distance else None


def _format_iso_utc(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_line_map(path: Path) -> dict[tuple[Any, ...], int]:
    """Map YAML key-paths to 1-indexed line numbers.

    Used to attach line annotations to value-level diagnostics
    (e.g. ``device_category_severity['unknown'] = 'medium'``). Best-
    effort: if the file does not parse, returns an empty map and the
    caller falls back to file-level messages.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            node = yaml.compose(fh)
    except (OSError, yaml.YAMLError):
        return {}
    out: dict[tuple[Any, ...], int] = {}

    def visit(n: Any, prefix: tuple[Any, ...]) -> None:
        if n is None:
            return
        if isinstance(n, yaml.MappingNode):
            for key_node, val_node in n.value:
                key = getattr(key_node, "value", None)
                full = prefix + (key,)
                out[full] = key_node.start_mark.line + 1
                visit(val_node, full)
        elif isinstance(n, yaml.SequenceNode):
            for i, item in enumerate(n.value):
                full = prefix + (i,)
                out[full] = item.start_mark.line + 1
                visit(item, full)

    visit(node, ())
    return out


def _yaml_parse_error_line(exc: yaml.YAMLError) -> int | None:
    """Best-effort line number for a YAMLError. ``problem_mark`` is 0-indexed."""
    mark = getattr(exc, "problem_mark", None)
    if mark is None:
        return None
    return mark.line + 1


def _try_load_yaml(path: Path) -> tuple[Any, Issue | None]:
    """Open and ``yaml.safe_load`` ``path``. Returns ``(data, error_issue)``.

    On parse error, returns ``(None, Issue)`` with a line number when
    the parser exposed one. On OSError, returns ``(None, Issue)`` with
    no line. On success returns ``(data, None)`` where ``data`` is the
    parsed YAML (possibly ``None`` for an empty file).
    """
    try:
        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        line = _yaml_parse_error_line(exc)
        return None, Issue(
            severity="error",
            message=f"YAML parse error: {exc}",
            file=path,
            line=line,
        )
    except OSError as exc:
        return None, Issue(
            severity="error",
            message=f"could not read file: {exc}",
            file=path,
        )
    return data, None


# --- per-file validators ----------------------------------------------------


def validate_lynceus_yaml(path: Path) -> tuple[FileReport, Config | None]:
    """Validate ``lynceus.yaml`` and return the loaded ``Config`` on success.

    The ``Config`` return is used by the orchestrator to derive the
    paths of the other config files. On any error the second tuple
    element is ``None`` and downstream validators are skipped.
    """
    issues: list[Issue] = []
    if not path.exists():
        issues.append(
            Issue(
                severity="error",
                message="config file not found",
                file=path,
                hint=(
                    "Run lynceus-setup to scaffold one, or pass --scope "
                    "to point at a different location."
                ),
            )
        )
        return FileReport(
            file=path,
            exists=False,
            valid=False,
            summary="missing",
            issues=tuple(issues),
        ), None

    parsed, parse_issue = _try_load_yaml(path)
    if parse_issue is not None:
        issues.append(parse_issue)
        return FileReport(
            file=path,
            exists=True,
            valid=False,
            summary="unparseable",
            issues=tuple(issues),
        ), None

    try:
        cfg = load_config(str(path))
    except ValidationError as exc:
        for err in exc.errors():
            loc = ".".join(str(part) for part in err.get("loc", ()))
            msg = err.get("msg", "validation error")
            issues.append(
                Issue(
                    severity="error",
                    message=(f"{loc}: {msg}" if loc else msg),
                    file=path,
                )
            )
    except FileNotFoundError:
        # Race between exists() check and load. Treat as missing.
        issues.append(
            Issue(severity="error", message="config file disappeared mid-validation", file=path)
        )
        return FileReport(
            file=path,
            exists=False,
            valid=False,
            summary="missing",
            issues=tuple(issues),
        ), None
    except yaml.YAMLError as exc:
        # Belt-and-suspenders: _try_load_yaml above should have caught it.
        issues.append(
            Issue(
                severity="error",
                message=f"YAML parse error: {exc}",
                file=path,
                line=_yaml_parse_error_line(exc),
            )
        )
        return FileReport(
            file=path,
            exists=True,
            valid=False,
            summary="unparseable",
            issues=tuple(issues),
        ), None
    else:
        for field_name, label in (
            ("rules_path", "rules_path"),
            ("severity_overrides_path", "severity_overrides_path"),
            ("allowlist_path", "allowlist_path"),
        ):
            ref = getattr(cfg, field_name, None)
            if ref:
                ref_path = Path(ref)
                if not ref_path.exists():
                    issues.append(
                        Issue(
                            severity="error",
                            message=(
                                f"{label} references missing file: {ref_path}"
                            ),
                            file=path,
                        )
                    )
        valid = not any(i.severity == "error" for i in issues)
        if valid:
            summary = "schema valid; all referenced paths exist"
        else:
            summary = "validation failed"
        return FileReport(
            file=path,
            exists=True,
            valid=valid,
            summary=summary,
            issues=tuple(issues),
        ), (cfg if valid else None)

    return FileReport(
        file=path,
        exists=True,
        valid=False,
        summary="validation failed",
        issues=tuple(issues),
    ), None


def validate_rules_yaml(path: Path) -> FileReport:
    issues: list[Issue] = []
    if not path.exists():
        issues.append(
            Issue(severity="error", message="rules file not found", file=path)
        )
        return FileReport(
            file=path, exists=False, valid=False, summary="missing", issues=tuple(issues)
        )

    _, parse_issue = _try_load_yaml(path)
    if parse_issue is not None:
        issues.append(parse_issue)
        return FileReport(
            file=path, exists=True, valid=False, summary="unparseable", issues=tuple(issues)
        )

    try:
        ruleset = load_ruleset(str(path))
    except ValidationError as exc:
        for err in exc.errors():
            loc = ".".join(str(part) for part in err.get("loc", ()))
            msg = err.get("msg", "validation error")
            issues.append(
                Issue(
                    severity="error",
                    message=(f"{loc}: {msg}" if loc else msg),
                    file=path,
                )
            )
        return FileReport(
            file=path,
            exists=True,
            valid=False,
            summary="validation failed",
            issues=tuple(issues),
        )
    except FileNotFoundError:
        issues.append(
            Issue(severity="error", message="rules file disappeared mid-validation", file=path)
        )
        return FileReport(
            file=path, exists=False, valid=False, summary="missing", issues=tuple(issues)
        )
    except yaml.YAMLError as exc:
        issues.append(
            Issue(
                severity="error",
                message=f"YAML parse error: {exc}",
                file=path,
                line=_yaml_parse_error_line(exc),
            )
        )
        return FileReport(
            file=path, exists=True, valid=False, summary="unparseable", issues=tuple(issues)
        )

    rule_count = len(ruleset.rules)
    if rule_count == 0:
        issues.append(
            Issue(
                severity="warning",
                message=(
                    "rules file loaded but contains no rules; "
                    "no alerts will fire from rules.yaml"
                ),
                file=path,
                hint="Add at least one rule entry, or unset rules_path in lynceus.yaml.",
            )
        )
    summary = f"{rule_count} rule(s) valid"
    return FileReport(
        file=path, exists=True, valid=True, summary=summary, issues=tuple(issues)
    )


def validate_severity_overrides_yaml(path: Path) -> FileReport:
    """Validate ``severity_overrides.yaml``.

    The runtime loader is lenient by design — malformed values surface
    as WARNINGs in the daemon log and the override is silently dropped.
    At edit time the operator wants to know, so the validator promotes
    drop-able malformed values to ERRORs and adds edit-time-only
    checks: unknown top-level keys (with Levenshtein hint), unknown
    Argus device categories, ``pattern_overrides`` keys that do not
    match the 16-hex ``argus_record_id`` shape.
    """
    issues: list[Issue] = []
    if not path.exists():
        return FileReport(
            file=path,
            exists=False,
            valid=True,
            summary="not present (runtime overrides disabled)",
            issues=tuple(issues),
        )

    parsed, parse_issue = _try_load_yaml(path)
    if parse_issue is not None:
        issues.append(parse_issue)
        return FileReport(
            file=path, exists=True, valid=False, summary="unparseable", issues=tuple(issues)
        )

    if parsed is None:
        return FileReport(
            file=path,
            exists=True,
            valid=True,
            summary="empty (no overrides active)",
            issues=tuple(issues),
        )

    if not isinstance(parsed, dict):
        issues.append(
            Issue(
                severity="error",
                message=(
                    f"top-level must be a YAML mapping, got {type(parsed).__name__}"
                ),
                file=path,
            )
        )
        return FileReport(
            file=path, exists=True, valid=False, summary="malformed", issues=tuple(issues)
        )

    line_map = _build_line_map(path)

    # Top-level unknown keys -> WARNING with closest-match hint.
    for key in parsed.keys():
        if not isinstance(key, str):
            issues.append(
                Issue(
                    severity="error",
                    message=f"top-level key must be a string, got {key!r}",
                    file=path,
                    line=line_map.get((key,)),
                )
            )
            continue
        if key not in SEVERITY_OVERRIDES_KNOWN_KEYS:
            closest = _closest(key, SEVERITY_OVERRIDES_KNOWN_KEYS)
            hint = f"did you mean '{closest}'?" if closest else None
            issues.append(
                Issue(
                    severity="warning",
                    message=f"unknown key '{key}'",
                    file=path,
                    line=line_map.get((key,)),
                    hint=hint,
                )
            )

    # device_category_severity: severity literal + category existence.
    dcs = parsed.get("device_category_severity")
    if dcs is not None:
        if not isinstance(dcs, dict):
            issues.append(
                Issue(
                    severity="error",
                    message=(
                        f"device_category_severity must be a mapping, "
                        f"got {type(dcs).__name__}"
                    ),
                    file=path,
                    line=line_map.get(("device_category_severity",)),
                )
            )
        else:
            for cat, sev in dcs.items():
                line = line_map.get(("device_category_severity", cat))
                if not isinstance(sev, str) or sev not in VALID_SEVERITIES:
                    issues.append(
                        Issue(
                            severity="error",
                            message=(
                                f"invalid severity {sev!r} for category "
                                f"{cat!r} -- must be one of: "
                                f"{', '.join(VALID_SEVERITIES)}"
                            ),
                            file=path,
                            line=line,
                        )
                    )
                if isinstance(cat, str) and cat not in DEFAULT_CATEGORY_SEVERITIES:
                    issues.append(
                        Issue(
                            severity="warning",
                            message=(
                                f"category {cat!r} is not in the canonical "
                                f"Argus category set; remap will have no effect "
                                f"unless Argus adds it later"
                            ),
                            file=path,
                            line=line,
                        )
                    )

    # suppress_categories: list of strings; warn on unknown categories.
    sc = parsed.get("suppress_categories")
    if sc is not None:
        if not isinstance(sc, list):
            issues.append(
                Issue(
                    severity="error",
                    message=(
                        f"suppress_categories must be a list, got {type(sc).__name__}"
                    ),
                    file=path,
                    line=line_map.get(("suppress_categories",)),
                )
            )
        else:
            for i, cat in enumerate(sc):
                line = line_map.get(("suppress_categories", i))
                if not isinstance(cat, str) or not cat.strip():
                    issues.append(
                        Issue(
                            severity="error",
                            message=(
                                f"suppress_categories[{i}] must be a non-empty "
                                f"string, got {cat!r}"
                            ),
                            file=path,
                            line=line,
                        )
                    )
                    continue
                if cat not in DEFAULT_CATEGORY_SEVERITIES:
                    issues.append(
                        Issue(
                            severity="warning",
                            message=(
                                f"suppress_categories entry {cat!r} is not in "
                                f"the canonical Argus category set; suppression "
                                f"will have no effect"
                            ),
                            file=path,
                            line=line,
                        )
                    )

    # suppress_vendors: list of non-empty strings.
    sv = parsed.get("suppress_vendors")
    if sv is not None:
        if not isinstance(sv, list):
            issues.append(
                Issue(
                    severity="error",
                    message=(
                        f"suppress_vendors must be a list, got {type(sv).__name__}"
                    ),
                    file=path,
                    line=line_map.get(("suppress_vendors",)),
                )
            )
        else:
            for i, entry in enumerate(sv):
                line = line_map.get(("suppress_vendors", i))
                if not isinstance(entry, str):
                    issues.append(
                        Issue(
                            severity="warning",
                            message=(
                                f"suppress_vendors[{i}] must be a string, "
                                f"got {type(entry).__name__}; entry will be dropped"
                            ),
                            file=path,
                            line=line,
                        )
                    )
                elif not entry.strip():
                    issues.append(
                        Issue(
                            severity="warning",
                            message=(
                                f"suppress_vendors[{i}] is empty after stripping "
                                f"whitespace; entry will be dropped"
                            ),
                            file=path,
                            line=line,
                        )
                    )

    # pattern_overrides: keys must be 16-hex argus_record_id; values
    # must be valid severity literals.
    po = parsed.get("pattern_overrides")
    if po is not None:
        if not isinstance(po, dict):
            issues.append(
                Issue(
                    severity="error",
                    message=(
                        f"pattern_overrides must be a mapping, got {type(po).__name__}"
                    ),
                    file=path,
                    line=line_map.get(("pattern_overrides",)),
                )
            )
        else:
            for key, sev in po.items():
                line = line_map.get(("pattern_overrides", key))
                if not isinstance(key, str):
                    issues.append(
                        Issue(
                            severity="error",
                            message=(
                                f"pattern_overrides key {key!r} must be a string"
                            ),
                            file=path,
                            line=line,
                        )
                    )
                    continue
                normalized = key.strip().lower()
                if len(normalized) != 16 or any(
                    c not in "0123456789abcdef" for c in normalized
                ):
                    issues.append(
                        Issue(
                            severity="error",
                            message=(
                                f"pattern_overrides key {key!r} is not a 16-hex "
                                f"argus_record_id (matches /^[0-9a-f]{{16}}$/i)"
                            ),
                            file=path,
                            line=line,
                        )
                    )
                if not isinstance(sev, str) or sev not in VALID_SEVERITIES:
                    issues.append(
                        Issue(
                            severity="error",
                            message=(
                                f"pattern_overrides[{key!r}] = {sev!r}: "
                                f"must be one of: {', '.join(VALID_SEVERITIES)}"
                            ),
                            file=path,
                            line=line,
                        )
                    )

    # Final sanity: call the loader to mirror exactly what the daemon
    # would see. If it returns None despite our parse succeeding,
    # something we did not catch slipped through — surface it as an
    # error so the layer isn't silently disabled at daemon startup.
    capture = _CaptureHandler()
    _rules_logger = logging.getLogger("lynceus.rules")
    capture.attach(_rules_logger)
    try:
        loaded = load_runtime_severity_overrides(str(path))
    finally:
        capture.detach(_rules_logger)
    if loaded is None and not any(i.severity == "error" for i in issues):
        for record in capture.records:
            if record.levelno >= logging.WARNING:
                issues.append(
                    Issue(
                        severity="error",
                        message=(
                            f"loader rejected file (would disable runtime "
                            f"override layer at startup): {record.getMessage()}"
                        ),
                        file=path,
                    )
                )
                break

    valid = not any(i.severity == "error" for i in issues)
    if valid:
        if loaded is None or loaded.is_empty():
            summary = "valid (no active runtime keys)"
        else:
            summary = (
                f"{len(loaded.device_category_severity)} remap(s), "
                f"{len(loaded.suppress_categories)} suppressed category(ies), "
                f"{len(loaded.suppress_vendors)} suppressed vendor(s), "
                f"{len(loaded.pattern_overrides)} pattern override(s)"
            )
    else:
        summary = "validation failed"
    return FileReport(
        file=path, exists=True, valid=valid, summary=summary, issues=tuple(issues)
    )


class _CaptureHandler(logging.Handler):
    """In-memory log capture for surfacing lenient-loader diagnostics."""

    def __init__(self) -> None:
        super().__init__(level=logging.WARNING)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)

    def attach(self, logger: logging.Logger) -> None:
        logger.addHandler(self)

    def detach(self, logger: logging.Logger) -> None:
        logger.removeHandler(self)


def _validate_allowlist_file(
    path: Path,
    *,
    is_ui_sibling: bool,
    now_ts: int | None = None,
) -> FileReport:
    """Shared validator body for ``allowlist.yaml`` and ``allowlist_ui.yaml``.

    Differences between the two files:
    - The primary's missing case is an ERROR (the operator pointed
      ``Config.allowlist_path`` at nothing).
    - The UI sibling's missing case is normal (it does not exist
      until the first UI write).
    """
    import time as _time

    if now_ts is None:
        now_ts = int(_time.time())

    issues: list[Issue] = []
    label = "allowlist UI sibling" if is_ui_sibling else "allowlist file"

    if not path.exists():
        if is_ui_sibling:
            return FileReport(
                file=path,
                exists=False,
                valid=True,
                summary="not present (no UI-written entries yet)",
                issues=tuple(issues),
            )
        issues.append(
            Issue(severity="error", message=f"{label} not found", file=path)
        )
        return FileReport(
            file=path, exists=False, valid=False, summary="missing", issues=tuple(issues)
        )

    parsed, parse_issue = _try_load_yaml(path)
    if parse_issue is not None:
        issues.append(parse_issue)
        return FileReport(
            file=path, exists=True, valid=False, summary="unparseable", issues=tuple(issues)
        )

    # Capture loader log records (allowlist loader is lenient on parse
    # / validation errors — logs ERROR/WARNING and returns empty).
    capture = _CaptureHandler()
    _allow_logger = logging.getLogger("lynceus.allowlist")
    capture.attach(_allow_logger)
    try:
        try:
            if is_ui_sibling:
                # The public load_allowlist consumes the PRIMARY path
                # and derives the sibling. For the sibling-only
                # validator we construct an Allowlist directly via the
                # same Pydantic class the loader uses.
                data = parsed if isinstance(parsed, dict) else {}
                allowlist = Allowlist(**data)
            else:
                allowlist = load_allowlist(str(path))
        except FileNotFoundError:
            issues.append(
                Issue(
                    severity="error",
                    message=f"{label} disappeared mid-validation",
                    file=path,
                )
            )
            return FileReport(
                file=path, exists=False, valid=False, summary="missing", issues=tuple(issues)
            )
        except ValidationError as exc:
            for err in exc.errors():
                loc = ".".join(str(part) for part in err.get("loc", ()))
                msg = err.get("msg", "validation error")
                issues.append(
                    Issue(
                        severity="error",
                        message=(f"{loc}: {msg}" if loc else msg),
                        file=path,
                    )
                )
            return FileReport(
                file=path,
                exists=True,
                valid=False,
                summary="validation failed",
                issues=tuple(issues),
            )
    finally:
        capture.detach(_allow_logger)

    # For the primary file, load_allowlist swallows Pydantic / yaml
    # errors at the inner _load_primary boundary and returns an empty
    # Allowlist with an ERROR log line. Promote that ERROR-log to an
    # ERROR issue so the operator sees it at validate time.
    if not is_ui_sibling:
        for record in capture.records:
            if record.levelno >= logging.ERROR:
                issues.append(
                    Issue(
                        severity="error",
                        message=(
                            f"loader rejected file (would empty the "
                            f"allowlist at startup): {record.getMessage()}"
                        ),
                        file=path,
                    )
                )

    # Expired-entry surface: scan for ``expires_at`` in the past so
    # the operator can prune dead snooze entries.
    if isinstance(parsed, dict):
        line_map = _build_line_map(path)
        raw_entries = parsed.get("entries")
        if isinstance(raw_entries, list):
            for i, raw_entry in enumerate(raw_entries):
                if not isinstance(raw_entry, dict):
                    continue
                expires_at = raw_entry.get("expires_at")
                if not isinstance(expires_at, int):
                    continue
                if expires_at <= now_ts:
                    pattern = raw_entry.get("pattern", "?")
                    issues.append(
                        Issue(
                            severity="warning",
                            message=(
                                f"entry for {pattern!r} expired on "
                                f"{_format_iso_utc(expires_at)}; it will "
                                f"never match -- consider removing"
                            ),
                            file=path,
                            line=line_map.get(("entries", i)),
                        )
                    )

    valid = not any(i.severity == "error" for i in issues)
    if valid:
        n = len(allowlist.entries)
        summary = f"{n} entr{'y' if n == 1 else 'ies'} valid"
    else:
        summary = "validation failed"
    return FileReport(
        file=path, exists=True, valid=valid, summary=summary, issues=tuple(issues)
    )


def validate_allowlist_yaml(path: Path, *, now_ts: int | None = None) -> FileReport:
    return _validate_allowlist_file(path, is_ui_sibling=False, now_ts=now_ts)


def validate_allowlist_ui_yaml(path: Path, *, now_ts: int | None = None) -> FileReport:
    return _validate_allowlist_file(path, is_ui_sibling=True, now_ts=now_ts)


# --- orchestrator + output --------------------------------------------------


def _collect_reports(scope: str, *, now_ts: int | None = None) -> list[FileReport]:
    """Run each per-file validator in order. ``lynceus.yaml`` first since
    it references the others; subsequent files use the paths it carries.

    Raises ``ConfigDirUnreachable`` (caught at the CLI boundary and
    surfaced as exit code 2) when the canonical config dir cannot be
    derived for the requested scope.
    """
    try:
        config_dir = paths.default_config_dir(scope)
    except (NotImplementedError, ValueError) as exc:
        raise ConfigDirUnreachable(str(exc)) from exc

    lynceus_path = config_dir / "lynceus.yaml"
    lynceus_report, cfg = validate_lynceus_yaml(lynceus_path)
    reports: list[FileReport] = [lynceus_report]
    if cfg is None:
        return reports

    if cfg.rules_path:
        reports.append(validate_rules_yaml(Path(cfg.rules_path)))
    if cfg.severity_overrides_path:
        reports.append(
            validate_severity_overrides_yaml(Path(cfg.severity_overrides_path))
        )
    if cfg.allowlist_path:
        primary_path = Path(cfg.allowlist_path)
        reports.append(validate_allowlist_yaml(primary_path, now_ts=now_ts))
        reports.append(
            validate_allowlist_ui_yaml(derive_ui_path(primary_path), now_ts=now_ts)
        )
    return reports


def _format_issue_line(issue: Issue) -> str:
    prefix = "ERROR" if issue.severity == "error" else "WARNING"
    location = f" (line {issue.line})" if issue.line is not None else ""
    msg = issue.message
    if issue.hint:
        msg = f"{msg} -- {issue.hint}"
    return f"  {prefix}{location}: {msg}"


def render_report(
    scope: str,
    reports: list[FileReport],
    *,
    quiet: bool,
) -> str:
    """Render the final stdout report for ``reports``.

    ``quiet`` suppresses per-file OK and WARNING lines (and the OK
    label entirely); ERRORs and the trailing Summary always print.
    """
    lines: list[str] = []
    lines.append(f"Validating Lynceus configuration (scope: {scope})")
    lines.append("")

    total_errors = 0
    total_warnings = 0

    for report in reports:
        errors = [i for i in report.issues if i.severity == "error"]
        warnings = [i for i in report.issues if i.severity == "warning"]
        total_errors += len(errors)
        total_warnings += len(warnings)

        if quiet and not errors:
            # Suppress entirely in quiet mode when nothing is wrong
            # AND nothing is warning-worthy enough to override quiet.
            continue
        lines.append(str(report.file))
        if not errors and not warnings:
            if not quiet:
                lines.append(f"  OK ({report.summary})")
        else:
            for issue in errors:
                lines.append(_format_issue_line(issue))
            if not quiet:
                for issue in warnings:
                    lines.append(_format_issue_line(issue))
        lines.append("")

    error_word = "error" if total_errors == 1 else "errors"
    warning_word = "warning" if total_warnings == 1 else "warnings"
    file_count = len(reports)
    file_word = "file" if file_count == 1 else "files"
    lines.append(
        f"Summary: {total_errors} {error_word}, {total_warnings} "
        f"{warning_word} across {file_count} {file_word}"
    )
    return "\n".join(lines)


# --- CLI entry point --------------------------------------------------------


class ConfigDirUnreachable(Exception):
    """Tool-level failure: the canonical config dir cannot be derived."""


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lynceus-validate",
        description=(
            "Read-only validator for Lynceus configuration files. "
            "Checks lynceus.yaml, rules.yaml, severity_overrides.yaml, "
            "and allowlist.yaml (plus the UI sibling) for schema "
            "errors, unknown keys, malformed values, and missing "
            "referenced paths. Reports per-file results to stdout. "
            "Exit code 0 on success, 1 on errors, 2 on tool failure."
        ),
    )
    p.add_argument(
        "--scope",
        choices=("user", "system"),
        default="user",
        help=(
            "scope used to derive default config dir (default: %(default)s). "
            "Matches lynceus-import-argus's scope-resolution convention."
        ),
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        help="suppress OK and WARNING lines; print only ERRORs and the Summary.",
    )
    p.add_argument(
        "--no-color",
        action="store_true",
        help=(
            "no-op in v1 (output is always plain text); reserved for "
            "future color support."
        ),
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"lynceus-validate {__version__}",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        reports = _collect_reports(args.scope)
    except ConfigDirUnreachable as exc:
        print(f"lynceus-validate: cannot resolve config dir: {exc}", file=sys.stderr)
        return 2

    output = render_report(args.scope, reports, quiet=args.quiet)
    print(output)

    has_errors = any(
        any(i.severity == "error" for i in r.issues) for r in reports
    )
    return 1 if has_errors else 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
