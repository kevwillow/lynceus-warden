"""Pure config-application core for ``lynceus-setup``.

This module owns the deterministic side-effect chain that lynceus-setup
performs once the operator has answered every prompt: write
``lynceus.yaml``, scaffold ``severity_overrides.yaml``, create + chown
``data_dir`` and ``log_dir``, subprocess into ``lynceus-import-argus``
to import the bundled watchlist, and (when the caller has decided)
write ``rules.yaml``.

The chain is wrapped in ``apply_config(config, ...)`` so neither the
CLI wizard (``lynceus.cli.setup``) nor the eventual run-once web wizard
(Phase 2) has to re-implement the order-sensitive permissions sequence
that closes rc1 bugs S1, S2, and Bug 6. The two frontends differ only
in how they collect input and stream progress — see ``ProgressSink``.

All file-write helpers preserved verbatim from the pre-refactor
``lynceus.cli.setup`` module. They are re-exported there for back-compat
so the 200 existing setup-wizard tests' import paths keep working.
"""

from __future__ import annotations

import importlib.resources
import logging
import os
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Literal

from lynceus import paths
from lynceus.config import Config
from lynceus.setup.models import ApplyReport, ApplyStep, ProgressSink

logger = logging.getLogger(__name__)


# --- Errors -----------------------------------------------------------------


class SetupError(Exception):
    """Raised by the wizard helpers for operator-actionable failures.

    Caught at the ``run_wizard`` boundary and rendered to stderr with a
    non-zero exit code. Distinguished from ad-hoc ``RuntimeError`` so a
    test can assert exactly which failure mode it's exercising.
    """


# --- Platform indirection ---------------------------------------------------


def _is_windows() -> bool:
    """Indirection point for tests — monkeypatch this rather than ``os.name``,
    which would also flip pathlib's native Path subclass at runtime."""
    return os.name == "nt"


def _frontend_is_windows() -> bool:
    """Lazy lookup of ``_is_windows`` through the CLI frontend module.

    The 200-test suite predates the F6 Phase 1 split and pins the
    "are we on Windows?" branch via ``monkeypatch.setattr(wiz,
    "_is_windows", ...)``. After the move, the file-write helpers in
    this module would consult their own module-local ``_is_windows``,
    so the test patch on ``cli.setup._is_windows`` would not reach
    them. Routing the check through the CLI frontend at call time
    preserves the existing test seam without a 30-site test edit.

    The import is intentionally lazy: ``cli.setup`` re-imports from
    this module at load time, so an eager import here would cycle. By
    call time both modules are fully loaded and the lookup is a
    ``sys.modules`` dict hit.
    """
    from lynceus.cli import setup as _frontend
    return _frontend._is_windows()


def _frontend_render_config_yaml(answers: dict) -> str:
    """Late lookup of ``render_config_yaml`` through the CLI frontend.

    Same compat shim as ``_frontend_is_windows``: the legacy test
    ``test_existing_rules_path_in_lynceus_yaml_does_not_duplicate``
    patches ``wiz.render_config_yaml`` to inject a pre-existing
    ``rules_path:`` and asserts that the post-render append-rules-path
    code path detects the existing key and skips the duplicate. The
    patched render must reach ``apply_config``'s render call, which
    would otherwise resolve to this module's local binding and miss
    the patch.
    """
    from lynceus.cli import setup as _frontend
    return _frontend.render_config_yaml(answers)


def _frontend_import_bundled_watchlist(
    db_path: str, override_file: str | None
) -> tuple[bool, str]:
    """Late lookup of ``import_bundled_watchlist`` through the CLI frontend.

    Seven legacy tests stub the bundled-import subprocess via
    ``monkeypatch.setattr(wiz, "import_bundled_watchlist", fake_bundled)``
    and drive ``run_wizard`` end-to-end. After the move, ``apply_config``
    calling ``import_bundled_watchlist`` directly would hit this
    module's binding, not the patched ``wiz.`` binding. Routing through
    ``cli.setup`` at call time preserves the test seam.
    """
    from lynceus.cli import setup as _frontend
    return _frontend.import_bundled_watchlist(
        db_path=db_path, override_file=override_file
    )


# --- Atomic writes + system-mode permissions --------------------------------
#
# rc1 had three independent footguns in the way it laid down state under
# ``--system`` mode:
#
#   * Bug 6: config written 0600 root:root → ``User=lynceus`` daemon could
#     not read it → unit failed on first start.
#   * S1:    data_dir + lynceus.db owned by root → daemon could not write
#     → first poll failed with "attempt to write a readonly database".
#   * S2:    secrets-bearing config briefly world-readable between
#     ``write_text`` and the follow-up ``chmod`` (race window in BOTH user
#     and system mode).
#
# The fix is a coordinated change: ``_atomic_write`` collapses the S2
# race by setting the target mode at fd-creation time, and the
# ``_apply_system_perms_*`` helpers give system mode a clean ownership
# story (``root:lynceus 0640`` for files, ``lynceus:lynceus 0750`` for
# directories the daemon must write to). User mode behaviour is
# unchanged — the helpers are wired in only when ``scope == "system"``.


def _atomic_write(path: Path, content: str, *, mode: int = 0o600) -> None:
    """Write ``content`` to ``path`` with ``mode`` set at creation time.

    Closes the S2 race: the legacy "write the file then chmod" two-step
    leaves a window in which the file exists with umask-derived bits
    (typically world-readable ``0o644``) before the chmod lands. Anyone
    reading the file in that interval sees the secret-bearing config
    in the clear. Setting the mode in the ``os.open`` flags eliminates
    the window — the file never exists on disk with permissions broader
    than requested.

    On Windows the POSIX mode bits are meaningless, so we fall back to
    ``path.write_text`` to match the chmod-skip pattern used elsewhere.
    """
    if _frontend_is_windows():
        path.write_text(content, encoding="utf-8")
        return
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(content)


def _apply_system_perms_to_file(path: Path, *, group: str = "lynceus", mode: int = 0o640) -> None:
    """Set ``root:<group>`` ownership and ``mode`` on a system-mode file.

    Used for ``/etc/lynceus/lynceus.yaml`` and the severity-overrides
    file: the config is owned by root (so a compromised daemon cannot
    rewrite its own config) but readable by the lynceus group (so the
    ``User=lynceus`` daemon can actually load it).
    """
    if _frontend_is_windows():
        return
    if sys.platform == "darwin":
        raise SetupError("--system mode is Linux-only with systemd; not supported on macOS.")
    import grp

    try:
        gid = grp.getgrnam(group).gr_gid
    except KeyError as exc:
        raise SetupError(
            f"Group '{group}' does not exist. "
            "Run `sudo ./install.sh --system` first to create the system user/group."
        ) from exc
    os.chown(str(path), 0, gid)
    os.chmod(str(path), mode)


def _apply_system_perms_to_dir(
    path: Path,
    *,
    owner: str = "lynceus",
    group: str = "lynceus",
    mode: int = 0o750,
) -> None:
    """Set ``<owner>:<group>`` ownership and ``mode`` on a system-mode dir.

    Used for ``/var/lib/lynceus`` and ``/var/log/lynceus``: the daemon
    needs to create files in these directories, so they must be owned
    by the lynceus user, not root. Same shape as
    ``_apply_system_perms_to_file`` but resolves a UID too.
    """
    if _frontend_is_windows():
        return
    if sys.platform == "darwin":
        raise SetupError("--system mode is Linux-only with systemd; not supported on macOS.")
    import grp
    import pwd

    try:
        uid = pwd.getpwnam(owner).pw_uid
    except KeyError as exc:
        raise SetupError(
            f"User '{owner}' does not exist. "
            "Run `sudo ./install.sh --system` first to create the system user/group."
        ) from exc
    try:
        gid = grp.getgrnam(group).gr_gid
    except KeyError as exc:
        raise SetupError(
            f"Group '{group}' does not exist. "
            "Run `sudo ./install.sh --system` first to create the system user/group."
        ) from exc
    os.chown(str(path), uid, gid)
    os.chmod(str(path), mode)


# --- Defaults ---------------------------------------------------------------

DEFAULT_UI_PORT = 8765
# Bound the bundled-watchlist subprocess so a stuck lynceus-import-argus
# cannot wedge --system setup at the import step with no visible
# progress. Sized for the 22k-row bundled CSV running on Pi-class
# hardware (Raspberry Pi 4/5 on SD-card storage): cli/import_argus.py's
# pass-3 commits per row (one `with db._conn:` block per survivor), so
# wall-clock import time on a Pi SD card is dominated by sqlite fsync
# and can run several minutes. The previous 120s ceiling was sized for
# a much smaller bundled CSV and fired on real Pi hardware during the
# v0.7.0 Linux smoke. 600s gives generous headroom; any real import
# that needs longer wants to be the operator's explicit follow-up
# `lynceus-import-argus --from-github` rather than the wizard's
# auto-import.
BUNDLED_IMPORT_TIMEOUT_SECONDS = 600


SEVERITY_OVERRIDES_TEMPLATE = """\
# Lynceus severity overrides — consumed by TWO layers:
#
#   IMPORT-TIME (lynceus-import-argus --override-file): keys
#     vendor_overrides, geographic_filter, confidence_downgrade_threshold.
#     Edits require re-importing to apply.
#
#   RUNTIME (the poller / daemon): keys device_category_severity,
#     suppress_categories, suppress_vendors, pattern_overrides,
#     vendor_severity. Edits require only a daemon restart;
#     already-imported rows fire at the new severity (or are
#     suppressed) without re-importing.
#
# Each section is optional. Uncomment and edit only what you want to change.
# Each section below carries an inline `# LAYER:` tag so it's clear which
# layer (and what action) the change requires.

# vendor_overrides:           # LAYER: IMPORT-TIME — re-import to apply
#   # Force a specific severity for any record from this manufacturer at
#   # IMPORT time. Use the literal string "drop" to skip records from a
#   # vendor entirely — that "drop" is import-skip semantics (the row
#   # never lands in the DB). For RUNTIME-only vendor suppression on
#   # already-imported rows, use suppress_vendors below instead; for
#   # RUNTIME-only vendor severity tuning, use vendor_severity below.
#   "ACME Surveillance Inc": high
#   "Hobbyist Drone Co":     drop

# vendor_severity:            # LAYER: RUNTIME — daemon restart applies live
#   # Vendor-level severity remap. Maps manufacturer strings
#   # (case-insensitive exact match on the watchlist row's
#   # manufacturer, same comparison shape as suppress_vendors below)
#   # to a severity literal (low / med / high). The runtime remap
#   # counterpart to suppress_vendors: tune severity across every
#   # device from a vendor without enumerating individual rows.
#   #
#   # Precedence: more specific than device_category_severity (a
#   # vendor remap on an alpr device wins over alpr → med); less
#   # specific than pattern_overrides (a row-level remap on the same
#   # row wins over the vendor remap). Suppression at either layer
#   # (suppress_vendors / suppress_categories) always wins — vendor
#   # remap is not an UNSUPPRESS knob.
#   #
#   # Distinct from import-time vendor_overrides above: that key's
#   # "drop" sentinel means skip-at-import. vendor_severity is a
#   # separate RUNTIME key so the "drop" semantic stays unambiguous.
#   #
#   # Example: bump every surveillance camera vendor to high
#   # regardless of category:
#   #   "Axon Enterprise, Inc.": high
#   #   "Flock Safety":          high

# device_category_severity:   # LAYER: BOTH — daemon restart applies live
#   # Remap the severity for an Argus device_category.
#   # Import time bakes this into the watchlist row at write time;
#   # the poller re-applies it at alert time on top of whatever was
#   # baked, so an edit takes effect on the next daemon restart with
#   # no re-import needed. Built-ins:
#   #   imsi_catcher=high, alpr=high, body_cam=med, drone=med,
#   #   gunshot_detect=med, hacking_tool=high, in_vehicle_router=med,
#   #   unknown=low.
#   imsi_catcher: high
#   drone: low
#   # automotive_telematics: med
#   # # Forward-compat category from Argus §F.1. Argus v1.4.1 ships the
#   # # `automotive_telematics` device_category enum value but with zero
#   # # active rows; the Parrot Automotive arm and v1.4.2 cellular-IoT
#   # # vendor backlog will populate the category later. Seating the
#   # # hint at `med` now so operator severity is already tuned when
#   # # the data lands. (Argus engineer's "medium" → Lynceus's "med"
#   # # literal; `medium` is not in VALID_SEVERITIES and would silently
#   # # disable the override.)

# pattern_overrides:          # LAYER: RUNTIME — daemon restart applies live
#   # Row-level severity remap keyed by argus_record_id (16-hex
#   # stable Argus identifier on watchlist_metadata.argus_record_id).
#   # More specific than device_category_severity above — carves
#   # individual rows out of the category-level default. Less
#   # specific than suppress_categories / suppress_vendors above:
#   # if either suppression layer fires for a row, this remap is
#   # never consulted (per-row UNSUPPRESS is not a feature). Only
#   # rows imported from Argus have argus_record_id populated;
#   # operator-supplied rows seeded via lynceus-seed-watchlist
#   # without metadata fall through to the category layer.
#   #
#   # Find an argus_record_id for a row of interest with:
#   #   sqlite3 lynceus.db "SELECT m.argus_record_id, w.pattern,
#   #                              w.severity, m.vendor
#   #                       FROM watchlist w
#   #                       JOIN watchlist_metadata m
#   #                         ON w.id = m.watchlist_id
#   #                       LIMIT 5;"
#   #
#   # Example: bump a specific row from baked low → high.
#   #   "a1b2c3d4e5f60718": high

# suppress_categories:        # LAYER: RUNTIME — daemon restart applies live
#   # Categories listed here produce NO alerts at runtime, even if
#   # delegation rules in rules.yaml are active for the matched
#   # pattern_type. The matching row stays in the watchlist DB (the
#   # importer is unaffected); only alert emission is suppressed.
#   # Useful when an operator wants to keep enrichment metadata for
#   # a category without producing alerts on it.
#   # - some_category

# suppress_vendors:           # LAYER: RUNTIME — daemon restart applies live
#   # Manufacturers listed here produce NO alerts at runtime, even if
#   # delegation rules in rules.yaml are active for the matched
#   # pattern_type. Comparison is case-insensitive exact match
#   # (lowercase + whitespace-trim normalization applied to both sides),
#   # so casing and accidental leading/trailing spaces do not matter —
#   # but partial substrings do NOT match (use vendor_overrides above
#   # for import-time skip-by-substring).
#   # Use the canonical vendor string from the watchlist row (the same
#   # string the Argus CSV exports in the `manufacturer` column).
#   # Runtime cousin of vendor_overrides' "drop" sentinel; the watchlist
#   # row stays in the DB, only alert emission is silenced. Vendor
#   # suppression takes precedence over the category-driven keys above.
#   # - "Mitsubishi Electric US, Inc."

# geographic_filter:          # LAYER: IMPORT-TIME — re-import to apply
#   # Only import records whose geographic_scope matches one of these values
#   # (records with scope "global" are always kept). Empty/unset = no filter.
#   - US
#   - global

# confidence_downgrade_threshold: 70   # LAYER: IMPORT-TIME — re-import to apply
# # Argus records below this confidence (0-100) get their severity downgraded
# # one notch (high -> med, med -> low) at import. Set to 0 to disable.

# argus_schema_version_accept_list:   # LAYER: IMPORT-TIME — re-import to apply
#   # Operator-tunable accept-list for the Argus CSV's
#   # `# meta: schema_version=N` ingress value. Values outside this
#   # list trip a WARNING-without-abort during import; values in the
#   # list are accepted silently. Defaults to ["25", "26"] (the
#   # v1.4.1 transition window — pre-Phase-1 regen anchor exports
#   # were tagged "25", v1.4.1 ships at "26"). Set to null or [] to
#   # disable the check entirely; older Argus exports without a
#   # schema_version key always pass silently (no regression for
#   # archived-export imports).
#   - "25"
#   - "26"
"""


# --- YAML serialization helpers ---------------------------------------------


def _yaml_str(value: str) -> str:
    """Quote a string for safe inclusion in a single-line YAML value."""
    if value is None:
        return "null"
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _yaml_bool(value: bool) -> str:
    return "true" if value else "false"


# --- Config write -----------------------------------------------------------


def render_config_yaml(answers: dict) -> str:
    """Build the lynceus.yaml content with section comments. Hand-rolled so
    the operator gets explanatory comments, not a bare yaml.safe_dump."""
    sources_lines = ["kismet_sources:"]
    for src in answers["kismet_sources"]:
        sources_lines.append(f"  - {src}")
    lines = [
        "# Lynceus configuration — generated by lynceus-setup.",
        "# Edit this file directly, or re-run `lynceus-setup --reconfigure`.",
        "",
        "# --- Kismet source ---",
        "# REST API endpoint and the cookie token used to authenticate.",
        f"kismet_url: {answers['kismet_url']}",
        f"kismet_api_key: {_yaml_str(answers['kismet_api_key'])}",
        "",
        "# --- Capture sources ---",
        "# Inclusive filter on Kismet source (adapter) names. Only observations",
        "# from listed sources are processed; others are silently dropped.",
        *sources_lines,
        "",
        "# --- Tier 1 passive metadata capture ---",
        "# Privacy-sensitive toggles. probe_ssids reveals device WiFi history",
        "# (off by default). ble_friendly_names captures BLE GAP advertisement",
        "# names — broadcast publicly with intent (on by default).",
        "capture:",
        f"  probe_ssids: {_yaml_bool(answers['probe_ssids'])}",
        f"  ble_friendly_names: {_yaml_bool(answers['ble_friendly_names'])}",
        "",
        "# --- Notifications (ntfy) ---",
        "# Topic acts as the shared secret — anyone who knows it can publish",
        "# AND subscribe. Pick something unguessable. Empty strings disable ntfy.",
        f"ntfy_url: {_yaml_str(answers['ntfy_url'])}",
        f"ntfy_topic: {_yaml_str(answers['ntfy_topic'])}",
        "",
        "# --- RSSI floor ---",
        "# Drop observations weaker than this RSSI in dBm. -70 is reasonable",
        "# indoors; -85 is more permissive.",
        f"min_rssi: {int(answers['min_rssi'])}",
        "",
        "# --- Web UI ---",
        f"ui_bind_port: {DEFAULT_UI_PORT}",
        "",
    ]
    return "\n".join(lines)


def write_config(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(path, content)


def scaffold_severity_overrides(path: Path) -> bool:
    """Create the default override file if it doesn't already exist.
    Returns True when newly created, False when an existing file was kept."""
    if path.exists():
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write(path, SEVERITY_OVERRIDES_TEMPLATE)
    return True


# --- Argus import -----------------------------------------------------------


BUNDLED_WATCHLIST_PACKAGE = "lynceus.data"
BUNDLED_WATCHLIST_RESOURCE = "default_watchlist.csv"
BUNDLED_ABSENT_MESSAGE = "no bundled watchlist"


def import_bundled_watchlist(db_path: str, override_file: str | None) -> tuple[bool, str]:
    """Auto-import the bundled default_watchlist.csv when shipped in
    ``lynceus.data``. Returns ``(success, message)``.

    Silently returns ``(False, "no bundled watchlist")`` when the data
    package or CSV resource is missing — that is the expected case for
    source builds without bundled threat data, not an error. On subprocess
    failure returns ``(False, "import failed: <reason>")`` with stderr (or
    stdout) captured in the reason. On success returns ``(True, <summary>)``
    where the summary is the import_argus summary line if recognisable.
    """
    try:
        resource = importlib.resources.files(BUNDLED_WATCHLIST_PACKAGE).joinpath(
            BUNDLED_WATCHLIST_RESOURCE
        )
    except (ModuleNotFoundError, FileNotFoundError):
        return False, BUNDLED_ABSENT_MESSAGE
    try:
        present = resource.is_file()
    except (FileNotFoundError, OSError):
        return False, BUNDLED_ABSENT_MESSAGE
    if not present:
        return False, BUNDLED_ABSENT_MESSAGE

    try:
        with importlib.resources.as_file(resource) as csv_path:
            cmd = [
                "lynceus-import-argus",
                "--input",
                str(csv_path),
                "--db",
                db_path,
            ]
            if override_file:
                cmd += ["--override-file", override_file]
            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
            except FileNotFoundError:
                return False, "import failed: lynceus-import-argus not found on PATH"
            # Bound the wait so a stuck child cannot wedge --system setup
            # silently. The previous unbounded communicate() would leave
            # the wizard hanging with no progress output if
            # lynceus-import-argus itself hung on, say, a malformed DB
            # file or a stuck sqlite lock — the operator-visible symptom
            # was identical to the "after-completion silent hang" the
            # explicit-completion-marker fix addresses below.
            try:
                stdout, stderr = proc.communicate(
                    timeout=BUNDLED_IMPORT_TIMEOUT_SECONDS
                )
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
                return False, (
                    f"import failed: lynceus-import-argus exceeded "
                    f"{BUNDLED_IMPORT_TIMEOUT_SECONDS}s timeout (process killed)"
                )
            rc = proc.returncode
    except (FileNotFoundError, OSError) as e:
        return False, f"import failed: {e}"

    if rc != 0:
        detail = (stderr or stdout or f"exit code {rc}").strip().splitlines()
        reason = detail[-1] if detail else f"exit code {rc}"
        return False, f"import failed: {reason}"

    summary = next(
        (line for line in stdout.splitlines() if line.lstrip().startswith("imported")),
        "imported successfully",
    )
    return True, summary


# --- Enable-alerting helpers ------------------------------------------------
#
# DELEGATION_RULES drives both the per-pattern-type counts (so the wizard
# only prompts for types with at least one row in the watchlist DB) and
# the rules.yaml rendering. The CLI frontend asks the prompts; the core
# only provides the data shape and the writers.

# Each tuple: (rule_name in YAML, rule_type, pattern_type in DB, plural
# label used in the prompt, description shown in rules.yaml).
#
# rule_type / pattern_type intentionally diverge for ble_uuid: the
# pattern_type column in the watchlist table is ``ble_uuid``, and the
# rule_type used by rules.py is also ``ble_uuid`` (without the
# ``watchlist_`` prefix the four other delegation types carry — see
# rules.py:27 / 75 / 98). Match what an operator will read in their
# generated rules.yaml rather than inventing a third name.
DELEGATION_RULES: tuple[tuple[str, str, str, str, str], ...] = (
    (
        "argus_mac_range",
        "watchlist_mac_range",
        "mac_range",
        "MAC ranges",
        "Argus mac_range corpus — IEEE registry sub-allocations",
    ),
    (
        "argus_mac",
        "watchlist_mac",
        "mac",
        "MAC addresses",
        "Argus + bundled exact-MAC watchlist",
    ),
    (
        "argus_oui",
        "watchlist_oui",
        "oui",
        "vendor prefixes",
        "Argus + bundled OUI watchlist",
    ),
    (
        "argus_ssid",
        "watchlist_ssid",
        "ssid",
        "SSID patterns",
        "Argus + bundled SSID watchlist",
    ),
    (
        "argus_ble_uuid",
        "ble_uuid",
        "ble_uuid",
        "BLE UUIDs",
        "Argus + bundled BLE service-UUID watchlist",
    ),
    (
        "argus_ble_manufacturer_id",
        "watchlist_ble_manufacturer_id",
        "ble_manufacturer_id",
        "BLE manufacturer IDs",
        "Argus BLE manufacturer-ID watchlist (Bluetooth SIG company IDs)",
    ),
    (
        "argus_drone_id_prefix",
        "watchlist_drone_id_prefix",
        "drone_id_prefix",
        "drone Remote-ID prefixes",
        "Argus drone Remote-ID prefix watchlist (ANSI/CTA-2063-A)",
    ),
    (
        "argus_ble_local_name",
        "watchlist_ble_local_name",
        "ble_local_name",
        "BLE local names",
        "Argus BLE local-name watchlist (Flock Safety device names)",
    ),
)


def count_watchlist_by_pattern_type(db_path: str) -> dict[str, int]:
    """Return a ``{pattern_type: count}`` map of watchlist rows.

    Every delegation-relevant pattern_type appears as a key; missing
    types map to 0. If the database file is absent, unreadable, or
    lacks the ``watchlist`` table (source build with no bundled CSV,
    never imported), every key maps to 0 and the caller silently skips
    every per-type prompt — the wizard offers no alerting flow when
    there's nothing to alert on.
    """
    counts = {pattern_type: 0 for (_, _, pattern_type, _, _) in DELEGATION_RULES}
    if not Path(db_path).exists():
        return counts
    try:
        conn = sqlite3.connect(db_path)
        try:
            rows = conn.execute(
                "SELECT pattern_type, COUNT(*) FROM watchlist GROUP BY pattern_type"
            ).fetchall()
        finally:
            conn.close()
    except sqlite3.Error as exc:
        logger.warning("watchlist count query failed for %s: %s", db_path, exc)
        return counts
    for pattern_type, n in rows:
        if pattern_type in counts:
            counts[pattern_type] = int(n)
    return counts


def render_rules_yaml(enabled_rule_types: set[str]) -> str:
    """Build rules.yaml content with selected delegation rule_types active.

    Every delegation entry appears in the output. Entries whose
    rule_type is in ``enabled_rule_types`` are uncommented and active;
    the rest ship as commented-out templates the operator can enable
    later by hand. The bundled ``config/rules.yaml`` template is the
    structural model; the generated file is leaner (delegation-only,
    no in-memory pattern examples) so the file an operator opens after
    the wizard runs is small enough to scan top-to-bottom.

    Severity for delegation matches is sourced from the matched
    watchlist row (see rules.py:643+), not from the ``severity`` field
    below — the inline comment on each entry reminds the operator.
    """
    lines = [
        "# Lynceus detection rules — generated by lynceus-setup.",
        "# Edit this file directly to enable additional rule_types, or",
        "# re-run `lynceus-setup --reconfigure` to regenerate it.",
        "#",
        "# Each entry below corresponds to a delegation rule_type. An",
        "# ACTIVE entry alerts on every matching row of that pattern_type",
        "# currently in the watchlist DB. The `severity` field is",
        "# IGNORED for delegation — the emitted alert's severity comes",
        "# from the matched watchlist row's severity column (populated",
        "# by lynceus-import-argus from device_category).",
        "#",
        "# To enable a rule_type later: uncomment its block.",
        "# To disable: comment the block back out.",
        "",
        "rules:",
    ]
    for index, (name, rule_type, _pt, _label, description) in enumerate(DELEGATION_RULES):
        if index > 0:
            lines.append("")
        active = rule_type in enabled_rule_types
        prefix = "  " if active else "  # "
        lines.extend(
            [
                f"{prefix}- name: {name}",
                f"{prefix}  rule_type: {rule_type}",
                f"{prefix}  severity: low  # ignored — actual severity comes from the matched row",
                f"{prefix}  patterns: []",
                f'{prefix}  description: "{description}"',
            ]
        )
    lines.append("")
    return "\n".join(lines)


def append_rules_path_to_config(target: Path, rules_path: Path) -> None:
    """Append a ``rules_path:`` setting to an existing lynceus.yaml.

    The wizard writes lynceus.yaml before the enable-alerting flow
    runs, so the rules_path chosen during that flow lands as an append
    on the already-secure file. Appending preserves the file's
    existing mode (set atomically by ``_atomic_write`` during the
    original ``write_config`` call) and avoids re-applying the
    system-mode chown/chmod we already did.
    """
    with target.open("a", encoding="utf-8") as fh:
        fh.write("\n# --- Rules engine ---\n")
        fh.write("# Path to rules.yaml, wired by lynceus-setup's\n")
        fh.write("# enable-alerting flow. Unset → no rules load → no alerts fire.\n")
        fh.write(f"rules_path: {_yaml_str(str(rules_path))}\n")


# --- apply_config -----------------------------------------------------------


def _answers_from_config(config: Config) -> dict:
    """Build the dict ``render_config_yaml`` expects from a validated ``Config``.

    The hand-rolled renderer was originally written against the wizard's
    in-progress ``answers`` dict; this adapter lets ``apply_config``
    drive the same renderer without rewriting it. ``ntfy_url`` /
    ``ntfy_topic`` are stringified (renderer expects empty string for
    "skip ntfy", not ``None``).
    """
    return {
        "kismet_url": config.kismet_url,
        "kismet_api_key": config.kismet_api_key or "",
        "kismet_sources": list(config.kismet_sources or []),
        "probe_ssids": config.capture.probe_ssids,
        "ble_friendly_names": config.capture.ble_friendly_names,
        "ntfy_url": config.ntfy_url or "",
        "ntfy_topic": config.ntfy_topic or "",
        "min_rssi": config.min_rssi if config.min_rssi is not None else 0,
    }


def apply_config(
    config: Config,
    *,
    scope: Literal["user", "system"],
    target_path: Path,
    severity_overrides_path: Path,
    enabled_rule_types: set[str] | None,
    run_bundled_import: bool = True,
    progress: ProgressSink | None = None,
) -> ApplyReport:
    """Run the deterministic side-effect chain for a validated ``Config``.

    Returns an ``ApplyReport`` carrying one ``ApplyStep`` per phase in
    the exact emission order required by the rc1 system-mode fixes:

      1. ``write_config``                — render + atomic write +
                                            ``root:lynceus 0640`` under
                                            ``--system``.
      2. ``scaffold_severity_overrides`` — template (or kept existing)
                                            + perms.
      3. ``create_data_dir``             — ``mkdir(exist_ok=True)`` +
                                            ``lynceus:lynceus 0750``
                                            under ``--system``.
      4. ``create_log_dir``              — same shape for the log dir.
      5. ``import_bundled_watchlist``    — subprocess into
                                            ``lynceus-import-argus``
                                            (skipped when
                                            ``run_bundled_import``
                                            is False).
      6. ``chown_db_files``              — sqlite DB + sidecars to
                                            ``lynceus:lynceus 0640``;
                                            ``--system`` only and gated
                                            on import success (S1).
      7. ``write_rules``                 — render + atomic write +
                                            perms; gated on
                                            ``enabled_rule_types`` non-
                                            empty AND
                                            ``Config.rules_path`` set.

    The ``--system`` chown sequence between (4) and (6) is the rc1 fix
    that closes S1: the daemon (``User=lynceus``) must own its data
    directory before sqlite first writes to it, and the bundled-import
    output must be chowned after the subprocess returns. Reordering for
    "code clarity" silently re-introduces the bug — pin the order with
    a regression test.

    ``progress.record(step)`` fires synchronously per step. ``progress``
    is optional; passing ``None`` runs the chain silently and the caller
    inspects the returned ``ApplyReport.steps`` instead.

    Raises ``SetupError`` when a system-mode perms call fails (missing
    ``lynceus`` user/group, macOS host). The exception fires from inside
    the helper that raised; the partial ``ApplyReport`` is not returned
    in that case.
    """
    recorded: list[ApplyStep] = []

    def _emit(step: ApplyStep) -> None:
        recorded.append(step)
        if progress is not None:
            progress.record(step)

    # 1. write_config — render + atomic write + perms under --system.
    content = _frontend_render_config_yaml(_answers_from_config(config))
    if config.rules_path:
        # Single-render path: caller pre-decided alerting and pre-set
        # Config.rules_path, so emit it inline rather than appending
        # later. Same wire format as ``append_rules_path_to_config``
        # would produce; an operator reading either file sees the same
        # comment block.
        content = (
            content
            + "\n# --- Rules engine ---\n"
            + "# Path to rules.yaml, wired by lynceus-setup's\n"
            + "# enable-alerting flow. Unset → no rules load → no alerts fire.\n"
            + f"rules_path: {_yaml_str(config.rules_path)}\n"
        )
    write_config(target_path, content)
    if scope == "system":
        _apply_system_perms_to_file(target_path)
    _emit(
        ApplyStep(
            name="write_config",
            status="ok",
            message=f"Config written to {target_path}",
            detail={"path": str(target_path)},
        )
    )

    # 2. scaffold_severity_overrides — template (or keep existing) + perms.
    created = scaffold_severity_overrides(severity_overrides_path)
    if scope == "system":
        # Apply on every system run, not just when newly scaffolded:
        # an existing file inherited from a botched rc1 install may
        # still be 0600 root:root and unreadable by the daemon.
        _apply_system_perms_to_file(severity_overrides_path)
    _emit(
        ApplyStep(
            name="scaffold_severity_overrides",
            status="ok",
            message=(
                f"Scaffolded {severity_overrides_path}"
                if created
                else f"Kept existing {severity_overrides_path}"
            ),
            detail={
                "path": str(severity_overrides_path),
                "scaffolded": created,
            },
        )
    )

    # 3. + 4. create_data_dir / create_log_dir — mkdir + perms.
    # Defensive: ensure data + log directories exist before we hand off
    # to lynceus-import-argus. On a fresh box neither exists, and
    # sqlite refuses to open ``<missing>/lynceus.db`` with "unable to
    # open database file". Under --system the daemon (User=lynceus)
    # also needs to OWN these directories, otherwise the first poll
    # fails with "attempt to write a readonly database".
    data_dir = paths.default_data_dir(scope)
    log_dir = paths.default_log_dir(scope)
    data_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)
    if scope == "system":
        _apply_system_perms_to_dir(data_dir)
        _apply_system_perms_to_dir(log_dir)
    _emit(
        ApplyStep(
            name="create_data_dir",
            status="ok",
            message=f"Ready: {data_dir}",
            detail={"path": str(data_dir)},
        )
    )
    _emit(
        ApplyStep(
            name="create_log_dir",
            status="ok",
            message=f"Ready: {log_dir}",
            detail={"path": str(log_dir)},
        )
    )

    # 5. import_bundled_watchlist — subprocess (silent skip when absent).
    db_path = paths.default_db_path(scope)
    bundled_ok = False
    if run_bundled_import:
        bundled_ok, bundled_msg = _frontend_import_bundled_watchlist(
            db_path=str(db_path),
            override_file=str(severity_overrides_path),
        )
        if bundled_msg == BUNDLED_ABSENT_MESSAGE:
            _emit(
                ApplyStep(
                    name="import_bundled_watchlist",
                    status="skipped",
                    message="No bundled watchlist resource shipped",
                    detail={"reason": BUNDLED_ABSENT_MESSAGE},
                )
            )
        elif bundled_ok:
            _emit(
                ApplyStep(
                    name="import_bundled_watchlist",
                    status="ok",
                    message=bundled_msg,
                    detail={"db_path": str(db_path)},
                )
            )
        else:
            _emit(
                ApplyStep(
                    name="import_bundled_watchlist",
                    status="failed",
                    message=bundled_msg,
                    detail={"db_path": str(db_path)},
                )
            )
    else:
        _emit(
            ApplyStep(
                name="import_bundled_watchlist",
                status="skipped",
                message="run_bundled_import=False",
            )
        )

    # 6. chown_db_files — system-mode only, gated on import success.
    # The DB must be OWNED by lynceus (not just group-readable) so the
    # daemon can write to it — root:lynceus 0640 would let the first
    # poll fail with "attempt to write a readonly database". We reuse
    # the dir helper because it already does the ``lynceus:lynceus``
    # lookup; mode is overridden to 0o640 to keep DB files
    # non-executable.
    if scope == "system" and bundled_ok:
        chowned: list[str] = []
        for candidate in sorted(db_path.parent.glob(db_path.name + "*")):
            if candidate.is_file():
                _apply_system_perms_to_dir(candidate, mode=0o640)
                chowned.append(str(candidate))
        _emit(
            ApplyStep(
                name="chown_db_files",
                status="ok",
                message=(
                    f"Applied lynceus:lynceus 0640 to {len(chowned)} DB file(s)"
                ),
                detail={"files": chowned},
            )
        )
    else:
        # Operator-readable skip reason. The terse "scope=user"
        # string read as alarming in the v0.7.0 Linux smoke (the ⏭
        # icon next to a cryptic literal looked like a partial
        # failure). User-scope installs intentionally skip the chown
        # — the daemon runs as the operator, not the lynceus system
        # user, so file ownership is already correct without it.
        reason = (
            "Not applicable for user-scope install "
            "(DB files are already owned by the operator)"
            if scope != "system"
            else "Bundled Argus import did not complete; "
            "leaving DB files unchowned so the operator can re-run "
            "after fixing the underlying import failure"
        )
        _emit(
            ApplyStep(
                name="chown_db_files",
                status="skipped",
                message=reason,
            )
        )

    # 7. write_rules — render + atomic write + perms.
    # Gated on BOTH enabled_rule_types non-empty AND Config.rules_path
    # set. The CLI frontend in v0.6.x runs its alerting prompts AFTER
    # apply_config returns (so per-type counts reflect the just-imported
    # DB), so this branch is only exercised by callers that pre-decide
    # alerting — the eventual web wizard, and Touch 2's new tests.
    if enabled_rule_types and config.rules_path:
        rules_target = Path(config.rules_path)
        rules_target.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write(rules_target, render_rules_yaml(enabled_rule_types))
        if scope == "system":
            _apply_system_perms_to_file(rules_target)
        active = sorted(
            rt for (_n, rt, _pt, _l, _d) in DELEGATION_RULES if rt in enabled_rule_types
        )
        _emit(
            ApplyStep(
                name="write_rules",
                status="ok",
                message=(
                    f"Wrote rules.yaml to {rules_target} with "
                    f"{len(active)} active rule(s)"
                ),
                detail={"path": str(rules_target), "enabled": active},
            )
        )
    else:
        if enabled_rule_types and not config.rules_path:
            reason = "enabled_rule_types provided but Config.rules_path not set"
        elif config.rules_path and not enabled_rule_types:
            reason = "Config.rules_path set but enabled_rule_types empty"
        else:
            reason = "Alerting not enabled by caller"
        _emit(
            ApplyStep(
                name="write_rules",
                status="skipped",
                message=reason,
            )
        )

    return ApplyReport(steps=tuple(recorded))
