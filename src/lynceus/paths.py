"""Canonical config / data / log directory helpers.

Single source of truth for where Lynceus expects to find or write its
files under each scope. The packaging layer (``install.sh``), the setup
wizard, and the quickstart launcher all consult these helpers so we do
not drift between hardcoded ``lynceus.db`` strings and FHS-correct
locations.

Linux user:    XDG (``$XDG_*_HOME`` or ``~/.config``, ``~/.local/share``,
               ``~/.local/state``).
Linux system:  ``/etc/lynceus``, ``/var/lib/lynceus``, ``/var/log/lynceus``.
macOS user:    ``~/Library/Application Support/Lynceus`` for both config
               and data; ``~/Library/Logs/Lynceus`` for logs.
macOS system:  unsupported; raises ``NotImplementedError``.
Windows user:  ``%APPDATA%\\Lynceus``, ``%LOCALAPPDATA%\\Lynceus``,
               ``%LOCALAPPDATA%\\Lynceus\\Logs``.
Windows system: unsupported; raises ``NotImplementedError``.

The existing CLI tools (``lynceus``, ``lynceus-ui``, ``lynceus-import-argus``)
keep their explicit ``--db`` / ``--config`` flags. These helpers only
supply better defaults inside the orchestration layer.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Literal

Scope = Literal["user", "system"]

_VALID_SCOPES = ("user", "system")
_APP_NAME = "Lynceus"  # Used in macOS / Windows path components.
_PKG_DIR = "lynceus"  # Used in Linux/XDG path components.


# --- platform indirection --------------------------------------------------


def _platform() -> str:
    """Return one of ``"linux"``, ``"darwin"``, ``"windows"``.

    Indirection point for tests — monkeypatch this rather than
    ``sys.platform`` so we don't have to mock the whole ``Path`` machinery.
    """
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "darwin":
        return "darwin"
    if sys.platform in ("win32", "cygwin"):
        return "windows"
    return sys.platform


def _check_scope(scope: str) -> None:
    if scope not in _VALID_SCOPES:
        raise ValueError(f"scope must be one of {_VALID_SCOPES}; got {scope!r}")


def _system_unsupported(platform: str) -> None:
    raise NotImplementedError(
        f"--system scope is Linux-only; not supported on {platform}. "
        "Use --user, or run on a Linux host."
    )


# --- directory helpers -----------------------------------------------------


def default_config_dir(scope: Scope) -> Path:
    """Directory holding ``lynceus.yaml`` and ``severity_overrides.yaml``."""
    _check_scope(scope)
    plat = _platform()
    if plat == "linux":
        if scope == "system":
            return Path("/etc") / _PKG_DIR
        xdg = os.environ.get("XDG_CONFIG_HOME")
        base = Path(xdg) if xdg else Path.home() / ".config"
        return base / _PKG_DIR
    if plat == "darwin":
        if scope == "system":
            _system_unsupported("macOS")
        return Path.home() / "Library" / "Application Support" / _APP_NAME
    if plat == "windows":
        if scope == "system":
            _system_unsupported("Windows")
        appdata = os.environ.get("APPDATA")
        base = Path(appdata) if appdata else Path.home() / "AppData" / "Roaming"
        return base / _APP_NAME
    # Unknown platform: fall back to user-home dotfile so callers still
    # get something writable instead of a crash.
    return Path.home() / f".{_PKG_DIR}"


def default_data_dir(scope: Scope) -> Path:
    """Directory holding the SQLite database and other persistent state."""
    _check_scope(scope)
    plat = _platform()
    if plat == "linux":
        if scope == "system":
            return Path("/var/lib") / _PKG_DIR
        xdg = os.environ.get("XDG_DATA_HOME")
        base = Path(xdg) if xdg else Path.home() / ".local" / "share"
        return base / _PKG_DIR
    if plat == "darwin":
        if scope == "system":
            _system_unsupported("macOS")
        return Path.home() / "Library" / "Application Support" / _APP_NAME
    if plat == "windows":
        if scope == "system":
            _system_unsupported("Windows")
        local = os.environ.get("LOCALAPPDATA")
        base = Path(local) if local else Path.home() / "AppData" / "Local"
        return base / _APP_NAME
    return Path.home() / f".{_PKG_DIR}"


def default_log_dir(scope: Scope) -> Path:
    """Directory for daemon / UI log files."""
    _check_scope(scope)
    plat = _platform()
    if plat == "linux":
        if scope == "system":
            return Path("/var/log") / _PKG_DIR
        xdg = os.environ.get("XDG_STATE_HOME")
        base = Path(xdg) if xdg else Path.home() / ".local" / "state"
        return base / _PKG_DIR
    if plat == "darwin":
        if scope == "system":
            _system_unsupported("macOS")
        return Path.home() / "Library" / "Logs" / _APP_NAME
    if plat == "windows":
        if scope == "system":
            _system_unsupported("Windows")
        local = os.environ.get("LOCALAPPDATA")
        base = Path(local) if local else Path.home() / "AppData" / "Local"
        return base / _APP_NAME / "Logs"
    return Path.home() / f".{_PKG_DIR}" / "logs"


# --- composite file paths --------------------------------------------------


def default_db_path(scope: Scope) -> Path:
    """Canonical SQLite database path: ``<data_dir>/lynceus.db``."""
    return default_data_dir(scope) / "lynceus.db"


def default_config_path(scope: Scope) -> Path:
    """Canonical config file path: ``<config_dir>/lynceus.yaml``."""
    return default_config_dir(scope) / "lynceus.yaml"


def default_overrides_path(scope: Scope) -> Path:
    """Canonical severity overrides path: ``<config_dir>/severity_overrides.yaml``."""
    return default_config_dir(scope) / "severity_overrides.yaml"


def default_allowlist_path(scope: Scope) -> Path:
    """Canonical allowlist path: ``<config_dir>/allowlist.yaml``.

    Scaffolded as an empty-but-commented YAML file during
    ``lynceus-setup`` apply so the dashboard's /allowlist page
    reports an existing-but-empty allowlist instead of the
    misleading "No allowlist_path configured" empty state.
    """
    return default_config_dir(scope) / "allowlist.yaml"


def resolve_existing_config() -> Path | None:
    """Return the first existing canonical config file, preferring user scope.

    Probes ``default_config_path("user")`` first, then
    ``default_config_path("system")``. Returns ``None`` when neither exists.

    On macOS / Windows the system-scope helper raises
    ``NotImplementedError`` — that case is treated as "no system path to
    probe" and the function returns ``None`` if the user path is also
    absent. Callers that need the probed paths for an error message should
    re-derive them rather than rely on this helper to surface them.
    """
    user_path = default_config_path("user")
    if user_path.exists():
        return user_path
    try:
        system_path = default_config_path("system")
    except NotImplementedError:
        return None
    if system_path.exists():
        return system_path
    return None


def classify_config_scope(path: Path | str) -> Scope | None:
    """Return the canonical scope (``"user"`` / ``"system"``) whose config
    path equals ``path``, or ``None`` when ``path`` is a custom location
    matching neither.

    Used for the startup scope label (so an operator sees at a glance which
    scope's config the daemon loaded) and for cross-scope shadow detection.
    Both sides are resolved before comparison so a symlinked or ``..``-laden
    ``--config`` argument that points at the canonical file is still
    recognised rather than mislabelled "custom". A scope whose default path
    is unsupported on this platform (``system`` on macOS / Windows) simply
    doesn't match.
    """
    target = Path(path)
    try:
        resolved_target = target.resolve()
    except OSError:
        resolved_target = target
    for scope in _VALID_SCOPES:
        try:
            candidate = default_config_path(scope)
        except NotImplementedError:
            continue
        try:
            resolved_candidate = candidate.resolve()
        except OSError:
            resolved_candidate = candidate
        if resolved_candidate == resolved_target:
            return scope  # type: ignore[return-value]
    return None


def find_shadowing_config(active_path: Path | str) -> Path | None:
    """Return the canonical config in the scope OTHER than ``active_path``'s
    when both exist — i.e. the file ``active_path`` is silently shadowing.

    Returns ``None`` when ``active_path`` is a custom location (matches no
    canonical scope), when the other scope's file does not exist, or when the
    other scope is unsupported on this platform. A pure existence probe: does
    not read or load either file.
    """
    scope = classify_config_scope(active_path)
    if scope is None:
        return None
    other: Scope = "system" if scope == "user" else "user"
    try:
        other_path = default_config_path(other)
    except NotImplementedError:
        return None
    return other_path if other_path.exists() else None


def describe_shadowing(active_path: Path | str) -> str | None:
    """Build the one-line cross-scope shadowing warning, or ``None`` when
    there is nothing to warn about.

    When ``active_path`` is a canonical user/system config AND the OTHER
    canonical scope also holds a config, that other file is being silently
    ignored — the exact footgun behind a stale-key death ("I edited /etc but
    the daemon read ~/.config"). The message names BOTH files, says which is
    in use, and — when both mtimes are readable — flags which copy is newer,
    since an ignored-but-newer copy almost always means a recent edit landed
    in the scope that isn't being used. Shared by the daemon and quickstart so
    both surfaces read identically. Pure: probes existence + mtime, never
    reads contents, never raises.
    """
    other = find_shadowing_config(active_path)
    if other is None:
        return None
    active = Path(active_path)
    active_label = _scope_label(classify_config_scope(active_path))
    other_label = _scope_label(classify_config_scope(other))
    newer_clause = ""
    try:
        active_mtime: float | None = active.stat().st_mtime
        other_mtime: float | None = other.stat().st_mtime
    except OSError:
        active_mtime = other_mtime = None
    if active_mtime is not None and other_mtime is not None:
        if other_mtime > active_mtime:
            newer_clause = (
                f" — the ignored {other_label} copy is NEWER, which usually means "
                "a recent edit landed in the scope that isn't being used"
            )
        elif active_mtime > other_mtime:
            newer_clause = f" — the in-use {active_label} copy is newer"
    return (
        f"config scope shadowing: using {active} ({active_label}); a config also "
        f"exists at {other} ({other_label}) and is being IGNORED{newer_clause}. "
        "If you meant to use the ignored one, point --config at it or "
        "consolidate to a single scope."
    )


def _scope_label(scope: Scope | None) -> str:
    """Human label for a classify_config_scope() result: ``"user scope"`` /
    ``"system scope"`` / ``"custom path"``."""
    return f"{scope} scope" if scope else "custom path"
