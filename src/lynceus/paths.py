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
