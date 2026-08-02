"""Tests for lynceus.paths — canonical config/data/log directory helpers.

These helpers are the single source of truth for where Lynceus expects to
find or write its config, database, logs, and severity overrides under
each scope (user vs system). Cross-platform branches matter: on Linux we
use XDG, on macOS we use ~/Library, on Windows we use %APPDATA% /
%LOCALAPPDATA%, and ``--system`` is Linux-only.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from lynceus import paths

# --- helpers ---------------------------------------------------------------


def _force_linux(monkeypatch):
    monkeypatch.setattr(paths, "_platform", lambda: "linux")


def _force_macos(monkeypatch):
    monkeypatch.setattr(paths, "_platform", lambda: "darwin")


def _force_windows(monkeypatch):
    monkeypatch.setattr(paths, "_platform", lambda: "windows")


# --- linux user scope ------------------------------------------------------


def test_linux_user_config_dir_uses_xdg_when_set(monkeypatch):
    _force_linux(monkeypatch)
    monkeypatch.setenv("XDG_CONFIG_HOME", "/tmp/cfg")
    assert paths.default_config_dir("user") == Path("/tmp/cfg/lynceus")


def test_linux_user_config_dir_falls_back_to_dot_config(monkeypatch):
    _force_linux(monkeypatch)
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: Path("/home/op")))
    assert paths.default_config_dir("user") == Path("/home/op/.config/lynceus")


def test_linux_user_data_dir_uses_xdg_when_set(monkeypatch):
    _force_linux(monkeypatch)
    monkeypatch.setenv("XDG_DATA_HOME", "/tmp/data")
    assert paths.default_data_dir("user") == Path("/tmp/data/lynceus")


def test_linux_user_data_dir_falls_back_to_local_share(monkeypatch):
    _force_linux(monkeypatch)
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: Path("/home/op")))
    assert paths.default_data_dir("user") == Path("/home/op/.local/share/lynceus")


def test_linux_user_log_dir_uses_xdg_state(monkeypatch):
    _force_linux(monkeypatch)
    monkeypatch.setenv("XDG_STATE_HOME", "/tmp/state")
    assert paths.default_log_dir("user") == Path("/tmp/state/lynceus")


def test_linux_user_log_dir_falls_back_to_local_state(monkeypatch):
    _force_linux(monkeypatch)
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: Path("/home/op")))
    assert paths.default_log_dir("user") == Path("/home/op/.local/state/lynceus")


# --- linux system scope ----------------------------------------------------


def test_linux_system_paths_are_fhs(monkeypatch):
    _force_linux(monkeypatch)
    assert paths.default_config_dir("system") == Path("/etc/lynceus")
    assert paths.default_data_dir("system") == Path("/var/lib/lynceus")
    assert paths.default_log_dir("system") == Path("/var/log/lynceus")


# --- macOS user scope ------------------------------------------------------


def test_macos_user_config_and_data_share_app_support(monkeypatch):
    _force_macos(monkeypatch)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: Path("/Users/op")))
    expected = Path("/Users/op/Library/Application Support/Lynceus")
    assert paths.default_config_dir("user") == expected
    assert paths.default_data_dir("user") == expected


def test_macos_user_logs_go_to_library_logs(monkeypatch):
    _force_macos(monkeypatch)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: Path("/Users/op")))
    assert paths.default_log_dir("user") == Path("/Users/op/Library/Logs/Lynceus")


# --- macOS system scope is unsupported -------------------------------------


def test_macos_system_scope_raises(monkeypatch):
    _force_macos(monkeypatch)
    with pytest.raises(NotImplementedError):
        paths.default_config_dir("system")
    with pytest.raises(NotImplementedError):
        paths.default_data_dir("system")
    with pytest.raises(NotImplementedError):
        paths.default_log_dir("system")


# --- windows user scope ----------------------------------------------------


def test_windows_user_config_dir_uses_appdata(monkeypatch):
    _force_windows(monkeypatch)
    monkeypatch.setenv("APPDATA", r"C:\Users\op\AppData\Roaming")
    assert paths.default_config_dir("user") == Path(r"C:\Users\op\AppData\Roaming") / "Lynceus"


def test_windows_user_data_dir_uses_localappdata(monkeypatch):
    _force_windows(monkeypatch)
    monkeypatch.setenv("LOCALAPPDATA", r"C:\Users\op\AppData\Local")
    assert paths.default_data_dir("user") == Path(r"C:\Users\op\AppData\Local") / "Lynceus"


def test_windows_user_log_dir_under_localappdata_logs(monkeypatch):
    _force_windows(monkeypatch)
    monkeypatch.setenv("LOCALAPPDATA", r"C:\Users\op\AppData\Local")
    expected = Path(r"C:\Users\op\AppData\Local") / "Lynceus" / "Logs"
    assert paths.default_log_dir("user") == expected


# --- windows system scope is unsupported -----------------------------------


def test_windows_system_scope_raises(monkeypatch):
    _force_windows(monkeypatch)
    with pytest.raises(NotImplementedError):
        paths.default_config_dir("system")


# --- composite path helpers ------------------------------------------------


def test_default_db_path_is_data_dir_lynceus_db(monkeypatch):
    _force_linux(monkeypatch)
    monkeypatch.setenv("XDG_DATA_HOME", "/tmp/data")
    assert paths.default_db_path("user") == Path("/tmp/data/lynceus/lynceus.db")
    assert paths.default_db_path("system") == Path("/var/lib/lynceus/lynceus.db")


def test_default_config_path_is_config_dir_lynceus_yaml(monkeypatch):
    _force_linux(monkeypatch)
    monkeypatch.setenv("XDG_CONFIG_HOME", "/tmp/cfg")
    assert paths.default_config_path("user") == Path("/tmp/cfg/lynceus/lynceus.yaml")
    assert paths.default_config_path("system") == Path("/etc/lynceus/lynceus.yaml")


def test_default_overrides_path_is_config_dir_severity_yaml(monkeypatch):
    _force_linux(monkeypatch)
    monkeypatch.setenv("XDG_CONFIG_HOME", "/tmp/cfg")
    assert paths.default_overrides_path("user") == Path("/tmp/cfg/lynceus/severity_overrides.yaml")
    assert paths.default_overrides_path("system") == Path("/etc/lynceus/severity_overrides.yaml")


# --- input validation ------------------------------------------------------


def test_invalid_scope_rejected(monkeypatch):
    _force_linux(monkeypatch)
    with pytest.raises(ValueError):
        paths.default_config_dir("global")  # type: ignore[arg-type]


# --- resolve_existing_config: user-mode preferred, system fallback, none ---


def test_resolve_existing_config_returns_user_path_when_only_user_exists(monkeypatch, tmp_path):
    user_path = tmp_path / "user" / "lynceus.yaml"
    system_path = tmp_path / "system" / "lynceus.yaml"
    user_path.parent.mkdir(parents=True)
    user_path.write_text("ui_bind_port: 1\n")

    monkeypatch.setattr(
        paths,
        "default_config_path",
        lambda scope: user_path if scope == "user" else system_path,
    )
    assert paths.resolve_existing_config() == user_path


def test_resolve_existing_config_returns_system_path_when_only_system_exists(monkeypatch, tmp_path):
    user_path = tmp_path / "user" / "lynceus.yaml"
    system_path = tmp_path / "system" / "lynceus.yaml"
    system_path.parent.mkdir(parents=True)
    system_path.write_text("ui_bind_port: 1\n")

    monkeypatch.setattr(
        paths,
        "default_config_path",
        lambda scope: user_path if scope == "user" else system_path,
    )
    assert paths.resolve_existing_config() == system_path


def test_resolve_existing_config_prefers_user_when_both_exist(monkeypatch, tmp_path):
    user_path = tmp_path / "user" / "lynceus.yaml"
    system_path = tmp_path / "system" / "lynceus.yaml"
    user_path.parent.mkdir(parents=True)
    system_path.parent.mkdir(parents=True)
    user_path.write_text("ui_bind_port: 1\n")
    system_path.write_text("ui_bind_port: 2\n")

    monkeypatch.setattr(
        paths,
        "default_config_path",
        lambda scope: user_path if scope == "user" else system_path,
    )
    assert paths.resolve_existing_config() == user_path


def test_resolve_existing_config_returns_none_when_neither_exists(monkeypatch, tmp_path):
    user_path = tmp_path / "user" / "lynceus.yaml"
    system_path = tmp_path / "system" / "lynceus.yaml"

    monkeypatch.setattr(
        paths,
        "default_config_path",
        lambda scope: user_path if scope == "user" else system_path,
    )
    assert paths.resolve_existing_config() is None


def test_resolve_existing_config_swallows_system_unsupported(monkeypatch, tmp_path):
    """On macOS / Windows ``default_config_path("system")`` raises
    ``NotImplementedError``. The resolver treats that as 'no system probe'
    and returns ``None`` if the user path is also absent — it must not
    propagate the error to a caller that just wants to know whether any
    config was discoverable."""
    user_path = tmp_path / "user" / "lynceus.yaml"

    def fake_default_config_path(scope):
        if scope == "user":
            return user_path
        raise NotImplementedError("unsupported on this platform")

    monkeypatch.setattr(paths, "default_config_path", fake_default_config_path)
    assert paths.resolve_existing_config() is None


def test_resolve_existing_config_treats_unreadable_system_path_as_absent(
    monkeypatch, tmp_path
):
    """Regression for the Pi --system crash: ``/etc/lynceus`` is
    ``0750 root:lynceus``, so a non-``lynceus``-group account can't stat()
    inside it and ``Path.exists()`` on the system config raises
    ``PermissionError`` (it only maps ``FileNotFoundError`` → ``False``).
    Before the fix this propagated straight out of
    ``resolve_existing_config`` and aborted ``lynceus-quickstart``; it must
    now be treated as 'no system config' and return ``None``."""
    user_path = tmp_path / "user" / "lynceus.yaml"
    system_path = tmp_path / "system" / "lynceus.yaml"
    monkeypatch.setattr(
        paths,
        "default_config_path",
        lambda scope: user_path if scope == "user" else system_path,
    )

    real_exists = Path.exists

    def fake_exists(self):
        if self == system_path:
            raise PermissionError(13, "Permission denied")
        return real_exists(self)

    monkeypatch.setattr(Path, "exists", fake_exists)
    # User path genuinely absent; system path raises EACCES → treated absent.
    assert paths.resolve_existing_config() is None


def test_resolve_existing_config_falls_through_when_user_path_unreadable(
    monkeypatch, tmp_path
):
    """An EACCES on the *user*-scope probe must not abort the resolver
    either — it should fall through to a readable system config."""
    user_path = tmp_path / "user" / "lynceus.yaml"
    system_path = tmp_path / "system" / "lynceus.yaml"
    system_path.parent.mkdir(parents=True)
    system_path.write_text("ui_bind_port: 1\n")
    monkeypatch.setattr(
        paths,
        "default_config_path",
        lambda scope: user_path if scope == "user" else system_path,
    )

    real_exists = Path.exists

    def fake_exists(self):
        if self == user_path:
            raise PermissionError(13, "Permission denied")
        return real_exists(self)

    monkeypatch.setattr(Path, "exists", fake_exists)
    assert paths.resolve_existing_config() == system_path


# --- _safe_exists: EACCES-tolerant existence probe -------------------------


def test_safe_exists_true_for_existing_file(tmp_path):
    p = tmp_path / "present"
    p.write_text("x")
    assert paths._safe_exists(p) is True


def test_safe_exists_false_for_missing_file(tmp_path):
    assert paths._safe_exists(tmp_path / "nope") is False


def test_safe_exists_false_on_permission_error(monkeypatch, tmp_path):
    """The whole point of the helper: a PermissionError from an
    untraversable parent directory becomes ``False``, not a crash."""

    def boom(self):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(Path, "exists", boom)
    assert paths._safe_exists(tmp_path / "blocked") is False


# --- classify_config_scope: scope label for the startup provenance line ----


def _stub_scope_paths(monkeypatch, tmp_path):
    user_path = tmp_path / "user" / "lynceus.yaml"
    system_path = tmp_path / "system" / "lynceus.yaml"
    user_path.parent.mkdir(parents=True)
    system_path.parent.mkdir(parents=True)
    user_path.write_text("ui_bind_port: 1\n")
    system_path.write_text("ui_bind_port: 2\n")
    monkeypatch.setattr(
        paths,
        "default_config_path",
        lambda scope: user_path if scope == "user" else system_path,
    )
    return user_path, system_path


def test_classify_config_scope_user(monkeypatch, tmp_path):
    user_path, _ = _stub_scope_paths(monkeypatch, tmp_path)
    assert paths.classify_config_scope(user_path) == "user"


def test_classify_config_scope_system(monkeypatch, tmp_path):
    _, system_path = _stub_scope_paths(monkeypatch, tmp_path)
    assert paths.classify_config_scope(system_path) == "system"


def test_classify_config_scope_custom_returns_none(monkeypatch, tmp_path):
    _stub_scope_paths(monkeypatch, tmp_path)
    custom = tmp_path / "elsewhere" / "lynceus.yaml"
    custom.parent.mkdir(parents=True)
    custom.write_text("ui_bind_port: 3\n")
    assert paths.classify_config_scope(custom) is None


def test_classify_config_scope_accepts_str_and_resolves(monkeypatch, tmp_path):
    """A ``--config`` argument with a ``..`` segment that points at the
    canonical user file is still recognised as user scope, not 'custom'."""
    user_path, _ = _stub_scope_paths(monkeypatch, tmp_path)
    indirect = str(user_path.parent / ".." / "user" / "lynceus.yaml")
    assert paths.classify_config_scope(indirect) == "user"


def test_classify_config_scope_system_unsupported_does_not_crash(monkeypatch, tmp_path):
    """On macOS / Windows the system probe raises NotImplementedError; the
    classifier must skip that scope and still classify the user path."""
    user_path = tmp_path / "user" / "lynceus.yaml"
    user_path.parent.mkdir(parents=True)
    user_path.write_text("ui_bind_port: 1\n")

    def fake_default_config_path(scope):
        if scope == "user":
            return user_path
        raise NotImplementedError("unsupported on this platform")

    monkeypatch.setattr(paths, "default_config_path", fake_default_config_path)
    assert paths.classify_config_scope(user_path) == "user"
    assert paths.classify_config_scope(tmp_path / "nope.yaml") is None


# --- find_shadowing_config / describe_shadowing: cross-scope shadow warning -


def test_find_shadowing_config_returns_other_when_both_exist(monkeypatch, tmp_path):
    user_path, system_path = _stub_scope_paths(monkeypatch, tmp_path)
    assert paths.find_shadowing_config(user_path) == system_path
    assert paths.find_shadowing_config(system_path) == user_path


def test_find_shadowing_config_none_when_other_absent(monkeypatch, tmp_path):
    user_path = tmp_path / "user" / "lynceus.yaml"
    system_path = tmp_path / "system" / "lynceus.yaml"
    user_path.parent.mkdir(parents=True)
    user_path.write_text("ui_bind_port: 1\n")  # only user exists
    monkeypatch.setattr(
        paths,
        "default_config_path",
        lambda scope: user_path if scope == "user" else system_path,
    )
    assert paths.find_shadowing_config(user_path) is None


def test_find_shadowing_config_none_for_custom_path(monkeypatch, tmp_path):
    _stub_scope_paths(monkeypatch, tmp_path)
    custom = tmp_path / "elsewhere" / "lynceus.yaml"
    custom.parent.mkdir(parents=True)
    custom.write_text("ui_bind_port: 9\n")
    assert paths.find_shadowing_config(custom) is None


def test_describe_shadowing_names_both_and_marks_ignored(monkeypatch, tmp_path):
    user_path, system_path = _stub_scope_paths(monkeypatch, tmp_path)
    msg = paths.describe_shadowing(user_path)
    assert msg is not None
    assert str(user_path) in msg and str(system_path) in msg
    assert "user scope" in msg and "system scope" in msg
    assert "IGNORED" in msg


def test_describe_shadowing_flags_ignored_copy_as_newer(monkeypatch, tmp_path):
    user_path, system_path = _stub_scope_paths(monkeypatch, tmp_path)
    # In-use is user (resolved first); make the IGNORED system copy newer.
    os.utime(user_path, (1_000_000, 1_000_000))
    os.utime(system_path, (2_000_000, 2_000_000))
    msg = paths.describe_shadowing(user_path)
    assert msg is not None
    assert "NEWER" in msg


def test_describe_shadowing_none_when_no_other_scope(monkeypatch, tmp_path):
    user_path = tmp_path / "user" / "lynceus.yaml"
    system_path = tmp_path / "system" / "lynceus.yaml"
    user_path.parent.mkdir(parents=True)
    user_path.write_text("ui_bind_port: 1\n")
    monkeypatch.setattr(
        paths,
        "default_config_path",
        lambda scope: user_path if scope == "user" else system_path,
    )
    assert paths.describe_shadowing(user_path) is None


def _raise_eacces_on(monkeypatch, target):
    """Make ``Path.stat`` raise ``PermissionError`` for ``target`` only,
    simulating a root-owned, non-traversable parent dir (a regular user
    probing ``/etc/lynceus``). Every other path's ``stat`` is left untouched.
    ``Path.resolve`` uses ``os.readlink``/``os.lstat`` rather than ``Path.stat``,
    so scope classification still works."""
    real_stat = Path.stat

    def fake_stat(self, *args, **kwargs):
        if self == target:
            raise PermissionError(13, "Permission denied")
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", fake_stat)


def test_find_shadowing_config_treats_unreadable_other_as_present(monkeypatch, tmp_path):
    """Regression for the quickstart crash: a regular user probing a root-owned
    /etc/lynceus makes ``Path.exists()`` PROPAGATE PermissionError. The check
    must treat EACCES as 'present (unreadable)' and still flag the shadow, not
    crash. Fails against the old unguarded ``other_path.exists()``."""
    user_path, system_path = _stub_scope_paths(monkeypatch, tmp_path)
    _raise_eacces_on(monkeypatch, system_path)
    # (a) no exception; (b) the unreadable other-scope file is still a shadow.
    assert paths.find_shadowing_config(user_path) == system_path


def test_describe_shadowing_hedges_when_other_unreadable(monkeypatch, tmp_path):
    """The shadow warning must still FIRE when the other-scope config is
    present-but-unreadable, with hedged wording instead of an mtime comparison
    (and crucially without crashing)."""
    user_path, system_path = _stub_scope_paths(monkeypatch, tmp_path)
    _raise_eacces_on(monkeypatch, system_path)
    msg = paths.describe_shadowing(user_path)
    assert msg is not None
    assert str(system_path) in msg
    assert "unreadable" in msg
    assert "IGNORED" in msg
