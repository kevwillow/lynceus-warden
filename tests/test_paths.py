"""Tests for lynceus.paths — canonical config/data/log directory helpers.

These helpers are the single source of truth for where Lynceus expects to
find or write its config, database, logs, and severity overrides under
each scope (user vs system). Cross-platform branches matter: on Linux we
use XDG, on macOS we use ~/Library, on Windows we use %APPDATA% /
%LOCALAPPDATA%, and ``--system`` is Linux-only.
"""

from __future__ import annotations

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
