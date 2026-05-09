"""Tests for lynceus.cli.setup — the interactive first-run configuration wizard."""

from __future__ import annotations

import argparse
import contextlib
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

from lynceus.cli import setup as wiz

# ---- helpers ---------------------------------------------------------------


def _args(**overrides):
    """Build an argparse.Namespace with sensible defaults for the wizard."""
    base = dict(
        user=False,
        system=False,
        reconfigure=False,
        output=None,
        skip_probes=True,  # default tests off-network unless explicitly testing probes
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def _input_seq(answers):
    """Create an input function that returns successive entries from a list."""
    it = iter(answers)

    def _input(prompt=""):
        try:
            return next(it)
        except StopIteration as exc:  # pragma: no cover - test bug
            raise AssertionError(
                f"input() called past end of provided answers; prompt={prompt!r}"
            ) from exc

    return _input


def _getpass_seq(answers):
    """Create a getpass function that returns successive entries from a list."""
    it = iter(answers)

    def _gp(prompt=""):
        try:
            return next(it)
        except StopIteration as exc:  # pragma: no cover - test bug
            raise AssertionError(
                f"getpass() called past end of provided answers; prompt={prompt!r}"
            ) from exc

    return _gp


def _full_input_sequence(*, interface=None, ntfy_topic="lynceus-deadbeef"):
    """Default end-to-end input sequence used by the smoke test and probe variants.

    Tests using this helper must monkeypatch ``enumerate_bluetooth_adapters``
    to return ``None`` (or use ``_stub_path_resolution`` which does it), so
    no Bluetooth-related inputs need to be threaded in.
    """
    seq = [
        "",  # Kismet URL: accept default
    ]
    if interface == "numbered":
        seq.append("1")
    elif interface is None:
        seq.append("wlan0")  # free-form fallback
    elif interface == "freeform":
        seq.append("wlan0")
    seq += [
        "",  # probe_ssids: default (N -> False)
        "",  # ble_friendly_names: default (Y -> True)
        "https://ntfy.sh",  # ntfy URL (non-empty so we don't skip ntfy)
        ntfy_topic,  # ntfy topic
        "",  # RSSI: accept default
        "",  # severity overrides path: accept default
    ]
    return seq


# ---- pre-flight: existing config -------------------------------------------


def test_preflight_refuses_existing_config_without_reconfigure(tmp_path):
    target = tmp_path / "lynceus.yaml"
    target.write_text("kismet_url: x\n")
    err = wiz.preflight_existing(target, reconfigure=False)
    assert err is not None
    assert "Config already exists at" in err
    assert "--reconfigure" in err


def test_preflight_allows_existing_config_with_reconfigure(tmp_path):
    target = tmp_path / "lynceus.yaml"
    target.write_text("kismet_url: x\n")
    assert wiz.preflight_existing(target, reconfigure=True) is None


def test_preflight_allows_when_no_config_yet(tmp_path):
    target = tmp_path / "lynceus.yaml"
    assert wiz.preflight_existing(target, reconfigure=False) is None


# ---- pre-flight: scope/privilege -------------------------------------------


def test_system_on_posix_without_root_rejected(monkeypatch, tmp_path):
    monkeypatch.setattr(wiz, "_is_windows", lambda: False)
    monkeypatch.setattr(wiz, "_euid", lambda: 1000)
    err = wiz.preflight_scope("system", tmp_path / "lynceus.yaml")
    assert err is not None
    assert "sudo" in err
    assert "--user" in err


def test_system_on_posix_with_root_accepted(monkeypatch, tmp_path):
    monkeypatch.setattr(wiz, "_is_windows", lambda: False)
    monkeypatch.setattr(wiz, "_euid", lambda: 0)
    assert wiz.preflight_scope("system", tmp_path / "lynceus.yaml") is None


def test_user_scope_does_not_require_root(monkeypatch, tmp_path):
    monkeypatch.setattr(wiz, "_is_windows", lambda: False)
    monkeypatch.setattr(wiz, "_euid", lambda: 1000)
    assert wiz.preflight_scope("user", tmp_path / "lynceus.yaml") is None


def test_system_on_windows_without_writable_parent_rejected(monkeypatch, tmp_path):
    monkeypatch.setattr(wiz, "_is_windows", lambda: True)
    monkeypatch.setattr(wiz, "is_writable_system_path", lambda p: False)
    err = wiz.preflight_scope("system", tmp_path / "lynceus.yaml")
    assert err is not None
    assert "Administrator" in err


def test_user_is_default_when_not_root():
    args = _args()
    assert wiz.determine_scope(args) == "user"


def test_system_chosen_when_flag_set():
    args = _args(system=True)
    assert wiz.determine_scope(args) == "system"


# ---- path resolution -------------------------------------------------------


def test_path_user_linux_branch(monkeypatch):
    """Linux/macOS branch: ends with .config/lynceus/lynceus.yaml under home."""
    monkeypatch.setattr(wiz, "_is_windows", lambda: False)
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    p = wiz.resolve_config_path("user", None)
    assert p.parts[-3:] == (".config", "lynceus", "lynceus.yaml")


def test_path_user_linux_respects_xdg(monkeypatch):
    monkeypatch.setattr(wiz, "_is_windows", lambda: False)
    monkeypatch.setenv("XDG_CONFIG_HOME", "/var/operator/config")
    p = wiz.resolve_config_path("user", None)
    # Components ".../lynceus/lynceus.yaml"
    assert p.parts[-2:] == ("lynceus", "lynceus.yaml")
    assert "/var/operator/config" in p.as_posix()


def test_path_user_windows_branch(monkeypatch):
    """Windows branch: APPDATA/Lynceus/lynceus.yaml — verify components."""
    monkeypatch.setattr(wiz, "_is_windows", lambda: True)
    monkeypatch.setenv("APPDATA", "/some/appdata/dir")
    p = wiz.resolve_config_path("user", None)
    assert p.parts[-2:] == ("Lynceus", "lynceus.yaml")
    assert "appdata" in p.as_posix().lower()


def test_path_system_linux_branch(monkeypatch):
    monkeypatch.setattr(wiz, "_is_windows", lambda: False)
    p = wiz.resolve_config_path("system", None)
    assert p.as_posix() == "/etc/lynceus/lynceus.yaml"


def test_path_system_windows_branch(monkeypatch):
    monkeypatch.setattr(wiz, "_is_windows", lambda: True)
    monkeypatch.setenv("ProgramData", "/some/programdata")
    p = wiz.resolve_config_path("system", None)
    assert p.parts[-2:] == ("Lynceus", "lynceus.yaml")
    assert "programdata" in p.as_posix().lower()


def test_path_output_overrides_user(tmp_path):
    custom = str(tmp_path / "elsewhere.yaml")
    p = wiz.resolve_config_path("user", custom)
    assert p == Path(custom)


def test_path_output_overrides_system(tmp_path):
    custom = str(tmp_path / "elsewhere.yaml")
    p = wiz.resolve_config_path("system", custom)
    assert p == Path(custom)


# ---- prompt helpers --------------------------------------------------------


def test_prompt_default_accepts_default_on_empty():
    val = wiz.prompt_default("Q", default="hello", input_fn=_input_seq([""]))
    assert val == "hello"


def test_prompt_default_accepts_custom_value():
    val = wiz.prompt_default("Q", default="hello", input_fn=_input_seq(["world"]))
    assert val == "world"


def test_prompt_required_rejects_empty_then_accepts(capsys):
    val = wiz.prompt_default(
        "Q", default=None, required=True, input_fn=_input_seq(["", "  ", "value"])
    )
    assert val == "value"


def test_prompt_secret_required_rejects_empty(capsys):
    val = wiz.prompt_secret("Token", getpass_fn=_getpass_seq(["", "  ", "secret"]))
    assert val == "secret"


def test_prompt_yes_no_default_yes_on_empty():
    val = wiz.prompt_yes_no("OK?", default=True, input_fn=_input_seq([""]))
    assert val is True


def test_prompt_yes_no_default_no_on_empty():
    val = wiz.prompt_yes_no("OK?", default=False, input_fn=_input_seq([""]))
    assert val is False


def test_prompt_yes_no_accepts_y_and_n():
    assert wiz.prompt_yes_no("Q", default=False, input_fn=_input_seq(["y"])) is True
    assert wiz.prompt_yes_no("Q", default=True, input_fn=_input_seq(["n"])) is False


def test_prompt_yes_no_re_prompts_on_garbage(capsys):
    val = wiz.prompt_yes_no("Q", default=False, input_fn=_input_seq(["garbage", "y"]))
    assert val is True


def test_prompt_numbered_choice_valid_pick():
    val = wiz.prompt_numbered_choice("Pick:", ["a", "b", "c"], input_fn=_input_seq(["2"]))
    assert val == "b"


def test_prompt_numbered_choice_rejects_out_of_range_then_accepts(capsys):
    val = wiz.prompt_numbered_choice("Pick:", ["a", "b", "c"], input_fn=_input_seq(["9", "0", "1"]))
    assert val == "a"


def test_prompt_numbered_choice_rejects_non_integer(capsys):
    val = wiz.prompt_numbered_choice("Pick:", ["a", "b"], input_fn=_input_seq(["abc", "2"]))
    assert val == "b"


# ---- wireless interface enumeration ----------------------------------------


def test_enumerate_freeform_fallback_when_unavailable(monkeypatch):
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
    assert wiz.enumerate_wireless_interfaces() is None


# ---- probe: Kismet ---------------------------------------------------------


def test_kismet_probe_success(monkeypatch):
    fake = MagicMock()
    fake.health_check.return_value = {"reachable": True, "version": "2024-08-R1", "error": None}
    monkeypatch.setattr(wiz, "KismetClient", lambda **kw: fake)
    ok, version, error = wiz.probe_kismet("http://x", "tok")
    assert ok is True
    assert version == "2024-08-R1"
    assert error is None


def test_kismet_probe_failure(monkeypatch):
    fake = MagicMock()
    fake.health_check.return_value = {"reachable": False, "version": None, "error": "boom"}
    monkeypatch.setattr(wiz, "KismetClient", lambda **kw: fake)
    ok, version, error = wiz.probe_kismet("http://x", "tok")
    assert ok is False
    assert error == "boom"


# ---- probe: ntfy -----------------------------------------------------------


def test_ntfy_probe_success(monkeypatch):
    captured = {}

    def fake_post(url, data=None, timeout=None):
        captured["url"] = url
        captured["data"] = data
        r = MagicMock()
        r.status_code = 200
        return r

    monkeypatch.setattr(wiz.requests, "post", fake_post)
    ok, error = wiz.probe_ntfy("https://ntfy.sh", "lynceus-aaa")
    assert ok is True
    assert error is None
    assert captured["url"] == "https://ntfy.sh/lynceus-aaa"
    assert b"Lynceus setup test" in captured["data"]


def test_ntfy_probe_failure_http(monkeypatch):
    def fake_post(url, data=None, timeout=None):
        r = MagicMock()
        r.status_code = 503
        return r

    monkeypatch.setattr(wiz.requests, "post", fake_post)
    ok, error = wiz.probe_ntfy("https://ntfy.sh", "lynceus-aaa")
    assert ok is False
    assert "503" in error


def test_ntfy_probe_failure_network(monkeypatch):
    def fake_post(url, data=None, timeout=None):
        raise wiz.requests.exceptions.ConnectionError("no route")

    monkeypatch.setattr(wiz.requests, "post", fake_post)
    ok, error = wiz.probe_ntfy("https://ntfy.sh", "lynceus-aaa")
    assert ok is False
    assert "no route" in error


# ---- run_wizard: probe failure paths ---------------------------------------


def _stub_path_resolution(monkeypatch, tmp_path):
    """Make resolve_config_path return tmp_path/lynceus.yaml so tests don't
    touch real user/system paths.

    Also stubs ``enumerate_bluetooth_adapters`` to ``None`` so the wizard
    silently skips the BT section by default — tests that exercise the BT
    flow override this stub.
    """
    target = tmp_path / "lynceus.yaml"
    monkeypatch.setattr(wiz, "resolve_config_path", lambda scope, output: target)
    monkeypatch.setattr(wiz, "enumerate_bluetooth_adapters", lambda: None)
    return target


def _stub_bundled_import(monkeypatch, *, success: bool = False, msg: str = "no bundled watchlist"):
    """Stub ``import_bundled_watchlist`` so wizard end-to-end tests don't fork
    a real ``lynceus-import-argus`` against the now-shipping bundled CSV."""
    monkeypatch.setattr(
        wiz,
        "import_bundled_watchlist",
        lambda db_path, override_file: (success, msg),
    )


def test_run_wizard_kismet_probe_fail_continue_yes(monkeypatch, tmp_path, capsys):
    _stub_path_resolution(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
    monkeypatch.setattr(
        wiz, "probe_kismet", lambda url, token, timeout=None: (False, None, "connection refused")
    )
    monkeypatch.setattr(wiz, "probe_ntfy", lambda url, topic, timeout=None: (True, None))
    inputs = [
        "",  # kismet URL default
        "y",  # continue after kismet fail
        "wlan1",  # capture interface (freeform)
        "",  # probe_ssids default no
        "",  # ble_friendly_names default yes
        "https://ntfy.sh",  # ntfy URL (non-empty, so we don't skip ntfy)
        "lynceus-deadbeef",
        "",  # rssi default
        "",  # severity overrides default
    ]
    rc = wiz.run_wizard(
        _args(skip_probes=False),
        input_fn=_input_seq(inputs),
        getpass_fn=_getpass_seq(["sekret"]),
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "Kismet probe failed" in out


def test_run_wizard_kismet_probe_fail_continue_no_aborts(monkeypatch, tmp_path, capsys):
    _stub_path_resolution(monkeypatch, tmp_path)
    monkeypatch.setattr(
        wiz, "probe_kismet", lambda url, token, timeout=None: (False, None, "connection refused")
    )
    inputs = [
        "",  # kismet URL default
        "n",  # do not continue
    ]
    rc = wiz.run_wizard(
        _args(skip_probes=False),
        input_fn=_input_seq(inputs),
        getpass_fn=_getpass_seq(["sekret"]),
    )
    assert rc != 0


def test_run_wizard_skip_probes_does_not_call_probes(monkeypatch, tmp_path):
    _stub_path_resolution(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
    called = []
    monkeypatch.setattr(
        wiz,
        "probe_kismet",
        lambda *a, **kw: called.append("k") or (False, None, "should not be called"),
    )
    monkeypatch.setattr(
        wiz,
        "probe_kismet_sources",
        lambda *a, **kw: called.append("k_sources") or None,
    )
    monkeypatch.setattr(
        wiz,
        "probe_ntfy",
        lambda *a, **kw: called.append("n") or (False, "should not be called"),
    )
    rc = wiz.run_wizard(
        _args(skip_probes=True),
        input_fn=_input_seq(_full_input_sequence()),
        getpass_fn=_getpass_seq(["tok"]),
    )
    assert rc == 0
    assert called == []


def test_run_wizard_ntfy_probe_fail_continue_yes(monkeypatch, tmp_path, capsys):
    _stub_path_resolution(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
    monkeypatch.setattr(wiz, "probe_kismet", lambda url, token, timeout=None: (True, "v1", None))
    monkeypatch.setattr(wiz, "probe_kismet_sources", lambda *a, **kw: None)
    monkeypatch.setattr(wiz, "probe_ntfy", lambda url, topic, timeout=None: (False, "boom"))
    inputs = [
        "",  # kismet URL default
        "wlan0",  # capture interface
        "",  # probe_ssids default
        "",  # ble names default
        "https://ntfy.sh",  # ntfy URL (non-empty)
        "lynceus-cafe",
        "y",  # continue after ntfy fail
        "",  # rssi default
        "",  # severity overrides default
    ]
    rc = wiz.run_wizard(
        _args(skip_probes=False),
        input_fn=_input_seq(inputs),
        getpass_fn=_getpass_seq(["tok"]),
    )
    assert rc == 0
    assert "ntfy publish failed" in capsys.readouterr().out


def test_run_wizard_ntfy_probe_fail_continue_no_aborts(monkeypatch, tmp_path):
    _stub_path_resolution(monkeypatch, tmp_path)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
    monkeypatch.setattr(wiz, "probe_kismet", lambda url, token, timeout=None: (True, "v1", None))
    monkeypatch.setattr(wiz, "probe_kismet_sources", lambda *a, **kw: None)
    monkeypatch.setattr(wiz, "probe_ntfy", lambda url, topic, timeout=None: (False, "boom"))
    inputs = [
        "",  # kismet URL
        "wlan0",
        "",  # probe_ssids default
        "",  # ble names default
        "https://ntfy.sh",  # ntfy URL (non-empty)
        "lynceus-cafe",
        "n",  # don't continue
    ]
    rc = wiz.run_wizard(
        _args(skip_probes=False),
        input_fn=_input_seq(inputs),
        getpass_fn=_getpass_seq(["tok"]),
    )
    assert rc != 0


# ---- run_wizard: capture interface enumeration -----------------------------


def test_run_wizard_capture_interface_numbered_selection(monkeypatch, tmp_path):
    target = _stub_path_resolution(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: ["wlan0", "wlan1"])
    inputs = [
        "",  # kismet URL default
        "2",  # pick wlan1
        "",  # probe_ssids default
        "",  # ble names default
        "https://ntfy.sh",  # ntfy URL (non-empty)
        "lynceus-cafe",
        "",  # rssi default
        "",  # severity overrides default
    ]
    rc = wiz.run_wizard(
        _args(),
        input_fn=_input_seq(inputs),
        getpass_fn=_getpass_seq(["tok"]),
    )
    assert rc == 0
    data = yaml.safe_load(target.read_text())
    assert data["kismet_sources"] == ["wlan1"]


def test_run_wizard_capture_interface_freeform_when_enumeration_unavailable(monkeypatch, tmp_path):
    target = _stub_path_resolution(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
    inputs = [
        "",  # kismet URL default
        "wlx0c",  # free-form interface
        "",  # probe_ssids default
        "",  # ble names default
        "https://ntfy.sh",  # ntfy URL (non-empty)
        "lynceus-cafe",
        "",  # rssi default
        "",  # severity overrides default
    ]
    rc = wiz.run_wizard(_args(), input_fn=_input_seq(inputs), getpass_fn=_getpass_seq(["tok"]))
    assert rc == 0
    data = yaml.safe_load(target.read_text())
    assert data["kismet_sources"] == ["wlx0c"]


# ---- run_wizard: capture toggles defaults ----------------------------------


def test_run_wizard_probe_ssids_defaults_false(monkeypatch, tmp_path):
    target = _stub_path_resolution(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
    rc = wiz.run_wizard(
        _args(),
        input_fn=_input_seq(_full_input_sequence()),
        getpass_fn=_getpass_seq(["tok"]),
    )
    assert rc == 0
    data = yaml.safe_load(target.read_text())
    assert data["capture"]["probe_ssids"] is False


def test_run_wizard_ble_friendly_names_defaults_true(monkeypatch, tmp_path):
    target = _stub_path_resolution(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
    rc = wiz.run_wizard(
        _args(),
        input_fn=_input_seq(_full_input_sequence()),
        getpass_fn=_getpass_seq(["tok"]),
    )
    assert rc == 0
    data = yaml.safe_load(target.read_text())
    assert data["capture"]["ble_friendly_names"] is True


# ---- config write & shape --------------------------------------------------


def test_config_yaml_contains_expected_keys(monkeypatch, tmp_path):
    target = _stub_path_resolution(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
    rc = wiz.run_wizard(
        _args(),
        input_fn=_input_seq(_full_input_sequence()),
        getpass_fn=_getpass_seq(["tok-abc"]),
    )
    assert rc == 0
    data = yaml.safe_load(target.read_text())
    for key in (
        "kismet_url",
        "kismet_api_key",
        "kismet_sources",
        "capture",
        "ntfy_url",
        "ntfy_topic",
        "min_rssi",
    ):
        assert key in data, f"missing key: {key}"
    # And it should round-trip through the real Config validator without error.
    from lynceus.config import Config

    Config(**data)


def test_config_yaml_contains_api_token(monkeypatch, tmp_path):
    target = _stub_path_resolution(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
    rc = wiz.run_wizard(
        _args(),
        input_fn=_input_seq(_full_input_sequence()),
        getpass_fn=_getpass_seq(["super-secret-token-xyz"]),
    )
    assert rc == 0
    text = target.read_text()
    assert "super-secret-token-xyz" in text
    data = yaml.safe_load(text)
    assert data["kismet_api_key"] == "super-secret-token-xyz"


def test_write_config_uses_atomic_write_with_0600_mode_on_posix(monkeypatch, tmp_path):
    """write_config must hand off to ``_atomic_write`` so the file is
    created with mode 0o600 atomically — no umask-derived window between
    create and chmod (S2). The legacy ``write_text`` + ``chmod`` two-step
    is gone."""
    monkeypatch.setattr(wiz, "_is_windows", lambda: False)
    captured: dict = {}
    real_open = os.open

    def fake_open(path, flags, mode=0o777, *a, **kw):
        captured["path"] = str(path)
        captured["flags"] = flags
        captured["mode"] = mode
        return real_open(path, flags, mode, *a, **kw)

    monkeypatch.setattr(wiz.os, "open", fake_open)
    target = tmp_path / "lynceus.yaml"
    wiz.write_config(target, "kismet_url: x\n")
    assert target.exists()
    assert captured["mode"] == 0o600
    assert captured["flags"] & os.O_CREAT
    assert captured["flags"] & os.O_WRONLY
    assert captured["flags"] & os.O_TRUNC


def test_write_config_skips_atomic_open_on_windows(monkeypatch, tmp_path):
    """On Windows POSIX mode bits are meaningless, so ``_atomic_write``
    falls through to ``Path.write_text`` and never touches ``os.open``."""
    monkeypatch.setattr(wiz, "_is_windows", lambda: True)
    open_calls = []
    real_open = os.open
    monkeypatch.setattr(
        wiz.os,
        "open",
        lambda *a, **kw: open_calls.append((a, kw)) or real_open(*a, **kw),
    )
    target = tmp_path / "lynceus.yaml"
    wiz.write_config(target, "kismet_url: x\n")
    assert target.exists()
    assert open_calls == [], "Windows path must not use os.open with mode bits"


@pytest.mark.skipif(os.name != "posix", reason="POSIX-only file mode check")
def test_write_config_real_mode_is_0600(tmp_path):
    target = tmp_path / "lynceus.yaml"
    wiz.write_config(target, "kismet_url: x\n")
    mode = target.stat().st_mode & 0o777
    assert mode == 0o600


def test_write_config_creates_parent_dir(tmp_path):
    target = tmp_path / "nested" / "dir" / "lynceus.yaml"
    wiz.write_config(target, "kismet_url: x\n")
    assert target.exists()


# ---- severity overrides scaffold -------------------------------------------


def test_severity_overrides_created_when_missing(tmp_path):
    p = tmp_path / "severity_overrides.yaml"
    created = wiz.scaffold_severity_overrides(p)
    assert created is True
    assert p.exists()
    text = p.read_text()
    # Template should mention each known override section.
    assert "vendor_overrides" in text
    assert "device_category_severity" in text
    assert "geographic_filter" in text


def test_severity_overrides_not_overwritten_when_present(tmp_path):
    p = tmp_path / "severity_overrides.yaml"
    original = "# operator's existing notes\nvendor_overrides:\n  Acme: high\n"
    p.write_text(original)
    created = wiz.scaffold_severity_overrides(p)
    assert created is False
    assert p.read_text() == original


# ---- end-to-end smoke ------------------------------------------------------


def test_run_wizard_end_to_end_smoke(monkeypatch, tmp_path, capsys):
    target = tmp_path / "lynceus.yaml"
    monkeypatch.setattr(wiz, "resolve_config_path", lambda scope, output: target)
    monkeypatch.setattr(wiz, "enumerate_bluetooth_adapters", lambda: None)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: ["wlan0", "wlan1"])
    # Probes: skip via flag.
    inputs = [
        "http://10.0.0.5:2501",  # custom kismet URL
        "1",  # pick wlan0
        "y",  # opt in to probe ssids
        "",  # default ble names
        "https://ntfy.sh",  # explicit ntfy URL
        "lynceus-feedface",
        "-80",  # custom rssi
        "",  # severity overrides default path
    ]
    rc = wiz.run_wizard(
        _args(skip_probes=True),
        input_fn=_input_seq(inputs),
        getpass_fn=_getpass_seq(["my-token-123"]),
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert target.exists()
    data = yaml.safe_load(target.read_text())
    assert data["kismet_url"] == "http://10.0.0.5:2501"
    assert data["kismet_api_key"] == "my-token-123"
    assert data["kismet_sources"] == ["wlan0"]
    assert data["capture"]["probe_ssids"] is True
    assert data["capture"]["ble_friendly_names"] is True
    assert data["ntfy_url"] == "https://ntfy.sh"
    assert data["ntfy_topic"] == "lynceus-feedface"
    assert data["min_rssi"] == -80
    assert "Setup complete" in out
    assert str(target) in out
    # UI URL hint
    assert "http://127.0.0.1:" in out


# ---- main() ----------------------------------------------------------------


def test_main_refuses_existing_config_without_reconfigure(monkeypatch, tmp_path, capsys):
    target = tmp_path / "lynceus.yaml"
    target.write_text("kismet_url: x\n")
    monkeypatch.setattr(wiz, "resolve_config_path", lambda scope, output: target)
    rc = wiz.main(["--user"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "Config already exists" in err


def test_main_system_without_root_refuses(monkeypatch, tmp_path, capsys):
    target = tmp_path / "lynceus.yaml"
    monkeypatch.setattr(wiz, "resolve_config_path", lambda scope, output: target)
    monkeypatch.setattr(wiz, "_is_windows", lambda: False)
    monkeypatch.setattr(wiz, "_euid", lambda: 1000)
    rc = wiz.main(["--system"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "sudo" in err or "Administrator" in err


def test_main_returns_zero_on_full_skip_probes_run(monkeypatch, tmp_path):
    target = tmp_path / "lynceus.yaml"
    monkeypatch.setattr(wiz, "resolve_config_path", lambda scope, output: target)
    monkeypatch.setattr(wiz, "enumerate_bluetooth_adapters", lambda: None)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
    monkeypatch.setattr("builtins.input", _input_seq(_full_input_sequence()))
    monkeypatch.setattr(wiz.getpass, "getpass", _getpass_seq(["tok"]))
    rc = wiz.main(["--user", "--skip-probes"])
    assert rc == 0
    assert target.exists()


# ---- module-level constants ------------------------------------------------


def test_default_kismet_url_is_loopback():
    assert wiz.DEFAULT_KISMET_URL == "http://127.0.0.1:2501"


def test_default_ntfy_broker_is_ntfy_sh():
    assert wiz.DEFAULT_NTFY_BROKER == "https://ntfy.sh"


def test_default_rssi_threshold_is_minus_70():
    assert wiz.DEFAULT_RSSI_THRESHOLD == -70


# ---- bundled watchlist import ---------------------------------------------


def _patch_bundled_resource(
    monkeypatch,
    *,
    exists: bool,
    real_path: Path | None = None,
    raise_module_not_found: bool = False,
):
    """Stub importlib.resources.files / as_file for the bundled-import helper.

    - ``raise_module_not_found=True`` simulates ``lynceus.data`` not shipped.
    - ``exists=False`` simulates the package being present but the CSV missing.
    - ``exists=True`` requires ``real_path`` — the on-disk file the wizard
      will actually pass to the subprocess via ``importlib.resources.as_file``.
    """
    if raise_module_not_found:

        def _raises(_pkg):
            raise ModuleNotFoundError("lynceus.data")

        monkeypatch.setattr(wiz.importlib.resources, "files", _raises)
        return
    fake_traversable = MagicMock()
    fake_traversable.is_file.return_value = exists
    fake_files = MagicMock()
    fake_files.joinpath.return_value = fake_traversable
    monkeypatch.setattr(wiz.importlib.resources, "files", lambda _pkg: fake_files)
    if exists:
        if real_path is None:  # pragma: no cover - test bug
            raise AssertionError("must provide real_path when exists=True")

        @contextlib.contextmanager
        def fake_as_file(_traversable):
            yield real_path

        monkeypatch.setattr(wiz.importlib.resources, "as_file", fake_as_file)


def test_bundled_import_skip_when_data_package_missing(monkeypatch):
    _patch_bundled_resource(monkeypatch, exists=False, raise_module_not_found=True)
    popen_calls = []
    monkeypatch.setattr(
        wiz.subprocess,
        "Popen",
        lambda *a, **kw: popen_calls.append(a) or MagicMock(),
    )
    ok, msg = wiz.import_bundled_watchlist(db_path="/x/db.sqlite", override_file=None)
    assert ok is False
    assert msg == "no bundled watchlist"
    assert popen_calls == [], "Popen must not be called when data package is missing"


def test_bundled_import_skip_when_csv_resource_absent(monkeypatch):
    _patch_bundled_resource(monkeypatch, exists=False)
    popen_calls = []
    monkeypatch.setattr(
        wiz.subprocess,
        "Popen",
        lambda *a, **kw: popen_calls.append(a) or MagicMock(),
    )
    ok, msg = wiz.import_bundled_watchlist(db_path="/x/db.sqlite", override_file=None)
    assert ok is False
    assert msg == "no bundled watchlist"
    assert popen_calls == [], "Popen must not be called when CSV resource is absent"


def test_bundled_import_invokes_subprocess_with_correct_args(monkeypatch, tmp_path):
    csv = tmp_path / "default_watchlist.csv"
    csv.write_text("# meta: argus_export v3 (CP11)\n")
    _patch_bundled_resource(monkeypatch, exists=True, real_path=csv)
    captured = {}

    def fake_popen(args, **kwargs):
        captured["args"] = list(args)
        captured["kwargs"] = kwargs
        proc = MagicMock()
        proc.communicate.return_value = (
            "Total rows in CSV: 7\nimported 7 records, updated 0, dropped 0\n",
            "",
        )
        proc.returncode = 0
        return proc

    monkeypatch.setattr(wiz.subprocess, "Popen", fake_popen)
    ok, msg = wiz.import_bundled_watchlist(
        db_path="/data/lynceus.db", override_file="/etc/lynceus/sev.yaml"
    )
    assert ok is True
    assert "imported 7 records" in msg
    args = captured["args"]
    assert args[0] == "lynceus-import-argus"
    assert args[args.index("--input") + 1] == str(csv)
    assert args[args.index("--db") + 1] == "/data/lynceus.db"
    assert args[args.index("--override-file") + 1] == "/etc/lynceus/sev.yaml"


def test_bundled_import_omits_override_when_none(monkeypatch, tmp_path):
    csv = tmp_path / "default_watchlist.csv"
    csv.write_text("# meta: argus_export v3 (CP11)\n")
    _patch_bundled_resource(monkeypatch, exists=True, real_path=csv)
    captured = {}

    def fake_popen(args, **kwargs):
        captured["args"] = list(args)
        proc = MagicMock()
        proc.communicate.return_value = ("imported 1 records, updated 0, dropped 0", "")
        proc.returncode = 0
        return proc

    monkeypatch.setattr(wiz.subprocess, "Popen", fake_popen)
    ok, _msg = wiz.import_bundled_watchlist(db_path="db.sqlite", override_file=None)
    assert ok is True
    assert "--override-file" not in captured["args"]


def test_bundled_import_failure_returns_error_with_stderr(monkeypatch, tmp_path):
    csv = tmp_path / "default_watchlist.csv"
    csv.write_text("# meta:\n")
    _patch_bundled_resource(monkeypatch, exists=True, real_path=csv)

    def fake_popen(args, **kwargs):
        proc = MagicMock()
        proc.communicate.return_value = ("", "Traceback ...\nValueError: bad header")
        proc.returncode = 1
        return proc

    monkeypatch.setattr(wiz.subprocess, "Popen", fake_popen)
    ok, msg = wiz.import_bundled_watchlist(db_path="db.sqlite", override_file=None)
    assert ok is False
    assert msg.startswith("import failed:")
    assert "bad header" in msg


def test_bundled_import_failure_when_command_missing(monkeypatch, tmp_path):
    csv = tmp_path / "default_watchlist.csv"
    csv.write_text("# meta:\n")
    _patch_bundled_resource(monkeypatch, exists=True, real_path=csv)

    def fake_popen(args, **kwargs):
        raise FileNotFoundError(args[0])

    monkeypatch.setattr(wiz.subprocess, "Popen", fake_popen)
    ok, msg = wiz.import_bundled_watchlist(db_path="db.sqlite", override_file=None)
    assert ok is False
    assert "import failed" in msg


# ---- prompt-recording helper ----------------------------------------------


def _recording_input(answers):
    """Like _input_seq but records every prompt argument."""
    it = iter(answers)
    log: list[str] = []

    def _input(prompt=""):
        log.append(prompt)
        try:
            return next(it)
        except StopIteration as exc:  # pragma: no cover - test bug
            raise AssertionError(f"input() exhausted; prompt={prompt!r}") from exc

    return _input, log


# ---- wizard flow integration with bundled import --------------------------


def test_wizard_with_bundled_present_success_prints_summary(monkeypatch, tmp_path, capsys):
    target = tmp_path / "lynceus.yaml"
    monkeypatch.setattr(wiz, "resolve_config_path", lambda s, o: target)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
    monkeypatch.setattr(wiz, "enumerate_bluetooth_adapters", lambda: None)
    monkeypatch.setattr(
        wiz,
        "import_bundled_watchlist",
        lambda db_path, override_file: (True, "imported 42 records, updated 0, dropped 0"),
    )
    fn, prompts = _recording_input(_full_input_sequence())
    rc = wiz.run_wizard(
        _args(skip_probes=True),
        input_fn=fn,
        getpass_fn=_getpass_seq(["tok"]),
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "Imported bundled threat data" in out
    assert "42 records" in out
    # Additional-CSV prompt has been retired; ensure no flavour of it survives.
    assert not any("additional Argus CSV" in p for p in prompts)
    assert not any("Would you like to import Argus" in p for p in prompts)


def test_wizard_with_bundled_present_failure_warns(monkeypatch, tmp_path, capsys):
    target = tmp_path / "lynceus.yaml"
    monkeypatch.setattr(wiz, "resolve_config_path", lambda s, o: target)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
    monkeypatch.setattr(wiz, "enumerate_bluetooth_adapters", lambda: None)
    monkeypatch.setattr(
        wiz,
        "import_bundled_watchlist",
        lambda db_path, override_file: (False, "import failed: schema mismatch"),
    )
    fn, prompts = _recording_input(_full_input_sequence())
    rc = wiz.run_wizard(
        _args(skip_probes=True),
        input_fn=fn,
        getpass_fn=_getpass_seq(["tok"]),
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "Bundled threat-data import failed" in out
    assert "schema mismatch" in out
    assert "lynceus-import-argus" in out
    # Retired prompt must not have come back under any wording.
    assert not any("additional Argus CSV" in p for p in prompts)
    assert not any("Would you like to import Argus" in p for p in prompts)


def test_wizard_with_bundled_absent_prints_nothing_extra(monkeypatch, tmp_path, capsys):
    target = tmp_path / "lynceus.yaml"
    monkeypatch.setattr(wiz, "resolve_config_path", lambda s, o: target)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
    monkeypatch.setattr(wiz, "enumerate_bluetooth_adapters", lambda: None)
    monkeypatch.setattr(
        wiz,
        "import_bundled_watchlist",
        lambda db_path, override_file: (False, "no bundled watchlist"),
    )
    fn, prompts = _recording_input(_full_input_sequence())
    rc = wiz.run_wizard(
        _args(skip_probes=True),
        input_fn=fn,
        getpass_fn=_getpass_seq(["tok"]),
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "Imported bundled threat data" not in out
    assert "Bundled threat-data import failed" not in out
    assert "no bundled watchlist" not in out
    assert not any("Would you like to import Argus" in p for p in prompts)


def test_wizard_passes_db_path_and_severity_to_bundled_helper(monkeypatch, tmp_path):
    from lynceus import paths

    target = tmp_path / "lynceus.yaml"
    monkeypatch.setattr(wiz, "resolve_config_path", lambda s, o: target)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
    monkeypatch.setattr(wiz, "enumerate_bluetooth_adapters", lambda: None)
    captured = {}

    def fake_bundled(db_path, override_file):
        captured["db_path"] = db_path
        captured["override_file"] = override_file
        return (False, "no bundled watchlist")

    monkeypatch.setattr(wiz, "import_bundled_watchlist", fake_bundled)
    rc = wiz.run_wizard(
        _args(skip_probes=True),
        input_fn=_input_seq(_full_input_sequence()),
        getpass_fn=_getpass_seq(["tok"]),
    )
    assert rc == 0
    # Wizard now resolves the DB path through ``paths.default_db_path(scope)``
    # rather than the bare "lynceus.db" relative filename it used before.
    assert captured["db_path"] == str(paths.default_db_path("user"))
    assert captured["override_file"] is not None
    assert captured["override_file"].endswith("severity_overrides.yaml")


def test_wizard_uses_system_db_path_when_system_scope(monkeypatch, tmp_path):
    """Under --system, the bundled-import helper must receive the system
    DB path so the import lands in /var/lib/lynceus/lynceus.db rather than
    the operator's CWD. ``--system`` is Linux-only, so force the platform
    to Linux for this test regardless of where pytest is running."""
    from lynceus import paths

    monkeypatch.setattr(paths, "_platform", lambda: "linux")
    target = tmp_path / "lynceus.yaml"
    monkeypatch.setattr(wiz, "resolve_config_path", lambda s, o: target)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
    monkeypatch.setattr(wiz, "enumerate_bluetooth_adapters", lambda: None)
    monkeypatch.setattr(wiz, "_is_windows", lambda: False)
    monkeypatch.setattr(wiz.sys, "platform", "linux")
    monkeypatch.setattr(wiz, "_euid", lambda: 0)  # pretend we're root for --system
    # Stub data + log dir mkdirs onto tmp_path so we don't try to mkdir
    # /var/lib/lynceus on the test host.
    monkeypatch.setattr(paths, "default_data_dir", lambda scope: tmp_path / "data")
    monkeypatch.setattr(paths, "default_log_dir", lambda scope: tmp_path / "log")
    # System-mode now applies lynceus group ownership to the freshly
    # written config + dirs; stub the chown/chmod plumbing so this test
    # exercises only the DB-path resolution it cares about.
    monkeypatch.setattr(wiz.os, "chown", lambda *a, **kw: None, raising=False)
    monkeypatch.setattr(wiz.os, "chmod", lambda *a, **kw: None, raising=False)
    fake_grp = MagicMock()
    fake_grp.getgrnam.return_value = MagicMock(gr_gid=2000)
    fake_pwd = MagicMock()
    fake_pwd.getpwnam.return_value = MagicMock(pw_uid=2000)
    import sys as _sys

    monkeypatch.setitem(_sys.modules, "grp", fake_grp)
    monkeypatch.setitem(_sys.modules, "pwd", fake_pwd)

    captured = {}

    def fake_bundled(db_path, override_file):
        captured["db_path"] = db_path
        return (False, "no bundled watchlist")

    monkeypatch.setattr(wiz, "import_bundled_watchlist", fake_bundled)
    rc = wiz.run_wizard(
        _args(skip_probes=True, system=True),
        input_fn=_input_seq(_full_input_sequence()),
        getpass_fn=_getpass_seq(["tok"]),
    )
    assert rc == 0
    assert captured["db_path"] == str(paths.default_db_path("system"))


# ---- Bluetooth adapter enumeration ----------------------------------------


def test_enumerate_bluetooth_adapters_returns_none_on_windows(monkeypatch):
    monkeypatch.setattr(wiz.os, "name", "nt")
    assert wiz.enumerate_bluetooth_adapters() is None


def test_enumerate_bluetooth_adapters_returns_none_on_macos(monkeypatch):
    monkeypatch.setattr(wiz.os, "name", "posix")
    monkeypatch.setattr(wiz.sys, "platform", "darwin")
    assert wiz.enumerate_bluetooth_adapters() is None


def test_enumerate_bluetooth_adapters_returns_empty_when_dir_missing(monkeypatch):
    """When the platform is Linux but ``/sys/class/bluetooth`` is absent
    (e.g. running tests on a Windows host with the stubs below, or a
    Linux kernel without the BT subsystem), the function returns an empty
    list — distinct from ``None`` which means "platform not supported"."""
    monkeypatch.setattr(wiz.os, "name", "posix")
    monkeypatch.setattr(wiz.sys, "platform", "linux")
    # On a Windows host the path doesn't exist; on a Linux host without
    # bluez it also doesn't exist. Either way we expect [].
    if Path("/sys/class/bluetooth").is_dir():
        pytest.skip("real /sys/class/bluetooth present; cannot exercise missing-dir branch")
    assert wiz.enumerate_bluetooth_adapters() == []


# ---- run_wizard: Bluetooth flow -------------------------------------------


def test_run_wizard_bluetooth_unsupported_platform_skipped_silently(monkeypatch, tmp_path, capsys):
    _stub_path_resolution(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
    # _stub_path_resolution already stubs enumerate_bluetooth_adapters → None
    rc = wiz.run_wizard(
        _args(),
        input_fn=_input_seq(_full_input_sequence()),
        getpass_fn=_getpass_seq(["tok"]),
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "Bluetooth adapter selection not implemented on this platform" in out


def test_run_wizard_bluetooth_no_adapters_skipped_with_message(monkeypatch, tmp_path, capsys):
    _stub_path_resolution(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
    monkeypatch.setattr(wiz, "enumerate_bluetooth_adapters", lambda: [])
    rc = wiz.run_wizard(
        _args(),
        input_fn=_input_seq(_full_input_sequence()),
        getpass_fn=_getpass_seq(["tok"]),
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "No Bluetooth adapter detected" in out


def test_run_wizard_bluetooth_adapter_chosen_appends_to_kismet_sources(monkeypatch, tmp_path):
    target = _stub_path_resolution(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
    monkeypatch.setattr(wiz, "enumerate_bluetooth_adapters", lambda: ["hci0", "hci1"])
    inputs = [
        "",  # kismet URL default
        "wlan0",  # wifi capture interface (freeform)
        "",  # bluetooth: yes (default Y)
        "1",  # pick hci0
        "",  # probe_ssids default
        "",  # ble names default
        "https://ntfy.sh",
        "lynceus-cafe",
        "",  # rssi default
        "",  # severity overrides default
    ]
    rc = wiz.run_wizard(
        _args(),
        input_fn=_input_seq(inputs),
        getpass_fn=_getpass_seq(["tok"]),
    )
    assert rc == 0
    data = yaml.safe_load(target.read_text())
    assert data["kismet_sources"] == ["wlan0", "hci0"]


def test_run_wizard_bluetooth_declined_keeps_wifi_only(monkeypatch, tmp_path):
    target = _stub_path_resolution(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
    monkeypatch.setattr(wiz, "enumerate_bluetooth_adapters", lambda: ["hci0"])
    inputs = [
        "",  # kismet URL default
        "wlan0",
        "n",  # decline bluetooth source
        "",  # probe_ssids default
        "",  # ble names default
        "https://ntfy.sh",
        "lynceus-cafe",
        "",  # rssi default
        "",  # severity overrides default
    ]
    rc = wiz.run_wizard(_args(), input_fn=_input_seq(inputs), getpass_fn=_getpass_seq(["tok"]))
    assert rc == 0
    data = yaml.safe_load(target.read_text())
    assert data["kismet_sources"] == ["wlan0"]


# ---- run_wizard: severity-overrides explanation + path validation ---------


def test_run_wizard_severity_overrides_explanation_printed(monkeypatch, tmp_path, capsys):
    _stub_path_resolution(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
    rc = wiz.run_wizard(
        _args(),
        input_fn=_input_seq(_full_input_sequence()),
        getpass_fn=_getpass_seq(["tok"]),
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "Severity overrides let you customize" in out
    assert "Argus device category" in out


def test_run_wizard_severity_overrides_rejects_garbage_then_accepts_path(
    monkeypatch, tmp_path, capsys
):
    target = _stub_path_resolution(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
    accepted_path = str(tmp_path / "custom_sev.yaml")
    inputs = [
        "",  # kismet URL default
        "wlan0",
        "",  # probe_ssids default
        "",  # ble names default
        "https://ntfy.sh",
        "lynceus-cafe",
        "",  # rssi default
        "na",  # rejected
        "skip",  # rejected
        accepted_path,  # accepted (contains separator + .yaml)
    ]
    rc = wiz.run_wizard(_args(), input_fn=_input_seq(inputs), getpass_fn=_getpass_seq(["tok"]))
    assert rc == 0
    out = capsys.readouterr().out
    assert "doesn't look like a file path" in out
    assert target.exists()


def test_run_wizard_severity_overrides_default_accepted_on_enter(monkeypatch, tmp_path):
    target = _stub_path_resolution(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
    rc = wiz.run_wizard(
        _args(),
        input_fn=_input_seq(_full_input_sequence()),
        getpass_fn=_getpass_seq(["tok"]),
    )
    assert rc == 0
    # Default scaffold should have been written next to the config file.
    assert (tmp_path / "severity_overrides.yaml").exists()
    assert target.exists()


def test_looks_like_path_helper_accepts_paths_and_yaml():
    assert wiz._looks_like_path("/etc/lynceus/sev.yaml") is True
    assert wiz._looks_like_path("C:\\config\\sev.yaml") is True
    assert wiz._looks_like_path("relative/path") is True
    assert wiz._looks_like_path("sev.yaml") is True
    assert wiz._looks_like_path("sev.yml") is True


def test_looks_like_path_helper_rejects_garbage():
    assert wiz._looks_like_path("") is False
    assert wiz._looks_like_path("na") is False
    assert wiz._looks_like_path("skip") is False
    assert wiz._looks_like_path("none") is False
    assert wiz._looks_like_path("blah") is False


# ---- run_wizard: ntfy skip support ----------------------------------------


def test_run_wizard_ntfy_url_empty_skips_ntfy_and_probe(monkeypatch, tmp_path, capsys):
    target = _stub_path_resolution(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
    probe_called = []
    monkeypatch.setattr(
        wiz,
        "probe_ntfy",
        lambda *a, **kw: probe_called.append(True) or (True, None),
    )
    monkeypatch.setattr(wiz, "probe_kismet", lambda *a, **kw: (True, "v1", None))
    monkeypatch.setattr(wiz, "probe_kismet_sources", lambda *a, **kw: None)
    inputs = [
        "",  # kismet URL default
        "wlan0",
        "",  # probe_ssids default
        "",  # ble names default
        "",  # ntfy URL: empty → skip; no topic prompt should follow
        "",  # rssi default
        "",  # severity overrides default
    ]
    rc = wiz.run_wizard(
        _args(skip_probes=False),
        input_fn=_input_seq(inputs),
        getpass_fn=_getpass_seq(["tok"]),
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "Skipping ntfy" in out
    assert probe_called == [], "ntfy probe must not run when URL is empty"
    data = yaml.safe_load(target.read_text())
    assert data["ntfy_url"] == ""
    assert data["ntfy_topic"] == ""


def test_run_wizard_ntfy_url_set_topic_empty_re_prompts(monkeypatch, tmp_path):
    target = _stub_path_resolution(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
    inputs = [
        "",  # kismet URL default
        "wlan0",
        "",  # probe_ssids default
        "",  # ble names default
        "https://ntfy.sh",  # URL set
        "",  # topic empty → must re-prompt
        "  ",  # whitespace also rejected
        "lynceus-real",
        "",  # rssi default
        "",  # severity overrides default
    ]
    rc = wiz.run_wizard(
        _args(skip_probes=True),
        input_fn=_input_seq(inputs),
        getpass_fn=_getpass_seq(["tok"]),
    )
    assert rc == 0
    data = yaml.safe_load(target.read_text())
    assert data["ntfy_url"] == "https://ntfy.sh"
    assert data["ntfy_topic"] == "lynceus-real"


# ---- DB parent directory creation before bundled import -------------------


def test_db_parent_dir_created_before_bundled_import(monkeypatch, tmp_path):
    """The wizard must mkdir the data dir before invoking
    lynceus-import-argus, otherwise the subprocess crashes with a sqlite
    "unable to open database file" error on a fresh box."""
    from lynceus import paths

    _stub_path_resolution(monkeypatch, tmp_path)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
    fake_data_dir = tmp_path / "fresh_data" / "lynceus"
    fake_log_dir = tmp_path / "fresh_log" / "lynceus"
    monkeypatch.setattr(paths, "default_data_dir", lambda scope: fake_data_dir)
    monkeypatch.setattr(paths, "default_log_dir", lambda scope: fake_log_dir)
    assert not fake_data_dir.exists(), "precondition: data dir must not exist yet"

    captured = {}

    def fake_bundled(db_path, override_file):
        captured["db_path"] = db_path
        captured["parent_existed"] = Path(db_path).parent.is_dir()
        return (False, "no bundled watchlist")

    monkeypatch.setattr(wiz, "import_bundled_watchlist", fake_bundled)
    rc = wiz.run_wizard(
        _args(skip_probes=True),
        input_fn=_input_seq(_full_input_sequence()),
        getpass_fn=_getpass_seq(["tok"]),
    )
    assert rc == 0
    assert captured["parent_existed"] is True, (
        "data dir must be created before lynceus-import-argus runs"
    )
    assert fake_log_dir.is_dir(), "log dir must be created at setup time"


# ---- additional-CSV prompt removal ----------------------------------------


def test_run_wizard_does_not_prompt_for_additional_argus_csv(monkeypatch, tmp_path):
    """The optional 'import an additional Argus CSV' prompt was retired —
    the wizard should never ask the operator about it under any flow."""
    _stub_path_resolution(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
    fn, prompts = _recording_input(_full_input_sequence())
    rc = wiz.run_wizard(
        _args(skip_probes=True),
        input_fn=fn,
        getpass_fn=_getpass_seq(["tok"]),
    )
    assert rc == 0
    assert not any("additional Argus CSV" in p for p in prompts)
    assert not any("Would you like to import Argus" in p for p in prompts)
    assert not any("Path to Argus CSV" in p for p in prompts)


def test_run_wizard_prints_deferred_argus_import_hint(monkeypatch, tmp_path, capsys):
    _stub_path_resolution(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
    rc = wiz.run_wizard(
        _args(skip_probes=True),
        input_fn=_input_seq(_full_input_sequence()),
        getpass_fn=_getpass_seq(["tok"]),
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "To import a custom Argus CSV later" in out
    assert "lynceus-import-argus --input" in out


def test_maybe_import_argus_helper_is_gone():
    """The helper that drove the retired prompt should no longer exist."""
    assert not hasattr(wiz, "maybe_import_argus")


# ---- C1 fix: probe Kismet datasources for source names --------------------


def _wifi_source(name="external_wifi", interface="wlan1", capture_interface="wlan1mon"):
    return {
        "name": name,
        "interface": interface,
        "capture_interface": capture_interface,
        "uuid": "5fe308bd-0000-0000-0000-00c0caaaaaaa",
        "driver": "linuxwifi",
        "running": True,
    }


def _bt_source(name="local_bt", interface="hci0", capture_interface="hci0"):
    return {
        "name": name,
        "interface": interface,
        "capture_interface": capture_interface,
        "uuid": "6fe308bd-0000-0000-0000-00c0cabbbbbb",
        "driver": "linuxbluetooth",
        "running": True,
    }


def test_format_source_label_full_form():
    """Operator-visible label for a Kismet source must include the
    interface and capture-interface in parentheses so it's clear what
    the source is actually capturing on (e.g. wlan1 in monitor mode
    becoming wlan1mon)."""
    label = wiz._format_source_label(
        {"name": "external_wifi", "interface": "wlan1", "capture_interface": "wlan1mon"}
    )
    assert label == "external_wifi  (interface: wlan1, capture: wlan1mon)"


def test_format_source_label_drops_empty_subfields():
    """Sources without an interface or capture_interface (older Kismet,
    non-Linux, BT classic) should still render cleanly without empty
    parenthetical noise."""
    assert wiz._format_source_label({"name": "bare"}) == "bare"
    assert (
        wiz._format_source_label({"name": "iface_only", "interface": "wlan0"})
        == "iface_only  (interface: wlan0)"
    )


def test_probe_kismet_sources_returns_list_on_success(monkeypatch):
    """The wizard helper delegates to ``KismetClient.list_sources`` and
    passes through whatever it returns when the call succeeds."""
    fake = MagicMock()
    fake.list_sources.return_value = [_wifi_source()]
    monkeypatch.setattr(wiz, "KismetClient", lambda **kw: fake)
    result = wiz.probe_kismet_sources("http://x", "tok")
    assert result == [_wifi_source()]


def test_probe_kismet_sources_returns_none_on_exception(monkeypatch, caplog):
    """Any exception (HTTPError, ConnectionError, malformed JSON, timeout)
    must collapse to None so the wizard cleanly falls back to OS
    enumeration with a warning. The ground truth on what gets logged is
    asserted via caplog."""
    import logging as _logging

    fake = MagicMock()
    fake.list_sources.side_effect = RuntimeError("kaboom")
    monkeypatch.setattr(wiz, "KismetClient", lambda **kw: fake)
    with caplog.at_level(_logging.WARNING, logger="lynceus.cli.setup"):
        result = wiz.probe_kismet_sources("http://x", "tok")
    assert result is None
    assert any("list_sources probe failed" in r.getMessage() for r in caplog.records)


def test_probe_kismet_sources_passes_token_to_client(monkeypatch):
    """The wizard's probe helper must hand the API token through to
    KismetClient so the request hits Kismet authenticated."""
    captured = {}

    def fake_client(**kw):
        captured.update(kw)
        m = MagicMock()
        m.list_sources.return_value = []
        return m

    monkeypatch.setattr(wiz, "KismetClient", fake_client)
    wiz.probe_kismet_sources("http://x:2501", "the-token")
    assert captured.get("api_key") == "the-token"
    assert captured.get("base_url") == "http://x:2501"


def test_run_wizard_uses_kismet_source_name_when_probe_succeeds(monkeypatch, tmp_path):
    """Happy path: list_sources returns one wifi source named
    ``external_wifi``; the wizard offers it, the operator picks it, and
    the resulting ``kismet_sources`` is the source NAME — what the
    poller actually filters on."""
    target = _stub_path_resolution(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(wiz, "probe_kismet", lambda *a, **kw: (True, "v1", None))
    monkeypatch.setattr(
        wiz,
        "probe_kismet_sources",
        lambda *a, **kw: [_wifi_source(name="external_wifi")],
    )
    inputs = [
        "",  # kismet URL default
        "1",  # pick the only Kismet wifi source
        "",  # probe_ssids default
        "",  # ble names default
        "https://ntfy.sh",
        "lynceus-cafe",
        "",  # rssi default
        "",  # severity overrides default
    ]
    rc = wiz.run_wizard(
        _args(skip_probes=False),
        input_fn=_input_seq(inputs),
        getpass_fn=_getpass_seq(["tok"]),
    )
    assert rc == 0
    data = yaml.safe_load(target.read_text())
    assert data["kismet_sources"] == ["external_wifi"]


def test_run_wizard_presents_kismet_source_names_not_iw_interfaces(monkeypatch, tmp_path, capsys):
    """REGRESSION FOR C1 — the rc1 silent-drop bug.

    Construct the exact scenario that bit the operator in the field:
    iw enumerates ``wlan0``/``wlan1`` (kernel interface names), AND
    Kismet's configured source NAME is ``external_wifi``. The wizard
    must present ``external_wifi`` (the source name, which the poller
    filters on) and MUST NOT present the kernel interface names — those
    silently mismatch and cause every observation to be dropped.

    This test would have failed against rc1 setup.py because that code
    only ever called ``enumerate_wireless_interfaces()``. With the
    Kismet-source probe wired in, the iw output is reduced to a
    fallback for unreachable Kismet, and the prompt now offers the real
    source names.
    """
    target = _stub_path_resolution(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(wiz, "probe_kismet", lambda *a, **kw: (True, "v1", None))
    monkeypatch.setattr(
        wiz,
        "probe_kismet_sources",
        lambda *a, **kw: [_wifi_source(name="external_wifi")],
    )
    # iw enumeration is set up too — if the wizard fell back to it
    # (the bug), the test would observe wlan0/wlan1 in the output.
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: ["wlan0", "wlan1"])
    fn, prompts = _recording_input(
        [
            "",  # kismet URL default
            "1",  # pick the Kismet source
            "",  # probe_ssids default
            "",  # ble names default
            "https://ntfy.sh",
            "lynceus-cafe",
            "",  # rssi default
            "",  # severity overrides default
        ]
    )
    rc = wiz.run_wizard(
        _args(skip_probes=False),
        input_fn=fn,
        getpass_fn=_getpass_seq(["tok"]),
    )
    assert rc == 0
    out = capsys.readouterr().out
    # The Kismet source name MUST appear in the operator-visible prompt.
    assert "external_wifi" in out
    # The kernel interface names MUST NOT appear in the wifi-selection
    # prompt — they would silently mismatch the poller filter. The
    # parenthetical "(interface: wlan1, capture: wlan1mon)" is allowed
    # because that's clarifying context, not a selectable option; the
    # *fallback iw enumeration* is what we're guarding against.
    fallback_warning = "WARNING: Could not query Kismet for datasource names"
    assert fallback_warning not in out, (
        "Successful Kismet probe must not trigger the iw fallback warning"
    )
    # And the persisted config must contain the source NAME, not an iface.
    data = yaml.safe_load(target.read_text())
    assert data["kismet_sources"] == ["external_wifi"]
    assert "wlan0" not in data["kismet_sources"]
    assert "wlan1" not in data["kismet_sources"]
    # No prompt asks the operator to free-form-type a kernel interface;
    # ensure none of the prompts contain the iw fallback's signature
    # phrasing.
    assert not any("Capture interface name" in p for p in prompts)


def test_run_wizard_aborts_when_kismet_has_no_wifi_source(monkeypatch, tmp_path, capsys):
    """If Kismet is reachable but has zero wifi datasources, the wizard
    cannot guess a source name and must abort with an actionable
    message that points the operator at the kismet_site.conf snippet."""
    _stub_path_resolution(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(wiz, "probe_kismet", lambda *a, **kw: (True, "v1", None))
    # Kismet has only a BT source — wifi capture cannot proceed.
    monkeypatch.setattr(wiz, "probe_kismet_sources", lambda *a, **kw: [_bt_source()])
    rc = wiz.run_wizard(
        _args(skip_probes=False),
        input_fn=_input_seq([""]),  # only the kismet URL prompt is reached
        getpass_fn=_getpass_seq(["tok"]),
    )
    out = capsys.readouterr().out
    assert rc != 0
    assert "no Wi-Fi datasource configured" in out
    assert "source=wlan1:name=external_wifi" in out
    assert "/etc/kismet/kismet_site.conf" in out


def test_run_wizard_falls_back_to_iw_with_warning_when_list_sources_fails(
    monkeypatch, tmp_path, capsys
):
    """probe_kismet succeeds (Kismet up) but probe_kismet_sources fails
    (e.g. Kismet upgrade dropped the endpoint, or partial auth). The
    wizard must fall back to iw enumeration AND print the explicit
    name-matching warning so the operator knows to verify the value
    matches their Kismet ``name=`` line."""
    target = _stub_path_resolution(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(wiz, "probe_kismet", lambda *a, **kw: (True, "v1", None))
    monkeypatch.setattr(wiz, "probe_kismet_sources", lambda *a, **kw: None)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: ["wlan0", "wlan1"])
    inputs = [
        "",  # kismet URL default
        "2",  # pick wlan1
        "",  # probe_ssids default
        "",  # ble names default
        "https://ntfy.sh",
        "lynceus-cafe",
        "",  # rssi default
        "",  # severity overrides default
    ]
    rc = wiz.run_wizard(
        _args(skip_probes=False),
        input_fn=_input_seq(inputs),
        getpass_fn=_getpass_seq(["tok"]),
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "WARNING: Could not query Kismet for datasource names" in out
    assert "Falling back to OS interface enumeration" in out
    assert "silently drop every observation" in out
    data = yaml.safe_load(target.read_text())
    assert data["kismet_sources"] == ["wlan1"]


def test_run_wizard_kismet_probe_fail_continue_y_shows_warning(monkeypatch, tmp_path, capsys):
    """When the operator continues past a failed Kismet probe, the
    wizard must still print the name-matching warning before iw
    enumeration — they have no Kismet to query so the fallback rules
    apply."""
    _stub_path_resolution(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(
        wiz,
        "probe_kismet",
        lambda url, token, timeout=None: (False, None, "connection refused"),
    )
    list_sources_called = []
    monkeypatch.setattr(
        wiz,
        "probe_kismet_sources",
        lambda *a, **kw: list_sources_called.append(True) or None,
    )
    monkeypatch.setattr(wiz, "probe_ntfy", lambda *a, **kw: (True, None))
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
    inputs = [
        "",  # kismet URL default
        "y",  # continue past kismet failure
        "wlan0",  # freeform capture interface (fallback)
        "",  # probe_ssids default
        "",  # ble names default
        "https://ntfy.sh",
        "lynceus-cafe",
        "",  # rssi default
        "",  # severity overrides default
    ]
    rc = wiz.run_wizard(
        _args(skip_probes=False),
        input_fn=_input_seq(inputs),
        getpass_fn=_getpass_seq(["tok"]),
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "WARNING: Could not query Kismet for datasource names" in out
    assert list_sources_called == [], (
        "list_sources must not be called when probe_kismet itself failed — "
        "Kismet is unreachable, the second call would just hang another 5s"
    )


def test_run_wizard_skip_probes_does_not_print_fallback_warning(monkeypatch, tmp_path, capsys):
    """``--skip-probes`` is a deliberate operator opt-out, not a probe
    failure. The wizard must NOT emit the name-matching WARNING in this
    case; the operator already knows what they're doing."""
    _stub_path_resolution(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
    rc = wiz.run_wizard(
        _args(skip_probes=True),
        input_fn=_input_seq(_full_input_sequence()),
        getpass_fn=_getpass_seq(["tok"]),
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "WARNING: Could not query Kismet for datasource names" not in out


def test_run_wizard_kismet_probe_fail_does_not_call_list_sources(monkeypatch, tmp_path):
    """If probe_kismet itself fails, list_sources must not be called —
    Kismet is unreachable, a second blocking call would just stack a
    5-second timeout on top of the first."""
    _stub_path_resolution(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(
        wiz,
        "probe_kismet",
        lambda url, token, timeout=None: (False, None, "connection refused"),
    )
    list_sources_called = []
    monkeypatch.setattr(
        wiz,
        "probe_kismet_sources",
        lambda *a, **kw: list_sources_called.append(True) or None,
    )
    monkeypatch.setattr(wiz, "probe_ntfy", lambda *a, **kw: (True, None))
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
    inputs = [
        "",  # kismet URL
        "n",  # do not continue
    ]
    rc = wiz.run_wizard(
        _args(skip_probes=False),
        input_fn=_input_seq(inputs),
        getpass_fn=_getpass_seq(["tok"]),
    )
    assert rc != 0
    assert list_sources_called == []


def test_run_wizard_with_bt_source_offers_kismet_bt_prompt(monkeypatch, tmp_path, capsys):
    """When Kismet has both a wifi and BT source, the wizard offers the
    BT prompt using the Kismet source NAME (not /sys/class/bluetooth
    output), and the picked NAME is appended to kismet_sources."""
    target = _stub_path_resolution(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(wiz, "probe_kismet", lambda *a, **kw: (True, "v1", None))
    monkeypatch.setattr(
        wiz,
        "probe_kismet_sources",
        lambda *a, **kw: [
            _wifi_source(name="external_wifi"),
            _bt_source(name="local_bt"),
        ],
    )
    inputs = [
        "",  # kismet URL default
        "1",  # pick the wifi source
        "",  # accept default Y for BT prompt
        "1",  # pick the BT source
        "",  # probe_ssids default
        "",  # ble names default
        "https://ntfy.sh",
        "lynceus-cafe",
        "",  # rssi default
        "",  # severity overrides default
    ]
    rc = wiz.run_wizard(
        _args(skip_probes=False),
        input_fn=_input_seq(inputs),
        getpass_fn=_getpass_seq(["tok"]),
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "local_bt" in out
    data = yaml.safe_load(target.read_text())
    assert data["kismet_sources"] == ["external_wifi", "local_bt"]


def test_run_wizard_no_bt_source_in_kismet_skips_with_note(monkeypatch, tmp_path, capsys):
    """When Kismet is reachable but has no BT source configured, the
    wizard skips the BT prompt entirely and prints an actionable note
    showing the kismet_site.conf line the operator would need to add
    later."""
    target = _stub_path_resolution(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(wiz, "probe_kismet", lambda *a, **kw: (True, "v1", None))
    # Wifi only — no BT in the source list.
    monkeypatch.setattr(
        wiz, "probe_kismet_sources", lambda *a, **kw: [_wifi_source(name="external_wifi")]
    )
    inputs = [
        "",  # kismet URL default
        "1",  # pick the wifi source
        # no BT prompt expected
        "",  # probe_ssids default
        "",  # ble names default
        "https://ntfy.sh",
        "lynceus-cafe",
        "",  # rssi default
        "",  # severity overrides default
    ]
    rc = wiz.run_wizard(
        _args(skip_probes=False),
        input_fn=_input_seq(inputs),
        getpass_fn=_getpass_seq(["tok"]),
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "no Bluetooth datasource configured" in out
    assert "source=hci0:type=linuxbluetooth,name=local_bt" in out
    data = yaml.safe_load(target.read_text())
    assert data["kismet_sources"] == ["external_wifi"]


def test_run_wizard_multiple_bt_sources_picks_by_number(monkeypatch, tmp_path):
    """Two BT sources → numbered selection prompts with each Kismet
    source name; picked NAME is appended to kismet_sources."""
    target = _stub_path_resolution(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(wiz, "probe_kismet", lambda *a, **kw: (True, "v1", None))
    monkeypatch.setattr(
        wiz,
        "probe_kismet_sources",
        lambda *a, **kw: [
            _wifi_source(name="external_wifi"),
            _bt_source(name="local_bt"),
            _bt_source(name="usb_bt", interface="hci1", capture_interface="hci1"),
        ],
    )
    inputs = [
        "",  # kismet URL default
        "1",  # pick the wifi source
        "",  # accept default Y for BT prompt
        "2",  # pick the second BT source (usb_bt)
        "",  # probe_ssids default
        "",  # ble names default
        "https://ntfy.sh",
        "lynceus-cafe",
        "",  # rssi default
        "",  # severity overrides default
    ]
    rc = wiz.run_wizard(
        _args(skip_probes=False),
        input_fn=_input_seq(inputs),
        getpass_fn=_getpass_seq(["tok"]),
    )
    assert rc == 0
    data = yaml.safe_load(target.read_text())
    assert data["kismet_sources"] == ["external_wifi", "usb_bt"]


def test_run_wizard_kismet_bt_decline_keeps_wifi_only(monkeypatch, tmp_path):
    """If Kismet has a BT source but the operator declines the prompt,
    only the wifi source goes into kismet_sources."""
    target = _stub_path_resolution(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(wiz, "probe_kismet", lambda *a, **kw: (True, "v1", None))
    monkeypatch.setattr(
        wiz,
        "probe_kismet_sources",
        lambda *a, **kw: [_wifi_source(name="external_wifi"), _bt_source(name="local_bt")],
    )
    inputs = [
        "",  # kismet URL default
        "1",  # pick the wifi source
        "n",  # decline BT
        "",  # probe_ssids default
        "",  # ble names default
        "https://ntfy.sh",
        "lynceus-cafe",
        "",  # rssi default
        "",  # severity overrides default
    ]
    rc = wiz.run_wizard(
        _args(skip_probes=False),
        input_fn=_input_seq(inputs),
        getpass_fn=_getpass_seq(["tok"]),
    )
    assert rc == 0
    data = yaml.safe_load(target.read_text())
    assert data["kismet_sources"] == ["external_wifi"]


# ---- URL prompt validation -------------------------------------------------
#
# rc1's wizard accepted any string at the Kismet / ntfy URL prompt. Inputs
# without a scheme (``127.0.0.1:2501``) flowed straight into the probe and
# blew up with ``MissingSchema``. The belt-and-suspenders fix validates the
# input before any probe runs and re-prompts up to a hard cap before
# aborting, so a fat-fingered operator can't loop on us.


def test_prompt_url_accepts_well_formed_url_first_try():
    seq = _input_seq(["http://kismet.example.com:2501"])
    out = wiz.prompt_url("Kismet API URL", default=None, required=True, input_fn=seq)
    assert out == "http://kismet.example.com:2501"


def test_prompt_url_rejects_scheme_less_then_accepts(capsys):
    seq = _input_seq(["127.0.0.1:2501", "http://127.0.0.1:2501"])
    out = wiz.prompt_url("Kismet API URL", default=None, required=True, input_fn=seq)
    assert out == "http://127.0.0.1:2501"
    err_msg = capsys.readouterr().out
    assert "URL must include a scheme" in err_msg
    assert "127.0.0.1:2501" in err_msg


def test_prompt_url_rejects_scheme_only_no_host(capsys):
    seq = _input_seq(["http://", "https://kismet.local"])
    out = wiz.prompt_url("Kismet API URL", default=None, required=True, input_fn=seq)
    assert out == "https://kismet.local"
    assert "URL must include a scheme" in capsys.readouterr().out


def test_prompt_url_rejects_non_http_scheme(capsys):
    seq = _input_seq(["ftp://kismet", "http://kismet:2501"])
    out = wiz.prompt_url("Kismet API URL", default=None, required=True, input_fn=seq)
    assert out == "http://kismet:2501"
    assert "URL must include a scheme" in capsys.readouterr().out


def test_prompt_url_aborts_after_max_attempts(capsys):
    """Four invalid entries → abort sentinel raised. Caller turns this into
    a non-zero exit so the operator can re-run instead of looping forever."""
    seq = _input_seq(["bad1", "bad2", "bad3", "bad4"])
    with pytest.raises(wiz._URLPromptAborted):
        wiz.prompt_url("Kismet API URL", default=None, required=True, input_fn=seq)
    out = capsys.readouterr().out
    # All four rejections were reported to the user, not silently swallowed.
    assert out.count("URL must include a scheme") == 4


def test_prompt_url_accepts_default_via_enter():
    seq = _input_seq([""])
    out = wiz.prompt_url(
        "Kismet API URL",
        default=wiz.DEFAULT_KISMET_URL,
        required=True,
        input_fn=seq,
    )
    assert out == wiz.DEFAULT_KISMET_URL


def test_prompt_url_optional_empty_returns_empty():
    """When ``required=False`` (the ntfy URL), empty input means 'skip'."""
    seq = _input_seq([""])
    out = wiz.prompt_url("ntfy URL", default=None, required=False, input_fn=seq)
    assert out == ""


def test_run_wizard_aborts_on_persistently_invalid_kismet_url(monkeypatch, tmp_path, capsys):
    """Wizard returns non-zero after the operator can't produce a valid URL.

    G1-adjacent: the exit message tells the operator to re-run, not just a
    silent ``rc != 0``.
    """
    _stub_path_resolution(monkeypatch, tmp_path)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
    inputs = ["bad1", "bad2", "bad3", "bad4"]
    rc = wiz.run_wizard(
        _args(skip_probes=True),
        input_fn=_input_seq(inputs),
        getpass_fn=_getpass_seq([]),  # never reached: aborted before token prompt
    )
    assert rc == 1
    err = capsys.readouterr().err
    assert "Re-run lynceus-setup" in err


def test_run_wizard_re_prompts_on_scheme_less_kismet_url(monkeypatch, tmp_path, capsys):
    """Belt: bad URL gets rejected at the wizard layer with the clear error
    message, then accepted on the next attempt — no ``MissingSchema`` ever
    reaches a probe call."""
    target = _stub_path_resolution(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
    inputs = [
        "127.0.0.1:2501",  # rejected
        "http://10.0.0.5:2501",  # accepted
        "wlan0",
        "",  # probe_ssids
        "",  # ble names
        "",  # ntfy URL — skip
        "",  # rssi default
        "",  # severity overrides default
    ]
    rc = wiz.run_wizard(
        _args(skip_probes=True),
        input_fn=_input_seq(inputs),
        getpass_fn=_getpass_seq(["tok"]),
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "URL must include a scheme" in out
    assert "127.0.0.1:2501" in out
    data = yaml.safe_load(target.read_text())
    assert data["kismet_url"] == "http://10.0.0.5:2501"


def test_run_wizard_re_prompts_on_scheme_less_ntfy_url(monkeypatch, tmp_path, capsys):
    target = _stub_path_resolution(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
    inputs = [
        "",  # accept default kismet URL
        "wlan0",
        "",  # probe_ssids
        "",  # ble names
        "ntfy.sh",  # rejected — no scheme
        "https://ntfy.sh",  # accepted
        "lynceus-test",  # ntfy topic
        "",  # rssi default
        "",  # severity overrides default
    ]
    rc = wiz.run_wizard(
        _args(skip_probes=True),
        input_fn=_input_seq(inputs),
        getpass_fn=_getpass_seq(["tok"]),
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "URL must include a scheme" in out
    assert "ntfy.sh" in out
    data = yaml.safe_load(target.read_text())
    assert data["ntfy_url"] == "https://ntfy.sh"


def test_run_wizard_kismet_probe_never_sees_scheme_less_url(monkeypatch, tmp_path):
    """G1: probe_kismet must NEVER be called with a scheme-less URL.

    The pre-fix flow handed the raw input straight to ``probe_kismet`` →
    ``KismetClient(base_url=...)`` → ``requests.get`` and the operator got
    ``MissingSchema``. With the wizard-layer guard, the URL is validated
    BEFORE the probe runs, so any URL the probe receives is well-formed.
    """
    _stub_path_resolution(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)

    seen_urls: list[str] = []

    def fake_probe_kismet(url, token, timeout=None):
        seen_urls.append(url)
        return (True, "v1", None)

    monkeypatch.setattr(wiz, "probe_kismet", fake_probe_kismet)
    monkeypatch.setattr(wiz, "probe_kismet_sources", lambda *a, **k: None)
    monkeypatch.setattr(wiz, "probe_ntfy", lambda *a, **k: (True, None))

    inputs = [
        "127.0.0.1:2501",  # rejected at the prompt — never reaches probe
        "http://10.0.0.5:2501",  # accepted
        "wlan0",
        "",
        "",
        "",  # skip ntfy
        "",  # rssi default
        "",  # severity overrides default
    ]
    rc = wiz.run_wizard(
        _args(skip_probes=False),
        input_fn=_input_seq(inputs),
        getpass_fn=_getpass_seq(["tok"]),
    )
    assert rc == 0
    # Probe was called exactly once, and only with the well-formed URL.
    assert seen_urls == ["http://10.0.0.5:2501"]


# ---- system-mode ownership: Bug 6, S1, S2, S5 -----------------------------
#
# rc1's --system mode shipped three independent footguns that stacked
# into "broken-by-default":
#
#   Bug 6: config written 0600 root:root → daemon (User=lynceus) can't
#          read it → unit fails on first start.
#   S1:    data_dir + lynceus.db owned by root → daemon can't write
#          → first poll fails with "attempt to write a readonly database".
#   S2:    secrets-bearing config briefly world-readable between
#          ``write_text`` and the follow-up ``chmod`` (race window in
#          BOTH user and system mode).
#   S5:    /etc/lynceus dir is root:root 0755 → directory-traversal
#          denied to the lynceus group → even properly-owned config files
#          remain unreadable.
#
# Each test in this section is a regression: it exercises the path that
# pre-fix code did not implement, so it MUST FAIL against rc1.


# ---- S2: atomic write closes the chmod race ------------------------------


def test_atomic_write_opens_with_target_mode_on_posix(monkeypatch, tmp_path):
    """``_atomic_write`` must set the file mode at fd-creation time, not
    after the fact. ``os.open(...)`` is invoked with O_CREAT|O_WRONLY|
    O_TRUNC and the explicit 0o600 mode — no umask-derived window
    between create and chmod."""
    monkeypatch.setattr(wiz, "_is_windows", lambda: False)
    captured: dict = {}
    real_open = os.open

    def fake_open(path, flags, mode=0o777, *a, **kw):
        captured["path"] = str(path)
        captured["flags"] = flags
        captured["mode"] = mode
        return real_open(path, flags, mode, *a, **kw)

    monkeypatch.setattr(wiz.os, "open", fake_open)
    target = tmp_path / "secret.yaml"
    wiz._atomic_write(target, "kismet_api_key: secret\n")
    assert captured["mode"] == 0o600
    assert captured["flags"] & os.O_CREAT
    assert captured["flags"] & os.O_WRONLY
    assert captured["flags"] & os.O_TRUNC
    assert target.read_text() == "kismet_api_key: secret\n"


def test_atomic_write_honours_explicit_mode(monkeypatch, tmp_path):
    """The ``mode`` kwarg propagates to the ``os.open`` call so callers
    that need a different default (e.g. 0o640 for a system-mode file
    that's group-readable) get the bits they asked for."""
    monkeypatch.setattr(wiz, "_is_windows", lambda: False)
    captured: dict = {}
    real_open = os.open

    def fake_open(path, flags, mode=0o777, *a, **kw):
        captured["mode"] = mode
        return real_open(path, flags, mode, *a, **kw)

    monkeypatch.setattr(wiz.os, "open", fake_open)
    target = tmp_path / "shared.yaml"
    wiz._atomic_write(target, "x\n", mode=0o640)
    assert captured["mode"] == 0o640


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX-only file mode check")
def test_atomic_write_real_mode_is_0600(tmp_path):
    """Belt: actually stat the file after _atomic_write and verify the
    bits. The race window cannot exist if the mode is set at creation."""
    target = tmp_path / "secret.yaml"
    wiz._atomic_write(target, "kismet_api_key: secret\n")
    mode = target.stat().st_mode & 0o777
    assert mode == 0o600


def test_atomic_write_on_windows_falls_back_to_write_text(monkeypatch, tmp_path):
    """Windows has no meaningful POSIX mode bits, so the helper short-
    circuits to Path.write_text — ``os.open`` is never called."""
    monkeypatch.setattr(wiz, "_is_windows", lambda: True)
    open_calls: list = []
    real_open = os.open
    monkeypatch.setattr(
        wiz.os,
        "open",
        lambda *a, **kw: open_calls.append((a, kw)) or real_open(*a, **kw),
    )
    target = tmp_path / "secret.yaml"
    wiz._atomic_write(target, "kismet_api_key: secret\n")
    assert target.read_text() == "kismet_api_key: secret\n"
    assert open_calls == []


def test_setup_py_no_longer_uses_write_text_then_chmod_pattern():
    """The legacy ``write_text(...) + chmod(0o600)`` pair leaves a
    race window in which the secret-bearing config is briefly world-
    readable. After the S2 fix, the pattern must not exist anywhere
    in setup.py — every secrets-bearing write goes through
    ``_atomic_write``."""
    setup_py = Path(wiz.__file__).read_text()
    # No top-level write_text on a yaml/conf path immediately followed
    # by a chmod. Search for the most concrete witness: a chmod 0o600
    # call. Pre-fix code had two; post-fix code has none.
    assert "os.chmod(path, 0o600)" not in setup_py, (
        "Found a chmod-after-write_text remnant; convert the call site to _atomic_write."
    )
    assert "chmod(path, 0o600)" not in setup_py


# ---- Bug 6: config + overrides chowned root:lynceus 0640 -----------------


@pytest.fixture
def _stub_perms(monkeypatch):
    """Capture chown / chmod calls and stub pwd/grp lookups so the
    test never has to be running as root or have a real lynceus user.

    Yields a dict with ``chown_calls``, ``chmod_calls``, ``getgrnam``
    so individual tests can extend the stub (e.g. force a KeyError).

    ``raising=False`` on the os.* monkeypatches because Windows lacks
    those attributes natively — the stub adds them so tests can run
    cross-platform against the Linux code paths.
    """
    chown_calls: list = []
    chmod_calls: list = []
    monkeypatch.setattr(wiz, "_is_windows", lambda: False)
    monkeypatch.setattr(wiz.sys, "platform", "linux")
    monkeypatch.setattr(
        wiz.os,
        "chown",
        lambda p, u, g: chown_calls.append((str(p), u, g)),
        raising=False,
    )
    monkeypatch.setattr(
        wiz.os,
        "chmod",
        lambda p, m: chmod_calls.append((str(p), m)),
        raising=False,
    )

    fake_grp = MagicMock()
    fake_grp.getgrnam.return_value = MagicMock(gr_gid=2000)
    fake_pwd = MagicMock()
    fake_pwd.getpwnam.return_value = MagicMock(pw_uid=2000)
    import sys as _sys

    monkeypatch.setitem(_sys.modules, "grp", fake_grp)
    monkeypatch.setitem(_sys.modules, "pwd", fake_pwd)
    return {
        "chown_calls": chown_calls,
        "chmod_calls": chmod_calls,
        "fake_grp": fake_grp,
        "fake_pwd": fake_pwd,
    }


def test_apply_system_perms_to_file_chowns_and_chmods_to_0640(_stub_perms, tmp_path):
    target = tmp_path / "lynceus.yaml"
    target.write_text("x\n")
    wiz._apply_system_perms_to_file(target)
    # owner stays root (uid 0), group becomes the resolved lynceus gid
    assert _stub_perms["chown_calls"] == [(str(target), 0, 2000)]
    assert _stub_perms["chmod_calls"] == [(str(target), 0o640)]


def test_apply_system_perms_to_file_raises_setuperror_when_group_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(wiz, "_is_windows", lambda: False)
    monkeypatch.setattr(wiz.sys, "platform", "linux")
    fake_grp = MagicMock()
    fake_grp.getgrnam.side_effect = KeyError("lynceus")
    import sys as _sys

    monkeypatch.setitem(_sys.modules, "grp", fake_grp)
    monkeypatch.setattr(wiz.os, "chown", lambda *a, **kw: None, raising=False)
    monkeypatch.setattr(wiz.os, "chmod", lambda *a, **kw: None, raising=False)

    target = tmp_path / "lynceus.yaml"
    target.write_text("x\n")
    with pytest.raises(wiz.SetupError) as exc:
        wiz._apply_system_perms_to_file(target)
    assert "Group 'lynceus' does not exist" in str(exc.value)
    assert "install.sh --system" in str(exc.value)


def test_apply_system_perms_to_dir_chowns_to_lynceus_lynceus_0750(_stub_perms, tmp_path):
    d = tmp_path / "data"
    d.mkdir()
    wiz._apply_system_perms_to_dir(d)
    assert _stub_perms["chown_calls"] == [(str(d), 2000, 2000)]
    assert _stub_perms["chmod_calls"] == [(str(d), 0o750)]


def test_apply_system_perms_to_file_noop_on_windows(monkeypatch, tmp_path):
    monkeypatch.setattr(wiz, "_is_windows", lambda: True)
    chown_calls: list = []
    chmod_calls: list = []
    monkeypatch.setattr(wiz.os, "chown", lambda *a, **kw: chown_calls.append(a), raising=False)
    monkeypatch.setattr(wiz.os, "chmod", lambda *a, **kw: chmod_calls.append(a), raising=False)
    target = tmp_path / "x.yaml"
    target.write_text("x\n")
    wiz._apply_system_perms_to_file(target)
    assert chown_calls == []
    assert chmod_calls == []


def test_apply_system_perms_raises_setuperror_on_macos(monkeypatch, tmp_path):
    monkeypatch.setattr(wiz, "_is_windows", lambda: False)
    monkeypatch.setattr(wiz.sys, "platform", "darwin")
    target = tmp_path / "x.yaml"
    target.write_text("x\n")
    with pytest.raises(wiz.SetupError) as exc:
        wiz._apply_system_perms_to_file(target)
    assert "Linux-only" in str(exc.value)


# ---- run_wizard wiring: scope=system applies perms; scope=user does not --


def _system_scope_inputs():
    """Identical input shape to ``_full_input_sequence`` but trimmed for
    a wizard run that's testing the perms-applying tail."""
    return [
        "",  # kismet URL default
        "wlan0",  # capture interface (freeform, since enumerate_wireless returns None)
        "",  # probe_ssids default
        "",  # ble names default
        "https://ntfy.sh",
        "lynceus-cafe",
        "",  # rssi default
        "",  # severity overrides default
    ]


def _stub_system_wizard_paths(monkeypatch, tmp_path):
    """Force ``--system`` config, data, and log paths to land under
    ``tmp_path`` so the wizard doesn't try to mkdir /var/lib/lynceus on
    the test host. Returns a dict of the stubbed paths."""
    from lynceus import paths as paths_mod

    target = tmp_path / "etc" / "lynceus" / "lynceus.yaml"
    monkeypatch.setattr(wiz, "resolve_config_path", lambda s, o: target)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
    monkeypatch.setattr(wiz, "enumerate_bluetooth_adapters", lambda: None)
    monkeypatch.setattr(wiz, "_is_windows", lambda: False)
    monkeypatch.setattr(wiz.sys, "platform", "linux")
    monkeypatch.setattr(wiz, "_euid", lambda: 0)  # pretend we're root
    monkeypatch.setattr(paths_mod, "_platform", lambda: "linux")
    data_dir = tmp_path / "var" / "lib" / "lynceus"
    log_dir = tmp_path / "var" / "log" / "lynceus"
    db_path = data_dir / "lynceus.db"
    monkeypatch.setattr(paths_mod, "default_data_dir", lambda scope: data_dir)
    monkeypatch.setattr(paths_mod, "default_log_dir", lambda scope: log_dir)
    monkeypatch.setattr(paths_mod, "default_db_path", lambda scope: db_path)
    return {
        "target": target,
        "data_dir": data_dir,
        "log_dir": log_dir,
        "db_path": db_path,
    }


def test_run_wizard_system_scope_chowns_config_to_root_lynceus_0640(
    _stub_perms, monkeypatch, tmp_path
):
    """Bug 6 regression — pre-fix code wrote the config 0600 root:root and
    never chowned it, so the daemon (User=lynceus) couldn't read it."""
    paths_d = _stub_system_wizard_paths(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    rc = wiz.run_wizard(
        _args(skip_probes=True, system=True),
        input_fn=_input_seq(_system_scope_inputs()),
        getpass_fn=_getpass_seq(["tok"]),
    )
    assert rc == 0
    chown_pairs = {(p, u, g) for (p, u, g) in _stub_perms["chown_calls"]}
    chmod_pairs = {(p, m) for (p, m) in _stub_perms["chmod_calls"]}
    # Config: root (0) : lynceus (2000), mode 0o640.
    assert (str(paths_d["target"]), 0, 2000) in chown_pairs
    assert (str(paths_d["target"]), 0o640) in chmod_pairs


def test_run_wizard_system_scope_chowns_severity_overrides_to_root_lynceus_0640(
    _stub_perms, monkeypatch, tmp_path
):
    paths_d = _stub_system_wizard_paths(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    rc = wiz.run_wizard(
        _args(skip_probes=True, system=True),
        input_fn=_input_seq(_system_scope_inputs()),
        getpass_fn=_getpass_seq(["tok"]),
    )
    assert rc == 0
    sev_path = str(paths_d["target"].parent / "severity_overrides.yaml")
    chown_pairs = {(p, u, g) for (p, u, g) in _stub_perms["chown_calls"]}
    chmod_pairs = {(p, m) for (p, m) in _stub_perms["chmod_calls"]}
    assert (sev_path, 0, 2000) in chown_pairs
    assert (sev_path, 0o640) in chmod_pairs


def test_run_wizard_system_scope_exits_clean_when_lynceus_group_missing(
    monkeypatch, tmp_path, capsys
):
    """Operator ran ``sudo lynceus-setup --system`` without first running
    ``sudo ./install.sh --system``. The wizard must abort with a clear
    "run install.sh first" hint to stderr — not crash with an unhandled
    KeyError."""
    paths_d = _stub_system_wizard_paths(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(wiz.os, "chown", lambda *a, **kw: None, raising=False)
    monkeypatch.setattr(wiz.os, "chmod", lambda *a, **kw: None, raising=False)
    fake_grp = MagicMock()
    fake_grp.getgrnam.side_effect = KeyError("lynceus")
    fake_pwd = MagicMock()
    fake_pwd.getpwnam.return_value = MagicMock(pw_uid=2000)
    import sys as _sys

    monkeypatch.setitem(_sys.modules, "grp", fake_grp)
    monkeypatch.setitem(_sys.modules, "pwd", fake_pwd)

    rc = wiz.run_wizard(
        _args(skip_probes=True, system=True),
        input_fn=_input_seq(_system_scope_inputs()),
        getpass_fn=_getpass_seq(["tok"]),
    )
    assert rc != 0
    err = capsys.readouterr().err
    assert "lynceus" in err
    assert "install.sh --system" in err
    # Sanity: target dir got created (perms code ran AFTER write_config).
    assert paths_d["target"].exists()


def test_run_wizard_user_scope_never_calls_chown(monkeypatch, tmp_path):
    """User scope must NOT touch chown — the rc1 wizard didn't, and we
    shouldn't have regressed that. The file-mode contract for user-scope
    configs is 0600 owned by the running user, not root:lynceus 0640."""
    target = tmp_path / "lynceus.yaml"
    monkeypatch.setattr(wiz, "resolve_config_path", lambda s, o: target)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
    monkeypatch.setattr(wiz, "enumerate_bluetooth_adapters", lambda: None)
    _stub_bundled_import(monkeypatch)
    chown_calls: list = []
    monkeypatch.setattr(wiz.os, "chown", lambda *a, **kw: chown_calls.append(a), raising=False)

    rc = wiz.run_wizard(
        _args(skip_probes=True),  # user scope by default
        input_fn=_input_seq(_full_input_sequence()),
        getpass_fn=_getpass_seq(["tok"]),
    )
    assert rc == 0
    assert chown_calls == [], "user-scope wizard must not call chown"
    if os.name == "posix":
        # 0600, not 0640 — user-scope contract is unchanged.
        assert target.stat().st_mode & 0o777 == 0o600


def test_run_wizard_system_scope_chowns_data_and_log_dirs(_stub_perms, monkeypatch, tmp_path):
    """S1 part 1: data_dir and log_dir must be chowned lynceus:lynceus
    0750 so the daemon can write under them."""
    paths_d = _stub_system_wizard_paths(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    rc = wiz.run_wizard(
        _args(skip_probes=True, system=True),
        input_fn=_input_seq(_system_scope_inputs()),
        getpass_fn=_getpass_seq(["tok"]),
    )
    assert rc == 0
    chown_pairs = {(p, u, g) for (p, u, g) in _stub_perms["chown_calls"]}
    chmod_pairs = {(p, m) for (p, m) in _stub_perms["chmod_calls"]}
    assert (str(paths_d["data_dir"]), 2000, 2000) in chown_pairs
    assert (str(paths_d["log_dir"]), 2000, 2000) in chown_pairs
    assert (str(paths_d["data_dir"]), 0o750) in chmod_pairs
    assert (str(paths_d["log_dir"]), 0o750) in chmod_pairs


def test_run_wizard_system_scope_chowns_db_and_sidecars_after_import(
    _stub_perms, monkeypatch, tmp_path
):
    """S1 part 2: after lynceus-import-argus succeeds, the wizard must
    chown the resulting lynceus.db AND any sqlite sidecars (-wal, -shm)
    to ``lynceus:lynceus 0640``. The DB must be OWNED by lynceus (not
    just group-readable) so the daemon can write — root:lynceus 0640
    would manifest as "attempt to write a readonly database" on the
    first poll. Pre-fix code never did this."""
    paths_d = _stub_system_wizard_paths(monkeypatch, tmp_path)

    # Make the bundled import look successful AND lay down a fake DB +
    # WAL sidecar at the expected path so the post-import chown step
    # has something to find.
    paths_d["data_dir"].mkdir(parents=True, exist_ok=True)
    db = paths_d["db_path"]
    wal = Path(str(db) + "-wal")

    def fake_bundled(db_path, override_file):
        Path(db_path).write_text("fake sqlite\n")
        Path(str(db_path) + "-wal").write_text("fake wal\n")
        return (True, "imported 7 records")

    monkeypatch.setattr(wiz, "import_bundled_watchlist", fake_bundled)

    rc = wiz.run_wizard(
        _args(skip_probes=True, system=True),
        input_fn=_input_seq(_system_scope_inputs()),
        getpass_fn=_getpass_seq(["tok"]),
    )
    assert rc == 0
    chown_pairs = {(p, u, g) for (p, u, g) in _stub_perms["chown_calls"]}
    chmod_pairs = {(p, m) for (p, m) in _stub_perms["chmod_calls"]}
    # DB must be owned by lynceus (uid 2000 in our stub), not root.
    assert (str(db), 2000, 2000) in chown_pairs
    assert (str(wal), 2000, 2000) in chown_pairs
    assert (str(db), 0o640) in chmod_pairs
    assert (str(wal), 0o640) in chmod_pairs


def test_run_wizard_system_scope_db_chown_tolerant_of_missing_sidecars(
    _stub_perms, monkeypatch, tmp_path
):
    """Sidecar tolerance: a freshly-imported DB has no -wal yet (sqlite
    only creates it when the journal goes WAL). The chown step must not
    crash when the sidecar is absent."""
    paths_d = _stub_system_wizard_paths(monkeypatch, tmp_path)
    paths_d["data_dir"].mkdir(parents=True, exist_ok=True)
    db = paths_d["db_path"]

    def fake_bundled(db_path, override_file):
        Path(db_path).write_text("fake sqlite\n")
        # No sidecar files this time.
        return (True, "imported 1 record")

    monkeypatch.setattr(wiz, "import_bundled_watchlist", fake_bundled)
    rc = wiz.run_wizard(
        _args(skip_probes=True, system=True),
        input_fn=_input_seq(_system_scope_inputs()),
        getpass_fn=_getpass_seq(["tok"]),
    )
    assert rc == 0
    chown_pairs = {(p, u, g) for (p, u, g) in _stub_perms["chown_calls"]}
    assert (str(db), 2000, 2000) in chown_pairs


def test_run_wizard_system_scope_prints_summary_of_chowned_paths(
    _stub_perms, monkeypatch, tmp_path, capsys
):
    """One operator-visible summary line listing every file the wizard
    just gave lynceus group ownership to, so a `--system` run is
    auditable from the terminal output alone."""
    paths_d = _stub_system_wizard_paths(monkeypatch, tmp_path)
    paths_d["data_dir"].mkdir(parents=True, exist_ok=True)
    db = paths_d["db_path"]

    def fake_bundled(db_path, override_file):
        Path(db_path).write_text("fake\n")
        return (True, "imported 1 record")

    monkeypatch.setattr(wiz, "import_bundled_watchlist", fake_bundled)
    rc = wiz.run_wizard(
        _args(skip_probes=True, system=True),
        input_fn=_input_seq(_system_scope_inputs()),
        getpass_fn=_getpass_seq(["tok"]),
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "Applied lynceus group ownership" in out
    assert str(paths_d["target"]) in out
    assert str(db) in out


# ---- Integration: every daemon-touched path ends up correct -------------


def test_run_wizard_system_scope_all_daemon_touched_paths_have_correct_perms(
    _stub_perms, monkeypatch, tmp_path
):
    """The integration regression that would have caught rc1's
    broken-by-default --system mode end-to-end.

    A full wizard run in scope="system" must give EVERY file the daemon
    needs to read (config, severity overrides) and EVERY file/dir it
    needs to write (DB, data_dir, log_dir) the appropriate ownership
    and mode. If any of these regress, the unit fails on first start —
    that's what this test exists to prevent.
    """
    paths_d = _stub_system_wizard_paths(monkeypatch, tmp_path)
    paths_d["data_dir"].mkdir(parents=True, exist_ok=True)
    db = paths_d["db_path"]

    def fake_bundled(db_path, override_file):
        Path(db_path).write_text("fake sqlite\n")
        Path(str(db_path) + "-wal").write_text("fake wal\n")
        Path(str(db_path) + "-shm").write_text("fake shm\n")
        return (True, "imported 1 record")

    monkeypatch.setattr(wiz, "import_bundled_watchlist", fake_bundled)
    rc = wiz.run_wizard(
        _args(skip_probes=True, system=True),
        input_fn=_input_seq(_system_scope_inputs()),
        getpass_fn=_getpass_seq(["tok"]),
    )
    assert rc == 0

    chown_index: dict[str, tuple[int, int]] = {
        p: (u, g) for (p, u, g) in _stub_perms["chown_calls"]
    }
    chmod_index: dict[str, int] = {p: m for (p, m) in _stub_perms["chmod_calls"]}

    sev_path = str(paths_d["target"].parent / "severity_overrides.yaml")
    wal = str(db) + "-wal"
    shm = str(db) + "-shm"

    # READ paths: root:lynceus 0640.
    for p in (str(paths_d["target"]), sev_path):
        assert chown_index.get(p) == (0, 2000), f"{p} must be root:lynceus"
        assert chmod_index.get(p) == 0o640, f"{p} must be mode 0o640"

    # WRITE dirs: lynceus:lynceus 0750.
    for p in (str(paths_d["data_dir"]), str(paths_d["log_dir"])):
        assert chown_index.get(p) == (2000, 2000), f"{p} must be lynceus:lynceus"
        assert chmod_index.get(p) == 0o750, f"{p} must be mode 0o750"

    # WRITE files (DB + sidecars): lynceus:lynceus 0640. The daemon owns
    # them so it can write; mode keeps the file non-executable.
    for p in (str(db), wal, shm):
        assert chown_index.get(p) == (2000, 2000), f"{p} must be lynceus:lynceus"
        assert chmod_index.get(p) == 0o640, f"{p} must be mode 0o640"


# Suppress the unused-import warning for sys (used by helpers above).
_ = sys
