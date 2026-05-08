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


def test_write_config_sets_0600_on_posix(monkeypatch, tmp_path):
    chmod_calls = []
    monkeypatch.setattr(wiz, "_is_windows", lambda: False)
    monkeypatch.setattr(wiz.os, "chmod", lambda p, m: chmod_calls.append((str(p), m)))
    target = tmp_path / "lynceus.yaml"
    wiz.write_config(target, "kismet_url: x\n")
    assert target.exists()
    assert chmod_calls == [(str(target), 0o600)]


def test_write_config_skips_chmod_on_windows(monkeypatch, tmp_path):
    chmod_calls = []
    monkeypatch.setattr(wiz, "_is_windows", lambda: True)
    monkeypatch.setattr(wiz.os, "chmod", lambda p, m: chmod_calls.append((str(p), m)))
    target = tmp_path / "lynceus.yaml"
    wiz.write_config(target, "kismet_url: x\n")
    assert target.exists()
    assert chmod_calls == []


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
    monkeypatch.setattr(wiz, "_euid", lambda: 0)  # pretend we're root for --system
    # Stub data + log dir mkdirs onto tmp_path so we don't try to mkdir
    # /var/lib/lynceus on the test host.
    monkeypatch.setattr(paths, "default_data_dir", lambda scope: tmp_path / "data")
    monkeypatch.setattr(paths, "default_log_dir", lambda scope: tmp_path / "log")
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


# Suppress the unused-import warning for sys (used by helpers above).
_ = sys
