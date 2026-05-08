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
    """Default end-to-end input sequence used by the smoke test and probe variants."""
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
        "",  # ntfy URL: accept default
        ntfy_topic,  # ntfy topic
        "",  # RSSI: accept default
        "",  # severity overrides path: accept default
        "n",  # don't import argus
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
    touch real user/system paths."""
    target = tmp_path / "lynceus.yaml"
    monkeypatch.setattr(wiz, "resolve_config_path", lambda scope, output: target)
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
        "",  # ntfy URL default
        "lynceus-deadbeef",
        "",  # rssi default
        "",  # severity overrides default
        "n",  # skip argus import
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
        "",  # ntfy URL default
        "lynceus-cafe",
        "y",  # continue after ntfy fail
        "",  # rssi default
        "",  # severity overrides default
        "n",  # skip argus
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
        "",  # ntfy URL default
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
        "",  # ntfy URL default
        "lynceus-cafe",
        "",  # rssi default
        "",  # severity overrides default
        "n",  # skip argus
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
        "",  # ntfy URL default
        "lynceus-cafe",
        "",  # rssi default
        "",  # severity overrides default
        "n",  # skip argus
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


# ---- argus import ----------------------------------------------------------


def test_argus_import_yes_invokes_subprocess(monkeypatch, tmp_path):
    csv = tmp_path / "argus.csv"
    csv.write_text("# meta: argus_export v3 (CP11)\n")
    captured = {}

    def fake_popen(args, **kwargs):
        captured["args"] = args
        proc = MagicMock()
        proc.wait.return_value = 0
        return proc

    monkeypatch.setattr(wiz.subprocess, "Popen", fake_popen)
    wiz.maybe_import_argus(
        db_path="lynceus.db",
        severity_path=str(tmp_path / "sev.yaml"),
        input_fn=_input_seq(["y", str(csv)]),
    )
    assert captured["args"][0] == "lynceus-import-argus"
    assert "--input" in captured["args"]
    idx = captured["args"].index("--input")
    assert captured["args"][idx + 1] == str(csv)


def test_argus_import_no_prints_deferred_message(capsys, tmp_path):
    wiz.maybe_import_argus(
        db_path="lynceus.db",
        severity_path=str(tmp_path / "sev.yaml"),
        input_fn=_input_seq(["n"]),
    )
    out = capsys.readouterr().out
    assert "Skipping import" in out
    assert "lynceus-import-argus" in out


def test_argus_import_re_prompts_when_path_missing(monkeypatch, tmp_path):
    csv = tmp_path / "argus.csv"
    csv.write_text("# meta: argus_export v3 (CP11)\n")
    captured = {}

    def fake_popen(args, **kwargs):
        captured["args"] = args
        proc = MagicMock()
        proc.wait.return_value = 0
        return proc

    monkeypatch.setattr(wiz.subprocess, "Popen", fake_popen)
    wiz.maybe_import_argus(
        db_path="lynceus.db",
        severity_path=str(tmp_path / "sev.yaml"),
        input_fn=_input_seq(["y", "/no/such/file.csv", str(csv)]),
    )
    # Must have ultimately Popen'd with the existing file
    idx = captured["args"].index("--input")
    assert captured["args"][idx + 1] == str(csv)


def test_argus_import_failure_prints_retry_hint(monkeypatch, tmp_path, capsys):
    csv = tmp_path / "argus.csv"
    csv.write_text("# meta: argus_export v3 (CP11)\n")

    def fake_popen(args, **kwargs):
        proc = MagicMock()
        proc.wait.return_value = 2
        return proc

    monkeypatch.setattr(wiz.subprocess, "Popen", fake_popen)
    wiz.maybe_import_argus(
        db_path="lynceus.db",
        severity_path=str(tmp_path / "sev.yaml"),
        input_fn=_input_seq(["y", str(csv)]),
    )
    out = capsys.readouterr().out
    assert "Import failed" in out
    assert str(csv) in out


# ---- end-to-end smoke ------------------------------------------------------


def test_run_wizard_end_to_end_smoke(monkeypatch, tmp_path, capsys):
    target = tmp_path / "lynceus.yaml"
    monkeypatch.setattr(wiz, "resolve_config_path", lambda scope, output: target)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: ["wlan0", "wlan1"])
    # Probes: skip via flag.
    inputs = [
        "http://10.0.0.5:2501",  # custom kismet URL
        "1",  # pick wlan0
        "y",  # opt in to probe ssids
        "",  # default ble names
        "",  # default ntfy URL
        "lynceus-feedface",
        "-80",  # custom rssi
        "",  # severity overrides default path
        "n",  # skip argus import
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


# ---- maybe_import_argus prompt re-wording ----------------------------------


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


def test_maybe_import_argus_uses_reworded_prompt_when_bundled_succeeded(tmp_path):
    fn, prompts = _recording_input(["n"])
    wiz.maybe_import_argus(
        db_path="lynceus.db",
        severity_path=str(tmp_path / "sev.yaml"),
        input_fn=fn,
        bundled_succeeded=True,
    )
    assert any("additional Argus CSV" in p for p in prompts)
    assert not any("Would you like to import Argus" in p for p in prompts)


def test_maybe_import_argus_uses_original_prompt_when_bundled_not_succeeded(tmp_path):
    fn, prompts = _recording_input(["n"])
    wiz.maybe_import_argus(
        db_path="lynceus.db",
        severity_path=str(tmp_path / "sev.yaml"),
        input_fn=fn,
        bundled_succeeded=False,
    )
    assert any("Would you like to import Argus" in p for p in prompts)
    assert not any("additional Argus CSV" in p for p in prompts)


# ---- wizard flow integration with bundled import --------------------------


def test_wizard_with_bundled_present_success_prints_and_reworded_prompt(
    monkeypatch, tmp_path, capsys
):
    target = tmp_path / "lynceus.yaml"
    monkeypatch.setattr(wiz, "resolve_config_path", lambda s, o: target)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
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
    assert any("additional Argus CSV" in p for p in prompts)


def test_wizard_with_bundled_present_failure_warns_and_keeps_original_prompt(
    monkeypatch, tmp_path, capsys
):
    target = tmp_path / "lynceus.yaml"
    monkeypatch.setattr(wiz, "resolve_config_path", lambda s, o: target)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
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
    assert any("Would you like to import Argus" in p for p in prompts)


def test_wizard_with_bundled_absent_prints_nothing_keeps_original_prompt(
    monkeypatch, tmp_path, capsys
):
    target = tmp_path / "lynceus.yaml"
    monkeypatch.setattr(wiz, "resolve_config_path", lambda s, o: target)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
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
    assert any("Would you like to import Argus" in p for p in prompts)


def test_wizard_passes_db_path_and_severity_to_bundled_helper(monkeypatch, tmp_path):
    from lynceus import paths

    target = tmp_path / "lynceus.yaml"
    monkeypatch.setattr(wiz, "resolve_config_path", lambda s, o: target)
    monkeypatch.setattr(wiz, "enumerate_wireless_interfaces", lambda: None)
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
    monkeypatch.setattr(wiz, "_is_windows", lambda: False)
    monkeypatch.setattr(wiz, "_euid", lambda: 0)  # pretend we're root for --system
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


# Suppress the unused-import warning for sys (used by helpers above).
_ = sys
