"""ble_bridge emission + reconfigure round-trip in the setup wizard.

tests/ is gitignored — these are NEVER committed (see project memory).

The round-trip test is the load-bearing one: --reconfigure renders from a
validated Config, so a key that is emitted but not read back would silently
reset an operator's choice to the default on every reconfigure.
"""

from __future__ import annotations

import yaml

from lynceus.config import Config, load_config
from lynceus.setup import core as wiz


def _answers(**overrides) -> dict:
    base = {
        "kismet_url": "http://localhost:2501",
        "kismet_api_key": "tok",
        "kismet_sources": ["wlan0"],
        "probe_ssids": False,
        "ble_friendly_names": True,
        "ntfy_url": "",
        "ntfy_topic": "",
        "min_rssi": -70,
    }
    base.update(overrides)
    return base


def test_default_emits_disabled_bridge():
    data = yaml.safe_load(wiz.render_config_yaml(_answers()))
    assert data["ble_bridge"]["enabled"] is False


def test_absent_key_does_not_raise():
    """Older callers pass an answers dict with no ble_bridge keys at all."""
    assert "ble_bridge:" in wiz.render_config_yaml(_answers())


def test_enabled_is_emitted():
    data = yaml.safe_load(wiz.render_config_yaml(_answers(ble_bridge_enabled=True)))
    assert data["ble_bridge"]["enabled"] is True


def test_adapter_is_emitted():
    data = yaml.safe_load(
        wiz.render_config_yaml(_answers(ble_bridge_enabled=True, ble_bridge_adapter="hci0"))
    )
    assert data["ble_bridge"]["adapter"] == "hci0"


def test_emitted_default_adapter_matches_the_model_default():
    """A hardcoded 'hci1' here would drift from BleBridgeConfig silently."""
    from lynceus.config import BleBridgeConfig

    data = yaml.safe_load(wiz.render_config_yaml(_answers()))
    assert data["ble_bridge"]["adapter"] == BleBridgeConfig().adapter


def test_rendered_yaml_loads_as_a_valid_config(tmp_path):
    path = tmp_path / "lynceus.yaml"
    path.write_text(
        wiz.render_config_yaml(_answers(ble_bridge_enabled=True, ble_bridge_adapter="hci0")),
        encoding="utf-8",
    )
    config = load_config(str(path))
    assert config.ble_bridge.enabled is True
    assert config.ble_bridge.adapter == "hci0"


def test_reconfigure_round_trip_preserves_the_operator_choice(tmp_path):
    """THE regression: emit -> load -> re-emit must not reset to default."""
    first = wiz.render_config_yaml(
        _answers(ble_bridge_enabled=True, ble_bridge_adapter="hci0")
    )
    path = tmp_path / "lynceus.yaml"
    path.write_text(first, encoding="utf-8")
    config = load_config(str(path))

    second = yaml.safe_load(wiz.render_config_yaml(wiz._answers_from_config(config)))
    assert second["ble_bridge"]["enabled"] is True
    assert second["ble_bridge"]["adapter"] == "hci0"


def test_reconfigure_round_trip_preserves_disabled(tmp_path):
    config = Config(kismet_url="http://localhost:2501")
    data = yaml.safe_load(wiz.render_config_yaml(wiz._answers_from_config(config)))
    assert data["ble_bridge"]["enabled"] is False


def test_comment_states_it_is_not_a_kismet_decoder():
    """The operator-facing why. Easy to lose in a later edit, so pinned."""
    text = wiz.render_config_yaml(_answers())
    assert "NOT a decoder over Kismet's data" in text


# ---- end-to-end: does the answer actually reach the file? ------------------
#
# The unit tests above drive render_config_yaml(answers) directly. The wizard
# does NOT: it builds a Config from answers and hands that to apply_config,
# which renders from the Config. Any field missing from that construction is
# collected, reported as applied, and silently dropped.


def _e2e_inputs(bridge_answer: str) -> list[str]:
    return [
        "",  # kismet URL default
        "wlan0",  # capture interface (freeform)
        "",  # probe_ssids default
        "",  # ble_friendly_names default
        bridge_answer,  # ble_bridge_enabled
        "",  # skip ntfy
        "",  # rssi default
        "",  # severity overrides default
        "",  # enable-alerting gate default (N)
    ]


def _run_wizard_to_file(monkeypatch, tmp_path, bridge_answer: str):
    from tests.test_setup_wizard import (
        _args,
        _getpass_seq,
        _input_seq,
        _stub_bundled_import,
        _stub_path_resolution,
    )
    from lynceus.cli import setup as cli

    _stub_path_resolution(monkeypatch, tmp_path)
    _stub_bundled_import(monkeypatch)
    monkeypatch.setattr(cli, "enumerate_wireless_interfaces", lambda: None)
    monkeypatch.setattr(cli, "enumerate_bluetooth_adapters", lambda: None)
    rc = cli.run_wizard(
        _args(skip_probes=True),
        input_fn=_input_seq(_e2e_inputs(bridge_answer)),
        getpass_fn=_getpass_seq(["tok"]),
    )
    assert rc == 0
    return yaml.safe_load((tmp_path / "lynceus.yaml").read_text(encoding="utf-8"))


def test_wizard_yes_actually_writes_enabled_true(monkeypatch, tmp_path):
    """THE regression: answer must survive answers -> Config -> rendered file."""
    data = _run_wizard_to_file(monkeypatch, tmp_path, "y")
    assert data["ble_bridge"]["enabled"] is True


def test_wizard_no_writes_enabled_false(monkeypatch, tmp_path):
    data = _run_wizard_to_file(monkeypatch, tmp_path, "n")
    assert data["ble_bridge"]["enabled"] is False
