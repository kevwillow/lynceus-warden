"""Tests for the config layer."""

import logging

import pytest
import yaml
from pydantic import ValidationError

from lynceus.config import load_config


def _write(path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def test_defaults_load_with_empty_yaml(tmp_path):
    cfg_path = tmp_path / "lynceus.yaml"
    _write(cfg_path, "")
    cfg = load_config(str(cfg_path))
    assert cfg.kismet_url == "http://localhost:2501"
    assert cfg.kismet_api_key is None
    assert cfg.kismet_fixture_path is None
    assert cfg.db_path == "lynceus.db"
    assert cfg.location_id == "default"
    assert cfg.location_label == "Default Location"
    assert cfg.poll_interval_seconds == 60
    assert cfg.log_level == "INFO"


def test_yaml_overrides_defaults(tmp_path):
    cfg_path = tmp_path / "lynceus.yaml"
    _write(cfg_path, "poll_interval_seconds: 30\n")
    cfg = load_config(str(cfg_path))
    assert cfg.poll_interval_seconds == 30


def test_invalid_log_level_rejected(tmp_path):
    cfg_path = tmp_path / "lynceus.yaml"
    _write(cfg_path, "log_level: TRACE\n")
    with pytest.raises(ValidationError):
        load_config(str(cfg_path))


def test_poll_interval_too_low_rejected(tmp_path):
    cfg_path = tmp_path / "lynceus.yaml"
    _write(cfg_path, "poll_interval_seconds: 1\n")
    with pytest.raises(ValidationError):
        load_config(str(cfg_path))


def test_extra_field_rejected(tmp_path):
    cfg_path = tmp_path / "lynceus.yaml"
    _write(cfg_path, "unknown_key: 1\n")
    with pytest.raises(ValidationError):
        load_config(str(cfg_path))


def test_load_config_missing_file_raises(tmp_path):
    cfg_path = tmp_path / "nope.yaml"
    with pytest.raises(FileNotFoundError):
        load_config(str(cfg_path))


def test_load_config_malformed_yaml_raises(tmp_path):
    cfg_path = tmp_path / "lynceus.yaml"
    _write(cfg_path, "key: 'unterminated\n")
    with pytest.raises(yaml.YAMLError):
        load_config(str(cfg_path))


def test_rules_path_default_none(tmp_path):
    cfg_path = tmp_path / "lynceus.yaml"
    _write(cfg_path, "")
    cfg = load_config(str(cfg_path))
    assert cfg.rules_path is None
    assert cfg.allowlist_path is None


def test_alert_dedup_window_default_3600(tmp_path):
    cfg_path = tmp_path / "lynceus.yaml"
    _write(cfg_path, "")
    cfg = load_config(str(cfg_path))
    assert cfg.alert_dedup_window_seconds == 3600


def test_negative_dedup_window_rejected(tmp_path):
    cfg_path = tmp_path / "lynceus.yaml"
    _write(cfg_path, "alert_dedup_window_seconds: -1\n")
    with pytest.raises(ValidationError):
        load_config(str(cfg_path))


def test_ntfy_defaults_all_none(tmp_path):
    cfg_path = tmp_path / "lynceus.yaml"
    _write(cfg_path, "")
    cfg = load_config(str(cfg_path))
    assert cfg.ntfy_url is None
    assert cfg.ntfy_topic is None
    assert cfg.ntfy_auth_token is None


def test_ntfy_url_without_topic_rejected(tmp_path):
    cfg_path = tmp_path / "lynceus.yaml"
    _write(cfg_path, "ntfy_url: https://ntfy.sh\n")
    with pytest.raises(ValidationError):
        load_config(str(cfg_path))


def test_ntfy_topic_without_url_rejected(tmp_path):
    cfg_path = tmp_path / "lynceus.yaml"
    _write(cfg_path, "ntfy_topic: my-alerts\n")
    with pytest.raises(ValidationError):
        load_config(str(cfg_path))


def test_ntfy_auth_token_alone_no_error(tmp_path):
    cfg_path = tmp_path / "lynceus.yaml"
    _write(cfg_path, "ntfy_auth_token: secret\n")
    cfg = load_config(str(cfg_path))
    assert cfg.ntfy_url is None
    assert cfg.ntfy_topic is None
    assert cfg.ntfy_auth_token == "secret"


def test_fixture_and_url_both_set_logs_warning(tmp_path, caplog):
    cfg_path = tmp_path / "lynceus.yaml"
    _write(
        cfg_path,
        "kismet_fixture_path: /tmp/x.json\nkismet_url: http://other:1234\n",
    )
    with caplog.at_level(logging.WARNING, logger="lynceus.config"):
        load_config(str(cfg_path))
    assert any(r.levelname == "WARNING" for r in caplog.records)


# ------------------- multi-source / multi-adapter additions -----------------


def test_kismet_sources_default_none(tmp_path):
    cfg_path = tmp_path / "lynceus.yaml"
    _write(cfg_path, "")
    cfg = load_config(str(cfg_path))
    assert cfg.kismet_sources is None


def test_kismet_sources_empty_list_rejected(tmp_path):
    cfg_path = tmp_path / "lynceus.yaml"
    _write(cfg_path, "kismet_sources: []\n")
    with pytest.raises(ValidationError):
        load_config(str(cfg_path))


def test_kismet_sources_strips_whitespace(tmp_path):
    cfg_path = tmp_path / "lynceus.yaml"
    _write(cfg_path, "kismet_sources:\n  - '  alfa-2.4ghz  '\n  - builtin-bt\n")
    cfg = load_config(str(cfg_path))
    assert cfg.kismet_sources == ["alfa-2.4ghz", "builtin-bt"]


def test_kismet_sources_blank_entry_rejected(tmp_path):
    cfg_path = tmp_path / "lynceus.yaml"
    _write(cfg_path, "kismet_sources:\n  - alfa\n  - '   '\n")
    with pytest.raises(ValidationError):
        load_config(str(cfg_path))


def test_kismet_source_locations_default_none(tmp_path):
    cfg_path = tmp_path / "lynceus.yaml"
    _write(cfg_path, "")
    cfg = load_config(str(cfg_path))
    assert cfg.kismet_source_locations is None


def test_kismet_source_locations_empty_value_rejected(tmp_path):
    cfg_path = tmp_path / "lynceus.yaml"
    _write(cfg_path, "kismet_source_locations:\n  alfa-2.4ghz: ''\n")
    with pytest.raises(ValidationError):
        load_config(str(cfg_path))


def test_kismet_source_locations_strips_whitespace(tmp_path):
    cfg_path = tmp_path / "lynceus.yaml"
    _write(
        cfg_path,
        "kismet_source_locations:\n  '  alfa-2.4ghz  ': '  wifi-corner  '\n",
    )
    cfg = load_config(str(cfg_path))
    assert cfg.kismet_source_locations == {"alfa-2.4ghz": "wifi-corner"}


def test_min_rssi_default_none(tmp_path):
    cfg_path = tmp_path / "lynceus.yaml"
    _write(cfg_path, "")
    cfg = load_config(str(cfg_path))
    assert cfg.min_rssi is None


def test_min_rssi_in_valid_range_accepted(tmp_path):
    for v in (-85, -1, -120, 0):
        cfg_path = tmp_path / "lynceus.yaml"
        _write(cfg_path, f"min_rssi: {v}\n")
        cfg = load_config(str(cfg_path))
        assert cfg.min_rssi == v


def test_min_rssi_out_of_range_rejected(tmp_path):
    for v in (-121, 1, 50):
        cfg_path = tmp_path / "lynceus.yaml"
        _write(cfg_path, f"min_rssi: {v}\n")
        with pytest.raises(ValidationError):
            load_config(str(cfg_path))


def test_kismet_timeout_default_10(tmp_path):
    cfg_path = tmp_path / "lynceus.yaml"
    _write(cfg_path, "")
    cfg = load_config(str(cfg_path))
    assert cfg.kismet_timeout_seconds == 10.0


def test_kismet_timeout_zero_rejected(tmp_path):
    cfg_path = tmp_path / "lynceus.yaml"
    _write(cfg_path, "kismet_timeout_seconds: 0\n")
    with pytest.raises(ValidationError):
        load_config(str(cfg_path))


def test_kismet_timeout_negative_rejected(tmp_path):
    cfg_path = tmp_path / "lynceus.yaml"
    _write(cfg_path, "kismet_timeout_seconds: -1\n")
    with pytest.raises(ValidationError):
        load_config(str(cfg_path))


def test_kismet_timeout_too_large_rejected(tmp_path):
    cfg_path = tmp_path / "lynceus.yaml"
    _write(cfg_path, "kismet_timeout_seconds: 121.0\n")
    with pytest.raises(ValidationError):
        load_config(str(cfg_path))


def test_kismet_health_check_on_startup_default_true(tmp_path):
    cfg_path = tmp_path / "lynceus.yaml"
    _write(cfg_path, "")
    cfg = load_config(str(cfg_path))
    assert cfg.kismet_health_check_on_startup is True
