"""Tests for the config layer."""

import logging
from urllib.parse import urlsplit

import pytest
import requests
import yaml
from pydantic import ValidationError

from lynceus import config as config_mod
from lynceus.cli import setup as setup_mod
from lynceus.config import Config, load_config


def _write(path, content: str) -> None:
    path.write_text(content, encoding="utf-8")


def test_defaults_load_with_empty_yaml(tmp_path):
    cfg_path = tmp_path / "lynceus.yaml"
    _write(cfg_path, "")
    cfg = load_config(str(cfg_path))
    assert cfg.kismet_url == "http://127.0.0.1:2501"
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


# ------------------- G1 regression: URL scheme validation -------------------
#
# rc1 shipped without scheme validation on ``kismet_url`` / ``ntfy_url``.
# Operators typing ``127.0.0.1:2501`` at the wizard would land that string
# into the config; the daemon then handed it to ``requests.get`` and crashed
# at poll time with ``MissingSchema``. The unit tests of the day mocked
# ``requests``, so they never saw the failure mode that bit production.
#
# These tests demonstrate the failure mode against the *real* parser /
# real ``requests``, then prove the validator now blocks it.


def test_real_urlsplit_on_scheme_less_input_has_no_netloc():
    """``urlsplit`` on ``"127.0.0.1:2501"`` does not produce an http URL.

    Documents exactly what the rc1 mocks papered over. Depending on Python
    version the parser may put the host into ``scheme`` (treating
    ``127.0.0.1`` as the scheme) or leave both fields empty — but the
    netloc is always empty, which is what our validator hinges on.
    """
    parts = urlsplit("127.0.0.1:2501")
    assert parts.netloc == ""
    assert parts.scheme not in ("http", "https")


def test_requests_get_on_scheme_less_url_raises():
    """Real ``requests.get`` refuses scheme-less URLs at request time.

    Two failure modes the validator catches:

    * ``InvalidSchema`` for inputs with a colon (``requests`` parses
      ``127.0.0.1:2501/foo`` as ``<scheme=127.0.0.1>:<rest>`` and finds no
      transport adapter for that scheme). This is what bit rc1.
    * ``MissingSchema`` for bare hosts (``kismet.local/foo``).

    Both are unusable for HTTP. We use a tiny timeout because the library
    raises synchronously during URL parsing — no network call is attempted.
    """
    with pytest.raises(requests.exceptions.InvalidSchema):
        requests.get("127.0.0.1:2501/foo", timeout=0.001)
    with pytest.raises(requests.exceptions.MissingSchema):
        requests.get("kismet.local/foo", timeout=0.001)


@pytest.mark.parametrize(
    "bad_url",
    [
        "127.0.0.1:2501",
        "localhost:2501",
        "kismet.local",
        "://nohost:2501",
        "http:",
        "http://",
        "ftp://example.com",
        "ws://example.com",
        "",
        "   ",
    ],
)
def test_kismet_url_invalid_rejected(tmp_path, bad_url):
    cfg_path = tmp_path / "lynceus.yaml"
    _write(cfg_path, f"kismet_url: {bad_url!r}\n")
    with pytest.raises(ValidationError) as exc:
        load_config(str(cfg_path))
    assert "kismet_url" in str(exc.value)


@pytest.mark.parametrize(
    "good_url",
    [
        "http://127.0.0.1:2501",
        "http://localhost:2501",
        "https://kismet.example.com",
        "https://kismet.example.com:9000/path",
    ],
)
def test_kismet_url_valid_accepted(tmp_path, good_url):
    cfg_path = tmp_path / "lynceus.yaml"
    _write(cfg_path, f"kismet_url: {good_url}\n")
    cfg = load_config(str(cfg_path))
    assert cfg.kismet_url == good_url


@pytest.mark.parametrize(
    "bad_url",
    [
        "ntfy.sh",
        "127.0.0.1:80",
        "ftp://ntfy.sh",
        "://nohost",
    ],
)
def test_ntfy_url_invalid_rejected_when_set(tmp_path, bad_url):
    cfg_path = tmp_path / "lynceus.yaml"
    _write(cfg_path, f"ntfy_url: {bad_url!r}\nntfy_topic: my-topic\n")
    with pytest.raises(ValidationError) as exc:
        load_config(str(cfg_path))
    assert "ntfy_url" in str(exc.value)


def test_ntfy_url_empty_string_collapses_to_none(tmp_path):
    """Operators (and the wizard) write ``ntfy_url: ""`` to disable ntfy.

    The before-validator collapses empty / whitespace-only inputs to
    ``None`` so they pair cleanly with ``ntfy_topic: ""`` and skip the
    ntfy_pair model_validator.
    """
    cfg_path = tmp_path / "lynceus.yaml"
    _write(cfg_path, 'ntfy_url: ""\nntfy_topic: ""\n')
    cfg = load_config(str(cfg_path))
    assert cfg.ntfy_url is None
    assert cfg.ntfy_topic == ""


def test_ntfy_url_whitespace_only_collapses_to_none(tmp_path):
    cfg_path = tmp_path / "lynceus.yaml"
    _write(cfg_path, 'ntfy_url: "   "\n')
    cfg = load_config(str(cfg_path))
    assert cfg.ntfy_url is None


@pytest.mark.parametrize(
    "good_url",
    [
        "http://ntfy.example.com",
        "https://ntfy.sh",
        "https://ntfy.example.com:8443/foo",
    ],
)
def test_ntfy_url_valid_accepted(tmp_path, good_url):
    cfg_path = tmp_path / "lynceus.yaml"
    _write(cfg_path, f"ntfy_url: {good_url}\nntfy_topic: my-topic\n")
    cfg = load_config(str(cfg_path))
    assert cfg.ntfy_url == good_url


def test_kismet_url_validator_runs_on_re_validation():
    """Direct ``Config`` construction (re-validation) triggers the validator.

    The config layer must reject scheme-less URLs no matter how the model
    was built — load_config, ``Config(**data)``, or ``model_validate``.
    """
    with pytest.raises(ValidationError):
        Config(kismet_url="127.0.0.1:2501")
    with pytest.raises(ValidationError):
        Config.model_validate({"kismet_url": "kismet.local"})


# ------------------- S4: DEFAULT_KISMET_URL is a single source of truth ----


def test_default_kismet_url_unified_across_modules():
    """The wizard, the config defaults, and the fixture-wins comparison
    must all reference the same constant. Two diverging values caused the
    rc1 ``fixture wins`` warning to misfire silently because the comparison
    was against the wrong literal."""
    assert config_mod.DEFAULT_KISMET_URL == "http://127.0.0.1:2501"
    assert setup_mod.DEFAULT_KISMET_URL is config_mod.DEFAULT_KISMET_URL


def test_fixture_warning_compares_against_unified_default(tmp_path, caplog):
    """When ``kismet_url`` matches ``DEFAULT_KISMET_URL`` (the loopback IP),
    setting ``kismet_fixture_path`` alongside it should NOT trigger the
    fixture-vs-non-default-url warning. Pre-fix this misfired because the
    constant was ``http://localhost:2501`` while the wizard wrote
    ``http://127.0.0.1:2501``."""
    cfg_path = tmp_path / "lynceus.yaml"
    _write(
        cfg_path,
        "kismet_fixture_path: /tmp/x.json\nkismet_url: http://127.0.0.1:2501\n",
    )
    with caplog.at_level(logging.WARNING, logger="lynceus.config"):
        load_config(str(cfg_path))
    assert not any("fixture wins" in r.message for r in caplog.records if r.levelname == "WARNING")
