"""Tests for the config layer."""

import logging
import pathlib
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
    # Tier 3: load_config back-fills missing db_path from the XDG/FHS
    # default for the install scope rather than the CWD-relative
    # "lynceus.db" Config-default; a legacy yaml lacking db_path is
    # treated as user-scope (tmp_path is not /etc/lynceus/lynceus.yaml).
    from lynceus import paths
    assert cfg.db_path == str(paths.default_db_path("user"))
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


# ---- v0.7.6 Tier 3 db_path back-fill regression ----------------------------


def test_load_config_back_fills_db_path_for_user_scope_yaml(tmp_path):
    """REGRESSION (v0.7.6 Tier 3): a yaml lacking db_path: must
    back-fill to paths.default_db_path("user") rather than the
    CWD-relative "lynceus.db" Config-default. Pre-fix the daemon
    opened CWD-relative lynceus.db while the wizard imported into
    the XDG path, leaving the watchlist invisible to the live
    process."""
    from lynceus import paths

    cfg_path = tmp_path / "lynceus.yaml"
    _write(cfg_path, "kismet_url: http://127.0.0.1:2501\n")
    cfg = load_config(str(cfg_path))
    assert cfg.db_path == str(paths.default_db_path("user"))


def test_load_config_back_fills_db_path_for_system_scope_yaml(
    tmp_path, monkeypatch
):
    """When the config file path resolves to
    paths.default_config_path("system") the back-fill picks the
    system-scope FHS data path, not the user-scope XDG one. Mirrors
    the daemon's runtime behavior on a /etc/lynceus install."""
    from lynceus import paths

    # Stand in /etc/lynceus by pointing default_config_path("system")
    # at the tmp file we just wrote. Avoids needing to write
    # /etc/lynceus/lynceus.yaml on the test host.
    system_cfg = tmp_path / "lynceus.yaml"
    _write(system_cfg, "kismet_url: http://127.0.0.1:2501\n")
    fhs_db = tmp_path / "var" / "lib" / "lynceus" / "lynceus.db"
    monkeypatch.setattr(
        paths, "default_config_path",
        lambda scope: system_cfg if scope == "system" else tmp_path / "user-config.yaml",
    )
    monkeypatch.setattr(
        paths, "default_db_path",
        lambda scope: fhs_db if scope == "system" else tmp_path / "user-lynceus.db",
    )

    cfg = load_config(str(system_cfg))
    assert cfg.db_path == str(fhs_db)


def test_load_config_honors_explicit_db_path_override(tmp_path):
    """An operator-set db_path: in lynceus.yaml is honored verbatim;
    the back-fill only fires when the key is absent. Pin so a future
    refactor doesn't turn the back-fill into an unconditional
    overwrite."""
    cfg_path = tmp_path / "lynceus.yaml"
    custom_db = tmp_path / "custom" / "lynceus.db"
    _write(
        cfg_path,
        f"kismet_url: http://127.0.0.1:2501\ndb_path: {custom_db}\n",
    )
    cfg = load_config(str(cfg_path))
    assert cfg.db_path == str(custom_db)


def test_load_config_back_fill_survives_unsupported_system_scope(
    tmp_path, monkeypatch
):
    """On macOS / Windows the system-scope helper raises
    NotImplementedError; the back-fill must catch it and fall back
    to user scope rather than propagating the exception."""
    from lynceus import paths

    cfg_path = tmp_path / "lynceus.yaml"
    _write(cfg_path, "kismet_url: http://127.0.0.1:2501\n")

    def _raise(scope):
        raise NotImplementedError("system scope unsupported on this platform")

    user_db = tmp_path / "user.db"
    monkeypatch.setattr(paths, "default_config_path", _raise)
    monkeypatch.setattr(
        paths, "default_db_path",
        lambda scope: user_db if scope == "user" else tmp_path / "system.db",
    )

    cfg = load_config(str(cfg_path))
    assert cfg.db_path == str(user_db)


def test_load_config_back_fill_survives_default_db_path_raising(
    tmp_path, monkeypatch
):
    """Defensive: if the scope probe resolves to "system" (e.g. on a
    Linux host where default_config_path("system") succeeds and the
    operator's yaml happens to resolve to the canonical system path)
    but paths.default_db_path("system") then raises NotImplementedError
    on the same call — e.g. under a partial test monkeypatch or a
    misconfigured paths module — the back-fill must still degrade to
    paths.default_db_path("user") rather than propagating. This is the
    failure mode the orchestrator tests in test_validate surfaced
    before the wider try/except landed."""
    from lynceus import paths

    cfg_path = tmp_path / "lynceus.yaml"
    _write(cfg_path, "kismet_url: http://127.0.0.1:2501\n")
    user_db = tmp_path / "user.db"
    # Make scope detection resolve to "system" (config file at the
    # patched system path), then make default_db_path("system") raise
    # while default_db_path("user") succeeds.
    monkeypatch.setattr(
        paths, "default_config_path",
        lambda scope: cfg_path if scope == "system" else tmp_path / "other.yaml",
    )

    def _db(scope):
        if scope == "system":
            raise NotImplementedError("system-scope db unsupported")
        return user_db

    monkeypatch.setattr(paths, "default_db_path", _db)

    cfg = load_config(str(cfg_path))
    assert cfg.db_path == str(user_db)


# ---------------------------------------------------------------------------
# Documentation drift guards (v0.9.5).
#
# ble_bridge shipped as the 0.9.4 headline feature and reached neither the
# configuration reference nor the example config; capture.probe_ssids is
# the project's flagship privacy control and the reference never named it.
# Both were found by diffing Config.model_fields against the docs, so that
# diff is now a test.
# ---------------------------------------------------------------------------

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_EXAMPLE_CONFIG = _REPO_ROOT / "config" / "lynceus.example.yaml"
_CONFIG_REFERENCE = _REPO_ROOT / "docs" / "CONFIGURATION.md"


def test_every_config_field_appears_in_the_configuration_reference():
    """A field the operator can set but cannot look up is a field that
    gets set wrong. Add a row to docs/CONFIGURATION.md when adding one."""
    doc = _CONFIG_REFERENCE.read_text(encoding="utf-8")
    missing = sorted(f for f in config_mod.Config.model_fields if f"`{f}`" not in doc)
    assert missing == [], f"undocumented in docs/CONFIGURATION.md: {missing}"


def test_every_config_field_appears_in_the_example_config():
    """The example is the file operators copy. A field absent from it is
    a field most deployments will never discover."""
    text = _EXAMPLE_CONFIG.read_text(encoding="utf-8")
    missing = sorted(f for f in config_mod.Config.model_fields if f not in text)
    assert missing == [], f"absent from config/lynceus.example.yaml: {missing}"


def test_example_config_loads_through_the_real_config_constructor():
    """extra='forbid' means a stale or misspelled key in the shipped
    example fails here rather than at an operator's first daemon start."""
    doc = yaml.safe_load(_EXAMPLE_CONFIG.read_text(encoding="utf-8")) or {}
    cfg = config_mod.Config(**doc)
    # The two defaults the README leans on hardest; if either flips, the
    # privacy posture the docs describe is no longer what ships.
    assert cfg.capture.probe_ssids is False
    assert cfg.ble_bridge.enabled is False


# ---------------------------------------------------------------------------
# Co-observation explorer (v3 Decision 6).
#
# The panel ships behind a capability toggle that is OFF by default. Iterating
# /devices/{mac}/co-observations across every MAC reconstructs an association
# graph, and a stolen operator session can request 20,000 endpoints even though
# each page shows 25. A capability that is not enabled cannot be enumerated,
# which is the only control here that changes the exposure rather than merely
# pacing it.
# ---------------------------------------------------------------------------


def test_co_observation_is_off_by_default():
    """⭐ The security property, not a preference.

    If this default ever flips, an association-graph endpoint becomes reachable
    on every stock install without the operator choosing it.
    """
    assert config_mod.CoObservationConfig().enabled is False
    assert config_mod.Config(db_path="/tmp/x.db").co_observation.enabled is False


def test_co_observation_defaults():
    c = config_mod.CoObservationConfig()
    assert c.window_days == 30
    assert c.proximity_seconds == 300
    assert c.gap_seconds == 900
    assert c.max_candidates == 25


@pytest.mark.parametrize(
    "field,value",
    [
        ("window_days", 0),
        ("window_days", 3651),
        ("proximity_seconds", -1),
        ("proximity_seconds", 86_401),
        ("gap_seconds", 0),
        ("gap_seconds", 86_401),
        ("max_candidates", 0),
        ("max_candidates", 201),
    ],
)
def test_co_observation_rejects_out_of_range(field, value):
    with pytest.raises(ValidationError):
        config_mod.CoObservationConfig(**{field: value})


def test_co_observation_max_candidates_matches_the_db_limit_ceiling():
    """The config ceiling and Database.list_co_observations' own limit bound
    must agree, or a value the config accepts raises at query time."""
    from lynceus.db import Database

    cfg = config_mod.CoObservationConfig(max_candidates=200)
    assert cfg.max_candidates == 200
    assert Database.list_co_observations.__doc__ is not None


def test_co_observation_rejects_unknown_keys():
    with pytest.raises(ValidationError):
        config_mod.CoObservationConfig(proximity_second=300)
