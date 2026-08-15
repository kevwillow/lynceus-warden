"""`lynceus-setup --reconfigure` must not silently revert hand-edited settings.

The wizard collects ten answers; ``Config`` has forty fields. ``--reconfigure``
is a blind overwrite — ``preflight_existing`` gates only on whether the file
exists, and nothing ever read the old one back — so every setting the operator
hand-edited was reverted to its default while the wizard reported success.

⭐ The field list here is DERIVED from ``Config.model_fields``, never
transcribed. A hand-copied derivation looks derived and isn't: transcribing it
would mean a field added tomorrow is silently untested, which is the exact
shape of the bug being fixed.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from lynceus.config import Config, load_config
from lynceus.setup.core import (
    DEFAULT_UI_PORT,
    _answers_from_config,
    apply_config,
    carry_forward_settings,
    render_config_yaml,
)

# Every field set to something that is NOT its default. A fixture value equal
# to the default would make "it survived" true for a setting that was actually
# discarded — a control that cannot fail. `_assert_all_non_default` enforces it.
NON_DEFAULT: dict = {
    "kismet_url": "http://10.0.0.9:2501",
    "kismet_api_key": "SECRETKEY",
    "kismet_fixture_path": "/tmp/lynceus-fixture.json",
    "db_path": "/tmp/lynceus-custom.db",
    "location_id": "safehouse",
    "location_label": "Safe House",
    "poll_interval_seconds": 17,
    "log_level": "DEBUG",
    "rules_path": "/tmp/lynceus-rules.yaml",
    "allowlist_path": "/tmp/lynceus-allowlist.yaml",
    "severity_overrides_path": "/tmp/lynceus-overrides.yaml",
    "alert_dedup_window_seconds": 111,
    "ntfy_url": "https://ntfy.example.org",
    "ntfy_topic": "my-topic",
    "ntfy_auth_token": "tk_secret",
    "ui_bind_host": "0.0.0.0",
    "ui_allow_remote": True,
    "ui_bind_port": 9999,
    "kismet_sources": ["wlan0mon"],
    "kismet_source_locations": {"wlan0mon": "roof"},
    "min_rssi": -70,
    "kismet_timeout_seconds": 33.0,
    "kismet_health_check_on_startup": False,
    "heartbeat_enabled": True,
    "heartbeat_interval_hours": 6,
    "evidence_capture_enabled": False,
    "evidence_retention_days": 7,
    "sightings_retention_days": 45,
    "watchlist_staleness_warn_days": 5,
    "evidence_store_gps": True,
    "capture": {"probe_ssids": True, "ble_friendly_names": False},
    "ble_bridge": {"enabled": True, "adapter": "hci7", "flush_interval": 42},
    "co_observation": {
        "enabled": True,
        "window_days": 14,
        "proximity_seconds": 60,
        "gap_seconds": 120,
        "max_candidates": 50,
    },
}


def _leaf_fields(cfg: Config) -> dict[str, object]:
    """Flatten a Config to ``{"a": v, "nested.b": v}``, derived from the model."""
    out: dict[str, object] = {}
    for name in type(cfg).model_fields:
        value = getattr(cfg, name)
        nested = type(value)
        if hasattr(nested, "model_fields"):  # a sub-model: recurse one level
            for sub in nested.model_fields:
                out[f"{name}.{sub}"] = getattr(value, sub)
        else:
            out[name] = value
    return out


def _assert_all_non_default(cfg: Config) -> None:
    """VERIFY THE CONTROL: a seeded value equal to the default proves nothing."""
    defaults = _leaf_fields(Config())
    for key, value in _leaf_fields(cfg).items():
        assert value != defaults[key], (
            f"fixture value for {key!r} equals the default — this test would "
            f"report it as 'preserved' even if the code discarded it"
        )


def test_fixture_covers_every_config_field():
    """Guards the derivation itself. Without this, a field added to Config is
    silently absent from NON_DEFAULT and every test below skips it."""
    missing = set(Config.model_fields) - set(NON_DEFAULT)
    assert not missing, (
        f"Config gained {sorted(missing)}; add non-default value(s) to "
        f"NON_DEFAULT or these tests silently stop covering them"
    )


@pytest.fixture
def hand_edited(tmp_path: Path) -> tuple[Path, Config]:
    """A config carrying a non-default value for every field, on disk."""
    cfg = Config(**{**NON_DEFAULT, "db_path": str(tmp_path / "custom.db")})
    _assert_all_non_default(cfg)
    target = tmp_path / "lynceus.yaml"
    target.write_text(yaml.safe_dump(cfg.model_dump(mode="json")), encoding="utf-8")
    return target, cfg


def _reconfigure(target: Path, cfg: Config, tmp_path: Path) -> Config:
    """Run the wizard's own apply chain over an existing config, as
    ``--reconfigure`` does, then read it back with the daemon's own loader."""
    apply_config(
        cfg,
        scope="user",
        target_path=target,
        severity_overrides_path=tmp_path / "severity_overrides.yaml",
        allowlist_path=tmp_path / "allowlist.yaml",
        enabled_rule_types=None,
        run_bundled_import=False,
    )
    return load_config(str(target))


def test_reconfigure_preserves_every_setting_the_wizard_does_not_ask_about(
    hand_edited, tmp_path
):
    """The measured defect: rotating the Kismet API key silently reverted eight
    hand-edited settings, heartbeat_enabled (the dead-man's switch) among them."""
    target, cfg = hand_edited
    before = load_config(str(target))

    after = _reconfigure(target, before.model_copy(update={"kismet_api_key": "ROTATED"}), tmp_path)

    before_leaves, after_leaves = _leaf_fields(before), _leaf_fields(after)
    # Owned by the caller, not by the operator's file: `db_path`,
    # `allowlist_path` and `severity_overrides_path` are explicit `apply_config`
    # ARGUMENTS, and both real callers derive them from
    # `paths.default_*_path(scope)`. apply_config scaffolds real files at those
    # paths, so pointing the config at what it just created is coherent.
    #
    # ⚠️ It is coherent, not harmless: an operator who relocated their allowlist
    # is repointed at a freshly scaffolded EMPTY one, so every device they had
    # suppressed starts alerting again. That is a change to what `--reconfigure`
    # MEANS (adopt the operator's location, or relocate them?), not a defect
    # with an obvious fix, so it is measured and registered rather than
    # silently widened into this change. Reported on internal/SESSION_BOARD.md
    # for the register; deliberately not given a Finding number here, because
    # docs/AUDIT_REGISTER.md belongs to another session and a guessed number
    # is worse than none.
    owned = {"kismet_api_key", "db_path", "allowlist_path", "severity_overrides_path"}
    lost = {
        k: (before_leaves[k], after_leaves[k])
        for k in before_leaves
        if k not in owned and before_leaves[k] != after_leaves[k]
    }
    assert not lost, (
        "--reconfigure reverted settings the operator set and the wizard never "
        f"asked about: {lost}"
    )
    # "sweep all X" needs a floor, or an empty derivation passes vacuously.
    assert len(before_leaves) >= 35, f"only compared {len(before_leaves)} settings"


def test_reconfigure_still_applies_the_change_it_was_run_for(hand_edited, tmp_path):
    """⛔ Presence assertion. Without it, `preserve everything` — i.e. never
    writing anything at all — satisfies the test above."""
    target, _ = hand_edited
    before = load_config(str(target))
    assert before.kismet_api_key == "SECRETKEY"

    after = _reconfigure(target, before.model_copy(update={"kismet_api_key": "ROTATED"}), tmp_path)

    assert after.kismet_api_key == "ROTATED", (
        "the wizard failed to apply the change it was run for; preservation "
        "must not mean refusing to write"
    )


def test_a_previous_config_that_cannot_be_read_is_a_warning_not_a_silent_loss(
    tmp_path, monkeypatch
):
    """Fails CLOSED. The file is overwritten by the time the operator could
    check, so claiming "ok" for settings we could not read is the worst
    available outcome."""
    target = tmp_path / "lynceus.yaml"
    target.write_text("kismet_url: [unclosed\n", encoding="utf-8")
    cfg = Config(db_path=str(tmp_path / "d.db"))

    preserved, error = carry_forward_settings(target, "kismet_url: x\n")
    assert preserved == {}
    assert error is not None and "could not parse" in error

    report = apply_config(
        cfg,
        scope="user",
        target_path=target,
        severity_overrides_path=tmp_path / "so.yaml",
        allowlist_path=tmp_path / "al.yaml",
        enabled_rule_types=None,
        run_bundled_import=False,
    )
    step = next(s for s in report.steps if s.name == "write_config")
    assert step.status == "warning", f"expected a warning, got {step.status!r}"
    assert "GONE" in step.message


def test_a_readable_previous_config_is_reported_ok(hand_edited, tmp_path):
    """Presence assertion beside the absence one above: the warning must be
    reachable AND avoidable, or `always warn` would pass that test."""
    target, cfg = hand_edited
    report = apply_config(
        load_config(str(target)),
        scope="user",
        target_path=target,
        severity_overrides_path=tmp_path / "so.yaml",
        allowlist_path=tmp_path / "al.yaml",
        enabled_rule_types=None,
        run_bundled_import=False,
    )
    step = next(s for s in report.steps if s.name == "write_config")
    assert step.status == "ok", f"a readable config should not warn, got {step.message!r}"
    assert step.detail["carried_forward"], "nothing was reported as carried forward"


def test_no_unhandled_wizard_owned_subkey():
    """DERIVES the nested sub-keys the renderer rewrites but never asks about.

    A top-level setting the renderer omits is rescued automatically by
    carry_forward_settings. A NESTED one cannot be: appending a second
    `ble_bridge:` key would make YAML take the last occurrence and silently drop
    `enabled`/`adapter` with it. Each such sub-key therefore needs explicit
    handling, and this fails when a new one appears rather than trusting a
    comment to stay true.
    """
    rendered = yaml.safe_load(render_config_yaml(_answers_from_config(Config(**NON_DEFAULT))))
    handled = {"ble_bridge.flush_interval"}

    unowned = set()
    for key, value in rendered.items():
        if not isinstance(value, dict):
            continue
        model = type(getattr(Config(), key))
        for sub in model.model_fields:
            if sub not in value:
                unowned.add(f"{key}.{sub}")

    assert unowned <= handled, (
        f"{sorted(unowned - handled)} are rewritten by the renderer but never "
        f"asked about, so --reconfigure will silently revert them and "
        f"carry_forward_settings cannot rescue a nested key. Emit them in "
        f"render_config_yaml the way ble_bridge.flush_interval is."
    )


def test_ble_bridge_flush_interval_survives_reconfigure(hand_edited, tmp_path):
    """The nested case, end to end — the one carry_forward_settings can't reach."""
    target, _ = hand_edited
    before = load_config(str(target))
    assert before.ble_bridge.flush_interval == 42

    # As on the real --reconfigure path: the wizard never asks, so the incoming
    # Config carries None and the value must come off the existing file.
    fresh = before.model_copy(
        update={"ble_bridge": before.ble_bridge.model_copy(update={"flush_interval": None})}
    )
    after = _reconfigure(target, fresh, tmp_path)

    assert after.ble_bridge.flush_interval == 42
    assert after.ble_bridge.enabled is True, "carrying the sub-key dropped its siblings"
    assert after.ble_bridge.adapter == "hci7", "carrying the sub-key dropped its siblings"


def test_fresh_install_port_matches_the_default(tmp_path):
    """`ui_bind_port` is no longer emitted from a module constant. An absent key
    and an explicit 8765 must load identically, or removing the line changed
    behaviour for every fresh install."""
    rendered = render_config_yaml(_answers_from_config(Config(db_path=str(tmp_path / "d.db"))))
    assert "ui_bind_port" not in (yaml.safe_load(rendered) or {})

    target = tmp_path / "lynceus.yaml"
    target.write_text(rendered, encoding="utf-8")
    assert load_config(str(target)).ui_bind_port == DEFAULT_UI_PORT


def test_carry_forward_derives_the_owned_set_from_the_rendered_output(tmp_path):
    """The owned set must come from parsing the render, not a constant. Pinning
    it here means a field added to the renderer stops being carried forward
    automatically — and one removed starts being carried forward automatically."""
    target = tmp_path / "lynceus.yaml"
    target.write_text("kismet_url: http://a\nheartbeat_enabled: true\n", encoding="utf-8")

    preserved, error = carry_forward_settings(target, "kismet_url: http://b\n")
    assert error is None
    assert preserved == {"heartbeat_enabled": True}

    # Same existing file, a render that now owns heartbeat_enabled too.
    preserved, _ = carry_forward_settings(
        target, "kismet_url: http://b\nheartbeat_enabled: false\n"
    )
    assert preserved == {}, "a key the renderer emits must not also be carried forward"
