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
    "kismet_fixture_shift_to_now": True,
    "db_path": "/tmp/lynceus-custom.db",
    "location_id": "safehouse",
    "location_label": "Safe House",
    "poll_interval_seconds": 17,
    "log_level": "DEBUG",
    "rules_path": "/tmp/lynceus-rules.yaml",
    "allowlist_path": "/tmp/lynceus-allowlist.yaml",
    "ui_allowlist_path": "/tmp/lynceus-allowlist_ui.yaml",
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
    leaves = _leaf_fields(cfg)
    assert len(leaves) >= 35, (
        f"_leaf_fields flattened only {len(leaves)} settings — the control "
        f"check below would pass without examining anything"
    )
    for key, value in leaves.items():
        assert value != defaults[key], (
            f"fixture value for {key!r} equals the default — this test would "
            f"report it as 'preserved' even if the code discarded it"
        )


def test_fixture_covers_every_config_field():
    """Guards the derivation itself. Without this, a field added to Config is
    silently absent from NON_DEFAULT and every test below skips it."""
    assert len(Config.model_fields) >= 30, (
        f"Config reports only {len(Config.model_fields)} fields — the set "
        f"difference below would be empty for the wrong reason"
    )
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


def _wizard_shaped(before: Config, tmp_path: Path, **overrides) -> Config:
    """A ``Config`` shaped the way the REAL wizard hands one to ``apply_config``.

    ⛔ Passing ``before.model_copy(...)`` — the operator's own loaded config —
    was a shared-source flaw: every unasked setting arrived already carrying the
    operator's value, so "it survived" could be satisfied by the INPUT rather
    than by the carry-forward. `cli/setup.py` and `web/review.py` both build the
    Config from the wizard's ANSWERS, which means DEFAULTS for the thirty
    settings it never asks about. Only the file can supply those.
    """
    answered = {
        # the wizard's own answer set, and nothing else
        "kismet_url": before.kismet_url,
        "kismet_api_key": before.kismet_api_key,
        "kismet_sources": before.kismet_sources,
        "ntfy_url": before.ntfy_url,
        "ntfy_topic": before.ntfy_topic,
        "min_rssi": before.min_rssi,
        "capture": before.capture,
        "ble_bridge": before.ble_bridge.model_copy(update={"flush_interval": None}),
    }
    cfg = Config(db_path=str(tmp_path / "custom.db"), **{**answered, **overrides})
    # ⛔ Drift guard, stated as the CONTRACT rather than as a count. A ">= 25
    # settings differ" floor was too loose to notice the input being widened:
    # adding `heartbeat_enabled` and `log_level` back into `answered` left 28
    # differing, so the floor passed and the tests stopped proving the
    # carry-forward did the work. Measured with exactly that plant — it failed
    # NOTHING. The set below is what the wizard actually asks about; anything
    # else carrying a non-default value here means the input, not the file,
    # could be the source.
    ANSWERED_LEAVES = {
        "db_path",
        "kismet_url",
        "kismet_api_key",
        "kismet_sources",
        "ntfy_url",
        "ntfy_topic",
        "min_rssi",
        "capture.probe_ssids",
        "capture.ble_friendly_names",
        "ble_bridge.enabled",
        "ble_bridge.adapter",
    }
    defaults = _leaf_fields(Config())
    carried_by_input = {k for k, v in _leaf_fields(cfg).items() if v != defaults[k]}
    assert carried_by_input <= ANSWERED_LEAVES, (
        f"the wizard-shaped input carries {sorted(carried_by_input - ANSWERED_LEAVES)}, "
        f"which the wizard never asks about — so 'it survived' could be "
        f"satisfied by the input instead of by the carry-forward"
    )
    return cfg


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

    after = _reconfigure(
        target, _wizard_shaped(before, tmp_path, kismet_api_key="ROTATED"), tmp_path
    )

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

    after = _reconfigure(
        target, _wizard_shaped(before, tmp_path, kismet_api_key="ROTATED"), tmp_path
    )

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

    preserved, dropped, error = carry_forward_settings(target, "kismet_url: x\n")
    assert preserved == {}
    assert dropped == {}
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
    assert "NOT carried forward" in step.message


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
    # ⛔ Naming the keys, not just counting them: "reported a non-empty list"
    # is satisfied by preserving the wrong things.
    carried = set(step.detail["carried_forward"])
    for expected in ("heartbeat_enabled", "ntfy_auth_token", "log_level"):
        assert expected in carried, f"{expected} was not carried: {sorted(carried)}"


def test_no_unhandled_wizard_owned_subkey():
    """DERIVES the nested sub-keys the renderer rewrites but never asks about.

    A top-level setting the renderer omits is rescued automatically by
    carry_forward_settings. A NESTED one cannot be: appending a second
    `ble_bridge:` key would make YAML take the last occurrence and silently drop
    `enabled`/`adapter` with it. Each such sub-key therefore needs explicit
    handling, and this fails when a new one appears rather than trusting a
    comment to stay true.

    ⛔ The loop is driven from ``Config``, NOT from the rendered output, and that
    is load-bearing. Driving it from ``rendered`` made it **vacuous**: the body
    ran only for values that are dicts, so a renderer emitting ``capture: null``
    — or dropping the sub-keys entirely, which is exactly the regression this
    exists to catch — skipped every iteration and the subset assertion was
    trivially true. Measured with that plant: **1 passed**.

    🪤 And the plant that "proved" it before was a different bug. Commenting the
    block headers out orphaned their indented sub-lines, so the test died on
    ``yaml.parser.ParserError`` — a failure, but not this guard firing. Naming
    the invariant and checking the failure names it too is what separated them.
    """
    rendered = yaml.safe_load(render_config_yaml(_answers_from_config(Config(**NON_DEFAULT))))
    handled = {"ble_bridge.flush_interval"}

    # Side A: which fields ARE sub-models, according to the model itself.
    defaults = Config()
    nested = {
        name
        for name in Config.model_fields
        if hasattr(type(getattr(defaults, name)), "model_fields")
    }
    assert len(nested) >= 3, (
        f"only found {len(nested)} sub-model field(s) on Config — the derivation "
        f"is broken, and every assertion below would pass without examining "
        f"anything"
    )

    # Side B: what the renderer actually emitted for each of them.
    #
    # ⚠️ Three cases, and only the middle one is a defect:
    #   absent entirely  -> fine. carry_forward_settings rescues the whole key,
    #                       which is how `co_observation` survives today.
    #   present as a map -> its sub-keys must each be emitted or handled.
    #   present, NOT a map -> the bad one. `carry_forward_settings` sees the key
    #                       in the rendered output and declines to carry it,
    #                       while the renderer supplies nothing usable, so the
    #                       operator's whole sub-model is dropped.
    examined = 0
    unowned = set()
    for key in sorted(nested):
        if key not in rendered:
            continue
        value = rendered[key]
        assert isinstance(value, dict), (
            f"the renderer emitted `{key}: {value!r}` — a key the carry-forward "
            f"will therefore treat as wizard-owned and decline to rescue, while "
            f"the renderer supplies nothing usable. Every {key}.* setting the "
            f"operator holds would be dropped."
        )
        examined += 1
        for sub in type(getattr(defaults, key)).model_fields:
            if sub not in value:
                unowned.add(f"{key}.{sub}")

    assert examined >= 2, (
        f"only {examined} rendered sub-model(s) examined — the sub-key sweep "
        f"below would pass without looking at anything"
    )

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

    # As on the real --reconfigure path: the wizard never asks about
    # flush_interval, so the incoming Config carries None and the value must
    # come off the existing file. ⛔ The SIBLINGS matter as much: asserting them
    # against a config that already held them proved nothing.
    after = _reconfigure(target, _wizard_shaped(before, tmp_path), tmp_path)

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
    # ⛔ 8765 as a LITERAL, not DEFAULT_UI_PORT: importing the oracle from the
    # module under test means both sides move together, and the test would
    # keep passing if the documented default silently changed.
    assert load_config(str(target)).ui_bind_port == 8765
    assert DEFAULT_UI_PORT == 8765, 'the documented default changed'


def test_carry_forward_derives_the_owned_set_from_the_rendered_output(tmp_path):
    """The owned set must come from parsing the render, not a constant. Pinning
    it here means a field added to the renderer stops being carried forward
    automatically — and one removed starts being carried forward automatically."""
    target = tmp_path / "lynceus.yaml"
    target.write_text("kismet_url: http://a\nheartbeat_enabled: true\n", encoding="utf-8")

    preserved, dropped, error = carry_forward_settings(target, "kismet_url: http://b\n")
    assert error is None
    assert dropped == {}
    assert preserved == {"heartbeat_enabled": True}

    # Same existing file, a render that now owns heartbeat_enabled too.
    preserved, _, _ = carry_forward_settings(
        target, "kismet_url: http://b\nheartbeat_enabled: false\n"
    )
    assert preserved == {}, "a key the renderer emits must not also be carried forward"


# ---------------------------------------------------------------------------
# Round 1 of the red-team on the carry-forward (codex gpt-5.6-sol, verified
# here before being believed). Three findings landed on this path.
# ---------------------------------------------------------------------------


def test_an_unrecognised_key_is_dropped_and_named_not_carried_forward(tmp_path):
    """⛔ A REGRESSION the carry-forward introduced, and the worst of the three.

    `Config` sets `extra="forbid"`, so carrying an unknown key forward verbatim
    makes the config fail to LOAD. Measured: an existing file holding
    `heartbeat_interal_hours: 12` — one transposed letter — survived
    `--reconfigure` and then raised ValidationError, i.e. the daemon would not
    start. Before the carry-forward existed, the misspelling was discarded and
    the wizard produced a runnable config.

    Re-running setup is exactly what an operator would try in order to recover
    from a typo; preservation must not take that away.
    """
    target = tmp_path / "lynceus.yaml"
    target.write_text(
        "kismet_url: http://127.0.0.1:2501\n"
        "heartbeat_enabled: true\n"
        "heartbeat_interal_hours: 12\n",
        encoding="utf-8",
    )

    report = apply_config(
        Config(db_path=str(tmp_path / "d.db")),
        scope="user",
        target_path=target,
        severity_overrides_path=tmp_path / "so.yaml",
        allowlist_path=tmp_path / "al.yaml",
        enabled_rule_types=None,
        run_bundled_import=False,
    )

    # The whole point: the daemon can still load what the wizard wrote.
    reloaded = load_config(str(target))
    assert reloaded.heartbeat_enabled is True, "the real setting was not preserved"

    step = next(s for s in report.steps if s.name == "write_config")
    assert list(step.detail["dropped"]) == ["heartbeat_interal_hours"]
    assert "not a Lynceus setting" in step.detail["dropped"]["heartbeat_interal_hours"]
    assert "heartbeat_interal_hours" in step.message, (
        f"the key was dropped silently — the operator cannot fix a typo they "
        f"are never shown: {step.message!r}"
    )
    assert step.status == "warning"


def test_an_unreadable_previous_config_is_copied_aside_before_being_overwritten(
    tmp_path,
):
    """⛔ "Fails closed" has to mean the bytes survive, not just that we said so.

    The previous version reported a warning and overwrote anyway, which is
    fail-OPEN for the operator's data: one YAML typo and every hand-edited
    setting — `ntfy_auth_token` included — was gone, with the notice arriving
    after the bytes had already been replaced.
    """
    target = tmp_path / "lynceus.yaml"
    original = "heartbeat_enabled: true\nntfy_auth_token: secret-token\nbroken: [\n"
    target.write_text(original, encoding="utf-8")

    report = apply_config(
        Config(db_path=str(tmp_path / "d.db")),
        scope="user",
        target_path=target,
        severity_overrides_path=tmp_path / "so.yaml",
        allowlist_path=tmp_path / "al.yaml",
        enabled_rule_types=None,
        run_bundled_import=False,
    )

    step = next(s for s in report.steps if s.name == "write_config")
    backup = Path(step.detail["backup_path"])
    assert backup.exists(), "no copy was kept of a config we could not read"
    assert backup.read_text(encoding="utf-8") == original, "the copy is not byte-for-byte"
    assert "secret-token" in backup.read_text(encoding="utf-8")
    assert str(backup) in step.message, "the operator is not told where the copy is"


def test_a_readable_config_is_not_backed_up(tmp_path):
    """Presence assertion beside it: a copy of every readable config would be
    litter, and "always back up" would satisfy the test above."""
    target = tmp_path / "lynceus.yaml"
    target.write_text("heartbeat_enabled: true\n", encoding="utf-8")

    report = apply_config(
        Config(db_path=str(tmp_path / "d.db")),
        scope="user",
        target_path=target,
        severity_overrides_path=tmp_path / "so.yaml",
        allowlist_path=tmp_path / "al.yaml",
        enabled_rule_types=None,
        run_bundled_import=False,
    )

    step = next(s for s in report.steps if s.name == "write_config")
    assert step.detail["backup_path"] is None
    # ⛔ Enumerate the directory rather than globbing one anticipated name:
    # a copy to `.bak`, or anywhere else, would pass a shape-specific glob.
    assert {p.name for p in tmp_path.iterdir()} == {
        "lynceus.yaml", "so.yaml", "al.yaml",
    }, sorted(p.name for p in tmp_path.iterdir())


@pytest.mark.parametrize("source", ["*missing", "null", "true", "[wlan0]", "name: value"])
def test_a_source_name_cannot_break_the_rendered_yaml(tmp_path, source):
    """`kismet_sources` entries were emitted unquoted, so `*missing` became a
    YAML ALIAS and `yaml.safe_load` raised — inside `carry_forward_settings`,
    which reparses the render to decide ownership. A source label the operator
    is allowed to type could therefore crash `--reconfigure` outright."""
    cfg = Config(db_path=str(tmp_path / "d.db"), kismet_sources=[source])
    rendered = render_config_yaml(_answers_from_config(cfg))

    loaded = yaml.safe_load(rendered)
    assert loaded["kismet_sources"] == [source], (
        f"{source!r} did not survive the render as a string: "
        f"{loaded['kismet_sources']!r}"
    )
    target = tmp_path / "lynceus.yaml"
    target.write_text(rendered, encoding="utf-8")
    assert load_config(str(target)).kismet_sources == [source]


# ---------------------------------------------------------------------------
# Round 2: a cold drift-review of round 1's own diff (codex gpt-5.6-terra),
# each finding reproduced here before being believed. Two were real defects in
# round 1, one was a prose overclaim, one was refuted.
# ---------------------------------------------------------------------------


def test_a_known_key_with_an_unloadable_value_is_dropped_too(tmp_path):
    """🪤 Round 1 filtered on `Config.model_fields` — NAMES only — and its
    docstring claimed it carried forward "only keys Config will accept".

    `heartbeat_interval_hours: nope` is a perfectly good key carrying a value
    pydantic rejects, so the name check passed it through and the daemon still
    could not load the file. Measured: ValidationError at load, i.e. the very
    outcome round 1 existed to prevent, reached by a route it did not check.
    """
    target = tmp_path / "lynceus.yaml"
    target.write_text(
        "kismet_url: http://127.0.0.1:2501\n"
        "heartbeat_enabled: true\n"
        "heartbeat_interval_hours: nope\n",
        encoding="utf-8",
    )

    report = apply_config(
        Config(db_path=str(tmp_path / "d.db")),
        scope="user",
        target_path=target,
        severity_overrides_path=tmp_path / "so.yaml",
        allowlist_path=tmp_path / "al.yaml",
        enabled_rule_types=None,
        run_bundled_import=False,
    )

    reloaded = load_config(str(target))
    assert reloaded.heartbeat_enabled is True, "the valid setting was thrown out too"

    step = next(s for s in report.steps if s.name == "write_config")
    assert "heartbeat_interval_hours" in step.detail["dropped"]
    assert "value rejected" in step.detail["dropped"]["heartbeat_interval_hours"]


def test_a_non_string_yaml_key_does_not_crash_the_wizard(tmp_path):
    """YAML mappings may key on non-strings: `123: value` is legal.

    Round 1 sorted and joined the dropped keys as text, so an int key raised
    TypeError — AFTER `write_config` had already replaced the file, so the
    wizard crashed mid-apply having destroyed the original.
    """
    target = tmp_path / "lynceus.yaml"
    target.write_text("kismet_url: http://127.0.0.1:2501\n123: value\n", encoding="utf-8")

    report = apply_config(
        Config(db_path=str(tmp_path / "d.db")),
        scope="user",
        target_path=target,
        severity_overrides_path=tmp_path / "so.yaml",
        allowlist_path=tmp_path / "al.yaml",
        enabled_rule_types=None,
        run_bundled_import=False,
    )

    load_config(str(target))  # must still load
    step = next(s for s in report.steps if s.name == "write_config")
    assert "123" in step.detail["dropped"]


def test_a_wizard_side_validation_failure_does_not_discard_operator_settings(tmp_path):
    """⛔ The drop loop must not paper over the WIZARD's own bad answers by
    eating operator data. Presence assertion for the `if not bad: break` arm —
    without it, "drop until it validates" would strip a valid carried block
    whenever the rendered half was at fault."""
    target = tmp_path / "lynceus.yaml"
    target.write_text("heartbeat_enabled: true\nlog_level: DEBUG\n", encoding="utf-8")

    preserved, dropped, error = carry_forward_settings(
        target,
        # ntfy_url set with no ntfy_topic: a cross-field failure owned entirely
        # by the rendered half, naming neither carried key.
        "kismet_url: http://127.0.0.1:2501\nntfy_url: https://ntfy.example.org\n",
    )

    assert error is None
    assert preserved == {"heartbeat_enabled": True, "log_level": "DEBUG"}, (
        f"operator settings were discarded to hide a wizard-side failure: {dropped}"
    )
