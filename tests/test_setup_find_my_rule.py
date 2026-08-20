"""Tests for the wizard-generated ``apple_find_my`` rule.

The bundled ``config/rules.yaml`` ships ``apple_find_my`` ACTIVE — fixed
upstream in SHA ``c2b3f36``. This file pins the OTHER half, the
file the wizard generates from ``render_rules_yaml()`` and writes via
``apply_config()``. The wizard derives the rule's active/commented
state from the operator's ``ble_bridge.enabled`` answer rather than
asking for it in a new prompt, because nothing but the passive BLE
bridge ever populates ``ble_device_class`` (see
``lynceus.db.count_devices_by_ble_device_class`` and the rc5 audit
notes). Two failure modes are pinned here:

* a bridge-enabled, zero-delegation operator used to receive NO
  ``rules.yaml`` at all — the legacy ``enabled_rule_types and
  config.rules_path`` gate dropped the file before
  ``render_rules_yaml`` could emit anything, and so the Find My rule
  silently never landed on disk;
* the wizard's emitted block must be ACTIVE when the bridge is on and
  COMMENTED otherwise, and the difference must show in the PARSED
  YAML — a substring check on the rendered text would happily accept a
  commented-out line and make the test pass on the wrong fixture.
"""

from __future__ import annotations

import yaml

from lynceus import paths as paths_mod
from lynceus import rules as rules_mod
from lynceus.cli import setup as wiz
from lynceus.config import BleBridgeConfig, Config
from lynceus.setup.core import (
    DECODED_CLASS_RULES,
    apply_config,
    render_rules_yaml,
)

# ---- helpers --------------------------------------------------------------


def _find_rule(parsed_rules, name):
    """Return the rule dict whose ``name`` matches, asserting exactly one
    match. Commented-out entries are skipped by the YAML parser so they
    do not appear in ``parsed_rules`` at all — distinguishing
    ACTIVE/INACTIVE without a substring check."""
    matches = [r for r in parsed_rules if isinstance(r, dict) and r.get("name") == name]
    assert len(matches) == 1, (
        f"expected exactly one rule named {name!r}, got {len(matches)}: {matches!r}"
    )
    return matches[0]


def _stub_apply_env(monkeypatch, tmp_path):
    """Pin every external path ``apply_config`` resolves so the test
    stays hermetic. Mirrors the shape used by
    ``tests/test_setup_cli_sink.py``. Returns the staging dir."""
    monkeypatch.setattr(wiz, "_is_windows", lambda: False)
    monkeypatch.setattr(paths_mod, "default_data_dir", lambda scope: tmp_path / "data")
    monkeypatch.setattr(paths_mod, "default_log_dir", lambda scope: tmp_path / "log")
    monkeypatch.setattr(
        paths_mod,
        "default_db_path",
        lambda scope: tmp_path / "data" / "lynceus.db",
    )
    # Stub the bundled-import subprocess so no real ``lynceus-import-argus``
    # fork runs; the chown_db_files step must therefore skip, but the
    # rules-writing branch is independent of the import outcome.
    monkeypatch.setattr(
        wiz,
        "import_bundled_watchlist",
        lambda db_path, override_file: (False, "no bundled watchlist"),
    )


def _make_config(*, ble_bridge_enabled: bool, rules_path: str | None) -> Config:
    """Construct a minimal ``Config`` with the bridge flag and
    ``rules_path`` we want to drive. Everything else takes defaults."""
    return Config(
        kismet_url="http://127.0.0.1:2501",
        kismet_api_key="t",
        kismet_sources=["wlan0"],
        ntfy_url=None,
        ntfy_topic=None,
        min_rssi=-70,
        rules_path=rules_path,
        ble_bridge=BleBridgeConfig(enabled=ble_bridge_enabled),
    )


# ---- render_rules_yaml: the contract the daemon sees ------------------------


def test_render_rules_yaml_bridge_on_emits_active_apple_find_my_rule():
    """The block parses as YAML and contains an ACTIVE rule named
    ``apple_find_my`` with ``rule_type: ble_device_class``, severity
    ``med``, and inline patterns ``[find_my_separated, find_my]`` —
    byte-identical in structure to the bundled
    ``config/rules.yaml`` template."""
    content = render_rules_yaml(set(), ble_bridge_enabled=True)
    data = yaml.safe_load(content)
    rules = data["rules"]
    assert isinstance(rules, list)
    rule = _find_rule(rules, "apple_find_my")
    assert rule["rule_type"] == "ble_device_class"
    assert rule["severity"] == "med"
    assert rule["patterns"] == ["find_my_separated", "find_my"]
    assert rule["description"] == "Apple Find My tracker away from its owner"


def test_render_rules_yaml_bridge_on_loads_through_real_ruleset_loader(tmp_path):
    """The real question is "does the daemon see this rule", not "does
    the text appear". Round-trip through ``lynceus.rules.load_ruleset``
    so a future validator tightening (e.g. an empty-patterns check on
    ``ble_device_class``) shows up here rather than at daemon
    startup."""
    rules_file = tmp_path / "rules.yaml"
    rules_file.write_text(
        render_rules_yaml(set(), ble_bridge_enabled=True),
        encoding="utf-8",
    )
    ruleset = rules_mod.load_ruleset(str(rules_file))
    names = {rule.name for rule in ruleset.rules}
    assert "apple_find_my" in names
    find_my_rule = next(rule for rule in ruleset.rules if rule.name == "apple_find_my")
    assert find_my_rule.rule_type == "ble_device_class"
    assert find_my_rule.severity == "med"
    assert list(find_my_rule.patterns) == ["find_my_separated", "find_my"]


def test_render_rules_yaml_bridge_off_emits_commented_block_and_no_rule():
    """Bridge off → block is present in the text (so an operator can
    see WHAT they'd get by enabling it) but commented out, and the
    PARSED YAML contains no rule named ``apple_find_my``. A
    substring check would wrongly accept a commented line here."""
    content = render_rules_yaml(set(), ble_bridge_enabled=False)
    # Visible in the text as a commented-out template.
    assert "# - name: apple_find_my" in content
    assert "#   rule_type: ble_device_class" in content
    # But the PARSER skips it: rules is None (the entire section is
    # commented when no delegation types are active either).
    data = yaml.safe_load(content)
    rules = data.get("rules")
    if isinstance(rules, list):
        names = {r.get("name") for r in rules if isinstance(r, dict)}
        assert "apple_find_my" not in names
    else:
        assert rules is None


def test_render_rules_yaml_default_ble_bridge_enabled_is_false():
    """The new ``ble_bridge_enabled`` argument MUST default to ``False``
    so every existing positional caller (``render_rules_yaml(set())``,
    ``render_rules_yaml({"watchlist_mac_range"})``) keeps producing the
    legacy output. The test guards against a future refactor that
    flips the default to True and silently starts emitting the Find My
    rule for operators who never enabled the bridge — that would be a
    half-wire too: with the bridge off the column stays NULL and the
    rule can never match, but a present-but-inert entry in
    ``rules.yaml`` is a worse contract than no entry at all."""
    # No keyword argument at all.
    content = render_rules_yaml(set())
    assert "# - name: apple_find_my" in content
    data = yaml.safe_load(content)
    # All entries — delegation and decoded-class — are commented when
    # nothing is enabled, so rules parses as None.
    assert data == {"rules": None}


def test_render_rules_yaml_bridge_on_with_active_delegation_keeps_both():
    """Bridge on AND delegation types selected → the parsed YAML
    carries BOTH the active delegation entries AND the active Find My
    rule. Operators who previously enabled watchlist_mac_range via
    the wizard AND the bridge keep getting both."""
    rule_types = {"watchlist_mac_range"}
    content = render_rules_yaml(rule_types, ble_bridge_enabled=True)
    data = yaml.safe_load(content)
    rule_types_seen = {rule["rule_type"] for rule in data["rules"]}
    assert rule_types_seen == {"watchlist_mac_range", "ble_device_class"}
    _find_rule(data["rules"], "apple_find_my")


def test_render_rules_yaml_bridge_off_with_active_delegation_keeps_find_my_commented():
    """Bridge off but watchlist_mac_range selected → the parsed YAML
    carries the active delegation entry only; the Find My block is
    present in the text as a commented template but absent from the
    parsed rules list."""
    content = render_rules_yaml({"watchlist_mac_range"}, ble_bridge_enabled=False)
    data = yaml.safe_load(content)
    rule_types_seen = {rule["rule_type"] for rule in data["rules"]}
    assert rule_types_seen == {"watchlist_mac_range"}
    # The commented block is still visible in the file so the operator
    # can see what they'd get by enabling the bridge.
    assert "# - name: apple_find_my" in content


def test_decoded_class_rules_table_matches_bundled_template():
    """Source-of-truth check: the tuple literal matches the bundled
    ``config/rules.yaml`` exactly. Drift here would be silent — the
    wizard would emit a structurally-different rule than the bundled
    template, and a regression test on the daemon's match semantics
    for one would not catch drift on the other."""
    by_name = {
        (n, (rt, sev, patterns_inline))
        for (n, rt, sev, patterns_inline, _d) in DECODED_CLASS_RULES
    }
    assert dict(by_name) == {
        "apple_find_my": (
            "ble_device_class",
            "med",
            "find_my_separated, find_my",
        ),
    }


# ---- apply_config: the gate that used to drop the rule ---------------------


def test_apply_config_bridge_on_with_empty_delegation_writes_rules_yaml(tmp_path, monkeypatch):
    """The defect this packet fixes: bridge enabled, operator answers N
    to every delegation prompt, so ``enabled_rule_types == set()`` —
    the legacy gate ``enabled_rule_types and config.rules_path``
    dropped the file, and the Find My rule silently never landed on
    disk. After the fix the file IS written and contains the active
    Find My rule."""
    _stub_apply_env(monkeypatch, tmp_path)
    rules_path = tmp_path / "rules.yaml"
    config = _make_config(ble_bridge_enabled=True, rules_path=str(rules_path))

    report = apply_config(
        config,
        scope="user",
        target_path=tmp_path / "lynceus.yaml",
        severity_overrides_path=tmp_path / "severity_overrides.yaml",
        allowlist_path=tmp_path / "allowlist.yaml",
        enabled_rule_types=set(),
    )

    assert rules_path.exists(), (
        "rules.yaml was not written; report steps: "
        + ", ".join(f"{s.name}:{s.status}" for s in report.steps)
    )
    rules_data = yaml.safe_load(rules_path.read_text(encoding="utf-8"))
    rule_names = {r["name"] for r in rules_data["rules"]}
    assert "apple_find_my" in rule_names

    # And the write_rules step must report success with the Find My
    # rule_type in its enabled list — the operator-facing message
    # counts the rule truthfully rather than under-counting by one.
    write_step = next(s for s in report.steps if s.name == "write_rules")
    assert write_step.status == "ok"
    assert write_step.detail["enabled"] == ["ble_device_class"]


def test_apply_config_bridge_off_with_empty_delegation_writes_nothing(tmp_path, monkeypatch):
    """Inverse: bridge off AND no delegation types AND no
    ``rules_path`` → no file written, ``write_rules`` step skipped
    with a truthful reason. The widened gate MUST NOT regress the
    legacy no-bridge-no-delegation case."""
    _stub_apply_env(monkeypatch, tmp_path)
    config = _make_config(ble_bridge_enabled=False, rules_path=None)

    report = apply_config(
        config,
        scope="user",
        target_path=tmp_path / "lynceus.yaml",
        severity_overrides_path=tmp_path / "severity_overrides.yaml",
        allowlist_path=tmp_path / "allowlist.yaml",
        enabled_rule_types=set(),
    )

    rules_steps = [s for s in report.steps if s.name == "write_rules"]
    assert len(rules_steps) == 1
    assert rules_steps[0].status == "skipped"
    assert "Alerting not enabled by caller" in rules_steps[0].message
    # And no file landed on disk under tmp_path.
    assert not list(tmp_path.glob("rules.yaml"))


def test_apply_config_bridge_off_with_empty_delegation_but_rules_path_writes_nothing(
    tmp_path, monkeypatch
):
    """Edge: ``rules_path`` is set in lynceus.yaml but neither
    delegation types nor the bridge is enabled → still no file is
    written. The widened gate widens on the OR-side; the AND-side
    (``rules_path`` set) is unchanged. This guards against an
    over-correction that wrote a file for an operator who turned
    alerting off in both legs."""
    _stub_apply_env(monkeypatch, tmp_path)
    rules_path = tmp_path / "rules.yaml"
    config = _make_config(ble_bridge_enabled=False, rules_path=str(rules_path))

    report = apply_config(
        config,
        scope="user",
        target_path=tmp_path / "lynceus.yaml",
        severity_overrides_path=tmp_path / "severity_overrides.yaml",
        allowlist_path=tmp_path / "allowlist.yaml",
        enabled_rule_types=set(),
    )

    write_step = next(s for s in report.steps if s.name == "write_rules")
    assert write_step.status == "skipped"
    assert not rules_path.exists()


def test_apply_config_bridge_on_with_active_delegation_writes_both(tmp_path, monkeypatch):
    """Bridge on AND a delegation type selected → both make it into
    the file, and the ``write_rules`` detail's ``enabled`` list
    contains both rule_types (truthful operator-facing count)."""
    _stub_apply_env(monkeypatch, tmp_path)
    rules_path = tmp_path / "rules.yaml"
    config = _make_config(ble_bridge_enabled=True, rules_path=str(rules_path))

    report = apply_config(
        config,
        scope="user",
        target_path=tmp_path / "lynceus.yaml",
        severity_overrides_path=tmp_path / "severity_overrides.yaml",
        allowlist_path=tmp_path / "allowlist.yaml",
        enabled_rule_types={"watchlist_mac_range"},
    )

    rules_data = yaml.safe_load(rules_path.read_text(encoding="utf-8"))
    rule_types_seen = {r["rule_type"] for r in rules_data["rules"]}
    assert rule_types_seen == {"watchlist_mac_range", "ble_device_class"}

    write_step = next(s for s in report.steps if s.name == "write_rules")
    assert write_step.status == "ok"
    assert write_step.detail["enabled"] == ["ble_device_class", "watchlist_mac_range"]
    # The message count agrees with the enabled-list length — under-
    # counting by one here was the original operator-facing half of
    # the bug.
    assert "2 active rule(s)" in write_step.message


# --- the CLI wizard path ----------------------------------------------------
#
# ⛔ `apply_config` is NOT the write an operator actually sees. The CLI runs its
# alerting prompts AFTER apply_config returns and writes rules.yaml itself, so a
# fix applied only to apply_config is overwritten moments later by a file with
# the Find My rule commented out. That is the wired-on-one-path-only defect this
# whole change exists to close, and it had a THIRD site nobody had counted.


def _cli_flow(monkeypatch, tmp_path, answers, *, ble_bridge_enabled):
    """Drive the real run_enable_alerting_flow with scripted prompt answers."""
    from lynceus.cli import setup as cli_setup

    monkeypatch.setattr(
        cli_setup.paths, "default_config_dir", lambda _scope: tmp_path
    )
    replies = iter(answers)
    return cli_setup.run_enable_alerting_flow(
        "user",
        str(tmp_path / "lynceus.db"),
        input_fn=lambda *_a, **_k: next(replies),
        ble_bridge_enabled=ble_bridge_enabled,
    )


def test_cli_declining_argus_alerting_still_writes_find_my_when_bridge_on(
    monkeypatch, tmp_path
):
    """Declining ARGUS alerting is not declining FIND MY alerting.

    Two different questions; the gate only ever asked the first. An operator
    who turned the BLE bridge on and said no to Argus watchlist alerts must
    still get the tracker rule -- otherwise the wizard half of this feature
    does nothing for exactly the operator who wanted it.
    """
    target, wrote = _cli_flow(
        monkeypatch, tmp_path, ["n"], ble_bridge_enabled=True
    )
    assert wrote is True, "declined Argus + bridge on wrote no rules.yaml"
    assert target is not None
    from lynceus.rules import load_ruleset

    rules = load_ruleset(str(target))
    names = [r.name for r in rules.rules]
    assert "apple_find_my" in names, (
        f"the CLI wrote a rules.yaml without the Find My rule: {names}"
    )
    # And nothing Argus-shaped leaked in on the back of it.
    assert names == ["apple_find_my"], f"unexpected extra rules: {names}"


def test_cli_declining_argus_alerting_writes_nothing_when_bridge_off(
    monkeypatch, tmp_path
):
    """The inverse, so the fix above cannot be a blanket 'always write'."""
    target, wrote = _cli_flow(
        monkeypatch, tmp_path, ["n"], ble_bridge_enabled=False
    )
    assert (target, wrote) == (None, False)
    assert not (tmp_path / "rules.yaml").exists(), (
        "wrote a rules.yaml for an operator who declined alerting and has no "
        "BLE bridge -- that is a behavioural change they never asked for"
    )


def test_apply_config_bridge_on_with_none_rule_types_does_not_crash(tmp_path):
    """`enabled_rule_types=None` + bridge on must not TypeError.

    ⛔ Found by CI, not by the targeted tests written alongside the change.
    `apply_config` declares `enabled_rule_types: set[str] | None`, and before
    the BLE-bridge leg was added to the write gate, the gate ITSELF guaranteed
    the value was truthy by the time the code below it ran. Widening a guard
    silently changes what every line under it may assume: with the bridge on
    and no alerting selection, `rt in enabled_rule_types` became `rt in None`.

    A crash, not a wrong answer -- which is why no assertion caught it and a
    caller in an unrelated test file did.
    """
    target = tmp_path / "lynceus.yaml"
    rules_path = tmp_path / "rules.yaml"
    config = Config(
        kismet_url="http://localhost:2501",
        db_path=str(tmp_path / "l.db"),
        rules_path=str(rules_path),
        ble_bridge=BleBridgeConfig(enabled=True),
    )
    report = apply_config(
        config,
        scope="user",
        target_path=target,
        severity_overrides_path=tmp_path / "severity.yaml",
        allowlist_path=tmp_path / "allowlist.yaml",
        enabled_rule_types=None,
        run_bundled_import=False,
    )
    assert report is not None
    assert rules_path.exists(), "bridge on + None selection wrote no rules.yaml"
    names = [r.name for r in rules_mod.load_ruleset(str(rules_path)).rules]
    assert names == ["apple_find_my"], f"unexpected rules: {names}"
