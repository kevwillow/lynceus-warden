"""Duplicate-key detection over hand-edited YAML.

The premise, re-measured here rather than assumed, is that `yaml.safe_load`
resolves a duplicate key by keeping the LAST one and saying nothing. A test
docstring in this repo asserted the opposite ("would break yaml.safe_load with
a 'duplicate key' error and the daemon would fail to start"), which is a good
reason to pin the real behaviour beside the detector that exists because of it.
"""

from __future__ import annotations

import ast
import logging
import pathlib

import pytest
import yaml

from lynceus.config import load_config
from lynceus.rules import load_ruleset, load_runtime_severity_overrides
from lynceus.yaml_duplicates import find_duplicate_keys, warn_duplicate_keys


def _write(tmp_path, body: str):
    p = tmp_path / "f.yaml"
    p.write_text(body, encoding="utf-8")
    return p


def test_pyyaml_keeps_the_last_duplicate_silently(recwarn):
    """The premise. If this ever fails, the detector may be unnecessary --
    which is a far better reason to revisit it than someone's recollection."""
    assert yaml.safe_load("a: 1\na: 2") == {"a": 2}
    assert recwarn.list == []


def test_no_duplicates_in_a_clean_file(tmp_path):
    p = _write(tmp_path, "entries:\n  - pattern: x\n    pattern_type: mac\n")
    assert find_duplicate_keys(p) == []


def test_a_repeated_top_level_key_is_found(tmp_path):
    p = _write(tmp_path, "alpha: 1\nbeta: 2\nalpha: 3\n")
    (dupe,) = find_duplicate_keys(p)
    assert dupe.key_path == "alpha"
    assert dupe.first_line == 1
    assert dupe.winning_line == 3


def test_a_repeated_key_inside_a_list_item_is_found_with_its_path(tmp_path):
    p = _write(
        tmp_path,
        (
            "entries:\n"
            "  - pattern: a\n"
            "    pattern_type: mac\n"
            "  - pattern: b\n"
            "    pattern: c\n"
            "    pattern_type: mac\n"
        ),
    )
    (dupe,) = find_duplicate_keys(p)
    assert dupe.key_path == "entries[1].pattern"
    assert (dupe.first_line, dupe.winning_line) == (4, 5)


def test_the_same_key_in_sibling_mappings_is_not_a_duplicate(tmp_path):
    """The control. Every list entry has a `pattern`; that is the normal
    shape of these files, not a defect. A detector that flags it would be
    unusable and would train operators to ignore the real one."""
    p = _write(
        tmp_path,
        (
            "entries:\n"
            "  - pattern: a\n"
            "    pattern_type: mac\n"
            "  - pattern: b\n"
            "    pattern_type: mac\n"
        ),
    )
    assert find_duplicate_keys(p) == []


def test_a_nested_mapping_duplicate_is_found(tmp_path):
    p = _write(
        tmp_path,
        "device_category_severity:\n  drone: high\n  tracker: low\n  drone: low\n",
    )
    (dupe,) = find_duplicate_keys(p)
    assert dupe.key_path == "device_category_severity.drone"
    assert (dupe.first_line, dupe.winning_line) == (2, 4)


def test_several_duplicates_are_all_reported_in_file_order(tmp_path):
    p = _write(tmp_path, "a: 1\nb: 2\na: 3\nb: 4\n")
    assert [d.key_path for d in find_duplicate_keys(p)] == ["a", "b"]


def test_an_unparseable_file_reports_nothing(tmp_path):
    """The caller reports parse errors itself; the same fault described
    twice in different words is worse than once."""
    p = _write(tmp_path, "entries: [unbalanced\n")
    assert find_duplicate_keys(p) == []


def test_a_missing_file_reports_nothing(tmp_path):
    assert find_duplicate_keys(tmp_path / "nope.yaml") == []


def test_an_empty_file_reports_nothing(tmp_path):
    assert find_duplicate_keys(_write(tmp_path, "")) == []


def test_the_message_names_both_lines_and_which_one_wins(tmp_path):
    p = _write(tmp_path, "alpha: 1\nalpha: 2\n")
    (dupe,) = find_duplicate_keys(p)
    msg = dupe.describe()
    assert "line 1" in msg and "line 2" in msg
    assert "LAST" in msg


# ---------------------------------------------------------------------------
# warn_duplicate_keys -- the shared daemon-side reporter
#
# #122 wired duplicate detection into the ALLOWLIST loader and into
# `lynceus-validate`. Every other loader was left on a plain `yaml.safe_load`,
# deliberately and in writing. Measured on `7eb96b8`, that left five ways for a
# hand-edit to change what the daemon enforces with nothing anywhere saying so.
#
# ⭐ The organising fact, and the reason "the daemon already logs a count" is
# NOT a defence: every startup signal this project emits narrates a COUNT
# (`Poller.__init__` logs "N active rules"; the override loader logs five
# totals). A duplicate that changes a VALUE inside a preserved structure moves
# no count at all -- a stray second `patterns:` line swaps the watched
# addresses and the startup line is byte-identical to the correct file's.
# ---------------------------------------------------------------------------


def test_warn_duplicate_keys_says_nothing_about_a_clean_file(tmp_path, caplog):
    """The control. Without it, a reporter that warned unconditionally would
    look identical on every treatment case below."""
    p = _write(tmp_path, "a: 1\nb: 2\n")
    with caplog.at_level(logging.DEBUG):
        warn_duplicate_keys(p, logger=logging.getLogger("t"), subject="thing")
    assert caplog.records == []


def test_warn_duplicate_keys_names_the_key_path_and_both_lines(tmp_path, caplog):
    p = _write(tmp_path, "alpha: 1\nbeta: 2\nalpha: 3\n")
    with caplog.at_level(logging.DEBUG):
        warn_duplicate_keys(p, logger=logging.getLogger("t"), subject="thing")
    (rec,) = [r for r in caplog.records if r.levelno == logging.WARNING]
    msg = rec.getMessage()
    assert "alpha" in msg and "line 1" in msg and "line 3" in msg


def test_a_broken_detector_cannot_raise_out_of_the_reporter(tmp_path, caplog, monkeypatch):
    """⛔ THE REGRESSION GUARD, and it is the one that matters.

    #122's own allowlist helper sat inside `_load_primary`'s `except
    Exception`, so a raise from the DIAGNOSTIC was reported as "could not be
    parsed" and, under `raise_on_parse_error`, became an `AllowlistParseError`
    -- a valid file loading as zero entries and the poller announcing
    SUPPRESSION DISABLED. `find_duplicate_keys` absorbs OSError and YAMLError,
    but `yaml.compose` can still raise past both (RecursionError, MemoryError).
    """
    import lynceus.yaml_duplicates as mod

    def explode(_path):
        raise RecursionError("maximum recursion depth exceeded")

    monkeypatch.setattr(mod, "find_duplicate_keys", explode)
    p = _write(tmp_path, "a: 1\na: 2\n")
    with caplog.at_level(logging.DEBUG):
        warn_duplicate_keys(p, logger=logging.getLogger("t"), subject="thing")
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("skipped" in r.getMessage() for r in caplog.records)


def test_a_broken_detector_cannot_change_what_load_ruleset_returns(
    tmp_path, monkeypatch
):
    """The property above, asserted where it actually bites: the loader's
    RETURN VALUE, not just the absence of an exception."""
    import lynceus.yaml_duplicates as mod

    body = (
        "rules:\n"
        "  - name: r\n"
        "    rule_type: watchlist_mac\n"
        "    severity: high\n"
        '    patterns: ["de:ad:be:ef:00:01"]\n'
    )
    p = tmp_path / "rules.yaml"
    p.write_text(body, encoding="utf-8")
    healthy = load_ruleset(str(p))

    monkeypatch.setattr(
        mod, "find_duplicate_keys", lambda _p: (_ for _ in ()).throw(MemoryError())
    )
    with_broken_detector = load_ruleset(str(p))
    assert [r.name for r in with_broken_detector.rules] == [r.name for r in healthy.rules]
    assert [r.patterns for r in with_broken_detector.rules] == [
        r.patterns for r in healthy.rules
    ]


# --- the three daemon loaders, each with its control ------------------------


def _rules(dup: bool) -> str:
    tail = '    patterns: ["00:00:00:00:00:00"]\n' if dup else ""
    return (
        "rules:\n"
        "  - name: known_bad_mac\n"
        "    rule_type: watchlist_mac\n"
        "    severity: high\n"
        '    patterns: ["de:ad:be:ef:00:01"]\n' + tail
    )


@pytest.mark.parametrize("dup", [False, True])
def test_load_ruleset_warns_only_when_a_duplicate_is_present(tmp_path, caplog, dup):
    p = tmp_path / "rules.yaml"
    p.write_text(_rules(dup), encoding="utf-8")
    with caplog.at_level(logging.WARNING):
        rs = load_ruleset(str(p))
    warned = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert bool(warned) is dup
    if dup:
        # The count is UNCHANGED -- one rule either way. This is precisely the
        # case no count-based startup line can surface.
        assert len(rs.rules) == 1
        assert rs.rules[0].patterns == ["00:00:00:00:00:00"]
        assert "patterns" in warned[0].getMessage()


@pytest.mark.parametrize("dup", [False, True])
def test_load_config_warns_only_when_a_duplicate_is_present(tmp_path, caplog, dup):
    body = "heartbeat_enabled: true\n" + ("heartbeat_enabled: false\n" if dup else "")
    p = tmp_path / "lynceus.yaml"
    p.write_text(body, encoding="utf-8")
    with caplog.at_level(logging.WARNING):
        cfg = load_config(str(p))
    warned = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert bool(warned) is dup
    # The dead-man's switch, disarmed, with nothing else anywhere to say so:
    # `poller.py` returns early on every tick without logging when this is off.
    assert cfg.heartbeat_enabled is not dup


@pytest.mark.parametrize("dup", [False, True])
def test_load_runtime_severity_overrides_warns_only_on_a_duplicate(
    tmp_path, caplog, dup
):
    body = 'suppress_vendors: []\n' + ('suppress_vendors: ["acme"]\n' if dup else "")
    p = tmp_path / "severity_overrides.yaml"
    p.write_text(body, encoding="utf-8")
    with caplog.at_level(logging.WARNING):
        ov = load_runtime_severity_overrides(str(p))
    warned = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert bool(warned) is dup
    assert ("acme" in ov.suppress_vendors) is dup


# --- the coverage guard -----------------------------------------------------

# Every function in `src/lynceus` that calls `yaml.safe_load`, classified.
# A site is either WIRED to a duplicate-key reporter or listed here WITH THE
# REASON it does not need one. A new loader is in neither set and fails.
#
# ⚠️ Derived, not transcribed: the wired side is discovered by walking the AST
# for any call whose name contains "duplicate", because the first version of
# this scan hardcoded three helper names, missed that the allowlist's is called
# `_warn_on_duplicate_keys`, and reported a WIRED loader as unwired.
_EXEMPT: dict[str, str] = {
    "lynceus/cli/validate.py::_try_load_yaml": (
        "validate reports duplicates itself via _duplicate_key_issues, "
        "as an ERROR, per validator"
    ),
    "lynceus/cli/quickstart.py::_read_ui_port_from_config": (
        "machine-written port override, not an operator-authored file"
    ),
    "lynceus/cli/quickstart.py::_write_port_override_config": "machine-written port override",
    "lynceus/setup/core.py::carry_forward_settings": (
        "parses the renderer's OWN output, which is generated, not hand-edited"
    ),
}


_SRC = pathlib.Path(__file__).resolve().parents[1] / "src" / "lynceus"

# Any of these, called on a YAML file, collapses a duplicate key silently.
_LOADER_NAMES = frozenset(
    {
        "safe_load",
        "load",
        "full_load",
        "unsafe_load",
        # ⚠️ The *_all variants were missing, so a loader reading a multi-document
        # operator file was invisible to this guard entirely.
        "safe_load_all",
        "load_all",
        "full_load_all",
    }
)


def _reporter_names() -> frozenset[str]:
    """Duplicate-key reporters DEFINED in the tree, derived by walking it.

    ⛔ Neither transcribed nor fuzzy, and both alternatives were shipped and
    were wrong. A hardcoded list of three names missed that the allowlist's
    reporter is called `_warn_on_duplicate_keys` and marked a wired loader
    unwired. Replacing it with "any called name containing 'duplicate'" then
    made the guard gameable in the other direction -- a call to an unrelated
    `deduplicate_cache()` in the same function certified the loader as
    protected. ⇒ The answer to a transcribed list is a DERIVED list, not a
    loose one.
    """
    names = set()
    for f in sorted(_SRC.rglob("*.py")):
        for node in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
            if isinstance(node, ast.FunctionDef) and "duplicate" in node.name.lower():
                if node.name.lstrip("_").startswith("warn"):
                    names.add(node.name)
    return frozenset(names)


def _yaml_module_aliases(tree: ast.AST) -> set[str]:
    """Names the module is bound to, e.g. `yaml` plus any `import yaml as y`.

    ⚠️ The scan used to require the receiver to be literally named `yaml`, so

        import yaml as y
        def load_thing(p): return y.safe_load(p)

    was invisible. Three separate blind spots were found in one cold read --
    this one, module-level calls outside any function, and the `*_all`
    variants -- all in a guard whose entire job is to stop a loader joining
    the codebase unwired.
    """
    out = {"yaml"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "yaml" and alias.asname:
                    out.add(alias.asname)
    return out


def _yaml_import_aliases(tree: ast.AST) -> set[str]:
    """Names bound by `from yaml import safe_load[, load as ...]` in a module.

    ⚠️ Without this the scan matched only `yaml.safe_load(...)` as an
    attribute, so a module doing `from yaml import safe_load` and then calling
    a bare `safe_load(path)` was INVISIBLE to the guard -- a straight bypass of
    the anti-rot mechanism, found by a cold read rather than by any of the five
    defects planted against it.
    """
    out = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "yaml":
            for alias in node.names:
                if alias.name in _LOADER_NAMES:
                    out.add(alias.asname or alias.name)
    return out


def _safe_load_sites() -> dict[str, bool]:
    """Map "<module>::<function>" -> is it wired to a duplicate reporter."""
    reporters = _reporter_names()
    sites: dict[str, bool] = {}
    for f in sorted(_SRC.rglob("*.py")):
        tree = ast.parse(f.read_text(encoding="utf-8"))
        aliases = _yaml_import_aliases(tree)
        modules = _yaml_module_aliases(tree)
        rel = f.relative_to(_SRC.parent).as_posix()

        def scan(
            body_nodes,
            label: str,
            *,
            modules=modules,
            aliases=aliases,
            rel=rel,
        ) -> None:
            # Bound as defaults, not captured: ruff B023. A late-binding closure
            # here would grade every file against the LAST file's import table.
            names, loads = set(), False
            for top in body_nodes:
                for sub in ast.walk(top):
                    if not isinstance(sub, ast.Call):
                        continue
                    fn = sub.func
                    if isinstance(fn, ast.Attribute):
                        names.add(fn.attr)
                        if (
                            isinstance(fn.value, ast.Name)
                            and fn.value.id in modules
                            and fn.attr in _LOADER_NAMES
                        ):
                            loads = True
                    elif isinstance(fn, ast.Name):
                        names.add(fn.id)
                        if fn.id in aliases:
                            loads = True
            if loads:
                sites[f"{rel}::{label}"] = bool(names & reporters)

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                scan([node], node.name)
        # ⚠️ Module level too. `DATA = yaml.safe_load(open(CONFIG))` at import
        # time is a loader with no enclosing function, and the previous scan
        # only ever looked inside `def`s -- so the one form that runs before
        # anything else could get logged was the one form it could not see.
        scan(
            [n for n in tree.body if not isinstance(
                n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            )],
            "<module>",
        )
    return sites


def test_the_scan_finds_the_loaders_it_is_supposed_to_grade():
    """The instrument's own control. A scan that silently matched nothing
    would make the guard below pass vacuously -- this project has shipped a
    0-of-3 vacuous sweep before."""
    sites = _safe_load_sites()
    assert len(sites) >= 12, sites
    assert sites.get("lynceus/rules.py::load_ruleset") is True
    assert sites.get("lynceus/allowlist.py::_load_primary") is True


def test_every_yaml_loader_is_wired_or_exempt_with_a_reason():
    """⛔ A new `yaml.safe_load` on an operator-authored file must not be able
    to join the codebase silently. #122 fixed one loader; the class had five
    more, and the note recording that lived in a gitignored file."""
    unclassified = [
        site for site, wired in _safe_load_sites().items()
        if not wired and site not in _EXEMPT
    ]
    assert unclassified == [], (
        "these call yaml.safe_load but neither report duplicates nor carry a "
        f"documented exemption: {unclassified}"
    )


def test_no_exemption_is_stale():
    """An exemption naming a site that no longer exists is a comment claiming
    a guarantee about nothing."""
    sites = _safe_load_sites()
    assert [s for s in _EXEMPT if s not in sites] == []


def test_every_exemption_states_an_actual_reason():
    """⛔ The exemption model checked bookkeeping, not content. An empty string
    satisfied every other test here -- and #138 already proved a *false* reason
    survives indefinitely, so the least this can do is refuse a blank one."""
    empty = [site for site, reason in _EXEMPT.items() if not reason.strip()]
    assert empty == [], f"exempted with no stated reason: {empty}"
    too_short = [
        site for site, reason in _EXEMPT.items() if len(reason.strip()) < 25
    ]
    assert too_short == [], (
        f"exemption reason too short to be a reason: {too_short}"
    )


def test_no_exemption_survives_its_site_becoming_wired():
    """⛔ The other direction, and it is the one that let a wrong exemption sit
    unchallenged. `_EXEMPT` is only consulted for UNWIRED sites, so once a site
    gains a reporter its exemption stops being read and stops being checked --
    a stale justification that outlives the thing it justified, and the next
    reader takes it as a live statement about the code.

    Both `allowlist.py` UI-sibling entries were exempted on the reason
    "daemon-managed, not hand-edited". Measured, that was false: a duplicate
    there moves the suppression exactly as it does in the primary, and one UI
    write then LAUNDERS it -- the address the operator meant disappears from
    the file and only the stray survives. They are wired now, so their
    exemptions must be gone.
    """
    still_exempt_but_wired = [
        site for site, wired in _safe_load_sites().items()
        if wired and site in _EXEMPT
    ]
    assert still_exempt_but_wired == [], (
        "these are wired now, so their exemption text is a stale claim about "
        f"code that no longer needs it: {still_exempt_but_wired}"
    )


# ---------------------------------------------------------------------------
# Round two: five defects a cold cross-model read found in the work above,
# AFTER five planted defects had all been caught by it. Fifth round running
# that the plants proved only the failures their author had imagined.
# ---------------------------------------------------------------------------


def test_a_triplicated_key_names_the_line_that_actually_wins(tmp_path):
    """⛔ The pairwise version emitted TWO records for three occurrences, and
    the first said "line 2 is the one in force" when safe_load keeps line 3.
    An operator following that message edits line 2, watches nothing change,
    and the dangerous value stays live.

    The assertion is against `safe_load`'s OWN answer, not a transcribed 3 --
    the two sides must have independent sources.
    """
    p = _write(tmp_path, "a: 1\na: 2\na: 3\n")
    (dupe,) = find_duplicate_keys(p)
    assert dupe.occurrence_lines == (1, 2, 3)
    assert dupe.winning_line == 3
    assert dupe.first_line == 1
    # the value on winning_line is the value in force, checked against PyYAML
    assert yaml.safe_load(p.read_text(encoding="utf-8"))["a"] == 3
    msg = dupe.describe()
    assert "line 3 is the one in force" in msg
    assert "line 2 is the one in force" not in msg


def test_every_reported_winner_agrees_with_safe_load(tmp_path):
    """The general form of the above, over several shapes at once."""
    body = "a: 1\na: 2\na: 3\nb: 10\nb: 20\nc: 5\n"
    p = _write(tmp_path, body)
    loaded = yaml.safe_load(body)
    lines = body.splitlines()
    for dupe in find_duplicate_keys(p):
        key = dupe.key_path
        winning_text = lines[dupe.winning_line - 1]
        assert winning_text.strip() == f"{key}: {loaded[key]}", (
            f"{key}: message points at line {dupe.winning_line} "
            f"({winning_text!r}) but safe_load holds {loaded[key]!r}"
        )


class _ExplodingLogger(logging.Logger):
    """A logger whose emit path raises -- a full disk on a FileHandler, a
    broken formatter, a filter with a bug. None of it is exotic."""

    def warning(self, *a, **k):
        raise RuntimeError("handler exploded")

    def debug(self, *a, **k):
        raise RuntimeError("handler exploded")


def test_a_raising_logger_cannot_escape_the_reporter(tmp_path):
    """⛔ The first version wrapped only the DETECTION call; the emit loop sat
    outside the try. `logger.warning` is not inert, so the helper documented as
    "Never raises" propagated straight through `load_config` and `load_ruleset`
    and took the daemon down at startup on a file it had already parsed fine.
    The docstring was the defect, not just the code.
    """
    p = _write(tmp_path, "dup: 1\ndup: 2\n")
    warn_duplicate_keys(p, logger=_ExplodingLogger("boom"), subject="thing")


def test_a_raising_logger_cannot_change_what_load_ruleset_returns(tmp_path, monkeypatch):
    """The property where it bites: the loader's return value, via a logger
    that raises rather than a detector that does."""
    body = (
        "rules:\n"
        "  - name: r\n"
        "    rule_type: watchlist_mac\n"
        "    severity: high\n"
        '    patterns: ["de:ad:be:ef:00:01"]\n'
        '    patterns: ["00:00:00:00:00:00"]\n'
    )
    p = tmp_path / "rules.yaml"
    p.write_text(body, encoding="utf-8")
    import lynceus.rules as rules_mod

    monkeypatch.setattr(rules_mod, "logger", _ExplodingLogger("boom"))
    rs = load_ruleset(str(p))
    assert [r.name for r in rs.rules] == ["r"]
    assert rs.rules[0].patterns == ["00:00:00:00:00:00"]


def test_a_resolved_key_collision_is_now_DETECTED_not_a_blind_spot(tmp_path):
    """⭐ This test used to pin the opposite, and said so: "if this ever fails
    because a loader ACCEPTS the collision, the detector must start resolving
    keys." A cold read then showed raw-text identity was wrong in BOTH
    directions, so it now does.

    `on:` and `true:` are different text and the SAME Python key under YAML 1.1
    -- `safe_load` keeps one and discards the other, which is exactly what this
    module exists to report and it used to miss.
    """
    body = "on: 1\ntrue: 2\n"
    p = _write(tmp_path, body)
    assert len(yaml.safe_load(body)) == 1, "PyYAML no longer collapses these"
    (dupe,) = find_duplicate_keys(p)
    assert dupe.occurrence_lines == (1, 2)


def test_the_same_text_resolving_to_DIFFERENT_keys_is_not_a_duplicate(tmp_path):
    """⛔ The other direction, and the worse one: `on:` and `"on":` are the SAME
    text and DIFFERENT Python keys (`True` and `'on'`). Nothing is discarded.
    Raw-text identity reported a duplicate here -- this module telling an
    operator something untrue about their own file, which is precisely the
    defect class it was built to catch.
    """
    body = 'on: first\n"on": second\n'
    p = _write(tmp_path, body)
    assert len(yaml.safe_load(body)) == 2, "both keys should survive"
    assert find_duplicate_keys(p) == []


def test_a_recursive_alias_does_not_crash_the_detector(tmp_path):
    """⛔ Valid YAML that `yaml.compose` represents as a CYCLE. Without a
    visited-node guard the walk recursed forever, raised RecursionError past
    `find_duplicate_keys`'s OSError/YAMLError catch, and `lynceus-validate`
    CRASHED on the file it was asked to report on."""
    p = _write(tmp_path, "x: &x\n  self: *x\n")
    assert find_duplicate_keys(p) == []


def test_the_validator_reports_rather_than_crashing_on_a_pathological_file(tmp_path):
    """The end-to-end half. `_duplicate_key_issues` calls the DETECTOR, not the
    warn-only wrapper, so the wrapper's never-raise contract did not cover it.
    A validator that dies gives the operator a traceback where they asked for a
    verdict."""
    from lynceus.cli.validate import validate_lynceus_yaml

    p = tmp_path / "lynceus.yaml"
    p.write_text("x: &x\n  self: *x\n", encoding="utf-8")
    report, _cfg = validate_lynceus_yaml(p)
    assert report is not None


def test_a_nested_duplicate_under_a_DISCARDED_parent_is_not_reported_as_in_force(
    tmp_path,
):
    """⛔ For `outer: {x: 1, x: 2}` followed by a second `outer:`, the whole
    first mapping is discarded -- so NEITHER `x` is in force. The walk descended
    into losing occurrences and announced `outer.x` line 3 as "the one in
    force", sending an operator to edit a line that governs nothing."""
    body = "outer:\n  x: 1\n  x: 2\nouter:\n  y: 3\n"
    p = _write(tmp_path, body)
    loaded = yaml.safe_load(body)
    assert loaded == {"outer": {"y": 3}}
    paths_reported = [d.key_path for d in find_duplicate_keys(p)]
    assert "outer" in paths_reported
    assert "outer.x" not in paths_reported, (
        f"reported a key inside a discarded mapping: {paths_reported}"
    )

def test_the_scan_sees_a_bare_safe_load_bound_by_from_yaml_import(tmp_path):
    """⚠️ The scan matched only the `yaml.safe_load` ATTRIBUTE form, so

        from yaml import safe_load
        def loader(p): return safe_load(open(p))

    was invisible to the guard -- a straight bypass of the anti-rot mechanism,
    found by a cold read after five planted defects had all been caught.
    """
    mod = tmp_path / "sneaky.py"
    mod.write_text(
        "from yaml import safe_load\n\n\ndef loader(p):\n    return safe_load(open(p))\n",
        encoding="utf-8",
    )
    tree = ast.parse(mod.read_text(encoding="utf-8"))
    assert _yaml_import_aliases(tree) == {"safe_load"}


def test_an_unrelated_duplicate_named_call_does_not_certify_a_loader():
    """⛔ "any called name containing 'duplicate'" certified this as wired:

        def loader(p):
            deduplicate_cache()
            return yaml.safe_load(open(p))

    The reporter set is now derived from the functions actually defined in the
    tree, so an unrelated name cannot vouch for a loader.
    """
    reporters = _reporter_names()
    assert "deduplicate_cache" not in reporters
    assert "warn_duplicate_keys" in reporters
    # the allowlist's differently-named reporter is discovered, not transcribed
    assert "_warn_on_duplicate_keys" in reporters


def test_the_reporter_set_is_not_empty():
    """The derived set's own control: if the discovery predicate ever matches
    nothing, every loader scores as unwired and the suite fails loudly rather
    than certifying everything as fine."""
    assert len(_reporter_names()) >= 2, _reporter_names()


# --- the three CLI loaders: behaviour, not just an AST assertion ------------
#
# ⛔ The cold read's largest cross-suite finding: these three were wired and
# then covered ONLY by the AST guard. A call could use the wrong path, sit on
# one branch, or be a no-op whose name merely contains "duplicate" -- and the
# scan would still certify them. An AST guard proves a call EXISTS; only these
# prove it fires on the file the loader actually read.


def test_import_argus_override_file_warns_on_a_duplicate(tmp_path, caplog):
    from lynceus.cli.import_argus import load_override_config

    p = tmp_path / "overrides.yaml"
    p.write_text("vendor_overrides: {}\nvendor_overrides:\n  acme: drop\n", encoding="utf-8")
    with caplog.at_level(logging.WARNING):
        load_override_config(str(p))
    warned = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any("vendor_overrides" in r.getMessage() for r in warned), warned
    assert any(str(p) in r.getMessage() for r in warned), "must name the file it read"


def test_import_argus_override_file_is_silent_when_clean(tmp_path, caplog):
    """The control -- half the guard. Without it the assertion above passes for
    a reporter that warns on every file."""
    from lynceus.cli.import_argus import load_override_config

    p = tmp_path / "overrides.yaml"
    p.write_text("vendor_overrides:\n  acme: drop\n", encoding="utf-8")
    with caplog.at_level(logging.WARNING):
        load_override_config(str(p))
    assert [r for r in caplog.records if "duplicate key" in r.getMessage()] == []


def test_setup_core_carry_forward_read_warns_on_a_duplicate(tmp_path, caplog):
    """`--reconfigure` carries this result forward, so the winning value is
    rewritten into the new file as though the operator had chosen it."""
    from lynceus.setup.core import _existing_mapping

    p = tmp_path / "lynceus.yaml"
    p.write_text("heartbeat_enabled: true\nheartbeat_enabled: false\n", encoding="utf-8")
    with caplog.at_level(logging.WARNING):
        loaded, err = _existing_mapping(p)
    assert err is None
    assert loaded["heartbeat_enabled"] is False
    assert any("heartbeat_enabled" in r.getMessage() for r in caplog.records)


def test_setup_core_carry_forward_read_is_silent_when_clean(tmp_path, caplog):
    from lynceus.setup.core import _existing_mapping

    p = tmp_path / "lynceus.yaml"
    p.write_text("heartbeat_enabled: true\n", encoding="utf-8")
    with caplog.at_level(logging.WARNING):
        _existing_mapping(p)
    assert [r for r in caplog.records if "duplicate key" in r.getMessage()] == []


def test_seed_watchlist_yaml_warns_on_a_duplicate_pattern(tmp_path, caplog):
    """#122's defect pointed the other way: there a duplicate silenced a
    device, here it watches one the operator never named."""
    from lynceus.cli.seed_watchlist import seed_from_yaml
    from lynceus.db import Database

    p = tmp_path / "seed.yaml"
    p.write_text(
        "entries:\n"
        '  - pattern: "de:ad:be:ef:00:01"\n'
        '    pattern: "de:ad:be:ef:99:99"\n'
        "    pattern_type: mac\n"
        "    severity: high\n",
        encoding="utf-8",
    )
    db = Database(str(tmp_path / "t.db"))
    with caplog.at_level(logging.WARNING):
        seed_from_yaml(db, str(p))
    assert any("entries[0].pattern" in r.getMessage() for r in caplog.records), [
        r.getMessage() for r in caplog.records
    ]


def test_the_allowlist_reporter_now_delegates_to_the_shared_one(tmp_path, caplog):
    """The overclaim this round fixed: the PR said the never-raise property was
    "implemented once so it is tested once" while the allowlist kept its own
    copy -- which had the same logger-outside-the-try hole. It delegates now,
    so the guards above cover it too."""
    import lynceus.allowlist as al

    p = tmp_path / "allowlist.yaml"
    p.write_text(
        'entries:\n  - pattern: "ac:de:48:00:11:22"\n'
        '    pattern: "ac:de:48:99:99:99"\n    pattern_type: mac\n',
        encoding="utf-8",
    )
    monkey = _ExplodingLogger("boom")
    original, al.logger = al.logger, monkey
    try:
        al._warn_on_duplicate_keys(p)  # must not raise
    finally:
        al.logger = original


# --- the UI sibling: an exemption I wrote, and never measured ---------------
#
# ⛔ #130 exempted these two loaders on the reason "daemon-managed sibling, not
# hand-edited". That was an assumption about operator behaviour, written into a
# guard whose entire purpose is to demand a REASON -- and the file is plain
# YAML in the config directory beside one this project has already proven
# people hand-edit. Measured, all three claims below were false.


def _ui_with_dup(tmp_path):
    """A valid primary beside a sibling carrying a stray second `pattern:`.

    `ac:de:48` is a genuine universally-administered OUI. `de:ad:be`/`aa:bb:cc`
    have the locally-administered bit set and are discarded before matching --
    a fixture that does not populate what the code reads is how five confident
    wrong findings got made here.
    """
    primary = tmp_path / "allowlist.yaml"
    primary.write_text("entries: []\n", encoding="utf-8")
    ui = tmp_path / "allowlist_ui.yaml"
    ui.write_text(
        "entries:\n"
        '  - pattern: "ac:de:48:00:11:22"\n'
        '    pattern: "ac:de:48:99:99:99"\n'
        "    pattern_type: mac\n"
        "    note: kev phone\n",
        encoding="utf-8",
    )
    return primary, ui


def test_a_duplicate_in_the_ui_sibling_warns_at_daemon_load(tmp_path, caplog):
    from lynceus.allowlist import load_allowlist

    primary, _ui = _ui_with_dup(tmp_path)
    with caplog.at_level(logging.WARNING):
        load_allowlist(str(primary))
    assert any(
        "entries[0].pattern" in r.getMessage() for r in caplog.records
    ), [r.getMessage() for r in caplog.records]


def test_a_clean_ui_sibling_warns_nothing(tmp_path, caplog):
    """The control -- half the guard, and the half that fails if the reporter
    is wired unconditionally."""
    from lynceus.allowlist import load_allowlist

    primary = tmp_path / "allowlist.yaml"
    primary.write_text("entries: []\n", encoding="utf-8")
    ui = tmp_path / "allowlist_ui.yaml"
    ui.write_text(
        'entries:\n  - pattern: "ac:de:48:00:11:22"\n    pattern_type: mac\n',
        encoding="utf-8",
    )
    with caplog.at_level(logging.WARNING):
        load_allowlist(str(primary))
    assert [r for r in caplog.records if "duplicate key" in r.getMessage()] == []


def test_a_ui_write_launders_the_duplicate_but_no_longer_silently(tmp_path, caplog):
    """⛔ Why this path was WORSE than the primary's, not merely equal to it.

    In the primary a duplicate stays in the file, so an operator reading it can
    still see the stray line. Here `_read_ui_yaml` round-trips through
    `yaml.safe_dump`, so ONE "Allowlist this device" click rewrites the file
    with only the winner: the address the operator actually meant is GONE and
    the file reads as though they had always chosen the other one. The daemon
    destroys its own evidence.

    The laundering is pinned as behaviour rather than fixed -- rewriting is
    what makes a UI write REPAIR a damaged file, which is load-bearing. What
    changed is that it can no longer happen without a record naming both lines.
    """
    from lynceus.allowlist import AllowlistEntry, add_ui_entry

    _primary, ui = _ui_with_dup(tmp_path)
    before = ui.read_text(encoding="utf-8")
    assert "ac:de:48:00:11:22" in before and "ac:de:48:99:99:99" in before

    with caplog.at_level(logging.WARNING):
        add_ui_entry(
            ui,
            AllowlistEntry(
                pattern="aa:11:22:33:44:55", pattern_type="mac", note="unrelated"
            ),
        )
    after = ui.read_text(encoding="utf-8")

    # the laundering itself, pinned so a future change to it is deliberate
    assert "ac:de:48:00:11:22" not in after, "intended address survived; update this pin"
    assert "ac:de:48:99:99:99" in after
    # and the record that must exist BEFORE the evidence goes
    assert any(
        "ac:de:48" in r.getMessage() or "entries[0].pattern" in r.getMessage()
        for r in caplog.records
    ), [r.getMessage() for r in caplog.records]


def test_the_validator_survives_a_detector_that_raises_anything(tmp_path, monkeypatch):
    """⭐ Added because a PLANT SURVIVED, and the survivor was informative.

    Narrowing `_duplicate_key_issues`'s catch broke no test, because the cycle
    guard added upstream means the recursive-alias case never reaches it any
    more. Two independent fixes covered one input, so the wrapper looked
    load-bearing and was actually untested.

    It still matters: `_duplicate_key_issues` calls the DETECTOR directly, not
    the warn-only wrapper that owns the never-propagate contract, so it is the
    one duplicate-key caller with no protection of its own. This pins it
    against ANY exception rather than against the one input that used to
    produce one.
    """
    import lynceus.cli.validate as V
    from lynceus.cli.validate import validate_lynceus_yaml

    def explode(_path):
        raise RecursionError("something pathological")

    monkeypatch.setattr(V, "find_duplicate_keys", explode)
    p = tmp_path / "lynceus.yaml"
    p.write_text("heartbeat_enabled: true\n", encoding="utf-8")
    report, _cfg = validate_lynceus_yaml(p)
    assert report is not None
    assert any("duplicate" in i.message for i in report.issues), [
        i.message for i in report.issues
    ]
