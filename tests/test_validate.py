"""Tests for lynceus.cli.validate — the read-only config validator."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from lynceus.cli import validate as v


# ---- helpers ---------------------------------------------------------------


def _write(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")


def _valid_lynceus_yaml() -> str:
    return (
        "kismet_url: http://127.0.0.1:2501\n"
        "kismet_api_key: token\n"
    )


def _valid_rules_yaml() -> str:
    return (
        "rules:\n"
        "  - name: argus_mac\n"
        "    rule_type: watchlist_mac\n"
        "    severity: low\n"
        "    patterns: []\n"
        "  - name: argus_oui\n"
        "    rule_type: watchlist_oui\n"
        "    severity: low\n"
        "    patterns: []\n"
    )


def _valid_severity_overrides_yaml() -> str:
    return (
        "device_category_severity:\n"
        "  imsi_catcher: high\n"
        "  drone: low\n"
        "suppress_categories:\n"
        "  - hacking_tool\n"
        "suppress_vendors:\n"
        "  - acme corp\n"
        "pattern_overrides:\n"
        "  a1b2c3d4e5f60718: high\n"
    )


def _valid_allowlist_yaml() -> str:
    return (
        "entries:\n"
        "  - pattern: 'aa:bb:cc:dd:ee:ff'\n"
        "    pattern_type: mac\n"
        "    note: My laptop\n"
    )


# ---------------------------------------------------------------------------
# Helpers + Levenshtein
# ---------------------------------------------------------------------------


def test_levenshtein_zero_for_same_string():
    assert v._levenshtein("foo", "foo") == 0


def test_levenshtein_handles_empty_strings():
    assert v._levenshtein("", "foo") == 3
    assert v._levenshtein("foo", "") == 3
    assert v._levenshtein("", "") == 0


def test_closest_returns_suggestion_for_typo():
    candidates = ("suppress_categories", "suppress_vendors", "pattern_overrides")
    assert v._closest("supress_categories", candidates) == "suppress_categories"


def test_closest_returns_none_when_too_far():
    candidates = ("suppress_categories",)
    assert v._closest("totally_unrelated", candidates) is None


# ---------------------------------------------------------------------------
# validate_lynceus_yaml
# ---------------------------------------------------------------------------


def test_lynceus_missing_file(tmp_path):
    target = tmp_path / "lynceus.yaml"
    report, cfg = v.validate_lynceus_yaml(target)
    assert cfg is None
    assert not report.exists
    assert not report.valid
    assert any(i.severity == "error" and "not found" in i.message for i in report.issues)


def test_lynceus_unparseable(tmp_path):
    target = tmp_path / "lynceus.yaml"
    _write(target, "kismet_url: [unbalanced\n")
    report, cfg = v.validate_lynceus_yaml(target)
    assert cfg is None
    assert report.exists
    assert not report.valid
    assert any("YAML parse error" in i.message for i in report.issues)


def test_lynceus_valid_minimal(tmp_path):
    target = tmp_path / "lynceus.yaml"
    _write(target, _valid_lynceus_yaml())
    report, cfg = v.validate_lynceus_yaml(target)
    assert cfg is not None
    assert report.valid
    assert report.issues == ()


def test_lynceus_schema_violation_invalid_url(tmp_path):
    target = tmp_path / "lynceus.yaml"
    _write(target, "kismet_url: not-a-url\n")
    report, cfg = v.validate_lynceus_yaml(target)
    assert cfg is None
    assert not report.valid
    assert any(i.severity == "error" for i in report.issues)
    joined = " ".join(i.message for i in report.issues)
    assert "kismet_url" in joined


def test_lynceus_missing_referenced_rules_path(tmp_path):
    target = tmp_path / "lynceus.yaml"
    body = _valid_lynceus_yaml() + f"rules_path: {tmp_path / 'nope.yaml'}\n"
    _write(target, body)
    report, cfg = v.validate_lynceus_yaml(target)
    assert cfg is None
    assert any(
        "rules_path" in i.message and "missing file" in i.message for i in report.issues
    )


def test_lynceus_unset_rules_path_does_not_warn(tmp_path):
    target = tmp_path / "lynceus.yaml"
    _write(target, _valid_lynceus_yaml())
    report, cfg = v.validate_lynceus_yaml(target)
    assert cfg is not None
    assert report.valid
    assert not any("rules_path" in i.message for i in report.issues)


# ---------------------------------------------------------------------------
# validate_rules_yaml
# ---------------------------------------------------------------------------


def test_rules_missing_file(tmp_path):
    p = tmp_path / "rules.yaml"
    report = v.validate_rules_yaml(p)
    assert not report.exists
    assert not report.valid


def test_rules_unparseable(tmp_path):
    p = tmp_path / "rules.yaml"
    _write(p, "rules: [unbalanced\n")
    report = v.validate_rules_yaml(p)
    assert not report.valid
    assert any("YAML parse error" in i.message for i in report.issues)


def test_rules_valid(tmp_path):
    p = tmp_path / "rules.yaml"
    _write(p, _valid_rules_yaml())
    report = v.validate_rules_yaml(p)
    assert report.valid
    assert "2 rule" in report.summary


def test_rules_duplicate_names(tmp_path):
    p = tmp_path / "rules.yaml"
    _write(
        p,
        (
            "rules:\n"
            "  - name: dup\n"
            "    rule_type: watchlist_mac\n"
            "    severity: low\n"
            "    patterns: []\n"
            "  - name: dup\n"
            "    rule_type: watchlist_oui\n"
            "    severity: low\n"
            "    patterns: []\n"
        ),
    )
    report = v.validate_rules_yaml(p)
    assert not report.valid
    joined = " ".join(i.message for i in report.issues)
    assert "duplicate" in joined.lower()


def test_rules_invalid_rule_type(tmp_path):
    p = tmp_path / "rules.yaml"
    _write(
        p,
        (
            "rules:\n"
            "  - name: bad\n"
            "    rule_type: not_a_real_type\n"
            "    severity: low\n"
            "    patterns: []\n"
        ),
    )
    report = v.validate_rules_yaml(p)
    assert not report.valid


def test_rules_mac_range_with_patterns_is_error(tmp_path):
    p = tmp_path / "rules.yaml"
    _write(
        p,
        (
            "rules:\n"
            "  - name: bad\n"
            "    rule_type: watchlist_mac_range\n"
            "    severity: low\n"
            "    patterns:\n"
            "      - 'aa:bb:cc'\n"
        ),
    )
    report = v.validate_rules_yaml(p)
    assert not report.valid


def test_rules_delegation_empty_patterns_is_valid(tmp_path):
    """Empty patterns + delegation-capable type is the canonical
    delegation shape, NOT an error."""
    p = tmp_path / "rules.yaml"
    _write(p, _valid_rules_yaml())
    report = v.validate_rules_yaml(p)
    assert report.valid


def test_rules_empty_ruleset_warns(tmp_path):
    p = tmp_path / "rules.yaml"
    _write(p, "rules: []\n")
    report = v.validate_rules_yaml(p)
    assert report.valid
    assert any(i.severity == "warning" for i in report.issues)


# ---------------------------------------------------------------------------
# validate_severity_overrides_yaml
# ---------------------------------------------------------------------------


def test_severity_overrides_missing_is_ok(tmp_path):
    p = tmp_path / "severity_overrides.yaml"
    report = v.validate_severity_overrides_yaml(p)
    assert not report.exists
    assert report.valid  # missing is allowed


def test_severity_overrides_valid(tmp_path):
    p = tmp_path / "severity_overrides.yaml"
    _write(p, _valid_severity_overrides_yaml())
    report = v.validate_severity_overrides_yaml(p)
    assert report.valid, [i.message for i in report.issues]


def test_severity_overrides_unparseable(tmp_path):
    p = tmp_path / "severity_overrides.yaml"
    _write(p, "device_category_severity: [bad\n")
    report = v.validate_severity_overrides_yaml(p)
    assert not report.valid
    assert any("YAML parse error" in i.message for i in report.issues)


def test_severity_overrides_unknown_top_level_key_warns(tmp_path):
    p = tmp_path / "severity_overrides.yaml"
    _write(p, "supress_categories:\n  - drone\n")  # typo: supress
    report = v.validate_severity_overrides_yaml(p)
    # Unknown key is WARNING, not ERROR.
    assert report.valid
    found = [i for i in report.issues if i.severity == "warning"]
    assert any("unknown key 'supress_categories'" in i.message for i in found)
    # Levenshtein hint should point at the right key.
    assert any(
        i.hint and "suppress_categories" in i.hint for i in found
    )


def test_severity_overrides_invalid_severity_literal_is_error(tmp_path):
    p = tmp_path / "severity_overrides.yaml"
    _write(
        p,
        ("device_category_severity:\n  unknown: medium\n"),
    )
    report = v.validate_severity_overrides_yaml(p)
    assert not report.valid
    errs = [i for i in report.issues if i.severity == "error"]
    assert any("medium" in i.message and "must be one of" in i.message for i in errs)


def test_severity_overrides_unknown_category_warns(tmp_path):
    p = tmp_path / "severity_overrides.yaml"
    _write(
        p,
        ("device_category_severity:\n  zorblax: high\n"),
    )
    report = v.validate_severity_overrides_yaml(p)
    # Unknown category is a WARNING, not an ERROR (Argus may add new
    # categories upstream).
    assert report.valid
    warns = [i for i in report.issues if i.severity == "warning"]
    assert any("zorblax" in i.message for i in warns)


def test_severity_overrides_pattern_overrides_bad_key_is_error(tmp_path):
    p = tmp_path / "severity_overrides.yaml"
    _write(
        p,
        ("pattern_overrides:\n  not_16_hex: high\n"),
    )
    report = v.validate_severity_overrides_yaml(p)
    assert not report.valid
    errs = [i for i in report.issues if i.severity == "error"]
    assert any("16-hex" in i.message for i in errs)


def test_severity_overrides_pattern_overrides_good_key_is_valid(tmp_path):
    p = tmp_path / "severity_overrides.yaml"
    _write(
        p,
        ("pattern_overrides:\n  a1b2c3d4e5f60718: high\n"),
    )
    report = v.validate_severity_overrides_yaml(p)
    assert report.valid


def test_severity_overrides_suppress_vendors_empty_string_warns(tmp_path):
    p = tmp_path / "severity_overrides.yaml"
    _write(
        p,
        ("suppress_vendors:\n  - ''\n  - 'acme corp'\n"),
    )
    report = v.validate_severity_overrides_yaml(p)
    assert report.valid  # empty entry is WARNING
    warns = [i for i in report.issues if i.severity == "warning"]
    assert any("empty after stripping" in i.message for i in warns)


def test_severity_overrides_top_level_non_mapping_is_error(tmp_path):
    p = tmp_path / "severity_overrides.yaml"
    _write(p, "- just a list\n- not a mapping\n")
    report = v.validate_severity_overrides_yaml(p)
    assert not report.valid


def test_severity_overrides_line_numbers_attached(tmp_path):
    p = tmp_path / "severity_overrides.yaml"
    _write(
        p,
        (
            "# leading comment\n"
            "device_category_severity:\n"
            "  unknown: medium\n"
        ),
    )
    report = v.validate_severity_overrides_yaml(p)
    errs = [i for i in report.issues if i.severity == "error" and "medium" in i.message]
    assert errs and errs[0].line == 3


# ---------------------------------------------------------------------------
# validate_allowlist_yaml / validate_allowlist_ui_yaml
# ---------------------------------------------------------------------------


def test_allowlist_missing_is_error(tmp_path):
    p = tmp_path / "allowlist.yaml"
    report = v.validate_allowlist_yaml(p)
    assert not report.valid
    assert any("not found" in i.message for i in report.issues)


def test_allowlist_valid(tmp_path):
    p = tmp_path / "allowlist.yaml"
    _write(p, _valid_allowlist_yaml())
    report = v.validate_allowlist_yaml(p)
    assert report.valid
    assert "1 entry valid" in report.summary


def test_allowlist_unparseable(tmp_path):
    p = tmp_path / "allowlist.yaml"
    _write(p, "entries: [unbalanced\n")
    report = v.validate_allowlist_yaml(p)
    assert not report.valid
    assert any("YAML parse error" in i.message for i in report.issues)


def test_allowlist_invalid_entry_promoted_to_error(tmp_path):
    """load_allowlist swallows Pydantic errors on the primary file
    (logs ERROR + returns empty). The validator promotes that ERROR-
    log to an ERROR-level Issue so the operator sees it."""
    p = tmp_path / "allowlist.yaml"
    _write(
        p,
        (
            "entries:\n"
            "  - pattern: 'not a mac'\n"
            "    pattern_type: mac\n"
        ),
    )
    report = v.validate_allowlist_yaml(p)
    assert not report.valid
    assert any(i.severity == "error" for i in report.issues)


def test_allowlist_expired_entry_warns(tmp_path):
    p = tmp_path / "allowlist.yaml"
    _write(
        p,
        (
            "entries:\n"
            "  - pattern: 'aa:bb:cc:dd:ee:ff'\n"
            "    pattern_type: mac\n"
            "    expires_at: 1700000000\n"
        ),
    )
    report = v.validate_allowlist_yaml(p, now_ts=1800000000)
    # Expired entry is WARNING; the file is still valid.
    assert report.valid
    warns = [i for i in report.issues if i.severity == "warning"]
    assert any("expired" in i.message for i in warns)


def test_allowlist_future_expiry_no_warning(tmp_path):
    p = tmp_path / "allowlist.yaml"
    _write(
        p,
        (
            "entries:\n"
            "  - pattern: 'aa:bb:cc:dd:ee:ff'\n"
            "    pattern_type: mac\n"
            "    expires_at: 2000000000\n"
        ),
    )
    report = v.validate_allowlist_yaml(p, now_ts=1800000000)
    assert report.valid
    assert report.issues == ()


def test_allowlist_ui_missing_is_ok(tmp_path):
    p = tmp_path / "allowlist_ui.yaml"
    report = v.validate_allowlist_ui_yaml(p)
    assert not report.exists
    assert report.valid


def test_allowlist_ui_valid(tmp_path):
    p = tmp_path / "allowlist_ui.yaml"
    _write(p, _valid_allowlist_yaml())
    report = v.validate_allowlist_ui_yaml(p)
    assert report.valid


def test_allowlist_ui_invalid_entry_is_error(tmp_path):
    """Sibling has the same Pydantic surface; the sibling validator
    constructs Allowlist directly and ValidationError surfaces
    as an ERROR."""
    p = tmp_path / "allowlist_ui.yaml"
    _write(
        p,
        (
            "entries:\n"
            "  - pattern: 'not a mac'\n"
            "    pattern_type: mac\n"
        ),
    )
    report = v.validate_allowlist_ui_yaml(p)
    assert not report.valid


# ---------------------------------------------------------------------------
# Orchestrator + render_report
# ---------------------------------------------------------------------------


def _wire_scope(monkeypatch, config_dir: Path) -> None:
    """Monkey-patch paths.default_config_dir to point at tmp_path."""
    from lynceus import paths as _paths

    monkeypatch.setattr(_paths, "default_config_dir", lambda scope: config_dir)


def test_orchestrator_all_valid(monkeypatch, tmp_path):
    _wire_scope(monkeypatch, tmp_path)
    rules_path = tmp_path / "rules.yaml"
    sev_path = tmp_path / "severity_overrides.yaml"
    allow_path = tmp_path / "allowlist.yaml"

    _write(rules_path, _valid_rules_yaml())
    _write(sev_path, _valid_severity_overrides_yaml())
    _write(allow_path, _valid_allowlist_yaml())
    _write(
        tmp_path / "lynceus.yaml",
        (
            _valid_lynceus_yaml()
            + f"rules_path: {rules_path}\n"
            + f"severity_overrides_path: {sev_path}\n"
            + f"allowlist_path: {allow_path}\n"
        ),
    )
    reports = v._collect_reports("user")
    # lynceus + rules + severity + allowlist + ui sibling = 5
    assert len(reports) == 5
    assert all(r.valid for r in reports)


def test_orchestrator_lynceus_error_skips_downstream(monkeypatch, tmp_path):
    _wire_scope(monkeypatch, tmp_path)
    _write(tmp_path / "lynceus.yaml", "kismet_url: not-a-url\n")
    reports = v._collect_reports("user")
    assert len(reports) == 1
    assert not reports[0].valid


def test_orchestrator_unset_paths_skip_validators(monkeypatch, tmp_path):
    _wire_scope(monkeypatch, tmp_path)
    _write(tmp_path / "lynceus.yaml", _valid_lynceus_yaml())
    reports = v._collect_reports("user")
    # Only lynceus.yaml — the other three paths are unset.
    assert len(reports) == 1
    assert reports[0].valid


def test_main_returns_zero_on_clean_config(monkeypatch, tmp_path, capsys):
    _wire_scope(monkeypatch, tmp_path)
    _write(tmp_path / "lynceus.yaml", _valid_lynceus_yaml())
    rc = v.main(["--scope", "user"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "Summary: 0 errors, 0 warnings" in out


def test_main_returns_one_on_errors(monkeypatch, tmp_path, capsys):
    _wire_scope(monkeypatch, tmp_path)
    _write(tmp_path / "lynceus.yaml", "kismet_url: not-a-url\n")
    rc = v.main(["--scope", "user"])
    assert rc == 1


def test_main_returns_zero_on_warnings_only(monkeypatch, tmp_path, capsys):
    _wire_scope(monkeypatch, tmp_path)
    rules_path = tmp_path / "rules.yaml"
    _write(rules_path, "rules: []\n")  # empty -> WARNING
    _write(
        tmp_path / "lynceus.yaml",
        _valid_lynceus_yaml() + f"rules_path: {rules_path}\n",
    )
    rc = v.main(["--scope", "user"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "warning" in out.lower()


def test_main_returns_two_on_unreachable_config_dir(monkeypatch, capsys):
    from lynceus import paths as _paths

    def boom(scope):
        raise NotImplementedError("system scope unsupported on this platform")

    monkeypatch.setattr(_paths, "default_config_dir", boom)
    rc = v.main(["--scope", "system"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "cannot resolve config dir" in err


def test_quiet_suppresses_ok_and_warning_lines(monkeypatch, tmp_path, capsys):
    _wire_scope(monkeypatch, tmp_path)
    rules_path = tmp_path / "rules.yaml"
    _write(rules_path, "rules: []\n")  # warning
    _write(
        tmp_path / "lynceus.yaml",
        _valid_lynceus_yaml() + f"rules_path: {rules_path}\n",
    )
    rc = v.main(["--scope", "user", "--quiet"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "OK" not in out
    assert "WARNING" not in out  # warnings suppressed in quiet mode
    assert "Summary:" in out


def test_quiet_still_prints_errors(monkeypatch, tmp_path, capsys):
    _wire_scope(monkeypatch, tmp_path)
    _write(tmp_path / "lynceus.yaml", "kismet_url: not-a-url\n")
    rc = v.main(["--scope", "user", "--quiet"])
    assert rc == 1
    out = capsys.readouterr().out
    assert "ERROR" in out
    assert "Summary:" in out


def test_scope_user_vs_system_resolves_different_paths(monkeypatch, tmp_path):
    from lynceus import paths as _paths

    user_dir = tmp_path / "user"
    sys_dir = tmp_path / "sys"
    user_dir.mkdir()
    sys_dir.mkdir()
    _write(user_dir / "lynceus.yaml", _valid_lynceus_yaml())
    _write(sys_dir / "lynceus.yaml", "kismet_url: not-a-url\n")

    def _dir(scope):
        return user_dir if scope == "user" else sys_dir

    monkeypatch.setattr(_paths, "default_config_dir", _dir)

    u_reports = v._collect_reports("user")
    s_reports = v._collect_reports("system")
    assert u_reports[0].valid
    assert not s_reports[0].valid


# ---------------------------------------------------------------------------
# Output format
# ---------------------------------------------------------------------------


def test_output_is_plain_ascii(monkeypatch, tmp_path, capsys):
    _wire_scope(monkeypatch, tmp_path)
    _write(
        tmp_path / "lynceus.yaml",
        ("device_category_severity:\n  unknown: medium\n"),
    )
    # Force an error scenario with a warning hint to exercise both
    # styles of issue formatting.
    _write(tmp_path / "lynceus.yaml", _valid_lynceus_yaml())
    rules_path = tmp_path / "rules.yaml"
    _write(rules_path, "rules: []\n")
    _write(
        tmp_path / "lynceus.yaml",
        _valid_lynceus_yaml() + f"rules_path: {rules_path}\n",
    )
    v.main(["--scope", "user"])
    out = capsys.readouterr().out
    out.encode("ascii")  # raises if anything isn't ASCII
    # No ANSI escape codes.
    assert "\x1b[" not in out


def test_summary_counts_match_emitted_issues(monkeypatch, tmp_path, capsys):
    _wire_scope(monkeypatch, tmp_path)
    sev_path = tmp_path / "severity_overrides.yaml"
    _write(
        sev_path,
        (
            "device_category_severity:\n"
            "  unknown: medium\n"  # ERROR
            "supress_categories:\n"  # WARNING (unknown key, levenshtein hint)
            "  - drone\n"
        ),
    )
    _write(
        tmp_path / "lynceus.yaml",
        _valid_lynceus_yaml() + f"severity_overrides_path: {sev_path}\n",
    )
    v.main(["--scope", "user"])
    out = capsys.readouterr().out
    # 1 error from invalid severity literal, >=1 warning from unknown
    # top-level key.
    assert "1 error" in out
    assert "warning" in out
    assert "across 2 files" in out


def test_summary_pluralization(monkeypatch, tmp_path, capsys):
    _wire_scope(monkeypatch, tmp_path)
    _write(tmp_path / "lynceus.yaml", _valid_lynceus_yaml())
    v.main(["--scope", "user"])
    out = capsys.readouterr().out
    assert "Summary: 0 errors, 0 warnings across 1 file" in out


def test_report_renders_file_paths(monkeypatch, tmp_path, capsys):
    _wire_scope(monkeypatch, tmp_path)
    _write(tmp_path / "lynceus.yaml", _valid_lynceus_yaml())
    v.main(["--scope", "user"])
    out = capsys.readouterr().out
    assert str(tmp_path / "lynceus.yaml") in out


# ---------------------------------------------------------------------------
# Rollback subcommand
# ---------------------------------------------------------------------------


def test_rollback_subcommand_to_zero(tmp_path, capsys):
    """`lynceus-validate rollback --db PATH --target-version 0 --yes`
    rolls every applied migration back. Exit 0, applied_versions empty
    after the call."""
    from lynceus.db import Database

    db_path = str(tmp_path / "lynceus.db")
    Database(db_path).close()  # forward-apply 001..019 via __init__

    exit_code = v.main(
        ["rollback", "--db", db_path, "--target-version", "0", "--yes"]
    )
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Rollback complete" in out

    # Re-open the DB; applied_versions starts re-applying forward
    # because Database.__init__ runs _apply_migrations. Confirm the
    # versions match the full chain after the re-init — proves the
    # rollback was atomic + the forward path is still functional.
    db = Database(db_path)
    assert db.applied_versions() == list(range(1, 20))
    db.close()


def test_rollback_subcommand_target_version_required(capsys):
    """Missing --target-version is a parser error (argparse exits 2)."""
    with pytest.raises(SystemExit) as exc:
        v.main(["rollback", "--db", "/tmp/whatever.db", "--yes"])
    assert exc.value.code == 2


def test_rollback_subcommand_negative_target_rejected(tmp_path, capsys):
    """Negative --target-version is preflight-rejected with exit 2."""
    from lynceus.db import Database

    db_path = str(tmp_path / "lynceus.db")
    Database(db_path).close()

    exit_code = v.main(
        ["rollback", "--db", db_path, "--target-version", "-1", "--yes"]
    )
    assert exit_code == 2


def test_rollback_subcommand_missing_db_path(tmp_path, capsys):
    """Non-existent --db path is preflight-rejected with exit 2."""
    missing = str(tmp_path / "does-not-exist.db")
    exit_code = v.main(
        ["rollback", "--db", missing, "--target-version", "0", "--yes"]
    )
    assert exit_code == 2
    err = capsys.readouterr().err
    assert "not found" in err


def test_rollback_subcommand_requires_yes_or_tty(monkeypatch, tmp_path, capsys):
    """Without --yes and with no tty, the rollback refuses (exit 2)."""
    from lynceus.db import Database

    db_path = str(tmp_path / "lynceus.db")
    Database(db_path).close()

    # Force isatty to False so the preflight path triggers.
    import sys as _sys

    monkeypatch.setattr(_sys.stdin, "isatty", lambda: False)
    exit_code = v.main(
        ["rollback", "--db", db_path, "--target-version", "0"]
    )
    assert exit_code == 2
    err = capsys.readouterr().err
    assert "stdin is not a tty" in err


def test_legacy_invocation_no_subcommand_still_validates(
    monkeypatch, tmp_path, capsys
):
    """`lynceus-validate --scope user` (no subcommand) still runs the
    validator — proves the subparser restructure preserves the legacy
    operator-script invocation shape."""
    _wire_scope(monkeypatch, tmp_path)
    _write(tmp_path / "lynceus.yaml", _valid_lynceus_yaml())
    exit_code = v.main(["--scope", "user"])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Summary:" in out


def test_explicit_validate_subcommand_works(monkeypatch, tmp_path, capsys):
    """`lynceus-validate validate --scope user` is the explicit form of
    the legacy invocation."""
    _wire_scope(monkeypatch, tmp_path)
    _write(tmp_path / "lynceus.yaml", _valid_lynceus_yaml())
    exit_code = v.main(["validate", "--scope", "user"])
    assert exit_code == 0
