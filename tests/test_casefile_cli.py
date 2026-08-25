"""lynceus-export-case.

The CLI is one of two entry points and it makes no disclosure decision
of its own: it parses arguments, calls the choke point and writes what
comes back. What is tested here is the operator-facing contract, which
is that a failure is loud and a success is checkable.
"""

from __future__ import annotations

import json

import pytest

from lynceus.cli.export_case import main
from tests.test_casefile_query import TARGET, _add_evidence, _seed


@pytest.fixture
def seeded(tmp_path):
    db, alert_id = _seed(tmp_path)
    _add_evidence(db, alert_id, TARGET)
    second = db.add_alert(
        ts=1_699_840_820,
        rule_name="watchlist-mac",
        mac=TARGET,
        message="second sighting",
        severity="high",
        rule_type="watchlist_mac",
    )
    _add_evidence(db, second, TARGET, do_not_publish=1, captured_at=1_699_840_821)
    db.close()
    return tmp_path / "case.db"


def test_a_successful_export_exits_zero_and_writes_a_real_bundle(seeded, tmp_path, capsys):
    out = tmp_path / "cases"
    code = main([TARGET, "--db", str(seeded), "--out", str(out)])
    assert code == 0, capsys.readouterr().err

    bundles = [p for p in out.iterdir() if p.is_dir()]
    assert len(bundles) == 1
    bundle = bundles[0]
    assert (bundle / "case-file.html").exists()
    assert (bundle / "README.txt").exists()
    manifest = json.loads((bundle / "manifest.json").read_text())
    for name in manifest["files"]:
        assert (bundle / name).exists(), f"manifest names a file that is not there: {name}"


def test_the_summary_prints_the_do_not_publish_exclusion(seeded, tmp_path, capsys):
    """A withheld row the operator is not told about is the failure this
    whole rule exists to avoid."""
    main([TARGET, "--db", str(seeded), "--out", str(tmp_path / "cases")])
    out = capsys.readouterr().out
    assert "do_not_publish" in out
    assert "1 evidence" in out


def test_the_summary_prints_the_manifest_digest(seeded, tmp_path, capsys):
    """The digest is the only part of the output a recipient can check
    the bundle against, so it belongs on the terminal, not only in a file."""
    main([TARGET, "--db", str(seeded), "--out", str(tmp_path / "cases")])
    out = capsys.readouterr().out
    bundle = next((tmp_path / "cases").iterdir())
    digest = json.loads((bundle / "manifest.json").read_text())["manifest_sha256"]
    assert digest[:16] in out


def test_an_unknown_mac_exits_non_zero_with_a_readable_message(seeded, tmp_path, capsys):
    code = main(["11:22:33:44:55:66", "--db", str(seeded), "--out", str(tmp_path / "cases")])
    assert code != 0
    err = capsys.readouterr().err
    assert "11:22:33:44:55:66" in err
    assert "lynceus-export-case" in err


def test_a_malformed_mac_is_refused_before_anything_is_written(seeded, tmp_path, capsys):
    out = tmp_path / "cases"
    code = main(["../../etc/passwd", "--db", str(seeded), "--out", str(out)])
    assert code != 0
    assert not out.exists() or not any(out.iterdir())


def test_a_missing_database_is_reported_rather_than_created(tmp_path, capsys):
    """Pointing at the wrong path must not silently produce an empty
    database and then an empty case file."""
    missing = tmp_path / "nope.db"
    code = main([TARGET, "--db", str(missing), "--out", str(tmp_path / "cases")])
    assert code != 0
    assert "nope.db" in capsys.readouterr().err
    assert not missing.exists(), "the CLI created the database it was told to read"
