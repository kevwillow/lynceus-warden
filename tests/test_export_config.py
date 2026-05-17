"""Tests for lynceus.cli.export_config — the operator config-bundle CLI.

The CLI is read-only end-to-end. These tests build a tmp_path fixture
filled with stand-in config files, point lynceus.paths at it via
monkeypatching the directory helpers, run main(...) for a flag
combination, then either re-open the resulting tar.gz to assert
contents and manifest, or scan stdout (for --dry-run).

The whole suite is filesystem-only — no QApplication, no subprocess,
no network. Runs on Linux and Windows because tarfile + pathlib is
cross-platform.
"""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from lynceus.cli import export_config as ec
from lynceus.redact import REDACTED_PLACEHOLDER


# --- shared fixture --------------------------------------------------------


@pytest.fixture
def lynceus_layout(tmp_path, monkeypatch):
    """Stand-in user-scope filesystem layout.

    Builds:
      <root>/config/lynceus.yaml         (with kismet_api_key + ntfy_*)
      <root>/config/rules.yaml
      <root>/config/severity_overrides.yaml
      <root>/config/allowlist.yaml
      <root>/config/allowlist_ui.yaml
      <root>/data/lynceus.db             (small sqlite-shaped bytes)
      <root>/data/lynceus.db-wal         (small sqlite-shaped bytes)

    Monkeypatches paths.default_config_dir / default_data_dir /
    default_overrides_path / default_db_path / default_config_path to
    return the corresponding paths under <root> regardless of platform.
    """
    config_dir = tmp_path / "config"
    data_dir = tmp_path / "data"
    config_dir.mkdir()
    data_dir.mkdir()

    lynceus_yaml = config_dir / "lynceus.yaml"
    lynceus_yaml.write_text(
        "kismet_url: http://127.0.0.1:2501\n"
        "kismet_api_key: realsecrettoken12345\n"
        "location_id: home\n"
        "ntfy_url: https://ntfy.sh\n"
        "ntfy_topic: lynceus-supersecret\n"
        "ntfy_auth_token: tk_abcdef\n",
        encoding="utf-8",
    )
    (config_dir / "rules.yaml").write_text(
        "rules:\n  - name: r1\n    rule_type: watchlist_mac\n    severity: low\n    patterns: []\n",
        encoding="utf-8",
    )
    (config_dir / "severity_overrides.yaml").write_text(
        "device_category_severity:\n  imsi_catcher: high\n",
        encoding="utf-8",
    )
    (config_dir / "allowlist.yaml").write_text(
        "entries:\n  - pattern: aa:bb:cc:dd:ee:ff\n    pattern_type: mac\n    note: my laptop\n",
        encoding="utf-8",
    )
    (config_dir / "allowlist_ui.yaml").write_text(
        "entries: []\n",
        encoding="utf-8",
    )

    # SQLite file header + a bit of body. Real-DB header is "SQLite
    # format 3\x00" (16 bytes); we just need non-empty deterministic
    # bytes for the SHA256 round-trip check.
    (data_dir / "lynceus.db").write_bytes(b"SQLite format 3\x00" + b"\x00" * 32)
    (data_dir / "lynceus.db-wal").write_bytes(b"WAL-FAKE" + b"\x00" * 8)
    # Intentionally NO -shm to exercise the "sidecar absent" branch.

    from lynceus import paths as p

    def _dir(scope):
        assert scope == "user"
        return config_dir

    def _data(scope):
        assert scope == "user"
        return data_dir

    def _ov(scope):
        return config_dir / "severity_overrides.yaml"

    def _db(scope):
        return data_dir / "lynceus.db"

    def _cfg(scope):
        return config_dir / "lynceus.yaml"

    monkeypatch.setattr(p, "default_config_dir", _dir)
    monkeypatch.setattr(p, "default_data_dir", _data)
    monkeypatch.setattr(p, "default_overrides_path", _ov)
    monkeypatch.setattr(p, "default_db_path", _db)
    monkeypatch.setattr(p, "default_config_path", _cfg)

    return {
        "root": tmp_path,
        "config_dir": config_dir,
        "data_dir": data_dir,
        "lynceus_yaml": lynceus_yaml,
    }


def _open_archive(path: Path) -> dict[str, bytes]:
    """Read every regular file from a tar.gz into a name -> bytes dict.
    Names are the POSIX-style archive paths."""
    out: dict[str, bytes] = {}
    with tarfile.open(path, "r:gz") as tar:
        for member in tar.getmembers():
            if not member.isreg():
                continue
            f = tar.extractfile(member)
            assert f is not None  # regular files always extract
            out[member.name] = f.read()
    return out


def _manifest_from(archive_contents: dict[str, bytes]) -> dict:
    [manifest_name] = [n for n in archive_contents if n.endswith("/manifest.json")]
    return json.loads(archive_contents[manifest_name])


# --- default behavior ------------------------------------------------------


def test_default_export_redacts_and_omits_state(lynceus_layout, tmp_path):
    out = tmp_path / "default.tar.gz"
    rc = ec.main(["--scope", "user", "--output", str(out)])
    assert rc == 0
    assert out.exists()

    contents = _open_archive(out)
    archive_names = sorted(contents.keys())
    # No state/ entries in the default export.
    assert not any(n.split("/", 2)[1] == "state" for n in archive_names if "/" in n)
    # All five configs were bundled.
    config_files = [n for n in contents if "/config/" in n]
    assert len(config_files) == 5

    # lynceus.yaml must NOT contain the raw secrets.
    [lynceus_arcname] = [n for n in contents if n.endswith("/config/lynceus.yaml")]
    body = contents[lynceus_arcname].decode("utf-8")
    assert "realsecrettoken12345" not in body
    assert "lynceus-supersecret" not in body
    assert "tk_abcdef" not in body
    assert REDACTED_PLACEHOLDER in body

    manifest = _manifest_from(contents)
    assert manifest["scope"] == "user"
    assert manifest["redaction_applied"] is True
    assert manifest["include_state"] is False
    # Three redacted-field entries: kismet_api_key + ntfy_topic + ntfy_auth_token.
    fields = sorted(manifest["redacted_fields"])
    assert fields == sorted(
        [
            "config/lynceus.yaml:kismet_api_key",
            "config/lynceus.yaml:ntfy_topic",
            "config/lynceus.yaml:ntfy_auth_token",
        ]
    )


def test_manifest_sha256_matches_archive_content(lynceus_layout, tmp_path):
    import hashlib

    out = tmp_path / "sha.tar.gz"
    rc = ec.main(["--scope", "user", "--output", str(out)])
    assert rc == 0

    contents = _open_archive(out)
    manifest = _manifest_from(contents)

    # Each file entry's SHA256 must match the bytes actually in the archive.
    for entry in manifest["files"]:
        [arcname] = [n for n in contents if n.endswith(f"/{entry['path']}")]
        actual_sha = hashlib.sha256(contents[arcname]).hexdigest()
        assert actual_sha == entry["sha256"], (
            f"sha mismatch on {entry['path']}"
        )
        assert entry["size_bytes"] == len(contents[arcname])


def test_manifest_carries_required_top_level_fields(lynceus_layout, tmp_path):
    out = tmp_path / "fields.tar.gz"
    rc = ec.main(["--scope", "user", "--output", str(out)])
    assert rc == 0
    manifest = _manifest_from(_open_archive(out))
    for key in (
        "lynceus_version",
        "export_timestamp_utc",
        "scope",
        "exporter_command",
        "include_state",
        "redaction_applied",
        "redacted_fields",
        "files",
        "missing",
        "errored",
    ):
        assert key in manifest, f"manifest missing {key}"
    # The exporter_command always begins with the CLI basename so a
    # support recipient can tell which tool produced the bundle.
    assert isinstance(manifest["exporter_command"], list)
    assert manifest["exporter_command"][0] != ""


def test_readme_present_in_archive(lynceus_layout, tmp_path):
    out = tmp_path / "readme.tar.gz"
    rc = ec.main(["--scope", "user", "--output", str(out)])
    assert rc == 0
    contents = _open_archive(out)
    [readme_name] = [n for n in contents if n.endswith("/README.txt")]
    body = contents[readme_name].decode("utf-8")
    assert "Lynceus configuration export" in body
    assert "Restoring" in body
    # Redacted exports tell the receiver to replace placeholders.
    assert REDACTED_PLACEHOLDER in body


# --- missing files ---------------------------------------------------------


def test_missing_severity_overrides_logged_in_manifest(lynceus_layout, tmp_path):
    (lynceus_layout["config_dir"] / "severity_overrides.yaml").unlink()
    out = tmp_path / "missing.tar.gz"
    rc = ec.main(["--scope", "user", "--output", str(out)])
    # Missing inputs are not errors — exit 0.
    assert rc == 0
    contents = _open_archive(out)
    manifest = _manifest_from(contents)
    assert "config/severity_overrides.yaml" in manifest["missing"]
    # The missing file is absent from the files block AND from the archive.
    files_block_paths = {e["path"] for e in manifest["files"]}
    assert "config/severity_overrides.yaml" not in files_block_paths
    archive_paths = [n for n in contents if "severity_overrides.yaml" in n]
    assert archive_paths == []


# --- flag combinations -----------------------------------------------------


def test_include_state_adds_db_and_wal(lynceus_layout, tmp_path):
    out = tmp_path / "state.tar.gz"
    rc = ec.main(["--scope", "user", "--include-state", "--output", str(out)])
    assert rc == 0
    contents = _open_archive(out)
    state_names = [n for n in contents if "/state/" in n]
    # DB + WAL sidecar (we created -wal but not -shm in the fixture).
    state_basenames = sorted(Path(n).name for n in state_names)
    assert state_basenames == ["lynceus.db", "lynceus.db-wal"]
    manifest = _manifest_from(contents)
    assert manifest["include_state"] is True
    state_files = [e for e in manifest["files"] if e["path"].startswith("state/")]
    assert len(state_files) == 2


def test_include_state_db_byte_identical(lynceus_layout, tmp_path):
    out = tmp_path / "state_identity.tar.gz"
    rc = ec.main(["--scope", "user", "--include-state", "--output", str(out)])
    assert rc == 0
    contents = _open_archive(out)
    [db_arcname] = [n for n in contents if n.endswith("/state/lynceus.db")]
    on_disk = (lynceus_layout["data_dir"] / "lynceus.db").read_bytes()
    assert contents[db_arcname] == on_disk


def test_include_secrets_leaves_raw_credentials(lynceus_layout, tmp_path):
    out = tmp_path / "secrets.tar.gz"
    rc = ec.main(["--scope", "user", "--include-secrets", "--output", str(out)])
    assert rc == 0
    contents = _open_archive(out)
    [lynceus_arcname] = [n for n in contents if n.endswith("/config/lynceus.yaml")]
    body = contents[lynceus_arcname].decode("utf-8")
    # The bypass is the whole point of --include-secrets.
    assert "realsecrettoken12345" in body
    assert "lynceus-supersecret" in body
    assert "tk_abcdef" in body
    assert REDACTED_PLACEHOLDER not in body
    manifest = _manifest_from(contents)
    assert manifest["redaction_applied"] is False
    assert manifest["redacted_fields"] == []


def test_include_state_and_secrets_compose(lynceus_layout, tmp_path):
    out = tmp_path / "both.tar.gz"
    rc = ec.main(
        [
            "--scope", "user",
            "--include-state",
            "--include-secrets",
            "--output", str(out),
        ]
    )
    assert rc == 0
    contents = _open_archive(out)
    [lynceus_arcname] = [n for n in contents if n.endswith("/config/lynceus.yaml")]
    assert "realsecrettoken12345" in contents[lynceus_arcname].decode("utf-8")
    assert any("/state/lynceus.db" in n for n in contents)


# --- dry-run ---------------------------------------------------------------


def test_dry_run_writes_nothing(lynceus_layout, tmp_path, capsys):
    out = tmp_path / "would_be.tar.gz"
    rc = ec.main(["--scope", "user", "--dry-run", "--output", str(out)])
    assert rc == 0
    assert not out.exists()
    captured = capsys.readouterr()
    assert "Would export to:" in captured.out
    assert "Scope: user" in captured.out
    # Inventory lists each config file we created (5).
    assert captured.out.count("lynceus.yaml") >= 1
    assert "Redaction: enabled" in captured.out
    # State omitted by default — message says so.
    assert "State files: not included" in captured.out


def test_dry_run_with_include_state_lists_db(lynceus_layout, tmp_path, capsys):
    out = tmp_path / "would_be.tar.gz"
    rc = ec.main(
        ["--scope", "user", "--dry-run", "--include-state", "--output", str(out)]
    )
    assert rc == 0
    captured = capsys.readouterr()
    assert "State files:" in captured.out
    assert "lynceus.db" in captured.out
    assert not out.exists()


# --- safety / output-path validation ---------------------------------------


def test_refuses_to_clobber_existing_without_force(lynceus_layout, tmp_path, capsys):
    out = tmp_path / "preexisting.tar.gz"
    out.write_bytes(b"prior contents")
    rc = ec.main(["--scope", "user", "--output", str(out)])
    assert rc == 1
    # Original bytes are untouched.
    assert out.read_bytes() == b"prior contents"
    captured = capsys.readouterr()
    assert "refusing to overwrite" in captured.err


def test_force_clobbers_existing(lynceus_layout, tmp_path):
    out = tmp_path / "preexisting.tar.gz"
    out.write_bytes(b"prior contents")
    rc = ec.main(["--scope", "user", "--force", "--output", str(out)])
    assert rc == 0
    # File was replaced — first two bytes of a gzip stream are 0x1F 0x8B.
    head = out.read_bytes()[:2]
    assert head == b"\x1f\x8b"


def test_refuses_directory_output(lynceus_layout, tmp_path, capsys):
    out = tmp_path / "is_a_dir"
    out.mkdir()
    rc = ec.main(["--scope", "user", "--output", str(out)])
    assert rc == 1
    captured = capsys.readouterr()
    assert "is a directory" in captured.err


def test_refuses_missing_parent(lynceus_layout, tmp_path, capsys):
    out = tmp_path / "no" / "such" / "dir" / "out.tar.gz"
    rc = ec.main(["--scope", "user", "--output", str(out)])
    assert rc == 1
    captured = capsys.readouterr()
    assert "parent directory does not exist" in captured.err


# --- scope handling --------------------------------------------------------


def test_scope_auto_resolves_to_user_when_user_path_exists(
    lynceus_layout, tmp_path, monkeypatch
):
    """``--scope auto`` should pick user when the user-scope config exists."""
    out = tmp_path / "auto.tar.gz"
    rc = ec.main(["--scope", "auto", "--output", str(out)])
    assert rc == 0
    manifest = _manifest_from(_open_archive(out))
    assert manifest["scope"] == "user"


def test_scope_auto_defaults_to_user_when_no_config_present(
    tmp_path, monkeypatch
):
    """No config at either scope → auto defaults to user (with all
    configs appearing as missing in the manifest)."""
    nonexistent = tmp_path / "nope"
    nonexistent.mkdir()
    from lynceus import paths as p

    def _missing_user(scope):
        return nonexistent / f"{scope}.yaml"  # never exists

    def _raise_system(scope):
        if scope == "system":
            raise NotImplementedError("system not supported on this fixture")
        return nonexistent / "user.yaml"

    monkeypatch.setattr(p, "default_config_dir", lambda s: nonexistent)
    monkeypatch.setattr(p, "default_data_dir", lambda s: nonexistent)
    monkeypatch.setattr(p, "default_overrides_path", lambda s: nonexistent / "ov.yaml")
    monkeypatch.setattr(p, "default_db_path", lambda s: nonexistent / "lynceus.db")
    monkeypatch.setattr(p, "default_config_path", _raise_system)

    out = tmp_path / "empty.tar.gz"
    rc = ec.main(["--scope", "auto", "--output", str(out)])
    assert rc == 0
    manifest = _manifest_from(_open_archive(out))
    assert manifest["scope"] == "user"
    # All five configs reported as missing — the export succeeds but is
    # essentially empty content-wise.
    assert len(manifest["missing"]) == 5


# --- round-trip ------------------------------------------------------------


def test_round_trip_extract_yields_consistent_files(lynceus_layout, tmp_path):
    """End-to-end: build an archive, untar to a fresh dir, confirm all
    expected pieces are present and that state files are byte-identical
    to the sources."""
    out = tmp_path / "round.tar.gz"
    rc = ec.main(
        ["--scope", "user", "--include-state", "--output", str(out)]
    )
    assert rc == 0
    extract_to = tmp_path / "extract"
    extract_to.mkdir()
    with tarfile.open(out, "r:gz") as tar:
        for m in tar.getmembers():
            tar.extract(m, extract_to)

    # The archive root directory is a single timestamped dir.
    [root_dir] = [p for p in extract_to.iterdir() if p.is_dir()]
    assert (root_dir / "README.txt").exists()
    assert (root_dir / "manifest.json").exists()
    assert (root_dir / "config" / "lynceus.yaml").exists()
    assert (root_dir / "config" / "rules.yaml").exists()
    assert (root_dir / "state" / "lynceus.db").exists()

    # State files are byte-identical.
    extracted_db = (root_dir / "state" / "lynceus.db").read_bytes()
    source_db = (lynceus_layout["data_dir"] / "lynceus.db").read_bytes()
    assert extracted_db == source_db

    # Redacted file has the placeholder, not the secret.
    redacted_yaml = (root_dir / "config" / "lynceus.yaml").read_text(encoding="utf-8")
    assert REDACTED_PLACEHOLDER in redacted_yaml
    assert "realsecrettoken12345" not in redacted_yaml

    # Manifest is parseable and refers to the same files.
    manifest = json.loads((root_dir / "manifest.json").read_text(encoding="utf-8"))
    files_paths = {e["path"] for e in manifest["files"]}
    assert "config/lynceus.yaml" in files_paths
    assert "state/lynceus.db" in files_paths


# --- archive shape ---------------------------------------------------------


def test_archive_inner_dir_name_matches_scope_and_timestamp(
    lynceus_layout, tmp_path
):
    """The archive's root directory follows ``lynceus-export-<scope>-
    <timestamp>`` regardless of the operator's --output filename."""
    out = tmp_path / "weirdname.tgz"
    rc = ec.main(["--scope", "user", "--output", str(out)])
    assert rc == 0
    with tarfile.open(out, "r:gz") as tar:
        names = [m.name for m in tar.getmembers()]
    [root] = sorted({n.split("/", 1)[0] for n in names})
    assert root.startswith("lynceus-export-user-")
    # Compact timestamp matches the YYYYMMDDTHHMMSSZ pattern by length.
    suffix = root[len("lynceus-export-user-"):]
    assert len(suffix) == len("20260517T143022Z")
    assert suffix.endswith("Z")


def test_default_output_path_uses_cwd_and_timestamp(lynceus_layout, tmp_path, monkeypatch):
    """When --output is omitted, the archive lands in CWD with a name
    matching the scope-and-timestamp template."""
    monkeypatch.chdir(tmp_path)
    rc = ec.main(["--scope", "user"])
    assert rc == 0
    produced = list(tmp_path.glob("lynceus-export-user-*.tar.gz"))
    assert len(produced) == 1


# --- redaction-only config files pass through clean ------------------------


def test_non_secret_configs_marked_unredacted_in_manifest(lynceus_layout, tmp_path):
    """rules.yaml / allowlist.yaml etc. are eligible for the redactor
    but contain no secrets — manifest must show them as ``redacted: false``,
    so the receiver can distinguish "ran through redactor, no secrets"
    from "skipped redaction entirely"."""
    out = tmp_path / "shape.tar.gz"
    rc = ec.main(["--scope", "user", "--output", str(out)])
    assert rc == 0
    manifest = _manifest_from(_open_archive(out))
    by_path = {e["path"]: e for e in manifest["files"]}
    assert by_path["config/lynceus.yaml"]["redacted"] is True
    for clean in (
        "config/rules.yaml",
        "config/severity_overrides.yaml",
        "config/allowlist.yaml",
        "config/allowlist_ui.yaml",
    ):
        assert by_path[clean]["redacted"] is False
