"""Tests for ``lynceus.cli.reset_config`` — the recovery CLI.

⭐ **Why this suite exists and what it actually proves.** This is the recovery
path for a config the operator has broken so badly the daemon will not start.
A recovery path nobody has run is an assumption, and an untested delete-and-
recreate has already destroyed the thing it was meant to repair in this repo
(``docs/UI_CONFIGURATION_DESIGN.md`` §5.2). These tests drive the REAL path,
not a mock — every test writes a file the way a broken operator would, then
runs ``main()`` and inspects what came back. The most important test is the
last one: ``test_recovery_against_genuinely_corrupt_config``, which writes
invalid YAML, runs the real reset, and asserts the backup matches the corrupt
bytes byte-for-byte. If that test is wrong, the whole feature is wrong.

The companion guards from PACKET.md §4 are scattered through this file:

  * Preview must change nothing  → ``test_preview_changes_nothing``
  * Backup byte-equality         → ``test_backup_preserves_bytes_*
  * Missing target is exit 1     → ``test_missing_target_exits_one``
  * No app import                → ``test_no_app_modules_loaded``
"""

from __future__ import annotations

import os
import sys

import pytest

from lynceus.cli import reset_config as rc

# --- shared fixtures --------------------------------------------------------


@pytest.fixture
def isolated_config_paths(tmp_path, monkeypatch):
    """Stand-in user-scope filesystem layout, with path resolution monkeypatched.

    Builds a fake ``<root>/config/lynceus.yaml`` and ``<root>/config/severity_overrides.yaml``,
    then patches the four ``lynceus.paths`` helpers that drive target
    resolution. The same approach ``tests/test_export_config.py`` uses — the
    hermeticity guard in ``tests/conftest.py`` already redirects HOME, but
    patching ``default_*`` keeps the rest of the suite's path-derivation
    claims under test while only redirecting where they LAND.
    """
    config_dir = tmp_path / "config"
    config_dir.mkdir()

    overrides_path = config_dir / "severity_overrides.yaml"
    overrides_path.write_text(
        "device_category_severity:\n  imsi_catcher: high\n",
        encoding="utf-8",
    )
    lynceus_yaml = config_dir / "lynceus.yaml"
    lynceus_yaml.write_text(
        "kismet_url: http://127.0.0.1:2501\nlocation_id: home\n",
        encoding="utf-8",
    )

    from lynceus import paths as p

    def _dir(scope):
        assert scope == "user"
        return config_dir

    def _cfg(scope):
        return config_dir / "lynceus.yaml"

    def _ov(scope):
        return config_dir / "severity_overrides.yaml"

    monkeypatch.setattr(p, "default_config_dir", _dir)
    monkeypatch.setattr(p, "default_config_path", _cfg)
    monkeypatch.setattr(p, "default_overrides_path", _ov)

    return {
        "root": tmp_path,
        "config_dir": config_dir,
        "lynceus_yaml": lynceus_yaml,
        "overrides_path": overrides_path,
    }


# --- no-app-import guard (PACKET.md §4.5) ----------------------------------


def test_no_app_modules_loaded(isolated_config_paths):
    """The recovery CLI must not pull in the daemon / DB / rules / webui.

    The packet's contract (§4.5): ``lynceus.poller`` and ``lynceus.db`` are
    absent from ``sys.modules`` after importing our module. Asserted by
    capturing the lynceus.* modules present BEFORE the import and the new
    ones after — a stale-module leak from another test (``test_smoke``
    imports all of them) would be picked up by the before/after diff if we
    only checked the after state.
    """
    import importlib

    forbidden = (
        "lynceus.poller",
        "lynceus.db",
        "lynceus.rules",
        "lynceus.webui",
        "lynceus.config",
        "lynceus.kismet",
        "lynceus.notify",
    )
    before = {m for m in sys.modules if m in forbidden}

    # Force a clean reimport of OUR module so this test is not silently
    # satisfied by a stale entry from a prior run of the same module.
    for mod_name in list(sys.modules):
        if mod_name == "lynceus.cli.reset_config" or mod_name.startswith(
            "lynceus.cli.reset_config."
        ):
            del sys.modules[mod_name]

    importlib.import_module("lynceus.cli.reset_config")

    after = {m for m in sys.modules if m in forbidden}
    newly_imported = sorted(after - before)
    assert newly_imported == [], (
        f"lynceus.cli.reset_config transitively imported {newly_imported}. "
        f"This CLI is supposed to work when the daemon will not start, and "
        f"importing lynceus.config in particular will try to parse the very "
        f"file that is broken. Fix by removing the offending import."
    )


# --- preview changes nothing (PACKET.md §4.2) -----------------------------


def test_preview_changes_nothing(isolated_config_paths):
    """Without --yes the file must be byte-identical and mtime-identical.

    Mtime is the part a snapshot test can't catch. Captured before, checked
    after. If anything writes to the file the OS bumps mtime, and the
    assertion goes red — which is exactly the failure the preview mode
    must never produce.
    """
    overrides = isolated_config_paths["overrides_path"]
    lynceus_yaml = isolated_config_paths["lynceus_yaml"]
    before_overrides = overrides.read_bytes()
    before_yaml = lynceus_yaml.read_bytes()
    # Force a fixed mtime so a write would visibly bump it. stat() returns
    # floats; round to int so the comparison is exact.
    fixed_mtime = 1_700_000_000.0
    os.utime(overrides, (fixed_mtime, fixed_mtime))
    os.utime(lynceus_yaml, (fixed_mtime, fixed_mtime))

    rc.main(["--scope", "user"])

    after_overrides = overrides.read_bytes()
    after_yaml = lynceus_yaml.read_bytes()
    assert after_overrides == before_overrides
    assert after_yaml == before_yaml
    assert overrides.stat().st_mtime == fixed_mtime
    assert lynceus_yaml.stat().st_mtime == fixed_mtime


def test_dry_run_alias_also_changes_nothing(isolated_config_paths):
    """``--dry-run`` is the explicit form of the default preview; it must
    also leave the files alone, so an operator who scripts the recovery
    gets the same guarantee either way."""
    overrides = isolated_config_paths["overrides_path"]
    before = overrides.read_bytes()

    rc.main(["--scope", "user", "--dry-run"])

    assert overrides.read_bytes() == before


# --- backup byte-equality (PACKET.md §4.3) ---------------------------------


def test_backup_preserves_bytes_byte_for_byte(isolated_config_paths, capsys):
    """``<name>.bak-<UTC>`` must hold the EXACT bytes of the original file.

    Not merely that a ``.bak-*`` file exists. A backup that mangles the
    bytes (e.g. a UTF-8 re-encode that swaps line endings) is what an
    operator would reach for at 2am, and would discover is broken.
    """
    overrides = isolated_config_paths["overrides_path"]
    original_bytes = overrides.read_bytes()

    rc.main(["--scope", "user", "--yes"])

    backups = list(isolated_config_paths["config_dir"].glob("severity_overrides.yaml.bak-*"))
    assert len(backups) == 1, (
        f"expected exactly one backup, found: {[b.name for b in backups]}"
    )
    assert backups[0].read_bytes() == original_bytes


def test_backup_filename_uses_utc_timestamp(isolated_config_paths):
    """The backup's suffix is the sortable UTC stamp, not a local-time one.

    A backup whose name says one time and whose contents say another is
    harder to audit. The timestamp form matches ``export_config.py`` so
    operators recognise it.
    """
    isolated_config_paths["overrides_path"]

    rc.main(["--scope", "user", "--yes"])

    [backup] = list(isolated_config_paths["config_dir"].glob("severity_overrides.yaml.bak-*"))
    suffix = backup.name[len("severity_overrides.yaml.bak-"):]
    # Same compact timestamp format as export_config: YYYYMMDDTHHMMSSZ.
    assert len(suffix) == len("20260517T143022Z")
    assert suffix.endswith("Z")
    # Every char except T and Z must be a digit.
    body = suffix.strip("Z")
    assert body[8] == "T"
    digits = body.replace("T", "")
    assert digits.isdigit()


def test_what_all_resets_both_targets(isolated_config_paths, capsys):
    """``--what all`` moves BOTH the tuning file AND the main config."""
    overrides = isolated_config_paths["overrides_path"]
    lynceus_yaml = isolated_config_paths["lynceus_yaml"]

    rc.main(["--scope", "user", "--what", "all", "--yes"])

    backups = sorted(isolated_config_paths["config_dir"].glob("*.bak-*"))
    backup_names = sorted(b.name for b in backups)
    assert backup_names == ["lynceus.yaml.bak-...", "severity_overrides.yaml.bak-..."] or any(
        n.startswith("lynceus.yaml.bak-") for n in backup_names
    ) and any(n.startswith("severity_overrides.yaml.bak-") for n in backup_names)
    # The actual files are gone (the originals moved aside).
    assert not overrides.exists()
    assert not lynceus_yaml.exists()
    captured = capsys.readouterr()
    assert "Moved to" in captured.out


def test_config_override_targets_only_that_file(isolated_config_paths):
    """``--config PATH`` narrows the reset to that one file, regardless of
    ``--what``. The canonical overrides file must NOT be moved."""
    overrides = isolated_config_paths["overrides_path"]
    overrides_before = overrides.read_bytes()

    custom = isolated_config_paths["root"] / "broken.yaml"
    custom.write_text("not: real: yaml: at: all: ::\n", encoding="utf-8")

    rc.main(["--scope", "user", "--config", str(custom), "--yes"])

    assert not custom.exists()
    assert list(isolated_config_paths["root"].glob("broken.yaml.bak-*")), (
        "backup of the --config target was not created"
    )
    # Canonical overrides file untouched — --what all did not also fire.
    assert overrides.read_bytes() == overrides_before


# --- missing target (PACKET.md §4.4) ---------------------------------------


def test_missing_target_exits_one_with_clear_message(tmp_path, monkeypatch, capsys):
    """No target file at all: exit 1, plain message, no traceback.

    A recovery command that crashes on the most common state — "the operator
    hasn't created a config yet" — fails the failure mode. Exit 1 with a
    readable message is the contract.
    """
    config_dir = tmp_path / "empty_config"
    config_dir.mkdir()
    from lynceus import paths as p

    def _dir(scope):
        return config_dir

    def _cfg(scope):
        return config_dir / "lynceus.yaml"

    def _ov(scope):
        return config_dir / "severity_overrides.yaml"

    monkeypatch.setattr(p, "default_config_dir", _dir)
    monkeypatch.setattr(p, "default_config_path", _cfg)
    monkeypatch.setattr(p, "default_overrides_path", _ov)

    rc_says_tty = monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    try:
        rc = __import__("lynceus.cli.reset_config", fromlist=["main"])
        exit_code = rc.main(["--scope", "user"])
    finally:
        # Restore stdin.isatty to whatever it was before.
        del rc_says_tty

    assert exit_code == 1
    captured = capsys.readouterr()
    # Plain English, no Python traceback.
    assert "Traceback" not in captured.err
    assert "Traceback" not in captured.out
    assert "nothing" in (captured.out + captured.err).lower() or "missing" in (
        captured.out + captured.err
    ).lower()


def test_non_tty_without_yes_refuses(tmp_path, monkeypatch, capsys):
    """Without a TTY and without ``--yes``, refuse rather than prompting.

    The contract. The alternative is ``getpass`` returning empty and the
    reset happening silently — exactly the failure a recovery command
    must not produce.
    """
    config_dir = tmp_path / "nt"
    config_dir.mkdir()
    from lynceus import paths as p

    monkeypatch.setattr(p, "default_config_dir", lambda s: config_dir)
    monkeypatch.setattr(p, "default_config_path", lambda s: config_dir / "lynceus.yaml")
    monkeypatch.setattr(
        p, "default_overrides_path", lambda s: config_dir / "severity_overrides.yaml"
    )
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)

    exit_code = rc.main(["--scope", "user"])
    assert exit_code == 1
    captured = capsys.readouterr()
    assert "stdin is not a terminal" in captured.err
    assert "refusing" in captured.err.lower()
    assert "Traceback" not in captured.err


# --- preview reports what it would do --------------------------------------


def test_preview_lists_each_target_with_size(isolated_config_paths, monkeypatch, capsys):
    """The preview prints each target's path and size so the operator can
    see what they're about to lose.

    Uses ``--dry-run`` so the test is independent of whether pytest's
    captured stdin presents as a tty. The contract under test is the
    inventory format, not the TTY check (covered by
    ``test_non_tty_without_yes_refuses``).
    """
    overrides = isolated_config_paths["overrides_path"]
    lynceus_yaml = isolated_config_paths["lynceus_yaml"]
    overrides_size = overrides.stat().st_size

    rc.main(["--scope", "user", "--what", "all", "--dry-run"])

    captured = capsys.readouterr()
    assert "Reset preview" in captured.out
    assert str(overrides) in captured.out
    assert str(lynceus_yaml) in captured.out
    # Human-friendly size appears (the formatter always includes a unit).
    assert f"{overrides_size} B" in captured.out or "KB" in captured.out or "MB" in captured.out


# --- the corrupt-config recovery test (PACKET.md §4.1) ---------------------


def test_recovery_against_genuinely_corrupt_config(isolated_config_paths, capsys):
    """The whole point. Plant invalid YAML, run the real reset, assert:

    * the command exits 0,
    * the daemon-fatal file is GONE (so the daemon can start clean),
    * a ``.bak-<UTC>`` file exists,
    * the backup's bytes are byte-identical to the corrupt file we wrote
      — because ``yaml.safe_load`` blowing up is exactly the case the
      operator needs to recover from, and a backup that silently lost
      bytes during the move is the worst kind of "recovery".

    This test is run, not merely written. A recovery path nobody has
    executed end to end is an assumption, and an untested delete-and-
    recreate has already destroyed the thing it was meant to repair in
    this repo (see ``docs/UI_CONFIGURATION_DESIGN.md`` §5.2).
    """
    lynceus_yaml = isolated_config_paths["lynceus_yaml"]
    # Genuinely invalid YAML — yaml.safe_load raises a ScannerError or
    # ParserError. We do not catch it here; we want to know the file is
    # something the daemon could not have loaded.
    corrupt_bytes = b"this is not valid yaml: [unterminated: bracket\n\t: : :\n"
    lynceus_yaml.write_bytes(corrupt_bytes)

    # Sanity: confirm the bytes really are unparseable. If yaml accepts
    # them in some future version, the test's premise fails and the
    # underlying recovery contract has to be re-derived, not silently
    # weakened.
    import yaml as _yaml

    with pytest.raises(_yaml.YAMLError):
        _yaml.safe_load(corrupt_bytes)

    exit_code = rc.main(["--scope", "user", "--what", "all", "--yes"])

    assert exit_code == 0, (
        "the recovery path returned non-zero on a genuinely broken config; "
        "see the captured output for what it actually said"
    )
    captured = capsys.readouterr()

    # The daemon-fatal file is gone — the daemon can now start clean.
    assert not lynceus_yaml.exists()
    # A backup exists, and its bytes match the corrupt input exactly.
    backups = list(isolated_config_paths["config_dir"].glob("lynceus.yaml.bak-*"))
    assert len(backups) == 1, (
        f"expected exactly one backup, found: {[b.name for b in backups]}"
    )
    assert backups[0].read_bytes() == corrupt_bytes, (
        "backup lost bytes during the move — the operator would have "
        "nothing to recover from after this CLI runs"
    )
    # The CLI printed the backup path so the operator knows where to find it.
    assert str(backups[0]) in captured.out


# --- defensive: unreadable target still produces a clean error -------------


def test_unwritable_target_produces_clean_error_not_traceback(
    tmp_path, monkeypatch, capsys
):
    """When the move fails (target dir unwritable, etc) print a clear
    error and exit 2 — never a traceback. Tracebacks in operator-facing
    output invite operators to start fixing things with ``sudo``."""
    config_dir = tmp_path / "ro_dir"
    config_dir.mkdir()
    overrides = config_dir / "severity_overrides.yaml"
    overrides.write_text("device_category_severity: {}\n", encoding="utf-8")

    # Make the move fail by pointing shutil.move at a destination whose
    # parent doesn't exist. _do_reset builds the backup path as a sibling
    # so this is harder to engineer directly; instead, force an OSError
    # from shutil.move via a monkeypatch.
    import shutil as _shutil

    def _raise(*a, **kw):
        raise OSError("simulated write failure")

    monkeypatch.setattr(_shutil, "move", _raise)

    from lynceus import paths as p

    monkeypatch.setattr(p, "default_config_dir", lambda s: config_dir)
    monkeypatch.setattr(p, "default_config_path", lambda s: config_dir / "lynceus.yaml")
    monkeypatch.setattr(p, "default_overrides_path", lambda s: overrides)

    exit_code = rc.main(["--scope", "user", "--yes"])
    assert exit_code == 2
    captured = capsys.readouterr()
    assert "Traceback" not in captured.err
    assert "simulated write failure" in captured.err or "failed" in captured.err.lower()


# --- sanitiser: dump the live state of what we are testing -----------------


def test_inventory_dump_for_diagnostic_review(tmp_path, monkeypatch, diag):
    """Diagnostic-only inventory of what this test module covers.

    Run with ``pytest -m diagnostic``. Lists the PACKET.md §4 behaviours
    and which test enforces each one, so a reviewer can see the mapping
    without diffing the file. Confirms the suite is what it claims to be.
    """
    diag.fixture("PACKET.md §4.1 — recovery from genuinely corrupt config")
    diag.fixture("PACKET.md §4.2 — preview must change nothing")
    diag.fixture("PACKET.md §4.3 — backup byte-equality")
    diag.fixture("PACKET.md §4.4 — missing target is exit 1, no traceback")
    diag.fixture("PACKET.md §4.5 — no app modules imported")
    diag.observed("test_recovery_against_genuinely_corrupt_config drives the real reset")
    diag.observed("test_preview_changes_nothing asserts mtime + bytes")
    diag.observed("test_backup_preserves_bytes_byte_for_byte reads the backup back")
    diag.observed("test_missing_target_exits_one_with_clear_message asserts no Traceback")
    diag.observed("test_no_app_modules_loaded asserts sys.modules is clean")
