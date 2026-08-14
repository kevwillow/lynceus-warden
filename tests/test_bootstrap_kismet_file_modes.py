"""File modes written by the Kismet bootstrapper.

⭐ Why this file exists. `cli/bootstrap_kismet.py` is 1,589 lines with no
behavioural test of any kind — `patch_kismet_site_conf`, `_atomic_write_bytes`
and `_atomic_write_text` had zero references anywhere under `tests/`. CodeQL's
`py/overly-permissive-file` pointed at the `chmod` inside `_atomic_write_bytes`
and the lead turned out to be real, though not for the reason the rule gives.

The mechanism: `_atomic_write_bytes` writes a tmpfile and `os.replace`s it over
the target, so the surviving inode is a NEW file carrying the *requested* mode,
not the target's. Every re-run therefore reset the file to the `0o644` default.
`patch_kismet_site_conf` promises in its own docstring that operator
customisations are "preserved verbatim" — it preserved the content and dropped
the permissions. Kismet honours `httpd_password=` in `kismet_site.conf`, so an
operator who correctly hardened that file to `0o600` had it silently widened to
world-readable, with the password still inside, by an unrelated `--add-source`
run. Measured before the fix: `0o600 -> 0o644`, secret intact.

⚠️ Both directions are pinned below on purpose. A "fix" that simply hardcoded
`0o600` would satisfy the preservation test while breaking the two callers that
legitimately need world-readable output — the apt keyring and `sources.list`,
which every apt invocation must read. Testing only the shape that bit us would
bless the opposite defect, which is the trap `test_observation_loss.py` records
for the watermark.

The invariant itself is not new to this repo: `tests/test_db.py` already pins
"an operator's chmod must survive a daemon restart" for the database file.
This is the same rule applied to the file that can hold a password.
"""

from __future__ import annotations

import os
import stat

import pytest

from lynceus.cli.bootstrap_kismet import (
    _atomic_write_bytes,
    _atomic_write_text,
    patch_kismet_site_conf,
)

SECRET_LINE = "httpd_password=hunter2-operator-secret"


def _mode(path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


# --- Creation: the requested mode still applies ----------------------------


@pytest.mark.parametrize("requested", [0o644, 0o600, 0o640])
def test_atomic_write_bytes_applies_requested_mode_when_creating(tmp_path, requested):
    """A file that does not exist yet gets exactly the mode asked for.

    This is the arm that keeps the apt keyring and sources.list readable:
    `_atomic_write_bytes(KISMET_KEYRING_PATH, ..., mode=0o644)` must still
    produce 0o644, or apt cannot read the key it was given.
    """
    target = tmp_path / "created.conf"
    assert not target.exists()

    _atomic_write_bytes(target, b"payload\n", mode=requested)

    assert _mode(target) == requested, (
        f"creation must honour the requested mode, got {oct(_mode(target))}"
    )
    # Presence assertion beside the mode assertion: prove it actually wrote.
    assert target.read_bytes() == b"payload\n"


def test_atomic_write_text_creation_mode_matches_bytes_helper(tmp_path):
    target = tmp_path / "created.txt"
    _atomic_write_text(target, "hello\n", mode=0o600)
    assert _mode(target) == 0o600
    assert target.read_text(encoding="utf-8") == "hello\n"


# --- Rewrite: the operator's mode survives ---------------------------------


@pytest.mark.parametrize("hardened", [0o600, 0o640, 0o400])
def test_atomic_write_bytes_preserves_existing_mode(tmp_path, hardened):
    """An existing file keeps its own mode, whatever the caller requests.

    `mode=` is a creation default, not an instruction to re-apply on every
    write. The default is the world-readable 0o644, so without this the
    caller silently widens anything it touches.
    """
    target = tmp_path / "existing.conf"
    target.write_text("original\n", encoding="utf-8")
    os.chmod(target, hardened)

    _atomic_write_bytes(target, b"rewritten\n", mode=0o644)

    assert _mode(target) == hardened, (
        f"operator mode {oct(hardened)} must survive a rewrite, "
        f"got {oct(_mode(target))}"
    )
    # Presence assertion: the rewrite has to have actually happened, or a
    # no-op implementation would satisfy the mode check perfectly.
    assert target.read_bytes() == b"rewritten\n"


def test_patch_kismet_site_conf_does_not_widen_a_secret_bearing_conf(tmp_path):
    """The end-to-end shape that was measured broken.

    Operator hardens a kismet_site.conf containing httpd_password to 0o600,
    then runs the bootstrapper to add a capture source. The password must not
    become world-readable as a side effect of adding an unrelated line.
    """
    conf = tmp_path / "kismet_site.conf"
    conf.write_text(
        f"# operator overrides\n{SECRET_LINE}\nsource=wlan9\n", encoding="utf-8"
    )
    os.chmod(conf, 0o600)

    added = patch_kismet_site_conf(conf, ["wlan1"], [], dry_run=False)

    body = conf.read_text(encoding="utf-8")
    # Presence: the patcher did the job it was called for...
    assert added, "expected the new interface to be added"
    assert any("wlan1" in line for line in added)
    assert "wlan1" in body
    # ...and preserved the operator's content verbatim, as it promises...
    assert SECRET_LINE in body
    assert "source=wlan9" in body
    # ...without widening the file that holds the password.
    assert _mode(conf) == 0o600, f"expected 0o600 preserved, got {oct(_mode(conf))}"
    assert not _mode(conf) & stat.S_IROTH, "secret-bearing conf became world-readable"


def test_patch_kismet_site_conf_creates_with_default_mode(tmp_path):
    """A conf the operator never created has no mode to preserve.

    Kismet must be able to read its own site conf, so a freshly laid-down
    file keeps the 0o644 default rather than inheriting anything.
    """
    conf = tmp_path / "fresh_site.conf"
    assert not conf.exists()

    added = patch_kismet_site_conf(conf, ["wlan1"], [], dry_run=False)

    assert added
    assert conf.exists()
    assert _mode(conf) == 0o644, f"expected 0o644 on creation, got {oct(_mode(conf))}"


def test_dry_run_writes_nothing_and_leaves_mode_untouched(tmp_path):
    conf = tmp_path / "kismet_site.conf"
    conf.write_text(f"{SECRET_LINE}\n", encoding="utf-8")
    os.chmod(conf, 0o600)

    added = patch_kismet_site_conf(conf, ["wlan1"], [], dry_run=True)

    assert added, "dry-run still reports what it would add"
    assert conf.read_text(encoding="utf-8") == f"{SECRET_LINE}\n"
    assert _mode(conf) == 0o600
