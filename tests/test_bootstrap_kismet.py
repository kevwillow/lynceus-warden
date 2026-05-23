"""Tests for lynceus.cli.bootstrap_kismet -- the Kismet apt installer.

Integration testing (actual apt + Kismet install) requires a fresh
Debian/Ubuntu/Kali VM; that's manual-smoke territory and lives in the
CHANGELOG / verify section. These tests cover the pieces we CAN
exercise without root or apt: pure parsers (os-release, iw dev, iw
phy info), filesystem-level state probes, idempotent file patching,
the unsupported-distro and non-root exit paths, and the --dry-run
contract that nothing mutates outside the args.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from lynceus.cli import bootstrap_kismet as bk


# ---------------------------------------------------------------------------
# parse_os_release
# ---------------------------------------------------------------------------


def test_parse_os_release_strips_quotes_and_comments():
    content = (
        '# comment line\n'
        'NAME="Kali GNU/Linux"\n'
        "ID=kali\n"
        "VERSION_CODENAME=kali-rolling\n"
        "\n"
        "PRETTY_NAME='Kali GNU/Linux Rolling'\n"
    )
    out = bk.parse_os_release(content)
    assert out["NAME"] == "Kali GNU/Linux"
    assert out["ID"] == "kali"
    assert out["VERSION_CODENAME"] == "kali-rolling"
    assert out["PRETTY_NAME"] == "Kali GNU/Linux Rolling"


def test_parse_os_release_ignores_malformed_lines():
    content = "ID=debian\nbroken-line-no-equals\nVERSION_CODENAME=trixie\n"
    out = bk.parse_os_release(content)
    assert out == {"ID": "debian", "VERSION_CODENAME": "trixie"}


# ---------------------------------------------------------------------------
# detect_distro
# ---------------------------------------------------------------------------


def _write_os_release(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "os-release"
    p.write_text(body, encoding="utf-8")
    return p


def test_detect_distro_kali_uses_literal_kali_codename(tmp_path):
    # Kali reports VERSION_CODENAME=kali-rolling, but the Kismet repo
    # path uses just `kali`.
    p = _write_os_release(tmp_path, "ID=kali\nVERSION_CODENAME=kali-rolling\n")
    assert bk.detect_distro(p) == ("kali", "kali")


def test_detect_distro_debian_bookworm(tmp_path):
    p = _write_os_release(tmp_path, "ID=debian\nVERSION_CODENAME=bookworm\n")
    assert bk.detect_distro(p) == ("debian", "bookworm")


def test_detect_distro_debian_trixie(tmp_path):
    p = _write_os_release(tmp_path, "ID=debian\nVERSION_CODENAME=trixie\n")
    assert bk.detect_distro(p) == ("debian", "trixie")


def test_detect_distro_ubuntu_noble(tmp_path):
    p = _write_os_release(tmp_path, "ID=ubuntu\nVERSION_CODENAME=noble\n")
    assert bk.detect_distro(p) == ("ubuntu", "noble")


def test_detect_distro_unsupported_distro_id(tmp_path):
    p = _write_os_release(tmp_path, "ID=fedora\nVERSION_CODENAME=anything\n")
    assert bk.detect_distro(p) == (None, None)


def test_detect_distro_unsupported_ubuntu_version(tmp_path):
    # Ubuntu Bionic 18.04 is listed in the Kismet repo but i386-only;
    # we treat it as unsupported in v1.
    p = _write_os_release(tmp_path, "ID=ubuntu\nVERSION_CODENAME=bionic\n")
    assert bk.detect_distro(p) == (None, None)


def test_detect_distro_missing_file(tmp_path):
    assert bk.detect_distro(tmp_path / "does-not-exist") == (None, None)


# ---------------------------------------------------------------------------
# iw dev parser
# ---------------------------------------------------------------------------


IW_DEV_FIXTURE = """\
phy#1
\tInterface wlan1
\t\tifindex 5
\t\twdev 0x100000001
\t\taddr aa:bb:cc:dd:ee:01
\t\ttype managed
\t\ttxpower 20.00 dBm
phy#0
\tInterface wlan0
\t\tifindex 3
\t\twdev 0x1
\t\taddr aa:bb:cc:dd:ee:00
\t\ttype managed
"""


def test_parse_iw_dev_extracts_phy_iface_pairs():
    pairs = bk.parse_iw_dev(IW_DEV_FIXTURE)
    assert pairs == [("phy1", "wlan1"), ("phy0", "wlan0")]


def test_parse_iw_dev_empty():
    assert bk.parse_iw_dev("") == []


def test_parse_iw_dev_phy_with_no_interface():
    # Sometimes a phy is registered but has no Interface yet.
    out = bk.parse_iw_dev("phy#2\n")
    assert out == []


# ---------------------------------------------------------------------------
# iw phy info monitor-mode detection
# ---------------------------------------------------------------------------


IW_PHY_INFO_MONITOR_OK = """\
Wiphy phy0
\tmax # scan SSIDs: 4
\tSupported interface modes:
\t\t * IBSS
\t\t * managed
\t\t * AP
\t\t * AP/VLAN
\t\t * monitor
\t\t * mesh point
\tBand 1:
\t\tCapabilities: ...
"""


IW_PHY_INFO_NO_MONITOR = """\
Wiphy phy1
\tSupported interface modes:
\t\t * managed
\t\t * P2P-client
\tBand 1:
\t\tCapabilities: ...
"""


def test_parse_iw_phy_info_detects_monitor():
    assert bk.parse_iw_phy_info_supports_monitor(IW_PHY_INFO_MONITOR_OK) is True


def test_parse_iw_phy_info_no_monitor():
    assert bk.parse_iw_phy_info_supports_monitor(IW_PHY_INFO_NO_MONITOR) is False


def test_parse_iw_phy_info_empty():
    assert bk.parse_iw_phy_info_supports_monitor("") is False


# ---------------------------------------------------------------------------
# Bluetooth detection (sysfs-based)
# ---------------------------------------------------------------------------


def test_detect_bluetooth_interfaces_picks_hci_dirs(tmp_path):
    (tmp_path / "hci0").mkdir()
    (tmp_path / "hci1").mkdir()
    (tmp_path / "input0").mkdir()  # irrelevant
    (tmp_path / "hci-not-numeric").mkdir()  # ignored
    out = bk.detect_bluetooth_interfaces(tmp_path)
    assert out == ["hci0", "hci1"]


def test_detect_bluetooth_interfaces_missing_sysfs(tmp_path):
    assert bk.detect_bluetooth_interfaces(tmp_path / "does-not-exist") == []


# ---------------------------------------------------------------------------
# kismet_site.conf patcher
# ---------------------------------------------------------------------------


def test_existing_source_interfaces_parses_basic_lines():
    body = (
        "# comment\n"
        "server_name=Foo\n"
        "source=wlan0:type=linuxwifi\n"
        "source=wlan1:name=external\n"
        "  source=wlan2  \n"
        "#source=wlan3:type=linuxwifi\n"  # commented out, should not count
    )
    out = bk.existing_source_interfaces(body)
    assert out == {"wlan0", "wlan1", "wlan2"}


def test_kismet_site_conf_additions_only_adds_missing():
    existing = "source=wlan0:type=linuxwifi,name=foo\n"
    add = bk.kismet_site_conf_additions(existing, ["wlan0", "wlan1"], ["hci0"])
    assert add == [
        "source=wlan1:type=linuxwifi",
        "source=hci0:type=linuxbluetooth",
    ]


def test_patch_kismet_site_conf_creates_file_when_absent(tmp_path):
    target = tmp_path / "kismet_site.conf"
    added = bk.patch_kismet_site_conf(
        target, ["wlan0"], ["hci0"], dry_run=False
    )
    assert added == [
        "source=wlan0:type=linuxwifi",
        "source=hci0:type=linuxbluetooth",
    ]
    body = target.read_text(encoding="utf-8")
    assert "source=wlan0:type=linuxwifi" in body
    assert "source=hci0:type=linuxbluetooth" in body
    assert "lynceus-bootstrap-kismet" in body  # header comment


def test_patch_kismet_site_conf_idempotent(tmp_path):
    target = tmp_path / "kismet_site.conf"
    bk.patch_kismet_site_conf(target, ["wlan0"], [], dry_run=False)
    first_body = target.read_text(encoding="utf-8")

    # Second run should add nothing -- the source line already exists.
    added = bk.patch_kismet_site_conf(target, ["wlan0"], [], dry_run=False)
    assert added == []
    assert target.read_text(encoding="utf-8") == first_body


def test_patch_kismet_site_conf_preserves_operator_customisation(tmp_path):
    target = tmp_path / "kismet_site.conf"
    pre = (
        "# operator wrote this\n"
        "server_name=Custom\n"
        "source=wlan0:type=linuxwifi,name=external,channel_list=1,6,11\n"
    )
    target.write_text(pre, encoding="utf-8")
    bk.patch_kismet_site_conf(target, ["wlan0", "wlan1"], ["hci0"], dry_run=False)
    after = target.read_text(encoding="utf-8")

    # Operator content survives verbatim.
    assert "server_name=Custom" in after
    assert "channel_list=1,6,11" in after
    # wlan0 was already present -- not duplicated.
    assert after.count("source=wlan0") == 1
    # wlan1 and hci0 appended.
    assert "source=wlan1:type=linuxwifi" in after
    assert "source=hci0:type=linuxbluetooth" in after


def test_patch_kismet_site_conf_no_changes_when_all_present(tmp_path, capsys):
    target = tmp_path / "kismet_site.conf"
    target.write_text(
        "source=wlan0:type=linuxwifi\nsource=hci0:type=linuxbluetooth\n",
        encoding="utf-8",
    )
    out = bk.patch_kismet_site_conf(target, ["wlan0"], ["hci0"], dry_run=False)
    assert out == []
    captured = capsys.readouterr()
    assert "no changes needed" in captured.out


def test_patch_kismet_site_conf_dry_run_does_not_write(tmp_path):
    target = tmp_path / "kismet_site.conf"
    added = bk.patch_kismet_site_conf(target, ["wlan0"], [], dry_run=True)
    assert added == ["source=wlan0:type=linuxwifi"]
    assert not target.exists()


# ---------------------------------------------------------------------------
# backup_kismet_site_conf + --reset-config flag
# ---------------------------------------------------------------------------
#
# --reset-config covers the "I removed an adapter and re-ran bootstrap but
# the stale source= line is still in kismet_site.conf" operator complaint.
# Default behaviour stays append-only (regression-pinned below); the flag
# opts in to a backup-then-fresh rewrite.


def test_backup_kismet_site_conf_returns_none_when_absent(tmp_path):
    target = tmp_path / "kismet_site.conf"
    assert bk.backup_kismet_site_conf(target, dry_run=False) is None


def test_backup_kismet_site_conf_renames_to_bak_with_unix_ts(tmp_path):
    target = tmp_path / "kismet_site.conf"
    target.write_text("source=wlan_old:type=linuxwifi\n", encoding="utf-8")
    backup = bk.backup_kismet_site_conf(target, dry_run=False)
    assert backup is not None
    assert backup.name.startswith("kismet_site.conf.bak-")
    # ts suffix is digits only — lets the operator sort by timestamp and
    # repeated --reset-config runs won't collide on second-resolution.
    suffix = backup.name.removeprefix("kismet_site.conf.bak-")
    assert suffix.isdigit()
    # Original moved, backup carries the content.
    assert not target.exists()
    assert backup.read_text(encoding="utf-8") == "source=wlan_old:type=linuxwifi\n"


def test_backup_kismet_site_conf_dry_run_returns_path_without_renaming(tmp_path):
    target = tmp_path / "kismet_site.conf"
    target.write_text("source=wlan_old:type=linuxwifi\n", encoding="utf-8")
    backup = bk.backup_kismet_site_conf(target, dry_run=True)
    assert backup is not None
    assert backup.name.startswith("kismet_site.conf.bak-")
    # File is untouched in dry-run; the returned path is a preview.
    assert target.exists()
    assert not backup.exists()


def _setup_run_env(monkeypatch, conf_dir: Path) -> None:
    """Wire bk.run into a tmp_path conf dir, mocked away from the real host."""
    monkeypatch.setattr(bk, "_is_root", lambda: True)
    monkeypatch.setattr("sys.platform", "linux")
    monkeypatch.setattr(bk, "detect_distro", lambda *a, **kw: ("kali", "kali"))
    monkeypatch.setattr(bk, "_kismet_installed", lambda: True)
    monkeypatch.setattr(bk, "_apt_source_configured", lambda: True)
    monkeypatch.setattr(bk, "detect_wifi_monitor_capable", lambda: [])
    monkeypatch.setattr(bk, "detect_bluetooth_interfaces", lambda *a, **kw: [])
    monkeypatch.setattr(bk, "KISMET_SITE_CONF_DIRS", (conf_dir,))
    # Group / usermod path: pretend we're a non-root operator already
    # in the kismet group so the orchestrator doesn't try to usermod.
    monkeypatch.setattr(bk, "_real_operator_user", lambda: "kev")
    monkeypatch.setattr(bk, "_group_exists", lambda group: True)
    monkeypatch.setattr(bk, "_user_in_group", lambda user, group: True)


def test_run_without_reset_config_preserves_stale_source_line(monkeypatch, tmp_path):
    """Default behaviour regression guard: without --reset-config, a stale
    source= line from a prior run stays in kismet_site.conf. The operator
    must opt in to the rewrite — flipping the default would surprise every
    operator who carried hand-edits across re-runs."""
    conf_dir = tmp_path / "kismet"
    conf_dir.mkdir()
    target = conf_dir / "kismet_site.conf"
    target.write_text(
        "# operator hand-edit\nsource=wlan_old:type=linuxwifi\n",
        encoding="utf-8",
    )
    _setup_run_env(monkeypatch, conf_dir)
    # Re-run with only wlan0 selected — wlan_old should still be present.
    rc = bk.run(_args(interface=["wlan0"], interface_type="wifi"))
    assert rc == 0
    body = target.read_text(encoding="utf-8")
    assert "source=wlan_old" in body
    assert "source=wlan0:type=linuxwifi" in body
    # No backup file was created on the default path.
    assert not any(p.name.startswith("kismet_site.conf.bak-") for p in conf_dir.iterdir())


def test_run_with_reset_config_drops_stale_source_line(monkeypatch, tmp_path, capsys):
    """The flag's contract: a source= line for an interface no longer
    selected disappears from the resulting kismet_site.conf, the previous
    file lands as a .bak-<ts> sibling, and the closing hint surfaces the
    backup path so operators know where to recover from."""
    conf_dir = tmp_path / "kismet"
    conf_dir.mkdir()
    target = conf_dir / "kismet_site.conf"
    target.write_text(
        "# operator hand-edit\n"
        "server_name=Custom\n"
        "source=wlan_old:type=linuxwifi\n",
        encoding="utf-8",
    )
    _setup_run_env(monkeypatch, conf_dir)
    rc = bk.run(_args(interface=["wlan0"], interface_type="wifi", reset_config=True))
    assert rc == 0
    body = target.read_text(encoding="utf-8")
    # Stale line is gone, fresh line present.
    assert "source=wlan_old" not in body
    assert "source=wlan0:type=linuxwifi" in body
    # Backup file exists with the operator's prior content intact.
    backups = sorted(p for p in conf_dir.iterdir() if p.name.startswith("kismet_site.conf.bak-"))
    assert len(backups) == 1
    backup_body = backups[0].read_text(encoding="utf-8")
    assert "server_name=Custom" in backup_body
    assert "source=wlan_old" in backup_body
    # Closing hint mentions the backup path so the operator can recover.
    captured = capsys.readouterr()
    assert "--reset-config" in captured.out
    assert backups[0].name in captured.out


def test_main_help_advertises_reset_config(capsys):
    """argparse --help should surface the flag so operators see it without
    reading the source."""
    with pytest.raises(SystemExit):
        bk.main(["--help"])
    out = capsys.readouterr().out
    assert "--reset-config" in out


def test_closing_pointer_advertises_reset_config_on_normal_run(capsys):
    """Discoverability: a normal bootstrap run (no --reset-config) shows
    a one-line tip pointing operators at the flag for future re-runs
    after adapter removal. Without this, --reset-config is only
    discoverable via --help or the changelog — meaning operators who
    physically remove an adapter and re-run keep accumulating stale
    source= lines without ever learning the cleanup exists."""
    bk.print_closing_pointer(
        operator="kev",
        skip_install=False,
        distro_supported=True,
        kismet_on_path=True,
        site_conf_path=Path("/etc/kismet/kismet_site.conf"),
        site_conf_skipped=False,
        backup_path=None,  # the normal-run case
    )
    out = capsys.readouterr().out
    assert "--reset-config" in out
    assert "removed an adapter" in out


def test_closing_pointer_omits_reset_config_tip_when_just_used(capsys):
    """The operator who just used --reset-config does NOT need to be told
    the flag exists — surfacing the tip in that case would be noise
    layered on top of the existing 'previous kismet_site.conf was
    backed up to ...' note. Pinning the suppression keeps the closing
    block focused on what's still actionable."""
    bk.print_closing_pointer(
        operator="kev",
        skip_install=False,
        distro_supported=True,
        kismet_on_path=True,
        site_conf_path=Path("/etc/kismet/kismet_site.conf"),
        site_conf_skipped=False,
        backup_path=Path("/etc/kismet/kismet_site.conf.bak-1234567890"),
    )
    out = capsys.readouterr().out
    # Backup note still appears (Touch 1's existing behavior).
    assert "backed up" in out
    # ...but the discoverability tip does not — operator already knows.
    assert "removed an adapter" not in out


# ---------------------------------------------------------------------------
# main() exit paths -- non-root, unsupported distro
# ---------------------------------------------------------------------------


def _args(**overrides):
    base = dict(
        skip_install=False,
        interface=[],
        interface_type="wifi",
        no_network=False,
        dry_run=False,
        yes=True,  # default tests off-interactive
        reset_config=False,
    )
    base.update(overrides)
    return argparse.Namespace(**base)


def test_main_refuses_non_root(monkeypatch, capsys):
    monkeypatch.setattr(bk, "_is_root", lambda: False)
    code = bk.run(_args())
    assert code == 2
    captured = capsys.readouterr()
    assert "must run as root" in captured.err


def test_main_unsupported_distro_exits_zero(monkeypatch, capsys, tmp_path):
    """Default-path behaviour preserved: unsupported distro WITHOUT
    --skip-install gets the manual-install pointer + exit 0.

    Contract clarification (Touch A): the distro gate now guards ONLY
    the apt-install path. With --skip-install the apt matrix doesn't
    apply and the flow continues -- see
    test_main_unsupported_distro_with_skip_install_proceeds for that
    branch.
    """
    monkeypatch.setattr(bk, "_is_root", lambda: True)
    monkeypatch.setattr("sys.platform", "linux")
    # Don't accidentally touch the real host's OS at all.
    monkeypatch.setattr(bk, "detect_distro", lambda *a, **kw: (None, None))
    code = bk.run(_args())
    assert code == 0
    captured = capsys.readouterr()
    assert "not in the Kismet-apt matrix" in captured.out
    assert "kismetwireless.net/packages" in captured.out


def test_main_dry_run_does_not_invoke_apt(monkeypatch, tmp_path, capsys):
    """End-to-end-ish dry-run: every mutating side-effect skipped."""
    monkeypatch.setattr(bk, "_is_root", lambda: True)
    monkeypatch.setattr("sys.platform", "linux")
    monkeypatch.setattr(bk, "detect_distro", lambda *a, **kw: ("kali", "kali"))
    monkeypatch.setattr(bk, "_kismet_installed", lambda: False)
    monkeypatch.setattr(bk, "_apt_source_configured", lambda: False)
    monkeypatch.setattr(bk, "detect_wifi_monitor_capable", lambda: ["wlan0"])
    monkeypatch.setattr(bk, "detect_bluetooth_interfaces", lambda *a, **kw: ["hci0"])
    monkeypatch.setattr(bk, "_real_operator_user", lambda: "alice")
    monkeypatch.setattr(bk, "_group_exists", lambda g: True)
    monkeypatch.setattr(bk, "_user_in_group", lambda u, g: False)

    # Redirect the site-conf candidate set into tmp so resolve picks
    # up a writable directory instead of trying /etc/kismet (denied
    # anyway). Touch A replaced the single KISMET_SITE_CONF_PATH
    # constant with a candidate-tuple KISMET_SITE_CONF_DIRS to support
    # both apt and from-source layouts.
    kismet_dir = tmp_path / "kismet"
    kismet_dir.mkdir()
    monkeypatch.setattr(bk, "KISMET_SITE_CONF_DIRS", (kismet_dir,))

    # No subprocess should actually run on the dry-run path: assert by
    # monkeypatching subprocess.run to a sentinel that raises if called.
    sentinel_called = []
    real_run = bk.subprocess.run

    def _raise_if_called(*args, **kwargs):
        sentinel_called.append(args)
        raise AssertionError(
            f"subprocess.run called in dry-run: {args!r}"
        )

    monkeypatch.setattr(bk.subprocess, "run", _raise_if_called)

    code = bk.run(_args(dry_run=True, yes=True))
    assert code == 0
    assert sentinel_called == []
    # Also: the kismet_site.conf file was not created.
    assert not (kismet_dir / "kismet_site.conf").exists()

    captured = capsys.readouterr()
    assert "DRY-RUN" in captured.out


def test_main_missing_kismet_group_errors(monkeypatch, tmp_path, capsys):
    """If the .deb hasn't created the kismet group on a supported
    distro, we surface, don't paper over.
    """
    monkeypatch.setattr(bk, "_is_root", lambda: True)
    monkeypatch.setattr("sys.platform", "linux")
    monkeypatch.setattr(bk, "detect_distro", lambda *a, **kw: ("kali", "kali"))
    # Skip the install step.
    monkeypatch.setattr(bk, "_kismet_installed", lambda: True)
    monkeypatch.setattr(bk, "detect_wifi_monitor_capable", lambda: [])
    monkeypatch.setattr(bk, "detect_bluetooth_interfaces", lambda *a, **kw: [])
    monkeypatch.setattr(bk, "_real_operator_user", lambda: "alice")
    monkeypatch.setattr(bk, "_group_exists", lambda g: False)
    # Touch A: also block site-conf path-detection so it doesn't try
    # to read /etc/kismet on the host running the test.
    monkeypatch.setattr(bk, "KISMET_SITE_CONF_DIRS", (tmp_path / "absent",))

    code = bk.run(_args(skip_install=True, yes=True))
    assert code == 1
    captured = capsys.readouterr()
    assert "kismet" in captured.err and "group" in captured.err
    # Supported-distro phrasing -- mentions dpkg / postinst.
    assert "postinst" in captured.err or "dpkg" in captured.err


# ---------------------------------------------------------------------------
# Touch A: universal --skip-install + adaptive behaviour matrix
# ---------------------------------------------------------------------------
#
# The v1 distro gate fired BEFORE --skip-install was checked, so the
# flag's contract ("apt is my problem; do the rest") was a no-op on any
# distro outside Debian/Ubuntu/Kali. The cases below pin the new
# behaviour so a future refactor doesn't quietly regress it.


def _stub_run_environment(monkeypatch, tmp_path, *, kismet_on_path: bool):
    """Common run() scaffolding: root, linux, no real subprocess, no
    real interface enumeration, a controlled SUDO_USER already in the
    kismet group (so the usermod step is a no-op). Returns the tmp
    kismet config dir (which the caller may create or leave absent
    depending on which branch they're exercising).
    """
    monkeypatch.setattr(bk, "_is_root", lambda: True)
    monkeypatch.setattr("sys.platform", "linux")
    monkeypatch.setattr(bk, "_kismet_installed", lambda: kismet_on_path)
    monkeypatch.setattr(bk, "detect_wifi_monitor_capable", lambda: [])
    monkeypatch.setattr(bk, "detect_bluetooth_interfaces", lambda *a, **kw: [])
    monkeypatch.setattr(bk, "_real_operator_user", lambda: "alice")
    monkeypatch.setattr(bk, "_group_exists", lambda g: True)
    # Already in the group -- so usermod is skipped and subprocess.run
    # never fires from this code path. Tests exercising the missing-
    # group branch override this.
    monkeypatch.setattr(bk, "_user_in_group", lambda u, g: True)
    # Block any accidental subprocess call -- the matrix tests below
    # never want apt or usermod to actually fire.
    def _refuse(*args, **kwargs):
        raise AssertionError(f"subprocess.run unexpectedly called: {args!r}")
    monkeypatch.setattr(bk.subprocess, "run", _refuse)
    kismet_dir = tmp_path / "kismet"
    return kismet_dir


def test_main_unsupported_distro_with_skip_install_proceeds(
    monkeypatch, tmp_path, capsys
):
    """Unsupported distro + --skip-install + Kismet on PATH: skip the
    apt path, write kismet_site.conf if interfaces are selected, exit 0.
    """
    kismet_dir = _stub_run_environment(monkeypatch, tmp_path, kismet_on_path=True)
    kismet_dir.mkdir()
    monkeypatch.setattr(bk, "KISMET_SITE_CONF_DIRS", (kismet_dir,))
    monkeypatch.setattr(bk, "detect_distro", lambda *a, **kw: (None, None))

    code = bk.run(_args(skip_install=True, yes=True))
    assert code == 0
    out = capsys.readouterr().out
    # Up-front banner about the unsupported-but-skipping branch.
    assert "Unsupported distro" in out
    assert "--skip-install given" in out
    # Closing pointer's adaptive notes block fires.
    assert "apt-install path was skipped" in out
    # No "not in the Kismet-apt matrix" pointer (that's the default-path
    # exit message, suppressed when --skip-install is present).
    assert "not in the Kismet-apt matrix" not in out


def test_main_unsupported_distro_skip_install_warns_when_kismet_missing(
    monkeypatch, tmp_path, capsys
):
    """Unsupported distro + --skip-install + Kismet NOT on PATH: still
    exit 0, but the closing pointer flags missing-binary so the
    operator knows the obvious next move.
    """
    kismet_dir = _stub_run_environment(monkeypatch, tmp_path, kismet_on_path=False)
    kismet_dir.mkdir()
    monkeypatch.setattr(bk, "KISMET_SITE_CONF_DIRS", (kismet_dir,))
    monkeypatch.setattr(bk, "detect_distro", lambda *a, **kw: (None, None))

    code = bk.run(_args(skip_install=True, yes=True))
    assert code == 0
    out = capsys.readouterr().out
    assert "Kismet was not installed by this script" in out
    assert "kismetwireless.net/packages" in out


def test_main_supported_distro_skip_install_proceeds(
    monkeypatch, tmp_path, capsys
):
    """Supported distro + --skip-install: existing behaviour preserved
    (skip apt, run config + group steps). This was already exercised by
    test_main_missing_kismet_group_errors but exit-0 path was not.
    """
    kismet_dir = _stub_run_environment(monkeypatch, tmp_path, kismet_on_path=True)
    kismet_dir.mkdir()
    monkeypatch.setattr(bk, "KISMET_SITE_CONF_DIRS", (kismet_dir,))
    monkeypatch.setattr(bk, "detect_distro", lambda *a, **kw: ("kali", "kali"))

    code = bk.run(_args(skip_install=True, yes=True))
    assert code == 0
    out = capsys.readouterr().out
    # Supported-distro banner fires; the unsupported-skip note does not.
    assert "Detected distro: kali" in out
    assert "apt-install path was skipped" not in out


def test_main_no_network_implies_skip_install(monkeypatch, tmp_path, capsys):
    """--no-network is documented as implying --skip-install. Confirm
    the unified handling: no apt is attempted, and the unsupported-
    distro + --no-network combination behaves like --skip-install.
    """
    kismet_dir = _stub_run_environment(monkeypatch, tmp_path, kismet_on_path=True)
    kismet_dir.mkdir()
    monkeypatch.setattr(bk, "KISMET_SITE_CONF_DIRS", (kismet_dir,))
    monkeypatch.setattr(bk, "detect_distro", lambda *a, **kw: (None, None))

    code = bk.run(_args(skip_install=False, no_network=True, yes=True))
    assert code == 0
    out = capsys.readouterr().out
    assert "--no-network implies --skip-install" in out
    # The unsupported-distro + skip note fires (because --no-network
    # implied --skip-install upstream).
    assert "Unsupported distro" in out


def test_main_unsupported_distro_no_skip_install_unchanged(
    monkeypatch, tmp_path, capsys
):
    """Default-path: unsupported distro and no --skip-install exits
    early with the pointer. Pinned so a future refactor doesn't
    quietly turn the default path into "always try to configure".
    """
    monkeypatch.setattr(bk, "_is_root", lambda: True)
    monkeypatch.setattr("sys.platform", "linux")
    monkeypatch.setattr(bk, "detect_distro", lambda *a, **kw: (None, None))
    # If we got past the gate this would explode -- the matrix tests
    # mock these out; this test does NOT, so an early-exit is the only
    # way it returns 0.
    code = bk.run(_args())
    assert code == 0
    out = capsys.readouterr().out
    assert "not in the Kismet-apt matrix" in out


# ---------------------------------------------------------------------------
# resolve_site_conf_path: auto-detection between apt and from-source layouts
# ---------------------------------------------------------------------------


def test_resolve_site_conf_path_prefers_etc_kismet(tmp_path):
    etc = tmp_path / "etc"
    usr_local = tmp_path / "usr_local"
    etc.mkdir()
    usr_local.mkdir()
    # Both exist; the apt-convention dir wins because it's first in
    # the candidate tuple.
    out = bk.resolve_site_conf_path((etc, usr_local))
    assert out == etc / "kismet_site.conf"


def test_resolve_site_conf_path_falls_back_to_usr_local(tmp_path):
    """From-source build default --prefix=/usr/local lays Kismet's
    config under /usr/local/etc/kismet/. If only that dir exists, we
    use it -- no need for operator hand-editing on from-source hosts.
    """
    etc = tmp_path / "etc"  # NOT created
    usr_local = tmp_path / "usr_local"
    usr_local.mkdir()
    out = bk.resolve_site_conf_path((etc, usr_local))
    assert out == usr_local / "kismet_site.conf"


def test_resolve_site_conf_path_returns_none_when_neither_exists(tmp_path):
    """Operator is likely mid-install. The caller surfaces a warning
    rather than guessing a path the operator would then have to fix.
    """
    out = bk.resolve_site_conf_path(
        (tmp_path / "etc", tmp_path / "usr_local")
    )
    assert out is None


def test_main_warns_when_site_conf_dir_missing(monkeypatch, tmp_path, capsys):
    """Interfaces selected but neither candidate dir exists: warn loudly
    naming both candidates, do NOT write anywhere, do NOT exit non-zero.
    """
    monkeypatch.setattr(bk, "_is_root", lambda: True)
    monkeypatch.setattr("sys.platform", "linux")
    monkeypatch.setattr(bk, "detect_distro", lambda *a, **kw: ("kali", "kali"))
    monkeypatch.setattr(bk, "_kismet_installed", lambda: True)
    # Interface selection MUST yield at least one entry so we exercise
    # the "would-write-but-no-dir" branch (an empty selection skips the
    # patcher entirely, not what we're testing).
    monkeypatch.setattr(bk, "detect_wifi_monitor_capable", lambda: ["wlan0"])
    monkeypatch.setattr(bk, "detect_bluetooth_interfaces", lambda *a, **kw: [])
    monkeypatch.setattr(bk, "_real_operator_user", lambda: "alice")
    monkeypatch.setattr(bk, "_group_exists", lambda g: True)
    # Already in group -- usermod is skipped so subprocess refuser stays clean.
    monkeypatch.setattr(bk, "_user_in_group", lambda u, g: True)
    # Both candidates point at tmp paths that don't exist.
    absent_etc = tmp_path / "absent_etc"
    absent_usr_local = tmp_path / "absent_usr_local"
    monkeypatch.setattr(
        bk, "KISMET_SITE_CONF_DIRS", (absent_etc, absent_usr_local)
    )
    # Refuse subprocess so we'd notice if anything tried to apt or usermod.
    def _refuse(*args, **kwargs):
        raise AssertionError(f"subprocess.run unexpectedly called: {args!r}")
    monkeypatch.setattr(bk.subprocess, "run", _refuse)

    code = bk.run(_args(skip_install=True, yes=True))
    assert code == 0
    out = capsys.readouterr().out
    # The in-line warning at the patch site fires.
    assert "no Kismet config directory found" in out
    assert str(absent_etc) in out
    assert str(absent_usr_local) in out
    # The closing-pointer adaptive note also surfaces.
    assert "No kismet_site.conf was written" in out
    # Neither candidate was created.
    assert not absent_etc.exists()
    assert not absent_usr_local.exists()


def test_main_uses_usr_local_kismet_when_only_it_exists(
    monkeypatch, tmp_path, capsys
):
    """From-source build path-detection end-to-end: only
    /usr/local/etc/kismet/ exists; patcher writes there; closing
    pointer surfaces the non-default location."""
    monkeypatch.setattr(bk, "_is_root", lambda: True)
    monkeypatch.setattr("sys.platform", "linux")
    monkeypatch.setattr(bk, "detect_distro", lambda *a, **kw: (None, None))
    monkeypatch.setattr(bk, "_kismet_installed", lambda: True)
    monkeypatch.setattr(bk, "detect_wifi_monitor_capable", lambda: ["wlan0"])
    monkeypatch.setattr(bk, "detect_bluetooth_interfaces", lambda *a, **kw: [])
    monkeypatch.setattr(bk, "_real_operator_user", lambda: "alice")
    monkeypatch.setattr(bk, "_group_exists", lambda g: True)
    # Already in group -- usermod skipped so the subprocess refuser stays clean.
    monkeypatch.setattr(bk, "_user_in_group", lambda u, g: True)
    def _refuse(*args, **kwargs):
        raise AssertionError(f"subprocess.run unexpectedly called: {args!r}")
    monkeypatch.setattr(bk.subprocess, "run", _refuse)
    # Order matches the production tuple: etc first, usr_local second.
    absent_etc = tmp_path / "absent_etc"
    usr_local = tmp_path / "usr_local_kismet"
    usr_local.mkdir()
    monkeypatch.setattr(
        bk, "KISMET_SITE_CONF_DIRS", (absent_etc, usr_local)
    )

    code = bk.run(_args(skip_install=True, yes=True))
    assert code == 0
    # Site-conf was written to the fallback dir, not the apt dir.
    written = usr_local / "kismet_site.conf"
    assert written.exists()
    assert "source=wlan0:type=linuxwifi" in written.read_text(encoding="utf-8")
    out = capsys.readouterr().out
    # Adaptive note surfaces the non-default path.
    assert "non-default" in out
    assert str(written) in out


# ---------------------------------------------------------------------------
# Touch B: Raspberry Pi OS regression-protection
# ---------------------------------------------------------------------------
#
# Raspberry Pi OS Bookworm (the project's primary deployment target as
# of this writing) reports ID=debian + VERSION_CODENAME=bookworm --
# the Bullseye-era ID=raspbian was retired when the underlying Debian
# tracked Bookworm (verified against the raspberrypi/bookworm-feedback
# issue tracker). This means RPi OS Bookworm is automatically covered
# by the existing SUPPORTED_DEBIAN_CODENAMES set with no code change
# needed. We pin the fingerprint here so a future change to the
# detection logic that doesn't recognise ID=debian + bookworm would
# fail this test and surface the regression before it ships.


RPI_OS_BOOKWORM_OS_RELEASE = """\
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
VERSION_ID="12"
VERSION="12 (bookworm)"
VERSION_CODENAME=bookworm
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"
"""


def test_detect_distro_rpi_os_bookworm_supported(tmp_path):
    """Raspberry Pi OS Bookworm's os-release falls through to the
    Debian branch (ID=debian + VERSION_CODENAME=bookworm), so RPi OS
    is supported with no additional code in the distro matrix.
    """
    p = _write_os_release(tmp_path, RPI_OS_BOOKWORM_OS_RELEASE)
    assert bk.detect_distro(p) == ("debian", "bookworm")


# ---------------------------------------------------------------------------
# argparse: --version, --help return successfully (smoke)
# ---------------------------------------------------------------------------


def test_argparse_help_smoke(capsys):
    parser = bk._build_parser()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["--help"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "lynceus-bootstrap-kismet" in captured.out


def test_argparse_version_includes_lynceus_version(capsys):
    parser = bk._build_parser()
    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["--version"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    out = captured.out + captured.err
    from lynceus import __version__
    assert __version__ in out
