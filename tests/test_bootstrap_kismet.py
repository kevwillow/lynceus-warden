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
    monkeypatch.setattr(bk, "_is_root", lambda: True)
    monkeypatch.setattr("sys.platform", "linux")
    # Don't accidentally touch the real host's OS at all.
    monkeypatch.setattr(bk, "detect_distro", lambda *a, **kw: (None, None))
    code = bk.run(_args())
    assert code == 0
    captured = capsys.readouterr()
    assert "not supported" in captured.out
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

    # Redirect kismet_site.conf path into tmp so we don't try to
    # write /etc/kismet (which would be denied anyway).
    monkeypatch.setattr(
        bk, "KISMET_SITE_CONF_PATH", tmp_path / "kismet_site.conf"
    )

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
    assert not (tmp_path / "kismet_site.conf").exists()

    captured = capsys.readouterr()
    assert "DRY-RUN" in captured.out


def test_main_missing_kismet_group_errors(monkeypatch, tmp_path, capsys):
    """If the .deb hasn't created the kismet group, we surface, don't paper over."""
    monkeypatch.setattr(bk, "_is_root", lambda: True)
    monkeypatch.setattr("sys.platform", "linux")
    monkeypatch.setattr(bk, "detect_distro", lambda *a, **kw: ("kali", "kali"))
    # Skip the install step.
    monkeypatch.setattr(bk, "_kismet_installed", lambda: True)
    monkeypatch.setattr(bk, "detect_wifi_monitor_capable", lambda: [])
    monkeypatch.setattr(bk, "detect_bluetooth_interfaces", lambda *a, **kw: [])
    monkeypatch.setattr(bk, "_real_operator_user", lambda: "alice")
    monkeypatch.setattr(bk, "_group_exists", lambda g: False)

    code = bk.run(_args(skip_install=True, yes=True))
    assert code == 1
    captured = capsys.readouterr()
    assert "kismet" in captured.err and "group" in captured.err


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
