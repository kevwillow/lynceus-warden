"""`--interface` must not silently configure a capture source that cannot exist.

`_select_interfaces` returns `args.interface` verbatim, bypassing detection
entirely. That escape hatch is deliberate and must stay: an operator may be
configuring a remote rig, or an adapter that is not plugged in yet.

⛔ But it was completely unvalidated, and for THIS tool that is the worst
available failure. `lynceus-bootstrap-kismet --interface wlan99` wrote
`source=wlan99:type=linuxwifi` and reported success. Kismet then captures
nothing, and the operator believes their sensor is watching. Silence that looks
like safety is precisely the ambiguity the heartbeat and the Kismet-loss alert
exist to remove -- and here it starts at setup, before either can help.

⇒ The fix is a WARNING, not an error. Blocking would break the remote-rig and
not-plugged-in-yet cases, which are legitimate and which the flag exists for.
Naming the risk costs nothing and closes the silence.

`cli/bootstrap_kismet.py` is 1,607 lines and had no behavioural test until
`test_bootstrap_kismet_file_modes.py`; this covers the interface-selection half
that the orchestration plan named as W3-C's highest-value case ("it can write a
wrong-interface config and report success").
"""

from __future__ import annotations

import argparse

import pytest

from lynceus.cli import bootstrap_kismet as bk


def _args(**kw) -> argparse.Namespace:
    base = dict(interface=None, interface_type="wifi", yes=True)
    base.update(kw)
    return argparse.Namespace(**base)


@pytest.fixture()
def sysfs(tmp_path, monkeypatch):
    """A fake /sys/class/net holding exactly one real interface.

    ⚠️ Patches the BLUETOOTH tree too, at an empty directory. The absence check
    now consults the other tree before blaming the name, so leaving
    ``_SYS_CLASS_BLUETOOTH`` unpatched would let these tests read the real
    ``/sys/class/bluetooth`` of whatever machine they run on -- passing on a
    host with no controller and behaving differently on one with an ``hci0``.
    """
    net = tmp_path / "net"
    (net / "wlan0" / "device").mkdir(parents=True)
    bt = tmp_path / "bluetooth"
    bt.mkdir(parents=True)
    monkeypatch.setattr(bk, "_SYS_CLASS_NET", net, raising=False)
    monkeypatch.setattr(bk, "_SYS_CLASS_BLUETOOTH", bt, raising=False)
    return net


@pytest.fixture()
def both_trees(tmp_path, monkeypatch):
    """A host with a real wifi interface, a wired NIC, and a bluetooth controller.

    ⚠️ ``wlan0/wireless`` is the kernel attribute that distinguishes a cfg80211
    device from every other thing in ``/sys/class/net``. ``eth0`` deliberately
    lacks it: without a non-wireless network interface in the fixture, "is it
    wireless?" and "is it in /sys/class/net?" are the same question and a test
    cannot tell the two apart.
    """
    net = tmp_path / "net"
    (net / "wlan0" / "device").mkdir(parents=True)
    (net / "wlan0" / "wireless").mkdir(parents=True)
    (net / "eth0" / "device").mkdir(parents=True)
    bt = tmp_path / "bluetooth"
    (bt / "hci0").mkdir(parents=True)
    monkeypatch.setattr(bk, "_SYS_CLASS_NET", net, raising=False)
    monkeypatch.setattr(bk, "_SYS_CLASS_BLUETOOTH", bt, raising=False)
    return net, bt


def test_a_named_interface_that_exists_is_not_warned_about(sysfs, capsys):
    """The presence assertion beside the absence one: a warning that fires
    every time would satisfy the test below while telling the operator
    nothing."""
    wifi, bt = bk._select_interfaces(_args(interface=["wlan0"]), input_fn=lambda _: "y")
    assert wifi == ["wlan0"]
    assert bt == []
    out = capsys.readouterr().out
    assert "not present" not in out.lower(), out


def test_a_named_interface_that_does_not_exist_is_warned_about(sysfs, capsys):
    """The defect: configured, reported successful, captures nothing."""
    wifi, _ = bk._select_interfaces(_args(interface=["wlan99"]), input_fn=lambda _: "y")
    out = capsys.readouterr().out
    assert "wlan99" in out, out
    assert "not present" in out.lower(), (
        f"a nonexistent capture interface was configured silently: {out!r}"
    )


def test_the_warning_does_not_block_the_escape_hatch(sysfs, capsys):
    """⛔ The half that must not regress. The flag exists for remote rigs and
    adapters that are not plugged in yet; turning the warning into a refusal
    would break the exact workflow it is there to serve."""
    wifi, _ = bk._select_interfaces(_args(interface=["wlan99"]), input_fn=lambda _: "y")
    assert wifi == ["wlan99"], "the interface was dropped instead of merely flagged"


def test_bluetooth_interfaces_are_checked_against_their_own_class(tmp_path, monkeypatch, capsys):
    """A bt controller lives under /sys/class/bluetooth, not /sys/class/net.
    Checking it against the wrong class would warn about every valid
    controller -- noise that trains the operator to ignore the warning."""
    net = tmp_path / "net"
    (net / "wlan0").mkdir(parents=True)
    bt = tmp_path / "bluetooth"
    (bt / "hci0").mkdir(parents=True)
    monkeypatch.setattr(bk, "_SYS_CLASS_NET", net, raising=False)
    monkeypatch.setattr(bk, "_SYS_CLASS_BLUETOOTH", bt, raising=False)

    _, bts = bk._select_interfaces(
        _args(interface=["hci0"], interface_type="bt"), input_fn=lambda _: "y"
    )
    assert bts == ["hci0"]
    assert "not present" not in capsys.readouterr().out.lower()


def test_several_named_interfaces_are_each_checked(sysfs, capsys):
    """One bad name among several must not be masked by the good ones."""
    wifi, _ = bk._select_interfaces(
        _args(interface=["wlan0", "wlan99"]), input_fn=lambda _: "y"
    )
    assert wifi == ["wlan0", "wlan99"]
    out = capsys.readouterr().out
    assert "wlan99" in out
    assert "wlan0 " not in out.replace("wlan99", ""), (
        "the interface that DOES exist was also flagged"
    )


# ---------------------------------------------------------------------------
# Two causes, opposite fixes. They used to produce the same sentence.
#
# `--interface-type` defaults to `wifi`, so `--interface hci0` -- the obvious
# way to add a Bluetooth adapter -- warned "not present under /sys/class/net
# ... otherwise check the name". Measured on a host with a real hci0, that is
# byte-identical to the warning for `wlan99`, which genuinely does not exist.
# The name was right; the KIND was wrong. An operator who follows the advice,
# checks the name, finds it correct and dismisses the warning lands on
# `source=hci0:type=linuxwifi` -- which Kismet cannot open. That is the exact
# "configured, capturing nothing" state the warning exists to prevent, reached
# by doing what the warning said.
# ---------------------------------------------------------------------------


def test_a_bluetooth_controller_named_without_the_type_flag_names_the_real_cause(
    both_trees, capsys
):
    """The defect. `hci0` exists -- as a bt controller, not a wifi interface."""
    wifi, _ = bk._select_interfaces(_args(interface=["hci0"]), input_fn=lambda _: "y")
    out = capsys.readouterr().out

    assert "--interface-type bt" in out, (
        "the operator was not told the one thing that fixes this; the name is "
        f"correct and re-checking it teaches them nothing: {out!r}"
    )
    assert "check the name" not in out.lower(), (
        f"told to check a name that is already right: {out!r}"
    )
    # ⛔ Still a warning, never a refusal -- the escape hatch must survive.
    assert wifi == ["hci0"], "the interface was dropped instead of merely flagged"


def test_the_reverse_misclassification_is_named_too(both_trees, capsys):
    """Derived from the same rule, not a special case for bluetooth. A wifi
    interface named with `--interface-type bt` is the mirror image."""
    _, bts = bk._select_interfaces(
        _args(interface=["wlan0"], interface_type="bt"), input_fn=lambda _: "y"
    )
    out = capsys.readouterr().out

    assert "--interface-type wifi" in out, out
    assert bts == ["wlan0"]


def test_a_name_that_exists_in_neither_tree_still_blames_the_name(both_trees, capsys):
    """⛔ The presence assertion beside the two above. Without it, a warning
    that says "--interface-type" unconditionally would satisfy them -- and
    would misdiagnose every genuinely wrong name, which is the larger case."""
    wifi, _ = bk._select_interfaces(_args(interface=["wlan99"]), input_fn=lambda _: "y")
    out = capsys.readouterr().out

    assert "check the name" in out.lower(), out
    assert "--interface-type" not in out, (
        f"a name that exists nowhere was blamed on the kind instead: {out!r}"
    )
    assert wifi == ["wlan99"]


def test_the_misclassification_warning_quotes_the_line_kismet_would_get(
    both_trees, capsys
):
    """The operator should not have to reconstruct what was about to be written.
    Derived from `build_source_line`, so a change to the wire format moves the
    message with it instead of leaving a stale quote behind."""
    bk._select_interfaces(_args(interface=["hci0"]), input_fn=lambda _: "y")
    out = capsys.readouterr().out

    assert bk.build_source_line("hci0", "wifi") in out, out


def test_an_unreadable_other_tree_falls_back_instead_of_guessing(
    both_trees, monkeypatch, capsys
):
    """Absence of evidence is not evidence of absence -- the same reasoning the
    base lookup already applies. A sharper diagnosis we cannot substantiate is
    worse than the general one."""
    _, bt = both_trees

    class _Boom:
        def __truediv__(self, other):
            return self

        def exists(self):
            raise OSError("hardened mount")

    monkeypatch.setattr(bk, "_SYS_CLASS_BLUETOOTH", _Boom(), raising=False)

    wifi, _ = bk._select_interfaces(_args(interface=["hci0"]), input_fn=lambda _: "y")
    out = capsys.readouterr().out

    assert "check the name" in out.lower(), out
    assert "--interface-type" not in out, out
    assert wifi == ["hci0"]


# ---------------------------------------------------------------------------
# Round 1 of the red-team on the fix above (codex gpt-5.6-sol, verified here).
# Three of its findings landed on this function; all three were reproduced
# before being fixed, and each gets the plant that proves the guard.
# ---------------------------------------------------------------------------


def test_a_wired_nic_is_not_advised_to_be_captured_as_wifi(both_trees, capsys):
    """⛔ The misclassification branch, aimed back at itself.

    `/sys/class/bluetooth` holds only controllers, so a hit there proves `bt`.
    `/sys/class/net` holds ethernet, loopback, bridges, VLANs, tunnels and every
    veth a container ever made, so a hit there proves NOTHING about wifi.
    Measured before the fix: `--interface eth0 --interface-type bt` was advised
    to "pass --interface-type wifi", yielding `source=eth0:type=linuxwifi` — a
    source Kismet cannot capture with, recommended in the tool's own voice.
    """
    _, bts = bk._select_interfaces(
        _args(interface=["eth0"], interface_type="bt"), input_fn=lambda _: "y"
    )
    out = capsys.readouterr().out

    assert "--interface-type wifi" not in out, (
        f"advised capturing a wired NIC as wifi — a concrete WRONG remedy, "
        f"which is worse than the vague right one: {out!r}"
    )
    assert "not a wireless one" in out, f"said nothing useful about eth0: {out!r}"
    assert bts == ["eth0"], "still a warning, never a refusal"


def test_a_real_wireless_interface_is_still_advised(both_trees, capsys):
    """⛔ Presence assertion beside it. Requiring proof of wirelessness must not
    turn the useful advice off — `never suggest wifi` would pass the test above."""
    _, bts = bk._select_interfaces(
        _args(interface=["wlan0"], interface_type="bt"), input_fn=lambda _: "y"
    )
    out = capsys.readouterr().out

    assert "--interface-type wifi" in out, out
    assert bts == ["wlan0"]


@pytest.mark.parametrize(
    "bad", ["", ".", "..", "/etc/passwd", "wlan0/../wlan0", "wlan0\x00x"]
)
def test_a_string_that_is_not_an_interface_name_is_refused_not_looked_up(
    both_trees, capsys, bad
):
    """`base / iface` is path arithmetic, not a child lookup.

    `""` and `"."` resolve to `base` itself — which exists, so the check passed
    silently — and an ABSOLUTE iface discards `base` entirely, so
    `--interface /etc/passwd` was reported present. Measured: all five of these
    returned present with NO warning, and each would then be written into
    kismet_site.conf as a capture source.
    """
    present = bk._warn_if_interface_absent(bad, "wifi")
    out = capsys.readouterr().out

    assert present is False, f"{bad!r} was accepted as an existing interface"
    assert "not a valid interface name" in out, out


def test_a_missing_sysfs_tree_makes_no_claim_either_way(tmp_path, monkeypatch, capsys):
    """🪤 `Path.exists()` returns False for a missing tree and never raises, so
    the OSError branch does not cover this. In a container with no
    /sys/class/net mounted, every name produced a confident "not present" that
    meant nothing — the noise that teaches operators to ignore warnings."""
    monkeypatch.setattr(bk, "_SYS_CLASS_NET", tmp_path / "absent", raising=False)
    monkeypatch.setattr(bk, "_SYS_CLASS_BLUETOOTH", tmp_path / "gone", raising=False)

    present = bk._warn_if_interface_absent("wlan0", "wifi")
    out = capsys.readouterr().out

    assert present is True, "claimed absence with no evidence either way"
    assert out.strip() == "", f"warned without evidence: {out!r}"


# ---------------------------------------------------------------------------
# Round 3: an audit of these tests' own oracles (codex gpt-5.6-sol) asked what
# else could produce "configured, captures nothing". Its sharpest point was not
# about a case — it was that every test above stops at `_select_interfaces` and
# so proves nothing about what the OPERATOR sees, or about what gets written.
#
# ⭐ Wiring-in is not behaviour. `_select_interfaces` returning the right thing
# and printing the right warning is worth nothing if `run()` never calls it, or
# calls it and discards the output. That has been a real defect in this repo
# before, so it gets asserted rather than assumed.
# ---------------------------------------------------------------------------


def _run_bootstrap(monkeypatch, tmp_path, both_trees, interface, interface_type):
    """Drive the real `run()` end to end, in dry-run, with sysfs and the target
    conf path redirected. Returns (exit_code, stdout)."""
    site_conf = tmp_path / "kismet_site.conf"
    monkeypatch.setattr(bk, "_is_root", lambda: True, raising=False)
    monkeypatch.setattr(bk, "resolve_site_conf_path", lambda: site_conf, raising=False)
    monkeypatch.setattr(bk, "ensure_kismet_group", lambda *a, **kw: None, raising=False)
    args = argparse.Namespace(
        interface=[interface], interface_type=interface_type, yes=True,
        dry_run=True, install=False, no_network=True, reset_config=False,
    )
    code = bk.run(args, input_fn=lambda _: "y")
    return code, site_conf


def test_the_misclassification_warning_actually_reaches_the_operator(
    monkeypatch, tmp_path, both_trees, capsys
):
    """End to end through `run()`, not `_select_interfaces`: the warning must
    survive the call chain the operator actually invokes."""
    _run_bootstrap(monkeypatch, tmp_path, both_trees, "hci0", "wifi")
    out = capsys.readouterr().out

    assert "--interface-type bt" in out, (
        f"the warning never reached stdout through run(): {out[-400:]!r}"
    )


def test_a_wired_nic_warning_also_reaches_the_operator(
    monkeypatch, tmp_path, both_trees, capsys
):
    """The other new branch, through the same real path."""
    _run_bootstrap(monkeypatch, tmp_path, both_trees, "eth0", "bt")
    out = capsys.readouterr().out

    assert "not a wireless one" in out, out
    assert "--interface-type wifi" not in out, (
        f"advised capturing a wired NIC as wifi, through the real CLI path: {out!r}"
    )


def test_the_named_interface_still_reaches_the_config_despite_the_warning(
    monkeypatch, tmp_path, both_trees, capsys
):
    """⛔ Presence assertion, and the one that makes the two above mean
    something: warning must not become refusal. `--interface` exists to bypass
    detection for remote rigs, so the source line must still be written."""
    _, site_conf = _run_bootstrap(monkeypatch, tmp_path, both_trees, "hci0", "wifi")
    out = capsys.readouterr().out

    # dry-run previews rather than writes, so assert on what it says it would do
    assert bk.build_source_line("hci0", "wifi") in out, (
        f"the interface was dropped instead of merely flagged: {out[-400:]!r}"
    )
