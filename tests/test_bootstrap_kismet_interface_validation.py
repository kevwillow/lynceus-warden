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
    """A host with a real wifi interface AND a real bluetooth controller."""
    net = tmp_path / "net"
    (net / "wlan0" / "device").mkdir(parents=True)
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
