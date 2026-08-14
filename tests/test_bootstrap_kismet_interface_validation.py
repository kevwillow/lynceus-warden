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
    """A fake /sys/class/net holding exactly one real interface."""
    net = tmp_path / "net"
    (net / "wlan0" / "device").mkdir(parents=True)
    monkeypatch.setattr(bk, "_SYS_CLASS_NET", net, raising=False)
    return net


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
