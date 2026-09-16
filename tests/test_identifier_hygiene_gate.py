"""The standalone hygiene gate must not drift from the product's own sets.

`scripts/check_identifier_hygiene.py` inlines the reserved-prefix sets instead
of importing them, because importing `lynceus.rules` needs PyYAML and a gate
that can be silenced by a packaging failure is not a gate. The cost of inlining
is drift, so it is paid here, where the full environment exists.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

from lynceus import rules

_GATE = Path(__file__).resolve().parents[1] / "scripts" / "check_identifier_hygiene.py"


def _gate():
    spec = importlib.util.spec_from_file_location("_hygiene_gate", _GATE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_gates_inlined_reserved_sets_match_the_products():
    gate = _gate()
    assert gate._RESERVED_OUI_PREFIXES_EXACT == rules._RESERVED_OUI_PREFIXES_EXACT
    assert (
        gate._RESERVED_MAC_PREFIXES_TWO_OCTET
        == rules._RESERVED_MAC_PREFIXES_TWO_OCTET
    )


def test_the_gate_imports_nothing_from_the_package():
    """⛔ The whole point of inlining. If someone reinstates the import, the
    gate starts depending on the package installing — and a CI job that skips
    the install gets ModuleNotFoundError instead of a hygiene result."""
    src = _GATE.read_text(encoding="utf-8")
    offenders = [
        line.strip()
        for line in src.splitlines()
        if line.strip().startswith(("import lynceus", "from lynceus"))
    ]
    assert not offenders, (
        f"the gate imports from the package again: {offenders}. "
        "Inline the constant and assert it here instead."
    )


def test_the_locally_administered_bit_is_what_decides():
    gate = _gate()
    # Globally administered: bit 1 of the first octet CLEAR -> could be real.
    assert gate._could_identify_a_real_device("00:0c:41:82:b2:55")
    assert gate._could_identify_a_real_device("dc:a6:32:aa:bb:cc")
    # Locally administered: bit 1 SET -> assigned to nobody, all four nibbles.
    for octet in ("02", "06", "0a", "0e", "ff", "bb", "37", "f3"):
        mac = f"{octet}:11:22:33:44:55"
        assert not gate._could_identify_a_real_device(mac), mac
    # The product's reserved prefixes.
    assert not gate._could_identify_a_real_device("00:00:00:11:22:33")
    assert not gate._could_identify_a_real_device("33:33:00:00:00:01")


def test_an_ssid_needs_a_reason_in_every_malformed_shape(tmp_path, monkeypatch):
    """⛔ Four ways to write an entry with no reason. All must be refused.

    A plant that greps for ONE rejection message reports a false survivor here:
    the SSID path and the MAC path fail with different (both correct) messages.
    Assert the EXIT, not the wording.
    """
    gate = _gate()
    original = gate.ALLOWLIST.read_text(encoding="utf-8")
    fake = tmp_path / "allow.yaml"
    for form in ('"X":', '"X": ', "aa:bb:cc:dd:ee:f0:", "commit abcd1234:"):
        fake.write_text(original + form + "\n", encoding="utf-8")
        monkeypatch.setattr(gate, "ALLOWLIST", fake)
        with pytest.raises(SystemExit):
            gate._load_allowlist()


def test_an_ssid_may_contain_a_colon(tmp_path, monkeypatch):
    """⛔ Why SSIDs are quoted. An SSID is arbitrary text and may legally hold a
    colon, which is also the MAC separator AND the key/reason separator. An
    unquoted format would mis-split it and silently allowlist the wrong thing."""
    gate = _gate()
    fake = tmp_path / "allow.yaml"
    fake.write_text('"Guest: 5GHz": invented fixture name\n', encoding="utf-8")
    monkeypatch.setattr(gate, "ALLOWLIST", fake)
    macs, ssids, commits = gate._load_allowlist()
    assert ssids == {"Guest: 5GHz": "invented fixture name"}
    assert not macs and not commits


def test_a_commit_exemption_never_writes_the_identifier_into_the_tree():
    """⛔ The design's whole point. Historical commit messages are exempted BY
    SHA, because listing the MAC would put a redacted value back into a tracked
    file — which is exactly what redacting it was for."""
    gate = _gate()
    text = gate.ALLOWLIST.read_text(encoding="utf-8")
    for line in text.splitlines():
        if line.startswith("commit "):
            assert not gate._MAC.search(line), (
                f"a commit exemption carries a full MAC: {line!r}. "
                "Exempt the SHA, never the identifier."
            )


def test_the_ssid_universe_is_fields_not_values():
    """An SSID has no structural marker, so the scan keys on the FIELD. Prove
    the field matcher covers what Kismet actually emits."""
    gate = _gate()
    for key in ("ssid", "SSID", "dot11.device.probed_ssid_map", "kismet.device.base.name",
                "essid", "network_name"):
        assert gate._SSID_KEY.search(key), key
    for key in ("mac", "rssi", "manuf", "last_seen"):
        assert not gate._SSID_KEY.search(key), key
