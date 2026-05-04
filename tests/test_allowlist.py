"""Tests for the allowlist."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from talos.allowlist import Allowlist, AllowlistEntry, load_allowlist
from talos.kismet import DeviceObservation

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "allowlist_example.yaml"


def _obs(mac: str, ssid: str | None = None) -> DeviceObservation:
    return DeviceObservation(
        mac=mac,
        device_type="wifi",
        first_seen=1700000000,
        last_seen=1700000100,
        rssi=-50,
        ssid=ssid,
        oui_vendor=None,
        is_randomized=False,
    )


# ------------------------------ load_allowlist ------------------------------


def test_load_empty_allowlist_file(tmp_path):
    p = tmp_path / "allowlist.yaml"
    p.write_text("", encoding="utf-8")
    al = load_allowlist(str(p))
    assert isinstance(al, Allowlist)
    assert al.entries == []


def test_load_with_entries_from_fixture():
    al = load_allowlist(str(FIXTURE_PATH))
    assert len(al.entries) == 4
    types = [e.pattern_type for e in al.entries]
    assert types == ["mac", "mac", "oui", "ssid"]
    assert al.entries[0].note == "My laptop"
    assert al.entries[3].pattern == "HomeNet"


def test_load_missing_file_raises_filenotfounderror(tmp_path):
    missing = tmp_path / "nope.yaml"
    with pytest.raises(FileNotFoundError):
        load_allowlist(str(missing))


# --------------------------- pattern normalization ---------------------------


def test_mac_normalized_uppercase_to_lowercase():
    e = AllowlistEntry(pattern="A4:83:E7:11:22:33", pattern_type="mac")
    assert e.pattern == "a4:83:e7:11:22:33"


def test_oui_normalized_uppercase_to_lowercase():
    e = AllowlistEntry(pattern="AA:BB:CC", pattern_type="oui")
    assert e.pattern == "aa:bb:cc"


def test_oui_normalized_hyphens_to_colons():
    e = AllowlistEntry(pattern="aa-bb-cc", pattern_type="oui")
    assert e.pattern == "aa:bb:cc"


# ------------------------------ rejected input ------------------------------


def test_invalid_mac_rejected():
    with pytest.raises(ValidationError):
        AllowlistEntry(pattern="not-a-mac", pattern_type="mac")


def test_invalid_oui_too_short_rejected():
    with pytest.raises(ValidationError):
        AllowlistEntry(pattern="aa:bb", pattern_type="oui")


def test_invalid_oui_non_hex_rejected():
    with pytest.raises(ValidationError):
        AllowlistEntry(pattern="gg:hh:ii", pattern_type="oui")


def test_invalid_pattern_type_rejected():
    with pytest.raises(ValidationError):
        AllowlistEntry(pattern="anything", pattern_type="bssid")


def test_extra_field_rejected():
    with pytest.raises(ValidationError):
        AllowlistEntry(
            pattern="aa:bb:cc:dd:ee:ff",
            pattern_type="mac",
            extra_field="nope",
        )


# --------------------------------- is_allowed --------------------------------


def test_is_allowed_mac_match():
    al = Allowlist(entries=[AllowlistEntry(pattern="A4:83:E7:11:22:33", pattern_type="mac")])
    assert al.is_allowed(_obs("a4:83:e7:11:22:33")) is True


def test_is_allowed_mac_no_match():
    al = Allowlist(entries=[AllowlistEntry(pattern="A4:83:E7:11:22:33", pattern_type="mac")])
    assert al.is_allowed(_obs("de:ad:be:ef:00:01")) is False


def test_is_allowed_oui_match():
    al = Allowlist(entries=[AllowlistEntry(pattern="AA:BB:CC", pattern_type="oui")])
    assert al.is_allowed(_obs("aa:bb:cc:11:22:33")) is True


def test_is_allowed_oui_no_match():
    al = Allowlist(entries=[AllowlistEntry(pattern="AA:BB:CC", pattern_type="oui")])
    assert al.is_allowed(_obs("aa:bb:cd:11:22:33")) is False


def test_is_allowed_ssid_match():
    al = Allowlist(entries=[AllowlistEntry(pattern="HomeNet", pattern_type="ssid")])
    assert al.is_allowed(_obs("aa:bb:cc:dd:ee:ff", ssid="HomeNet")) is True


def test_is_allowed_ssid_returns_false_when_obs_ssid_none():
    al = Allowlist(entries=[AllowlistEntry(pattern="HomeNet", pattern_type="ssid")])
    assert al.is_allowed(_obs("aa:bb:cc:dd:ee:ff", ssid=None)) is False
