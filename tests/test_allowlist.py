"""Tests for the allowlist."""

import logging
from pathlib import Path

import pytest
from pydantic import ValidationError

from lynceus.allowlist import (
    Allowlist,
    AllowlistEntry,
    add_ui_entry,
    derive_ui_path,
    load_allowlist,
    remove_ui_entry,
)
from lynceus.kismet import DeviceObservation

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
    matched = al.is_allowed(_obs("a4:83:e7:11:22:33"))
    assert matched is not None
    assert matched.pattern == "a4:83:e7:11:22:33"


def test_is_allowed_mac_no_match():
    al = Allowlist(entries=[AllowlistEntry(pattern="A4:83:E7:11:22:33", pattern_type="mac")])
    assert al.is_allowed(_obs("de:ad:be:ef:00:01")) is None


def test_is_allowed_oui_match():
    al = Allowlist(entries=[AllowlistEntry(pattern="AA:BB:CC", pattern_type="oui")])
    matched = al.is_allowed(_obs("aa:bb:cc:11:22:33"))
    assert matched is not None
    assert matched.pattern_type == "oui"


def test_is_allowed_oui_no_match():
    al = Allowlist(entries=[AllowlistEntry(pattern="AA:BB:CC", pattern_type="oui")])
    assert al.is_allowed(_obs("aa:bb:cd:11:22:33")) is None


def test_is_allowed_ssid_match():
    al = Allowlist(entries=[AllowlistEntry(pattern="HomeNet", pattern_type="ssid")])
    matched = al.is_allowed(_obs("aa:bb:cc:dd:ee:ff", ssid="HomeNet"))
    assert matched is not None
    assert matched.pattern == "HomeNet"


def test_is_allowed_ssid_returns_none_when_obs_ssid_none():
    al = Allowlist(entries=[AllowlistEntry(pattern="HomeNet", pattern_type="ssid")])
    assert al.is_allowed(_obs("aa:bb:cc:dd:ee:ff", ssid=None)) is None


def test_is_allowed_docstring_pins_precedence_note():
    """Docstring regression guard: the precedence-over-watchlist note on
    Allowlist.is_allowed pairs with poller.poll_once's audit-log block — if
    a future refactor drops one, the other becomes mysterious."""
    assert Allowlist.is_allowed.__doc__ is not None
    assert "precedence" in Allowlist.is_allowed.__doc__


# --------------------------- schema: expiry + added_at ----------------------


def test_entry_with_expires_at_and_added_at_parses():
    e = AllowlistEntry(
        pattern="aa:bb:cc:dd:ee:ff",
        pattern_type="mac",
        expires_at=1_800_000_000,
        added_at=1_799_000_000,
    )
    assert e.expires_at == 1_800_000_000
    assert e.added_at == 1_799_000_000


def test_entry_without_expires_at_and_added_at_defaults_to_none():
    """Backward compat: pre-existing YAML files have no expiry fields and
    must continue to parse with both new fields defaulting to None."""
    e = AllowlistEntry(pattern="aa:bb:cc:dd:ee:ff", pattern_type="mac")
    assert e.expires_at is None
    assert e.added_at is None


def test_entry_is_frozen_against_mutation():
    e = AllowlistEntry(pattern="aa:bb:cc:dd:ee:ff", pattern_type="mac")
    with pytest.raises(ValidationError):
        e.expires_at = 1_800_000_000  # type: ignore[misc]


# --------------------------- is_allowed: expiry semantics --------------------


def test_is_allowed_skips_expired_entry():
    """Snooze whose window has passed must not suppress."""
    al = Allowlist(
        entries=[
            AllowlistEntry(
                pattern="aa:bb:cc:dd:ee:ff",
                pattern_type="mac",
                expires_at=1_700_000_000,
            )
        ]
    )
    assert al.is_allowed(_obs("aa:bb:cc:dd:ee:ff"), now_ts=1_800_000_000) is None


def test_is_allowed_honors_unexpired_entry():
    """Snooze still in its window must suppress."""
    al = Allowlist(
        entries=[
            AllowlistEntry(
                pattern="aa:bb:cc:dd:ee:ff",
                pattern_type="mac",
                expires_at=1_800_000_000,
            )
        ]
    )
    matched = al.is_allowed(_obs("aa:bb:cc:dd:ee:ff"), now_ts=1_700_000_000)
    assert matched is not None
    assert matched.expires_at == 1_800_000_000


def test_is_allowed_defaults_now_ts_to_wall_clock():
    """Without now_ts, the call still works (using current time)."""
    al = Allowlist(entries=[AllowlistEntry(pattern="aa:bb:cc:dd:ee:ff", pattern_type="mac")])
    assert al.is_allowed(_obs("aa:bb:cc:dd:ee:ff")) is not None


def test_is_allowed_mixed_permanent_and_expired_and_future():
    """Permanent stays, expired is skipped, future-expiry suppresses."""
    permanent = AllowlistEntry(pattern="aa:00:00:00:00:01", pattern_type="mac")
    expired = AllowlistEntry(
        pattern="aa:00:00:00:00:02",
        pattern_type="mac",
        expires_at=1_700_000_000,
    )
    future = AllowlistEntry(
        pattern="aa:00:00:00:00:03",
        pattern_type="mac",
        expires_at=1_900_000_000,
    )
    al = Allowlist(entries=[permanent, expired, future])
    now_ts = 1_800_000_000
    assert al.is_allowed(_obs("aa:00:00:00:00:01"), now_ts=now_ts) is not None
    assert al.is_allowed(_obs("aa:00:00:00:00:02"), now_ts=now_ts) is None
    assert al.is_allowed(_obs("aa:00:00:00:00:03"), now_ts=now_ts) is not None


# --------------------------- split-storage loader ----------------------------


def _write_yaml(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")


def test_derive_ui_path_basic():
    assert derive_ui_path(Path("/etc/lynceus/allowlist.yaml")) == Path(
        "/etc/lynceus/allowlist_ui.yaml"
    )


def test_derive_ui_path_preserves_unusual_extension():
    assert derive_ui_path(Path("/x/allowlist.yml")) == Path("/x/allowlist_ui.yml")


def test_split_loader_primary_only_matches_single_file_today(tmp_path):
    primary = tmp_path / "allowlist.yaml"
    _write_yaml(
        primary,
        "entries:\n  - pattern: aa:bb:cc:dd:ee:ff\n    pattern_type: mac\n",
    )
    al = load_allowlist(str(primary))
    assert len(al.entries) == 1
    assert al.entries[0].pattern == "aa:bb:cc:dd:ee:ff"


def test_split_loader_ui_only_still_loads(tmp_path):
    """Primary present-but-empty, UI sibling with one entry. The UI entries
    are merged into the in-memory allowlist."""
    primary = tmp_path / "allowlist.yaml"
    _write_yaml(primary, "entries: []\n")
    ui = derive_ui_path(primary)
    _write_yaml(
        ui,
        "entries:\n  - pattern: 11:22:33:44:55:66\n    pattern_type: mac\n"
        "    added_at: 1799000000\n",
    )
    al = load_allowlist(str(primary))
    assert len(al.entries) == 1
    assert al.entries[0].pattern == "11:22:33:44:55:66"
    assert al.entries[0].added_at == 1_799_000_000


def test_split_loader_both_files_concatenated(tmp_path):
    primary = tmp_path / "allowlist.yaml"
    _write_yaml(
        primary,
        "entries:\n  - pattern: aa:bb:cc:dd:ee:ff\n    pattern_type: mac\n",
    )
    ui = derive_ui_path(primary)
    _write_yaml(
        ui,
        "entries:\n  - pattern: 11:22:33:44:55:66\n    pattern_type: mac\n",
    )
    al = load_allowlist(str(primary))
    assert len(al.entries) == 2
    patterns = {e.pattern for e in al.entries}
    assert patterns == {"aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"}


def test_split_loader_malformed_ui_logs_warning_treats_as_empty(tmp_path, caplog):
    primary = tmp_path / "allowlist.yaml"
    _write_yaml(
        primary,
        "entries:\n  - pattern: aa:bb:cc:dd:ee:ff\n    pattern_type: mac\n",
    )
    ui = derive_ui_path(primary)
    _write_yaml(ui, ":::not valid yaml:::")
    with caplog.at_level(logging.WARNING, logger="lynceus.allowlist"):
        al = load_allowlist(str(primary))
    assert len(al.entries) == 1  # primary survives
    assert al.entries[0].pattern == "aa:bb:cc:dd:ee:ff"
    assert any("could not be parsed" in r.message for r in caplog.records)


def test_split_loader_malformed_primary_logs_error_treats_as_empty(tmp_path, caplog):
    """A typo in the operator's primary file logs ERROR rather than crashing
    the daemon. The startup ERROR line is the surfacing path for operators."""
    primary = tmp_path / "allowlist.yaml"
    _write_yaml(primary, ":::not valid yaml:::")
    with caplog.at_level(logging.ERROR, logger="lynceus.allowlist"):
        al = load_allowlist(str(primary))
    assert al.entries == []
    assert any("could not be parsed" in r.message for r in caplog.records)


def test_split_loader_ui_absent_is_normal(tmp_path):
    """Pre-first-UI-write state: only the primary exists. No warning, no error,
    behavior identical to the single-file world."""
    primary = tmp_path / "allowlist.yaml"
    _write_yaml(
        primary,
        "entries:\n  - pattern: aa:bb:cc:dd:ee:ff\n    pattern_type: mac\n",
    )
    al = load_allowlist(str(primary))
    assert len(al.entries) == 1


# --------------------------- writer helpers ----------------------------------


def test_add_ui_entry_creates_file_with_one_entry(tmp_path):
    ui = tmp_path / "allowlist_ui.yaml"
    entry = AllowlistEntry(
        pattern="aa:bb:cc:dd:ee:ff",
        pattern_type="mac",
        added_at=1_799_000_000,
    )
    add_ui_entry(ui, entry)
    assert ui.exists()
    al = Allowlist(**__import__("yaml").safe_load(ui.read_text(encoding="utf-8")))
    assert len(al.entries) == 1
    assert al.entries[0].pattern == "aa:bb:cc:dd:ee:ff"
    assert al.entries[0].added_at == 1_799_000_000


def test_add_ui_entry_appends_to_existing_file(tmp_path):
    ui = tmp_path / "allowlist_ui.yaml"
    add_ui_entry(ui, AllowlistEntry(pattern="aa:bb:cc:dd:ee:01", pattern_type="mac"))
    add_ui_entry(ui, AllowlistEntry(pattern="aa:bb:cc:dd:ee:02", pattern_type="mac"))
    al = Allowlist(**__import__("yaml").safe_load(ui.read_text(encoding="utf-8")))
    assert len(al.entries) == 2
    assert {e.pattern for e in al.entries} == {
        "aa:bb:cc:dd:ee:01",
        "aa:bb:cc:dd:ee:02",
    }


def test_add_ui_entry_creates_parent_directory(tmp_path):
    """The daemon-managed sibling may sit in a directory the daemon
    hasn't materialized yet (e.g., a fresh install where /etc/lynceus
    exists but no UI writes have happened). add_ui_entry must mkdir
    rather than fail."""
    ui = tmp_path / "nested" / "allowlist_ui.yaml"
    add_ui_entry(ui, AllowlistEntry(pattern="aa:bb:cc:dd:ee:ff", pattern_type="mac"))
    assert ui.exists()


def test_remove_ui_entry_removes_and_returns_true(tmp_path):
    ui = tmp_path / "allowlist_ui.yaml"
    add_ui_entry(ui, AllowlistEntry(pattern="aa:bb:cc:dd:ee:01", pattern_type="mac"))
    add_ui_entry(ui, AllowlistEntry(pattern="aa:bb:cc:dd:ee:02", pattern_type="mac"))
    removed = remove_ui_entry(ui, "aa:bb:cc:dd:ee:01", "mac")
    assert removed is True
    al = Allowlist(**__import__("yaml").safe_load(ui.read_text(encoding="utf-8")))
    assert len(al.entries) == 1
    assert al.entries[0].pattern == "aa:bb:cc:dd:ee:02"


def test_remove_ui_entry_on_missing_pattern_returns_false(tmp_path):
    ui = tmp_path / "allowlist_ui.yaml"
    add_ui_entry(ui, AllowlistEntry(pattern="aa:bb:cc:dd:ee:01", pattern_type="mac"))
    assert remove_ui_entry(ui, "00:00:00:00:00:00", "mac") is False
    # File untouched.
    al = Allowlist(**__import__("yaml").safe_load(ui.read_text(encoding="utf-8")))
    assert len(al.entries) == 1


def test_remove_ui_entry_on_absent_file_returns_false(tmp_path):
    ui = tmp_path / "does_not_exist.yaml"
    assert remove_ui_entry(ui, "anything", "mac") is False


def test_writer_does_not_touch_primary_file(tmp_path):
    """The hard invariant: daemon never writes to the operator-curated
    primary file. add_ui_entry writes only to the sibling."""
    primary = tmp_path / "allowlist.yaml"
    primary_text = (
        "# Operator comment that must be preserved.\n"
        "entries:\n  - pattern: aa:bb:cc:dd:ee:ff\n    pattern_type: mac\n"
    )
    primary.write_text(primary_text, encoding="utf-8")
    primary_mtime_before = primary.stat().st_mtime
    ui = derive_ui_path(primary)
    add_ui_entry(ui, AllowlistEntry(pattern="11:22:33:44:55:66", pattern_type="mac"))
    # Primary byte-for-byte unchanged (including the operator comment).
    assert primary.read_text(encoding="utf-8") == primary_text
    # And its mtime did not move.
    assert primary.stat().st_mtime == primary_mtime_before
