"""A device-chosen attribute must not silence an explicit watchlist hit.

⭐ Why this file exists. `Allowlist._entry_matches` returns True if **any one**
attribute matches, and several of those attributes are free text the device
puts in its own advertisement. So an attacker only had to name themselves after
something the operator had allowlisted.

Measured before the fix — operator allowlists their own headphones by name,
which is the documented use of `ble_local_name`:

    the real headphones                mac=aa:bb:cc:dd:ee:01  suppressed=YES
    AN ATTACKER broadcasting that name mac=de:ad:be:ef:00:99  suppressed=YES
    the same attacker, not spoofing    mac=de:ad:be:ef:00:99  suppressed=no

The operator's own HIGH-severity watchlist entry for that MAC went silent. In a
tool whose entire job is noticing who is following you, that is **detection
evasion**, not noise control.

⛔ **Tightening allowlisting to MAC-only is not the fix and would break the
feature.** BLE devices use randomised, rotating addresses — which is *precisely
why* name/UUID/manufacturer matching exists. The fix has to keep soft matching
and bound what it is allowed to silence.

⭐ **The code already computed the answer and threw it away.** On an allowlist
hit, `process_observation` re-evaluates the rules purely to LOG the watchlist
hits it just suppressed — an INFO line that exists because someone judged those
events to matter. Turning that log line into a decision is the whole change.

⚠️ Both directions are pinned below. "Ignore soft allowlist entries entirely"
would satisfy the attacker test perfectly while destroying the legitimate
everyday use, so `test_a_soft_entry_still_suppresses_ambient_noise` is the one
that stops the over-correction.
"""

from __future__ import annotations

import re

import pytest

from lynceus.allowlist import (
    HARD_ALLOWLIST_PATTERN_TYPES,
    SOFT_ALLOWLIST_PATTERN_TYPES,
    Allowlist,
    AllowlistEntry,
    is_soft_attribute,
)
from lynceus.config import Config
from lynceus.db import Database
from lynceus.kismet import DeviceObservation
from lynceus.poller import process_observation
from lynceus.rules import load_ruleset

ATTACKER = "de:ad:be:ef:00:99"
HEADPHONES = "aa:bb:cc:dd:ee:01"
SPOOFED_NAME = "Kev's AirPods"


class RecordingNotifier:
    """Records what it was handed. A double that cannot fail would hide the
    difference between 'suppressed' and 'delivered but unobservable'."""

    def __init__(self) -> None:
        self.sent: list[tuple[str, str]] = []

    def send(self, severity, title, message, priority_override=None) -> bool:
        self.sent.append((severity, title))
        return True


@pytest.fixture
def pipeline(tmp_path):
    db = Database(str(tmp_path / "d.db"))
    # The operator deliberately watchlists the attacker's MAC at HIGH.
    db.add_watchlist(
        pattern=ATTACKER, pattern_type="mac", severity="high", description="stalker"
    )
    config = Config(db_path=str(tmp_path / "d.db"), rules_path="config/rules.yaml")
    ruleset = load_ruleset(config.rules_path)
    yield db, config, ruleset
    db.close()


def _observe(db, config, ruleset, allowlist, notifier, *, mac, name, ts=1_700_000_000):
    process_observation(
        DeviceObservation(
            mac=mac,
            device_type="ble",
            first_seen=ts,
            last_seen=ts,
            rssi=-40,
            ssid=None,
            oui_vendor=None,
            is_randomized=False,
            ble_local_name=name,
        ),
        db,
        config,
        ts,
        effective_location_id="home",
        effective_location_label="Home",
        ensured_locations=set(),
        processed_counter=[0],
        admitted_counter=[0],
        ruleset=ruleset,
        clock_trusted=True,
        allowlist=allowlist,
        notifier=notifier,
    )


def _name_allowlist() -> Allowlist:
    """The documented, legitimate use: silence my own headphones by name."""
    return Allowlist(
        entries=[
            AllowlistEntry(
                pattern=SPOOFED_NAME,
                pattern_type="ble_local_name",
                note="my own headphones",
            )
        ]
    )


# --- the defect ------------------------------------------------------------


def test_a_spoofed_name_cannot_silence_a_watchlisted_mac(pipeline):
    """The measured attack. Before the fix this produced zero alerts."""
    db, config, ruleset = pipeline
    notifier = RecordingNotifier()

    _observe(
        db, config, ruleset, _name_allowlist(), notifier,
        mac=ATTACKER, name=SPOOFED_NAME,
    )

    alerts = db._conn.execute("SELECT rule_name, severity FROM alerts").fetchall()
    assert alerts, (
        "an attacker broadcasting an allowlisted local name silenced the "
        "operator's own HIGH-severity watchlist entry for their MAC"
    )
    assert any(row[1] == "high" for row in alerts)
    # Presence beside the absence: the alert must actually have been DELIVERED,
    # not merely written. A row with no notification is its own failure mode.
    assert notifier.sent, "the alert was written but never sent"


# --- the over-correction, which is what stops "just ignore soft entries" ----


def test_a_soft_entry_still_suppresses_ambient_noise(pipeline):
    """A soft match must keep working for the case it exists for.

    The operator's headphones are NOT watchlisted; the allowlist entry should
    still stop them generating new-device noise. A fix that simply ignored
    soft entries would pass the attacker test above and break this.
    """
    db, config, ruleset = pipeline
    notifier = RecordingNotifier()

    _observe(
        db, config, ruleset, _name_allowlist(), notifier,
        mac=HEADPHONES, name=SPOOFED_NAME,
    )

    alerts = db._conn.execute("SELECT rule_name FROM alerts").fetchall()
    assert alerts == [], (
        f"the operator's own headphones generated {alerts} — a soft allowlist "
        f"entry must still suppress ambient noise for a device that is NOT "
        f"watchlisted"
    )
    assert notifier.sent == []


def test_a_hard_entry_still_suppresses_a_watchlist_hit(pipeline):
    """Unchanged behaviour for radio-level identifiers.

    Allowlisting a MAC is a deliberate statement about a specific device, and
    an attacker cannot present it without spoofing the address it transmits
    on. That keeps full suppressing power.
    """
    db, config, ruleset = pipeline
    notifier = RecordingNotifier()
    hard = Allowlist(
        entries=[AllowlistEntry(pattern=ATTACKER, pattern_type="mac", note="mine")]
    )

    _observe(db, config, ruleset, hard, notifier, mac=ATTACKER, name="whatever")

    assert db._conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0
    assert notifier.sent == []


# --- the classification itself ---------------------------------------------


def test_every_schema_pattern_type_is_classified():
    """Derived from the live CHECK constraint, not a hardcoded list.

    ⚠️ A new pattern_type must not silently inherit full suppressing power.
    Parsed from `sqlite_master` so the two sides of this assertion have
    genuinely independent sources — the same reason the watchlist manifest
    guard reads the schema rather than a copy of itself.
    """
    import os
    import tempfile

    db = Database(os.path.join(tempfile.mkdtemp(), "c.db"))
    try:
        sql = db._conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='watchlist'"
        ).fetchone()[0]
        match = re.search(r"CHECK\(pattern_type IN \((.*?)\)\)", sql, re.S)
        assert match is not None, "could not find the pattern_type CHECK constraint"
        schema = set(re.findall(r"'(\w+)'", match.group(1)))
    finally:
        db.close()

    assert len(schema) >= 8, f"implausibly few pattern types parsed: {sorted(schema)}"
    classified = HARD_ALLOWLIST_PATTERN_TYPES | SOFT_ALLOWLIST_PATTERN_TYPES
    assert schema <= classified, (
        f"unclassified allowlist pattern type(s): {sorted(schema - classified)}. "
        f"Decide whether each is a radio-level identifier (may suppress a "
        f"watchlist hit) or a device-chosen attribute (may not)."
    )


def test_hard_and_soft_do_not_overlap():
    overlap = HARD_ALLOWLIST_PATTERN_TYPES & SOFT_ALLOWLIST_PATTERN_TYPES
    assert not overlap, f"a pattern type is both hard and soft: {sorted(overlap)}"


@pytest.mark.parametrize("pattern_type", sorted(HARD_ALLOWLIST_PATTERN_TYPES))
def test_radio_level_identifiers_are_hard(pattern_type):
    assert not is_soft_attribute(pattern_type)


@pytest.mark.parametrize("pattern_type", sorted(SOFT_ALLOWLIST_PATTERN_TYPES))
def test_device_chosen_attributes_are_soft(pattern_type):
    assert is_soft_attribute(pattern_type)


def test_an_unknown_pattern_type_defaults_to_SOFT():
    """Fail closed. A type nobody classified must not inherit the power to
    silence a watchlist hit just because it was added later."""
    assert is_soft_attribute("some_future_pattern_type")


# --- the scope of this policy, pinned so it is not mistaken for broken -------


def test_the_policy_only_bites_on_hand_edited_primary_entries():
    """⚠️ Where this fix does and does not apply — recorded deliberately.

    The web UI's "allowlist this device" path writes `pattern_type="mac"`, so
    **every UI-created suppression is a HARD type** and keeps full suppressing
    power under this policy. Soft types only ever arrive from the operator's
    hand-edited primary allowlist file.

    That is the intended design — a UI click names a specific device by its
    address, which is exactly the deliberate, radio-level statement the hard
    class is for. But it means someone testing this through the UI will see no
    behaviour change and may conclude the fix does not work.

    Pinned as a test rather than a comment because a comment cannot fail if the
    UI path ever starts writing a soft type, which would silently widen what a
    single click can silence.
    """
    assert not is_soft_attribute("mac"), (
        "the UI writes pattern_type='mac'; if that became soft, every UI "
        "suppression would stop silencing watchlist hits"
    )
    assert is_soft_attribute("ble_local_name")
