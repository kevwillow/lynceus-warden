"""Which matching allowlist entry answers for a device — and why it matters.

⭐ Why this file exists. `Allowlist.is_allowed` returns ONE entry, and since the
hard/soft split (#82) that entry's `pattern_type` is what decides whether
suppression happens at all: `poller.process_observation` asks
`is_soft_attribute` about *the returned entry*. While `is_allowed` returned the
first match in file order, an unrelated SOFT entry sitting above a HARD one
answered for the device — and the operator's explicit "ignore this MAC" did
nothing.

Measured on the shipped ruleset, one device, one watchlist row, the same two
allowlist entries; only the FILE ORDER differs:

    hard `mac` entry only                 -> suppressed
    hard `mac` first, then soft `name`    -> suppressed
    soft `name` first, then hard `mac`    -> *** 2 ALERTS, 2 SENT ***

Nothing surfaced the ordering dependency — and `allowlist.py`'s module docstring
positively asserted that order does not affect matching semantics, which is the
kind of prose that stops anyone looking.

⚠️ Both directions are pinned. The obvious over-corrections each pass the defect
test above while breaking something real:

  * "return the hard entry, or None"      -> kills soft suppression entirely
                                             (test_a_soft_only_allowlist_...)
  * "prefer hard, ignoring expiry"        -> a LAPSED snooze starts silencing
                                             watchlist hits
                                             (test_an_expired_hard_entry_...)
  * "return a hard entry if one exists"   -> suppresses devices that match
                                             nothing (test_a_hard_entry_that_...)

⚠️ `SOFT_ALLOWLIST_PATTERN_TYPES` deliberately names two types the allowlist
cannot store (`ssid_pattern`, `imei_tac`). That is not drift: the classification
is checked against the WATCHLIST schema's ten types so a future allowlist type
cannot inherit hard power silently, while `AllowlistPatternType` is the eight an
operator can actually write. Everything below derives from the storable eight.
"""

from __future__ import annotations

import typing
from pathlib import Path

import pytest

from lynceus.allowlist import (
    HARD_ALLOWLIST_PATTERN_TYPES,
    SOFT_ALLOWLIST_PATTERN_TYPES,
    Allowlist,
    AllowlistEntry,
    AllowlistPatternType,
)
from lynceus.config import Config
from lynceus.db import Database
from lynceus.kismet import DeviceObservation
from lynceus.poller import process_observation
from lynceus.rules import load_ruleset

REPO_ROOT = Path(__file__).resolve().parents[1]
SHIPPED_RULES = str(REPO_ROOT / "config" / "rules.yaml")

NOW = 1_700_000_000
# ⚠️ A genuine universally-administered OUI. `de:ad:be` and `aa:bb:cc` both have
# the locally-administered bit set and are discarded by the reserved-OUI guard
# in rules.py, which reads exactly like "the watchlist row never matched".
TARGET = "ac:de:48:11:22:33"

#: The types an operator can actually STORE in an allowlist, derived from the
#: Literal rather than transcribed — a new type must land in the sweep below,
#: not be silently skipped by a hand-copied list.
STORABLE = frozenset(typing.get_args(AllowlistPatternType))

#: pattern_type -> (stored pattern, observation kwargs matching it EXACTLY).
#: Every case matches the SAME device, so a hard and a soft entry can both be
#: live for one observation — which is the whole situation under test.
CASES: dict[str, tuple[str, dict]] = {
    "mac": (TARGET, {}),
    "oui": ("ac:de:48", {}),
    # /24 is rejected by design (that shape is an OUI); only /28 and /36 parse.
    "mac_range": ("ac:de:48:1/28", {}),
    "ssid": ("MyTargetNet", {"ssid": "MyTargetNet"}),
    "ble_uuid": (
        "0000fd5a-0000-1000-8000-00805f9b34fb",
        {"ble_service_uuids": ("0000fd5a-0000-1000-8000-00805f9b34fb",)},
    ),
    "ble_manufacturer_id": ("004c", {"ble_manufacturer_id": "004c"}),
    "ble_local_name": ("TrackerTag", {"ble_local_name": "TrackerTag"}),
    # An LCP prefix; the captured wire serial is longer, so the matcher is
    # leading-substring. Equality here would never match and would read as a
    # dead type.
    "drone_id_prefix": ("1581F", {"drone_id_prefix": "1581FABC"}),
}


def test_the_case_map_covers_every_storable_pattern_type():
    """The guard that keeps the sweep below honest.

    A hand-copied derivation looks derived and isn't: the watchlist round
    reported "6 of 9" for what was 7 of 10 because exactly this pairing was
    missing.
    """
    assert set(CASES) == STORABLE, (
        f"case map drifted from AllowlistPatternType: "
        f"missing={sorted(STORABLE - set(CASES))}, "
        f"extra={sorted(set(CASES) - STORABLE)}"
    )
    assert len(STORABLE) >= 8, f"implausibly few storable types: {sorted(STORABLE)}"


class RecordingNotifier:
    """Records what it was handed. A double that cannot fail would hide the
    difference between 'suppressed' and 'delivered but unobservable'."""

    def __init__(self) -> None:
        self.sent: list[tuple[str, str]] = []

    def send(self, severity, title, message, priority_override=None) -> bool:
        self.sent.append((severity, title))
        return True


def _entry(pattern_type: str, **kw) -> AllowlistEntry:
    pattern, _ = CASES[pattern_type]
    return AllowlistEntry(pattern=pattern, pattern_type=pattern_type, **kw)


def _observation(pattern_types) -> DeviceObservation:
    """One device carrying every attribute the named types match on."""
    kw: dict = {}
    for pt in pattern_types:
        kw.update(CASES[pt][1])
    return DeviceObservation(
        mac=TARGET,
        device_type="ble",
        first_seen=NOW,
        last_seen=NOW,
        rssi=-40,
        ssid=kw.pop("ssid", None),
        oui_vendor=None,
        is_randomized=False,
        **kw,
    )


#: Bumped per `_observe` call so every run gets its OWN database.
#: ⚠️ Not cosmetic. Keying the filename on the arguments collided whenever one
#: test observed twice with the same entry count, and the second call then ran
#: against a database where the device was no longer NEW and the first call's
#: alert rows were still present — a contaminated result that looks exactly like
#: a suppression failure. Caught by `test_an_expired_hard_entry_...`.
_RUN = [0]


def _observe(tmp_path, entries, obs, *, watchlisted: bool = True):
    """Drive the real pipeline; return (alert rows, notifier sends).

    ``watchlisted`` seeds the operator's own HIGH-severity watchlist row for
    TARGET, so there is an explicit hit for a soft entry to fail to silence.
    """
    _RUN[0] += 1
    db_path = str(tmp_path / f"{'w' if watchlisted else 'n'}-{_RUN[0]}.db")
    db = Database(db_path)
    try:
        if watchlisted:
            db.add_watchlist(
                pattern=TARGET, pattern_type="mac", severity="high", description="stalker"
            )
        config = Config(db_path=db_path, rules_path=SHIPPED_RULES)
        notifier = RecordingNotifier()
        process_observation(
            obs,
            db,
            config,
            NOW,
            effective_location_id="home",
            effective_location_label="Home",
            ensured_locations=set(),
            processed_counter=[0],
            admitted_counter=[0],
            ruleset=load_ruleset(config.rules_path),
            clock_trusted=True,
            allowlist=Allowlist(entries=entries),
            notifier=notifier,
        )
        alerts = db._conn.execute("SELECT rule_name, severity FROM alerts").fetchall()
    finally:
        db.close()
    return alerts, notifier.sent


# --- the defect ------------------------------------------------------------


def test_a_soft_entry_above_a_hard_one_does_not_defeat_it(tmp_path):
    """The measured defect. Before the fix this produced 2 alerts and 2 sends."""
    obs = _observation(["ble_local_name"])
    soft = _entry("ble_local_name", note="my headphones")
    hard = _entry("mac", note="my own device")

    alerts, sent = _observe(tmp_path, [soft, hard], obs)

    assert alerts == [], (
        f"an explicit hard `mac` allowlist entry was defeated by an unrelated "
        f"soft entry sitting above it in the file; alerts fired: {alerts}"
    )
    assert sent == []


def test_the_control_the_test_above_depends_on(tmp_path):
    """⚠️ The presence assertion. Without it, the absence above is satisfied by
    a pipeline that alerts on nothing at all — the failure mode that would make
    every result in this file a confident fiction.

    Same device, same watchlist row, the SOFT entry alone: the watchlist hit
    must still fire, because a device-chosen attribute may not silence it.
    """
    obs = _observation(["ble_local_name"])
    alerts, sent = _observe(tmp_path, [_entry("ble_local_name")], obs)

    assert alerts, "the pipeline produced no alert at all; every absence assertion here is vacuous"
    assert any(row[1] == "high" for row in alerts), f"expected the HIGH watchlist hit, got {alerts}"
    assert sent, "the alert was written but never sent"


@pytest.mark.parametrize("hard_type", sorted(HARD_ALLOWLIST_PATTERN_TYPES & STORABLE))
@pytest.mark.parametrize("soft_type", sorted(SOFT_ALLOWLIST_PATTERN_TYPES & STORABLE))
def test_no_soft_type_can_outrank_any_hard_type(soft_type, hard_type, tmp_path):
    """The sweep, over the derived cross-product rather than one example pair.

    Every (soft, hard) combination an operator could write, with the soft entry
    FIRST — the losing order. The hard entry must answer in all of them.
    """
    obs = _observation([soft_type, hard_type])
    soft, hard = _entry(soft_type), _entry(hard_type)

    # Control: both entries must genuinely match this device, or "suppressed"
    # below would just mean "the soft entry never applied".
    assert Allowlist(entries=[soft]).is_allowed(obs, now_ts=NOW) is not None, (
        f"control invalid: the {soft_type} entry does not match the observation"
    )
    assert Allowlist(entries=[hard]).is_allowed(obs, now_ts=NOW) is not None, (
        f"control invalid: the {hard_type} entry does not match the observation"
    )

    matched = Allowlist(entries=[soft, hard]).is_allowed(obs, now_ts=NOW)
    assert matched is not None and matched.pattern_type == hard_type, (
        f"a soft `{soft_type}` entry answered for a device the operator had "
        f"allowlisted by `{hard_type}`; got {matched and matched.pattern_type!r}"
    )

    alerts, _ = _observe(tmp_path, [soft, hard], obs)
    assert alerts == [], f"{soft_type} above {hard_type} still leaked alerts: {alerts}"


def test_the_sweep_above_covers_the_whole_cross_product():
    """`assert seen >= N` for the parametrised sweep — a filter that silently
    emptied either set would leave zero cases running and a green suite."""
    hard = HARD_ALLOWLIST_PATTERN_TYPES & STORABLE
    soft = SOFT_ALLOWLIST_PATTERN_TYPES & STORABLE
    assert len(hard) >= 3, f"too few storable hard types: {sorted(hard)}"
    assert len(soft) >= 5, f"too few storable soft types: {sorted(soft)}"
    # Every storable type is on exactly one side; a new one must be classified.
    assert hard | soft == STORABLE, (
        f"storable pattern types missing a hard/soft classification: "
        f"{sorted(STORABLE - (hard | soft))}"
    )
    assert not hard & soft


def test_order_does_not_change_the_outcome(tmp_path):
    """The promise `allowlist.py`'s module docstring makes, asserted rather than
    stated. Both permutations of the same two entries, same device."""
    obs = _observation(["ble_local_name"])
    soft, hard = _entry("ble_local_name"), _entry("mac")

    soft_first = Allowlist(entries=[soft, hard]).is_allowed(obs, now_ts=NOW)
    hard_first = Allowlist(entries=[hard, soft]).is_allowed(obs, now_ts=NOW)

    assert soft_first is not None and hard_first is not None
    assert soft_first.pattern_type == hard_first.pattern_type == "mac"


# --- the over-corrections --------------------------------------------------


def test_a_soft_only_allowlist_still_suppresses_ambient_noise(tmp_path):
    """Stops "return the hard entry, or None".

    The operator's headphones are NOT watchlisted; the soft entry must still
    stop them generating new-device noise. That is the everyday use of soft
    matching and a hard-only fix would silently destroy it while passing every
    test above.
    """
    obs = _observation(["ble_local_name"])
    alerts, sent = _observe(tmp_path, [_entry("ble_local_name")], obs, watchlisted=False)

    assert alerts == [], f"a soft-only allowlist stopped suppressing ambient noise: {alerts}"
    assert sent == []


def test_an_expired_hard_entry_does_not_outrank_a_live_soft_one(tmp_path):
    """Stops "prefer hard, ignoring expiry".

    A lapsed snooze is not a match at all. If preference were applied before
    expiry, an expired hard entry would start silencing watchlist hits — the
    same defect pointing the other way, and strictly worse than the original.
    """
    obs = _observation(["ble_local_name"])
    expired_hard = _entry("mac", expires_at=NOW - 1, added_at=NOW - 100)
    live_soft = _entry("ble_local_name")

    matched = Allowlist(entries=[live_soft, expired_hard]).is_allowed(obs, now_ts=NOW)
    assert matched is not None and matched.pattern_type == "ble_local_name", (
        f"an EXPIRED hard entry answered for the device; got "
        f"{matched and matched.pattern_type!r}"
    )

    # Behaviour, not just the returned object: soft semantics must apply, so
    # the operator's watchlist hit is NOT silenced.
    alerts, sent = _observe(tmp_path, [live_soft, expired_hard], obs)
    assert alerts, "an expired hard entry silenced a watchlist hit"
    assert sent

    # Presence beside absence: the same hard entry UNEXPIRED does suppress, so
    # the assertion above is about expiry and not about the entry never matching.
    live_hard = _entry("mac")
    alerts_live, _ = _observe(tmp_path, [live_soft, live_hard], obs)
    assert alerts_live == []


def test_a_hard_entry_that_does_not_match_is_not_returned(tmp_path):
    """Stops "return a hard entry if one exists".

    A preference implemented as "scan for any hard entry" rather than "any
    MATCHING hard entry" would suppress a device the operator never
    allowlisted — silently, and in the dangerous direction.
    """
    obs = _observation(["ble_local_name"])
    other_device = AllowlistEntry(
        pattern="ac:de:48:99:99:99", pattern_type="mac", note="a different device"
    )

    assert Allowlist(entries=[other_device]).is_allowed(obs, now_ts=NOW) is None

    # With a matching soft entry beside it, the SOFT one must answer — the
    # non-matching hard entry is irrelevant, not preferred.
    matched = Allowlist(entries=[other_device, _entry("ble_local_name")]).is_allowed(
        obs, now_ts=NOW
    )
    assert matched is not None and matched.pattern_type == "ble_local_name"

    # And the watchlist hit still fires, because soft semantics apply.
    alerts, _ = _observe(tmp_path, [other_device, _entry("ble_local_name")], obs)
    assert alerts


def test_position_still_breaks_ties_within_a_class(tmp_path):
    """The unchanged half, pinned so a fix cannot quietly reorder soft matches.

    Two soft entries both match; the FIRST still answers. The poller reports
    the matched entry's `expires_at` on the suppression audit line, so shuffling
    which soft entry wins would change operator-visible output for no reason.
    """
    obs = _observation(["ble_local_name", "ble_manufacturer_id"])
    first = _entry("ble_local_name", expires_at=NOW + 3600, added_at=NOW)
    second = _entry("ble_manufacturer_id", expires_at=NOW + 7200, added_at=NOW)

    matched = Allowlist(entries=[first, second]).is_allowed(obs, now_ts=NOW)
    assert matched is not None and matched.pattern_type == "ble_local_name"

    reversed_match = Allowlist(entries=[second, first]).is_allowed(obs, now_ts=NOW)
    assert reversed_match is not None and reversed_match.pattern_type == "ble_manufacturer_id"
