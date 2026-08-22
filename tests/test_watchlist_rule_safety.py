"""A delegation rule must not ship enabled while its corpus matches bystanders.

BLE-G1 in `BACKLOG.md` is marked BLOCKING and its enforcement is a commented-out
line in `config/rules.yaml`. A comment is not a safety boundary. This is.

The harm is specific and it is the one this project exists to oppose. A rule that
alerts on every passer-by's phone is not a detection: it trains the operator to
ignore alerts, and it is itself surveillance of bystanders. Measured 2026-08-22
against the shipped `default_watchlist.csv` (41,508 rows, schema_version=31):

    pattern_type          rows  categorised   what enabling it would alert on
    ble_manufacturer_id   4684    4 (0.09%)   every Apple, Samsung, Google and
                                              Microsoft device in range
    ble_uuid               140  130 (92.9%)   looks clean, but the 10
                                              uncategorised rows are Apple
                                              Find My, Tile, Samsung and Google

⇒ **A ratio is the wrong predicate.** `ble_uuid` is 92.9% categorised and still
storms, because one row in it is Apple's `fd44`. So this guard is keyed on the
specific identifiers that belong to consumer platforms, not on how tidy the
corpus looks in aggregate.

⭐ **It is a take-effect pair, not a blocklist.** The check is "an ENABLED
delegation rule must not reach an UNCATEGORISED consumer-platform row". If Argus
later categorises `004c` as something actionable, or curates it out, enabling the
rule passes. The rule is not banned; the combination is. `test_a_curated_corpus_
permits_the_same_rule` is the half that proves that, and without it this file
would be satisfied by refusing everything.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

import pytest

from lynceus.cli.import_argus import IDENTIFIER_TYPE_MAP
from lynceus.kismet import normalize_uuid
from lynceus.patterns import normalize_pattern
from lynceus.rules import load_ruleset

REPO = Path(__file__).resolve().parents[1]
SHIPPED_RULES = REPO / "config" / "rules.yaml"
SHIPPED_CORPUS = REPO / "src" / "lynceus" / "data" / "default_watchlist.csv"

#: Identifiers owned by consumer platforms. Every one of these is worn by
#: hundreds of devices in any populated place, so a watchlist row carrying one is
#: a bystander detector rather than a surveillance detector.
#:
#: ⚠️ This list is deliberately short and each entry says who and why. It is not
#: an attempt to enumerate consumer Bluetooth. It names the ones present in the
#: shipped corpus today, and `test_the_named_identifiers_are_still_in_the_corpus`
#: fails if a whole section of it goes stale.
CONSUMER_PLATFORM_IDENTIFIERS: dict[str, dict[str, str]] = {
    "ble_manufacturer_id": {
        "004c": "Apple. Every iPhone, iPad, Mac, Watch and pair of AirPods in range.",
        "0075": "Samsung. Every Galaxy phone and pair of Buds in range.",
        "00e0": "Google. Every Pixel, and every Fast Pair accessory.",
        "0006": "Microsoft. Every Surface and Windows laptop advertising Swift Pair.",
    },
    "ble_uuid": {
        "fd44": "Apple Find My and Nearby. Worn by essentially every Apple device.",
        "fd5a": "Samsung.",
        "fe9f": "Google.",
        "7dfc9000": "Tile. A consumer tracker, so a match is usually its owner.",
    },
}

#: Which watchlist ``pattern_type`` rows a delegation rule_type consults.
#:
#: ⚠️ ``watchlist_ssid`` dispatches BOTH shapes from one rule, which is why the
#: values are tuples. Anything missing from here is caught by
#: `test_every_delegation_rule_type_is_mapped`, so a new delegation rule type
#: cannot quietly escape this guard.
RULE_TYPE_PATTERN_TYPES: dict[str, tuple[str, ...]] = {
    "watchlist_mac": ("mac",),
    "watchlist_oui": ("oui",),
    "watchlist_ssid": ("ssid", "ssid_pattern"),
    "watchlist_mac_range": ("mac_range",),
    "ble_uuid": ("ble_uuid",),
    "watchlist_ble_manufacturer_id": ("ble_manufacturer_id",),
    "watchlist_drone_id_prefix": ("drone_id_prefix",),
    "watchlist_ble_local_name": ("ble_local_name",),
}

#: Rule types that never delegate to the watchlist, so no corpus reaches them.
NON_DELEGATING_RULE_TYPES = frozenset({
    "new_non_randomized_device",
    "watchful_recurrence",
    "ble_device_class",
})


@dataclass(frozen=True)
class Exposure:
    """One enabled rule that can reach one uncategorised consumer identifier."""

    rule_name: str
    pattern_type: str
    identifier: str
    who: str

    def __str__(self) -> str:
        return (
            f"rule {self.rule_name!r} delegates to {self.pattern_type} rows, which "
            f"include the uncategorised identifier {self.identifier!r}: {self.who}"
        )


def _normalise(pattern_type: str, identifier: str) -> str | None:
    """Canonicalise using the APP's normaliser, never a local reimplementation.

    ⛔ The corpus carries `0x004C` and `0x4C` for the same company, and `fd44`,
    `0000fd44` and the full 128-bit form for the same UUID. A guard with its own
    string handling would match one rendering and miss the others, which is the
    failure mode this repo keeps recording. `normalize_pattern` and
    `normalize_uuid` are what the matcher itself uses.
    """
    try:
        if pattern_type == "ble_uuid":
            return normalize_uuid(identifier)
        return normalize_pattern(pattern_type, identifier)
    except ValueError:
        return None


def load_corpus(path: Path) -> list[dict[str, str]]:
    """Rows of the shipped Argus CSV, past its leading ``# meta:`` line."""
    with path.open(newline="", encoding="utf-8") as fh:
        fh.readline()
        return list(csv.DictReader(fh))


def enabled_delegation_rules(rules) -> list:
    """Rules that ship enabled AND take their patterns from the watchlist.

    Empty ``patterns`` is the delegation idiom: the rule matches whatever the
    watchlist holds for its pattern type. A rule with explicit patterns can only
    match what an author wrote down, so it is not exposed to corpus drift.
    """
    return [
        r
        for r in rules
        if not r.patterns and r.rule_type not in NON_DELEGATING_RULE_TYPES
    ]


def bystander_exposure(rules, corpus: list[dict[str, str]]) -> list[Exposure]:
    """Every enabled delegation rule that can reach an uncategorised consumer row.

    ``device_category != 'unknown'`` is treated as Argus having made a positive
    statement about the row. An uncategorised row carrying a consumer platform's
    identifier is the storm case.
    """
    by_pattern_type: dict[str, set[str]] = {}
    for row in corpus:
        pattern_type = IDENTIFIER_TYPE_MAP.get(row["identifier_type"])
        if pattern_type is None or row["device_category"] != "unknown":
            continue
        canonical = _normalise(pattern_type, row["identifier"])
        if canonical is not None:
            by_pattern_type.setdefault(pattern_type, set()).add(canonical)

    found: list[Exposure] = []
    for rule in enabled_delegation_rules(rules):
        for pattern_type in RULE_TYPE_PATTERN_TYPES.get(rule.rule_type, ()):
            uncategorised = by_pattern_type.get(pattern_type, set())
            for identifier, who in CONSUMER_PLATFORM_IDENTIFIERS.get(pattern_type, {}).items():
                canonical = _normalise(pattern_type, identifier)
                if canonical is not None and canonical in uncategorised:
                    found.append(Exposure(rule.name, pattern_type, identifier, who))
    return found


# --------------------------------------------------------------------------
# The guard itself
# --------------------------------------------------------------------------


def test_no_shipped_rule_alerts_on_bystanders():
    """The one that enforces BLE-G1 on the files this repo actually ships."""
    ruleset = load_ruleset(str(SHIPPED_RULES))
    corpus = load_corpus(SHIPPED_CORPUS)

    exposures = bystander_exposure(ruleset.rules, corpus)
    assert not exposures, (
        "the shipped config would alert on bystanders:\n  "
        + "\n  ".join(str(e) for e in exposures)
        + "\n\nSee BLE-G1 in BACKLOG.md. Enabling a delegation rule needs its corpus "
        "curated first, not just the line uncommented."
    )


def test_the_shipped_config_still_has_enabled_delegation_rules():
    """Non-vacuity. The guard above passes trivially if nothing delegates.

    Somebody commenting out every delegation rule would make this file green for
    a reason that has nothing to do with safety.
    """
    ruleset = load_ruleset(str(SHIPPED_RULES))
    enabled = enabled_delegation_rules(ruleset.rules)
    assert enabled, "no delegation rule ships enabled, so the guard above proves nothing"


def test_the_named_identifiers_are_still_in_the_corpus():
    """Non-vacuity, the other half. A stale list guards nothing.

    If Argus stops shipping any of a pattern type's consumer identifiers, the
    guard would pass for a reason unrelated to the rule being safe. Per pattern
    type rather than per identifier, so one id being curated out does not turn
    this red.
    """
    corpus = load_corpus(SHIPPED_CORPUS)
    present: dict[str, set[str]] = {}
    for row in corpus:
        pattern_type = IDENTIFIER_TYPE_MAP.get(row["identifier_type"])
        if pattern_type is None:
            continue
        canonical = _normalise(pattern_type, row["identifier"])
        if canonical is not None:
            present.setdefault(pattern_type, set()).add(canonical)

    for pattern_type, identifiers in CONSUMER_PLATFORM_IDENTIFIERS.items():
        canonical = {
            _normalise(pattern_type, i) for i in identifiers
        } - {None}
        assert canonical & present.get(pattern_type, set()), (
            f"none of the consumer identifiers named for {pattern_type} are in the "
            f"shipped corpus any more. Either Argus curated them out, in which case "
            f"delete the entry and say so, or the normalisation drifted."
        )


def test_every_delegation_rule_type_is_mapped():
    """A new delegation rule type must not escape the guard by being unmapped.

    Derived from the engine's own ``RuleType`` rather than from a list here, so
    adding a rule type without deciding which watchlist rows it reads fails.
    """
    from typing import get_args

    from lynceus.rules import RuleType

    declared = set(get_args(RuleType))
    assert declared, "could not read RuleType; this check would be vacuous"
    unaccounted = declared - set(RULE_TYPE_PATTERN_TYPES) - NON_DELEGATING_RULE_TYPES
    assert not unaccounted, (
        f"rule types {sorted(unaccounted)} are neither mapped to a watchlist "
        f"pattern_type nor listed as non-delegating, so this guard does not cover them"
    )


# --------------------------------------------------------------------------
# Take-effect pair: it must refuse the bad case AND permit the good one
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class _FakeRule:
    name: str
    rule_type: str
    patterns: tuple[str, ...] = ()


def _corpus_row(identifier_type: str, identifier: str, category: str) -> dict[str, str]:
    return {
        "identifier_type": identifier_type,
        "identifier": identifier,
        "device_category": category,
    }


def test_enabling_the_company_id_rule_is_refused():
    """The treatment. Turning on the rule BLE-G1 blocks must be caught."""
    rules = [_FakeRule("argus_ble_manufacturer_id", "watchlist_ble_manufacturer_id")]
    corpus = [
        _corpus_row("ble_manufacturer_id", "0x004C", "unknown"),
        _corpus_row("ble_manufacturer_id", "0x1234", "cctv_camera"),
    ]
    exposures = bystander_exposure(rules, corpus)
    assert [e.identifier for e in exposures] == ["004c"]
    assert "Apple" in str(exposures[0])


def test_a_curated_corpus_permits_the_same_rule():
    """The control, and the reason this file is not just a blocklist.

    ⛔ Without this, `bystander_exposure` returning a non-empty list for every
    input would satisfy the treatment above. The SAME rule on a corpus where
    Argus has made a positive statement about `004c` must be allowed.
    """
    rules = [_FakeRule("argus_ble_manufacturer_id", "watchlist_ble_manufacturer_id")]
    curated = [
        _corpus_row("ble_manufacturer_id", "0x004C", "gps_tracker"),
        _corpus_row("ble_manufacturer_id", "0x1234", "cctv_camera"),
    ]
    assert bystander_exposure(rules, curated) == []


def test_a_rule_with_explicit_patterns_is_not_exposed():
    """A non-delegating rule cannot be surprised by corpus drift.

    It matches only what its author wrote down, so the corpus is irrelevant to
    it. Treating it as exposed would make the guard fire on rules it has no
    business judging.
    """
    rules = [_FakeRule("hand_written", "watchlist_ble_manufacturer_id", patterns=("0x9999",))]
    corpus = [_corpus_row("ble_manufacturer_id", "0x004C", "unknown")]
    assert bystander_exposure(rules, corpus) == []


@pytest.mark.parametrize("rendering", ["0x004C", "0x4C", "004c", "0X004c"])
def test_every_rendering_of_the_same_company_id_is_caught(rendering):
    """The corpus carries several spellings of one company id.

    A guard doing its own string handling would catch `0x004C` and miss `0x4C`,
    which is the shape of defect this repo has shipped before.
    """
    rules = [_FakeRule("argus_ble_manufacturer_id", "watchlist_ble_manufacturer_id")]
    corpus = [_corpus_row("ble_manufacturer_id", rendering, "unknown")]
    assert len(bystander_exposure(rules, corpus)) == 1, rendering


@pytest.mark.parametrize(
    "rendering", ["fd44", "0000fd44", "0000fd44-0000-1000-8000-00805f9b34fb"]
)
def test_every_rendering_of_the_same_service_uuid_is_caught(rendering):
    """Same for UUIDs, which the corpus carries in three widths."""
    rules = [_FakeRule("argus_ble_uuid", "ble_uuid")]
    corpus = [_corpus_row("ble_service_uuid", rendering, "unknown")]
    assert len(bystander_exposure(rules, corpus)) == 1, rendering
