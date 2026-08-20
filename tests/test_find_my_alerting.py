"""Behavioural tests for the apple_find_my rule.

Three contracts. Each test fails if the behaviour it names breaks.

Test 1 -- the zero-behavioural-change guarantee.
    A Kismet-only deployment (no BLE bridge) sees NO alerts from this rule.
    `ble_device_class` is None on every Kismet-path observation, so the rule
    cannot fire -- by construction rather than by policy. The precondition
    (ble_device_class IS None) is asserted explicitly too, so a future change
    that starts populating it makes this test name WHICH half broke.

Test 2 -- the separated Find My advert fires end to end.
    Drives the real bridge seam (bridge._record_advert -> bridge._flush) with
    the structurally-genuine separated frame, asserts exactly one alert row
    AND a notification dispatch AND severity "med".

Test 3 -- the paired form raises nothing.
    Same seam, paired frame (every passer-by's own iPhone), asserts zero
    apple_find_my alerts AND that the device row WAS written with
    ble_device_class == "find_my_paired". A test that silently ingested
    nothing would pass vacuously and prove nothing.

Real config/rules.yaml is loaded (not a fixture copy), the real
process_observation is exercised through the real bridge seam, and the real
RecordingNotifier captures notifications. No mocking of evaluate,
process_observation, add_alert, or the notifier's send.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from lynceus.allowlist import Allowlist
from lynceus.bridges.ble import BleBridge
from lynceus.config import Config
from lynceus.db import Database
from lynceus.kismet import DeviceObservation
from lynceus.notify import RecordingNotifier
from lynceus.rules import load_ruleset

_REPO_ROOT = Path(__file__).resolve().parents[1]
_RULES_PATH = _REPO_ROOT / "config" / "rules.yaml"

_APPLE = 0x004C
_MSG_FIND_MY = 0x12
_RSSI = -55
_NOW = 1_700_000_000

ADVERT_SEPARATED = {_APPLE: bytes([_MSG_FIND_MY, 0x19]) + bytes(25)}
ADVERT_PAIRED = {_APPLE: bytes([_MSG_FIND_MY, 0x02]) + bytes(2)}

MAC_SEPARATED = "c2:ff:ee:5e:aa:11"
MAC_PAIRED = "c2:ff:ee:bb:11:ed"


def _kismet_observations():
    """Two observations as the Kismet classic-HCI path would build them.

    A wifi one and a BLE one. Neither carries a Continuity payload, so
    ble_device_class is None on both -- the structural reason this rule
    cannot fire on a Kismet-only deployment.
    """
    wifi = DeviceObservation(
        device_type="wifi",
        mac="aa:bb:cc:00:11:22",
        first_seen=_NOW,
        last_seen=_NOW,
        rssi=-60,
        ssid="example",
        oui_vendor=None,
        is_randomized=False,
    )
    ble = DeviceObservation(
        device_type="ble",
        mac="aa:bb:cc:33:44:55",
        first_seen=_NOW,
        last_seen=_NOW,
        rssi=-70,
        ssid=None,
        oui_vendor=None,
        is_randomized=True,
    )
    return wifi, ble


def test_kismet_path_observations_never_fire_apple_find_my():
    """The zero-behavioural-change guarantee for a Kismet-only deployment.

    `ble_device_class` is None on every observation built by the Kismet
    classic-HCI path, so the `ble_device_class` branch of rules.evaluate
    cannot fire on it. This test fails if any future change starts
    populating `ble_device_class` from a non-bridge source.
    """
    ruleset = load_ruleset(str(_RULES_PATH))
    rule_names = [r.name for r in ruleset.rules]
    assert "apple_find_my" in rule_names, (
        "the shipped rules.yaml no longer contains apple_find_my; this test's "
        "guarantee is meaningless if the rule is not in the loaded ruleset"
    )

    wifi_obs, ble_obs = _kismet_observations()

    assert wifi_obs.ble_device_class is None, (
        "wifi DeviceObservation has a non-None ble_device_class -- a future "
        "change has populated it from a non-bridge path; the apple_find_my "
        "rule will now fire on wifi observations"
    )
    assert ble_obs.ble_device_class is None, (
        "ble DeviceObservation (Kismet path, no bridge) has a non-None "
        "ble_device_class -- a future change has populated it from a "
        "non-bridge path; the apple_find_my rule will now fire on Kismet "
        "observations that never went through the passive BLE bridge"
    )

    wifi_hits = evaluate_with_real_ruleset(ruleset, wifi_obs)
    ble_hits = evaluate_with_real_ruleset(ruleset, ble_obs)

    wifi_apple = [h for h in wifi_hits if h.rule_name == "apple_find_my"]
    ble_apple = [h for h in ble_hits if h.rule_name == "apple_find_my"]
    assert wifi_apple == [], (
        f"Kismet-path wifi observation fired apple_find_my: {wifi_apple!r}; "
        "the rule must be inert without the passive BLE bridge"
    )
    assert ble_apple == [], (
        f"Kismet-path ble observation fired apple_find_my: {ble_apple!r}; "
        "the rule must be inert without the passive BLE bridge"
    )


def evaluate_with_real_ruleset(ruleset, obs):
    """Run lynceus.rules.evaluate over the real shipped ruleset.

    `evaluate` is imported inside the function so this module's top-level
    import surface does not pull in the full rules engine for readers
    only interested in the seam-level tests below.
    """
    from lynceus.rules import evaluate

    return evaluate(ruleset, obs, is_new_device=True)


@pytest.fixture
def bridge(tmp_path):
    """A bridge wired exactly as the Poller wires it, with the REAL ruleset.

    The Poller passes its ruleset unchanged; this fixture mirrors that
    contract and loads the actual config/rules.yaml so the rule under
    proof is the one shipped in this repo, not a hand-typed fixture.
    """
    ruleset = load_ruleset(str(_RULES_PATH))
    rule_names = [r.name for r in ruleset.rules]
    assert "apple_find_my" in rule_names, (
        "the shipped rules.yaml no longer contains apple_find_my; this "
        "fixture proves nothing without the rule under test"
    )

    db = Database(str(tmp_path / "ble.db"))
    config = Config(db_path=str(tmp_path / "ble.db"))
    notifier = RecordingNotifier()
    b = BleBridge(
        db=db,
        config=config,
        ruleset=ruleset,
        allowlist_provider=Allowlist,
        notifier=notifier,
        severity_overrides=None,
        location_id=config.location_id,
        location_label=config.location_label,
        adapter="hci0",
        flush_interval=1.0,
    )
    yield b, db, notifier, ruleset
    db.close()


def test_separated_find_my_advert_fires_one_alert_and_a_notification(bridge):
    """The separated form: alert row + notification + severity med.

    The advert bytes are not invented: type 0x12 (Find My message) with body
    length 0x19 (25) is the separated form; the body content is irrelevant
    to the decode -- it is the LENGTH that carries the separation state.
    bytes(25) stands in for the rotating key material we deliberately
    never retain.
    """
    b, db, notifier, _ruleset = bridge
    b._record_advert(
        mac_raw=MAC_SEPARATED,
        rssi=_RSSI,
        manufacturer_data=ADVERT_SEPARATED,
        service_uuids=(),
        service_data={},
    )
    flushed = b._flush(int(time.time()))
    assert flushed == 1, "the bridge did not hand the advert to the pipeline"

    alerts = db.list_alerts()
    apple = [a for a in alerts if a["rule_name"] == "apple_find_my"]
    assert len(apple) == 1, (
        f"expected exactly one apple_find_my alert, got {len(apple)}: "
        f"{[a['rule_name'] for a in alerts]!r}"
    )
    assert apple[0]["severity"] == "med", (
        f"alert severity is {apple[0]['severity']!r}; apple_find_my is "
        "declared med in the shipped rules.yaml"
    )

    assert notifier.calls, (
        "alert row was written but the operator was never notified -- the "
        "rule fired but the dispatch path is broken"
    )


def test_paired_find_my_advert_raises_nothing_but_persists_the_class(bridge):
    """The paired form: zero apple_find_my alerts, device row written.

    Every passer-by's own iPhone looks like this. Matching it would turn
    the feature into a noise generator, which is why 'find_my_paired' is
    deliberately NOT listed in apple_find_my.patterns. Asserting the
    device row's ble_device_class == "find_my_paired" prevents a
    vacuously-passing test where the bridge silently ingested nothing.
    """
    b, db, notifier, _ruleset = bridge
    b._record_advert(
        mac_raw=MAC_PAIRED,
        rssi=_RSSI,
        manufacturer_data=ADVERT_PAIRED,
        service_uuids=(),
        service_data={},
    )
    flushed = b._flush(int(time.time()))
    assert flushed == 1, (
        "the bridge did not hand the paired advert to the pipeline; the "
        "negative-case assertion below would pass vacuously"
    )

    apple = [a for a in db.list_alerts() if a["rule_name"] == "apple_find_my"]
    assert apple == [], (
        f"paired Find My advert fired apple_find_my: {apple!r}; every "
        "passer-by's own iPhone looks like this and would drown the operator"
    )

    device_row = next(
        (d for d in db.list_devices() if d["mac"] == MAC_PAIRED), None
    )
    assert device_row is not None, (
        "paired advert was flushed but no device row was written; either "
        "the capture path is broken or the test is exercising the wrong "
        "seam"
    )
    assert device_row["ble_device_class"] == "find_my_paired", (
        f"paired device row has ble_device_class={device_row['ble_device_class']!r}; "
        "the decode must identify this as the paired form so the rule can "
        "correctly stay silent"
    )

    assert notifier.calls == [], (
        f"paired advert produced {len(notifier.calls)} notification(s); the "
        "negative case must be silent end to end, not just silent on the "
        "alert table"
    )
