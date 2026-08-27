"""Shadow rules: evaluate a rule the operator has NOT enabled, alert on none of it.

This is how BLE-G1 gets answered. The argument for keeping the Bluetooth bridge
off is that enabling it *might* storm the operator, computed against the shipped
watchlist rather than against their airspace. Nobody could check, because the
data needed to replay it was never stored: `DeviceObservation` carries
`ble_manufacturer_id`, the `devices` table does not, and the raw Kismet record
is persisted only when an alert fires. A rule that is commented out never fires,
so there is nothing to replay. Shadow mode measures forward instead.

⛔ The safety property is the whole point, and it is structural rather than
conventional. `evaluate()` returns ONLY alertable hits. A shadow rule's hits go
to the caller-supplied `shadow_sink` and appear in no other return value, so a
caller cannot alert on one by forgetting a flag. Omit the sink and you lose the
counts; you can never gain an alert.

The tests below are written so that a broken implementation cannot pass by
accident: every "shadow produced nothing" assertion is paired with a control
proving the SAME rule fires when not shadowed. A zero from a rule that could
never match is not evidence.
"""

from __future__ import annotations

import pytest

from lynceus.kismet import DeviceObservation
from lynceus.rules import Rule, Ruleset, evaluate


def _obs(mac: str = "aa:bb:cc:dd:ee:ff") -> DeviceObservation:
    return DeviceObservation(
        mac=mac,
        device_type="wifi",
        first_seen=1_700_000_000,
        last_seen=1_700_000_000,
        is_randomized=False,
        rssi=-40,
        ssid=None,
        oui_vendor="ACME",
    )


def _rule(**kw) -> Rule:
    base = dict(
        name="r", rule_type="new_non_randomized_device", severity="high"
    )
    base.update(kw)
    return Rule(**base)


# --- the control: this rule really does fire ------------------------------


def test_control_the_same_rule_fires_when_not_shadowed():
    """⚠️ Runs FIRST and matters most.

    Every shadow assertion below is "returned nothing". That is only evidence
    if the identical rule demonstrably returns something when not shadowed.
    Without this control, a typo in the rule_type would produce a green suite
    that proves the opposite of what it claims.
    """
    hits = evaluate(Ruleset(rules=[_rule()]), _obs(), True)
    assert len(hits) == 1, (
        "the control rule did not fire, so every 'shadow suppressed it' "
        "assertion in this file would be vacuous"
    )


# --- the safety property ---------------------------------------------------


def test_a_shadow_rule_never_appears_in_the_return_value():
    sink: list = []
    hits = evaluate(Ruleset(rules=[_rule(shadow=True)]), _obs(), True, shadow_sink=sink)
    assert hits == [], (
        f"a shadow rule reached the caller's alertable hits: {hits}. This is "
        f"the alert storm shadow mode exists to measure without firing."
    )


def test_the_sink_receives_what_would_have_alerted():
    sink: list = []
    evaluate(Ruleset(rules=[_rule(shadow=True)]), _obs(), True, shadow_sink=sink)
    assert len(sink) == 1
    assert sink[0].rule_name == "r"
    assert sink[0].severity == "high", (
        "the count must carry the severity the alert WOULD have had, or an "
        "operator cannot tell a storm of 'low' from a storm of 'high'"
    )


def test_omitting_the_sink_is_silent_not_loud():
    """⛔ The failure mode must be the boring one.

    A caller that knows nothing about shadow mode, including every caller that
    existed before it, must get today's behaviour: no shadow alert, no crash.
    """
    hits = evaluate(Ruleset(rules=[_rule(shadow=True)]), _obs(), True)
    assert hits == []


def test_disabled_still_beats_shadow():
    """`enabled: false` is not a synonym for shadow. It skips entirely, so it
    must not even produce a count."""
    sink: list = []
    hits = evaluate(
        Ruleset(rules=[_rule(enabled=False, shadow=True)]), _obs(), True, shadow_sink=sink
    )
    assert hits == []
    assert sink == [], "a disabled rule was still evaluated for counting"


def test_shadow_and_real_rules_coexist_without_cross_contamination():
    """The diversion is per-rule. A shadow rule must not swallow a real rule's
    hits, and a real rule must not leak into the counts."""
    rs = Ruleset(
        rules=[
            _rule(name="real"),
            _rule(name="shadowed", shadow=True),
        ]
    )
    sink: list = []
    hits = evaluate(rs, _obs(), True, shadow_sink=sink)
    assert [h.rule_name for h in hits] == ["real"], (
        f"alertable hits were contaminated: {[h.rule_name for h in hits]}"
    )
    assert [h.rule_name for h in sink] == ["shadowed"], (
        f"shadow counts were contaminated: {[h.rule_name for h in sink]}"
    )


def test_the_sink_is_extended_not_replaced():
    """A caller may reuse one sink across observations, so evaluate must append
    rather than rebind."""
    sink: list = [object()]
    evaluate(Ruleset(rules=[_rule(shadow=True)]), _obs(), True, shadow_sink=sink)
    assert len(sink) == 2, "evaluate replaced the caller's list instead of extending it"


def test_shadow_defaults_to_false():
    assert _rule().shadow is False, (
        "shadow must be opt-in; defaulting to True would silence every "
        "existing rule on upgrade"
    )


@pytest.mark.parametrize("shadow", [True, False])
def test_the_only_difference_is_where_the_hit_lands(shadow):
    """Same rule, same observation, same match. Shadow decides the destination
    and nothing else, so a count is a faithful preview of the alert."""
    sink: list = []
    hits = evaluate(
        Ruleset(rules=[_rule(shadow=shadow)]), _obs(), True, shadow_sink=sink
    )
    landed = sink if shadow else hits
    other = hits if shadow else sink
    assert len(landed) == 1 and other == []
    assert landed[0].rule_name == "r" and landed[0].severity == "high"


# --- a bookkeeping failure must never cost an alert -----------------------


def test_a_raising_sink_does_not_swallow_real_hits():
    """⛔ The one direction this feature must never fail in.

    `shadow_sink.extend(...)` runs before the real hits are returned. Unwrapped,
    a sink whose `extend` raises propagates out of `evaluate` and the genuine
    alert is lost to a counter failure.

    Found by a cold red-team of the diff, which spotted the asymmetry:
    `_record_shadow_hits` was already wrapped for exactly this reason and the
    delivery into it was not.
    """

    class BrokenSink(list):
        def extend(self, values):  # noqa: D102
            raise RuntimeError("counter unavailable")

    rs = Ruleset(rules=[_rule(name="real"), _rule(name="shadowed", shadow=True)])
    hits = evaluate(rs, _obs(), True, shadow_sink=BrokenSink())

    assert [h.rule_name for h in hits] == ["real"], (
        "a broken shadow counter swallowed a genuine alert. Counts are "
        "expendable; alerts are not."
    )


def test_a_raising_sink_is_reported_not_silent():
    """Losing counts is acceptable. Losing them silently is not: the operator
    would read a low number and conclude the rule is quiet."""

    class BrokenSink(list):
        def extend(self, values):  # noqa: D102
            raise RuntimeError("counter unavailable")

    import logging

    rs = Ruleset(rules=[_rule(name="shadowed", shadow=True)])
    logger = logging.getLogger("lynceus.rules")
    records: list = []

    class _Grab(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    h = _Grab()
    logger.addHandler(h)
    try:
        evaluate(rs, _obs(), True, shadow_sink=BrokenSink())
    finally:
        logger.removeHandler(h)

    assert any("shadow sink rejected" in m for m in records), (
        f"a lost count was not reported anywhere: {records}"
    )


# --- the denominator: a zero count must be interpretable -------------------


class _FakeDB:
    """Minimal key/value stand-in for the poller_state accessors."""

    def __init__(self):
        self.kv: dict[str, str] = {}

    def get_state(self, key):
        return self.kv.get(key)

    def set_state(self, key, value):
        self.kv[key] = value


def test_field_presence_is_counted_so_zero_is_interpretable():
    """⛔ Without a denominator, a shadow count of zero means two opposite
    things: nothing was in range, or the field is never populated so the rule
    cannot fire. `kismet.py` records the BLE manufacturer-ID probe paths as
    UNVERIFIED against a real capture, so the second is a live possibility.
    """
    from lynceus.poller import _record_shadow_field_presence

    db = _FakeDB()
    _record_shadow_field_presence(db, _obs(), 1_700_000_000)
    assert db.kv.get("shadow_seen:ssid") is None, (
        "ssid was None on this observation and must not be counted as carried"
    )


def test_a_carried_field_increments_its_denominator():
    from lynceus.poller import _record_shadow_field_presence

    db = _FakeDB()
    obs = _obs().model_copy(update={"ble_manufacturer_id": "0x004C"})
    _record_shadow_field_presence(db, obs, 1_700_000_000)
    _record_shadow_field_presence(db, obs, 1_700_000_001)
    assert db.kv["shadow_seen:ble_manufacturer_id"] == "2"


def test_an_empty_tuple_is_absent_not_present():
    """`ble_service_uuids` defaults to `()`. Counting that as carried would
    manufacture a denominator out of nothing and hide the exact broken-plumbing
    case this exists to expose."""
    from lynceus.poller import _record_shadow_field_presence

    db = _FakeDB()
    obs = _obs()
    assert obs.ble_service_uuids == ()
    _record_shadow_field_presence(db, obs, 1_700_000_000)
    assert "shadow_seen:ble_service_uuids" not in db.kv


def test_the_denominator_is_not_paid_for_without_a_shadow_rule():
    from lynceus.poller import _any_shadow_rule

    assert _any_shadow_rule(Ruleset(rules=[_rule()])) is False
    assert _any_shadow_rule(Ruleset(rules=[_rule(shadow=True)])) is True
    assert _any_shadow_rule(Ruleset(rules=[_rule(shadow=True, enabled=False)])) is False, (
        "a disabled shadow rule is not running, so its denominator is not owed"
    )


def test_presence_accounting_never_raises():
    """A counter that fails must not take down the poll tick it measures.

    ⚠️ The observation MUST carry a denominator field. An earlier version of
    this test passed `_obs()`, whose fields are all absent, so the loop
    `continue`d on every one, the database was never touched, and no exception
    could be raised. It passed trivially and survived a plant that narrowed the
    `except` clause to a type it would never see. A test whose subject is never
    reached is not a test.
    """
    from lynceus.poller import _record_shadow_field_presence

    class Exploding:
        def get_state(self, key):
            raise RuntimeError("db gone")

        def set_state(self, key, value):
            raise RuntimeError("db gone")

    obs = _obs().model_copy(update={"ble_manufacturer_id": "0x004C"})

    # Control: prove this observation really does reach the database, so the
    # assertion below is about the except clause and not about an empty loop.
    reached = _FakeDB()
    _record_shadow_field_presence(reached, obs, 1_700_000_000)
    assert reached.kv.get("shadow_seen:ble_manufacturer_id") == "1", (
        "the control observation never reached the db, so this test would be "
        "vacuous again"
    )

    _record_shadow_field_presence(Exploding(), obs, 1_700_000_000)
