"""The /settings shadow card must never let a zero read as "safe to enable".

`shadow_report` exists for one reason: a bare hit count of zero is ambiguous in
the dangerous direction. It reads as "this rule would be quiet, switch it on",
and an operator acting on that when the real cause is a field the capture never
populates enables a rule that does nothing while believing they gained
coverage.

The three verdicts, and why the middle one is load-bearing:

    fired   hits > 0
    quiet   0 hits, field WAS seen        -> evidence about this site
    inert   0 hits, field NEVER seen      -> measures the plumbing, not the air

"inert" is live rather than hypothetical: `kismet.py` records the BLE
manufacturer-ID and drone-ID probe paths as UNVERIFIED against a real capture,
so those observation fields may read None on every observation an operator has.
"""

from __future__ import annotations

import pytest

from lynceus.rules import Rule, Ruleset
from lynceus.webui.liveness import shadow_report


class _FakeDB:
    def __init__(self, kv=None):
        self.kv = dict(kv or {})

    def get_state(self, key):
        return self.kv.get(key)


def _rs(*rules):
    return Ruleset(rules=list(rules))


def _shadow_rule(name="s", rule_type="watchlist_ble_manufacturer_id"):
    return Rule(name=name, rule_type=rule_type, severity="low", shadow=True, patterns=[])


def test_no_shadow_rule_means_no_card():
    out = shadow_report(_FakeDB(), _rs(Rule(name="r", rule_type="watchlist_oui", severity="low")))
    assert out["configured"] is False
    assert out["rules"] == []


def test_a_disabled_shadow_rule_is_not_reported():
    r = Rule(
        name="s",
        rule_type="watchlist_ble_manufacturer_id",
        severity="low",
        shadow=True,
        enabled=False,
        patterns=[],
    )
    assert shadow_report(_FakeDB(), _rs(r))["configured"] is False


def test_an_unreadable_ruleset_does_not_raise():
    """The card must degrade, not take the page down. `_build_settings_context`
    passes None when the ruleset could not be read."""
    assert shadow_report(_FakeDB(), None)["configured"] is False


# --- the three verdicts ----------------------------------------------------


def test_hits_report_fired():
    db = _FakeDB({"shadow:s": "7", "shadow_seen:ble_manufacturer_id": "300"})
    row = shadow_report(db, _rs(_shadow_rule()))["rules"][0]
    assert row["verdict"] == "fired"
    assert row["hits"] == 7


def test_zero_hits_with_the_field_seen_reports_quiet():
    db = _FakeDB({"shadow:s": "0", "shadow_seen:ble_manufacturer_id": "4200"})
    row = shadow_report(db, _rs(_shadow_rule()))["rules"][0]
    assert row["verdict"] == "quiet"
    assert row["field_seen"] == 4200


def test_zero_hits_with_the_field_never_seen_reports_inert():
    """⛔ The case the whole card exists for. Identical hit count to the test
    above, opposite meaning, opposite operator response."""
    db = _FakeDB({"shadow:s": "0"})
    row = shadow_report(db, _rs(_shadow_rule()))["rules"][0]
    assert row["verdict"] == "inert", (
        "0 hits with a field that was never present was reported as quiet. An "
        "operator would read that as 'safe to enable' and switch on a rule "
        "that cannot fire."
    )


def test_quiet_and_inert_are_distinguishable_from_the_count_alone():
    """The two states share a hit count of 0. If the verdict did not separate
    them, the card would be showing the same number for opposite conclusions."""
    seen = shadow_report(
        _FakeDB({"shadow:s": "0", "shadow_seen:ble_manufacturer_id": "4200"}),
        _rs(_shadow_rule()),
    )["rules"][0]
    unseen = shadow_report(_FakeDB({"shadow:s": "0"}), _rs(_shadow_rule()))["rules"][0]
    assert seen["hits"] == unseen["hits"] == 0
    assert seen["verdict"] != unseen["verdict"]


def test_a_mac_keyed_rule_is_never_inert():
    """Every observation carries a MAC, so a zero from a MAC-keyed rule is
    always the honest kind and must not be labelled broken plumbing."""
    db = _FakeDB({"shadow:s": "0"})
    row = shadow_report(db, _rs(_shadow_rule(rule_type="watchlist_oui")))["rules"][0]
    assert row["field"] is None
    assert row["verdict"] == "quiet"


# --- the counters are read defensively ------------------------------------


@pytest.mark.parametrize("junk", ["", "not-an-int", None])
def test_a_corrupt_counter_reads_as_zero_not_a_crash(junk):
    db = _FakeDB({"shadow:s": junk, "shadow_seen:ble_manufacturer_id": "1"})
    row = shadow_report(db, _rs(_shadow_rule()))["rules"][0]
    assert row["hits"] == 0


def test_a_corrupt_since_timestamp_reads_as_none():
    db = _FakeDB({"shadow_since": "yesterday", "shadow:s": "1"})
    assert shadow_report(db, _rs(_shadow_rule()))["since_ts"] is None


def test_since_is_reported_because_a_total_without_a_window_is_not_a_rate():
    db = _FakeDB({"shadow_since": "1700000000", "shadow:s": "5"})
    assert shadow_report(db, _rs(_shadow_rule()))["since_ts"] == 1_700_000_000


# --- the card must actually RENDER, not just compute -----------------------


def _render_settings(tmp_path, rules_yaml: str) -> str:
    """Build a real app against a real rules.yaml and fetch /settings."""
    from fastapi.testclient import TestClient

    from lynceus.config import Config
    from lynceus.db import Database
    from lynceus.webui.app import create_app

    rules_path = tmp_path / "rules.yaml"
    rules_path.write_text(rules_yaml, encoding="utf-8")
    db = Database(str(tmp_path / "s.db"))
    db.ensure_location("default", "Default")
    try:
        config = Config(db_path=str(tmp_path / "s.db"), rules_path=str(rules_path))
        app = create_app(config, db)
        with TestClient(app) as client:
            resp = client.get("/settings")
        assert resp.status_code == 200, resp.status_code
        return resp.text
    finally:
        db.close()


_SHADOW_YAML = """
rules:
  - name: argus_ble_manufacturer_id
    rule_type: watchlist_ble_manufacturer_id
    severity: low
    patterns: []
    shadow: true
"""

_PLAIN_YAML = """
rules:
  - name: plain_oui
    rule_type: watchlist_oui
    severity: low
    patterns: []
"""


def test_the_card_is_absent_when_no_shadow_rule_is_configured(tmp_path):
    body = _render_settings(tmp_path, _PLAIN_YAML)
    assert "shadow rules" not in body


def test_the_card_renders_and_names_the_rule(tmp_path):
    """⛔ The context tests above all pass with a template that renders nothing.
    This drives the real page."""
    body = _render_settings(tmp_path, _SHADOW_YAML)
    assert "shadow rules" in body, "the shadow card did not render at all"
    assert "argus_ble_manufacturer_id" in body


def test_the_rendered_card_says_a_zero_could_not_have_fired(tmp_path):
    """With no counts written, the field was never seen, so the page must say
    the rule could not have fired rather than showing a bare 0.

    This is the whole reason the card exists, asserted against the bytes an
    operator actually reads rather than against the dict behind them.
    """
    body = _render_settings(tmp_path, _SHADOW_YAML)
    assert "could not have fired" in body, (
        "the page showed a zero without saying it measures the capture path "
        "rather than the airspace; an operator would read it as 'safe to "
        "enable'"
    )
    assert "Enabling this rule would change nothing." in body


def test_the_rendered_card_carries_the_quiet_caveat(tmp_path):
    body = _render_settings(tmp_path, _SHADOW_YAML)
    assert "not a" in body and "property of the rule" in body, (
        "the page did not carry the caveat that a quiet window is evidence "
        "about this site and this window"
    )
