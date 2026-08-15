"""A rule type you can add, that is counted, and that has never matched.

`ble_manufacturer_id` is accepted by `add_watchlist`, stored, and counted in the
pattern-type breakdown on `/settings`. But the manufacturer company id is read
from candidate Kismet field paths that the source itself describes as
unconfirmed — `kismet.py` says in as many words that the rule "fires zero alerts
on real hardware".

Measured 2026-08-14 at `0e4f87f`: across **every** BLE device in every fixture
in this repo — 8 of them, in `dev_kismet.json`, `integration_kismet_t1.json` and
`kismet_devices.json` — `ble_manufacturer_id` resolved **0 times**. The one real
Kismet 2025.09 capture contains no BLE devices at all, so nothing in the repo
can currently make this rule fire.

⇒ The gap is not that the code is wrong; the limitation is documented in the
source. It is that the documentation is in the source, where an operator never
looks, while the *config surface* accepts the rule and `/settings` counts it
like any other. These tests pin the note that closes that gap.

⚠️ Deliberately NOT rejecting the pattern type. Argus imports these rows and the
import + DB half of the feature is load-bearing; refusing them would break that
for a display problem.
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import create_app

NOTE = "ble_manufacturer_id rules are not currently matching"


def _prose(html: str) -> str:
    """Collapse whitespace before asserting on rendered prose.

    🪤 Template text wraps across source lines, so a sentence that reads as one
    phrase in the file is not contiguous in the HTML. Asserting on the raw body
    makes a test that fails when someone rewraps a paragraph and passes when
    they delete half of it — brittle in the direction that wastes time and
    blind in the direction that matters.
    """
    return " ".join(html.split())


@pytest.fixture()
def client(tmp_path):
    cfg = Config(db_path=str(tmp_path / "s.db"))
    db = Database(cfg.db_path)
    db.ensure_location("default", "Default")
    app = create_app(cfg, db)
    with TestClient(app) as c:
        c.db = db
        yield c
    db.close()


def test_the_warning_is_absent_when_no_such_rule_exists(client):
    """Presence assertion, and the more important half. A watchlist with none
    of these must carry NO warning — a caution an operator sees permanently is
    one they learn to scroll past, which costs more than the note is worth."""
    client.db.add_watchlist(pattern="aa:bb:cc:dd:ee:ff", pattern_type="mac", severity="high")

    body = _prose(client.get("/settings").text)

    assert NOTE not in body


def test_the_warning_appears_when_such_a_rule_exists(client):
    client.db.add_watchlist(
        pattern="004c", pattern_type="ble_manufacturer_id", severity="high"
    )

    body = _prose(client.get("/settings").text)

    assert NOTE in body, (
        "an operator can add a ble_manufacturer_id rule and see it counted on "
        "/settings, with nothing saying it has never been observed to match"
    )


def test_the_warning_names_the_rule_type_that_does_work(client):
    """A caution that only says "this does not work" leaves the operator with
    no next step. For Apple devices `ble_device_class` is decoded from the
    advert itself and does match."""
    client.db.add_watchlist(
        pattern="004c", pattern_type="ble_manufacturer_id", severity="high"
    )

    body = _prose(client.get("/settings").text)

    assert "ble_device_class" in body


def test_the_warning_says_other_rule_types_are_unaffected(client):
    """Scope the alarm. Without this an operator reading it has no way to tell
    whether their MAC and SSID rules are also silently dead."""
    client.db.add_watchlist(
        pattern="004c", pattern_type="ble_manufacturer_id", severity="high"
    )

    body = _prose(client.get("/settings").text)

    assert "other rule types are unaffected" in body
