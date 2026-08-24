"""One malformed Kismet record must not be able to livelock the daemon.

`parse_kismet_device` contains a poison record by returning None, and the
caller counts that in `unparseable_counter` alongside the guarded drops. The
containment matters because the client parses EAGERLY inside the fetch: a raise
escapes `poll_once` entirely, the tick aborts, `last_poll` never advances, and
the next tick re-fetches the same record. The daemon stays alive and never
progresses — diagnosed and written up as finding A1, and closed for
`ValidationError` at the model-construction site.

⛔ `ValidationError` is not the only class that reaches the caller. Measured by
putting 16 adversarial records through the real parser on the clean tree:

    AttributeError   mac is int / list / dict   normalize_mac calls .strip()
    TypeError        mac is bytes               the MAC regex against bytes
    TypeError        type is list / dict        _TYPE_MAP.get(unhashable)

Three sites, two classes — the register's "three other exception classes" was a
miscount, and the sites are what matter. Everything else thrown at it (junk
seenby, junk probed map, junk signal, junk uuids, junk manufacturer data, dict
first_time, int type) already returned None or parsed cleanly.

⚠️ The fix is BOTH: named guards at the two sites, so the log line names the
real cause, AND an outer net, because the point of the containment is that an
UNKNOWN shape cannot stop the daemon — and enumerating shapes is exactly the
move that left ValidationError as the only one covered. The net logs at ERROR
with a traceback: contained is not the same as silent, and a parser raising on
its own bug should still be loud.
"""

from __future__ import annotations

import logging

import pytest

from lynceus.kismet import parse_kismet_device

GOOD = {
    "kismet.device.base.macaddr": "aa:bb:cc:11:22:33",
    "kismet.device.base.type": "Wi-Fi AP",
    "kismet.device.base.first_time": 1_700_000_000,
    "kismet.device.base.last_time": 1_700_000_100,
}


def _record(**over):
    r = dict(GOOD)
    r.update(over)
    return r


# --- the control: a good record still parses -------------------------------
# Without this, "never raises" is satisfied by a parser that returns None for
# everything, which would silently stop the product from seeing anything.


def test_a_well_formed_record_still_parses():
    obs = parse_kismet_device(GOOD)
    assert obs is not None
    assert obs.mac == "aa:bb:cc:11:22:33"
    assert obs.device_type == "wifi"


def test_a_genuinely_malformed_record_is_still_rejected():
    """Containment must not become admission. A record that cannot be
    understood has to be dropped, not coerced into a plausible observation."""
    assert parse_kismet_device(_record(**{"kismet.device.base.macaddr": "nonsense"})) is None
    assert parse_kismet_device(_record(**{"kismet.device.base.type": "Toaster"})) is None
    assert parse_kismet_device(_record(**{"kismet.device.base.first_time": None})) is None


# --- the guard: the measured escapes ---------------------------------------


@pytest.mark.parametrize(
    ("label", "over"),
    [
        ("mac is an int", {"kismet.device.base.macaddr": 12345}),
        ("mac is a list", {"kismet.device.base.macaddr": ["aa:bb"]}),
        ("mac is a dict", {"kismet.device.base.macaddr": {"x": 1}}),
        ("mac is bytes", {"kismet.device.base.macaddr": b"aa:bb:cc:11:22:33"}),
        ("type is a list", {"kismet.device.base.type": ["Wi-Fi AP"]}),
        ("type is a dict", {"kismet.device.base.type": {"a": 1}}),
        ("type is a set", {"kismet.device.base.type": frozenset({"Wi-Fi AP"})}),
        ("first_time is a list", {"kismet.device.base.first_time": [1, 2]}),
    ],
)
def test_a_poison_record_is_contained_not_raised(label, over):
    """Each of these used to reach the caller, abort the tick, and leave
    `last_poll` frozen on a record the next tick would re-fetch."""
    assert parse_kismet_device(_record(**over), capture_probe_ssids=True) is None, label


@pytest.mark.parametrize(
    ("label", "over"),
    [
        ("signal is a string", {"kismet.device.base.signal": "strong"}),
        ("service_uuids is a dict", {"kismet.device.base.service_uuids": {"a": 1}}),
        ("seenby is a dict", {"kismet.device.base.seenby": {"a": 1}}),
        ("probed map is a string", {"dot11.device": "oops"}),
    ],
)
def test_junk_in_an_optional_field_still_yields_an_observation(label, over):
    """⚠️ The opposite direction, and it is not a formality.

    Containment must not spread. These four are already tolerated correctly —
    the required fields are intact and the junk is in a field the parser is
    allowed to skip — so the record has to become an OBSERVATION, not a drop.
    A blanket try/except placed too wide is exactly the fix that would turn
    every one of them into a silent None and stop the product seeing devices
    Kismet reported perfectly well.
    """
    obs = parse_kismet_device(_record(**over), capture_probe_ssids=True)
    assert obs is not None, label
    assert obs.mac == "aa:bb:cc:11:22:33"


def test_the_outer_net_catches_a_shape_nobody_enumerated():
    """The enumerated list above is the part that will go stale. This one asks
    the question the list cannot: an object that raises from somewhere inside
    the parse must still be contained."""

    class _Hostile(dict):
        def get(self, key, default=None):
            raise RuntimeError("hostile record")

    assert parse_kismet_device(_Hostile()) is None


def test_a_known_bad_shape_does_not_trip_the_outer_net(caplog):
    """⭐ The two layers must stay distinguishable, and only this pins it.

    Planting the removal of the named mac guard did NOT fail any other test in
    this file: the outer net catches the AttributeError and returns None, so
    every outcome assertion stays green while the diagnosis silently degrades.

    That difference is operational, not cosmetic. A non-string MAC is JUNK FROM
    KISMET — expected, WARNING, name the value. A record that reaches the outer
    net is "the parser raised on a shape nobody predicted", logged at ERROR
    with a traceback and explicitly calling itself a defect. If every malformed
    record starts arriving as the second, the ERROR level stops meaning
    anything and the real parser bug is lost in the noise.
    """
    with caplog.at_level(logging.DEBUG, logger="lynceus.kismet"):
        assert parse_kismet_device(_record(**{"kismet.device.base.macaddr": 12345})) is None
    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert not errors, (
        "a known-bad MAC shape fell through to the outer net and was reported "
        f"as a parser defect: {[r.getMessage() for r in errors]}"
    )
    assert any(r.levelno == logging.WARNING for r in caplog.records)

    caplog.clear()
    with caplog.at_level(logging.DEBUG, logger="lynceus.kismet"):
        assert parse_kismet_device(_record(**{"kismet.device.base.type": ["Wi-Fi AP"]})) is None
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert any(r.levelno == logging.WARNING for r in caplog.records)


def test_the_outer_net_reports_itself_as_a_defect(caplog):
    """The CONTRAST. An unpredicted shape must be loud in a way a routine
    malformed record is not, or the level carries no information."""

    class _Hostile(dict):
        def get(self, key, default=None):
            raise RuntimeError("hostile record")

    with caplog.at_level(logging.DEBUG, logger="lynceus.kismet"):
        assert parse_kismet_device(_Hostile()) is None
    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert errors, "the outer net swallowed a parser failure without an ERROR"
    assert errors[0].exc_info is not None, "no traceback to debug from"


def test_containment_is_loud(caplog):
    """Contained is not silent. A record the parser could not handle for a
    reason nobody predicted is a finding about Kismet or about us, and it has
    to leave something in the journal to debug from."""
    with caplog.at_level(logging.WARNING, logger="lynceus.kismet"):
        parse_kismet_device(_record(**{"kismet.device.base.macaddr": 12345}))
    assert caplog.records, "a poison record was dropped with no log line at all"
    assert any("12345" in r.getMessage() for r in caplog.records), (
        "the log line does not identify the record it dropped"
    )
