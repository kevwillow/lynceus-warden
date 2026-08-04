"""Parser regression anchor built from REAL Kismet output, not hand-built dicts.

Every other Kismet ingest test constructs device dicts by hand, which means they
encode our *belief* about Kismet's JSON shape. This one is anchored to output an
actual Kismet server produced, so it cannot drift from reality the way a
hand-built fixture silently can -- which is the exact failure that shipped
428fbcc ("read Remote-ID from the field paths Kismet actually emits").

Provenance of tests/fixtures/kismet_devices_real_2025_09.json:
  * Kismet 2025.09.0-b5d5a2d04 (current release), run 2026-08-04 in a container.
  * Source: a pcap replay of a public 802.11 sample capture (wpa-Induction.pcap
    from the Wireshark sample set) via `-c file.pcap:type=pcapfile`. The MACs are
    that public sample's (Cisco-Linksys, Apple), NOT any capture rig's.
  * Pulled from the real REST endpoint Lynceus polls,
    /devices/last-time/0/devices.json, then trimmed to the fields
    parse_kismet_device reads. The trim was proven parse-equivalent to the full
    capture before committing: telemetry the parser never touches (per-device
    *.rrd vectors, the datasource channel/hop/antenna block, all of dot11.device
    except probed_ssid_map) was dropped; every field the parser reads is verbatim.

⚠️ Do NOT hand-edit this fixture. Its value is that it is real. To refresh it for
a newer Kismet, re-capture via the same pcap-replay path and re-trim; if parsing
changes, that is a real finding about Kismet's shape, not a test to "fix".

Not covered here (needs a real drone in the capture, not fixable at a desk):
the uav.* Remote-ID path. That is the highest fixture-vs-reality risk left and
wants live capture or a genuine drone pcap.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lynceus.kismet import _TYPE_MAP, parse_kismet_device

_FIXTURE = Path(__file__).parent / "fixtures" / "kismet_devices_real_2025_09.json"


@pytest.fixture
def real_devices() -> list[dict]:
    return json.loads(_FIXTURE.read_text(encoding="utf-8"))


def test_every_real_device_parses(real_devices):
    """Real Kismet 2025.09 output must parse cleanly -- 0 dropped.

    A drop here means the current parser cannot read current Kismet, which no
    hand-built fixture would reveal."""
    parsed = [parse_kismet_device(d, capture_probe_ssids=True) for d in real_devices]
    dropped = [
        d.get("kismet.device.base.macaddr")
        for d, o in zip(real_devices, parsed, strict=True)
        if o is None
    ]
    assert dropped == [], f"parser dropped real devices: {dropped}"
    assert len(parsed) == 4


def test_real_device_types_are_all_mapped(real_devices):
    """Every device type this real capture contains is in _TYPE_MAP.

    Guards against Kismet renaming a type string out from under the map, which
    drops that whole class of device silently at ingest."""
    types = {d.get("kismet.device.base.type") for d in real_devices}
    unmapped = types - set(_TYPE_MAP)
    assert unmapped == set(), f"real Kismet emitted unmapped type(s): {unmapped}"


def test_seenby_source_name_extracted_from_the_real_nested_dict(real_devices):
    """⭐ The 428fbcc-class path, against real output.

    Real Kismet nests the source name inside kismet.common.seenby.source as a
    DICT (kismet.datasource.name), not a flat string. The source-gate that
    silently drops observations equality-matches this value, so if the parser
    read it wrong every observation from a named source would vanish. Confirm the
    real nested shape AND that the parser resolves it to the datasource name."""
    # the fixture really is the nested-dict shape, not a flattened string
    entry = real_devices[0]["kismet.device.base.seenby"][0]
    assert isinstance(entry["kismet.common.seenby.source"], dict)

    for d in real_devices:
        obs = parse_kismet_device(d)
        assert obs is not None
        assert obs.seen_by_sources == ("wpalab",), obs.seen_by_sources


def test_probe_ssids_extracted_from_the_real_probed_ssid_map(real_devices):
    """dot11.device.probed_ssid_map -> ssid, against the real structure.

    The two probing devices in this capture asked for 'Coherer' and 'linksys'."""
    by_mac = {}
    for d in real_devices:
        obs = parse_kismet_device(d, capture_probe_ssids=True)
        by_mac[obs.mac] = obs.probe_ssids
    assert by_mac["00:0d:93:82:36:3a"] == ("Coherer",)
    assert by_mac["00:0f:66:16:94:73"] == ("linksys",)


def test_probe_ssids_absent_when_capture_is_off(real_devices):
    """The privacy default: no probe SSIDs stored unless explicitly enabled,
    even when the real capture carries them."""
    for d in real_devices:
        obs = parse_kismet_device(d, capture_probe_ssids=False)
        assert obs is not None
        assert obs.probe_ssids is None or obs.probe_ssids == ()
