"""Tests for the built-in threat-OUI seed data."""

from __future__ import annotations

import re

from lynceus.seeds.ble_uuids import TRACKER_UUIDS
from lynceus.seeds.threat_ouis import THREAT_OUIS

OUI_RE = re.compile(r"^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
VALID_SEVERITIES = {"low", "med", "high"}


def test_threat_ouis_structure():
    for entry in THREAT_OUIS:
        assert set(entry.keys()) >= {"pattern", "severity", "description"}
        assert entry["severity"] in VALID_SEVERITIES, entry
        assert OUI_RE.match(entry["pattern"]), f"bad OUI format: {entry['pattern']!r}"


def test_threat_ouis_no_duplicates():
    patterns = [e["pattern"] for e in THREAT_OUIS]
    assert len(patterns) == len(set(patterns)), f"duplicates in {patterns}"


def test_threat_ouis_descriptions_non_empty():
    for entry in THREAT_OUIS:
        desc = entry["description"]
        assert isinstance(desc, str)
        assert desc.strip(), f"empty description for {entry['pattern']}"


def test_threat_ouis_minimum_count():
    assert len(THREAT_OUIS) >= 5, "threat OUI list shrank below safety floor"


def test_tracker_uuids_structure():
    for entry in TRACKER_UUIDS:
        assert set(entry.keys()) >= {"pattern", "severity", "description"}
        assert entry["severity"] in VALID_SEVERITIES, entry
        assert UUID_RE.match(entry["pattern"]), f"bad UUID format: {entry['pattern']!r}"
        desc = entry["description"]
        assert isinstance(desc, str) and desc.strip()


def test_tracker_uuids_no_duplicates():
    patterns = [e["pattern"] for e in TRACKER_UUIDS]
    assert len(patterns) == len(set(patterns)), f"duplicates in {patterns}"


def test_tracker_uuids_minimum_count():
    assert len(TRACKER_UUIDS) >= 3, "tracker UUID list shrank below safety floor"
