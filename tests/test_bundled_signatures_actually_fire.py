"""The bundled substring signatures, put through the real matcher.

⭐ This is the test that would have caught S1. Every other guard on this data
reads the CSV and asserts things about its TEXT. This one loads the shipped
rows into a real schema and asks the real resolver whether a device named the
way that vendor names its devices produces a match.

Before the re-cut, `DJI-Phantom4`, `DJI_Mavic`, `Phantom-3` and `MP70_a1b2` all
returned None, because the identifiers were stored as Python regexes in a
column matched with `LIKE '%' || pattern || '%'`. The whole drone fleet, the
forensic-extraction tools and the in-vehicle routers were inert while
`/watchlist` and `/healthz.json` graded them LIVE.

⚠️ The negative cases are not decoration. Re-cutting a regex to a literal stem
is the fix, and doing it carelessly is a worse bug than the one it fixes: a
bare `phantom` or `magnet` alerts on an ordinary home network, and for the
people this product is for, being told a police forensic tool is nearby when it
is a neighbour's router is not a small error. `InspireWiFi`, `Phantom Gaming
5G`, `Parrot Cafe` and `MagnetHomeWiFi` are here because three of them DID
match during development — see the LIKE-wildcard note below.
"""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from lynceus.db import Database

_CSV = Path(__file__).parent.parent / "src" / "lynceus" / "data" / "default_watchlist.csv"

#: Device names in the shape the vendor actually uses. Each must match.
_SHOULD_MATCH_SSID = [
    "DJI-Phantom4", "DJI_Mavic", "Phantom-3", "MP70_a1b2", "FlockSafety-Cam-14",
    "Mavic_Air_2", "Skydio2-A1", "ANAFI-1234", "cradlepoint-9f", "GrayKey-01",
    "Oxygen-Forensic-Suite", "MSAB-XRY-2", "AUTEL-EVO-II", "AirLink-RV50x",
]
#: Ordinary networks. Each must NOT match.
_SHOULD_NOT_MATCH_SSID = [
    "Hendricks_Home", "CoffeeShop-Guest", "Calibri-Net", "MagnetHomeWiFi",
    "InspireWiFi", "Phantom Gaming 5G", "Parrot Cafe", "TELUS1234", "eduroam",
]
_SHOULD_MATCH_BLE = [
    "Flock-1234", "Penguin-A7", "ShotSpotter-9", "Axon-Body-3", "Fleet-2",
    "UFED-Touch2", "Signal-Sidearm", "WatchGuard-V300", "Raven-77",
]
_SHOULD_NOT_MATCH_BLE = [
    "John's iPhone", "Galaxy Buds", "Tile", "Falcon", "AB2", "APX 6000",
    "Bose QC35", "Raven",
]


@pytest.fixture(scope="module")
def loaded(tmp_path_factory):
    """Every bundled substring row, in a real schema, behind the real matcher."""
    db = Database(str(tmp_path_factory.mktemp("sig") / "sig.db"))
    with _CSV.open(encoding="utf-8") as handle:
        handle.readline()  # the `# meta:` provenance line
        rows = [
            r for r in csv.DictReader(handle)
            if r["identifier_type"] in Database.SUBSTRING_PATTERN_TYPES
        ]
    with db._conn:
        for row in rows:
            db._conn.execute(
                "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
                "VALUES (?, ?, ?, ?)",
                (row["identifier"], row["identifier_type"], "high", row["manufacturer"]),
            )
    db.loaded_rows = len(rows)
    yield db
    db.close()


def test_the_fixture_actually_loaded_something(loaded):
    """A resolver with an empty watchlist returns None for everything, which
    would make every negative case below pass and every positive case fail for
    a reason that has nothing to do with the data."""
    assert loaded.loaded_rows >= 40, f"only {loaded.loaded_rows} substring rows loaded"


@pytest.mark.parametrize("ssid", _SHOULD_MATCH_SSID)
def test_a_real_device_ssid_matches(loaded, ssid):
    assert loaded.resolve_matched_ssid_pattern_for_eval(ssid) is not None, (
        f"{ssid!r} matched no bundled signature — this product ships a "
        "signature claiming to detect it"
    )


@pytest.mark.parametrize("ssid", _SHOULD_NOT_MATCH_SSID)
def test_an_ordinary_ssid_does_not_match(loaded, ssid):
    match = loaded.resolve_matched_ssid_pattern_for_eval(ssid)
    assert match is None, (
        f"{ssid!r} matched bundled signature {match.watchlist_id} "
        f"({match.manufacturer}) — a false positive here tells the operator a "
        "surveillance device is nearby when it is a neighbour's router"
    )


@pytest.mark.parametrize("name", _SHOULD_MATCH_BLE)
def test_a_real_device_ble_name_matches(loaded, name):
    assert loaded.resolve_matched_ble_local_name_for_eval(name) is not None, name


@pytest.mark.parametrize("name", _SHOULD_NOT_MATCH_BLE)
def test_an_ordinary_ble_name_does_not_match(loaded, name):
    match = loaded.resolve_matched_ble_local_name_for_eval(name)
    assert match is None, (
        f"{name!r} matched bundled signature {match.watchlist_id} "
        f"({match.manufacturer})"
    )


def test_underscore_in_a_needle_is_a_literal_not_a_wildcard(loaded):
    """⛔ The one that nearly shipped a false positive.

    `_` is LIKE's any-single-character wildcard. The generic stems in this data
    are deliberately anchored to the separator the vendor uses — `phantom-` and
    `phantom_` — precisely so the dictionary word `phantom` cannot fire on its
    own. Unescaped, `phantom_` means "phantom followed by ANY character", which
    matched `phantom ` and alerted on **Phantom Gaming 5G**. The separator that
    was supposed to make the stem safe was the thing making it generic again.

    Measured during development: `InspireWiFi`, `Phantom Gaming 5G` and `Parrot
    Cafe` all matched before the needle was escaped.
    """
    assert loaded.resolve_matched_ssid_pattern_for_eval("PhantomXGaming") is None
    assert loaded.resolve_matched_ssid_pattern_for_eval("inspireX") is None
    # And the literal separator forms still work, or the escaping went too far.
    assert loaded.resolve_matched_ssid_pattern_for_eval("Phantom_4") is not None
    assert loaded.resolve_matched_ssid_pattern_for_eval("Phantom-4") is not None


def test_percent_in_an_observed_name_cannot_widen_a_match(loaded):
    """The sibling wildcard. A needle containing `%` would match everything."""
    with loaded._conn:
        loaded._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity) VALUES (?, ?, ?)",
            ("zz%zz", "ssid_pattern", "high"),
        )
    try:
        assert loaded.resolve_matched_ssid_pattern_for_eval("zzANYTHINGzz") is None
        assert loaded.resolve_matched_ssid_pattern_for_eval("my-zz%zz-net") is not None
    finally:
        with loaded._conn:
            loaded._conn.execute("DELETE FROM watchlist WHERE pattern = 'zz%zz'")
