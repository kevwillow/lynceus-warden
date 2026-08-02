"""Local-only tests for ble_device_class persistence (migration 023).

tests/ is gitignored — these are NEVER committed (see project memory).
"""

from __future__ import annotations

from lynceus.ble_continuity import CLASS_AIRPODS, CLASS_FIND_MY
from lynceus.db import Database


def _db(tmp_path):
    return Database(str(tmp_path / "t.db"))


def test_upsert_stores_device_class(tmp_path):
    db = _db(tmp_path)
    db.upsert_device(
        mac="aa:bb:cc:dd:ee:ff",
        device_type="ble",
        oui_vendor=None,
        is_randomized=0,
        now_ts=100,
        ble_device_class=CLASS_FIND_MY,
    )
    assert db.get_device("aa:bb:cc:dd:ee:ff")["ble_device_class"] == CLASS_FIND_MY


def test_none_does_not_clobber_existing_class(tmp_path):
    """A later partial advert must not erase a class we already learned."""
    db = _db(tmp_path)
    db.upsert_device(
        mac="aa:bb:cc:dd:ee:ff",
        device_type="ble",
        oui_vendor=None,
        is_randomized=0,
        now_ts=100,
        ble_device_class=CLASS_FIND_MY,
    )
    db.upsert_device(
        mac="aa:bb:cc:dd:ee:ff",
        device_type="ble",
        oui_vendor=None,
        is_randomized=0,
        now_ts=200,
        ble_device_class=None,
    )
    assert db.get_device("aa:bb:cc:dd:ee:ff")["ble_device_class"] == CLASS_FIND_MY


def test_new_class_overwrites_old(tmp_path):
    db = _db(tmp_path)
    for ts, cls in ((100, CLASS_FIND_MY), (200, CLASS_AIRPODS)):
        db.upsert_device(
            mac="aa:bb:cc:dd:ee:ff",
            device_type="ble",
            oui_vendor=None,
            is_randomized=0,
            now_ts=ts,
            ble_device_class=cls,
        )
    assert db.get_device("aa:bb:cc:dd:ee:ff")["ble_device_class"] == CLASS_AIRPODS


def test_sighting_count_still_increments_with_class(tmp_path):
    """The COALESCE addition must not disturb the existing upsert semantics."""
    db = _db(tmp_path)
    for ts in (100, 200, 300):
        db.upsert_device(
            mac="aa:bb:cc:dd:ee:ff",
            device_type="ble",
            oui_vendor=None,
            is_randomized=0,
            now_ts=ts,
            ble_device_class=CLASS_FIND_MY,
        )
    row = db.get_device("aa:bb:cc:dd:ee:ff")
    assert row["sighting_count"] == 3
    assert row["last_seen"] == 300
    assert row["first_seen"] == 100


def test_default_arg_keeps_existing_callers_working(tmp_path):
    db = _db(tmp_path)
    db.upsert_device(
        mac="aa:bb:cc:dd:ee:01",
        device_type="wifi",
        oui_vendor=None,
        is_randomized=0,
        now_ts=100,
    )
    assert db.get_device("aa:bb:cc:dd:ee:01")["ble_device_class"] is None


def test_list_devices_exposes_class(tmp_path):
    db = _db(tmp_path)
    db.upsert_device(
        mac="aa:bb:cc:dd:ee:ff",
        device_type="ble",
        oui_vendor=None,
        is_randomized=0,
        now_ts=100,
        ble_device_class=CLASS_AIRPODS,
    )
    rows = db.list_devices(limit=10)
    assert rows[0]["ble_device_class"] == CLASS_AIRPODS


def test_get_device_with_sightings_exposes_class(tmp_path):
    """The detail page reads through this enumerated-column query, not
    get_device's SELECT * — it needs the column explicitly."""
    db = _db(tmp_path)
    db.upsert_device(
        mac="aa:bb:cc:dd:ee:ff",
        device_type="ble",
        oui_vendor=None,
        is_randomized=0,
        now_ts=100,
        ble_device_class=CLASS_AIRPODS,
    )
    # Returns a nested {"device": ..., "sightings": [...]} shape.
    row = db.get_device_with_sightings("aa:bb:cc:dd:ee:ff")
    assert row["device"]["ble_device_class"] == CLASS_AIRPODS
