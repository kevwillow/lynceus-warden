"""Local validation for the /devices search bar (0.9.0 arc).

Mirrors the /watchful ``q`` filter (form GET, param ``q``, 100-char cap,
strip-to-None empty handling), widened to the identity columns the
devices table surfaces: mac, ble_name, oui_vendor, and the device's
*last* SSID (the value rendered in the "Last SSID" column). Operator
decision for this arc: search those four columns (MAC + name + vendor +
SSID).

tests/ is gitignored; this file is local-only validation and is never
committed. Run with the pinned 3.11 venv.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import create_app

NOW = 1_700_001_000


def _make_db(tmp_path) -> tuple[Config, Database]:
    config = Config(
        db_path=str(tmp_path / "devsearch.db"),
        kismet_health_check_on_startup=False,
        evidence_capture_enabled=False,
    )
    db = Database(config.db_path)
    return config, db


def _seed(db: Database) -> None:
    """A small mix exercising every searched column.

    - a4:83:e7… wifi, vendor Apple, no ble_name, last SSID 'HomeNet'
      (also carries an OLDER 'OldGuestNet' sighting to prove only the
      last SSID is matched, not the whole history).
    - 02:11:22… wifi, vendor None, no ble_name, no sighting (random).
    - 06:aa:bb… ble, vendor Unknown, ble_name 'Tile_AB12'.
    - 00:1a:7d… bt_classic, vendor Cambridge Silicon, ble_name
      'Sony WH-1000XM4'.
    - 5a:11:22… ble, vendor Apple, no ble_name (so an 'Apple' search
      hits two devices across two types — used for the compose test).
    """
    db.ensure_location("default", "Default Location")
    db.upsert_device(mac="a4:83:e7:11:22:33", device_type="wifi",
                     oui_vendor="Apple", is_randomized=0, now_ts=NOW)
    db.upsert_device(mac="02:11:22:33:44:55", device_type="wifi",
                     oui_vendor=None, is_randomized=1, now_ts=NOW)
    db.upsert_device(mac="06:aa:bb:cc:dd:ee", device_type="ble",
                     oui_vendor="Unknown", is_randomized=1, now_ts=NOW)
    db.update_device_ble_name("06:aa:bb:cc:dd:ee", "Tile_AB12")
    db.upsert_device(mac="00:1a:7d:da:71:11", device_type="bt_classic",
                     oui_vendor="Cambridge Silicon", is_randomized=0, now_ts=NOW)
    db.update_device_ble_name("00:1a:7d:da:71:11", "Sony WH-1000XM4")
    db.upsert_device(mac="5a:11:22:33:44:55", device_type="ble",
                     oui_vendor="Apple", is_randomized=1, now_ts=NOW)
    # Apple wifi device: older OldGuestNet, then newer HomeNet (the last).
    db.insert_sighting("a4:83:e7:11:22:33", NOW - 100, -40, "OldGuestNet", "default")
    db.insert_sighting("a4:83:e7:11:22:33", NOW - 10, -42, "HomeNet", "default")


# --------------------------------------------------------------------------
# DB layer: the shared filter builder feeds list + count identically.
# --------------------------------------------------------------------------

def test_db_search_matches_mac_substring(tmp_path):
    _, db = _make_db(tmp_path)
    try:
        _seed(db)
        macs = {d["mac"] for d in db.list_devices(q="1a:7d")}
        assert macs == {"00:1a:7d:da:71:11"}
        assert db.count_devices(q="1a:7d") == 1
    finally:
        db.close()


def test_db_search_matches_ble_name(tmp_path):
    _, db = _make_db(tmp_path)
    try:
        _seed(db)
        macs = {d["mac"] for d in db.list_devices(q="Sony")}
        assert macs == {"00:1a:7d:da:71:11"}
    finally:
        db.close()


def test_db_search_matches_vendor_case_insensitive(tmp_path):
    """SQLite LIKE is ASCII case-insensitive: 'apple' matches 'Apple'."""
    _, db = _make_db(tmp_path)
    try:
        _seed(db)
        macs = {d["mac"] for d in db.list_devices(q="apple")}
        assert macs == {"a4:83:e7:11:22:33", "5a:11:22:33:44:55"}
    finally:
        db.close()


def test_db_search_matches_last_ssid_only(tmp_path):
    """The SSID term matches the *last* sighting's SSID (the rendered
    'Last SSID'), not older history — searching the superseded SSID
    must NOT match, so a hit always corresponds to a visible cell."""
    _, db = _make_db(tmp_path)
    try:
        _seed(db)
        assert {d["mac"] for d in db.list_devices(q="HomeNet")} == {
            "a4:83:e7:11:22:33"
        }
        assert db.list_devices(q="OldGuestNet") == []
    finally:
        db.close()


def test_db_search_composes_with_type_filter(tmp_path):
    """'Apple' alone hits two devices (wifi + ble); adding
    device_type='wifi' narrows to the wifi one — both predicates AND,
    neither overrides the other."""
    _, db = _make_db(tmp_path)
    try:
        _seed(db)
        assert db.count_devices(q="Apple") == 2
        macs = {d["mac"] for d in db.list_devices(q="Apple", device_type="wifi")}
        assert macs == {"a4:83:e7:11:22:33"}
        assert db.count_devices(q="Apple", device_type="wifi") == 1
    finally:
        db.close()


def test_db_search_empty_returns_all(tmp_path):
    _, db = _make_db(tmp_path)
    try:
        _seed(db)
        assert db.count_devices(q=None) == 5
        assert len(db.list_devices(q=None)) == 5
    finally:
        db.close()


def test_db_count_and_list_agree_under_search(tmp_path):
    """The shared _device_filter_sql keeps COUNT and SELECT in lockstep
    so pagination totals never drift from the rendered rows."""
    _, db = _make_db(tmp_path)
    try:
        _seed(db)
        for q in ("Apple", "Sony", "1a", "HomeNet", "zzz-no-match"):
            assert db.count_devices(q=q) == len(db.list_devices(q=q)), q
    finally:
        db.close()


# --------------------------------------------------------------------------
# Route layer: mirrors the watchful form-GET behavior end to end.
# --------------------------------------------------------------------------

def test_route_search_filters_list(tmp_path):
    config, db = _make_db(tmp_path)
    try:
        _seed(db)
        app = create_app(config, db)
        with TestClient(app) as client:
            r = client.get("/devices?q=Sony")
        assert r.status_code == 200
        assert "00:1a:7d:da:71:11" in r.text
        assert "a4:83:e7:11:22:33" not in r.text
        # Search appears in the filter summary so the operator sees it.
        assert "search=Sony" in r.text
    finally:
        db.close()


def test_route_search_composes_with_type(tmp_path):
    config, db = _make_db(tmp_path)
    try:
        _seed(db)
        app = create_app(config, db)
        with TestClient(app) as client:
            r = client.get("/devices?q=Apple&device_type=wifi")
        assert r.status_code == 200
        assert "a4:83:e7:11:22:33" in r.text  # Apple + wifi
        assert "5a:11:22:33:44:55" not in r.text  # Apple but ble
        assert "1 device(s) total" in r.text
    finally:
        db.close()


def test_route_search_whitespace_is_unfiltered(tmp_path):
    config, db = _make_db(tmp_path)
    try:
        _seed(db)
        app = create_app(config, db)
        with TestClient(app) as client:
            r = client.get("/devices?q=%20%20%20")
        assert r.status_code == 200
        assert "5 device(s) total" in r.text
    finally:
        db.close()


def test_route_search_preserved_across_pages(tmp_path):
    """11 vendor='Acme' devices, page_size=10 -> 2 pages; the next link
    carries q=Acme, and page 2 returns the 11th match."""
    config, db = _make_db(tmp_path)
    try:
        db.ensure_location("default", "Default Location")
        for i in range(11):
            db.upsert_device(mac=f"ac:de:00:00:00:{i:02x}", device_type="wifi",
                             oui_vendor="Acme", is_randomized=0, now_ts=NOW + i)
        # A non-matching decoy that must never appear under the search.
        db.upsert_device(mac="ff:ff:ff:ff:ff:ff", device_type="wifi",
                         oui_vendor="Other", is_randomized=0, now_ts=NOW)
        app = create_app(config, db)
        with TestClient(app) as client:
            r1 = client.get("/devices?q=Acme&page_size=10")
            r2 = client.get("/devices?q=Acme&page_size=10&page=2")
        assert r1.status_code == 200 and r2.status_code == 200
        assert "11 device(s) total" in r1.text
        assert "q=Acme" in r1.text          # search preserved in nav links
        assert "page=2" in r1.text          # next link present
        assert "ff:ff:ff:ff:ff:ff" not in r1.text
        assert "ff:ff:ff:ff:ff:ff" not in r2.text
        # Page 2 holds exactly the 11th match (last_seen DESC -> i=0 row).
        assert "ac:de:00:00:00:00" in r2.text
    finally:
        db.close()


def test_route_search_is_read_only(tmp_path):
    """A search is a GET filter: no rows created/removed, POST not allowed."""
    config, db = _make_db(tmp_path)
    try:
        _seed(db)
        before = db.count_devices()
        app = create_app(config, db)
        with TestClient(app) as client:
            assert client.get("/devices?q=Apple").status_code == 200
            # No POST surface for search: the CSRF middleware rejects the
            # unsafe method (403) before routing, and there is no /devices
            # POST route anyway (405). Either way it's not a 2xx mutation.
            assert client.post("/devices?q=Apple").status_code in (403, 405)
        assert db.count_devices() == before == 5
    finally:
        db.close()


def test_route_search_over_100_chars_rejected(tmp_path):
    """Mirrors the watchful 100-char cap."""
    config, db = _make_db(tmp_path)
    try:
        _seed(db)
        app = create_app(config, db)
        with TestClient(app) as client:
            r = client.get("/devices?q=" + "a" * 101)
        assert r.status_code == 400
    finally:
        db.close()
