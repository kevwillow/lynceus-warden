"""Local validation for /devices server-side column sort + the reusable
table macro (0.9.2 table-UX arc, Touch 1).

Covers the brief's VALIDATE checklist:
  1. Each sortable column asc/desc reorders the DB result correctly.
  2. sort + preset-filter + pagination COMPOSE in the URL (changing sort
     preserves filters + page_size; changing page preserves sort).
  3. Unknown/garbage ?sort= falls back silently to the default (no 500),
     and cannot inject SQL.
  4. The pagination_footer macro serves BOTH footer idioms (individual
     vars now; structurally the pagination-object path).
Plus a regression guard that the no-param default ordering is unchanged
(last_seen DESC, mac).

tests/ is gitignored; this file is local-only validation and is never
committed. Run with the pinned 3.11 venv.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import create_app

# Four devices, every sortable column given fully distinct values so the
# expected order under each key is unambiguous (no ties to reason about
# except where deliberately probing the mac tie-break).
A = "11:00:00:00:00:01"
B = "22:00:00:00:00:02"
C = "33:00:00:00:00:03"
D = "44:00:00:00:00:04"

# mac, type, first_seen, last_seen, sighting_count, vendor, rand, ble, rssi, ssid
_ROWS = [
    (A, "wifi",       100, 400, 2, "delta",   0, "alpha",   -30, "net-d"),
    (B, "ble",        200, 300, 4, "charlie", 1, "bravo",   -50, "net-c"),
    (C, "bt_classic", 300, 200, 1, "bravo",   0, "charlie", -70, "net-b"),
    (D, "wifi",       400, 100, 3, "alpha",   1, "delta",   -90, "net-a"),
]


def _make_db(tmp_path) -> tuple[Config, Database]:
    config = Config(
        db_path=str(tmp_path / "devsort.db"),
        kismet_health_check_on_startup=False,
        evidence_capture_enabled=False,
    )
    return config, Database(config.db_path)


def _seed(db: Database) -> None:
    db.ensure_location("default", "Default Location")
    with db._conn:
        for mac, dtype, fs, ls, cnt, vendor, rand, ble, _rssi, _ssid in _ROWS:
            db._conn.execute(
                "INSERT INTO devices(mac, device_type, first_seen, last_seen, "
                "sighting_count, oui_vendor, is_randomized, ble_name) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (mac, dtype, fs, ls, cnt, vendor, rand, ble),
            )
    for mac, *_rest in _ROWS:
        rssi, ssid = _rest[-2], _rest[-1]
        db.insert_sighting(mac, 1000, rssi, ssid, "default")


def _order(db, sort, direction):
    return [d["mac"] for d in db.list_devices(sort=sort, direction=direction, limit=200)]


# Expected ascending order per key; descending is the reverse ONLY for
# keys with no ties. Tie-bearing keys (is_randomized, device_type) are
# listed explicitly for both directions because the mac tie-break stays
# ascending regardless of the primary direction.
_ASC = {
    "mac": [A, B, C, D],
    "oui_vendor": [D, C, B, A],          # alpha, bravo, charlie, delta
    "ble_name": [A, B, C, D],            # alpha, bravo, charlie, delta
    "first_seen": [A, B, C, D],          # 100,200,300,400
    "last_seen": [D, C, B, A],           # 100,200,300,400
    "sighting_count": [C, A, D, B],      # 1,2,3,4
    "last_rssi": [D, C, B, A],           # -90,-70,-50,-30
    "last_ssid": [D, C, B, A],           # net-a,b,c,d
}


def test_db_each_clean_column_sorts_both_directions(tmp_path):
    _, db = _make_db(tmp_path)
    try:
        _seed(db)
        for key, asc in _ASC.items():
            assert _order(db, key, "asc") == asc, f"{key} asc"
            assert _order(db, key, "desc") == list(reversed(asc)), f"{key} desc"
    finally:
        db.close()


def test_db_tiebreak_columns_use_mac_secondary(tmp_path):
    _, db = _make_db(tmp_path)
    try:
        _seed(db)
        # is_randomized: A=0,C=0,B=1,D=1 -> mac asc within each group.
        assert _order(db, "is_randomized", "asc") == [A, C, B, D]
        assert _order(db, "is_randomized", "desc") == [B, D, A, C]
        # device_type string order: ble(B) < bt_classic(C) < wifi(A,D mac asc).
        assert _order(db, "device_type", "asc") == [B, C, A, D]
        assert _order(db, "device_type", "desc") == [A, D, C, B]
    finally:
        db.close()


def test_db_default_matches_legacy_ordering(tmp_path):
    """No-param default must reproduce the prior ORDER BY last_seen DESC,
    mac exactly -- the regression guard for 'no query params behaves as
    before'."""
    _, db = _make_db(tmp_path)
    try:
        _seed(db)
        assert _order(db, "last_seen", "desc") == [A, B, C, D]
        assert [d["mac"] for d in db.list_devices(limit=200)] == [A, B, C, D]
    finally:
        db.close()


def test_db_bad_sort_falls_back_no_injection(tmp_path):
    _, db = _make_db(tmp_path)
    try:
        _seed(db)
        # Garbage + an injection attempt both fall back to default order.
        for bad in ("bogus", "mac); DROP TABLE devices--", ""):
            assert _order(db, bad, "desc") == [A, B, C, D], bad
        # Non-asc direction normalizes to DESC at the DB layer.
        assert _order(db, "mac", "sideways") == [D, C, B, A]
        assert db.count_devices() == 4  # table intact
    finally:
        db.close()


def test_route_sort_changes_rendered_order(tmp_path):
    config, db = _make_db(tmp_path)
    try:
        _seed(db)
        app = create_app(config, db)
        with TestClient(app) as client:
            r = client.get("/devices?sort=oui_vendor&dir=asc")
        assert r.status_code == 200
        # vendor asc -> D (alpha) before A (delta) in the body.
        assert r.text.index(D) < r.text.index(A)
        # active-column affordance present.
        assert "th-sort-active" in r.text
        assert 'aria-sort="ascending"' in r.text
        assert "&#9650;" in r.text  # the asc caret entity
    finally:
        db.close()


def test_route_sort_filter_pagination_compose(tmp_path):
    config, db = _make_db(tmp_path)
    try:
        _seed(db)
        app = create_app(config, db)
        with TestClient(app) as client:
            # sort + preset filter together: only wifi rows, ordered by
            # first_seen asc (A=100 then D=400).
            r = client.get("/devices?device_type=wifi&sort=first_seen&dir=asc")
            assert r.status_code == 200
            assert B not in r.text and C not in r.text  # non-wifi excluded
            assert r.text.index(A) < r.text.index(D)
            # Sort header links carry the active filter (so clicking a
            # different column keeps device_type=wifi).
            assert "device_type=wifi" in r.text
            assert "sort=last_seen" in r.text  # some other header link
            # Pagination preserves the active sort. Need >1 page, and the
            # page size must be an allowed value (2 would silently clamp to
            # the default 50). Add fillers to reach 14 rows, page_size=10.
            with db._conn:
                for i in range(10):
                    db._conn.execute(
                        "INSERT INTO devices(mac, device_type, first_seen, "
                        "last_seen, sighting_count, is_randomized) "
                        "VALUES (?, 'wifi', 1, 1, 0, 0)",
                        (f"aa:00:00:00:00:{i:02x}",),
                    )
            r2 = client.get("/devices?sort=mac&dir=asc&page_size=10")
            assert r2.status_code == 200
            # The next link composes filter+sort+dir+page (page 1 of 2).
            assert "sort=mac" in r2.text
            assert "dir=asc" in r2.text
            assert "page=2" in r2.text
    finally:
        db.close()


def test_route_bad_input_no_500(tmp_path):
    config, db = _make_db(tmp_path)
    try:
        _seed(db)
        app = create_app(config, db)
        with TestClient(app) as client:
            for url in (
                "/devices?sort=bogus&dir=asc",
                "/devices?sort=mac;DROP%20TABLE%20devices--",
                "/devices?dir=sideways",
                "/devices?sort=&dir=",
            ):
                assert client.get(url).status_code == 200, url
    finally:
        db.close()


def test_footer_macro_serves_both_idioms(tmp_path):
    """The pagination_footer macro renders the minimal individual-vars
    footer (devices) and, when total+per_page are supplied, the richer
    pagination-object footer (alerts/watchlist/...)."""
    config, db = _make_db(tmp_path)
    try:
        app = create_app(config, db)
        env = app.state.templates.env
        # Idiom B (individual vars): minimal "page X of Y", no extras.
        b = env.from_string(
            "{% from '_table_macro.html' import pagination_footer %}"
            "{{ pagination_footer('/devices', 'page_size=50', 2, 5) }}"
        ).render()
        assert "page 2 of 5" in b
        assert "total" not in b and "per_page=" not in b
        assert "page=1" in b and "page=3" in b  # prev + next targets
        # Idiom A (pagination object): appends "· N total · per_page=K".
        a = env.from_string(
            "{% from '_table_macro.html' import pagination_footer %}"
            "{{ pagination_footer('/alerts', 'page_size=50', 2, 5,"
            " total=42, per_page=25) }}"
        ).render()
        assert "page 2 of 5" in a
        assert "42 total" in a and "per_page=25" in a
        # Boundaries: page 1 has no prev link; last page has no next link.
        first = env.from_string(
            "{% from '_table_macro.html' import pagination_footer %}"
            "{{ pagination_footer('/devices', 'page_size=50', 1, 3) }}"
        ).render()
        assert "page=0" not in first
        last = env.from_string(
            "{% from '_table_macro.html' import pagination_footer %}"
            "{{ pagination_footer('/devices', 'page_size=50', 3, 3) }}"
        ).render()
        assert "page=4" not in last
    finally:
        db.close()
