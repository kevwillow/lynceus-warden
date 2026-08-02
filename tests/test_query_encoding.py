"""Local validation for URL-encoding of the /devices + /watchful
search/filter query strings in their pagination links (0.9.0 fix).

Before the fix the templates built pagination hrefs by raw string
concatenation (``'q=' ~ q``), so a devices search like ``AT&T`` emitted
``q=AT&T`` -- the bare ``&`` silently truncated the query string,
dropping the search term (and every param after it) the moment the
operator paged. ``#`` / space / ``+`` mis-parse the same way. The fix
runs each text-valued param value through Jinja's ``| urlencode`` filter,
leaving the ``=`` / ``&`` separators intact.

These tests assert the *rendered pagination href* carries the ENCODED
value (e.g. ``q=AT%26T``, never ``q=AT&T``) and that following that
exact href re-applies the search and composes with an active filter.

The request URL is built with ``urllib.parse.quote`` so the value the
server receives is unambiguous; the rendered href is HTML-unescaped
(``&amp;`` -> ``&``) before it is followed, exactly as a browser would.

tests/ is gitignored: local-only validation, never committed. Run with
the pinned 3.11 venv.
"""

from __future__ import annotations

import html
import re
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import create_app

NOW = 1_700_002_000

# The four characters that break a raw query string, each paired with the
# percent-encoded form the pagination href must carry instead.
_SPECIAL_TERMS = [
    ("AT&T", "AT%26T"),   # & -> truncates the query string at the value
    ("a#b", "a%23b"),     # # -> starts a fragment
    ("a b", "a%20b"),     # space -> illegal raw in a URL
    ("a+b", "a%2Bb"),     # + -> would decode back to a space
]


def _make_db(tmp_path) -> tuple[Config, Database]:
    config = Config(
        db_path=str(tmp_path / "qenc.db"),
        kismet_health_check_on_startup=False,
        evidence_capture_enabled=False,
    )
    return config, Database(config.db_path)


# --------------------------------------------------------------------------
# /devices -- the search now matches free-text columns (vendor/name/ssid)
# that routinely contain & # + and spaces, so this is the real bug surface.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("term,encoded", _SPECIAL_TERMS)
def test_devices_pagination_encodes_search_term(tmp_path, term, encoded):
    """11 vendor==<term> devices, page_size=10 -> 2 pages. The next-page
    href must carry ``q=<encoded>``; the raw term -- which would truncate
    or mis-parse the query string -- must never appear in a link."""
    config, db = _make_db(tmp_path)
    try:
        db.ensure_location("default", "Default Location")
        for i in range(11):
            db.upsert_device(mac=f"ac:de:00:00:00:{i:02x}", device_type="wifi",
                             oui_vendor=term, is_randomized=0, now_ts=NOW + i)
        app = create_app(config, db)
        with TestClient(app) as client:
            r = client.get(f"/devices?q={quote(term)}&page_size=10")
        assert r.status_code == 200
        assert "11 device(s) total" in r.text          # all matched -> 2 pages
        assert f"q={encoded}" in r.text                 # encoded value in nav link
        assert f"q={term}" not in r.text                # never the raw, breaking form
    finally:
        db.close()


def test_devices_search_roundtrips_through_pagination_and_filter(tmp_path):
    """The AT&T case end to end: the next-page href encodes the term AND
    preserves the device_type filter; following that exact href re-applies
    both -- the search still narrows and the non-matching decoy stays
    hidden on page 2 -- proving the encoded link is functional, not just
    well-formed."""
    config, db = _make_db(tmp_path)
    try:
        db.ensure_location("default", "Default Location")
        for i in range(11):
            db.upsert_device(mac=f"a7:00:00:00:00:{i:02x}", device_type="wifi",
                             oui_vendor="AT&T", is_randomized=0, now_ts=NOW + i)
        # A wifi decoy that does NOT match the search: must stay hidden
        # under the AT&T filter on either page.
        db.upsert_device(mac="ff:ff:ff:ff:ff:ff", device_type="wifi",
                         oui_vendor="Other", is_randomized=0, now_ts=NOW)
        app = create_app(config, db)
        with TestClient(app) as client:
            r1 = client.get(f"/devices?q={quote('AT&T')}&device_type=wifi&page_size=10")
            assert r1.status_code == 200
            assert "11 device(s) total" in r1.text
            assert "q=AT%26T" in r1.text                 # search encoded...
            assert "device_type=wifi" in r1.text         # ...filter composed in
            assert "q=AT&T" not in r1.text               # never the raw form
            assert "ff:ff:ff:ff:ff:ff" not in r1.text    # decoy excluded
            # Pull the rendered next-page href and follow it verbatim, as a
            # browser would (HTML-unescaping the &amp; separators first).
            m = re.search(r'href="(/devices\?[^"]*page=2[^"]*)"', r1.text)
            assert m, "next-page href not found on page 1"
            next_href = html.unescape(m.group(1))
            assert "q=AT%26T" in next_href
            r2 = client.get(next_href)
        assert r2.status_code == 200
        assert "ff:ff:ff:ff:ff:ff" not in r2.text        # search still applied
        assert "a7:00:00:00:00:00" in r2.text            # 11th match (i=0, oldest)
    finally:
        db.close()


# --------------------------------------------------------------------------
# /watchful -- q is a MAC substring, so real data only ever contains
# hex+colons. The colon already needs encoding (``:`` -> ``%3A``), and the
# link-building was the same latent pattern, so we exercise both a
# realistic colon term and a synthetic ``&`` term (raw MAC inserts bypass
# format checks) to prove the truncation class is closed here too.
# --------------------------------------------------------------------------

def _insert_watchful(db, mac, *, ts=NOW):
    db._conn.execute(
        "INSERT INTO watchful_recurrence("
        "mac, created_at, first_seen_at, last_seen_at, sighting_count) "
        "VALUES (?, ?, ?, ?, 1)",
        (mac, ts, ts, ts),
    )
    db._conn.commit()


@pytest.mark.parametrize("term,encoded", [("aa:bb", "aa%3Abb"), ("a&b", "a%26b")])
def test_watchful_pagination_encodes_search_term(tmp_path, term, encoded):
    """26 rows whose MAC contains <term>, page_size=25 -> 2 pages. The
    next-page href must carry ``q=<encoded>`` (``:`` -> ``%3A`` for a real
    MAC substring; ``&`` -> ``%26`` for the truncation class), never the
    raw value."""
    config, db = _make_db(tmp_path)
    try:
        for i in range(26):
            _insert_watchful(db, mac=f"{term}:00:00:00:{i:02x}")
        app = create_app(config, db)
        with TestClient(app) as client:
            r = client.get(f"/watchful?q={quote(term)}&page_size=25")
        assert r.status_code == 200
        assert "26 total" in r.text                      # all matched -> 2 pages
        assert f"q={encoded}" in r.text                  # encoded value in nav link
        assert f"q={term}" not in r.text                 # never the raw form
    finally:
        db.close()


def test_watchful_search_roundtrips_through_pagination(tmp_path):
    """Realistic colon term end to end: the next-page href encodes the MAC
    substring, and following it keeps the search applied -- the
    non-matching decoy stays hidden on page 2."""
    config, db = _make_db(tmp_path)
    try:
        for i in range(26):
            _insert_watchful(db, mac=f"aa:bb:cc:00:{i // 256:02x}:{i % 256:02x}")
        # Decoy MAC without the "aa:bb" substring: must never appear.
        _insert_watchful(db, mac="ff:ee:dd:cc:bb:99")
        app = create_app(config, db)
        with TestClient(app) as client:
            r1 = client.get(f"/watchful?q={quote('aa:bb')}&page_size=25")
            assert r1.status_code == 200
            assert "26 total" in r1.text                 # decoy excluded from count
            assert "q=aa%3Abb" in r1.text
            assert "q=aa:bb" not in r1.text
            assert "ff:ee:dd:cc:bb:99" not in r1.text
            m = re.search(r'href="(/watchful\?[^"]*page=2[^"]*)"', r1.text)
            assert m, "next-page href not found on page 1"
            next_href = html.unescape(m.group(1))
            assert "q=aa%3Abb" in next_href
            r2 = client.get(next_href)
        assert r2.status_code == 200
        assert "ff:ee:dd:cc:bb:99" not in r2.text        # search still applied
    finally:
        db.close()
