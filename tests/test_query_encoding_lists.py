"""Local validation for URL-encoding of the /alerts + /allowlist +
/watchlist search/filter query strings in their pagination links.

Sibling of test_query_encoding.py (which covered /devices + /watchful).
Those three list templates carried the same latent raw-concatenation
pattern (``'q=' ~ q`` ... ``qs | join('&')``): a search term containing
``&`` emitted ``q=AT&T``, whose bare ``&`` silently truncated the query
string -- dropping the search term and every param after it the moment
the operator paged. ``#`` / space / ``+`` mis-parse the same way. The fix
runs each text-valued param value through Jinja's ``| urlencode`` filter,
leaving the ``=`` / ``&`` separators intact.

These tests assert the *rendered pagination href* carries the ENCODED
value (e.g. ``q=AT%26T``, never ``q=AT&T``) and that following that exact
href re-applies the search -- the non-matching decoy stays excluded and
the total stays narrowed -- proving the encoded link is functional, not
just well-formed.

The rendered href is HTML-unescaped (``&amp;`` -> ``&``) before it is
followed, exactly as a browser would.

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


def _make_db(tmp_path, **config_kw) -> tuple[Config, Database]:
    config = Config(
        db_path=str(tmp_path / "qenc.db"),
        kismet_health_check_on_startup=False,
        evidence_capture_enabled=False,
        **config_kw,
    )
    return config, Database(config.db_path)


def _next_href(text: str, path: str) -> str:
    """Pull the rendered next-page href and unescape it as a browser would."""
    m = re.search(rf'href="({re.escape(path)}\?[^"]*page=2[^"]*)"', text)
    assert m, f"next-page href not found for {path}"
    return html.unescape(m.group(1))


# --------------------------------------------------------------------------
# /alerts -- q is the device search (matches mac / message / vendor); a
# free-text term routinely contains & # + and spaces.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("term,encoded", _SPECIAL_TERMS)
def test_alerts_pagination_encodes_search_term(tmp_path, term, encoded):
    """26 alerts whose message contains <term>, page_size=25 -> 2 pages.
    The next-page href must carry ``q=<encoded>``; the raw term -- which
    would truncate or mis-parse the query string -- must never appear in
    the href. (The filter-summary line renders the raw term as display
    text by design; the assertion is scoped to the pagination href.)"""
    config, db = _make_db(tmp_path)
    try:
        for i in range(26):
            db.add_alert(ts=NOW + i, rule_name="r", mac=None,
                         message=f"{term} hit {i}", severity="low")
        app = create_app(config, db)
        with TestClient(app) as client:
            r = client.get(f"/alerts?q={quote(term)}&page_size=25")
        assert r.status_code == 200
        assert "26 total" in r.text                  # all matched -> 2 pages
        href = _next_href(r.text, "/alerts")
        assert f"q={encoded}" in href                # encoded value in nav link
        assert f"q={term}" not in href               # never the raw, breaking form
    finally:
        db.close()


def test_alerts_search_roundtrips_through_pagination(tmp_path):
    """The AT&T case end to end: the next-page href encodes the term, and
    following that exact href keeps the search applied -- the non-matching
    decoy stays excluded from the count and from page 2."""
    config, db = _make_db(tmp_path)
    try:
        for i in range(26):
            db.add_alert(ts=NOW + i, rule_name="r", mac=None,
                         message=f"AT&T hit {i}", severity="low")
        # A decoy alert that does NOT match the search: must never count.
        db.add_alert(ts=NOW + 99, rule_name="r", mac=None,
                     message="Other boring decoy", severity="low")
        app = create_app(config, db)
        with TestClient(app) as client:
            r1 = client.get(f"/alerts?q={quote('AT&T')}&page_size=25")
            assert r1.status_code == 200
            assert "26 total" in r1.text             # decoy excluded from count
            assert "q=AT%26T" in r1.text             # search encoded
            assert "q=AT&T" not in r1.text           # never the raw form
            assert "Other boring decoy" not in r1.text
            next_href = _next_href(r1.text, "/alerts")
            assert "q=AT%26T" in next_href
            r2 = client.get(next_href)
        assert r2.status_code == 200
        assert "26 total" in r2.text                 # filter survived paging
        assert "Other boring decoy" not in r2.text   # search still applied
        assert "hit 0" in r2.text                    # oldest match on page 2
    finally:
        db.close()


# --------------------------------------------------------------------------
# /watchlist -- q matches pattern / vendor / argus id / category.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("term,encoded", _SPECIAL_TERMS)
def test_watchlist_pagination_encodes_search_term(tmp_path, term, encoded):
    """26 ssid patterns containing <term>, page_size=25 -> 2 pages. The
    next-page href must carry ``q=<encoded>``, never the raw value."""
    config, db = _make_db(tmp_path)
    try:
        for i in range(26):
            db.add_watchlist(pattern=f"{term}-net-{i:02d}",
                             pattern_type="ssid", severity="low")
        app = create_app(config, db)
        with TestClient(app) as client:
            r = client.get(f"/watchlist?q={quote(term)}&page_size=25")
        assert r.status_code == 200
        assert "26 total" in r.text
        href = _next_href(r.text, "/watchlist")
        assert f"q={encoded}" in href
        assert f"q={term}" not in href
    finally:
        db.close()


def test_watchlist_search_roundtrips_through_pagination(tmp_path):
    """AT&T end to end: the next-page href encodes the term, and following
    it keeps the search applied -- the non-matching decoy stays excluded."""
    config, db = _make_db(tmp_path)
    try:
        for i in range(26):
            db.add_watchlist(pattern=f"AT&T-net-{i:02d}",
                             pattern_type="ssid", severity="low")
        db.add_watchlist(pattern="Other-net-decoy",
                         pattern_type="ssid", severity="low")
        app = create_app(config, db)
        with TestClient(app) as client:
            r1 = client.get(f"/watchlist?q={quote('AT&T')}&page_size=25")
            assert r1.status_code == 200
            assert "26 total" in r1.text
            assert "q=AT%26T" in r1.text
            assert "q=AT&T" not in r1.text
            assert "Other-net-decoy" not in r1.text
            next_href = _next_href(r1.text, "/watchlist")
            assert "q=AT%26T" in next_href
            r2 = client.get(next_href)
        assert r2.status_code == 200
        assert "26 total" in r2.text
        assert "Other-net-decoy" not in r2.text      # search still applied
        assert "net-25" in r2.text                    # last match on page 2
    finally:
        db.close()


# --------------------------------------------------------------------------
# /allowlist -- q matches pattern + note across the merged YAML entries.
# --------------------------------------------------------------------------

def _write_allowlist(tmp_path, term: str):
    """26 mac entries whose note contains <term>, plus one non-matching
    decoy. Returns the yaml path."""
    lines = ["entries:"]
    for i in range(26):
        lines.append(f"  - pattern: 'aa:bb:cc:00:00:{i:02x}'")
        lines.append("    pattern_type: mac")
        lines.append(f"    note: '{term} site {i}'")
    lines.append("  - pattern: 'ff:ff:ff:ff:ff:ff'")
    lines.append("    pattern_type: mac")
    lines.append("    note: 'Other decoy'")
    path = tmp_path / "allowlist.yaml"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


@pytest.mark.parametrize("term,encoded", _SPECIAL_TERMS)
def test_allowlist_pagination_encodes_search_term(tmp_path, term, encoded):
    """26 entries whose note contains <term>, page_size=25 -> 2 pages. The
    next-page href must carry ``q=<encoded>``, never the raw value."""
    allowlist_yaml = _write_allowlist(tmp_path, term)
    config, db = _make_db(tmp_path, allowlist_path=str(allowlist_yaml))
    try:
        app = create_app(config, db)
        with TestClient(app) as client:
            r = client.get(f"/allowlist?q={quote(term)}&page_size=25")
        assert r.status_code == 200
        assert "26 total" in r.text                  # decoy excluded -> 2 pages
        href = _next_href(r.text, "/allowlist")
        assert f"q={encoded}" in href
        assert f"q={term}" not in href
    finally:
        db.close()


def test_allowlist_search_roundtrips_through_pagination(tmp_path):
    """AT&T end to end: the next-page href encodes the term, and following
    it keeps the search applied -- the decoy mac stays excluded on page 2
    and the total stays narrowed to the 26 matches."""
    allowlist_yaml = _write_allowlist(tmp_path, "AT&T")
    config, db = _make_db(tmp_path, allowlist_path=str(allowlist_yaml))
    try:
        app = create_app(config, db)
        with TestClient(app) as client:
            r1 = client.get(f"/allowlist?q={quote('AT&T')}&page_size=25")
            assert r1.status_code == 200
            assert "26 total" in r1.text             # decoy excluded from count
            assert "q=AT%26T" in r1.text
            assert "q=AT&T" not in r1.text
            assert "ff:ff:ff:ff:ff:ff" not in r1.text
            next_href = _next_href(r1.text, "/allowlist")
            assert "q=AT%26T" in next_href
            r2 = client.get(next_href)
        assert r2.status_code == 200
        assert "26 total" in r2.text                 # filter survived paging
        assert "ff:ff:ff:ff:ff:ff" not in r2.text    # search still applied
    finally:
        db.close()
