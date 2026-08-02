"""LOCAL-ONLY validation for the homepage recently-seen table change
(0.9.1 arc): cap raised 10 -> 25, scrollable container, count line,
and a 'view all devices' link to /devices.

tests/ is gitignored (OPSEC). This file is NEVER staged or committed --
it exists to prove the change locally and is referenced by sha in the
commit body only.

Covers what IS test-confirmable:
  - the recently-seen table renders up to 25 rows (not 10)
  - rows are ordered by last_seen DESC (most-recent first), same column
    /devices orders by, so the 'view all' link lands on a consistent list
  - a 'view all devices' link targets /devices
  - the 'showing N of M' count line renders (I6)

NOT confirmable here (require operator eyes-on the rig): the vertical
scroll behavior and the phone/narrow-viewport appearance.
"""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import create_app

pytestmark = pytest.mark.webui

_BASE_TS = 1_700_000_000


def _seed_devices(db: Database, n: int) -> list[str]:
    """Insert ``n`` devices with strictly increasing last_seen so the
    expected last_seen-DESC order is deterministic. Returns the MACs in
    seed order (oldest first); newest-first is the reverse."""
    macs: list[str] = []
    for i in range(n):
        mac = f"02:00:00:00:00:{i:02x}"
        macs.append(mac)
        db.upsert_device(
            mac=mac,
            device_type="wifi",
            oui_vendor=None,
            is_randomized=0,
            now_ts=_BASE_TS + i,  # strictly increasing -> last_seen order
        )
    return macs


def _recent_article(html: str) -> str:
    """Slice the 'recently seen devices' <article> out of the home page
    so assertions can't accidentally match the alerts table above it."""
    start = html.find("recently seen devices")
    assert start >= 0, "recently-seen section missing from home page"
    end = html.find("</article>", start)
    return html[start : end if end >= 0 else len(html)]


def _row_macs(article_html: str) -> list[str]:
    """MACs in render order from the recently-seen <tbody>."""
    tbody = re.search(r"<tbody>(.*?)</tbody>", article_html, flags=re.DOTALL)
    assert tbody, "recently-seen table has no <tbody>"
    return re.findall(r'/devices/([0-9a-f:]{17})"', tbody.group(1))


def _make_client(tmp_path):
    config = Config(
        db_path=str(tmp_path / "home.db"),
        kismet_health_check_on_startup=False,
        evidence_capture_enabled=False,
    )
    db = Database(config.db_path)
    return config, db


def test_home_caps_at_25_rows_not_10(tmp_path):
    config, db = _make_client(tmp_path)
    seeded = _seed_devices(db, 30)
    app = create_app(config, db)
    with TestClient(app) as client:
        resp = client.get("/")
    db.close()

    assert resp.status_code == 200
    macs = _row_macs(_recent_article(resp.text))
    # The regression: it used to be 10. With 30 devices present the
    # table must surface 25.
    assert len(macs) == 25, f"expected 25 rows, got {len(macs)}"

    # Ordering: last_seen DESC -> newest seeded (index 29) first, and the
    # visible set is exactly the top-25 most-recent.
    expected = list(reversed(seeded))[:25]
    assert macs == expected, "rows not ordered by last_seen DESC (top-25)"


def test_home_shows_fewer_when_under_cap(tmp_path):
    config, db = _make_client(tmp_path)
    _seed_devices(db, 7)
    app = create_app(config, db)
    with TestClient(app) as client:
        resp = client.get("/")
    db.close()

    macs = _row_macs(_recent_article(resp.text))
    assert len(macs) == 7  # cap is a ceiling, not a floor


def test_home_has_view_all_devices_link(tmp_path):
    config, db = _make_client(tmp_path)
    _seed_devices(db, 5)
    app = create_app(config, db)
    with TestClient(app) as client:
        resp = client.get("/")
    db.close()

    article = _recent_article(resp.text)
    assert 'href="/devices"' in article, "view-all link target /devices missing"
    assert "view all devices" in article.lower()


def test_home_count_line_shows_n_of_total(tmp_path):
    config, db = _make_client(tmp_path)
    _seed_devices(db, 30)
    app = create_app(config, db)
    with TestClient(app) as client:
        resp = client.get("/")
    db.close()

    article = _recent_article(resp.text)
    # I6 count indicator: 25 shown out of 30 total devices.
    assert "showing 25 of 30" in re.sub(r"\s+", " ", article)
