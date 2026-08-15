""""Acknowledge all visible" must act on what was VISIBLE.

The route recomputes a RELATIVE window (`window=24h` -> `now - 24h`) at POST
time, so an alert arriving between the page rendering and the operator clicking
falls inside the window and is acknowledged unseen. It then drops out of the
default unacknowledged views, and there is no bulk undo.

⭐ Measured with NO clock jump at all — this is an ordinary race, not an edge
case: three alerts on the page, a fourth HIGH-severity alert arrives, the
operator clicks "acknowledge all 3 matching", and the fourth is acknowledged.

⚠️ The route's own comments already call an unmirrored filter "the worst class of
bug for a bulk-write surface", and every filter IS carefully mirrored into the
form. The time window is the one filter that MOVES ON ITS OWN, so mirroring the
parameter was never enough — the GET's instant has to be carried too.

Found by a `gpt-5.6-sol` red-team of the webui clock surface, which framed it as
a clock-step bug; the clock step turns out to be the rarer trigger for the same
defect.
"""

from __future__ import annotations

import re
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lynceus.config import Config  # noqa: E402
from lynceus.db import Database  # noqa: E402
from lynceus.webui.app import create_app  # noqa: E402
from lynceus.webui.csrf import CSRF_COOKIE_NAME, CSRF_FORM_FIELD  # noqa: E402

pytestmark = pytest.mark.webui


@pytest.fixture()
def rig(tmp_path):
    db_path = str(tmp_path / "ui.db")
    db = Database(db_path)
    app = create_app(Config(db_path=db_path), db)
    yield app, db, int(time.time())
    db.close()


def _seed(db, ts, n=3):
    for i in range(n):
        db.upsert_device(f"aa:bb:cc:dd:ee:0{i}", "wifi", None, 0, ts)
        db.add_alert(
            ts=ts, rule_name="r", mac=f"aa:bb:cc:dd:ee:0{i}",
            message=f"on the page {i}", severity="high",
        )


def _arrive(db, ts):
    db.upsert_device("ff:ff:ff:ff:ff:ff", "wifi", None, 0, ts)
    return db.add_alert(
        ts=ts, rule_name="r", mac="ff:ff:ff:ff:ff:ff",
        message="ARRIVED WHILE THEY WERE READING", severity="high",
    )


def test_an_alert_arriving_after_render_is_not_acknowledged(rig):
    """The operator must never acknowledge something they were not shown."""
    from fastapi.testclient import TestClient

    app, db, now = rig
    _seed(db, now - 3600)
    with TestClient(app, follow_redirects=False) as c:
        page = c.get("/alerts?window=24h")
        token = page.cookies[CSRF_COOKIE_NAME]
        m = re.search(r'name="rendered_at" value="(\d+)"', page.text)
        assert m, "the ack-all form does not carry the render instant"

        new_id = _arrive(db, now + 5)
        r = c.post(
            "/alerts/ack-all-visible",
            data={CSRF_FORM_FIELD: token, "window": "24h", "rendered_at": m.group(1)},
        )
        assert r.status_code == 200

    assert db.get_alert(new_id)["acknowledged"] == 0, (
        "an alert that arrived while the operator was reading the page was "
        "acknowledged; they never saw it and there is no bulk undo"
    )


def test_the_alerts_that_were_on_the_page_are_still_acknowledged(rig):
    """⚠️ The 'good thing must still happen' twin.

    Bounding the write is worthless if it bounds away everything — a route that
    acknowledged nothing would pass the test above perfectly.
    """
    from fastapi.testclient import TestClient

    app, db, now = rig
    _seed(db, now - 3600)
    with TestClient(app, follow_redirects=False) as c:
        page = c.get("/alerts?window=24h")
        token = page.cookies[CSRF_COOKIE_NAME]
        m = re.search(r'name="rendered_at" value="(\d+)"', page.text)
        c.post(
            "/alerts/ack-all-visible",
            data={CSRF_FORM_FIELD: token, "window": "24h", "rendered_at": m.group(1)},
        )

    acked = [a for a in db.list_alerts(limit=50) if a["acknowledged"]]
    assert len(acked) == 3, f"expected the 3 rendered alerts acknowledged, got {len(acked)}"


def test_an_operator_until_filter_still_narrows(rig):
    """`rendered_at` is an ADDITIONAL ceiling, never a replacement.

    An operator who set their own `until` must keep it — combining with `min`
    rather than overwriting is what makes the two independent.
    """
    from fastapi.testclient import TestClient

    app, db, now = rig
    _seed(db, now - 3600)
    with TestClient(app, follow_redirects=False) as c:
        page = c.get("/alerts?window=24h")
        token = page.cookies[CSRF_COOKIE_NAME]
        m = re.search(r'name="rendered_at" value="(\d+)"', page.text)
        # `until` far in the past: nothing should qualify, despite rendered_at
        # being generous.
        c.post(
            "/alerts/ack-all-visible",
            data={
                CSRF_FORM_FIELD: token,
                "window": "24h",
                "until": "2000-01-01",
                "rendered_at": m.group(1),
            },
        )
    assert not [a for a in db.list_alerts(limit=50) if a["acknowledged"]], (
        "the operator's own `until` filter was overridden by rendered_at"
    )


def test_a_missing_or_junk_rendered_at_does_not_break_the_route(rig):
    """Backward compatibility: an older cached page, or a hand-made request,
    must still work rather than 500. It simply gets the old unbounded
    behaviour, which is what it would have had anyway."""
    from fastapi.testclient import TestClient

    app, db, now = rig
    _seed(db, now - 3600)
    with TestClient(app, follow_redirects=False) as c:
        page = c.get("/alerts?window=24h")
        token = page.cookies[CSRF_COOKIE_NAME]
        for value in (None, "", "not-a-number", "-5"):
            data = {CSRF_FORM_FIELD: token, "window": "24h"}
            if value is not None:
                data["rendered_at"] = value
            r = c.post("/alerts/ack-all-visible", data=data)
            assert r.status_code == 200, f"rendered_at={value!r} broke the route"
