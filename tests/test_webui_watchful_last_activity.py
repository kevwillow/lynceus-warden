"""`/watchful` reported a device as "last seen" at the instant of a button click.

``watchful_recurrence.last_seen_at`` has THREE writers and only one of them is
an observation:

* ``record_watchful_sighting``  -- a counted sighting (>=24h since the last one)
* ``reset_watchful_recurrence`` -- the OPERATOR'S RESET CLICK, which sets
  ``last_seen_at = now_ts`` alongside ``sighting_count = 1``
* ``repair_future_dated_watchful_last_seen`` -- a clock-repair clamp

Both surfaces rendered that column under the label **last seen**. Measured
through the real reset route on an entry whose device had not been observed for
27 days (``internal/session2-harnesses/reset_probe.py``, parts D and E):

    newest row in `sightings`        27 days ago      (independent source)
    /watchful    "last seen"         27d ago  ->  just now
    /watchful/1  "last seen"         27d ago  ->  just now

⛔ And the column is not merely decorative -- it is the list's ORDER BY and the
column the "recent" window filters on, so the same click moves the row to the
top of the triage view and into a window it does not belong in:

    /watchful order (top first)      ['2', '1']  ->  ['1', '2']
    entry 1 under ?window=1h         False       ->  True

⛔ **The overwrite is NOT the defect and must not be "fixed" in the db layer.**
``last_seen_at`` is also the 90-day auto-archive clock
(``auto_archive_watchful_recurrence``: ``last_seen_at <= now - 90d``). An entry
last counted 89 days ago that the operator explicitly resets would archive the
next day -- silently closing a watch the operator just chose to keep. That is
the unsafe direction, and it is the same shape as Finding 44's "obvious" dedup.
The column is right; the surfaces describing it were wrong.

⚠️ The marker covers the ONE provenance the row can prove. A clock repair leaves
a row byte-identical to one whose device was seen at the repair instant, so it
is stated in the page copy rather than silently folded in -- see
``test_the_clock_repair_provenance_is_stated_rather_than_silently_covered``.
"""

from __future__ import annotations

import re
from pathlib import Path

from starlette.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import create_app
from lynceus.webui.csrf import CSRF_COOKIE_NAME, CSRF_FORM_FIELD

REPO_ROOT = Path(__file__).resolve().parents[1]

MAC = "aa:bb:cc:11:22:33"


def test_this_suite_is_testing_the_tree_it_lives_in():
    import lynceus.webui.app as under_test

    assert Path(under_test.__file__).resolve().is_relative_to(REPO_ROOT)


def _prose(html: str) -> str:
    """Visible text only.

    ⚠️ Needles that span ``<code>``/``<strong>`` boundaries reported a surface
    silent when it was speaking, twice in this track. Strip the tags once here
    rather than shaping every needle around the markup.
    """
    s = re.sub(r"<!--.*?-->", " ", html, flags=re.S)
    return " ".join(re.sub(r"<[^>]+>", " ", s).split())


def _build(tmp_path):
    db_path = str(tmp_path / "ui.db")
    config = Config(db_path=db_path)
    db = Database(db_path)
    return create_app(config, db), db


def _insert(
    db,
    *,
    last_seen_at,
    sighting_count,
    reset_count=0,
    escalated_at=None,
    created_at=1000,
    first_seen_at=1000,
):
    cur = db._conn.execute(
        "INSERT INTO watchful_recurrence("
        "mac, created_at, first_seen_at, last_seen_at, sighting_count, "
        "escalated_at, reset_count) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (MAC, created_at, first_seen_at, last_seen_at, sighting_count,
         escalated_at, reset_count),
    )
    db._conn.commit()
    return int(cur.lastrowid)


def _note_text(html: str) -> str:
    """The explanatory note's OWN text.

    🪤 The first version of the recency/ordering guard searched the whole page
    for "recent" and "order" and survived a plant that deleted the sentence
    entirely -- the filter dropdown is labelled "recent" and the table macro's
    column controls say "reorder". A needle that can be satisfied by a sibling
    element is not a guard on this element.
    """
    m = re.search(
        r'<small class="dim watchful-last-activity-note">(.*?)</small>', html, re.S
    )
    return _prose(m.group(1)) if m else ""


def _pages(client, entry_id):
    return {
        "/watchful": client.get("/watchful").text,
        "detail": client.get(f"/watchful/{entry_id}").text,
    }


# ---------------------------------------------------------------- the label


def test_neither_surface_calls_the_column_last_seen(tmp_path):
    """The label is the claim. 'last seen' asserts an observation that three
    different writers can put in this column, only one of which is one."""
    app, db = _build(tmp_path)
    eid = _insert(db, last_seen_at=2000, sighting_count=4)
    with TestClient(app) as client:
        for name, html in _pages(client, eid).items():
            text = _prose(html).lower()
            assert "last seen" not in text, f"{name} still labels the column 'last seen'"
            assert "last activity" in text, f"{name} does not name the column at all"
            # ⚠️ `_prose` strips attributes, and a `title=` IS shown to the
            # operator as a tooltip -- so the prose check alone would pass a
            # relabel that only moved the claim into an attribute. These two
            # cover the label shapes the stripped text cannot see.
            assert 'title="last seen"' not in html.lower(), (
                f"{name} moved 'last seen' into a tooltip"
            )
            assert not re.findall(r">[^<>]{0,4}last seen[^<>]{0,4}[:<]", html, re.I), (
                f"{name} still renders a 'last seen' label"
            )
    db.close()


def test_first_seen_is_untouched_by_the_relabel(tmp_path):
    """⛔ The other column on that line genuinely IS an observation.

    A relabel driven by a substring match would take 'first seen' with it, and
    the resulting page would be less true, not more.
    """
    app, db = _build(tmp_path)
    eid = _insert(db, last_seen_at=2000, sighting_count=4)
    with TestClient(app) as client:
        for name, html in _pages(client, eid).items():
            assert "first seen" in _prose(html).lower(), f"{name} lost 'first seen'"
    db.close()


# --------------------------------------------------------------- the marker


def test_a_reset_row_does_not_present_its_timestamp_as_a_sighting(tmp_path):
    """reset_count > 0 AND sighting_count == 1 == "no counted sighting has
    happened since the reset", so the stored value IS the reset instant."""
    app, db = _build(tmp_path)
    eid = _insert(db, last_seen_at=2000, sighting_count=1, reset_count=1)
    with TestClient(app) as client:
        for name, html in _pages(client, eid).items():
            assert "watchful-last-activity-reset" in html, (
                f"{name} renders the reset instant with nothing saying it is not a sighting"
            )
    db.close()


def test_the_marker_names_what_the_timestamp_actually_is(tmp_path):
    """A marker that only says 'reset' repeats the state badge. It has to say
    the thing the operator would otherwise get wrong: this is not a sighting."""
    app, db = _build(tmp_path)
    eid = _insert(db, last_seen_at=2000, sighting_count=1, reset_count=1)
    with TestClient(app) as client:
        for name, html in _pages(client, eid).items():
            # ⚠️ VISIBLE text, not the raw HTML. The marker's own `title=`
            # explains the same thing at length, so a raw-HTML needle would go
            # on passing after the visible label was reduced to "(reset)" --
            # which a planted defect proved it did.
            assert re.search(r"not a sighting", _prose(html), re.I), (
                f"{name}'s marker does not say the timestamp is not an observation"
            )
    db.close()


def test_a_counted_sighting_since_the_reset_clears_the_marker(tmp_path):
    """The other direction. Once a real sighting lands, sighting_count leaves 1
    and the column IS an observation again -- a marker that stuck would be the
    same class of false claim pointing the other way."""
    app, db = _build(tmp_path)
    eid = _insert(db, last_seen_at=2000, sighting_count=2, reset_count=1)
    with TestClient(app) as client:
        for name, html in _pages(client, eid).items():
            assert "watchful-last-activity-reset" not in html, (
                f"{name} still calls this a reset after a counted sighting"
            )
    db.close()


def test_a_row_that_was_never_reset_is_not_marked(tmp_path):
    """A fresh entry also has sighting_count == 1, and its timestamp IS the
    sighting that created it. Only the conjunction is the reset."""
    app, db = _build(tmp_path)
    eid = _insert(db, last_seen_at=2000, sighting_count=1, reset_count=0)
    with TestClient(app) as client:
        for name, html in _pages(client, eid).items():
            assert "watchful-last-activity-reset" not in html, (
                f"{name} marks a never-reset row as a reset"
            )
    db.close()


# ------------------------------------------------- through the actual route


def test_the_marker_appears_after_a_reset_driven_through_the_route(tmp_path):
    """⭐ The state built by the CODE, not by this file's INSERT.

    A hand-built fixture certifies the model this test encodes, including a
    wrong one. This drives the operator's own POST and then asks the page.
    """
    app, db = _build(tmp_path)
    eid = _insert(db, last_seen_at=2000, sighting_count=4, escalated_at=3000)
    with TestClient(app) as client:
        before = _pages(client, eid)
        assert "watchful-last-activity-reset" not in before["/watchful"]

        client.get("/watchful")
        token = client.cookies[CSRF_COOKIE_NAME]
        resp = client.post(
            f"/watchful/{eid}/reset",
            data={CSRF_FORM_FIELD: token},
            follow_redirects=False,
        )
        assert resp.status_code == 303, resp.status_code

        row = db.get_watchful_recurrence(eid)
        assert row.reset_count == 1 and row.sighting_count == 1
        for name, html in _pages(client, eid).items():
            assert "watchful-last-activity-reset" in html, (
                f"{name} is unmarked after a real reset"
            )
    db.close()


# ------------------------------------------------------------- stated limits


def test_the_clock_repair_provenance_is_stated_rather_than_silently_covered(tmp_path):
    """⛔ The marker cannot see a clock repair and must not imply it can.

    ``repair_future_dated_watchful_last_seen`` clamps the column without
    touching ``sighting_count``, leaving a row indistinguishable from one whose
    device was seen at the repair instant. Saying so on the page is the only
    honest handling; a reader who trusts the marker to mean "every value not
    marked is a sighting" would be wrong.
    """
    app, db = _build(tmp_path)
    eid = _insert(db, last_seen_at=2000, sighting_count=4)
    with TestClient(app) as client:
        for name, html in _pages(client, eid).items():
            text = _prose(html).lower()
            assert "clock repair" in text, f"{name} does not state the clock-repair provenance"
            assert "operator reset" in text, f"{name} does not state the reset provenance"
    db.close()


def test_the_page_says_the_column_is_what_the_recency_filter_uses(tmp_path):
    """The same column is the ORDER BY and the ?window= filter, which is why a
    reset moves a row to the top of the list and into 'last 1h'. An operator
    reading a triage list is owed that, not just a corrected label."""
    app, db = _build(tmp_path)
    eid = _insert(db, last_seen_at=2000, sighting_count=4)
    with TestClient(app) as client:
        note = _note_text(client.get("/watchful").text).lower()
        assert note, "/watchful renders no last-activity note at all"
        assert "order" in note and "recent" in note, (
            "the note does not connect the column to the ordering and the recency filter"
        )
        # The detail page has no list to order and no window filter, so it
        # carries the provenance sentence WITHOUT that clause. Asserted so the
        # two callers cannot silently converge on one copy that is wrong for
        # one of them.
        detail_note = _note_text(client.get(f"/watchful/{eid}").text).lower()
        assert detail_note, "the detail page renders no last-activity note"
        assert "order" not in detail_note, (
            "the detail page claims an ordering it does not have"
        )
    db.close()
