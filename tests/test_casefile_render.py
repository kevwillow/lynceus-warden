"""The rendered document, and the section that keeps it honest.

The limits section is the most important page in the document and it is
carried as static prose in the template, not as a loop over data, so an
empty CaseFile cannot empty it. A plant that deletes the block is
recorded in the PR.
"""

from __future__ import annotations

import pytest

import lynceus.casefile.render as render_mod
from lynceus.casefile.query import build_case_file
from lynceus.casefile.render import render_html
from lynceus.db import Database
from tests.test_casefile_query import NOW, TARGET, WATCHLISTED_NEIGHBOUR, _add_evidence, _seed

#: A real Argus metadata row carries a source URL. The self-contained
#: guard below is only worth anything if the fixture actually has one to
#: leak, so this is seeded into the real table rather than assumed absent.
SOURCE_URL = "https://example.org/argus/record/1"


@pytest.fixture
def sample_case_file(tmp_path):
    db, alert_id = _seed(tmp_path)
    _add_evidence(db, alert_id, TARGET)
    neighbour_id = next(
        row["id"]
        for row in db.list_watchlist()
        if row["pattern"] == WATCHLISTED_NEIGHBOUR
    )
    with db.transaction() as conn:
        conn.execute(
            "INSERT INTO watchlist_metadata("
            "watchlist_id, argus_record_id, device_category, confidence, vendor, "
            "source, source_url) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (neighbour_id, "argus-1", "body_camera", 90, "Axon", "Argus", SOURCE_URL),
        )
    return build_case_file(db, TARGET, now_ts=NOW)


@pytest.fixture
def empty_case_file(tmp_path):
    db = Database(str(tmp_path / "empty.db"))
    db.upsert_device(
        mac=TARGET,
        device_type="wifi",
        oui_vendor="Acme",
        is_randomized=0,
        now_ts=NOW - 100,
    )
    return build_case_file(db, TARGET, now_ts=NOW)


def test_the_renderer_cannot_reach_the_database():
    """The choke point is only real if the renderer cannot go around it."""
    source = open(render_mod.__file__, encoding="utf-8").read()
    assert "from ..db" not in source
    assert "import sqlite3" not in source
    assert "Database" not in source


def test_all_five_limits_are_present(sample_case_file):
    html = render_html(sample_case_file)
    for phrase in [
        "keyed on MAC",
        "retention",
        "absence of data cannot be distinguished",
        "receiver",
        "not prove",
    ]:
        assert phrase in html, f"limits section is missing: {phrase}"


def test_every_limit_the_data_model_carries_is_actually_rendered(sample_case_file):
    """Derived, not transcribed. The template states the limits as static
    prose and the CaseFile carries them as data; this fails if either side
    gains, loses or reworks one without the other."""
    html = render_html(sample_case_file)
    assert sample_case_file.limits, "no limits to check, the guard would be vacuous"
    for limit in sample_case_file.limits:
        assert limit["heading"] in html, f"unrendered limit: {limit['heading']}"


def test_the_parameters_are_rendered(sample_case_file):
    html = render_html(sample_case_file)
    assert "proximity_seconds" in html and "300" in html


def test_the_empty_record_says_so_instead_of_rendering_a_blank_document(empty_case_file):
    html = render_html(empty_case_file)
    assert "no sightings retained" in html.lower()
    assert "keyed on MAC" in html, "an empty document still carries its limits"


def test_the_html_is_self_contained(sample_case_file):
    """It gets opened from a downloads folder with no network."""
    assert SOURCE_URL in repr(sample_case_file), (
        "the fixture must carry a URL for this guard to have anything to catch"
    )
    html = render_html(sample_case_file)
    assert "http://" not in html and "https://" not in html
    assert "<script" not in html.lower(), "a case file must not execute anything"


def test_the_unnamed_co_observers_are_explained_not_just_counted(sample_case_file):
    """A bare number invites the reader to assume the export failed. The
    document has to say the omission was a decision."""
    html = render_html(sample_case_file)
    assert "did not match the watchlist" in html
