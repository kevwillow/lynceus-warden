"""Watchful escalation rendering must report whether an operator was told."""

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
CREATED_AT = 1_700_000_000
ESCALATED_AT = CREATED_AT + 1_000


def test_this_suite_is_testing_the_tree_it_lives_in():
    import lynceus.webui.app as under_test

    assert Path(under_test.__file__).resolve().is_relative_to(REPO_ROOT)


def _prose(html: str) -> str:
    s = re.sub(r"<!--.*?-->", " ", html, flags=re.S)
    return " ".join(re.sub(r"<[^>]+>", " ", s).split())


def _build(tmp_path):
    db_path = str(tmp_path / "ui.db")
    config = Config(db_path=db_path)
    db = Database(db_path)
    return create_app(config, db), db


def _create_escalated_watchful_entry(db) -> int:
    db.upsert_device(MAC, "wifi", None, 0, CREATED_AT)
    source_alert_id = db.add_alert(
        ts=CREATED_AT,
        rule_name="source",
        mac=MAC,
        message="m",
        severity="high",
    )
    entry_id = db.create_watchful_from_alert(
        source_alert_id, snooze_duration_seconds=None, now_ts=CREATED_AT,
    )
    assert entry_id is not None
    assert db.escalate_watchful_recurrence(entry_id, ESCALATED_AT) is not None
    return entry_id


def _create_tracking_watchful_entry(db) -> int:
    db.upsert_device(MAC, "wifi", None, 0, CREATED_AT)
    source_alert_id = db.add_alert(
        ts=CREATED_AT,
        rule_name="source",
        mac=MAC,
        message="m",
        severity="high",
    )
    entry_id = db.create_watchful_from_alert(
        source_alert_id, snooze_duration_seconds=None, now_ts=CREATED_AT,
    )
    assert entry_id is not None
    return entry_id


def _pages(client, entry_id: int, *, list_status: str = "active") -> dict[str, str]:
    return {
        "list": client.get(f"/watchful?status={list_status}").text,
        "detail": client.get(f"/watchful/{entry_id}").text,
    }


def _add_escalation_alert(db, *, notified: bool) -> None:
    alert_id = db.add_alert(
        ts=ESCALATED_AT,
        rule_name="watchful_recurrence",
        mac=MAC,
        message="m",
        severity="high",
        rule_type="watchful_recurrence",
    )
    if notified:
        db.mark_alert_notified(alert_id, now_ts=ESCALATED_AT)


def test_a_suppressed_escalation_is_marked_never_sent_on_both_surfaces(tmp_path):
    app, db = _build(tmp_path)
    try:
        entry_id = _create_escalated_watchful_entry(db)
        with TestClient(app) as client:
            for html in _pages(client, entry_id).values():
                assert "badge-watchful-nosend" in html
    finally:
        db.close()


def test_a_delivered_escalation_is_not_marked(tmp_path):
    app, db = _build(tmp_path)
    try:
        entry_id = _create_escalated_watchful_entry(db)
        _add_escalation_alert(db, notified=True)
        with TestClient(app) as client:
            for html in _pages(client, entry_id).values():
                assert "badge-watchful-nosend" not in html
                assert "badge-watchful-undelivered" not in html
    finally:
        db.close()


def test_an_undelivered_escalation_is_marked_not_delivered_not_never_sent(tmp_path):
    app, db = _build(tmp_path)
    try:
        entry_id = _create_escalated_watchful_entry(db)
        _add_escalation_alert(db, notified=False)
        with TestClient(app) as client:
            for html in _pages(client, entry_id).values():
                assert "badge-watchful-undelivered" in html
                assert "badge-watchful-nosend" not in html
    finally:
        db.close()


def test_an_entry_that_never_escalated_carries_no_delivery_badge(tmp_path):
    app, db = _build(tmp_path)
    try:
        entry_id = _create_tracking_watchful_entry(db)
        with TestClient(app) as client:
            for html in _pages(client, entry_id).values():
                assert "badge-watchful-nosend" not in html
                assert "badge-watchful-undelivered" not in html
    finally:
        db.close()


def test_a_confirmed_safe_entry_does_not_also_claim_a_current_investigation(tmp_path):
    app, db = _build(tmp_path)
    try:
        entry_id = _create_tracking_watchful_entry(db)
        with TestClient(app) as client:
            client.get("/watchful")
            token = client.cookies[CSRF_COOKIE_NAME]
            investigate = client.post(
                f"/watchful/{entry_id}/investigate",
                data={CSRF_FORM_FIELD: token},
                follow_redirects=False,
            )
            assert investigate.status_code == 303
            confirm_safe = client.post(
                f"/watchful/{entry_id}/confirm-safe",
                data={CSRF_FORM_FIELD: token},
                follow_redirects=False,
            )
            assert confirm_safe.status_code == 303
            for html in _pages(client, entry_id, list_status="all").values():
                prose = _prose(html).lower()
                assert "was flagged for investigation" in prose
                assert not re.search(r"(?<!was )flagged for investigation", prose)
    finally:
        db.close()


def test_a_flagged_entry_that_is_not_confirmed_safe_still_reads_as_current(tmp_path):
    app, db = _build(tmp_path)
    try:
        entry_id = _create_tracking_watchful_entry(db)
        with TestClient(app) as client:
            client.get("/watchful")
            token = client.cookies[CSRF_COOKIE_NAME]
            response = client.post(
                f"/watchful/{entry_id}/investigate",
                data={CSRF_FORM_FIELD: token},
                follow_redirects=False,
            )
            assert response.status_code == 303
            pages = _pages(client, entry_id)
            assert "badge-watchful-flagged" in pages["list"]
            assert 'title="flagged for investigation"' in pages["list"]
            detail_prose = _prose(pages["detail"]).lower()
            assert "flagged for investigation" in detail_prose
            assert "was flagged for investigation" not in detail_prose
    finally:
        db.close()
