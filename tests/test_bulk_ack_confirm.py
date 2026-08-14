"""The two bulk-acknowledge forms must be confirm-guarded.

Found by driving the real UI in Chromium (`internal/tools/crawl_ui.py`): every
destructive control on `/alerts/{id}` and `/devices/{mac}` carries a
`data-confirm`, but the two BULK controls on `/alerts` carried none.

Why they need one when per-row `ack` does not: acknowledging one alert is
reversible with one click (`POST /alerts/{id}/unack`), but **there is no
bulk-unack route**. Measured on a 40-alert backlog:

    unacknowledged before = 40
    ONE click on 'acknowledge all' -> HTTP 200
    unacknowledged after  = 0
    per-alert unack POSTs needed to undo -> 40

Acknowledging is how an alert leaves the operator's own view, so a mis-click
here hides real detections rather than merely changing a label.

⛔ `data-confirm`, never `onsubmit="return confirm(...)"`. A CSP nonce
authorises `<script>` ELEMENTS only and never inline `on*=` attributes, so the
latter is blocked outright -- and the failure is worse than "no dialog": a
blocked `onsubmit` never returns false, so the form submits immediately. That
is the defect PR #19 fixed for "Permanently silence this device".
"""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import create_app

NOW = 1_700_000_000


def _app_with_alerts(tmp_path, n: int):
    cfg = Config(db_path=str(tmp_path / "acks.db"))
    db = Database(cfg.db_path)
    db.ensure_location("default", "Default")
    for i in range(n):
        mac = f"12:34:56:00:00:{i:02x}"
        db.upsert_device(mac=mac, device_type="wifi", oui_vendor=None,
                         is_randomized=0, now_ts=NOW - i)
        db.add_alert(ts=NOW - i, rule_name="watchlist_mac_hit", mac=mac,
                     message="m", severity="high")
    return create_app(cfg, db), db


def _form_with_action(body: str, action: str) -> str:
    """Return the opening <form> tag whose action is `action`."""
    m = re.search(r"<form[^>]*action=\"" + re.escape(action) + r"\"[^>]*>", body)
    assert m, f"no form posting to {action} was rendered"
    return m.group(0)


@pytest.mark.webui
@pytest.mark.parametrize("action", ["/alerts/ack-all-visible", "/alerts/bulk-ack"])
def test_bulk_ack_forms_are_confirm_guarded(tmp_path, action):
    app, db = _app_with_alerts(tmp_path, 3)
    try:
        with TestClient(app) as client:
            body = client.get("/alerts").text
        tag = _form_with_action(body, action)
        assert "data-confirm=" in tag, f"{action} has no confirmation guard"
    finally:
        db.close()


@pytest.mark.webui
def test_ack_all_names_the_number_it_will_acknowledge(tmp_path):
    """"Acknowledge all" reads very differently at 3 than at 900, and the
    operator cannot judge the blast radius without the count."""
    app, db = _app_with_alerts(tmp_path, 7)
    try:
        with TestClient(app) as client:
            body = client.get("/alerts").text
        tag = _form_with_action(body, "/alerts/ack-all-visible")
        assert "all 7 matching alerts" in tag, tag
    finally:
        db.close()


@pytest.mark.webui
@pytest.mark.parametrize("action", ["/alerts/ack-all-visible", "/alerts/bulk-ack"])
def test_the_guard_says_there_is_no_bulk_undo(tmp_path, action):
    """The specific fact that makes these worth guarding. A generic "are you
    sure?" would not tell the operator what is actually at stake."""
    app, db = _app_with_alerts(tmp_path, 3)
    try:
        with TestClient(app) as client:
            body = client.get("/alerts").text
        tag = _form_with_action(body, action)
        assert "no bulk undo" in tag, tag
    finally:
        db.close()


@pytest.mark.webui
@pytest.mark.parametrize("action", ["/alerts/ack-all-visible", "/alerts/bulk-ack"])
def test_the_guard_is_not_an_inline_handler(tmp_path, action):
    """⛔ A presence assertion beside the absence one.

    `data-confirm` being present does not prove an inline `onsubmit` was not
    ALSO added, and an inline handler is worse than nothing under the CSP: it
    is blocked, never returns false, and the form submits unconfirmed.
    """
    app, db = _app_with_alerts(tmp_path, 3)
    try:
        with TestClient(app) as client:
            body = client.get("/alerts").text
        tag = _form_with_action(body, action)
        assert "onsubmit" not in tag.lower(), (
            "inline handler on a CSP-protected page: it will be blocked and the "
            "form will submit UNCONFIRMED"
        )
    finally:
        db.close()


@pytest.mark.webui
def test_the_no_bulk_undo_claim_is_still_true(tmp_path):
    """⭐ The guard's wording asserts a fact about the app. If a bulk-unack
    route is ever added, this message becomes a lie and should be reworded --
    so pin the fact, not just the string.
    """
    app, db = _app_with_alerts(tmp_path, 2)
    try:
        routes = {getattr(r, "path", "") for r in app.routes}
        bulk_unack = {p for p in routes if "unack" in p and ("bulk" in p or "all" in p)}
        assert not bulk_unack, (
            f"a bulk-unack route now exists {bulk_unack}; the confirmation text "
            "claiming 'no bulk undo' is now false and must be reworded"
        )
    finally:
        db.close()
