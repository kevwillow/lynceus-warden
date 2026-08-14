"""The co-observation audit log must not claim an access that did not happen.

Decision 6 kept an audit log **instead of** rate limiting, so this log is the
only enumeration control the feature has. That makes its honesty load-bearing:
an investigator reading it after a stolen session is relying on it to say what
was actually accessed.

Two failures of that, both from the co-observation red team (2026-08-06):

- **Finding 1, fixed in PR #16:** the line sat one branch too late, so a MAC that
  was *not* in the database left no trace at all. Enumeration is overwhelmingly
  misses, so the control was blind to exactly the thing it existed to catch.
- **This file:** the line sat before the query and read as a *completed* access,
  so a query that raised still left a log entry indistinguishable from a served
  page.

⭐ Note the fix for the second is NOT "move the line after the query" -- that
would re-introduce the first. An attempt that fails must still be recorded, or
an attacker who can provoke failures erases themselves from the trail. The
attempt is logged as an attempt; the outcome is logged separately.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from lynceus.config import Config, CoObservationConfig
from lynceus.db import Database
from lynceus.webui.app import create_app

MAC = "aa:bb:cc:dd:ee:01"
NOW = 1_700_000_000


def _app(tmp_path, *, enabled=True):
    cfg = Config(
        db_path=str(tmp_path / "co.db"),
        co_observation=CoObservationConfig(enabled=enabled),
    )
    db = Database(cfg.db_path)
    db.ensure_location("default", "Default")
    db.upsert_device(mac=MAC, device_type="wifi", oui_vendor=None,
                     is_randomized=0, now_ts=NOW)
    db.insert_sighting(mac=MAC, ts=NOW, rssi=-40, ssid="t", location_id="default")
    return create_app(cfg, db), db


@pytest.mark.webui
def test_a_failed_query_is_not_logged_as_a_completed_access(tmp_path, caplog, monkeypatch):
    """The defect: the log said a query happened, and nothing contradicted it."""
    app, db = _app(tmp_path)
    try:
        def _explode(*_a, **_kw):
            raise RuntimeError("simulated query failure")

        monkeypatch.setattr(db, "list_co_observations", _explode)
        with caplog.at_level("INFO", logger="lynceus.webui.app"):
            with TestClient(app, raise_server_exceptions=False) as client:
                client.get(f"/devices/{MAC}/co-observations")

        joined = caplog.text
        assert "FAILED" in joined, (
            f"a query that raised left a log reading as a completed access: {joined!r}"
        )
        assert MAC in joined
    finally:
        db.close()


@pytest.mark.webui
def test_the_attempt_is_still_recorded_when_the_query_fails(tmp_path, caplog, monkeypatch):
    """⛔ The half that must NOT regress while fixing the other.

    If the attempt line were moved after the query, an attacker able to provoke
    failures would leave no trail at all -- erasing themselves from the one
    control Decision 6 kept after explicitly rejecting rate limiting. That is
    red-team finding 1 in a new place.
    """
    app, db = _app(tmp_path)
    try:
        monkeypatch.setattr(
            db, "list_co_observations",
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")),
        )
        with caplog.at_level("INFO", logger="lynceus.webui.app"):
            with TestClient(app, raise_server_exceptions=False) as client:
                client.get(f"/devices/{MAC}/co-observations")

        joined = caplog.text
        assert "ATTEMPT" in joined, (
            f"a failed query left no record that it was even attempted: {joined!r}"
        )
        assert MAC in joined
    finally:
        db.close()


@pytest.mark.webui
def test_a_successful_query_is_not_labelled_failed(tmp_path, caplog):
    """The presence assertion beside the absence one: a guard that fires on
    every request would satisfy the two tests above while making the log
    useless."""
    app, db = _app(tmp_path)
    try:
        with caplog.at_level("INFO", logger="lynceus.webui.app"):
            with TestClient(app) as client:
                r = client.get(f"/devices/{MAC}/co-observations")
        assert r.status_code == 200
        joined = caplog.text
        assert "ATTEMPT" in joined
        assert "FAILED" not in joined, f"a successful query was logged as failed: {joined!r}"
    finally:
        db.close()


@pytest.mark.webui
def test_the_error_still_propagates(tmp_path, monkeypatch):
    """The handler exists to make the trail honest, not to swallow the error.
    Turning a 500 into a silent 200 would hide a broken feature from the
    operator, which is a worse failure than the one being fixed."""
    app, db = _app(tmp_path)
    try:
        monkeypatch.setattr(
            db, "list_co_observations",
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")),
        )
        with TestClient(app, raise_server_exceptions=False) as client:
            r = client.get(f"/devices/{MAC}/co-observations")
        assert r.status_code >= 500, "the exception was swallowed"
    finally:
        db.close()


@pytest.mark.webui
@pytest.mark.parametrize("enabled", [True, False])
def test_the_absent_response_is_not_cacheable(tmp_path, enabled):
    """`_absent()` is the shared response for BOTH 'capability off' and 'no such
    device', so it is a statement about which MACs the operator has seen -- the
    exact fact the shared response exists to withhold.

    It was previously protected only incidentally, by the CSRF `Set-Cookie` that
    happens to accompany every response and stops shared caches storing it. That
    is protection from an unrelated mechanism, and it would vanish silently the
    day CSRF cookies moved or became conditional.
    """
    app, db = _app(tmp_path, enabled=enabled)
    try:
        with TestClient(app) as client:
            r = client.get("/devices/aa:bb:cc:dd:ee:99/co-observations")
        assert r.status_code == 404
        assert "no-store" in r.headers.get("cache-control", "").lower(), (
            "the absent response is cacheable; it reveals which MACs are unknown"
        )
    finally:
        db.close()
