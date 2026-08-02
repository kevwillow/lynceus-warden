"""Tests for the silenced/snoozed indicator on the device LIST page.

Regression coverage for the render-gap fix: device snooze/silence
mutations persisted to allowlist_ui.yaml (proven by the device-detail
page) but the /devices list query never resolved that state and the
template had no badge. The fix resolves silence state per page via
_resolve_silence_states and renders a badge-snoozed indicator per row.

Both states must show (permanent = indefinite label; temporary = remaining
time via relative_time), a non-silenced device must show nothing, and an
EXPIRED temporary snooze must show nothing (matcher skips expired, matching
suppression semantics).
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from lynceus.allowlist import AllowlistEntry, add_ui_entry, derive_ui_path
from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import create_app

MAC = "aa:bb:cc:dd:ee:01"


def _make_app(tmp_path):
    config = Config(
        db_path=str(tmp_path / "dev.db"),
        kismet_health_check_on_startup=False,
        evidence_capture_enabled=False,
        allowlist_path=str(tmp_path / "allowlist.yaml"),
    )
    db = Database(config.db_path)
    app = create_app(config, db)
    return app, db, config


def _seed_device(db, mac=MAC, *, now_ts=100):
    db.upsert_device(mac, "wifi", "Acme", 0, now_ts)


def _ui_path(config):
    return derive_ui_path(Path(config.allowlist_path))


@pytest.mark.webui
def test_permanent_silence_shows_indefinite_badge(tmp_path):
    app, db, config = _make_app(tmp_path)
    _seed_device(db)
    add_ui_entry(
        _ui_path(config),
        AllowlistEntry(
            pattern=MAC, pattern_type="mac", note="perm",
            added_at=int(time.time()), expires_at=None,
        ),
    )
    with TestClient(app) as client:
        html = client.get("/devices").text
    assert "badge-snoozed" in html
    assert "silenced" in html
    # Permanent => indefinite, NOT a "(until ...)" expiry phrasing.
    assert "silenced (until" not in html


@pytest.mark.webui
def test_temporary_snooze_shows_remaining_time_badge(tmp_path):
    app, db, config = _make_app(tmp_path)
    _seed_device(db)
    add_ui_entry(
        _ui_path(config),
        AllowlistEntry(
            pattern=MAC, pattern_type="mac", note="temp",
            added_at=int(time.time()), expires_at=int(time.time()) + 24 * 3600,
        ),
    )
    with TestClient(app) as client:
        html = client.get("/devices").text
    assert "badge-snoozed" in html
    # Temporary => the "(until ...)" expiry phrasing with a relative time.
    assert "silenced (until" in html


@pytest.mark.webui
def test_non_silenced_device_shows_no_badge(tmp_path):
    app, db, _config = _make_app(tmp_path)
    _seed_device(db)
    with TestClient(app) as client:
        html = client.get("/devices").text
    assert MAC in html  # device row renders
    assert "badge-snoozed" not in html


@pytest.mark.webui
def test_expired_temporary_snooze_shows_no_badge(tmp_path):
    app, db, config = _make_app(tmp_path)
    _seed_device(db)
    add_ui_entry(
        _ui_path(config),
        AllowlistEntry(
            pattern=MAC, pattern_type="mac", note="expired",
            added_at=int(time.time()) - 48 * 3600,
            expires_at=int(time.time()) - 3600,  # already in the past
        ),
    )
    with TestClient(app) as client:
        html = client.get("/devices").text
    assert MAC in html  # device row still renders
    assert "badge-snoozed" not in html
