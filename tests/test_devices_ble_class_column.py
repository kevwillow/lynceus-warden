"""Local-only tests for the BLE class column on /devices and detail.

tests/ is gitignored — these are NEVER committed (see project memory).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from lynceus.ble_continuity import CLASS_AIRPODS
from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import create_app


def _make_app(tmp_path):
    config = Config(db_path=str(tmp_path / "ui.db"))
    db = Database(str(tmp_path / "ui.db"))
    app = create_app(config, db)
    return app, db


@pytest.mark.webui
def test_devices_list_shows_class_column(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        db.upsert_device(
            mac="aa:bb:cc:dd:ee:ff",
            device_type="ble",
            oui_vendor=None,
            is_randomized=0,
            now_ts=100,
            ble_device_class=CLASS_AIRPODS,
        )
        with TestClient(app) as client:
            r = client.get("/devices")
        assert r.status_code == 200
        assert "BLE class" in r.text
        assert CLASS_AIRPODS in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_devices_list_renders_without_class(tmp_path):
    """A device with no class must still render — the column is present
    and the cell falls back rather than blowing up the row."""
    app, db = _make_app(tmp_path)
    try:
        db.upsert_device(
            mac="aa:bb:cc:dd:ee:01",
            device_type="wifi",
            oui_vendor="Acme",
            is_randomized=0,
            now_ts=100,
        )
        with TestClient(app) as client:
            r = client.get("/devices")
        assert r.status_code == 200
        assert "BLE class" in r.text
        assert "aa:bb:cc:dd:ee:01" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_device_detail_shows_class(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        db.upsert_device(
            mac="aa:bb:cc:dd:ee:ff",
            device_type="ble",
            oui_vendor=None,
            is_randomized=0,
            now_ts=100,
            ble_device_class=CLASS_AIRPODS,
        )
        with TestClient(app) as client:
            r = client.get("/devices/aa:bb:cc:dd:ee:ff")
        assert r.status_code == 200
        assert "BLE class" in r.text
        assert CLASS_AIRPODS in r.text
    finally:
        db.close()
