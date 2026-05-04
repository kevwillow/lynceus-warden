"""Tests for the read-only web UI skeleton."""

from __future__ import annotations

import io
from contextlib import redirect_stdout

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from talos.config import Config
from talos.db import Database
from talos.webui.app import create_app


def _make_app(tmp_path):
    config = Config(db_path=str(tmp_path / "ui.db"))
    db = Database(config.db_path)
    app = create_app(config, db)
    return app, db


@pytest.mark.webui
def test_healthz_returns_200_and_renders(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/healthz")
        assert r.status_code == 200
        assert "schema version" in r.text
        assert "devices tracked" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_healthz_reflects_db_state(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        db.upsert_device("aa:bb:cc:dd:ee:01", "wifi", "Acme", 0, 100)
        db.upsert_device("aa:bb:cc:dd:ee:02", "wifi", "Acme", 0, 100)
        db.add_alert(ts=200, rule_name="rule_a", mac=None, message="boom", severity="high")

        with TestClient(app) as client:
            r = client.get("/healthz")
        assert r.status_code == 200
        text = r.text
        # Loose assertions — tighten when real views land in prompt 15.
        idx_devices = text.find("devices tracked")
        assert idx_devices != -1
        assert "2" in text[idx_devices : idx_devices + 200]
        idx_alerts_total = text.find("alerts (total)")
        assert idx_alerts_total != -1
        assert "1" in text[idx_alerts_total : idx_alerts_total + 200]
    finally:
        db.close()


@pytest.mark.webui
def test_root_renders_same_as_healthz_for_now(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r_root = client.get("/")
            r_health = client.get("/healthz")
        assert r_root.status_code == 200
        assert r_health.status_code == 200
        assert "schema version" in r_root.text
        assert "devices tracked" in r_root.text
    finally:
        db.close()


@pytest.mark.webui
def test_static_pico_css_served(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/static/pico.min.css")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/css")
    finally:
        db.close()


@pytest.mark.webui
def test_static_htmx_js_served(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/static/htmx.min.js")
        assert r.status_code == 200
        assert "javascript" in r.headers["content-type"]
    finally:
        db.close()


@pytest.mark.webui
def test_openapi_disabled(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            assert client.get("/openapi.json").status_code == 404
            assert client.get("/docs").status_code == 404
            assert client.get("/redoc").status_code == 404
    finally:
        db.close()


@pytest.mark.webui
def test_app_factory_returns_distinct_apps(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    app1, db1 = _make_app(tmp_path / "a")
    app2, db2 = _make_app(tmp_path / "b")
    try:
        assert app1 is not app2
        assert app1.state.db is not app2.state.db
    finally:
        db1.close()
        db2.close()


@pytest.mark.webui
def test_main_version_flag_exits_zero():
    from talos import __version__
    from talos.webui.server import main

    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = main(["--version"])
    assert rc == 0
    assert __version__ in buf.getvalue()


@pytest.mark.webui
def test_main_missing_config_returns_one(tmp_path):
    from talos.webui.server import main

    rc = main(["--config", str(tmp_path / "nonexistent.yaml")])
    assert rc == 1


@pytest.mark.webui
def test_config_default_ui_bind_host_loopback():
    cfg = Config()
    assert cfg.ui_bind_host == "127.0.0.1"
    assert cfg.ui_bind_port == 8765
    assert cfg.ui_allow_remote is False


@pytest.mark.webui
def test_config_non_loopback_without_remote_flag_rejected():
    with pytest.raises(ValidationError) as exc_info:
        Config(ui_bind_host="0.0.0.0")
    assert "ui_allow_remote" in str(exc_info.value)


@pytest.mark.webui
def test_config_non_loopback_with_remote_flag_accepted():
    cfg = Config(ui_bind_host="0.0.0.0", ui_allow_remote=True)
    assert cfg.ui_bind_host == "0.0.0.0"
    assert cfg.ui_allow_remote is True


@pytest.mark.webui
def test_config_localhost_string_accepted():
    cfg = Config(ui_bind_host="localhost")
    assert cfg.ui_bind_host == "localhost"
    assert cfg.ui_allow_remote is False


@pytest.mark.webui
def test_config_invalid_port_rejected():
    with pytest.raises(ValidationError):
        Config(ui_bind_port=0)
    with pytest.raises(ValidationError):
        Config(ui_bind_port=70000)
