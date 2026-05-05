"""Regression tests guarding the vendored Pico CSS and HTMX assets.

These tests fail loudly if someone replaces the real vendored libraries with
placeholder stubs (or accidentally truncates them during a refactor). The
sizes encoded here are deliberately conservative — they catch placeholder
stubs without being so tight that a Pico/HTMX patch release breaks them.

The placeholder marker check looks for the exact phrase used in the original
stubs ("Replace with vendored copy"), not the bare word "placeholder" — Pico
uses the `::placeholder` CSS pseudo-element legitimately, so the bare-word
check would always fail against the real library.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import create_app

STATIC_DIR = Path(__file__).resolve().parent.parent / "src" / "lynceus" / "webui" / "static"


def _make_app(tmp_path):
    config = Config(db_path=str(tmp_path / "ui.db"))
    db = Database(config.db_path)
    app = create_app(config, db)
    return app, db


@pytest.mark.webui
def test_pico_css_is_real():
    pico = STATIC_DIR / "pico.min.css"
    data = pico.read_bytes()
    assert len(data) > 15000, (
        f"pico.min.css is {len(data)} bytes — under 15 KB; the real classless "
        f"build is ~25-40 KB+. This usually means a placeholder snuck back in."
    )
    head = data[:2000].decode("utf-8", errors="replace")
    sentinels = (":root", "Pico", "@charset", "html", "body")
    assert any(s in head for s in sentinels), (
        f"pico.min.css head looks unrecognisable: {head[:200]!r}"
    )
    assert b"Replace with vendored copy" not in data, (
        "pico.min.css still contains the original placeholder stub phrase"
    )
    assert b"Pico CSS placeholder." not in data


@pytest.mark.webui
def test_htmx_js_is_real():
    htmx = STATIC_DIR / "htmx.min.js"
    data = htmx.read_bytes()
    assert len(data) > 30000, (
        f"htmx.min.js is {len(data)} bytes — under 30 KB; HTMX 2.x minified is "
        f"roughly 45-55 KB. This usually means a placeholder snuck back in."
    )
    head = data[:2000].decode("utf-8", errors="replace").lower()
    assert "htmx" in head, f"htmx.min.js head missing 'htmx' marker: {head[:200]!r}"
    assert b"Replace with vendored copy" not in data, (
        "htmx.min.js still contains the original placeholder stub phrase"
    )
    assert b"HTMX placeholder." not in data


@pytest.mark.webui
def test_pico_served_with_real_content(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/static/pico.min.css")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/css")
        assert len(r.content) > 15000
        assert b"Replace with vendored copy" not in r.content
        assert b"Pico CSS placeholder." not in r.content
    finally:
        db.close()


@pytest.mark.webui
def test_htmx_served_with_real_content(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/static/htmx.min.js")
        assert r.status_code == 200
        assert "javascript" in r.headers["content-type"]
        assert len(r.content) > 30000
        assert b"Replace with vendored copy" not in r.content
        assert b"HTMX placeholder." not in r.content
    finally:
        db.close()
