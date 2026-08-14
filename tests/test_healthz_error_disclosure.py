"""``/healthz.json`` must not hand a raw driver exception to an anonymous caller.

`_check_db` caught every exception and returned ``{"status": "error",
"detail": str(exc)}``, and `/healthz.json` returned that dict verbatim in a
503. The route has **no authentication** -- loopback binding is the only
control, and `ui_allow_remote: true` removes it -- so with remote access on,
an unauthenticated caller received whatever SQLite happened to say. SQLite
error text routinely carries the database file path, and on a disk or schema
failure it carries more.

The fix keeps the operator's diagnostics: the real exception still goes to the
server log at ERROR, where the person running the daemon can read it. Only the
HTTP body is generalised.

⚠️ The pre-existing shape tests assert `isinstance(detail, str)` and that it is
non-empty; both still hold, deliberately. This file pins the part those cannot
see -- that the string is not the driver's own words.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import _check_db, create_app

# A marker standing in for the kind of thing SQLite puts in its messages: an
# absolute path. If any of these reach the HTTP body, so would a real one.
LEAKY = "/srv/private/lynceus-data/operator-secret.db"


def _make_app(tmp_path: Path):
    config = Config(db_path=str(tmp_path / "ui.db"))
    db = Database(config.db_path)
    db.ensure_location("default", "Default")
    return create_app(config, db), db


class _ExplodingConn:
    """Stands in for a dead connection whose driver error names a real path.

    ``close`` is a no-op rather than absent: without it the ``finally:
    db.close()`` teardown raises ``AttributeError`` and every test in this
    file fails for a reason that has nothing to do with what it asserts.
    """

    def __init__(self, message: str) -> None:
        self._message = message

    def execute(self, *_a, **_kw):
        raise RuntimeError(self._message)

    def close(self) -> None:
        return None


@pytest.mark.webui
def test_check_db_does_not_return_the_driver_message(tmp_path):
    _, db = _make_app(tmp_path)
    try:
        db._conn = _ExplodingConn(f"unable to open database file: {LEAKY}")
        result = _check_db(db)

        assert result["status"] == "error"
        # The pre-existing contract still holds.
        assert isinstance(result["detail"], str) and result["detail"]
        # ...but it is not the driver's words.
        assert LEAKY not in result["detail"], (
            f"driver message reached the caller: {result['detail']!r}"
        )
        assert "unable to open database file" not in result["detail"]
    finally:
        db.close()


@pytest.mark.webui
def test_healthz_json_503_body_carries_no_driver_message(tmp_path):
    """The end-to-end path, which is what an unauthenticated caller sees."""
    app, db = _make_app(tmp_path)
    try:
        db._conn = _ExplodingConn(f"disk I/O error while reading {LEAKY}")
        with TestClient(app) as client:
            r = client.get("/healthz.json")

        assert r.status_code == 503
        body = r.json()
        assert body["checks"]["db"]["status"] == "error"
        assert isinstance(body["checks"]["db"]["detail"], str)
        assert LEAKY not in r.text, "database path disclosed in an unauthenticated 503"
        assert "disk I/O error" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_the_real_error_is_still_logged_for_the_operator(tmp_path, caplog):
    """Generalising the response must not cost the operator the diagnosis.

    Without this, a future reader could 'fix' the disclosure by discarding the
    exception entirely and nobody would notice the daemon had gone blind.
    """
    _, db = _make_app(tmp_path)
    try:
        db._conn = _ExplodingConn(f"unable to open database file: {LEAKY}")
        with caplog.at_level(logging.ERROR):
            _check_db(db)

        assert LEAKY in caplog.text, (
            "the real driver error must still reach the server log"
        )
    finally:
        db.close()


@pytest.mark.webui
def test_healthy_connection_shape_is_unchanged(tmp_path):
    _, db = _make_app(tmp_path)
    try:
        assert _check_db(db) == {"status": "ok", "detail": None}
    finally:
        db.close()
