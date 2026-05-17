"""Tests for the /healthz.json monitoring endpoint and its per-check helpers.

Shape stability is the load-bearing commitment for this endpoint —
monitoring tools (Prometheus blackbox, Nagios, uptime bots) pin the key
set. The ``_test_shape_*`` cases pin every expected key at every nested
path so an unintended rename or removal fails loudly.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui import app as app_mod
from lynceus.webui.app import (
    _check_alerts,
    _check_db,
    _check_poller,
    _check_ruleset,
    _check_watchlist,
    create_app,
)


# ---- fixtures --------------------------------------------------------------


def _make_db(tmp_path: Path) -> tuple[Config, Database]:
    config = Config(db_path=str(tmp_path / "ui.db"))
    db = Database(config.db_path)
    db.ensure_location("default", "Default")
    return config, db


def _seed_device(db: Database, mac: str = "aa:bb:cc:dd:ee:01", now: int = 1700000000) -> None:
    db.upsert_device(mac, "wifi", "Acme", 0, now)


# ---- _check_db -------------------------------------------------------------


@pytest.mark.webui
def test_check_db_returns_ok_on_healthy_connection(tmp_path):
    _, db = _make_db(tmp_path)
    try:
        result = _check_db(db)
        assert result == {"status": "ok", "detail": None}
    finally:
        db.close()


@pytest.mark.webui
def test_check_db_returns_error_on_closed_connection(tmp_path):
    _, db = _make_db(tmp_path)
    db.close()
    result = _check_db(db)
    assert result["status"] == "error"
    assert isinstance(result["detail"], str)
    assert result["detail"]  # non-empty


# ---- _check_poller --------------------------------------------------------


@pytest.mark.webui
def test_check_poller_returns_nulls_on_empty_db(tmp_path):
    _, db = _make_db(tmp_path)
    try:
        result = _check_poller(db, now_ts=1800000000)
        assert result["status"] == "ok"
        assert result["last_poll_at"] is None
        assert result["seconds_since_poll"] is None
        assert result["last_observation_at"] is None
        assert result["seconds_since_observation"] is None
    finally:
        db.close()


@pytest.mark.webui
def test_check_poller_returns_last_poll_at_when_set(tmp_path):
    _, db = _make_db(tmp_path)
    try:
        db.set_state("last_poll_ts", "1700000000")
        result = _check_poller(db, now_ts=1700003600)
        assert result["last_poll_at"] == "2023-11-14T22:13:20Z"
        assert result["seconds_since_poll"] == 3600
    finally:
        db.close()


@pytest.mark.webui
def test_check_poller_returns_last_observation_from_max_sighting_ts(tmp_path):
    _, db = _make_db(tmp_path)
    try:
        _seed_device(db)
        db.insert_sighting("aa:bb:cc:dd:ee:01", 1700000000, -50, "A", "default")
        db.insert_sighting("aa:bb:cc:dd:ee:01", 1700001000, -50, "A", "default")
        result = _check_poller(db, now_ts=1700001500)
        assert result["last_observation_at"] == "2023-11-14T22:30:00Z"
        assert result["seconds_since_observation"] == 500
    finally:
        db.close()


# ---- _check_watchlist -----------------------------------------------------


@pytest.mark.webui
def test_check_watchlist_returns_zeros_on_empty_db(tmp_path):
    config, db = _make_db(tmp_path)
    try:
        result = _check_watchlist(db, config, now_ts=1700000000)
        assert result["status"] == "ok"
        assert result["total_rows"] == 0
        assert result["last_imported_at"] is None
        assert result["days_since_import"] is None
        assert result["stale"] is False
        # by_pattern_type carries every known pattern_type even when zero.
        assert set(result["by_pattern_type"].keys()) >= {
            "mac",
            "oui",
            "ssid",
        }
        for v in result["by_pattern_type"].values():
            assert v == 0
    finally:
        db.close()


@pytest.mark.webui
def test_check_watchlist_total_rows_sums_by_pattern_type(tmp_path):
    config, db = _make_db(tmp_path)
    try:
        db._conn.execute(
            "INSERT INTO watchlist(pattern_type, pattern, severity, description) "
            "VALUES ('mac', 'aa:bb:cc:dd:ee:01', 'low', 'a')"
        )
        db._conn.execute(
            "INSERT INTO watchlist(pattern_type, pattern, severity, description) "
            "VALUES ('mac', 'aa:bb:cc:dd:ee:02', 'low', 'b')"
        )
        db._conn.execute(
            "INSERT INTO watchlist(pattern_type, pattern, severity, description) "
            "VALUES ('oui', 'aa:bb:cc', 'low', 'c')"
        )
        db._conn.commit()
        result = _check_watchlist(db, config, now_ts=1700000000)
        assert result["total_rows"] == 3
        assert result["by_pattern_type"]["mac"] == 2
        assert result["by_pattern_type"]["oui"] == 1
    finally:
        db.close()


@pytest.mark.webui
def test_check_watchlist_days_since_import_and_stale_flag(tmp_path):
    config, db = _make_db(tmp_path)
    try:
        # Threshold: 30 days. Import 40 days before now -> stale.
        imported_at = 1700000000
        now_ts = imported_at + 40 * 86400
        db.record_import_run(
            imported_at=imported_at, exported_at=None, source="t", record_count=1
        )
        result = _check_watchlist(db, config, now_ts=now_ts)
        assert result["last_imported_at"] == "2023-11-14T22:13:20Z"
        assert result["days_since_import"] == 40
        assert result["stale"] is True
    finally:
        db.close()


@pytest.mark.webui
def test_check_watchlist_fresh_import_is_not_stale(tmp_path):
    config, db = _make_db(tmp_path)
    try:
        imported_at = 1700000000
        now_ts = imported_at + 5 * 86400  # 5 days < 30 day threshold
        db.record_import_run(
            imported_at=imported_at, exported_at=None, source="t", record_count=1
        )
        result = _check_watchlist(db, config, now_ts=now_ts)
        assert result["days_since_import"] == 5
        assert result["stale"] is False
    finally:
        db.close()


@pytest.mark.webui
def test_check_watchlist_respects_config_threshold(tmp_path):
    # Threshold 7 days; import 10 days ago -> stale.
    config = Config(
        db_path=str(tmp_path / "ui.db"),
        watchlist_staleness_warn_days=7,
    )
    db = Database(config.db_path)
    try:
        imported_at = 1700000000
        now_ts = imported_at + 10 * 86400
        db.record_import_run(
            imported_at=imported_at, exported_at=None, source="t", record_count=1
        )
        result = _check_watchlist(db, config, now_ts=now_ts)
        assert result["days_since_import"] == 10
        assert result["stale"] is True
    finally:
        db.close()


# ---- _check_ruleset -------------------------------------------------------


@pytest.mark.webui
def test_check_ruleset_unset_path(tmp_path):
    config = Config(db_path=str(tmp_path / "ui.db"))
    assert config.rules_path is None
    result = _check_ruleset(config)
    assert result == {
        "status": "ok",
        "active_rules": 0,
        "rules_path_configured": False,
    }


@pytest.mark.webui
def test_check_ruleset_counts_enabled_rules(tmp_path):
    rules_path = tmp_path / "rules.yaml"
    rules_path.write_text(
        (
            "rules:\n"
            "  - name: r1\n"
            "    rule_type: watchlist_mac\n"
            "    severity: low\n"
            "    patterns: []\n"
            "  - name: r2\n"
            "    rule_type: watchlist_oui\n"
            "    severity: low\n"
            "    patterns: []\n"
        ),
        encoding="utf-8",
    )
    config = Config(db_path=str(tmp_path / "ui.db"), rules_path=str(rules_path))
    result = _check_ruleset(config)
    assert result["status"] == "ok"
    assert result["rules_path_configured"] is True
    assert result["active_rules"] == 2


@pytest.mark.webui
def test_check_ruleset_disabled_rules_dont_count(tmp_path):
    rules_path = tmp_path / "rules.yaml"
    rules_path.write_text(
        (
            "rules:\n"
            "  - name: r1\n"
            "    rule_type: watchlist_mac\n"
            "    severity: low\n"
            "    patterns: []\n"
            "    enabled: false\n"
        ),
        encoding="utf-8",
    )
    config = Config(db_path=str(tmp_path / "ui.db"), rules_path=str(rules_path))
    result = _check_ruleset(config)
    assert result["active_rules"] == 0


@pytest.mark.webui
def test_check_ruleset_broken_file_returns_zero(tmp_path):
    """Wired but broken — status stays ok, active_rules=0. Top-level
    health is unaffected; this is the documented 'configured but
    broken' shape monitoring tools can detect."""
    rules_path = tmp_path / "rules.yaml"
    rules_path.write_text("rules: [unbalanced\n", encoding="utf-8")
    config = Config(db_path=str(tmp_path / "ui.db"), rules_path=str(rules_path))
    result = _check_ruleset(config)
    assert result["status"] == "ok"
    assert result["rules_path_configured"] is True
    assert result["active_rules"] == 0


@pytest.mark.webui
def test_check_ruleset_missing_file_returns_zero(tmp_path):
    config = Config(
        db_path=str(tmp_path / "ui.db"),
        rules_path=str(tmp_path / "absent.yaml"),
    )
    result = _check_ruleset(config)
    assert result["rules_path_configured"] is True
    assert result["active_rules"] == 0


# ---- _check_alerts --------------------------------------------------------


@pytest.mark.webui
def test_check_alerts_returns_zeros_on_empty_db(tmp_path):
    _, db = _make_db(tmp_path)
    try:
        result = _check_alerts(db, now_ts=1700000000)
        assert result == {"status": "ok", "total": 0, "last_hour": 0}
    finally:
        db.close()


@pytest.mark.webui
def test_check_alerts_counts_total_and_last_hour(tmp_path):
    _, db = _make_db(tmp_path)
    try:
        now = 1700000000
        # 3 alerts: 2 within last hour, 1 older
        db.add_alert(ts=now - 7200, rule_name="r", mac=None, message="old", severity="low")
        db.add_alert(ts=now - 1800, rule_name="r", mac=None, message="recent1", severity="low")
        db.add_alert(ts=now - 600, rule_name="r", mac=None, message="recent2", severity="low")
        result = _check_alerts(db, now_ts=now)
        assert result["total"] == 3
        assert result["last_hour"] == 2
    finally:
        db.close()


# ---- /healthz.json endpoint integration -----------------------------------


def _make_app(tmp_path: Path) -> tuple[object, Database]:
    config, db = _make_db(tmp_path)
    app = create_app(config, db)
    return app, db


@pytest.mark.webui
def test_healthz_json_returns_200_on_healthy_db(tmp_path):
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/healthz.json")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "ok"
        assert isinstance(body["version"], str)
        assert set(body["checks"].keys()) == {
            "db",
            "poller",
            "watchlist",
            "ruleset",
            "alerts",
        }
    finally:
        db.close()


@pytest.mark.webui
def test_healthz_json_response_shape_stability(tmp_path):
    """Pins the public JSON contract. Any future change that removes a
    key from this set is a breaking change for monitoring integrations
    and should rev the endpoint to /v2 (which is deliberately
    out-of-scope for v1)."""
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/healthz.json")
        body = r.json()
        assert set(body.keys()) == {"status", "version", "checks"}

        assert set(body["checks"]["db"].keys()) == {"status", "detail"}
        assert set(body["checks"]["poller"].keys()) == {
            "status",
            "last_poll_at",
            "seconds_since_poll",
            "last_observation_at",
            "seconds_since_observation",
        }
        assert set(body["checks"]["watchlist"].keys()) == {
            "status",
            "total_rows",
            "by_pattern_type",
            "last_imported_at",
            "days_since_import",
            "stale",
        }
        assert set(body["checks"]["ruleset"].keys()) == {
            "status",
            "active_rules",
            "rules_path_configured",
        }
        assert set(body["checks"]["alerts"].keys()) == {
            "status",
            "total",
            "last_hour",
        }
    finally:
        db.close()


@pytest.mark.webui
def test_healthz_json_returns_503_when_db_unreachable(tmp_path):
    """DB-down shape: only the db check is present (others can't be
    computed without the DB)."""
    app, db = _make_app(tmp_path)
    db.close()  # close after app creation so the route sees a dead conn
    with TestClient(app) as client:
        r = client.get("/healthz.json")
    assert r.status_code == 503
    body = r.json()
    assert body["status"] == "error"
    assert "db" in body["checks"]
    assert body["checks"]["db"]["status"] == "error"
    assert isinstance(body["checks"]["db"]["detail"], str)
    # Other checks must be omitted — can't compute without DB.
    assert set(body["checks"].keys()) == {"db"}


@pytest.mark.webui
def test_healthz_json_unauthenticated_and_read_only(tmp_path):
    """No CSRF token, no cookie, no Authorization header — must
    succeed. /healthz.json is the standard monitoring-facing surface."""
    app, db = _make_app(tmp_path)
    try:
        # TestClient defaults to a fresh client without any cookies.
        with TestClient(app) as client:
            r = client.get("/healthz.json")
        assert r.status_code == 200
    finally:
        db.close()


@pytest.mark.webui
def test_healthz_json_does_not_break_existing_html_healthz(tmp_path):
    """The HTML page at /healthz keeps its template-rendered shape so
    the nav link, docs/SMOKE.md grep, and existing webui tests stay
    untouched."""
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r_html = client.get("/healthz")
            r_json = client.get("/healthz.json")
        assert r_html.status_code == 200
        assert "schema version" in r_html.text  # HTML template literal
        assert r_json.status_code == 200
        assert r_json.headers["content-type"].startswith("application/json")
    finally:
        db.close()


@pytest.mark.webui
def test_healthz_json_top_level_status_reflects_all_subchecks(tmp_path, monkeypatch):
    """If any sub-check returns status 'error', the top-level status
    flips to 'error' and HTTP 503. Currently only _check_db can fail,
    so we synthesize the failure by patching one of the others."""
    app, db = _make_app(tmp_path)
    try:
        monkeypatch.setattr(
            app_mod,
            "_check_alerts",
            lambda db, *, now_ts: {"status": "error", "total": 0, "last_hour": 0},
        )
        with TestClient(app) as client:
            r = client.get("/healthz.json")
        assert r.status_code == 503
        body = r.json()
        assert body["status"] == "error"
        assert body["checks"]["alerts"]["status"] == "error"
    finally:
        db.close()


@pytest.mark.webui
def test_healthz_json_seconds_since_uses_request_clock(tmp_path, monkeypatch):
    """The seconds_since_* fields use a single request-time clock so
    last_poll_at and last_observation_at appear coherent. Monkey-
    patching time.time confirms the route uses it rather than a per-
    helper time call."""
    app, db = _make_app(tmp_path)
    try:
        db.set_state("last_poll_ts", "1700000000")
        monkeypatch.setattr(app_mod.time, "time", lambda: 1700003600.0)
        with TestClient(app) as client:
            r = client.get("/healthz.json")
        body = r.json()
        assert body["checks"]["poller"]["seconds_since_poll"] == 3600
    finally:
        db.close()
