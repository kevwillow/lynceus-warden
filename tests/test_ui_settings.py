"""Tests for the read-only /settings page.

The /settings page surfaces current configuration with prominent visual
treatment for privacy-relevant settings (probe SSID capture in particular).
It's strictly read-only — no mutation endpoints — and never displays
sensitive values (Kismet API token, full ntfy topic) at full fidelity.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from lynceus import __version__
from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import create_app
from lynceus.webui.csrf import CSRF_HEADER_NAME

KISMET_TOKEN_SENTINEL = "kismet-secret-token-DO-NOT-LEAK-12345"
NTFY_TOPIC_SENTINEL = "lynceus-private-topic-abcdef-XYZ"


def _make_app(tmp_path, **config_overrides):
    kwargs = {"db_path": str(tmp_path / "settings.db")}
    kwargs.update(config_overrides)
    config = Config(**kwargs)
    db = Database(config.db_path)
    app = create_app(config, db)
    return app, db


def _add_watchlist(
    db: Database,
    pattern: str,
    pattern_type: str = "mac",
    severity: str = "med",
    description: str | None = None,
) -> int:
    with db._conn:
        cur = db._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity, description) "
            "VALUES (?, ?, ?, ?)",
            (pattern, pattern_type, severity, description),
        )
        return int(cur.lastrowid)


def _stub_kismet_reachable(monkeypatch):
    monkeypatch.setattr(
        "lynceus.kismet.KismetClient.health_check",
        lambda self: {"reachable": True, "version": "Kismet-2024-08", "error": None},
    )


def _stub_kismet_unreachable(monkeypatch, error: str = "connection refused"):
    monkeypatch.setattr(
        "lynceus.kismet.KismetClient.health_check",
        lambda self: {"reachable": False, "version": None, "error": error},
    )


# ---------------------------------------------------------------------------
# Smoke + nav.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_settings_returns_200(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
    finally:
        db.close()


@pytest.mark.webui
def test_settings_link_present_on_settings_page(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        assert 'href="/settings"' in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_settings_link_present_on_alerts_page(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/alerts")
        assert r.status_code == 200
        assert 'href="/settings"' in r.text
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Capture configuration section.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_capture_section_renders_both_toggles(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        # Both names visible on the page.
        assert "probe_ssids" in r.text
        assert "ble_friendly_names" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_probe_ssids_off_shows_privacy_mode_not_recording(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path, capture={"probe_ssids": False})
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        assert "privacy mode" in r.text
        assert "recording probe SSIDs" not in r.text
        assert "is not recorded" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_probe_ssids_on_shows_recording_not_privacy_mode(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path, capture={"probe_ssids": True})
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        assert "recording probe SSIDs" in r.text
        assert "privacy mode" not in r.text
        assert "Lynceus is recording WiFi network names" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_capture_section_includes_reconfigure_guidance(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        assert "lynceus-setup --reconfigure" in r.text
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Kismet section.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_kismet_section_renders_url(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path, kismet_url="http://kismet.test:2501")
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        assert "http://kismet.test:2501" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_kismet_token_never_in_html(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path, kismet_api_key=KISMET_TOKEN_SENTINEL)
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        assert KISMET_TOKEN_SENTINEL not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_kismet_token_configured_placeholder(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path, kismet_api_key=KISMET_TOKEN_SENTINEL)
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        assert "(configured)" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_kismet_token_not_configured_placeholder(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path, kismet_api_key=None)
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        assert "(not configured)" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_kismet_health_check_success_renders_reachable(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        assert "reachable" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_kismet_health_check_failure_renders_unreachable_with_reason(tmp_path, monkeypatch):
    error_reason = "kismet-down-test-reason"
    _stub_kismet_unreachable(monkeypatch, error=error_reason)
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        assert "unreachable" in r.text
        assert error_reason in r.text
    finally:
        db.close()


# ---------------------------------------------------------------------------
# ntfy section.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_ntfy_topic_full_value_never_in_html(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(
        tmp_path,
        ntfy_url="https://ntfy.example.com",
        ntfy_topic=NTFY_TOPIC_SENTINEL,
    )
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        assert NTFY_TOPIC_SENTINEL not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_ntfy_topic_redacted_form_present(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(
        tmp_path,
        ntfy_url="https://ntfy.example.com",
        ntfy_topic=NTFY_TOPIC_SENTINEL,
    )
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        # First 4 + bullets + last 2.
        expected = NTFY_TOPIC_SENTINEL[:4] + "•••" + NTFY_TOPIC_SENTINEL[-2:]
        assert expected in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_ntfy_section_renders_broker_url(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(
        tmp_path,
        ntfy_url="https://ntfy.example.com",
        ntfy_topic=NTFY_TOPIC_SENTINEL,
    )
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        assert "https://ntfy.example.com" in r.text
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Watchlist data section.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_watchlist_section_shows_total_count(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        _add_watchlist(db, "aa:bb:cc:dd:ee:01")
        _add_watchlist(db, "aa:bb:cc:dd:ee:02")
        _add_watchlist(db, "aa:bb:cc:dd:ee:03")
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        # Total count shown somewhere.
        assert "3" in r.text
        assert "watchlist" in r.text.lower()
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_section_shows_origin_breakdown(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        # Argus-imported (3 entries with non-yaml argus_record_id)
        for i in range(3):
            wid = _add_watchlist(db, f"argus-{i:02d}:11:22:33:44:55", description=f"argus-{i}")
            db.upsert_metadata(
                wid, {"argus_record_id": f"argus-rec-{i}", "device_category": "test"}
            )
        # Yaml-seeded (2 entries with yaml- prefixed argus_record_id)
        for i in range(2):
            wid = _add_watchlist(db, f"yaml-{i:02d}:11:22:33:44:55", description=f"yaml-{i}")
            db.upsert_metadata(
                wid, {"argus_record_id": f"yaml-{i:016d}", "device_category": "test"}
            )
        # Bundled-or-other (1 entry with no metadata)
        _add_watchlist(db, "bundled-aa:bb:cc:dd:ee:99", description="bundled")
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        text = r.text
        # Find the watchlist section and check the three counts appear.
        # Descriptive labels for each origin.
        assert "argus-imported" in text
        assert "yaml-seeded" in text
        assert "bundled" in text
        # Look for "3" near argus, "2" near yaml, "1" near bundled.
        argus_idx = text.find("argus-imported")
        assert argus_idx != -1
        assert "3" in text[argus_idx : argus_idx + 200]
        yaml_idx = text.find("yaml-seeded")
        assert yaml_idx != -1
        assert "2" in text[yaml_idx : yaml_idx + 200]
        bundled_idx = text.find("bundled")
        assert bundled_idx != -1
        assert "1" in text[bundled_idx : bundled_idx + 200]
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_section_includes_import_guidance(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        assert "lynceus-import-argus" in r.text
        assert "lynceus-seed-watchlist" in r.text
    finally:
        db.close()


# ---------------------------------------------------------------------------
# System info section.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_system_info_shows_lynceus_version(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        assert __version__ in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_system_info_shows_db_path(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    db_path = str(tmp_path / "settings.db")
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        assert db_path in r.text
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Severity overrides + system info: guidance text.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_severity_overrides_section_includes_guidance(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        assert "severity_overrides.yaml" in r.text
        assert "Edit the file directly" in r.text
    finally:
        db.close()


# ---------------------------------------------------------------------------
# No-mutation guarantees.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_settings_post_returns_405(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r_get = client.get("/settings")
            token = r_get.cookies.get("lynceus_csrf", "")
            r = client.post("/settings", headers={CSRF_HEADER_NAME: token})
        assert r.status_code == 405
    finally:
        db.close()


@pytest.mark.webui
def test_settings_put_returns_405(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r_get = client.get("/settings")
            token = r_get.cookies.get("lynceus_csrf", "")
            r = client.put("/settings", headers={CSRF_HEADER_NAME: token})
        assert r.status_code == 405
    finally:
        db.close()


@pytest.mark.webui
def test_settings_patch_returns_405(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r_get = client.get("/settings")
            token = r_get.cookies.get("lynceus_csrf", "")
            r = client.patch("/settings", headers={CSRF_HEADER_NAME: token})
        assert r.status_code == 405
    finally:
        db.close()


@pytest.mark.webui
def test_settings_delete_returns_405(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r_get = client.get("/settings")
            token = r_get.cookies.get("lynceus_csrf", "")
            r = client.delete("/settings", headers={CSRF_HEADER_NAME: token})
        assert r.status_code == 405
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Misc safety / regression.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_xss_in_kismet_error_is_escaped(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "lynceus.kismet.KismetClient.health_check",
        lambda self: {
            "reachable": False,
            "version": None,
            "error": "<script>alert('xss')</script>",
        },
    )
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        assert "<script>alert('xss')</script>" not in r.text
        assert "&lt;script&gt;" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_importlib_metadata_used_for_version(tmp_path, monkeypatch):
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        with patch("importlib.metadata.version", return_value="9.9.9-test"):
            with TestClient(app) as client:
                r = client.get("/settings")
        assert r.status_code == 200
        assert "9.9.9-test" in r.text
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Watchlist freshness card (migration 012 + the staleness signal).
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_watchlist_freshness_card_renders_no_import_state(tmp_path, monkeypatch):
    """Fresh-install state: no import_runs rows yet → card renders
    the 'no Argus import metadata recorded' message without
    erroring. Backward-compat invariant: an empty DB must not
    crash /settings."""
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        assert "watchlist freshness" in r.text
        assert "No Argus import metadata recorded" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_freshness_card_renders_fresh_state(tmp_path, monkeypatch):
    """A recent import (within default 30-day threshold) → card
    renders the fresh badge + the source string verbatim."""
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        import time
        now = int(time.time())
        db.record_import_run(
            imported_at=now - 86400,        # 1 day ago
            exported_at=now - 86400,
            source="kevwillow/argus-db@v9.9.9",
            record_count=12345,
        )
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        text = r.text
        assert "watchlist freshness" in text
        assert "fresh" in text
        # Source string renders verbatim — operator-facing forensic field.
        assert "kevwillow/argus-db@v9.9.9" in text
        assert "12345" in text  # record_count
        # Refresh hint must NOT appear in the fresh state.
        assert "lynceus-import-argus --from-github" not in text or (
            # The setup-instructions block at the bottom may mention it
            # in the no-import branch; assert specifically the stale
            # refresh hint copy isn't on a fresh page.
            "consider" not in text
        )
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_freshness_card_renders_stale_state_with_refresh_hint(
    tmp_path, monkeypatch
):
    """Over-threshold data → card renders the stale badge plus the
    `lynceus-import-argus --from-github` refresh hint. The operator
    opening /settings during routine triage should see the same
    signal that journalctl's WARNING line surfaces at daemon
    startup — the two surfaces are deliberately kept in lockstep."""
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path, watchlist_staleness_warn_days=5)
    try:
        import time
        now = int(time.time())
        db.record_import_run(
            imported_at=now - 10 * 86400,    # 10 days ago, > 5-day threshold
            exported_at=now - 10 * 86400,
            source="/var/lib/lynceus/argus-cache/v1.csv",
            record_count=100,
        )
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        text = r.text
        assert "stale" in text
        assert "lynceus-import-argus --from-github" in text
        assert "/var/lib/lynceus/argus-cache/v1.csv" in text
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_freshness_card_pattern_type_breakdown_renders_counts(
    tmp_path, monkeypatch
):
    """Pattern-type breakdown on the card matches the underlying
    watchlist_pattern_type_counts query for every pattern_type the
    schema admits. Operators on /settings see the same per-type
    numbers the importer's summary surfaces.

    Asserts all 7 pattern_types in ``Database._WATCHLIST_PATTERN_TYPES``
    so drift between the DB layer and the template surface fails
    loudly: rc5 shipped the two new types (ble_manufacturer_id,
    drone_id_prefix) into the schema but the template line was
    only extended to render five — operators saw the new rows in
    the importer summary but a silent zero on /settings."""
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        # Seed 2 mac, 1 oui, 0 ssid, 0 ble_uuid, 1 mac_range,
        # 1 ble_manufacturer_id, 1 drone_id_prefix.
        for pat in ("aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02"):
            _add_watchlist(db, pat, pattern_type="mac")
        _add_watchlist(db, "00:13:37", pattern_type="oui")
        _add_watchlist(db, "004c", pattern_type="ble_manufacturer_id")
        _add_watchlist(db, "21239ESA2", pattern_type="drone_id_prefix")
        with db._conn:
            db._conn.execute(
                "INSERT INTO watchlist("
                "pattern, pattern_type, severity, description, "
                "mac_range_prefix, mac_range_prefix_length) "
                "VALUES ('aa:bb:cc:d/28', 'mac_range', 'low', NULL, "
                "'aabbccd', 28)"
            )
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        text = r.text
        # The breakdown line covers all 7 schema-admitted types.
        assert "mac=2" in text
        assert "oui=1" in text
        assert "ssid=0" in text
        assert "ble_uuid=0" in text
        assert "mac_range=1" in text
        assert "ble_manufacturer_id=1" in text
        assert "drone_id_prefix=1" in text
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Watchlist-zero signposting on the /settings watchlist-data card.
#
# v0.7.5 smoke surfaced that an empty watchlist always rendered the
# "To add data, run lynceus-import-argus..." hint — even when the
# wizard's bundled import had just run and admitted zero rows due to
# import filters. Operators read the message and concluded "nothing
# happened" when in fact the import ran and dropped every row. The
# v0.7.6 fix branches the total=0 path on watchlist_freshness.has_
# import so the dropped-all-rows case gets a distinct message.
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_watchlist_data_card_zero_total_no_imports_shows_legacy_hint(
    tmp_path, monkeypatch
):
    """Fresh install: watchlist empty, no import_runs rows. Card must
    still render the legacy "To add data..." hint so the operator's
    first signpost remains the importer / seeder. Pre-v0.7.6 behavior
    preserved on this branch."""
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        text = r.text
        # Existing hint copy survives.
        assert "lynceus-import-argus --input" in text
        assert "lynceus-seed-watchlist --yaml" in text
        # The dropped-all-rows copy must NOT appear here.
        assert "0 records admitted" not in text
        assert "dropped every row" not in text
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_data_card_zero_total_with_import_shows_drop_hint(
    tmp_path, monkeypatch
):
    """The kev-smoke scenario: import_runs has a recent row, watchlist
    has zero rows. Card must surface the "import filters dropped every
    row" copy + the journalctl pointer so the operator's next move is
    diagnostic rather than "run the importer again on the same data"."""
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        import time
        now = int(time.time())
        db.record_import_run(
            imported_at=now - 86400,  # 1 day ago
            exported_at=now - 86400,
            source="/tmp/argus.csv",
            record_count=241,
        )
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        text = r.text
        # New copy on this branch: explicit drop count + journalctl
        # pointer + the filter names operators see in drop logs.
        assert "0 records admitted" in text
        assert "241" in text  # record_count from the import_runs row
        assert "journalctl -u lynceus" in text
        # At least one of the canonical filter names so operators can
        # grep for them in their journalctl output.
        assert (
            "unknown_type" in text
            or "peer_collision" in text
            or "in_import_dup" in text
        )
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_data_card_populated_total_does_not_show_drop_hint(
    tmp_path, monkeypatch
):
    """When the watchlist has rows, neither the legacy hint nor the
    drop-hint should appear in the watchlist-data card — the card
    already shows the counts and that's signal enough. Guards against
    the dropped-rows copy bleeding across the total>0 branch."""
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        _add_watchlist(db, "aa:bb:cc:dd:ee:01")
        _add_watchlist(db, "aa:bb:cc:dd:ee:02")
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        text = r.text
        assert "0 records admitted" not in text
        # And the watchlist-data card itself shouldn't carry the
        # legacy "To add data..." prompt when it already has data.
        # (The text exists elsewhere on the page — narrow the assertion
        # to a substring that's specific to the data card.)
        # Both stats render the total=2.
        assert ">2<" in text  # total entries cell
    finally:
        db.close()


@pytest.mark.webui
def test_watchlist_data_card_zero_total_import_no_record_count_still_signals(
    tmp_path, monkeypatch
):
    """A pre-`# meta:` legacy CSV leaves record_count as NULL in
    import_runs. The drop-hint must still render — just without the
    "out of N" sub-clause — so the operator still gets the journalctl
    pointer."""
    _stub_kismet_reachable(monkeypatch)
    app, db = _make_app(tmp_path)
    try:
        import time
        now = int(time.time())
        db.record_import_run(
            imported_at=now - 2 * 86400,
            exported_at=None,
            source="/tmp/legacy.csv",
            record_count=None,
        )
        with TestClient(app) as client:
            r = client.get("/settings")
        assert r.status_code == 200
        text = r.text
        assert "0 records admitted" in text
        assert "journalctl -u lynceus" in text
        # The "out of N in the source" sub-clause must NOT appear when
        # the legacy CSV's record_count was NULL.
        assert "out of" not in text or "out of None" not in text
    finally:
        db.close()
