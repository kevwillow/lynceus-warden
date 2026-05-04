"""End-to-end integration tests covering the full poller pipeline."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from talos.allowlist import load_allowlist
from talos.config import Config
from talos.db import Database
from talos.notify import NullNotifier, RecordingNotifier
from talos.poller import STATE_KEY_LAST_POLL, build_kismet_client, poll_once
from talos.rules import load_ruleset

FIXTURES = Path(__file__).parent / "fixtures"
KISMET_T1 = FIXTURES / "integration_kismet_t1.json"
KISMET_T2 = FIXTURES / "integration_kismet_t2.json"
RULES = FIXTURES / "integration_rules.yaml"
ALLOWLIST = FIXTURES / "integration_allowlist.yaml"

APPLE_MAC = "a4:83:e7:55:55:55"
PINEAPPLE_MAC = "00:13:37:ab:cd:ef"
RANDOM_CLIENT_MAC = "02:ff:ee:dd:cc:bb"
CAMBRIDGE_MAC = "00:1a:7d:da:71:99"
NEWCOMER_MAC = "de:ad:be:ef:00:99"


def _make_config(tmp_path, fixture_path, rules_path, allowlist_path, dedup_window=3600):
    return Config(
        kismet_fixture_path=str(fixture_path),
        db_path=str(tmp_path / "talos.db"),
        rules_path=str(rules_path),
        allowlist_path=str(allowlist_path),
        alert_dedup_window_seconds=dedup_window,
        location_id="integration",
        location_label="Integration Test",
    )


def _build_pipeline(config):
    db = Database(config.db_path)
    client = build_kismet_client(config)
    ruleset = load_ruleset(config.rules_path)
    allowlist = load_allowlist(config.allowlist_path)
    notifier = RecordingNotifier()
    return db, client, ruleset, allowlist, notifier


def _run_poll(client, db, config, now_ts, ruleset, allowlist, notifier) -> int:
    return poll_once(
        client,
        db,
        config,
        now_ts,
        ruleset=ruleset,
        allowlist=allowlist,
        notifier=notifier,
    )


def _count(db, table):
    return db._conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]


def _alerts(db):
    rows = db._conn.execute(
        "SELECT rule_name, mac, severity FROM alerts ORDER BY id"
    ).fetchall()
    return [(r["rule_name"], r["mac"], r["severity"]) for r in rows]


def test_e2e_first_poll_writes_devices_sightings_alerts_and_notifications(tmp_path):
    config = _make_config(tmp_path, KISMET_T1, RULES, ALLOWLIST)
    db, client, ruleset, allowlist, notifier = _build_pipeline(config)
    try:
        processed = _run_poll(client, db, config, 1700000200, ruleset, allowlist, notifier)
        assert processed == 4

        assert _count(db, "devices") == 4

        sighting_rows = db._conn.execute(
            "SELECT location_id FROM sightings"
        ).fetchall()
        assert len(sighting_rows) == 4
        assert all(r["location_id"] == "integration" for r in sighting_rows)

        alerts = _alerts(db)
        assert alerts == [
            ("pineapple_oui", PINEAPPLE_MAC, "high"),
            ("new_non_random", PINEAPPLE_MAC, "low"),
            ("new_non_random", CAMBRIDGE_MAC, "low"),
        ]

        # Apple MAC must NOT have any alerts (allowlisted)
        apple_alerts = db._conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE mac = ?", (APPLE_MAC,)
        ).fetchone()[0]
        assert apple_alerts == 0

        # Randomized client must NOT have any alerts
        random_alerts = db._conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE mac = ?", (RANDOM_CLIENT_MAC,)
        ).fetchone()[0]
        assert random_alerts == 0

        assert notifier.calls == [
            ("high", "talos: HIGH alert", notifier.calls[0][2]),
            ("low", "talos: LOW alert", notifier.calls[1][2]),
            ("low", "talos: LOW alert", notifier.calls[2][2]),
        ]
        assert PINEAPPLE_MAC in notifier.calls[0][2]
        assert PINEAPPLE_MAC in notifier.calls[1][2]
        assert CAMBRIDGE_MAC in notifier.calls[2][2]

        assert db.get_state(STATE_KEY_LAST_POLL) == "1700000200"
    finally:
        db.close()


def test_e2e_second_poll_dedup_suppresses_repeat_alerts(tmp_path):
    config_t1 = _make_config(tmp_path, KISMET_T1, RULES, ALLOWLIST)
    db, client_t1, ruleset, allowlist, notifier_t1 = _build_pipeline(config_t1)
    try:
        _run_poll(client_t1, db, config_t1, 1700000200, ruleset, allowlist, notifier_t1)
        baseline_alerts = _count(db, "alerts")
        assert baseline_alerts == 3

        # Build a second config/client targeting the t2 fixture but the same db.
        config_t2 = config_t1.model_copy(update={"kismet_fixture_path": str(KISMET_T2)})
        client_t2 = build_kismet_client(config_t2)
        notifier_t2 = RecordingNotifier()

        processed = _run_poll(
            client_t2, db, config_t2, 1700000300, ruleset, allowlist, notifier_t2
        )
        assert processed == 3

        assert _count(db, "alerts") == 3
        assert notifier_t2.calls == []

        assert _count(db, "devices") == 5

        apple_count = db._conn.execute(
            "SELECT sighting_count FROM devices WHERE mac = ?", (APPLE_MAC,)
        ).fetchone()[0]
        assert apple_count == 2

        pineapple_count = db._conn.execute(
            "SELECT sighting_count FROM devices WHERE mac = ?", (PINEAPPLE_MAC,)
        ).fetchone()[0]
        assert pineapple_count == 2
    finally:
        db.close()


def test_e2e_dedup_window_expiry_re_fires_alert(tmp_path):
    config_t1 = _make_config(tmp_path, KISMET_T1, RULES, ALLOWLIST, dedup_window=3600)
    db, client_t1, ruleset, allowlist, notifier_t1 = _build_pipeline(config_t1)
    try:
        _run_poll(client_t1, db, config_t1, 1700000200, ruleset, allowlist, notifier_t1)

        late_ts = 1700000200 + 3601
        inline_fixture = tmp_path / "kismet_t3_inline.json"
        inline_fixture.write_text(
            json.dumps(
                [
                    {
                        "kismet.device.base.macaddr": PINEAPPLE_MAC,
                        "kismet.device.base.type": "Wi-Fi AP",
                        "kismet.device.base.first_time": 1700000000,
                        "kismet.device.base.last_time": late_ts,
                        "kismet.device.base.signal": {
                            "kismet.common.signal.last_signal": -50
                        },
                        "kismet.device.base.manuf": "Hak5",
                        "kismet.device.base.name": "definitely_not_a_pineapple",
                    }
                ]
            ),
            encoding="utf-8",
        )

        config_t2 = config_t1.model_copy(
            update={"kismet_fixture_path": str(inline_fixture)}
        )
        client_t2 = build_kismet_client(config_t2)
        notifier_t2 = RecordingNotifier()

        _run_poll(client_t2, db, config_t2, late_ts, ruleset, allowlist, notifier_t2)

        new_pineapple_alerts = db._conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE rule_name = ? AND mac = ? AND ts = ?",
            ("pineapple_oui", PINEAPPLE_MAC, late_ts),
        ).fetchone()[0]
        assert new_pineapple_alerts == 1

        assert len(notifier_t2.calls) == 1
        severity, title, _msg = notifier_t2.calls[0]
        assert severity == "high"
        assert title == "talos: HIGH alert"
    finally:
        db.close()


def test_e2e_no_notifications_when_null_notifier(tmp_path):
    config = _make_config(tmp_path, KISMET_T1, RULES, ALLOWLIST)
    db, client, ruleset, allowlist, _ = _build_pipeline(config)

    class _CountingNullNotifier(NullNotifier):
        def __init__(self):
            self.return_values: list[bool] = []

        def send(self, severity, title, message):
            ok = super().send(severity, title, message)
            self.return_values.append(ok)
            return ok

    notifier = _CountingNullNotifier()
    try:
        _run_poll(client, db, config, 1700000200, ruleset, allowlist, notifier)

        assert _count(db, "alerts") == 3
        assert len(notifier.return_values) == 3
        assert all(v is True for v in notifier.return_values)
    finally:
        db.close()


def test_e2e_observation_persist_failure_does_not_block_others(tmp_path):
    config = _make_config(tmp_path, KISMET_T1, RULES, ALLOWLIST)
    db, client, ruleset, allowlist, notifier = _build_pipeline(config)

    db.ensure_location(config.location_id, config.location_label)

    state = {"calls": 0}
    orig = db.upsert_device

    def flaky(*args, **kwargs):
        state["calls"] += 1
        if state["calls"] == 2:
            raise sqlite3.OperationalError("simulated upsert failure")
        return orig(*args, **kwargs)

    try:
        db.upsert_device = flaky  # type: ignore[method-assign]

        processed = _run_poll(client, db, config, 1700000200, ruleset, allowlist, notifier)
        assert processed == 3

        assert _count(db, "devices") == 3

        # The failed observation was the Pineapple (second in the fixture); it must
        # have produced no alerts.
        pineapple_alerts = db._conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE mac = ?", (PINEAPPLE_MAC,)
        ).fetchone()[0]
        assert pineapple_alerts == 0

        # Cambridge is the only device that should still trigger an alert
        # (Apple is allowlisted, randomized client matches no rule).
        assert _alerts(db) == [("new_non_random", CAMBRIDGE_MAC, "low")]
    finally:
        db.upsert_device = orig  # type: ignore[method-assign]
        db.close()


def test_e2e_state_advances_even_with_zero_observations(tmp_path):
    empty_fixture = tmp_path / "kismet_empty.json"
    empty_fixture.write_text("[]", encoding="utf-8")

    config = _make_config(tmp_path, empty_fixture, RULES, ALLOWLIST)
    db, client, ruleset, allowlist, notifier = _build_pipeline(config)
    try:
        db.set_state(STATE_KEY_LAST_POLL, "1000")

        processed = _run_poll(client, db, config, 2000, ruleset, allowlist, notifier)
        assert processed == 0

        assert db.get_state(STATE_KEY_LAST_POLL) == "2000"
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))
