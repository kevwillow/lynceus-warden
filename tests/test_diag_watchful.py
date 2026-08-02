"""Diagnostic dumps for the watchful tracking gate + snooze interaction.

Observation-only: each test exercises the gate via ``poll_once`` (or
direct DB helpers when the gate path is unreachable) and writes a
labeled FIXTURE/EXERCISE/OBSERVED/NOTES section to
``tests/diagnostic_output/<test_name>.log``. The reviewer reads
those logs offline against the design-doc intent.

Gate ordering per ``poller.poll_once``:

    allowlist -> watchful tracking -> rule eval
                                   -> per-rule_type snooze
                                   -> per-alert (watchful) snooze
                                   -> emit

Constants under observation: ``Database.WATCHFUL_RECURRENCE_DEBOUNCE_SECONDS``
(24h sighting gap) and ``Database.WATCHFUL_RECURRENCE_ESCALATION_THRESHOLD``
(sighting_count >= 4 triggers escalation).
"""

from __future__ import annotations

import pytest

from lynceus.allowlist import Allowlist, AllowlistEntry
from lynceus.config import Config
from lynceus.db import Database
from lynceus.kismet import DeviceObservation, KismetClient
from lynceus.notify import RecordingNotifier
from lynceus.poller import poll_once
from lynceus.rules import Rule, Ruleset

pytestmark = pytest.mark.diagnostic


WATCHFUL_MAC = "aa:bb:cc:11:22:33"
NOW_TS = 1_700_000_000


class _StubKismetClient(KismetClient):
    """Hand-built observation source — bypasses fixture parsing.

    The constructor is the KismetClient base initializer with a
    deliberately-unreachable base_url; ``get_devices_since`` returns
    the canned observation list passed in. No network I/O.
    """

    def __init__(self, observations: list[DeviceObservation]) -> None:
        super().__init__(base_url="", api_key=None)
        self._observations = observations

    def get_devices_since(self, since_ts: int, **kwargs) -> list[DeviceObservation]:
        return list(self._observations)

    def health_check(self) -> dict:
        return {"reachable": True, "version": "stub", "error": None}


def _make_obs(mac: str, *, last_seen: int = NOW_TS) -> DeviceObservation:
    return DeviceObservation(
        mac=mac,
        device_type="wifi",
        first_seen=last_seen,
        last_seen=last_seen,
        rssi=-60,
        ssid="diag-ssid",
        oui_vendor="DiagVendor",
        is_randomized=False,
    )


def _insert_watchful(
    db: Database,
    mac: str,
    *,
    created_at: int = 1000,
    first_seen_at: int = 1000,
    last_seen_at: int = 1000,
    sighting_count: int = 1,
    snooze_expires_at: int | None = None,
    escalated_at: int | None = None,
    archived_at: int | None = None,
) -> int:
    cur = db._conn.execute(
        "INSERT INTO watchful_recurrence("
        "mac, created_at, first_seen_at, last_seen_at, sighting_count, "
        "snooze_expires_at, escalated_at, archived_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (
            mac,
            created_at,
            first_seen_at,
            last_seen_at,
            sighting_count,
            snooze_expires_at,
            escalated_at,
            archived_at,
        ),
    )
    db._conn.commit()
    return int(cur.lastrowid)


def _read_watchful(db: Database, entry_id: int) -> dict:
    row = db._conn.execute(
        "SELECT id, mac, created_at, first_seen_at, last_seen_at, "
        "sighting_count, snooze_expires_at, escalated_at, archived_at "
        "FROM watchful_recurrence WHERE id = ?",
        (entry_id,),
    ).fetchone()
    return dict(row) if row is not None else {}


def _count_alerts(db: Database) -> int:
    return int(db._conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])


def _setup(tmp_path):
    db = Database(str(tmp_path / "diag.db"))
    config = Config(
        db_path=str(tmp_path / "diag.db"),
        location_id="diagloc",
        location_label="Diagnostic",
    )
    return db, config


# ---------------------------------------------------------------------------
# Test 1 — allowlisted MAC + watchful row interaction
# ---------------------------------------------------------------------------


def test_diag_watchful_allowlisted_mac(diag, tmp_path):
    db, config = _setup(tmp_path)
    wr_id = _insert_watchful(
        db, WATCHFUL_MAC, sighting_count=2, last_seen_at=NOW_TS - 200_000
    )
    diag.fixture(f"WATCHFUL_RECURRENCE_ESCALATION_THRESHOLD = "
                 f"{Database.WATCHFUL_RECURRENCE_ESCALATION_THRESHOLD}")
    diag.fixture(f"WATCHFUL_RECURRENCE_DEBOUNCE_SECONDS = "
                 f"{Database.WATCHFUL_RECURRENCE_DEBOUNCE_SECONDS}")
    diag.fixture(f"watchful row pre-state: {_read_watchful(db, wr_id)}")

    allowlist = Allowlist(
        entries=[AllowlistEntry(pattern=WATCHFUL_MAC, pattern_type="mac")]
    )
    diag.fixture(f"allowlist: 1 mac entry pattern={WATCHFUL_MAC!r}")

    notifier = RecordingNotifier()
    client = _StubKismetClient([_make_obs(WATCHFUL_MAC)])

    diag.exercise("poll_once(client, db, config, NOW_TS, ruleset=Ruleset(), "
                  "allowlist=<allowlist>, notifier=<recorder>)")
    processed = poll_once(
        client, db, config, NOW_TS,
        ruleset=Ruleset(), allowlist=allowlist, notifier=notifier,
    )

    diag.observed(f"poll_once returned processed={processed}")
    diag.observed(f"watchful row post-state: {_read_watchful(db, wr_id)}")
    diag.observed(f"alerts row count: {_count_alerts(db)}")
    diag.observed(f"notifier.calls: {notifier.calls}")
    diag.notes("Gate order is allowlist -> watchful; allowlist match continues "
               "before watchful is consulted. Expect zero sighting_count "
               "increment AND zero alert emit.")
    db.close()


# ---------------------------------------------------------------------------
# Test 2 — threshold escalation at the documented boundary
# ---------------------------------------------------------------------------


def test_diag_watchful_threshold_escalation(diag, tmp_path):
    db, config = _setup(tmp_path)
    threshold = Database.WATCHFUL_RECURRENCE_ESCALATION_THRESHOLD
    diag.fixture(f"WATCHFUL_RECURRENCE_ESCALATION_THRESHOLD = {threshold}")
    diag.notes("Prompt text mentioned 'threshold 5 / 4 prior sightings'; "
               "actual code constant differs -- this dump shows the live value.")

    # One short of the threshold so the next debounced count crosses it.
    pre_count = threshold - 1
    wr_id = _insert_watchful(
        db, WATCHFUL_MAC,
        sighting_count=pre_count,
        last_seen_at=NOW_TS - 200_000,  # > 86400 s ago so the next obs counts
    )
    diag.fixture(f"watchful row pre-state: {_read_watchful(db, wr_id)}")

    notifier = RecordingNotifier()
    client = _StubKismetClient([_make_obs(WATCHFUL_MAC)])

    diag.exercise("poll_once with empty allowlist and threshold-crossing observation")
    poll_once(
        client, db, config, NOW_TS,
        ruleset=Ruleset(), allowlist=Allowlist(), notifier=notifier,
    )

    post = _read_watchful(db, wr_id)
    diag.observed(f"watchful row post-state: {post}")
    diag.observed(f"sighting_count delta: {post.get('sighting_count') - pre_count}")
    diag.observed(f"escalated_at populated: {post.get('escalated_at') is not None}")
    diag.observed(f"notifier.calls count: {len(notifier.calls)}")
    diag.observed(f"notifier.priority_overrides: {notifier.priority_overrides}")
    diag.observed(f"alerts row count: {_count_alerts(db)}")
    diag.notes("Watchful escalation alert is independent of the original alert "
               "pipeline; emit goes via _emit_watchful_escalation, subject only "
               "to the rule_type snooze on 'watchful_recurrence'.")
    db.close()


# ---------------------------------------------------------------------------
# Test 3 — active rule_type snooze on 'watchful_recurrence'
# ---------------------------------------------------------------------------


def test_diag_watchful_with_active_snooze(diag, tmp_path):
    db, config = _setup(tmp_path)
    threshold = Database.WATCHFUL_RECURRENCE_ESCALATION_THRESHOLD

    # Active rule_type snooze covers the threshold-cross emit window.
    db.add_rule_type_snooze(
        rule_type="watchful_recurrence",
        expires_at=NOW_TS + 3600,
        added_at=NOW_TS - 60,
        note="diag-test",
    )
    diag.fixture(f"rule_type_snoozes: watchful_recurrence expires_at={NOW_TS + 3600}")
    diag.fixture(f"is_rule_type_snoozed('watchful_recurrence', NOW_TS): "
                 f"{db.is_rule_type_snoozed('watchful_recurrence', NOW_TS)}")

    wr_id = _insert_watchful(
        db, WATCHFUL_MAC,
        sighting_count=threshold - 1,
        last_seen_at=NOW_TS - 200_000,
    )
    diag.fixture(f"watchful row pre-state: {_read_watchful(db, wr_id)}")

    notifier = RecordingNotifier()
    client = _StubKismetClient([_make_obs(WATCHFUL_MAC)])

    diag.exercise("poll_once -> threshold cross under active rule_type snooze")
    poll_once(
        client, db, config, NOW_TS,
        ruleset=Ruleset(), allowlist=Allowlist(), notifier=notifier,
    )

    post = _read_watchful(db, wr_id)
    diag.observed(f"watchful row post-state: {post}")
    diag.observed(f"escalated_at populated despite snooze: "
                  f"{post.get('escalated_at') is not None}")
    diag.observed(f"notifier.calls count (escalation suppressed): "
                  f"{len(notifier.calls)}")
    diag.observed(f"notifier.calls payload: {notifier.calls}")
    diag.observed(f"alerts row count: {_count_alerts(db)}")
    diag.notes("Design doc: detection runs while rule_type snooze active; "
               "notification does not. escalated_at SHOULD be set even when "
               "the ntfy push is suppressed.")
    db.close()


# ---------------------------------------------------------------------------
# Test 4 — per-MAC watchful snooze (snooze_expires_at on the row)
# ---------------------------------------------------------------------------


def test_diag_watchful_with_per_alert_snooze(diag, tmp_path):
    db, config = _setup(tmp_path)

    # snooze_expires_at gates the original alert pipeline for this MAC
    # but does NOT gate the escalation pipeline (per OQ-3 / poller.py:342).
    snooze_until = NOW_TS + 7200
    wr_id = _insert_watchful(
        db, WATCHFUL_MAC,
        sighting_count=1,
        last_seen_at=NOW_TS - 200_000,
        snooze_expires_at=snooze_until,
    )
    diag.fixture(f"watchful row pre-state: {_read_watchful(db, wr_id)}")
    diag.fixture(f"per-MAC snooze (snooze_expires_at) until {snooze_until}; "
                 f"now_ts={NOW_TS}")

    # Pair with a rule that WOULD fire on this MAC absent the snooze.
    rule = Rule(
        name="diag-watchful-mac",
        rule_type="watchlist_mac",
        severity="med",
        patterns=[WATCHFUL_MAC],
    )
    ruleset = Ruleset(rules=[rule])
    diag.fixture(f"ruleset: 1 in-memory watchlist_mac rule matching {WATCHFUL_MAC}")

    notifier = RecordingNotifier()
    client = _StubKismetClient([_make_obs(WATCHFUL_MAC)])

    diag.exercise("poll_once with watchful row carrying active snooze_expires_at "
                  "AND a matching in-memory watchlist_mac rule")
    poll_once(
        client, db, config, NOW_TS,
        ruleset=ruleset, allowlist=Allowlist(), notifier=notifier,
    )

    post = _read_watchful(db, wr_id)
    diag.observed(f"watchful row post-state: {post}")
    diag.observed(f"sighting_count incremented: "
                  f"{post.get('sighting_count') != 1}")
    diag.observed(f"notifier.calls (original alert suppressed): "
                  f"count={len(notifier.calls)} payload={notifier.calls}")
    diag.observed(f"alerts row count (original alerts also gated): "
                  f"{_count_alerts(db)}")
    diag.notes("snooze_expires_at suppresses the original alert pipeline only. "
               "sighting_count still counts. If the threshold is later crossed, "
               "the escalation alert fires regardless of this per-MAC snooze.")
    db.close()
