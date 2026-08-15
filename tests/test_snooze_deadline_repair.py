"""A snooze created by a process whose clock was wrong must not outlive its window.

The web UI is a SEPARATE PROCESS from the poller. It has no `ClockAnchor` and no
`clock_trusted` gate — `webui/app.py` computes
`expires_at = int(time.time()) + duration_seconds` and persists that absolute
deadline. So an operator clicking "snooze 24h" while the host clock is wrong
stores a deadline wrong by the same amount.

Measured with the clock +91 days fast: the 24-hour snooze stayed active for
**92 days** after NTP corrected it. They silenced something for a day and it was
silent for three months.

⭐ No schema change is needed, which is the whole point. `add_rule_type_snooze`
already persists BOTH `expires_at` and `added_at`, and its docstring says the
caller computes `expires_at = now_ts + duration_seconds` — so
`expires_at - added_at` IS the operator's intended duration, already stored.

⚠️ Nothing in the poller can PREVENT that write; it happens in another process.
So this is a repair, the same shape as the suppression-anchor self-heal: where
bad state is written somewhere a gate cannot see, the state has to be fixable
afterwards.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lynceus.db import Database  # noqa: E402

NOW = 1_700_000_000
DAY = 86_400
HOUR = 3600


@pytest.fixture()
def db(tmp_path):
    d = Database(str(tmp_path / "s.db"))
    yield d
    d.close()


def _rows(db):
    return {
        r["rule_type"]: (r["added_at"], r["expires_at"])
        for r in db._conn.execute(
            "SELECT rule_type, added_at, expires_at FROM rule_type_snoozes"
        )
    }


def test_a_snooze_written_on_a_fast_clock_is_rebased(db):
    """The measured case: "snooze 24h" clicked while the host clock is +91d."""
    wrong = NOW + 91 * DAY
    db.add_rule_type_snooze("watchlist_hit", expires_at=wrong + DAY, added_at=wrong)

    # Before: the operator's 24 hours has become 92 days.
    assert db.is_rule_type_snoozed("watchlist_hit", NOW + 40 * DAY) is not None

    repaired = db.repair_future_dated_rule_type_snoozes(NOW)
    assert repaired == [("watchlist_hit", DAY)], (
        f"the intended duration was not recovered: {repaired}"
    )

    added, expires = _rows(db)["watchlist_hit"]
    assert added == NOW
    assert expires == NOW + DAY, "the operator's 24 hours was not preserved"

    assert db.is_rule_type_snoozed("watchlist_hit", NOW + HOUR) is not None
    assert db.is_rule_type_snoozed("watchlist_hit", NOW + 25 * HOUR) is None


def test_a_healthy_snooze_is_never_touched(db):
    """⚠️ The 'good thing must still happen' twin, and the sharp edge here.

    A live snooze ALWAYS has `expires_at` in the future — that is what live
    means. Keying the repair on `expires_at` instead of `added_at` would re-base
    every healthy snooze on every poll tick, silently extending each one
    forever. This is the assertion that rejects that implementation.
    """
    db.add_rule_type_snooze("probe_burst", expires_at=NOW + 7 * DAY, added_at=NOW)
    before = _rows(db)

    assert db.repair_future_dated_rule_type_snoozes(NOW) == []
    assert _rows(db) == before, "a healthy snooze was rewritten"

    # And repeatedly, since the poller calls this every tick.
    for _ in range(5):
        db.repair_future_dated_rule_type_snoozes(NOW + 60)
    assert _rows(db) == before


def test_a_past_snooze_is_left_alone(db):
    """An already-expired snooze is the purge's business, not the repair's."""
    db.add_rule_type_snooze(
        "watchlist_hit", expires_at=NOW - DAY, added_at=NOW - 2 * DAY
    )
    before = _rows(db)
    assert db.repair_future_dated_rule_type_snoozes(NOW) == []
    assert _rows(db) == before


def test_an_incoherent_row_is_not_given_a_window_it_never_had(db):
    """`expires_at <= added_at` is not merely future-dated, it is incoherent.

    ⚠️ Inventing a duration for it would grant a silence the operator never
    chose. Leaving it lets the ordinary expiry path retire it.
    """
    wrong = NOW + 91 * DAY
    db.add_rule_type_snooze("watchlist_hit", expires_at=wrong, added_at=wrong)
    assert db.repair_future_dated_rule_type_snoozes(NOW) == []
    added, expires = _rows(db)["watchlist_hit"]
    assert (added, expires) == (wrong, wrong), "an incoherent row was rewritten"


def test_the_repair_runs_before_the_purge(db):
    """⭐ Ordering is load-bearing, not tidiness.

    `cleanup_expired_rule_type_snoozes` deletes `expires_at <= now_ts`. A snooze
    written on a BACKWARD-jumped clock has exactly that shape while still being
    inside the operator's intended window — so purging first would delete the
    row the repair was about to rescue, and a deleted snooze cannot be restored.
    """
    from lynceus import poller as _poller

    src = _poller.__file__
    text = Path(src).read_text()
    repair_at = text.index("repair_future_dated_rule_type_snoozes")
    purge_at = text.index("cleanup_expired_rule_type_snoozes(now_ts)")
    assert repair_at < purge_at, (
        "the purge runs before the repair; it will delete rows the repair "
        "would have rescued"
    )


def test_repair_rejects_a_non_int_clock(db):
    """The repair is only safe against a TRUSTED clock; a caller passing
    something else should fail loudly rather than corrupt healthy rows."""
    with pytest.raises(ValueError):
        db.repair_future_dated_rule_type_snoozes("nope")


# --------------------------------------------------------------------------
# the same defect in the OTHER storage backend
# --------------------------------------------------------------------------


def _ui(tmp_path):
    from lynceus.allowlist import derive_ui_path

    primary = tmp_path / "allowlist.yaml"
    primary.write_text("entries: []\n", encoding="utf-8")
    return primary, derive_ui_path(primary)


def test_a_device_snooze_written_on_a_fast_clock_is_rebased(tmp_path):
    """`webui/app.py::_write_ui_allowlist` has the same
    `expires_at = time.time() + seconds` shape, writing to the UI YAML instead
    of the database.

    ⚠️ Worse than the rule_type case: the operator picked that MAC deliberately.
    Measured at +91 days — a 24-hour snooze on ONE SUSPICIOUS DEVICE suppressed
    it for 92 days.

    ⭐ I missed this in my own sweep because I grepped for
    `db.<method>(now_ts=...)`, which structurally cannot see a write that goes
    to a file. Found by a `gpt-5.6-sol` red-team of the same surface.
    """
    from lynceus.allowlist import (
        AllowlistEntry,
        add_ui_entry,
        load_allowlist,
        repair_future_dated_ui_entries,
    )
    from lynceus.kismet import DeviceObservation

    primary, ui = _ui(tmp_path)
    mac = "aa:bb:cc:dd:ee:01"
    wrong = NOW + 91 * DAY
    add_ui_entry(
        ui,
        AllowlistEntry(
            pattern=mac, pattern_type="mac", added_at=wrong, expires_at=wrong + DAY
        ),
    )

    assert repair_future_dated_ui_entries(ui, NOW) == [(mac, DAY)]

    obs = DeviceObservation(
        mac=mac,
        device_type="wifi",
        first_seen=NOW,
        last_seen=NOW,
        rssi=-40,
        ssid=None,
        oui_vendor=None,
        is_randomized=False,
    )
    al = load_allowlist(str(primary))
    assert al.is_allowed(obs, now_ts=NOW + HOUR) is not None
    assert al.is_allowed(obs, now_ts=NOW + 25 * HOUR) is None, (
        "the device stayed suppressed past the 24 hours the operator chose"
    )


def test_a_permanent_allowlist_entry_is_never_rebased(tmp_path):
    """⚠️ `expires_at is None` is a PERMANENT allowlist entry, not a snooze.

    It has no duration to preserve. Giving it one would silently convert the
    operator's "always ignore my own headphones" into a temporary snooze that
    expires — turning a suppression into an alert storm.
    """
    from lynceus.allowlist import (
        AllowlistEntry,
        _load_ui_entries,
        add_ui_entry,
        repair_future_dated_ui_entries,
    )

    _, ui = _ui(tmp_path)
    add_ui_entry(
        ui,
        AllowlistEntry(
            pattern="aa:bb:cc:dd:ee:99", pattern_type="mac", added_at=NOW + 91 * DAY
        ),
    )
    assert repair_future_dated_ui_entries(ui, NOW) == []
    assert _load_ui_entries(ui)[0].expires_at is None


def test_a_healthy_ui_snooze_is_untouched_and_the_file_is_not_rewritten(tmp_path):
    """⚠️ Two claims, and the second matters on a Pi.

    This runs on EVERY poll tick. Rewriting an unchanged file would churn the
    SD card and break the "an intact file is untouched" guarantee the
    corruption suite asserts.
    """
    from lynceus.allowlist import (
        AllowlistEntry,
        add_ui_entry,
        repair_future_dated_ui_entries,
    )

    _, ui = _ui(tmp_path)
    add_ui_entry(
        ui,
        AllowlistEntry(
            pattern="aa:bb:cc:dd:ee:77",
            pattern_type="mac",
            added_at=NOW,
            expires_at=NOW + 7 * DAY,
        ),
    )
    before_text = ui.read_text()
    before_mtime = ui.stat().st_mtime_ns

    for _ in range(5):
        assert repair_future_dated_ui_entries(ui, NOW + 60) == []

    assert ui.read_text() == before_text
    assert ui.stat().st_mtime_ns == before_mtime, (
        "the UI file was rewritten despite nothing needing repair"
    )


# --------------------------------------------------------------------------
# the THIRD site, and the most harmful
# --------------------------------------------------------------------------


def _watchful(db, mac, duration, at):
    db.upsert_device(
        mac=mac, device_type="wifi", oui_vendor=None, is_randomized=0, now_ts=NOW
    )
    db.insert_sighting(mac=mac, ts=NOW, rssi=-40, ssid=None, location_id="home")
    alert_id = db.add_alert(
        ts=NOW, rule_name="r", mac=mac, message="m", severity="high"
    )
    return db.create_watchful_from_alert(alert_id, duration, at)


def test_a_watchful_snooze_written_on_a_fast_clock_is_rebased(db):
    """⚠️ The most harmful of the three sites.

    `snooze_expires_at` gates the ORIGINAL alert pipeline for that MAC (OQ-3),
    not merely the recurrence escalation. Measured with the web clock +91 days
    fast, on a device the operator had explicitly watchlisted as HIGH severity:

        day  1: high-severity notifications = 0
        day 30: high-severity notifications = 0
        day 60: high-severity notifications = 0

    ⇒ "Watch this device, snooze its alerts for 24 hours" silenced their own
    stalker alert for 92 days.
    """
    db.ensure_location("home", "Home")
    mac = "aa:bb:cc:dd:ee:01"
    _watchful(db, mac, DAY, NOW + 91 * DAY)

    assert db.repair_future_dated_watchful_snoozes(NOW) == [(mac, DAY)]

    row = db._conn.execute(
        "SELECT snooze_expires_at FROM watchful_recurrence"
    ).fetchone()
    assert row["snooze_expires_at"] == NOW + DAY, (
        "the operator's 24 hours was not restored"
    )


def test_a_forever_watchful_snooze_is_never_rebased(db):
    """⚠️ `snooze_expires_at IS NULL` is the deliberate 'forever' option.

    It has no duration to preserve. Inventing one would convert an explicit
    permanent suppression into a snooze that silently expires — turning the
    operator's choice into an alert storm they did not ask for.
    """
    db.ensure_location("home", "Home")
    _watchful(db, "bb:bb:bb:bb:bb:bb", None, NOW + 91 * DAY)
    assert db.repair_future_dated_watchful_snoozes(NOW) == []
    row = db._conn.execute(
        "SELECT snooze_expires_at FROM watchful_recurrence"
    ).fetchone()
    assert row["snooze_expires_at"] is None


def test_a_healthy_watchful_snooze_is_untouched(db):
    """The twin: a live snooze always has a future `snooze_expires_at`, so
    keying on that instead of `created_at` would re-base every healthy entry
    on every poll tick."""
    db.ensure_location("home", "Home")
    _watchful(db, "cc:cc:cc:cc:cc:cc", 7 * DAY, NOW)
    before = db._conn.execute(
        "SELECT created_at, snooze_expires_at FROM watchful_recurrence"
    ).fetchone()
    for _ in range(5):
        assert db.repair_future_dated_watchful_snoozes(NOW + 60) == []
    after = db._conn.execute(
        "SELECT created_at, snooze_expires_at FROM watchful_recurrence"
    ).fetchone()
    assert dict(after) == dict(before)


def test_all_three_repair_sites_are_wired_into_the_poller():
    """⛔ I shipped the first two repairs believing that was the whole class.

    Three storage sites, three separate discoveries, one shape. This asserts
    every repair helper is actually CALLED — a helper nobody invokes is the
    quietest way for the fourth instance to arrive.
    """
    from lynceus import poller as _poller

    text = Path(_poller.__file__).read_text()
    for name in (
        "repair_future_dated_rule_type_snoozes",
        "repair_future_dated_ui_entries",
        "repair_future_dated_watchful_snoozes",
    ):
        assert f"{name}(" in text, f"{name} exists but the poller never calls it"


def test_every_timestamp_column_is_classified(db):
    """⭐ A RATCHET over the whole class, derived from the schema.

    I found the first site, a red-team found two more, and I shipped a fix TWICE
    believing the class was closed. Then a FOURTH turned up that the first
    version of this ratchet could not see, because it only looked at columns
    whose name mentioned expiry — and `watchful_recurrence.last_seen_at` is a
    BASELINE, not a deadline.

    ⇒ So the ratchet now covers EVERY timestamp column and forces each to be
    classified. Enumerating by hand does not work; nor does grepping, which
    found 1 of the 3 known sites because one of them reads
    `expires_at = None if seconds is None else now_ts + seconds` and the `=` is
    followed by `None`.

    ⚠️ REPAIRED means a wrong value there changes a DECISION and the poller
    repairs it. RECORD_ONLY means a wrong value is displayed or audited but
    drives nothing — each one carries the reason, because "it's just a
    timestamp" is exactly the assumption that produced four bugs.

    If a migration adds a column, this fails and names it. Classify it.
    """
    REPAIRED = {
        # repair_future_dated_rule_type_snoozes
        "rule_type_snoozes.expires_at",
        # repair_future_dated_watchful_snoozes
        "watchful_recurrence.snooze_expires_at",
        # repair_future_dated_watchful_baselines -- the 24h recurrence debounce
        "watchful_recurrence.last_seen_at",
    }
    RECORD_ONLY = {
        # Read only for display/audit, or tested for NULL-ness rather than
        # compared to a clock. Verified by grepping for a time comparison on
        # each: only escalated_at appears in one, and that is a display listing.
        "alert_actions.ts": "audit trail; never compared to a clock",
        "alerts.note_updated_at": "display only",
        "alerts.notified_at": "NULL-tested for delivery; value never compared",
        "alerts.ts":
            "written by the gated poller; retention keys on sightings.ts",
        "evidence_snapshots.captured_at":
            "evidence provenance; the prune is gated in the poller",
        "evidence_snapshots.gps_captured_at": "display provenance",
        "heartbeats.notified_at": "bounded by not_after= at every scheduling read (#69)",
        "heartbeats.ts": "bounded by not_after= at every scheduling read (#69)",
        "import_runs.exported_at": "provenance of an external file",
        "import_runs.imported_at": "provenance of a CLI run",
        "rule_type_snoozes.added_at":
            "PROVENANCE marker the repairs key on; must not be clamped",
        "schema_migrations.applied_at": "migration bookkeeping",
        "sightings.ts": "clamped at write time to now_ts (#69)",
        "watchful_recurrence.archived_at": "NULL-tested; value never compared",
        "watchful_recurrence.created_at":
            "PROVENANCE marker the snooze repair keys on; must not be clamped",
        "watchful_recurrence.escalated_at":
            "compared only in list_recent_watchful_escalations, a display listing",
        "watchful_recurrence.first_seen_at": "display only; the debounce uses last_seen_at",
        "watchlist_metadata.created_at": "display only",
        "watchlist_metadata.updated_at": "display only",
    }

    found = set()
    tables = [
        r["name"]
        for r in db._conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        )
    ]
    for table in tables:
        for col in db._conn.execute(f"PRAGMA table_info({table})"):
            name = col["name"]
            if name.endswith("_at") or name == "ts" or name.endswith("_ts"):
                found.add(f"{table}.{name}")

    classified = REPAIRED | set(RECORD_ONLY)
    assert found == classified, (
        f"unclassified timestamp column(s): {sorted(found - classified)}; "
        f"stale entries: {sorted(classified - found)}.\n"
        "Decide whether a wrong value there changes a DECISION (add a repair in "
        "the poller's gated housekeeping) or is RECORD_ONLY (add it above with "
        "the reason). Four bugs in this class came from assuming the latter."
    )


def test_the_yaml_backend_deadline_is_covered_too():
    """The third backend, which no schema query can see.

    ⚠️ Asserted structurally because that is the only way to state it: the field
    exists on the model, and a repair for it exists and is exported.
    """
    from lynceus.allowlist import AllowlistEntry, repair_future_dated_ui_entries

    assert "expires_at" in AllowlistEntry.model_fields, (
        "AllowlistEntry lost its expires_at field; the UI-snooze repair is "
        "now pointing at nothing"
    )
    assert callable(repair_future_dated_ui_entries)


# --------------------------------------------------------------------------
# the FOURTH site: a baseline, not a deadline
# --------------------------------------------------------------------------


def test_a_watchful_baseline_pushed_into_the_future_is_clamped(db):
    """⛔ This one bypasses the gate #69 added.

    `last_seen_at` is the baseline for the 24-hour recurrence debounce, so #69
    gated the POLLER's write to it. `reset_watchful_recurrence` writes the same
    column from the WEB process, which has no anchor.

    Measured — the operator clicks "reset" on an escalated entry while the host
    clock is +91 days fast, then the clock is corrected:

        real sighting at day  4: counted=False
        real sighting at day 30: counted=False
        real sighting at day 91: counted=False
        real sighting at day 92: counted=True

    ⇒ Their intent in clicking reset is "start watching this device fresh". The
    tool did the opposite and stopped watching for three months.
    """
    db.ensure_location("home", "Home")
    mac = "aa:bb:cc:dd:ee:01"
    db.upsert_device(
        mac=mac, device_type="wifi", oui_vendor=None, is_randomized=0, now_ts=NOW
    )
    db.insert_sighting(mac=mac, ts=NOW, rssi=-40, ssid=None, location_id="home")
    alert_id = db.add_alert(
        ts=NOW, rule_name="r", mac=mac, message="m", severity="high"
    )
    entry_id = db.create_watchful_from_alert(alert_id, None, NOW)
    for day in (1, 2, 3):
        db.record_watchful_sighting(entry_id, NOW + day * DAY)
    db.escalate_watchful_recurrence(entry_id, NOW + 3 * DAY)

    db.reset_watchful_recurrence(entry_id, now_ts=NOW + 91 * DAY)
    assert db.repair_future_dated_watchful_baselines(NOW) == [(mac, 91 * DAY)]

    outcome = db.record_watchful_sighting(entry_id, NOW + DAY)
    assert outcome is not None and outcome.counted, (
        "recurrence counting is still frozen; the operator asked to start "
        "watching this device fresh and it stopped watching instead"
    )


def test_the_baseline_repair_does_not_erase_the_snooze_repair_s_evidence(db):
    """⭐ ORDERING, and it is subtle enough to be worth its own test.

    `repair_future_dated_watchful_snoozes` recognises a row written on a jumped
    clock by `created_at > now_ts`. If the baseline repair clamped `created_at`
    too — it is future-dated by the same reset — it would erase that provenance
    and silently disable the other repair.

    ⚠️ A fix that quietly breaks a neighbouring fix is worse than no fix, and
    nothing else in the suite would have noticed.
    """
    db.ensure_location("home", "Home")
    mac = "cc:cc:cc:cc:cc:cc"
    db.upsert_device(
        mac=mac, device_type="wifi", oui_vendor=None, is_randomized=0, now_ts=NOW
    )
    db.insert_sighting(mac=mac, ts=NOW, rssi=-40, ssid=None, location_id="home")
    alert_id = db.add_alert(
        ts=NOW, rule_name="r", mac=mac, message="m", severity="high"
    )
    # created on a jumped clock WITH a finite snooze: both repairs are due.
    db.create_watchful_from_alert(alert_id, DAY, NOW + 91 * DAY)

    db.repair_future_dated_watchful_baselines(NOW)
    row = db._conn.execute(
        "SELECT created_at FROM watchful_recurrence"
    ).fetchone()
    assert row["created_at"] > NOW, (
        "the baseline repair clamped created_at; the snooze repair can no "
        "longer tell this row was written on a jumped clock"
    )
    assert db.repair_future_dated_watchful_snoozes(NOW) == [(mac, DAY)], (
        "the snooze repair no longer fires after the baseline repair ran"
    )


def test_an_honest_baseline_is_untouched(db):
    """The twin: clamping every baseline would reset the debounce constantly."""
    db.ensure_location("home", "Home")
    mac = "dd:dd:dd:dd:dd:dd"
    db.upsert_device(
        mac=mac, device_type="wifi", oui_vendor=None, is_randomized=0, now_ts=NOW
    )
    db.insert_sighting(mac=mac, ts=NOW, rssi=-40, ssid=None, location_id="home")
    alert_id = db.add_alert(
        ts=NOW, rule_name="r", mac=mac, message="m", severity="high"
    )
    db.create_watchful_from_alert(alert_id, None, NOW)
    before = db._conn.execute(
        "SELECT last_seen_at FROM watchful_recurrence"
    ).fetchone()["last_seen_at"]
    for _ in range(5):
        assert db.repair_future_dated_watchful_baselines(NOW + 60) == []
    after = db._conn.execute(
        "SELECT last_seen_at FROM watchful_recurrence"
    ).fetchone()["last_seen_at"]
    assert after == before
