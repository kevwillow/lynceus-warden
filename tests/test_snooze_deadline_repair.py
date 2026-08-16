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
    """Keep the safe ordering — but it protects nothing today, and the reason
    this docstring used to give was FALSE.

    ⛔ It claimed: *"A snooze written on a BACKWARD-jumped clock has exactly that
    shape while still being inside the operator's intended window — so purging
    first would delete the row the repair was about to rescue."*

    Measured across all three reachable shapes, a 24h request:

        correct clock (sanity)   purgeable=False repaired=0 purged=0  ->  24.0h
        forward-jumped (+91d)    purgeable=False repaired=1 purged=0  ->  24.0h
        backward-jumped (-6y)    purgeable=True  repaired=0 purged=1  ->   0.0h

    ⇒ **No row is ever both purgeable and repairable.** "Repairable" means
    `added_at` in the FUTURE; "purgeable" means `expires_at` in the PAST; those
    are disjoint for every coherent write. The ordering cannot change any
    outcome.

    ⚠️ The dangerous part was not the inert assertion — it was that the
    rationale implied the backward jump is HANDLED. It is not: nothing repairs
    it, and the operator gets 0h for a 24h request (Finding 41).
    `test_a_past_snooze_is_left_alone`, three functions above, already states the
    true rule — "an already-expired snooze is the purge's business, not the
    repair's" — so the two docstrings in this file contradicted each other, and
    the backward case survived in the gap between them.

    ⭐ The test is KEPT because the ordering is the safe one and a future repair
    that did key on `expires_at` would need it. It is documented as a
    forward-looking constraint rather than a live protection, which is the
    honest version of what it does.

    ⇒ Found by session `d47d7e0b` by asking what the `added_at > now_ts`
    predicate structurally CANNOT match, rather than by reading the comments —
    which is the only reason a self-consistent, confident, wrong rationale was
    caught at all.
    """
    from lynceus import poller as _poller

    src = _poller.__file__
    text = Path(src).read_text()
    repair_at = text.index("repair_future_dated_rule_type_snoozes")
    purge_at = text.index("cleanup_expired_rule_type_snoozes(now_ts)")
    assert repair_at < purge_at, (
        "the purge now runs before the repair. Harmless for today's repair (the "
        "two predicates are disjoint — see this docstring), but the safe order "
        "is free and a repair keyed on expires_at would need it."
    )


def test_no_snooze_is_both_purgeable_and_repairable(db):
    """The measurement the docstring above now rests on, asserted rather than
    described — so "the ordering is inert" cannot rot into being wrong.

    ⚠️ If a future repair DOES become able to rescue a purgeable row, this fails
    and the ordering above stops being decorative. That is the signal to rewrite
    both docstrings, not to delete this.
    """
    now = 1_700_000_000
    day = 86_400
    shapes = {
        "correct": (now, now + day),
        "forward-jumped": (now + 91 * day, now + 91 * day + day),
        "backward-jumped": (now - 6 * 365 * day, now - 6 * 365 * day + day),
    }
    overlap = []
    seen = 0
    for label, (added_at, expires_at) in shapes.items():
        db.remove_rule_type_snooze("watchlist_mac")
        db.add_rule_type_snooze("watchlist_mac", expires_at=expires_at, added_at=added_at)
        purgeable = expires_at <= now
        repairable = bool(db.repair_future_dated_rule_type_snoozes(now))
        seen += 1
        if purgeable and repairable:
            overlap.append(label)
    # `assert seen >= N`: a shapes dict that emptied would make this vacuous.
    assert seen == len(shapes) >= 3
    assert not overlap, (
        f"{overlap} is now BOTH purgeable and repairable, so repair-before-purge "
        "has become load-bearing. Rewrite test_the_repair_runs_before_the_purge's "
        "docstring — it currently says the ordering cannot change any outcome."
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


# --------------------------------------------------------------------------
# a FIFTH site, in the state KV backend: the heartbeat's staleness check
# --------------------------------------------------------------------------


def _hb(db, tick_anchor, now):
    from lynceus.config import Config
    from lynceus.poller import (
        STATE_KEY_LAST_TICK_ADMITTED,
        STATE_KEY_LAST_TICK_COMPLETED_AT,
        _compose_heartbeat,
    )

    cfg = Config(
        db_path=":memory:",
        rules_path="config/rules.yaml",
        heartbeat_enabled=True,
        poll_interval_seconds=60,
    )
    db.set_state(STATE_KEY_LAST_TICK_ADMITTED, "5")
    db.set_state(STATE_KEY_LAST_TICK_COMPLETED_AT, str(tick_anchor))
    return _compose_heartbeat(db, cfg, now_ts=now)


def test_a_future_tick_anchor_does_not_hide_a_dead_poll_loop(db):
    """⛔ The fifth site, in the `state` KV backend — which no schema query can
    enumerate, so the column ratchet cannot see it either.

    `last_tick_completed_at` drives the heartbeat's staleness clause. A NEGATIVE
    age means the anchor sits in the future, and a bare `age > threshold` reads
    that as "extremely recent". Measured with a +91d anchor and a poll loop that
    had stopped completing ticks for an hour:

        healthy=True, "Still watching."

    ⇒ The one thing this clause exists to catch, disabled for the length of the
    excursion.

    ⚠️ `retention.py` and `evidence.py` both already guard the identical shape
    with `0 <= elapsed`. Three siblings disagreeing about the same impossible
    value is how this survived — the same way two atomic-write helpers
    disagreeing about durability produced #77.
    """
    healthy, message = _hb(db, NOW + 91 * DAY, NOW + 3600)
    assert healthy is False, (
        "a future tick anchor reported the daemon healthy while the poll loop "
        "had not completed a tick for an hour"
    )
    assert "FUTURE" in message


def test_a_genuinely_stale_tick_is_still_reported(db):
    """The twin: the original detection must survive the new branch."""
    healthy, message = _hb(db, NOW, NOW + 3600)
    assert healthy is False
    assert "no poll tick for 3600s" in message


def test_a_recent_tick_is_still_healthy(db):
    """And the other twin: normal operation must not become a fault."""
    healthy, _ = _hb(db, NOW + 3500, NOW + 3600)
    assert healthy is True


# ---------------------------------------------------------------------------
# Finding 41, the BACKWARD half. The repair above keys on `added_at > now_ts`,
# so it is structurally blind to a snooze written while the clock read BEHIND:
# that row arrives with `expires_at` already past, the purge deletes it, and the
# operator's "24 hours" was ZERO with nothing logged above DEBUG.
#
# ⭐ The discriminator is an ORDERING fact, not a clock judgement: a row cannot
# predate its own database's first migration. That is what makes it usable where
# the register recorded post-hoc detection as "believed impossible".
#
# ⛔ These tests pin REPORTING and explicitly pin NON-resurrection. A snooze
# suppresses alerting, so the safe direction is the one it already fails in.
# ---------------------------------------------------------------------------

YEAR = 365 * DAY


def _set_floor(db, ts):
    """Pin the migration floor. Test DBs migrate at real wall-clock time while
    NOW is a 2023 constant, so an uncontrolled floor would decide these cases
    by when the suite happened to run."""
    with db._conn:
        db._conn.execute("UPDATE schema_migrations SET applied_at = ?", (ts,))


def test_an_impossible_snooze_is_reported_but_NOT_resurrected(db):
    """The finding: reported, and still purged. Both halves matter."""
    _set_floor(db, NOW)
    db.add_rule_type_snooze(
        "ble_uuid", expires_at=NOW - 6 * YEAR + DAY, added_at=NOW - 6 * YEAR
    )

    found = db.find_impossible_rule_type_snoozes(NOW)
    # the MIDDLE element is what the poller renders as "it is stamped <X>".
    # Slicing it out let an impl that returned `expires_at` there pass while
    # showing the operator the wrong timestamp -- the diagnostic's whole point.
    assert found == [("ble_uuid", NOW - 6 * YEAR, DAY)], found

    db.cleanup_expired_rule_type_snoozes(NOW)
    assert _rows(db) == {}, "the row was resurrected -- that would start suppressing"
    assert db.is_rule_type_snoozed("ble_uuid", now_ts=NOW) is None


def test_an_ordinary_expired_snooze_is_purged_WITHOUT_being_reported(db):
    """⛔ The control the whole change rests on.

    If this reported, every stale row on every install would produce a warning
    telling the operator their clock is broken. The report would be noise and
    the real case would be lost in it."""
    _set_floor(db, NOW - YEAR)
    db.add_rule_type_snooze("watchlist_hit", expires_at=NOW - DAY, added_at=NOW - 2 * DAY)

    assert db.find_impossible_rule_type_snoozes(NOW) == []
    assert db.cleanup_expired_rule_type_snoozes(NOW) == 1


def test_a_healthy_snooze_is_neither_reported_nor_purged(db):
    _set_floor(db, NOW - YEAR)
    db.add_rule_type_snooze("ble_uuid", expires_at=NOW + DAY, added_at=NOW)

    assert db.find_impossible_rule_type_snoozes(NOW) == []
    assert db.cleanup_expired_rule_type_snoozes(NOW) == 0
    assert db.is_rule_type_snoozed("ble_uuid", now_ts=NOW) is not None


def test_the_reported_duration_is_the_operator_s_intent_not_a_clock_reading(db):
    """`expires_at - added_at` is stamped by ONE clock, so the delta survives
    that clock being wrong. It is what lets the message say "the 24h snooze"."""
    _set_floor(db, NOW)
    db.add_rule_type_snooze(
        "ssid_pattern", expires_at=NOW - 6 * YEAR + 6 * HOUR, added_at=NOW - 6 * YEAR
    )
    assert db.find_impossible_rule_type_snoozes(NOW)[0][2] == 6 * HOUR


def test_the_floor_is_the_MINIMUM_not_a_hardcoded_migration_version(db):
    """Hardcoding the version that created the table has broken five call sites
    across four files here before. A later migration must not raise the floor
    and start flagging rows written before it."""
    _set_floor(db, NOW - YEAR)
    with db._conn:
        db._conn.execute(
            "INSERT INTO schema_migrations(version, applied_at) VALUES (?, ?)",
            (9_999, NOW + YEAR),
        )
    db.add_rule_type_snooze("ble_uuid", expires_at=NOW - DAY, added_at=NOW - 2 * DAY)

    assert db.find_impossible_rule_type_snoozes(NOW) == [], (
        "the floor tracked a LATER migration; every pre-upgrade row is now 'impossible'"
    )


def test_a_broken_detector_cannot_change_what_the_purge_does(db):
    """⛔ This project has shipped a diagnostic that changed its caller's answer
    twice -- once emptying an allowlist, once taking the daemon down at startup.
    The property is pinned on the RETURN VALUE, not on 'nothing propagated'.

    `sqlite3.Connection.execute` is read-only, so the connection itself is
    swapped rather than monkeypatched -- the failure is injected where the
    helper actually reaches, not somewhere convenient."""
    _set_floor(db, NOW - YEAR)
    db.add_rule_type_snooze("watchlist_hit", expires_at=NOW - DAY, added_at=NOW - 2 * DAY)

    class _Broken:
        def execute(self, *a, **k):
            raise MemoryError("detector is broken")

    real = db._conn
    db._conn = _Broken()
    try:
        assert db.find_impossible_rule_type_snoozes(NOW) == []
    finally:
        db._conn = real

    assert db.cleanup_expired_rule_type_snoozes(NOW) == 1


def test_the_impossibility_report_runs_BEFORE_the_purge():
    """The purge destroys the evidence, so order is correctness, not taste.

    ⛔ Parsed, not grepped. The first version of this test used `str.index`, and
    a planted defect that replaced the call with `for ... in []:  # db.find_...`
    SURVIVED it -- the needle still matched, in the comment left behind. A guard
    that matches a spelling passes on any change that keeps the spelling.
    """
    import ast as _ast

    src = (
        Path(__file__).resolve().parents[1] / "src" / "lynceus" / "poller.py"
    ).read_text(encoding="utf-8")

    def call_lines(name):
        return [
            n.lineno
            for n in _ast.walk(_ast.parse(src))
            if isinstance(n, _ast.Call)
            and isinstance(n.func, _ast.Attribute)
            and n.func.attr == name
        ]

    report = call_lines("find_impossible_rule_type_snoozes")
    purge = call_lines("cleanup_expired_rule_type_snoozes")
    assert len(report) == 1, f"expected exactly one report call, found {report}"
    assert len(purge) == 1, f"expected exactly one purge call, found {purge}"
    assert report[0] < purge[0], "the report runs after the purge; it can never fire"


# ---------------------------------------------------------------------------
# Regressions from a cold cross-model read of the MERGED change (#135).
# Every one was reproduced in internal/session1-harnesses/verify_sol_f41.py
# before it was believed, and every one is a defect in my own fix.
# ---------------------------------------------------------------------------


def test_a_snooze_STILL_IN_FORCE_is_never_reported_as_discarded(db):
    """⛔ The report had no expiry condition, so it named rows that were live.

    The daemon told the operator a snooze *"has already passed"* and *"is being
    discarded"* about one they could watch working, and repeated it every poll.
    """
    _set_floor(db, NOW)
    # written before the floor, but its deadline is still in the future
    db.add_rule_type_snooze("ssid_pattern", expires_at=NOW + DAY, added_at=NOW - YEAR)

    assert db.find_impossible_rule_type_snoozes(NOW) == []
    assert db.cleanup_expired_rule_type_snoozes(NOW) == 0
    assert db.is_rule_type_snoozed("ssid_pattern", now_ts=NOW) is not None


def test_a_clock_AHEAD_at_install_does_not_condemn_a_healthy_snooze(db):
    """⛔ The counter-example to "MIN is conservative, so no false positives".

    A database migrated while the clock read AHEAD (bad RTC or timezone at
    provisioning) stamps a floor in the FUTURE, so every legitimate later write
    sits below it. Being a subset of a faulty heuristic is not soundness.
    """
    _set_floor(db, NOW + 10 * YEAR)  # migrations ran on a fast clock
    db.add_rule_type_snooze("ble_uuid", expires_at=NOW + DAY, added_at=NOW)

    assert db.find_impossible_rule_type_snoozes(NOW) == []
    assert db.is_rule_type_snoozed("ble_uuid", now_ts=NOW) is not None


def test_the_report_does_not_repeat_once_the_row_is_gone(db):
    """Nothing marks a row reported, so the bound comes from scoping the report
    to exactly the rows the purge then deletes. Without that it warned forever."""
    _set_floor(db, NOW)
    db.add_rule_type_snooze("ble_uuid", expires_at=NOW - YEAR + DAY, added_at=NOW - YEAR)

    assert len(db.find_impossible_rule_type_snoozes(NOW)) == 1
    db.cleanup_expired_rule_type_snoozes(NOW)
    assert db.find_impossible_rule_type_snoozes(NOW) == []


def test_the_warning_does_not_re_acquire_the_claims_it_had_to_retract():
    """⛔ Every other test here calls the helper directly, so replacing the
    poller's logging block with `pass` left them all green -- a cold read found
    exactly that. This guards the OPERATOR-VISIBLE TEXT instead.

    ⚠️ Labelled honestly: this is a SOURCE check, not proof the line executes.
    The ordering test above covers reachability. What it does prove is that the
    three claims the code cannot establish do not come back -- and they are the
    reason this message had to be rewritten at all:
      * that the clock "was wrong" (the schema stamp shares that clock)
      * that the snooze suppressed NOTHING (it is in force until correction)
      * that a row still IN FORCE is "being discarded"
    """
    src = (
        Path(__file__).resolve().parents[1] / "src" / "lynceus" / "poller.py"
    ).read_text(encoding="utf-8")
    block = src[src.index("find_impossible_rule_type_snoozes") :][:2000].lower()

    assert "disagree" in block, "the message no longer frames this as a disagreement"
    assert "without having suppressed anything" not in block, (
        "the message claims the snooze suppressed nothing; it may have been in "
        "force for the entire period before the clock was corrected"
    )
    assert "so that reading was wrong" not in block, (
        "the message asserts which clock was wrong; the schema stamp comes from "
        "the same clock, so the code cannot establish that"
    )


def test_the_helper_is_called_with_the_polls_own_now_ts():
    """The expiry scope is only real if the caller passes the tick's clock."""
    import ast as _ast

    src = (
        Path(__file__).resolve().parents[1] / "src" / "lynceus" / "poller.py"
    ).read_text(encoding="utf-8")
    calls = [
        n
        for n in _ast.walk(_ast.parse(src))
        if isinstance(n, _ast.Call)
        and isinstance(n.func, _ast.Attribute)
        and n.func.attr == "find_impossible_rule_type_snoozes"
    ]
    assert len(calls) == 1, f"expected one call, found {len(calls)}"
    assert [a.id for a in calls[0].args if isinstance(a, _ast.Name)] == ["now_ts"], (
        "the report is not scoped to this tick's clock, so it can name rows the "
        "purge will not touch"
    )


def test_the_discriminator_is_added_at_NOT_expires_at(db):
    """⛔ Without this case, an impl keying on `expires_at < floor` passes the
    ENTIRE suite -- and it would flag every expired snooze ever written, which
    is the exact log-flood the scoping was added to prevent.

    The split only shows up on a row whose `added_at` is below the floor while
    its `expires_at` is ABOVE it, and which has nonetheless expired by now.
    Found by an adversarial read of these tests, not by the tests themselves.
    """
    floor = NOW
    _set_floor(db, floor)
    db.add_rule_type_snooze("ble_uuid", expires_at=floor + DAY, added_at=floor - 1)

    now = floor + 2 * DAY  # the row has expired by now, but expires_at > floor
    found = db.find_impossible_rule_type_snoozes(now)

    assert found == [("ble_uuid", floor - 1, DAY + 1)], (
        "an impl keying on expires_at rather than added_at reports nothing here, "
        "and reports every ordinary expired snooze in production"
    )
