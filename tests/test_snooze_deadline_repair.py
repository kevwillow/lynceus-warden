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
