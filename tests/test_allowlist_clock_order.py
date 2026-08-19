"""The YAML deadline backend's BACKWARD reporter, and the limits of its claim.

⭐ **Finding 56 recorded this backend as unreachable and it was wrong about the
conclusion, not the evidence.** Its text: the UI allowlist *"has no
``schema_migrations`` row to compare against, so the ordering discriminator does
not exist for it."* True as stated. But `schema_migrations` was never the
ordering fact — it was one *instance* of one. This file's list order **is** its
append order, so position and timestamp are two independent records of the same
event, and they can contradict each other without consulting any clock.

⛔ **Every test here is a CONJUNCTION test.** "Report the bad row" alone is
satisfied by `return everything`; "stay silent on the good row" alone is
satisfied by `return []`. This project has shipped both halves separately
before (#135 → #139), so each population below has its opposite in the file.

⚠️ **Two things this suite pins as SILENT that are not successes**: the
all-behind-clock install (no earlier row to contradict) and the repair-induced
residual. They are silent by construction, they are published as blind spots in
`find_impossible_ui_entries`, and pinning them here is what stops someone
reading a green run as "this backend is covered."
"""

from __future__ import annotations

from pathlib import Path

import pytest

from lynceus.allowlist import (
    UI_ORDER_TOLERANCE_SECONDS,
    AllowlistEntry,
    add_ui_entry,
    find_impossible_ui_entries,
    repair_future_dated_ui_entries,
)
from lynceus.webui.clock import CLOCK_BEHIND_TOLERANCE_SECONDS

DAY = 86400
YEAR = 365 * DAY
NOW = 1_700_000_000
ASKED = 24 * 3600


def _mac(n: int) -> str:
    return f"aa:bb:cc:dd:ee:{n:02x}"


def _write(ui: Path, mac: str, clock: int, seconds: int | None = ASKED) -> None:
    """Exactly what `webui.app._write_ui_allowlist` persists, at any clock."""
    add_ui_entry(
        ui,
        AllowlistEntry(
            pattern=mac,
            pattern_type="mac",
            note=f"snoozed 24h via webui at {clock}",
            added_at=clock,
            expires_at=None if seconds is None else clock + seconds,
        ),
    )


@pytest.fixture()
def ui(tmp_path: Path) -> Path:
    return tmp_path / "allowlist_ui.yaml"


# --------------------------------------------------------------------------
# The population this exists for
# --------------------------------------------------------------------------
def test_a_snooze_written_after_a_backward_jump_is_reported(ui):
    """The defect, end to end: 24h asked for, 0h delivered, previously silent."""
    _write(ui, _mac(1), NOW)
    _write(ui, _mac(2), NOW - 6 * YEAR)

    found = find_impossible_ui_entries(ui, NOW + DAY)

    assert len(found) == 1, found
    row = found[0]
    assert row.pattern == _mac(2)
    # The DURATION survives the wrong clock because both stamps moved together.
    # If this ever reads 0 or a negative number the operator is being told they
    # asked for nothing.
    assert row.duration_seconds == ASKED
    assert row.behind_by_seconds == 6 * YEAR
    # ⛔ The evidence must name the row it disagrees WITH. A message that says
    # "your clock is wrong" without naming what it is wrong relative to is the
    # kind of warning that gets dismissed.
    assert row.preceded_by_pattern == _mac(1)
    assert row.preceded_by_added_at == NOW


def test_every_write_after_the_jump_is_reported_not_just_the_first(ui):
    """The running maximum must not advance onto a violating row.

    Three clicks after one backward jump are three short suppressions, and the
    operator owns all three. Advancing the maximum onto the first would report
    it and silently clear the other two.
    """
    _write(ui, _mac(1), NOW)
    for i in (2, 3, 4):
        _write(ui, _mac(i), NOW - 30 * DAY + i)

    found = find_impossible_ui_entries(ui, NOW + DAY)

    assert [r.pattern for r in found] == [_mac(2), _mac(3), _mac(4)], found


# --------------------------------------------------------------------------
# The other half of every conjunction
# --------------------------------------------------------------------------
def test_a_healthy_file_reports_nothing(ui):
    for i in range(4):
        _write(ui, _mac(i), NOW + i * DAY)
    assert find_impossible_ui_entries(ui, NOW + 10 * DAY) == []


def test_a_single_entry_reports_nothing(ui):
    """One row has nothing to contradict. Guards against a reporter that keys
    on the reading clock instead of on the file."""
    _write(ui, _mac(1), NOW - 6 * YEAR)
    assert find_impossible_ui_entries(ui, NOW) == []


def test_an_absent_file_reports_nothing(ui):
    assert not ui.exists()
    assert find_impossible_ui_entries(ui, NOW) == []


def test_a_suppression_still_in_force_is_not_reported(ui):
    """⛔ The `expires_at <= now_ts` half, and it is REQUIRED.

    A snooze written on a behind clock still works if its duration outruns the
    gap -- the operator gets less than they asked for, but they are getting
    something. #139 had to add exactly this scope to the DB sibling after #135
    shipped without it and told operators a working snooze had failed.
    """
    _write(ui, _mac(1), NOW)
    _write(ui, _mac(2), NOW - 3600, seconds=24 * 3600)  # 1h behind, 24h asked

    # Two hours in: the deadline is 22h away and the device IS silenced.
    assert find_impossible_ui_entries(ui, NOW + 2 * 3600) == []
    # ...and once that deadline really has passed, it is reported.
    assert len(find_impossible_ui_entries(ui, NOW + 30 * 3600)) == 1


def test_a_permanent_entry_is_never_reported(ui):
    """⚠️ Unlike the SQLite sibling -- where `NULL <= x` is never true and the
    equivalent guard is redundant -- this one is load-bearing: in Python the
    comparison raises, and the function's blanket `except` would turn that into
    a silently empty report for the WHOLE file."""
    _write(ui, _mac(1), NOW)
    _write(ui, _mac(2), NOW - 6 * YEAR, seconds=None)  # permanent

    assert find_impossible_ui_entries(ui, NOW + DAY) == []

    # The control: the same out-of-order entry WITH a deadline is reported, so
    # the silence above is the permanence and not a broken comparison.
    _write(ui, _mac(3), NOW - 6 * YEAR)
    assert [r.pattern for r in find_impossible_ui_entries(ui, NOW + DAY)] == [_mac(3)]


def test_an_entry_with_no_added_at_neither_reports_nor_breaks_the_chain(ui):
    """Operator hand-edits carry no provenance. Skipping them must not reset
    the running maximum, or a hand-edited row between two UI writes would hide
    a real jump."""
    _write(ui, _mac(1), NOW)
    add_ui_entry(ui, AllowlistEntry(pattern=_mac(7), pattern_type="mac"))
    _write(ui, _mac(2), NOW - 30 * DAY)

    assert [r.pattern for r in find_impossible_ui_entries(ui, NOW + DAY)] == [_mac(2)]


# --------------------------------------------------------------------------
# Tolerance
# --------------------------------------------------------------------------
def test_the_clock_tolerances_stay_equal():
    """⛔ Not imported: `webui` imports `allowlist`, so importing back would
    invert the layering for one integer. Two components disagreeing about what
    counts as a clock problem is how an operator gets told the clock is fine on
    one page and broken on another -- `webui/clock.py` makes the same trade
    against the poller's constant and pins it the same way."""
    assert UI_ORDER_TOLERANCE_SECONDS == CLOCK_BEHIND_TOLERANCE_SECONDS


@pytest.mark.parametrize("slip", [1, 60, UI_ORDER_TOLERANCE_SECONDS - 1])
def test_an_ordinary_ntp_slew_is_not_reported(ui, slip):
    _write(ui, _mac(1), NOW)
    _write(ui, _mac(2), NOW - slip)
    assert find_impossible_ui_entries(ui, NOW + DAY) == []


def test_a_jump_past_the_tolerance_is_reported(ui):
    """The other half: without this, raising the tolerance to a year would
    still pass the test above."""
    _write(ui, _mac(1), NOW)
    _write(ui, _mac(2), NOW - (UI_ORDER_TOLERANCE_SECONDS + 100))
    assert len(find_impossible_ui_entries(ui, NOW + DAY)) == 1


# --------------------------------------------------------------------------
# Interaction with the FORWARD repair -- measured, both directions
# --------------------------------------------------------------------------
def test_the_forward_repair_does_not_manufacture_a_report(ui):
    """⭐ `repair_future_dated_ui_entries` rewrites `added_at` in place without
    moving the row, so a forward-dated entry repaired AFTER a later healthy
    write leaves the file genuinely out of order. Measured: a 10-second
    inversion on two perfectly good suppressions. The `expires_at` scope is
    what excludes them -- both are still live."""
    _write(ui, _mac(1), NOW + 91 * DAY)  # clock reads 91 days fast
    _write(ui, _mac(2), NOW + 10)  # clock corrected, healthy click
    repaired = repair_future_dated_ui_entries(ui, NOW + 20)

    assert len(repaired) == 1, "precondition: the repair must have fired"
    assert find_impossible_ui_entries(ui, NOW + 30) == []


def test_the_repair_residual_false_positive_is_real_and_pinned(ui):
    """⚠️ **This test asserts a FALSE POSITIVE happens.** It is not an
    aspiration and it must not be "fixed" by loosening the reporter.

    If the poller stays down past the later healthy entry's own deadline, the
    `expires_at` scope no longer excludes it and a healthy row is reported. The
    direction is the recoverable one -- the operator is told to check a clock
    that is fine, about a suppression that already worked -- and it is the same
    trade `webui/clock.py` documents for its own false positives.

    Pinned so that if someone closes it, this test fails and they have to say
    so deliberately rather than discover it in the field.
    """
    _write(ui, _mac(1), NOW + 91 * DAY)
    _write(ui, _mac(2), NOW + 10)
    repaired = repair_future_dated_ui_entries(ui, NOW + 2 * DAY)

    assert len(repaired) == 1, "precondition: the repair must have fired"
    found = find_impossible_ui_entries(ui, NOW + 2 * DAY)
    assert len(found) == 1 and found[0].pattern == _mac(2), (
        "the published residual changed; re-measure it before editing this test"
    )


# --------------------------------------------------------------------------
# The blind spot, pinned as a blind spot
# --------------------------------------------------------------------------
def test_an_install_whose_every_write_shares_one_behind_clock_is_blind(ui):
    """⛔ Silent BY CONSTRUCTION -- there is no earlier-stamped row to
    contradict. This is Finding 41's RTC-less-Pi population, and it is exactly
    the population `MIN(schema_migrations.applied_at)` cannot see either.

    Pinned so a green suite is never read as "this backend is covered."
    """
    for i in range(4):
        _write(ui, _mac(i), NOW - 6 * YEAR + i * 60)

    assert find_impossible_ui_entries(ui, NOW) == []


# --------------------------------------------------------------------------
# Never raises
# --------------------------------------------------------------------------
def test_a_corrupt_file_reports_nothing_and_does_not_raise(ui):
    """⛔ A diagnostic that can change what its caller does is the defect this
    project has shipped twice -- once from inside this very module's loader."""
    ui.write_text("entries: [[[not valid\n")
    assert find_impossible_ui_entries(ui, NOW) == []


def test_a_non_int_now_ts_reports_nothing_and_does_not_raise(ui):
    _write(ui, _mac(1), NOW)
    _write(ui, _mac(2), NOW - 6 * YEAR)
    assert find_impossible_ui_entries(ui, "not a timestamp") == []  # type: ignore[arg-type]
    assert find_impossible_ui_entries(ui, True) == []  # bool is an int subclass


# --------------------------------------------------------------------------
# The surface. A reporter nobody can see is not a report.
# --------------------------------------------------------------------------
def _app(tmp_path: Path):
    """A real /allowlist page over a real allowlist pair."""
    from lynceus.config import Config
    from lynceus.db import Database
    from lynceus.webui.app import create_app

    primary = tmp_path / "allowlist.yaml"
    primary.write_text("entries: []\n")
    db = Database(str(tmp_path / "lynceus.db"))
    app = create_app(Config(db_path=str(tmp_path / "lynceus.db"),
                            allowlist_path=str(primary)), db)
    return app, db, tmp_path / "allowlist_ui.yaml"


def test_the_allowlist_page_shows_the_disagreement(tmp_path, monkeypatch):
    from starlette.testclient import TestClient

    app, db, ui = _app(tmp_path)
    _write(ui, _mac(1), NOW)
    _write(ui, _mac(2), NOW - 30 * DAY)
    monkeypatch.setattr("lynceus.webui.app.time.time", lambda: float(NOW + DAY))
    try:
        with TestClient(app) as c:
            body = c.get("/allowlist").text
    finally:
        db.close()

    assert "disagree" in body, "the operator is told nothing"
    assert _mac(2) in body
    # ⛔ It must name the row it disagrees WITH, not just the suspect. A banner
    # that says "your clock is wrong" and nothing else is the warning shape this
    # project has already had dismissed twice.
    assert _mac(1) in body
    # ⛔ And it must NOT assert which side is wrong -- the check cannot know.
    assert "clock is wrong" not in body.lower()


def test_the_allowlist_page_is_silent_on_a_healthy_file(tmp_path, monkeypatch):
    """The other half. Without it, always rendering the banner passes above."""
    from starlette.testclient import TestClient

    app, db, ui = _app(tmp_path)
    _write(ui, _mac(1), NOW)
    _write(ui, _mac(2), NOW + DAY)
    monkeypatch.setattr("lynceus.webui.app.time.time", lambda: float(NOW + 10 * DAY))
    try:
        with TestClient(app) as c:
            body = c.get("/allowlist").text
    finally:
        db.close()

    assert "disagree" not in body


def test_a_filter_cannot_hide_the_disagreement(tmp_path, monkeypatch):
    """⛔ The evidence is an ORDERING fact between TWO entries. Deriving the
    banner from the filtered rows would let an operator searching for one MAC
    be told their clock was fine, because the row it contradicts was filtered
    out from under it."""
    from starlette.testclient import TestClient

    app, db, ui = _app(tmp_path)
    _write(ui, _mac(1), NOW)
    _write(ui, _mac(2), NOW - 30 * DAY)
    monkeypatch.setattr("lynceus.webui.app.time.time", lambda: float(NOW + DAY))
    try:
        with TestClient(app) as c:
            body = c.get(f"/allowlist?q={_mac(2)}").text
    finally:
        db.close()

    assert "disagree" in body
    assert _mac(1) in body, "the contradicted row must still be named as evidence"


def test_an_unconfigured_allowlist_path_does_not_break_the_page(tmp_path):
    """The `not configured` branch has to bind the name too, or /allowlist
    500s for every legacy install with no allowlist_path."""
    from starlette.testclient import TestClient

    from lynceus.config import Config
    from lynceus.db import Database
    from lynceus.webui.app import create_app

    db = Database(str(tmp_path / "lynceus.db"))
    app = create_app(Config(db_path=str(tmp_path / "lynceus.db")), db)
    try:
        with TestClient(app) as c:
            r = c.get("/allowlist")
    finally:
        db.close()
    assert r.status_code == 200
    assert "disagree" not in r.text
