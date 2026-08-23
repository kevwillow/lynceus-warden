"""Two ways the watchful lifecycle can leave a device silently suppressed.

Both are about the same thing: a suppression is the one state in this product
where getting it wrong is not an inconvenience. An entry that fails to archive
is visible and retryable. A device that is allowlisted when nobody asked, or
snoozed by a row the operator cannot see, stops alerting — and the operator has
no way to notice, because the symptom is silence, which is also what "nothing
is out there" looks like.

## S8 — the allowlist file is written before the DB row is claimed

`promote_watchful_to_allowlist` writes the yaml first and archives second. Its
docstring reasons carefully about the yaml write failing ("the DB row is
untouched -- we have not yet started the transaction") and about the row being
concurrently archived (`rowcount == 0`, best-effort yaml rollback). It does not
reason about the third case: the DB write RAISING. A lock timeout, a full disk,
a busy database — the exception propagates, and the yaml entry that was already
written stays.

⇒ The device is permanently allowlisted while its watchful entry is still
active. The operator's UI says they are watching it. They are not being told
about it, ever.

The orders are not symmetric and that is the whole argument:

    yaml first, DB fails   -> device silenced, operator believes it is watched
    DB first, yaml fails   -> entry archived, device still alerts

The second is wrong too, but it is wrong in the direction that keeps
telling the operator things.

## S9 — the duplicate-active check is not enforced anywhere that matters

`create_watchful_from_alert` calls `get_active_watchful_recurrence_by_mac` OUTSIDE
the `with self._lock, self._conn:` block, so two callers can both see None and
both insert. A second active row for one MAC carries its own
`snooze_expires_at`, and the poller's gate resolves by MAC — so a phantom row
can suppress the operator's own HIGH alerts for a device they never snoozed.

⛔ Moving the SELECT inside `self._lock` does NOT fix it. `self._lock` is a
`threading.Lock`, and the poller, the BLE bridge and the web UI are separate
PROCESSES with separate connections. A per-process lock is not a lock. The only
thing all of them share is the database file, so the invariant has to live in
the schema — which also makes it true of rows already in the table, rather than
true of rows inserted through one function.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from lynceus.db import Database

MAC = "aa:bb:cc:dd:ee:ff"


@pytest.fixture()
def db(tmp_path):
    d = Database(str(tmp_path / "lynceus.db"))
    d.ensure_location("default", "Default")
    d.upsert_device(MAC, "wifi", "TestVendor", 0, 1_700_000_000)
    yield d
    d.close()


def _alert(db) -> int:
    return db.add_alert(
        ts=1_700_000_000,
        rule_name="watchlist_mac",
        mac=MAC,
        message="seen",
        severity="high",
    )


def _allowlist_paths(tmp_path) -> tuple[Path, Path]:
    primary = tmp_path / "allowlist.yaml"
    primary.write_text("entries: []\n", encoding="utf-8")
    return primary, tmp_path / "allowlist_ui.yaml"


def _insert_watchful(db, mac: str = MAC) -> int:
    return db.create_watchful_from_alert(
        _alert(db), snooze_duration_seconds=None, now_ts=1_700_000_000
    )


# ==========================================================================
# S8
# ==========================================================================


class _ExplodingLock:
    """Stands in for a DB write that fails after the precondition check.

    Raising from the lock acquisition puts the failure at the same place a
    `database is locked` or a full disk would: after the caller has committed
    to the promote, before the row is actually claimed.
    """

    def __enter__(self):
        raise sqlite3.OperationalError("database is locked")

    def __exit__(self, *exc):
        return False


def test_a_failed_archive_leaves_no_allowlist_entry(db, tmp_path, monkeypatch):
    """THE GUARD. The device must not end up silenced by a promote that failed."""
    from lynceus.allowlist import load_allowlist

    primary, ui_path = _allowlist_paths(tmp_path)
    entry_id = _insert_watchful(db)
    monkeypatch.setattr(db, "_lock", _ExplodingLock())

    with pytest.raises(sqlite3.OperationalError):
        db.promote_watchful_to_allowlist(
            entry_id,
            allowlist_path=ui_path,
            pattern=MAC,
            pattern_type="mac",
            note=None,
            expires_at=None,
            now_ts=5000,
        )

    assert load_allowlist(str(primary)).entries == [], (
        "the promote failed but the device was allowlisted anyway — it is now "
        "permanently suppressed while its watchful entry is still active"
    )


def test_a_failed_archive_leaves_the_entry_active(db, tmp_path, monkeypatch):
    """And the entry must still be there to retry, not half-archived."""
    _primary, ui_path = _allowlist_paths(tmp_path)
    entry_id = _insert_watchful(db)
    monkeypatch.setattr(db, "_lock", _ExplodingLock())

    with pytest.raises(sqlite3.OperationalError):
        db.promote_watchful_to_allowlist(
            entry_id,
            allowlist_path=ui_path,
            pattern=MAC,
            pattern_type="mac",
            note=None,
            expires_at=None,
            now_ts=5000,
        )

    assert db.get_watchful_recurrence(entry_id).archived_at is None


def test_a_failed_allowlist_write_does_not_archive_the_entry(db, tmp_path, monkeypatch):
    """The MIRROR case, and the one the new ordering has to pay for.

    With the DB write first, a yaml failure has to be compensated or the entry
    is archived while the device was never allowlisted. That is the safe
    direction — the device keeps alerting — but "safe" is not "correct", and an
    entry that vanished from the operator's list without doing anything is its
    own bug.
    """
    import lynceus.allowlist as allowlist_mod

    _primary, ui_path = _allowlist_paths(tmp_path)
    entry_id = _insert_watchful(db)

    def boom(*a, **kw):
        raise OSError("read-only file system")

    monkeypatch.setattr(allowlist_mod, "add_ui_entry", boom)

    with pytest.raises(OSError):
        db.promote_watchful_to_allowlist(
            entry_id,
            allowlist_path=ui_path,
            pattern=MAC,
            pattern_type="mac",
            note=None,
            expires_at=None,
            now_ts=5000,
        )

    assert db.get_watchful_recurrence(entry_id).archived_at is None, (
        "the entry was archived but the allowlist write failed — the operator's "
        "watch silently disappeared and nothing was allowlisted"
    )


def test_a_successful_promote_still_does_both(db, tmp_path):
    """The CONTROL. Without it, "never leaves a half state" is satisfied by a
    promote that does nothing at all."""
    from lynceus.allowlist import load_allowlist

    primary, ui_path = _allowlist_paths(tmp_path)
    entry_id = _insert_watchful(db)

    assert (
        db.promote_watchful_to_allowlist(
            entry_id,
            allowlist_path=ui_path,
            pattern=MAC,
            pattern_type="mac",
            note="known device",
            expires_at=None,
            now_ts=5000,
        )
        is True
    )

    assert db.get_watchful_recurrence(entry_id).archived_at == 5000
    entries = load_allowlist(str(primary)).entries
    assert len(entries) == 1
    assert entries[0].pattern == MAC


# ==========================================================================
# S9
# ==========================================================================


def test_the_database_itself_refuses_a_second_active_row(db):
    """THE GUARD, and deliberately at the layer that can actually hold it.

    This goes round `create_watchful_from_alert` entirely and inserts through raw
    SQL, because the point is that the invariant is not a property of one
    Python function. Three processes write this table.
    """
    _insert_watchful(db)
    with pytest.raises(sqlite3.IntegrityError):
        with db._conn:
            db._conn.execute(
                "INSERT INTO watchful_recurrence("
                "mac, created_at, first_seen_at, last_seen_at, sighting_count) "
                "VALUES (?, ?, ?, ?, 1)",
                (MAC, 1, 1, 1),
            )


def test_archived_rows_do_not_block_a_new_watch(db):
    """The PERMIT half. A MAC the operator watched, archived, and wants to watch
    again must be insertable — a plain UNIQUE(mac) would forbid that and break
    the feature while passing the guard above."""
    first = _insert_watchful(db)
    db.dismiss_watchful_recurrence(first, 2_000)
    second = _insert_watchful(db)
    assert second != first


def test_many_archived_rows_for_one_mac_are_allowed(db):
    """Watch/archive is a repeatable cycle; the history must accumulate."""
    for i in range(3):
        entry_id = _insert_watchful(db)
        db.dismiss_watchful_recurrence(entry_id, 2_000 + i)
    rows = db._conn.execute(
        "SELECT COUNT(*) FROM watchful_recurrence WHERE mac = ?", (MAC,)
    ).fetchone()[0]
    assert rows == 3


def test_the_public_helper_still_gives_a_readable_error(db):
    """The schema constraint must not turn the operator-facing double-click into
    a raw sqlite3.IntegrityError traceback in the web UI."""
    _insert_watchful(db)
    with pytest.raises(ValueError, match="already has active watchful entry"):
        _insert_watchful(db)
