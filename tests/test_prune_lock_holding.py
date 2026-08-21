"""A retention prune must not hold SQLite's write lock for the whole backlog.

⛔ **The defect this exists to stop is not a slow prune. It is a LOST WRITE in
another process.** The poller, the web UI and the ble-bridge hold separate
connections, so no Python lock serialises them — only SQLite does, by making the
second writer wait ``busy_timeout`` (5000 ms) and then giving up. Measured, with
the product's own prune running while a second OS process did ordinary
``add_alert`` writes:

===================  =========  ==================  =============
prune                deleted    write lock held     writes LOST
===================  =========  ==================  =============
CONTROL (deletes 0)  0          0.00 s              0
evidence 160k rows   80,000     3.50 s              0
evidence 240k rows   120,000    **5.67 s**          **1**
evidence 400k rows   200,000    **16.38 s**         **3**
sightings 4M rows    2,000,000  **7.23 s**          **1**
===================  =========  ==================  =============

⚠️ That is on NVMe SSD; the Pi's SD storage crosses sooner by an unmeasured
factor. ⚠️ And ``evidence_retention_days`` **defaults to 90 and is on**, so this
needs no operator opt-in — though the trigger is a step change (the first prune
after lowering the retention, or on a long-accumulated install) rather than
steady state, where a daily prune deletes a day.

⭐ **What the victim does with the loss is why it matters.** ``poll_once``
catches, logs, and HOLDS the Kismet watermark so the tick is retried.
``bridges/ble.py``'s ``_flush`` clears its buffer up front and then does
``except Exception: warning; continue`` — no watermark, no retry, no counter, no
health surface. So the default daily maintenance job could silently drop Find My
tracker observations for the length of the prune.

These tests pin the mechanism that prevents it: **many bounded transactions, not
one unbounded one.** The durations above are a measurement and cannot live in a
suite; the transaction structure that produces them can, and does.
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

import pytest

from lynceus.db import Database
from lynceus.evidence import prune_old_evidence
from lynceus.retention import prune_old_sightings

NOW = 1_800_000_000
DAY = 86_400


@pytest.fixture
def db(tmp_path):
    database = Database(str(tmp_path / "p.db"))
    database.ensure_location("loc", "loc")
    yield database
    database.close()


def _fill_sightings(db, n_old, n_new):
    with db.transaction() as conn:
        conn.execute(
            "INSERT INTO devices (mac, device_type, first_seen, last_seen, "
            "sighting_count, is_randomized) VALUES ('aa:bb:cc:dd:ee:ff','wifi',?,?,1,0)",
            (NOW - 500 * DAY, NOW),
        )
        conn.executemany(
            "INSERT INTO sightings (mac, ts, location_id) VALUES ('aa:bb:cc:dd:ee:ff',?,'loc')",
            [(NOW - 200 * DAY,)] * n_old + [(NOW - 1 * DAY,)] * n_new,
        )


class _CountingTransactions:
    """Records how many separate transactions a call opens.

    ⭐ This is the assertion that discriminates, and it cannot flake. Timing the
    prune would: on a small fixture the batched and unbounded forms both finish
    in milliseconds, so a duration bound would pass for BOTH and the guard would
    be decorative. The transaction COUNT is exactly 1 for the defect and exactly
    ceil(rows/batch)+/-1 for the fix, on any hardware, at any load.
    """

    def __init__(self, db):
        self.db, self.count, self._real = db, 0, type(db).transaction

    def __enter__(self):
        outer = self

        def counting(self_db):
            outer.count += 1
            return outer._real(self_db)

        type(self.db).transaction = counting
        return self

    def __exit__(self, *exc):
        type(self.db).transaction = self._real
        return False


def test_a_sightings_prune_uses_many_bounded_transactions_not_one(db):
    _fill_sightings(db, n_old=2500, n_new=40)
    with _CountingTransactions(db) as spy:
        deleted, oldest = prune_old_sightings(db, 100, now_ts=NOW)

    assert deleted == 2500
    assert spy.count >= 3, (
        f"the prune ran in {spy.count} transaction(s); a single unbounded DELETE "
        f"holds the write lock for the whole backlog and loses another process's "
        f"concurrent write. Expected roughly 2500/{Database.DELETE_BATCH_ROWS} + 1."
    )
    # ⭐ The other direction: batching must not become an excuse to leave rows
    # behind, nor to delete rows the cutoff protects.
    assert db._conn.execute("SELECT COUNT(*) FROM sightings").fetchone()[0] == 40
    assert oldest == NOW - 1 * DAY


def test_an_evidence_prune_uses_many_bounded_transactions_not_one(db):
    alert_id = db.add_alert(
        ts=NOW, rule_name="r", mac=None, message="m", severity="low"
    )
    with db.transaction() as conn:
        conn.executemany(
            "INSERT INTO evidence_snapshots (alert_id, mac, captured_at, "
            "kismet_record_json, do_not_publish) VALUES (?, 'aa:bb:cc:dd:ee:ff', ?, '{}', 0)",
            [(alert_id, NOW - 200 * DAY)] * 2500 + [(alert_id, NOW - 1 * DAY)] * 40,
        )
    with _CountingTransactions(db) as spy:
        deleted, _ = prune_old_evidence(db, 100, now_ts=NOW)

    assert deleted == 2500
    assert spy.count >= 3, f"the prune ran in {spy.count} transaction(s), not batches"
    assert (
        db._conn.execute("SELECT COUNT(*) FROM evidence_snapshots").fetchone()[0] == 40
    )


def test_no_batch_ever_deletes_more_than_the_bound(db):
    """The bound is the whole point: one batch is the longest the lock is held."""
    # ⛔ Must exceed DELETE_BATCH_ROWS or this passes trivially: one batch of
    # 350 is "under the bound" while proving nothing about batching at all.
    n_old = Database.DELETE_BATCH_ROWS * 2 + 137
    _fill_sightings(db, n_old=n_old, n_new=5)
    sizes = []
    real = Database.transaction

    class _Recording:
        def __init__(self, cm):
            self.cm = cm

        def __enter__(self):
            self.conn = self.cm.__enter__()
            self.before = self.conn.execute(
                "SELECT COUNT(*) FROM sightings"
            ).fetchone()[0]
            return self.conn

        def __exit__(self, *exc):
            sizes.append(
                self.before
                - self.conn.execute("SELECT COUNT(*) FROM sightings").fetchone()[0]
            )
            return self.cm.__exit__(*exc)

    Database.transaction = lambda self_db: _Recording(real(self_db))
    try:
        deleted, _ = prune_old_sightings(db, 100, now_ts=NOW)
    finally:
        Database.transaction = real

    assert deleted == n_old
    assert sizes, "no transaction was observed at all; the recorder is broken"
    assert len(sizes) >= 3, f"only {len(sizes)} transaction(s); batching did not happen"
    # ⚠️ Derived from the constant, never transcribed — a bump to
    # DELETE_BATCH_ROWS must not silently leave this guard testing the old value.
    assert max(sizes) <= Database.DELETE_BATCH_ROWS, (
        f"a batch deleted {max(sizes)} rows, over the {Database.DELETE_BATCH_ROWS} bound"
    )


def test_the_batch_bound_is_honoured_for_an_explicit_size(db):
    _fill_sightings(db, n_old=250, n_new=3)
    result = db.delete_in_batches(
        "sightings", "ts < ?", (NOW - 100 * DAY,), batch_size=10
    )
    assert result.deleted == 250
    assert result.batches == 26, f"expected 25 full + 1 short, got {result.batches}"
    assert result.complete is True


def test_hitting_the_batch_bound_is_LOGGED_not_swallowed(db, monkeypatch, caplog):
    """⛔ The fail-closed direction. A maintenance job that quietly stops early
    and reports success turns the retention promise into a lie that nothing
    surfaces. If the loop bails, it must say so and say how much is left."""
    _fill_sightings(db, n_old=50, n_new=2)
    monkeypatch.setattr(Database, "_DELETE_MAX_BATCHES", 2)
    with caplog.at_level(logging.WARNING):
        result = db.delete_in_batches(
            "sightings", "ts < ?", (NOW - 100 * DAY,), batch_size=5
        )

    assert (result.deleted, result.batches) == (10, 2)
    # ⛔ The field that stops a caller reporting success it did not achieve.
    assert result.complete is False
    assert db._conn.execute("SELECT COUNT(*) FROM sightings").fetchone()[0] == 42
    warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("hit its 2-batch bound" in m for m in warnings), warnings
    assert any("40 still match" in m for m in warnings), (
        f"the warning must name what is LEFT, not just that it stopped: {warnings}"
    )


def test_a_table_name_that_is_not_an_identifier_is_refused(db):
    """`table` and `where` are interpolated. The docstring says callers must pass
    literals; this makes the obvious injection shape impossible rather than
    merely discouraged."""
    with pytest.raises(ValueError, match="bare identifier"):
        db.delete_in_batches("sightings; DROP TABLE alerts", "1=1", ())
    with pytest.raises(ValueError, match="batch_size"):
        db.delete_in_batches("sightings", "1=1", (), batch_size=0)


def test_the_pruner_stands_aside_between_batches(db):
    """⛔ Batching alone is NOT the property, and this is the test that says so.

    Measured on a 400,000-row prune BEFORE this yield existed: 401 batches, max
    batch 56.77ms — and **100% of the prune's wall-clock was inside a held
    lock**, because the loop reacquired instantly. SQLite offers a waiting
    writer no fairness, so a second process still waited 1.57s. ⚠️ Shrinking the
    batch makes that worse (more reacquisitions), which is exactly the fix a
    reasonable person reaches for first.

    So this measures the GAPS, not the durations: the wall-clock a prune spends
    with the write lock released and available to another process.
    """
    _fill_sightings(db, n_old=Database.DELETE_BATCH_ROWS * 4, n_new=3)
    spans = []
    real = Database.transaction

    class _Timed:
        def __init__(self, cm):
            self.cm = cm

        def __enter__(self):
            self.t0 = time.monotonic()
            return self.cm.__enter__()

        def __exit__(self, *exc):
            r = self.cm.__exit__(*exc)
            spans.append((self.t0, time.monotonic()))
            return r

    Database.transaction = lambda self_db: _Timed(real(self_db))
    try:
        prune_old_sightings(db, 100, now_ts=NOW)
    finally:
        Database.transaction = real

    assert len(spans) >= 4, f"only {len(spans)} transactions; batching did not happen"
    held = sum(end - start for start, end in spans)
    gaps = sum(
        max(0.0, spans[i + 1][0] - spans[i][1]) for i in range(len(spans) - 1)
    )
    assert gaps >= held * 0.3, (
        f"the pruner held the lock {held * 1000:.0f}ms and left only "
        f"{gaps * 1000:.0f}ms of gap. It is reacquiring immediately, so a waiting "
        f"process in another OS process can be starved out past busy_timeout even "
        f"though every individual batch is short."
    )


def test_an_incomplete_prune_WARNS_and_does_not_only_say_Pruned(db, monkeypatch, caplog):
    """⭐ The caller's half of the honesty. `delete_in_batches` warns, but the
    line an operator actually reads is the prune's own INFO "Pruned N ...",
    which reads as "the retention policy was applied". Both prunes must say
    plainly when that is false."""
    _fill_sightings(db, n_old=50, n_new=2)
    monkeypatch.setattr(Database, "_DELETE_MAX_BATCHES", 1)
    monkeypatch.setattr(Database, "DELETE_BATCH_ROWS", 5)
    with caplog.at_level(logging.INFO):
        deleted, _ = prune_old_sightings(db, 100, now_ts=NOW)

    assert deleted == 5
    msgs = [r.getMessage() for r in caplog.records]
    assert any("Pruned 5 sightings" in m for m in msgs), msgs
    warns = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("did NOT finish" in m and "REMAIN" in m for m in warns), (
        f"an operator reading only the INFO line would believe the policy was "
        f"applied: {msgs}"
    )


def test_every_table_delete_in_batches_is_used_on_is_a_plain_rowid_table():
    """⛔ The helper's contract, enforced against the schema rather than trusted.

    `delete_in_batches` picks its batch with `WHERE rowid IN (SELECT rowid ...
    LIMIT n)`. That bound is only real for an ordinary rowid table with no
    delete-time side effects. Verified for the two tables it is used on today:
    neither is WITHOUT ROWID, neither declares a column named `rowid` (which
    would shadow the hidden one and, if non-unique, let one batch delete more
    rows than the bound), the schema has no triggers at all, and nothing
    cascades from either on delete.

    ⚠️ The tables are DERIVED from the call sites, so adding a third caller puts
    it under this check automatically instead of quietly outside it.
    """
    import ast

    src = Path(__file__).resolve().parents[1] / "src" / "lynceus"
    tables: set[str] = set()
    for path in src.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "delete_in_batches"
                and node.args
                and isinstance(node.args[0], ast.Constant)
            ):
                tables.add(node.args[0].value)
    assert tables == {"sightings", "evidence_snapshots"}, (
        f"the call sites changed: {tables}. Re-check the schema facts below for "
        f"any new table before adding it here."
    )

    import tempfile

    database = Database(str(Path(tempfile.mkdtemp()) / "schema.db"))
    try:
        conn = database._conn
        assert not conn.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger'"
        ).fetchall(), "the schema now has triggers; re-check the batch bound"
        for table in sorted(tables):
            create = conn.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)
            ).fetchone()[0]
            assert "WITHOUT ROWID" not in create.upper(), table
            cols = [r["name"].lower() for r in conn.execute(f"PRAGMA table_info({table})")]
            assert "rowid" not in cols, f"{table} shadows the hidden rowid"
            for other in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ):
                for fk in conn.execute(f"PRAGMA foreign_key_list({other[0]})"):
                    assert fk["table"] != table, (
                        f"{other[0]} now references {table}; a cascade makes one "
                        f"batch delete an unbounded number of rows"
                    )
    finally:
        database.close()
