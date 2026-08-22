"""Finding 52 — the cross-process half, REPRODUCED rather than simulated.

⛔ Every concurrency measurement on this project until now was either
single-threaded or produced by monkeypatching a ``raise`` into a transaction.
The register said so in its own open-items list: *"the poller/web-UI race that
makes ``database is locked`` reachable was simulated by raising, not
reproduced."* A defect that only appears under an injected exception is a
defect nobody has actually seen.

This file uses **two real OS processes**, one real database file, two real
``Database`` objects and a real product write method. Nothing is patched and
nothing raises on cue.

**What it establishes.**

``db._lock`` is per-process. The poller, the web UI and the ble-bridge are
separate processes holding separate connections, so no Python lock serialises
them — SQLite does, by making the second writer wait. It waits for
``busy_timeout`` milliseconds and then gives up, and the write is **lost**:

======================  ==================  ===================
holder holds the lock   second writer       row committed
======================  ==================  ===================
0.5 s                   waits 0.44 s, ok    yes
2.0 s                   waits 1.94 s, ok    yes
4.0 s                   waits 3.94 s, ok    yes
6.0 s                   OperationalError    **no**
12.0 s                  OperationalError    **no**
======================  ==================  ===================

⚠️ **The threshold is 5.00 s, and nothing in this product chose it.**
``busy_timeout`` is never set anywhere in ``src/``; 5000 ms is
``sqlite3.connect``'s inherited default (``timeout=5.0``). The one place that
even names it is ``bridges/ble.py``'s docstring. The number is therefore a
property of CPython's defaults, which is why this file pins it — if someone
sets the pragma deliberately, this test should be the thing that notices.
"""

from __future__ import annotations

import ast
import logging
import re
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from lynceus.db import Database

_REPO_SRC = str(Path(__file__).resolve().parents[1] / "src")

# The holder runs in its own interpreter. It takes the write lock through the
# SAME primitive the product uses, announces that it holds it, and then waits
# for the parent to say when to let go — so the test never races a sleep.
_HOLDER = """
import sys, time, pathlib
sys.path.insert(0, {src!r})
from lynceus.db import Database
db = Database({path!r})
release = pathlib.Path({release!r})
with db.transaction() as conn:
    conn.execute(
        "INSERT INTO alerts (ts, rule_name, message, severity) VALUES (?,?,?,?)",
        (1, "holder", "holder", "low"),
    )
    print("HELD", repr(time.time()), flush=True)
    deadline = time.monotonic() + {max_hold!r}
    while not release.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
print("RELEASED", repr(time.time()), flush=True)
"""


def _start_holder(tmp_path, *, release_name, max_hold):
    """Launch the holder and return once it really holds the write lock."""
    script = _HOLDER.format(
        src=_REPO_SRC,
        path=str(tmp_path / "lock.db"),
        release=str(tmp_path / release_name),
        max_hold=max_hold,
    )
    proc = subprocess.Popen(
        [sys.executable, "-c", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    line = proc.stdout.readline()
    if not line.startswith("HELD "):
        out, err = proc.communicate(timeout=30)
        pytest.fail(f"holder never took the lock: {line!r} {out!r} {err!r}")
    return proc


def _released_at(proc) -> float:
    """The wall-clock instant the holder actually left its transaction.

    Both processes are on this machine and this clock, so this timestamp is
    directly comparable with the parent's — which is what turns "the writer
    probably contended" into an observed ordering.
    """
    line = proc.stdout.readline()
    assert line.startswith("RELEASED "), f"holder did not report releasing: {line!r}"
    return float(line.split(maxsplit=1)[1])


@pytest.fixture
def locked_db(tmp_path):
    """A migrated database, plus this process's own connection to it."""
    db = Database(str(tmp_path / "lock.db"))  # migrate ONCE, before any contention
    yield db
    db.close()


# How long the control makes the writer wait. Comfortably inside the 5s busy
# timeout, comfortably outside the noise floor of an uncontended write (which is
# sub-millisecond), so the lower bound below discriminates rather than decorates.
_CONTROL_HOLD_SECONDS = 1.0


def test_a_second_process_waits_for_a_short_write_and_then_succeeds(tmp_path, locked_db):
    """⭐ THE CONTROL. Without it, the failure below could mean anything.

    If contention never actually happened, the treatment's exception would be
    telling us about something other than the lock. So this asserts the writer
    genuinely BLOCKED and then still committed its row.

    ⛔ **The first version of this test released the lock BEFORE starting the
    writer, and asserted only an upper bound** — so the holder could commit
    before ``add_alert`` was ever called and the control passed having measured
    no contention at all, while its own docstring claimed it proved the
    opposite. A cross-model read of this file found it. The release is now armed
    on a timer that fires *while the writer is already waiting*, and the wait is
    bounded from **below**, which is the half that makes it a control.
    """
    proc = _start_holder(tmp_path, release_name="go", max_hold=30)
    releaser = threading.Timer(_CONTROL_HOLD_SECONDS, (tmp_path / "go").touch)
    try:
        time.sleep(0.3)  # the holder is inside its transaction
        releaser.start()  # ...and will let go only after the writer is blocked
        started, started_wall = time.monotonic(), time.time()
        locked_db.add_alert(
            ts=1, rule_name="writer", mac=None, message="writer", severity="low"
        )
        elapsed = time.monotonic() - started
        released_wall = _released_at(proc)
    finally:
        releaser.cancel()
        (tmp_path / "go").touch()
        proc.wait(timeout=30)

    rows = locked_db._conn.execute(
        "SELECT rule_name FROM alerts ORDER BY rule_name"
    ).fetchall()
    assert [r[0] for r in rows] == ["holder", "writer"], (
        "both writes should survive when the holder releases inside the timeout"
    )
    # ⭐ THE ORDERING, which is the actual proof. A duration alone is not one:
    # if this process were descheduled for half a second between the timer
    # firing and SQLite being reached, the holder could have committed first and
    # `elapsed` would still clear any lower bound — a green arm that measured no
    # contention whatsoever. Both timestamps come from the same wall clock on
    # the same machine, so this comparison is meaningful across the two
    # processes: the writer STARTED while the lock was demonstrably still held.
    assert started_wall < released_wall, (
        f"the writer began at {started_wall!r} but the holder had already "
        f"released at {released_wall!r} — no contention occurred, so this arm "
        f"proves nothing about the lock"
    )
    assert elapsed >= _CONTROL_HOLD_SECONDS * 0.5, (
        f"the writer returned in {elapsed:.3f}s — too fast to have waited out the "
        f"holder (an uncontended write is <1ms)"
    )
    assert elapsed < 5.0, f"the writer should not have hit the busy timeout ({elapsed:.2f}s)"


def test_a_write_held_past_the_busy_timeout_is_LOST_in_the_other_process(
    tmp_path, locked_db
):
    """The reproduction. Two processes, no patching, no injected raise.

    ⛔ The row is not queued, not retried and not reported anywhere by
    ``db.py`` — it raises ``OperationalError`` at the call site and the caller
    decides. ``poll_once`` catches it per-observation, logs a WARNING and holds
    the Kismet watermark so the tick is retried; a web route has no such
    handling and 500s.
    """
    proc = _start_holder(tmp_path, release_name="go", max_hold=30)
    try:
        time.sleep(0.3)
        started = time.monotonic()
        with pytest.raises(sqlite3.OperationalError) as excinfo:
            locked_db.add_alert(
                ts=1, rule_name="writer", mac=None, message="writer", severity="low"
            )
        elapsed = time.monotonic() - started
    finally:
        (tmp_path / "go").touch()
        proc.wait(timeout=30)

    assert "locked" in str(excinfo.value), str(excinfo.value)

    # ⭐ Assert the BARRIER fired: the writer must actually have sat on the busy
    # handler for the full timeout. A fast failure would mean it never really
    # contended and the exception came from somewhere else entirely.
    assert 4.0 <= elapsed <= 12.0, (
        f"expected the writer to block for the ~5s busy timeout, waited {elapsed:.2f}s"
    )

    # And the write is GONE. Not deferred — gone.
    rows = locked_db._conn.execute("SELECT rule_name FROM alerts").fetchall()
    assert [r[0] for r in rows] == ["holder"], (
        f"the second process's write should have been lost, found {rows}"
    )


def test_exactly_one_place_chooses_the_busy_timeout_and_it_chooses_5000():
    """The number the two tests above depend on, and its single source of truth.

    ⭐ This test used to assert that **nothing** in ``src/`` set ``busy_timeout``
    — because nothing did, and 5000 ms was `sqlite3.connect`'s inherited
    ``timeout=5.0``. It went red the moment that was made deliberate, which is
    exactly what it was written to do: the pragma is now chosen, so the
    assertion is about the CHOICE rather than its absence.

    Two things are pinned, and the second is the one that rots otherwise:

    1. the runtime value really is 5000 ms on a live connection, and WAL is on;
    2. **exactly one** place in the package decides it. A second setter, or a
       `connect(..., timeout=...)` alongside the pragma, means two sources of
       truth for one number and the loser is silent.

    ⚠️ Changing the value here is a real product decision, not a tuning knob —
    it is the whole cross-process contention policy. Raising it makes the lost
    write rarer and a wedged writer block longer; lowering it does the reverse.
    Read ``Database.transaction``'s docstring and the two tests above first.
    """
    # ⚠️ On the CONSTRUCT, not the spelling. A case-sensitive substring scan
    # over raw lines missed `PRAGMA BUSY_TIMEOUT = 5000`, a positional
    # `sqlite3.connect(path, 30)`, a bare `from sqlite3 import connect`, and a
    # pragma held in a variable — all four reproduced before this was widened.
    src = Path(__file__).resolve().parents[1] / "src" / "lynceus"
    pragma = re.compile(r"\bpragma\s+busy_timeout\s*=\s*(\d+)", re.IGNORECASE)
    setters: list[tuple[str, int | None]] = []
    connect_timeouts: list[str] = []
    for path in sorted(src.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            lineno = getattr(node, "lineno", "?")
            where = f"{path.relative_to(src)}:{lineno}"
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                m = pragma.search(node.value)
                if m:
                    setters.append((where, int(m.group(1))))
                continue
            if not isinstance(node, ast.Call):
                continue
            name = (
                node.func.attr
                if isinstance(node.func, ast.Attribute)
                else getattr(node.func, "id", None)
            )
            if name != "connect":
                continue
            if any(kw.arg == "timeout" for kw in node.keywords):
                connect_timeouts.append(f"{where} (timeout=)")
            elif len(node.args) >= 2:
                connect_timeouts.append(f"{where} (positional timeout)")

    assert len(setters) == 1, (
        f"expected exactly one place to choose busy_timeout, found {setters}. "
        f"Two setters means two sources of truth for one number."
    )
    assert setters[0][1] == 5000, (
        f"busy_timeout is now {setters[0][1]} at {setters[0][0]}, not 5000 — the "
        f"two cross-process tests above assert the 5s threshold. Re-read them."
    )
    assert not connect_timeouts, (
        f"a connect() timeout is set at {connect_timeouts} as well as the pragma; "
        f"one of the two silently loses. Keep the pragma as the only decision."
    )


def test_the_live_connection_really_carries_that_timeout(locked_db):
    """⭐ The source scan above proves what the code SAYS. This proves what the
    connection DOES — the two are only the same if the pragma actually applies.
    """
    assert locked_db._conn.execute("PRAGMA busy_timeout").fetchone()[0] == 5000
    assert locked_db._conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


# --- Database.run(): the retry policy -------------------------------------
#
# The tests above establish the defect: the loser of a write race waits out
# `busy_timeout` and its write is GONE. `run()` is the retryable form. It does
# not change `busy_timeout` (which one guard pins at 5000ms in one place) and
# it does not make contention cheaper. It converts "lost write" into "slower
# successful write", bounded by a deadline the CALLER derives from its own
# budget.


def test_run_RECOVERS_the_write_the_old_path_loses(tmp_path, locked_db):
    """⭐ The whole point, against a real second process.

    The holder keeps the lock for 6s, which is just past the 5s busy timeout.
    The old path loses this write outright -- that is
    ``test_a_write_held_past_the_busy_timeout_is_LOST_in_the_other_process``
    directly above. Through ``run()`` the same write survives.
    """
    proc = _start_holder(tmp_path, release_name="go", max_hold=6.0)
    try:
        time.sleep(0.3)
        started = time.monotonic()
        locked_db.run(
            lambda conn: conn.execute(
                "INSERT INTO alerts (ts, rule_name, message, severity) VALUES (?,?,?,?)",
                (2, "retrier", "retrier", "low"),
            ),
            deadline_seconds=20,
        )
        elapsed = time.monotonic() - started
    finally:
        (tmp_path / "go").touch()
        proc.wait(timeout=30)

    rows = sorted(r[0] for r in locked_db._conn.execute("SELECT rule_name FROM alerts"))
    assert rows == ["holder", "retrier"], f"the retried write did not survive: {rows}"

    # ⭐ The barrier, same discipline as the tests above: prove it really
    # contended. A sub-second success would mean the holder never had the lock
    # and this test proves nothing about retrying.
    assert elapsed >= 4.0, (
        f"succeeded in {elapsed:.2f}s, so it never waited out a busy timeout "
        "and never actually retried"
    )


def test_run_gives_up_at_the_deadline_and_RAISES_rather_than_returning(tmp_path, locked_db, caplog):
    """Exhaustion must surface. A caller that could not write has to find out.

    ⚠️ This also pins the documented overshoot: the deadline is checked BETWEEN
    attempts, so a 1s deadline still costs one whole 5s busy timeout because an
    attempt cannot be interrupted once SQLite is waiting inside it. That is the
    real worst case and the docstring says so rather than rounding it off.
    """
    proc = _start_holder(tmp_path, release_name="go", max_hold=30)
    try:
        time.sleep(0.3)
        started = time.monotonic()
        with caplog.at_level(logging.WARNING):
            with pytest.raises(sqlite3.OperationalError) as excinfo:
                locked_db.run(
                    lambda conn: conn.execute(
                        "INSERT INTO alerts (ts, rule_name, message, severity) "
                        "VALUES (?,?,?,?)",
                        (3, "doomed", "doomed", "low"),
                    ),
                    deadline_seconds=1.0,
                )
        elapsed = time.monotonic() - started
    finally:
        (tmp_path / "go").touch()
        proc.wait(timeout=30)

    assert "locked" in str(excinfo.value)
    assert 4.0 <= elapsed <= 12.0, (
        f"expected one full busy timeout despite the 1s deadline, got {elapsed:.2f}s"
    )
    rows = [r[0] for r in locked_db._conn.execute("SELECT rule_name FROM alerts")]
    assert rows == ["holder"], f"the doomed write should not be present: {rows}"
    warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("giving up" in m for m in warnings), warnings


def test_run_does_NOT_retry_an_error_that_is_not_contention(locked_db):
    """⛔ The safety of the whole thing. Disk-full, corruption, a constraint
    failure and a plain SQL mistake are all OperationalError too. Retrying one
    turns an operational failure into a slow operational failure and then
    reports it as contention."""
    calls = []

    def boom(conn):
        calls.append(1)
        conn.execute("SELECT * FROM no_such_table_at_all")

    started = time.monotonic()
    with pytest.raises(sqlite3.OperationalError) as excinfo:
        locked_db.run(boom, deadline_seconds=30)
    elapsed = time.monotonic() - started

    assert "no such table" in str(excinfo.value)
    assert calls == [1], f"a non-contention error was retried {len(calls)} times"
    assert elapsed < 1.0, f"it burned {elapsed:.2f}s retrying something unretryable"


def test_run_is_free_when_nothing_is_contending(locked_db):
    """The control. Retry must not add cost to the uncontended path, which is
    every write on a single-writer install."""
    calls = []
    started = time.monotonic()
    locked_db.run(
        lambda conn: calls.append(
            conn.execute(
                "INSERT INTO alerts (ts, rule_name, message, severity) VALUES (?,?,?,?)",
                (4, "quiet", "quiet", "low"),
            )
        ),
        deadline_seconds=30,
    )
    elapsed = time.monotonic() - started
    assert len(calls) == 1, "the callable ran more than once with no contention"
    assert elapsed < 1.0, f"an uncontended write took {elapsed:.2f}s"


def test_run_refuses_a_deadline_that_cannot_permit_an_attempt(locked_db):
    for bad in (0, -1, -0.5):
        with pytest.raises(ValueError, match="deadline_seconds"):
            locked_db.run(lambda conn: None, deadline_seconds=bad)
