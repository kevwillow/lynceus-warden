"""A suppression the operator was told they made must not be silently discarded.

Every UI-allowlist mutator is read → modify → `os.replace`. Two of them running
at once both read the same starting state, and the second write throws the first
one's change away. Measured on the real functions, with a sequential control
that keeps both:

- two concurrent `add_ui_entry` calls → one suppression **gone**, both callers
  told they succeeded;
- the poller's `repair_future_dated_ui_entries` racing a single UI click → the
  operator's click **discarded**, needing no operator concurrency at all.

`add_ui_entry`'s docstring called this "last-write-wins by file mtime —
acceptable given the UI cadence is operator-driven (manual button clicks)".
A double-click or two browser tabs is enough; no request rate is needed. The
claim did not survive the fix, and neither should it.

⛔ Two plausible-looking fixes are wrong, and a test here exists to kill each:

1. **`threading.Lock`** — the repair runs in the POLLER and the clicks in the
   web process. Different processes; an in-process lock serialises neither.
   Killed by `test_a_click_during_the_pollers_repair_is_not_discarded`.
2. **`flock` on `allowlist_ui.yaml` itself** — `_atomic_write_yaml` ends in
   `os.replace`, which swaps the inode behind the path, so the next writer
   opens a different file and acquires "the lock" immediately.
   Killed by `test_the_write_lock_is_not_dissolved_by_the_atomic_replace`.

⚠️ A concurrency test that does not actually interleave is not a concurrency
test — this project has shipped one that passed with the fix removed. Each test
below asserts that contention genuinely occurred, not merely that the result
looked right.
"""

from __future__ import annotations

import ast
import fcntl
import os
import sys
import threading
import time
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
sys.path.insert(0, str(SRC))

import lynceus.allowlist as al  # noqa: E402
from lynceus.allowlist import (  # noqa: E402
    AllowlistEntry,
    add_ui_entry,
    remove_ui_entry,
    repair_future_dated_ui_entries,
    ui_lock_path,
)

M1 = "ac:de:48:00:00:01"
M2 = "ac:de:48:00:00:02"

ALLOWLIST_SRC = SRC / "lynceus" / "allowlist.py"

# Readers of the UI file. A mutator is a function that WRITES it; the read
# helpers are listed so the guard can also require the read to be inside the
# lock -- locking only the write still loses the update.
_READ_CALLS = {"_read_ui_yaml", "_load_ui_entries"}
_WRITE_CALL = "_atomic_write_yaml"
_LOCK_CALL = "_ui_write_lock"


def _entry(mac: str, note: str = "click", **kw: object) -> AllowlistEntry:
    return AllowlistEntry(pattern=mac, pattern_type="mac", note=note, **kw)


def _called_names(node: ast.AST) -> set[str]:
    out = set()
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            f = n.func
            if isinstance(f, ast.Name):
                out.add(f.id)
            elif isinstance(f, ast.Attribute):
                out.add(f.attr)
    return out


def _mutators() -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    """DERIVE the set of UI-file mutators from the source, never transcribe it.

    A hand-copied list looks derived and is not: it cannot see the fifth
    mutator somebody adds next month, which is precisely how this project has
    twice shipped a fix that covered only the first match.

    ⚠️ `AsyncFunctionDef` is included deliberately. A cold read of an earlier
    version of this guard pointed out that walking only `FunctionDef` made an
    `async def` mutator invisible to the derivation — it would not have been
    reported as unguarded, it would not have been seen at all. Measured before
    fixing: a synthetic `async def` mutator was not in the derived set.
    """
    tree = ast.parse(ALLOWLIST_SRC.read_text(encoding="utf-8"))
    found: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        if node.name == _WRITE_CALL:
            continue  # the write helper itself is not a mutator
        if _WRITE_CALL in _called_names(node):
            found[node.name] = node
    return found


def _first_arg_name(call: ast.Call) -> str | None:
    """The variable a call's first positional argument names, if it is a name."""
    if call.args and isinstance(call.args[0], ast.Name):
        return call.args[0].id
    return None


# --------------------------------------------------------------------------
# 1. the same-process race: two clicks
# --------------------------------------------------------------------------


def test_two_concurrent_clicks_both_survive(tmp_path, monkeypatch):
    """Both suppressions survive, AND the second writer genuinely contended."""
    ui = tmp_path / "allowlist_ui.yaml"
    ui.write_text("entries: []\n", encoding="utf-8")

    real_write = al._atomic_write_yaml
    inside = threading.Event()
    hold = 0.4

    def slow_write(path, payload):
        # Hold the critical section open so a second writer must queue.
        if not inside.is_set():
            inside.set()
            time.sleep(hold)
        return real_write(path, payload)

    monkeypatch.setattr(al, "_atomic_write_yaml", slow_write)

    started: dict[str, float] = {}
    finished: dict[str, float] = {}

    def click(mac: str) -> None:
        started[mac] = time.monotonic()
        add_ui_entry(ui, _entry(mac))
        finished[mac] = time.monotonic()

    t1 = threading.Thread(target=click, args=(M1,))
    t2 = threading.Thread(target=click, args=(M2,))
    t1.start()
    inside.wait(timeout=5)  # thread 1 is inside the critical section
    t2.start()
    t1.join(timeout=30)
    t2.join(timeout=30)

    text = ui.read_text(encoding="utf-8")
    assert M1 in text and M2 in text, (
        f"a click the operator was told succeeded is GONE: {text!r}"
    )

    # ⚠️ The assertion that makes this a concurrency test: the second writer
    # must have been made to WAIT. Without it, two threads that simply never
    # overlapped would score exactly the same as mutual exclusion.
    second = max(started, key=lambda m: started[m])
    waited = finished[second] - started[second]
    assert waited >= hold * 0.5, (
        f"the second writer never contended (waited {waited:.3f}s); "
        "this test would pass with the lock removed"
    )


def test_sequential_clicks_keep_both_entries(tmp_path):
    """CONTROL. If this fails, the concurrency results above mean nothing."""
    ui = tmp_path / "allowlist_ui.yaml"
    ui.write_text("entries: []\n", encoding="utf-8")
    for mac in (M1, M2):
        add_ui_entry(ui, _entry(mac, "seq"))
    text = ui.read_text(encoding="utf-8")
    assert M1 in text and M2 in text


# --------------------------------------------------------------------------
# 2. the cross-process race: the poller's repair vs a click
# --------------------------------------------------------------------------


def test_a_click_during_the_pollers_repair_is_not_discarded(tmp_path):
    """⛔ The test a `threading.Lock` implementation cannot pass.

    The repair runs in the poller process; the click runs in the web process.
    """
    ui = tmp_path / "allowlist_ui.yaml"
    now = int(time.time())
    ui.write_text("entries: []\n", encoding="utf-8")
    # A future-dated entry, so the repair actually rewrites the file.
    add_ui_entry(ui, _entry(M1, "future", added_at=now + 9000,
                            expires_at=now + 9000 + 3600))

    r_ready, w_ready = os.pipe()
    r_go, w_go = os.pipe()

    pid = os.fork()
    if pid == 0:  # child == the poller
        try:
            real_load = al._load_ui_entries

            def gated_load(p):
                out = real_load(p)
                os.write(w_ready, b"x")  # "I have read the file"
                os.read(r_go, 1)         # hold the window open
                return out

            al._load_ui_entries = gated_load
            repair_future_dated_ui_entries(ui, now)
        except Exception:
            pass
        finally:
            os.close(w_ready)
            os._exit(0)

    # ⛔ Close the parent's copy of the write end, or a child that dies without
    # signalling leaves no reader at EOF and this test HANGS instead of
    # failing. Measured on the earlier version: the parent blocked forever.
    os.close(w_ready)
    ready = os.read(r_ready, 1)
    assert ready == b"x", (
        "the child poller never signalled; it died before reading the file, "
        "so no race was set up and this test proves nothing"
    )

    # ⛔ The click runs on a thread and the poller is released on a TIMER, not
    # when the click returns: once the lock is real the click blocks, so
    # signalling afterwards would deadlock the test against a correct fix.
    done = threading.Event()

    def click() -> None:
        add_ui_entry(ui, _entry(M2, "click-during-repair"))
        done.set()

    t = threading.Thread(target=click)
    t.start()
    time.sleep(0.4)
    blocked = not done.is_set()
    os.write(w_go, b"x")
    os.waitpid(pid, 0)
    t.join(timeout=30)

    text = ui.read_text(encoding="utf-8")
    assert M2 in text, (
        "the operator's click was discarded by the poller's repair: " + repr(text)
    )
    assert blocked, (
        "the click never waited for the poller, so no cross-process exclusion "
        "was demonstrated; a threading.Lock would score the same here"
    )


# --------------------------------------------------------------------------
# 3. the lock must not be dissolved by the atomic replace
# --------------------------------------------------------------------------


def test_the_write_lock_is_not_dissolved_by_the_atomic_replace(tmp_path):
    """⛔ The test a `flock(allowlist_ui.yaml)` implementation cannot pass.

    `os.replace` swaps the inode behind the path. A lock held on the data file
    therefore protects a file no longer reachable by name, and the next writer
    opens the new inode and walks straight in.
    """
    ui = tmp_path / "allowlist_ui.yaml"
    ui.write_text("entries: []\n", encoding="utf-8")

    with al._ui_write_lock(ui):
        # Do exactly what a mutator does while holding the lock.
        al._atomic_write_yaml(ui, {"entries": []})

        # A second process must still be excluded AFTER that replace.
        r, w = os.pipe()
        pid = os.fork()
        if pid == 0:
            try:
                fd = os.open(ui_lock_path(ui), os.O_CREAT | os.O_RDWR, 0o600)
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    os.write(w, b"G")  # GOT the lock -- exclusion is broken
                except BlockingIOError:
                    os.write(w, b"B")  # BLOCKED -- correct
            except Exception:
                os.write(w, b"E")
            finally:
                os._exit(0)
        os.waitpid(pid, 0)
        verdict = os.read(r, 1)

    assert verdict == b"B", (
        "a second writer acquired the lock while the first still held it "
        f"(verdict={verdict!r}); the atomic replace dissolved the exclusion"
    )


def test_the_lock_file_is_not_the_data_file(tmp_path):
    """The property test 3 depends on, stated directly."""
    ui = tmp_path / "allowlist_ui.yaml"
    assert ui_lock_path(ui) != ui


# --------------------------------------------------------------------------
# 4. the derived guard: EVERY mutator, not just the ones I fixed
# --------------------------------------------------------------------------


def test_every_ui_file_mutator_holds_the_write_lock():
    """Derived from the source, so a mutator added later cannot slip through.

    ⚠️ Requires the READ inside the lock too: a mutator that locks only its
    write still reads stale state and still loses the update.
    """
    mutators = _mutators()

    # Vacuity control: an empty derivation would make this test pass forever.
    assert mutators, "derived NO mutators -- the guard is vacuous"

    # The derivation itself must not silently collapse to a subset. These four
    # are a floor on the INSTRUMENT's coverage, not the population it checks.
    for known in (
        "add_ui_entry",
        "remove_ui_entry",
        "bulk_remove_ui_entries",
        "repair_future_dated_ui_entries",
    ):
        assert known in mutators, f"derivation missed known mutator {known}"

    unguarded: list[str] = []
    for name, node in mutators.items():
        # Map each locked call to the PATH its `with` statement locked. A lock
        # on some other path is not exclusion on this one.
        # ⚠️ Checking only that `_ui_write_lock` appears somewhere in the
        # `with` was the earlier version of this guard, and a cold read killed
        # it: measured, a mutator rewritten to lock `Path('/tmp/unrelated')`
        # passed. The argument has to be compared, not just the call name.
        locked_calls: dict[int, str | None] = {}
        for n in ast.walk(node):
            if not isinstance(n, ast.With):
                continue
            locked_path: str | None = None
            is_lock = False
            for item in n.items:
                ctx = item.context_expr
                if isinstance(ctx, ast.Call) and isinstance(ctx.func, ast.Name) \
                        and ctx.func.id == _LOCK_CALL:
                    is_lock = True
                    locked_path = _first_arg_name(ctx)
            if not is_lock:
                continue
            for inner in ast.walk(n):
                if isinstance(inner, ast.Call):
                    locked_calls[id(inner)] = locked_path

        for n in ast.walk(node):
            if not isinstance(n, ast.Call):
                continue
            f = n.func
            fname = f.id if isinstance(f, ast.Name) else getattr(f, "attr", "")
            if fname not in _READ_CALLS | {_WRITE_CALL}:
                continue
            if id(n) not in locked_calls:
                unguarded.append(f"{name}:{fname}@line{n.lineno} (no lock)")
                continue
            target = _first_arg_name(n)
            held = locked_calls[id(n)]
            if target is not None and held != target:
                unguarded.append(
                    f"{name}:{fname}@line{n.lineno} "
                    f"(operates on {target!r} but the lock holds {held!r})"
                )

    assert not unguarded, (
        "read-modify-write outside the cross-process write lock: "
        + ", ".join(unguarded)
    )


# --------------------------------------------------------------------------
# 5. the other half of the acceptance criterion: the poller must still reload
# --------------------------------------------------------------------------


class _WatchStub:
    """Minimal stand-in carrying only what the poller's watch actually reads.

    ⚠️ This drives `Poller._current_allowlist_mtimes` itself. An earlier version
    of these two tests asserted proxies — that the yaml's mtime moved, and that
    two paths were unequal — and a cold read correctly pointed out that both
    would pass even if the poller ignored the UI file entirely. Calling the
    real method is the difference between checking the claim and checking
    something adjacent to it.
    """

    def __init__(self, primary: Path, ui: Path) -> None:
        self._allowlist_primary_path = primary
        self._allowlist_ui_path = ui


def test_the_poller_still_sees_a_locked_write(tmp_path):
    """A lock that stopped the poller reloading would trade a lost suppression
    for a stale one, so the poller's OWN watch must report the change."""
    from lynceus.poller import Poller

    primary = tmp_path / "allowlist.yaml"
    ui = tmp_path / "allowlist_ui.yaml"
    primary.write_text("entries: []\n", encoding="utf-8")
    ui.write_text("entries: []\n", encoding="utf-8")
    stub = _WatchStub(primary, ui)

    before = Poller._current_allowlist_mtimes(stub)
    time.sleep(0.01)
    add_ui_entry(ui, _entry(M1))
    after = Poller._current_allowlist_mtimes(stub)

    assert after != before, (
        "the poller's own mtime watch did not register the operator's click, "
        "so the lock traded a lost suppression for a stale one"
    )
    assert after[ui] != before[ui], "the change was not seen on the UI file"


def test_the_lock_file_is_not_in_the_pollers_watch_set(tmp_path):
    """Derived from the poller's real watch set, not asserted about paths.

    If the lock file were watched, every UI write would look like two changes
    and the poller would reload twice per click.
    """
    from lynceus.poller import Poller

    primary = tmp_path / "allowlist.yaml"
    ui = tmp_path / "allowlist_ui.yaml"
    primary.write_text("entries: []\n", encoding="utf-8")
    ui.write_text("entries: []\n", encoding="utf-8")
    add_ui_entry(ui, _entry(M1))  # creates the lock file

    assert ui_lock_path(ui).exists(), "expected the lock file to have been created"
    watched = set(Poller._current_allowlist_mtimes(_WatchStub(primary, ui)))
    assert watched == {primary, ui}, f"unexpected watch set: {watched}"
    assert ui_lock_path(ui) not in watched


# --------------------------------------------------------------------------
# 6. a raising mutator must not wedge the poller forever
# --------------------------------------------------------------------------


def test_a_failed_write_releases_the_lock(tmp_path, monkeypatch):
    """If a mutator raises while holding the lock, the next one must still run.

    A stranded lock would hang the poller's repair on every subsequent tick.
    """
    ui = tmp_path / "allowlist_ui.yaml"
    ui.write_text("entries: []\n", encoding="utf-8")

    def boom(path, payload):
        raise OSError("disk full")

    monkeypatch.setattr(al, "_atomic_write_yaml", boom)
    with pytest.raises(OSError):
        add_ui_entry(ui, _entry(M1))
    monkeypatch.undo()

    # The lock must be free: acquire it non-blockingly from another process.
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            fd = os.open(ui_lock_path(ui), os.O_CREAT | os.O_RDWR, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                os.write(w, b"F")  # FREE
            except BlockingIOError:
                os.write(w, b"S")  # STRANDED
        except Exception:
            os.write(w, b"E")
        finally:
            os._exit(0)
    os.waitpid(pid, 0)
    assert os.read(r, 1) == b"F", "the lock was stranded by a raising mutator"

    # And the module is still usable.
    add_ui_entry(ui, _entry(M2, "after"))
    assert M2 in ui.read_text(encoding="utf-8")


def test_remove_and_bulk_remove_still_work_under_the_lock(tmp_path):
    """The lock must not change the mutators' documented return contracts."""
    ui = tmp_path / "allowlist_ui.yaml"
    ui.write_text("entries: []\n", encoding="utf-8")
    add_ui_entry(ui, _entry(M1))
    add_ui_entry(ui, _entry(M2))
    assert remove_ui_entry(ui, M1, "mac") is True
    assert remove_ui_entry(ui, M1, "mac") is False
    assert al.bulk_remove_ui_entries(ui, [(M2, "mac")]) == 1
    assert al.bulk_remove_ui_entries(ui, [(M2, "mac")]) == 0
