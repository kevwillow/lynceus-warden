"""A wall-clock jump must not delete data inside the retention window.

Session 3 measured the defect (`internal/handoffs/FINDINGS_2026-08-14_SESSION3_CLOCK_CLASS.md`):
30 daily sightings, `retention_days=30`, nothing stale at the correct time --

    clock   deleted   should have deleted
    +7d     6         0
    +30d    29        0
    +365d   30        0

and `evidence.py` has the same shape on the ALWAYS-ON path
(`evidence_retention_days` defaults to 90; sightings retention is opt-in).

⛔ **It is not fixable inside `retention.py`, and that is why this lives here.**
From inside that module, "the clock jumped forward" and "the table holds only
old rows" are the SAME observation -- and the second is *required* behaviour:
`test_sightings_retention.py::test_returns_none_oldest_when_table_is_emptied`
asserts a wholly-stale table is fully deleted. A data-anchored clamp, a volume
bound and a cutoff-plausibility bound each refuse that legitimate prune, and any
"elapsed since last prune" bound is computed from the same corrupt clock, so it
is circular.

⇒ You cannot detect a wall-clock jump using only the wall clock. It needs a
monotonic reference, and the only place that can hold one across ticks is the
daemon itself.

🪤 Note what is NOT gated: the heartbeat. The fail-safe direction is
subsystem-specific -- an untrustworthy clock means "do NOT prune" here (fail
toward keeping data) and "DO send" for the dead-man's switch (fail toward
noise). `test_the_heartbeat_still_fires_on_an_untrusted_clock` pins that, and
it must survive any later unification behind a shared clock helper.
"""

from __future__ import annotations

import time

import pytest

from lynceus.config import Config
from lynceus.poller import (
    CLOCK_JUMP_MAX_HOLDS,
    CLOCK_JUMP_TOLERANCE_SECONDS,
    ClockAnchor,
)


class _FakePoller:
    """Just the clock machinery, without standing up a Kismet client or DB.

    This used to bind `Poller.clock_is_trusted` to a bare object carrying
    `_clock_anchor`/`_clock_holds`, because the machinery was only reachable
    through a Poller. It now lives in `ClockAnchor`, which is directly
    constructible, so this drives the real production object and only overrides
    the anchor -- one less thing standing between the test and the code.
    """

    def __init__(self, wall: float, mono: float) -> None:
        self._clock = ClockAnchor()
        self._clock._anchor = (wall, mono)
        self._clock._holds = 0

    def clock_is_trusted(self, now_ts: int) -> bool:
        return self._clock.is_trusted(now_ts)

    # The hold counter and anchor are what several tests below assert on
    # directly; expose them under their historical names so those assertions
    # keep describing the same state rather than being rewritten around the
    # refactor.
    @property
    def _clock_holds(self) -> int:
        return self._clock._holds

    @property
    def _clock_anchor(self) -> tuple[float, float]:
        return self._clock._anchor


def _p(monkeypatch, *, mono_now: float) -> _FakePoller:
    """Anchor at wall=1_700_000_000, mono=1000, then freeze monotonic."""
    p = _FakePoller(1_700_000_000.0, 1000.0)
    monkeypatch.setattr(time, "monotonic", lambda: mono_now)
    return p


def test_a_normally_advancing_clock_is_trusted(monkeypatch):
    """60s of monotonic time and 60s of wall time: nothing has moved."""
    p = _p(monkeypatch, mono_now=1060.0)
    assert p.clock_is_trusted(1_700_000_060) is True


def test_small_drift_inside_the_tolerance_is_trusted(monkeypatch):
    """NTP slew must not suspend housekeeping; the cost of a false positive is
    a skipped prune, but the cost of being twitchy is never pruning at all."""
    p = _p(monkeypatch, mono_now=1060.0)
    drifted = 1_700_000_060 + CLOCK_JUMP_TOLERANCE_SECONDS - 1
    assert p.clock_is_trusted(drifted) is True


@pytest.mark.parametrize("jump", [7 * 86400, 30 * 86400, 365 * 86400])
def test_a_forward_jump_is_not_trusted(monkeypatch, jump):
    """The measured data-destroying case."""
    p = _p(monkeypatch, mono_now=1060.0)
    assert p.clock_is_trusted(1_700_000_060 + jump) is False


def test_a_backward_jump_is_not_trusted(monkeypatch):
    """The inverse excursion, which stalls pruning rather than over-pruning --
    a table whose whole purpose is to stop unbounded growth on a Pi."""
    p = _p(monkeypatch, mono_now=1060.0)
    assert p.clock_is_trusted(1_700_000_060 - 200 * 86400) is False


def test_the_hold_is_bounded_and_then_re_anchors(monkeypatch):
    """🪤 Holding forever is the OTHER broken extreme.

    On a machine whose clock is permanently wrong -- an RTC-less Pi that never
    reaches NTP, squarely this project's target -- an unbounded hold protects
    capture data by never pruning, and loses the table to unbounded growth
    instead. Both extremes are broken, so the bound is the design.
    """
    p = _p(monkeypatch, mono_now=1060.0)
    jumped = 1_700_000_060 + 30 * 86400
    for i in range(CLOCK_JUMP_MAX_HOLDS - 1):
        assert p.clock_is_trusted(jumped) is False, f"hold {i} should still refuse"
    # The bounding tick accepts the new clock.
    assert p.clock_is_trusted(jumped) is True
    # ...and having re-anchored, the new clock is now the reference.
    assert p.clock_is_trusted(jumped) is True


def test_the_hold_counter_resets_when_the_clock_agrees_again(monkeypatch):
    """A transient blip must not accumulate toward the bound across hours."""
    p = _p(monkeypatch, mono_now=1060.0)
    assert p.clock_is_trusted(1_700_000_060 + 30 * 86400) is False
    assert p._clock_holds == 1
    assert p.clock_is_trusted(1_700_000_060) is True
    assert p._clock_holds == 0


def test_a_restart_after_genuine_downtime_is_not_flagged():
    """The anchor is per-process. A daemon that was stopped for a week and
    restarted takes a fresh anchor, so real downtime is never mistaken for a
    jump -- which is exactly why the wall clock alone cannot do this."""
    p = _FakePoller(time.time(), time.monotonic())
    assert p.clock_is_trusted(int(time.time())) is True


# --- wiring: does poll_once actually honour the flag? -----------------------
#
# ⛔ Every test above exercises `clock_is_trusted` in isolation. All of them
# would still pass with the gate in `poll_once` deleted, and the anchor would
# be decorative. Same lesson as PR #18's `maybe_prune_evidence` wiring.


def _poll_once_with(tmp_path, *, clock_trusted, notifier=None, **cfg_kwargs):
    from lynceus.db import Database
    from lynceus.kismet import FakeKismetClient
    from lynceus.poller import poll_once

    fixture = tmp_path / "empty.json"
    fixture.write_text("[]", encoding="utf-8")
    cfg = Config(
        db_path=str(tmp_path / "clock.db"),
        kismet_fixture_path=str(fixture),
        **cfg_kwargs,
    )
    db = Database(cfg.db_path)
    db.ensure_location("default", "Default")
    try:
        poll_once(
            FakeKismetClient(str(fixture)), db, cfg, 1_700_000_000,
            notifier=notifier, clock_trusted=clock_trusted,
        )
        return db
    finally:
        db.close()


@pytest.mark.parametrize("trusted", [True, False])
def test_poll_once_gates_both_prunes_on_the_flag(tmp_path, monkeypatch, trusted):
    """A take-effect pair. Asserting only that prunes are skipped would pass
    against code that never prunes; only that they run, against code that
    ignores the flag."""
    from lynceus import poller as poller_mod

    called: list[str] = []
    monkeypatch.setattr(poller_mod, "maybe_prune_evidence",
                        lambda *a, **k: called.append("evidence"))
    monkeypatch.setattr(poller_mod, "maybe_prune_sightings",
                        lambda *a, **k: called.append("sightings"))

    _poll_once_with(tmp_path, clock_trusted=trusted)

    if trusted:
        assert called == ["evidence", "sightings"], f"prunes did not run: {called}"
    else:
        assert called == [], f"prunes ran on an untrusted clock: {called}"


def test_the_heartbeat_still_fires_on_an_untrusted_clock(tmp_path, monkeypatch):
    """🪤 The fail-safe direction is subsystem-specific, and unifying these
    naively would break one of them.

    Retention fails toward KEEPING data; the dead-man's switch fails toward
    SENDING. A spurious heartbeat costs one notification; a suppressed one
    costs the entire guarantee, because its absence is what the operator reads
    as "the daemon is dead". If anyone later hides both behind one clock
    helper, this asymmetry has to survive it.
    """
    from lynceus import poller as poller_mod

    monkeypatch.setattr(poller_mod, "maybe_prune_evidence", lambda *a, **k: None)
    monkeypatch.setattr(poller_mod, "maybe_prune_sightings", lambda *a, **k: None)

    sent: list[str] = []

    class _N:
        def send(self, severity, title, message, priority_override=None):
            sent.append(title)
            return True

    _poll_once_with(tmp_path, clock_trusted=False, notifier=_N(),
                    heartbeat_enabled=True)
    assert sent, "the dead-man's switch was silenced by an untrusted clock"
