"""Destructive housekeeping must not run on a clock the daemon does not trust.

#35 gated the retention prunes and #40 the poll watermark. **Two destructive
`now_ts`-driven calls sitting directly above them were left ungated**, and the
same tick logged *"clock is untrusted this tick"* twice while they ran anyway.

Measured on `main` before this fix, `clock_trusted=False` throughout:

    before                  : snoozes=1  active watchful=1
    poll at +8d             : snoozes=0  active watchful=1   <- 7-day snooze DELETED
    poll at +91d            : snoozes=0  active watchful=0   <- watchful tracking ARCHIVED

⭐ The watchful one is the serious one for this product. Watchful recurrence is
how the tool notices a device that **keeps coming back** — the core signal for
"someone is following me". One forward jump past the 90-day quiet-stretch
silently stops tracking every live entry, and the operator is told nothing: the
surface simply empties.

The snooze one is subtler but still operator-facing: a snooze is an explicit
"stop telling me about this until then". Cancelling it early resumes alerting
the operator deliberately silenced, which is how people learn to ignore a tool.

🪤 Both were reported on the session board **four times** before being fixed,
because they sat in another session's write set. The lesson is not about
process: it is that *"I gated the obvious destructive call"* is not the same as
*"I gated the destructive calls"*, and only enumerating them proves the latter.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from lynceus.config import Config
from lynceus.db import Database
from lynceus.kismet import FakeKismetClient
from lynceus.poller import poll_once

NOW = 1_700_000_000
DAY = 86_400


@pytest.fixture()
def env(tmp_path):
    fixture = tmp_path / "empty.json"
    fixture.write_text("[]", encoding="utf-8")
    cfg = Config(db_path=str(tmp_path / "p.db"), kismet_fixture_path=str(fixture))
    db = Database(cfg.db_path)
    db.ensure_location("default", "Default")
    mac = "aa:bb:cc:dd:ee:01"
    db.upsert_device(mac=mac, device_type="wifi", oui_vendor=None,
                     is_randomized=0, now_ts=NOW)
    db.insert_sighting(mac=mac, ts=NOW, rssi=-40, ssid="t", location_id="default")
    alert_id = db.add_alert(ts=NOW, rule_name="watchlist_mac_hit", mac=mac,
                            message="m", severity="high")
    db.create_watchful_from_alert(alert_id, None, NOW)
    db.add_rule_type_snooze("watchlist_mac_hit", NOW + 7 * DAY, NOW)
    yield FakeKismetClient(str(fixture)), db, cfg
    db.close()


def _snoozes(db) -> int:
    return db._conn.execute("SELECT COUNT(*) FROM rule_type_snoozes").fetchone()[0]


def _active_watchful(db) -> int:
    return db._conn.execute(
        "SELECT COUNT(*) FROM watchful_recurrence WHERE archived_at IS NULL"
    ).fetchone()[0]


def test_an_untrusted_clock_does_not_expire_a_live_snooze(env):
    """The operator said "not until day 7". A jump to day 8 is not day 8."""
    client, db, cfg = env
    assert _snoozes(db) == 1
    poll_once(client, db, cfg, NOW + 8 * DAY, clock_trusted=False)
    assert _snoozes(db) == 1, (
        "a 7-day snooze was cancelled by an untrusted clock jump; the operator "
        "deliberately silenced this rule and will now be alerted again"
    )


def test_an_untrusted_clock_does_not_archive_live_watchful_tracking(env):
    """⭐ The one that matters most: the tool stops watching a device that
    keeps coming back, and says nothing."""
    client, db, cfg = env
    assert _active_watchful(db) == 1
    poll_once(client, db, cfg, NOW + 91 * DAY, clock_trusted=False)
    assert _active_watchful(db) == 1, (
        "live watchful tracking was archived by an untrusted clock jump; the "
        "recurrence surface silently empties and the operator is not told"
    )


def test_a_trusted_clock_still_expires_a_genuinely_expired_snooze(env):
    """⛔ The presence assertion. A guard that simply never expired anything
    would satisfy the two tests above while breaking the feature -- housekeeping
    that never runs is the other broken extreme, and the tables grow forever."""
    client, db, cfg = env
    poll_once(client, db, cfg, NOW + 8 * DAY, clock_trusted=True)
    assert _snoozes(db) == 0, "a genuinely expired snooze was not cleaned up"


def test_a_trusted_clock_still_archives_a_genuinely_stale_watchful_entry(env):
    """The presence assertion for the other half."""
    client, db, cfg = env
    poll_once(client, db, cfg, NOW + 91 * DAY, clock_trusted=True)
    assert _active_watchful(db) == 0, (
        "a genuinely stale watchful entry was not archived"
    )


def test_housekeeping_resumes_after_the_clock_is_trusted_again(env):
    """The hold must be a hold, not a permanent disable. `clock_is_trusted`
    re-anchors after CLOCK_JUMP_MAX_HOLDS, so a bad clock defers this work
    rather than cancelling it."""
    client, db, cfg = env
    poll_once(client, db, cfg, NOW + 91 * DAY, clock_trusted=False)
    assert (_snoozes(db), _active_watchful(db)) == (1, 1)
    poll_once(client, db, cfg, NOW + 91 * DAY, clock_trusted=True)
    assert (_snoozes(db), _active_watchful(db)) == (0, 0)


def test_every_now_ts_driven_destructive_call_is_inside_the_gate():
    """⭐ Enumerate rather than spot-check.

    The two defects this file pins existed *because* the previous fixes gated
    the destructive calls someone thought of, not the destructive calls that
    exist. This asserts the property over the source: every call in `poll_once`
    naming one of the known destructive housekeeping helpers must appear after
    an `if clock_trusted:` and be indented inside it.

    🪤 It is a source-shape check, so it cannot see a NEW helper with a
    different name. It is a ratchet against the known set, not a proof about
    the unknown one -- said plainly so a green run is not over-read.
    """
    import ast

    import lynceus.poller as poller_mod

    tree = ast.parse(Path(poller_mod.__file__).read_text(encoding="utf-8"))
    fn = next(
        n for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == "poll_once"
    )

    DESTRUCTIVE = {
        "cleanup_expired_rule_type_snoozes",
        "auto_archive_watchful_recurrence",
        "maybe_prune_evidence",
        "maybe_prune_sightings",
    }

    def _gates_on_clock(node: ast.If) -> bool:
        return any(
            isinstance(x, ast.Name) and x.id == "clock_trusted"
            for x in ast.walk(node.test)
        )

    def _called(call: ast.Call) -> str:
        f = call.func
        return f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")

    # Walk statement-first, so `gated` means ENCLOSED BY an `if clock_trusted:`.
    #
    # 🪤 The first version tested `isinstance(child, ast.If)` while iterating a
    # node's CHILDREN, so a top-level `if clock_trusted:` statement was never
    # recognised as a gate and all four calls reported ungated. The one before
    # that scanned backwards for the nearest preceding `if clock_trusted:` text,
    # which passed any call sitting AFTER a gated block. Both are the same
    # mistake this file exists to catch: a check that matches the shape of the
    # thing rather than the thing.
    ungated: list[str] = []

    def visit(node, gated: bool):
        if isinstance(node, ast.If):
            on_clock = gated or _gates_on_clock(node)
            for stmt in node.body:
                visit(stmt, on_clock)
            for stmt in node.orelse:
                visit(stmt, gated)          # the else branch is NOT gated
            return
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.Call) and _called(child) in DESTRUCTIVE and not gated:
                ungated.append(f"{_called(child)} at line {child.lineno}")
            visit(child, gated)

    for stmt in fn.body:
        visit(stmt, False)

    assert ungated == [], (
        f"destructive now_ts-driven calls outside the clock gate: {ungated}. "
        f"A wall-clock jump makes these delete or archive live operator state."
    )
