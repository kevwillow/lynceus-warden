"""A page must classify a row from ONE instant, not two.

⛔ **The defect, measured on `/watchlist/{id}`.** `entry_can_alert` and
`allowlist_entries` both call `_match_all_mac_in_entries` with the SAME
arguments — and each took its own `int(time.time())`. With an allowlist entry
expiring between the two reads:

    both reads before expiry   entry_can_alert=False  allowlist_entries=1   consistent
    both reads after  expiry   entry_can_alert=True   allowlist_entries=0   consistent
    reads STRADDLE the expiry  entry_can_alert=False  allowlist_entries=0   <- impossible

The page then says *"this row cannot alert because it is allowlisted"* while
showing **nothing** suppressing it. Neither consistent state produces that pair.

⭐ Found by sweeping the CLASS after the same shape was fixed on `/allowlist`,
where the table called a row `snoozed` while the banner called it an expired
suppression. That one came from a cross-model red-team; this one came from
asking how many other handlers read the wall clock more than once. **Four did.**

⚠️ Reading the clock twice is not automatically a defect. A handler that gates
on the clock and then writes a timestamp reads twice for good reason — the two
values feed different things and a one-second gap changes nothing anyone can
see. What makes it a defect is **two DISPLAYED classifications of the same row**
derived from different instants. The guard below is scoped to that.
"""

from __future__ import annotations

import ast
import pathlib
import warnings

import pytest
from starlette.testclient import TestClient

import lynceus.webui.app as appmod
from lynceus.config import Config
from lynceus.db import Database

APP_PY = pathlib.Path(appmod.__file__)
MAC = "aa:bb:cc:dd:ee:01"
T = 1_700_000_000

#: Handlers allowed to read the wall clock more than once, each with the reason.
#: ⛔ An exemption is a claim: every one of these was read, and the second read
#: feeds a WRITE or a filename, never a second classification of a row already
#: classified by the first.
_MULTI_READ_EXEMPT: dict[str, str] = {
    "ack_all_visible": "gate/count read, then the acknowledge write's own stamp",
    "snooze_alert_post": "clock-behind gate, then the snooze deadline it writes",
    "watch_alert_post": "clock-behind gate, then the watchlist write's stamp",
    "watchful_reset_post": "clock-behind gate, then the reset's last_seen_at",
    "device_watch_post": "clock-behind gate, then the watchlist write's stamp",
    "device_snooze_post": "clock-behind gate, then the snooze deadline",
    "_build_settings_context": "independent freshness readouts, not one row twice",
}


def _clock_reads_per_function() -> dict[str, int]:
    """`{function_name: number of `time.time()` calls in its own body}`.

    Derived from the AST, so a handler added tomorrow is graded automatically
    rather than needing to be added to a list.
    """
    tree = ast.parse(APP_PY.read_text())
    out: dict[str, int] = {}
    funcs = [
        n for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
    ]
    for fn in funcs:
        nested_nodes = {
            id(x) for c in fn.body for n in ast.walk(c)
            if isinstance(n, ast.FunctionDef | ast.AsyncFunctionDef)
            for x in ast.walk(n)
        }
        count = sum(
            1 for x in ast.walk(fn)
            if id(x) not in nested_nodes
            and isinstance(x, ast.Call)
            and isinstance(x.func, ast.Attribute)
            and x.func.attr == "time"
            and isinstance(x.func.value, ast.Name)
            and x.func.value.id == "time"
        )
        if count:
            out[fn.name] = count
    return out


def test_the_scan_finds_the_clock_reads_it_is_supposed_to_grade():
    """The instrument's own control — a scan matching nothing would make the
    guard below pass vacuously, which has shipped in this repo before."""
    reads = _clock_reads_per_function()
    assert len(reads) >= 20, reads
    # ⛔ The scan counts a function's OWN body only, so the `create_app` factory
    # must NOT appear with its nested routes' reads aggregated into it. My first
    # version of this control asserted the opposite and failed — a control that
    # asserts a false thing would have masked a broken scan.
    assert reads.get("create_app", 0) == 0, (
        "nested route reads are leaking into the enclosing factory"
    )
    # The handler this file exists for now reads exactly once...
    assert reads.get("watchlist_detail") == 1, reads.get("watchlist_detail")
    # ...and the scan can still SEE a two-read handler, or the guard below
    # would pass by blindness rather than by correctness.
    assert reads.get("snooze_alert_post", 0) == 2, reads.get("snooze_alert_post")


def test_no_render_handler_reads_the_wall_clock_twice():
    """⛔ Fails on the next handler that classifies a row from two instants.

    Exempt handlers are listed with a written reason; an unlisted one has to be
    read and either fixed or justified."""
    reads = _clock_reads_per_function()
    offenders = {
        name: n
        for name, n in reads.items()
        if n > 1 and name not in _MULTI_READ_EXEMPT and name != "create_app"
    }
    assert offenders == {}, (
        "these read the wall clock more than once and are not exempt; two reads "
        f"can classify one row from two instants: {offenders}"
    )


def test_no_exemption_is_stale():
    """An exemption naming a handler that no longer reads twice is a comment
    claiming a guarantee about nothing."""
    reads = _clock_reads_per_function()
    stale = [n for n in _MULTI_READ_EXEMPT if reads.get(n, 0) <= 1]
    assert stale == [], f"these no longer read twice; drop the exemption: {stale}"


# --------------------------------------------------------------------------
# Behavioural. ⛔ An AST count proves how many reads exist; it cannot prove the
# page is consistent. This project has shipped that exact gap.
# --------------------------------------------------------------------------
def _detail_context(tmp_path, clock_values):
    warnings.filterwarnings("ignore")
    (tmp_path / "allowlist.yaml").write_text(
        f"entries:\n  - pattern: {MAC}\n    pattern_type: mac\n    expires_at: {T}\n"
    )
    db = Database(str(tmp_path / "lynceus.db"))
    wid, _ = db.add_watchlist(pattern=MAC, pattern_type="mac", severity="high")
    app = appmod.create_app(
        Config(db_path=str(tmp_path / "lynceus.db"),
               allowlist_path=str(tmp_path / "allowlist.yaml")),
        db,
    )
    captured: dict = {}
    orig = app.state.templates.TemplateResponse

    def spy(*a, **kw):
        if "context" in kw:
            captured.update(kw["context"])
        return orig(*a, **kw)

    app.state.templates.TemplateResponse = spy
    seq = iter(clock_values)
    real = appmod.time.time
    appmod.time.time = lambda: next(seq, float(T) + 100)
    try:
        with TestClient(app) as c:
            c.get(f"/watchlist/{wid}")
    finally:
        appmod.time.time = real
        db.close()
    return captured.get("entry_can_alert"), len(captured.get("allowlist_entries") or [])


@pytest.mark.parametrize(
    ("label", "clocks"),
    [
        ("both reads before expiry", [float(T) - 1, float(T) - 0.5, float(T) - 0.4]),
        ("both reads after expiry", [float(T) + 1, float(T) + 2, float(T) + 3]),
        ("reads straddle the expiry", [float(T) - 1, float(T) - 0.5, float(T) + 0.5]),
    ],
)
def test_the_detail_page_is_never_internally_contradictory(tmp_path, label, clocks):
    """`entry_can_alert is False` means "something is suppressing this row", so
    the covering-entry list must be non-empty. The impossible pair is
    `(False, 0)`: cannot alert, and nothing suppressing it."""
    can_alert, n_entries = _detail_context(tmp_path, clocks)
    assert not (can_alert is False and n_entries == 0), (
        f"{label}: page says the row cannot alert while showing no allowlist "
        "entry suppressing it"
    )


def test_the_detail_page_still_reports_a_real_suppression(tmp_path):
    """⛔ The control. Always returning `can_alert=True` would satisfy the test
    above while deleting the suppression readout entirely."""
    can_alert, n_entries = _detail_context(
        tmp_path, [float(T) - 10, float(T) - 10, float(T) - 10]
    )
    assert can_alert is False and n_entries == 1
