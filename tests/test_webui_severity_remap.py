"""The watchlist showed a severity the runtime layer had already re-decided.

Finding 42. ``watchlist.severity`` is what the importer baked in;
``rules._apply_runtime_overrides`` re-applies the overrides file at ALERT time
on top of it. Every watchlist surface rendered the stored column.

Measured on the rendered pages before any of this was built — one `mac` entry,
vendor "AcmeCorp", category "tracker", argus_record_id set, stored ``high``:

    device_category_severity: {tracker: low}   page said high, alert carried low
    vendor_severity: {acmecorp: low}           page said high, alert carried low
    pattern_overrides: {<argus id>: low}       page said high, alert carried low
    (no overrides file)                        page said high, alert carried high

⭐ **Three axes, not one.** The register recorded
``device_category_severity``; the same divergence exists on all three, and
`/watchlist.csv` -- the export that exists for offline triage -- carried the
stored value too.

⚠️ **Not "will it fire" but "at what severity".** That is why it reads as
cosmetic and is not: the severity column is the surface an operator triages,
sorts and filters on.

## What this suite is actually asserting

The interesting half is NOT "a badge appears". It is:

1. the rendered value is graded against what ``rules.evaluate`` ACTUALLY emits
   for a matching observation — the two sides are the template and the rules
   engine, never two copies of one table;
2. the STORED value stays visible, because the rendering decision was "show
   both", and a later simplification to "just render the effective value" would
   silently disagree with the severity filter and the CSV;
3. an install with no overrides file renders exactly what it rendered before —
   the over-correction shape, which costs more than the silence did;
4. a remap that maps to the severity already stored is NOT marked, because
   nothing is being hidden in that case.
"""

from __future__ import annotations

import logging
import re
import textwrap
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.kismet import DeviceObservation
from lynceus.rules import evaluate, load_ruleset, load_runtime_severity_overrides
from lynceus.webui.app import create_app
from lynceus.webui.liveness import (
    effective_severity,
    load_overrides,
    matching_remap_axes,
    severity_remap,
    severity_remap_axis,
    suppression_axes_of,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SHIPPED_RULES = REPO_ROOT / "config" / "rules.yaml"

MAC = "3c:5a:b4:dd:ee:01"
VENDOR = "AcmeCorp"
CATEGORY = "tracker"
ARGUS_ID = "a1b2c3d4e5f60718"
STORED = "high"


def test_this_suite_is_testing_the_tree_it_lives_in():
    """``pyproject``'s ``pythonpath = ["src"]`` pytest ini DEFEATS
    ``PYTHONPATH``, so pytest run from a worktree silently imports the PRIMARY
    checkout and every result here describes code that is not under review.
    """
    import lynceus.webui.liveness as under_test

    assert Path(under_test.__file__).resolve().is_relative_to(REPO_ROOT), (
        f"this suite lives in {REPO_ROOT} but imported lynceus from "
        f"{under_test.__file__} — run pytest with -o pythonpath=<worktree>/src"
    )


def _prose(html: str) -> str:
    return " ".join(re.sub(r"<!--.*?-->", " ", html, flags=re.S).split())


def _build(tmp_path, overrides_body: str | None, *, stored: str = STORED):
    allowlist = tmp_path / "allow.yaml"
    allowlist.write_text("entries: []\n", encoding="utf-8")
    overrides_path = None
    if overrides_body is not None:
        overrides_path = tmp_path / "severity_overrides.yaml"
        overrides_path.write_text(textwrap.dedent(overrides_body), encoding="utf-8")
    cfg = Config(
        db_path=str(tmp_path / "s.db"),
        # ⚠️ The SHIPPED ruleset, not a synthetic all-delegating one:
        # `watchlist_mac` is enabled with empty patterns there, so this row
        # really does fire on a default install and the measurement describes
        # what an operator has.
        rules_path=str(SHIPPED_RULES),
        allowlist_path=str(allowlist),
        severity_overrides_path=str(overrides_path) if overrides_path else None,
    )
    db = Database(cfg.db_path)
    db.ensure_location("default", "Default")
    wid, _ = db.add_watchlist(pattern=MAC, pattern_type="mac", severity=stored)
    db.upsert_metadata(
        wid,
        {
            "argus_record_id": ARGUS_ID,
            "vendor": VENDOR,
            "device_category": CATEGORY,
        },
    )
    return cfg, db, create_app(cfg, db), wid


def _emitted_severity(cfg, db) -> str | None:
    """What ``rules.evaluate`` ACTUALLY produces for a device matching the row.

    ⭐ This is the independent side of every comparison below. It reads the
    rules engine, not the module under test, so a remap the UI invents or misses
    shows up as a disagreement rather than as two copies of one answer.
    """
    obs = DeviceObservation(
        mac=MAC,
        device_type="wifi",
        first_seen=1_786_800_000,
        last_seen=1_786_800_000,
        rssi=-40,
        ssid=None,
        oui_vendor=None,
        is_randomized=False,
    )
    hits = evaluate(
        load_ruleset(cfg.rules_path),
        obs,
        False,
        db=db,
        severity_overrides=(
            load_runtime_severity_overrides(cfg.severity_overrides_path)
            if cfg.severity_overrides_path
            else None
        ),
    )
    return hits[0].severity if hits else None


def _row_badge(html: str) -> str:
    """The severity badge inside the watchlist row for MAC, and nothing else.

    ⚠️ Isolates the ELEMENT. `/watchlist` carries the words low/med/high in the
    severity filter dropdown, so a page-level search reports a severity that is
    not any row's.
    """
    rows = [r for r in re.findall(r"<tr>(.*?)</tr>", html, flags=re.S) if MAC in r]
    assert len(rows) == 1, f"expected exactly one row for {MAC}, got {len(rows)}"
    badges = re.findall(r'badge-(low|med|high)"', rows[0])
    assert badges, f"no severity badge in the row for {MAC}"
    return badges[0]


def _csv_effective(html: str) -> str:
    header, *lines = [ln for ln in html.splitlines() if ln.strip()]
    columns = header.split(",")
    row = [ln for ln in lines if MAC in ln]
    assert len(row) == 1, f"expected one CSV row for {MAC}, got {len(row)}"
    return dict(zip(columns, row[0].split(","), strict=True))["effective_severity"]


# --------------------------------------------------------------------------
# 1. The rendered value is graded against what the engine actually emits.
# --------------------------------------------------------------------------

REMAP_CASES = {
    "device_category_severity": f"device_category_severity:\n  {CATEGORY}: low\n",
    "vendor_severity": f"vendor_severity:\n  {VENDOR.lower()}: low\n",
    "pattern_overrides": f"pattern_overrides:\n  {ARGUS_ID}: low\n",
    # ⭐ The control, and it is not decoration: without it a UI that simply
    # printed "low" for every row would pass every case above.
    "(none configured)": None,
}


@pytest.mark.parametrize("case", sorted(REMAP_CASES))
def test_every_watchlist_surface_shows_the_severity_the_engine_emits(case, tmp_path):
    """⭐ The core guard for Finding 42, on all three surfaces at once.

    One side of the assertion is the rendered page / export; the other is
    ``rules.evaluate`` running against a real observation. A surface that
    reverts to the stored column fails here, and so does one that invents a
    remap the engine does not perform.
    """
    cfg, db, app, wid = _build(tmp_path, REMAP_CASES[case])
    try:
        emitted = _emitted_severity(cfg, db)
        assert emitted is not None, "fixture is broken: the row produced no alert"
        with TestClient(app) as client:
            listed = _row_badge(client.get("/watchlist").text)
            detail = client.get(f"/watchlist/{wid}").text
            csv_value = _csv_effective(client.get("/watchlist.csv").text)
    finally:
        db.close()

    assert listed == emitted, (
        f"[{case}] /watchlist renders severity {listed!r} for {MAC}, but an "
        f"alert for that device actually carries {emitted!r}"
    )
    detail_badges = re.findall(r'badge-(low|med|high)"', detail)
    assert detail_badges and detail_badges[0] == emitted, (
        f"[{case}] /watchlist/{wid} renders {detail_badges[:1]} but an alert "
        f"carries {emitted!r}"
    )
    assert csv_value == emitted, (
        f"[{case}] /watchlist.csv effective_severity={csv_value!r} but an alert "
        f"carries {emitted!r}"
    )


@pytest.mark.parametrize("case", sorted(set(REMAP_CASES) - {"(none configured)"}))
def test_the_stored_value_stays_visible_when_it_is_superseded(case, tmp_path):
    """The rendering decision, pinned.

    ⛔ The stored value is REAL — it is what `/watchlist.csv`'s `severity`
    column exports and what the severity filter matches on. Rendering only the
    effective value would make this page silently disagree with both, which is
    Finding 42 pointed in the other direction. Show both, or the decision has
    quietly been reversed.
    """
    cfg, db, app, wid = _build(tmp_path, REMAP_CASES[case])
    try:
        with TestClient(app) as client:
            listed = _prose(client.get("/watchlist").text)
            detail = _prose(client.get(f"/watchlist/{wid}").text)
    finally:
        db.close()

    assert f"stored <s>{STORED}</s>" in listed, (
        f"[{case}] /watchlist no longer shows the stored severity beside the "
        f"effective one; an operator comparing the page against the CSV or "
        f"filtering by severity now sees two surfaces disagree with no "
        f"explanation"
    )
    assert f"stored <s>{STORED}</s>" in detail, (
        f"[{case}] /watchlist/{wid} no longer shows the stored severity"
    )


def test_an_install_with_no_overrides_renders_exactly_what_it_did_before(tmp_path):
    """The over-correction control. A "superseded" marker on an install that
    configures no remap is a new false claim, and it would appear on every
    page for every operator who never touched the overrides file.
    """
    cfg, db, app, wid = _build(tmp_path, None)
    try:
        with TestClient(app) as client:
            listed = _prose(client.get("/watchlist").text)
            detail = _prose(client.get(f"/watchlist/{wid}").text)
    finally:
        db.close()

    for name, body in (("/watchlist", listed), ("/watchlist/{id}", detail)):
        assert "stored <s>" not in body, (
            f"{name} marks a severity superseded with no overrides file"
        )
        assert "alerts at a different severity" not in body, (
            f"{name} claims a remap on an install that configures none"
        )


def test_a_remap_to_the_severity_already_stored_is_not_marked(tmp_path):
    """A matching selector that maps to the value already stored changes
    nothing the operator receives, so marking it "superseded" would be a
    warning about a difference that does not exist.

    ⚠️ The engine is still consulted here — this asserts the two AGREE, which
    is the direction a "mark whenever a selector matches" implementation gets
    wrong.
    """
    cfg, db, app, wid = _build(
        tmp_path, f"device_category_severity:\n  {CATEGORY}: {STORED}\n"
    )
    try:
        assert _emitted_severity(cfg, db) == STORED
        with TestClient(app) as client:
            listed = _prose(client.get("/watchlist").text)
            detail = _prose(client.get(f"/watchlist/{wid}").text)
    finally:
        db.close()

    assert "stored <s>" not in listed
    assert "alerts at a different severity" not in detail


# --------------------------------------------------------------------------
# 2. A suppressed row has no effective severity — and rendering it logs nothing.
# --------------------------------------------------------------------------


def test_a_suppressed_row_reports_no_effective_severity(tmp_path):
    """``suppress_vendors`` means no alert at all, so there is no severity to
    receive. Reporting the remapped value beside "this row's alerts are
    discarded" would invite it to be read as what arrives.
    """
    cfg, db, app, wid = _build(
        tmp_path,
        f"""
        suppress_vendors: [{VENDOR.lower()}]
        device_category_severity:
          {CATEGORY}: low
        """,
    )
    try:
        assert _emitted_severity(cfg, db) is None, "fixture: the row still alerts"
        with TestClient(app) as client:
            csv_value = _csv_effective(client.get("/watchlist.csv").text)
            listed = _prose(client.get("/watchlist").text)
    finally:
        db.close()

    assert csv_value == "", (
        f"/watchlist.csv reports effective_severity={csv_value!r} for a row "
        f"whose alerts are suppressed entirely"
    )
    assert "stored <s>" not in listed


def test_rendering_a_suppressed_row_writes_no_alert_log(tmp_path, caplog):
    """⛔ ``_apply_runtime_overrides``' suppression branches emit an INFO line
    describing an alert being dropped at poll time. Reaching them from a page
    render would write that line once per suppressed row per page load — a log
    entry asserting an event that never happened, on a surface an operator
    reads to find out what IS happening.

    ``effective_severity`` returns before the engine call for suppressed rows,
    which makes that structural rather than a comment asking for care. This is
    the guard that keeps it structural.
    """
    cfg, db, app, wid = _build(tmp_path, f"suppress_vendors: [{VENDOR.lower()}]")
    try:
        with caplog.at_level(logging.INFO, logger="lynceus.rules"):
            with TestClient(app) as client:
                client.get("/watchlist")
                client.get(f"/watchlist/{wid}")
                client.get("/watchlist.csv")
    finally:
        db.close()

    offending = [r.getMessage() for r in caplog.records if "suppressing" in r.getMessage()]
    assert not offending, (
        f"rendering the watchlist wrote {len(offending)} alert-suppression log "
        f"line(s) — these describe alerts being dropped by the poller, and a "
        f"page render did not drop any: {offending[:3]}"
    )


# --------------------------------------------------------------------------
# 3. The named axis is the one the engine used, and the precedence is real.
# --------------------------------------------------------------------------

# Each case configures two or three axes with DISTINCT target severities, so the
# severity the engine emits identifies which axis won — the winner is read out
# of the engine's answer, not out of the module under test.
PRECEDENCE_CASES = {
    "row beats vendor": (
        f"pattern_overrides:\n  {ARGUS_ID}: low\nvendor_severity:\n  {VENDOR.lower()}: med\n",
        "pattern_overrides",
        "low",
    ),
    "row beats category": (
        f"pattern_overrides:\n  {ARGUS_ID}: low\ndevice_category_severity:\n  {CATEGORY}: med\n",
        "pattern_overrides",
        "low",
    ),
    "vendor beats category": (
        f"vendor_severity:\n  {VENDOR.lower()}: low\n"
        f"device_category_severity:\n  {CATEGORY}: med\n",
        "vendor_severity",
        "low",
    ),
    "all three": (
        f"pattern_overrides:\n  {ARGUS_ID}: low\n"
        f"vendor_severity:\n  {VENDOR.lower()}: med\n"
        f"device_category_severity:\n  {CATEGORY}: med\n",
        "pattern_overrides",
        "low",
    ),
}


@pytest.mark.parametrize("case", sorted(PRECEDENCE_CASES))
def test_the_named_axis_is_the_one_the_engine_actually_used(case, tmp_path):
    """Every case gives its axes DIFFERENT target severities, so the value the
    engine emits says which one won. The page names an axis; this asserts the
    engine agrees.

    ⭐ Without the distinct values this would be two readings of one dict. With
    them, a precedence written the wrong way round here produces a name that
    contradicts the severity the engine chose.
    """
    body, expected_axis, expected_severity = PRECEDENCE_CASES[case]
    cfg, db, app, wid = _build(tmp_path, body)
    try:
        emitted = _emitted_severity(cfg, db)
        overrides = load_overrides(cfg)
        named = severity_remap_axis(VENDOR, CATEGORY, ARGUS_ID, overrides)
    finally:
        db.close()

    assert emitted == expected_severity, (
        f"[{case}] the engine emitted {emitted!r}; this case was built so that "
        f"{expected_severity!r} identifies {expected_axis}. The engine's "
        f"precedence has changed and this suite's model of it is stale."
    )
    assert named is not None and named[0] == expected_axis, (
        f"[{case}] the page would name {named!r} as the override in force, but "
        f"the engine emitted {emitted!r}, which is the value configured under "
        f"{expected_axis}"
    )


@pytest.mark.parametrize("case", sorted(PRECEDENCE_CASES))
def test_every_engine_remap_can_be_attributed_to_an_axis(case, tmp_path):
    """Whenever the engine changes the severity, the UI can say WHICH entry did
    it. A remap the module cannot attribute renders as "a severity override" —
    honest, but it means ``severity_remap_axis`` has drifted from
    ``_apply_runtime_overrides``, so it must be unreachable.
    """
    body, _, _ = PRECEDENCE_CASES[case]
    cfg, db, app, wid = _build(tmp_path, body)
    try:
        emitted = _emitted_severity(cfg, db)
        overrides = load_overrides(cfg)
        suppressions = suppression_axes_of(overrides)
        remap = severity_remap(
            STORED, VENDOR, CATEGORY, ARGUS_ID, suppressions, overrides
        )
    finally:
        db.close()

    assert emitted != STORED, "fixture: this case does not remap anything"
    assert remap is not None and remap["axis"] is not None, (
        f"[{case}] the engine remapped {STORED} -> {emitted} and no override "
        f"axis was attributed"
    )
    assert remap["effective"] == emitted


def test_when_two_entries_match_the_page_does_not_promise_the_stored_value_back(
    tmp_path,
):
    """🪤 The first draft said "removing that entry from the overrides file
    restores <stored>". With two axes matching, removing the winner hands the
    row to the NEXT TIER — measured here with the engine, not asserted from the
    template — so the operator would edit the file and watch a third value
    appear. A page that states a cause it has not established is the same
    defect class as an error message that does (#106).
    """
    both = (
        f"vendor_severity:\n  {VENDOR.lower()}: low\n"
        f"device_category_severity:\n  {CATEGORY}: med\n"
    )
    cfg, db, app, wid = _build(tmp_path, both)
    try:
        assert _emitted_severity(cfg, db) == "low", "fixture: vendor should win"
        overrides = load_overrides(cfg)
        assert len(matching_remap_axes(VENDOR, CATEGORY, ARGUS_ID, overrides)) == 2
        with TestClient(app) as client:
            detail = _prose(client.get(f"/watchlist/{wid}").text)
    finally:
        db.close()

    # And the measurement the prose rests on: drop the winning entry, ask the
    # engine again, and confirm it lands on the next tier rather than on the
    # stored value.
    next_tier = tmp_path / "next"
    next_tier.mkdir()
    cfg2, db2, _app2, _wid2 = _build(
        next_tier, f"device_category_severity:\n  {CATEGORY}: med\n"
    )
    try:
        assert _emitted_severity(cfg2, db2) == "med"
    finally:
        db2.close()

    assert "hands it to the next entry" in detail, (
        "the detail page promises the stored severity back when a second "
        "override entry would take over"
    )
    assert f"restores <code>{STORED}</code>" not in detail


def test_when_one_entry_matches_the_page_does_promise_the_stored_value_back(tmp_path):
    """The other half of the pair. Without this, hardcoding the "more than one"
    wording would pass the test above forever.
    """
    cfg, db, app, wid = _build(tmp_path, f"vendor_severity:\n  {VENDOR.lower()}: low\n")
    try:
        with TestClient(app) as client:
            detail = _prose(client.get(f"/watchlist/{wid}").text)
    finally:
        db.close()

    assert f"restores <code>{STORED}</code>" in detail
    assert "hands it to the next entry" not in detail


# --------------------------------------------------------------------------
# 4. The severity filter is declared, not silently redefined.
# --------------------------------------------------------------------------

CAVEAT = "This filter matches the severity <strong>stored</strong> on each entry"


# 🪤 The third value is not padding. With only "a remap file" and "no file at
# all", `has_configured_remap` could be written `overrides is not None` and
# every case would still pass — a planted defect that did exactly that
# SURVIVED, because no fixture distinguished "no overrides file" from "an
# overrides file that configures no remap". The suppress-only file is the case
# that separates them.
OVERRIDE_FILES = {
    "remap configured": f"device_category_severity:\n  {CATEGORY}: low\n",
    "suppression only": f"suppress_vendors: [{VENDOR.lower()}]\n",
    "no file at all": None,
}


@pytest.mark.parametrize(
    ("filtering", "overrides_case", "expected"),
    [
        (True, "remap configured", True),
        (True, "suppression only", False),
        (True, "no file at all", False),
        (False, "remap configured", False),
        (False, "suppression only", False),
        (False, "no file at all", False),
    ],
)
def test_the_stored_severity_caveat_appears_only_where_it_can_mislead(
    filtering, overrides_case, expected, tmp_path
):
    """⭐ A take-effect pair in both variables. The filter cannot be made
    remap-aware without applying the override layer to every row in the table
    on every request — the full-table scan #111 refused — so it is DECLARED
    instead. Declared in the one place it can mislead: a page that carried this
    notice unconditionally would teach operators to scroll past it.
    """
    cfg, db, app, wid = _build(tmp_path, OVERRIDE_FILES[overrides_case])
    try:
        with TestClient(app) as client:
            url = f"/watchlist?severity={STORED}" if filtering else "/watchlist"
            body_html = _prose(client.get(url).text)
    finally:
        db.close()

    present = CAVEAT in body_html
    assert present is expected, (
        f"filtering={filtering} overrides={overrides_case!r}: expected the "
        f"stored-severity caveat {'shown' if expected else 'absent'}, got "
        f"{'shown' if present else 'absent'}"
    )


# --------------------------------------------------------------------------
# 5. /settings names the remap selectors it had been silent about.
# --------------------------------------------------------------------------

SETTINGS_NOTE = "Your severity overrides rewrite the severity of some alerts."


def test_settings_names_the_configured_remap_selectors(tmp_path):
    """`/settings` listed the keys that SILENCE and said nothing about the three
    that rewrite severity, so a row alerting at a severity other than the one
    stored against it had no page anywhere admitting it.

    ⚠️ Asserts the SELECTOR is named, not a count of affected rows — counting
    means scanning 17k+ rows on every page load.
    """
    cfg, db, app, wid = _build(
        tmp_path,
        f"device_category_severity:\n  {CATEGORY}: low\n"
        f"vendor_severity:\n  {VENDOR.lower()}: med\n",
    )
    try:
        with TestClient(app) as client:
            settings = _prose(client.get("/settings").text)
    finally:
        db.close()

    assert SETTINGS_NOTE in settings
    assert f"<code>{CATEGORY}</code>&rarr;<code>low</code>" in settings
    assert f"<code>{VENDOR.lower()}</code>&rarr;<code>med</code>" in settings


def test_settings_says_nothing_when_no_remap_is_configured(tmp_path):
    """The other half. A note that renders whatever the file contains is not a
    report about the file.
    """
    cfg, db, app, wid = _build(tmp_path, f"suppress_vendors: [{VENDOR.lower()}]\n")
    try:
        with TestClient(app) as client:
            settings = _prose(client.get("/settings").text)
    finally:
        db.close()

    assert SETTINGS_NOTE not in settings


def test_effective_severity_passes_through_when_no_overrides_are_loaded():
    """The fast path, asserted directly: no overrides object means the stored
    value is the answer, byte-identical to pre-override behaviour.
    """
    assert (
        effective_severity(STORED, VENDOR, CATEGORY, ARGUS_ID, {"configured": False}, None)
        == STORED
    )
