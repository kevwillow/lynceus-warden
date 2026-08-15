"""A severity override silences an individual watchlist entry, and nothing said so.

Finding 39. ``rules._apply_runtime_overrides`` returns ``None`` for a match whose
manufacturer is in ``suppress_vendors`` or whose category is in
``suppress_categories``, and every delegation branch then emits nothing.

Measured before any of this was built — one `mac` entry, vendor "AcmeCorp",
category "tracker", matching device observed:

    no overrides file               -> 1 alert
    suppress_vendors: [acmecorp]    -> 0 alerts
    suppress_categories: [tracker]  -> 0 alerts

...and the liveness report said ``live_count=1`` in all three. Live on any
install using overrides today.

⭐ **This cause is PER ROW**, unlike inert (no delegating rule) and snoozed (a
rule_type snooze) — both of which are properties of the pattern_type. An entry
can be perfectly live at the type level and still have every alert discarded
because of its vendor. So it is rendered as an independent marker, not another
branch of the same chain.

⛔ Deliberately no row COUNT on /settings or /healthz.json. Counting affected
rows means scanning the whole watchlist — 17k+ rows on an Argus install — on
every page load, with no indexed vendor filter to do it cheaply. The suppressed
vendors/categories are named instead, and the rows themselves are marked where
they are already loaded, which also answers *which*.
"""

from __future__ import annotations

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
    is_row_suppressed_by_overrides,
    runtime_suppressions,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SHIPPED_RULES = REPO_ROOT / "config" / "rules.yaml"

SUPPRESSED_MAC = "3c:5a:b4:dd:ee:01"
HEALTHY_MAC = "3c:5a:b4:dd:ee:02"
VENDOR = "AcmeCorp"
CATEGORY = "tracker"

BADGE = "badge-snoozed-type"
DETAIL_NOTE = "a severity override drops its alerts"
SETTINGS_NOTE = "configured to silence"


def test_this_suite_is_testing_the_tree_it_lives_in():
    import lynceus.webui.liveness as under_test

    assert Path(under_test.__file__).resolve().is_relative_to(REPO_ROOT)


def _prose(html: str) -> str:
    return " ".join(re.sub(r"<!--.*?-->", " ", html, flags=re.S).split())


def _overrides_file(tmp_path, body: str | None) -> str | None:
    if body is None:
        return None
    path = tmp_path / "severity_overrides.yaml"
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return str(path)


def _build(tmp_path, overrides_body: str | None):
    allowlist = tmp_path / "allow.yaml"
    allowlist.write_text("entries: []\n", encoding="utf-8")
    cfg = Config(
        db_path=str(tmp_path / "s.db"),
        rules_path=str(SHIPPED_RULES),
        allowlist_path=str(allowlist),
        severity_overrides_path=_overrides_file(tmp_path, overrides_body),
    )
    db = Database(cfg.db_path)
    db.ensure_location("default", "Default")
    sup_id, _ = db.add_watchlist(
        pattern=SUPPRESSED_MAC, pattern_type="mac", severity="high"
    )
    db.upsert_metadata(
        sup_id,
        {"argus_record_id": "A-1", "vendor": VENDOR, "device_category": CATEGORY},
    )
    ok_id, _ = db.add_watchlist(
        pattern=HEALTHY_MAC, pattern_type="mac", severity="high"
    )
    db.upsert_metadata(
        ok_id,
        {"argus_record_id": "A-2", "vendor": "Innocent Ltd", "device_category": "phone"},
    )
    return cfg, db, create_app(cfg, db), sup_id, ok_id


def _observe(db, cfg, mac: str) -> int:
    """How many alerts the rules engine actually emits for this device."""
    obs = DeviceObservation(
        mac=mac,
        device_type="wifi",
        first_seen=1_786_800_000,
        last_seen=1_786_800_000,
        rssi=-40,
        ssid=None,
        oui_vendor=None,
        is_randomized=False,
    )
    overrides = load_runtime_severity_overrides(cfg.severity_overrides_path)
    return len(
        evaluate(
            load_ruleset(SHIPPED_RULES), obs, False, db=db, severity_overrides=overrides
        )
    )


# --------------------------------------------------------------------------
# 1. The marker is graded against what the rules engine actually does.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "overrides_body"),
    [
        ("none", None),
        ("vendor", "suppress_vendors:\n  - acmecorp\n"),
        ("category", "suppress_categories:\n  - tracker\n"),
        ("unrelated", "suppress_vendors:\n  - someoneelse\n"),
    ],
)
def test_the_marker_agrees_with_whether_an_alert_actually_fires(
    tmp_path, label, overrides_body
):
    """⭐ The assertion that makes the marker worth rendering.

    One side is ``is_row_suppressed_by_overrides``; the other is
    ``rules.evaluate`` running against a real observation with the real loaded
    overrides. A marker that used different normalisation, read the wrong field,
    or drifted from the engine fails here — and marking a row silenced when it
    is not is as bad as missing one, because the operator would go and edit an
    override that was not the reason.
    """
    cfg, db, _app, sup_id, ok_id = _build(tmp_path, overrides_body)
    try:
        suppressions = runtime_suppressions(cfg)
        marked = is_row_suppressed_by_overrides(VENDOR, CATEGORY, suppressions)
        fired = _observe(db, cfg, SUPPRESSED_MAC)

        assert marked == (fired == 0), (
            f"[{label}] marker says suppressed={marked} but evaluate() emitted "
            f"{fired} alert(s) for the same row and the same overrides"
        )

        # The control row, every time: an unrelated entry must keep alerting
        # whatever the overrides say, or the contrast above proves nothing.
        assert _observe(db, cfg, HEALTHY_MAC) == 1, (
            "the control entry stopped alerting; the experiment is void"
        )
        assert not is_row_suppressed_by_overrides(
            "Innocent Ltd", "phone", suppressions
        )
    finally:
        db.close()


def test_vendor_matching_uses_the_engines_normalisation(tmp_path):
    """``_apply_runtime_overrides`` compares ``vendor.strip().lower()``. A
    marker using different rules would flag rows the engine does not suppress
    and miss rows it does."""
    cfg, db, _app, _s, _o = _build(
        tmp_path, "suppress_vendors:\n  - acmecorp\n"
    )
    try:
        sup = runtime_suppressions(cfg)
        for spelling in ("AcmeCorp", "  acmecorp  ", "ACMECORP"):
            assert is_row_suppressed_by_overrides(spelling, None, sup), spelling
        assert not is_row_suppressed_by_overrides("acmecorpX", None, sup)
    finally:
        db.close()


def test_category_matching_is_NOT_normalised_because_the_engine_does_not(tmp_path):
    """⚠️ Asymmetric on purpose. The engine lower-cases the vendor and compares
    the category raw, so this must too. Pinned because "make them consistent"
    is the obvious wrong tidy-up."""
    cfg, db, _app, _s, _o = _build(tmp_path, "suppress_categories:\n  - tracker\n")
    try:
        sup = runtime_suppressions(cfg)
        assert is_row_suppressed_by_overrides(None, "tracker", sup)
        assert not is_row_suppressed_by_overrides(None, "Tracker", sup), (
            "category matching became case-insensitive here but not in "
            "rules._apply_runtime_overrides -- the marker now disagrees with "
            "the engine"
        )
    finally:
        db.close()


def test_no_overrides_configured_marks_nothing(tmp_path):
    cfg, db, _app, _s, _o = _build(tmp_path, None)
    try:
        sup = runtime_suppressions(cfg)
        assert sup["configured"] is False
        assert not is_row_suppressed_by_overrides(VENDOR, CATEGORY, sup)
    finally:
        db.close()


# --------------------------------------------------------------------------
# 2. The shape trap that actually bit, pinned.
# --------------------------------------------------------------------------


def test_both_row_shapes_the_two_routes_hand_over_are_marked(tmp_path):
    """🪤 The bug this test exists for, and the reason it now drives the ROUTES.

    ``/watchlist`` hands over a ``WatchlistRow`` NamedTuple; ``/watchlist/{id}``
    hands over a dict. The first marker took "a row" and read it via
    ``row.get(...)`` behind ``hasattr(row, "get")`` — so the NamedTuple silently
    answered "not suppressed". The detail page marked rows correctly, the list
    page marked nothing, and **nothing raised**.

    ⛔ The first version of THIS test called the helper directly with manually
    extracted properties — so it would have passed with the route wiring still
    broken, which is precisely the defect it is named for. A cold read caught
    that. It now asserts through both rendered responses.
    """
    cfg, db, app, sup_id, ok_id = _build(
        tmp_path, "suppress_vendors:\n  - acmecorp\n"
    )
    try:
        with TestClient(app) as client:
            list_page = client.get("/watchlist").text
            detail = _prose(client.get(f"/watchlist/{sup_id}").text)
    finally:
        db.close()

    assert ">override<" in _row_html(list_page, sup_id), (
        "the LIST route (WatchlistRow NamedTuple) does not mark the row"
    )
    assert DETAIL_NOTE in detail, "the DETAIL route (dict) does not mark the row"


def test_the_engine_null_semantics_are_matched_exactly(tmp_path):
    """⚠️ ``_apply_runtime_overrides`` tests ``is not None``, not truthiness,
    and the loader ADMITS ``""`` into ``suppress_categories`` — measured. A
    truthiness check here would skip a row whose category is ``""`` and mark it
    live while the engine discards every alert it produces."""
    cfg, db, _app, _s, _o = _build(tmp_path, 'suppress_categories:\n  - ""\n')
    try:
        sup = runtime_suppressions(cfg)
        assert "" in sup["categories"], (
            "the loader no longer admits an empty category; if that is "
            "deliberate this test can go, but check the engine agrees"
        )
        assert is_row_suppressed_by_overrides(None, "", sup), (
            "an empty-string category is suppressed by the engine and missed here"
        )
        assert not is_row_suppressed_by_overrides(None, None, sup), (
            "a row with NO category must not be swept up by an empty selector"
        )
    finally:
        db.close()


def test_the_reason_names_the_axis_that_actually_matched(tmp_path):
    """Only one axis may match. Reporting the other sends the operator to
    remove a suppression that had nothing to do with it."""
    from lynceus.webui.liveness import override_suppression_reason

    cfg, db, _app, _s, _o = _build(tmp_path, "suppress_vendors:\n  - acmecorp\n")
    try:
        sup = runtime_suppressions(cfg)
        assert override_suppression_reason(VENDOR, CATEGORY, sup) == "vendor"
        assert override_suppression_reason(None, CATEGORY, sup) is None
    finally:
        db.close()

    cfg, db, _app, _s, _o = _build(tmp_path, "suppress_categories:\n  - tracker\n")
    try:
        sup = runtime_suppressions(cfg)
        assert override_suppression_reason(VENDOR, CATEGORY, sup) == "category"
        assert override_suppression_reason(VENDOR, None, sup) is None
    finally:
        db.close()


# --------------------------------------------------------------------------
# 3. The rendered surfaces. Both shapes, every time.
# --------------------------------------------------------------------------


def _row_html(page: str, watchlist_id: int) -> str:
    match = re.search(
        r'/watchlist/' + str(watchlist_id) + r'".{0,600}?</tr>', _prose(page)
    )
    assert match, f"row {watchlist_id} not found in the rendered table"
    return match.group(0)


def test_the_suppressed_row_is_badged_and_the_healthy_one_is_not(tmp_path):
    cfg, db, app, sup_id, ok_id = _build(
        tmp_path, "suppress_vendors:\n  - acmecorp\n"
    )
    try:
        with TestClient(app) as client:
            page = client.get("/watchlist").text
    finally:
        db.close()

    assert ">override<" in _row_html(page, sup_id)
    assert ">override<" not in _row_html(page, ok_id), (
        "an entry no override touches is marked; the operator would go editing "
        "a suppression that is not the reason"
    )


def test_the_detail_page_explains_it_for_the_suppressed_entry_only(tmp_path):
    cfg, db, app, sup_id, ok_id = _build(
        tmp_path, "suppress_categories:\n  - tracker\n"
    )
    try:
        with TestClient(app) as client:
            suppressed = _prose(client.get(f"/watchlist/{sup_id}").text)
            healthy = _prose(client.get(f"/watchlist/{ok_id}").text)
    finally:
        db.close()

    assert suppressed.count(DETAIL_NOTE) == 1
    assert CATEGORY in suppressed, "the note does not name the matching value"
    assert DETAIL_NOTE not in healthy


def test_settings_names_the_suppressed_vendors_and_categories(tmp_path):
    cfg, db, app, _s, _o = _build(
        tmp_path,
        "suppress_vendors:\n  - acmecorp\nsuppress_categories:\n  - tracker\n",
    )
    try:
        with TestClient(app) as client:
            body = _prose(client.get("/settings").text)
    finally:
        db.close()

    assert body.count(SETTINGS_NOTE) == 1
    assert "acmecorp" in body
    assert "tracker" in body


@pytest.mark.parametrize("path_kind", ["list", "detail", "settings"])
def test_nothing_is_said_when_no_override_suppresses_anything(tmp_path, path_kind):
    """⭐ The over-correction shape. A marker on every install is one an
    operator learns to ignore — and here it would be false."""
    cfg, db, app, sup_id, _o = _build(tmp_path, None)
    try:
        with TestClient(app) as client:
            if path_kind == "list":
                body = _prose(client.get("/watchlist").text)
            elif path_kind == "detail":
                body = _prose(client.get(f"/watchlist/{sup_id}").text)
            else:
                body = _prose(client.get("/settings").text)
    finally:
        db.close()

    assert ">override<" not in body
    assert DETAIL_NOTE not in body
    assert SETTINGS_NOTE not in body


def test_an_overrides_file_with_no_suppressions_says_nothing(tmp_path):
    """Configured but empty is not the same as suppressing. An operator who uses
    overrides only for severity REMAPS must see no suppression notice."""
    cfg, db, app, sup_id, _o = _build(
        tmp_path, "device_category_severity:\n  tracker: high\n"
    )
    try:
        sup = runtime_suppressions(cfg)
        with TestClient(app) as client:
            body = _prose(client.get("/settings").text)
    finally:
        db.close()

    assert sup["vendors"] == ()
    assert sup["categories"] == ()
    assert SETTINGS_NOTE not in body


# --------------------------------------------------------------------------
# 4. The export. #109's rule applied to this change: does the fix sit on
#    EVERY path that reaches the mechanism?
# --------------------------------------------------------------------------


def _csv_rows(client):
    import csv as _csv
    import io as _io

    return list(_csv.reader(_io.StringIO(client.get("/watchlist.csv").text)))


def test_the_csv_reports_override_in_its_OWN_column(tmp_path):
    """🪤 Two fixes, and a cold read caught the second.

    `can_fire` first answered from the TYPE-level verdict alone, so it said
    `yes` for a row an override silences. The first fix made `override` a fifth
    enum value — which merely traded one wrong answer for another: the checks
    run in order, so an **inert AND override-suppressed** row reported `no`,
    and an operator who then fixed `rules.yaml` would still hear nothing.

    ⇒ A single enum cannot carry two INDEPENDENT causes. `can_fire` stays
    type-level; `override_suppressed` is its own column.
    """
    cfg, db, app, sup_id, ok_id = _build(
        tmp_path, "suppress_vendors:\n  - acmecorp\n"
    )
    try:
        with TestClient(app) as client:
            rows = _csv_rows(client)
    finally:
        db.close()

    header, data = rows[0], rows[1:]
    idx = {n: header.index(n) for n in ("id", "can_fire", "override_suppressed")}
    by_id = {int(r[idx["id"]]): r for r in data}

    assert by_id[sup_id][idx["override_suppressed"]] == "yes"
    assert by_id[sup_id][idx["can_fire"]] == "yes", (
        "can_fire must stay the TYPE-level verdict -- this row's type is live"
    )
    assert by_id[ok_id][idx["override_suppressed"]] == "no"


def test_the_csv_carries_BOTH_causes_for_a_row_that_has_both(tmp_path):
    """⭐ The case a single enum could not express, and the reason for the
    split. An `oui` row is inert (no delegating rule) AND override-suppressed:
    the export must say both, because fixing only one changes nothing."""
    cfg, db, app, _sup, _ok = _build(
        tmp_path, "suppress_vendors:\n  - acmecorp\n"
    )
    try:
        both_id, _ = db.add_watchlist(
            pattern="ac:de:48", pattern_type="oui", severity="high"
        )
        db.upsert_metadata(
            both_id,
            {"argus_record_id": "A-3", "vendor": VENDOR, "device_category": "phone"},
        )
        with TestClient(app) as client:
            rows = _csv_rows(client)
    finally:
        db.close()

    header, data = rows[0], rows[1:]
    idx = {n: header.index(n) for n in ("id", "can_fire", "override_suppressed")}
    row = next(r for r in data if int(r[idx["id"]]) == both_id)

    assert row[idx["can_fire"]] == "no", "the type-level cause is lost"
    assert row[idx["override_suppressed"]] == "yes", "the per-row cause is lost"


def test_the_csv_still_reports_the_type_level_verdicts(tmp_path):
    """The per-row cause must not shadow the two type-level ones — `inert`
    stays `no`, and a row with no overrides configured stays `yes`."""
    cfg, db, app, _sup, ok_id = _build(tmp_path, None)
    try:
        inert_id, _ = db.add_watchlist(
            pattern="ac:de:48", pattern_type="oui", severity="high"
        )
        with TestClient(app) as client:
            rows = _csv_rows(client)
    finally:
        db.close()

    header, data = rows[0], rows[1:]
    idx = {name: header.index(name) for name in ("id", "can_fire")}
    verdicts = {int(r[idx["id"]]): r[idx["can_fire"]] for r in data}

    assert verdicts[inert_id] == "no"
    assert verdicts[ok_id] == "yes"


def test_a_configured_suppression_that_matches_nothing_marks_no_rows(tmp_path):
    """⚠️ The case behind the /settings wording. A selector naming a vendor
    nobody has is configured but affects nothing — so the page may say a
    suppression is CONFIGURED and must not say entries are silenced."""
    cfg, db, app, sup_id, ok_id = _build(
        tmp_path, "suppress_vendors:\n  - nobody-has-this-vendor\n"
    )
    try:
        with TestClient(app) as client:
            settings = _prose(client.get("/settings").text)
            list_page = client.get("/watchlist").text
    finally:
        db.close()

    assert SETTINGS_NOTE in settings, "a configured selector should still be surfaced"
    assert ">override<" not in _row_html(list_page, sup_id), (
        "a row nothing matches is marked; the operator would go editing a "
        "suppression that is not the reason"
    )
    assert ">override<" not in _row_html(list_page, ok_id)
