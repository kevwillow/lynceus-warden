"""Four surfaces that promised the operator something they could not get.

Each is measured rather than reasoned about: the page is rendered and read.

1. The home page's alerts tile said **"none unacknowledged"** beside the count
   of unacknowledged alerts, because the note was chosen from the 30-day
   high-severity count alone.
2. ``/settings`` and ``/watchlist`` said *"you snoozed `ssid` — lift it on the
   rules page"*, naming a **pattern type**; ``/rules`` is keyed on **rule type**
   and offers no control called ``ssid``.
3. "Remove from allowlist" was offered for a UI-file entry of **any** shape,
   while both remove endpoints delete an exact ``mac`` entry — so for an ``oui``
   entry the click returned a success redirect and changed nothing.
4. ``/settings`` rendered the user-scope **default** config path under a heading
   calling the page a view of the *active* configuration.

⭐ Every one of these asserts the CONTROL as well as the treatment: the tile
still says "none unacknowledged" when nothing is unacknowledged, the button is
still offered (and still works) for the exact-MAC entry it can remove, and the
operator-managed hint is unchanged for a primary-file entry. A fix in this class
is only half done until the case it must NOT change is pinned.
"""

from __future__ import annotations

import re
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from lynceus.allowlist import AllowlistEntry, add_ui_entry, derive_ui_path
from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import create_app
from lynceus.webui.csrf import CSRF_COOKIE_NAME, CSRF_FORM_FIELD

MAC = "aa:bb:cc:dd:ee:ff"


def _prose(html: str) -> str:
    return " ".join(html.split())


# ---------------------------------------------------------------------------
# 1. The alerts tile
# ---------------------------------------------------------------------------


def _app_with_alerts(tmp_path, *, medium: int = 0, high: int = 0):
    config = Config(db_path=str(tmp_path / "ui.db"))
    db = Database(config.db_path)
    now = int(time.time())
    for i in range(medium + high):
        mac = f"aa:bb:cc:dd:ee:{i:02x}"
        db.upsert_device(mac, "wifi", None, 0, now)
        db.add_alert(
            ts=now,
            rule_name="r",
            mac=mac,
            message="m",
            severity="high" if i < high else "med",
        )
    return create_app(config, db), db


def _alerts_tile(html: str) -> str:
    match = re.search(r'<a class="nav-tile[^"]*" href="/alerts">.*?</a>', _prose(html))
    assert match, "the alerts tile is not on the page"
    return re.sub(r"<[^>]+>", " ", match.group(0))


@pytest.mark.webui
def test_alerts_tile_does_not_deny_the_count_it_is_showing(tmp_path):
    """🪤 Seven unacknowledged mediums rendered `alerts | 7 | none unacknowledged`.

    The tile's accessible name — which the template's own note calls the whole
    reason the tile exists — was "alerts, 7, none unacknowledged". The colour
    was already correct, which is how this survived being looked at.
    """
    app, db = _app_with_alerts(tmp_path, medium=7)
    try:
        with TestClient(app) as client:
            tile = _alerts_tile(client.get("/").text)
    finally:
        db.close()
    assert "7" in tile, f"the tile is not showing the count at all: {tile!r}"
    assert "none unacknowledged" not in tile, (
        f"the tile denies the count beside it: {tile!r}"
    )


@pytest.mark.webui
def test_alerts_tile_still_says_none_when_none_are_unacknowledged(tmp_path):
    """The control. "none unacknowledged" is correct here and must survive."""
    app, db = _app_with_alerts(tmp_path)
    try:
        with TestClient(app) as client:
            tile = _alerts_tile(client.get("/").text)
    finally:
        db.close()
    assert "none unacknowledged" in tile, tile


@pytest.mark.webui
def test_alerts_tile_leads_with_the_high_severity_count(tmp_path):
    """The second control: a high-severity headline still wins the note."""
    app, db = _app_with_alerts(tmp_path, medium=2, high=3)
    try:
        with TestClient(app) as client:
            tile = _alerts_tile(client.get("/").text)
    finally:
        db.close()
    assert "high in 30d" in tile, tile
    assert "none unacknowledged" not in tile, tile


# ---------------------------------------------------------------------------
# 2. The snooze remedy names an identifier /rules actually offers
# ---------------------------------------------------------------------------


def _app_with_snoozed_ssid(tmp_path):
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "rules:\n"
        "  - name: ssid_watch\n"
        "    rule_type: watchlist_ssid\n"
        "    enabled: true\n"
        "    severity: med\n",
        encoding="utf-8",
    )
    config = Config(db_path=str(tmp_path / "ui.db"), rules_path=str(rules))
    db = Database(config.db_path)
    db.add_watchlist(
        pattern="HomeNet", pattern_type="ssid", severity="high", description="d"
    )
    now = int(time.time())
    db.add_rule_type_snooze("watchlist_ssid", now + 3600, now)
    return create_app(config, db), db


def _identifiers_named_in(sentence: str) -> list[str]:
    """The `<code>` values inside a rendered sentence, in order."""
    return re.findall(r"<code>([^<]+)</code>", sentence)


@pytest.mark.webui
@pytest.mark.parametrize(
    "route,needle",
    [
        ("/settings", r"You silenced.{0,400}?rules page</a>"),
        ("/watchlist", r"you snoozed.{0,400}?rules page"),
    ],
)
def test_the_snooze_remedy_names_something_the_rules_page_offers(
    tmp_path, route, needle
):
    """⛔ Derived from the page, not transcribed.

    Whatever identifier the sentence names, ``/rules`` must carry an unsnooze
    control for it. Asserting the literal ``watchlist_ssid`` would pass on a
    page that names it and a ``/rules`` that has since stopped offering it.
    """
    app, db = _app_with_snoozed_ssid(tmp_path)
    try:
        with TestClient(app) as client:
            page = _prose(client.get(route).text)
            rules_page = _prose(client.get("/rules").text)
    finally:
        db.close()

    match = re.search(needle, page)
    assert match, f"{route} did not render the snooze remedy at all"
    named = _identifiers_named_in(match.group(0))
    assert named, f"{route} named no identifier: {match.group(0)!r}"
    # The FIRST identifier is the thing to lift; any others are what it serves.
    to_lift = named[0]
    offered = sorted(set(re.findall(r'action="/rules/([^/]+)/unsnooze"', rules_page)))
    assert f'action="/rules/{to_lift}/unsnooze"' in rules_page, (
        f"{route} sends the operator to /rules to lift {to_lift!r}, which that "
        f"page offers no control for. It offers: {offered}"
    )


def test_every_snoozeable_rule_type_can_be_named_in_the_remedy(tmp_path):
    """The sentence must never render with a blank where the identifier goes.

    ⭐ Iterated over ``RULE_TYPE_DELEGATES_TO`` rather than a copied list, so a
    rule type added to the map is covered the day it lands. A hand-written set
    would look derived and would not be.
    """
    from lynceus.webui.liveness import RULE_TYPE_DELEGATES_TO, watchlist_liveness

    rules = tmp_path / "rules.yaml"
    rules.write_text("rules: []\n", encoding="utf-8")
    config = Config(db_path=str(tmp_path / "ui.db"), rules_path=str(rules))
    db = Database(config.db_path)
    now = int(time.time())
    try:
        assert RULE_TYPE_DELEGATES_TO, "the map is empty; this test proves nothing"
        for rule_type, pattern_types in RULE_TYPE_DELEGATES_TO.items():
            if not pattern_types:
                continue
            db.add_rule_type_snooze(rule_type, now + 3600, now)
            liveness = watchlist_liveness(
                config,
                {pt: 1 for pt in pattern_types},
                db=db,
                now_ts=now,
            )
            db.remove_rule_type_snooze(rule_type)
            assert liveness["suppressed_count"], rule_type
            assert rule_type in liveness["suppressing_rule_types"], (
                f"{rule_type} silences {sorted(pattern_types)} and the remedy "
                f"would name {liveness['suppressing_rule_types']!r}"
            )
    finally:
        db.close()


# ---------------------------------------------------------------------------
# 3. "Remove from allowlist" is offered only when it can remove
# ---------------------------------------------------------------------------


def _app_with_allowlist_shape(tmp_path, shape: str):
    """``shape`` is one of ui-mac, ui-oui, primary-mac."""
    primary = tmp_path / "allowlist.yaml"
    ui_path = derive_ui_path(primary)
    now = int(time.time())
    if shape == "primary-mac":
        primary.write_text(
            f"entries:\n  - pattern: {MAC}\n    pattern_type: mac\n", encoding="utf-8"
        )
    else:
        primary.write_text("entries: []\n", encoding="utf-8")
    config = Config(db_path=str(tmp_path / "ui.db"), allowlist_path=str(primary))
    db = Database(config.db_path)
    db.upsert_device(MAC, "wifi", None, 0, now)
    alert_id = db.add_alert(
        ts=now, rule_name="r", mac=MAC, message="m", severity="med"
    )
    if shape == "ui-mac":
        add_ui_entry(
            ui_path, AllowlistEntry(pattern=MAC, pattern_type="mac", added_at=now)
        )
    elif shape == "ui-oui":
        add_ui_entry(
            ui_path,
            AllowlistEntry(pattern="aa:bb:cc", pattern_type="oui", added_at=now),
        )
    return create_app(config, db), db, alert_id, ui_path


def _post_remove(client, alert_id: int, page: str):
    token = re.search(
        r'name="' + CSRF_FORM_FIELD + r'" value="([^"]+)"', _prose(page)
    )
    return client.post(
        f"/alerts/{alert_id}/allowlist/remove",
        data={CSRF_FORM_FIELD: token.group(1) if token else ""},
        cookies=client.cookies,
    )


@pytest.mark.webui
def test_removal_is_not_offered_for_a_ui_entry_it_cannot_remove(tmp_path):
    """⛔ Measured before the fix: button offered, 303 back, file byte-identical,
    device still silenced. A success redirect over a write that never happened.
    """
    app, db, alert_id, ui_path = _app_with_allowlist_shape(tmp_path, "ui-oui")
    try:
        before = ui_path.read_text(encoding="utf-8")
        with TestClient(app, follow_redirects=False) as client:
            page = client.get(f"/alerts/{alert_id}").text
            assert "Remove from allowlist" not in page, (
                "the page offers a button that cannot remove this entry"
            )
            # The remedy has to name what covers the device and where to act.
            prose = _prose(page)
            assert "aa:bb:cc" in prose, "the covering entry is not named"
            assert str(ui_path) in prose, "the file holding it is not named"
            assert 'href="/allowlist"' in prose, "no surface offered to act on"
            # And the endpoint, if reached directly, still changes nothing --
            # so the page is honest about the endpoint's actual behaviour.
            _post_remove(client, alert_id, page)
        assert ui_path.read_text(encoding="utf-8") == before
    finally:
        db.close()


@pytest.mark.webui
def test_removal_is_still_offered_and_still_works_for_an_exact_mac_entry(tmp_path):
    """The control. Narrowing the offer must not withdraw the working case."""
    app, db, alert_id, ui_path = _app_with_allowlist_shape(tmp_path, "ui-mac")
    try:
        with TestClient(app, follow_redirects=False) as client:
            page = client.get(f"/alerts/{alert_id}").text
            assert "Remove from allowlist" in page
            response = _post_remove(client, alert_id, page)
            assert response.status_code == 303
            after = _prose(client.get(f"/alerts/{alert_id}").text)
        assert "Allowlisted" not in after, "the entry was not actually removed"
        assert MAC not in ui_path.read_text(encoding="utf-8")
    finally:
        db.close()


@pytest.mark.webui
def test_a_primary_file_entry_still_gets_the_operator_managed_hint(tmp_path):
    """The second control: the primary-file wording is a different case and
    must not be replaced by the new UI-file one."""
    app, db, alert_id, _ = _app_with_allowlist_shape(tmp_path, "primary-mac")
    try:
        with TestClient(app) as client:
            prose = _prose(client.get(f"/alerts/{alert_id}").text)
    finally:
        db.close()
    assert "operator-managed" in prose
    assert "edit that file directly" in prose
    assert "Remove from allowlist" not in prose
    assert "remove it on the" not in prose, (
        "a primary-file entry was given the UI-file remedy"
    )


# ---------------------------------------------------------------------------
# 4. The config path is the one this process loaded
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_settings_names_the_config_file_this_process_loaded(tmp_path):
    loaded = tmp_path / "site.yaml"
    loaded.write_text("db_path: x\n", encoding="utf-8")
    config = Config(db_path=str(tmp_path / "ui.db"))
    db = Database(config.db_path)
    try:
        app = create_app(config, db, config_path=str(loaded))
        with TestClient(app) as client:
            prose = _prose(client.get("/settings").text)
    finally:
        db.close()
    assert str(loaded) in prose
    assert "not recorded by this process" not in prose


@pytest.mark.webui
def test_settings_says_so_when_it_does_not_know_the_config_file(tmp_path):
    """⛔ The default was rendered as the active file. Unknown must read as
    unknown -- the same rule the liveness verdict already follows."""
    config = Config(db_path=str(tmp_path / "ui.db"))
    db = Database(config.db_path)
    try:
        app = create_app(config, db)
        with TestClient(app) as client:
            prose = _prose(client.get("/settings").text)
    finally:
        db.close()
    assert "not recorded by this process" in prose
    assert "not necessarily the file in use" in prose


def test_the_ui_entry_point_passes_the_config_path_it_was_given():
    """The wiring, not just the template.

    ⚠️ The template test above passes an explicit ``config_path``; that proves
    the page can say it, not that anything ever does. The production entry point
    is the only caller that knows the path, so it is read here.
    """
    server = (
        Path(__file__).resolve().parents[1] / "src/lynceus/webui/server.py"
    ).read_text(encoding="utf-8")
    assert "create_app(config, db, config_path=args.config)" in server, (
        "lynceus-ui builds the app without telling it which file it loaded"
    )


# ---------------------------------------------------------------------------
# 5. An unreadable rules file must not become a promise (or a false blocker)
# ---------------------------------------------------------------------------

# Parses as YAML, fails the Ruleset schema -> `load_ruleset` raises and the
# verdict is UNKNOWN, which is the state this whole section is about.
UNREADABLE_RULES = "rules:\n  - this is not a rule\n"
DELEGATING_RULES = (
    "rules:\n"
    "  - name: m\n"
    "    rule_type: watchlist_mac\n"
    "    enabled: true\n"
    "    severity: med\n"
)


def _app_with_remapped_row(tmp_path, rules_body: str, *, snooze: bool = False):
    rules = tmp_path / "rules.yaml"
    rules.write_text(rules_body, encoding="utf-8")
    overrides = tmp_path / "sev.yaml"
    overrides.write_text("device_category_severity:\n  tracker: low\n", encoding="utf-8")
    config = Config(
        db_path=str(tmp_path / "s.db"),
        rules_path=str(rules),
        severity_overrides_path=str(overrides),
    )
    db = Database(config.db_path)
    db.ensure_location("default", "Default")
    watchlist_id, _ = db.add_watchlist(
        pattern="3c:5a:b4:11:22:33", pattern_type="mac", severity="high"
    )
    db.upsert_metadata(
        watchlist_id,
        {"argus_record_id": "A-1", "vendor": "V", "device_category": "tracker"},
    )
    if snooze:
        now = int(time.time())
        db.add_rule_type_snooze("watchlist_mac", now + 3600, now)
    return create_app(config, db), db, watchlist_id


@pytest.mark.webui
def test_an_unreadable_ruleset_is_not_rendered_as_a_row_that_alerts(tmp_path):
    """⛔ `is_pattern_type_live` returns True on an UNKNOWN verdict on purpose,
    so no row is falsely marked inert. That benefit of the doubt reached the
    remap block and came out as "This entry alerts at a different severity" and
    "what an alert will actually carry" — a present-tense promise about a
    daemon whose rules file will not parse, while /settings one click away
    correctly reported the verdict as unreadable.
    """
    app, db, watchlist_id = _app_with_remapped_row(tmp_path, UNREADABLE_RULES)
    try:
        with TestClient(app) as client:
            detail = _prose(client.get(f"/watchlist/{watchlist_id}").text)
            settings = _prose(client.get("/settings").text)
    finally:
        db.close()
    assert "different severity from the one stored" in detail, (
        "the remap block did not render at all; this test proves nothing"
    )
    assert "This entry alerts at a different severity" not in detail
    assert "will actually carry" not in detail
    assert "cannot be determined" in detail
    # ...and the two pages agree about why.
    assert "could not be read" in settings


@pytest.mark.webui
def test_a_readable_ruleset_still_states_the_remap_in_the_present_tense(tmp_path):
    """The control. Unknown must read as unknown; KNOWN must still read as
    known, or the fix has simply deleted the useful sentence."""
    app, db, watchlist_id = _app_with_remapped_row(tmp_path, DELEGATING_RULES)
    try:
        with TestClient(app) as client:
            detail = _prose(client.get(f"/watchlist/{watchlist_id}").text)
    finally:
        db.close()
    assert "This entry alerts at a different severity" in detail
    assert "will actually carry" in detail
    assert "cannot be determined" not in detail


@pytest.mark.webui
def test_a_known_snooze_is_reported_even_when_the_ruleset_verdict_is_not(tmp_path):
    """⛔ The list page and the detail page disagreed about one row.

    `is_pattern_type_snoozed` gated on `known` (the RULESET verdict) rather
    than `snoozes_known`, though the two are independent and the dict was
    carrying the snooze all along. Measured at cca7c5c: with an unreadable
    rules file /watchlist showed the snoozed badge and /watchlist/<id> showed
    no snooze at all — and, because the same flag feeds `entry_can_alert`, went
    on to describe what an alert would carry.
    """
    app, db, watchlist_id = _app_with_remapped_row(
        tmp_path, UNREADABLE_RULES, snooze=True
    )
    try:
        with TestClient(app) as client:
            listing = _prose(client.get("/watchlist").text)
            detail = _prose(client.get(f"/watchlist/{watchlist_id}").text)
    finally:
        db.close()
    assert "badge-snoozed-type" in listing, "the list page lost the badge"
    assert "snoozed" in detail, (
        "the detail page reports no snooze for a row the list page badges"
    )
    # A snooze is a DEFINITE blocker, established without reading the ruleset,
    # so it outranks the unknown verdict rather than being masked by it.
    assert "cannot be determined" not in detail
    assert "This entry alerts at a different severity" not in detail


@pytest.mark.webui
def test_a_snooze_shown_under_an_unknown_ruleset_does_not_claim_the_row_matches(
    tmp_path,
):
    """⛔ A regression THIS BRANCH introduced, caught by asking what branch the
    fix newly reaches.

    Making the snooze visible under an unknown ruleset (the fix above) routed
    the row into a block whose text asserts "This entry matches, but its alerts
    are being dropped" and "The rule still runs and still matches this pattern"
    -- four claims about a ruleset that could not be read. `entry_is_live` is
    True for UNKNOWN as well as for delegated, which is exactly the benefit of
    the doubt that must not become a promise.

    The snooze is known; the matching is not. They are reported separately.
    """
    app, db, watchlist_id = _app_with_remapped_row(
        tmp_path, UNREADABLE_RULES, snooze=True
    )
    try:
        with TestClient(app) as client:
            detail = _prose(client.get(f"/watchlist/{watchlist_id}").text)
    finally:
        db.close()
    assert "snoozed" in detail, "the snooze block did not render"
    assert "This entry matches" not in detail
    assert "still matches this pattern" not in detail
    assert "could not be answered" in detail


@pytest.mark.webui
def test_a_snooze_under_a_readable_ruleset_still_says_the_row_matches(tmp_path):
    """The control. The useful sentence must survive for the state where it is
    true, or the fix above has simply deleted it."""
    app, db, watchlist_id = _app_with_remapped_row(
        tmp_path, DELEGATING_RULES, snooze=True
    )
    try:
        with TestClient(app) as client:
            detail = _prose(client.get(f"/watchlist/{watchlist_id}").text)
    finally:
        db.close()
    assert "This entry matches, but its alerts are being dropped." in detail
    assert "still matches this pattern" in detail
    assert "could not be answered" not in detail


# ---------------------------------------------------------------------------
# 6. The rules page carries a control for every snooze it is blamed for
# ---------------------------------------------------------------------------

OUI_ONLY_RULES = (
    "rules:\n"
    "  - name: o\n"
    "    rule_type: watchlist_oui\n"
    "    enabled: true\n"
    "    severity: med\n"
)


def _app_with_snooze(tmp_path, rules_body: str | None, snoozed_type: str):
    config_kwargs = {"db_path": str(tmp_path / "s.db")}
    if rules_body is not None:
        rules = tmp_path / "rules.yaml"
        rules.write_text(rules_body, encoding="utf-8")
        config_kwargs["rules_path"] = str(rules)
    config = Config(**config_kwargs)
    db = Database(config.db_path)
    db.ensure_location("default", "Default")
    db.add_watchlist(
        pattern="HomeNet", pattern_type="ssid", severity="high", description="d"
    )
    now = int(time.time())
    db.add_rule_type_snooze(snoozed_type, now + 3600, now)
    return create_app(config, db), db


def _unsnooze_controls(html: str) -> list[str]:
    return sorted(set(re.findall(r'action="/rules/([^/]+)/unsnooze"', _prose(html))))


@pytest.mark.webui
@pytest.mark.parametrize("query", ["", "?status=snoozed", "?status=all"])
def test_a_snooze_with_no_loaded_rule_can_still_be_lifted(tmp_path, query):
    """⛔ /watchlist and /settings say "lift it on the rules page". Measured at
    cca7c5c, that page offered ZERO unsnooze controls for this snooze -- on the
    default view, on ?status=snoozed, on ?status=all, and filtered by the type.
    The snooze stays in force in the poller, so re-adding a rule of that type
    later leaves it silently suppressed.

    Reachable through the UI's own instructions: snooze the type here, then
    "Edit <rules file> on disk and restart", as this page's footer says.
    """
    app, db = _app_with_snooze(tmp_path, OUI_ONLY_RULES, "watchlist_ssid")
    try:
        with TestClient(app) as client:
            assert "watchlist_ssid" in _unsnooze_controls(
                client.get("/rules" + query).text
            ), f"/rules{query} offers no way to lift the snooze it is blamed for"
    finally:
        db.close()


@pytest.mark.webui
def test_lifting_an_orphaned_snooze_actually_lifts_it(tmp_path):
    """The button is only worth adding if the endpoint takes it.

    ⭐ It does: the unsnooze route validates against the ``RuleType`` literal,
    not against the loaded ruleset. Driven rather than read.
    """
    app, db = _app_with_snooze(tmp_path, OUI_ONLY_RULES, "watchlist_ssid")
    try:
        with TestClient(app, follow_redirects=False) as client:
            page = client.get("/rules").text
            token = re.search(
                r'name="' + CSRF_FORM_FIELD + r'" value="([^"]+)"', _prose(page)
            )
            response = client.post(
                "/rules/watchlist_ssid/unsnooze",
                data={CSRF_FORM_FIELD: token.group(1) if token else ""},
                cookies=client.cookies,
            )
            assert response.status_code == 303
            after = client.get("/rules").text
            watchlist_after = _prose(client.get("/watchlist").text)
        assert _unsnooze_controls(after) == []
        assert "you snoozed" not in watchlist_after, (
            "the watchlist still reports a snooze that was just lifted"
        )
    finally:
        db.close()


@pytest.mark.webui
def test_a_snooze_with_a_loaded_rule_is_not_listed_as_orphaned(tmp_path):
    """The control. A type with a rule has its own row and its own button; it
    must not also appear in the orphan block, or one snooze reads as two."""
    app, db = _app_with_snooze(tmp_path, OUI_ONLY_RULES, "watchlist_oui")
    try:
        with TestClient(app) as client:
            prose = _prose(client.get("/rules").text)
    finally:
        db.close()
    assert "watchlist_oui" in _unsnooze_controls(prose)
    # ⚠️ Asserted as "the orphan block did not render", not as a count of
    # unsnooze forms. This page already renders two for a loaded type -- one on
    # the rule row and one in the per-rule_type summary -- which is pre-existing
    # and unrelated. A count assertion here would have been a guard against the
    # wrong thing that happened to be red.
    assert "no rule of that type loaded" not in prose
    assert "No ruleset is loaded" not in prose


@pytest.mark.webui
def test_with_no_ruleset_at_all_every_active_snooze_is_still_liftable(tmp_path):
    """No `rules_path` means no rows on this page at all -- and, before this,
    no snooze controls either, while the snoozes went on silencing."""
    app, db = _app_with_snooze(tmp_path, None, "watchlist_ssid")
    try:
        with TestClient(app) as client:
            page = client.get("/rules").text
    finally:
        db.close()
    assert "watchlist_ssid" in _unsnooze_controls(page)
    assert "No ruleset is loaded" in _prose(page)


# ---------------------------------------------------------------------------
# 7. The overrides card does not retract itself three lines later
# ---------------------------------------------------------------------------


def _app_with_overrides(tmp_path, *, configured: bool):
    kwargs = {"db_path": str(tmp_path / "s.db")}
    if configured:
        overrides = tmp_path / "sev.yaml"
        overrides.write_text(
            "device_category_severity:\n  tracker: low\n", encoding="utf-8"
        )
        kwargs["severity_overrides_path"] = str(overrides)
    config = Config(**kwargs)
    db = Database(config.db_path)
    db.ensure_location("default", "Default")
    return create_app(config, db), db


@pytest.mark.webui
def test_the_overrides_card_does_not_tell_you_to_edit_a_file_nothing_reads(tmp_path):
    """🪤 The path and status rows were carefully conditional and the paragraph
    under them was not, so the card said "nothing is configured, so the runtime
    override layer is off" and then "Two layers read this file: ... restart the
    daemon to apply". Following that changes nothing until the setting exists.
    """
    app, db = _app_with_overrides(tmp_path, configured=False)
    try:
        with TestClient(app) as client:
            prose = _prose(client.get("/settings").text)
    finally:
        db.close()
    assert "nothing is configured" in prose, "the card is not in the state under test"
    assert "Two layers read this file" not in prose
    assert "Nothing reads this file yet" in prose
    assert "severity_overrides_path" in prose


@pytest.mark.webui
def test_the_overrides_card_keeps_its_instructions_when_configured(tmp_path):
    """The control: a configured path must still get the editing guidance."""
    app, db = _app_with_overrides(tmp_path, configured=True)
    try:
        with TestClient(app) as client:
            prose = _prose(client.get("/settings").text)
    finally:
        db.close()
    assert "Two layers read this file" in prose
    assert "Nothing reads this file yet" not in prose
    assert "restart the daemon to apply" in prose


# ---------------------------------------------------------------------------
# 8. "showing all entries" only when it is showing all entries
# ---------------------------------------------------------------------------


def _app_with_three_watchlist_rows(tmp_path):
    config = Config(db_path=str(tmp_path / "s.db"))
    db = Database(config.db_path)
    db.ensure_location("default", "Default")
    db.add_watchlist(pattern="aa:bb:cc:dd:ee:01", pattern_type="mac", severity="high")
    db.add_watchlist(pattern="aa:bb:cc:dd:ee:02", pattern_type="mac", severity="low")
    db.add_watchlist(pattern="HomeNet", pattern_type="ssid", severity="low")
    return create_app(config, db), db


def _row_count(html: str) -> int:
    return len(re.findall(r'href="/watchlist/\d+"', _prose(html)))


@pytest.mark.webui
def test_a_dropped_filter_does_not_claim_the_whole_watchlist(tmp_path):
    """⛔ Measured at cca7c5c: `?pattern_type=bogus&severity=high` rendered ONE
    of three rows under a banner saying all of them were shown. On the list of
    devices an operator is specifically watching for, a false "nothing else is
    here" is the inaction direction.
    """
    app, db = _app_with_three_watchlist_rows(tmp_path)
    try:
        with TestClient(app) as client:
            html = client.get("/watchlist?pattern_type=bogus&severity=high").text
    finally:
        db.close()
    prose = _prose(html)
    assert "filter ignored" in prose, "the dropped-filter banner did not render"
    # The page IS narrowed -- that is the whole point of the test.
    assert _row_count(html) < 3, "the fixture is not exercising a narrowed view"
    assert "showing <strong>all</strong> entries" not in prose
    assert "not</strong> the whole watchlist" in prose


@pytest.mark.webui
def test_a_dropped_filter_alone_still_says_showing_all(tmp_path):
    """The control. When the unrecognised filter was the ONLY one, the page
    really is showing everything and must still say so."""
    app, db = _app_with_three_watchlist_rows(tmp_path)
    try:
        with TestClient(app) as client:
            html = client.get("/watchlist?pattern_type=bogus").text
    finally:
        db.close()
    prose = _prose(html)
    assert "filter ignored" in prose
    assert _row_count(html) == 3, "the control is not showing every row"
    assert "showing <strong>all</strong> entries" in prose


@pytest.mark.webui
def test_no_banner_when_every_filter_is_recognised(tmp_path):
    """The second control: a valid filter must not trip the ignored-filter
    banner, or the page cries wolf on every ordinary search."""
    app, db = _app_with_three_watchlist_rows(tmp_path)
    try:
        with TestClient(app) as client:
            html = client.get("/watchlist?severity=high").text
    finally:
        db.close()
    assert "filter ignored" not in _prose(html)


# ---------------------------------------------------------------------------
# 9. Two findings from a cold read of this very branch
# ---------------------------------------------------------------------------


@pytest.mark.webui
def test_remedies_name_the_config_file_this_process_loaded(tmp_path):
    """⛔ The fix applied in one direction only, caught by a cold read.

    The /settings "config path" ROW was corrected to name the loaded file while
    three REMEDIES went on saying "set X in `lynceus.yaml`" -- which, for
    `lynceus-ui --config /etc/lynceus/site.yml`, names a file the process never
    reads. Exactly the class this change set exists to remove, reintroduced by
    two sentences it added itself.
    """
    loaded = tmp_path / "site.yml"
    loaded.write_text("db_path: x\n", encoding="utf-8")
    config = Config(db_path=str(tmp_path / "s.db"))
    db = Database(config.db_path)
    db.ensure_location("default", "Default")
    try:
        app = create_app(config, db, config_path=str(loaded))
        with TestClient(app) as client:
            rules_page = _prose(client.get("/rules").text)
            settings = _prose(client.get("/settings").text)
    finally:
        db.close()
    assert "No rules file is loaded" in rules_page, "the unset-rules banner is absent"
    assert str(loaded) in rules_page
    assert "<code>lynceus.yaml</code>" not in rules_page
    assert str(loaded) in settings
    assert "<code>lynceus.yaml</code>" not in settings


@pytest.mark.webui
def test_remedies_fall_back_to_the_generic_name_when_the_path_is_unknown(tmp_path):
    """The control. With no recorded path the sentence must still be usable --
    a blank where the filename goes is worse than a generic name."""
    config = Config(db_path=str(tmp_path / "s.db"))
    db = Database(config.db_path)
    db.ensure_location("default", "Default")
    try:
        with TestClient(create_app(config, db)) as client:
            rules_page = _prose(client.get("/rules").text)
    finally:
        db.close()
    assert "your <code>lynceus.yaml</code>" in rules_page
    assert not re.search(r"<code>\s*</code>", rules_page)


@pytest.mark.webui
@pytest.mark.parametrize(
    "rules_body,expected",
    [
        (None, "no rules_path is configured"),
        (UNREADABLE_RULES, "the rules file could not be read"),
    ],
    ids=["unset", "unreadable"],
)
def test_an_undeterminable_verdict_names_its_own_cause(tmp_path, rules_body, expected):
    """⛔ Two causes must not share one sentence.

    `known=False` covers BOTH "the rules file would not load" and "no
    `rules_path` is configured at all". The new unknown branch said "because the
    rules file could not be read", which sends an operator with the second cause
    into syntax and permission checks for a file they never set.
    `liveness.reason` already distinguishes them.
    """
    overrides = tmp_path / "sev.yaml"
    overrides.write_text("device_category_severity:\n  tracker: low\n", encoding="utf-8")
    kwargs = {
        "db_path": str(tmp_path / "s.db"),
        "severity_overrides_path": str(overrides),
    }
    if rules_body is not None:
        rules = tmp_path / "rules.yaml"
        rules.write_text(rules_body, encoding="utf-8")
        kwargs["rules_path"] = str(rules)
    config = Config(**kwargs)
    db = Database(config.db_path)
    db.ensure_location("default", "Default")
    try:
        watchlist_id, _ = db.add_watchlist(
            pattern="3c:5a:b4:11:22:33", pattern_type="mac", severity="high"
        )
        db.upsert_metadata(
            watchlist_id,
            {"argus_record_id": "A-1", "vendor": "V", "device_category": "tracker"},
        )
        with TestClient(create_app(config, db)) as client:
            detail = _prose(client.get(f"/watchlist/{watchlist_id}").text)
    finally:
        db.close()
    assert "cannot be determined" in detail, "the unknown branch did not render"
    assert expected in detail


# ---------------------------------------------------------------------------
# 10. A success flash must not assert a number the page cannot check
# ---------------------------------------------------------------------------


def _app_with_ui_entries(tmp_path, n: int = 3):
    primary = tmp_path / "allowlist.yaml"
    primary.write_text("entries: []\n", encoding="utf-8")
    ui_path = derive_ui_path(primary)
    now = int(time.time())
    for i in range(n):
        add_ui_entry(
            ui_path,
            AllowlistEntry(
                pattern=f"aa:bb:cc:dd:ee:{i:02x}", pattern_type="mac", added_at=now
            ),
        )
    config = Config(db_path=str(tmp_path / "s.db"), allowlist_path=str(primary))
    db = Database(config.db_path)
    db.ensure_location("default", "Default")
    return create_app(config, db), db, ui_path


@pytest.mark.webui
@pytest.mark.parametrize(
    "query",
    [
        "?success=bulk_remove",
        "?success=bulk_remove&count=-5",
        "?success=bulk_remove&count=99999999999999999999",
    ],
    ids=["absent", "negative", "above-any-plausible-file"],
)
def test_an_implausible_flash_count_is_not_rendered_as_a_fact(tmp_path, query):
    """⛔ `count` reaches this flash straight from the query string.

    Measured at 7958b28, with the file byte-identical in every case:

        ?success=bulk_remove              -> "Removed None entries."
        ?success=bulk_remove&count=-5     -> "Removed -5 entries."
        ...&count=99999999999999999999    -> echoed verbatim

    The last is the unbounded-integer channel Finding 66 closed for row ids,
    arriving through a flash instead of a path parameter. The page cannot
    confirm any of them -- a removal that already happened leaves nothing to
    check against -- so an implausible value loses its number rather than being
    printed as one.
    """
    app, db, ui_path = _app_with_ui_entries(tmp_path)
    try:
        before = ui_path.read_text(encoding="utf-8")
        with TestClient(app) as client:
            prose = _prose(client.get("/allowlist" + query).text)
        assert ui_path.read_text(encoding="utf-8") == before, "a GET mutated the file"
    finally:
        db.close()
    assert "Bulk removal finished." in prose, "the flash vanished instead of degrading"
    assert "Removed" not in prose
    assert "None" not in prose


@pytest.mark.webui
def test_a_real_bulk_removal_still_reports_its_count(tmp_path):
    """⛔ The control, driven end to end rather than simulated by visiting the
    redirect URL. Dropping implausible counts is only correct if the real one
    survives."""
    app, db, ui_path = _app_with_ui_entries(tmp_path)
    try:
        with TestClient(app, follow_redirects=False) as client:
            token = client.get("/allowlist").cookies[CSRF_COOKIE_NAME]
            response = client.post(
                "/allowlist/bulk_remove",
                data={
                    CSRF_FORM_FIELD: token,
                    "entry_keys": ["mac:aa:bb:cc:dd:ee:00", "mac:aa:bb:cc:dd:ee:01"],
                },
            )
            assert response.status_code == 303
            assert response.headers["location"] == (
                "/allowlist?success=bulk_remove&count=2"
            )
            prose = _prose(client.get(response.headers["location"]).text)
        remaining = ui_path.read_text(encoding="utf-8").count("pattern:")
    finally:
        db.close()
    assert "Removed 2 entries." in prose
    assert remaining == 1, "the removal itself did not happen"


@pytest.mark.webui
def test_an_unknown_success_token_renders_no_flash_at_all(tmp_path):
    """The second control: the TOKEN was already effectively whitelisted by the
    template's equality checks, and must stay that way. It was the count that
    was echoed unchecked."""
    app, db, _ = _app_with_ui_entries(tmp_path)
    try:
        with TestClient(app) as client:
            prose = _prose(client.get("/allowlist?success=nonsense&count=7").text)
    finally:
        db.close()
    assert "Removed" not in prose
    assert "Bulk removal finished." not in prose

