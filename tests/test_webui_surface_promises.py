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
from lynceus.webui.csrf import CSRF_FORM_FIELD

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
