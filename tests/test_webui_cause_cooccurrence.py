"""Two surfaces named OPPOSITE causes for the same watchlist row.

#116 made ``inert`` and ``snoozed`` independent flags in ``liveness.py`` — a
type can be both, and fixing either one alone restores nothing. It did not
revisit the surfaces, which were all written when a type could not be both.

Measured at ``11893cc`` on a row of an inert pattern_type whose delegating
rule_type also carried an active snooze:

    model            inert_types=('ble_uuid',)  suppressed_types=('ble_uuid',)
    /watchlist       row badge: inert            -> "edit rules.yaml"
    /watchlist/{id}  snoozed ONLY, verbatim:
                     "Nothing in rules.yaml needs changing."   <- FALSE for this row
    /watchlist.csv   can_fire=no, and the snooze appeared nowhere

⛔ **One click apart, the UI gave two contradictory diagnoses**, and each named
a fix that alone restores nothing. The detail page's sentence was not merely
incomplete; it was false.

⭐ **The state is operator-reachable**, which is why this is a defect and not a
curiosity: ``POST /rules/{rule_type}/snooze`` validates against the
``rules.RuleType`` literal set, not against the loaded ruleset, so a rule_type
whose rule ships commented out is snoozeable — and the ordinary path is
snoozing a live rule_type and later commenting the rule out (or giving it an
inline ``patterns:`` list, which turns delegation off just as completely).

🪤 The detail template also carried the comment *"they are mutually exclusive by
construction: liveness intersects the snooze set with the LIVE types"* — a
description of code #116 deleted. Prose that was accurate when written and
quietly stopped being.
"""

from __future__ import annotations

import csv as _csv
import io
import re
import time
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import create_app
from lynceus.webui.csrf import CSRF_COOKIE_NAME, CSRF_FORM_FIELD
from lynceus.webui.liveness import watchlist_liveness

REPO_ROOT = Path(__file__).resolve().parents[1]
SHIPPED_RULES = REPO_ROOT / "config" / "rules.yaml"

# `ble_uuid` is inert against the SHIPPED ruleset (its delegating rule ships
# commented out — Finding 32) and is also the rule_type name, so one snooze row
# reaches it. Nothing synthetic about either half.
BOTH_PATTERN = "0000fd5a-0000-1000-8000-00805f9b34fb"
BOTH_TYPE = "ble_uuid"
BOTH_RULE_TYPE = "ble_uuid"

# `mac` delegates in the shipped ruleset, so this row is the LIVE control that
# stops a surface passing by marking everything.
LIVE_PATTERN = "3c:5a:b4:dd:ee:02"
LIVE_TYPE = "mac"

INERT_EXPLANATION = "This entry cannot currently fire."
SNOOZE_LIVE_EXPLANATION = "This entry matches, but its alerts are being dropped."
SNOOZE_ALSO_EXPLANATION = "You have also snoozed this entry's rule type."
RULES_YAML_IS_FINE = "Nothing in <code>rules.yaml</code> needs changing."


def test_this_suite_is_testing_the_tree_it_lives_in():
    import lynceus.webui.liveness as under_test

    assert Path(under_test.__file__).resolve().is_relative_to(REPO_ROOT), (
        f"imported lynceus from {under_test.__file__} — run pytest with "
        f"-o pythonpath=<worktree>/src"
    )


def _prose(html: str) -> str:
    return " ".join(re.sub(r"<!--.*?-->", " ", html, flags=re.S).split())


def _build(tmp_path, *, snooze: str | None):
    allowlist = tmp_path / "allow.yaml"
    allowlist.write_text("entries: []\n", encoding="utf-8")
    cfg = Config(
        db_path=str(tmp_path / "s.db"),
        rules_path=str(SHIPPED_RULES),
        allowlist_path=str(allowlist),
    )
    db = Database(cfg.db_path)
    db.ensure_location("default", "Default")
    both_id, _ = db.add_watchlist(
        pattern=BOTH_PATTERN, pattern_type=BOTH_TYPE, severity="high"
    )
    live_id, _ = db.add_watchlist(
        pattern=LIVE_PATTERN, pattern_type=LIVE_TYPE, severity="high"
    )
    app = create_app(cfg, db)
    if snooze is not None:
        # ⭐ Created through the ROUTE, not by calling the DB helper, so the
        # state under test is one an operator can actually reach from this UI.
        with TestClient(app, follow_redirects=False) as boot:
            boot.get("/")
            posted = boot.post(
                f"/rules/{snooze}/snooze",
                data={
                    "duration_seconds": "86400",
                    CSRF_FORM_FIELD: boot.cookies.get(CSRF_COOKIE_NAME),
                },
            )
        active = [s.rule_type for s in db.list_active_rule_type_snoozes(int(time.time()))]
        assert snooze in active, (
            f"POST /rules/{snooze}/snooze returned {posted.status_code} and no "
            f"snooze row exists — the fixture never reached the state under test"
        )
    return cfg, db, app, both_id, live_id


def test_the_state_under_test_is_reachable_and_the_model_reports_both(tmp_path):
    """⭐ The control for everything below. If the model stopped reporting both,
    every surface assertion here would pass by describing a state that no longer
    exists — a suite grading a fixture instead of a UI.
    """
    cfg, db, app, both_id, live_id = _build(tmp_path, snooze=BOTH_RULE_TYPE)
    try:
        liveness = watchlist_liveness(
            cfg, db.watchlist_pattern_type_counts(), db=db, now_ts=int(time.time())
        )
    finally:
        db.close()

    assert BOTH_TYPE in liveness["inert_types"]
    assert BOTH_TYPE in liveness["suppressed_types"]
    assert liveness["both_types"] == (BOTH_TYPE,)
    assert LIVE_TYPE not in liveness["inert_types"], (
        "the live control row is inert too — the shipped ruleset changed and "
        "this suite can no longer tell 'marks everything' from 'marks the "
        "right row'"
    )


def test_the_list_row_carries_BOTH_badges_not_the_first_one(tmp_path):
    """The `{% elif %}` chain showed `inert` and swallowed `snoozed`."""
    cfg, db, app, both_id, live_id = _build(tmp_path, snooze=BOTH_RULE_TYPE)
    try:
        with TestClient(app) as client:
            html = client.get("/watchlist").text
    finally:
        db.close()

    rows = [r for r in re.findall(r"<tr>(.*?)</tr>", html, flags=re.S) if BOTH_PATTERN in r]
    assert len(rows) == 1
    badges = re.findall(r'badge-(?:inert|snoozed-type)"[^>]*>([a-z]+)</span>', rows[0])
    assert badges == ["inert", "snoozed"], (
        f"the row for a type that is both inert and snoozed carries {badges}; "
        f"an operator acting on one badge fixes one cause and still hears "
        f"nothing"
    )

    live_rows = [
        r for r in re.findall(r"<tr>(.*?)</tr>", html, flags=re.S) if LIVE_PATTERN in r
    ]
    assert len(live_rows) == 1
    assert not re.findall(
        r'badge-(?:inert|snoozed-type)"[^>]*>([a-z]+)</span>', live_rows[0]
    ), "the live control row is marked too — this surface marks everything"


def test_the_detail_page_explains_both_causes_and_retracts_the_false_sentence(tmp_path):
    """⛔ The sharpest half. The detail page said *"Nothing in rules.yaml needs
    changing"* about a row for which rules.yaml is exactly what needs changing.
    """
    cfg, db, app, both_id, live_id = _build(tmp_path, snooze=BOTH_RULE_TYPE)
    try:
        with TestClient(app) as client:
            detail = _prose(client.get(f"/watchlist/{both_id}").text)
    finally:
        db.close()

    assert INERT_EXPLANATION in detail, "the inert cause is not explained at all"
    assert SNOOZE_ALSO_EXPLANATION in detail, "the snooze cause is not explained at all"
    assert RULES_YAML_IS_FINE not in detail, (
        "the detail page still tells the operator that rules.yaml is fine for a "
        "row whose pattern_type has no enabled delegating rule"
    )
    assert SNOOZE_LIVE_EXPLANATION not in detail, (
        "the page claims the rule 'matches' for a type no enabled rule delegates to"
    )
    assert "will <strong>not</strong> restore alerting" in detail, (
        "neither cause says that fixing it alone changes nothing"
    )


def test_a_snoozed_but_delegated_type_keeps_the_original_wording(tmp_path):
    """⭐ The other half of the pair, and the reason the sentences above are
    conditional rather than deleted. For a type that IS delegated, the rule
    really does run and match, and `rules.yaml` really is fine — telling that
    operator to go and edit it would be the mirror-image false claim.
    """
    cfg, db, app, both_id, live_id = _build(tmp_path, snooze="watchlist_mac")
    try:
        with TestClient(app) as client:
            detail = _prose(client.get(f"/watchlist/{live_id}").text)
    finally:
        db.close()

    assert SNOOZE_LIVE_EXPLANATION in detail
    assert RULES_YAML_IS_FINE in detail
    assert INERT_EXPLANATION not in detail


def test_an_inert_but_unsnoozed_type_says_nothing_about_a_snooze(tmp_path):
    """The third leg. Without it, rendering the snooze block unconditionally
    would pass both tests above.
    """
    cfg, db, app, both_id, live_id = _build(tmp_path, snooze=None)
    try:
        with TestClient(app) as client:
            detail = _prose(client.get(f"/watchlist/{both_id}").text)
    finally:
        db.close()

    assert INERT_EXPLANATION in detail
    assert SNOOZE_ALSO_EXPLANATION not in detail
    assert SNOOZE_LIVE_EXPLANATION not in detail
    assert "will <strong>not</strong> restore alerting" not in detail, (
        "a row with ONE cause is told that fixing it changes nothing"
    )


BOTH_BANNER = "inert <strong>and</strong> snoozed"


@pytest.mark.parametrize(
    ("snooze", "expected"),
    [(BOTH_RULE_TYPE, True), ("watchlist_mac", False), (None, False)],
)
def test_the_list_banner_names_the_co_occurrence_only_when_it_exists(
    snooze, expected, tmp_path
):
    """A take-effect triple: both causes, one cause on a different type, and no
    snooze at all. A banner that renders whenever a snooze exists would be a new
    false claim on the most common install.
    """
    cfg, db, app, both_id, live_id = _build(tmp_path, snooze=snooze)
    try:
        with TestClient(app) as client:
            body = _prose(client.get("/watchlist").text)
    finally:
        db.close()

    assert (BOTH_BANNER in body) is expected


def test_the_snooze_banner_no_longer_asserts_that_the_rule_matches(tmp_path):
    """🪤 "matching but silenced" was a claim about the RULESET made by a banner
    that only ever looked at the snooze table. True for a delegated type, false
    for one that is also inert.
    """
    cfg, db, app, both_id, live_id = _build(tmp_path, snooze=BOTH_RULE_TYPE)
    try:
        with TestClient(app) as client:
            body = _prose(client.get("/watchlist").text)
    finally:
        db.close()

    assert "silenced by a rule_type snooze" in body
    assert "matching but silenced" not in body


def test_settings_retracts_the_same_sentence_when_a_snoozed_type_is_also_inert(tmp_path):
    cfg, db, app, both_id, live_id = _build(tmp_path, snooze=BOTH_RULE_TYPE)
    try:
        with TestClient(app) as client:
            settings = _prose(client.get("/settings").text)
    finally:
        db.close()

    assert "snoozed, not dead" in settings
    assert "Nothing in <code>rules.yaml</code> needs changing — lift it" not in settings
    assert "also inert" in settings


def test_settings_keeps_the_sentence_when_the_snoozed_type_delegates(tmp_path):
    cfg, db, app, both_id, live_id = _build(tmp_path, snooze="watchlist_mac")
    try:
        with TestClient(app) as client:
            settings = _prose(client.get("/settings").text)
    finally:
        db.close()

    assert "Nothing in <code>rules.yaml</code> needs changing — lift it" in settings
    assert "also inert" not in settings


def _csv_rows(client):
    return list(_csv.reader(io.StringIO(client.get("/watchlist.csv").text)))


def test_the_csv_reports_the_snooze_independently_of_can_fire(tmp_path):
    """`can_fire` answers `no` for a row that is both, because inert is checked
    first — so the snooze vanished from the export entirely and an operator
    acting on `no` would edit rules.yaml and still hear nothing.

    ⚠️ Asserts `can_fire` is UNCHANGED as well: the fix had to be additive,
    because altering that column's value set breaks positional and value-based
    consumers to close a hole a new column closes on its own.
    """
    cfg, db, app, both_id, live_id = _build(tmp_path, snooze=BOTH_RULE_TYPE)
    try:
        with TestClient(app) as client:
            rows = _csv_rows(client)
    finally:
        db.close()

    header, data = rows[0], rows[1:]
    idx = {n: header.index(n) for n in ("pattern_type", "can_fire", "type_snoozed")}
    by_type = {r[idx["pattern_type"]]: r for r in data}

    assert by_type[BOTH_TYPE][idx["can_fire"]] == "no"
    assert by_type[BOTH_TYPE][idx["type_snoozed"]] == "yes", (
        "a row that is inert AND snoozed exports no trace of the snooze"
    )
    assert by_type[LIVE_TYPE][idx["can_fire"]] == "yes"
    assert by_type[LIVE_TYPE][idx["type_snoozed"]] == "no", (
        "the unsnoozed control row is marked snoozed — this column marks everything"
    )


def test_the_csv_snooze_column_is_unknown_when_liveness_is(tmp_path):
    """An unreadable rules file means the question was not answered. Exporting
    `no` there would be a claim nothing established — the same defect
    `liveness_known` exists to prevent on `/healthz.json`.
    """
    allowlist = tmp_path / "allow.yaml"
    allowlist.write_text("entries: []\n", encoding="utf-8")
    broken = tmp_path / "broken.yaml"
    broken.write_text("rules: [[[\n", encoding="utf-8")
    cfg = Config(
        db_path=str(tmp_path / "s.db"),
        rules_path=str(broken),
        allowlist_path=str(allowlist),
    )
    db = Database(cfg.db_path)
    try:
        db.ensure_location("default", "Default")
        db.add_watchlist(pattern=LIVE_PATTERN, pattern_type=LIVE_TYPE, severity="high")
        with TestClient(create_app(cfg, db)) as client:
            rows = _csv_rows(client)
    finally:
        db.close()

    header, data = rows[0], rows[1:]
    idx = header.index("type_snoozed")
    assert [r[idx] for r in data] == ["unknown"]


def test_settings_does_not_claim_the_rules_still_match_for_a_both_type(tmp_path):
    """🪤 The first fix here scoped only "Nothing in rules.yaml needs changing"
    and left "the rules still match, the alerts are dropped until the snooze
    expires" rendering unconditionally — false in every clause for a type no
    enabled rule delegates to. A cold read caught the half-fix.
    """
    cfg, db, app, both_id, live_id = _build(tmp_path, snooze=BOTH_RULE_TYPE)
    try:
        with TestClient(app) as client:
            settings = _prose(client.get("/settings").text)
    finally:
        db.close()

    assert "also inert" in settings
    assert "the rules still match" not in settings.lower(), (
        "settings still asserts the rules match for a type nothing delegates to"
    )


def test_settings_keeps_the_matching_claim_when_the_snoozed_type_delegates(tmp_path):
    """The other half — for a delegated type the rules DO still match, and
    deleting the sentence outright would be the mirror-image false claim.
    """
    cfg, db, app, both_id, live_id = _build(tmp_path, snooze="watchlist_mac")
    try:
        with TestClient(app) as client:
            settings = _prose(client.get("/settings").text)
    finally:
        db.close()

    assert "The rules still match" in settings
    assert "also inert" not in settings


def test_the_detail_page_names_the_rule_type_not_the_pattern_type(tmp_path):
    """⛔ "You snoozed the `ssid_pattern` rule type" names something that does
    not exist on /rules. The rule_type is `watchlist_ssid`, and it serves both
    `ssid` and `ssid_pattern`.
    """
    cfg, db, app, both_id, live_id = _build(tmp_path, snooze="watchlist_mac")
    try:
        with TestClient(app) as client:
            detail = _prose(client.get(f"/watchlist/{live_id}").text)
    finally:
        db.close()

    assert "You snoozed <code>watchlist_mac</code>" in detail, (
        "the page does not name the rule_type the operator has a button for"
    )
    assert "You snoozed the <code>mac</code> rule type" not in detail
