"""An operator can see which of their watchlist entries can actually fire.

Seven of the ten storable pattern_types produce no alert against the shipped
ruleset (Finding 32). ``tests/test_watchlist_pattern_types_are_wired.py`` pins
that *fact*; nothing made it visible to the person who stored the entry. They
add a row, the UI accepts it, ``/settings`` counts it, ``/healthz.json`` reports
it — and it will never fire.

⭐ **The interesting half of this suite is not "the warning appears".** It is:

1. the verdict is DERIVED from the loaded ruleset, so enabling a delegating
   rule in ``rules.yaml`` silences the warning with no code change here — a
   hardcoded list of dead types would keep warning and become a new lie;
2. the rule_type → pattern_type map is cross-checked against what
   ``rules.evaluate`` ACTUALLY does with a real observation, under **two**
   different rulesets, so the two sides read genuinely different things;
3. a healthy watchlist carries **no warning at all**, and an unreadable rules
   file reports **unknown** rather than dead. Those are the over-correction
   shapes, and they cost more than the silence would.

🪤 Absence assertions here run on comment-stripped, whitespace-collapsed prose.
Both traps have bitten this track before: a broad needle matched the word
"never" inside a CSS comment and reported a warning that did not exist, and
template prose wraps across source lines so a phrase that reads as one string
in the file is not contiguous in the HTML.
"""

from __future__ import annotations

import ast
import re
import sqlite3
from pathlib import Path
from typing import get_args

import pytest
from starlette.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.rules import Rule, Ruleset, RuleType, evaluate, load_ruleset
from lynceus.webui.app import create_app
from lynceus.webui.liveness import (
    DEAD_BY_MODEL,
    NON_DELEGATING_RULE_TYPES,
    RULE_TYPE_DELEGATES_TO,
    live_pattern_types,
    watchlist_liveness,
)

# ⛔ Imported, not re-transcribed. `CASES` maps each pattern_type to a stored
# pattern plus the observation kwargs that match it EXACTLY, and it is itself
# guarded: test_the_admitted_types_are_exactly_the_ones_we_have_classified
# parses the live CHECK constraint and fails when the two diverge. Copying it
# here would produce a second manifest that could drift from the first, which
# is the exact defect that produced Finding 32's mis-stated "6 of 9".
from tests.test_watchlist_pattern_types_are_wired import CASES, _observation

REPO_ROOT = Path(__file__).resolve().parents[1]
SHIPPED_RULES = REPO_ROOT / "config" / "rules.yaml"


def test_this_suite_is_testing_the_tree_it_lives_in():
    """🔴 ``pyproject``'s ``pythonpath = ["src"]`` pytest ini DEFEATS
    ``PYTHONPATH``, so pytest run from a worktree silently imports the PRIMARY
    checkout. Every result in this file would then describe code that is not
    the code under review — a green run proving nothing about the diff.

    Cheap enough to keep permanently; it has cost this project real time.
    """
    import lynceus.webui.liveness as under_test

    assert Path(under_test.__file__).resolve().is_relative_to(REPO_ROOT), (
        f"this suite lives in {REPO_ROOT} but imported lynceus from "
        f"{under_test.__file__} — run pytest with -o pythonpath=<worktree>/src"
    )


def _prose(html: str) -> str:
    """Rendered HTML as a single whitespace-collapsed line, comments removed.

    🪤 Two measured traps, both of which produce a GREEN run:

    * **Comments.** A guard that matches its own documentation proves nothing.
      HTML comments are stripped before any assertion. (Jinja ``{# #}`` never
      reaches the output, but a template author reaching for ``<!-- -->``
      would silently re-arm this.)
    * **Wrapping.** Template prose wraps across source lines, so a sentence
      that is one phrase in the file is not contiguous in the HTML. Asserting
      on the raw body fails when someone rewraps a paragraph and passes when
      they delete half of it — brittle in the direction that wastes time and
      blind in the direction that matters.

    Inherited from #67, which learned both the hard way.
    """
    return " ".join(re.sub(r"<!--.*?-->", " ", html, flags=re.S).split())


def _admitted_pattern_types(tmp_path: Path) -> set[str]:
    """Parse the live CHECK constraint, so this side of every assertion reads
    the SCHEMA rather than the Python tuple the app also reads."""
    Database(str(tmp_path / "schema.db"))
    conn = sqlite3.connect(str(tmp_path / "schema.db"))
    try:
        sql = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='watchlist'"
        ).fetchone()[0]
    finally:
        conn.close()
    check = re.search(r"pattern_type\s+TEXT[^,]*?CHECK\s*\((.*?)\)\s*(?:,|$)", sql, re.S)
    assert check, f"could not find the pattern_type CHECK constraint in:\n{sql}"
    types = set(re.findall(r"'([a-z_]+)'", check.group(1)))
    assert len(types) >= 10, f"only found {len(types)} admitted pattern types: {types}"
    return types


def _all_delegating_enabled() -> Ruleset:
    """A ruleset in which every delegation-capable rule_type is enabled with
    empty patterns — i.e. what the shipped file would be if Kev uncommented
    the six rules Finding 32 names.

    ⛔ Built by ITERATING ``RULE_TYPE_DELEGATES_TO``, never by listing rules.
    A hand-written list here would be a second transcription and could omit
    exactly the rule_type whose absence the test is meant to catch.
    """
    return Ruleset(
        rules=[
            Rule(name=f"delegating_{rt}", rule_type=rt, severity="high", patterns=[])
            for rt in sorted(RULE_TYPE_DELEGATES_TO)
        ]
    )


# --------------------------------------------------------------------------
# 1. The map is not trusted. It is graded against what evaluate() really does.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("pattern_type", sorted(CASES))
@pytest.mark.parametrize("ruleset_name", ["shipped", "all_delegating_enabled"])
def test_the_liveness_verdict_matches_what_evaluate_actually_does(
    pattern_type, ruleset_name, tmp_path
):
    """For every storable pattern_type, under two different rulesets: does the
    module's verdict agree with whether a perfectly matching device actually
    produces an alert?

    ⭐ This is the assertion that makes ``RULE_TYPE_DELEGATES_TO`` legitimate.
    One side is a static map plus the ruleset's enabled/patterns fields; the
    other is the rules engine running against a real observation. A map entry
    pointing at the wrong pattern_type, a missing entry, or a delegation branch
    that changes which type it consults all fail here.

    ⚠️ Run under BOTH rulesets on purpose. Under the shipped ruleset alone,
    a module that simply hardcoded ``{mac, ssid, ssid_pattern}`` would pass
    every case.
    """
    ruleset = (
        load_ruleset(SHIPPED_RULES)
        if ruleset_name == "shipped"
        else _all_delegating_enabled()
    )
    predicted_live = pattern_type in live_pattern_types(ruleset)

    pattern, obs_kwargs = CASES[pattern_type]
    if obs_kwargs is None:
        # DEAD_BY_MODEL: no observation field exists to carry this, so no
        # ruleset can make it fire. The module must never predict it live.
        assert not predicted_live, (
            f"{pattern_type} is predicted live, but no DeviceObservation field "
            f"exists to compare a stored pattern against — it cannot fire "
            f"under any ruleset"
        )
        return

    db = Database(str(tmp_path / f"{pattern_type}-{ruleset_name}.db"))
    try:
        db.add_watchlist(pattern=pattern, pattern_type=pattern_type, severity="high")
        actually_fired = bool(evaluate(ruleset, _observation(**obs_kwargs), False, db=db))
    finally:
        db.close()

    assert predicted_live == actually_fired, (
        f"under the {ruleset_name} ruleset, liveness says {pattern_type} is "
        f"{'live' if predicted_live else 'inert'} but evaluate() "
        f"{'DID' if actually_fired else 'did NOT'} produce an alert for a "
        f"device matching it exactly. RULE_TYPE_DELEGATES_TO is wrong."
    )


def test_the_two_rulesets_actually_disagree(tmp_path):
    """The control for the test above. If both rulesets produced the same
    verdict for every type, that parametrisation would be two copies of one
    experiment and a hardcoded module would sail through it.

    ⭐ A broken treatment fails loudly; a broken control fabricates a result.
    """
    shipped = live_pattern_types(load_ruleset(SHIPPED_RULES))
    enabled = live_pattern_types(_all_delegating_enabled())

    assert shipped < enabled, (
        f"expected enabling the delegating rules to REVIVE types; shipped="
        f"{sorted(shipped)} enabled={sorted(enabled)}"
    )
    assert len(enabled - shipped) >= 5, (
        f"only {len(enabled - shipped)} types differ between the two rulesets; "
        f"the contrast is too weak to prove the verdict is derived"
    )


def test_a_rule_with_inline_patterns_does_not_make_its_type_live():
    """The mechanism Finding 32 turns on, and the one that is easy to get
    backwards. A non-empty ``patterns:`` list is not a stricter delegation —
    it switches delegation OFF for that rule and matches in-memory instead.

    This is why ``watchlist_oui`` *looks* wired in the shipped file:
    ``hak5_pineapple_oui`` carries an inline ``patterns: ["00:13:37"]``, so an
    operator's OUI rows are never consulted.
    """
    inline = Ruleset(
        rules=[
            Rule(
                name="hak5_pineapple_oui",
                rule_type="watchlist_oui",
                severity="high",
                patterns=["00:13:37"],
            )
        ]
    )
    delegating = Ruleset(
        rules=[
            Rule(name="watchlist_oui", rule_type="watchlist_oui", severity="high", patterns=[])
        ]
    )

    assert "oui" not in live_pattern_types(inline)
    assert "oui" in live_pattern_types(delegating)


def test_a_disabled_delegating_rule_does_not_make_its_type_live():
    disabled = Ruleset(
        rules=[
            Rule(
                name="watchlist_oui",
                rule_type="watchlist_oui",
                severity="high",
                patterns=[],
                enabled=False,
            )
        ]
    )

    assert "oui" not in live_pattern_types(disabled)


# --------------------------------------------------------------------------
# 2. Nothing may be added upstream and silently fall out of the classification.
# --------------------------------------------------------------------------


def test_every_rule_type_is_classified_as_delegating_or_not():
    """Derived from ``rules.RuleType`` itself. Adding a rule_type there and
    forgetting this module makes its watchlist rows silently ungraded — they
    would be reported inert while firing perfectly well."""
    declared = set(get_args(RuleType))
    classified = set(RULE_TYPE_DELEGATES_TO) | set(NON_DELEGATING_RULE_TYPES)

    assert declared == classified, (
        f"unclassified rule_types: {sorted(declared - classified)}; "
        f"classified but not declared: {sorted(classified - declared)}"
    )


def test_every_admitted_pattern_type_is_served_or_declared_dead(tmp_path):
    """Derived from the live CHECK constraint. A pattern_type admitted by the
    schema that no rule_type serves and that is not declared DEAD_BY_MODEL is
    a type an operator can store and that this module would quietly grade as
    inert without anyone having decided that."""
    admitted = _admitted_pattern_types(tmp_path)
    served = {pt for pts in RULE_TYPE_DELEGATES_TO.values() for pt in pts}
    accounted = served | set(DEAD_BY_MODEL)

    assert admitted <= accounted, (
        f"pattern types the schema admits but nothing accounts for: "
        f"{sorted(admitted - accounted)}"
    )
    assert served <= admitted, (
        f"the map claims to serve pattern types the schema does not admit: "
        f"{sorted(served - admitted)}"
    )


def test_the_settings_breakdown_renders_every_admitted_pattern_type(tmp_path):
    """⛔ This line WAS eight hardcoded lookups under a name promising "pattern
    types", while the schema admits ten. ``ssid_pattern`` and ``imei_tac`` were
    counted by the DB and rendered by nothing — an operator whose entries were
    all of one of those two read a breakdown that did not mention them.

    Derived from the schema, with a floor, so a loop that silently rendered
    nothing could not pass.
    """
    admitted = _admitted_pattern_types(tmp_path)
    cfg = Config(db_path=str(tmp_path / "s.db"), rules_path=str(SHIPPED_RULES))
    db = Database(cfg.db_path)
    db.ensure_location("default", "Default")
    try:
        with TestClient(create_app(cfg, db)) as client:
            body = _prose(client.get("/settings").text)
    finally:
        db.close()

    breakdown = re.search(r"pattern types:.*?</p>", body)
    assert breakdown, "the /settings pattern-type breakdown is gone entirely"
    rendered = set(re.findall(r"([a-z_]+)=\d+", breakdown.group(0)))

    assert len(rendered) >= 10, f"only {len(rendered)} types rendered: {sorted(rendered)}"
    assert rendered == admitted, (
        f"the breakdown and the schema disagree. Missing from /settings: "
        f"{sorted(admitted - rendered)}; rendered but not admitted: "
        f"{sorted(rendered - admitted)}"
    )


# --------------------------------------------------------------------------
# 3. The operator-facing surfaces. Both shapes, every time.
# --------------------------------------------------------------------------

INERT_TYPE = "oui"  # dead against the SHIPPED ruleset; revived by enabling its rule
LIVE_TYPE = "mac"

CANNOT_FIRE = "cannot currently fire"
CANNOT_FIRE_LIST = "cannot fire"
#: Unique to the /watchlist PAGE-LEVEL banner. Nothing else on the page renders
#: this sentence.
#:
#: 🪤 Found by a planted defect, and it is the trap this project keeps meeting:
#: deleting the banner entirely left the suite GREEN, because the per-row
#: badge's `title` tooltip also contains "cannot fire" and the assertion was
#: matching THAT. The guard was testing a different rendering than the one it
#: named. Absence of a phrase is not absence of an element — so the banner and
#: the row badge are now asserted separately, each with a needle only it emits.
BANNER = "Marked inert in the table below"


def _client(tmp_path, *, rules_path: str | None, entries: list[tuple[str, str]]):
    cfg = Config(db_path=str(tmp_path / "s.db"), rules_path=rules_path)
    db = Database(cfg.db_path)
    db.ensure_location("default", "Default")
    for pattern_type, pattern in entries:
        db.add_watchlist(pattern=pattern, pattern_type=pattern_type, severity="high")
    return cfg, db, create_app(cfg, db)


@pytest.fixture()
def inert_client(tmp_path):
    """One entry that cannot fire, one that can — so every presence assertion
    below is made on a page that ALSO contains a healthy row. A warning that
    only renders when the whole watchlist is dead helps nobody."""
    cfg, db, app = _client(
        tmp_path,
        rules_path=str(SHIPPED_RULES),
        entries=[(INERT_TYPE, "ac:de:48"), (LIVE_TYPE, "3c:5a:b4:dd:ee:01")],
    )
    with TestClient(app) as c:
        c.db = db
        yield c
    db.close()


@pytest.fixture()
def healthy_client(tmp_path):
    """The over-correction control: a watchlist whose every entry CAN fire.
    Every absence assertion below runs against this."""
    cfg, db, app = _client(
        tmp_path,
        rules_path=str(SHIPPED_RULES),
        entries=[(LIVE_TYPE, "3c:5a:b4:dd:ee:01"), ("ssid", "MyTargetNet")],
    )
    with TestClient(app) as c:
        c.db = db
        yield c
    db.close()


def test_the_control_watchlist_really_is_all_live(healthy_client):
    """⭐ Verify the CONTROL, not just the treatment. If the "healthy" fixture
    were quietly all-inert, every absence assertion below would pass for the
    wrong reason and report a working guard over a broken one."""
    liveness = watchlist_liveness(
        healthy_client.app.state.config,
        healthy_client.db.watchlist_pattern_type_counts(),
    )

    assert liveness["known"] is True
    assert liveness["inert_count"] == 0, f"control is not clean: {liveness}"
    assert liveness["live_count"] == 2


def test_the_inert_fixture_really_is_mixed(inert_client):
    """The other half of the same rule: the treatment must be a treatment."""
    liveness = watchlist_liveness(
        inert_client.app.state.config,
        inert_client.db.watchlist_pattern_type_counts(),
    )

    assert liveness["known"] is True
    assert liveness["inert_count"] == 1
    assert liveness["live_count"] == 1
    assert liveness["inert_types"] == (INERT_TYPE,)


@pytest.mark.parametrize("path", ["/settings", "/watchlist/1"])
def test_an_inert_entry_is_flagged_on_every_surface_that_counts_it(inert_client, path):
    """⚠️ ``== 1``, not ``in``. A needle that appears twice can be satisfied by
    an element other than the one under test, and deleting the real one then
    leaves the suite green — measured on /watchlist, where the per-row tooltip
    also carried the phrase.
    """
    body = _prose(inert_client.get(path).text)

    assert body.count(CANNOT_FIRE) == 1, (
        f"{path} counts a {INERT_TYPE} entry that no enabled rule delegates "
        f"to, and says nothing about it (found {body.count(CANNOT_FIRE)} "
        f"occurrences of {CANNOT_FIRE!r}; expected exactly one)"
    )
    assert INERT_TYPE in body


def test_the_list_page_banner_reports_the_inert_count(inert_client):
    """The page-level headline, asserted with a needle ONLY the banner emits.

    🪤 This test exists because its predecessor did not fail when the banner
    was deleted: it matched "cannot fire" inside the per-row badge's `title`
    tooltip instead. Two renderings, one needle, and the guard was asleep.
    """
    body = _prose(inert_client.get("/watchlist").text)

    assert body.count(BANNER) == 1, (
        "the /watchlist page-level inert banner is missing (or duplicated)"
    )
    assert "status-pill-warn" in body
    assert INERT_TYPE in body


def test_the_list_page_marks_the_inert_row(inert_client):
    """The per-row marker, asserted separately from the banner. Deleting either
    one must fail exactly one of these two tests, not neither."""
    body = _prose(inert_client.get("/watchlist").text)

    row = re.search(r"<td>" + INERT_TYPE + r".{0,220}?</td>", body)
    assert row, f"could not locate the {INERT_TYPE} row in the rendered table"
    assert "badge-inert" in row.group(0), (
        f"the {INERT_TYPE} row carries no inert marker: {row.group(0)[:200]}"
    )


@pytest.mark.parametrize("path", ["/settings", "/watchlist", "/watchlist/1"])
def test_a_healthy_watchlist_carries_no_warning_anywhere(healthy_client, path):
    """⭐ The over-correction shape, and the more important half. A caution an
    operator sees on every install is one they learn to scroll past, which
    costs more than the note is worth — and here it would be false."""
    body = _prose(healthy_client.get(path).text)

    assert CANNOT_FIRE not in body
    assert CANNOT_FIRE_LIST not in body
    assert BANNER not in body
    assert "badge-inert" not in body


def test_the_live_entry_on_a_mixed_page_is_not_marked_inert(inert_client):
    """Scope the alarm to the row it applies to. A page-level warning that
    also marked the healthy rows would send an operator deleting entries that
    work."""
    body = _prose(inert_client.get("/watchlist").text)

    row = re.search(
        r"<td>" + LIVE_TYPE + r"(?:</td>|\s*<span[^>]*badge-inert)", body
    )
    assert row, f"could not locate the {LIVE_TYPE} row in the rendered table"
    assert "badge-inert" not in row.group(0), (
        f"the {LIVE_TYPE} row is marked inert; it can fire"
    )


def test_the_detail_page_of_a_live_entry_says_nothing(inert_client):
    """The live entry is #2 in the same mixed watchlist as the inert #1."""
    body = _prose(inert_client.get("/watchlist/2").text)

    assert CANNOT_FIRE not in body


def test_enabling_the_delegating_rule_silences_the_warning(tmp_path):
    """⭐ The whole point of deriving. Kev enables the six commented-out rules;
    the UI must go quiet with no code change here. A hardcoded list of dead
    types passes every other test in this file and fails this one.
    """
    revived = tmp_path / "revived.yaml"
    revived.write_text(
        "rules:\n"
        + "".join(
            f"  - name: delegating_{rt}\n"
            f"    rule_type: {rt}\n"
            f"    severity: high\n"
            f"    patterns: []\n"
            for rt in sorted(RULE_TYPE_DELEGATES_TO)
        ),
        encoding="utf-8",
    )
    cfg, db, app = _client(
        tmp_path, rules_path=str(revived), entries=[(INERT_TYPE, "ac:de:48")]
    )
    try:
        with TestClient(app) as client:
            settings = _prose(client.get("/settings").text)
            watchlist = _prose(client.get("/watchlist").text)
    finally:
        db.close()

    assert CANNOT_FIRE not in settings, (
        "the same entry that was flagged against the shipped ruleset is still "
        "flagged after its delegating rule was enabled — the verdict is not "
        "derived from the ruleset"
    )
    assert CANNOT_FIRE_LIST not in watchlist
    assert BANNER not in watchlist
    assert "badge-inert" not in watchlist


# --------------------------------------------------------------------------
# 4. Unknown must read as unknown. Never as dead.
# --------------------------------------------------------------------------


@pytest.mark.parametrize("broken", ["unset", "missing_file", "unparseable"])
def test_an_unanswerable_question_is_reported_as_unknown_not_as_dead(tmp_path, broken):
    """⛔ Telling an operator "your entries are inert" because the rules file
    has a typo would be a worse lie than the silence this replaces — they would
    go and delete rows that were fine.
    """
    if broken == "unset":
        rules_path = None
    elif broken == "missing_file":
        rules_path = str(tmp_path / "nope.yaml")
    else:
        bad = tmp_path / "bad.yaml"
        bad.write_text("rules: [[[not yaml", encoding="utf-8")
        rules_path = str(bad)

    cfg, db, app = _client(
        tmp_path, rules_path=rules_path, entries=[(INERT_TYPE, "ac:de:48")]
    )
    try:
        liveness = watchlist_liveness(cfg, db.watchlist_pattern_type_counts())
        with TestClient(app) as client:
            settings = _prose(client.get("/settings").text)
            watchlist = _prose(client.get("/watchlist").text)
            detail = _prose(client.get("/watchlist/1").text)
    finally:
        db.close()

    assert liveness["known"] is False
    assert liveness["inert_types"] == ()
    assert liveness["reason"], "unknown liveness must say WHY"

    assert CANNOT_FIRE not in settings
    assert CANNOT_FIRE not in detail
    assert CANNOT_FIRE_LIST not in watchlist
    assert BANNER not in watchlist
    assert "unknown" in settings, (
        "liveness could not be determined and /settings does not say so"
    )


# --------------------------------------------------------------------------
# 5. /healthz.json — the surface a monitoring tool reads.
# --------------------------------------------------------------------------


def test_healthz_reports_live_and_inert_rows(inert_client):
    """"Your watchlist has 12 entries" is a lie if seven of them cannot fire.
    A monitoring tool polling total_rows reads a healthy number over a
    watchlist that watches nothing."""
    check = inert_client.get("/healthz.json").json()["checks"]["watchlist"]

    assert check["total_rows"] == 2
    assert check["liveness_known"] is True
    assert check["live_rows"] == 1
    assert check["inert_rows"] == 1
    assert check["inert_pattern_types"] == [INERT_TYPE]


def test_healthz_keeps_its_existing_keys(inert_client):
    """The documented contract on /healthz.json is additions-only: existing
    keys never disappear. A consumer alerting on total_rows must not have the
    number change meaning under it."""
    check = inert_client.get("/healthz.json").json()["checks"]["watchlist"]

    for key in ("status", "total_rows", "by_pattern_type", "last_imported_at",
                "days_since_import", "stale"):
        assert key in check, f"/healthz.json watchlist check lost {key!r}"
    assert check["by_pattern_type"][INERT_TYPE] == 1


def test_healthz_reports_unknown_liveness_as_null_not_as_a_count(tmp_path):
    """⛔ These were `live_rows: <total>, inert_rows: 0` beside
    `liveness_known: false` — a contradiction shipped as a reassurance. A
    monitoring tool graphing `live_rows` without gating on the boolean read a
    clean bill off an unreadable rules file.

    🪤 **The previous version of this test asserted `inert_rows` and not
    `live_rows`**, so the defect passed it. An absence assertion with no
    presence assertion beside it is exactly the shape this project keeps
    getting caught by. Both are asserted now, and `total_rows` too — because
    "no count is known" must not be confused with "there are no rows".
    """
    cfg, db, app = _client(tmp_path, rules_path=None, entries=[(INERT_TYPE, "ac:de:48")])
    try:
        with TestClient(app) as client:
            check = client.get("/healthz.json").json()["checks"]["watchlist"]
    finally:
        db.close()

    assert check["liveness_known"] is False
    assert check["live_rows"] is None, (
        "liveness is unknown, so no row is KNOWN live; a number here is a claim "
        "nothing established"
    )
    assert check["inert_rows"] is None
    assert check["snoozed_rows"] is None
    assert check["inert_pattern_types"] == []
    assert check["snoozed_pattern_types"] == []
    # The presence half: the rows themselves are still counted and reported.
    assert check["total_rows"] == 1


# --------------------------------------------------------------------------
# 6. The map's completeness is proven against rules.py's SOURCE, not itself.
# --------------------------------------------------------------------------


def _delegating_rule_types_from_evaluate_source() -> dict[str, list[str]]:
    """Parse ``rules.evaluate`` and return every ``rule_type`` whose branch
    actually consults ``db``.

    ⭐ This exists because a cold review caught the previous proof being
    **partly circular**: ``_all_delegating_enabled()`` builds its ruleset by
    iterating ``RULE_TYPE_DELEGATES_TO``, so a real delegation branch MISSING
    from the map never got a rule of that type, evaluate() produced no hit,
    the module also said "not live", and the two agreed — passing.

    Reading the source is a genuinely independent side: it knows nothing about
    the map, and a new `elif rule.rule_type == "x":` branch that calls `db.`
    shows up here the moment it is written.
    """
    tree = ast.parse((REPO_ROOT / "src/lynceus/rules.py").read_text(encoding="utf-8"))
    evaluate_fn = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef) and n.name == "evaluate"
    )
    found: dict[str, list[str]] = {}
    for node in ast.walk(evaluate_fn):
        if not isinstance(node, ast.If):
            continue
        test = node.test
        if not (
            isinstance(test, ast.Compare)
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.Eq)
            and isinstance(test.left, ast.Attribute)
            and test.left.attr == "rule_type"
            and isinstance(test.comparators[0], ast.Constant)
        ):
            continue
        calls = sorted(set(re.findall(r"db\.(\w+)", ast.unparse(node.body))))
        if calls:
            found[test.comparators[0].value] = calls
    return found


def test_the_delegating_rule_types_are_derived_from_evaluate_not_from_the_map():
    """A branch that consults the DB and is absent from the map is a
    pattern_type reported inert while it fires perfectly well."""
    from_source = _delegating_rule_types_from_evaluate_source()

    assert len(from_source) >= 8, (
        f"only found {len(from_source)} DB-consulting branches in evaluate(); "
        f"the AST derivation has probably stopped matching: {sorted(from_source)}"
    )
    assert set(from_source) == set(RULE_TYPE_DELEGATES_TO), (
        f"delegation branches in rules.evaluate but NOT in the map: "
        f"{sorted(set(from_source) - set(RULE_TYPE_DELEGATES_TO))}; "
        f"in the map but with no DB-consulting branch: "
        f"{sorted(set(RULE_TYPE_DELEGATES_TO) - set(from_source))}"
    )


def test_a_rule_type_consulting_two_matchers_maps_to_two_pattern_types():
    """``watchlist_ssid`` dispatches `ssid` and `ssid_pattern` under one
    rule_type. Derived from the source rather than asserted as a literal: the
    branch calls two distinct `resolve_matched_*` helpers, and the map must
    carry as many pattern_types as the branch has matchers."""
    from_source = _delegating_rule_types_from_evaluate_source()

    multi = {
        rt: calls
        for rt, calls in from_source.items()
        if len([c for c in calls if c.startswith("resolve_matched_")]) > 1
    }
    assert multi, "expected at least one rule_type with two matchers"
    for rule_type, calls in multi.items():
        matchers = [c for c in calls if c.startswith("resolve_matched_")]
        assert len(RULE_TYPE_DELEGATES_TO[rule_type]) == len(matchers), (
            f"{rule_type} consults {len(matchers)} matchers ({matchers}) but the "
            f"map gives it {RULE_TYPE_DELEGATES_TO[rule_type]}"
        )


# --------------------------------------------------------------------------
# 7. Snoozed is not inert. A different cause, a different fix, said separately.
# --------------------------------------------------------------------------

SNOOZE_RULE_TYPE = "watchlist_mac"  # the rule_type serving LIVE_TYPE
SNOOZED_NOTE = "matches, but its alerts are being dropped"
SNOOZED_BANNER = "matching but silenced"


def _snooze_via_the_ui(client, rule_type: str = SNOOZE_RULE_TYPE) -> None:
    """Snooze through the sanctioned web path, not a direct DB write — the
    point of the finding is that this is reachable from the UI in one click."""
    client.get("/")
    token = client.cookies.get("lynceus_csrf")
    r = client.request(
        "POST",
        f"/rules/{rule_type}/snooze",
        data={"duration_seconds": "86400", "_csrf": token},
        follow_redirects=False,
    )
    assert r.status_code == 303, f"snooze POST failed: {r.status_code} {r.text[:200]}"


@pytest.fixture()
def snoozed_client(tmp_path):
    """A watchlist whose every entry's type is LIVE, with that rule_type
    snoozed from the UI. So every assertion below distinguishes 'silenced by
    the operator' from 'dead', on a watchlist with nothing wrong with it."""
    cfg, db, app = _client(
        tmp_path,
        rules_path=str(SHIPPED_RULES),
        entries=[(LIVE_TYPE, "3c:5a:b4:dd:ee:01")],
    )
    with TestClient(app) as c:
        c.db = db
        _snooze_via_the_ui(c)
        yield c
    db.close()


def test_the_snooze_fixture_really_snoozed_something(snoozed_client):
    """⭐ Verify the control. If the POST silently did nothing, every
    assertion below would pass against an unsnoozed watchlist and report a
    working feature that does not exist."""
    import time as _time

    snooze = snoozed_client.db.is_rule_type_snoozed(SNOOZE_RULE_TYPE, int(_time.time()))

    assert snooze is not None, "the UI snooze POST did not create a snooze"
    assert snooze.expires_at > int(_time.time())


def test_a_snoozed_type_is_reported_suppressed_and_NOT_inert(snoozed_client):
    """⛔ The whole point. Folding this into `inert_types` would tell the
    operator "no enabled rule delegates to this type" about a type they
    silenced themselves — sending them into rules.yaml to fix a file that is
    already correct."""
    import time as _time

    liveness = watchlist_liveness(
        snoozed_client.app.state.config,
        snoozed_client.db.watchlist_pattern_type_counts(),
        db=snoozed_client.db,
        now_ts=int(_time.time()),
    )

    assert liveness["suppressed_types"] == (LIVE_TYPE,)
    assert liveness["suppressed_count"] == 1
    assert liveness["inert_types"] == (), "a snoozed type must NOT read as inert"
    assert liveness["inert_count"] == 0
    assert liveness["live_types"] == (), "a suppressed type is not also counted live"
    assert liveness["live_count"] == 0


@pytest.mark.parametrize(
    ("path", "needle"),
    [
        ("/settings", "snoozed, not dead"),
        ("/watchlist", SNOOZED_BANNER),
        ("/watchlist/1", SNOOZED_NOTE),
    ],
)
def test_a_snoozed_entry_says_so_on_every_surface(snoozed_client, path, needle):
    body = _prose(snoozed_client.get(path).text)

    assert body.count(needle) == 1, (
        f"{path} does not report the snooze (found {body.count(needle)} "
        f"occurrences of {needle!r}, expected exactly one)"
    )
    assert CANNOT_FIRE not in body, (
        f"{path} calls a snoozed entry dead — that is the wrong explanation and "
        f"the wrong next step"
    )


def test_the_snoozed_row_is_badged_snoozed_and_not_inert(snoozed_client):
    body = _prose(snoozed_client.get("/watchlist").text)

    row = re.search(r"<td>" + LIVE_TYPE + r".{0,260}?</td>", body)
    assert row, f"could not locate the {LIVE_TYPE} row"
    assert "badge-snoozed-type" in row.group(0)
    assert "badge-inert" not in row.group(0)


def test_healthz_reports_a_snooze_separately_from_inert(snoozed_client):
    check = snoozed_client.get("/healthz.json").json()["checks"]["watchlist"]

    assert check["snoozed_rows"] == 1
    assert check["snoozed_pattern_types"] == [LIVE_TYPE]
    assert check["inert_rows"] == 0
    assert check["live_rows"] == 0


def test_a_healthy_watchlist_reports_no_snooze(healthy_client):
    """The absence half. Nothing is snoozed, so nothing may say it is."""
    check = healthy_client.get("/healthz.json").json()["checks"]["watchlist"]

    assert check["snoozed_rows"] == 0
    assert check["snoozed_pattern_types"] == []
    for path in ("/settings", "/watchlist", "/watchlist/1"):
        body = _prose(healthy_client.get(path).text)
        assert SNOOZED_BANNER not in body
        assert SNOOZED_NOTE not in body
        assert "badge-snoozed-type" not in body


def test_an_expired_snooze_stops_being_reported(tmp_path):
    """A snooze is temporary, and the report must be too — otherwise the
    warning outlives the condition and becomes the noise it was meant to
    replace. Graded at a now_ts past the expiry rather than by sleeping."""
    import time as _time

    cfg, db, app = _client(
        tmp_path, rules_path=str(SHIPPED_RULES), entries=[(LIVE_TYPE, "3c:5a:b4:dd:ee:01")]
    )
    try:
        with TestClient(app) as client:
            _snooze_via_the_ui(client)
        now = int(_time.time())
        during = watchlist_liveness(
            cfg, db.watchlist_pattern_type_counts(), db=db, now_ts=now
        )
        after = watchlist_liveness(
            cfg, db.watchlist_pattern_type_counts(), db=db, now_ts=now + 86_400 + 60
        )
    finally:
        db.close()

    assert during["suppressed_types"] == (LIVE_TYPE,)
    assert after["suppressed_types"] == (), "the snooze expired; the report did not"
    assert after["live_types"] == (LIVE_TYPE,)


def test_a_snooze_on_an_inert_type_does_not_offer_unsnooze_as_the_fix(tmp_path):
    """⚠️ Inert wins over snoozed, deliberately. Lifting a snooze on a type
    whose delegating rule is commented out changes nothing — reporting it as
    "snoozed" would offer a fix that does not work."""
    import time as _time

    cfg, db, app = _client(
        tmp_path, rules_path=str(SHIPPED_RULES), entries=[(INERT_TYPE, "ac:de:48")]
    )
    try:
        with TestClient(app) as client:
            _snooze_via_the_ui(client, "watchlist_oui")
        liveness = watchlist_liveness(
            cfg, db.watchlist_pattern_type_counts(), db=db, now_ts=int(_time.time())
        )
    finally:
        db.close()

    assert liveness["inert_types"] == (INERT_TYPE,)
    assert liveness["suppressed_types"] == ()


def test_liveness_without_a_db_reports_no_snoozes_rather_than_failing(tmp_path):
    """``db``/``now_ts`` are optional. A caller that only wants the ruleset
    verdict must still get one, and must not get a fabricated snooze set."""
    cfg, db, app = _client(
        tmp_path, rules_path=str(SHIPPED_RULES), entries=[(LIVE_TYPE, "3c:5a:b4:dd:ee:01")]
    )
    try:
        liveness = watchlist_liveness(cfg, db.watchlist_pattern_type_counts())
    finally:
        db.close()

    assert liveness["known"] is True
    assert liveness["suppressed_types"] == ()
    assert liveness["live_types"] == (LIVE_TYPE,)


# --------------------------------------------------------------------------
# 8. /watchlist.csv — the export an operator reviews offline.
# --------------------------------------------------------------------------


def _csv_rows(client, path="/watchlist.csv"):
    import csv as _csv
    import io as _io

    return list(_csv.reader(_io.StringIO(client.get(path).text)))


def test_the_csv_carries_can_fire_as_the_LAST_column(inert_client):
    """⚠️ Appended, never inserted. A consumer reading the existing columns
    positionally must keep working; a new column in the middle is a silent
    data-corruption bug in someone's spreadsheet.

    The prior column order is pinned as a literal ON PURPOSE — deriving it
    from the same header list the route builds would compare the code to
    itself and could never catch a reorder."""
    rows = _csv_rows(inert_client)
    header = rows[0]

    assert header[-1] == "can_fire"
    assert header[:21] == [
        "id", "pattern", "pattern_type", "severity", "description",
        "mac_range_prefix", "mac_range_prefix_length", "argus_record_id",
        "device_category", "confidence", "vendor", "source", "source_url",
        "source_excerpt", "fcc_id", "geographic_scope", "first_seen_iso_utc",
        "first_seen_unix", "last_verified_iso_utc", "last_verified_unix",
        "notes",
    ], "an existing CSV column moved; positional consumers just broke"


def test_the_csv_says_no_for_an_inert_row_and_yes_for_a_live_one(inert_client):
    rows = _csv_rows(inert_client)
    header, data = rows[0], rows[1:]
    pt, cf = header.index("pattern_type"), header.index("can_fire")
    verdicts = {r[pt]: r[cf] for r in data}

    assert verdicts[INERT_TYPE] == "no"
    assert verdicts[LIVE_TYPE] == "yes", (
        "the live row must say yes — an export that marked everything 'no' "
        "would pass a test that only checked the inert row"
    )


def test_the_csv_says_snoozed_and_unknown_in_those_states(snoozed_client, tmp_path):
    rows = _csv_rows(snoozed_client)
    header, data = rows[0], rows[1:]
    cf = header.index("can_fire")
    assert [r[cf] for r in data] == ["snoozed"]

    cfg, db, app = _client(
        tmp_path, rules_path=None, entries=[(LIVE_TYPE, "3c:5a:b4:dd:ee:01")]
    )
    try:
        with TestClient(app) as client:
            rows = _csv_rows(client)
    finally:
        db.close()
    assert [r[rows[0].index("can_fire")] for r in rows[1:]] == ["unknown"]
