"""Every surface that names a config file must name the one the daemon loads.

⛔ The defect these guard: twenty-one renderings across seven templates hard-coded
``rules.yaml`` / ``allowlist.yaml`` / ``allowlist_ui.yaml``, while the daemon
loads whatever ``config.rules_path`` and ``config.allowlist_path`` point at and
derives the UI sibling with :func:`lynceus.allowlist.derive_ui_path`, which
carries the stem AND the extension across. Seven of the twenty-one were
REMEDIES --
*"edit that file directly to remove"*, *"Edit rules.yaml on disk and restart"* --
so an operator with a non-default path was told to edit a file that does not
exist on their machine, and the entry they were trying to remove stayed silent.

⚠️ **The fixture uses non-default filenames on purpose.** The pre-existing guard
for this text (``test_alert_detail_state2_primary_match_shows_no_button``)
asserts ``"allowlist.yaml" in r.text`` against a fixture whose file IS named
``allowlist.yaml``, so it passed on the hard-coded literal and would have passed
on any other correct-by-accident spelling too. A guard for a wrong-filename
defect cannot use the right filename.

⭐ **Both directions are asserted for every surface**: the configured path must
be PRESENT, and the default basename must be ABSENT. The absence half alone is
satisfied by a block that stopped rendering at all, which is how a
"fixed"-looking template loses the sentence entirely.
"""

from __future__ import annotations

import re
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from lynceus.allowlist import derive_ui_path
from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import create_app

# Deliberately neither ``rules.yaml`` nor ``allowlist.yaml``, and one of them
# on a ``.yml`` extension so ``derive_ui_path``'s stem-preserving behaviour is
# exercised rather than assumed.
PRIMARY_NAME = "site-devices.yml"
RULES_NAME = "site-rules.yml"

# The literals that must never reach a rendered page. Not a style rule: each is
# a filename this install does not have.
DEFAULT_LITERALS = ("allowlist.yaml", "allowlist_ui.yaml", "rules.yaml")

MAC = "aa:bb:cc:dd:ee:ff"

# ⚠️ ONE exemption, and it is a claim, so it carries its reason and is asserted
# to still exist. `ble_bridge_checks.py`'s remedy names the repo's shipped file
# ON PURPOSE -- "the rules file this daemon actually loads -- `rules_path` in
# lynceus.yaml, which is not necessarily the config/rules.yaml shipped in the
# repo" -- which is the opposite of the defect these tests guard: it names the
# file in order to deny that it is the one in use. Exempted as an exact phrase,
# never as a substring like "config/", so a NEW sentence that merely mentions
# the same filename is still caught.
CORRECT_MENTIONS = (
    "which is not necessarily the config/rules.yaml shipped in the repo.",
)


def _drop_correct_mentions(text: str) -> str:
    for phrase in CORRECT_MENTIONS:
        text = text.replace(phrase, "")
    return text


def _prose(html: str) -> str:
    """Collapse whitespace so a needle can span the template's line wrapping.

    🪤 The sibling file records this trap twice already: a phrase that reads as
    one sentence on the page is not contiguous in the source, because the
    template wraps it -- and because ``<code>`` sits in the middle of several of
    these. Needles below are runs of PLAIN prose only, never spanning a tag.
    """
    return " ".join(html.split())


def _make_app(tmp_path, *, rules: bool = True, allowlist: bool = True):
    """App whose config files are named nothing like the defaults."""
    primary = tmp_path / PRIMARY_NAME
    rules_file = tmp_path / RULES_NAME
    if allowlist:
        primary.write_text(
            f"entries:\n  - pattern: {MAC}\n    pattern_type: mac\n", encoding="utf-8"
        )
    if rules:
        # `watchlist_oui` only: an `ssid` watchlist row is then INERT, which is
        # what makes the "no enabled rule delegates" prose render.
        rules_file.write_text(
            "rules:\n"
            "  - name: r1\n"
            "    rule_type: watchlist_oui\n"
            "    enabled: true\n"
            "    severity: med\n",
            encoding="utf-8",
        )
    config = Config(
        db_path=str(tmp_path / "ui.db"),
        allowlist_path=str(primary) if allowlist else None,
        rules_path=str(rules_file) if rules else None,
    )
    db = Database(config.db_path)
    return create_app(config, db), db, config


def _seed(db) -> tuple[int, int]:
    """A device + alert on the allowlisted MAC, and an inert watchlist row."""
    ts = 100
    db.upsert_device(MAC, "wifi", None, 0, ts)
    alert_id = db.add_alert(ts=ts, rule_name="r", mac=MAC, message="m", severity="med")
    watchlist_id, _ = db.add_watchlist(
        pattern="HomeNet", pattern_type="ssid", severity="high", description="d"
    )
    return alert_id, watchlist_id


# Which configured path each surface has to name. Derived from the Config at
# assert time -- never a copied string, so a change to the fixture cannot leave
# a test asserting a filename nothing renders.
SURFACES = (
    ("/alerts/{alert_id}", "allowlist"),
    ("/allowlist", "allowlist"),
    (f"/devices/{MAC}", "allowlist"),
    ("/rules", "rules"),
    ("/settings", "rules"),
    ("/watchlist", "rules"),
    ("/watchlist/{watchlist_id}", "rules"),
)


@pytest.mark.webui
@pytest.mark.parametrize("route,which", SURFACES, ids=[s[0] for s in SURFACES])
def test_surface_names_the_configured_file_and_not_the_default(tmp_path, route, which):
    app, db, config = _make_app(tmp_path)
    try:
        alert_id, watchlist_id = _seed(db)
        with TestClient(app) as client:
            r = client.get(route.format(alert_id=alert_id, watchlist_id=watchlist_id))
        assert r.status_code == 200, route
        expected = config.allowlist_path if which == "allowlist" else config.rules_path
        # Treatment: the file the daemon loads is the file the page names.
        assert expected in r.text, (
            f"{route} names no configured path; it must name {expected!r}"
        )
        # Control: and the file it does NOT load is named nowhere.
        scanned = _drop_correct_mentions(" ".join(r.text.split()))
        for literal in DEFAULT_LITERALS:
            assert literal not in scanned, (
                f"{route} still renders the literal {literal!r}"
            )
    finally:
        db.close()


@pytest.mark.webui
def test_allowlist_page_names_the_derived_ui_sibling(tmp_path):
    """The UI file is DERIVED, so the page cannot name a fixed one.

    ``derive_ui_path`` preserves stem and extension: the sibling of
    ``site-devices.yml`` is ``site-devices_ui.yml``, not ``allowlist_ui.yaml``.
    """
    app, db, config = _make_app(tmp_path)
    try:
        _seed(db)
        with TestClient(app) as client:
            r = client.get("/allowlist")
        assert r.status_code == 200
        expected_ui = str(derive_ui_path(Path(config.allowlist_path)))
        assert expected_ui.endswith("site-devices_ui.yml"), expected_ui  # fixture sanity
        assert expected_ui in r.text
    finally:
        db.close()


@pytest.mark.webui
@pytest.mark.parametrize("route", ["/rules", "/watchlist/{watchlist_id}"])
def test_no_surface_renders_an_empty_file_reference(tmp_path, route):
    """With no ``rules_path`` at all, no page may render a blank filename.

    ⚠️ These are the two sites that can render with the path unset -- every
    other rules-file sentence sits behind a liveness verdict, and ``known`` is
    False when there is no ``rules_path``. A blank ``<code></code>`` reads as a
    filename the operator failed to notice, which is worse than the wrong name
    this change removed.
    """
    app, db, _ = _make_app(tmp_path, rules=False)
    try:
        _, watchlist_id = _seed(db)
        with TestClient(app) as client:
            r = client.get(route.format(watchlist_id=watchlist_id))
        assert r.status_code == 200
        assert not re.search(r"<code>\s*</code>", r.text), (
            f"{route} rendered an empty <code> element with rules_path unset"
        )
        for literal in DEFAULT_LITERALS:
            assert literal not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_rules_footer_says_no_rules_file_is_loaded_when_unset(tmp_path):
    """The unset case gets its own sentence, not a degraded one.

    "Edit rules.yaml on disk and restart" sent an operator with no configured
    rules file to edit a file the daemon would never read, and the restart it
    told them to perform would have changed nothing.
    """
    app, db, _ = _make_app(tmp_path, rules=False)
    try:
        with TestClient(app) as client:
            r = client.get("/rules")
        assert r.status_code == 200
        assert "No rules file is loaded" in _prose(r.text)
        assert "rules_path" in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_snoozed_note_names_the_configured_rules_file(tmp_path):
    """The snooze branch carries the same sentence and the same defect.

    Reached only by an entry whose type is delegated AND snoozed, which is why
    it is driven here rather than left to the parametrised sweep above.
    """
    app, db, config = _make_app(tmp_path)
    try:
        # `oui` is delegated by the fixture ruleset, so this row is live...
        watchlist_id, _ = db.add_watchlist(
            pattern="00:11:22", pattern_type="oui", severity="high", description="d"
        )
        now = int(time.time())
        # ...and snoozing its serving rule_type puts it in the snoozed branch.
        db.add_rule_type_snooze("watchlist_oui", now + 3600, now)
        with TestClient(app) as client:
            r = client.get(f"/watchlist/{watchlist_id}")
        assert r.status_code == 200
        assert "needs changing" in _prose(r.text), "the snoozed branch did not render"
        assert config.rules_path in r.text
        assert "rules.yaml" not in r.text
    finally:
        db.close()


@pytest.mark.webui
def test_never_match_note_names_the_configured_rules_file(tmp_path):
    """The OUI never-matches note is the one rules-file sentence with no
    liveness guard in front of it, so it is driven separately.

    ⚠️ It is also the only one the parametrised sweep above cannot reach: the
    row has to be on a reserved prefix, which ``add_watchlist`` refuses to
    insert, so it goes in the way the importer puts it there.
    """
    app, db, config = _make_app(tmp_path)
    try:
        with db._conn:
            cur = db._conn.execute(
                "INSERT INTO watchlist(pattern, pattern_type, severity) VALUES (?, ?, ?)",
                ("de:ad:be", "oui", "high"),
            )
            watchlist_id = int(cur.lastrowid)
        with TestClient(app) as client:
            r = client.get(f"/watchlist/{watchlist_id}")
        assert r.status_code == 200
        prose = _prose(r.text)
        assert "This entry can never match." in prose, "the never-match branch did not render"
        assert "will not change that for this row" in prose
        assert config.rules_path in r.text
        assert "rules.yaml" not in r.text
    finally:
        db.close()


def _strip_jinja_comments(text: str) -> str:
    """Blank ``{# ... #}`` blocks -- they never reach the operator.

    The comments in these templates deliberately quote the old wording as the
    record of what was wrong with it, so a scan that did not strip them would
    have to be satisfied with a weaker pattern.

    ⚠️ Blanked, not deleted: newlines are preserved so the line numbers this
    guard reports are the FILE's. The first version removed them and reported
    settings.html:121 for a line that is at 131 -- a guard that sends you to the
    wrong line costs more than the seconds it saves.
    """
    return re.sub(
        r"\{#.*?#\}",
        lambda m: re.sub(r"[^\n]", " ", m.group(0)),
        text,
        flags=re.DOTALL,
    )


def test_no_template_hard_codes_a_config_filename():
    """Backstop: the next surface to name a file must not name a fixed one.

    ⚠️ This is a spelling guard, and it is here precisely because the defect IS
    a spelling -- it catches a NEW hard-coded site that the per-surface tests
    above cannot, since they only visit surfaces that already exist. It is not
    a substitute for them: it cannot tell a correct path from a missing one.
    """
    template_dir = Path(__file__).resolve().parents[1] / "src/lynceus/webui/templates"
    templates = sorted(template_dir.glob("*.html"))
    assert len(templates) > 20, f"template glob found only {len(templates)} files"
    offenders = []
    for path in templates:
        body = _strip_jinja_comments(path.read_text(encoding="utf-8"))
        for lineno, line in enumerate(body.splitlines(), 1):
            for literal in DEFAULT_LITERALS:
                if literal in line:
                    offenders.append(f"{path.name}:{lineno}: {line.strip()}")
    assert not offenders, (
        "templates must name the configured path (rules_file() / allowlist_file() "
        "/ allowlist_ui_file()), never a fixed filename:\n" + "\n".join(offenders)
    )


@pytest.mark.webui
def test_the_exemption_is_live_and_is_still_the_sentence_it_was_written_for(tmp_path):
    """An exemption is a claim, so it is checked rather than trusted.

    ⭐ Asserted against the RENDERED page, not the source: the remedy is built
    from implicit string concatenation, so a source grep would be testing the
    line wrapping. This proves the exempted phrase actually reaches the page
    (an exemption nobody hits is a hole waiting for a different sentence) and
    that it still reads as a DENIAL that the repo file is the one in use.
    """
    app, db, _ = _make_app(tmp_path)
    try:
        _seed(db)
        with TestClient(app) as client:
            rendered = " ".join(client.get("/settings").text.split())
    finally:
        db.close()
    for phrase in CORRECT_MENTIONS:
        assert phrase in rendered, (
            f"the exemption is not exercised by any page; re-read it: {phrase!r}"
        )
    assert "the rules file this daemon actually loads" in rendered
    # ...and with it removed, the page is clean -- i.e. the exemption is the
    # ONLY thing standing between this page and the assertion above.
    assert "rules.yaml" not in _drop_correct_mentions(rendered)

