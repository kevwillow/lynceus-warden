"""Reserved and locally-administered OUI rows remain permanently unmatchable."""

from __future__ import annotations

import re
from pathlib import Path

from starlette.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.kismet import DeviceObservation
from lynceus.rules import Rule, Ruleset, evaluate
from lynceus.webui.app import create_app
from lynceus.webui.liveness import oui_prefix_never_matches

REPO_ROOT = Path(__file__).resolve().parents[1]
SHIPPED_RULES = REPO_ROOT / "config" / "rules.yaml"


def _insert_watchlist(db: Database, pattern: str, pattern_type: str) -> int:
    """Mirror the importer path, which bypasses add_watchlist validation."""
    with db._conn:
        cur = db._conn.execute(
            "INSERT INTO watchlist(pattern, pattern_type, severity) VALUES (?, ?, ?)",
            (pattern, pattern_type, "high"),
        )
        return int(cur.lastrowid)


def _prose(html: str) -> str:
    return " ".join(re.sub(r"<!--.*?-->", " ", html, flags=re.S).split())


def _row_html(page: str, watchlist_id: int) -> str:
    # 🪤 NOT an f-string. `{0,800}` inside one is parsed as a FORMAT FIELD, so
    # the pattern became `/watchlist/1".(0, 800)?</tr>` and matched nothing —
    # the test failed while the feature worked. Concatenate instead, so the
    # regex quantifier stays a regex quantifier.
    match = re.search(
        r'/watchlist/' + str(watchlist_id) + r'".{0,800}?</tr>', _prose(page)
    )
    assert match, f"row {watchlist_id} not found in the rendered table"
    return match.group(0)


def _observation(mac: str) -> DeviceObservation:
    return DeviceObservation(
        mac=mac,
        device_type="wifi",
        first_seen=1_786_800_000,
        last_seen=1_786_800_000,
        rssi=-40,
        ssid=None,
        oui_vendor=None,
        is_randomized=False,
    )


def test_oui_prefix_never_matches_uses_the_rules_engine_check_as_is():
    assert oui_prefix_never_matches("oui", "00:00:00") == "00:00:00"
    assert oui_prefix_never_matches("oui", "de:ad:be") == (
        "locally-administered (first octet de)"
    )
    assert oui_prefix_never_matches("oui", "3c:5a:b4") is None
    assert oui_prefix_never_matches("mac", "de:ad:be:11:22:33") is None
    assert oui_prefix_never_matches("oui", None) is None


def test_reserved_oui_rows_cannot_alert_even_with_the_delegating_rule_enabled(tmp_path):
    db = Database(str(tmp_path / "watchlist.db"))
    try:
        _insert_watchlist(db, "de:ad:be", "oui")
        _insert_watchlist(db, "3c:5a:b4", "oui")
        ruleset = Ruleset(
            rules=[
                Rule(
                    name="delegating_oui",
                    rule_type="watchlist_oui",
                    severity="high",
                    patterns=[],
                )
            ]
        )

        assert not evaluate(ruleset, _observation("de:ad:be:11:22:33"), False, db=db)
        assert len(evaluate(ruleset, _observation("3c:5a:b4:11:22:33"), False, db=db)) == 1
    finally:
        db.close()


def test_watchlist_renders_never_independently_of_the_inert_marker(tmp_path):
    cfg = Config(db_path=str(tmp_path / "watchlist.db"), rules_path=str(SHIPPED_RULES))
    db = Database(cfg.db_path)
    db.ensure_location("default", "Default")
    try:
        never_id = _insert_watchlist(db, "de:ad:be", "oui")
        control_id = _insert_watchlist(db, "3c:5a:b4", "oui")
        mac_id = _insert_watchlist(db, "de:ad:be:11:22:33", "mac")
        with TestClient(create_app(cfg, db)) as client:
            list_page = client.get("/watchlist").text
            detail = _prose(client.get(f"/watchlist/{never_id}").text)
    finally:
        db.close()

    never_row = _row_html(list_page, never_id)
    assert ">never<" in never_row
    assert ">inert<" in never_row, "the permanent warning shadowed the inert cause"
    assert ">never<" not in _row_html(list_page, control_id)
    assert ">never<" not in _row_html(list_page, mac_id)
    assert "This entry can never match." in detail
    # 🪤 Needle chosen to contain NO inline markup. The template renders
    # `Editing <code>rules.yaml</code> will not change that...`, so the obvious
    # phrase is not contiguous in the HTML. Third instance of this trap today
    # (a CSS comment, a <span> splitting "Marked inert", now <code>).
    # ⇒ Assert on a run of plain prose, never one spanning a tag.
    assert "will not change that for this row" in detail
    assert "rules.yaml" in detail, "the note does not name the file it is about"
    assert "locally-administered (first octet de)" in detail
    assert "This entry cannot currently fire." in detail


def test_the_verdict_decides_not_the_reason_string(monkeypatch):
    """⚠️ `oui_prefix_never_matches` must key on the BOOLEAN, never on whether
    the reason string is truthy.

    The first version returned `reason if is_reserved else None`, so a
    `(True, None)` or `(True, "")` from the rules engine would silently answer
    "this row can match" — a guard reporting "no" because it could not describe
    its own finding. Unreachable today; this pins it.
    """
    import lynceus.webui.liveness as liveness

    monkeypatch.setattr(liveness, "_is_reserved_oui_mac", lambda mac: (True, None))
    assert liveness.oui_prefix_never_matches("oui", "de:ad:be") is not None

    monkeypatch.setattr(liveness, "_is_reserved_oui_mac", lambda mac: (True, ""))
    assert liveness.oui_prefix_never_matches("oui", "de:ad:be") is not None

    monkeypatch.setattr(liveness, "_is_reserved_oui_mac", lambda mac: (False, "noise"))
    assert liveness.oui_prefix_never_matches("oui", "ac:de:48") is None
