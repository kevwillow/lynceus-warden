"""Diagnostic: read-only baseline of the home-page unacknowledged-alerts
ack-flow (0.9.0 FIX arc, step 1).

Captures, in a runnable + inspectable form, the behavior AS OF the 0.9.0
FIX arc step-1, so the step-2 htmx-partial-swap fix had a documented
baseline to diff against.

⚠️ Step-2 has since SHIPPED. The bullets below are that pre-fix baseline,
NOT current behavior: the home ack control now carries hx-post/hx-target/
hx-swap, and htmx wiring is no longer absent from the templates. The
assertions at the foot of this test are the part that tracks today's
state; read them, not this list, for what is true now.

Baseline as captured:

  - the per-alert ack route's response when clicked from the home
    surface: POST /alerts/{id}/ack -> 303 redirect to / (a FULL document
    navigation, NOT a partial swap)
  - the home query that builds the unacknowledged-alerts table:
    db.list_alerts(limit=10, acknowledged=False), ORDER BY a.ts DESC,
    a.id DESC LIMIT ? OFFSET ?
  - the ack control's wiring in index.html (plain <form method="post">,
    NO hx-* attributes, NO stable per-row id usable as a swap target)
  - that htmx.min.js is LOADED but DORMANT: no template emits any hx-*
    attribute, and the bulk-ack "partial" (bulk_ack_result.html) actually
    extends base.html (a full page) -- so there is NO existing
    partial-swap pattern to mirror
  - the two-symptoms-one-root mechanism: because ack triggers a full
    reload that re-renders the entire top-N unack list, (a) the document
    scrolls to top, and (b) a live-poll insert reorders/replaces what the
    operator saw between render and reload

Observation-only, plus a handful of baseline assertions that PIN the
current full-reload behavior. Those assertions are expected to FLIP when
the ack flow becomes an htmx in-place swap -- which is exactly what makes
this a useful regression anchor for the next step.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import create_app
from lynceus.webui.csrf import CSRF_COOKIE_NAME, CSRF_FORM_FIELD

pytestmark = pytest.mark.diagnostic

_TEMPLATES = (
    Path(__file__).resolve().parent.parent
    / "src" / "lynceus" / "webui" / "templates"
)
_STATIC = (
    Path(__file__).resolve().parent.parent
    / "src" / "lynceus" / "webui" / "static"
)


_UNACKED_HEADING = "recent unacknowledged alerts"


def _home_unacked_block(index_html: str) -> str:
    """Return the markup of the home page's unacknowledged-alerts card.

    ⚠️ Anchor on the operator-facing heading TEXT, never on the container
    markup. The original form of this extractor pinned
    ``<article>\\s*<header><strong>recent unacknowledged alerts</strong>``,
    and the dashboard restructure — which moved the card to
    ``<section class="block block-alerts">`` with an ``<h3>`` heading, and
    changed nothing about the ack control this diagnostic exists to observe —
    reduced it to a sentinel string. It failed loudly only because a later
    assertion happened to look inside the result.

    So: find the heading wherever it is and at whatever level, walk back to
    the container that opens it and forward to that container's close, and
    raise here rather than returning a placeholder that fails somewhere less
    informative.
    """
    heading = re.search(
        rf"<h[1-6][^>]*>\s*{re.escape(_UNACKED_HEADING)}\s*</h[1-6]>",
        index_html,
        flags=re.IGNORECASE,
    )
    if heading is None:
        raise AssertionError(
            f"no heading matching {_UNACKED_HEADING!r} in index.html. Either "
            "the home page no longer surfaces unacknowledged alerts under that "
            "name — in which case this diagnostic needs re-scoping, not a "
            "wider regex — or the heading is no longer an <h1>-<h6>."
        )
    starts = [
        index_html.rfind(f"<{tag}", 0, heading.start()) for tag in ("section", "article")
    ]
    start = max(starts)
    if start < 0:
        raise AssertionError(
            "found the unacknowledged-alerts heading but no enclosing <section> "
            "or <article> before it; the card's container tag has changed."
        )
    opener = "section" if index_html.startswith("<section", start) else "article"
    close = index_html.find(f"</{opener}>", heading.end())
    if close < 0:
        raise AssertionError(
            "found the unacknowledged-alerts container but not its closing tag."
        )
    return index_html[start:close]


def _csrf_token(client) -> str:
    """Mirror tests/test_webui.py::_csrf_setup -- a safe-method GET sets
    the double-submit cookie; the same value goes in the _csrf form field."""
    resp = client.get("/")
    return resp.cookies[CSRF_COOKIE_NAME]


def _recent_unack_table_rows(html: str) -> list[list[str]]:
    """Pull the <td> cells of each row in the 'recent unacknowledged
    alerts' table on the home page."""
    idx = html.find("recent unacknowledged alerts")
    if idx < 0:
        return []
    table_m = re.search(r"<table>(.*?)</table>", html[idx:], flags=re.DOTALL)
    if not table_m:
        return []
    tbody_m = re.search(r"<tbody>(.*?)</tbody>", table_m.group(1), flags=re.DOTALL)
    if not tbody_m:
        return []
    rows: list[list[str]] = []
    for tr in re.findall(r"<tr[^>]*>(.*?)</tr>", tbody_m.group(1), flags=re.DOTALL):
        cells = [
            re.sub(r"\s+", " ", c).strip()
            for c in re.findall(r"<td[^>]*>(.*?)</td>", tr, flags=re.DOTALL)
        ]
        rows.append(cells)
    return rows


def _seed_unacked(db: Database, n: int, *, base_ts: int) -> list[int]:
    """Seed n unacknowledged alerts with strictly increasing ts so the
    home query's ORDER BY ts DESC, id DESC returns them newest-first.
    Returns the alert ids in seeding (ascending-ts) order."""
    ids: list[int] = []
    for i in range(n):
        mac = f"de:ad:be:ef:00:{i:02x}"
        # alerts.mac is a FK -> devices(mac), so the device must exist first.
        db.upsert_device(
            mac=mac, device_type="wifi", oui_vendor="DiagVendor",
            is_randomized=0, now_ts=base_ts + i,
        )
        aid = db.add_alert(
            ts=base_ts + i,
            rule_name=f"rule_{i:02d}",
            mac=mac,
            message=f"alert seeded #{i:02d}",
            severity=("high" if i % 3 == 0 else "med" if i % 3 == 1 else "low"),
        )
        ids.append(aid)
    return ids


def test_diag_home_ack_flow(diag, tmp_path):
    config = Config(
        db_path=str(tmp_path / "diag.db"),
        kismet_health_check_on_startup=False,
        evidence_capture_enabled=False,
    )
    db = Database(config.db_path)
    app = create_app(config, db)

    # =================================================================
    # ITEM 1 + 5 -- ROUTE + SCROLL: what does ack return from home?
    # =================================================================
    diag.section("ITEM 1/5 -- ack route response from the home surface")
    base_ts = 1_700_000_000
    ids = _seed_unacked(db, 12, base_ts=base_ts)
    diag.fixture(
        f"seeded {len(ids)} unacknowledged alerts, ts {base_ts}..{base_ts + 11} "
        f"(ids {ids[0]}..{ids[-1]})"
    )
    diag.fixture(
        "home query is db.list_alerts(limit=10, acknowledged=False) -- "
        "so 10 of 12 are visible; ids for ts 1700000000 and 1700000001 "
        "are OFF-PAGE below the limit-10 cut."
    )

    top_alert_id = ids[-1]  # highest ts -> top row of the home table
    with TestClient(app, follow_redirects=False) as client:
        token = _csrf_token(client)
        diag.exercise(
            f"POST /alerts/{top_alert_id}/ack with Referer http://testserver/ "
            "(the home surface) and a valid _csrf form field"
        )
        ack_resp = client.post(
            f"/alerts/{top_alert_id}/ack",
            data={CSRF_FORM_FIELD: token},
            headers={"Referer": "http://testserver/"},
        )
        diag.observed(f"ack response status_code: {ack_resp.status_code}")
        diag.observed(
            f"ack response Location header: {ack_resp.headers.get('location')!r}"
        )
        diag.observed(
            f"ack response Content-Type: "
            f"{ack_resp.headers.get('content-type')!r}"
        )
        diag.observed(f"ack response body length: {len(ack_resp.content)} bytes")
        diag.observed(
            "ack response carries NO HX-* response headers "
            f"(HX-Retarget/HX-Reswap/HX-Trigger): "
            f"{[k for k in ack_resp.headers if k.lower().startswith('hx-')]}"
        )

        # Follow the redirect manually to show it lands on a FULL document.
        reload_resp = client.get("/")
        diag.observed(f"following redirect -> GET / status: {reload_resp.status_code}")
        is_full_doc = (
            "<!DOCTYPE html>" in reload_resp.text
            and "</html>" in reload_resp.text
        )
        diag.observed(
            "GET / returns a FULL HTML document "
            f"(<!DOCTYPE html> .. </html> present): {is_full_doc}"
        )
        diag.observed(
            f"acked alert {top_alert_id} now acknowledged in DB: "
            f"{db.get_alert(top_alert_id)['acknowledged']}"
        )

    diag.notes(
        "CONFIRMS recall on path/verb: the route IS POST /alerts/{id}/ack "
        "(webui/app.py:2084 ack_alert). It returns RedirectResponse(target, "
        "303) where target = _safe_redirect_target(request, default='/alerts'). "
        "From the home surface the Referer is /, so _safe_redirect_target "
        "(webui/app.py:639) returns '/' -- a 303 to GET /, a full document "
        "navigation. THIS is the scroll-jump mechanism (item 5): the browser "
        "replaces the document and resets scroll to the top. No partial swap "
        "is involved."
    )

    # =================================================================
    # ITEM 2 -- HOME TEMPLATE: ack control wiring + row id
    # =================================================================
    diag.section("ITEM 2 -- index.html ack control wiring")
    index_html = (_TEMPLATES / "index.html").read_text(encoding="utf-8")
    block = _home_unacked_block(index_html)
    diag.observed("--- index.html 'recent unacknowledged alerts' block (verbatim) ---")
    for line in block.splitlines():
        diag.observed(f"  {line}")
    ack_form_needle = '<form method="post" action="/alerts/'
    diag.observed(
        f"ack control is a plain form POST: {ack_form_needle in block}"
    )
    diag.observed(
        f"block contains any hx-* attribute: {'hx-' in block}"
    )
    has_row_id = bool(re.search(r'<tr[^>]*\\bid=', block))
    diag.observed(
        "per-row <tr> has class row-sev-<sev> but NO id attribute: "
        f"row id present = {has_row_id}; "
        "the DB alert id (a.id) appears ONLY inside URLs "
        "(/alerts/{id}, /alerts/{id}/ack), not as an element id/swap target."
    )

    # =================================================================
    # ITEM 3 -- ALERT MODEL / QUERY: fields, ordering, filter, limit
    # =================================================================
    diag.section("ITEM 3 -- alert fields + home unack query")
    cols = [r["name"] for r in db._conn.execute("PRAGMA table_info(alerts)")]
    diag.observed(f"alerts table columns: {cols}")
    diag.observed(
        "home query: webui/app.py:1425 -> db.list_alerts(limit=10, "
        "acknowledged=False)"
    )
    diag.observed(
        "list_alerts SQL (db.py:1320): SELECT a.id, a.ts, a.rule_name, "
        "a.rule_type, a.mac, a.message, a.severity, a.acknowledged ... "
        "WHERE a.acknowledged = 0 ORDER BY a.ts DESC, a.id DESC LIMIT ? OFFSET ?"
    )
    rows = db.list_alerts(limit=10, acknowledged=False)
    diag.observed(f"rows returned by the home query (count): {len(rows)}")
    diag.observed(
        "ordering as returned (id, ts, severity): "
        + ", ".join(f"({r['id']},{r['ts']},{r['severity']})" for r in rows)
    )
    diag.notes(
        "Newest-first by ts then id, capped at 10. A live-poll INSERT mints "
        "an alert with ts = now (>= every existing ts), so it lands at the "
        "TOP and pushes the whole list down one slot -- and any alert that "
        "was sitting at slot 10 falls off the page. This is the structural "
        "cause of symptom (b)."
    )

    # =================================================================
    # ITEM 4 -- HTMX PATTERN PRESENT? (recall said maybe; verify)
    # =================================================================
    diag.section("ITEM 4 -- existing htmx partial-swap pattern?")
    hx_hits: list[str] = []
    for tpl in sorted(_TEMPLATES.glob("*.html")):
        text = tpl.read_text(encoding="utf-8")
        for m in re.finditer(r"hx-[a-z-]+", text):
            hx_hits.append(f"{tpl.name}: {m.group(0)}")
    diag.observed(f"hx-* attribute occurrences across ALL templates: {len(hx_hits)}")
    for h in hx_hits:
        diag.observed(f"  {h}")
    base_html = (_TEMPLATES / "base.html").read_text(encoding="utf-8")
    diag.observed(
        f"base.html loads htmx.min.js: {'htmx.min.js' in base_html}"
    )
    bulk = (_TEMPLATES / "bulk_ack_result.html").read_text(encoding="utf-8")
    diag.observed(
        "bulk_ack_result.html FIRST LINE (is it a partial or a full page?): "
        f"{bulk.splitlines()[0]!r}"
    )
    extends_marker = '{% extends "base.html" %}'
    diag.observed(
        "bulk_ack_result.html extends base.html (=> full page, NOT a partial): "
        f"{extends_marker in bulk}"
    )
    watchful = (_TEMPLATES / "_watchful_actions.html").read_text(encoding="utf-8")
    diag.observed(
        f"_watchful_actions.html uses any hx-* attribute: {'hx-' in watchful}"
    )
    watchful_form_needle = 'method="post"'
    diag.observed(
        "_watchful_actions.html confirm/dismiss/promote are plain "
        f"<form method=\"post\" ...>: {watchful_form_needle in watchful}"
    )
    lynceus_js = (_STATIC / "lynceus.js").read_text(encoding="utf-8")
    diag.observed(
        "lynceus.js references htmx ONLY via an htmx:afterSwap listener "
        "(re-formats <time> elements after a swap that currently never "
        f"fires): {'htmx:afterSwap' in lynceus_js}"
    )
    diag.notes(
        "RECALL WAS WRONG. There is NO existing htmx in-place / partial-swap "
        "pattern anywhere -- not in the allowlist UI, not in watchful "
        "confirm/dismiss. htmx.min.js is loaded in base.html and lynceus.js "
        "registers an htmx:afterSwap handler, but ZERO templates emit any "
        "hx-* attribute, so nothing ever triggers a swap. The bulk-ack "
        "surfaces (POST /alerts/bulk-ack and POST /alerts/ack-all-visible) "
        "render bulk_ack_result.html, which EXTENDS base.html -- i.e. a full "
        "results page reached by full navigation, not a partial swap. The fix "
        "must BUILD a new htmx swap pattern, not mirror an existing one."
    )

    # =================================================================
    # symptom (b) DEMONSTRATION -- live-poll insert reorders the list
    # =================================================================
    diag.section("symptom (b) -- live-poll insert reorders/replaces visible rows")
    config2 = Config(
        db_path=str(tmp_path / "diag2.db"),
        kismet_health_check_on_startup=False,
        evidence_capture_enabled=False,
    )
    db2 = Database(config2.db_path)
    app2 = create_app(config2, db2)
    ids2 = _seed_unacked(db2, 12, base_ts=base_ts)
    diag.fixture(f"fresh DB, seeded 12 alerts (ids {ids2[0]}..{ids2[-1]})")

    with TestClient(app2, follow_redirects=False) as client:
        token2 = _csrf_token(client)
        before = _recent_unack_table_rows(client.get("/").text)
        diag.observed(f"BEFORE ack: visible top-{len(before)} rows (Timestamp|Sev|Rule cells):")
        for i, cells in enumerate(before):
            # cells[0]=time, [1]=sev badge, [2]=rule link
            diag.observed(f"  slot[{i}] = {cells[:3]}")

        the_row_operator_sees = ids2[-1]  # top of the table (highest ts)
        diag.exercise(
            "LIVE POLL fires between render and click: daemon mints a NEW "
            f"alert with ts {base_ts + 999} (newer than everything on screen)"
        )
        db2.upsert_device(
            mac="de:ad:be:ef:99:99", device_type="wifi", oui_vendor="DiagVendor",
            is_randomized=0, now_ts=base_ts + 999,
        )
        new_id = db2.add_alert(
            ts=base_ts + 999,
            rule_name="rule_LIVE_POLL",
            mac="de:ad:be:ef:99:99",
            message="freshly minted by the daemon mid-interaction",
            severity="high",
        )
        diag.exercise(
            f"operator clicks Acknowledge on the row they SAW at the top "
            f"(alert id {the_row_operator_sees}); full POST -> 303 -> reload"
        )
        client.post(
            f"/alerts/{the_row_operator_sees}/ack",
            data={CSRF_FORM_FIELD: token2},
            headers={"Referer": "http://testserver/"},
        )
        after = _recent_unack_table_rows(client.get("/").text)
        diag.observed(f"AFTER ack+reload: visible top-{len(after)} rows:")
        for i, cells in enumerate(after):
            diag.observed(f"  slot[{i}] = {cells[:3]}")
        diag.observed(
            f"newly-minted alert id {new_id} (rule_LIVE_POLL) now occupies "
            "the TOP slot the operator's acked row used to hold."
        )

    db2.close()
    diag.notes(
        "Symptom (b) reproduced: the alert the operator acked is gone, but "
        "the freshly-minted rule_LIVE_POLL alert took the top slot and every "
        "remaining row shifted down. To the operator this reads as 'the row "
        "I clicked didn't go away / was replaced by a different entry'. "
        "Because the full reload also resets scroll to the top (symptom a), "
        "BOTH symptoms share ONE root cause: ack does a full-document "
        "navigation that re-renders the entire ordered+limited unack list."
    )

    # =================================================================
    # ITEM 6 -- OPPORTUNISTIC button-sizing recon (home page only)
    # =================================================================
    diag.section("ITEM 6 -- home-page button/popover sizing (read-only recon)")
    css = (_STATIC / "lynceus.css").read_text(encoding="utf-8")
    ack_css_m = re.search(
        r"\.ack-button-inline,\s*\.watch-button-inline\s*\{[^}]*\}", css, flags=re.DOTALL
    )
    diag.observed(
        "home ack button class is .ack-button-inline; its CSS rule "
        "(lynceus.css ~130):"
    )
    ack_css_text = re.sub(r'\\s+', ' ', ack_css_m.group(0)) if ack_css_m else '(rule not found)'
    diag.observed(f"  {ack_css_text}")
    diag.observed(
        "home page renders NO <details>/<summary> popover and NO watchful-save "
        "control: index.html contains '<details' = "
        f"{'<details' in index_html}, 'watchful-action' = "
        f"{'watchful-action' in index_html}."
    )
    diag.notes(
        "The home-page Acknowledge button is already constrained "
        "(width:auto; padding:2px 8px; font-size:0.85em; line-height:1.4; "
        "box-sizing:border-box; v0.7.9 Touch 4). It is NOT a candidate for "
        "the reported oversized/page-shifting-button issue -- that lives on "
        "devices / watchlist / watchful-save surfaces, OUT OF SCOPE here. "
        "Recorded only so the later button-sizing FIX does not waste time on "
        "the home ack button."
    )

    db.close()

    # -----------------------------------------------------------------
    # Baseline assertions. The non-HX path is UNCHANGED by the 0.9.0 FIX
    # arc step-2 htmx swap (the POST above carries no HX-Request header),
    # so these three still pin the full-reload fallback:
    # -----------------------------------------------------------------
    assert ack_resp.status_code == 303
    assert ack_resp.headers["location"] == "/"
    assert is_full_doc
    # FLIPPED by 0.9.0 FIX arc step-2: the home ack control now carries
    # hx-post/hx-target/hx-swap. (Was: `assert "hx-" not in block` /
    # `assert len(hx_hits) == 0` -- both pinned the pre-fix "no htmx wiring
    # anywhere" baseline.)
    #
    # This diagnostic's subject is the HOME ack flow, so `block` is what it
    # gets to assert on. It used to add `all("index.html" in h for h in
    # hx_hits)`, claiming the swap stayed isolated to the home unack table.
    # That clause pinned a boundary the project deliberately crossed:
    # _device_actions.html gained hx-post at 7cb6667 and _alert_row.html at
    # d886a18. htmx wiring is now a general pattern, not a home-page
    # exception, so a global "only index.html" claim asserts something the
    # codebase never promised and re-breaks on every new htmx surface.
    # hx_hits stays as recorded observation (ITEM 4 above prints all of it);
    # it is asserted non-empty only to catch htmx being ripped out wholesale.
    assert "hx-post" in block
    assert hx_hits
    assert '{% extends "base.html" %}' in bulk  # bulk-ack "partial" is a full page
