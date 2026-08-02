"""Localize the bare 'Q' identifier the operator reports seeing across
multiple dashboard pages (#D).

The conventional FastAPI search-param name is ``q`` across /alerts,
/watchlist, /allowlist, /watchful. Operator reports a bare 'Q' label
rendering somewhere on the affected pages. Hypotheses:

  * a form <label> whose visible text is literally 'q' (the bare param
    name) -- common when the original template author used the param
    name as the label as a placeholder and never replaced it with a
    human-readable string
  * a Jinja expression like {{ q|upper }} that rendered an empty Q
  * an HTML icon-font fallback that renders as 'Q'
  * a per-column header named 'Q' (less likely; tables on these pages
    don't have a 'q' column)

This diagnostic does two passes:

  PHASE A -- static grep of every dashboard template. Looks for:
    - literal 'q' / 'Q' text nodes (>q< / >Q<) outside Jinja blocks
    - <label> elements whose visible text resolves to just 'q' / 'Q'
    - Jinja expressions that could render as 'Q' (uppercased q)
    - 'q' substring inside aria-label / title / placeholder

  PHASE B -- render every dashboard page via TestClient against an
  empty DB. Scan the rendered HTML for tokens that match the
  operator's report and dump the surrounding context.

Cross-correlating phase A static hits with phase B render hits
pinpoints each instance with template file + line + render context.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import create_app

pytestmark = pytest.mark.diagnostic


_TEMPLATE_DIRS: list[Path] = [
    Path(__file__).resolve().parent.parent
    / "src" / "lynceus" / "webui" / "templates",
    Path(__file__).resolve().parent.parent
    / "src" / "lynceus" / "setup" / "web" / "templates",
]


_DASHBOARD_PATHS: list[tuple[str, str]] = [
    ("home", "/"),
    ("alerts", "/alerts"),
    ("devices", "/devices"),
    ("watchful", "/watchful"),
    ("watchlist", "/watchlist"),
    ("allowlist", "/allowlist"),
    ("rules", "/rules"),
    ("settings", "/settings"),
    ("healthz", "/healthz"),
]


def _phase_a_static_scan(diag) -> dict[str, list[str]]:
    """Scan every template for 'q' / 'Q' tokens that could surface to
    the operator. Returns a per-template list of human-readable hits
    so phase B can cross-correlate against the live render output.
    """
    diag.section("phase A: static template scan")
    hits_by_template: dict[str, list[str]] = {}
    for tdir in _TEMPLATE_DIRS:
        if not tdir.is_dir():
            diag.observed(f"template dir does not exist: {tdir}")
            continue
        for path in sorted(tdir.rglob("*.html")):
            rel = path.relative_to(tdir.parent.parent.parent.parent)
            text = path.read_text(encoding="utf-8")
            hits: list[str] = []

            # Pattern 1: <label>q  -- visible label text starting with
            # bare q or Q at the start of the label content (the exact
            # shape investigation found on alerts_list / watchful_list /
            # watchlist_list).
            for m in re.finditer(
                r"<label[^>]*>(\s*[Qq])\b", text
            ):
                line = text[: m.start()].count("\n") + 1
                hits.append(
                    f"{line}: <label> with bare {m.group(1).strip()!r} text: "
                    f"{text[m.start() : m.start() + 80].splitlines()[0]!r}"
                )

            # Pattern 2: text nodes containing a standalone 'Q' or 'q'
            # in HTML text position (not part of an attribute / Jinja).
            # The naive >Q< check catches things like <th>Q</th>,
            # <span>Q</span>.
            for m in re.finditer(r">\s*([Qq])\s*<", text):
                line = text[: m.start()].count("\n") + 1
                hits.append(
                    f"{line}: standalone {m.group(1)!r} text node: "
                    f"{text[max(0, m.start() - 30) : m.end() + 30]!r}"
                )

            # Pattern 3: Jinja expressions that could render as Q.
            # Tracks {{ q|upper }}, {{ ...|upper }} with a 'q' source.
            for m in re.finditer(
                r"\{\{[^}]*\b[qQ]\b[^}]*(?:\|upper)?[^}]*\}\}", text
            ):
                line = text[: m.start()].count("\n") + 1
                hits.append(
                    f"{line}: Jinja expr referencing q: {m.group(0)!r}"
                )

            # Pattern 4: aria-label / title / placeholder containing
            # bare 'q' / 'Q' as visible text.
            for m in re.finditer(
                r'(aria-label|title|placeholder)="([qQ])"', text
            ):
                line = text[: m.start()].count("\n") + 1
                hits.append(
                    f"{line}: {m.group(1)}={m.group(2)!r}: {m.group(0)!r}"
                )

            if hits:
                hits_by_template[str(rel)] = hits
                for h in hits:
                    diag.observed(f"  {rel}:{h}")

    if not hits_by_template:
        diag.observed(
            "no static-scan hits across any template; phase B may still "
            "surface render-time hits from dynamic data."
        )
    return hits_by_template


def _phase_b_render_scan(diag, app) -> dict[str, list[str]]:
    """Walk every dashboard page; scan rendered HTML for standalone 'Q'
    or 'q' tokens in text positions."""
    diag.section("phase B: render-time scan")
    render_hits: dict[str, list[str]] = {}
    with TestClient(app) as client:
        for label, path in _DASHBOARD_PATHS:
            try:
                resp = client.get(path)
            except Exception as exc:
                diag.observed(f"--- {label} ({path}) ---  EXCEPTION: {exc!r}")
                continue
            diag.observed(f"--- {label} ({path}) ---  status={resp.status_code}")
            if resp.status_code != 200:
                if 300 <= resp.status_code < 400:
                    diag.observed(
                        f"  redirect Location: {resp.headers.get('location')!r}"
                    )
                continue
            body = resp.text
            hits: list[str] = []

            # Standalone 'Q' / 'q' in text position. The render scan is
            # noisier than static (whole words like 'request' contain
            # 'q'), so we constrain to whitespace-bounded single chars
            # OR exact >Q< text nodes.
            for m in re.finditer(r">\s*([Qq])\s*<", body):
                # Surrounding 200 chars of context.
                ctx_start = max(0, m.start() - 100)
                ctx_end = min(len(body), m.end() + 100)
                hits.append(
                    f"text-node {m.group(1)!r}: "
                    f"...{body[ctx_start : m.start()]!r}>"
                    f"[{m.group(1)}]"
                    f"<{body[m.end() : ctx_end]!r}..."
                )

            # <label>q -- the form-label shape that statically appears
            # in alerts_list / watchful_list / watchlist_list. Confirms
            # the live render preserves the bare letter.
            for m in re.finditer(r"<label[^>]*>\s*[Qq]\b", body):
                ctx_start = max(0, m.start() - 50)
                ctx_end = min(len(body), m.end() + 100)
                hits.append(
                    f"<label> bare q: ...{body[ctx_start : ctx_end]!r}..."
                )

            if hits:
                render_hits[label] = hits
                for h in hits:
                    diag.observed(f"  {label}: {h}")
            else:
                diag.observed(f"  {label}: no Q-token hits")
    return render_hits


def test_diag_dashboard_q_identifier(diag, tmp_path):
    diag.section("setup")
    diag.fixture(
        "scope: dashboard webui templates + setup/wizard templates "
        "(checked for completeness even though operator reports the issue "
        "on dashboard pages -- a shared partial included by both worlds "
        "would surface in both)"
    )
    diag.fixture(
        f"dashboard pages walked: {[p for _, p in _DASHBOARD_PATHS]}"
    )

    static_hits = _phase_a_static_scan(diag)

    # Build a real dashboard app against an empty DB so the render
    # path exercises every default-state template (no alerts, no
    # watchlist rows, no devices). The bare label issue is rendered
    # in the form chrome which is present even without data.
    config = Config(db_path=str(tmp_path / "diag-q.db"))
    db = Database(config.db_path)
    try:
        app = create_app(config, db)
        render_hits = _phase_b_render_scan(diag, app)
    finally:
        db.close()

    diag.section("phase A x phase B cross-correlation")
    if not static_hits and not render_hits:
        diag.observed(
            "no static OR render hits. If the operator still sees 'Q', it "
            "may be a browser font-icon fallback (e.g. a missing glyph "
            "rendering as a tofu box that LOOKS like 'Q' in some fonts), "
            "or a screenshot they're describing colloquially. Ask for a "
            "screenshot to narrow further."
        )
        diag.notes("phase A/B both empty -- recommend operator screenshot.")
        return

    # Map render hits back to templates from static hits to localize
    # the source line.
    diag.observed("static-scan hits per template (the candidate source sites):")
    for tpl, hits in static_hits.items():
        diag.observed(f"  {tpl}:")
        for h in hits:
            diag.observed(f"    {h}")
    diag.observed("render-scan hits per page (operator-visible surfaces):")
    for page, hits in render_hits.items():
        diag.observed(f"  {page}:")
        for h in hits:
            diag.observed(f"    {h}")

    # The localized finding: <label>q in three of the four search-form
    # pages (alerts, watchful, watchlist) -- allowlist uses 'search' as
    # the label. This is the inconsistency the operator reported.
    diag.section("localized finding (most likely source)")
    diag.observed(
        "The bare 'q' the operator sees is the <label>q text in the "
        "search form on alerts_list.html, watchful_list.html, and "
        "watchlist_list.html. allowlist_list.html (the fourth "
        "search-bearing page) uses <label>search instead -- this is "
        "the inconsistency the operator's eye picked up."
    )
    diag.observed(
        "Operator's browser may render the lowercase 'q' as visually "
        "capital depending on font / size; the underlying template "
        "string is lowercase 'q' verbatim."
    )

    diag.notes(
        "Fix-direction for the follow-up prompt:\n"
        " * Replace <label>q with <label>search (or 'filter' / "
        "'query') across alerts_list.html (line ~75), "
        "watchful_list.html (line ~42), watchlist_list.html "
        "(line ~43) so all four search-bearing dashboard pages "
        "render the SAME human-readable label. The form param name "
        "'q' stays the same -- URLs don't change.\n"
        " * Consider also updating the placeholder text consistently "
        "across the four (currently: 'mac / ssid / vendor substring' "
        "on alerts, 'mac substring' on watchful, etc -- each page "
        "should keep its scope-specific hint but the label itself "
        "should be uniform)."
    )
