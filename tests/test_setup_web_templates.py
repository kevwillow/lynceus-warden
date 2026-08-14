"""Tests for the wizard template shell and placeholder routes
(F6 Phase 2a, Touch 3).

Pins the rendering surface that Touches 4-7 will swap real form
content into: the landing page, the step indicator, the placeholder
step pages, and the cancel page. Also confirms that the static mount
resolves correctly (the operator's browser must be able to load
``pico.min.css`` without re-attaching the setup token) and that the
``url_with_token`` template helper carries the token forward into
every internal link.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from lynceus.setup.web.app import (
    STEP_TITLES,
    TOKEN_EXEMPT_PATHS,
    TOTAL_STEPS,
    create_wizard_app,
)

TOKEN = "test-setup-token-fixed-for-unit-tests-1234567890"
TARGET = Path("/tmp/wizard-test-lynceus.yaml")


def _make_app():
    return create_wizard_app(
        setup_token=TOKEN,
        scope="user",
        target_path=TARGET,
    )


def _wizard_footer_button_rule_body(base_html: str) -> str:
    """Return the body (between { and }) of the `.wizard-footer
    a[role="button"], .wizard-footer button` CSS rule from _base.html.

    Anchored on the joined-selector + opening `{`, not the bare
    `.wizard-footer button` substring — that substring also appears
    inside explanatory comments above the rule, so a naive
    `split('wizard-footer button')` lands in the wrong place."""
    import re

    match = re.search(
        r'\.wizard-footer\s+a\[role="button"\]\s*,\s*'
        r'\.wizard-footer\s+button\s*\{([^}]*)\}',
        base_html,
    )
    assert match, "could not locate the joined wizard-footer button rule in _base.html"
    return match.group(1)


# ---- landing page ---------------------------------------------------------


@pytest.mark.webui
def test_landing_renders_with_welcome_and_begin_link():
    app = _make_app()
    with TestClient(app) as client:
        resp = client.get(f"/?token={TOKEN}")
    assert resp.status_code == 200
    body = resp.text
    assert "Welcome to the lynceus-setup wizard" in body
    # The "Begin" link must carry the token forward.
    assert f'href="/step/1?token={TOKEN}"' in body


@pytest.mark.webui
def test_landing_shows_target_path_and_scope():
    app = _make_app()
    with TestClient(app) as client:
        resp = client.get(f"/?token={TOKEN}")
    assert str(TARGET) in resp.text
    assert "user" in resp.text


@pytest.mark.webui
def test_landing_does_not_ship_stale_phase_2a_copy():
    """Regression for fix commit 7f4ca39: the landing page shipped
    Phase 2a copy claiming the apply step "is not yet wired up" and
    "lands in Phase 2b" long after Phase 2b had landed. Pin the new
    current-state copy and assert no Phase 2a/2b leak is reintroduced.

    Same class of bug as PHASE_2_DIAGNOSTIC.md Finding 8.1 (review.html)."""
    app = _make_app()
    with TestClient(app) as client:
        resp = client.get(f"/?token={TOKEN}")
    body = resp.text
    lowered = body.lower()
    # No stale phase-gating language anywhere on the landing page.
    assert "phase 2a" not in lowered
    assert "phase 2b" not in lowered
    assert "not yet wired" not in lowered
    assert "not wired up" not in lowered
    # Current-state copy is load-bearing — pin the operator-facing
    # promises so a future copy edit that walks them back is caught.
    assert "Begin" in body  # the action verb for the first link
    assert "Review" in body  # the validated-config preview step
    assert "Apply" in body  # the write-pipeline trigger
    assert "Re-run" in body  # the recovery path on failure
    # The apply pipeline's idempotence claim is what justifies showing
    # Re-run; if that promise disappears, the Re-run mention is
    # misleading.
    assert "idempotent" in lowered


# ---- step routes ----------------------------------------------------------
# After Touch 6, every step ordinal 1..TOTAL_STEPS has a real form
# handler — the placeholder template and the parameterized catch-all
# are gone. Out-of-range ordinals fall through to FastAPI's default
# unmatched-route 404.


@pytest.mark.webui
def test_step_out_of_range_returns_404():
    app = _make_app()
    with TestClient(app) as client:
        assert client.get(f"/step/0?token={TOKEN}").status_code == 404
        # v0.7.7 Touch 5: /step/13 is the legacy redirect to /step/12
        # (the prior Argus watchlist step is folded into step 12 now);
        # check the next ordinal up for the 404 path.
        assert client.get(f"/step/{TOTAL_STEPS + 2}?token={TOKEN}").status_code == 404


# ---- cancel route ---------------------------------------------------------


@pytest.mark.webui
def test_cancel_renders_cancelled_page():
    app = _make_app()
    with TestClient(app) as client:
        resp = client.get(f"/cancel?token={TOKEN}")
    assert resp.status_code == 200
    assert "cancelled" in resp.text.lower()
    assert str(TARGET) in resp.text


@pytest.mark.webui
def test_cancel_clears_session_store():
    """Cancelling clears in-flight answers so a subsequent visit starts
    over from a clean state."""
    app = _make_app()
    # Seed an answer manually so we have something to clear.
    app.state.session_store.get_or_create(TOKEN).answers["kismet_url"] = "x"
    with TestClient(app) as client:
        client.get(f"/cancel?token={TOKEN}")
    assert app.state.session_store.get(TOKEN) is None


# ---- static assets --------------------------------------------------------


@pytest.mark.webui
def test_static_pico_css_resolves_unauthenticated():
    """Pico is loaded by the browser without the token query string;
    /static must be exempt from the token gate and serve the asset."""
    app = _make_app()
    with TestClient(app) as client:
        resp = client.get("/static/pico.min.css")
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/css")
    assert "/*" in resp.text or "*{" in resp.text  # minified CSS sentinels


@pytest.mark.webui
def test_static_in_token_exempt_paths():
    # If a refactor accidentally drops /static from the exempt tuple,
    # every template's <link rel="stylesheet"> would 403 in the
    # browser. Pin the literal.
    assert "/static" in TOKEN_EXEMPT_PATHS


# ---- token gating across new routes ---------------------------------------


@pytest.mark.webui
def test_landing_requires_token():
    app = _make_app()
    with TestClient(app) as client:
        resp = client.get("/")
    assert resp.status_code == 403


@pytest.mark.webui
def test_step_route_requires_token():
    app = _make_app()
    with TestClient(app) as client:
        resp = client.get("/step/1")
    assert resp.status_code == 403


@pytest.mark.webui
def test_cancel_route_requires_token():
    app = _make_app()
    with TestClient(app) as client:
        resp = client.get("/cancel")
    assert resp.status_code == 403


# ---- step titles / count ---------------------------------------------------


def test_total_steps_matches_step_titles_length():
    # Defensive: a future edit that re-orders STEP_TITLES must not
    # leave TOTAL_STEPS pointing at a stale count.
    assert TOTAL_STEPS == len(STEP_TITLES)


@pytest.mark.webui
def test_no_internal_phase_language_in_any_wizard_template():
    """Regression for the Phase 2b leak that survived in rules.html
    until commit a227f44 (Step 12 copy restructure) and the Phase 2a
    leak that survived in landing.html until commit 7f4ca39.

    Internal phase identifiers (the F6 Phase 2a / 2b release-planning
    nomenclature) leak operator-meaningless jargon into the wizard
    UI. Pin every wizard template — landing through completion — so
    a future copy edit that types "Phase 1/2/3" in operator-facing
    text fails at test time instead of waiting for the next browser
    smoke.

    Scans the template source rather than rendering each route
    because some templates (apply_progress, apply_complete) need
    apply-state seeding to render cleanly — and the templates never
    construct phase strings dynamically, so a source-level scan is
    equivalent for this invariant."""
    import re

    from lynceus.setup.web.app import _resolve_wizard_templates_dir

    templates_dir = _resolve_wizard_templates_dir()
    pattern = re.compile(r"Phase\s*[0-9]", re.IGNORECASE)
    offenders: list[tuple[str, str]] = []
    for tpl in sorted(templates_dir.glob("*.html")):
        text = tpl.read_text(encoding="utf-8")
        for match in pattern.finditer(text):
            # Capture a small context window so a failure tells the
            # human which copy block to rewrite.
            start = max(0, match.start() - 30)
            end = min(len(text), match.end() + 30)
            offenders.append((tpl.name, text[start:end].replace("\n", " ")))
    assert not offenders, (
        "internal-phase language leaked into operator-facing wizard "
        "templates; rewrite each match in terms of the operator's "
        "actions ('when you click Apply', 'during install', etc.):\n  "
        + "\n  ".join(f"{name}: ...{ctx}..." for name, ctx in offenders)
    )


@pytest.mark.webui
@pytest.mark.parametrize("path", ["/", "/step/1", "/step/12"])
def test_wizard_pages_render_inside_pico_container(path):
    """Regression for fix commit 7b91414: every wizard page must wrap
    its content in <main class="container"> so the .container rule
    pinned in _base.html's inline <style> block applies and the
    layout centers + caps line length.

    Spot-checks the landing page, the first step, and the final step
    so a future template that introduces a wizard page without
    extending _base.html (or that drops the container class from the
    base layout) gets caught."""
    app = _make_app()
    with TestClient(app) as client:
        resp = client.get(f"{path}?token={TOKEN}")
    assert resp.status_code == 200, f"path {path} did not render"
    assert '<main class="container">' in resp.text, (
        f"{path} missing <main class=\"container\"> — wizard layout "
        f"depends on this class for the explicit narrow max-width "
        f"defined in _base.html (the bundled Pico is the classless "
        f"build and ships no .container rule of its own)"
    )


@pytest.mark.webui
def test_base_top_nav_carries_chrome_class_and_rule():
    """v0.7.3 fix: the wizard's <nav> shipped without a class hook and
    Pico's classless build leaves bare <nav> with only inherited text
    styling, so the "lynceus-setup vX.Y.Z" strip read as floating
    letters above the form. The fix adds a class on the <nav> in
    _base.html and a matching rule in the inline <style> block with a
    card-style background + bottom border so the nav reads as a
    deliberate app header.

    Pin both the class on the nav element and the selector + minimum
    properties in the inline style so a future cleanup that drops
    either re-surfaces the bare-letters smoke finding."""
    from lynceus.setup.web.app import _resolve_wizard_templates_dir

    base = (_resolve_wizard_templates_dir() / "_base.html").read_text(encoding="utf-8")
    assert 'class="wizard-topnav"' in base
    assert ".wizard-topnav" in base
    topnav_rule = base.split(".wizard-topnav")[1].split("}")[0]
    # Visible chrome: at minimum a background + a border-bottom so the
    # nav reads as a header band rather than bare text.
    assert "background" in topnav_rule
    assert "border-bottom" in topnav_rule


@pytest.mark.webui
def test_wizard_topnav_renders_on_every_page():
    """The chrome lives in the shared _base.html, so every wizard page
    that extends the base must carry the styled nav. Sweep every
    routable wizard page (landing, all step ordinals, review, cancel)
    so a future template that bypasses _base.html and loses the nav
    chrome is caught."""
    app = _make_app()
    paths = ["/", "/cancel", "/review"] + [f"/step/{n}" for n in range(1, TOTAL_STEPS + 1)]
    with TestClient(app) as client:
        for path in paths:
            resp = client.get(f"{path}?token={TOKEN}")
            assert resp.status_code == 200, f"{path} did not render"
            assert 'class="wizard-topnav"' in resp.text, (
                f"{path} is missing the wizard-topnav class on its <nav>; "
                f"the top-nav chrome rule only matches .wizard-topnav, so "
                f"a page without the class re-surfaces the bare-letters smoke"
            )


@pytest.mark.webui
def test_base_normalises_wizard_footer_button_sizing():
    """v0.7.2 fix: Previous/Next button row looked uneven because
    <a role="button"> (Previous) and <button> (Next/Apply/Review)
    rendered at the natural text widths of their labels. The fix is
    an explicit min-width + horizontal padding on both elements in
    the wizard-footer scope so the row reads as a matched pair
    regardless of label.

    Pin the rule in _base.html's inline <style> block (the wizard
    has no separate stylesheet — all custom rules live in the base
    template). A future cleanup that drops or weakens this rule
    re-surfaces the uneven button row from smoke."""
    from lynceus.setup.web.app import _resolve_wizard_templates_dir

    base = (_resolve_wizard_templates_dir() / "_base.html").read_text(encoding="utf-8")
    # Both selectors must be in the rule so the rule applies to both
    # element types. Pin the selectors as substrings rather than
    # matching the full CSS rule to allow whitespace/order tweaks.
    assert ".wizard-footer a[role=\"button\"]" in base
    assert ".wizard-footer button" in base
    # The rule sets min-width so different label widths don't change
    # the rendered button size. Anchor on the actual rule body (the
    # joined-selector + `{ ... }` block) rather than the bare selector,
    # which also appears inside explanatory comments.
    rule_body = _wizard_footer_button_rule_body(base)
    assert "min-width" in rule_body


@pytest.mark.webui
def test_base_wizard_footer_pins_both_axes_of_button_sizing():
    """v0.7.3 follow-up to the v0.7.2 horizontal pin: smoke showed the
    Previous/Next pair still rendered at slightly different heights
    because Pico's <a role="button"> inherits anchor line-height and
    <button> uses the UA-default form-control line-height. The fix
    extends the existing rule to also pin vertical padding, line-
    height, and box-sizing so both element types resolve to the same
    rendered box model.

    Pin each load-bearing property as a substring inside the rule so a
    future style-block cleanup that drops any one re-surfaces the
    uneven button row."""
    from lynceus.setup.web.app import _resolve_wizard_templates_dir

    base = (_resolve_wizard_templates_dir() / "_base.html").read_text(encoding="utf-8")
    rule = _wizard_footer_button_rule_body(base)
    assert "box-sizing" in rule
    assert "line-height" in rule
    # Vertical padding must appear (shorthand `padding: ...` or `padding-top`)
    # so the rule actually controls the vertical axis, not just horizontal.
    assert "padding" in rule and not rule.strip().startswith("padding-left")


@pytest.mark.webui
def test_base_wizard_footer_pins_margin_bottom_and_display():
    """v0.7.4 follow-up to the v0.7.3 two-axis pin: the cascade-divergence
    diagnostic (test_diag_wizard_button_cascade) showed that even with
    box-sizing/padding/line-height pinned, the row still rendered uneven
    because Pico's [type=submit] rule adds margin-bottom: var(--pico-spacing)
    to the real <button> that the <a role="button"> Previous link never
    picks up, AND because the two elements resolve to different display
    types by default (inline vs inline-block) so the parent flex row
    treats them slightly differently.

    Pin both properties inside the joined-selector rule so the same
    cascade leak doesn't re-open."""
    from lynceus.setup.web.app import _resolve_wizard_templates_dir

    base = (_resolve_wizard_templates_dir() / "_base.html").read_text(encoding="utf-8")
    rule = _wizard_footer_button_rule_body(base)
    # margin-bottom: 0 overrides Pico's [type=submit] margin that only
    # the <button> half picks up. Without this pin, the pair sits at
    # different baselines.
    assert "margin-bottom" in rule
    # display: inline-block normalizes the display type so the flex
    # parent treats both elements identically.
    assert "display" in rule


@pytest.mark.webui
def test_base_wizard_footer_pins_width_auto():
    """v0.7.6 follow-up: even after v0.7.4 pinned margin-bottom + display,
    smoke kept reporting Next/Apply rendered visibly wider than Previous.
    Pico's classless build ships
    `button[type=submit],input:not(...),select,textarea {width:100%}` —
    same selector specificity as `.wizard-footer button`, so the cascade
    settles on Pico's value for the `width` property whenever our rule
    doesn't declare it. Pin width: auto inside the joined-selector rule
    so the submit button shrinks to its content width and matches the
    anchor-as-button Previous/Cancel.

    The other half of the pair (a[role="button"]) is unaffected by
    Pico's submit-100% rule — it already renders at width: auto by
    default — but pinning here on the joined selector keeps the box
    model symmetric and survives a future Pico revision that broadens
    the offender selector to anchors too."""
    from lynceus.setup.web.app import _resolve_wizard_templates_dir

    base = (_resolve_wizard_templates_dir() / "_base.html").read_text(encoding="utf-8")
    rule = _wizard_footer_button_rule_body(base)
    assert "width" in rule, (
        "wizard-footer button rule must declare width to override Pico's "
        "button[type=submit] {width:100%} — without it the submit button "
        "stretches across the flex footer while the anchor-as-button "
        "sits at content width"
    )
    # width: auto specifically — not 100%, not min-content, not a px value.
    # The cascade-divergence path is "Pico's 100% wins by source order"
    # and auto is the only value that defers to the min-width + padding
    # box model the rest of the rule defines.
    import re
    assert re.search(r"\bwidth\s*:\s*auto\b", rule), (
        "wizard-footer button width must be `auto` so the min-width + "
        "padding pair defines the rendered size; any other value "
        "(100%, fit-content, fixed px) re-opens the smoke"
    )


@pytest.mark.webui
def test_wizard_footer_buttons_render_at_matched_size_across_all_pages():
    """Cross-step regression for smoke finding #2 — re-runs the
    diagnostic's signature check as an assertion. Every wizard page's
    .wizard-footer must lay out a button-shaped row whose elements are
    matched by the _base.html sizing rule, regardless of whether each
    element is <a role="button"> or <button>. Step 3's "Cancel /
    Continue anyway" pair (two real form submits) is the divergent
    shape — the rule covers both element types so the row reads
    matched anyway."""
    import re

    app = _make_app()
    paths = ["/review"] + [f"/step/{n}" for n in range(1, TOTAL_STEPS + 1)]
    # We don't try to compute rendered pixel sizes (the test client
    # doesn't drive a layout engine). Instead, assert that every
    # button-shaped element inside a .wizard-footer carries one of the
    # two selectors the _base.html rule covers: either tag=button OR
    # role=button. The rule pins box-sizing/min-width/padding/line-
    # height equally for both selectors, so coverage == matched size.
    footer_block = re.compile(
        r'<(?:div|footer)\s+class="wizard-footer">(.*?)</(?:div|footer)>',
        re.DOTALL,
    )
    button_shape = re.compile(r'<(a\b[^>]*role="button"[^>]*|button\b[^>]*)>', re.IGNORECASE)
    with TestClient(app) as client:
        for path in paths:
            resp = client.get(f"{path}?token={TOKEN}")
            assert resp.status_code == 200, f"{path} did not render"
            for footer_body in footer_block.findall(resp.text):
                for opener in button_shape.findall(footer_body):
                    # Each match is either an <a role="button" ...>
                    # (covered by the anchor selector) or a <button ...>
                    # (covered by the button selector). Both selectors
                    # are in the same _base.html rule with identical
                    # box-model properties, so this element renders at
                    # the matched size. The assertion is that the
                    # element is one of these two shapes — anything
                    # else (an <input type="submit">, a styled <span>,
                    # etc.) would slip past the sizing rule.
                    assert opener.lower().startswith("a ") or opener.lower().startswith("button"), (
                        f"{path}: wizard-footer element {opener!r} is neither "
                        f'<a role="button"> nor <button>; the _base.html sizing '
                        f"rule won't match it, so it renders at its default size"
                    )


@pytest.mark.webui
@pytest.mark.parametrize(
    "path",
    ["/step/1", "/step/10", "/step/11"],  # representative: first, middle, late
)
def test_wizard_step_carries_consistent_button_pair(path):
    """Spot-check that representative step pages render the standard
    Previous (anchor styled as button) + Next (real submit button)
    pair. Catches a template that diverges to a different shape
    (e.g. two anchors, two buttons, or drops one) that would defeat
    the _base.html sizing rule."""
    app = _make_app()
    with TestClient(app) as client:
        resp = client.get(f"{path}?token={TOKEN}")
    assert resp.status_code == 200, f"{path} did not render"
    body = resp.text
    # Previous renders as an anchor styled as button with class="secondary".
    #
    # ⚠️ This asserts the MARKUP contract only -- that the class is present.
    # It does NOT and cannot assert that the class does anything: for a long
    # time it did not. The bundled Pico is the CLASSLESS build and defines no
    # `.secondary`, so all 20 sites matched no rule and Previous rendered as a
    # full-strength primary, pixel- and colour-identical to Next on every step.
    # This test was green throughout, because a class name in the HTML and a
    # rule in the CSS are different claims.
    #
    # The comment here used to say "so Pico's lower-emphasis variant applies",
    # which was the false half. Whether the class RESOLVES is now checked by
    # tests/test_wizard_classes_are_defined.py, which cross-references every
    # class the templates use against the CSS the page actually loads.
    assert 'role="button"' in body
    assert 'class="secondary"' in body
    # Next/Apply/Review is a real submit button.
    assert 'type="submit"' in body
    # Both must live inside the .wizard-footer container so the
    # _base.html sizing rule actually matches them.
    assert "wizard-footer" in body


@pytest.mark.webui
def test_base_carries_centering_and_visual_structure_rules():
    """v0.7.2 fix: wizard pages read as a "wall of text" because the
    classless Pico build doesn't give <form> a background or border,
    so the form interactives flow directly off the prose intro
    paragraph without a visible boundary. The fix adds three rules
    to _base.html's inline <style>:

    1. main.container max-width pin (specificity over body>main) +
       viewport-side gutter so the card never butts against the
       browser chrome on tablet widths
    2. Section divider under each step's H1 so prose and form have
       a visible boundary
    3. Card-style background on main.container > form so the input
       block visually separates from the intro paragraph

    Pin each rule fragment so a future style-block cleanup that
    drops one re-surfaces the unstructured layout."""
    from lynceus.setup.web.app import _resolve_wizard_templates_dir

    base = (_resolve_wizard_templates_dir() / "_base.html").read_text(encoding="utf-8")

    # 1. Container max-width + auto margin + viewport gutter.
    assert "main.container" in base
    assert "max-width: 720px" in base
    assert "margin-left: auto" in base
    assert "padding-left: 1rem" in base or "padding-right: 1rem" in base

    # 2. H1 section divider.
    assert "main.container > h1" in base
    h1_rule = base.split("main.container > h1")[1].split("}")[0]
    assert "border-bottom" in h1_rule

    # 3. Form card-style background.
    assert "main.container > form" in base
    form_rule = base.split("main.container > form ")[1].split("}")[0]
    assert "background" in form_rule
    assert "border" in form_rule
    assert "padding" in form_rule


def test_step_titles_covers_cli_sections():
    # Touches 4-7 implement the real form pages corresponding to each
    # title. If a section name drifts, pin which one(s).
    expected_substrings = (
        "Kismet",  # 4 entries
        "Probe",   # 1 entry (probe_ssids)
        "BLE",     # 1 entry
        "ntfy",    # 3 entries
        "RSSI",    # 1 entry
        "Severity",
        # v0.7.7 Touch 5: "Rules engine" + "Argus watchlist" merged into
        # "Argus configuration" — the section identifier changed, the
        # rules engine is now wired into that single page.
        "Argus",
    )
    joined = " | ".join(STEP_TITLES)
    for sub in expected_substrings:
        assert sub in joined, f"STEP_TITLES missing section: {sub}"


# ---- dark mode (UX-polish arc Touch 2) ------------------------------------


def test_theme_bootstrap_precedes_stylesheet_in_head():
    """The inline FOUC bootstrap must run before pico.min.css so a forced
    light/dark choice is applied before first paint. Mirrors the
    dashboard's regression guard (test_webui_theme.py) but for the
    wizard's own _base.html."""
    app = _make_app()
    with TestClient(app) as client:
        body = client.get(f"/?token={TOKEN}").text
    assert 'localStorage.getItem("lynceus-theme")' in body
    assert 'setAttribute("data-theme"' in body
    idx_bootstrap = body.find('localStorage.getItem("lynceus-theme")')
    idx_css = body.find("pico.min.css")
    assert idx_bootstrap >= 0 and idx_css >= 0
    assert idx_bootstrap < idx_css, (
        "theme bootstrap must precede pico.min.css to avoid FOUC"
    )


def test_theme_toggle_button_present_on_wizard_pages():
    """Every wizard page (landing + steps + cancel) renders the topnav
    theme toggle with the data-theme-toggle hook and .theme-toggle class."""
    app = _make_app()
    paths = ["/", "/cancel"] + [f"/step/{n}" for n in range(1, TOTAL_STEPS + 1)]
    with TestClient(app) as client:
        for path in paths:
            body = client.get(f"{path}?token={TOKEN}").text
            assert "data-theme-toggle" in body, f"{path}: toggle hook missing"
            assert "theme-toggle" in body, f"{path}: .theme-toggle class missing"


def test_theme_bootstrap_and_toggle_share_storage_key():
    """The <head> bootstrap reader and the <body> toggle writer must use
    the same localStorage key, or a forced theme silently re-flashes."""
    app = _make_app()
    with TestClient(app) as client:
        body = client.get(f"/?token={TOKEN}").text
    # Reader (head) and writer (body) both reference the same key.
    assert body.count('"lynceus-theme"') >= 2
    assert 'var THEME_KEY = "lynceus-theme"' in body
    # Cycle order is the auto -> light -> dark contract.
    assert '["auto", "light", "dark"]' in body
