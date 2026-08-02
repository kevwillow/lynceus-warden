"""Diagnostic dump for wizard layout chrome (smoke findings #1, #2, #3).

Per the v0.7.2 smoke:

  #1  Top navigation renders as bare letters with no visual treatment.
  #2  Previous/Next buttons render at different sizes.
  #3  Content is not centered.

v0.7.2 shipped two layout patches: aba9c0e (normalize Prev/Next sizing)
and 9319a85 (tighten page centering). If the smoke complaint stands
post-patch the failure is in one of:

  - the rules in _base.html's <style> block (specificity, missing
    selector for the actual element rendered)
  - per-step divergence (one or more step templates not using the
    shared shell, e.g. literal anchors / buttons outside .wizard-footer)
  - the top-nav <nav> markup carrying no class so Pico classless
    can't style it

This diagnostic dumps, for every step ordinal 1..12 plus landing /
review:

  - the literal <nav> block in the rendered HTML (top-nav chrome)
  - the literal <main ...> wrapper open tag (centering container)
  - the literal wizard-footer block (Prev/Next chrome)
  - the <link rel="stylesheet"> chain
  - the full <style> block from _base.html (rules in scope)

Computed CSS values would require a headless browser; this diag
dumps the class strings + the CSS rules they target so a reviewer
can resolve specificity offline.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import lynceus.setup.web.steps_kismet as steps_kismet
from lynceus.setup.web.app import STEP_TITLES, create_wizard_app

pytestmark = pytest.mark.diagnostic

TOKEN = "diag-layout-chrome-token-1234567890"
TARGET = Path("/tmp/diag-layout-lynceus.yaml")


def _seed_session_for_full_walk(app):
    """Pre-populate session.answers with the prereqs every step's GET
    handler checks. Without this seeding, /step/3 redirects to /step/1
    (missing kismet_url), /step/8 to /step/7 (missing ntfy_url), etc.,
    and the diagnostic would dump the redirect target page repeatedly
    instead of each step's own chrome."""
    session = app.state.session_store.get_or_create(TOKEN)
    session.answers.update(
        {
            "kismet_url": "http://localhost:2501",
            "kismet_api_key": "diag-key-stub",
            "kismet_probe_ok": True,
            "kismet_probe_version": "diag-fake-version",
            "kismet_probe_error": None,
            "kismet_probe_sources": [],
            "kismet_sources": ["wlan1"],
            "probe_ssids": False,
            "ble_friendly_names": False,
            "ntfy_url": "https://ntfy.sh",
            "ntfy_topic": "diag-topic",
            "ntfy_probe_ok": True,
            "ntfy_probe_error": None,
            "min_rssi": -75,
            "severity_overrides": {},
            "rules": [],
        }
    )


_PAGES: list[tuple[str, str]] = [
    ("landing", "/"),
    ("step01_kismet_url", "/step/1"),
    ("step02_kismet_key", "/step/2"),
    ("step03_kismet_probe", "/step/3"),
    ("step04_kismet_sources", "/step/4"),
    ("step05_probe_ssids", "/step/5"),
    ("step06_ble_friendly_names", "/step/6"),
    ("step07_ntfy_url", "/step/7"),
    ("step08_ntfy_topic", "/step/8"),
    ("step09_ntfy_probe", "/step/9"),
    ("step10_rssi", "/step/10"),
    ("step11_severity", "/step/11"),
    ("step12_rules", "/step/12"),
    ("review", "/review"),
]


def _slice(html: str, pattern: str, *, flags=re.DOTALL) -> str:
    """Return the first match for `pattern` in `html`, or '<MISSING>' so
    the dump records absence as data rather than as a silent gap."""
    m = re.search(pattern, html, flags=flags)
    if m is None:
        return "<MISSING>"
    return m.group(0)


def _compact(s: str) -> str:
    """Collapse runs of whitespace so log lines stay readable. The
    original HTML is preserved separately for the chrome-critical
    blocks; this is just for the per-page summary."""
    return re.sub(r"\s+", " ", s).strip()


def test_diag_wizard_layout_chrome(diag, monkeypatch):
    # Skip the live Kismet/ntfy probes for steps that POST would hit;
    # GET-only renders here, so the autouse fixtures already cover it
    # in the regular suite — but the diagnostic test isn't autouse, so
    # patch defensively to be sure no real network call escapes.
    monkeypatch.setattr(
        steps_kismet, "probe_kismet", lambda url, key: (False, None, "diag-no-kismet")
    )
    monkeypatch.setattr(steps_kismet, "probe_kismet_sources", lambda url, key: None)

    diag.section("setup")
    diag.fixture(
        "shared base template: src/lynceus/setup/web/templates/_base.html"
    )
    diag.fixture(
        "step indicator partial: src/lynceus/setup/web/templates/_progress.html"
    )
    diag.fixture(f"step ordinals walked: 1..{len(STEP_TITLES)} ({STEP_TITLES})")
    diag.fixture(
        "v0.7.2 layout-patch commits: aba9c0e (normalize Prev/Next sizing) "
        "+ 9319a85 (tighten page centering). _base.html <style> block as of "
        "v0.7.2 contains: main.container { max-width: 720px; margin auto; ... } "
        "and .wizard-footer a[role='button'], .wizard-footer button "
        "{ min-width: 9em; padding 1.5em; text-align: center; }"
    )

    # -----------------------------------------------------------------
    # Dump the _base.html <style> block verbatim so the diag artifact
    # is self-contained — reviewers don't have to cross-reference the
    # template to know what rules are in scope.
    # -----------------------------------------------------------------
    diag.section("_base.html inline <style> block (rules in scope)")
    base_template = (
        Path(__file__).resolve().parent.parent
        / "src" / "lynceus" / "setup" / "web" / "templates" / "_base.html"
    )
    base_text = base_template.read_text(encoding="utf-8")
    style_block = _slice(base_text, r"<style>.*?</style>")
    diag.observed(f"_base.html path: {base_template}")
    diag.observed("--- <style> ---")
    for line in style_block.splitlines():
        diag.observed(f"  {line}")
    # Also dump the literal <nav> from _base.html so the top-nav
    # markup is visible regardless of which step rendered it.
    nav_block = _slice(base_text, r"<nav>.*?</nav>")
    diag.observed("--- <nav> in _base.html ---")
    for line in nav_block.splitlines():
        diag.observed(f"  {line}")

    # -----------------------------------------------------------------
    # Walk every page and dump per-page chrome.
    # -----------------------------------------------------------------
    diag.section("per-page chrome dump")
    app = create_wizard_app(setup_token=TOKEN, scope="user", target_path=TARGET)
    _seed_session_for_full_walk(app)

    # Bucket per-page slices so a follow-up diff between any two steps
    # is straightforward (the dump groups them by element kind below).
    nav_per_page: dict[str, str] = {}
    main_per_page: dict[str, str] = {}
    footer_per_page: dict[str, str] = {}
    css_links_per_page: dict[str, list[str]] = {}

    with TestClient(app, follow_redirects=False) as client:
        for label, path in _PAGES:
            resp = client.get(f"{path}?token={TOKEN}")
            status = resp.status_code
            location = resp.headers.get("location")
            diag.observed(f"--- {label} ({path}) ---")
            diag.observed(f"  status: {status}")
            if location:
                diag.observed(f"  redirect Location: {location}")
            if status != 200:
                # Redirects (303) get logged but skipped for chrome
                # capture — the location header above tells the
                # reviewer where the deep-link goes.
                continue
            body = resp.text
            # Top-nav block — first <nav>..</nav> in body.
            nav = _slice(body, r"<nav>.*?</nav>")
            nav_per_page[label] = nav
            diag.observed(f"  <nav> (compact): {_compact(nav)!r}")
            # Main container open tag.
            main_open = _slice(body, r"<main[^>]*>")
            main_per_page[label] = main_open
            diag.observed(f"  <main> open tag: {main_open!r}")
            # Wizard footer block. Most steps wrap it in
            # <footer class="wizard-footer"> (from _base.html) OR
            # <div class="wizard-footer"> (per-step inside <form>).
            footers = re.findall(
                r"<(?:footer|div)[^>]*\bwizard-footer\b[^>]*>.*?</(?:footer|div)>",
                body,
                flags=re.DOTALL,
            )
            footer_per_page[label] = "\n----\n".join(footers) if footers else "<MISSING>"
            diag.observed(f"  wizard-footer block count: {len(footers)}")
            for i, f in enumerate(footers):
                diag.observed(f"  wizard-footer[{i}] (compact): {_compact(f)!r}")
            # CSS chain.
            css_links = re.findall(
                r'<link[^>]*rel="stylesheet"[^>]*>',
                body,
            )
            css_per_page = []
            for link in css_links:
                href_m = re.search(r'href="([^"]+)"', link)
                href = href_m.group(1) if href_m else "<no-href>"
                css_per_page.append(href)
            css_links_per_page[label] = css_per_page
            diag.observed(f"  stylesheet chain: {css_per_page}")

    # -----------------------------------------------------------------
    # Cross-step divergence summary. The point: if v0.7.2's
    # "normalize button sizing" patch worked, every step's
    # wizard-footer chrome should be byte-identical (modulo the
    # previous-step ordinal in the href). If they differ in class
    # strings or element types (anchor-vs-button mix), THAT is the
    # finding #2 root cause.
    # -----------------------------------------------------------------
    diag.section("cross-step divergence: top-nav identity check")
    distinct_navs = set(nav_per_page.values())
    diag.observed(f"distinct <nav> bodies across {len(nav_per_page)} pages: {len(distinct_navs)}")
    for i, n in enumerate(sorted(distinct_navs)):
        diag.observed(f"  variant[{i}] (compact): {_compact(n)!r}")
        diag.observed(
            f"  pages with this variant: "
            f"{sorted(k for k, v in nav_per_page.items() if v == n)}"
        )

    diag.section("cross-step divergence: <main> open-tag identity check")
    distinct_mains = set(main_per_page.values())
    diag.observed(f"distinct <main> open tags: {len(distinct_mains)}")
    for i, m in enumerate(sorted(distinct_mains)):
        diag.observed(f"  variant[{i}]: {m!r}")
        diag.observed(
            f"  pages: {sorted(k for k, v in main_per_page.items() if v == m)}"
        )

    diag.section("cross-step divergence: wizard-footer button-class check")
    # Per page, extract the class strings on every <a role='button'>
    # and <button> inside the footer. Identical class lists across
    # steps means the v0.7.2 normalization patch took; any divergence
    # is the suspect.
    button_classes_per_page: dict[str, list[str]] = {}
    for label, footer in footer_per_page.items():
        if footer == "<MISSING>":
            button_classes_per_page[label] = ["<no-footer>"]
            continue
        classes: list[str] = []
        for tag in re.findall(r"<(?:a|button)\b[^>]*>", footer):
            class_m = re.search(r'class="([^"]*)"', tag)
            role_m = re.search(r'role="([^"]*)"', tag)
            type_m = re.search(r'type="([^"]*)"', tag)
            classes.append(
                f"<{tag[1:].split()[0]} "
                f"role={role_m.group(1) if role_m else '-'} "
                f"type={type_m.group(1) if type_m else '-'} "
                f"class={class_m.group(1) if class_m else '-'}>"
            )
        button_classes_per_page[label] = classes
    for label, classes in button_classes_per_page.items():
        diag.observed(f"  {label}: {classes}")
    distinct_class_signatures = set(
        tuple(c) for c in button_classes_per_page.values()
    )
    diag.observed(
        f"distinct button-tag signatures across pages: "
        f"{len(distinct_class_signatures)}"
    )
    for i, sig in enumerate(sorted(distinct_class_signatures)):
        diag.observed(f"  signature[{i}] = {list(sig)}")
        diag.observed(
            f"  pages: "
            f"{sorted(k for k, v in button_classes_per_page.items() if tuple(v) == sig)}"
        )

    # -----------------------------------------------------------------
    # Top-nav specificity / Pico-classless gap. The wizard's <nav>
    # carries no class, so any Pico class-targeted rule (e.g. for
    # .topnav like the dashboard uses) does NOT apply. Surface that
    # gap explicitly so finding #1 has a concrete root cause.
    # -----------------------------------------------------------------
    diag.section("finding #1 root-cause: top-nav has no class hooks")
    diag.observed(
        "_base.html renders <nav><strong>lynceus-setup</strong> <small>v...</small> ...</nav>. "
        "There is NO class on the <nav>, NO classes inside it, and Pico's "
        "classless build styles bare nav elements minimally (text color "
        "only; no border, no background, no padding). The dashboard's "
        "<nav class='topnav'> by contrast has a per-class rule in "
        "src/lynceus/webui/static/lynceus.css. The wizard ships no "
        "equivalent — bundled CSS chain is just pico.min.css, no "
        "wizard-side lynceus.css. To fix #1 the wizard either needs "
        "(a) a class on the nav + a rule in _base.html's <style> block, "
        "OR (b) the dashboard's lynceus.css ported / re-mounted under "
        "the wizard's /static."
    )

    diag.notes(
        "Findings #1 (top-nav bare letters), #2 (Prev/Next sizing), "
        "#3 (centering) all map to the same root layer: chrome lives in "
        "_base.html's inline <style> block + per-step Prev/Next markup. "
        "If the cross-step button-class signatures section above shows a "
        "single signature for every step, the v0.7.2 normalization landed "
        "and #2 is now a CSS specificity / Pico-default override question; "
        "if signatures differ, that step is the divergence to fix. The "
        "<main> identity check section similarly localizes #3."
    )
