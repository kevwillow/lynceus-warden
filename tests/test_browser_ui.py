"""Drive every web UI surface in a real browser and assert what actually breaks.

⛔ **Deselected by default.** This needs Chromium and the `playwright` package,
neither of which is in `.venv` or on a stock CI runner. Run it explicitly:

    LYNCEUS_PLAYWRIGHT_SITE=/path/to/a/venv/lib/python3.11/site-packages \
        pytest -m browser

Everything else in `tests/` asserts server-rendered HTML or captured template
context. That cannot see a Content-Security-Policy blocking a handler the page
depends on, a JavaScript error that stops a form submitting, or a link that
404s. Those are the defects this file exists to catch, and PR #19 shipped one of
them: a CSP-blocked `onsubmit="return confirm()"` turned "permanently silence
this device" into one unconfirmed click.

The measurements it makes are the browser's own. CSP violations come from the
`securitypolicyviolation` event, which is what the browser BLOCKED rather than
what the header claims. Inline handlers are counted on the live DOM, so a
template that stops emitting one and a policy that stops allowing one are
distinguishable.

⚠️ Two behaviours are recorded rather than treated as defects, and both were
false positives in the harness this file grew out of:

1. A download does not navigate. Chromium aborts the navigation and playwright
   raises, so driving `/alerts.csv` through the browser always looked like a
   hard failure. Those routes are fetched over plain HTTP instead.
2. A route that correctly 404s also logs `Failed to load resource: 404` to the
   console. That is the browser narrating the expected answer, not a defect.
"""
from __future__ import annotations

import contextlib
import os
import pwd
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from lynceus import kismet
from lynceus.config import Config, CoObservationConfig
from lynceus.db import Database
from lynceus.webui.app import create_app

pytestmark = pytest.mark.browser

#: The device pages are keyed on a MAC, so the fixture's own MAC is spliced in
#: and spliced back out again before anything is compared. `{mac}` is the
#: placeholder in every expectation below.
MAC_PLACEHOLDER = "{mac}"

#: Every surface the UI serves, with the answer each one owes.
#:
#: ⛔ `/devices/{mac}/co-observations` is 404 ON PURPOSE. Co-observation ships
#: disabled, and that route is a capability toggle as well as a privacy control:
#: serving it while the capability is off would be the defect. Asserting the
#: refusal is the point. It is also why this file cannot claim to have rendered
#: the co-observation page; see "not covered" at the bottom.
EXPECTED_STATUS = {
    "/": 200,
    "/alerts": 200,
    "/alerts/1": 200,
    "/devices": 200,
    f"/devices/{MAC_PLACEHOLDER}": 200,
    f"/devices/{MAC_PLACEHOLDER}/co-observations": 404,
    "/probes": 200,
    "/rules": 200,
    "/settings": 200,
    "/watchlist": 200,
    "/allowlist": 200,
    "/watchful": 200,
    "/healthz": 200,
    "/healthz.json": 200,
    "/alerts.csv": 200,
    "/watchlist.csv": 200,
}

#: Routes a browser downloads rather than renders. Fetched over HTTP instead.
#:
#: ⚠️ Add a suffix here when a route starts serving a download, or the crawl
#: records it as a BROKEN link rather than as a download. Measured when the
#: case-file export landed: Chromium aborts the navigation, playwright raises,
#: and `/devices/<mac>/case-file.zip` came back as -1. The default suite
#: deselects this file, so nothing but this gate would have caught it, and this
#: gate runs at release time.
DOWNLOAD_SUFFIXES = (".csv", ".json", ".zip")

#: ⭐ THE RECORDED DECISION. These controls change state and ask nothing first.
#: It is a decision rather than a defect list, so it is written down here and
#: enforced rather than left to be rediscovered.
#:
#: The working rule: a control carries `data-confirm` when getting it wrong is
#: expensive to undo. Silencing a device, allowlisting one and destroying a
#: triage note all change what you will be told about later, and nothing on
#: screen says it happened. Acknowledging an alert is one click to undo, it is
#: done in bulk during triage, and a dialog on every row trains the operator to
#: dismiss dialogs, which is how the guarded ones stop working.
#:
#: ⚠️ The shipped UI does not apply that rule uniformly. Both exceptions are
#: recorded here rather than smoothed over:
#:
#: 1. "Watch" is guarded on `/devices/{mac}` and unguarded on `/alerts`. Same
#:    action, two surfaces. The device page guards all four of its controls,
#:    which reads as a blanket rather than a decision.
#: 2. `/allowlist` bulk-remove is unguarded while both bulk controls on
#:    `/alerts` are guarded. Neither page has a working select-all, so both act
#:    only on rows ticked by hand. What separates them is direction: removing an
#:    allowlist entry makes a device noisy again, so the failure is more
#:    alerting rather than less.
#:
#: Neither exception was changed here. Changing them is a UI decision for the
#: operator, not a drive-by edit inside a test.
#:
#: ⚠️ This is an equality assertion in both directions. A new unguarded control
#: fails it, and so does newly guarding one of these. Either way somebody comes
#: back to this comment and decides again, on purpose.
EXPECTED_UNGUARDED = {
    "/": 3,
    "/alerts": 6,
    "/alerts/1": 2,
    "/allowlist": 2,
}

#: Guarded controls, by route. ⛔ A floor here would be satisfied by the wrong
#: forms carrying the guard, so this is exact too.
#:
#: * `/devices/{mac}`: add to watchlist, watch this device, silence
#:   permanently, silence temporarily. All four.
#: * `/alerts/1`: allowlist this device, snooze, clear note.
#: * `/alerts`: the two bulk controls, acknowledge-all-visible and
#:   acknowledge-selected.
EXPECTED_GUARDED = {
    "/alerts": 2,
    "/alerts/1": 3,
    f"/devices/{MAC_PLACEHOLDER}": 4,
}

#: Below this the crawl saw a broken fixture rather than a working UI, and every
#: "zero problems" assertion in this file would pass vacuously.
MIN_HTML_PAGES = 12
MIN_INTERNAL_LINKS = 30


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _http_status(url: str) -> tuple[int, str]:
    """(status, content-type) over plain HTTP, for routes a browser downloads."""
    try:
        r = urllib.request.urlopen(url, timeout=10)
        return r.status, (r.headers.get("content-type") or "").split(";")[0]
    except urllib.error.HTTPError as e:
        return e.code, "http-error"
    except Exception as e:  # noqa: BLE001 - reported, not swallowed
        return -1, type(e).__name__


def _sync_playwright():
    """Import playwright, or fail loudly saying how to get it.

    ⛔ Deliberately not a skip. Reaching here means the `browser` marker was
    selected, so somebody asked for this gate. A gate that quietly skips when it
    cannot run reports the same green as a gate that ran and found nothing.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ModuleNotFoundError:
        site = os.environ.get("LYNCEUS_PLAYWRIGHT_SITE", "")
        if site and Path(site).is_dir():
            sys.path.append(site)
            try:
                from playwright.sync_api import sync_playwright
            except ModuleNotFoundError:
                pytest.fail(f"LYNCEUS_PLAYWRIGHT_SITE={site} has no playwright in it")
        else:
            pytest.fail(
                "playwright is not importable and LYNCEUS_PLAYWRIGHT_SITE is unset or not a "
                "directory. It is not a runtime dependency of lynceus and is not in .venv: "
                "build a side venv on the same interpreter, `pip install playwright`, and point "
                "LYNCEUS_PLAYWRIGHT_SITE at its site-packages."
            )
    return sync_playwright


def _chromium_executable() -> str | None:
    """An explicit browser path, or None to let playwright pick its own.

    ⚠️ The cached browser build and the build playwright asks for drift apart:
    the package resolves a revision by version, and an existing cache from an
    older install does not move. Passing the path found on disk is what makes
    this runnable without a fresh `playwright install`.

    ⛔ `Path.home()` is wrong here and this file proved it on its own first run.
    The suite redirects `HOME` per test so nothing can write into the real
    `~/.config/lynceus`, and the browser cache lives in the REAL home. Reading
    `HOME` resolved the cache inside the sandbox, found nothing, fell through to
    playwright's own lookup, which reads `HOME` too, and every test errored with
    "Executable doesn't exist" pointing at a pytest tmp directory. The passwd
    entry is the user's home whatever the environment says.
    """
    explicit = os.environ.get("LYNCEUS_CHROME", "")
    if explicit:
        if not Path(explicit).is_file():
            pytest.fail(f"LYNCEUS_CHROME={explicit} is not a file")
        return explicit
    browsers_path = os.environ.get("PLAYWRIGHT_BROWSERS_PATH", "")
    if browsers_path:
        cache = Path(browsers_path)
    else:
        cache = Path(pwd.getpwuid(os.getuid()).pw_dir) / ".cache" / "ms-playwright"
    for pattern in (
        "chromium_headless_shell-*/chrome-headless-shell-linux*/chrome-headless-shell",
        "chromium-*/chrome-linux*/chrome",
    ):
        hits = sorted(p for p in cache.glob(pattern) if p.is_file())
        if hits:
            return str(hits[-1])
    return None


@contextlib.contextmanager
def _serve(app):
    """Run an app on a real socket, and refuse to yield until it is up."""
    import uvicorn

    port = _free_port()
    server = uvicorn.Server(
        uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.1)
    assert server.started, "uvicorn never came up, so nothing below measured the UI"
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=10)


@pytest.fixture(scope="module")
def _isolated_home(tmp_path_factory):
    """The same hermeticity guard `conftest.py` gives every test, at module scope.

    The autouse one there is function-scoped, and a module-scoped fixture is
    built before it runs. Without this, app construction here would see the real
    `~/.config/lynceus` of whoever ran the suite.
    """
    home = tmp_path_factory.mktemp("browser-home")
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("HOME", str(home))
        mp.setenv("XDG_CONFIG_HOME", str(home / ".config"))
        mp.setenv("XDG_DATA_HOME", str(home / ".local" / "share"))
        mp.setenv("XDG_STATE_HOME", str(home / ".local" / "state"))
        yield home


@pytest.fixture(scope="module")
def _served_ui(_isolated_home, tmp_path_factory):
    """The real app, on a real socket, seeded so every guarded form renders.

    ⚠️ Fixture traps, each one measured rather than guessed:

    * The MAC must be normalized. Ingest normalizes before upsert and
      `/devices/{mac}` looks up the normalized form, so an uppercase seed makes
      every device page 404.
    * The allowlist file must exist for the triage section to render at all, and
      must NOT match the seeded devices. An allowlisted device renders the
      "already allowlisted" branch, which has no buttons, and the guarded forms
      silently vanish.
    * An alert needs a note, or the "clear the triage note" form does not render.
    """
    tmp = tmp_path_factory.mktemp("browser-ui")
    allowlist = tmp / "allowlist.yaml"
    allowlist.write_text(
        "entries:\n"
        '  - pattern: "99:99:99:00:00:01"\n'
        "    pattern_type: mac\n"
        "    note: deliberately unrelated to the seeded devices\n"
    )
    # ⛔ The UI-managed sibling needs an entry too, and it must also miss the
    # seeded devices. `/allowlist` renders its "Remove selected" submit control
    # only when at least one UI-managed entry exists, so without this the
    # bulk-remove form has no submit button at all and the inventory below
    # records a form nobody can send. A fixture that hides a control cannot
    # notice that control changing.
    (tmp / "allowlist_ui.yaml").write_text(
        "entries:\n"
        '  - pattern: "88:88:88:00:00:02"\n'
        "    pattern_type: mac\n"
        "    note: UI-managed, and also unrelated to the seeded devices\n"
    )
    config = Config(db_path=str(tmp / "browser.db"), allowlist_path=str(allowlist))
    db = Database(config.db_path)
    now = int(time.time())
    db.ensure_location("default", "Default")
    macs = [kismet.normalize_mac(f"12:34:56:DD:EE:{i:02X}") for i in range(3)]
    for i, mac in enumerate(macs):
        db.upsert_device(
            mac=mac,
            device_type="wifi",
            oui_vendor="Test Vendor Ltd",
            is_randomized=0,
            now_ts=now - i * 60,
        )
        db.insert_sighting(
            mac=mac, ts=now - i * 60, rssi=-40 - i, ssid="testnet", location_id="default"
        )
        db.add_alert(
            ts=now - i * 60,
            rule_name="watchlist_mac_hit",
            mac=mac,
            message="Watchlisted MAC observed near the perimeter sensor",
            severity="high",
        )
    db.update_alert_note(1, "triage note so the clear-note form renders")

    try:
        with _serve(create_app(config, db)) as base:
            yield base, macs[0]
    finally:
        db.close()


@pytest.fixture(scope="module")
def crawl(_served_ui):
    """Visit every route once, in Chromium, and return what the browser saw.

    One crawl, many assertions. Each test below reads a different facet of this
    report, so a failure names the defect class rather than "the crawl failed".
    """
    base, mac = _served_ui
    sync_playwright = _sync_playwright()
    executable = _chromium_executable()

    pages: dict[str, dict] = {}
    links: dict[str, int] = {}

    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=executable)
        ctx = browser.new_context(viewport={"width": 1400, "height": 1000})
        for template in EXPECTED_STATUS:
            route = template.replace(MAC_PLACEHOLDER, mac)
            if route.endswith(DOWNLOAD_SUFFIXES):
                status, ctype = _http_status(base + route)
                pages[template] = {
                    "status": status,
                    "content_type": ctype,
                    "html": False,
                    "csp": [],
                    "js_errors": [],
                    "inline": 0,
                    "controls": [],
                    "links": [],
                    "overlaps": [],
                    "help_pairs": 0,
                }
                continue

            page = ctx.new_page()
            js_errors: list[str] = []
            page.on(
                "console",
                lambda m, sink=js_errors: sink.append(m.text) if m.type == "error" else None,
            )
            page.on("pageerror", lambda exc, sink=js_errors: sink.append(str(exc)))
            page.add_init_script(
                """
                window.__cspv = [];
                document.addEventListener('securitypolicyviolation', e => {
                    window.__cspv.push(e.violatedDirective + ' <- ' +
                        (e.blockedURI || '') + ' @' + (e.sourceFile || '') +
                        ':' + (e.lineNumber || ''));
                });
                """
            )
            try:
                resp = page.goto(base + route, wait_until="networkidle", timeout=15000)
                status = resp.status if resp else 0
                ctype = (resp.headers or {}).get("content-type", "") if resp else ""
            except Exception as e:  # noqa: BLE001 - recorded as the page's status
                pages[template] = {
                    "status": f"navigation {type(e).__name__}",
                    "content_type": "",
                    "html": False,
                    "csp": [],
                    "js_errors": [str(e)],
                    "inline": 0,
                    "controls": [],
                    "links": [],
                    "overlaps": [],
                    "help_pairs": 0,
                }
                page.close()
                continue

            is_html = "html" in ctype
            record = {
                "status": status,
                "content_type": ctype.split(";")[0],
                "html": is_html,
                "csp": [],
                "js_errors": [],
                "inline": 0,
                "controls": [],
                "links": [],
                "overlaps": [],
                "help_pairs": 0,
            }
            if is_html:
                page.wait_for_timeout(400)
                record["csp"] = page.evaluate("window.__cspv || []")
                # ⛔ Form CONTROLS are included even though they have children
                # (<option>), which the first version of this probe got wrong:
                # filtering to childless leaves silently excluded every
                # <select> and reported zero overlaps on a page that had one.
                # ⛔ Narrow ON PURPOSE: a control against the helper text
                # that BELONGS to it, i.e. its own immediately-following
                # <small> sibling. A general "do any two boxes intersect"
                # sweep was tried first and reported 40 pairs across /alerts
                # and /allowlist -- table cells, column-toggle checkboxes and
                # a disclosure summary, every one of them correct layout. A
                # guard that noisy gets switched off, and then it guards
                # nothing. This pairing is exactly the defect class that was
                # real, and it stays checkable.
                record["overlaps"] = page.evaluate(
                    """() => {
                        const out = [];
                        let seen = 0;
                        document.querySelectorAll(
                            'input + small, select + small, textarea + small'
                        ).forEach(note => {
                            seen++;
                            const control = note.previousElementSibling;
                            if (!control) return;
                            const rc = control.getBoundingClientRect();
                            const rn = note.getBoundingClientRect();
                            if (rc.width < 2 || rn.width < 2) return;
                            const ox = Math.min(rc.right, rn.right) - Math.max(rc.left, rn.left);
                            const oy = Math.min(rc.bottom, rn.bottom) - Math.max(rc.top, rn.top);
                            if (ox > 2 && oy > 2) {
                                const what = note.textContent.trim().slice(0, 60);
                                out.push(
                                    control.tagName + '[' + (control.name || '') +
                                    '] over its own help text ' + JSON.stringify(what) +
                                    ' by ' + Math.round(ox) + 'x' + Math.round(oy) + 'px'
                                );
                            }
                        });
                        window.__helpPairs = seen;
                        return out;
                    }"""
                )
                record["help_pairs"] = page.evaluate("window.__helpPairs || 0")
                record["controls"] = page.evaluate(
                    """() => {
                        const out = [];
                        document.querySelectorAll('form').forEach(f => {
                            const post =
                                (f.getAttribute('method') || 'get').toLowerCase() === 'post'
                                || !!f.getAttribute('hx-post');
                            if (!post) return;
                            // ⚠️ The button that SUBMITS, not the first button in
                            // the form. A `data_table` puts its own
                            // `type="button"` reset control above the real
                            // submit, and taking the first one labelled the
                            // allowlist bulk-remove control "reset columns".
                            const btn = f.querySelector(
                                'button[type=submit], button:not([type]), input[type=submit]'
                            ) || f.querySelector('button');
                            out.push({
                                action: f.getAttribute('action')
                                     || f.getAttribute('hx-post') || '',
                                guarded: !!f.getAttribute('data-confirm'),
                                label: (btn ? btn.textContent : '').trim().slice(0, 40),
                            });
                        });
                        return out;
                    }"""
                )
                record["links"] = page.evaluate(
                    """() => [...document.querySelectorAll('a[href]')]
                        .map(a => a.getAttribute('href'))
                        .filter(h => h && !h.startsWith('#') && !h.startsWith('http')
                                  && !h.startsWith('mailto'))"""
                )
                record["inline"] = page.evaluate(
                    """() => {
                        let n = 0;
                        for (const el of document.querySelectorAll('*'))
                            for (const a of el.attributes)
                                if (a.name.startsWith('on')) n++;
                        return n;
                    }"""
                )
                # The browser narrating an expected 404 is not a JS defect.
                expected_404 = EXPECTED_STATUS[template] == 404 and status == 404
                record["js_errors"] = [
                    e for e in js_errors if not (expected_404 and "404" in str(e))
                ]
            pages[template] = record
            page.close()

        # Follow every internal link the pages actually offered.
        page = ctx.new_page()
        for record in pages.values():
            for href in sorted(set(record["links"])):
                if href in links:
                    continue
                if href.endswith(DOWNLOAD_SUFFIXES):
                    links[href] = _http_status(base + href)[0]
                    continue
                try:
                    r = page.goto(base + href, wait_until="domcontentloaded", timeout=12000)
                    links[href] = r.status if r else 0
                except Exception:  # noqa: BLE001 - recorded as a broken link
                    links[href] = -1
        ctx.close()
        browser.close()

    # ⛔ Fail closed before any test reads this. A crawl that rendered nothing
    # reports zero CSP violations and zero JS errors, which is indistinguishable
    # from a clean UI.
    html_pages = [t for t, r in pages.items() if r["html"]]
    assert len(html_pages) >= MIN_HTML_PAGES, (
        f"only {len(html_pages)} pages parsed as HTML, expected at least {MIN_HTML_PAGES}. "
        f"The fixture is broken and every assertion in this file would pass vacuously."
    )
    controls = sum(len(r["controls"]) for r in pages.values())
    assert controls, "the crawl found no state-changing forms at all, so it graded nothing"
    return {"pages": pages, "links": links, "mac": mac}


def test_every_route_answers_what_it_owes(crawl):
    """Identity, not a floor: this route set, these statuses."""
    assert set(crawl["pages"]) == set(EXPECTED_STATUS), "the crawl did not visit every route"
    actual = {route: record["status"] for route, record in crawl["pages"].items()}
    expected = dict(EXPECTED_STATUS)
    assert actual == expected


def test_no_form_control_is_drawn_over_its_own_help_text(crawl):
    """Geometry the browser computed, not an impression from a screenshot.

    🪤 The defect this caught is a Pico inconsistency, and it is invisible to
    every server-rendered assertion in `tests/`. Pico pulls helper text up
    under a control with `margin-top: calc(var(--pico-spacing) * -.75)` to
    cancel that control's bottom margin, and separately zeroes that bottom
    margin when the control sits inside a <label>. Where both apply, the pull
    has nothing to cancel and drags the note INTO the control.

    Measured on /devices before the fix: the `probing` select was drawn 15px
    over `probe-SSID capture is disabled, so this view is empty; enabling it
    has a privacy tradeoff`, so the sentence explaining a privacy tradeoff
    read as struck through. The HTML was perfect throughout.
    """
    # ⛔ An empty universe scores as green. If no page renders a control
    # followed by its own help text, this test inspected nothing and would
    # pass over any amount of breakage.
    inspected = sum(record["help_pairs"] for record in crawl["pages"].values())
    assert inspected > 0, (
        "the crawl found no control-plus-help-text pairs at all, so this test "
        "proved nothing. Either the fixture stopped rendering them, or the "
        "markup pattern changed and this selector needs to change with it."
    )

    collisions = {
        route: record["overlaps"]
        for route, record in crawl["pages"].items()
        if record["overlaps"]
    }
    assert not collisions, (
        f"a form control is drawn over another element's box: {collisions}. "
        f"Text under a control is usually the thing explaining what the "
        f"control costs, so an overlap here loses the explanation, not decoration."
    )


def test_no_content_security_policy_violations(crawl):
    """What the browser BLOCKED, not what the header says it would allow."""
    violations = {
        route: record["csp"] for route, record in crawl["pages"].items() if record["csp"]
    }
    assert not violations, f"the CSP blocked something the page needs: {violations}"


def test_no_uncaught_javascript_errors(crawl):
    errors = {
        route: record["js_errors"]
        for route, record in crawl["pages"].items()
        if record["js_errors"]
    }
    assert not errors, f"JavaScript failed on these pages: {errors}"


def test_no_inline_event_handlers_survive_at_runtime(crawl):
    """The PR #19 class, measured on the live DOM rather than in the template.

    An inline `on*=` attribute under this app's CSP is a control that silently
    does nothing. Counting them in the rendered DOM is what makes a template
    that stops emitting one distinguishable from a policy that starts allowing
    one.
    """
    inline = {
        route: record["inline"] for route, record in crawl["pages"].items() if record["inline"]
    }
    assert not inline, f"inline on*= attributes present at runtime: {inline}"


def test_every_internal_link_resolves(crawl):
    links = crawl["links"]
    assert len(links) >= MIN_INTERNAL_LINKS, (
        f"only {len(links)} internal links were followed, expected at least "
        f"{MIN_INTERNAL_LINKS}. A page that stopped rendering its navigation would "
        f"otherwise make this file report a healthy UI."
    )
    broken = {href: status for href, status in links.items() if status >= 400 or status < 0}
    assert not broken, f"internal links that do not resolve: {broken}"


def test_state_changing_controls_match_the_recorded_decision(crawl):
    """Which destructive controls carry a confirmation, decided on purpose.

    ⛔ Read `EXPECTED_UNGUARDED` above before changing this. It is a decision
    with reasons, and this test is where the decision is enforced. Both
    directions fail: adding an unguarded control and guarding an existing one
    both land here so somebody has to decide again.
    """
    mac = crawl["mac"]
    unguarded, guarded = {}, {}
    for route, record in crawl["pages"].items():
        n_unguarded = sum(1 for c in record["controls"] if not c["guarded"])
        n_guarded = sum(1 for c in record["controls"] if c["guarded"])
        if n_unguarded:
            unguarded[route] = n_unguarded
        if n_guarded:
            guarded[route] = n_guarded

    def describe(control):
        mark = "GUARDED  " if control["guarded"] else "unguarded"
        action = control["action"].replace(mac, MAC_PLACEHOLDER)
        return f"{mark} {action}  [{control['label']}]"

    detail = {
        route: [describe(c) for c in record["controls"]]
        for route, record in crawl["pages"].items()
        if record["controls"]
    }
    assert unguarded == EXPECTED_UNGUARDED, f"unguarded controls changed: {detail}"
    assert guarded == EXPECTED_GUARDED, f"guarded controls changed: {detail}"


@pytest.fixture(scope="module")
def _served_ui_with_co_observation(_isolated_home, tmp_path_factory):
    """A second app, with the co-observation capability ON.

    ⛔ The main crawl asserts `/devices/{mac}/co-observations` **404s**, because
    the capability ships disabled and serving it while off would be the defect.
    That is the right assertion and it leaves a real gap: the rendered page has
    never been in a browser. This closes it without weakening the refusal, by
    building a second app rather than turning the capability on in the first.

    Seeded so the page has something to draw. Two devices at one location with
    sightings inside `proximity_seconds` (300 by default) of each other are what
    makes a pair, so a page rendered from this fixture must list a candidate. A
    page that renders empty is indistinguishable from a page that renders
    broken, and both would satisfy "HTTP 200".
    """
    tmp = tmp_path_factory.mktemp("browser-coobs")
    allowlist = tmp / "allowlist.yaml"
    allowlist.write_text(
        "entries:\n"
        '  - pattern: "99:99:99:00:00:01"\n'
        "    pattern_type: mac\n"
        "    note: deliberately unrelated to the seeded devices\n"
    )
    config = Config(
        db_path=str(tmp / "coobs.db"),
        allowlist_path=str(allowlist),
        co_observation=CoObservationConfig(enabled=True),
    )
    db = Database(config.db_path)
    now = int(time.time())
    db.ensure_location("default", "Default")
    macs = [kismet.normalize_mac(f"12:34:56:DD:EE:{i:02X}") for i in range(2)]
    for i, mac in enumerate(macs):
        db.upsert_device(
            mac=mac,
            device_type="wifi",
            oui_vendor="Test Vendor Ltd",
            is_randomized=0,
            now_ts=now - 60,
        )
        # Both sighted at the same place, 30s apart, three times over three
        # days. One pair proves nothing about runs; repeated pairs are what the
        # page counts.
        for day in range(3):
            db.insert_sighting(
                mac=mac,
                ts=now - day * 86400 - i * 30,
                rssi=-40 - i,
                ssid="testnet",
                location_id="default",
            )
    try:
        with _serve(create_app(config, db)) as base:
            yield base, macs[0]
    finally:
        db.close()


@pytest.fixture(scope="module")
def co_observation_page(_served_ui_with_co_observation):
    """Render the co-observation page in Chromium and report what it drew."""
    base, mac = _served_ui_with_co_observation
    sync_playwright = _sync_playwright()
    executable = _chromium_executable()
    route = f"/devices/{mac}/co-observations"

    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=executable)
        ctx = browser.new_context(viewport={"width": 1400, "height": 1000})
        page = ctx.new_page()
        js_errors: list[str] = []
        page.on(
            "console",
            lambda m, sink=js_errors: sink.append(m.text) if m.type == "error" else None,
        )
        page.on("pageerror", lambda exc, sink=js_errors: sink.append(str(exc)))
        page.add_init_script(
            """
            window.__cspv = [];
            document.addEventListener('securitypolicyviolation', e => {
                window.__cspv.push(e.violatedDirective + ' <- ' + (e.blockedURI || ''));
            });
            """
        )
        resp = page.goto(base + route, wait_until="networkidle", timeout=15000)
        page.wait_for_timeout(400)
        record = {
            "status": resp.status if resp else 0,
            "csp": page.evaluate("window.__cspv || []"),
            "js_errors": js_errors,
            "inline": page.evaluate(
                """() => {
                    let n = 0;
                    for (const el of document.querySelectorAll('*'))
                        for (const a of el.attributes)
                            if (a.name.startsWith('on')) n++;
                    return n;
                }"""
            ),
            # Candidate rows link to the other device's page. Counting the links
            # rather than the rows keeps this off the table's shape, which the
            # page changes between its list and detail views.
            "candidates": page.evaluate(
                """() => [...document.querySelectorAll('table a[href^="/devices/"]')].length"""
            ),
            "route": route,
        }
        ctx.close()
        browser.close()
    return record


def test_the_co_observation_page_renders_when_the_capability_is_on(co_observation_page):
    """The one surface the main crawl is not allowed to reach.

    Keeping this separate from `crawl` is deliberate. The main fixture must go
    on proving that the route REFUSES while the capability is off, and a single
    fixture cannot assert both answers.
    """
    record = co_observation_page
    assert record["status"] == 200, f"{record['route']} answered {record['status']}"
    assert not record["csp"], f"the CSP blocked something the page needs: {record['csp']}"
    assert not record["js_errors"], f"JavaScript failed: {record['js_errors']}"
    assert not record["inline"], (
        f"{record['inline']} inline on*= attribute(s) present at runtime"
    )
    # ⛔ Non-vacuity. A page that rendered its empty state also answers 200 with
    # no CSP violations and no JS errors, and would pass everything above.
    assert record["candidates"] > 0, (
        "the page rendered with no co-observed devices, so the assertions above "
        "graded an empty page. The fixture seeds two devices at one location "
        "within the proximity window, which must produce at least one candidate."
    )


# --- Authentication, in a real browser ----------------------------------------
#
# ⛔ A third app, for the same reason `_served_ui_with_co_observation` is a
# second one: the main crawl must go on proving the UI serves every route with
# NO credential, because that is the shipped default on a loopback bind. One
# fixture cannot assert both answers.
#
# ⭐ Why this is worth a browser at all. `/login` is the only page an operator
# sees before they can get in, and it is the one page where a CSS or CSP mistake
# is not a cosmetic bug but a locked-out operator with no way to report it. It
# also carries brand-new styles (`.login-card`, `.topnav .signout`) that no
# other test renders. The unit tests prove the middleware refuses; only this
# proves a human can then get past it.


@pytest.fixture(scope="module")
def _served_ui_with_auth(_isolated_home, tmp_path_factory):
    """The app with a password configured, on a real socket."""
    from lynceus.webui.auth import hash_password
    from lynceus.webui.credentials import write_credentials

    tmp = tmp_path_factory.mktemp("browser-auth")
    allowlist = tmp / "allowlist.yaml"
    allowlist.write_text(
        "entries:\n"
        '  - pattern: "99:99:99:00:00:01"\n'
        "    pattern_type: mac\n"
        "    note: deliberately unrelated to the seeded devices\n"
    )
    config = Config(db_path=str(tmp / "auth.db"), allowlist_path=str(allowlist))
    write_credentials(config.resolved_ui_auth_path(), hash_password(BROWSER_PASSWORD))
    db = Database(config.db_path)
    now = int(time.time())
    db.ensure_location("default", "Default")
    mac = kismet.normalize_mac("12:34:56:DD:EE:10")
    db.upsert_device(
        mac=mac, device_type="wifi", oui_vendor="Test Vendor Ltd", is_randomized=0, now_ts=now
    )
    db.add_alert(
        ts=now,
        rule_name="watchlist_mac_hit",
        mac=mac,
        message="Watchlisted MAC observed near the perimeter sensor",
        severity="high",
    )
    try:
        with _serve(create_app(config, db)) as base:
            yield base
    finally:
        db.close()


#: Long enough to clear MIN_PASSWORD_LENGTH, and obviously not a real one.
BROWSER_PASSWORD = "browser-gate-passphrase"


@pytest.fixture(scope="module")
def login_journey(_served_ui_with_auth):
    """Drive the whole sign-in journey once and report what the browser saw.

    Ordered deliberately: an unauthenticated dashboard visit FIRST, so the
    redirect is measured before any session exists, then the login page, then
    the submit, then the authenticated page. A journey that logged in first
    could not tell a working redirect from a route that was never protected.
    """
    base = _served_ui_with_auth
    sync_playwright = _sync_playwright()
    executable = _chromium_executable()

    with sync_playwright() as pw:
        browser = pw.chromium.launch(executable_path=executable)
        # 1280 is the narrower of the two widths the layout work targets, so a
        # card that overflows anywhere overflows here first.
        ctx = browser.new_context(viewport={"width": 1280, "height": 900})
        page = ctx.new_page()
        js_errors: list[str] = []
        page.on(
            "console",
            lambda m, sink=js_errors: sink.append(m.text) if m.type == "error" else None,
        )
        page.on("pageerror", lambda exc, sink=js_errors: sink.append(str(exc)))
        page.add_init_script(
            """
            window.__cspv = [];
            document.addEventListener('securitypolicyviolation', e => {
                window.__cspv.push(e.violatedDirective + ' <- ' + (e.blockedURI || ''));
            });
            """
        )

        # 1. An unauthenticated browser asking for the dashboard.
        page.goto(base + "/alerts", wait_until="networkidle", timeout=15000)
        landed_on = page.url

        # 2. The login page itself.
        page.goto(base + "/login", wait_until="networkidle", timeout=15000)
        page.wait_for_timeout(300)
        login_metrics = page.evaluate(
            """() => {
                const card = document.querySelector('.login-card');
                const field = document.querySelector('input[type="password"]');
                const submit = document.querySelector('.login-card button[type="submit"]');
                const r = card ? card.getBoundingClientRect() : null;
                return {
                    hasCard: !!card,
                    hasField: !!field,
                    hasSubmit: !!submit,
                    // ⚠️ Measured, not reasoned about. A card wider than the
                    // viewport is the failure mode of a max-width that lost to
                    // a Pico rule, and it is invisible in a unit test.
                    cardWidth: r ? Math.round(r.width) : 0,
                    cardLeft: r ? Math.round(r.left) : 0,
                    viewport: document.documentElement.clientWidth,
                    bodyScrollWidth: document.body.scrollWidth,
                    // The password must never be rendered into the page.
                    fieldValue: field ? field.value : null,
                    submitWidth: submit ? Math.round(submit.getBoundingClientRect().width) : 0,
                };
            }"""
        )
        login_csp = page.evaluate("window.__cspv || []")

        # 3. Sign in the way an operator does: type it and press the button.
        page.fill('input[type="password"]', BROWSER_PASSWORD)
        page.click('.login-card button[type="submit"]')
        page.wait_for_load_state("networkidle", timeout=15000)
        page.wait_for_timeout(300)
        after_login_url = page.url

        # 4. And now a guarded page, with the nav that only exists when auth is on.
        page.goto(base + "/alerts", wait_until="networkidle", timeout=15000)
        page.wait_for_timeout(300)
        authed_metrics = page.evaluate(
            """() => {
                const nav = document.querySelector('.topnav');
                const out = document.querySelector('.topnav .signout');
                const navR = nav ? nav.getBoundingClientRect() : null;
                const outR = out ? out.getBoundingClientRect() : null;
                return {
                    status: 200,
                    hasSignout: !!out,
                    // ⛔ The sign-out control must sit INSIDE the nav strip.
                    // margin-left:auto only works because .topnav is flex, and
                    // "it's flex" is exactly the kind of assumption this repo
                    // has been wrong about every time it was not measured.
                    signoutRight: outR ? Math.round(outR.right) : 0,
                    navRight: navR ? Math.round(navR.right) : 0,
                    navScrollWidth: nav ? nav.scrollWidth : 0,
                    navClientWidth: nav ? nav.clientWidth : 0,
                    bodyScrollWidth: document.body.scrollWidth,
                    viewport: document.documentElement.clientWidth,
                    alertRows: document.querySelectorAll('table tbody tr').length,
                };
            }"""
        )
        authed_csp = page.evaluate("window.__cspv || []")
        ctx.close()
        browser.close()

    return {
        "base": base,
        "landed_on": landed_on,
        "login": login_metrics,
        "login_csp": login_csp,
        "after_login_url": after_login_url,
        "authed": authed_metrics,
        "authed_csp": authed_csp,
        "js_errors": js_errors,
    }


def test_an_unauthenticated_browser_lands_on_the_login_page(login_journey):
    assert "/login" in login_journey["landed_on"], (
        f"an unauthenticated browser asking for /alerts ended up at "
        f"{login_journey['landed_on']}, not the login page"
    )


def test_the_login_page_draws_a_usable_form(login_journey):
    """⛔ Non-vacuity first. A 200 with an empty body passes every CSP and JS
    assertion below, so the controls are asserted before the absences are."""
    m = login_journey["login"]
    assert m["hasCard"], "no .login-card rendered"
    assert m["hasField"], "no password field rendered"
    assert m["hasSubmit"], "no submit button rendered"
    assert not m["fieldValue"], "the password field came pre-filled from the server"
    assert m["submitWidth"] > 0, "the submit button has no width; it cannot be clicked"


def test_the_login_card_fits_its_viewport(login_journey):
    """Measured, because the last four CSS assumptions in this repo were wrong.

    ``form button[type=submit] { width: auto }`` exists precisely because Pico's
    classless defaults outrank class selectors, and `.login-card` opts back into
    full width. That interaction is only observable in a browser.
    """
    m = login_journey["login"]
    assert m["cardWidth"] <= m["viewport"], (
        f"the login card is {m['cardWidth']}px in a {m['viewport']}px viewport"
    )
    assert m["cardLeft"] >= 0, f"the login card starts at x={m['cardLeft']}, off-screen left"
    assert m["bodyScrollWidth"] <= m["viewport"] + 1, (
        f"the login page scrolls horizontally: body is {m['bodyScrollWidth']}px "
        f"in a {m['viewport']}px viewport"
    )


def test_the_login_page_violates_no_policy_and_throws_nothing(login_journey):
    assert not login_journey["login_csp"], (
        f"the CSP blocked something the login page needs: {login_journey['login_csp']}"
    )
    assert not login_journey["js_errors"], f"JavaScript failed: {login_journey['js_errors']}"


def test_signing_in_through_the_form_reaches_the_dashboard(login_journey):
    """The half the unit tests cannot reach: a real browser, a real form POST,
    a real Set-Cookie that the browser then chooses to return.

    ⚠️ **What this canNOT catch, measured rather than assumed.** An earlier draft
    of this docstring claimed it would have caught the ``Secure``-on-plain-HTTP
    bug this repo already shipped once. It would not. Planting that defect —
    forcing ``Secure`` onto the session cookie unconditionally — left all 15
    browser tests passing, because **Chromium treats ``http://127.0.0.1`` as a
    secure context** and returns ``Secure`` cookies over it anyway. This harness
    serves on loopback, so it is structurally blind to that class, and the real
    bug only ever bit an operator browsing to a NON-loopback address.

    ⇒ The guard for that property is
    ``tests/test_webui_auth.py::test_the_session_cookie_is_httponly_and_samesite_and_not_secure_over_http``,
    which reads the ``Set-Cookie`` header directly instead of asking a browser
    that has been told to be lenient. Recorded here so nobody reads this test as
    covering it.

    What this DOES prove: the form exists, the POST is accepted, the cookie
    round-trips, and the operator ends up somewhere other than the login page.
    """
    assert "/login" not in login_journey["after_login_url"], (
        f"after submitting the correct password the browser was still at "
        f"{login_journey['after_login_url']} — the session cookie was not "
        f"accepted or was not returned"
    )


def test_the_authenticated_nav_carries_a_sign_out_control_inside_the_strip(login_journey):
    m = login_journey["authed"]
    assert m["hasSignout"], "no sign-out control in the nav of an authenticated page"
    assert m["signoutRight"] <= m["navRight"] + 1, (
        f"the sign-out control ends at x={m['signoutRight']} but the nav ends at "
        f"x={m['navRight']} — it is overflowing the strip"
    )
    assert m["navScrollWidth"] <= m["navClientWidth"] + 1, (
        f"the nav scrolls: {m['navScrollWidth']}px of content in "
        f"{m['navClientWidth']}px. Adding sign-out pushed the strip over."
    )
    assert m["bodyScrollWidth"] <= m["viewport"] + 1, (
        f"the authenticated page scrolls horizontally: {m['bodyScrollWidth']}px "
        f"in {m['viewport']}px"
    )


def test_the_authenticated_page_actually_rendered_its_data(login_journey):
    """⛔ Non-vacuity for the test above. A logged-in page that rendered an
    empty table also has a well-placed sign-out button."""
    m = login_journey["authed"]
    assert m["alertRows"] > 0, (
        "the authenticated /alerts page rendered no rows, so the layout "
        "assertions above graded an empty page"
    )
    assert not login_journey["authed_csp"], (
        f"the CSP blocked something the authenticated page needs: "
        f"{login_journey['authed_csp']}"
    )
