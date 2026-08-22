"""Every GET form in the UI survives being submitted exactly as rendered.

⛔ THE DEFECT THIS EXISTS FOR, and it shipped through every gate this repo has.

`/alerts` renders `<form method="get">` whose severity select defaults to
`<option value="" selected>any</option>`. A browser submits `severity=` for
that control. The route's validator read the empty string as invalid and
returned **400**. So an operator who pressed *filter* without changing anything
landed on an error page, on the product's main surface, one click from the home
page.

Nothing caught it:

  * the unit tests call routes with the parameters a TEST author chose, never
    the ones the TEMPLATE emits;
  * `tests/test_browser_ui.py` crawls every route and checks CSP violations,
    JavaScript errors and inline handlers -- but never presses a button;
  * ruff, CodeQL, actionlint, shellcheck and the wheel smoke are all blind to it.

⇒ The gap was not "no gate ran". It was that **no gate ever submitted the
application's own form with the application's own defaults.** That is the class
this file closes, and it closes it for every list page at once rather than for
the one that was reported.

⚠️ WHY THIS IS A SERVER-SIDE TEST AND NOT A BROWSER ONE. The browser gate is
`@pytest.mark.browser`, deselected in CI because it needs Chromium. A gate that
only runs on a developer's machine would not have caught this either. This runs
in the default suite, on every push, with no extra dependency: it parses the
rendered HTML for the form's own controls and replays them.
"""

from __future__ import annotations

import html.parser
import time

import pytest
from fastapi.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import create_app

# Every page that renders a filter form. ⛔ Identity, not a floor: if a page is
# added here it gets covered, and if one is REMOVED the test below fails rather
# than quietly shrinking its own universe.
# ⚠️ `/allowlist` is deliberately absent: measured, it renders NO GET form, so
# including it made the non-vacuity floor below assert something false. The
# instrument bounds the finding -- a sweep whose page list is wrong returns a
# confident wrong number.
FORM_PAGES = ["/alerts", "/devices", "/watchlist", "/watchful", "/probes"]


class _FormExtractor(html.parser.HTMLParser):
    """Pull out each GET form's action and the name=value pairs it would submit.

    Deliberately a parser rather than a regex: the point is to send what the
    BROWSER would send, and a regex over `<option selected>` gets the
    "which option is selected" question wrong in exactly the cases that matter.
    """

    def __init__(self):
        super().__init__()
        self.forms: list[dict] = []
        self._current: dict | None = None
        self._select_name: str | None = None
        self._select_has_selection = False
        self._first_option: str | None = None
        self._pending_option: str | None = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            if (a.get("method") or "get").lower() == "get":
                self._current = {"action": a.get("action") or "", "fields": []}
            return
        if self._current is None:
            return
        if tag == "input":
            name, itype = a.get("name"), (a.get("type") or "text").lower()
            if not name or itype in {"submit", "button", "reset"}:
                return
            if itype in {"checkbox", "radio"}:
                if "checked" in a:
                    self._current["fields"].append((name, a.get("value", "on")))
                return
            self._current["fields"].append((name, a.get("value", "")))
        elif tag == "select":
            self._select_name = a.get("name")
            self._select_has_selection = False
            self._first_option = None
        elif tag == "option" and self._select_name:
            value = a.get("value", "")
            if self._first_option is None:
                self._first_option = value
            if "selected" in a:
                self._current["fields"].append((self._select_name, value))
                self._select_has_selection = True

    def handle_endtag(self, tag):
        if tag == "select" and self._select_name and self._current is not None:
            # A select with no explicit selection submits its FIRST option --
            # which is how a browser behaves and is easy to get wrong by hand.
            if not self._select_has_selection and self._first_option is not None:
                self._current["fields"].append((self._select_name, self._first_option))
            self._select_name = None
        elif tag == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    """A database with one of everything, so the pages render their real form.

    ⛔ An empty database can render an empty state with no form at all, and the
    sweep would then submit nothing and pass. `test_the_sweep_found_forms`
    below fails if that happens.
    """
    tmp = tmp_path_factory.mktemp("forms")
    db = Database(str(tmp / "f.db"))
    db.ensure_location("home", "Home")
    now = int(time.time())
    db.upsert_device(
        mac="aa:bb:cc:00:00:01", device_type="wifi", oui_vendor="Axon Enterprise",
        is_randomized=0, now_ts=now,
    )
    db.insert_sighting(
        mac="aa:bb:cc:00:00:01", ts=now, rssi=-50, ssid=None, location_id="home"
    )
    db.add_alert(
        ts=now, rule_name="watchlist_oui", mac="aa:bb:cc:00:00:01",
        message="Body-worn camera seen nearby", severity="high",
    )
    with TestClient(create_app(Config(db_path=str(tmp / "f.db")), db)) as c:
        yield c
    db.close()


def _forms_on(client, path):
    response = client.get(path)
    assert response.status_code == 200, f"{path} did not render: {response.status_code}"
    parser = _FormExtractor()
    parser.feed(response.text)
    return parser.forms


def test_the_sweep_found_forms(client):
    """⛔ An empty universe scores as green.

    If the pages stopped rendering GET forms, or the parser stopped
    recognising them, every assertion below would pass while submitting
    nothing at all. Fail loudly instead.
    """
    per_page = {path: len(_forms_on(client, path)) for path in FORM_PAGES}
    missing = [path for path, n in per_page.items() if n == 0]
    assert not missing, (
        f"no GET form parsed on {missing}. This sweep replays forms parsed out "
        f"of the rendered HTML; if the markup changed, fix the parser rather "
        f"than deleting the test. Found: {per_page}"
    )
    # And each form must actually carry fields, or "submitting it" sends nothing.
    empty = [
        (path, form["action"])
        for path in FORM_PAGES
        for form in _forms_on(client, path)
        if not form["fields"]
    ]
    assert not empty, (
        f"these forms parsed with zero fields, so replaying them proves nothing: {empty}"
    )


@pytest.mark.parametrize("path", FORM_PAGES)
def test_submitting_a_form_unchanged_is_not_an_error(client, path):
    """Press the button without touching anything. That must not 4xx or 5xx."""
    for form in _forms_on(client, path):
        action = form["action"] or path
        response = client.get(action, params=form["fields"])
        assert response.status_code < 400, (
            f"submitting {action} with its own rendered defaults "
            f"{form['fields']!r} returned {response.status_code}. An operator who "
            f"presses the filter button without changing anything gets this."
        )


@pytest.mark.parametrize("path", FORM_PAGES)
def test_a_genuinely_invalid_value_is_still_rejected(client, path):
    """⛔ The control, and it is what keeps the fix honest.

    The fix for `/alerts` was to treat the form's own empty value as
    "unselected". It must NOT have been to stop validating: a typo the operator
    actually typed is still their typo, and a route that accepts anything would
    pass the test above trivially.
    """
    forms = _forms_on(client, path)
    select_fields = [
        (name, value)
        for form in forms
        for name, value in form["fields"]
        if name in {"severity", "acknowledged", "type", "device_type", "pattern_type"}
    ]
    if not select_fields:
        pytest.skip(f"{path} renders no constrained select to probe")

    # ⛔ EVERY constrained select, not the first one. Probing only the first
    # missed the real defect: on `/watchlist` the first is `pattern_type`,
    # which had already been fixed, while `severity` and `device_category`
    # four lines below it were still dropping silently. A guard that checks
    # one member of a set reports on the member, not the set.
    bogus = "definitely-not-a-valid-value"
    silent: list[str] = []
    for name in sorted({n for n, _ in select_fields}):
        response = client.get(path, params={name: bogus})

        # ⚠️ TWO honest answers, not one. `/alerts` rejects with 400.
        # `/watchlist` is deliberately lenient so a stale bookmark keeps
        # working, and instead SAYS it dropped the filter -- its own comment
        # calls silently dropping it "the page lying about what it is
        # showing". Either is fine. What is not fine is 200 with the filter
        # quietly ignored, because the operator then reads an unfiltered list
        # as a filtered one.
        if response.status_code == 400:
            continue
        if response.status_code != 200:
            silent.append(f"{name} -> {response.status_code}")
            continue
        body = response.text.lower()
        if "does not recognise" not in body and "does not recognize" not in body:
            silent.append(name)

    assert not silent, (
        f"{path} accepted a bogus value for {silent} with 200 and said nothing. "
        f"The page is showing unfiltered rows to an operator who believes they "
        f"are filtered."
    )
