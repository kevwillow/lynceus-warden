"""Diagnostic reproduction of the /devices filter -> JSON 400 path
(smoke finding #8).

Smoke v0.7.2: clicking 'filter' on the /devices page returns a JSON
response {"detail": "invalid device type"} with no rendered page and
no back button.

Diagnostic establishes:

  - the form's submit URL + method + every form field's option values
    (as rendered by devices_list.html)
  - the request shape the browser POSTs when the operator clicks
    'filter' with default ('any') selections
  - the route's validation chain in app.py:2464 devices_list and where
    in the function the 400 fires
  - how the 400 surfaces to the operator (raw JSON because no global
    exception handler installed for HTTPException with HTML fallback)
  - a KNOWN-GOOD and KNOWN-BAD input pair so the fix prompt has a
    clear before/after test target
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


def test_diag_dashboard_devices_filter_error(diag, tmp_path):
    config = Config(
        db_path=str(tmp_path / "diag.db"),
        kismet_health_check_on_startup=False,
        evidence_capture_enabled=False,
    )
    db = Database(config.db_path)
    app = create_app(config, db)

    # -----------------------------------------------------------------
    # Section 1 — what the form actually emits in its rendered HTML
    # -----------------------------------------------------------------
    diag.section("form shape: rendered devices_list.html filter row")
    diag.fixture(
        "form source: src/lynceus/webui/templates/devices_list.html:7-33"
    )
    with TestClient(app) as client:
        get_resp = client.get("/devices")
    diag.observed(f"GET /devices status: {get_resp.status_code}")
    form_m = re.search(
        r'<form\s+method="get"\s+action="/devices">(.*?)</form>',
        get_resp.text,
        flags=re.DOTALL,
    )
    if form_m is None:
        diag.observed("filter form: NOT FOUND")
    else:
        # method + action
        diag.observed("form method: GET")
        diag.observed("form action: /devices")
        # Every <select name="..."> and its <option> values.
        for select_m in re.finditer(
            r'<select\s+name="([^"]+)">(.*?)</select>',
            form_m.group(1),
            flags=re.DOTALL,
        ):
            name = select_m.group(1)
            options = re.findall(
                r'<option\s+value="([^"]*)"[^>]*>([^<]*)</option>',
                select_m.group(2),
            )
            diag.observed(f"  select name={name!r} options:")
            for value, label in options:
                diag.observed(f"    value={value!r} label={label!r}")

    # -----------------------------------------------------------------
    # Section 2 — the trip wire: device_type="" (the 'any' option)
    # -----------------------------------------------------------------
    diag.section("trip wire 1: device_type='' (browser-emitted 'any')")
    diag.fixture(
        "route validation: src/lynceus/webui/app.py:2472-2475\n"
        "  if device_type is not None and device_type not in (\n"
        "      'wifi', 'ble', 'bt_classic', 'remote_id'\n"
        "  ):\n"
        "      raise HTTPException(status_code=400, detail='invalid device_type')\n"
        "Note the bug: an empty string is NOT None, AND NOT in the "
        "allowed set, so the guard fires. The form's 'any' <option> "
        "has value=\"\" — selecting 'any' and clicking filter "
        "triggers this branch."
    )
    with TestClient(app) as client:
        bad_resp = client.get("/devices", params={"device_type": ""})
    diag.observed(f"GET /devices?device_type=  status: {bad_resp.status_code}")
    diag.observed(f"  content-type: {bad_resp.headers.get('content-type')!r}")
    diag.observed(f"  body (first 200 chars): {bad_resp.text[:200]!r}")
    # The smoke transcription said 'invalid device type' (with space).
    # Actual emit is 'invalid device_type' (with underscore). Surface
    # the discrepancy so the next prompt doesn't grep for the wrong
    # string.
    diag.observed(
        "  smoke note literal claimed 'invalid device type' (space); "
        "actual emit is 'invalid device_type' (underscore). The "
        "smoke operator likely transcribed loosely."
    )

    # -----------------------------------------------------------------
    # Section 3 — trip wire 2: randomized="" (same pattern)
    # -----------------------------------------------------------------
    diag.section("trip wire 2: randomized='' (same root-cause)")
    diag.fixture(
        "helper: _parse_bool_str at app.py:103-110 — accepts None / "
        "'true' / 'false' and raises HTTPException(400, "
        "f'invalid {name}: expected true or false') for anything else. "
        "Empty string falls through to the raise. Sequencing in the "
        "route: the device_type guard fires FIRST, so an 'any/any' "
        "form submission trips Section-2's 400 before reaching "
        "this one. With device_type=wifi + randomized='' the second "
        "trip fires."
    )
    with TestClient(app) as client:
        rand_bad = client.get(
            "/devices",
            params={"device_type": "wifi", "randomized": ""},
        )
    diag.observed(
        f"GET /devices?device_type=wifi&randomized=  status: "
        f"{rand_bad.status_code}"
    )
    diag.observed(f"  body (first 200): {rand_bad.text[:200]!r}")

    # -----------------------------------------------------------------
    # Section 4 — known-good and known-bad pairs
    # -----------------------------------------------------------------
    diag.section("known-good vs. known-bad request matrix")
    cases = [
        # (description, params, expected outcome)
        ("no query params at all (initial visit)",
         None, "200 — renders the page; no filter applied"),
        ("device_type omitted, randomized omitted",
         {}, "200 — same as above; FastAPI defaults both to None"),
        ("device_type=wifi, randomized omitted",
         {"device_type": "wifi"}, "200 — filters to wifi rows only"),
        ("device_type=wifi, randomized=true",
         {"device_type": "wifi", "randomized": "true"},
         "200 — filters to wifi + randomized rows"),
        ("device_type=EMPTY (the form's 'any' option)",
         {"device_type": ""}, "400 invalid device_type"),
        ("device_type=invalid (unknown literal)",
         {"device_type": "garbage"}, "400 invalid device_type"),
        ("device_type=wifi, randomized=EMPTY (form's 'any' option)",
         {"device_type": "wifi", "randomized": ""},
         "400 invalid randomized"),
        ("device_type=wifi, randomized=garbage",
         {"device_type": "wifi", "randomized": "lol"},
         "400 invalid randomized"),
    ]
    with TestClient(app) as client:
        for desc, params, expected in cases:
            if params is None:
                r = client.get("/devices")
            else:
                r = client.get("/devices", params=params)
            diag.observed(f"  {desc}")
            diag.observed(f"    params={params}")
            diag.observed(f"    status={r.status_code} expected={expected!r}")
            if r.status_code != 200:
                diag.observed(f"    body={r.text[:200]!r}")

    # -----------------------------------------------------------------
    # Section 5 — error-handler chain: why JSON instead of HTML
    # -----------------------------------------------------------------
    diag.section("error handler chain: why the operator sees raw JSON")
    # Grep create_app for an HTTPException handler. None installed ->
    # FastAPI's default kicks in: JSONResponse({"detail": ...}).
    app_source = (
        Path(__file__).resolve().parent.parent
        / "src" / "lynceus" / "webui" / "app.py"
    ).read_text(encoding="utf-8")
    has_exception_handler = bool(
        re.search(r"@app\.exception_handler\b", app_source)
        or re.search(r"add_exception_handler\b", app_source)
    )
    diag.observed(
        f"src/lynceus/webui/app.py defines an HTTPException handler? "
        f"{has_exception_handler}"
    )
    diag.observed(
        "No app-level handler => FastAPI's default fires. Per "
        "fastapi.exception_handlers.http_exception_handler the "
        "default emits JSONResponse({'detail': exc.detail}, "
        "status_code=exc.status_code). The operator sees raw JSON "
        "in the browser, no template, no back button, no /devices "
        "link to recover."
    )
    diag.observed(
        "Compare: src/lynceus/webui/app.py also returns the "
        "not_found.html template explicitly for unknown MACs at "
        "/devices/{mac:path} (app.py:2510-2520, 2522-2532). The "
        "/devices filter validations don't take that path — they "
        "use raise HTTPException, which bypasses any template "
        "rendering. Fix options:\n"
        "  (a) normalize empty-string params to None at route entry, "
        "or treat empty string as 'any' (most surgical)\n"
        "  (b) install a global HTTPException handler that renders "
        "an error template with a /devices back link\n"
        "  (c) both."
    )

    db.close()

    diag.notes(
        "Smoke finding #8 root cause: the form's <option value=\"\"> "
        "for 'any' on both device_type and randomized selects emits "
        "an empty-string query param when submitted, but the route "
        "validates `device_type is not None` rather than "
        "`device_type` (truthiness). The trip wire is a one-line "
        "fix (treat empty string as None / 'any') OR a template-"
        "side fix (render `<option value=\"any\">` and accept "
        "'any' as the no-filter sentinel). Either way, today the "
        "operator's first click on the filter button is guaranteed "
        "to 400 unless they remember to manually select non-default "
        "values for BOTH selects beforehand — a hostile UX. "
        "The error-handler-chain section also flags that even "
        "legitimate 400s (operator hand-edits the URL) lack any "
        "HTML fallback; a global exception handler is a follow-up "
        "regardless of how the trip wire is closed."
    )
