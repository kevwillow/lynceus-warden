"""Regression tests for two proven webui defects found in m3 round 1.

Both bugs surface on operator-visible surfaces, both reproduce against an
unmodified ``src/lynceus/webui/app.py``, and both have a concrete "what
the operator saw" reading. Each test pair is structured as:

    test_X_bug_proves_X_on_unmodified_code    -- pre-fix failure
    test_X_bug_fix_works_after_change        -- post-fix pass

A test file that is watched fail against the broken code, then pass
against the fix, is the contract the packet requires; ``git log
--grep=m3-webui`` finds the paired commits.
"""

from __future__ import annotations

import warnings
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import create_app

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def app_dir(tmp_path: Path):
    """Per-test sandbox: a config dir + an empty allowlist."""
    (tmp_path / "allowlist.yaml").write_text("entries: []\n")
    return tmp_path


@pytest.fixture()
def client(app_dir: Path):
    """A TestClient wired to a fresh empty DB and the sandbox allowlist."""
    warnings.filterwarnings("ignore")
    config = Config(
        db_path=str(app_dir / "lynceus.db"),
        allowlist_path=str(app_dir / "allowlist.yaml"),
    )
    db = Database(config.db_path)
    app = create_app(config, db)
    try:
        with TestClient(app, raise_server_exceptions=False) as c:
            yield c
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Bug 1 — empty filter values posted by ordinary form submission 400
#
# The /alerts and /alerts.csv handlers reject empty-string severity and
# acknowledged values with HTTP 400, but their own templates render the
# severity dropdown with <option value="" selected>any</option> as the
# default. An operator who loads /alerts and clicks "filter" without
# changing the dropdown posts severity='' (empty string) and lands on a
# styled 400 page. /devices, /watchlist and the other list pages all
# accept empty filter values as "unselected" and render the unfiltered
# list — so /alerts is the lone outlier on the operator's primary list.
# ---------------------------------------------------------------------------


def test_alerts_does_not_400_on_an_empty_severity_filter(client):
    """Form's 'any' severity option posts severity=''. /alerts must accept it."""
    r = client.get("/alerts", params={"severity": ""})
    assert r.status_code == 200, (
        f"GET /alerts?severity= returned {r.status_code}, expected 200. "
        "An operator clicking 'filter' with the default 'any' severity "
        "dropdown posts severity= (empty string) and lands on a 400 error "
        "page instead of the unfiltered alerts list."
    )


def test_alerts_does_not_400_on_an_empty_acknowledged_filter(client):
    """The 'acknowledged' dropdown's 'any' option posts acknowledged=''."""
    r = client.get("/alerts", params={"acknowledged": ""})
    assert r.status_code == 200, (
        f"GET /alerts?acknowledged= returned {r.status_code}, expected 200. "
        "The 'any' option on the acknowledged dropdown posts the empty "
        "string and is rejected with 400; /devices, /watchlist and other "
        "list pages treat empty as 'unselected'."
    )


def test_alerts_csv_does_not_400_on_an_empty_severity_filter(client):
    """The CSV export mirrors the same filter; the same defect must not repeat."""
    r = client.get("/alerts.csv", params={"severity": ""})
    assert r.status_code == 200, (
        f"GET /alerts.csv?severity= returned {r.status_code}, expected 200."
    )


def test_alerts_still_rejects_a_bogus_severity(client):
    """Sanity: the bug fix must NOT silently rewrite an unknown value.

    Rejecting only empty strings (the form's 'any') keeps 'bogus' rejected
    with 400 — a typo by the operator is still their typo.
    """
    r = client.get("/alerts", params={"severity": "bogus"})
    assert r.status_code == 400, (
        f"GET /alerts?severity=bogus returned {r.status_code}, expected 400. "
        "An invalid value must still 400; only empty strings (the form's "
        "default 'any' option) should be accepted as 'unselected'."
    )


def test_alerts_form_default_post_renders_unfiltered(client):
    """The exact form submission an operator produces by clicking 'filter'
    without changing anything must return 200 with the unfiltered list.

    This is the strongest end-to-end reproduction: a real browser sends
    every dropdown's selected value, including the empty 'any' values.
    """
    # Mirror the alerts_list.html form's defaults so this stays in step
    # with the template if the dropdowns change. Per the template at the
    # time of writing:
    #   severity: option value=""  any
    #   rule_type: option value=""  any
    #   acknowledged: option value=""  any
    #   has_note: option value="all"  any
    #   has_action: option value="all"  any
    #   window: option value=""  any time
    #   page_size: option value="50" (the default)
    form_defaults = {
        "severity": "",
        "rule_type": "",
        "acknowledged": "",
        "has_note": "all",
        "has_action": "all",
        "window": "",
        "page_size": "50",
    }
    r = client.get("/alerts", params=form_defaults)
    assert r.status_code == 200, (
        f"GET /alerts with form defaults returned {r.status_code}, expected "
        "200. The 'any' option on the severity and acknowledged dropdowns "
        "is selected by default; clicking 'filter' without changing them "
        f"posts {form_defaults} and is currently rejected."
    )
