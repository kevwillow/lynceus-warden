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

import csv
import io
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


# ---------------------------------------------------------------------------
# Bug 2 — CSV formula injection in /alerts.csv and /watchlist.csv
#
# The streaming CSV writers use ``csv.QUOTE_MINIMAL`` and write every
# row cell verbatim. A value whose first character is =, +, - or @ is
# left unquoted by the standard csv module (those characters are not
# quote triggers) and a spreadsheet application — Excel, Google Sheets,
# LibreOffice Calc — interprets the leading character as the start of a
# formula. An operator exporting their alerts or watchlist to CSV and
# opening the file in a spreadsheet therefore executes attacker-supplied
# payloads.
#
# The watchlist description, alerts.message and alerts.note columns all
# carry externally-controllable data: the watchlist description arrives
# via the Argus importer (operator-controlled, but a hostile export file
# could plant any string); alerts.message is produced by the rules
# engine from Kismet-captured radio frames; alerts.note is set by the
# operator through the alert detail form. A leading '=' in any of those
# is enough.
#
# The fix is to prefix any cell whose first character is one of =, +, -
# or @ with a single quote (') — Excel/Sheets render the quote as a
# hidden string prefix and display the rest as text.
# ---------------------------------------------------------------------------


_FORMULA_PREFIXES = ("=", "+", "-", "@")


def _parse_csv(text: str) -> tuple[list[str], list[list[str]]]:
    reader = csv.reader(io.StringIO(text))
    rows = list(reader)
    return rows[0], rows[1:]


def _seed_alert(db: Database, *, mac: str, message: str, ts: int = 1_700_000_000) -> int:
    db.upsert_device(
        mac=mac, device_type="wifi", oui_vendor="V",
        is_randomized=0, now_ts=ts,
    )
    return db.add_alert(
        ts=ts, rule_name="r", mac=mac, message=message, severity="high",
    )


def db_path(client: TestClient) -> Database:
    """Reach back from the TestClient to the Database fixture.

    The DB is closed in the ``client`` fixture's teardown, so this
    accessor is only valid inside a test body.
    """
    # The FastAPI app stores its Database on app.state.db. The TestClient
    # carries the app on ``client.app`` (httpx/Starlette convention); from
    # there we read the same instance the route handlers see.
    return client.app.state.db


@pytest.mark.parametrize("prefix", _FORMULA_PREFIXES)
def test_alerts_csv_neutralises_a_formula_in_the_message_column(
    client, prefix: str,
):
    """A message that begins with =, +, - or @ is a CSV injection (CWE-1236).

    Reproduced against unmodified ``/alerts.csv``: the cell is emitted
    verbatim and a spreadsheet interprets the leading character as the
    start of a formula. After the fix, the leading character is preceded
    by a single quote so the spreadsheet shows the value as text.
    """
    payload = f"{prefix}2+3"
    _seed_alert(db_path(client), mac="aa:bb:cc:dd:ee:01", message=payload)

    r = client.get("/alerts.csv")
    assert r.status_code == 200
    header, data = _parse_csv(r.text)
    msg_col = header.index("message")
    cells = [row[msg_col] for row in data]
    assert any(payload in c for c in cells), (
        f"payload {payload!r} was not echoed in /alerts.csv at all; "
        "this test is now stale"
    )
    # The cell must NOT begin with the dangerous character. A single
    # quote prefix renders safely in Excel/Sheets/LibreOffice; a CSV-
    # standard quoting ('"=2+3"') would also neutralise but the standard
    # csv module only quotes when the cell contains delimiters, which
    # '=' alone does not.
    for cell in cells:
        if cell.startswith("'"):
            continue  # fix applied
        assert not cell.startswith(prefix), (
            f"/alerts.csv leaked a CSV-formula payload {cell!r} "
            f"(prefix {prefix!r}). When opened in Excel, Google Sheets or "
            "LibreOffice Calc, that cell will be interpreted as a formula "
            "and executed — a CSV formula injection (CWE-1236)."
        )


@pytest.mark.parametrize("prefix", _FORMULA_PREFIXES)
def test_watchlist_csv_neutralises_a_formula_in_the_description_column(
    client, prefix: str,
):
    """Same defect on /watchlist.csv, against a column the Argus importer
    populates with externally-controlled strings.
    """
    db_path(client).add_watchlist(
        pattern="AA:BB:CC:DD:EE:FF",
        pattern_type="mac",
        severity="high",
        description=f"{prefix}SUM(1,1)",
    )

    r = client.get("/watchlist.csv")
    assert r.status_code == 200
    header, data = _parse_csv(r.text)
    desc_col = header.index("description")
    cells = [row[desc_col] for row in data]
    assert cells, "watchlist row was not exported"
    for cell in cells:
        if cell.startswith("'"):
            continue  # fix applied
        assert not cell.startswith(prefix), (
            f"/watchlist.csv leaked a CSV-formula payload {cell!r} "
            f"(prefix {prefix!r}) in the description column. The Argus "
            "importer populates this column from externally-supplied "
            "data, so a malicious import file could deliver a formula "
            "that fires when an operator opens the export in a "
            "spreadsheet — a CSV formula injection (CWE-1236)."
        )


def test_alerts_csv_does_not_mutate_normal_message_cells(client):
    """Sanity: the fix must not rewrite plain text values. A normal
    message should still appear verbatim — only the leading-character
    rule applies. Without this guard a fix that wraps every cell in
    quotes (or strips the first char) would 'pass' the other tests
    vacuously.
    """
    _seed_alert(db_path(client), mac="aa:bb:cc:dd:ee:01", message="plain alert")
    r = client.get("/alerts.csv")
    assert r.status_code == 200
    header, data = _parse_csv(r.text)
    msg_col = header.index("message")
    cells = [row[msg_col] for row in data]
    assert "plain alert" in cells, cells


def test_watchlist_csv_does_not_mutate_normal_description_cells(client):
    """Same guard for the watchlist export."""
    db_path(client).add_watchlist(
        pattern="AA:BB:CC:DD:EE:FF",
        pattern_type="mac",
        severity="high",
        description="normal description",
    )
    r = client.get("/watchlist.csv")
    assert r.status_code == 200
    header, data = _parse_csv(r.text)
    desc_col = header.index("description")
    cells = [row[desc_col] for row in data]
    assert "normal description" in cells, cells
