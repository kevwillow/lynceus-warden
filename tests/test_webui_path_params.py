"""An int path parameter that becomes a SQLite row id must be BOUNDED.

⛔ **The defect.** FastAPI's `int` path converter is an arbitrary-precision
Python int with no upper bound. SQLite's INTEGER is signed 64-bit. So a path
param went straight into a parameterised query and raised

    OverflowError: Python int too large to convert to SQLite INTEGER

out of the route. Measured before the fix, on **all 15** routes carrying one:

    GET  /alerts/9223372036854775808          500      <- 2**63
    GET  /alerts/9223372036854775807          404      <- 2**63 - 1, correct

⚠️ **Graded rather than inflated.** The response body is Starlette's plain
"Internal Server Error" and leaks nothing; the daemon keeps serving (the very
next request 404s normally); the raise happens on the lookup, before any write.
This is a wrong status code on hostile input — not a security defect and not an
availability one. It is fixed because the class is 15 surfaces wide, not because
any single instance is severe.

⭐ **Found by driving `/watchful/{entry_id}/reset`**, which `AUDIT_REGISTER.md`
recorded as *"never exercised by Round 13's form-field sweep... unexamined, not
cleared."* Driving it cleared it — and turned up something that was never about
that route at all. A sweep aimed at one surface found a property of fifteen.

⛔ **The guard below is DERIVED from the route templates, not from a list of
names.** A transcribed list is how this project re-committed the same
first-match-only fix three PRs later. `{probe_id}` added tomorrow fails here on
its own.
"""

from __future__ import annotations

import ast
import pathlib
import tempfile
import warnings

import pytest
from starlette.testclient import TestClient

from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import SQLITE_MAX_ROWID, create_app
from lynceus.webui.csrf import CSRF_COOKIE_NAME, CSRF_FORM_FIELD

APP_PY = pathlib.Path(__file__).resolve().parents[1] / "src" / "lynceus" / "webui" / "app.py"


def _routed_int_params() -> dict[str, str]:
    """``{"handler:param": annotation}`` for every PATH param of every route.

    Derived: the placeholder names come out of the route template on the
    decorator, so a new route with a new param name is graded automatically.
    """
    tree = ast.parse(APP_PY.read_text())
    out: dict[str, str] = {}
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        templates: list[str] = []
        for dec in node.decorator_list:
            call = dec if isinstance(dec, ast.Call) else None
            if call is None or not isinstance(call.func, ast.Attribute):
                continue
            if call.func.attr not in {"get", "post", "put", "patch", "delete"}:
                continue
            if call.args and isinstance(call.args[0], ast.Constant):
                templates.append(str(call.args[0].value))
        if not templates:
            continue
        # `{mac:path}` -> `mac`; a converter suffix is not part of the name.
        placeholders = {
            seg.split(":")[0]
            for t in templates
            for seg in __import__("re").findall(r"\{([^}]*)\}", t)
        }
        for arg in list(node.args.args) + list(node.args.kwonlyargs):
            if arg.arg not in placeholders or arg.annotation is None:
                continue
            out[f"{node.name}:{arg.arg}"] = ast.unparse(arg.annotation)
    return out


def test_the_scan_finds_the_params_it_is_supposed_to_grade():
    """The instrument's own control. A scan matching nothing would make the
    guard below pass vacuously, which has shipped in this repo before."""
    found = _routed_int_params()
    assert len(found) >= 15, found
    assert found.get("watchful_reset_post:entry_id") == "RowId"
    # A string path param must still be visible to the scan -- otherwise
    # "everything the scan sees is a RowId" would be true by blindness.
    assert any(a == "str" for a in found.values()), found


def test_every_int_path_param_is_bounded():
    """⛔ Fails on the 16th route, which is the entire point of deriving it."""
    unbounded = [
        site for site, ann in _routed_int_params().items() if ann == "int"
    ]
    assert unbounded == [], (
        "these path params are a bare `int`, so a value above SQLITE_MAX_ROWID "
        f"reaches the query layer and 500s: {unbounded}. Annotate them RowId."
    )


# --------------------------------------------------------------------------
# Behaviour. ⛔ An AST assertion proves an annotation exists; it cannot prove
# the boundary is in the right place. This project has shipped that exact gap.
# --------------------------------------------------------------------------
@pytest.fixture()
def client(tmp_path):
    warnings.filterwarnings("ignore")
    (tmp_path / "allowlist.yaml").write_text("entries: []\n")
    db = Database(str(tmp_path / "lynceus.db"))
    app = create_app(
        Config(db_path=str(tmp_path / "lynceus.db"),
               allowlist_path=str(tmp_path / "allowlist.yaml")),
        db,
    )
    try:
        with TestClient(app, raise_server_exceptions=False) as c:
            yield c
    finally:
        db.close()


ROUTES = [
    ("get", "/alerts/{}"),
    ("get", "/watchful/{}"),
    ("get", "/watchlist/{}"),
    ("post", "/alerts/{}/ack"),
    ("post", "/watchful/{}/reset"),
]


@pytest.mark.parametrize(("method", "tmpl"), ROUTES)
def test_a_row_id_above_the_sqlite_ceiling_is_rejected_not_crashed(client, method, tmpl):
    client.get("/watchful")
    tok = client.cookies.get(CSRF_COOKIE_NAME)
    kw = {} if method == "get" else {"data": {CSRF_FORM_FIELD: tok}}
    r = getattr(client, method)(
        tmpl.format(SQLITE_MAX_ROWID + 1), follow_redirects=False, **kw
    )
    assert r.status_code == 422, r.status_code


@pytest.mark.parametrize(("method", "tmpl"), ROUTES)
def test_the_largest_valid_row_id_still_reaches_the_route(client, method, tmpl):
    """⛔ The other half. `le=0` would satisfy the test above perfectly while
    breaking every real id in the database."""
    client.get("/watchful")
    tok = client.cookies.get(CSRF_COOKIE_NAME)
    kw = {} if method == "get" else {"data": {CSRF_FORM_FIELD: tok}}
    r = getattr(client, method)(
        tmpl.format(SQLITE_MAX_ROWID), follow_redirects=False, **kw
    )
    assert r.status_code == 404, r.status_code


def test_an_ordinary_id_is_unaffected(client):
    """The bound must not disturb the normal path -- including the 400s that
    zero and negative ids already produce, which `ge` would have turned into
    422s and silently changed three existing tests' subject."""
    assert client.get("/alerts/1").status_code == 404
    assert client.get("/alerts/0").status_code in (400, 404)
    assert client.get("/alerts/-1").status_code in (400, 404, 422)


def test_the_ceiling_matches_sqlite_rather_than_being_a_round_number(tmp_path):
    """⛔ Derived from SQLite, not chosen. The constant must be exactly the
    largest value SQLite will store, or the bound rejects usable ids or lets
    the crash back in."""
    import sqlite3

    con = sqlite3.connect(":memory:")
    con.execute("CREATE TABLE t(x INTEGER)")
    con.execute("INSERT INTO t VALUES (?)", (SQLITE_MAX_ROWID,))
    with pytest.raises(OverflowError):
        con.execute("INSERT INTO t VALUES (?)", (SQLITE_MAX_ROWID + 1,))
    con.close()
