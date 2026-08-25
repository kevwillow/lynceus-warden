"""GET /devices/{mac}/case-file.zip.

⛔ The daemon must never write an export to disk. On a --system install
the units grant ReadWritePaths=/var/lib/lynceus /var/log/lynceus, and
writing outside that is exactly the 500 that #218 fixed for
allowlist_ui.yaml. It also means the download lands on the laptop the
operator is browsing from rather than on a headless Pi they would then
have to copy it off.
"""

from __future__ import annotations

import io
import time
import zipfile

import pytest
from fastapi.testclient import TestClient

from lynceus.casefile import bundle as bundle_mod
from lynceus.config import Config
from lynceus.db import Database
from lynceus.webui.app import create_app
from tests.test_casefile_query import BYSTANDER, NESTED_BYSTANDER, TARGET, _add_evidence, _seed

pytestmark = pytest.mark.webui


@pytest.fixture
def client(tmp_path):
    db, alert_id = _seed(tmp_path)
    _add_evidence(db, alert_id, TARGET)
    app = create_app(Config(db_path=str(tmp_path / "case.db")), db)
    with TestClient(app) as c:
        yield c
    db.close()


def test_the_route_streams_a_zip_and_writes_nothing_to_disk(client, tmp_path):
    before = set(tmp_path.rglob("*"))
    resp = client.get(f"/devices/{TARGET}/case-file.zip")
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"] == "application/zip"
    assert "attachment" in resp.headers["content-disposition"]

    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        names = zf.namelist()
    assert "case-file.html" in names
    assert "manifest.json" in names

    assert set(tmp_path.rglob("*")) == before, "the daemon wrote to disk"


def test_the_filename_offered_is_the_bundle_name(client):
    resp = client.get(f"/devices/{TARGET}/case-file.zip")
    assert "case-aabbccddee01-" in resp.headers["content-disposition"]
    assert resp.headers["content-disposition"].rstrip('"').endswith(".zip")


def test_unknown_device_is_404(client):
    assert client.get("/devices/00:00:00:00:00:00/case-file.zip").status_code == 404


def test_a_malformed_mac_is_rejected_before_any_query(client):
    resp = client.get("/devices/..%2F..%2Fetc%2Fpasswd/case-file.zip")
    assert resp.status_code in (400, 404)


def test_the_bystander_is_absent_from_every_file_in_the_stream(client):
    """The aggregation rule, applied to what actually goes over the wire."""
    resp = client.get(f"/devices/{TARGET}/case-file.zip")
    assert resp.status_code == 200
    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        assert zf.namelist(), "an empty zip would make this vacuous"
        for name in zf.namelist():
            body = zf.read(name)
            for label, needle in (
                ("co-observed", BYSTANDER),
                ("nested in the evidence record", NESTED_BYSTANDER),
            ):
                assert needle.encode() not in body, f"{label} bystander leaked into {name}"
                assert needle.replace(":", "").encode() not in body, f"{label}: {name}"


def test_an_oversized_export_refuses_and_names_the_cli(client, monkeypatch):
    """A refusal that names the way forward beats an OOM on the box that is
    supposed to be doing the watching.

    The threshold is monkeypatched rather than seeded past: the real number
    is a MEASUREMENT recorded in .claude/gates.md, and what needs proving
    here is that the refusal path exists and says where to go.
    """
    monkeypatch.setattr(bundle_mod, "MAX_STREAMED_BYTES", 16)
    resp = client.get(f"/devices/{TARGET}/case-file.zip")
    assert resp.status_code == 413
    assert "lynceus-export-case" in resp.text


def test_the_device_page_offers_the_export_and_the_link_works(client):
    """A button that renders and 404s is the gap worth catching, so this
    follows the href the page actually emits rather than one written here."""
    page = client.get(f"/devices/{TARGET}")
    assert page.status_code == 200
    assert "Export case file (contains location history)" in page.text, (
        "the disclosure belongs in the affordance, per spec section 11.3"
    )
    href = f"/devices/{TARGET}/case-file.zip"
    assert href in page.text
    assert client.get(href).status_code == 200


def test_the_route_and_the_cli_agree_on_what_is_disclosed(client, tmp_path):
    """Both entry points funnel through build_case_file. This is the guard
    that fails when someone later 'fixes' something at one of them."""
    from lynceus.casefile.bundle import write_directory
    from lynceus.casefile.query import build_case_file

    db = Database(str(tmp_path / "case.db"))
    case = build_case_file(db, TARGET, now_ts=int(time.time()))
    out = write_directory(case, tmp_path / "cli-out")
    on_disk = {str(p.relative_to(out)) for p in out.rglob("*") if p.is_file()}
    db.close()

    resp = client.get(f"/devices/{TARGET}/case-file.zip")
    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        streamed = set(zf.namelist())
    assert streamed == on_disk
