"""The CLI and the UI must disclose exactly the same things.

⛔ This is the entire reason ``query.py`` is a choke point, and it is the
guard that fails when somebody later "fixes" something at one entry
point. It is asserted byte for byte rather than by filename: two bundles
that merely agree about which files exist could still differ about what
is inside them, which is the disclosure question.

Byte parity needs both paths to see the same instant AND the same
config, so the clock is frozen and one Config object is handed to both.
Those are inputs, not rules. A guard that had to tolerate a difference
in them would have to tolerate every other difference too.

⚠️ The config really is an input the two paths can differ on: the daemon
always has one, and the CLI may not find a config file at all. That is
why the retention wording has three states rather than two, and why
``test_the_three_retention_states_say_three_different_things`` exists.
Collapsing "the setting was not available" into "retention is off" would
make the document assert that nothing was pruned on the strength of an
argument nobody made.
"""

from __future__ import annotations

import io
import time
import zipfile

import pytest
from fastapi.testclient import TestClient

from lynceus.casefile.bundle import build_artifacts, write_directory
from lynceus.casefile.query import build_case_file
from lynceus.config import Config
from lynceus.webui.app import create_app
from tests.test_casefile_query import BYSTANDER, NESTED_BYSTANDER, TARGET, _add_evidence, _seed

pytestmark = pytest.mark.webui

FROZEN = 1_700_100_000


@pytest.fixture
def rig(tmp_path, monkeypatch):
    monkeypatch.setattr(time, "time", lambda: float(FROZEN))
    db, alert_id = _seed(tmp_path)
    _add_evidence(db, alert_id, TARGET)
    config = Config(db_path=str(tmp_path / "case.db"))
    app = create_app(config, db)
    with TestClient(app) as client:
        yield db, client, tmp_path, config
    db.close()


def _streamed(client):
    resp = client.get(f"/devices/{TARGET}/case-file.zip")
    assert resp.status_code == 200, resp.text
    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        return {name: zf.read(name) for name in zf.namelist()}


def test_the_cli_and_the_ui_disclose_exactly_the_same_things(rig):
    db, client, tmp_path, config = rig

    case = build_case_file(db, TARGET, now_ts=int(time.time()), config=config)
    out = write_directory(case, tmp_path / "cli-out")
    on_disk = {str(p.relative_to(out)): p.read_bytes() for p in out.rglob("*") if p.is_file()}

    streamed = _streamed(client)

    assert on_disk, "an empty CLI bundle would make this guard vacuous"
    assert set(streamed) == set(on_disk)
    for name in sorted(on_disk):
        assert streamed[name] == on_disk[name], f"the two paths disagree about {name}"


def test_the_bystander_is_absent_from_EVERY_file_on_both_paths(rig):
    """The planted-bystander guard applied to the finished bundles rather
    than the dataclass: a leak into HTML, CSV, evidence JSON or the
    manifest shows up here on whichever path it happens."""
    db, client, tmp_path, config = rig

    case = build_case_file(db, TARGET, now_ts=int(time.time()), config=config)
    assert case.co_observers_aggregate >= 1, (
        "no bystander was co-observed, so this guard would be checking nothing"
    )

    needles = tuple(
        form
        for mac in (BYSTANDER, NESTED_BYSTANDER)
        for form in (mac.encode(), mac.replace(":", "").encode())
    )
    for label, artifacts in (
        ("cli", build_artifacts(case)),
        ("ui", _streamed(client)),
    ):
        assert artifacts, f"{label} produced no files"
        for name, payload in artifacts.items():
            for needle in needles:
                assert needle not in payload, f"bystander leaked into {label} {name}"


def test_both_paths_report_the_same_manifest_digest(rig):
    """The digest is what a recipient checks. If the two surfaces produce
    different ones for the same record, neither is worth quoting."""
    import json

    db, client, tmp_path, config = rig
    case = build_case_file(db, TARGET, now_ts=int(time.time()), config=config)
    cli_digest = json.loads(build_artifacts(case)["manifest.json"])["manifest_sha256"]
    ui_digest = json.loads(_streamed(client)["manifest.json"])["manifest_sha256"]
    assert cli_digest == ui_digest


def test_the_three_retention_states_say_three_different_things(tmp_path):
    """Retention configured, retention off, and "we were not told" are
    three different claims about the same database.

    ⛔ Collapsing the third into the second is the tempting simplification
    and it is a lie: it would have the document assert that nothing was
    pruned when nobody established that. This is also the difference the
    parity guard above has to hold constant, so it is pinned here rather
    than left as an implementation detail.
    """
    db, alert_id = _seed(tmp_path)
    _add_evidence(db, alert_id, TARGET)

    def wording(config):
        case = build_case_file(db, TARGET, now_ts=FROZEN, config=config)
        return next(limit["body"] for limit in case.limits if "Retention" in limit["heading"])

    unknown = wording(None)
    off = wording(Config(db_path=str(tmp_path / "case.db")))
    on = wording(Config(db_path=str(tmp_path / "case.db"), sightings_retention_days=30))
    db.close()

    assert len({unknown, off, on}) == 3, "two of the three states are indistinguishable"
    assert "not available" in unknown
    assert "not deleted on a schedule" in off
    assert "30 days" in on
