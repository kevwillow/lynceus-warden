"""The bundle: the same artifacts whether written to disk or streamed.

⛔ The directory and the zip must be byte-identical file for file. If
they are not, the CLI and the web UI are two different products that
happen to share a name, and the parity guard in
``test_casefile_parity.py`` is asserting something weaker than it looks.
"""

from __future__ import annotations

import io
import json
import zipfile

import pytest

from lynceus.casefile.bundle import build_artifacts, build_zip_bytes, write_directory
from lynceus.casefile.manifest import build_manifest
from lynceus.casefile.query import build_case_file
from tests.test_casefile_query import BYSTANDER, NOW, TARGET, _add_evidence, _seed


@pytest.fixture
def sample_case_file(tmp_path):
    db, alert_id = _seed(tmp_path)
    _add_evidence(db, alert_id, TARGET)
    return build_case_file(db, TARGET, now_ts=NOW)


def test_directory_and_zip_contain_identical_artifacts(sample_case_file, tmp_path):
    """The two surfaces must ship the same bytes."""
    out = write_directory(sample_case_file, tmp_path / "out")
    with zipfile.ZipFile(io.BytesIO(build_zip_bytes(sample_case_file))) as zf:
        zipped = {n: zf.read(n) for n in zf.namelist()}
    on_disk = {str(p.relative_to(out)): p.read_bytes() for p in out.rglob("*") if p.is_file()}
    assert zipped, "an empty zip would make this guard vacuous"
    assert set(zipped) == set(on_disk)
    for name in zipped:
        assert zipped[name] == on_disk[name], name


def test_manifest_covers_every_file_except_itself(sample_case_file):
    artifacts = build_artifacts(sample_case_file)
    manifest = json.loads(artifacts["manifest.json"])
    assert set(manifest["files"]) == set(artifacts) - {"manifest.json"}


def test_the_manifest_digests_match_the_bytes_actually_shipped(sample_case_file):
    """A manifest computed over something other than what was written
    would be worse than none: it would certify a bundle it never saw."""
    artifacts = build_artifacts(sample_case_file)
    payload = {k: v for k, v in artifacts.items() if k != "manifest.json"}
    recomputed = build_manifest(payload)
    shipped = json.loads(artifacts["manifest.json"])
    assert shipped["manifest_sha256"] == recomputed["manifest_sha256"]
    assert shipped["files"] == recomputed["files"]


def test_the_output_name_comes_from_the_NORMALISED_mac(sample_case_file, tmp_path):
    """A MAC-shaped path traversal must not reach the filesystem."""
    out = write_directory(sample_case_file, tmp_path / "out")
    assert ".." not in out.name and "/" not in out.name
    assert out.parent == (tmp_path / "out")


def test_readme_states_what_the_bundle_holds(sample_case_file):
    readme = build_artifacts(sample_case_file)["README.txt"].decode()
    assert "location" in readme.lower()
    assert "does not prove" in readme.lower()


def test_the_bystander_is_absent_from_every_artifact(sample_case_file):
    """Applied to the finished bytes rather than the dataclass: a leak
    into HTML, CSV, evidence JSON or the manifest shows up here."""
    assert sample_case_file.co_observers_aggregate >= 1, (
        "no bystander was co-observed, so this guard would pass on an empty "
        "fixture rather than on the aggregation rule"
    )
    for name, payload in build_artifacts(sample_case_file).items():
        assert BYSTANDER.encode() not in payload, f"bystander leaked into {name}"
        assert BYSTANDER.replace(":", "").encode() not in payload, name


def test_the_data_files_carry_the_rows_the_document_summarises(sample_case_file):
    """The CSVs exist so a recipient can check the document rather than
    read it. An empty one that still ships is the failure worth catching."""
    artifacts = build_artifacts(sample_case_file)
    sightings = artifacts["data/sightings.csv"].decode()
    assert sightings.count("\n") > 1, "header only, no rows"
    assert TARGET in sightings
    pairs = artifacts["data/co-observation-pairs.csv"].decode()
    assert pairs.count("\n") > 1, "the drill-down rows are the checkable part"


def test_an_empty_record_still_produces_a_complete_bundle(tmp_path):
    """No sightings must not mean no limits and no manifest."""
    from lynceus.db import Database

    db = Database(str(tmp_path / "empty.db"))
    db.upsert_device(
        mac=TARGET, device_type="wifi", oui_vendor="Acme", is_randomized=0, now_ts=NOW - 10
    )
    artifacts = build_artifacts(build_case_file(db, TARGET, now_ts=NOW))
    assert "case-file.html" in artifacts
    assert "manifest.json" in artifacts
    assert "README.txt" in artifacts
    assert b"keyed on MAC" in artifacts["case-file.html"]
