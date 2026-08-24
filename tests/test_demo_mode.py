"""The demo fixture must be valid, curated, and present in the WHEEL."""
import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from lynceus.demo import DEMO_FIXTURE_PATH
from lynceus.kismet import FakeKismetClient

REPO = Path(__file__).resolve().parents[1]


def test_the_fixture_exists_and_is_a_list():
    data = json.loads(DEMO_FIXTURE_PATH.read_text(encoding="utf-8"))
    assert isinstance(data, list)
    assert len(data) >= 6, "too thin to read as a story"


def test_every_record_parses_through_the_real_parser():
    """A fixture that silently fails to parse gives an empty demo dashboard."""
    client = FakeKismetClient(str(DEMO_FIXTURE_PATH), shift_to_now=True)
    observations = client.get_devices_since(0)
    raw = json.loads(DEMO_FIXTURE_PATH.read_text(encoding="utf-8"))
    assert len(observations) == len(raw), "some demo records were dropped by the parser"


def test_it_spans_at_least_three_locations():
    raw = json.loads(DEMO_FIXTURE_PATH.read_text(encoding="utf-8"))
    sources = set()
    for rec in raw:
        for seen in rec.get("kismet.device.base.seenby", []):
            src = seen.get("kismet.common.seenby.source", {})
            name = src.get("kismet.datasource.name")
            if name:
                sources.add(name)
    assert len(sources) >= 3, f"co-observation needs several places, got {sources}"


def test_one_device_appears_at_three_locations_and_is_not_watchlisted():
    """The identity-agnostic finding is the demo's whole point."""
    raw = json.loads(DEMO_FIXTURE_PATH.read_text(encoding="utf-8"))
    by_mac = {}
    for rec in raw:
        mac = rec["kismet.device.base.macaddr"]
        for seen in rec.get("kismet.device.base.seenby", []):
            src = seen.get("kismet.common.seenby.source", {})
            name = src.get("kismet.datasource.name")
            if name:
                by_mac.setdefault(mac, set()).add(name)
    assert any(len(v) >= 3 for v in by_mac.values()), (
        "no device is seen at 3+ places, so the demo cannot show the one claim "
        "a proximity keychain structurally cannot make"
    )


@pytest.mark.slow
def test_the_fixture_is_actually_in_the_built_wheel(tmp_path):
    """⛔ pytest reads the source tree. Only the wheel proves what ships."""
    # ⛔ Measured 2026-08-24: with a stale build/lib present, `python -m build`
    # repackages the OLD tree and this guard passes with the fixture deleted
    # from src/. A packaging guard that cannot fail is worse than no guard, so
    # the cleanup belongs HERE and not in the caller's instructions: a guard
    # that depends on somebody remembering to clean is not a guard.
    for stale in (REPO / "build", REPO / "src" / "lynceus.egg-info"):
        shutil.rmtree(stale, ignore_errors=True)
    subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(tmp_path), str(REPO)],
        check=True,
        capture_output=True,
    )
    wheels = list(tmp_path.glob("*.whl"))
    assert wheels, "no wheel was built"
    with zipfile.ZipFile(wheels[0]) as zf:
        names = zf.namelist()
    assert "lynceus/demo/demo_kismet.json" in names, (
        "the demo fixture is missing from the wheel: every test passes and the "
        "installed product has no demo"
    )
