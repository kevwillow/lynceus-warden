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


def test_demo_needs_no_existing_config(tmp_path, monkeypatch):
    """The whole point: a stranger with no lynceus.yaml can still see it run."""
    from lynceus.cli import quickstart

    monkeypatch.setattr(quickstart.paths, "resolve_existing_config", lambda: None)
    cfg_path = quickstart.build_demo_config(tmp_path)
    import yaml

    cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    assert cfg["kismet_fixture_path"] == str(DEMO_FIXTURE_PATH)
    assert cfg["kismet_fixture_shift_to_now"] is True
    assert str(tmp_path) in cfg["db_path"], "demo must not touch a real database"


def test_demo_config_validates(tmp_path):
    """A demo that writes an invalid config fails in front of the person we are
    trying to impress."""
    from lynceus.cli import quickstart
    from lynceus.config import load_config

    cfg = load_config(str(quickstart.build_demo_config(tmp_path)))
    assert cfg.kismet_fixture_shift_to_now is True


def test_the_demo_filter_keeps_the_rows_the_cast_can_actually_match(tmp_path):
    """⛔ The guard the demo's only alert never had.

    `_filter_watchlist_csv_for_demo` reduces the 41,518-row bundled corpus to
    the handful the nine demo devices can match. Two defects have already lived
    in that reduction, and NEITHER produced a failing test: the first tested the
    MAPPED pattern_type (`"ssid"`) against the RAW `identifier_type` column and
    so dropped every `ssid_exact` row, and before that the whole corpus was
    imported and the demo took 4m27s to start.

    The failure mode is not a red suite. It is a demo that opens with zero
    alerts in front of the person being evaluated, which is verbatim the
    "tests pass, dashboard shows nothing real" gap `_seed_demo_watchlist`'s
    docstring says the demo exists to close.

    ⚠️ Keyed on the row TYPES surviving the filter rather than on a literal
    identifier, so it also fails if the bundled corpus is recut and the stems
    the cast depends on move. The corpus carries
    `local_recut=2026-08-22-S1-literal-stems`; it has been recut before and will
    be again.
    """
    import csv as _csv

    from lynceus.cli.quickstart import _filter_watchlist_csv_for_demo
    from lynceus.demo import DEMO_FIXTURE_PATH

    src = Path(__file__).resolve().parents[1] / "src/lynceus/data/default_watchlist.csv"
    if not src.is_file():
        pytest.skip("bundled watchlist not present in this build")

    out = tmp_path / "demo_watchlist.csv"
    _filter_watchlist_csv_for_demo(src, DEMO_FIXTURE_PATH, out)

    text = out.read_text(encoding="utf-8").splitlines()
    lines = [ln for ln in text if not ln.startswith("# meta:")]
    rows = list(_csv.DictReader(lines))
    kinds = {r["identifier_type"] for r in rows}

    assert rows, (
        "the filter kept NO rows: the demo would import an empty watchlist and "
        "open with no alerts at all"
    )
    # ⛔ Each type asserted SEPARATELY, never as an `or`. The first version of
    # this test said `"ssid_exact" in kinds or "ssid_pattern" in kinds`, and when
    # the ssid_exact defect was planted back in it PASSED: the surviving
    # ssid_pattern row satisfied the or. A guard for a specific defect has to
    # name that defect. ⇒ [[plant-what-would-fool-the-weaker-assertion]]
    assert "ssid_exact" in kinds, (
        "no ssid_exact row survived the filter. That is the defect fixed in "
        "32bf09a: testing the MAPPED pattern_type against the RAW "
        f"identifier_type column drops every ssid_exact row. kinds={kinds}"
    )
    assert "ssid_pattern" in kinds, (
        "no ssid_pattern row survived, so the Flock SSID detection the demo "
        f"actually fires cannot happen. kinds={kinds}"
    )
    assert "oui" in kinds, (
        "no OUI row survived the filter, so watchlist_oui is enabled but inert "
        f"and the demo can only ever show a substring SSID hit. kinds={kinds}"
    )
