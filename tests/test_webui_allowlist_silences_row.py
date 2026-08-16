"""The fifth silencing mechanism, narrowed from "unreportable" to "mac rows".

``liveness.py``'s limits table said an allowlist match cannot be reported per
watchlist row: it suppresses by DEVICE, and one row can match many devices, so
no single verdict is honest.

⭐ **That is right for `oui`, `mac_range`, `ssid`, `ssid_pattern`, `ble_*` and
`drone_id_prefix`, and wrong for `mac`** — a `mac` row names exactly one device,
so the question has exactly one answer. It is also the pattern_type this UI
creates and one of the three the shipped ruleset actually delegates to, so the
blanket limit hid the answer precisely where it existed.

Measured END TO END through ``poller.process_observation`` before any of this
was built — one `mac` watchlist row, one matching device:

    hard `mac` entry for this MAC        0 alerts, 0 sent
    (control) the same entry EXPIRED     2 alerts, 2 sent
    (control) entry for another MAC      2 alerts, 2 sent
    (control) SOFT ble_local_name entry  2 alerts, 2 sent   <- #82's policy
    (control) no entries at all          2 alerts, 2 sent

⛔ The SOFT line is the one that decides the shape of the marker. Since #82 a
device-chosen value cannot silence an explicit watchlist hit, so marking a row
on a SOFT match would report a silence that does not happen.
"""

from __future__ import annotations

import csv as _csv
import io
import re
import textwrap
import time
from pathlib import Path

import pytest
from starlette.testclient import TestClient

from lynceus.allowlist import (
    HARD_ALLOWLIST_PATTERN_TYPES,
    load_allowlist,
)
from lynceus.config import Config
from lynceus.db import Database
from lynceus.kismet import DeviceObservation
from lynceus.poller import process_observation
from lynceus.rules import load_ruleset
from lynceus.webui.app import _match_mac_in_entries, _merged_allowlist_entries, create_app
from lynceus.webui.liveness import allowlist_answerable_for

REPO_ROOT = Path(__file__).resolve().parents[1]
SHIPPED_RULES = REPO_ROOT / "config" / "rules.yaml"

MAC = "3c:5a:b4:dd:ee:01"
OTHER_MAC = "3c:5a:b4:dd:ee:02"
NAME = "AcmeBuds"

HARD_ENTRY = f"""
    entries:
      - pattern: "{MAC}"
        pattern_type: mac
        note: allowlisted by the operator
    """
SOFT_ENTRY = f"""
    entries:
      - pattern: "{NAME}"
        pattern_type: ble_local_name
        note: a value the device chooses for itself
    """
EXPIRED_ENTRY = f"""
    entries:
      - pattern: "{MAC}"
        pattern_type: mac
        note: lapsed
        expires_at: 1000
    """
NO_ENTRIES = "entries: []\n"

BADGE = "allowlisted"
DETAIL_NOTE = "This entry's device is on the allowlist"


def test_this_suite_is_testing_the_tree_it_lives_in():
    import lynceus.webui.liveness as under_test

    assert Path(under_test.__file__).resolve().is_relative_to(REPO_ROOT)


def _prose(html: str) -> str:
    s = re.sub(r"<!--.*?-->", " ", html, flags=re.S)
    return " ".join(re.sub(r"<[^>]+>", " ", s).split())


def _build(tmp_path, allowlist_body: str, *, pattern=MAC, pattern_type="mac"):
    al = tmp_path / "allow.yaml"
    al.write_text(textwrap.dedent(allowlist_body), encoding="utf-8")
    cfg = Config(
        db_path=str(tmp_path / "s.db"),
        rules_path=str(SHIPPED_RULES),
        allowlist_path=str(al),
        evidence_capture_enabled=False,
        kismet_health_check_on_startup=False,
    )
    db = Database(cfg.db_path)
    db.ensure_location("default", "Default")
    wid, _ = db.add_watchlist(pattern=pattern, pattern_type=pattern_type, severity="high")
    return cfg, db, create_app(cfg, db), wid


class _Recorder:
    def __init__(self):
        self.sent = []

    def send(self, *a, **k):
        self.sent.append((a, k))
        return True


def _alerts_raised(cfg, db) -> int:
    """How many alerts the POLLER actually writes for a matching device.

    ⭐ The independent side. It runs ``process_observation`` — the same gate
    chain a live deployment runs — rather than re-deriving the allowlist
    predicate the marker uses, so a marker that disagrees with the poller shows
    up as a disagreement instead of as two readings of one function.
    """
    now = int(time.time())
    obs = DeviceObservation(
        mac=MAC,
        device_type="wifi",
        first_seen=now,
        last_seen=now,
        rssi=-40,
        ssid=None,
        oui_vendor=None,
        is_randomized=False,
        ble_local_name=NAME,
    )
    process_observation(
        obs,
        db,
        cfg,
        now,
        effective_location_id="default",
        effective_location_label="Default",
        ensured_locations=set(),
        processed_counter=[0],
        admitted_counter=[0],
        ruleset=load_ruleset(cfg.rules_path),
        allowlist=load_allowlist(cfg.allowlist_path),
        notifier=_Recorder(),
        clock_trusted=True,
    )
    return db._conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]


@pytest.mark.parametrize(
    ("case", "body", "expect_marked"),
    [
        ("hard mac entry", HARD_ENTRY, True),
        ("expired hard entry", EXPIRED_ENTRY, False),
        ("soft ble_local_name entry", SOFT_ENTRY, False),
        ("no entries", NO_ENTRIES, False),
    ],
)
def test_the_marker_agrees_with_whether_the_poller_actually_alerts(
    case, body, expect_marked, tmp_path
):
    """⭐ The core guard: the badge is graded against the POLLER, not against
    the helper that draws it. Marked ⇔ the device raises no alert.
    """
    cfg, db, app, wid = _build(tmp_path, body)
    try:
        with TestClient(app) as client:
            listed = client.get("/watchlist").text
            detail = _prose(client.get(f"/watchlist/{wid}").text)
        raised = _alerts_raised(cfg, db)
    finally:
        db.close()

    rows = [r for r in re.findall(r"<tr>(.*?)</tr>", listed, flags=re.S) if MAC in r]
    assert len(rows) == 1
    marked = BADGE in rows[0]

    assert marked is expect_marked, f"[{case}] badge={marked}, expected {expect_marked}"
    assert (raised == 0) is expect_marked, (
        f"[{case}] the poller raised {raised} alerts but the page "
        f"{'marks' if marked else 'does not mark'} the row allowlisted — the "
        f"marker and the gate chain disagree"
    )
    assert (DETAIL_NOTE in detail) is expect_marked


def test_a_soft_allowlist_entry_does_not_mark_the_row(tmp_path):
    """⛔ Called out on its own because it is the case that decides the shape.

    Since #82 a device-chosen value cannot silence an explicit watchlist hit.
    A marker keyed on "any allowlist entry matches this device" would report a
    silence that does not happen, which is the same class of lie as the one
    this whole track is closing.
    """
    cfg, db, app, wid = _build(tmp_path, SOFT_ENTRY)
    try:
        assert _alerts_raised(cfg, db) > 0, "fixture: the soft entry suppressed after all"
        with TestClient(app) as client:
            listed = client.get("/watchlist").text
    finally:
        db.close()

    assert BADGE not in listed


def test_the_marker_covers_exactly_the_hard_pattern_types(tmp_path):
    """The helper that draws the badge must recognise every type that can
    actually silence a watchlist hit.

    ⚠️ Iterates ``HARD_ALLOWLIST_PATTERN_TYPES`` rather than listing the three,
    so adding a fourth hard type FAILS here instead of silently under-marking.
    """
    now = int(time.time())
    # 🪤 The /36 prefix is 9 hex digits, and the model REFUSES a prefix whose
    # shape disagrees with the declared length. A wrong sample here made the
    # loader log an error, hand back an empty allowlist, and the assertion below
    # then read as "the helper cannot see mac_range entries" — a broken fixture
    # imitating the finding.
    samples = {
        "mac": MAC,
        "oui": MAC[:8],
        "mac_range": f"{MAC[:13]}/36",
    }
    assert set(samples) == set(HARD_ALLOWLIST_PATTERN_TYPES), (
        f"a hard allowlist pattern_type has been added or removed "
        f"({HARD_ALLOWLIST_PATTERN_TYPES}); _match_mac_in_entries and this "
        f"sample set both need it, or `mac` rows silently stop being marked"
    )
    for pattern_type, pattern in samples.items():
        body = textwrap.dedent(
            f"""
            entries:
              - pattern: "{pattern}"
                pattern_type: {pattern_type}
                note: hard
            """
        )
        path = tmp_path / f"{pattern_type}.yaml"
        path.write_text(body, encoding="utf-8")
        cfg = Config(
            db_path=str(tmp_path / f"{pattern_type}.db"),
            rules_path=str(SHIPPED_RULES),
            allowlist_path=str(path),
        )
        entries = _merged_allowlist_entries(cfg)
        assert _match_mac_in_entries(entries, MAC, now) is not None, (
            f"a hard {pattern_type} allowlist entry covering {MAC} is not "
            f"recognised, so a watchlist row it silences renders unmarked"
        )


@pytest.mark.parametrize(
    "pattern_type", ["oui", "mac_range", "ssid", "ssid_pattern", "ble_local_name"]
)
def test_a_row_that_can_match_many_devices_is_never_marked(pattern_type):
    """⛔ The limit that REMAINS, pinned so a later change cannot quietly widen
    the marker into a claim it cannot support. One `oui` row covers 16 million
    addresses; some of those devices may be allowlisted and some not, so any
    single verdict on the row is false for part of the set.
    """
    assert not allowlist_answerable_for(pattern_type)
    assert allowlist_answerable_for("mac")


def test_the_csv_says_n_a_rather_than_no_for_a_many_device_row(tmp_path):
    """`n/a` is not a hedge. `no` on an `oui` row would assert that none of the
    devices it covers is allowlisted — a claim nothing checked.
    """
    cfg, db, app, wid = _build(tmp_path, HARD_ENTRY)
    try:
        db.add_watchlist(pattern="3c:5a:b4", pattern_type="oui", severity="high")
        with TestClient(app) as client:
            rows = list(_csv.reader(io.StringIO(client.get("/watchlist.csv").text)))
    finally:
        db.close()

    header, data = rows[0], rows[1:]
    pt, al = header.index("pattern_type"), header.index("allowlist_suppressed")
    by_type = {r[pt]: r[al] for r in data}
    assert by_type["mac"] == "yes"
    assert by_type["oui"] == "n/a", (
        "an oui row reports a per-row allowlist verdict it cannot have"
    )


def test_an_unallowlisted_mac_row_says_no_not_n_a(tmp_path):
    """The other half: `mac` rows get a real answer in both directions."""
    cfg, db, app, wid = _build(tmp_path, NO_ENTRIES)
    try:
        with TestClient(app) as client:
            rows = list(_csv.reader(io.StringIO(client.get("/watchlist.csv").text)))
    finally:
        db.close()

    header, data = rows[0], rows[1:]
    al = header.index("allowlist_suppressed")
    assert [r[al] for r in data] == ["no"]


def test_the_detail_page_names_the_entry_to_remove(tmp_path):
    """A marker that does not say WHICH line to delete leaves the operator
    grepping two files. The page names the pattern, its type, and whether it
    expires.
    """
    cfg, db, app, wid = _build(tmp_path, HARD_ENTRY)
    try:
        with TestClient(app) as client:
            detail = _prose(client.get(f"/watchlist/{wid}").text)
    finally:
        db.close()

    # 🪤 `MAC in detail` is NOT enough, and a planted defect proved it: the
    # page already prints the row's own pattern at the top, so blanking the
    # entry's pattern to "redacted" left the assertion matching a SIBLING
    # element and the guard asleep. Assert the contiguous phrase that only this
    # block renders, and assert it once.
    # ⚠️ Stops at the MAC. Stripping tags turns `<code>mac</code>` into
    # ` mac `, so reaching past it would pin the stripper's spacing rather than
    # the page's meaning — brittle in the direction that wastes time.
    named = f"The allowlist entry is {MAC}"
    assert detail.count(named) == 1, (
        f"expected exactly one {named!r} on the page; the block that names the "
        f"entry to remove is the only thing that should render it"
    )
    assert "permanent" in detail
    assert "allowlist page" in detail


def test_a_watchlist_with_no_mac_rows_does_not_read_the_allowlist(tmp_path, monkeypatch):
    """⚠️ The cost gate, asserted rather than asserted-in-a-comment. This page
    is rendered constantly; loading the allowlist YAML for a watchlist that
    cannot use the answer is pure waste.
    """
    cfg, db, app, wid = _build(tmp_path, HARD_ENTRY, pattern="3c:5a:b4", pattern_type="oui")
    calls = []
    import lynceus.webui.app as app_mod

    real = app_mod._merged_allowlist_entries
    monkeypatch.setattr(
        app_mod,
        "_merged_allowlist_entries",
        lambda config: (calls.append(1), real(config))[1],
    )
    try:
        with TestClient(app) as client:
            client.get("/watchlist")
    finally:
        db.close()

    assert calls == [], "the allowlist was loaded for a page with no `mac` rows"
