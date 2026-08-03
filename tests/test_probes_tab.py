"""Local validation for the aggregated Probes tab (0.9.0 arc).

The /probes page is the aggregated sibling of the per-device "Probes"
column: it rolls devices.probe_ssids up two ways. "device" grouping
(default) lists which networks each device probed; "ssid" grouping
inverts to which devices probed each network (unnested with json_each).

This is the most PII-sensitive surface in the app, so the hard rule is
collapsed-by-default -- but what is collapsed differs per grouping, and
this docstring used to get its own file's rule backwards.

⛔ It is the device-to-network PAIRING that is always behind the reveal,
not the SSID string itself:

- device grouping: the SSID names are collapsed. The summary shows only
  a count ("reveal 3 network(s)"). Asserted by
  ``test_route_device_grouping_collapsed_by_default``, which requires
  "HomeNet" to be inside <details> and NOT outside it.
- ssid grouping: the network NAME is a visible row header, and the
  DEVICE IDENTITIES are collapsed, because there the identifying
  concentration is which devices wanted that network. Asserted by
  ``test_route_ssid_grouping_name_visible_devices_collapsed``, which
  requires "HomeNet" NOT to be inside <details>.

The previous wording claimed "in BOTH groupings the SSID strings live
inside a closed <details>", which the second of those tests directly
contradicts, and README.md carried the same overstatement. An auditor
read the README version and reported the ssid grouping as a broken
privacy promise; the code and its tests were right and the prose was
wrong. Fixed in both places -- do not reintroduce it.

These tests also assert the collapse markup is never force-expanded,
that the grouping toggle and search filter compose, that pagination
preserves group+q URL-encoded, that the empty/disabled state renders,
that SSIDs are XSS-escaped, and that the ssid grouping never fans out
into an N+1.

Run with the pinned 3.11 venv.
"""

from __future__ import annotations

import re

from fastapi.testclient import TestClient

from lynceus.config import CaptureConfig, Config
from lynceus.db import Database
from lynceus.webui.app import create_app

NOW = 1_700_002_000


_DETAILS_RE = re.compile(r"<details\b.*?</details>", flags=re.DOTALL)


def _details_text(html: str) -> str:
    """Concatenate the inner text of every <details>...</details> block.

    A substring found here is collapsed-by-default (hidden behind a
    reveal until the operator expands it).
    """
    return " ".join(_DETAILS_RE.findall(html))


def _outside_details(html: str) -> str:
    """The page with every <details>...</details> block stripped out.

    A substring found here is VISIBLE on load. Pairing this with
    _details_text pins down exactly which side of the reveal a value
    lands on.
    """
    return _DETAILS_RE.sub("", html)


def _make(tmp_path, *, capture=False) -> tuple[Config, Database]:
    config = Config(
        db_path=str(tmp_path / "probes.db"),
        kismet_health_check_on_startup=False,
        evidence_capture_enabled=False,
        capture=CaptureConfig(probe_ssids=capture),
    )
    return config, Database(config.db_path)


def _seed(db: Database) -> None:
    """A small mix that exercises both groupings and edge cases.

    - aa device probed HomeNet, Starbucks, Airport_Free
    - bb device (label 'Joe iPhone') probed HomeNet, Marriott
    - cc device probed Starbucks, eduroam
    - dd device has NO probes (must never appear on /probes)
    - ff device probed eduroam, HomeNet, Starbucks, Marriott

    Distinct SSIDs: HomeNet(3), Starbucks(3), Marriott(2), eduroam(2),
    Airport_Free(1).
    """
    db.ensure_location("default", "Default Location")
    db.upsert_device(mac="aa:aa:aa:aa:aa:aa", device_type="wifi",
                     oui_vendor="Apple", is_randomized=0, now_ts=NOW - 5)
    db.merge_device_probe_ssids("aa:aa:aa:aa:aa:aa",
                                ["HomeNet", "Starbucks", "Airport_Free"])
    db.upsert_device(mac="bb:bb:bb:bb:bb:bb", device_type="wifi",
                     oui_vendor="Apple", is_randomized=0, now_ts=NOW - 1)
    db.update_device_ble_name("bb:bb:bb:bb:bb:bb", "Joe iPhone")
    db.merge_device_probe_ssids("bb:bb:bb:bb:bb:bb", ["HomeNet", "Marriott"])
    db.upsert_device(mac="cc:cc:cc:cc:cc:cc", device_type="wifi",
                     oui_vendor="Samsung", is_randomized=0, now_ts=NOW - 3)
    db.merge_device_probe_ssids("cc:cc:cc:cc:cc:cc", ["Starbucks", "eduroam"])
    db.upsert_device(mac="dd:dd:dd:dd:dd:dd", device_type="wifi",
                     oui_vendor="Intel", is_randomized=0, now_ts=NOW - 9)
    db.upsert_device(mac="ff:ff:ff:ff:ff:ff", device_type="wifi",
                     oui_vendor="Sony", is_randomized=0, now_ts=NOW - 2)
    db.merge_device_probe_ssids("ff:ff:ff:ff:ff:ff",
                                ["eduroam", "HomeNet", "Starbucks", "Marriott"])


# --------------------------------------------------------------------------
# DB layer -- device grouping (SSIDs already on the row).
# --------------------------------------------------------------------------

def test_db_count_probe_devices_excludes_no_probe_rows(tmp_path):
    _, db = _make(tmp_path)
    try:
        _seed(db)
        # 4 devices carry probes; dd (none) is excluded.
        assert db.count_probe_devices() == 4
        macs = {d["mac"] for d in db.list_probe_devices()}
        assert "dd:dd:dd:dd:dd:dd" not in macs
        assert macs == {
            "aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb",
            "cc:cc:cc:cc:cc:cc", "ff:ff:ff:ff:ff:ff",
        }
    finally:
        db.close()


def test_db_probe_devices_q_matches_ssid_and_identity(tmp_path):
    _, db = _make(tmp_path)
    try:
        _seed(db)
        # SSID substring inside the JSON text column.
        assert {d["mac"] for d in db.list_probe_devices(q="home")} == {
            "aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb", "ff:ff:ff:ff:ff:ff",
        }
        # device identity (vendor) still matches.
        assert {d["mac"] for d in db.list_probe_devices(q="sony")} == {
            "ff:ff:ff:ff:ff:ff",
        }
        # count and list stay in lockstep under search.
        for q in ("home", "star", "sony", "zzz"):
            assert db.count_probe_devices(q=q) == len(db.list_probe_devices(q=q)), q
    finally:
        db.close()


def test_db_probe_devices_newest_first(tmp_path):
    _, db = _make(tmp_path)
    try:
        _seed(db)
        order = [d["mac"] for d in db.list_probe_devices()]
        # last_seen DESC: bb(-1) ff(-2) cc(-3) aa(-5)
        assert order == [
            "bb:bb:bb:bb:bb:bb", "ff:ff:ff:ff:ff:ff",
            "cc:cc:cc:cc:cc:cc", "aa:aa:aa:aa:aa:aa",
        ]
    finally:
        db.close()


# --------------------------------------------------------------------------
# DB layer -- ssid grouping (json_each unnest).
# --------------------------------------------------------------------------

def test_db_count_probe_ssids_distinct(tmp_path):
    _, db = _make(tmp_path)
    try:
        _seed(db)
        assert db.count_probe_ssids() == 5  # HomeNet,Starbucks,Marriott,eduroam,Airport_Free
        assert db.count_probe_ssids(q="star") == 1
    finally:
        db.close()


def test_db_list_probe_ssids_ordered_by_device_count(tmp_path):
    _, db = _make(tmp_path)
    try:
        _seed(db)
        rows = db.list_probe_ssids()
        # device_count DESC, then ssid asc for ties.
        assert [(r["ssid"], r["device_count"]) for r in rows] == [
            ("HomeNet", 3), ("Starbucks", 3), ("Marriott", 2),
            ("eduroam", 2), ("Airport_Free", 1),
        ]
        assert db.count_probe_ssids() == len(rows)
    finally:
        db.close()


def test_db_devices_for_probe_ssids_groups_and_caps(tmp_path):
    _, db = _make(tmp_path)
    try:
        _seed(db)
        grouped = db.list_devices_for_probe_ssids(["HomeNet", "Starbucks"])
        assert {d["mac"] for d in grouped["HomeNet"]} == {
            "aa:aa:aa:aa:aa:aa", "bb:bb:bb:bb:bb:bb", "ff:ff:ff:ff:ff:ff",
        }
        assert {d["mac"] for d in grouped["Starbucks"]} == {
            "aa:aa:aa:aa:aa:aa", "cc:cc:cc:cc:cc:cc", "ff:ff:ff:ff:ff:ff",
        }
        # per-SSID cap bounds the materialized list (count still 3 in db).
        capped = db.list_devices_for_probe_ssids(["HomeNet"], per_ssid_cap=1)
        assert len(capped["HomeNet"]) == 1
        # empty input never touches the DB.
        assert db.list_devices_for_probe_ssids([]) == {}
    finally:
        db.close()


def test_db_malformed_probe_row_does_not_crash_ssid_grouping(tmp_path):
    """A hand-edited/legacy non-JSON probe_ssids row must skip silently in
    the json_each path (json_valid guard), not 500 the whole aggregation --
    matching the webui's safe-by-default decode."""
    _, db = _make(tmp_path)
    try:
        _seed(db)
        # Force a malformed payload past the merge helper.
        db._conn.execute(
            "UPDATE devices SET probe_ssids = ? WHERE mac = ?",
            ("not-json-at-all", "dd:dd:dd:dd:dd:dd"),
        )
        db._conn.commit()
        # SSID grouping still returns the 5 valid distinct SSIDs.
        assert db.count_probe_ssids() == 5
        assert len(db.list_probe_ssids()) == 5
        # Device grouping counts it (matches the existing probing filter,
        # which uses the same NULL/''/'[]' predicate) but it decodes empty.
        assert db.count_probe_devices() == 5
    finally:
        db.close()


# --------------------------------------------------------------------------
# Route -- both groupings render; collapsed-by-default reveal.
# --------------------------------------------------------------------------

def test_route_device_grouping_collapsed_by_default(tmp_path):
    config, db = _make(tmp_path, capture=True)
    try:
        _seed(db)
        app = create_app(config, db)
        with TestClient(app) as client:
            r = client.get("/probes")  # default group=device
        assert r.status_code == 200
        # Reveal markup present, never force-expanded.
        assert "<details>" in r.text
        assert "<summary>" in r.text
        assert "<details open" not in r.text
        # Summary exposes only the count, not the network names.
        assert "reveal 3 network(s)" in r.text  # aa probed 3
        # The per-device SSID list stays INSIDE the collapsed <details>
        # (the device's own fingerprint -- unchanged by the ssid-view fix):
        # HomeNet is in the reveal, never visible on load.
        assert "HomeNet" in _details_text(r.text)
        assert "HomeNet" not in _outside_details(r.text)
        # A no-probe device is absent.
        assert "dd:dd:dd:dd:dd:dd" not in r.text
        assert "4 device(s) total" in r.text
    finally:
        db.close()


def test_route_ssid_grouping_name_visible_devices_collapsed(tmp_path):
    """SSID-grouped: the network name is a VISIBLE header (scannable on
    load, outside <details>); the device list -- the sensitive
    concentration -- stays collapsed-by-default inside a closed <details>."""
    config, db = _make(tmp_path, capture=True)
    try:
        _seed(db)
        app = create_app(config, db)
        with TestClient(app) as client:
            r = client.get("/probes?group=ssid")
        assert r.status_code == 200
        html = r.text
        details = _details_text(html)
        # (a) SSID name is rendered as a visible header, OUTSIDE any <details>.
        assert (
            '<p class="probe-ssid-name">network: <strong>HomeNet</strong></p>'
            in html
        )
        assert "HomeNet" not in details  # not buried in the collapsed reveal
        # (b) the device list stays INSIDE a closed <details> (never expanded).
        assert "<details>" in html
        assert "<details open" not in html
        assert "aa:aa:aa:aa:aa:aa" in details  # a device identity is collapsed
        # the reveal now labels the device list, not the network name.
        assert "reveal 3 device(s)" in html
        assert "5 network(s) total" in html
    finally:
        db.close()


def test_route_group_toggle_switches_view(tmp_path):
    config, db = _make(tmp_path, capture=True)
    try:
        _seed(db)
        app = create_app(config, db)
        with TestClient(app) as client:
            dev = client.get("/probes?group=device").text
            ssid = client.get("/probes?group=ssid").text
        assert "device(s) total" in dev
        assert "network(s) total" in ssid
        # Unknown group normalizes to the device default (no 400).
        with TestClient(app) as client:
            bogus = client.get("/probes?group=banana")
        assert bogus.status_code == 200
        assert "device(s) total" in bogus.text
    finally:
        db.close()


def test_route_search_filters_both_groupings(tmp_path):
    config, db = _make(tmp_path, capture=True)
    try:
        _seed(db)
        app = create_app(config, db)
        with TestClient(app) as client:
            dev = client.get("/probes?group=device&q=sony")
            ssid = client.get("/probes?group=ssid&q=star")
        # device grouping: only the Sony device row.
        assert "ff:ff:ff:ff:ff:ff" in dev.text
        assert "aa:aa:aa:aa:aa:aa" not in dev.text
        assert "1 device(s) total" in dev.text
        assert "search=sony" in dev.text
        # ssid grouping: only Starbucks (3 devices).
        assert "1 network(s) total" in ssid.text
    finally:
        db.close()


def test_route_pagination_preserves_group_and_q_urlencoded(tmp_path):
    config, db = _make(tmp_path, capture=True)
    try:
        db.ensure_location("default", "Default Location")
        # 12 devices each probing a network whose name contains 'Net X'
        # (a space -> proves URL-encoding) so q matches all of them.
        for i in range(12):
            mac = f"10:00:00:00:00:{i:02x}"
            db.upsert_device(mac=mac, device_type="wifi", oui_vendor="Acme",
                             is_randomized=0, now_ts=NOW - i)
            db.merge_device_probe_ssids(mac, [f"Net X{i}"])
        app = create_app(config, db)
        with TestClient(app) as client:
            r = client.get("/probes?group=device&q=Net%20X&page_size=10")
        assert r.status_code == 200
        assert "12 device(s) total" in r.text
        # next link carries group + URL-encoded q + page 2.
        assert "group=device" in r.text
        assert "q=Net%20X" in r.text
        assert "page=2" in r.text
        # the raw space must not leak into the href.
        assert "q=Net X" not in r.text
    finally:
        db.close()


def test_route_empty_and_disabled_state(tmp_path):
    # No devices at all + capture disabled -> empty + honesty note.
    config, db = _make(tmp_path, capture=False)
    try:
        app = create_app(config, db)
        with TestClient(app) as client:
            r = client.get("/probes")
        assert r.status_code == 200
        assert "probe-SSID capture is disabled" in r.text
        assert "No probing devices match" in r.text
        assert "0 device(s) total" in r.text
    finally:
        db.close()


def test_route_capture_enabled_hides_disabled_note(tmp_path):
    config, db = _make(tmp_path, capture=True)
    try:
        _seed(db)
        app = create_app(config, db)
        with TestClient(app) as client:
            r = client.get("/probes")
        assert "probe-SSID capture is disabled" not in r.text
    finally:
        db.close()


def test_route_ssid_xss_escaped(tmp_path):
    config, db = _make(tmp_path, capture=True)
    try:
        db.ensure_location("default", "Default Location")
        db.upsert_device(mac="ab:cd:ef:00:00:01", device_type="wifi",
                         oui_vendor="Apple", is_randomized=0, now_ts=NOW)
        db.merge_device_probe_ssids("ab:cd:ef:00:00:01",
                                    ["<script>alert(1)</script>"])
        app = create_app(config, db)
        with TestClient(app) as client:
            dev = client.get("/probes?group=device").text
            ssid = client.get("/probes?group=ssid").text
        for body in (dev, ssid):
            assert "<script>alert(1)</script>" not in body
            assert "&lt;script&gt;" in body
        # The relocated ssid-grouped header keeps the SSID autoescaped:
        # the escaped name renders in the VISIBLE header (outside <details>).
        assert "&lt;script&gt;" in _outside_details(ssid)
    finally:
        db.close()


def test_route_ssid_grouping_no_n_plus_1(tmp_path):
    """The ssid grouping must use a fixed number of json_each queries
    regardless of how many SSID groups the page shows -- one bounded
    follow-up for the whole page, never one-per-group."""
    config, db = _make(tmp_path, capture=True)
    try:
        db.ensure_location("default", "Default Location")
        # 40 devices, each probing 3 distinct networks -> 120 distinct SSIDs.
        for i in range(40):
            mac = f"20:00:00:00:00:{i:02x}"
            db.upsert_device(mac=mac, device_type="wifi", oui_vendor="V",
                             is_randomized=0, now_ts=NOW - i)
            db.merge_device_probe_ssids(
                mac, [f"NetA{i}", f"NetB{i}", f"NetC{i}"]
            )
        app = create_app(config, db)

        seen: list[str] = []
        db._conn.set_trace_callback(seen.append)
        try:
            with TestClient(app) as client:
                r = client.get("/probes?group=ssid&page_size=50")
        finally:
            db._conn.set_trace_callback(None)
        assert r.status_code == 200
        # Exactly three json_each statements: count + page-of-ssids +
        # one IN(...) device fetch for the whole page. Not 50 (one each).
        json_each_stmts = [s for s in seen if "json_each" in s.lower()]
        assert len(json_each_stmts) == 3, (
            f"expected 3 json_each queries, saw {len(json_each_stmts)}"
        )
    finally:
        db.close()


def test_disabled_notice_does_not_claim_empty_while_showing_retained_history(tmp_path):
    """Capture OFF does not empty this view.

    Turning probe capture off stops NEW values being written
    (poller.py:229-237) but nothing purges the existing
    ``devices.probe_ssids`` column. The notice used to be gated only on
    ``not probe_capture_enabled``, never on row count, so the page asserted
    "this view is empty" while rendering retained MACs and retained SSIDs --
    telling the operator their probe history was gone while displaying it.
    """
    db_path = tmp_path / "probes.db"
    with Database(str(db_path)) as db:
        db.upsert_device("aa:aa:aa:aa:aa:aa", "wifi", "Acme", 0, NOW)
        db.merge_device_probe_ssids("aa:aa:aa:aa:aa:aa", ["RetainedNet"])
        # capture disabled, but history from when it was on remains
        cfg = Config(db_path=str(db_path), capture=CaptureConfig(probe_ssids=False))
        app = create_app(cfg, db)
        with TestClient(app) as client:
            r = client.get("/probes")
    assert r.status_code == 200
    html = r.text
    assert "capture is disabled" in html, "the disabled notice must still appear"
    # The retained row really is on the page...
    assert "aa:aa:aa:aa:aa:aa" in html
    assert "1 device(s) total" in html
    # ...so the page must NOT also claim to be empty.
    assert "this view is empty" not in html, (
        "the page claims to be empty while rendering retained probe history"
    )
    assert "nothing new is being recorded" in html


def test_disabled_notice_still_says_empty_when_there_is_no_history(tmp_path):
    """The genuinely-empty case keeps its original, accurate wording."""
    db_path = tmp_path / "probes-empty.db"
    with Database(str(db_path)) as db:
        cfg = Config(db_path=str(db_path), capture=CaptureConfig(probe_ssids=False))
        app = create_app(cfg, db)
        with TestClient(app) as client:
            r = client.get("/probes")
    assert r.status_code == 200
    assert "this view is empty" in r.text
