"""Local validation for the 0.9.1 Probes-tab reveal layout fix.

The probes reveal is a native <details> inside a .table-scroll cell. That
cell sets `white-space: nowrap` (to drive the table's horizontal scroll),
which is inherited into the revealed list; combined with Pico drawing the
<summary> marker as a `float: right` chevron on a block-level (column-width)
summary, expanding one row widened the shared table COLUMN and slid every
other row's chevron to the new right edge, long network names overflowed,
and the chevron sat off-center.

The fix is two CSS rules in lynceus.css, scoped to the probe reveals via
their `.probe-reveal` list so no other table's <details> is touched:

  details:has(> .probe-reveal) > summary::after { float: none;
      display: inline-block; vertical-align: middle; }
  .probe-reveal { white-space: normal; overflow-wrap: anywhere; }

WHAT THESE TESTS COVER (server-renderable / static):
  * the rendered DOM shape the CSS selector keys on -- each <details>
    directly contains a <summary> immediately followed by its
    <ul class="probe-reveal"> -- in BOTH groupings;
  * a long network name is rendered inside .probe-reveal (so it is subject
    to the wrap rule), not outside it;
  * the fix is present in lynceus.css AND scoped (no bare/global summary
    or float-override rule that would leak into other tables -- the scope
    fence as a regression guard).

WHAT THEY DO NOT COVER (visual / layout -- operator eyes-on, per the arc):
  * that expanding one row no longer moves sibling rows' arrows;
  * that the arrow is visually centered;
  * that a long name actually wraps rather than clips.
  These are real-browser layout outcomes and are confirmed on the rig.

tests/ is gitignored; this file is local-only validation, never committed.
Run with the pinned 3.11 venv:
    .venv/Scripts/python -m pytest tests/test_probes_reveal_layout.py -q
"""

from __future__ import annotations

import re
from pathlib import Path

import lynceus.webui
from fastapi.testclient import TestClient

from lynceus.config import CaptureConfig, Config
from lynceus.db import Database
from lynceus.webui.app import create_app

NOW = 1_700_002_000

# A network name long enough that, un-wrapped, it would widen the shared
# column -- the exact condition that drove the sibling-arrow reflow.
LONG_SSID = "A_Very_Long_Probed_Network_Name_That_Would_Otherwise_Overflow_The_Cell"

_DETAILS_RE = re.compile(r"<details\b.*?</details>", flags=re.DOTALL)
# A <details> whose first element child is a <summary> immediately followed
# (only whitespace between) by its <ul class="probe-reveal"> -- i.e. the
# summary and the reveal list are siblings directly under <details>, which
# is what `details:has(> .probe-reveal) > summary` keys on.
_SHAPE_RE = re.compile(
    r"<details\b[^>]*>\s*<summary\b[^>]*>.*?</summary>\s*"
    r'<ul class="probe-reveal"',
    flags=re.DOTALL,
)


def _details_blocks(html: str) -> list[str]:
    return _DETAILS_RE.findall(html)


def _details_text(html: str) -> str:
    return " ".join(_details_blocks(html))


def _outside_details(html: str) -> str:
    return _DETAILS_RE.sub("", html)


def _make(tmp_path) -> tuple[Config, Database]:
    config = Config(
        db_path=str(tmp_path / "probes.db"),
        kismet_health_check_on_startup=False,
        evidence_capture_enabled=False,
        capture=CaptureConfig(probe_ssids=True),
    )
    return config, Database(config.db_path)


def _seed(db: Database) -> None:
    db.ensure_location("default", "Default Location")
    # Three devices so a column-width change would be visible across rows;
    # one of them probed the long-named network.
    db.upsert_device(mac="aa:aa:aa:aa:aa:aa", device_type="wifi",
                     oui_vendor="Apple", is_randomized=0, now_ts=NOW - 5)
    db.merge_device_probe_ssids("aa:aa:aa:aa:aa:aa", ["HomeNet", "Starbucks"])
    db.upsert_device(mac="bb:bb:bb:bb:bb:bb", device_type="wifi",
                     oui_vendor="Apple", is_randomized=0, now_ts=NOW - 1)
    db.merge_device_probe_ssids("bb:bb:bb:bb:bb:bb", [LONG_SSID, "HomeNet"])
    db.upsert_device(mac="cc:cc:cc:cc:cc:cc", device_type="wifi",
                     oui_vendor="Samsung", is_randomized=0, now_ts=NOW - 3)
    db.merge_device_probe_ssids("cc:cc:cc:cc:cc:cc", ["Starbucks"])


def _css() -> str:
    static = Path(lynceus.webui.__file__).resolve().parent / "static"
    return (static / "lynceus.css").read_text(encoding="utf-8")


# --------------------------------------------------------------------------
# Rendered DOM shape the CSS selector depends on.
# --------------------------------------------------------------------------

def test_device_grouping_reveal_shape_matches_selector(tmp_path):
    """Every device-grouped <details> is `<summary>` directly followed by
    `<ul class="probe-reveal">` -- the shape `details:has(> .probe-reveal)
    > summary::after` targets."""
    config, db = _make(tmp_path)
    try:
        _seed(db)
        app = create_app(config, db)
        with TestClient(app) as client:
            html = client.get("/probes?group=device").text
        blocks = _details_blocks(html)
        assert blocks, "expected at least one reveal <details>"
        for block in blocks:
            assert _SHAPE_RE.match(block), f"unexpected reveal shape: {block!r}"
        # collapse-by-default invariant intact (markup untouched by the fix).
        assert "<details open" not in html
    finally:
        db.close()


def test_ssid_grouping_reveal_shape_matches_selector(tmp_path):
    """Same shape holds in the network-grouped view, where the <details>
    also carries a trailing <p> after the .probe-reveal list."""
    config, db = _make(tmp_path)
    try:
        _seed(db)
        app = create_app(config, db)
        with TestClient(app) as client:
            html = client.get("/probes?group=ssid").text
        blocks = _details_blocks(html)
        assert blocks, "expected at least one reveal <details>"
        for block in blocks:
            assert _SHAPE_RE.match(block), f"unexpected reveal shape: {block!r}"
        assert "<details open" not in html
    finally:
        db.close()


def test_long_network_name_renders_inside_reveal(tmp_path):
    """The long name lands INSIDE .probe-reveal (subject to the wrap rule),
    never visible on load -- so wrapping it can't change the collapse
    semantics."""
    config, db = _make(tmp_path)
    try:
        _seed(db)
        app = create_app(config, db)
        with TestClient(app) as client:
            html = client.get("/probes?group=device").text
        assert LONG_SSID in _details_text(html)
        assert LONG_SSID not in _outside_details(html)
    finally:
        db.close()


# --------------------------------------------------------------------------
# Fix is present in lynceus.css AND scoped (scope-fence regression guard).
# --------------------------------------------------------------------------

def test_css_reveal_fix_present():
    css = _css()
    # marker override, scoped to the probe reveals.
    assert "details:has(> .probe-reveal) > summary::after" in css
    # the revealed list opts out of the cell's nowrap and wraps long names.
    reveal = re.search(r"\.probe-reveal\s*\{(.*?)\}", css, flags=re.DOTALL)
    assert reveal, ".probe-reveal rule missing"
    body = reveal.group(1)
    assert re.search(r"white-space:\s*normal", body)
    assert re.search(r"overflow-wrap:\s*anywhere", body)


def test_css_marker_override_is_scoped_not_global():
    """Scope fence: every summary-marker override and every `float: none`
    must be COMPONENT-scoped, never global, so a fix can never leak into the
    other tables' <details> (alerts, rules, watchlist, ...). Two legitimate
    scopes exist: `.probe-reveal` (the probes chevron flow fix) and
    `.watchful-actions` (the watchful disclosures styled as buttons, which
    suppress the chevron). A bare/unscoped `summary::after` would still fail."""
    css = _css()
    marker_scopes = (".probe-reveal", ".watchful-actions")
    # Every `summary::after` selector in our stylesheet is component-scoped.
    for m in re.finditer(r"([^{}]*?)summary::after\s*\{", css):
        assert any(s in m.group(1) for s in marker_scopes), (
            f"unscoped summary::after override: {m.group(1)!r}"
        )
    # Every `float: none` lives in a probe-scoped rule.
    for m in re.finditer(r"([^{}]*)\{[^{}]*float:\s*none", css, flags=re.DOTALL):
        assert ".probe-reveal" in m.group(1), (
            f"unscoped float override: {m.group(1)!r}"
        )
