"""Local validation for the 0.9.2 column-resize *discoverability* fix
(Touch 1): the grip's vertical bar must now be a PERSISTENT, faint column
separator at rest (so the resize affordance is visible without hovering) and
must DARKEN on hover / during a drag.

Structure-level only. The actual visual weight -- "is the rest separator
subtle-but-visible, does the darken read as a handle" -- is TASTE and is an
operator eyes-on check on the rig, not something this suite can assert. These
tests only guard that the CSS still ships:

  1. a non-zero rest-state separator opacity, exposed via an easy-to-tweak
     custom property (regression guard against the old opacity:0 invisible
     behaviour silently coming back), and
  2. a hover / .lyn-resizing rule that strengthens it to the active weight.

tests/ is gitignored; never committed. Run with the pinned 3.11 venv.
"""

from __future__ import annotations

import re
from pathlib import Path

CSS = (
    Path(__file__).resolve().parent.parent
    / "src"
    / "lynceus"
    / "webui"
    / "static"
    / "lynceus.css"
).read_text(encoding="utf-8")


def _block(selector_fragment: str) -> str:
    """Return the first declaration block whose selector contains the fragment."""
    idx = CSS.index(selector_fragment)
    open_brace = CSS.index("{", idx)
    close_brace = CSS.index("}", open_brace)
    return CSS[open_brace + 1 : close_brace]


# --- 1. rest-state separator is persistent and tweakable -----------------


def test_rest_separator_opacity_is_nonzero_and_variable_driven():
    # The rest weight is exposed as a custom property so the operator can
    # dial it without hunting through the rule.
    m = re.search(r"--lyn-col-separator-rest:\s*([0-9.]+)\s*;", CSS)
    assert m, "missing --lyn-col-separator-rest custom property"
    rest = float(m.group(1))
    assert rest > 0, (
        f"--lyn-col-separator-rest is {rest}; a zero rest opacity is exactly "
        f"the old invisible-until-hover bug this fix removes"
    )

    # The grip bar's rest opacity is driven by that property, not a literal 0.
    grip = _block(".col-resizer::after")
    assert "opacity: var(--lyn-col-separator-rest" in grip, (
        "grip ::after rest opacity must reference --lyn-col-separator-rest"
    )
    assert "opacity: 0;" not in grip, "grip still hard-coded to invisible at rest"


# --- 2. grip darkens on hover / during drag ------------------------------


def test_grip_darkens_on_hover_and_while_resizing():
    m = re.search(r"--lyn-col-separator-active:\s*([0-9.]+)\s*;", CSS)
    assert m, "missing --lyn-col-separator-active custom property"
    active = float(m.group(1))
    rest = float(re.search(r"--lyn-col-separator-rest:\s*([0-9.]+)", CSS).group(1))
    assert active > rest, (
        f"active weight {active} must exceed rest weight {rest} so the bar "
        f"visibly darkens on hover"
    )

    hover = _block(".col-resizer:hover::after")
    assert "var(--lyn-col-separator-active" in hover, (
        "hover rule must strengthen to --lyn-col-separator-active"
    )
    # The drag state (.lyn-resizing) shares the hover rule's selector list.
    assert "lyn-resizing" in CSS, "missing .lyn-resizing darken selector"
