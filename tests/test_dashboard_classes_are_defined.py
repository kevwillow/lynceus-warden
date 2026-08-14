"""No NEW class may be emitted by a dashboard template without a CSS rule.

The dashboard counterpart to `test_wizard_classes_are_defined.py`. Same defect
class, fourth and fifth instances: a template asks for a class the loaded CSS
does not define, the page renders HTTP 200 with plausible HTML, and the styling
simply does not happen. A status-code crawl cannot see it.

⚠️ **This is a RATCHET, not a clean bill.** 22 classes are inert today. They are
listed in `KNOWN_INERT` and this suite does not fail on them, because fixing
them is a design decision rather than a defect fix — see below. What it does
guarantee is that the 23rd cannot be added silently.

⛔ **Why the existing 22 were not simply "fixed".** `lynceus.css:509-514` already
documents that `.outline` and `.secondary` are inert and that the affected
buttons therefore "render as Pico's default compact FILLED button" — and the
`.watchful-actions` summary styling was then deliberately matched to that real
filled appearance. Adding a global `.outline` rule would make those buttons
outlined while their sibling summaries stayed filled, breaking a visual match
that was made on purpose. That is a decision for the maintainer, not a tidy-up.

🪤 **What this guard CANNOT see: scope shadowing.** `.outline` does not appear in
`KNOWN_INERT` because `.watchful-actions .outline` exists, so the name is
"defined" — yet the four `.outline` sites outside `.watchful-actions` match no
rule. A name-level check cannot distinguish those. Detecting it needs the
browser (`document.querySelectorAll` + rule matching), which is not available in
this suite. **Do not read a green run here as "every class applies."**
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_TEMPLATES = _ROOT / "src/lynceus/webui/templates"
_STATIC = _ROOT / "src/lynceus/webui/static"
#: The dashboard's only <link> is app.css, a cascade-layer entry that
#: @imports these two. Reading app.css alone would find almost no selectors.
_SHEETS = ("pico.min.css", "lynceus.css", "app.css")

#: Inert as of bfb217b. Measured twice: once by me, once by an independent
#: review that was asked to refute the method. Both agree on exactly these.
KNOWN_INERT = frozenset({
    "alert-note-indicator", "alert-note-text", "alerts-page-next",
    "alerts-page-prev", "block-recent-devices", "filter-shortcut-hint",
    "filters-summary", "probe-ssid-name", "probing-capture-note", "secondary",
    "shortcut-hint", "snooze-duration-select", "status",
    "watchful-action-dismiss", "watchful-action-investigate",
    "watchful-action-promote", "watchful-action-reset", "watchful-action-safe",
    "watchful-investigate-summary", "watchful-promote-summary",
    "watchful-safe-summary", "wizard-error",
})


def _loaded_css() -> str:
    """Every stylesheet the dashboard loads, with comments removed.

    🪤 Comments ONLY. An earlier version also stripped `url(...)` payloads and
    quoted strings, on the theory that `.status` inside `url(icon.status.svg)`
    could wrongly mark a class defined. Measured: that concern finds exactly
    `css`, `min`, `org`, `w3` in this codebase — none of them class names — while
    the stripping itself destroyed **118 of 132** selectors, because unbalanced
    quotes in minified Pico make a naive string regex swallow whole rule blocks.
    The defensive fix was far worse than the thing it defended against.

    Comment stripping IS load-bearing: `.secondary` appears in a comment at
    `lynceus.css:510`, and without this the guard would rubber-stamp it using
    the codebase's own documentation as evidence.
    """
    css = "".join((_STATIC / f).read_text(encoding="utf-8") for f in _SHEETS)
    return re.sub(r"/\*.*?\*/", " ", css, flags=re.S)


def _literal_classes(attr: str) -> list[str]:
    """Literal tokens from a class attribute, including mixed literal+Jinja.

    `class="badge-{{ sev }} sev-label"` yields `sev-label` only: a token ending
    in `-` is the prefix of a computed name, not a class. Skipping such
    attributes wholesale — as the first version did — discarded 5 real literal
    classes including `row-acked` and `th-sort-active`.
    """
    cleaned = re.sub(r"\{\{.*?\}\}|\{%.*?%\}", " ", attr)
    return [w for w in cleaned.split() if w and not w.endswith("-")]


def _classes_used() -> dict[str, set[str]]:
    used: dict[str, set[str]] = {}
    for tpl in sorted(_TEMPLATES.glob("*.html")):
        txt = tpl.read_text(encoding="utf-8")
        txt = re.sub(r"<!--.*?-->", " ", txt, flags=re.S)
        txt = re.sub(r"\{#.*?#\}", " ", txt, flags=re.S)
        for attr in re.findall(r'class="([^"]*)"', txt):
            for cls in _literal_classes(attr):
                used.setdefault(cls, set()).add(tpl.name)
    return used


def _defined() -> set[str]:
    return set(re.findall(r"\.([A-Za-z][\w-]*)", _loaded_css()))


def test_the_corpora_are_non_empty():
    """⭐ A cross-check that silently enumerated nothing would pass forever."""
    assert len(_classes_used()) >= 100, "template scan found too few classes"
    assert len(_defined()) >= 100, "stylesheet scan found too few selectors"


def test_no_new_inert_class_has_been_introduced():
    """The ratchet. Adding a class with no rule is caught; the 22 already
    there are not re-litigated on every run."""
    used = _classes_used()
    inert = {c for c in used if c not in _defined()}
    new = sorted(inert - KNOWN_INERT)
    assert new == [], (
        f"these classes are emitted by a dashboard template but matched by no "
        f"rule in any loaded stylesheet: {new}. The bundled Pico is the "
        f"CLASSLESS build and defines no modifier classes. Either add a rule to "
        f"lynceus.css, or remove the class if it was decorative — do not leave "
        f"markup implying an intent the stylesheet does not honour. Sites: "
        f"{ {c: sorted(used[c]) for c in new} }"
    )


def test_the_known_inert_list_has_not_silently_become_stale():
    """⭐ The other direction. If someone adds a rule for a KNOWN_INERT class,
    this list must shrink — otherwise it rots into a permanent excuse and the
    ratchet stops meaning anything."""
    fixed = sorted(KNOWN_INERT & _defined())
    assert fixed == [], (
        f"these are in KNOWN_INERT but now HAVE a rule: {fixed}. Remove them "
        f"from KNOWN_INERT so the ratchet keeps its teeth."
    )


def test_comment_stripping_is_actually_applied():
    """🪤 Guards the guard. `.secondary` appears in a COMMENT at lynceus.css:510
    while having no rule. Without comment stripping this suite would report it
    as defined — passing by matching the codebase's own documentation, which is
    the exact failure that bit the wizard version of this check."""
    raw = "".join((_STATIC / f).read_text(encoding="utf-8") for f in _SHEETS)
    assert ".secondary" in raw, "fixture assumption gone: no .secondary in the raw CSS"
    assert "secondary" not in _defined(), (
        "comment stripping is not being applied — .secondary is being counted "
        "as defined on the strength of a comment that says it is NOT"
    )


@pytest.mark.parametrize("sheet", _SHEETS)
def test_every_expected_stylesheet_exists(sheet):
    """A missing sheet would shrink `_defined()` and make everything look
    inert — a false alarm rather than a false pass, but still wrong."""
    assert (_STATIC / sheet).is_file(), f"{sheet} is missing from the static dir"
