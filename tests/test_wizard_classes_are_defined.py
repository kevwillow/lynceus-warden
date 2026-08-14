"""Every class the wizard styles with must actually exist in the CSS it serves.

⛔ This is the general form of a trap this repo has now hit **three times**, and
it is silent every time: a template asks for a class the bundled *classless*
Pico build does not define, the page renders HTTP 200 with plausible-looking
HTML, and the styling simply does not happen.

    1. `.container`  — documented in `_base.html`'s own comments
    2. `.grid`       — the `/alerts` filter form, fixed earlier
    3. `.secondary`  — 20 sites across all 13 wizard steps, this file

⚠️ **A status-code crawl cannot see any of them.** Nor can a test that asserts
the class STRING is present — which is exactly what
`test_setup_web_templates.py` did, while its own comment claimed *"so Pico's
lower-emphasis variant applies"*. The comment asserted an effect; the code
checked a spelling. It was green the entire time `.secondary` did nothing.

⇒ The only check that works is the one below: cross-reference the classes the
templates actually use against the CSS the page actually loads. Note this is
the LOUD half of that defect class — an undefined Jinja *filter* raises at
compile time and yields a 500, so it needs no test. Only undefined CSS classes
are silent.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_TEMPLATES = Path(__file__).resolve().parents[1] / "src/lynceus/setup/web/templates"
_BASE = _TEMPLATES / "_base.html"
#: The wizard mounts the dashboard's static dir (`_resolve_webui_static_dir`),
#: so this is the stylesheet its `<link>` actually resolves to. It does NOT
#: load `lynceus.css` — a rule added there would not reach the wizard.
_PICO = Path(__file__).resolve().parents[1] / "src/lynceus/webui/static/pico.min.css"

#: Classes that carry no visual meaning, with the reason each is exempt. An
#: unexplained allowlist is how a check like this rots into a rubber stamp, so
#: every entry names why it is here rather than being fixed.
_NON_VISUAL = {
    # Selector hook for the step-6 rule checkboxes; behaviour, not appearance.
    "rule-type-checkbox",
}


def _strip_css_comments(css: str) -> str:
    """Remove `/* ... */`, because a comment is not a rule.

    🪤 Caught by planting: with the `.secondary` RULE deleted, the check below
    still passed — it was matching the word `.secondary` inside the long
    explanatory comment in `_base.html` that describes the very bug. The guard
    would have rubber-stamped the defect it exists to catch, using its own
    documentation as evidence.

    That is the same shape as the thing this file was written to replace (a
    test asserting a class STRING is present rather than that it does
    anything), one level up. Comments in this repo mention class names
    constantly, so stripping them is load-bearing, not tidiness.
    """
    return re.sub(r"/\*.*?\*/", " ", css, flags=re.S)


def _wizard_css() -> str:
    """Everything that styles a wizard page: the inline block plus Pico."""
    base = _BASE.read_text(encoding="utf-8")
    inline = "\n".join(re.findall(r"<style>(.*?)</style>", base, re.S))
    pico = _PICO.read_text(encoding="utf-8") if _PICO.exists() else ""
    return _strip_css_comments(inline + "\n" + pico)


def _classes_used() -> set[str]:
    used: set[str] = set()
    for tpl in sorted(_TEMPLATES.glob("*.html")):
        for attr in re.findall(r'class="([^"{}]+)"', tpl.read_text(encoding="utf-8")):
            used.update(attr.split())
    return used


def _is_defined(css: str, cls: str) -> bool:
    """A rule selecting `.cls`, not merely the substring.

    🪤 The naive `f".{cls}" in css` check would have passed for `.secondary`:
    `lynceus.css` mentions it in a COMMENT. That is the guards-that-cannot-fail
    shape this suite exists to avoid, so require a selector boundary.
    """
    return re.search(rf"\.{re.escape(cls)}(?![\w-])", css) is not None


def test_the_fixture_finds_templates_and_css_at_all():
    """⭐ A cross-check that silently enumerated nothing would pass forever
    while checking nothing. Assert both corpora are non-empty first."""
    assert len(_classes_used()) >= 5, "no classes discovered — the regex or path is wrong"
    assert len(_wizard_css()) > 1000, "no CSS discovered — the path is wrong"


@pytest.mark.parametrize("cls", sorted(_classes_used() - _NON_VISUAL))
def test_every_class_the_wizard_uses_is_defined_somewhere_it_loads(cls):
    assert _is_defined(_wizard_css(), cls), (
        f'the wizard templates use class="{cls}" but no rule in the CSS they '
        f"load matches it, so it renders with no styling at all. The bundled "
        f"Pico is the CLASSLESS build and defines no modifier classes -- add a "
        f"rule to the inline <style> block in _base.html, as .container and "
        f".secondary already do."
    )


def test_secondary_is_visually_distinct_from_the_primary_button():
    """The specific regression, pinned beyond mere existence.

    Defining `.secondary` with the *same* background as the primary would
    satisfy the check above while leaving Previous and Next indistinguishable
    -- which is the actual defect, measured as pixel- and colour-identical
    buttons on all 13 steps.
    """
    css = _wizard_css()
    m = re.search(
        r"\.wizard-footer a\[role=\"button\"\]\.secondary[^{]*\{([^}]*)\}", css, re.S
    )
    assert m, "no .secondary rule scoped to the wizard footer"
    body = m.group(1)
    assert "background" in body, ".secondary must change the background, not only the border"
    assert "#0172ad" not in body, (
        ".secondary uses the primary colour, so Previous and Next remain "
        "indistinguishable -- the defect this rule exists to fix"
    )


def test_the_footer_sizing_rule_still_normalises_geometry():
    """⛔ The guard against over-correcting. The sizing rule deliberately makes
    both controls the same shape; this fix changes only the emphasis axis. A
    later 'tidy-up' that dropped the sizing pin would reintroduce the uneven
    row that three rounds of smoke testing were spent on."""
    css = _wizard_css()
    assert re.search(r"\.wizard-footer a\[role=\"button\"\],\s*\.wizard-footer button", css)
    assert "min-width: 9em" in css
