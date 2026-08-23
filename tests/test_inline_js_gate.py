"""The gate that checks the templates' inline JavaScript, checked itself.

`scripts/check_inline_js.py` runs in CI and decides whether ~10.6 KB of
first-party JavaScript parses. A gate is only worth its green tick if the
extraction feeding it is right, and the first version of that extraction had a
real defect that CodeQL found and no test would have:

    <script>var a = 1;</script >

HTML permits whitespace before the `>` of a closing tag. Against `</script>`
the pattern skipped that close tag entirely and ran on to the NEXT one, so the
"JavaScript" it handed to `node --check` was:

    'var a = 1;</script >\\n<p>not javascript at all, this is prose</p>\\n<script>var b = 2;'

Two failure modes, both bad: the gate reports a parse error on HTML prose, or
it merges two blocks and silently stops checking one of them. A
malformed-input bug in the tool whose entire job is malformed input.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).parent.parent / "scripts" / "check_inline_js.py"


@pytest.fixture(scope="module")
def gate():
    spec = importlib.util.spec_from_file_location("check_inline_js", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_a_close_tag_with_whitespace_is_still_a_close_tag(gate):
    """THE GUARD. `</script >` must end the block it ends."""
    html = (
        "<script>var a = 1;</script >\n"
        "<p>not javascript at all, this is prose</p>\n"
        "<script>var b = 2;</script>\n"
    )
    bodies = gate.inline_blocks(html)
    assert bodies == ["var a = 1;", "var b = 2;"], (
        "the extraction ran past a whitespace-padded close tag and captured "
        f"HTML as JavaScript: {bodies!r}"
    )


@pytest.mark.parametrize(
    "close_tag", ["</script>", "</script >", "</script\n>", "</script bar>", "</SCRIPT  >"]
)
def test_every_legal_close_tag_ends_the_block(gate, close_tag):
    """⛔ CodeQL flagged this TWICE: once for the whitespace form, and again on
    the fix, because HTML also permits attributes in an end tag and ignores
    them. Patching until the alert went quiet would have shipped the second
    hole. Each of these must terminate the block it terminates."""
    html = f"<script>var a = 1;{close_tag}<p>prose, not javascript</p>"
    assert gate.inline_blocks(html) == ["var a = 1;"], close_tag


def test_the_ordinary_close_tag_still_works(gate):
    """The CONTROL. A pattern loosened until it matches nothing useful would
    satisfy the guard above by returning two empty bodies."""
    assert gate.inline_blocks("<script>var a = 1;</script>") == ["var a = 1;"]


def test_a_src_script_is_skipped(gate):
    """External scripts are already their own files and are checked by the
    `git ls-files '*.js'` step. Parsing an empty body would fail the gate."""
    assert gate.inline_blocks('<script src="/static/htmx.min.js"></script>') == []


def test_jinja_expressions_become_valid_javascript(gate):
    """`{{ ... }}` is not JavaScript, so it has to be substituted before
    `node --check` sees it -- but substituted with something that keeps the
    surrounding code parseable."""
    out = gate.inline_blocks('<script>var n = "{{ request.state.csp_nonce }}";</script>')
    assert out == ['var n = "0";']


def test_a_script_tag_inside_a_jinja_comment_is_not_extracted(gate):
    """⛔ The templates carry long `{# ... #}` commentary that DISCUSSES
    `<script>` tags. Searching the raw template matches inside the comment and
    captures English prose as code -- which is what produced five bogus "does
    not parse" failures whose error text was sentences."""
    html = (
        "{# CSP requires listeners on ELEMENTS, never on*= attributes.\n"
        "   Do not add a <script> block here. #}\n"
        "<script>var real = 1;</script>\n"
    )
    assert gate.inline_blocks(html) == ["var real = 1;"]


def test_a_jinja_block_does_not_swallow_the_script_body(gate):
    html = "<script>{% if x %}var a = 1;{% endif %}</script>"
    assert gate.inline_blocks(html) == ["var a = 1;"]


def test_the_lexer_environment_autoescapes(gate):
    """Not because it renders -- it never does, it is only ever `.lex()`ed --
    but because a standing HIGH `py/jinja2/autoescape-false` alert is how a
    real one later gets waved through."""
    assert gate._env.autoescape is True


def test_the_real_templates_still_yield_blocks(gate):
    """Non-vacuity, against the shipped templates rather than fixtures. An
    extraction that quietly stopped matching would make every case above pass
    while CI checked nothing."""
    total = 0
    for path in (Path(__file__).parent.parent / "src").rglob("*.html"):
        total += len(gate.inline_blocks(path.read_text(encoding="utf-8")))
    assert total >= 8, f"only {total} inline blocks found across the templates"
