"""A CSS comment that closes early silently deletes the rule beneath it.

⛔ Measured 2026-08-31 on `lynceus.css`. A comment block closed four lines
early with a stray ``*/``. The prose that followed then parsed as CSS source,
the browser swallowed the next selector into an invalid one, and
``.status-line .status-error { max-width: 100%; word-break: break-word; }``
was **dropped entirely**. Confirmed in Chromium: zero parsed rules referenced
``status-error`` while the source plainly declared one.

Nothing failed. CSS error recovery is specified to be silent, so a dropped
rule looks exactly like a rule that was never written, and the only symptom is
that some element quietly stops being styled.

🪤 **Why the existing class guard could not see this.**
``tests/test_dashboard_classes_are_defined.py`` matches class NAMES against the
stylesheet TEXT. `status-error` appears in the text either way, so the name
reads as "defined" whether or not the browser ever parsed the rule. Text-level
checks are blind to parse failures by construction.

This guard is deliberately cheap and text-level too, but it asks a different
question: *is the comment structure itself well formed?* That is answerable
without a browser and runs in every CI job.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_STATIC = Path(__file__).resolve().parents[1] / "src/lynceus/webui/static"

#: Well-formed comments, non-greedy so each `/* ... */` pairs with its own
#: terminator rather than spanning to the last one in the file.
_COMMENT = re.compile(r"/\*.*?\*/", re.S)


def _css_files() -> list[Path]:
    return sorted(_STATIC.glob("*.css"))


def test_the_stylesheet_set_is_not_empty():
    """⛔ Without this, every parametrised test below would vacuously pass if
    the static directory moved. A guard whose corpus can silently empty is not
    a guard.
    """
    found = _css_files()
    assert found, f"no .css files under {_STATIC}; the guard below proves nothing"


@pytest.mark.parametrize("css", _css_files(), ids=lambda p: p.name)
def test_no_comment_closes_early(css: Path):
    """A `*/` outside any comment means an earlier comment closed too soon.

    Everything between the premature terminator and the real one is parsed as
    CSS source, which destroys whatever rule follows it.
    """
    src = css.read_text(encoding="utf-8")
    # Blank out well-formed comments, preserving offsets so reported line
    # numbers point at the real location in the file.
    masked = _COMMENT.sub(lambda m: " " * len(m.group(0)), src)

    strays = []
    for m in re.finditer(r"\*/", masked):
        line = src.count("\n", 0, m.start()) + 1
        context = src[max(0, m.start() - 70) : m.start() + 2].replace("\n", " ")
        strays.append(f"{css.name}:{line}: ...{context}")

    assert not strays, (
        "stray `*/` found outside any comment. An earlier comment closed early, "
        "so the prose after it is being parsed as CSS and the next rule is "
        "silently dropped by the browser:\n  " + "\n  ".join(strays)
    )


@pytest.mark.parametrize("css", _css_files(), ids=lambda p: p.name)
def test_no_comment_is_left_unterminated(css: Path):
    """The mirror failure: a `/*` with no `*/` at all swallows the file's tail.

    ⚠️ This catches only the case where NO later terminator exists. The far
    more likely shape is covered by `test_no_comment_swallows_a_later_block`
    below, and that distinction is load-bearing: a dropped terminator normally
    re-pairs with the next one down the file, which leaves the counts perfectly
    balanced and this assertion green. Proven by planting exactly that.
    """
    src = css.read_text(encoding="utf-8")
    masked = _COMMENT.sub(lambda m: " " * len(m.group(0)), src)
    opener = masked.find("/*")
    assert opener == -1, (
        f"{css.name}:{src.count(chr(10), 0, opener) + 1}: `/*` is never closed. "
        "Every rule after it is swallowed by the comment."
    )


@pytest.mark.parametrize("css", _css_files(), ids=lambda p: p.name)
def test_no_comment_swallows_a_later_block(css: Path):
    """A comment whose BODY contains `/*` has eaten a later comment, and every
    rule between them.

    ⛔ This is the failure a terminator-counting check cannot see. Delete one
    `*/` and the orphaned `/*` simply pairs with the next terminator further
    down; openers and closers stay balanced, nothing looks wrong, and every
    rule in between is silently gone. The only textual trace is that the
    resulting comment body now contains a comment opener.

    Measured on this tree: **0** of the 134 comments across all four
    stylesheets legitimately contain a nested `/*`, so this signal carries no
    false positives here. Planting a removed terminator produces exactly one
    hit, spanning 30 swallowed lines.
    """
    src = css.read_text(encoding="utf-8")
    offenders = []
    for m in _COMMENT.finditer(src):
        body = m.group(0)[2:]  # skip this comment's own opener
        if "/*" in body:
            line = src.count("\n", 0, m.start()) + 1
            offenders.append(
                f"{css.name}:{line}: comment spans {body.count(chr(10))} lines "
                f"and contains a nested `/*`; a terminator is missing above it"
            )
    assert not offenders, (
        "a comment has swallowed a later comment and every rule between them:\n  "
        + "\n  ".join(offenders)
    )


def test_the_rule_this_guard_was_written_for_is_reachable():
    """The specific regression. `.status-line .status-error` was the casualty.

    ⚠️ Asserting the rule's TEXT is present would pass even while the browser
    drops it, which is the exact failure this file exists for. So this asserts
    the structural precondition instead: no stray terminator appears before it
    in the file. The behavioural half needs a browser and lives in
    `internal/tools/scope_aware_classes.py`.

    ⛔ Searched in the COMMENT-STRIPPED source, not the raw text. The first
    version of this test searched raw source and passed against a tree where
    the rule had been renamed away, because the comment above it still spelled
    the old name. A guard that a comment can satisfy is not a guard. Proven by
    planting the rename.
    """
    src = (_STATIC / "lynceus.css").read_text(encoding="utf-8")
    masked = _COMMENT.sub(lambda m: " " * len(m.group(0)), src)

    idx = masked.find(".status-line .status-error")
    assert idx != -1, (
        "`.status-line .status-error` is not present as REAL css (mentions "
        "inside comments do not count). If the rule was deliberately removed, "
        "delete this test rather than loosening it."
    )
    assert "*/" not in masked[:idx], (
        "a stray `*/` appears before `.status-line .status-error`, so the rule "
        "is being parsed as part of an invalid selector and dropped"
    )
