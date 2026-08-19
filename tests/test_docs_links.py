"""Every relative link in the shipped docs must resolve to a file that exists.

⚠️ **Why this is a test and not a link checker.** It deliberately does NOT
touch the network. An external link checker in CI is a gate that goes red when
someone else's site rate-limits a runner, and this repo's whole position is
that a gate which fails for reasons unrelated to the change is a gate people
learn to ignore. Relative links are different: whether `docs/RULES.md` exists is
a fact about *this* commit, decidable offline, and it is the half that actually
rots — a doc gets renamed and six other files keep pointing at the old name.

⭐ **Why it matters more here than in most repos.** The README is 34 KB of
claims that invite a stranger to go and check them, and most of that checking
happens by following a link. A 404 on `CONTRIBUTING.md` from the paragraph
telling you to read it is the first thing a visitor sees.

🪤 **What this CANNOT see.** Anchors. `[x](docs/RULES.md#missing-heading)`
passes as long as the *file* exists — the fragment is stripped before the
existence check, because heading-to-anchor slugification differs between
GitHub, mkdocs and every other renderer, and encoding one renderer's rules here
would make the guard wrong somewhere else. External `http(s)` links are not
checked at all.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from urllib.parse import unquote

_ROOT = Path(__file__).resolve().parents[1]

#: `[text](target)`. Reference-style and bare autolinks are not matched; inline
#: is the form these docs use.
_LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")

#: Not documentation the project ships. `internal/` is already gitignored, so
#: `git ls-files` excludes it anyway — this is belt-and-braces for the day it
#: stops being ignored. It is working notes (audit reports, handoffs, rig
#: output) which reference throwaway paths on purpose.
_EXCLUDED_TOPLEVEL = {"internal", ".venv", "build", "dist", "node_modules"}


def _tracked_markdown() -> list[Path]:
    """Markdown files as git sees them.

    ⛔ `git ls-files`, not `rglob`. A glob would sweep up untracked scratch
    notes in a developer's worktree — and, in the direction that matters, would
    silently return nothing if the layout changed.
    """
    out = subprocess.run(
        ["git", "ls-files", "*.md"],
        cwd=_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    return [
        _ROOT / p
        for p in out
        if Path(p).parts[0] not in _EXCLUDED_TOPLEVEL
    ]


def _relative_targets(text: str) -> list[str]:
    targets = []
    for match in _LINK.finditer(text):
        raw = match.group(1).strip()
        # `[x](path "title")` — the title is not part of the path.
        target = raw.split()[0] if raw.split() else ""
        if not target or target.startswith(("http://", "https://", "mailto:", "#", "<")):
            continue
        targets.append(target)
    return targets


def test_the_docs_set_is_not_empty():
    """⛔ Guards the test below: an empty file list would pass it vacuously."""
    docs = _tracked_markdown()
    assert len(docs) >= 10, (
        f"only {len(docs)} tracked markdown files found; expected the shipped docs set. "
        "Either the docs moved or `git ls-files` returned nothing."
    )
    names = {p.name for p in docs}
    for required in ("README.md", "CONTRIBUTING.md", "SECURITY.md"):
        assert required in names, f"{required} is not in the scanned set"


def test_every_relative_doc_link_resolves():
    docs = _tracked_markdown()
    broken: list[str] = []
    checked = 0
    for doc in docs:
        text = doc.read_text(encoding="utf-8", errors="replace")
        for target in _relative_targets(text):
            # Strip the anchor: see the module docstring for why fragments are
            # deliberately not validated.
            path_part = unquote(target.split("#", 1)[0])
            if not path_part:
                continue
            checked += 1
            if not (doc.parent / path_part).resolve().exists():
                broken.append(f"{doc.relative_to(_ROOT)} -> {target}")

    assert checked > 0, "no relative links were checked; this assertion would be vacuous"
    assert not broken, (
        f"{len(broken)} broken relative link(s) out of {checked} checked:\n  "
        + "\n  ".join(broken)
    )
