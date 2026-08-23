#!/usr/bin/env python3
"""Syntax-check the first-party JavaScript that lives INSIDE Jinja templates.

The `web-assets` job checked `git ls-files '*.js'`, which is two files: a
vendored `htmx.min.js` and `lynceus.js`. Every other line of first-party
JavaScript this product ships is written inline in a `<script>` block in a
template, and was parsed by nothing:

    10.6 KB across 11 inline blocks in 6 templates

A gate keyed on a file EXTENSION reports on the extension. A syntax error in
any of those blocks reaches the operator's browser as a silently dead page --
the CSP work in this repo deliberately moved behaviour OUT of `on*=` attributes
and INTO these blocks, so they are where the interaction now lives.

⚠️ The blocks are Jinja templates, not JavaScript, so they cannot be fed to
`node --check` as they stand. This de-sugars them using **Jinja's own lexer**
rather than a regex over `{{`/`{%`:

  - `{{ expr }}` becomes the literal `0`, a valid JS expression.
  - `{% ... %}` and `{# ... #}` are dropped, keeping the text between them.

🪤 Using a regex here is wrong in a way that is not obvious and that produced a
confidently wrong answer while this was being written. `\\{\\{.*?\\}\\}` with
DOTALL matches from a real Jinja expression all the way to the next `}}` in
ordinary JavaScript -- and `}}` occurs whenever two blocks close together, which
is constantly. It silently swallowed hundreds of lines of real code.

🪤 And the templates carry long `{# ... #}` commentary that itself discusses
`<script>` tags. Searching the raw template for `<script` therefore matches
inside a comment and captures prose as if it were code. The de-sugaring has to
happen to the WHOLE template first, and the script blocks found in the result.

Exit 1 on any parse failure, on `node` being absent, or on finding zero blocks
-- a gate that silently checks nothing is worse than no gate, because it reports
success.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from jinja2 import Environment

# ⛔ `</script\b[^>]*>`, not `</script>`. Two ways an end tag legally differs
# from the tight form, and CodeQL's py/bad-tag-filter caught BOTH -- the
# second only after the first was fixed, which is the argument for reading the
# alert rather than patching until it goes quiet:
#
#   </script >     whitespace before the `>`
#   </script bar>  attributes, which HTML permits in an end tag and ignores
#
# Measured against `<script>var a = 1;</script >` followed by prose and a
# second block, the tight pattern produced ONE match whose body was:
#
#     'var a = 1;</script >\n<p>not javascript at all, this is prose</p>\n<script>var b = 2;'
#
# i.e. it swallowed the closing tag, the HTML between, and the next block --
# so the gate would report a parse failure on prose, or merge two blocks and
# stop checking one of them. A malformed-input bug in the tool that exists to
# catch malformed input.
_SCRIPT_RE = re.compile(r"<script\b([^>]*)>(.*?)</script\b[^>]*>", re.S | re.I)

# autoescape is irrelevant here -- this Environment is used ONLY as a lexer
# (`env.lex`) and never renders anything, so no output reaches a browser. It
# is set anyway: leaving a HIGH `py/jinja2/autoescape-false` alert standing
# because "we know it is fine" is how a real one later gets waved through.
_env = Environment(autoescape=True)


def dejinja(text: str) -> str:
    """Template text with Jinja constructs replaced by JS-valid filler."""
    out: list[str] = []
    for _lineno, token, value in _env.lex(text):
        if token == "data":
            out.append(value)
        elif token == "variable_begin":
            out.append("0")
    return "".join(out)


def inline_blocks(template: str) -> list[str]:
    """Inline `<script>` bodies from a de-sugared template, `src=` ones skipped."""
    blocks = []
    for attrs, body in _SCRIPT_RE.findall(dejinja(template)):
        if "src=" in attrs.lower() or not body.strip():
            continue
        blocks.append(body)
    return blocks


def main() -> int:
    if shutil.which("node") is None:
        print("::error::node not on PATH; nothing would be checked", file=sys.stderr)
        return 1

    repo = Path(__file__).resolve().parent.parent
    files = subprocess.run(
        ["git", "ls-files", "*.html"],
        cwd=repo, capture_output=True, text=True, check=True,
    ).stdout.split()

    checked = failed = total_bytes = 0
    for name in files:
        path = repo / name
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            print(f"::error file={name}::could not read: {exc}")
            failed += 1
            continue
        for index, body in enumerate(inline_blocks(text)):
            checked += 1
            total_bytes += len(body.encode())
            with tempfile.NamedTemporaryFile(
                "w", suffix=".js", delete=False, encoding="utf-8"
            ) as handle:
                handle.write(body)
                tmp = handle.name
            result = subprocess.run(
                ["node", "--check", tmp], capture_output=True, text=True
            )
            Path(tmp).unlink(missing_ok=True)
            if result.returncode:
                failed += 1
                print(f"::error file={name}::inline <script> #{index} does not parse")
                for line in result.stderr.strip().splitlines():
                    print(f"    {line}")
            else:
                print(f"  ok: {name} inline <script> #{index} ({len(body)} bytes)")

    print(f"checked {checked} inline block(s), {total_bytes} bytes")
    if checked == 0:
        print(
            "::error::no inline <script> blocks found; this gate would prove "
            "nothing. Either the de-sugaring broke or the templates moved.",
            file=sys.stderr,
        )
        return 1
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
