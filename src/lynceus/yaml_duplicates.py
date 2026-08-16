"""Find duplicate mapping keys in an operator-authored YAML file.

``yaml.safe_load`` resolves a duplicate key by keeping the LAST one, silently:

    >>> yaml.safe_load("a: 1\\na: 2")
    {'a': 2}

No error, no warning, on PyYAML 6.0.3. Every loader in this project uses
``yaml.safe_load``, so on every operator-authored file a duplicate key means the
value the operator can see at the top of their file is not the value in force,
and nothing anywhere says so.

⛔ The codebase believed the opposite. ``tests/test_setup_wizard.py`` justified
its no-duplicate-key guard with *"The duplicate would break yaml.safe_load with
a 'duplicate key' error and the daemon would fail to start"*. It does not, and
the daemon does not: it starts, and quietly uses the last value. That guard is
correct and stays; only its stated reason was wrong. A belief that duplicates
are self-detecting is a good explanation for why nothing checked for them.

⚠️ This module REPORTS; it does not decide what to do. The allowlist loader
warns (a duplicate is not grounds to drop every suppression in the file) while
``lynceus-validate`` raises it as an error, which is the split
``cli/validate.py`` already documents: the daemon is lenient at runtime, the
validator is louder so the typo surfaces at edit time rather than as a confused
silence at the next restart.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(frozen=True)
class DuplicateKey:
    """One key that appears more than once in the same mapping.

    ``key_path`` is the dotted route to the mapping that holds it, including
    list indices, e.g. ``entries[0].pattern``. ``first_line`` and
    ``winning_line`` are 1-indexed; the value on ``winning_line`` is the one
    ``yaml.safe_load`` keeps.
    """

    key_path: str
    first_line: int
    winning_line: int

    def describe(self) -> str:
        return (
            f"duplicate key {self.key_path!r}: defined on line "
            f"{self.first_line} and again on line {self.winning_line} -- "
            f"YAML keeps the LAST one, so the value on line "
            f"{self.winning_line} is the one in force"
        )


def _format_path(prefix: tuple[object, ...], key: str) -> str:
    out = ""
    for part in prefix:
        if isinstance(part, int):
            out += f"[{part}]"
        else:
            out = f"{out}.{part}" if out else str(part)
    return f"{out}.{key}" if out else key


def _walk(node: yaml.Node, prefix: tuple[object, ...], out: list[DuplicateKey]) -> None:
    if isinstance(node, yaml.MappingNode):
        # ⚠️ Keyed on the RAW scalar text, not on the resolved value. Resolving
        # would make `on:` and `true:` collide as keys, which is a different
        # (and much rarer) complaint than the one this module exists to report.
        seen: dict[str, int] = {}
        for key_node, value_node in node.value:
            if not isinstance(key_node, yaml.ScalarNode):
                # A complex key (a list or mapping used as a key). Legal YAML,
                # never produced by hand-editing these files; skipped rather
                # than guessed at.
                _walk(value_node, prefix, out)
                continue
            key = str(key_node.value)
            line = key_node.start_mark.line + 1
            if key in seen:
                out.append(
                    DuplicateKey(
                        key_path=_format_path(prefix, key),
                        first_line=seen[key],
                        winning_line=line,
                    )
                )
            else:
                seen[key] = line
            _walk(value_node, prefix + (key,), out)
    elif isinstance(node, yaml.SequenceNode):
        for i, item in enumerate(node.value):
            _walk(item, prefix + (i,), out)


def find_duplicate_keys(path: Path) -> list[DuplicateKey]:
    """Duplicate mapping keys in ``path``, in file order.

    Returns an empty list when the file is absent, unreadable, or does not
    parse -- every caller reports those conditions itself, and a parse error
    reported twice in different words is worse than one reported once.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            node = yaml.compose(fh)
    except (OSError, yaml.YAMLError):
        return []
    out: list[DuplicateKey] = []
    if node is not None:
        _walk(node, (), out)
    return out
