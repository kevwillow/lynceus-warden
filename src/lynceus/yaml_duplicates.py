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

import logging
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

    ``occurrence_lines`` holds every line the key appears on, in file order.
    ⛔ It exists because reporting duplicates PAIRWISE produced a false
    statement: on ``a: 1 / a: 2 / a: 3`` the old code emitted one record per
    repeat, and the first said *"line 2 is the one in force"* when
    ``safe_load`` keeps line 3. An operator following that message edits line 2
    and leaves the value that is actually in force untouched. One record per
    duplicated key now, with the real winner.
    """

    key_path: str
    first_line: int
    winning_line: int
    occurrence_lines: tuple[int, ...] = ()

    def describe(self) -> str:
        if len(self.occurrence_lines) > 2:
            middle = ", ".join(str(n) for n in self.occurrence_lines[1:-1])
            return (
                f"duplicate key {self.key_path!r}: defined on line "
                f"{self.first_line}, again on line {middle}, and again on line "
                f"{self.winning_line} -- YAML keeps the LAST one, so the value "
                f"on line {self.winning_line} is the one in force"
            )
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


_CONSTRUCTOR = yaml.constructor.SafeConstructor()


def _key_identity(key_node: yaml.ScalarNode) -> tuple[str, object]:
    """The identity `safe_load` will use for this key, not its raw text.

    ⛔ Raw text was wrong in BOTH directions, and each direction shipped:

    * false NEGATIVE -- `on:` and `true:` are different text and the same
      Python key (`True`) under YAML 1.1, so a real collapse went unreported.
    * false POSITIVE -- `on:` and `"on":` are the SAME text and different
      Python keys (`True` and `'on'`), so the tool warned that a value had
      been discarded when nothing had. That is the worse half: it is this
      module telling an operator something untrue about their own file.

    Resolving through PyYAML's own constructor makes both agree with the
    loader by construction rather than by a rule we maintain separately.
    Unhashable or unconstructible keys fall back to raw text -- they cannot
    collide in a dict anyway, so the fallback cannot invent a duplicate.
    """
    try:
        value = _CONSTRUCTOR.construct_object(key_node, deep=True)
        hash(value)
    except Exception:  # noqa: BLE001 -- fall back, never fail the scan
        return ("raw", key_node.value)
    return ("resolved", value)


def _walk(
    node: yaml.Node,
    prefix: tuple[object, ...],
    out: list[DuplicateKey],
    seen_nodes: set[int] | None = None,
) -> None:
    # ⛔ Cycle guard. A recursive alias is VALID YAML that `yaml.compose`
    # happily represents as a graph:
    #
    #     x: &x
    #       self: *x
    #
    # Without this set the walk recurses forever and raises RecursionError --
    # which `find_duplicate_keys` did not catch, so `lynceus-validate` CRASHED
    # on a file it was asked to report on instead of reporting on it.
    if seen_nodes is None:
        seen_nodes = set()
    if id(node) in seen_nodes:
        return
    seen_nodes.add(id(node))

    if isinstance(node, yaml.MappingNode):
        # Two passes on purpose. The winner is the LAST occurrence, which is
        # not known until the mapping has been read to the end, so nothing can
        # be emitted from inside the collecting loop without guessing.
        seen: dict[tuple[str, object], list[tuple[int, str]]] = {}
        for key_node, value_node in node.value:
            if not isinstance(key_node, yaml.ScalarNode):
                # A complex key (a list or mapping used as a key). Legal YAML,
                # never produced by hand-editing these files; skipped rather
                # than guessed at.
                _walk(value_node, prefix, out, seen_nodes)
                continue
            ident = _key_identity(key_node)
            seen.setdefault(ident, []).append(
                (key_node.start_mark.line + 1, str(key_node.value))
            )
        for occurrences in seen.values():
            if len(occurrences) > 1:
                lines = [line for line, _text in occurrences]
                out.append(
                    DuplicateKey(
                        key_path=_format_path(prefix, occurrences[0][1]),
                        first_line=lines[0],
                        winning_line=lines[-1],
                        occurrence_lines=tuple(lines),
                    )
                )
        # ⛔ Descend only into the value of the WINNING occurrence of each key.
        # Descending into a losing one produced statements that were simply
        # false: for `outer: {x: 1, x: 2}` followed by a second `outer:`, the
        # whole first mapping is discarded, so reporting "outer.x line 3 is the
        # one in force" names a line that is in force of nothing. An operator
        # edits it, nothing changes, and the tool has sent them to the wrong
        # place -- the same defect class this module exists to report.
        winner: dict[tuple[str, object], yaml.Node] = {}
        for key_node, value_node in node.value:
            if isinstance(key_node, yaml.ScalarNode):
                winner[_key_identity(key_node)] = value_node
        for key_node, value_node in node.value:
            if not isinstance(key_node, yaml.ScalarNode):
                continue
            ident = _key_identity(key_node)
            if winner.get(ident) is value_node:
                _walk(value_node, prefix + (str(key_node.value),), out, seen_nodes)
    elif isinstance(node, yaml.SequenceNode):
        for i, item in enumerate(node.value):
            _walk(item, prefix + (i,), out, seen_nodes)


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
    # `_walk` emits each mapping's duplicates before descending, so nested
    # results trail their parent's rather than following the file. Sorting by
    # first definition restores the documented "in file order".
    out.sort(key=lambda d: (d.first_line, d.winning_line))
    return out


def warn_duplicate_keys(
    path: Path | str, *, logger: logging.Logger, subject: str
) -> None:
    """WARN once per duplicate mapping key in ``path``. **Never raises.**

    ``subject`` names the file for the operator, e.g. ``"rules file"``.

    ⛔ **Swallowing every failure is the contract, not tidiness**, and this
    module owns it so the property is implemented and tested ONCE instead of
    re-derived at each call site. The allowlist's own version of this helper
    shipped inside ``_load_primary``'s ``except Exception``, where any raise
    from the diagnostic was reported as *"could not be parsed"* and, under
    ``raise_on_parse_error``, became an ``AllowlistParseError`` -- so at
    startup a **valid** file loaded as **zero entries** and the poller logged
    SUPPRESSION DISABLED. A helper whose only job is to add a warning must
    never be able to change what the caller loads.

    ``find_duplicate_keys`` already absorbs OSError and YAMLError, but
    ``yaml.compose`` on a pathological file can still raise past both
    (RecursionError on deep nesting, MemoryError), which is why the catch here
    is broad rather than narrow.

    ⚠️ This re-reads a file the caller has already parsed. That second read is
    deliberate: ``yaml.safe_load`` has by then collapsed the duplicate and
    cannot be asked which key it discarded.
    """
    try:
        for dupe in find_duplicate_keys(Path(path)):
            logger.warning(
                "%s %s: %s. Check which line you are editing.",
                subject,
                path,
                dupe.describe(),
            )
    except Exception as exc:  # noqa: BLE001 -- see above; never propagate
        # ⛔ The EMIT loop is inside this try, not just the detection call, and
        # that is the whole point. A cold read of the first version found the
        # loop sitting outside it: `logger.warning` is not inert -- a handler,
        # filter or formatter can raise (a full disk on a FileHandler will do
        # it) -- so the helper documented as "Never raises" propagated straight
        # through `load_config` and `load_ruleset` and took the daemon down at
        # startup. The docstring was the defect, not just the code.
        try:
            logger.debug("duplicate-key check skipped for %s (%s)", path, exc)
        except Exception:  # noqa: BLE001 -- the reporter of last resort
            pass
