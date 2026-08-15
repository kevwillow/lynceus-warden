"""One malformed UI entry must not destroy every other suppression.

`_load_ui_entries` validated the file as a whole (`Allowlist(**data)`), so a
single bad entry discarded all of them. `_read_ui_yaml` — the read half of the
UI's read-modify-write — did no schema validation at all.

⭐ Those two facts together are the bug: the WRITER was strictly more permissive
than the READER, so an entry the reader rejected got appended-to and written
back on the next UI click, entrenching the corruption forever while every read
returned nothing. The operator kept clicking "Allowlist this device", kept being
told it worked, and nothing was ever suppressed again.

Measured on the shipped code, with a file truncated mid-write (a power cut, or
SD-card rot on the Pi this runs on):

    5 UI suppressions -> truncate -> readable: 0
    operator adds one more via the UI          -> readable: 0
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lynceus.allowlist import (  # noqa: E402
    AllowlistEntry,
    _load_ui_entries,
    add_ui_entry,
)


def _seed(ui_path: Path, n: int = 5) -> None:
    for i in range(n):
        add_ui_entry(
            ui_path,
            AllowlistEntry(
                pattern=f"aa:bb:cc:dd:ee:0{i}",
                pattern_type="mac",
                note=f"neighbour {i}",
            ),
        )


@pytest.fixture()
def ui(tmp_path):
    p = tmp_path / "allowlist_ui.yaml"
    _seed(p)
    assert len(_load_ui_entries(p)) == 5, "precondition: the seed must load"
    return p


def _truncate(p: Path) -> None:
    """Cut the file in half — the shape a power cut leaves behind.

    ⚠️ The result is still VALID YAML: it parses to a list whose last element
    is missing `pattern_type`. That is what made this survive review — the file
    does not look corrupt, it looks fine and is quietly rejected.
    """
    text = p.read_text()
    p.write_text(text[: len(text) // 2])


def test_one_bad_entry_does_not_discard_the_good_ones(ui):
    """Before: 0 of 5 survived. The operator lost every suppression."""
    _truncate(ui)
    survivors = _load_ui_entries(ui)
    assert len(survivors) >= 2, (
        f"only {len(survivors)} suppressions survived a partial corruption; "
        "one malformed entry is discarding its neighbours"
    )
    assert all(e.pattern_type == "mac" for e in survivors)


def test_a_ui_write_repairs_the_file(ui):
    """⭐ The half that made it permanent. The writer must not preserve an
    entry the reader rejects, or every future read stays empty and every
    future UI click silently does nothing."""
    _truncate(ui)
    add_ui_entry(
        ui,
        AllowlistEntry(pattern="ff:ff:ff:ff:ff:ff", pattern_type="mac", note="new"),
    )
    after = _load_ui_entries(ui)
    patterns = {e.pattern for e in after}
    assert "ff:ff:ff:ff:ff:ff" in patterns, (
        "the newly added suppression is not readable — the UI reported success "
        "and did nothing"
    )
    assert len(after) >= 3, f"the surviving entries were discarded: {patterns}"

    # And a second write must be stable, not lossy.
    before = len(after)
    add_ui_entry(
        ui,
        AllowlistEntry(pattern="ee:ee:ee:ee:ee:ee", pattern_type="mac", note="two"),
    )
    assert len(_load_ui_entries(ui)) == before + 1

    # ⭐ The file must be REPAIRED, not merely tolerated. Per-entry validation
    # on the READ side alone makes a preserved bad entry harmless-but-permanent
    # — every load pays the warning and the file never heals. Asserting only
    # "the entries are readable" cannot tell those two apart, which is exactly
    # what a planted defect on the writer proved: it stayed green.
    import yaml as _yaml

    raw = _yaml.safe_load(ui.read_text())
    assert all(
        isinstance(e, dict) and "pattern_type" in e for e in raw["entries"]
    ), f"the malformed entry is still in the file after a UI write: {raw}"


def test_an_intact_file_is_untouched(ui):
    """⚠️ The 'good thing must still happen' twin. Dropping every entry would
    pass the tests above trivially, and repairing a healthy file would be a
    silent rewrite of the operator's data."""
    before = ui.read_text()
    entries = _load_ui_entries(ui)
    assert len(entries) == 5
    assert ui.read_text() == before, "reading rewrote an intact file"


def test_totally_unparseable_yaml_still_fails_soft(ui):
    """The daemon must not crash because the sibling file is rubbish."""
    ui.write_text("\x00\x00 not: [yaml")
    assert _load_ui_entries(ui) == []


def test_a_non_list_entries_key_is_handled(ui):
    """A structurally wrong file is not the same as a corrupt one."""
    ui.write_text("entries: not-a-list\n")
    assert _load_ui_entries(ui) == []


def test_rubbish_that_parses_as_yaml_still_warns(ui, caplog):
    """⚠️ A regression I nearly shipped, caught by the existing suite.

    `yaml.safe_load(":::not valid yaml:::")` does not raise — it returns the
    dict `{':::not valid yaml::': None}`. The original code fed that to
    `Allowlist(**data)`, whose `extra="forbid"` rejected it and logged. Moving
    to per-entry validation made the no-`entries`-key case return `[]` in
    silence, so the operator would lose every UI suppression with nothing said.

    ⭐ An empty mapping is the ordinary "nothing written yet" state and must
    stay quiet; a NON-empty mapping with no `entries` key is a corrupt file and
    must not.
    """
    import logging

    ui.write_text(":::not valid yaml:::")
    with caplog.at_level(logging.WARNING, logger="lynceus.allowlist"):
        assert _load_ui_entries(ui) == []
    assert any("could not be parsed" in r.message for r in caplog.records), (
        "a corrupt-but-parseable UI file was dropped silently"
    )


def test_an_empty_file_is_silent(ui, caplog):
    """The other side: no warning for the normal pre-first-write state."""
    import logging

    ui.write_text("{}\n")
    with caplog.at_level(logging.WARNING, logger="lynceus.allowlist"):
        assert _load_ui_entries(ui) == []
    assert not [r for r in caplog.records if "could not be parsed" in r.message], (
        "an empty UI file warned; that is the normal state and will train "
        "operators to ignore the warning"
    )
