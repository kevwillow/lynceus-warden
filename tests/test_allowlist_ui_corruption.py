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
    """Cut the file after a complete line, leaving VALID YAML.

    ⚠️ The result still parses: a list whose last element is missing
    `pattern_type`. That is what made the original bug survive review — the file
    does not look corrupt, it looks fine and is quietly rejected.

    ⭐ This is only ONE of the two shapes a truncation can take, and the
    distinction is not cosmetic. A cut landing mid-token produces a
    `ScannerError` and is unrecoverable by design (see
    `test_totally_unparseable_yaml_still_fails_soft`); a cut landing on a line
    boundary is recoverable, and that recovery is what this module is about.

    🪤 Which shape you get depends on incidental fixture details — entries
    carrying a `note` are three lines instead of two, so the half-way cut lands
    differently. A fixture chosen for convenience silently decided which code
    path the whole file exercised. Both shapes are now asserted explicitly
    rather than left to arithmetic.
    """
    lines = p.read_text().splitlines(keepends=True)
    # Keep whole lines, then drop the tail of the last entry so it is
    # structurally incomplete but still parseable.
    p.write_text("".join(lines[: len(lines) // 2]))


def _truncate_mid_token(p: Path) -> None:
    """Cut inside a MAC so the file ends on a dangling `:`, which YAML cannot
    scan at all.

    ⚠️ Not every mid-token cut does this — `pattern: aa:bb:cc` is perfectly
    valid YAML on its own, and my first attempt at this helper cut there and
    quietly asserted nothing. Measured across every cut point in a 5-entry
    file: 105 of 334 raise, so roughly a THIRD of truncations are
    unrecoverable and two thirds are not. The trailing colon is what breaks
    the scanner.
    """
    text = p.read_text()
    cut = text.index("pattern: aa:bb:cc:dd:ee:03") + len("pattern: aa:bb:")
    p.write_text(text[:cut])


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


def test_an_absurd_expiry_is_rejected_at_the_boundary():
    """`expires_at` was an unrestricted `int`, and the poller formats it:

        _dt.datetime.fromtimestamp(entry.expires_at, tz=_dt.UTC)

    Measured with a hand-edit typo of `expires_at: 99999999999999` — the kind
    an extra keypress makes — `process_observation` raised `ValueError: year
    3170843 is out of range`, AFTER the device and sighting were persisted and
    both counters advanced. That device is then unprocessable on every tick it
    appears, and the poll watermark is held and eventually advanced past it.

    ⭐ Validated at the model, not at the format call: this is the boundary
    where operator-authored YAML enters, and a bad value should be rejected
    once with a legible message rather than raising from an unrelated line on
    every poll.
    """
    from pydantic import ValidationError

    for bad in (99999999999999, -1):
        with pytest.raises(ValidationError, match="representable Unix timestamp"):
            AllowlistEntry(
                pattern="aa:bb:cc:dd:ee:01", pattern_type="mac", expires_at=bad
            )

    # ⚠️ The twin: a representable epoch must still be accepted, or the
    # validator is just an off-switch for expiring entries.
    ok = AllowlistEntry(
        pattern="aa:bb:cc:dd:ee:01", pattern_type="mac", expires_at=253_402_300_799
    )
    assert ok.expires_at == 253_402_300_799
    assert (
        AllowlistEntry(pattern="aa:bb:cc:dd:ee:01", pattern_type="mac").expires_at
        is None
    )


def test_a_bad_expiry_drops_only_its_own_entry(tmp_path):
    """The two fixes must compose: rejected at the boundary, and the rejection
    costs only that entry rather than the whole file."""
    import yaml as _yaml

    ui = tmp_path / "allowlist_ui.yaml"
    ui.write_text(
        _yaml.safe_dump(
            {
                "entries": [
                    {"pattern": "aa:bb:cc:dd:ee:01", "pattern_type": "mac"},
                    {
                        "pattern": "aa:bb:cc:dd:ee:02",
                        "pattern_type": "mac",
                        "expires_at": 99999999999999,
                    },
                    {"pattern": "aa:bb:cc:dd:ee:03", "pattern_type": "mac"},
                ]
            }
        )
    )
    kept = {e.pattern for e in _load_ui_entries(ui)}
    assert kept == {"aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:03"}, (
        f"one bad expiry took its neighbours with it: {kept}"
    )


def test_both_truncation_shapes_are_covered(ui):
    """⭐ Pins the distinction the fixture used to decide by accident.

    A truncation lands either on a line boundary (valid YAML, incomplete last
    entry → RECOVERABLE) or mid-token (`ScannerError` → not recoverable, and
    deliberately so). The module's central claim only holds for the first, and
    before this the test suite exercised whichever one the fixture's line count
    happened to produce.
    """
    import yaml as _yaml

    line_cut = ui.read_text()
    _truncate(ui)
    _yaml.safe_load(ui.read_text())  # must not raise: this is the valid shape
    assert len(_load_ui_entries(ui)) >= 2, "the recoverable shape lost everything"

    ui.write_text(line_cut)
    _truncate_mid_token(ui)
    with pytest.raises(_yaml.YAMLError):
        _yaml.safe_load(ui.read_text())  # must raise: this is the other shape
    assert _load_ui_entries(ui) == [], (
        "an unscannable file should fail soft to empty, not raise"
    )
