"""Duplicate-key detection over hand-edited YAML.

The premise, re-measured here rather than assumed, is that `yaml.safe_load`
resolves a duplicate key by keeping the LAST one and saying nothing. A test
docstring in this repo asserted the opposite ("would break yaml.safe_load with
a 'duplicate key' error and the daemon would fail to start"), which is a good
reason to pin the real behaviour beside the detector that exists because of it.
"""

from __future__ import annotations

import yaml

from lynceus.yaml_duplicates import find_duplicate_keys


def _write(tmp_path, body: str):
    p = tmp_path / "f.yaml"
    p.write_text(body, encoding="utf-8")
    return p


def test_pyyaml_keeps_the_last_duplicate_silently(recwarn):
    """The premise. If this ever fails, the detector may be unnecessary --
    which is a far better reason to revisit it than someone's recollection."""
    assert yaml.safe_load("a: 1\na: 2") == {"a": 2}
    assert recwarn.list == []


def test_no_duplicates_in_a_clean_file(tmp_path):
    p = _write(tmp_path, "entries:\n  - pattern: x\n    pattern_type: mac\n")
    assert find_duplicate_keys(p) == []


def test_a_repeated_top_level_key_is_found(tmp_path):
    p = _write(tmp_path, "alpha: 1\nbeta: 2\nalpha: 3\n")
    (dupe,) = find_duplicate_keys(p)
    assert dupe.key_path == "alpha"
    assert dupe.first_line == 1
    assert dupe.winning_line == 3


def test_a_repeated_key_inside_a_list_item_is_found_with_its_path(tmp_path):
    p = _write(
        tmp_path,
        (
            "entries:\n"
            "  - pattern: a\n"
            "    pattern_type: mac\n"
            "  - pattern: b\n"
            "    pattern: c\n"
            "    pattern_type: mac\n"
        ),
    )
    (dupe,) = find_duplicate_keys(p)
    assert dupe.key_path == "entries[1].pattern"
    assert (dupe.first_line, dupe.winning_line) == (4, 5)


def test_the_same_key_in_sibling_mappings_is_not_a_duplicate(tmp_path):
    """The control. Every list entry has a `pattern`; that is the normal
    shape of these files, not a defect. A detector that flags it would be
    unusable and would train operators to ignore the real one."""
    p = _write(
        tmp_path,
        (
            "entries:\n"
            "  - pattern: a\n"
            "    pattern_type: mac\n"
            "  - pattern: b\n"
            "    pattern_type: mac\n"
        ),
    )
    assert find_duplicate_keys(p) == []


def test_a_nested_mapping_duplicate_is_found(tmp_path):
    p = _write(
        tmp_path,
        "device_category_severity:\n  drone: high\n  tracker: low\n  drone: low\n",
    )
    (dupe,) = find_duplicate_keys(p)
    assert dupe.key_path == "device_category_severity.drone"
    assert (dupe.first_line, dupe.winning_line) == (2, 4)


def test_several_duplicates_are_all_reported_in_file_order(tmp_path):
    p = _write(tmp_path, "a: 1\nb: 2\na: 3\nb: 4\n")
    assert [d.key_path for d in find_duplicate_keys(p)] == ["a", "b"]


def test_an_unparseable_file_reports_nothing(tmp_path):
    """The caller reports parse errors itself; the same fault described
    twice in different words is worse than once."""
    p = _write(tmp_path, "entries: [unbalanced\n")
    assert find_duplicate_keys(p) == []


def test_a_missing_file_reports_nothing(tmp_path):
    assert find_duplicate_keys(tmp_path / "nope.yaml") == []


def test_an_empty_file_reports_nothing(tmp_path):
    assert find_duplicate_keys(_write(tmp_path, "")) == []


def test_the_message_names_both_lines_and_which_one_wins(tmp_path):
    p = _write(tmp_path, "alpha: 1\nalpha: 2\n")
    (dupe,) = find_duplicate_keys(p)
    msg = dupe.describe()
    assert "line 1" in msg and "line 2" in msg
    assert "LAST" in msg
