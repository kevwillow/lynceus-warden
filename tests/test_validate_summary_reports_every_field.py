"""`lynceus-validate`'s summary line must report every runtime override field.

⛔ Measured 2026-09-01 against a real operator file whose ONLY content was

    suppress_pattern_categories:
      ble_manufacturer_id: [unknown]

The validator printed "0 remap(s), 0 suppressed category(ies), 0 suppressed
vendor(s), 0 pattern override(s)" and never mentioned the one key the file
actually contained. That file was holding back a measured 100% match rate on
the BLE manufacturer-ID rule. A validator that reports a load-bearing
suppression as nothing at all invites deleting it.

🪤 **This is the same defect as #254, in the same module, one function away.**
#254 derived `SEVERITY_OVERRIDES_KNOWN_KEYS` from the model so validation could
not fall behind it, and left the *summary* as a hand-written list of four field
names. Both omitted exactly `vendor_severity` and `suppress_pattern_categories`.
Fixing a transcription in one place does not fix its siblings.
⇒ Ask what ELSE transcribes the same model.

The fix derives the reported set from `RuntimeSeverityOverride.model_fields`
and keeps the human labels in a lookup that can only affect wording, never
membership.
"""

from __future__ import annotations

from lynceus.cli.validate import (
    _RUNTIME_OVERRIDE_LABELS,
    _summarise_runtime_overrides,
)
from lynceus.rules import RuntimeSeverityOverride


def test_every_model_field_appears_in_the_summary():
    """The ratchet. Adding a field to the model cannot leave it unreported.

    ⚠️ Asserts on the RELATIONSHIP, not on today's six names. Listing the
    current names would pass against a fresh transcription and rot on the next
    field added, which is precisely how the bug this file exists for was born.
    """
    loaded = RuntimeSeverityOverride()
    summary = _summarise_runtime_overrides(loaded)
    missing = [
        name
        for name in RuntimeSeverityOverride.model_fields
        if _RUNTIME_OVERRIDE_LABELS.get(name, name) not in summary
    ]
    assert missing == [], (
        f"the validator's summary line does not report these runtime override "
        f"fields: {missing}. An operator using them would be told their file "
        f"contains nothing."
    )


def test_a_lone_suppress_pattern_categories_file_is_not_reported_as_empty():
    """The exact regression, with the exact shape that was mis-reported."""
    loaded = RuntimeSeverityOverride(
        suppress_pattern_categories={"ble_manufacturer_id": frozenset({"unknown"})}
    )
    assert not loaded.is_empty(), "fixture is wrong; this file is not empty"

    summary = _summarise_runtime_overrides(loaded)
    assert "1 suppressed pattern_category(ies)" in summary, (
        f"a file whose only content is suppress_pattern_categories was summarised as {summary!r}"
    )


def test_zero_counts_are_still_printed():
    """ "Absent" and "present but empty" must not look identical.

    An operator reads this line to confirm the setting they wrote is being
    seen. Dropping the zeros would make a typo'd key indistinguishable from a
    key that parsed to nothing.
    """
    loaded = RuntimeSeverityOverride(suppress_categories=frozenset({"unknown"}))
    summary = _summarise_runtime_overrides(loaded)
    assert "0 vendor remap(s)" in summary
    assert "1 suppressed category(ies)" in summary


def test_the_label_map_cannot_drop_a_field():
    """A missing label degrades to the raw field name; it never omits it.

    ⛔ The label map is wording only. If it were the source of membership, a
    forgotten entry would silently hide a field, recreating the bug.
    """
    loaded = RuntimeSeverityOverride(
        suppress_pattern_categories={"ble_manufacturer_id": frozenset({"unknown"})}
    )
    saved = dict(_RUNTIME_OVERRIDE_LABELS)
    try:
        _RUNTIME_OVERRIDE_LABELS.pop("suppress_pattern_categories")
        summary = _summarise_runtime_overrides(loaded)
        assert "suppress_pattern_categories" in summary, (
            "with its label removed the field vanished from the summary; "
            "membership is coming from the label map, not from the model"
        )
    finally:
        _RUNTIME_OVERRIDE_LABELS.clear()
        _RUNTIME_OVERRIDE_LABELS.update(saved)
