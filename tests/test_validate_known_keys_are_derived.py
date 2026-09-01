"""`lynceus-validate`'s known-key set must not fall behind the model.

⛔ It was a hand-written literal and it drifted twice. `vendor_severity` and
`suppress_pattern_categories` both existed on `rules.RuntimeSeverityOverride`
while the validator did not know them, so `lynceus-validate` reported an
operator's WORKING configuration as containing an "unknown key".

That is worse than no validation. The tool whose job is to check your config
told you a setting does not exist, which invites deleting the line that was
doing the work. The file was a real
`suppress_pattern_categories: {ble_manufacturer_id: [unknown]}` holding back a
continuous alert storm at the time it was called unknown.

⚠️ **This docstring used to claim "~8,000 would-be alerts a day". That figure
was never measured.** It was ``shadow_seen`` (the denominator: how often the
field was OBSERVED) read as a hit count, extrapolated from 65 seconds, taken
from a run whose database contains no ``shadow:<rule>`` key and no
``shadow_since`` at all, meaning zero hits were ever recorded there.

Re-measured 2026-08-31, one adapter, same corpus, 350s per arm:

    suppression OFF -> 22 hits / 22 observations   (100%, ~4,200/day here)
    suppression ON  ->  0 hits / 19 observations

So the storm is real and the suppression removes it completely; only the
published number was wrong. ⇒ The three-valued reading exists for exactly this
reason: a count is meaningless without its denominator, and the denominator is
not the count.
"""

from __future__ import annotations

from lynceus.cli.validate import SEVERITY_OVERRIDES_KNOWN_KEYS
from lynceus.rules import RuntimeSeverityOverride


def test_every_runtime_model_field_is_a_known_key():
    """The ratchet. Adding a field to the model can no longer make the
    validator call it unknown."""
    missing = sorted(set(RuntimeSeverityOverride.model_fields) - set(SEVERITY_OVERRIDES_KNOWN_KEYS))
    assert missing == [], (
        f"lynceus-validate does not know these runtime override keys: {missing}. "
        f"An operator using them would be told their working config contains an "
        f"unknown key."
    )


def test_the_runtime_half_is_derived_not_transcribed():
    """⚠️ Asserting the CURRENT names would pass against a fresh transcription
    and rot again the next time someone adds a field. This asserts the
    relationship instead: whatever the model holds, the validator knows.
    """
    known = set(SEVERITY_OVERRIDES_KNOWN_KEYS)
    assert set(RuntimeSeverityOverride.model_fields) <= known


def test_the_import_time_keys_are_still_present():
    """The import-time half is not modelled anywhere, so it stays a literal and
    must not be lost when the runtime half became derived."""
    for key in (
        "vendor_overrides",
        "geographic_filter",
        "confidence_downgrade_threshold",
        "argus_schema_version_accept_list",
    ):
        assert key in SEVERITY_OVERRIDES_KNOWN_KEYS, f"import-time key {key!r} was dropped"


def test_there_are_no_duplicates():
    """The two halves overlap on nothing today, but the union is built with
    dict.fromkeys precisely so a future overlap cannot produce a duplicate."""
    assert len(SEVERITY_OVERRIDES_KNOWN_KEYS) == len(set(SEVERITY_OVERRIDES_KNOWN_KEYS))
