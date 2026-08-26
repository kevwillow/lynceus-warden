"""Contract tests for the zero-cover surfaces of `cli/_adapter_descriptors.py`.

Measured at `c64a194`: the module reports 60% line cover from the whole
tracked suite, and the 25 missed statements are `format_adapter_descriptor`
in its entirety (lines 217-244) plus the parent-resolution failure branch of
`_read_sysfs_optional_walkup` (108-109). The sysfs readers are reached
indirectly through the wizard and bootstrap tests; the formatter is reached
by nothing. It is the module's only public symbol and the one whose output
an operator actually reads, on the web wizard's step-4 rows and on the
bootstrap prompt.

No tracked test file referenced this module before this one. The reason is
`.gitignore`: `tests/test_adapter_descriptors.py` and the two wizard sysfs
matrix files are withheld because they embed the operator's real capture
adapter MAC. That is the right call for those files and the wrong outcome
for CI, which could not see the formatter at all.

Each test pins a promise `format_adapter_descriptor`'s own docstring makes.
The six strings in `DOCUMENTED_DESCRIPTORS` are quoted verbatim from lines
190-201 of the module and were confirmed against the real function before
being written down -- a docstring is only a contract once you have run it.
Asserting full-string equality is deliberate: a `·` separator that drifts,
a bus that stops being uppercased, or a lead and an annotation that swap
places all still satisfy a substring or a truthiness check.

⛔ SYNTHETIC NAMES ONLY. This file is committed and published. The
identities below (`Alfa AWUS036ACS`, `Realtek`, the `148f:7610` and
`0bda:8812` chipset IDs, `wlan0`, `hci0`) are the module's own published
docstring examples and the canonical synthetic interface set. No `wlx*`
interface names, no `00:c0:ca` OUI, no real-looking MAC, no username, no
hostname -- that rule is why the original file is withheld.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from lynceus.cli import _adapter_descriptors as ad

# --- format_adapter_descriptor: the documented contract ---------------------

# (id, adapter row, exact rendering) -- quoted from the docstring, lines 190-201.
DOCUMENTED_DESCRIPTORS = [
    (
        "external-usb-dongle",
        {
            "vendor": "Alfa",
            "product": "Alfa AWUS036ACS",
            "usb_id": "148f:7610",
            "bus": "usb",
            "driver": "rt2800usb",
            "removable": "removable",
        },
        "Alfa AWUS036ACS 148f:7610 · USB · rt2800usb driver",
    ),
    (
        "builtin-bt-on-internal-hub",
        {
            "vendor": None,
            "product": None,
            "usb_id": None,
            "bus": "usb",
            "driver": "btusb",
            "removable": "fixed",
        },
        "Internal · btusb driver",
    ),
    (
        "vendor-only-no-product-string",
        {
            "vendor": "Realtek",
            "product": None,
            "usb_id": "0bda:8812",
            "bus": "usb",
            "driver": "rtl88xxau",
            "removable": "removable",
        },
        "Realtek 0bda:8812 · USB · rtl88xxau driver",
    ),
    (
        "usb-id-only-no-strings",
        {
            "vendor": None,
            "product": None,
            "usb_id": "148f:7610",
            "bus": "usb",
            "driver": "rt2800usb",
            "removable": "removable",
        },
        "148f:7610 · USB · rt2800usb driver",
    ),
    (
        "internal-soc-driver-only",
        {
            "vendor": None,
            "product": None,
            "usb_id": None,
            "bus": "sdio",
            "driver": "brcmfmac",
            "removable": None,
        },
        "SDIO · brcmfmac driver",
    ),
    (
        "nothing-readable",
        {
            "vendor": None,
            "product": None,
            "usb_id": None,
            "bus": None,
            "driver": None,
            "removable": None,
        },
        "",
    ),
]


@pytest.mark.parametrize(
    ("adapter", "expected"),
    [(row, text) for _, row, text in DOCUMENTED_DESCRIPTORS],
    ids=[name for name, _, _ in DOCUMENTED_DESCRIPTORS],
)
def test_each_documented_example_renders_exactly_as_the_docstring_promises(adapter, expected):
    """The six worked examples in the docstring are the module's public
    contract with two callers that must agree with each other. If one of
    these drifts, the wizard and the bootstrap CLI start describing the
    same dongle differently and the operator cannot tell two same-kind
    adapters apart, which is the whole reason the module exists."""
    assert ad.format_adapter_descriptor(adapter) == expected


def test_only_the_exact_value_fixed_relabels_the_bus_as_internal():
    """Docstring: "Any other ``removable`` value (``"removable"``,
    ``"unknown"``, ``None``) leaves the bus name unchanged so external
    dongles still annotate with ``USB``". The comparison is exact, so the
    kernel's other documented values and an unset attribute all fall
    through to the bus name. Pinned because widening this test to a
    truthiness or case-insensitive check would let an external dongle
    render as "Internal", which reads to an operator as "this adapter is
    soldered in" -- the opposite of the truth."""
    row = {"bus": "usb", "driver": "btusb"}

    assert ad.format_adapter_descriptor({**row, "removable": "fixed"}) == "Internal · btusb driver"

    for unchanged in ("removable", "unknown", None, "", "FIXED", "Fixed", "fixed "):
        assert ad.format_adapter_descriptor({**row, "removable": unchanged}) == (
            "USB · btusb driver"
        ), f"removable={unchanged!r} must not relabel the bus"


def test_the_product_string_leads_when_both_it_and_the_vendor_are_readable():
    """`human = product or vendor`. The product string is the model name
    printed on the dongle, so it is the more specific identity and wins.
    A row carrying both must not render the vendor, and must not render
    the two concatenated."""
    rendered = ad.format_adapter_descriptor(
        {"vendor": "Alfa", "product": "Alfa AWUS036ACS", "usb_id": "148f:7610", "bus": "usb"}
    )
    assert rendered == "Alfa AWUS036ACS 148f:7610 · USB"


def test_the_vendor_leads_only_when_no_product_string_was_readable():
    rendered = ad.format_adapter_descriptor(
        {"vendor": "Realtek", "product": None, "usb_id": "0bda:8812", "bus": "usb"}
    )
    assert rendered == "Realtek 0bda:8812 · USB"


def test_a_bus_name_is_uppercased_and_a_driver_is_suffixed_with_the_word_driver():
    """The two annotation shapes, isolated. `kismet_sources.html` renders
    the same convention, so a change here silently desynchronises the web
    template from the CLI."""
    assert ad.format_adapter_descriptor({"bus": "pci"}) == "PCI"
    assert ad.format_adapter_descriptor({"driver": "brcmfmac"}) == "brcmfmac driver"
    assert ad.format_adapter_descriptor({"bus": "pci", "driver": "brcmfmac"}) == (
        "PCI · brcmfmac driver"
    )


def test_a_lead_with_no_readable_annotations_stands_alone_without_a_separator():
    """Guards the `lead + "".join(...)` branch against growing a trailing
    separator when the annotation list is empty."""
    assert ad.format_adapter_descriptor({"product": "Alfa AWUS036ACS"}) == "Alfa AWUS036ACS"
    assert ad.format_adapter_descriptor({"usb_id": "148f:7610"}) == "148f:7610"


def test_extra_keys_on_a_full_enumeration_row_are_ignored():
    """Docstring: "additional keys on the dict are ignored, so callers can
    pass full ``enumerate_capture_adapters`` rows directly". Both callers
    do exactly that, so a formatter that started reading a seventh key
    would change their output without either caller changing."""
    minimal = {"product": "Alfa AWUS036ACS", "usb_id": "148f:7610", "bus": "usb"}
    full_row = {
        **minimal,
        "name": "wlan0",
        "kind": "wifi",
        "phy": "phy0",
        "monitor_capable": True,
        "vendor": None,
        "driver": None,
        "removable": None,
    }
    assert ad.format_adapter_descriptor(full_row) == ad.format_adapter_descriptor(minimal)


def test_a_row_missing_every_key_renders_empty_rather_than_raising():
    """The formatter reads through `.get`, so a caller that hands it a
    row assembled before enrichment gets the empty lead the docstring
    documents -- and the caller falls back to the bare interface name --
    instead of a KeyError inside a wizard step."""
    assert ad.format_adapter_descriptor({}) == ""


# --- _read_sysfs_optional_walkup: the parent-resolution failure branch ------


def test_the_walkup_returns_none_when_resolving_the_parent_raises(tmp_path, monkeypatch):
    """Lines 108-109. Every other reader in this module answers "no info"
    rather than raising, because the wizard renders a sparser label instead
    of crashing mid-enumeration. This branch is the walk-up's share of that
    promise and nothing reached it. Pinned by making `resolve` fail, since
    the layouts that make it fail for real are not constructible in a
    tmp_path fixture."""
    device_dir = tmp_path / "device"
    device_dir.mkdir()

    def boom(self, *args, **kwargs):
        raise OSError("synthetic resolve failure")

    monkeypatch.setattr(Path, "resolve", boom)

    assert ad._read_sysfs_optional_walkup(device_dir, "manufacturer") is None


def test_the_walkup_prefers_an_interface_level_attribute_over_the_parent(tmp_path):
    """The interface-level read short-circuits before the walk-up, so a
    kernel that exposes the attribute directly is never overridden by the
    parent's value."""
    parent = tmp_path / "1-1.2"
    device_dir = parent / "1-1.2:1.0"
    device_dir.mkdir(parents=True)
    (device_dir / "manufacturer").write_text("interface-level\n")
    (parent / "manufacturer").write_text("parent-level\n")

    assert ad._read_sysfs_optional_walkup(device_dir, "manufacturer") == "interface-level"
