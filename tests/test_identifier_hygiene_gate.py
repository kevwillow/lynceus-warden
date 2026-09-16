"""The standalone hygiene gate must not drift from the product's own sets.

`scripts/check_identifier_hygiene.py` inlines the reserved-prefix sets instead
of importing them, because importing `lynceus.rules` needs PyYAML and a gate
that can be silenced by a packaging failure is not a gate. The cost of inlining
is drift, so it is paid here, where the full environment exists.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

from lynceus import rules

_GATE = Path(__file__).resolve().parents[1] / "scripts" / "check_identifier_hygiene.py"


def _gate():
    spec = importlib.util.spec_from_file_location("_hygiene_gate", _GATE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_the_gates_inlined_reserved_sets_match_the_products():
    gate = _gate()
    assert gate._RESERVED_OUI_PREFIXES_EXACT == rules._RESERVED_OUI_PREFIXES_EXACT
    assert (
        gate._RESERVED_MAC_PREFIXES_TWO_OCTET
        == rules._RESERVED_MAC_PREFIXES_TWO_OCTET
    )


def test_the_gate_imports_nothing_from_the_package():
    """⛔ The whole point of inlining. If someone reinstates the import, the
    gate starts depending on the package installing — and a CI job that skips
    the install gets ModuleNotFoundError instead of a hygiene result."""
    src = _GATE.read_text(encoding="utf-8")
    offenders = [
        line.strip()
        for line in src.splitlines()
        if line.strip().startswith(("import lynceus", "from lynceus"))
    ]
    assert not offenders, (
        f"the gate imports from the package again: {offenders}. "
        "Inline the constant and assert it here instead."
    )


def test_the_locally_administered_bit_is_what_decides():
    gate = _gate()
    # Globally administered: bit 1 of the first octet CLEAR -> could be real.
    assert gate._could_identify_a_real_device("00:0c:41:82:b2:55")
    assert gate._could_identify_a_real_device("dc:a6:32:aa:bb:cc")
    # Locally administered: bit 1 SET -> assigned to nobody, all four nibbles.
    for octet in ("02", "06", "0a", "0e", "ff", "bb", "37", "f3"):
        mac = f"{octet}:11:22:33:44:55"
        assert not gate._could_identify_a_real_device(mac), mac
    # The product's reserved prefixes.
    assert not gate._could_identify_a_real_device("00:00:00:11:22:33")
    assert not gate._could_identify_a_real_device("33:33:00:00:00:01")
