"""CLI wizard prompt for the passive BLE bridge.

tests/ is gitignored — these are NEVER committed (see project memory).

Covers the prompt itself and the "warn, then allow" contract: the operator
is told what would stop the bridge working here, and is still allowed to
switch it on anyway.
"""

from __future__ import annotations

import io
from contextlib import redirect_stdout

from lynceus.ble_bridge_checks import check_bridge_readiness, collect_bridge_warnings
from lynceus.cli import setup as wiz


def _run_capture(fn, *args, **kwargs) -> tuple[object, str]:
    buf = io.StringIO()
    with redirect_stdout(buf):
        result = fn(*args, **kwargs)
    return result, buf.getvalue()


def test_default_answer_is_off():
    """Enabling must stay an explicit opt-in, never a default."""
    answer, _ = _run_capture(
        wiz.prompt_yes_no,
        "Enable the passive BLE bridge on hci1?",
        default=False,
        input_fn=lambda _: "",
    )
    assert answer is False


def test_contended_adapter_produces_a_warning_with_a_remedy():
    """The wizard's warning source — an operator who put hci1 in kismet_sources."""
    warnings = check_bridge_readiness(
        adapter="hci1",
        kismet_sources=["wlan0", "hci1"],
        enabled_rule_types=(),
    )
    assert warnings
    assert any("hci1" in w.summary for w in warnings)
    assert all(w.remedy for w in warnings)


def test_warnings_do_not_block_enabling():
    """'Warn, then allow' — a warned operator can still say yes."""
    assert wiz.prompt_yes_no(
        "Enable the passive BLE bridge on hci1?",
        default=False,
        input_fn=lambda _: "y",
    ) is True


def test_wizard_reexports_the_adapter_default():
    """The prompt names the adapter, so it must resolve the real default."""
    from lynceus.config import BleBridgeConfig

    assert wiz._DEFAULT_BLE_ADAPTER == BleBridgeConfig().adapter


def test_check_is_importable_from_the_cli_namespace():
    """Tests and the wizard both reach the checks through this binding.

    The wizard binds the composer, not the pure config-only check: an
    operator being asked whether to enable the bridge needs to hear that
    the scan library is missing, which is not a config fact.
    """
    assert wiz.collect_bridge_warnings is collect_bridge_warnings
