"""Pre-flight readiness checks for the passive BLE bridge — stdlib-only.

Enabling the bridge has four known ways to produce an install that looks
healthy and is not. Three are decidable from configuration alone, with no
adapter and no hardware, which is what lets the setup wizard warn an operator
before they commit and lets the web UI explain a bridge that is switched on
and contributing nothing. The fourth is decidable from the environment, and
lives in its own function so ``check_bridge_readiness`` stays pure.

The config checks correspond to the enablement gates in ``BACKLOG.md``:

- ``adapter_contention`` (BLE-G6) — Kismet holds a datasource for the life of
  the daemon, so if it is configured on the bridge's adapter the bridge can
  never open it.
- ``source_gate`` (BLE-G2) — the poller admits an observation only when one of
  its ``seen_by_sources`` is in ``kismet_sources``. The bridge stamps
  ``ble:<adapter>``, which is a synthetic name Kismet's own source list will
  never contain, so an operator who listed only real adapters silently drops
  every bridge observation.
- ``raw_company_id_rule`` (BLE-G1) — a rule matching ``ble_manufacturer_id``
  fires on a whole vendor. The Continuity decoder does not rescue this: that
  rule matches company id, not device class.

The fourth check, ``check_bleak_available`` (BLE-G7), is the one an operator
hits by default rather than by misconfiguration: ``bleak`` is an optional
extra, so a stock install does not have it and an enabled bridge logs a single
warning at startup and then captures nothing for the rest of its life. It is
kept out of ``check_bridge_readiness`` because that function is pure and
answers from config alone; this one probes the interpreter.

This module deliberately reports rather than decides. Every finding carries a
remedy, and the caller chooses whether to warn, block, or ignore.

Known limitation, and it is a false-negative one: the contention check compares
the adapter against ``kismet_sources`` by exact string. Kismet datasources can
be given arbitrary names (``source=hci1:type=linuxbluetooth,name=local_bt``),
and the wizard stores whichever form the operator picked, so a renamed source
on the bridge's adapter will not be spotted. An empty result therefore means
"nothing known is wrong", never "proven to work" — only a live capture shows
that. Substring matching was considered and rejected: it would flag unrelated
adapters whose names happen to overlap, and a warning an operator learns to
ignore is worse than one that is occasionally absent.
"""

from __future__ import annotations

import importlib.util
from collections.abc import Iterable
from dataclasses import dataclass

CHECK_ADAPTER_CONTENTION = "adapter_contention"
CHECK_SOURCE_GATE = "source_gate"
CHECK_RAW_COMPANY_ID_RULE = "raw_company_id_rule"
CHECK_BLEAK_MISSING = "bleak_missing"

# Import name of the BLE library the bridge scans with. The bridge imports it
# lazily (bridges/ble.py) so the module stays importable off-rig; that same
# tolerance is why a missing install surfaces as silence rather than a crash.
_BLEAK_MODULE = "bleak"

# The extra that installs it. Kept next to the module name so the remedy text
# and pyproject's optional-dependencies table are edited together.
_BLEAK_EXTRA = "ble"

# Where install.sh puts the venv for each scope. The operator cannot use a
# bare `pip install` here: the lynceus commands are symlinks into a venv that
# is deliberately never activated, so `pip` on their PATH is the system one
# and would install bleak somewhere the daemon never looks. These paths are
# install.sh's layout (create_or_update_venv), and they live here because the
# remedy text is the only thing that has ever needed them.
_VENV_PIP = {
    "user": "~/.local/share/lynceus/.venv/bin/pip",
    "system": "/opt/lynceus/.venv/bin/pip",
}


def bleak_install_command(scope: str | None = None) -> str:
    """The exact command that installs the bridge's scan library.

    ``scope`` is ``"user"`` or ``"system"`` when the caller knows which one
    it is, which the setup wizard does. Anything else, including ``None``,
    yields the editable-clone form, because that is what is left when the
    layout is not install.sh's.

    Returned rather than printed so the CLI wizard, the web wizard, and the
    /settings panel all quote the same string instead of three drifting
    copies of it.
    """
    pip = _VENV_PIP.get(scope or "")
    if pip is None:
        return f"pip install -e '.[{_BLEAK_EXTRA}]'"
    return f"{pip} install 'lynceus[{_BLEAK_EXTRA}]'"

# The rule type that matches a bare Bluetooth SIG company identifier.
_RAW_COMPANY_ID_RULE_TYPE = "watchlist_ble_manufacturer_id"


@dataclass(frozen=True)
class BridgeWarning:
    """One readiness finding. ``remedy`` is what the operator should do."""

    code: str
    summary: str
    remedy: str


def bridge_source_name(adapter: str) -> str:
    """Provenance the bridge stamps on its observations.

    Single source of truth for the ``ble:<adapter>`` form, which appears both
    in ``BleBridge._build_observation`` and in the source-gate allowlist an
    operator has to write by hand.
    """
    return f"ble:{adapter}"


def check_bleak_available() -> BridgeWarning | None:
    """Report the bridge's scan library being absent from this interpreter.

    ``bleak`` is an optional extra, so the default install does not have it.
    An enabled bridge in that state logs one warning at daemon start and then
    behaves exactly like a working bridge that has heard nothing — which is
    the failure this module exists to make legible, and the only one of the
    four that an operator gets without misconfiguring anything.

    Uses ``find_spec`` rather than an import: the answer is wanted by the web
    UI and the setup wizard, and neither should pull bleak's asyncio and
    D-Bus machinery into its process just to ask a yes/no question.

    Deliberately one-directional. A missing package is decisive, so it warns.
    A present package is NOT a claim that the bridge will work — bleak also
    needs BlueZ >= 5.55 and an adapter, neither of which is visible from
    here — so the check stays silent rather than implying more than it knows,
    matching this module's "nothing known is wrong" contract.
    """
    try:
        found = importlib.util.find_spec(_BLEAK_MODULE) is not None
    except (ImportError, ValueError):
        # A broken or partially-removed install can raise instead of
        # returning None. Unusable either way, so treat it as missing.
        found = False
    if found:
        return None
    return BridgeWarning(
        code=CHECK_BLEAK_MISSING,
        summary=(
            f"The {_BLEAK_MODULE} library is not installed, so the bridge cannot "
            "open a scan at all. It is an optional dependency and a default "
            "install does not include it. An enabled bridge will log one "
            "warning at startup and then capture nothing, looking identical "
            "to a working bridge with nothing in range."
        ),
        remedy=(
            f"Install the optional extra that provides it, then restart the daemon. "
            f"Use the venv's pip directly, not the one on your PATH: "
            f"`{bleak_install_command('user')}` for a --user install, or "
            f"`{bleak_install_command('system')}` for --system. From a clone, "
            f"`{bleak_install_command()}`. install.sh does not install it, because "
            f"the bridge ships off and the dependency stays opt-in with it."
        ),
    )


def collect_bridge_warnings(
    *,
    adapter: str,
    kismet_sources: Iterable[str] | None,
    enabled_rule_types: Iterable[str] | None,
) -> tuple[BridgeWarning, ...]:
    """Every readiness finding — environment first, then the config gates.

    What operator-facing surfaces should call. ``check_bleak_available`` leads
    because it is the most fundamental: with no scan library the adapter and
    source-gate findings are academic, so an operator reading top-down fixes
    the blocking problem first.

    Kept as a separate composer rather than folded into
    ``check_bridge_readiness`` so that function keeps its pure,
    config-only contract for callers that want exactly that.
    """
    environment = check_bleak_available()
    config_gates = check_bridge_readiness(
        adapter=adapter,
        kismet_sources=kismet_sources,
        enabled_rule_types=enabled_rule_types,
    )
    return ((environment,) if environment else ()) + config_gates


def check_bridge_readiness(
    *,
    adapter: str,
    kismet_sources: Iterable[str] | None,
    enabled_rule_types: Iterable[str] | None,
) -> tuple[BridgeWarning, ...]:
    """Findings that would make an enabled bridge useless or noisy.

    An empty result means nothing known is wrong — not that the bridge is
    proven to work, which only a live capture shows.
    """
    sources = tuple(kismet_sources or ())
    rule_types = tuple(enabled_rule_types or ())
    found: list[BridgeWarning] = []

    if adapter in sources:
        found.append(
            BridgeWarning(
                code=CHECK_ADAPTER_CONTENTION,
                summary=(
                    f"Kismet is configured to capture on {adapter}, which is the same "
                    "adapter the BLE bridge needs. Kismet holds a datasource for as "
                    "long as it runs, so the bridge will never be able to open it."
                ),
                remedy=(
                    f"Give the bridge an adapter of its own: remove {adapter} from "
                    "kismet_sources and from Kismet's own source= lines, or point "
                    "ble_bridge.adapter at a different adapter."
                ),
            )
        )

    # An unset source list means no filter at all, so there is no gate to fail.
    if sources and bridge_source_name(adapter) not in sources:
        found.append(
            BridgeWarning(
                code=CHECK_SOURCE_GATE,
                summary=(
                    "kismet_sources is set but does not list "
                    f"'{bridge_source_name(adapter)}'. The bridge stamps its "
                    "observations with that name, so every one of them will be "
                    "dropped by the source filter — it will scan and buffer "
                    "correctly while contributing nothing."
                ),
                remedy=(
                    f"Add '{bridge_source_name(adapter)}' to kismet_sources, or clear "
                    "kismet_sources entirely to disable source filtering."
                ),
            )
        )

    if _RAW_COMPANY_ID_RULE_TYPE in rule_types:
        found.append(
            BridgeWarning(
                code=CHECK_RAW_COMPANY_ID_RULE,
                summary=(
                    f"A {_RAW_COMPANY_ID_RULE_TYPE} rule is enabled. That matches a "
                    "Bluetooth company identifier, which covers an entire vendor — "
                    "'004c' is every Apple device in range. With the bridge feeding "
                    "it, this alerts on every passing phone and pair of earbuds."
                ),
                remedy=(
                    "Disable that rule and use a ble_device_class rule instead, which "
                    "matches the decoded Continuity class (e.g. find_my_separated) "
                    "rather than the vendor."
                ),
            )
        )

    return tuple(found)
