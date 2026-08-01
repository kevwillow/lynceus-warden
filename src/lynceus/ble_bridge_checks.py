"""Pre-flight readiness checks for the passive BLE bridge — pure, stdlib-only.

Enabling the bridge has three known ways to produce an install that looks
healthy and is not. All three are decidable from configuration alone, with no
adapter and no hardware, which is what lets the setup wizard warn an operator
before they commit and lets the web UI explain a bridge that is switched on
and contributing nothing.

The checks correspond to the enablement gates in ``BACKLOG.md``:

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

This module deliberately reports rather than decides. Every finding carries a
remedy, and the caller chooses whether to warn, block, or ignore.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

CHECK_ADAPTER_CONTENTION = "adapter_contention"
CHECK_SOURCE_GATE = "source_gate"
CHECK_RAW_COMPANY_ID_RULE = "raw_company_id_rule"

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
