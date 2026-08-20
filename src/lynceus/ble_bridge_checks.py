"""Pre-flight readiness checks for the passive BLE bridge — stdlib-only.

Enabling the bridge has five known ways to produce an install that looks
healthy and is not. Three are decidable from configuration alone, with no
adapter and no hardware, which is what lets the setup wizard warn an operator
before they commit and lets the web UI explain a bridge that is switched on
and contributing nothing. The other two are decidable only from the
environment, and live in their own functions so ``check_bridge_readiness``
stays pure.

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

The fifth, ``check_bluez_advertisement_monitor`` (BLE-G8), is the one that
actually bit. BlueZ only exposes ``AdvertisementMonitorManager1`` when
``bluetoothd`` runs with experimental features on, and bleak's passive scan
needs that interface. Measured on a host with BlueZ 5.72 and kernel 7.0.0 —
both comfortably above the minimums the bridge's own error message quotes —
with ``bleak`` installed, the adapter free, and the config clean: **every one
of the four checks above returned green and the bridge still captured
nothing**, looping "BLE scan failed (passive scanning on Linux requires
BlueZ >= 5.56 with --experimental enabled...)" forever. The version floors
were satisfied; the interface was simply absent, because ``Experimental`` was
commented out in ``/etc/bluetooth/main.conf``.

That also orders the gates. ``adapter_contention`` (G6) presumes the bridge
could otherwise open an adapter; without the monitor interface it cannot, so
G8 sits upstream of G6 and ``collect_bridge_warnings`` reports it first.

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
import shutil
import subprocess
import sys
from collections.abc import Iterable
from dataclasses import dataclass

CHECK_ADAPTER_CONTENTION = "adapter_contention"
CHECK_SOURCE_GATE = "source_gate"
CHECK_NO_DECODED_CLASS_CONSUMER = "no_decoded_class_consumer"
CHECK_RAW_COMPANY_ID_RULE = "raw_company_id_rule"
CHECK_BLEAK_MISSING = "bleak_missing"
CHECK_BLUEZ_NO_ADV_MONITOR = "bluez_no_advertisement_monitor"

# The rule type that consults the Continuity class the bridge decodes.
_DECODED_CLASS_RULE_TYPE = "ble_device_class"

# The D-Bus interface bleak's passive scan needs. BlueZ publishes it per
# adapter object, and only when bluetoothd is running with experimental
# features enabled.
_ADV_MONITOR_INTERFACE = "org.bluez.AdvertisementMonitorManager1"

# What proves the object we introspected is a real adapter. Required because
# `busctl introspect` on a path that does not exist EXITS 0 and prints only
# its header row -- measured against /org/bluez/hci9 on a two-adapter host.
# Without this, a typo'd adapter name would look exactly like a real adapter
# missing the monitor interface, and we would hand the operator a confident
# "enable experimental features" remedy for a device that is not plugged in.
_ADAPTER_INTERFACE = "org.bluez.Adapter1"

# systemd's D-Bus client. Used rather than a Python D-Bus binding because this
# module is stdlib-only by contract, and rather than parsing
# /etc/bluetooth/main.conf because the file is not the truth: bluetoothd can
# be given --experimental on its command line, and an edited-but-not-restarted
# daemon still reports the old state. Introspection asks the running daemon.
_BUSCTL = "busctl"

# Introspection is a local socket round-trip and normally answers in
# milliseconds. The bound exists so a wedged bluetoothd cannot hang a caller.
_BUSCTL_TIMEOUT_SECONDS = 5.0


def _is_linux() -> bool:
    """Indirection point for tests — patch this, not ``sys.platform``.

    Same rule as ``paths._platform`` and ``cli.quickstart._is_linux``:
    ``sys`` is the interpreter-wide singleton, so patching its ``platform``
    steers every other reader in the process too.
    """
    return sys.platform.startswith("linux")


# Import name of the BLE library the bridge scans with. The bridge imports it
# lazily (bridges/ble.py) so the module stays importable off-rig; that same
# tolerance is why a missing install surfaces as silence rather than a crash.
_BLEAK_MODULE = "bleak"

# The extra that installs it. Kept next to the module name so the remedy text
# and pyproject's optional-dependencies table are edited together.
_BLEAK_EXTRA = "ble"

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
            f"For an install.sh deployment that means the venv pip directly, e.g. "
            f"`~/.local/share/lynceus/.venv/bin/pip install 'lynceus[{_BLEAK_EXTRA}]'` "
            f"(--user scope) or `/opt/lynceus/.venv/bin/pip install 'lynceus[{_BLEAK_EXTRA}]'` "
            f"(--system). install.sh does not install it: the bridge ships off, so the "
            f"dependency stays opt-in with it."
        ),
    )


def check_bluez_advertisement_monitor(adapter: str) -> BridgeWarning | None:
    """Report BlueZ not exposing the interface the passive scan needs.

    Asks the running ``bluetoothd`` whether ``AdvertisementMonitorManager1``
    is published on this adapter's object. When it is not, the bridge starts,
    logs its "requires BlueZ >= 5.56 with --experimental" line on a loop, and
    captures nothing — while every config gate and the bleak check all report
    green, because none of them can see this.

    One-directional, exactly like ``check_bleak_available``, and for the same
    reason: only a *proven* absence warns. Every ambiguous outcome stays
    silent, because this module's contract is "nothing known is wrong", never
    "proven to work". Silence therefore covers all of:

    - not Linux (the interface is BlueZ-specific; bleak uses CoreBluetooth or
      WinRT elsewhere, where this question is meaningless)
    - no ``busctl`` on PATH (a non-systemd host, or a trimmed container)
    - ``busctl`` failing for any reason — bluetoothd not running, the adapter
      object absent, D-Bus policy refusing the caller. These are not
      distinguishable from each other by exit code, and at least one of them
      (adapter absent) is already the subject of a different, clearer failure,
      so guessing here would produce a confident wrong remedy.

    Not for a hot path. This spawns a process, so callers that render per
    request (the web UI) should cache it or call it at startup, unlike
    ``check_bleak_available``, which is a dict lookup.
    """
    if not _is_linux():
        return None
    if shutil.which(_BUSCTL) is None:
        return None
    try:
        proc = subprocess.run(
            [_BUSCTL, "--system", "introspect", "org.bluez", f"/org/bluez/{adapter}"],
            capture_output=True,
            text=True,
            timeout=_BUSCTL_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        # Includes TimeoutExpired. Unusable answer either way; stay silent.
        return None
    if proc.returncode != 0:
        return None
    if _ADAPTER_INTERFACE not in proc.stdout:
        # Not a real adapter object: no such adapter, or BlueZ is not
        # publishing it. Either way this check has nothing to say. See
        # _ADAPTER_INTERFACE for why exit code alone cannot tell us.
        return None
    if _ADV_MONITOR_INTERFACE in proc.stdout:
        return None
    return BridgeWarning(
        code=CHECK_BLUEZ_NO_ADV_MONITOR,
        summary=(
            f"BlueZ is running but does not publish {_ADV_MONITOR_INTERFACE} on "
            f"{adapter}, which is the interface the bridge's passive scan opens. "
            "This is what experimental features gate, and it is independent of "
            "version: a BlueZ and kernel that both clear the bridge's stated "
            "minimums still fail here. The bridge will start, log a scan-failed "
            "warning on a loop, and capture nothing."
        ),
        remedy=(
            "Enable experimental features and restart the daemon:\n"
            "  sudo sed -i 's/^#Experimental = false/Experimental = true/' "
            "/etc/bluetooth/main.conf\n"
            "  sudo systemctl restart bluetooth\n"
            "Then confirm the interface appeared:\n"
            f"  busctl --system introspect org.bluez /org/bluez/{adapter} | "
            "grep AdvertisementMonitor"
        ),
    )


def collect_bridge_warnings(
    *,
    adapter: str,
    kismet_sources: Iterable[str] | None,
    enabled_rule_types: Iterable[str] | None,
) -> tuple[BridgeWarning, ...]:
    """Every readiness finding — environment first, then the config gates.

    What operator-facing surfaces should call. Ordered most-blocking first, so
    an operator reading top-down fixes the thing that makes the rest academic:
    with no scan library nothing else matters, and with no
    ``AdvertisementMonitorManager1`` the bridge cannot open an adapter at all,
    which makes the contention and source-gate findings moot.

    ⚠️ Spawns a subprocess via ``check_bluez_advertisement_monitor``. Fine for
    the setup wizard and a startup check; cache it on a per-request surface.

    Kept as a separate composer rather than folded into
    ``check_bridge_readiness`` so that function keeps its pure,
    config-only contract for callers that want exactly that.
    """
    environment = (
        check_bleak_available(),
        check_bluez_advertisement_monitor(adapter),
    )
    config_gates = check_bridge_readiness(
        adapter=adapter,
        kismet_sources=kismet_sources,
        enabled_rule_types=enabled_rule_types,
    )
    return tuple(w for w in environment if w is not None) + config_gates


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

    # Sits AFTER the two gates that presume the bridge is actually feeding
    # observations in (adapter_contention, source_gate): with either of those
    # tripped, no decoded class ever lands, so a "nothing consumes it" warning
    # would be noise the operator cannot act on. Sits BEFORE the noisy-rule
    # warning, because a missing consumer is the more-blocking failure --
    # even after disabling the noisy rule the bridge still alerts on nothing.
    # ⛔ Keyed on `enabled_rule_types is not None`, NOT on `rule_types` being
    # non-empty, and the difference is the whole point. `None` means the CALLER
    # DOES NOT KNOW the rule state -- the setup wizard runs before a ruleset
    # exists -- and warning there would be a guess. An EMPTY tuple means the
    # caller looked and found no enabled rules, which is the WORST case: nothing
    # alerts at all. Collapsing the two suppresses the warning exactly where it
    # matters most, which is the defect this check was added to fix, reappearing
    # inside its own fix.
    if enabled_rule_types is not None and _DECODED_CLASS_RULE_TYPE not in rule_types:
        found.append(
            BridgeWarning(
                code=CHECK_NO_DECODED_CLASS_CONSUMER,
                summary=(
                    "The bridge decodes an Apple Continuity class for every Apple "
                    "device it hears, including Find My trackers, and no enabled "
                    "rule consults it -- so those adverts are decoded, counted "
                    "and recorded, and raise no alert ON THAT BASIS. Such a device "
                    "can still match your other rules by MAC, vendor or SSID."
                ),
                remedy=(
                    "Enable the apple_find_my block in config/rules.yaml -- it is "
                    "the rule that matches the decoded class."
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
                    "Requires both the bridge enabled AND a ble_device_class rule. "
                    "Disable this rule and enable the apple_find_my block in "
                    "config/rules.yaml."
                ),
            )
        )

    return tuple(found)
