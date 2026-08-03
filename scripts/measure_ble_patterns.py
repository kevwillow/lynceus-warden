"""On-rig A/B: does the BlueZ monitor survive an 8th OrPattern?

WHY. The bridge scans passively, and BlueZ only delivers adverts that match one
of the monitor's patterns. The current set is 7: Apple manufacturer data plus
six Flags content bytes. An Open Drone ID legacy advert matches NONE of them —
it is a single service-data element that fills all 31 bytes of the legacy
payload (transmitter-linux/bluetooth.c:168-184), so it carries no Flags element
and no manufacturer data. Adding (0, 0x16, FA FF 0D) is therefore mandatory for
the ODID receiver, and it takes the set to 8.

``bridges/ble.py`` says BlueZ "drops the monitor above ~7 patterns" and
``tests/test_ble_scan_or_patterns.py`` asserts <= 7. That limit was inferred
during the spike, never measured directly, and its failure mode is silent: the
scan runs clean, logs nothing, and captures zero. So it has to be measured, not
reasoned about.

ANSWERED 2026-08-03, hci1, matched 20s windows, radio verified powered before
and after every round. Four arms were run to separate the two variables that a
naive A/B confounds -- pattern COUNT versus the new service-data AD type:

    A shipped                7 patterns, no ODID   14 devices / 81 frames
    B shipped + ODID         8 patterns, ODID       0 devices /  0 frames
    C ODID swapped for 0x00  7 patterns, ODID      15 devices / 80 frames
    D extra Flags 0x07       8 patterns, no ODID    0 devices /  0 frames

D is decisive: eight patterns collapse to zero with no ODID involved at all, so
the ceiling is the COUNT. BlueZ has no objection to a service-data pattern -- C
carried it at 7 and matched A within noise. Flags 0x00 was traded away for ODID
and the loss was not detectable over those windows.

WHAT THIS DOES NOW. Re-verifies that finding against the CURRENT shipped set:
A must deliver at 7, B must collapse at 8. Alternates arm order between rounds
so a decaying radio environment cannot masquerade as a result.

This needs bleak, which is deliberately NOT installed in the project venv. Run
it from a throwaway venv:

    python3.11 -m venv /tmp/blevenv && /tmp/blevenv/bin/pip install bleak
    /tmp/blevenv/bin/python scripts/measure_ble_patterns.py --window 20
"""

from __future__ import annotations

import argparse
import asyncio
import re
import subprocess
import sys
import time
from pathlib import Path

from bleak import BleakScanner

try:
    from bleak.args.bluez import BlueZScannerArgs, OrPattern
except ImportError:  # older bleak module layout fallback
    from bleak.backends.bluezdbus.advertisement_monitor import OrPattern
    from bleak.backends.bluezdbus.scanner import BlueZScannerArgs

# Repo-relative: this file lives in scripts/, so parents[1] is the repo root.
BRIDGE = Path(__file__).resolve().parents[1] / "src" / "lynceus" / "bridges" / "ble.py"

FLAGS_AD_TYPE = 0x01
MFR_DATA_AD_TYPE = 0xFF
APPLE_COMPANY_BYTES = b"\x4c\x00"
FLAGS_CONTENT_BYTES = (0x06, 0x1A, 0x02, 0x04, 0x05)

SERVICE_DATA_AD_TYPE = 0x16
ODID_PATTERN_CONTENT = b"\xfa\xff\x0d"  # 0xFFFA little-endian + AD app code 0x0D

# The SHIPPED set as of 2026-08-03: Apple, five Flags bytes, and ODID. Seven.
SHIPPED = (
    ((0, MFR_DATA_AD_TYPE, APPLE_COMPANY_BYTES),)
    + tuple((0, FLAGS_AD_TYPE, bytes([b])) for b in FLAGS_CONTENT_BYTES)
    + ((0, SERVICE_DATA_AD_TYPE, ODID_PATTERN_CONTENT),)
)

# An eighth pattern, deliberately a plain Flags value so the arm tests COUNT and
# nothing else. 0x07 = LE Limited + General Discoverable, absent from the set.
PLUS_ONE = SHIPPED + ((0, FLAGS_AD_TYPE, bytes([0x07])),)

ARMS = (
    ("A shipped 7", SHIPPED),
    ("B shipped+1 = 8", PLUS_ONE),
)


def check_specs_are_current() -> None:
    """Refuse to measure a pattern set the bridge no longer ships.

    A measurement taken against a stale copy of the constants is worse than no
    measurement: it reads as evidence about code that is not running.
    """
    src = BRIDGE.read_text()
    flags = re.search(r"_FLAGS_CONTENT_BYTES = \(([^)]*)\)", src)
    if flags is None:
        sys.exit("⛔ could not find _FLAGS_CONTENT_BYTES in the bridge")
    found = tuple(int(x, 16) for x in re.findall(r"0x[0-9A-Fa-f]+", flags.group(1)))
    if found != FLAGS_CONTENT_BYTES:
        sys.exit(f"⛔ bridge Flags bytes are {found}, this script has {FLAGS_CONTENT_BYTES}")
    if 'b"\\x4c\\x00"' not in src:
        sys.exit("⛔ bridge Apple company bytes are no longer 4c 00")
    print(f"pattern set verified against {BRIDGE}")


def adapter_mac(adapter: str) -> str | None:
    """hciN -> BD address.

    ⚠️ NOT via /sys/class/bluetooth/<hci>/address — that attribute does not
    exist on this kernel (7.0.0); the directory holds only device, power,
    reset, rfkill<N>, subsystem and uevent. ``hcitool dev`` is the portable
    read, but it lists only interfaces that are UP, so unblock first.
    """
    try:
        out = subprocess.run(
            ["hcitool", "dev"],
            capture_output=True,
            text=True,
            timeout=15,
            stdin=subprocess.DEVNULL,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == adapter:
            return parts[1]
    return None


def is_powered(mac: str) -> bool:
    out = subprocess.run(
        ["bluetoothctl", "show", mac],
        capture_output=True,
        text=True,
        timeout=15,
        stdin=subprocess.DEVNULL,
    ).stdout
    return "Powered: yes" in out


def ensure_adapter_ready(adapter: str) -> str:
    """Unblock and power the adapter, or refuse to measure.

    ⛔ A desktop Bluetooth manager may re-assert the rfkill soft block behind
    your back. Measured 2026-08-03 on a box running blueman-applet, whose
    PowerManager plugin does exactly that within about a minute: two A/B runs
    were silently invalidated before anyone noticed, because both arms reported
    0 devices / 0 frames — which is ALSO exactly what "BlueZ dropped the
    monitor" looks like. A harness that cannot tell those two apart is worse
    than no harness, so this refuses to measure rather than guess.
    """
    # Unblock BEFORE resolving: hcitool dev lists only interfaces that are up,
    # so a blocked adapter reads as "no such adapter".
    subprocess.run(["rfkill", "unblock", "bluetooth"], timeout=15, check=False)
    time.sleep(1.0)
    mac = adapter_mac(adapter)
    if mac is None:
        sys.exit(f"⛔ no such adapter: {adapter}")
    subprocess.run(
        ["bluetoothctl", "power", "on"],
        input=f"select {mac}\npower on\nexit\n",
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    time.sleep(1.0)
    if not is_powered(mac):
        sys.exit(
            f"⛔ {adapter} ({mac}) will not stay powered. Something is re-blocking\n"
            f"   it — on this box that is blueman-applet's PowerManager plugin.\n"
            f"   Quit the applet (or run this as root with it stopped) and retry."
        )
    print(f"{adapter} ({mac}) powered and ready")
    return mac


async def one_round(label: str, specs, adapter: str, window: int) -> dict:
    macs: set[str] = set()
    frames = 0
    odid = 0
    service_data_frames = 0

    def on_detection(device, advertisement_data):
        nonlocal frames, odid, service_data_frames
        frames += 1
        macs.add(device.address.lower())
        sd = getattr(advertisement_data, "service_data", None) or {}
        if sd:
            service_data_frames += 1
        for uuid in sd:
            if str(uuid).lower() == "0000fffa-0000-1000-8000-00805f9b34fb":
                odid += 1

    scanner = BleakScanner(
        detection_callback=on_detection,
        scanning_mode="passive",
        bluez=BlueZScannerArgs(or_patterns=[OrPattern(*s) for s in specs]),
        adapter=adapter,
    )
    # ⛔ bleak 3.0.2 raises BleakDBusError[org.bluez.Error.DoesNotExist] from
    # stop() when BlueZ has already discarded the AdvertisementMonitor — i.e.
    # on the normal teardown path. Measured 2026-08-03. The counts are already
    # collected by then, so it is swallowed HERE to let the A/B finish; the
    # shipped bridge uses the same `async with scanner:` shape and pyproject
    # allows bleak<4.0, so this needs its own fix in bridges/ble.py.
    await scanner.start()
    try:
        await asyncio.sleep(window)
    finally:
        try:
            await scanner.stop()
        except Exception as exc:  # noqa: BLE001 - teardown quirk, counts are in
            if "DoesNotExist" not in str(exc):
                raise
            print(f"  {label:22} (teardown: {type(exc).__name__} DoesNotExist, ignored)")

    still_up = is_powered(adapter_mac(adapter) or "")
    result = {
        "valid": still_up,
        "label": label,
        "patterns": len(specs),
        "devices": len(macs),
        "frames": frames,
        "service_data_frames": service_data_frames,
        "odid_frames": odid,
    }
    if not still_up:
        print(f"  {label:22} ⛔ INVALID — adapter lost power mid-round")
    print(
        f"  {label:22} patterns={result['patterns']}  devices={result['devices']:3}  "
        f"frames={result['frames']:4}  with-service-data={service_data_frames:4}  "
        f"odid={odid}"
    )
    return result


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--adapter", default="hci1", help="hci1 is the bridge's default")
    ap.add_argument("--window", type=int, default=20, help="seconds per arm")
    ap.add_argument("--rounds", type=int, default=2, help="passes over all arms")
    args = ap.parse_args()

    check_specs_are_current()
    ensure_adapter_ready(args.adapter)
    print(f"adapter={args.adapter}  window={args.window}s  rounds={args.rounds}\n")

    results = []
    for i in range(args.rounds):
        print(f"round {i + 1}:")
        # Reverse the arm order on alternate rounds so no arm always gets the
        # warmer radio, and a decaying environment cannot masquerade as a result.
        order = list(ARMS) if i % 2 == 0 else list(reversed(ARMS))
        for label, specs in order:
            ensure_adapter_ready(args.adapter)
            results.append(await one_round(label, specs, args.adapter, args.window))

    dropped = [r for r in results if not r["valid"]]
    if dropped:
        print(f"\n⚠️  {len(dropped)} round(s) discarded — adapter lost power mid-round.")
    results = [r for r in results if r["valid"]]

    print("\ntotals (valid rounds only):")
    totals = {}
    for label, specs in ARMS:
        rs = [r for r in results if r["label"] == label]
        totals[label] = {
            "n": len(rs),
            "devices": sum(r["devices"] for r in rs),
            "frames": sum(r["frames"] for r in rs),
            "patterns": len(specs),
        }
        t = totals[label]
        print(
            f"  {label:24} patterns={t['patterns']}  rounds={t['n']}  "
            f"devices={t['devices']:3}  frames={t['frames']:4}"
        )

    if any(t["n"] == 0 for t in totals.values()):
        print("\n⛔ INCONCLUSIVE — an arm has no valid round. Do not read the totals.")
        return 2
    a, b = (totals[label] for label, _ in ARMS)
    print("")
    if a["frames"] == 0:
        print("⛔ REGRESSION — the SHIPPED 7-pattern set captured nothing. Either the")
        print("   radio/environment is dead, or a pattern change broke the monitor.")
        print("   Check the radio first; this arm is the control.")
        return 2
    if b["frames"] == 0:
        print("✅ CEILING HOLDS — 7 delivers, 8 collapses to zero, exactly as on")
        print("   2026-08-03. The <= 7 assertion in tests/test_ble_scan_or_patterns.py")
        print("   is still correct. Do not raise it.")
        return 0
    print("⚠️  THE CEILING MOVED — 8 patterns delivered this time. That contradicts")
    print("   the 2026-08-03 measurement (0 devices / 0 frames at 8, twice, with and")
    print("   without ODID). Re-run before acting; if it holds, something in BlueZ,")
    print("   the kernel or the controller changed and the <= 7 assertion can be")
    print("   revisited WITH THIS RUN CITED.")
    return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
