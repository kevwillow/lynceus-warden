"""THE JOINT HOP: a LIVE Find My advert, off the air, producing a real alert row.

⛔ This is the one thing v1.0.0 could not claim. Everything else was proven:

    live radio  ->  BleBridge scanner  ->  _detection_callback  ->  _record_advert
                                                                          |
    [ proven by scripts/audit/repro_stalker_chain.py, from HERE onward ]---+
                                                                          |
    _flush -> process_observation -> apple_find_my rule -> alert row + notification

`repro_stalker_chain.py` drives `_record_advert` with SYNTHETIC bytes, so the
chain below that seam is proven. What had never happened is the hop ABOVE it:
a real advertisement, received by a real scanner, entering that same chain. It
could not have happened before 2026-08-20 -- the `apple_find_my` rule shipped
COMMENTED OUT until #182 turned it on.

⭐ This harness closes exactly that gap and nothing more. It uses:
  - the SHIPPED config/rules.yaml (not a fixture) -- so it grades what operators get
  - the REAL BleBridge, wired as the Poller wires it (copied from run_arm)
  - the bridge's OWN `_make_scanner()` -- production or_patterns, production
    adapter handling. ⇒ Never re-derive the scanner here; importing it is the
    whole point. A probe built differently from its subject measures a
    different thing.

⚠️ WHAT A ZERO MEANS. If no find_my_separated advert arrives in the window, this
prints UNPROVEN, not "the chain is broken". A separated tracker has to be in
range and advertising. The adapter is asserted powered BEFORE and AFTER, so a
zero cannot be a dead-radio zero -- but it is still not evidence of anything.

⭐ RESULT ON RECORD — reproduce it, do not take it on faith. Run 2026-08-20 on
an 8-device-class adapter, 12-minute window, shipped config/rules.yaml:

    devices with a find_my class: 1
        ff:1f:9e:91:52:bc  class='find_my_separated'
    alert: apple_find_my / ble_device_class / severity med / notified_at set
    -> JOINT HOP PROVEN

⚠️ NEEDS HARDWARE, so CI cannot run it: a BlueZ adapter, `bleak` installed
(`pip install 'lynceus[ble]'`), and a SEPARATED Find My tracker in range —
one away from its owner, which is what makes it advertise the 25-byte form.
A paired tracker (every passer-by's phone) advertises the short form and
correctly raises nothing.

Usage:
    .venv/bin/python scripts/audit/repro_live_find_my_alert.py \
        --address <BD_ADDR> --index <N> --minutes 12

Exit codes are the finding: 0 proven, 2 captured-but-no-alert (a RULE gap),
3 nothing in range (UNPROVEN, and NOT evidence of anything).
"""

from __future__ import annotations

import argparse
import asyncio
import subprocess
import sys
import time
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "src"))

import lynceus  # noqa: E402
from lynceus.allowlist import Allowlist  # noqa: E402
from lynceus.bridges.ble import BleBridge  # noqa: E402
from lynceus.config import Config  # noqa: E402
from lynceus.db import Database  # noqa: E402
from lynceus.notify import RecordingNotifier  # noqa: E402
from lynceus.rules import load_ruleset  # noqa: E402

_resolved = Path(lynceus.__file__).resolve()
if _REPO / "src" not in _resolved.parents:
    raise SystemExit(
        f"REFUSING TO RUN: imported lynceus from {_resolved}, not from "
        f"{_REPO / 'src'}. An editable install won the import and this would "
        f"grade a different tree than it lives in."
    )

_SHIPPED_RULES = _REPO / "config" / "rules.yaml"


def adapter_power_state(address: str) -> tuple[str, str]:
    """(state, why). Same three-valued check as measure_find_my_rotation.

    ⛔ `btmgmt` is NOT used: it blocks forever unprivileged, and its timeout
    silently became "not powered" -- which is what made this box look like it
    had a dead radio for weeks. bluetoothctl answers without privileges.
    """
    try:
        proc = subprocess.run(
            ["bluetoothctl", "show", address], capture_output=True, text=True, timeout=15
        )
    except subprocess.TimeoutExpired:
        return "UNKNOWN", "bluetoothctl did not answer within 15s"
    except OSError as exc:
        return "UNKNOWN", f"could not run bluetoothctl ({exc})"
    if proc.returncode != 0:
        return "UNKNOWN", f"bluetoothctl exited {proc.returncode}"
    for line in proc.stdout.splitlines():
        s = line.strip().lower()
        if s.startswith("powered:"):
            v = s.split(":", 1)[1].strip()
            return ("POWERED" if v.startswith("yes") else "NOT_POWERED"), f"Powered: {v}"
    return "UNKNOWN", "bluetoothctl printed no 'Powered:' line"


def build_bridge(tmp: Path, adapter: str):
    """Wire a real BleBridge exactly as the Poller does, on the SHIPPED rules."""
    ruleset = load_ruleset(str(_SHIPPED_RULES))
    db_path = str(tmp / "live.db")
    db = Database(db_path)
    config = Config(db_path=db_path)
    notifier = RecordingNotifier()
    bridge = BleBridge(
        db=db,
        config=config,
        ruleset=ruleset,
        allowlist_provider=Allowlist,
        notifier=notifier,
        severity_overrides=None,
        location_id=config.location_id,
        location_label=config.location_label,
        adapter=adapter,
        flush_interval=1.0,
    )
    return bridge, db, notifier, [r.name for r in ruleset.rules]


async def scan(bridge, seconds: int) -> None:
    """Run the bridge's OWN scanner. Not a reimplementation of it."""
    scanner = bridge._make_scanner()
    await scanner.start()
    try:
        await asyncio.sleep(seconds)
    finally:
        await bridge._stop_scanner(scanner)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--address", required=True, help="controller BD address")
    ap.add_argument("--index", type=int, default=0, help="hci index for the scanner")
    ap.add_argument("--minutes", type=int, default=10)
    args = ap.parse_args()

    state, why = adapter_power_state(args.address)
    if state != "POWERED":
        raise SystemExit(
            f"REFUSING TO RUN: {args.address} is {state} — {why}.\n"
            "A zero from an adapter that is off or unknown is indistinguishable\n"
            "from 'no tracker present', and this harness exists to tell those apart."
        )
    print(f"tree under test:       {_REPO}")
    print(f"rules file (SHIPPED):  {_SHIPPED_RULES}")
    print(f"adapter {args.address} (hci{args.index}) powered before — {why}\n")

    import tempfile

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        bridge, db, notifier, rule_names = build_bridge(tmp, f"hci{args.index}")
        enabled = "apple_find_my" in rule_names
        print(f"rules loaded ({len(rule_names)}): {rule_names}")
        if not enabled:
            raise SystemExit(
                "REFUSING TO RUN: apple_find_my is NOT in the shipped ruleset, so a\n"
                "zero would prove nothing about the radio. Fix the config first."
            )
        print(f"apple_find_my enabled in the SHIPPED config: {enabled}\n")
        print(f"scanning {args.minutes} min on hci{args.index}…")
        asyncio.run(scan(bridge, args.minutes * 60))

        after, why_after = adapter_power_state(args.address)
        if after != "POWERED":
            raise SystemExit(
                f"\n⛔ DISCARDING: adapter is {after} after the window — {why_after}.\n"
                "Part of the window captured nothing for a reason unrelated to trackers."
            )
        print(f"adapter still powered after — {why_after}")

        flushed = bridge._flush(int(time.time()))
        alerts = db.list_alerts(limit=50)
        devices = db.list_devices(limit=200)
        fm = [d for d in devices if (d.get("ble_device_class") or "").startswith("find_my")]
        fm_alerts = [a for a in alerts if "find_my" in str(a).lower()]

        print(f"\nobservations flushed        : {flushed}")
        print(f"devices with a find_my class: {len(fm)}")
        for d in fm[:10]:
            print(f"    {d['mac']}  class={d.get('ble_device_class')!r}")
        print(f"alert rows                  : {len(alerts)}  (find_my-related: {len(fm_alerts)})")
        for a in alerts[:10]:
            print(f"    {a}")
        print(f"notifications dispatched    : {len(notifier.calls)}")
        for c in list(notifier.calls)[:10]:
            print(f"    {c}")

        db.close()

        print("\n" + "=" * 70)
        if fm_alerts and notifier.calls:
            print("✅ JOINT HOP PROVEN: a LIVE advert produced an alert row AND a")
            print("   notification, through the shipped rules, on real hardware.")
            return 0
        if fm:
            print("🟡 PARTIAL: a live find_my advert was captured and PERSISTED, but no")
            print("   alert row resulted. That is a RULE gap, not a radio gap — and it")
            print("   is a finding, not a non-result. Investigate the rule, not the antenna.")
            return 2
        print("⚠️  UNPROVEN — no find_my advert arrived in this window.")
        print("   The adapter was powered before AND after, so this is NOT a dead-radio")
        print("   zero. It is simply an absence of trackers in range. Not evidence.")
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
