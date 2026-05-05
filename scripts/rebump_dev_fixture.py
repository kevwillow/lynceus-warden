"""Rebump tests/fixtures/dev_kismet.json timestamps to be relative to
"now". Run this when the dev UI starts showing empty state for
recency-aware widgets ("devices seen in last 24h", sparkline, etc.).

This is a v0.2 maintenance script. The durable fix is auto-shift-on-load
in FakeKismetClient (see BACKLOG.md). Until that lands, re-run this
script every few months as needed.

Usage:
    python scripts/rebump_dev_fixture.py [--dry-run]

--dry-run prints the planned offsets without writing the file.
Without --dry-run, atomically replaces tests/fixtures/dev_kismet.json.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE = REPO_ROOT / "tests" / "fixtures" / "dev_kismet.json"

# Per-device offsets in seconds before the anchor. The anchor is
# (now - 3600), so device 0's last_time is one hour ago and device 6's
# is roughly 3h40m ago. Spread is intentional: clustering all devices at
# the same instant flattens the sparkline and makes per-hour stats
# uninformative.
DEVICE_OFFSETS_FROM_ANCHOR = [0, 600, 1800, 3600, 5400, 7200, 9600]
EXPECTED_DEVICE_COUNT = len(DEVICE_OFFSETS_FROM_ANCHOR)
SIGHTING_DURATION_SECONDS = 60


def _format_delta(seconds: int) -> str:
    sign = "+" if seconds >= 0 else "-"
    seconds = abs(seconds)
    if seconds < 3600:
        return f"{sign}{seconds // 60}m"
    if seconds < 86400:
        return f"{sign}{seconds // 3600}h"
    if seconds < 86400 * 60:
        return f"{sign}{seconds // 86400}d"
    return f"{sign}{seconds // (86400 * 30)} months"


def _load_fixture() -> list[dict]:
    if not FIXTURE.exists():
        print(f"error: fixture not found at {FIXTURE}", file=sys.stderr)
        sys.exit(1)
    try:
        data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"error: fixture is not valid JSON: {e}", file=sys.stderr)
        sys.exit(1)
    if not isinstance(data, list):
        print(
            f"error: fixture root must be a JSON list, got {type(data).__name__}",
            file=sys.stderr,
        )
        sys.exit(1)
    if len(data) != EXPECTED_DEVICE_COUNT:
        print(
            f"error: expected {EXPECTED_DEVICE_COUNT} devices in fixture, "
            f"found {len(data)}. Refusing to bump partial data.",
            file=sys.stderr,
        )
        sys.exit(1)
    return data


def _rebump(devices: list[dict], now_ts: int) -> list[tuple[str, int, int]]:
    """Mutate devices in place. Return [(mac, old_last_time, new_last_time), ...]."""
    anchor = now_ts - 3600
    rows: list[tuple[str, int, int]] = []
    for i, device in enumerate(devices):
        new_last = anchor - DEVICE_OFFSETS_FROM_ANCHOR[i]
        new_first = new_last - SIGHTING_DURATION_SECONDS
        old_last = int(device.get("kismet.device.base.last_time", 0))
        mac = str(device.get("kismet.device.base.macaddr", "?"))

        device["kismet.device.base.last_time"] = new_last
        device["kismet.device.base.first_time"] = new_first

        seenby = device.get("kismet.device.base.seenby")
        if isinstance(seenby, list):
            for entry in seenby:
                if not isinstance(entry, dict):
                    continue
                entry["kismet.common.seenby.first_time"] = new_first
                entry["kismet.common.seenby.last_time"] = new_last

        rows.append((mac, old_last, new_last))
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="rebump_dev_fixture",
        description="Rebump tests/fixtures/dev_kismet.json timestamps relative to now.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print planned offsets and exit without writing the file.",
    )
    args = parser.parse_args(argv)

    devices = _load_fixture()
    now_ts = int(time.time())

    rows = _rebump(devices, now_ts)

    if args.dry_run:
        print(f"now_ts = {now_ts}  anchor = {now_ts - 3600}")
        print(f"{'mac':<20} {'old last_time':>14} {'new last_time':>14} {'delta':>10}")
        print("-" * 64)
        for mac, old_last, new_last in rows:
            delta = new_last - old_last
            print(f"{mac:<20} {old_last:>14} {new_last:>14} {_format_delta(delta):>10}")
        return 0

    tmp = FIXTURE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(devices, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, FIXTURE)
    new_min = min(r[2] for r in rows)
    new_max = max(r[2] for r in rows)
    print(
        f"rebumped {len(rows)} devices in {FIXTURE.relative_to(REPO_ROOT)} "
        f"(last_time range: {new_min}..{new_max}, anchor={now_ts - 3600})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
