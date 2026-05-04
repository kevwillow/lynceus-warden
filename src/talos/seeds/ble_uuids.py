"""Known BLE service UUIDs associated with trackers and surveillance devices.

Conservative list — users should review for their threat model.

AirTag detection here uses the publicly observed Find My service UUID. Apple
rotates BLE addresses every ~15 minutes, so a single AirTag will appear as many
distinct MACs over time. Use the ble_uuid rule type rather than mac to track
them.
"""

from __future__ import annotations

TRACKER_UUIDS: list[dict] = [
    {
        "pattern": "0000fd5a-0000-1000-8000-00805f9b34fb",
        "severity": "high",
        "description": "Apple Find My / AirTag service",
    },
    {
        "pattern": "0000feed-0000-1000-8000-00805f9b34fb",
        "severity": "med",
        "description": "Tile tracker service",
    },
    {
        "pattern": "0000fd6f-0000-1000-8000-00805f9b34fb",
        "severity": "low",
        "description": (
            "Exposure Notification (Google/Apple) — informational, often present in public"
        ),
    },
]
