"""Built-in threat OUI seed list.

Users SHOULD review and adjust severities for their environment. Raspberry Pi
OUIs are flagged 'low' because they're informational, not inherently malicious.
This list is deliberately conservative — only OUIs with strong public attribution.
"""

from __future__ import annotations

THREAT_OUIS: list[dict] = [
    {
        "pattern": "00:13:37",
        "severity": "high",
        "description": "Hak5 (WiFi Pineapple, Bash Bunny, etc.)",
    },
    {
        "pattern": "00:c0:ca",
        "severity": "med",
        "description": "Alfa Networks (commonly used in pentest adapters)",
    },
    {
        "pattern": "00:11:22",
        "severity": "low",
        "description": "Cimsys (associated with surveillance hardware)",
    },
    {
        "pattern": "dc:a6:32",
        "severity": "low",
        "description": "Raspberry Pi Foundation (informational; common in DIY drop boxes)",
    },
    {
        "pattern": "b8:27:eb",
        "severity": "low",
        "description": "Raspberry Pi Foundation (older boards)",
    },
    {
        "pattern": "e4:5f:01",
        "severity": "low",
        "description": "Raspberry Pi Foundation (recent boards)",
    },
]
