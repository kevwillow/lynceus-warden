"""Static BLE GATT service-UUID → human-readable name lookup.

Sourced from the Bluetooth SIG assigned-numbers list. Entries here are
generic *service* UUIDs (heart rate, battery, device information, etc.)
— not surveillance- or tracker-specific patterns. Tracker UUIDs (AirTag,
Tile, ...) live in :mod:`lynceus.seeds.ble_uuids` because those drive the
v0.2 watchlist seed; this dict is purely for read-time enrichment.

The 16-bit short-form UUIDs registered with Bluetooth SIG are expanded
to 128-bit form using the standard base UUID
``0000XXXX-0000-1000-8000-00805f9b34fb``. :func:`lookup_service_name`
accepts any of: full 128-bit (with or without dashes), 32-bit, or 16-bit
short form, with or without a ``0x`` prefix, with arbitrary case and
internal colons. Lookup is O(1) — straight dict access, no regex.
"""

from __future__ import annotations

_BASE_UUID_TAIL = "-0000-1000-8000-00805f9b34fb"


def _expand(short: str) -> str:
    return f"0000{short.lower()}{_BASE_UUID_TAIL}"


# Curated subset of standard Bluetooth SIG GATT services. Patterns match
# v5.4 of the assigned-numbers list. Keep one entry per UUID.
_SHORT_FORM_SERVICES: dict[str, str] = {
    "1800": "Generic Access",
    "1801": "Generic Attribute",
    "1802": "Immediate Alert",
    "1803": "Link Loss",
    "1804": "Tx Power",
    "1805": "Current Time Service",
    "1806": "Reference Time Update Service",
    "1807": "Next DST Change Service",
    "1808": "Glucose",
    "1809": "Health Thermometer",
    "180a": "Device Information",
    "180d": "Heart Rate",
    "180e": "Phone Alert Status Service",
    "180f": "Battery Service",
    "1810": "Blood Pressure",
    "1811": "Alert Notification Service",
    "1812": "Human Interface Device",
    "1813": "Scan Parameters",
    "1814": "Running Speed and Cadence",
    "1815": "Automation IO",
    "1816": "Cycling Speed and Cadence",
    "1818": "Cycling Power",
    "1819": "Location and Navigation",
    "181a": "Environmental Sensing",
    "181b": "Body Composition",
    "181c": "User Data",
    "181d": "Weight Scale",
    "181e": "Bond Management Service",
    "181f": "Continuous Glucose Monitoring",
    "1820": "Internet Protocol Support Service",
    "1821": "Indoor Positioning",
    "1822": "Pulse Oximeter Service",
    "1823": "HTTP Proxy",
    "1824": "Transport Discovery",
    "1825": "Object Transfer Service",
    "1826": "Fitness Machine",
    "1827": "Mesh Provisioning Service",
    "1828": "Mesh Proxy Service",
    "1829": "Reconnection Configuration",
    "183a": "Insulin Delivery",
    "183b": "Binary Sensor",
    "183c": "Emergency Configuration",
    "183e": "Physical Activity Monitor",
}


SERVICE_NAMES: dict[str, str] = {
    _expand(short): name for short, name in _SHORT_FORM_SERVICES.items()
}


def _normalize_uuid(value: str) -> str | None:
    """Reduce a BLE UUID to canonical 128-bit lowercase dashed form.

    Returns None if the value is not a recognizable BLE UUID. Accepts
    short-form (16-bit, 32-bit), full 128-bit dashed, full 128-bit
    undashed, optionally prefixed with ``0x`` and with stray colons or
    whitespace.
    """
    if not isinstance(value, str):
        return None
    cleaned = value.strip().lower().replace(":", "").replace("-", "")
    if cleaned.startswith("0x"):
        cleaned = cleaned[2:]
    if not cleaned or any(c not in "0123456789abcdef" for c in cleaned):
        return None
    if len(cleaned) == 4:
        cleaned = f"0000{cleaned}"
    if len(cleaned) == 8:
        return f"{cleaned}{_BASE_UUID_TAIL}"
    if len(cleaned) == 32:
        return f"{cleaned[0:8]}-{cleaned[8:12]}-{cleaned[12:16]}-{cleaned[16:20]}-{cleaned[20:32]}"
    return None


def lookup_service_name(uuid: str) -> str | None:
    """Return the human-readable BLE service name, or None if unknown.

    Accepts the same input forms as :func:`_normalize_uuid`. Returns
    None for malformed input rather than raising — callers (UI, log
    enrichment) are expected to fall back to displaying the raw UUID.
    """
    canonical = _normalize_uuid(uuid)
    if canonical is None:
        return None
    return SERVICE_NAMES.get(canonical)
