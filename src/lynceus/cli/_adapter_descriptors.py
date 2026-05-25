"""Shared sysfs probes + label formatter for capture-adapter descriptors.

Both the web wizard's step 4 (``cli/setup.py``) and the apt-bootstrap
script (``cli/bootstrap_kismet.py``) need to surface vendor / product /
bus / driver descriptors to operators so two same-kind dongles read as
distinct rows. Pulling the helpers into one module keeps the two
codebases consistent: a fix to the fallback ladder or a new sysfs field
lands once and both surfaces pick it up.

The helpers are kept as raw sysfs readers (no Linux-specific imports)
so the unit tests work on any host — the wizard's existing matrix tests
already exercise every fallback combination via tmp_path fixtures.

``format_adapter_descriptor`` mirrors the row-rendering convention in
``kismet_sources.html`` line-for-line so the wizard and bootstrap show
identical text for the same adapter. Plain text (no markup) is the
shared register; HTML decoration stays in the template.
"""

from __future__ import annotations

from pathlib import Path


def _read_sysfs_mac(path: Path) -> str | None:
    """Read a sysfs ``address`` file's contents, stripped, or ``None``
    when the file can't be read. Returned to operators verbatim — sysfs
    is the canonical source for adapter MAC strings, so no normalization
    is applied here."""
    try:
        text = path.read_text().strip()
    except OSError:
        return None
    return text or None


def _read_sysfs_optional(path: Path) -> str | None:
    """Read a sysfs file's contents, stripped, or return ``None`` for the
    "field absent" cases this enumeration treats as non-fatal:

      - ``FileNotFoundError`` — non-USB adapter (internal PCI/SDIO Wi-Fi,
        motherboard BT) won't have USB string descriptors like
        ``device/manufacturer``; treat as "no info" rather than crashing
        the wizard.
      - ``PermissionError`` — the wizard process may not be privileged
        enough to read every sysfs node on some configurations; better
        to render a sparser label than to crash.
      - ``IsADirectoryError`` — symlinks to ``device/driver`` resolve to
        a directory when caller reaches for the directory by accident;
        treat as "no info" so the caller can stay one-shaped.

    Any *other* OSError (an unexpected filesystem fault) propagates so it
    surfaces in dev rather than getting silently swallowed."""
    try:
        text = path.read_text().strip()
    except (FileNotFoundError, PermissionError, IsADirectoryError):
        return None
    return text or None


def _read_sysfs_symlink_basename(path: Path) -> str | None:
    """Resolve a sysfs symlink and return its basename, or ``None`` when
    the symlink is absent.

    Used for ``device/driver`` (basename → kernel module like
    ``rt2800usb`` / ``btusb``) and ``device/subsystem`` (basename →
    bus like ``usb`` / ``pci`` / ``sdio``). Returns ``None`` on the
    same non-fatal cases ``_read_sysfs_optional`` handles, so an
    adapter whose driver symlink isn't there just renders a sparser
    label rather than crashing the wizard."""
    try:
        target = path.resolve(strict=True)
    except (FileNotFoundError, PermissionError, OSError):
        # OSError here covers the loop / too-many-links cases that
        # resolve() raises as a generic OSError; lumping them in keeps
        # the helper one-shaped — the caller just sees "no driver".
        return None
    return target.name or None


def _enrich_adapter_from_sysfs(device_dir: Path) -> dict:
    """Read the USB / bus / driver fields a Linux ``device/`` sysfs
    directory exposes for capture adapters. Returns a dict with the
    five additive keys (``bus``, ``driver``, ``vendor``, ``product``,
    ``usb_id``) each ``None`` when its source file isn't present.

    The Wi-Fi path is ``/sys/class/net/<name>/device/`` and the BT path
    is ``/sys/class/bluetooth/<name>/device/`` — both expose the same
    field names per the USB / driver model, so a single helper covers
    both. Non-USB adapters (internal PCI / SDIO Wi-Fi, on-board BT) have
    the bus + driver symlinks but no ``manufacturer`` / ``product`` /
    ``idVendor`` / ``idProduct`` files; those render as None.

    ``usb_id`` is composed as ``"VID:PID"`` only when both VID and PID
    were readable; otherwise ``None`` (a bare half-id like ``"148f:"``
    isn't useful to operators)."""
    vendor = _read_sysfs_optional(device_dir / "manufacturer")
    product = _read_sysfs_optional(device_dir / "product")
    id_vendor = _read_sysfs_optional(device_dir / "idVendor")
    id_product = _read_sysfs_optional(device_dir / "idProduct")
    usb_id = f"{id_vendor}:{id_product}" if id_vendor and id_product else None
    return {
        "bus": _read_sysfs_symlink_basename(device_dir / "subsystem"),
        "driver": _read_sysfs_symlink_basename(device_dir / "driver"),
        "vendor": vendor,
        "product": product,
        "usb_id": usb_id,
    }


def format_adapter_descriptor(adapter: dict) -> str:
    """Render a plain-text descriptor for an enriched adapter dict.

    Mirrors the fallback ladder in ``kismet_sources.html`` rows so the
    web wizard and the bootstrap CLI show identical text for the same
    adapter. Examples:

      * ``"Alfa AWUS036ACS (USB rt2800usb)"`` — full USB descriptor set
      * ``"Ralink (USB rt2800usb)"`` — vendor only, no product string
      * ``"148f:7610 (USB rt2800usb)"`` — VID:PID only, no strings
      * ``"(SDIO brcmfmac)"`` — internal SoC adapter, driver-only
      * ``""`` — nothing readable, caller falls back to bare iface name

    The parenthesized suffix is appended when bus is set (regardless of
    whether driver is also set); the lone-driver branch emits
    ``"(driver)"`` without parens-only padding. ``adapter`` is the dict
    shape that ``_enrich_adapter_from_sysfs`` returns — additional keys
    on the dict are ignored, so callers can pass full ``enumerate_
    capture_adapters`` rows directly."""
    bus = adapter.get("bus")
    driver = adapter.get("driver")
    product = adapter.get("product")
    vendor = adapter.get("vendor")
    usb_id = adapter.get("usb_id")

    if bus:
        suffix = f" ({bus.upper()} {driver})" if driver else f" ({bus.upper()})"
    else:
        suffix = ""

    if product:
        return f"{product}{suffix}"
    if vendor:
        return f"{vendor}{suffix}"
    if usb_id:
        return f"{usb_id}{suffix}"
    if driver:
        return f"({bus.upper()} {driver})" if bus else f"({driver})"
    return ""
