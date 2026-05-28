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


def _read_sysfs_optional_walkup(device_dir: Path, field: str) -> str | None:
    """Read a sysfs attribute that lives on the USB *device* node, trying
    the interface-level ``device_dir`` first and walking one level up.

    ``device_dir`` is the symlinked ``device/`` directory under the
    interface (``/sys/class/net/<iface>/device/`` for Wi-Fi or
    ``/sys/class/bluetooth/<hci>/device/`` for Bluetooth). For USB
    adapters it resolves to the USB *interface* (e.g.
    ``/sys/bus/usb/devices/1-1.2:1.0/``), while the USB string
    descriptors (``manufacturer`` / ``product`` / ``idVendor`` /
    ``idProduct``) and the ``removable`` flag live on the parent USB
    *device* (``/sys/bus/usb/devices/1-1.2/``).

    Resolving ``device_dir / ".."`` follows the ``device`` symlink to
    its real, nested location first (``/sys/devices/.../1-1.2/1-1.2:1.0``)
    so ``..`` lands on the device node (``.../1-1.2``) rather than the
    flat ``/sys/bus/usb/devices`` listing — the same walk-up that makes
    the bus/driver symlinks resolve. The interface-level path is tried
    first because some kernels expose attributes there directly, and the
    wizard's synthetic-tree tests write them at that level. Non-USB
    adapters (PCI / SDIO) expose none of these and return ``None`` from
    both probes."""
    direct = _read_sysfs_optional(device_dir / field)
    if direct is not None:
        return direct
    try:
        parent = (device_dir / "..").resolve(strict=False)
    except OSError:
        return None
    return _read_sysfs_optional(parent / field)


def _read_sysfs_removable(device_dir: Path) -> str | None:
    """Read the USB ``removable`` flag for the device backing an adapter.

    The kernel exposes ``removable`` on USB devices (per
    ``drivers/usb/core/sysfs.c``) with values:

      * ``"fixed"`` — built-in module connected via an internal USB hub
        (the operator-visible "internal" case: motherboard Bluetooth,
        on-board USB Wi-Fi soldered to an internal hub).
      * ``"removable"`` — hot-pluggable USB device (the operator-visible
        "external dongle" case).
      * ``"unknown"`` — the port's removable status couldn't be
        determined by the kernel; treated as the fallback case by the
        label formatter.

    Lives on the parent USB *device* node, so it goes through the shared
    ``_read_sysfs_optional_walkup`` (interface-level first, parent
    fallback). Non-USB adapters (PCI / SDIO) don't expose this attribute
    anywhere and return ``None``."""
    return _read_sysfs_optional_walkup(device_dir, "removable")


def _enrich_adapter_from_sysfs(device_dir: Path) -> dict:
    """Read the USB / bus / driver fields a Linux ``device/`` sysfs
    directory exposes for capture adapters. Returns a dict with the
    six additive keys (``bus``, ``driver``, ``vendor``, ``product``,
    ``usb_id``, ``removable``) each ``None`` when its source file
    isn't present.

    The Wi-Fi path is ``/sys/class/net/<name>/device/`` and the BT path
    is ``/sys/class/bluetooth/<name>/device/`` — both expose the same
    field names per the USB / driver model, so a single helper covers
    both. Non-USB adapters (internal PCI / SDIO Wi-Fi, on-board BT) have
    the bus + driver symlinks but no ``manufacturer`` / ``product`` /
    ``idVendor`` / ``idProduct`` files; those render as None.

    ``bus`` / ``driver`` are read off the interface-level ``subsystem`` /
    ``driver`` symlinks (which live on the interface node). The four USB
    string descriptors live on the parent USB *device* node, so they go
    through ``_read_sysfs_optional_walkup`` — without the walk-up they
    read as None on the common layout where ``device/`` resolves to the
    USB interface (``…:1.0``), which is the BT-rows-show-no-vendor bug.

    ``usb_id`` is composed as ``"VID:PID"`` only when both VID and PID
    were readable; otherwise ``None`` (a bare half-id like ``"148f:"``
    isn't useful to operators).

    ``removable`` distinguishes built-in modules connected to internal
    USB hubs (value ``"fixed"``, rendered as "Internal" by the
    formatter) from external dongles (``"removable"``, rendered as the
    bus name like "USB"). When the attribute is missing the formatter
    falls back to the bus-name behavior."""
    vendor = _read_sysfs_optional_walkup(device_dir, "manufacturer")
    product = _read_sysfs_optional_walkup(device_dir, "product")
    id_vendor = _read_sysfs_optional_walkup(device_dir, "idVendor")
    id_product = _read_sysfs_optional_walkup(device_dir, "idProduct")
    usb_id = f"{id_vendor}:{id_product}" if id_vendor and id_product else None
    return {
        "bus": _read_sysfs_symlink_basename(device_dir / "subsystem"),
        "driver": _read_sysfs_symlink_basename(device_dir / "driver"),
        "vendor": vendor,
        "product": product,
        "usb_id": usb_id,
        "removable": _read_sysfs_removable(device_dir),
    }


def format_adapter_descriptor(adapter: dict) -> str:
    """Render a plain-text descriptor for an enriched adapter dict.

    Mirrors the fallback ladder in ``kismet_sources.html`` rows so the
    web wizard and the bootstrap CLI show identical text for the same
    adapter. Examples:

      * ``"Alfa AWUS036ACS (USB rt2800usb)"`` — external USB dongle
      * ``"(Internal btusb)"`` — built-in BT module on an internal USB
        hub (``removable == "fixed"``), distinguishable from an
        external Bluetooth dongle which would render with ``USB``
      * ``"Ralink (USB rt2800usb)"`` — vendor only, no product string
      * ``"148f:7610 (USB rt2800usb)"`` — VID:PID only, no strings
      * ``"(SDIO brcmfmac)"`` — internal SoC adapter, driver-only
      * ``""`` — nothing readable, caller falls back to bare iface name

    The bus-name slot in the suffix is replaced with ``Internal`` when
    the adapter's ``removable`` is ``"fixed"`` — built-in modules
    connected via an internal USB hub read as "internal" to operators
    even though the kernel reports them as ``bus=usb``. Any other
    ``removable`` value (``"removable"``, ``"unknown"``, ``None``)
    leaves the bus name unchanged so external dongles still render
    with the original ``USB`` / ``PCI`` / ``SDIO`` prefix.

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
    removable = adapter.get("removable")

    bus_label = "Internal" if removable == "fixed" else (bus.upper() if bus else None)

    if bus_label:
        suffix = f" ({bus_label} {driver})" if driver else f" ({bus_label})"
    else:
        suffix = ""

    if product:
        return f"{product}{suffix}"
    if vendor:
        return f"{vendor}{suffix}"
    if usb_id:
        return f"{usb_id}{suffix}"
    if driver:
        return f"({bus_label} {driver})" if bus_label else f"({driver})"
    return ""
