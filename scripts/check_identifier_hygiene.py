#!/usr/bin/env python3
"""Refuse to commit a real-looking device identifier without a written reason.

⛔ **Why this exists, and why it is not paranoia.** This repository is public,
and its entire subject is recording identifiers that belong to other people:
MAC addresses, SSIDs a phone has probed for, the manufacturer of a device
somebody is carrying. A test fixture built from a real capture publishes those
third parties permanently, and they never consented to anything.

The repo already has the discipline. `tests/fixtures/kismet_devices_real_2025_09.json`
holds globally-administered MACs from real vendor blocks, and it is fine — its
commit and `tests/test_kismet_real_capture.py` both record that it is a replay
of Wireshark's public `wpa-Induction.pcap` sample, not a rig's capture.

⛔ **But that discipline is entirely human**: a filename convention, a commit
message and a docstring. Nothing mechanical stops the next fixture from being
last night's capture of a real street. This makes it structural — the same shape
the repo already uses for suppression exemptions: **an exemption is a claim, so
it has to be written down and it has to stay true.**

⇒ Every globally-administered MAC in a tracked file must appear in
`.identifier-allowlist.yaml` with a reason. New ones fail the build.

⭐ **The test is the IEEE locally-administered bit**, plus the product's own
reserved-prefix list. It is deliberately NOT `rules._is_reserved_oui_mac`,
which answers a different question — "should this match a watchlist OUI" — and
enumerates only the unicast locally-administered nibbles `{2,6,a,e}`. That set
misses `{3,7,b,f}`, which are locally-administered multicast and equally
incapable of identifying a device: reusing it flagged `ff:1f:9e:...` as a real
address. Right predicate, wrong question.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

# ⛔ INLINED, not imported from `lynceus.rules`, and this is deliberate after
# getting it wrong once: importing that module pulls its whole import chain
# (it needs PyYAML), so the gate died with ModuleNotFoundError in a CI job that
# had not installed the package. A hygiene gate that depends on the package
# installing correctly can be silenced by an unrelated packaging failure.
#
# These are IEEE facts rather than product policy, so they do not drift -- but
# "does not drift" is a claim, so `tests/test_identifier_hygiene_gate.py`
# asserts they still equal the product's own sets, where the full environment
# IS available.
_RESERVED_OUI_PREFIXES_EXACT = frozenset({"00:00:00", "ff:ff:ff", "01:00:5e"})
_RESERVED_MAC_PREFIXES_TWO_OCTET = frozenset({"33:33"})


def _could_identify_a_real_device(mac: str) -> bool:
    """True when this MAC could be a globally-assigned, real device address.

    IEEE 802: bit 1 of the first octet is the U/L flag. SET means locally
    administered — chosen by software, assigned to nobody, and therefore
    incapable of identifying a real device no matter what it looks like.
    CLEAR means it comes from a registered vendor block.
    """
    if mac[:8] in _RESERVED_OUI_PREFIXES_EXACT:
        return False
    if mac[:5] in _RESERVED_MAC_PREFIXES_TWO_OCTET:
        return False
    return not (int(mac[:2], 16) & 0x02)

ALLOWLIST = REPO / ".identifier-allowlist.yaml"

_MAC = re.compile(r"\b([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\b")

# Binary and generated files carry no reviewable identifiers.
_SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".pdf"}
# ⛔ The bundled surveillance-device corpus is the product's DATA, not a capture:
# every row is a published ALPR/surveillance identifier with a source_url. It is
# excluded by path, and that exclusion is itself listed here rather than hidden
# in a regex.
_SKIP_PATHS = {
    "src/lynceus/data/default_watchlist.csv",
    # ⛔ The allowlist itself. It is a tracked file listing every allowlisted
    # MAC, so scanning it makes each one "present in the tree" and the stale
    # check `set(allow) - seen` is EMPTY BY CONSTRUCTION -- it can never fire.
    # Caught by planting a stale entry and watching the check report OK.
    ".identifier-allowlist.yaml",
}


def _tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files"], capture_output=True, text=True, cwd=REPO, check=True
    ).stdout.split()
    return [
        f
        for f in out
        if Path(f).suffix.lower() not in _SKIP_SUFFIXES and f not in _SKIP_PATHS
    ]


def _load_allowlist() -> dict[str, str]:
    """``mac: reason`` pairs. Deliberately a hand-parsed flat file.

    No YAML dependency, and the format refuses an entry with no reason —
    an allowlist that accepts a bare identifier is a list of things nobody
    had to justify.
    """
    if not ALLOWLIST.exists():
        return {}
    entries: dict[str, str] = {}
    for lineno, raw in enumerate(
        ALLOWLIST.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if ":" not in line:
            raise SystemExit(f"{ALLOWLIST.name}:{lineno}: expected 'mac: reason'")
        mac, _, reason = line.partition(": ")
        mac = mac.strip().strip('"').lower()
        reason = reason.strip().strip('"')
        if not reason:
            raise SystemExit(
                f"{ALLOWLIST.name}:{lineno}: {mac} has no reason. "
                "An exemption without a reason is not an exemption."
            )
        entries[mac] = reason
    return entries


def scan() -> tuple[dict[str, list[str]], set[str]]:
    """Return (unallowlisted real-looking MACs -> where, all real MACs seen)."""
    allow = _load_allowlist()
    offenders: dict[str, list[str]] = {}
    seen: set[str] = set()
    files = _tracked_files()
    if not files:
        raise SystemExit("no tracked files scanned — the derivation proves nothing")
    for rel in files:
        try:
            text = (REPO / rel).read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        for m in _MAC.finditer(text):
            mac = m.group(1).lower()
            if not _could_identify_a_real_device(mac):
                continue
            seen.add(mac)
            if mac not in allow:
                offenders.setdefault(mac, []).append(rel)
    return offenders, seen


def main() -> int:
    offenders, seen = scan()
    allow = _load_allowlist()

    stale = sorted(set(allow) - seen)
    if stale:
        print(
            "STALE allowlist entries — these identifiers are no longer in the "
            "tree, so the reason attached to them is unverifiable. Remove them:"
        )
        for mac in stale:
            print(f"  {mac}  ({allow[mac]})")
        return 1

    if offenders:
        print(
            "A globally-administered MAC address was committed with no recorded "
            "reason. This repository is public and these identify real devices "
            "belonging to real people.\n"
        )
        for mac, files in sorted(offenders.items()):
            where = ", ".join(sorted(set(files))[:4])
            print(f"  {mac}   in {where}")
        print(
            f"\n{len(offenders)} unexplained identifier(s).\n"
            "If these are synthetic, use a locally-administered address "
            "(02:, 06:, 0a:, 0e: ...) and nothing needs explaining.\n"
            "If they come from a PUBLISHED corpus, add them to "
            f"{ALLOWLIST.name} with the source.\n"
            "⛔ If they came off a real radio, they do not belong in a public repo."
        )
        return 1

    print(f"identifier hygiene: OK ({len(seen)} allowlisted, all accounted for)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
