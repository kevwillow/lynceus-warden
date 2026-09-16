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

import json
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


def _load_allowlist() -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    """Return (macs, ssids, exempt_commits), each mapping key -> reason.

    Deliberately a hand-parsed flat file: no YAML dependency, so the gate keeps
    working when the package does not install. Three kinds of line:

        ac:de:48:00:11:22: reason          a MAC
        "CafeWiFi": reason                 an SSID, QUOTED
        commit 6d8ea11d: reason            a historical commit message

    ⛔ SSIDs are quoted because an SSID may legally contain a colon, which is
    also the MAC separator and the key/reason separator. The quote is what
    makes the line unambiguous rather than merely usually-right.

    ⛔ Historical commit messages are exempted BY SHA, never by identifier.
    Listing the identifier would write it back into a tracked file, which is
    precisely what redacting it from BACKLOG.md was for.

    Every form refuses an entry with no reason: an allowlist that accepts a
    bare identifier is a list of things nobody had to justify.
    """
    macs: dict[str, str] = {}
    ssids: dict[str, str] = {}
    commits: dict[str, str] = {}
    if not ALLOWLIST.exists():
        return macs, ssids, commits
    for lineno, raw in enumerate(
        ALLOWLIST.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw.split("#", 1)[0].strip() if not raw.lstrip().startswith('"') else raw.strip()
        if not line:
            continue

        if line.startswith('"'):
            end = line.find('"', 1)
            if end == -1:
                raise SystemExit(f"{ALLOWLIST.name}:{lineno}: unterminated quoted SSID")
            key, rest = line[1:end], line[end + 1 :]
            if not rest.startswith(": "):
                raise SystemExit(f"{ALLOWLIST.name}:{lineno}: expected '\"ssid\": reason'")
            reason = rest[2:].split("#", 1)[0].strip()
            target, norm = ssids, key
        elif line.startswith("commit "):
            sha, _, reason = line[len("commit ") :].partition(": ")
            target, norm, reason = commits, sha.strip().lower(), reason.strip()
        else:
            mac, _, reason = line.partition(": ")
            target, norm, reason = macs, mac.strip().lower(), reason.strip()

        if not reason:
            # `norm` keeps a trailing colon when `partition(": ")` found no
            # space; strip it so the message names the key, not the parse.
            raise SystemExit(
                f"{ALLOWLIST.name}:{lineno}: {norm.rstrip(':')!r} has no reason. "
                "An exemption without a reason is not an exemption."
            )
        target[norm] = reason
    return macs, ssids, commits


# Keys whose VALUE is a network name somebody's device broadcast or asked for.
# ⛔ An SSID has no structural marker the way a MAC has the U/L bit -- any
# string is a legal SSID -- so the universe is the FIELDS, not the values. That
# is the whole reason this is a per-field scan and not a regex over everything.
_SSID_KEY = re.compile(r"ssid|essid|network_?name|base\.name", re.I)


def _ssid_values(obj, keypath: str = ""):
    """Yield every string sitting under an SSID-ish key, at any depth."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if _SSID_KEY.search(k) and isinstance(v, str) and v.strip():
                yield v
            yield from _ssid_values(v, f"{keypath}.{k}")
    elif isinstance(obj, list):
        for v in obj:
            yield from _ssid_values(v, keypath)
    elif isinstance(obj, str) and _SSID_KEY.search(keypath) and obj.strip():
        yield obj


def scan() -> dict:
    """Everything unaccounted for, plus everything seen, for the stale check."""
    macs, ssids, exempt_commits = _load_allowlist()
    out = {
        "mac_offenders": {},
        "ssid_offenders": {},
        "msg_offenders": {},
        "macs_seen": set(),
        "ssids_seen": set(),
        "commits_seen": set(),
    }
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
            out["macs_seen"].add(mac)
            if mac not in macs:
                out["mac_offenders"].setdefault(mac, []).append(rel)
        if rel.endswith((".json", ".yaml", ".yml")):
            try:
                data = json.loads(text)
            except (ValueError, RecursionError):
                continue  # YAML that is not JSON: fixtures here are JSON
            for value in _ssid_values(data):
                out["ssids_seen"].add(value)
                if value not in ssids:
                    out["ssid_offenders"].setdefault(value, []).append(rel)

    # ⛔ Commit messages too. `DC:41:A9` was only ever in a message, which is
    # exactly why the file scan never saw it. Historical commits are exempted
    # BY SHA so no redacted value is written back into a tracked file.
    log = subprocess.run(
        ["git", "log", "--all", "--format=%H%x01%B%x02"],
        capture_output=True,
        text=True,
        cwd=REPO,
    ).stdout
    for record in log.split("\x02"):
        if "\x01" not in record:
            continue
        sha, body = record.split("\x01", 1)
        sha = sha.strip().lower()
        short = sha[:8]
        out["commits_seen"].add(short)
        if short in exempt_commits:
            continue
        for m in _MAC.finditer(body):
            mac = m.group(1).lower()
            if not _could_identify_a_real_device(mac):
                continue
            # ⚠️ Counts as SEEN even when allowlisted, or a MAC that lives only
            # in a commit message would be reported STALE the moment somebody
            # allowlists it by value.
            out["macs_seen"].add(mac)
            if mac in macs:
                continue
            out["msg_offenders"].setdefault(mac, []).append(short)
    return out


def main() -> int:
    found = scan()
    macs, ssids, exempt_commits = _load_allowlist()
    rc = 0

    # ⛔ Stale first. A reason attached to something no longer in the tree is
    # unverifiable, and an allowlist nobody prunes becomes the place real
    # exposures go to be forgotten.
    stale = (
        [f"  {m}  ({macs[m]})" for m in sorted(set(macs) - found["macs_seen"])]
        + [f'  "{v}"  ({ssids[v]})' for v in sorted(set(ssids) - found["ssids_seen"])]
        + [
            f"  commit {c}  ({exempt_commits[c]})"
            for c in sorted(set(exempt_commits) - found["commits_seen"])
        ]
    )
    if stale:
        print("STALE allowlist entries — no longer present, so their reasons")
        print("cannot be checked. Remove them:")
        print("\n".join(stale))
        rc = 1

    if found["mac_offenders"]:
        print(
            "\nA globally-administered MAC was committed with no recorded reason. "
            "This repository is public and these identify real devices.\n"
        )
        for mac, files in sorted(found["mac_offenders"].items()):
            print(f"  {mac}   in {', '.join(sorted(set(files))[:4])}")
        print(
            "\nIf synthetic, use a locally-administered address (02:, 06:, 0a:, "
            "0e: ...) and nothing needs explaining.\n"
            "If from a PUBLISHED corpus, add it to "
            f"{ALLOWLIST.name} with the source.\n"
            "⛔ If it came off a real radio, it does not belong in a public repo."
        )
        rc = 1

    if found["ssid_offenders"]:
        print(
            "\nA network name was committed with no recorded reason. An SSID names "
            "a PLACE — a home, an office, a hotel — and public wardriving datasets "
            "index them against GPS.\n"
        )
        for value, files in sorted(found["ssid_offenders"].items()):
            print(f'  "{value}"   in {", ".join(sorted(set(files))[:4])}')
        print(
            f"\nIf invented, add it to {ALLOWLIST.name} saying so.\n"
            "⛔ If a real device probed for it, it is somebody's network and does "
            "not belong here."
        )
        rc = 1

    if found["msg_offenders"]:
        print(
            "\nA COMMIT MESSAGE carries an unexplained device identifier. Redacting "
            "the file does not touch the message, and the message is published too.\n"
        )
        for mac, shas in sorted(found["msg_offenders"].items()):
            print(f"  {mac}   in commit(s) {', '.join(sorted(set(shas))[:4])}")
        print(
            "\n⛔ A commit message cannot be edited without rewriting history. "
            "Amend BEFORE pushing, or record the commit as a deliberate historical "
            f"exemption in {ALLOWLIST.name}:  commit <sha8>: <why>"
        )
        rc = 1

    if rc == 0:
        print(
            f"identifier hygiene: OK "
            f"({len(found['macs_seen'])} MACs, {len(found['ssids_seen'])} SSIDs, "
            f"{len(exempt_commits)} exempted commit(s), all accounted for)"
        )
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
