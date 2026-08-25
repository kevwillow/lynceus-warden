"""Hashing for a case-file bundle.

What this proves and what it does not. The digest shows the bundle has
not changed SINCE export. It does NOT show the observations are
accurate, and it is not a third-party attestation: the operator's own
installation produced it, and the operator controls the database. The
rendered document says so in those words, and this module's job is only
to make the narrow claim checkable.

Deliberately stdlib only. A signature scheme would add key generation,
storage and rotation to a product with no key management at all, and it
would prove the same install produced the bundle, which is
self-attestation dressed up as assurance.
"""

from __future__ import annotations

import hashlib

ALGORITHM = "sha256"


def build_manifest(artifacts: dict[str, bytes]) -> dict:
    """Hash every artifact, then hash the hashes.

    The manifest digest covers file NAMES as well as contents. Hashing
    only contents would let two files swap names undetected, which in a
    bundle whose filenames carry meaning (``evidence/<alert_id>.json``)
    is a substantive change, not a cosmetic one.

    Names are sorted before the digest is computed, so the caller's dict
    ordering cannot change it. Two byte-identical bundles must agree
    about their own identity regardless of how each was assembled.
    """
    files: dict[str, dict] = {}
    for name in sorted(artifacts):
        payload = artifacts[name]
        files[name] = {
            ALGORITHM: hashlib.sha256(payload).hexdigest(),
            "bytes": len(payload),
        }

    # A length-prefixed, sorted encoding. The prefixes keep the name and
    # the digest from running together, so no pair of differing inputs
    # can produce the same byte stream.
    digest = hashlib.sha256()
    for name in sorted(files):
        entry = files[name]
        digest.update(f"{len(name)}:{name}".encode())
        digest.update(f"{entry[ALGORITHM]}:{entry['bytes']}\n".encode())

    return {
        "algorithm": ALGORITHM,
        "files": files,
        "manifest_sha256": digest.hexdigest(),
    }
