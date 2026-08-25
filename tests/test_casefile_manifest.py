"""The bundle's hash manifest.

What it proves is narrow and the tests say so: the digest covers file
NAMES as well as contents, and it is independent of dict ordering, so
two identical bundles agree about their own identity.
"""

import hashlib

from lynceus.casefile.manifest import build_manifest


def test_hashes_each_artifact():
    m = build_manifest({"a.txt": b"hello", "b.txt": b"world"})
    assert m["algorithm"] == "sha256"
    assert m["files"]["a.txt"]["sha256"] == hashlib.sha256(b"hello").hexdigest()
    assert m["files"]["a.txt"]["bytes"] == 5


def test_manifest_digest_changes_when_any_artifact_changes():
    a = build_manifest({"a.txt": b"hello"})
    b = build_manifest({"a.txt": b"hello!"})
    assert a["manifest_sha256"] != b["manifest_sha256"]


def test_manifest_digest_is_order_independent():
    """Dict ordering must not change the digest, or two identical bundles
    disagree about their own identity."""
    a = build_manifest({"a.txt": b"x", "b.txt": b"y"})
    b = build_manifest({"b.txt": b"y", "a.txt": b"x"})
    assert a["manifest_sha256"] == b["manifest_sha256"]


def test_manifest_digest_covers_names_not_just_contents():
    """Renaming a file must change the digest; otherwise a swap goes undetected."""
    a = build_manifest({"a.txt": b"x"})
    b = build_manifest({"renamed.txt": b"x"})
    assert a["manifest_sha256"] != b["manifest_sha256"]
