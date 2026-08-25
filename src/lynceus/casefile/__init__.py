"""Case-file export: the longitudinal record for one device, as a bundle.

Four units, deliberately separated so the disclosure rules have exactly
one home:

    query.py     the choke point. Database -> CaseFile. Every decision
                 about what may be disclosed is made here.
    render.py    CaseFile -> HTML. Has no database access at all.
    manifest.py  SHA-256 per artifact plus a manifest digest.
    bundle.py    CaseFile -> files, as a directory or an in-memory zip.

The CLI and the web UI are two entry points and they both funnel through
query.py, so they cannot drift apart about what a case file contains.
"""

from __future__ import annotations

from .manifest import build_manifest

__all__ = ["build_manifest"]
