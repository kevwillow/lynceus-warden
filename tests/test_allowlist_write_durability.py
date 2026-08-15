"""A UI allowlist write must be durable, not merely atomic.

`_atomic_write_yaml` writes a tmpfile and `os.replace`s it. That is atomic with
respect to concurrent readers — they see the old content or the new, never a
half-written file — and the docstring said so correctly.

⛔ But atomic is not durable. Without an `fsync` before the replace, the rename
can reach disk ahead of the data, so a power loss leaves the file present and
empty or partially written. That is exactly the corruption
`_validate_ui_entries` exists to survive, arriving through the one path that was
supposed to prevent it — and on the SD-card-backed Pi this targets, it is not a
theoretical crash.

⭐ The sibling helper `cli.bootstrap_kismet._atomic_write_bytes` already does
`flush()` + `fsync()` before its `os.replace`. Two atomic-write helpers in one
codebase disagreeing about durability is the defect.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lynceus.allowlist import (  # noqa: E402
    AllowlistEntry,
    _load_ui_entries,
    add_ui_entry,
)


def test_a_ui_write_is_fsynced_before_the_rename(tmp_path, monkeypatch):
    """⚠️ A structural assertion, deliberately.

    Durability cannot be observed in-process — proving it needs a real power
    cut. What CAN be checked is the ordering contract: the data is fsynced
    while the tmpfile is still the tmpfile, and only then renamed. Asserting
    the sequence is the strongest available statement short of pulling the plug.
    """
    events: list[str] = []
    real_fsync, real_replace = os.fsync, os.replace

    def spy_fsync(fd):
        events.append("fsync")
        return real_fsync(fd)

    def spy_replace(src, dst):
        events.append("replace")
        return real_replace(src, dst)

    monkeypatch.setattr(os, "fsync", spy_fsync)
    monkeypatch.setattr(os, "replace", spy_replace)

    ui = tmp_path / "allowlist_ui.yaml"
    add_ui_entry(ui, AllowlistEntry(pattern="aa:bb:cc:dd:ee:01", pattern_type="mac"))

    assert "fsync" in events, (
        "the UI allowlist was renamed into place without an fsync; a power loss "
        "can leave it present and empty"
    )
    assert events.index("fsync") < events.index("replace"), (
        f"fsync must precede the rename, got {events}"
    )


def test_the_write_still_works(tmp_path):
    """⚠️ The twin. An fsync that broke writing would pass the test above."""
    ui = tmp_path / "allowlist_ui.yaml"
    for i in range(3):
        add_ui_entry(
            ui,
            AllowlistEntry(pattern=f"aa:bb:cc:dd:ee:0{i}", pattern_type="mac"),
        )
    assert len(_load_ui_entries(ui)) == 3
