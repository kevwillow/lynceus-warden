"""``_atomic_write`` must not leave a pre-existing config file permissive.

Sibling of ``test_bootstrap_kismet_file_modes.py``. The two atomic writers in
this repo look alike and need **opposite** fixes, which is exactly why both
need pinning:

- ``cli.bootstrap_kismet._atomic_write_bytes`` writes a tmpfile and
  ``os.replace``s it, so the result is a **new inode**. Its ``mode`` applies to
  that new inode, which would silently *reset* a file the operator had
  hardened. It must therefore **preserve** the existing mode.
- ``setup.core._atomic_write`` (here) opens the target directly with
  ``O_CREAT | O_TRUNC``, so it reuses the **same inode**. POSIX ignores the
  ``mode`` argument to ``open()`` when the file already exists, so a
  pre-existing ``0644`` survives untouched. It must therefore **enforce** the
  requested mode.

Copying either fix into the other reintroduces the bug it was written to fix.

The defect this file pins was real on ``main`` through ``8609fc9``. The
docstring on ``_atomic_write`` promised:

    the file never exists on disk with permissions broader than requested

Measured against that promise before the fix::

    fresh file     -> 0o600      (the only case the existing tests covered)
    before rewrite -> 0o644
    after  rewrite -> 0o644      content: 'kismet_api_key: ...\\nntfy_topic: ...'

⇒ every existing ``_atomic_write`` test created a fresh ``tmp_path`` file, and
two of them asserted the *argument handed to* ``os.open`` rather than the mode
the file actually ended up with. Wiring-in is not behaviour.
"""

from __future__ import annotations

import os
import stat
import sys

import pytest

from lynceus.setup import core as wiz

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX-only file mode semantics"
)

SECRETS = "kismet_api_key: s3cret-key-value\nntfy_topic: private-topic-abc123\n"


def _mode(path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@pytest.mark.parametrize("preexisting", [0o644, 0o664, 0o666, 0o640])
def test_rewrite_tightens_a_permissive_existing_config(tmp_path, preexisting):
    """The defect: an existing permissive config keeps its mode on rewrite.

    ``O_TRUNC`` empties the file but changes no permission bit, and ``open``'s
    ``mode`` argument applies to creation only. Before the fix this returned
    the ``preexisting`` mode with the secrets written into it.
    """
    target = tmp_path / "lynceus.yaml"
    target.write_text("stale: true\n")
    os.chmod(target, preexisting)
    assert _mode(target) == preexisting, "fixture did not take"

    wiz._atomic_write(target, SECRETS)

    assert _mode(target) == 0o600, (
        f"rewrite left {oct(_mode(target))} on a file containing the Kismet API "
        f"key and ntfy topic (was {oct(preexisting)} before the write)"
    )
    assert target.read_text() == SECRETS


@pytest.mark.parametrize("preexisting", [0o644, 0o664, 0o666])
def test_secrets_are_never_group_or_world_readable_after_rewrite(tmp_path, preexisting):
    """State the security property directly, not via an exact-mode equality.

    An exact ``== 0o600`` assertion passes for the wrong reason if the default
    ever changes. This one fails for any mode that lets another local user read
    the shared secrets, which is the thing that actually matters.
    """
    target = tmp_path / "lynceus.yaml"
    target.write_text("old\n")
    os.chmod(target, preexisting)

    wiz._atomic_write(target, SECRETS)

    mode = _mode(target)
    assert not mode & stat.S_IRGRP, f"group-readable ({oct(mode)}) with secrets in it"
    assert not mode & stat.S_IROTH, f"world-readable ({oct(mode)}) with secrets in it"
    assert not mode & stat.S_IWGRP, f"group-writable ({oct(mode)})"
    assert not mode & stat.S_IWOTH, f"world-writable ({oct(mode)})"


def test_rewrite_honours_an_explicit_mode(tmp_path):
    """``mode=`` must still win on an existing file.

    No production call site passes a non-default mode today -- system-mode
    group-readability is granted afterwards by ``_apply_system_perms_to_file``
    -- but the kwarg is public API and the fix must not quietly ignore it.
    """
    target = tmp_path / "shared.yaml"
    target.write_text("old\n")
    os.chmod(target, 0o644)

    wiz._atomic_write(target, "x\n", mode=0o640)

    assert _mode(target) == 0o640


def test_fresh_file_mode_is_unchanged_by_the_fix(tmp_path):
    """Regression guard: the creation path must still produce 0600."""
    target = tmp_path / "new.yaml"
    wiz._atomic_write(target, SECRETS)
    assert _mode(target) == 0o600
    assert target.read_text() == SECRETS


def test_mode_is_tightened_before_the_secret_is_written(tmp_path, monkeypatch):
    """Ordering is the whole point: no window where the secret is on disk
    under the old permissive mode.

    Records the file's mode at the moment of each ``write``. If the fix
    chmodded *after* writing, the secret would have been readable by every
    local user for that interval -- the same shape as the S2 race the
    docstring says this helper exists to close.
    """
    target = tmp_path / "lynceus.yaml"
    target.write_text("old\n")
    os.chmod(target, 0o644)

    modes_at_write: list[int] = []
    real_fdopen = os.fdopen

    def spy_fdopen(fd, *a, **kw):
        # Wrap the buffered handle rather than os.write: _atomic_write writes
        # through os.fdopen(), whose buffering means os.write may never be
        # called directly and a spy on it records nothing at all.
        handle = real_fdopen(fd, *a, **kw)
        real_handle_write = handle.write

        def spy_handle_write(data):
            modes_at_write.append(stat.S_IMODE(os.fstat(fd).st_mode))
            return real_handle_write(data)

        handle.write = spy_handle_write  # type: ignore[method-assign]
        return handle

    monkeypatch.setattr(wiz.os, "fdopen", spy_fdopen)
    wiz._atomic_write(target, SECRETS)

    assert modes_at_write, "no write observed; the spy did not take"
    assert all(m == 0o600 for m in modes_at_write), (
        f"secret written while the file was {[oct(m) for m in modes_at_write]}"
    )
