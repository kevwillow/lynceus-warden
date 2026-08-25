"""The web UI's credentials file: where the operator's password hash lives.

One file, one hash, ``0600``, in the STATE directory beside the database. Read
by ``lynceus-ui`` at startup; written only by ``lynceus-ui-passwd``.

⛔ **Not in ``lynceus.yaml``.** That file is operator config: it is quoted in bug
reports, copied between machines, and on a ``--system`` install it lives in
``/etc/lynceus``, which the systemd units deliberately exclude from
``ReadWritePaths`` so the daemon cannot rewrite it. A scrypt hash is built to be
stored, but it is still the one string an offline attacker wants, and keeping it
out of the file people paste costs nothing.

⛔ **State directory, not config directory.** Same reasoning that moved
``allowlist_ui.yaml`` (see ``allowlist.derive_ui_path``): a file the UI process
must be able to read on a system install belongs where that process has access.
"""

from __future__ import annotations

import json
import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path

#: Bumped only for a change that an older reader would MISREAD. Adding a key an
#: old reader ignores does not need it.
CREDENTIALS_VERSION = 1

CREDENTIALS_FILENAME = "ui_auth.json"

#: The mode the file is written at, and the mode ``world_readable`` measures
#: against.
CREDENTIALS_MODE = 0o600


class CredentialsError(Exception):
    """The credentials file exists but cannot be used."""


@dataclass(frozen=True)
class Credentials:
    """A loaded credentials file.

    ``over_broad_mode`` is the mode actually found on disk when it grants
    anything to group or other, else None. It is reported rather than enforced:
    refusing to start on a file an operator chmod'd themselves turns a hardening
    warning into an outage, and the operator is the only user of this system.
    ``lynceus-ui`` prints it to stderr at startup.
    """

    password_hash: str
    updated_at: int
    path: Path
    over_broad_mode: int | None = None


def default_credentials_path(db_path: str | Path) -> Path:
    """The credentials file that goes with a given database.

    Derived from ``db_path`` for the same reason ``allowlist_ui.yaml`` is: the
    database is the one path every deployment mode already gets right, and the
    state directory is the one place the UI process is guaranteed to be able to
    read on a ``--system`` install.
    """
    return Path(db_path).parent / CREDENTIALS_FILENAME


def load_credentials(path: str | Path) -> Credentials | None:
    """Load the credentials file, or None when there isn't one.

    ⛔ Returns None ONLY for "no file". Every other problem raises
    ``CredentialsError``, because a corrupt or truncated credentials file must
    not silently degrade into "authentication is not configured" — that is a
    fail-open, and it is reachable by anything that can make a disk write fail
    halfway.
    """
    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise CredentialsError(f"cannot read {p}: {exc}") from exc

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CredentialsError(
            f"{p} is not valid JSON ({exc}). Re-run `lynceus-ui-passwd` to "
            f"rewrite it, or delete it to turn authentication off."
        ) from exc

    if not isinstance(payload, dict):
        raise CredentialsError(f"{p} does not contain a JSON object")

    version = payload.get("version")
    if version != CREDENTIALS_VERSION:
        raise CredentialsError(
            f"{p} has version {version!r}, this build understands "
            f"{CREDENTIALS_VERSION}. A newer lynceus wrote it."
        )

    password_hash = payload.get("password_hash")
    if not isinstance(password_hash, str) or not password_hash:
        raise CredentialsError(f"{p} has no usable password_hash")

    updated_at = payload.get("updated_at")
    if not isinstance(updated_at, int):
        updated_at = 0

    return Credentials(
        password_hash=password_hash,
        updated_at=updated_at,
        path=p,
        over_broad_mode=_over_broad_mode(p),
    )


def _over_broad_mode(path: Path) -> int | None:
    """The file's mode when it grants group or other anything, else None."""
    if os.name != "posix":
        return None
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        return None
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        return mode
    return None


def write_credentials(path: str | Path, password_hash: str) -> Path:
    """Write the credentials file at ``0600``, creating the directory if needed.

    ⛔ The mode is set in ``os.open``'s creation flags AND enforced with
    ``os.fchmod`` on the open descriptor before a byte is written. Both are
    needed and the reason is measured, in ``setup.core._atomic_write``: the
    creation mode applies to a file being CREATED and POSIX ignores it when the
    path already exists, so the rewrite path — an operator changing their
    password, the common case — would leave a pre-existing ``0644`` file at
    ``0644`` and refill it with the hash.

    🪤 ``fchmod`` on the descriptor rather than ``chmod`` on the path: a path
    chmod can be raced by a symlink swap between the open and the chmod.

    ⚠️ Deliberately NOT tmpfile + ``os.replace``. That produces a new inode
    whose mode comes from the umask, which is the opposite bug, and this file
    has exactly one writer — an interactive CLI — so there is no concurrent
    reader to tear. ``cli.bootstrap_kismet._atomic_write_bytes`` is the sibling
    that needs the other behaviour; the two must not be conflated.

    ⚠️ Not imported from ``setup.core``, which has the same primitive. Measured
    2026-08-25: ``import lynceus.setup.core`` pulls in **366 modules and 142 ms**
    including ``requests``, and it is the setup wizard — the web UI must not
    depend on it to serve a login page.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": CREDENTIALS_VERSION,
        "password_hash": password_hash,
        "updated_at": int(time.time()),
    }
    content = json.dumps(payload, indent=2, sort_keys=True) + "\n"

    if os.name != "posix":
        # POSIX mode bits are meaningless on Windows; match the chmod-skip
        # pattern the rest of the codebase uses rather than pretending.
        p.write_text(content, encoding="utf-8")
        return p

    fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, CREDENTIALS_MODE)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        os.fchmod(fh.fileno(), CREDENTIALS_MODE)
        fh.write(content)
        fh.flush()
        os.fsync(fh.fileno())
    return p


def remove_credentials(path: str | Path) -> bool:
    """Delete the credentials file. True when one was there to delete."""
    p = Path(path)
    try:
        p.unlink()
        return True
    except FileNotFoundError:
        return False
