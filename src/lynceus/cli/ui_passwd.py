"""lynceus-ui-passwd — set, change, check or remove the web UI password.

The only writer of the credentials file. Everything else reads it.

    lynceus-ui-passwd --config /etc/lynceus/lynceus.yaml          # set / change
    lynceus-ui-passwd --config … --check                          # is one set?
    lynceus-ui-passwd --config … --remove                         # turn auth off
    lynceus-ui-passwd --config … --stdin < secret                 # scripted

⛔ **Setting a password does not affect a running server.** ``lynceus-ui`` reads
the credentials file once, at startup — see the comment in ``webui/app.py`` for
why. This command says so on every write rather than leaving it to be
discovered as "the password did not work".

⚠️ **``--stdin`` exists because the alternative is worse.** Without it an
operator automating an install pipes a password into an interactive prompt and
it fails, or worse, passes it as an argument where it lands in ``ps`` output and
shell history. There is deliberately no ``--password`` flag.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from .. import __version__
from ..config import load_config
from ..webui.auth import MIN_PASSWORD_LENGTH, PasswordError, hash_password, verify_password
from ..webui.credentials import (
    CredentialsError,
    load_credentials,
    remove_credentials,
    write_credentials,
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lynceus-ui-passwd",
        description="Set, check or remove the lynceus web UI password.",
    )
    parser.add_argument("--config", help="Path to lynceus.yaml. Required except for --version.")
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Read the password from stdin instead of prompting. "
        "The first line is used; a trailing newline is stripped.",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Report whether a password is set, and exit. Writes nothing.",
    )
    parser.add_argument(
        "--remove",
        action="store_true",
        help="Delete the credentials file, turning authentication off.",
    )
    parser.add_argument("--version", action="store_true", help="Print version and exit.")
    return parser


def _read_password_from_stdin() -> str:
    """First line of stdin, newline stripped.

    ⚠️ ``readline`` rather than ``read``: a here-string, a file with a trailing
    newline and ``echo`` all append one, and an operator whose password
    silently gained a ``\\n`` would be locked out by a character they cannot
    see. Taking the first line makes all three spellings agree.
    """
    line = sys.stdin.readline()
    return line.rstrip("\n").rstrip("\r")


def _prompt_for_password() -> str | None:
    """Prompt twice, confirming. None when they did not match."""
    first = getpass.getpass("New web UI password: ")
    second = getpass.getpass("Confirm: ")
    if first != second:
        return None
    return first


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.version:
        print(f"lynceus-ui-passwd {__version__}")
        return 0

    if not args.config:
        parser.print_usage(sys.stderr)
        print("lynceus-ui-passwd: error: --config is required", file=sys.stderr)
        return 1

    if args.check and args.remove:
        print(
            "lynceus-ui-passwd: error: --check and --remove are mutually exclusive",
            file=sys.stderr,
        )
        return 1

    try:
        config = load_config(args.config)
    except FileNotFoundError:
        print(f"lynceus-ui-passwd: no such config file: {args.config}", file=sys.stderr)
        return 1
    except Exception as exc:  # noqa: BLE001 — surface the parse error verbatim
        print(f"lynceus-ui-passwd: cannot load {args.config}: {exc}", file=sys.stderr)
        return 1

    path: Path = config.resolved_ui_auth_path()

    if args.check:
        return _do_check(path)
    if args.remove:
        return _do_remove(path, config)
    return _do_set(path, args)


def _do_check(path: Path) -> int:
    """Report the state. Exit 0 when a password is set, 1 when not.

    ⚠️ The exit code is the machine-readable half and it is the useful way
    round for a provisioning script: ``lynceus-ui-passwd --check || set-one``.
    """
    try:
        credentials = load_credentials(path)
    except CredentialsError as exc:
        print(f"lynceus-ui-passwd: {exc}", file=sys.stderr)
        return 3
    if credentials is None:
        print(f"No web UI password is set. ({path} does not exist.)")
        print("The UI will start unauthenticated on a loopback bind, and will")
        print("REFUSE to start on a non-loopback one.")
        return 1
    print(f"A web UI password is set. ({path})")
    if credentials.over_broad_mode is not None:
        print(
            f"⚠️  That file is mode {credentials.over_broad_mode:04o} and holds the "
            f"password hash. Fix with: chmod 600 {path}",
            file=sys.stderr,
        )
    return 0


def _do_remove(path: Path, config) -> int:
    from ..config import LOOPBACK_HOSTS

    removed = remove_credentials(path)
    if not removed:
        print(f"No web UI password was set. ({path} does not exist.)")
        return 0
    print(f"Removed {path}. The web UI no longer requires a password.")
    # ⛔ Name the consequence at the moment it is created, not in a document.
    # Removing the password on a host that is bound off-loopback does not
    # reopen the UI to the network — it stops lynceus-ui starting at all — and
    # an operator who learns that from a failed restart at 2am has been served
    # badly by this command.
    if config.ui_bind_host not in LOOPBACK_HOSTS:
        print(
            f"⚠️  ui_bind_host is {config.ui_bind_host}, which is not loopback. "
            f"lynceus-ui will now REFUSE to start until a password is set again "
            f"or the bind is moved back to 127.0.0.1.",
            file=sys.stderr,
        )
    print("Restart lynceus-ui for this to take effect.")
    return 0


def _do_set(path: Path, args) -> int:
    if args.stdin:
        password = _read_password_from_stdin()
        if not password:
            print("lynceus-ui-passwd: no password on stdin", file=sys.stderr)
            return 1
    else:
        if not sys.stdin.isatty():
            print(
                "lynceus-ui-passwd: stdin is not a terminal, so there is nowhere "
                "to prompt. Use --stdin to read the password from a pipe.",
                file=sys.stderr,
            )
            return 1
        password = _prompt_for_password()
        if password is None:
            print("lynceus-ui-passwd: passwords did not match", file=sys.stderr)
            return 1

    try:
        encoded = hash_password(password)
    except PasswordError as exc:
        print(f"lynceus-ui-passwd: {exc}", file=sys.stderr)
        if "at least" in str(exc):
            print(
                f"           A passphrase of {MIN_PASSWORD_LENGTH}+ characters you can "
                f"actually type beats a short one with punctuation in it.",
                file=sys.stderr,
            )
        return 1

    # ⛔ Verify the hash we are about to store round-trips BEFORE writing it.
    # A hash that cannot verify its own password locks the operator out of
    # their own dashboard, and the failure surfaces at the next login rather
    # than here, where it is still fixable. Cheap: one extra scrypt.
    if not verify_password(password, encoded):
        print(
            "lynceus-ui-passwd: the hash did not verify against the password it "
            "was just made from. Nothing was written. This is a bug — please "
            "report it.",
            file=sys.stderr,
        )
        return 3

    try:
        written = write_credentials(path, encoded)
    except OSError as exc:
        print(f"lynceus-ui-passwd: cannot write {path}: {exc}", file=sys.stderr)
        return 1

    print(f"Web UI password set. ({written})")
    print("Restart lynceus-ui for this to take effect.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
