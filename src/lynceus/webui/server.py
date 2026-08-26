"""Uvicorn entry point for lynceus-ui."""

from __future__ import annotations

import argparse
import logging
import sys
import traceback

from lynceus import __version__
from lynceus.config import LOOPBACK_HOSTS

logger = logging.getLogger(__name__)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lynceus-ui", description="Lynceus read-only web UI server."
    )
    parser.add_argument("--config", help="Path to lynceus.yaml config file.")
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print version and exit.",
    )
    return parser


def remote_bind_refusal(config, *, credentials_configured: bool) -> list[str]:
    """The lines to print when an off-loopback bind has no password, or [].

    ⛔ **A refusal, not a warning, and that is the whole point of this feature.**
    Until authentication existed the only honest thing to do here was to print
    an unmissable banner and start anyway. Now that a password can be set, an
    off-loopback bind without one is a configuration this build declines to
    serve — otherwise the feature ships switched off exactly where the exposure
    is, which is the failure mode this change exists to remove.

    ⚠️ Keyed on the BIND HOST, not on ``ui_allow_remote``. The flag is a
    permission and the bind is the fact: ``ui_allow_remote: true`` with the host
    left at loopback exposes nothing and must not refuse.

    ⭐ It prints the way forward rather than trying to repair anything. This
    repo has already paid for a recovery path that had never been executed —
    a delete-and-recreate written to fix a failed release destroyed the release
    it was meant to repair and burned a version number permanently. When the
    recovery is destructive and unproven, refuse and name the next command.
    """
    if config.ui_bind_host in LOOPBACK_HOSTS:
        return []
    if credentials_configured:
        return []
    rule = "=" * 74
    return [
        rule,
        "lynceus-ui REFUSES to start.",
        "",
        f"    bind            {config.ui_bind_host}:{config.ui_bind_port}",
        "    authentication  NONE — no password is set",
        "",
        "That address is reachable by other machines, and anything that can",
        "reach it could acknowledge alerts, edit the allowlist, snooze rules,",
        "read /probes — the probe-SSID history of every device in range, which",
        "is a record of where bystanders have been, not just you — and download",
        "a device's complete case file in a single request.",
        "",
        "Set a password, then start again:",
        "",
        "    lynceus-ui-passwd --config <your lynceus.yaml>",
        "",
        "Or keep the bind on loopback and tunnel to it, which needs no password:",
        "",
        f"    ssh -L {config.ui_bind_port}:127.0.0.1:{config.ui_bind_port} you@this-host",
        "",
        "or a private network such as Tailscale, which authenticates before any",
        "traffic reaches this process.",
        rule,
    ]


def remote_exposure_warning(config) -> list[str]:
    """The lines to print when the UI is about to listen off this machine.

    Reached only when a password IS set — ``remote_bind_refusal`` has already
    turned back the case where one is not — so this no longer says
    "authentication NONE". What it says instead is the thing a password does
    not fix.

    ⛔ **The transport is plain HTTP and nothing here serves TLS.** A password
    authenticates the operator to the server; it does nothing about the wire.
    Bound off-loopback, the password itself and the session cookie that follows
    it cross the network in cleartext, readable by anything on the path. That
    is a *worse* disclosure than the unauthenticated dashboard was, because it
    is a reusable credential rather than a snapshot, and it is exactly the
    conclusion an operator who has just set a password is least likely to reach
    on their own. Adding authentication is what made this warning necessary; it
    is not what made it unnecessary.

    ⭐ Keyed on the BIND HOST, not on ``ui_allow_remote``. The flag is a
    permission and the bind is the fact: ``ui_allow_remote: true`` with the
    host left at loopback exposes nothing and must not warn, or operators learn
    to scroll past it.
    """
    if config.ui_bind_host in LOOPBACK_HOSTS:
        return []
    rule = "=" * 74
    return [
        rule,
        "lynceus-ui is listening where other machines can reach it.",
        "",
        f"    bind            {config.ui_bind_host}:{config.ui_bind_port}",
        "    authentication  password (one operator)",
        "    transport       HTTP. NOT encrypted. lynceus serves no TLS.",
        "",
        "A password proves who you are to this server. It does not protect the",
        "wire. Over plain HTTP your password and the session cookie it issues",
        "cross the network in the clear, so anything on the path can read them",
        "and reuse them — which is a longer-lived disclosure than the dashboard",
        "itself. /probes is the probe-SSID history of every device in range, a",
        "record of where bystanders have been, not just you.",
        "",
        "The supported remote paths keep the bind on loopback and tunnel to it:",
        "",
        f"    ssh -L {config.ui_bind_port}:127.0.0.1:{config.ui_bind_port} you@this-host",
        "",
        "or a private network such as Tailscale, which authenticates before any",
        "traffic reaches this process. Both encrypt the hop this one does not.",
        rule,
    ]


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.version:
        print(f"lynceus-ui {__version__}")
        return 0

    if not args.config:
        parser.print_usage(sys.stderr)
        print("lynceus-ui: error: --config is required", file=sys.stderr)
        return 1

    db = None
    try:
        from lynceus.config import load_config
        from lynceus.db import Database
        from lynceus.webui.app import create_app

        config = load_config(args.config)
        logging.basicConfig(
            level=getattr(logging, config.log_level, logging.INFO),
            format="%(asctime)s %(levelname)s %(name)s %(message)s",
        )

        from lynceus.webui.credentials import CredentialsError, load_credentials

        try:
            credentials = load_credentials(config.resolved_ui_auth_path())
        except CredentialsError as exc:
            # ⛔ Fail closed, and say so in one readable line rather than a
            # traceback. A credentials file can be corrupt for ordinary reasons
            # — a disk full or a power cut mid-write — and the operator needs to
            # know the UI is refusing because it cannot read the password, NOT
            # that authentication has quietly turned itself off. Silently
            # treating this as "no password configured" would be the fail-open
            # this whole feature exists to close.
            print(f"lynceus-ui: {exc}", file=sys.stderr)
            print(
                "lynceus-ui: refusing to start rather than serving without the "
                "authentication that file configures.",
                file=sys.stderr,
            )
            return 2

        # ⛔ Refuse BEFORE the database is opened and before uvicorn binds.
        # A refusal that has already taken the port is not a refusal.
        refusal = remote_bind_refusal(
            config, credentials_configured=credentials is not None
        )
        if refusal:
            for line in refusal:
                print(line, file=sys.stderr)
            return 2

        # ⛔ stderr, not logger.warning. The warning has to survive
        # `log_level: ERROR`, which is exactly the setting an operator running
        # this unattended is likely to have chosen. A compensating control that
        # a config value can silence is not one.
        for line in remote_exposure_warning(config):
            print(line, file=sys.stderr)

        # Same reasoning, one notch quieter: a credentials file the rest of the
        # machine can read is a hardening problem, not an exposure, and the
        # operator is the only user. Reported, never enforced — refusing to
        # start on a file they chmod'd themselves turns advice into an outage.
        if credentials is not None and credentials.over_broad_mode is not None:
            print(
                f"lynceus-ui: {credentials.path} is mode "
                f"{credentials.over_broad_mode:04o}; it holds the UI password "
                f"hash and should be 0600. Fix with: chmod 600 {credentials.path}",
                file=sys.stderr,
            )

        db = Database(config.db_path)
        # ⭐ The path travels with the config. /settings used to render the
        # user-scope DEFAULT under "active configuration"; --config is required
        # here, so the real answer was always available and simply discarded.
        # ⛔ Hand over the credentials THIS function already checked. Re-reading
        # them inside create_app would make the non-loopback refusal above and
        # the AuthMiddleware decision read two different snapshots of a mutable
        # file; see create_app's comment for the fail-open that produced.
        app = create_app(
            config, db, config_path=args.config, credentials=credentials
        )

        import uvicorn

        uvicorn.run(
            app,
            host=config.ui_bind_host,
            port=config.ui_bind_port,
            log_level=config.log_level.lower(),
            access_log=True,
        )
        return 0
    except Exception:
        logger.error("lynceus-ui failed:\n%s", traceback.format_exc())
        return 1
    finally:
        if db is not None:
            try:
                db.close()
            except Exception:
                logger.exception("error closing database during shutdown")


if __name__ == "__main__":
    sys.exit(main())
