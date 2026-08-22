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


def remote_exposure_warning(config) -> list[str]:
    """The lines to print when the UI is about to listen off this machine.

    ⛔ This is a compensating control, not decoration, and it is the reason the
    CSRF cookie fix does not ship alone. Until that fix, setting
    ``ui_allow_remote`` attached ``Secure`` to a cookie served over plain HTTP,
    which broke every form. ``BACKLOG.md`` recorded that breakage as the
    exposure being "partially self-limiting ... by a bug rather than by
    design". It never limited anything that mattered, because a caller using
    curl sets both halves of the double-submit itself and was never impeded,
    but it did keep the remote UI unusable enough that nobody left one running.
    Repairing it removes that accident, so the thing it was accidentally hiding
    has to be said out loud instead.

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
        "    authentication  NONE. There is no login and no password.",
        "",
        "Anything that can reach that address can acknowledge alerts, edit the",
        "allowlist, snooze rules, and read /probes. That page is the probe-SSID",
        "history of every device in range, which is a record of where bystanders",
        "have been, not just you.",
        "",
        "The supported remote paths keep the bind on loopback and tunnel to it:",
        "",
        f"    ssh -L {config.ui_bind_port}:127.0.0.1:{config.ui_bind_port} you@this-host",
        "",
        "or a private network such as Tailscale, which authenticates before any",
        "traffic reaches this process.",
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
        # ⛔ stderr, not logger.warning. The warning has to survive
        # `log_level: ERROR`, which is exactly the setting an operator running
        # this unattended is likely to have chosen. A compensating control that
        # a config value can silence is not one.
        for line in remote_exposure_warning(config):
            print(line, file=sys.stderr)

        db = Database(config.db_path)
        # ⭐ The path travels with the config. /settings used to render the
        # user-scope DEFAULT under "active configuration"; --config is required
        # here, so the real answer was always available and simply discarded.
        app = create_app(config, db, config_path=args.config)

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
