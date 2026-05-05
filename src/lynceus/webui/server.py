"""Uvicorn entry point for lynceus-ui."""

from __future__ import annotations

import argparse
import logging
import sys
import traceback

from lynceus import __version__

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
        db = Database(config.db_path)
        app = create_app(config, db)

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
