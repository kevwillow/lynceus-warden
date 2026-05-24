"""Uvicorn entry point for the lynceus-setup web wizard.

Called from ``lynceus.cli.setup.main`` when the operator passes
``--web``. Generates a fresh per-run setup token, builds the wizard
app, prints the bound URL with the token to stdout, then starts the
ASGI server.

We construct ``uvicorn.Server`` explicitly (rather than calling the
``uvicorn.run`` convenience wrapper) so the ``/done`` handler in
``review.py`` can signal a clean shutdown via
``server.should_exit = True``. The server instance is stashed on
``app.state.server`` for the handler to reach.
"""

from __future__ import annotations

import logging
import secrets
from pathlib import Path

logger = logging.getLogger(__name__)

# Defaults exposed for the CLI argparse layer in ``lynceus.cli.setup``.
# Bind defaults to loopback because the wizard is a single-operator,
# single-machine ceremony; ``--bind 0.0.0.0`` is the explicit opt-out
# (mirrors ``Config.ui_allow_remote`` for the persistent dashboard).
# Port is one above ``Config.ui_bind_port`` (8765) so the wizard
# doesn't collide with a running ``lynceus-ui.service``.
DEFAULT_WIZARD_BIND: str = "127.0.0.1"
DEFAULT_WIZARD_PORT: int = 8766


def generate_setup_token() -> str:
    """Fresh single-use setup token for one wizard run."""
    return secrets.token_urlsafe(32)


def run_wizard_server(
    *,
    host: str,
    port: int,
    scope: str,
    target_path: Path,
    reconfigure: bool = False,
    skip_probes: bool = False,
) -> int:
    """Generate a token, build the wizard app, run uvicorn.

    Prints the URL with the token before binding so an operator who
    cancels with Ctrl-C still has the URL in their scrollback.

    The uvicorn Server is built explicitly and stashed on
    ``app.state.server`` so the /done handler can flip
    ``server.should_exit = True`` for a clean shutdown after the
    operator clicks Done. Ctrl-C continues to work via uvicorn's
    own signal handler — the manual fallback.

    Returns 0 once uvicorn exits cleanly.
    """
    import uvicorn

    from lynceus.setup.web.app import create_wizard_app

    setup_token = generate_setup_token()
    app = create_wizard_app(
        setup_token=setup_token,
        scope=scope,
        target_path=target_path,
        reconfigure=reconfigure,
        skip_probes=skip_probes,
    )

    print(f"lynceus-setup web wizard listening on http://{host}:{port}")
    print("open this URL in your browser:")
    print(f"  http://{host}:{port}/?token={setup_token}")

    config = uvicorn.Config(
        app,
        host=host,
        port=port,
        log_level="info",
        access_log=True,
    )
    server = uvicorn.Server(config)
    # Expose the server so the /done handler in review.py can signal a
    # clean shutdown. The handler does ``request.app.state.server
    # .should_exit = True`` after a brief delay so the "shutting down"
    # response flushes before the socket closes.
    app.state.server = server

    server.run()
    return 0
