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
import threading
import time
import webbrowser
from pathlib import Path

logger = logging.getLogger(__name__)

# How long the auto-open thread waits for uvicorn to report ``started``
# before giving up. The wizard binds in-process and is ready well under a
# second; the generous ceiling just covers a slow/loaded host. On timeout
# we open nothing — the URL+token print is the standing fallback.
BROWSER_OPEN_TIMEOUT_SECONDS = 10.0
BROWSER_OPEN_POLL_SECONDS = 0.1

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


def _browser_url(host: str, port: int, token: str) -> str:
    """Build the tokenized URL to hand the browser.

    An all-interfaces bind (``0.0.0.0`` / ``::``) is not itself browsable;
    the local machine reaches the wizard over loopback regardless, so we
    point the auto-open at ``127.0.0.1`` in that case. The prominent
    URL+token print still shows the literal bind host for remote operators.
    """
    browse_host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    return f"http://{browse_host}:{port}/?token={token}"


def _open_browser_when_ready(
    server,
    url: str,
    *,
    timeout: float = BROWSER_OPEN_TIMEOUT_SECONDS,
    poll: float = BROWSER_OPEN_POLL_SECONDS,
) -> None:
    """Wait for uvicorn to report ``started``, then open ``url`` in a browser.

    Mirrors ``lynceus-quickstart``'s launch mechanism: ``webbrowser.open``
    once the server is actually serving, with the printed URL as the
    fallback. Degrades cleanly where no browser can open — under sudo,
    headless, or no ``DISPLAY`` ``webbrowser.open`` returns False (or
    raises), and the URL+token already on stdout is the operator's path
    in. Intended to run on a daemon thread so it never blocks shutdown.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if getattr(server, "started", False):
            try:
                opened = webbrowser.open(url)
            except Exception as exc:  # pragma: no cover - platform-dependent
                logger.debug("auto-open browser raised: %s", exc)
                opened = False
            if not opened:
                print(f"(no browser opened automatically; visit {url} manually)")
            return
        time.sleep(poll)
    # Server never reported ready in the window — the printed URL stands.
    logger.debug("wizard server not ready within %.0fs; skipping auto-open", timeout)


def run_wizard_server(
    *,
    host: str,
    port: int,
    scope: str,
    target_path: Path,
    reconfigure: bool = False,
    skip_probes: bool = False,
    no_browser: bool = False,
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

    # Auto-open the operator's browser once the server is serving, mirroring
    # lynceus-quickstart. A daemon thread waits for uvicorn's ``started``
    # flag (server.run() blocks the main thread) and opens the tokenized
    # URL; it degrades to the printed URL+token under sudo/headless/no
    # browser. --no-browser opts out (headless hosts, the smoke harness).
    if not no_browser:
        threading.Thread(
            target=_open_browser_when_ready,
            args=(server, _browser_url(host, port, setup_token)),
            daemon=True,
        ).start()

    server.run()
    return 0
