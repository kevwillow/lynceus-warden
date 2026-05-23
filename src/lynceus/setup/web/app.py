"""FastAPI app factory for the lynceus-setup web wizard.

Separate app, separate lifecycle from ``lynceus.webui`` (the
persistent read-only dashboard). The wizard runs once when the
operator invokes ``lynceus-setup --web``, gates every non-exempt
route on a per-run setup token, reuses the existing
``CSRFMiddleware`` for state-changing routes, and serves a multi-
page form. Phase 2a ships the scaffold; routes for the form pages
land in Touches 3-7 below.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

from lynceus import __version__
from lynceus.setup.web.auth import SetupTokenMiddleware
from lynceus.setup.web.session import SessionStore
from lynceus.webui.csrf import CSRFMiddleware

# Exempt paths skip the setup-token check. ``/healthz`` is a liveness
# probe; ``/static`` is added in Touch 3 when the wizard mounts the
# webui static assets. Touch 1 keeps just liveness.
TOKEN_EXEMPT_PATHS: tuple[str, ...] = ("/healthz",)


def create_wizard_app(
    *,
    setup_token: str,
    scope: str,
    target_path: Path,
    reconfigure: bool = False,
    skip_probes: bool = False,
) -> FastAPI:
    """Build the wizard FastAPI app.

    ``setup_token`` gates every non-exempt route. ``scope``,
    ``target_path``, ``reconfigure``, ``skip_probes`` ride on
    ``app.state`` so the Phase 2b apply route can consume them without
    re-deriving from argparse.
    """
    app = FastAPI(
        title="lynceus-setup",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    app.state.setup_token = setup_token
    app.state.scope = scope
    app.state.target_path = target_path
    app.state.reconfigure = reconfigure
    app.state.skip_probes = skip_probes
    app.state.session_store = SessionStore()

    # Middleware order: ``add_middleware`` wraps LIFO, so the LAST
    # added is OUTERMOST. We want the token gate to run first (cheap
    # reject of unauth requests before CSRF state setup), so CSRF is
    # added first and Token second.
    app.add_middleware(CSRFMiddleware, cookie_secure=False)
    app.add_middleware(
        SetupTokenMiddleware,
        setup_token=setup_token,
        exempt_paths=TOKEN_EXEMPT_PATHS,
    )

    @app.get("/healthz")
    async def healthz() -> JSONResponse:
        return JSONResponse({"status": "ok", "service": "lynceus-setup-web"})

    @app.get("/", response_class=HTMLResponse)
    async def root_placeholder(request: Request) -> HTMLResponse:
        return HTMLResponse(
            "<!doctype html><title>lynceus-setup</title>"
            "<h1>lynceus-setup wizard</h1>"
            "<p>Wizard route stubs go here (Touch 3+).</p>"
        )

    return app
