"""FastAPI app factory for the lynceus-setup web wizard.

Separate app, separate lifecycle from ``lynceus.webui`` (the
persistent read-only dashboard). The wizard runs once when the
operator invokes ``lynceus-setup --web``, gates every non-exempt
route on a per-run setup token, reuses the existing
``CSRFMiddleware`` for state-changing routes, and serves a multi-
page form. Phase 2a ships the scaffold; routes for the form pages
land in Touches 4-7 below.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from lynceus import __version__
from lynceus.setup.web.auth import SetupTokenMiddleware
from lynceus.setup.web.session import SessionStore
from lynceus.webui.csrf import CSRFMiddleware, get_csrf_token

# Paths exempt from setup-token gating. ``/healthz`` is a liveness
# probe; ``/static`` is exempt so the operator's browser can fetch
# CSS without re-attaching the token to every asset URL (Pico assets
# are public anyway). Equal-or-child-of matching in the middleware
# means ``/static`` covers ``/static/pico.min.css`` without exempting
# ``/staticthing``.
TOKEN_EXEMPT_PATHS: tuple[str, ...] = ("/healthz", "/static")

# Ordered titles for the wizard's form steps. The progress indicator
# template reads this; the placeholder ``/step/<n>`` routes use the
# tuple length as the upper bound. Touches 4-7 below replace each
# placeholder with the real form route while keeping the same ordinal.
# Adding or reordering steps belongs in one place: here.
STEP_TITLES: tuple[str, ...] = (
    "Kismet URL",
    "Kismet API key",
    "Kismet probe",
    "Kismet sources",
    "Probe SSIDs",
    "BLE friendly names",
    "ntfy URL",
    "ntfy topic",
    "ntfy probe",
    "RSSI threshold",
    "Severity overrides",
    "Rules engine",
)
TOTAL_STEPS: int = len(STEP_TITLES)


def _resolve_wizard_templates_dir() -> Path:
    """Locate the wizard templates directory.

    Mirrors ``webui.app._resolve_templates_dir``: prefer
    ``importlib.resources`` (works inside an installed wheel), fall
    back to the source tree for editable installs and tests.
    """
    try:
        from importlib.resources import files

        p = Path(str(files("lynceus.setup.web") / "templates"))
        if p.is_dir():
            return p
    except (ModuleNotFoundError, TypeError, OSError):
        pass
    p = Path(__file__).resolve().parent / "templates"
    if p.is_dir():
        return p
    raise FileNotFoundError("Could not locate lynceus-setup wizard templates directory.")


def _resolve_webui_static_dir() -> Path:
    """Locate ``lynceus.webui``'s static dir for re-mounting.

    The wizard piggybacks on the dashboard's pico.css to avoid
    duplicating the asset (operator decision: shared mount). If the
    dashboard ever ships a wizard-incompatible CSS change, the wizard
    can carve out its own ``setup/web/static`` later — for now the
    shared mount is intentional.
    """
    try:
        from importlib.resources import files

        p = Path(str(files("lynceus.webui") / "static"))
        if p.is_dir():
            return p
    except (ModuleNotFoundError, TypeError, OSError):
        pass
    from lynceus import webui  # local import to avoid eager dashboard loading

    p = Path(webui.__file__).resolve().parent / "static"
    if p.is_dir():
        return p
    raise FileNotFoundError("Could not locate lynceus.webui static directory.")


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

    templates = Jinja2Templates(directory=str(_resolve_wizard_templates_dir()))
    templates.env.globals["csrf_token"] = lambda request: get_csrf_token(request)

    # url_with_token: helper so templates can produce token-bearing
    # links without hand-concatenating ``?token=``. Bound per-request
    # because the token comes from app.state, not the request.
    def _url_with_token(path: str) -> str:
        # Tokens are URL-safe base64 (token_urlsafe), so no escaping is
        # needed. Strip any leading slash dup so call sites can pass
        # either form.
        if not path.startswith("/"):
            path = "/" + path
        return f"{path}?token={setup_token}"

    templates.env.globals["url_with_token"] = _url_with_token
    app.state.templates = templates

    app.mount(
        "/static",
        StaticFiles(directory=str(_resolve_webui_static_dir())),
        name="static",
    )

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
    async def landing(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(
            request=request,
            name="landing.html",
            context={
                "version": __version__,
                "scope": scope,
                "target_path": str(target_path),
                "step_titles": STEP_TITLES,
                "total_steps": TOTAL_STEPS,
                "step_index": 0,
            },
        )

    @app.get("/cancel", response_class=HTMLResponse)
    async def cancel(request: Request) -> HTMLResponse:
        # Clear in-flight session state on cancel. The session store is
        # in-memory, but clearing makes the operator's "start over"
        # path predictable even if they re-open the wizard URL.
        app.state.session_store.clear()
        return templates.TemplateResponse(
            request=request,
            name="cancelled.html",
            context={
                "version": __version__,
                "target_path": str(target_path),
                "step_titles": STEP_TITLES,
                "total_steps": TOTAL_STEPS,
                "step_index": 0,
            },
        )

    # Real step routes. Each section module registers its own
    # ordinals; with Touch 6 landed, every step ordinal 1..TOTAL_STEPS
    # has a literal route, so /step/<unknown> 404s via FastAPI's
    # default unmatched-route handler.
    from lynceus.setup.web.steps_capture import register_capture_steps
    from lynceus.setup.web.steps_kismet import register_kismet_steps
    from lynceus.setup.web.steps_severity_rules import register_severity_rules_steps
    register_kismet_steps(app)
    register_capture_steps(app)
    register_severity_rules_steps(app)

    return app
