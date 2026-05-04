"""Talos read-only web UI. FastAPI app factory."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from talos import __version__
from talos.config import Config
from talos.db import Database

PACKAGE = "talos.webui"


def _resolve_templates_dir() -> Path:
    try:
        from importlib.resources import files

        p = Path(str(files(PACKAGE) / "templates"))
        if p.is_dir():
            return p
    except (ModuleNotFoundError, TypeError, OSError):
        pass
    repo = Path(__file__).resolve().parent / "templates"
    if repo.is_dir():
        return repo
    raise FileNotFoundError("Could not locate talos webui templates directory.")


def _resolve_static_dir() -> Path:
    try:
        from importlib.resources import files

        p = Path(str(files(PACKAGE) / "static"))
        if p.is_dir():
            return p
    except (ModuleNotFoundError, TypeError, OSError):
        pass
    repo = Path(__file__).resolve().parent / "static"
    if repo.is_dir():
        return repo
    raise FileNotFoundError("Could not locate talos webui static directory.")


def create_app(config: Config, db: Database) -> FastAPI:
    """App factory. Takes a live Config and Database. Used by both the production
    server entry point and the test client. Does NOT open the DB itself — that's the
    caller's responsibility, so tests can inject an in-memory or tmp_path DB."""

    app = FastAPI(
        title="talos",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    app.state.db = db
    app.state.config = config
    app.state.templates = Jinja2Templates(directory=str(_resolve_templates_dir()))

    app.mount(
        "/static",
        StaticFiles(directory=str(_resolve_static_dir())),
        name="static",
    )

    @app.get("/healthz", response_class=HTMLResponse)
    async def healthz(request: Request):
        health = db.healthcheck()
        return app.state.templates.TemplateResponse(
            request=request,
            name="healthz.html",
            context={"health": health, "version": __version__},
        )

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        return app.state.templates.TemplateResponse(
            request=request,
            name="healthz.html",
            context={"health": db.healthcheck(), "version": __version__},
        )

    return app
