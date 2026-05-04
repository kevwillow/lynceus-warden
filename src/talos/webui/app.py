"""Talos read-only web UI. FastAPI app factory."""

from __future__ import annotations

from math import ceil
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from talos import __version__, kismet
from talos import allowlist as allowlist_mod
from talos import rules as rules_mod
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


def _parse_bool_str(value: str | None, name: str) -> bool | None:
    if value is None:
        return None
    if value == "true":
        return True
    if value == "false":
        return False
    raise HTTPException(status_code=400, detail=f"invalid {name}: expected 'true' or 'false'")


def _total_pages(total_count: int, page_size: int) -> int:
    if total_count <= 0:
        return 1
    return max(1, ceil(total_count / page_size))


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
    def index(request: Request):
        return app.state.templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "version": __version__,
                "active": "home",
                "health": db.healthcheck(),
                "recent_alerts": db.list_alerts(limit=10, acknowledged=False),
                "recent_devices": db.list_devices(limit=10),
            },
        )

    @app.get("/alerts", response_class=HTMLResponse)
    def alerts_list(
        request: Request,
        severity: str | None = Query(default=None),
        acknowledged: str | None = Query(default=None),
        page: int = Query(default=1),
        page_size: int = Query(default=50),
    ):
        if severity is not None and severity not in ("low", "med", "high"):
            raise HTTPException(status_code=400, detail="invalid severity")
        ack_bool = _parse_bool_str(acknowledged, "acknowledged")
        if page < 1:
            raise HTTPException(status_code=400, detail="page must be >= 1")
        if page_size < 10 or page_size > 200:
            raise HTTPException(status_code=400, detail="page_size must be in [10, 200]")

        offset = (page - 1) * page_size
        total_count = db.count_alerts(severity=severity, acknowledged=ack_bool)
        alerts = db.list_alerts(
            limit=page_size,
            offset=offset,
            severity=severity,
            acknowledged=ack_bool,
        )
        return app.state.templates.TemplateResponse(
            request=request,
            name="alerts_list.html",
            context={
                "version": __version__,
                "active": "alerts",
                "alerts": alerts,
                "total_count": total_count,
                "page": page,
                "page_size": page_size,
                "total_pages": _total_pages(total_count, page_size),
                "severity": severity,
                "acknowledged": ack_bool,
            },
        )

    @app.get("/alerts/{alert_id}", response_class=HTMLResponse)
    def alert_detail(request: Request, alert_id: int):
        alert = db.get_alert(alert_id)
        if alert is None:
            return app.state.templates.TemplateResponse(
                request=request,
                name="not_found.html",
                context={
                    "version": __version__,
                    "active": "alerts",
                    "message": f"Alert {alert_id} not found.",
                },
                status_code=404,
            )
        return app.state.templates.TemplateResponse(
            request=request,
            name="alert_detail.html",
            context={
                "version": __version__,
                "active": "alerts",
                "alert": alert,
            },
        )

    @app.get("/devices", response_class=HTMLResponse)
    def devices_list(
        request: Request,
        device_type: str | None = Query(default=None),
        randomized: str | None = Query(default=None),
        page: int = Query(default=1),
        page_size: int = Query(default=50),
    ):
        if device_type is not None and device_type not in ("wifi", "ble", "bt_classic"):
            raise HTTPException(status_code=400, detail="invalid device_type")
        rand_bool = _parse_bool_str(randomized, "randomized")
        if page < 1:
            raise HTTPException(status_code=400, detail="page must be >= 1")
        if page_size < 10 or page_size > 200:
            raise HTTPException(status_code=400, detail="page_size must be in [10, 200]")

        offset = (page - 1) * page_size
        total_count = db.count_devices(device_type=device_type, randomized=rand_bool)
        devices = db.list_devices(
            limit=page_size,
            offset=offset,
            device_type=device_type,
            randomized=rand_bool,
        )
        return app.state.templates.TemplateResponse(
            request=request,
            name="devices_list.html",
            context={
                "version": __version__,
                "active": "devices",
                "devices": devices,
                "total_count": total_count,
                "page": page,
                "page_size": page_size,
                "total_pages": _total_pages(total_count, page_size),
                "device_type": device_type,
                "randomized": rand_bool,
            },
        )

    @app.get("/devices/{mac:path}", response_class=HTMLResponse)
    def device_detail(request: Request, mac: str):
        try:
            normalized = kismet.normalize_mac(mac)
        except ValueError:
            return app.state.templates.TemplateResponse(
                request=request,
                name="not_found.html",
                context={
                    "version": __version__,
                    "active": "devices",
                    "message": f"Malformed MAC address: {mac!r}.",
                },
                status_code=400,
            )
        result = db.get_device_with_sightings(normalized)
        if result is None:
            return app.state.templates.TemplateResponse(
                request=request,
                name="not_found.html",
                context={
                    "version": __version__,
                    "active": "devices",
                    "message": f"Device {normalized} not found.",
                },
                status_code=404,
            )
        return app.state.templates.TemplateResponse(
            request=request,
            name="device_detail.html",
            context={
                "version": __version__,
                "active": "devices",
                "device": result["device"],
                "sightings": result["sightings"],
            },
        )

    @app.get("/rules", response_class=HTMLResponse)
    def rules_list(request: Request):
        ruleset = None
        notice = None
        rules_path = app.state.config.rules_path
        if not rules_path:
            notice = "No rules_path configured. Set rules_path in talos.yaml."
        else:
            try:
                ruleset = rules_mod.load_ruleset(rules_path)
            except FileNotFoundError:
                notice = f"Rules file not found at {rules_path}."
        return app.state.templates.TemplateResponse(
            request=request,
            name="rules_list.html",
            context={
                "version": __version__,
                "active": "rules",
                "ruleset": ruleset,
                "notice": notice,
            },
        )

    @app.get("/allowlist", response_class=HTMLResponse)
    def allowlist_view(request: Request):
        allowlist = None
        notice = None
        allowlist_path = app.state.config.allowlist_path
        if not allowlist_path:
            notice = "No allowlist_path configured. Set allowlist_path in talos.yaml."
        else:
            try:
                allowlist = allowlist_mod.load_allowlist(allowlist_path)
            except FileNotFoundError:
                notice = f"Allowlist file not found at {allowlist_path}."
        return app.state.templates.TemplateResponse(
            request=request,
            name="allowlist_list.html",
            context={
                "version": __version__,
                "active": "allowlist",
                "allowlist": allowlist,
                "notice": notice,
            },
        )

    return app
