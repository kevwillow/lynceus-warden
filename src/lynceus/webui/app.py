"""Lynceus read-only web UI. FastAPI app factory."""

from __future__ import annotations

import datetime as _dt
import importlib.metadata
import json
import logging
import math
import time
from math import ceil
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from lynceus import __version__, kismet, paths
from lynceus import allowlist as allowlist_mod
from lynceus import rules as rules_mod
from lynceus.config import Config
from lynceus.db import Database
from lynceus.redact import redact_ntfy_topic
from lynceus.webui.csrf import CSRFMiddleware, get_csrf_token

logger = logging.getLogger(__name__)

PACKAGE = "lynceus.webui"

KISMET_STATUS_CACHE_TTL = 30


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
    raise FileNotFoundError("Could not locate lynceus webui templates directory.")


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
    raise FileNotFoundError("Could not locate lynceus webui static directory.")


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


def _parse_date_to_ts(value: str, *, end_of_day: bool, name: str) -> int:
    try:
        d = _dt.date.fromisoformat(value)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=f"invalid {name}: {value!r}") from exc
    base = _dt.datetime.combine(d, _dt.time.min, tzinfo=_dt.UTC)
    if end_of_day:
        base = base.replace(hour=23, minute=59, second=59)
    return int(base.timestamp())


def _normalize_optional_note(note: str | None) -> str | None:
    if note is None or note == "":
        return None
    if len(note) > 500:
        raise HTTPException(status_code=400, detail="note must be <= 500 chars")
    return note


def unix_to_iso(ts) -> str:
    """Format a unix epoch int as ISO 8601 UTC with 'Z' suffix.

    None/empty → "" so templates can render the value unconditionally.
    """
    if ts is None or ts == "":
        return ""
    dt = _dt.datetime.fromtimestamp(int(ts), tz=_dt.UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def unix_to_utc_human(ts) -> str:
    """Format a unix epoch int as 'YYYY-MM-DD HH:MM UTC' for human display."""
    if ts is None or ts == "":
        return ""
    dt = _dt.datetime.fromtimestamp(int(ts), tz=_dt.UTC)
    return dt.strftime("%Y-%m-%d %H:%M UTC")


_RSSI_SPARKLINE_WIDTH = 200
_RSSI_SPARKLINE_HEIGHT = 40


def render_rssi_sparkline(rssi_history) -> str:
    """Return a small inline SVG plotting the captured RSSI series.

    Empty / None input returns an empty string so the template can omit
    the section. A constant series renders a flat midline (no divide-by-
    zero in the normalization step). Stronger signal (less negative dBm)
    plots towards the top of the chart, matching operator intuition.

    The SVG uses ``stroke="currentColor"`` so it inherits the surrounding
    text color in both light and dark themes (no theme-specific palette
    needed). No user-controlled attributes are interpolated — every
    interpolated value is an int or a server-computed float — so the
    output is safe to render with Jinja's ``| safe``.
    """
    if not rssi_history:
        return ""
    values: list[int] = []
    for sample in rssi_history:
        if isinstance(sample, dict) and "rssi" in sample:
            try:
                values.append(int(sample["rssi"]))
            except (TypeError, ValueError):
                continue
    if not values:
        return ""
    n = len(values)
    rmin = min(values)
    rmax = max(values)
    span = rmax - rmin
    height = _RSSI_SPARKLINE_HEIGHT
    width = _RSSI_SPARKLINE_WIDTH
    if span == 0:
        ys = [height / 2.0] * n
    else:
        ys = [(rmax - v) / span * height for v in values]
    if n == 1:
        xs = [width / 2.0]
    else:
        step = width / (n - 1)
        xs = [i * step for i in range(n)]
    points = " ".join(f"{x:.2f},{y:.2f}" for x, y in zip(xs, ys, strict=True))
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" class="rssi-sparkline" '
        f'width="{width}" height="{height}" viewBox="0 0 {width} {height}" '
        f'role="img" aria-label="RSSI history over the last 60 seconds">'
        f'<polyline fill="none" stroke="currentColor" stroke-width="1.5" '
        f'points="{points}"/>'
        f'<text x="{width - 2}" y="10" text-anchor="end" font-size="9" '
        f'fill="currentColor">min: {rmin} max: {rmax}</text>'
        f"</svg>"
    )


_SEVERITY_ORDER = {"high": 0, "med": 1, "low": 2}


def _watchlist_sort_key(entry: dict) -> tuple[int, str]:
    return (_SEVERITY_ORDER.get(entry.get("severity"), 99), entry.get("pattern") or "")


def _enrich_alerts_with_devices(db, alerts: list[dict]) -> None:
    """Populate alert['device'] (a dict or None) for each alert in-place.

    Templates render the Device column off this enriched dict. Alerts
    with mac=None or with a mac that has no matching device row get
    device=None and the template renders an em dash.
    Errors on individual lookups are swallowed so one bad row cannot
    crash the page."""
    for alert in alerts:
        mac = alert.get("mac")
        if not mac:
            alert["device"] = None
            continue
        try:
            alert["device"] = db.get_device(mac)
        except Exception:
            alert["device"] = None


def _device_label(device: dict | None) -> str:
    """Best-available human label for a device.

    Priority: friendly_name (BLE/BT advertised name, v0.3+) → oui_vendor
    (Kismet manuf, v0.2) → "—". Forward-compatible: a v0.2 dict without
    the friendly_name key falls through to oui_vendor naturally."""
    if not device:
        return "—"
    name = device.get("friendly_name")
    if name and name.strip():
        return name.strip()
    vendor = device.get("oui_vendor")
    if vendor and vendor.strip():
        return vendor.strip()
    return "—"


def _safe_redirect_target(request: Request, default: str) -> str:
    referer = request.headers.get("referer")
    if not referer:
        return default
    try:
        parsed = urlparse(referer)
    except ValueError:
        return default
    request_host = request.url.netloc
    if parsed.netloc and parsed.netloc != request_host:
        return default
    if parsed.scheme and parsed.scheme not in ("http", "https"):
        return default
    path = parsed.path or ""
    if path == "/alerts":
        return "/alerts"
    if path.startswith("/alerts/"):
        suffix = path[len("/alerts/") :]
        if suffix.isdigit() and int(suffix) >= 1:
            return path
    return default


def _build_ui_kismet_client(config: Config) -> kismet.KismetClient:
    if config.kismet_fixture_path:
        return kismet.FakeKismetClient(config.kismet_fixture_path)
    return kismet.KismetClient(
        config.kismet_url,
        api_key=config.kismet_api_key,
        timeout=config.kismet_timeout_seconds,
    )


def _humanize_bytes(num: int) -> str:
    """Format a byte count as a short human string (e.g. ``"1.2 MB"``)."""
    n = float(num)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024.0:
            if unit == "B":
                return f"{int(n)} {unit}"
            return f"{n:.1f} {unit}"
        n /= 1024.0
    return f"{n:.1f} PB"


def _watchlist_origin_breakdown(db: Database) -> dict:
    """Return total + argus/yaml/bundled split for the watchlist.

    Discriminator: argus_record_id ``LIKE 'yaml-%'`` is yaml-seeded;
    other metadata rows are argus-imported; watchlist rows with no
    metadata row are bundled-or-other (matches Prompt 24's pattern).
    """
    conn = db._conn
    total = conn.execute("SELECT COUNT(*) AS c FROM watchlist").fetchone()["c"]
    argus = conn.execute(
        "SELECT COUNT(*) AS c FROM watchlist_metadata WHERE argus_record_id NOT LIKE 'yaml-%'"
    ).fetchone()["c"]
    yaml_seeded = conn.execute(
        "SELECT COUNT(*) AS c FROM watchlist_metadata WHERE argus_record_id LIKE 'yaml-%'"
    ).fetchone()["c"]
    bundled = conn.execute(
        "SELECT COUNT(*) AS c FROM watchlist w "
        "LEFT JOIN watchlist_metadata m ON m.watchlist_id = w.id "
        "WHERE m.id IS NULL"
    ).fetchone()["c"]
    last_imported = conn.execute("SELECT MAX(updated_at) AS ts FROM watchlist_metadata").fetchone()[
        "ts"
    ]
    return {
        "total": int(total),
        "argus": int(argus),
        "yaml": int(yaml_seeded),
        "bundled": int(bundled),
        "last_imported_ts": last_imported,
    }


def _build_settings_context(config: Config, db: Database, kismet_status: dict) -> dict:
    """Compute the read-only /settings page payload.

    Sensitive values (Kismet token, full ntfy topic) are redacted on the
    server — the raw values never leave this function. The template only
    sees the safe-to-render strings produced here.
    """
    ntfy_topic_display = redact_ntfy_topic(config.ntfy_topic) if config.ntfy_topic else ""
    kismet_token_display = "•••••• (configured)" if config.kismet_api_key else "(not configured)"

    db_path = Path(config.db_path)
    db_size_human: str | None = None
    db_mtime: int | None = None
    if db_path.exists():
        try:
            stat = db_path.stat()
            db_size_human = _humanize_bytes(stat.st_size)
            db_mtime = int(stat.st_mtime)
        except OSError:
            db_size_human = None
            db_mtime = None

    overrides_path = paths.default_overrides_path("user")
    config_path_default = paths.default_config_path("user")
    log_dir_default = paths.default_log_dir("user")

    try:
        lynceus_version = importlib.metadata.version("lynceus")
    except importlib.metadata.PackageNotFoundError:
        lynceus_version = __version__

    return {
        "capture": {
            "probe_ssids": bool(config.capture.probe_ssids),
            "ble_friendly_names": bool(config.capture.ble_friendly_names),
        },
        "kismet": {
            "url": config.kismet_url,
            "token_display": kismet_token_display,
            "sources": config.kismet_sources or [],
            "status": kismet_status,
        },
        "ntfy": {
            "url": config.ntfy_url or "",
            "topic_display": ntfy_topic_display,
            "configured": bool(config.ntfy_url and config.ntfy_topic),
        },
        "watchlist_stats": _watchlist_origin_breakdown(db),
        "severity_overrides": {
            "path": str(overrides_path),
            "exists": overrides_path.exists(),
        },
        "system": {
            "lynceus_version": lynceus_version,
            "db_path": str(db_path),
            "db_size_human": db_size_human,
            "db_mtime": db_mtime,
            "config_path": str(config_path_default),
            "log_dir": str(log_dir_default),
        },
    }


def _get_kismet_status(app: FastAPI, now: float) -> dict:
    cached = getattr(app.state, "_kismet_status_cache", None)
    cached_ts = getattr(app.state, "_kismet_status_cache_ts", None)
    if cached is not None and cached_ts is not None and (now - cached_ts) < KISMET_STATUS_CACHE_TTL:
        return cached
    client = getattr(app.state, "kismet_client", None)
    if client is None:
        client = _build_ui_kismet_client(app.state.config)
        app.state.kismet_client = client
    try:
        status = client.health_check()
    except Exception as e:
        status = {"reachable": False, "version": None, "error": str(e)}
    status = dict(status)
    status["checked_at"] = int(now)
    app.state._kismet_status_cache = status
    app.state._kismet_status_cache_ts = now
    return status


def create_app(config: Config, db: Database) -> FastAPI:
    """App factory. Takes a live Config and Database. Used by both the production
    server entry point and the test client. Does NOT open the DB itself — that's the
    caller's responsibility, so tests can inject an in-memory or tmp_path DB."""

    app = FastAPI(
        title="lynceus",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    app.state.db = db
    app.state.config = config
    app.state.templates = Jinja2Templates(directory=str(_resolve_templates_dir()))
    app.state.templates.env.globals["csrf_token"] = lambda request: get_csrf_token(request)
    app.state.templates.env.filters["unix_to_iso"] = unix_to_iso
    app.state.templates.env.filters["unix_to_utc_human"] = unix_to_utc_human
    app.state.templates.env.filters["device_label"] = _device_label

    app.mount(
        "/static",
        StaticFiles(directory=str(_resolve_static_dir())),
        name="static",
    )

    cookie_secure = bool(config.ui_allow_remote)
    app.add_middleware(CSRFMiddleware, cookie_secure=cookie_secure)

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
        now = time.time()
        now_int = int(now)
        kismet_status = _get_kismet_status(app, now)
        recent_alerts = db.list_alerts(limit=10, acknowledged=False)
        _enrich_alerts_with_devices(db, recent_alerts)
        return app.state.templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "version": __version__,
                "active": "home",
                "health": db.healthcheck(),
                "sev_24h": db.alert_severity_counts(since_ts=now_int - 86400),
                "sev_7d": db.alert_severity_counts(since_ts=now_int - 7 * 86400),
                "sev_30d": db.alert_severity_counts(since_ts=now_int - 30 * 86400),
                "per_day": db.alerts_per_day(days=30, now_ts=now_int),
                "recent_alerts": recent_alerts,
                "recent_devices": db.list_devices(limit=10),
                "device_seen": db.device_seen_counts(now_ts=now_int),
                "last_poll": db.latest_poll_ts(),
                "kismet_status": kismet_status,
            },
        )

    @app.get("/alerts", response_class=HTMLResponse)
    def alerts_list(
        request: Request,
        severity: str | None = Query(default=None),
        acknowledged: str | None = Query(default=None),
        page: int = Query(default=1),
        page_size: int = Query(default=50),
        since: str | None = Query(default=None),
        until: str | None = Query(default=None),
        search: str | None = Query(default=None),
    ):
        if severity is not None and severity not in ("low", "med", "high"):
            raise HTTPException(status_code=400, detail="invalid severity")
        ack_bool = _parse_bool_str(acknowledged, "acknowledged")
        if page < 1:
            raise HTTPException(status_code=400, detail="page must be >= 1")
        if page_size < 10 or page_size > 200:
            raise HTTPException(status_code=400, detail="page_size must be in [10, 200]")
        if search is not None and len(search) > 100:
            raise HTTPException(status_code=400, detail="search must be <= 100 chars")
        since_ts = _parse_date_to_ts(since, end_of_day=False, name="since") if since else None
        until_ts = _parse_date_to_ts(until, end_of_day=True, name="until") if until else None
        search_clean = search if search else None

        offset = (page - 1) * page_size
        total_count = db.count_alerts(
            severity=severity,
            acknowledged=ack_bool,
            since_ts=since_ts,
            until_ts=until_ts,
            search=search_clean,
        )
        alerts = db.list_alerts_with_match(
            {
                "limit": page_size,
                "offset": offset,
                "severity": severity,
                "acknowledged": ack_bool,
                "since_ts": since_ts,
                "until_ts": until_ts,
                "search": search_clean,
            }
        )
        _enrich_alerts_with_devices(db, alerts)
        filters_active = bool(
            severity or ack_bool is not None or since or until or (search and search != "")
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
                "since": since or "",
                "until": until or "",
                "search": search or "",
                "filters_active": filters_active,
            },
        )

    @app.get("/alerts/{alert_id}", response_class=HTMLResponse)
    def alert_detail(request: Request, alert_id: int):
        if alert_id < 1:
            raise HTTPException(status_code=400, detail="alert_id must be positive")
        alert = db.get_alert_with_match(alert_id)
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
        _enrich_alerts_with_devices(db, [alert])
        actions = db.list_alert_actions(alert_id)
        evidence = db.get_evidence_for_alert(alert_id)
        kismet_record_pretty: str | None = None
        rssi_sparkline_svg = ""
        if evidence is not None:
            if evidence["kismet_record_corrupt"]:
                logger.warning(
                    "evidence kismet_record_json could not be parsed for alert %d",
                    alert_id,
                )
            elif evidence["kismet_record"] is not None:
                kismet_record_pretty = json.dumps(evidence["kismet_record"], indent=2)
            if evidence["rssi_history_corrupt"]:
                logger.warning(
                    "evidence rssi_history_json could not be parsed for alert %d",
                    alert_id,
                )
            rssi_sparkline_svg = render_rssi_sparkline(evidence["rssi_history"])
            # Belt-and-suspenders against non-finite GPS values: capture
            # already sanitizes inf/nan to NULL (H-2), but pre-H-2 rows
            # or hand-edited DBs could still hold non-finite floats. The
            # OSM URL would render as "mlat=nan&mlon=inf..." which is
            # malformed. Treat non-finite as absent.
            lat = evidence["gps_lat"]
            lon = evidence["gps_lon"]
            if (isinstance(lat, float) and not math.isfinite(lat)) or (
                isinstance(lon, float) and not math.isfinite(lon)
            ):
                logger.warning(
                    "evidence gps coordinates non-finite for alert %d, hiding GPS section",
                    alert_id,
                )
                evidence["gps_lat"] = None
                evidence["gps_lon"] = None
                evidence["gps_alt"] = None
                evidence["gps_captured_at"] = None
        return app.state.templates.TemplateResponse(
            request=request,
            name="alert_detail.html",
            context={
                "version": __version__,
                "active": "alerts",
                "alert": alert,
                "actions": actions,
                "evidence": evidence,
                "kismet_record_pretty": kismet_record_pretty,
                "rssi_sparkline_svg": rssi_sparkline_svg,
            },
        )

    @app.post("/alerts/bulk-ack", response_class=HTMLResponse)
    def bulk_ack_alerts(
        request: Request,
        alert_ids: list[int] | None = Form(default=None),
        note: str | None = Form(default=None),
    ):
        if not alert_ids:
            raise HTTPException(status_code=400, detail="alert_ids required")
        if len(alert_ids) > 1000:
            raise HTTPException(status_code=400, detail="too many alert_ids")
        for aid in alert_ids:
            if aid < 1:
                raise HTTPException(status_code=400, detail="alert_id must be positive")
        note = _normalize_optional_note(note)
        actor = request.client.host if request.client else "unknown"
        now_ts = int(time.time())
        result = db.bulk_acknowledge_alerts(alert_ids, actor=actor, note=note, ts=now_ts)
        return app.state.templates.TemplateResponse(
            request=request,
            name="bulk_ack_result.html",
            context={
                "version": __version__,
                "active": "alerts",
                "result": result,
            },
        )

    @app.post("/alerts/ack-all-visible", response_class=HTMLResponse)
    def ack_all_visible(
        request: Request,
        severity: str | None = Form(default=None),
        acknowledged: str | None = Form(default=None),
        since: str | None = Form(default=None),
        until: str | None = Form(default=None),
        search: str | None = Form(default=None),
        note: str | None = Form(default=None),
    ):
        sev = severity if severity else None
        if sev is not None and sev not in ("low", "med", "high"):
            raise HTTPException(status_code=400, detail="invalid severity")
        ack_bool = _parse_bool_str(acknowledged if acknowledged else None, "acknowledged")
        if search is not None and len(search) > 100:
            raise HTTPException(status_code=400, detail="search must be <= 100 chars")
        since_ts = _parse_date_to_ts(since, end_of_day=False, name="since") if since else None
        until_ts = _parse_date_to_ts(until, end_of_day=True, name="until") if until else None
        search_clean = search if search else None
        note = _normalize_optional_note(note)

        # Overflow guard runs BEFORE any write so a too-broad filter cannot
        # silently ack thousands of records. count_alerts() is read-only.
        total = db.count_alerts(
            severity=sev,
            acknowledged=ack_bool,
            since_ts=since_ts,
            until_ts=until_ts,
            search=search_clean,
        )
        if total > 1000:
            raise HTTPException(
                status_code=400,
                detail=(
                    "ack-all-visible is capped at 1000 alerts; narrow your "
                    "filter or use bulk-ack with explicit IDs."
                ),
            )
        candidate_alerts = db.list_alerts(
            limit=1000,
            offset=0,
            severity=sev,
            acknowledged=ack_bool,
            since_ts=since_ts,
            until_ts=until_ts,
            search=search_clean,
        )
        ids = [a["id"] for a in candidate_alerts]
        actor = request.client.host if request.client else "unknown"
        now_ts = int(time.time())
        if not ids:
            result = {
                "requested": 0,
                "acknowledged": 0,
                "already_acked": 0,
                "missing": 0,
                "action_rows_written": 0,
            }
        else:
            result = db.bulk_acknowledge_alerts(ids, actor=actor, note=note, ts=now_ts)
        return app.state.templates.TemplateResponse(
            request=request,
            name="bulk_ack_result.html",
            context={
                "version": __version__,
                "active": "alerts",
                "result": result,
            },
        )

    @app.post("/alerts/{alert_id}/ack")
    def ack_alert(
        request: Request,
        alert_id: int,
        note: str | None = Form(default=None),
    ):
        if alert_id < 1:
            raise HTTPException(status_code=400, detail="alert_id must be positive")
        note = _normalize_optional_note(note)
        actor = request.client.host if request.client else "unknown"
        now_ts = int(time.time())
        ok = db.acknowledge_alert(alert_id, actor=actor, note=note, ts=now_ts)
        if not ok:
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
        target = _safe_redirect_target(request, default="/alerts")
        return RedirectResponse(target, status_code=303)

    @app.post("/alerts/{alert_id}/unack")
    def unack_alert(
        request: Request,
        alert_id: int,
        note: str | None = Form(default=None),
    ):
        if alert_id < 1:
            raise HTTPException(status_code=400, detail="alert_id must be positive")
        note = _normalize_optional_note(note)
        actor = request.client.host if request.client else "unknown"
        now_ts = int(time.time())
        ok = db.unacknowledge_alert(alert_id, actor=actor, note=note, ts=now_ts)
        if not ok:
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
        target = _safe_redirect_target(request, default="/alerts")
        return RedirectResponse(target, status_code=303)

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
            notice = "No rules_path configured. Set rules_path in lynceus.yaml."
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

    @app.get("/watchlist", response_class=HTMLResponse)
    def watchlist_list(request: Request):
        rows = db.list_watchlist_with_metadata()
        rows_sorted = sorted(rows, key=_watchlist_sort_key)
        return app.state.templates.TemplateResponse(
            request=request,
            name="watchlist_list.html",
            context={
                "version": __version__,
                "active": "watchlist",
                "entries": rows_sorted,
            },
        )

    @app.get("/watchlist/{watchlist_id}", response_class=HTMLResponse)
    def watchlist_detail(request: Request, watchlist_id: int):
        if watchlist_id < 1:
            raise HTTPException(status_code=400, detail="watchlist_id must be positive")
        rows = db.list_watchlist_with_metadata()
        row = next((r for r in rows if r["id"] == watchlist_id), None)
        if row is None:
            return app.state.templates.TemplateResponse(
                request=request,
                name="not_found.html",
                context={
                    "version": __version__,
                    "active": "watchlist",
                    "message": f"Watchlist entry {watchlist_id} not found.",
                },
                status_code=404,
            )
        entry = {
            "id": row["id"],
            "pattern": row["pattern"],
            "pattern_type": row["pattern_type"],
            "severity": row["severity"],
            "description": row["description"],
            "mac_range_prefix": row.get("mac_range_prefix"),
            "mac_range_prefix_length": row.get("mac_range_prefix_length"),
        }
        has_metadata = row.get("metadata_id") is not None
        metadata = None
        if has_metadata:
            metadata = {
                "argus_record_id": row.get("argus_record_id"),
                "device_category": row.get("device_category"),
                "confidence": row.get("confidence"),
                "vendor": row.get("vendor"),
                "source": row.get("source"),
                "source_url": row.get("source_url"),
                "source_excerpt": row.get("source_excerpt"),
                "fcc_id": row.get("fcc_id"),
                "geographic_scope": row.get("geographic_scope"),
                "first_seen": row.get("first_seen"),
                "last_verified": row.get("last_verified"),
                "notes": row.get("notes"),
            }
        return app.state.templates.TemplateResponse(
            request=request,
            name="watchlist_detail.html",
            context={
                "version": __version__,
                "active": "watchlist",
                "entry": entry,
                "has_metadata": has_metadata,
                "metadata": metadata,
            },
        )

    @app.get("/settings", response_class=HTMLResponse)
    def settings_view(request: Request):
        now = time.time()
        kismet_status = _get_kismet_status(app, now)
        ctx = _build_settings_context(app.state.config, db, kismet_status)
        return app.state.templates.TemplateResponse(
            request=request,
            name="settings.html",
            context={
                "version": __version__,
                "active": "settings",
                **ctx,
            },
        )

    @app.get("/allowlist", response_class=HTMLResponse)
    def allowlist_view(request: Request):
        allowlist = None
        notice = None
        allowlist_path = app.state.config.allowlist_path
        if not allowlist_path:
            notice = "No allowlist_path configured. Set allowlist_path in lynceus.yaml."
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
