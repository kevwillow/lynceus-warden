"""Review page + noop apply placeholder (F6 Phase 2a, Touch 7).

The review page is the wizard's final ceremony BEFORE the apply.
In Phase 2a this is the wizard's literal terminus — the operator
sees the validated ``Config`` rendered with secrets redacted, and
the Apply button hits a placeholder route that just confirms what
WOULD be applied. The real ``apply_config`` invocation + SSE
progress streaming + post-apply completion page all land in
Phase 2b.

Two output surfaces:
* ``GET /review`` — human-readable HTML, redacted, with
  "Edit step X" links per section so the operator can jump back
  to fix anything.
* ``GET /apply-preview.json`` — the validated ``Config`` as JSON,
  same redactions, for operators / scripts that want to diff the
  wizard's output against an existing lynceus.yaml.
* ``POST /apply`` — placeholder. Returns the apply_placeholder.html
  template confirming Phase 2a has no apply pipeline.

The Config built here uses the same constructor the daemon loads
its config through — there is no parallel validation surface.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import ValidationError

from lynceus.cli.setup import _redact_kismet_api_key
from lynceus.config import CaptureConfig, Config
from lynceus.redact import redact_ntfy_topic

if TYPE_CHECKING:
    from fastapi import FastAPI


# Map of Config field path (Pydantic loc tuple joined with ".") to
# the wizard step ordinal that owns it. Drives the "Edit step X"
# links the review page surfaces when validation fails on a
# specific field. Keys cover the fields the wizard captures; fields
# Config defaults silently aren't expected to fail and aren't
# represented here (a failure on one of those is surfaced generically
# with a link back to the review page itself).
FIELD_STEP_INDEX: dict[str, int] = {
    "kismet_url": 1,
    "kismet_api_key": 2,
    "kismet_sources": 4,
    "capture.probe_ssids": 5,
    "capture.ble_friendly_names": 6,
    "ntfy_url": 7,
    "ntfy_topic": 8,
    "min_rssi": 10,
    "severity_overrides_path": 11,
}


def _session(request: Request):
    state = request.app.state
    return state.session_store.get_or_create(state.setup_token)


def _render(request: Request, name: str, **context) -> HTMLResponse:
    from lynceus import __version__
    from lynceus.setup.web.app import STEP_TITLES, TOTAL_STEPS

    base = {
        "version": __version__,
        "step_titles": STEP_TITLES,
        "total_steps": TOTAL_STEPS,
        "step_index": 0,  # Review page sits outside the numbered flow.
    }
    base.update(context)
    return request.app.state.templates.TemplateResponse(
        request=request,
        name=name,
        context=base,
    )


def _build_config_from_session(answers: dict[str, Any]) -> Config:
    """Construct a ``Config`` from the wizard's per-step answers.

    Empty strings for optional secrets (ntfy_url, ntfy_topic) map
    to ``None`` so the daemon treats them as "ntfy disabled" rather
    than "empty topic" (which would 404 the publish). ``min_rssi``
    is preserved as-typed; missing means default.

    Raises ``ValidationError`` on any Config-level validation
    failure (URL scheme, range, etc.).
    """
    return Config(
        kismet_url=answers.get("kismet_url") or "",
        kismet_api_key=answers.get("kismet_api_key") or None,
        kismet_sources=answers.get("kismet_sources") or None,
        capture=CaptureConfig(
            probe_ssids=bool(answers.get("probe_ssids", False)),
            ble_friendly_names=bool(answers.get("ble_friendly_names", True)),
        ),
        ntfy_url=answers.get("ntfy_url") or None,
        ntfy_topic=answers.get("ntfy_topic") or None,
        min_rssi=answers.get("min_rssi"),
    )


def _format_validation_errors(exc: ValidationError) -> list[dict[str, Any]]:
    """Turn a Pydantic ValidationError into review-page rows."""
    rows = []
    for err in exc.errors():
        loc = ".".join(str(x) for x in err.get("loc", ()))
        rows.append({
            "field": loc,
            "message": err.get("msg", "invalid"),
            "step_index": FIELD_STEP_INDEX.get(loc),
        })
    return rows


def _redact_config_dict(data: dict[str, Any]) -> dict[str, Any]:
    """Apply per-field redactions to a dumped Config dict.

    Mutates ``data`` and returns it. Redacts the two shared-secret
    fields the wizard collects: ``kismet_api_key`` (head/tail
    preview) and ``ntfy_topic`` (head + bullets + tail).
    ``ntfy_url`` itself is not redacted — the URL is not a secret;
    the topic embedded in the path (when this wizard surfaces it
    via ``ntfy_url`` alone) would be, but the wizard collects URL
    and topic as separate fields.
    """
    if data.get("kismet_api_key"):
        data["kismet_api_key"] = _redact_kismet_api_key(data["kismet_api_key"])
    if data.get("ntfy_topic"):
        data["ntfy_topic"] = redact_ntfy_topic(data["ntfy_topic"])
    if data.get("ntfy_auth_token"):
        data["ntfy_auth_token"] = "•••"
    return data


def _summarize(answers: dict[str, Any], config: Config | None) -> dict[str, Any]:
    """Build the section-by-section summary the HTML template renders."""
    return {
        "kismet_url": answers.get("kismet_url", "") or "(not set)",
        "kismet_api_key_preview": (
            _redact_kismet_api_key(answers.get("kismet_api_key", ""))
            if answers.get("kismet_api_key") else "(not set)"
        ),
        "kismet_sources": answers.get("kismet_sources") or [],
        "probe_ssids": bool(answers.get("probe_ssids", False)),
        "ble_friendly_names": bool(answers.get("ble_friendly_names", True)),
        "ntfy_url": answers.get("ntfy_url", "") or "(ntfy skipped)",
        "ntfy_topic_preview": (
            redact_ntfy_topic(answers.get("ntfy_topic", ""))
            if answers.get("ntfy_topic") else "(ntfy skipped)"
        ),
        "min_rssi": answers.get("min_rssi", "(default)"),
        "severity_overrides_path": (
            answers.get("severity_overrides_path") or "(default)"
        ),
        "enable_alerting": bool(answers.get("enable_alerting", False)),
        "enabled_rule_types": answers.get("enabled_rule_types") or [],
    }


# ---- routes ----------------------------------------------------------------


async def review_get(request: Request) -> HTMLResponse:
    state = request.app.state
    session = _session(request)
    config: Config | None = None
    errors: list[dict[str, Any]] = []
    try:
        config = _build_config_from_session(session.answers)
    except ValidationError as exc:
        errors = _format_validation_errors(exc)
    return _render(
        request,
        "review.html",
        config=config,
        errors=errors,
        summary=_summarize(session.answers, config),
        scope=state.scope,
        target_path=str(state.target_path),
    )


async def apply_post(request: Request) -> HTMLResponse:
    """Phase 2a noop apply. Confirms what WOULD be applied; the
    actual ``apply_config`` invocation lands in Phase 2b."""
    state = request.app.state
    session = _session(request)
    # Re-validate so the placeholder page doesn't claim a config is
    # apply-ready when it would fail Config construction.
    errors: list[dict[str, Any]] = []
    try:
        _build_config_from_session(session.answers)
    except ValidationError as exc:
        errors = _format_validation_errors(exc)
    return _render(
        request,
        "apply_placeholder.html",
        errors=errors,
        scope=state.scope,
        target_path=str(state.target_path),
    )


async def apply_preview_json(request: Request) -> JSONResponse:
    """Validated Config as JSON, secrets redacted. The Phase 2b
    apply route will consume the SAME session.answers — this preview
    is the contract."""
    state = request.app.state
    session = _session(request)
    try:
        config = _build_config_from_session(session.answers)
    except ValidationError as exc:
        return JSONResponse(
            {"valid": False, "errors": _format_validation_errors(exc)},
            status_code=400,
        )
    data = config.model_dump(mode="json")
    _redact_config_dict(data)
    return JSONResponse({
        "valid": True,
        "config": data,
        "extras": {
            # Phase 2b apply args that aren't on the Config model.
            "severity_overrides_path": session.answers.get("severity_overrides_path"),
            "enable_alerting": bool(session.answers.get("enable_alerting", False)),
            "enabled_rule_types": session.answers.get("enabled_rule_types") or [],
            "scope": state.scope,
            "target_path": str(state.target_path),
            "reconfigure": bool(state.reconfigure),
            "skip_probes": bool(state.skip_probes),
        },
    })


# ---- registration ---------------------------------------------------------


def register_review_routes(app: "FastAPI") -> None:
    app.add_api_route("/review", review_get, methods=["GET"], response_class=HTMLResponse)
    app.add_api_route("/apply", apply_post, methods=["POST"], response_class=HTMLResponse)
    app.add_api_route(
        "/apply-preview.json", apply_preview_json, methods=["GET"], response_class=JSONResponse
    )
