"""Severity overrides + rules engine route handlers (F6 Phase 2a, Touch 6).

Implements steps 11-12 of the wizard:

    11. Severity overrides    (path input, validated via _looks_like_path)
    12. Rules engine          (alerting gate + per-rule-type enables)

The CLI flow runs these in two phases: step 11 input is captured
synchronously in ``cli/setup.py:run_wizard`` (line ~1007), then the
apply pipeline scaffolds the YAML; step 12 (alerting gate +
per-rule-type) is the ``run_enable_alerting_flow`` arc that runs
POST-import so per-type row counts are real.

Phase 2a captures the operator's choices into the session without
writing anything. Phase 2b's apply route will consume:
  * ``severity_overrides_path`` (path the apply will scaffold to)
  * ``enable_alerting`` (top-level gate bool)
  * ``enabled_rule_types`` (list of rule_type strings the operator
    opted into; filtered against post-import counts at apply time)

Pattern-type counts are surfaced in the form labels when the daemon
DB already exists (operator running ``--reconfigure`` over a live
install). When the DB doesn't exist yet (pre-apply common case),
every count is 0 and the form still lists every rule_type so the
operator can pre-stage their choices.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from lynceus import paths
from lynceus.setup.core import DELEGATION_RULES, count_watchlist_by_pattern_type
from lynceus.setup.prompts import _looks_like_path

if TYPE_CHECKING:
    from fastapi import FastAPI


def _session(request: Request):
    state = request.app.state
    return state.session_store.get_or_create(state.setup_token)


def _redirect(request: Request, path: str) -> RedirectResponse:
    token = request.app.state.setup_token
    return RedirectResponse(f"{path}?token={token}", status_code=303)


def _render(request: Request, name: str, **context) -> HTMLResponse:
    from lynceus import __version__
    from lynceus.setup.web.app import STEP_TITLES, TOTAL_STEPS

    base = {
        "version": __version__,
        "step_titles": STEP_TITLES,
        "total_steps": TOTAL_STEPS,
    }
    base.update(context)
    return request.app.state.templates.TemplateResponse(
        request=request,
        name=name,
        context=base,
    )


def _default_severity_path(request: Request) -> str:
    target = request.app.state.target_path
    return str(Path(target).parent / "severity_overrides.yaml")


# ---- Step 11: Severity overrides ------------------------------------------


async def severity_get(request: Request) -> HTMLResponse:
    session = _session(request)
    path = session.answers.get("severity_overrides_path") or _default_severity_path(request)
    return _render(
        request,
        "severity.html",
        step_index=11,
        severity_path=path,
        error=None,
    )


async def severity_post(request: Request) -> HTMLResponse:
    session = _session(request)
    form = await request.form()
    raw = (form.get("severity_path") or "").strip()
    if not raw:
        raw = _default_severity_path(request)
    if not _looks_like_path(raw):
        return _render(
            request,
            "severity.html",
            step_index=11,
            severity_path=raw,
            error="That doesn't look like a file path. Use a full path or leave blank for the default.",
        )
    session.answers["severity_overrides_path"] = raw
    return _redirect(request, "/step/12")


# ---- Step 12: Rules engine -----------------------------------------------


def _rule_type_choices(scope: str) -> list[dict]:
    """Return the per-rule-type rows the rules form iterates over.

    Each row: ``{"rule_type", "label", "description", "count"}``.
    Count comes from the daemon DB at ``paths.default_db_path(scope)``
    when present, else 0 (the form still shows the row so the operator
    can pre-stage opt-ins before any apply has happened).
    """
    db_path = str(paths.default_db_path(scope))
    counts = count_watchlist_by_pattern_type(db_path)
    rows = []
    for name, rule_type, pattern_type, label, description in DELEGATION_RULES:
        rows.append({
            "name": name,
            "rule_type": rule_type,
            "pattern_type": pattern_type,
            "label": label,
            "description": description,
            "count": counts.get(pattern_type, 0),
        })
    return rows


async def rules_get(request: Request) -> HTMLResponse:
    state = request.app.state
    session = _session(request)
    rows = _rule_type_choices(state.scope)
    return _render(
        request,
        "rules.html",
        step_index=12,
        rule_rows=rows,
        enable_alerting=bool(session.answers.get("enable_alerting", False)),
        enabled_rule_types=set(session.answers.get("enabled_rule_types", [])),
    )


async def rules_post(request: Request) -> HTMLResponse:
    state = request.app.state
    session = _session(request)
    form = await request.form()
    enable_alerting = form.get("enable_alerting") == "on"
    enabled: list[str] = []
    if enable_alerting:
        # Only collect per-type opt-ins when the top-level gate is on;
        # otherwise the form's per-type checkboxes are advisory at
        # best and we don't want a stale enable_<x>=on hidden in the
        # browser to imply opt-in.
        valid_rule_types = {rt for (_n, rt, _pt, _l, _d) in DELEGATION_RULES}
        for rt in valid_rule_types:
            if form.get(f"enable_{rt}") == "on":
                enabled.append(rt)
    session.answers["enable_alerting"] = enable_alerting
    session.answers["enabled_rule_types"] = sorted(enabled)
    return _redirect(request, "/step/13")


# ---- registration ----------------------------------------------------------


def register_severity_rules_steps(app: "FastAPI") -> None:
    """Mount the two severity/rules steps onto the wizard app."""
    app.add_api_route("/step/11", severity_get, methods=["GET"], response_class=HTMLResponse)
    app.add_api_route("/step/11", severity_post, methods=["POST"], response_class=HTMLResponse)
    app.add_api_route("/step/12", rules_get, methods=["GET"], response_class=HTMLResponse)
    app.add_api_route("/step/12", rules_post, methods=["POST"], response_class=HTMLResponse)
