"""Severity overrides + unified Argus configuration step (v0.7.7 Touch 5).

Implements steps 11-12 of the wizard:

    11. Severity overrides    (path input, validated via _looks_like_path)
    12. Argus configuration   (alerting gate + per-rule-type enables +
                                argus load-mode choice — unified at v0.7.7
                                from the prior split "Rules engine" /
                                "Argus watchlist" pair)

v0.7.7 Touch 5: steps 12 (rules engine) and 13 (argus loading) merged
into a single step. Operators conceptually treat Argus setup as one
decision; the split added friction without giving anything extra.
The apply pipeline still receives the same ArgusChoice + rules config
shape it always did — this is purely a UI consolidation.

Phase 2b's apply route consumes:
  * ``severity_overrides_path`` (path the apply will scaffold to)
  * ``enable_alerting`` (top-level gate bool)
  * ``enabled_rule_types`` (list of rule_type strings the operator
    opted into; filtered against post-import counts at apply time)
  * ``argus_choice`` (dict with mode + file_path + github_repo +
    github_ref — packaged by review.py into an ArgusChoice dataclass)

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
from lynceus.cli.import_argus import DEFAULT_GITHUB_REPO
from lynceus.setup.core import DELEGATION_RULES, count_watchlist_by_pattern_type
from lynceus.setup.prompts import _looks_like_path

if TYPE_CHECKING:
    from fastapi import FastAPI

_VALID_ARGUS_MODES = ("skip", "bundled", "github", "file")


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


def _current_argus_answer(session) -> dict:
    """Return the previously-captured argus choice as a form-friendly dict.

    Defaults to ``skip`` for fresh sessions so the form pre-selects
    the operator-safe default.
    """
    raw = session.answers.get("argus_choice") or {}
    mode = raw.get("mode") if isinstance(raw, dict) else None
    if mode not in _VALID_ARGUS_MODES:
        mode = "skip"
    return {
        "mode": mode,
        "file_path": raw.get("file_path", "") if isinstance(raw, dict) else "",
        "github_repo": raw.get("github_repo", "") if isinstance(raw, dict) else "",
        "github_ref": raw.get("github_ref", "") if isinstance(raw, dict) else "",
    }


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
        argus=_current_argus_answer(session),
        default_github_repo=DEFAULT_GITHUB_REPO,
        error=None,
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

    # Argus choice (v0.7.7 Touch 5 — merged from former step 13).
    mode = (form.get("argus_mode") or "skip").strip()
    file_path = (form.get("argus_file_path") or "").strip()
    github_repo = (form.get("argus_github_repo") or "").strip()
    github_ref = (form.get("argus_github_ref") or "").strip()

    rows = _rule_type_choices(state.scope)
    if mode not in _VALID_ARGUS_MODES:
        return _render(
            request,
            "rules.html",
            step_index=12,
            rule_rows=rows,
            enable_alerting=enable_alerting,
            enabled_rule_types=set(enabled),
            argus={
                "mode": "skip",
                "file_path": file_path,
                "github_repo": github_repo,
                "github_ref": github_ref,
            },
            default_github_repo=DEFAULT_GITHUB_REPO,
            error=f"Unknown argus load mode: {mode!r}.",
        )
    if mode == "file" and not file_path:
        # Block advance with both sections' state preserved so the
        # operator's rules-engine choices don't vanish on the validation
        # bounce.
        return _render(
            request,
            "rules.html",
            step_index=12,
            rule_rows=rows,
            enable_alerting=enable_alerting,
            enabled_rule_types=set(enabled),
            argus={
                "mode": mode,
                "file_path": file_path,
                "github_repo": github_repo,
                "github_ref": github_ref,
            },
            default_github_repo=DEFAULT_GITHUB_REPO,
            error=(
                "File mode selected but no file path was provided. "
                "Enter an absolute path to an Argus CSV, or pick a "
                "different mode."
            ),
        )

    session.answers["enable_alerting"] = enable_alerting
    session.answers["enabled_rule_types"] = sorted(enabled)
    session.answers["argus_choice"] = {
        "mode": mode,
        "file_path": file_path or None,
        "github_repo": github_repo or DEFAULT_GITHUB_REPO,
        "github_ref": github_ref or None,
    }
    return _redirect(request, "/review")


# ---- registration ----------------------------------------------------------


def register_severity_rules_steps(app: "FastAPI") -> None:
    """Mount the two severity/rules steps onto the wizard app."""
    app.add_api_route("/step/11", severity_get, methods=["GET"], response_class=HTMLResponse)
    app.add_api_route("/step/11", severity_post, methods=["POST"], response_class=HTMLResponse)
    app.add_api_route("/step/12", rules_get, methods=["GET"], response_class=HTMLResponse)
    app.add_api_route("/step/12", rules_post, methods=["POST"], response_class=HTMLResponse)
