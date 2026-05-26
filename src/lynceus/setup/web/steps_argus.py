"""Argus watchlist loading step (web wizard, v0.7.6 Tier 4).

Step 13 of the wizard: opt-in choice for how to load the Argus
watchlist into the daemon DB. Replaces the pre-Tier-4 unconditional
auto-import-the-bundled-snapshot behavior. Lynceus is a standalone
product enhanced by — but not dependent on — Argus, so the default
selection is ``Skip``.

Four modes:

* ``skip``    — apply emits a skipped import step; the existing
                watchlist (if any) is left exactly as it was.
* ``bundled`` — import the snapshot shipped in the wheel
                (``src/lynceus/data/default_watchlist.csv``). Fast
                and offline.
* ``github``  — fetch the latest snapshot from a GitHub repo
                (default: ``kevwillow/argus-db``). Network required;
                operator can override the repo and ref under an
                advanced disclosure.
* ``file``    — import a local CSV the operator points at.

The session.answers slot for this step is ``argus_choice``, which
``review._resolve_apply_args`` packages into the ``ArgusChoice``
dataclass and hands to ``apply_config``.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from lynceus.cli.import_argus import DEFAULT_GITHUB_REPO

if TYPE_CHECKING:
    from fastapi import FastAPI


_VALID_MODES = ("skip", "bundled", "github", "file")


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


def _current_argus_answer(session) -> dict:
    """Return the previously-captured argus choice as a form-friendly dict.

    Defaults to ``skip`` for fresh sessions so the form pre-selects the
    operator-safe default.
    """
    raw = session.answers.get("argus_choice") or {}
    mode = raw.get("mode") if isinstance(raw, dict) else None
    if mode not in _VALID_MODES:
        mode = "skip"
    return {
        "mode": mode,
        "file_path": raw.get("file_path", "") if isinstance(raw, dict) else "",
        "github_repo": (
            raw.get("github_repo", "") if isinstance(raw, dict) else ""
        ),
        "github_ref": (
            raw.get("github_ref", "") if isinstance(raw, dict) else ""
        ),
    }


async def argus_get(request: Request) -> HTMLResponse:
    session = _session(request)
    current = _current_argus_answer(session)
    return _render(
        request,
        "argus.html",
        step_index=13,
        argus=current,
        default_github_repo=DEFAULT_GITHUB_REPO,
        error=None,
    )


async def argus_post(request: Request) -> HTMLResponse:
    session = _session(request)
    form = await request.form()
    mode = (form.get("argus_mode") or "skip").strip()
    if mode not in _VALID_MODES:
        return _render(
            request,
            "argus.html",
            step_index=13,
            argus=_current_argus_answer(session),
            default_github_repo=DEFAULT_GITHUB_REPO,
            error=f"Unknown argus load mode: {mode!r}.",
        )

    file_path = (form.get("argus_file_path") or "").strip()
    github_repo = (form.get("argus_github_repo") or "").strip()
    github_ref = (form.get("argus_github_ref") or "").strip()

    if mode == "file" and not file_path:
        return _render(
            request,
            "argus.html",
            step_index=13,
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

    session.answers["argus_choice"] = {
        "mode": mode,
        "file_path": file_path or None,
        "github_repo": github_repo or DEFAULT_GITHUB_REPO,
        "github_ref": github_ref or None,
    }
    return _redirect(request, "/review")


def register_argus_step(app: "FastAPI") -> None:
    """Mount the argus loading step (step 13) onto the wizard app."""
    app.add_api_route("/step/13", argus_get, methods=["GET"], response_class=HTMLResponse)
    app.add_api_route("/step/13", argus_post, methods=["POST"], response_class=HTMLResponse)
