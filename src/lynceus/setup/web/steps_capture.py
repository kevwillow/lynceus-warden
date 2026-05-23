"""Capture + ntfy section route handlers (F6 Phase 2a, Touch 5).

Implements steps 5-10 of the wizard:

    5. probe_ssids              (privacy boolean)
    6. ble_friendly_names       (BLE name capture boolean)
    7. ntfy URL                 (empty = skip ntfy entirely)
    8. ntfy topic               (validated via _looks_like_ntfy_topic)
    9. ntfy probe               (probe_ntfy synchronous)
   10. RSSI threshold           (integer, signed)

Mirrors the CLI flow in ``cli/setup.py:run_wizard`` lines ~900-1000.
The notable branch is ntfy: an empty URL skips topic + probe (steps
8 and 9 redirect forward to /step/10). Defensive redirects send the
operator back to /step/7 if they deep-link into 8 or 9 with no URL
in session.
"""

from __future__ import annotations

import secrets
from typing import TYPE_CHECKING

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

from lynceus.cli.setup import (
    DEFAULT_NTFY_BROKER,
    DEFAULT_RSSI_THRESHOLD,
    probe_ntfy,
)
from lynceus.setup.prompts import _is_valid_url, _looks_like_ntfy_topic

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


# ---- Step 5: probe_ssids ---------------------------------------------------


async def probe_ssids_get(request: Request) -> HTMLResponse:
    session = _session(request)
    return _render(
        request,
        "probe_ssids.html",
        step_index=5,
        probe_ssids=bool(session.answers.get("probe_ssids", False)),
    )


async def probe_ssids_post(request: Request) -> HTMLResponse:
    session = _session(request)
    form = await request.form()
    session.answers["probe_ssids"] = form.get("probe_ssids") == "yes"
    return _redirect(request, "/step/6")


# ---- Step 6: ble_friendly_names -------------------------------------------


async def ble_names_get(request: Request) -> HTMLResponse:
    session = _session(request)
    return _render(
        request,
        "ble_friendly_names.html",
        step_index=6,
        ble_friendly_names=bool(session.answers.get("ble_friendly_names", True)),
    )


async def ble_names_post(request: Request) -> HTMLResponse:
    session = _session(request)
    form = await request.form()
    session.answers["ble_friendly_names"] = form.get("ble_friendly_names") == "yes"
    return _redirect(request, "/step/7")


# ---- Step 7: ntfy URL ------------------------------------------------------


async def ntfy_url_get(request: Request) -> HTMLResponse:
    session = _session(request)
    return _render(
        request,
        "ntfy_url.html",
        step_index=7,
        ntfy_url=session.answers.get("ntfy_url", ""),
        default_broker=DEFAULT_NTFY_BROKER,
        error=None,
    )


async def ntfy_url_post(request: Request) -> HTMLResponse:
    session = _session(request)
    form = await request.form()
    ntfy_url = (form.get("ntfy_url") or "").strip()
    if not ntfy_url:
        # Skip ntfy entirely. Clear topic too so a stale value from a
        # prior visit doesn't sneak into the final Config.
        session.answers["ntfy_url"] = ""
        session.answers["ntfy_topic"] = ""
        return _redirect(request, "/step/10")
    if not _is_valid_url(ntfy_url):
        return _render(
            request,
            "ntfy_url.html",
            step_index=7,
            ntfy_url=ntfy_url,
            default_broker=DEFAULT_NTFY_BROKER,
            error="URL must include scheme (http:// or https://) and a host.",
        )
    session.answers["ntfy_url"] = ntfy_url
    return _redirect(request, "/step/8")


# ---- Step 8: ntfy topic ----------------------------------------------------


def _suggest_topic() -> str:
    return f"lynceus-{secrets.token_hex(4)}"


async def ntfy_topic_get(request: Request) -> HTMLResponse:
    session = _session(request)
    if not session.answers.get("ntfy_url"):
        # Defensive: deep-linked here without an ntfy URL. Send back.
        return _redirect(request, "/step/7")
    # Suggest a fresh topic only if the operator hasn't already picked
    # one. A re-visit must show their prior choice so they don't
    # accidentally overwrite a topic they're already subscribed to.
    existing = session.answers.get("ntfy_topic", "")
    suggested = existing or _suggest_topic()
    return _render(
        request,
        "ntfy_topic.html",
        step_index=8,
        ntfy_topic=existing,
        suggested=suggested,
        error=None,
    )


async def ntfy_topic_post(request: Request) -> HTMLResponse:
    session = _session(request)
    if not session.answers.get("ntfy_url"):
        return _redirect(request, "/step/7")
    form = await request.form()
    suggested = (form.get("suggested") or _suggest_topic()).strip()
    entered = (form.get("ntfy_topic") or "").strip()
    chosen = entered or suggested
    if not _looks_like_ntfy_topic(chosen):
        return _render(
            request,
            "ntfy_topic.html",
            step_index=8,
            ntfy_topic=entered,
            suggested=suggested,
            error="Topic must be 6-64 chars, letters/digits/underscore/hyphen only.",
        )
    session.answers["ntfy_topic"] = chosen
    return _redirect(request, "/step/9")


# ---- Step 9: ntfy probe ---------------------------------------------------


async def ntfy_probe_get(request: Request) -> HTMLResponse:
    state = request.app.state
    session = _session(request)
    if not session.answers.get("ntfy_url") or not session.answers.get("ntfy_topic"):
        return _redirect(request, "/step/7")
    if state.skip_probes:
        return _render(
            request,
            "ntfy_probe.html",
            step_index=9,
            skipped=True,
            probe_ok=None,
            probe_error=None,
        )
    ok, error = probe_ntfy(session.answers["ntfy_url"], session.answers["ntfy_topic"])
    session.answers["ntfy_probe_ok"] = ok
    session.answers["ntfy_probe_error"] = error
    return _render(
        request,
        "ntfy_probe.html",
        step_index=9,
        skipped=False,
        probe_ok=ok,
        probe_error=error,
    )


async def ntfy_probe_post(request: Request) -> HTMLResponse:
    form = await request.form()
    action = form.get("action") or "continue"
    if action == "cancel":
        return _redirect(request, "/cancel")
    return _redirect(request, "/step/10")


# ---- Step 10: RSSI threshold ----------------------------------------------


async def rssi_get(request: Request) -> HTMLResponse:
    session = _session(request)
    return _render(
        request,
        "rssi.html",
        step_index=10,
        min_rssi=session.answers.get("min_rssi", DEFAULT_RSSI_THRESHOLD),
        default_rssi=DEFAULT_RSSI_THRESHOLD,
        error=None,
    )


async def rssi_post(request: Request) -> HTMLResponse:
    session = _session(request)
    form = await request.form()
    raw = (form.get("min_rssi") or "").strip()
    try:
        min_rssi = int(raw)
    except ValueError:
        return _render(
            request,
            "rssi.html",
            step_index=10,
            min_rssi=raw,
            default_rssi=DEFAULT_RSSI_THRESHOLD,
            error=f"RSSI must be an integer (got {raw!r}).",
        )
    # Sanity range — RSSI in dBm is always negative for received
    # signals; positive values point at operator confusion.
    if min_rssi > 0 or min_rssi < -120:
        return _render(
            request,
            "rssi.html",
            step_index=10,
            min_rssi=raw,
            default_rssi=DEFAULT_RSSI_THRESHOLD,
            error="RSSI must be between -120 and 0 dBm.",
        )
    session.answers["min_rssi"] = min_rssi
    return _redirect(request, "/step/11")


# ---- registration ----------------------------------------------------------


def register_capture_steps(app: "FastAPI") -> None:
    """Mount the six capture/ntfy/RSSI steps onto the wizard app."""
    app.add_api_route("/step/5", probe_ssids_get, methods=["GET"], response_class=HTMLResponse)
    app.add_api_route("/step/5", probe_ssids_post, methods=["POST"], response_class=HTMLResponse)
    app.add_api_route("/step/6", ble_names_get, methods=["GET"], response_class=HTMLResponse)
    app.add_api_route("/step/6", ble_names_post, methods=["POST"], response_class=HTMLResponse)
    app.add_api_route("/step/7", ntfy_url_get, methods=["GET"], response_class=HTMLResponse)
    app.add_api_route("/step/7", ntfy_url_post, methods=["POST"], response_class=HTMLResponse)
    app.add_api_route("/step/8", ntfy_topic_get, methods=["GET"], response_class=HTMLResponse)
    app.add_api_route("/step/8", ntfy_topic_post, methods=["POST"], response_class=HTMLResponse)
    app.add_api_route("/step/9", ntfy_probe_get, methods=["GET"], response_class=HTMLResponse)
    app.add_api_route("/step/9", ntfy_probe_post, methods=["POST"], response_class=HTMLResponse)
    app.add_api_route("/step/10", rssi_get, methods=["GET"], response_class=HTMLResponse)
    app.add_api_route("/step/10", rssi_post, methods=["POST"], response_class=HTMLResponse)
