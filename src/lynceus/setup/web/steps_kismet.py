"""Kismet section route handlers for the lynceus-setup web wizard.

Implements the four Kismet wizard steps (1-4) that the CLI flow runs
through synchronously in ``cli/setup.py:run_wizard`` lines ~700-900:

    1. Kismet URL              (validated via _is_valid_url)
    2. Kismet API key          (auto-locate from session.db OR paste)
    3. Kismet probe            (probe_kismet + probe_kismet_sources,
                                Continue Anyway gate on failure)
    4. Kismet sources          (numbered choice from probed sources,
                                OR interface enumeration fallback)

Each step has a GET (render form) and a POST (validate + advance).
Form values are stashed in the per-token ``WizardSession.answers``
dict; the final ``Config`` is built from that dict on the Touch 7
review page.

This module reuses the existing CLI helpers from ``cli/setup.py``
unchanged (probe_kismet, _kismet_api_key_candidate_paths, etc.) — no
parallel validators.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from lynceus.cli.setup import (
    _kismet_api_key_candidate_paths,
    _read_kismet_api_key,
    _redact_kismet_api_key,
    enumerate_wireless_interfaces,
    probe_kismet,
    probe_kismet_sources,
)
from lynceus.config import DEFAULT_KISMET_URL
from lynceus.setup.prompts import _is_valid_url

if TYPE_CHECKING:
    from fastapi import FastAPI

# ---- helpers ---------------------------------------------------------------


def _session(request: Request):
    state = request.app.state
    return state.session_store.get_or_create(state.setup_token)


def _redirect(request: Request, path: str) -> RedirectResponse:
    """303 redirect that carries the setup token forward.

    303 (not 302) because the operator just submitted a form; we want
    the browser to issue a GET on follow-through so a refresh on the
    next page doesn't resubmit.
    """
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


# ---- Step 1: Kismet URL ----------------------------------------------------


async def kismet_url_get(request: Request) -> HTMLResponse:
    session = _session(request)
    return _render(
        request,
        "kismet_url.html",
        step_index=1,
        kismet_url=session.answers.get("kismet_url", DEFAULT_KISMET_URL),
        error=None,
    )


async def kismet_url_post(request: Request) -> HTMLResponse:
    form = await request.form()
    kismet_url = (form.get("kismet_url") or "").strip()
    session = _session(request)
    if not kismet_url:
        return _render(
            request,
            "kismet_url.html",
            step_index=1,
            kismet_url=kismet_url,
            error="URL is required.",
        )
    if not _is_valid_url(kismet_url):
        return _render(
            request,
            "kismet_url.html",
            step_index=1,
            kismet_url=kismet_url,
            error="URL must include scheme (http:// or https://) and a host.",
        )
    session.answers["kismet_url"] = kismet_url
    return _redirect(request, "/step/2")


# ---- Step 2: Kismet API key ------------------------------------------------


def _try_autolocate(scope: str) -> tuple[str, str, str] | None:
    """Return ``(token, name, path)`` if a Kismet key is on disk.

    Mirrors the CLI's per-scope walk in ``run_wizard``. Returns None
    when nothing usable was found, mapping to "fall through to paste"
    in the template.
    """
    for candidate in _kismet_api_key_candidate_paths(scope):
        found = _read_kismet_api_key(candidate)
        if found is not None:
            token, name = found
            return token, name, str(candidate)
    return None


async def kismet_key_get(request: Request) -> HTMLResponse:
    state = request.app.state
    session = _session(request)
    located = _try_autolocate(state.scope)
    located_ctx = None
    if located is not None:
        token, name, path = located
        located_ctx = {
            "preview": _redact_kismet_api_key(token),
            "name": name,
            "path": path,
        }
    return _render(
        request,
        "kismet_key.html",
        step_index=2,
        located=located_ctx,
        kismet_api_key="",
        error=None,
    )


async def kismet_key_post(request: Request) -> HTMLResponse:
    state = request.app.state
    session = _session(request)
    form = await request.form()
    key_source = form.get("key_source") or ""
    # Re-locate so the radio "use this key" lookup is fresh — the
    # operator may have rotated the key on disk between GET and POST,
    # and trusting a stale stash would write the wrong value.
    located = _try_autolocate(state.scope)

    if key_source == "located" and located is not None:
        session.answers["kismet_api_key"] = located[0]
        return _redirect(request, "/step/3")

    pasted = (form.get("kismet_api_key") or "").strip()
    if not pasted:
        located_ctx = None
        if located is not None:
            token, name, path = located
            located_ctx = {
                "preview": _redact_kismet_api_key(token),
                "name": name,
                "path": path,
            }
        return _render(
            request,
            "kismet_key.html",
            step_index=2,
            located=located_ctx,
            kismet_api_key="",
            error="Paste the API key, or pick the auto-located one.",
        )
    session.answers["kismet_api_key"] = pasted
    return _redirect(request, "/step/3")


# ---- Step 3: Kismet probe --------------------------------------------------


async def kismet_probe_get(request: Request) -> HTMLResponse:
    state = request.app.state
    session = _session(request)
    if state.skip_probes:
        # Mirror the CLI's ``--skip-probes`` posture: no probe call,
        # no sources list; the next step falls back to OS interface
        # enumeration.
        session.answers["kismet_probe_ok"] = None
        session.answers["kismet_probe_version"] = None
        session.answers["kismet_probe_error"] = None
        session.answers["kismet_probe_sources"] = None
        return _render(
            request,
            "kismet_probe.html",
            step_index=3,
            skipped=True,
            probe_ok=None,
            probe_version=None,
            probe_error=None,
            sources_count=None,
        )

    kismet_url = session.answers.get("kismet_url")
    kismet_api_key = session.answers.get("kismet_api_key")
    if not kismet_url or not kismet_api_key:
        # Operator deep-linked into /step/3 without filling 1/2. Send
        # them back to the URL prompt rather than crashing the probe.
        return _redirect(request, "/step/1")

    ok, version, error = probe_kismet(kismet_url, kismet_api_key)
    sources_list = None
    if ok:
        sources_list = probe_kismet_sources(kismet_url, kismet_api_key)
    session.answers["kismet_probe_ok"] = ok
    session.answers["kismet_probe_version"] = version
    session.answers["kismet_probe_error"] = error
    session.answers["kismet_probe_sources"] = sources_list
    return _render(
        request,
        "kismet_probe.html",
        step_index=3,
        skipped=False,
        probe_ok=ok,
        probe_version=version,
        probe_error=error,
        sources_count=(len(sources_list) if sources_list is not None else None),
    )


async def kismet_probe_post(request: Request) -> HTMLResponse:
    session = _session(request)
    form = await request.form()
    action = form.get("action") or "continue"
    if action == "cancel":
        return _redirect(request, "/cancel")
    # action == "continue" (or anything else) → just advance. The
    # session already has the probe result stashed by the GET; the
    # POST is just the operator's "yes, proceed" gesture.
    if not session.answers.get("kismet_url"):
        return _redirect(request, "/step/1")
    return _redirect(request, "/step/4")


# ---- Step 4: Kismet sources ------------------------------------------------


def _split_sources(sources_list):
    if sources_list is None:
        return [], []
    wifi = [s for s in sources_list if s.get("driver") == "linuxwifi"]
    bt = [s for s in sources_list if s.get("driver") == "linuxbluetooth"]
    return wifi, bt


def _source_label(source: dict) -> str:
    name = source.get("name") or ""
    iface = source.get("interface") or ""
    parts = []
    if iface:
        parts.append(f"interface: {iface}")
    extra = f"  ({', '.join(parts)})" if parts else ""
    return f"{name}{extra}"


async def kismet_sources_get(request: Request) -> HTMLResponse:
    session = _session(request)
    sources_list = session.answers.get("kismet_probe_sources")
    wifi, bt = _split_sources(sources_list)
    interfaces = []
    if sources_list is None:
        # Probe failed (or skipped) — fall back to enumerated interfaces.
        interfaces = enumerate_wireless_interfaces() or []
    wifi_choices = [(s["name"], _source_label(s)) for s in wifi if s.get("name")]
    bt_choices = [(s["name"], _source_label(s)) for s in bt if s.get("name")]
    return _render(
        request,
        "kismet_sources.html",
        step_index=4,
        probed=(sources_list is not None),
        wifi_choices=wifi_choices,
        bt_choices=bt_choices,
        interfaces=interfaces,
        kismet_sources=session.answers.get("kismet_sources", []),
        error=None,
    )


async def kismet_sources_post(request: Request) -> HTMLResponse:
    session = _session(request)
    form = await request.form()
    wifi_source = (form.get("wifi_source") or "").strip()
    wifi_iface = (form.get("wifi_interface") or "").strip()
    bt_enable = form.get("bt_enable") == "on"
    bt_source = (form.get("bt_source") or "").strip()

    sources_list = session.answers.get("kismet_probe_sources")
    wifi, bt = _split_sources(sources_list)
    chosen_wifi = wifi_source or wifi_iface
    if not chosen_wifi:
        wifi_choices = [(s["name"], _source_label(s)) for s in wifi if s.get("name")]
        bt_choices = [(s["name"], _source_label(s)) for s in bt if s.get("name")]
        interfaces = []
        if sources_list is None:
            interfaces = enumerate_wireless_interfaces() or []
        return _render(
            request,
            "kismet_sources.html",
            step_index=4,
            probed=(sources_list is not None),
            wifi_choices=wifi_choices,
            bt_choices=bt_choices,
            interfaces=interfaces,
            kismet_sources=session.answers.get("kismet_sources", []),
            error="Pick a Wi-Fi source (or enter an interface name).",
        )

    chosen: list[str] = [chosen_wifi]
    if bt_enable and bt_source:
        chosen.append(bt_source)
    session.answers["kismet_sources"] = chosen
    return _redirect(request, "/step/5")


# ---- registration ----------------------------------------------------------


def register_kismet_steps(app: "FastAPI") -> None:
    """Mount the four Kismet steps onto the wizard app.

    Routes are added in registration order; literal ``/step/<n>``
    routes here MUST be added BEFORE the parameterized
    ``/step/{n}`` placeholder route in ``app.py`` or the catch-all
    would intercept them.
    """
    app.add_api_route("/step/1", kismet_url_get, methods=["GET"], response_class=HTMLResponse)
    app.add_api_route("/step/1", kismet_url_post, methods=["POST"], response_class=HTMLResponse)
    app.add_api_route("/step/2", kismet_key_get, methods=["GET"], response_class=HTMLResponse)
    app.add_api_route("/step/2", kismet_key_post, methods=["POST"], response_class=HTMLResponse)
    app.add_api_route("/step/3", kismet_probe_get, methods=["GET"], response_class=HTMLResponse)
    app.add_api_route("/step/3", kismet_probe_post, methods=["POST"], response_class=HTMLResponse)
    app.add_api_route("/step/4", kismet_sources_get, methods=["GET"], response_class=HTMLResponse)
    app.add_api_route("/step/4", kismet_sources_post, methods=["POST"], response_class=HTMLResponse)
