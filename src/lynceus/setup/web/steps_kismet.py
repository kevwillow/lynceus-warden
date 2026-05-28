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

import asyncio
import logging
from typing import TYPE_CHECKING

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from lynceus.cli.setup import (
    _kismet_api_key_candidate_paths,
    _read_kismet_api_key,
    _redact_kismet_api_key,
    enumerate_capture_adapters,
    enumerate_wireless_interfaces,
    probe_kismet,
    probe_kismet_sources,
)
from lynceus.config import DEFAULT_KISMET_URL
from lynceus.setup.prompts import _is_valid_url

if TYPE_CHECKING:
    from fastapi import FastAPI

logger = logging.getLogger(__name__)

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

    # Finding 3.6 (PRESHIP): probe_kismet and probe_kismet_sources
    # are synchronous (requests.get with PROBE_TIMEOUT_SECONDS=5).
    # Calling them directly from an async handler blocks the event
    # loop for up to 5s per probe, queueing any concurrent requests
    # (e.g., a second tab opening /apply-progress mid-probe). Wrap
    # in asyncio.to_thread so the event loop stays responsive —
    # same pattern the apply pipeline uses for apply_config.
    ok, version, error = await asyncio.to_thread(
        probe_kismet, kismet_url, kismet_api_key
    )
    sources_list = None
    if ok:
        sources_list = await asyncio.to_thread(
            probe_kismet_sources, kismet_url, kismet_api_key
        )
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


def _source_label(source: dict) -> str:
    # Sanity-check panel label for Kismet's probed datasource list.
    # Surfaces enough probe-response fields that the operator can
    # unambiguously match a row against Kismet's web-UI Datasources page —
    # capture_interface (what tcpdump shows) and the Kismet UUID
    # disambiguate when multiple Wi-Fi sources share a name.
    name = source.get("name") or ""
    iface = source.get("interface") or ""
    capture = source.get("capture_interface") or ""
    uuid = source.get("uuid") or ""
    parts: list[str] = []
    if iface:
        parts.append(f"interface: {iface}")
    if capture:
        parts.append(f"capture: {capture}")
    if uuid:
        parts.append(f"uuid: {uuid}")
    if parts:
        return f"{name}  ({', '.join(parts)})"
    return name


def _kismet_name_for_adapter(adapter: dict, sources_list: list[dict] | None) -> str | None:
    """Return the Kismet source ``name=`` for an OS adapter, if Kismet's
    probe already configured one matching this interface (or its capture
    interface). Returns None when Kismet doesn't yet know about it — the
    operator's checkbox value then defaults to the OS-side interface name
    and the silent-drop warning explains they must align Kismet's
    ``source=`` line with that name."""
    if not sources_list:
        return None
    iface = adapter["name"]
    for src in sources_list:
        if src.get("interface") == iface or src.get("capture_interface") == iface:
            return src.get("name") or None
    return None


def _read_kismet_site_conf_sources() -> set[str]:
    """Return the set of interface identifiers from ``source=`` lines in
    ``/etc/kismet/kismet_site.conf`` (apt-package layout) or
    ``/usr/local/etc/kismet/kismet_site.conf`` (from-source build).

    Empty set when no file is found or parse fails — wizard step 4
    falls back to detection-only behavior with an INFO log so the
    operator can still configure interfaces manually.

    Source of truth for "what did bootstrap-kismet already pick?" so
    re-running the wizard pre-checks those same selections rather
    than forcing the operator to re-select from scratch (v0.7.7
    Touch 3 — operators on Parrot were hitting source_allowlist
    mismatches when the two configs drifted).
    """
    from lynceus.cli.bootstrap_kismet import (
        existing_source_interfaces,
        resolve_site_conf_path,
    )
    site_conf = resolve_site_conf_path()
    if site_conf is None or not site_conf.exists():
        return set()
    try:
        content = site_conf.read_text(encoding="utf-8")
    except OSError as exc:
        logger.info(
            "step 4 prefill: could not read %s (%s); falling back to detection only",
            site_conf,
            exc,
        )
        return set()
    try:
        return existing_source_interfaces(content)
    except Exception as exc:
        logger.info(
            "step 4 prefill: could not parse %s (%s); falling back to detection only",
            site_conf,
            exc,
        )
        return set()


def _known_kismet_source_identifiers(sources_list: list[dict] | None) -> set[str]:
    """Identifiers Kismet would actually credit observations to: the
    ``name`` / ``interface`` / ``capture_interface`` of every live
    datasource the step-3 probe returned, plus the ``source=`` identifiers
    already in ``kismet_site.conf``. Touch 3 compares the operator's
    checkbox selection against this set so a source Kismet isn't capturing
    from surfaces a warning BEFORE apply rather than as silent drops.

    Returns an empty set when neither source of truth is available (probe
    failed/skipped AND no kismet_site.conf) — the caller then skips the
    check rather than false-warning on a host where we simply don't know
    what Kismet is capturing."""
    known: set[str] = set()
    for src in sources_list or []:
        for key in ("name", "interface", "capture_interface"):
            val = (src.get(key) or "").strip()
            if val:
                known.add(val)
    known |= _read_kismet_site_conf_sources()
    return known


def _build_adapter_rows(
    sources_list: list[dict] | None,
    preconfigured: set[str] | None = None,
) -> list[dict]:
    """Enumerate OS adapters + annotate each with its matched Kismet name
    (if any). Returned rows feed the step 4 checkbox list and carry both
    the OS-side label fields and the form ``value`` that POST will store
    into ``kismet_sources`` when checked.

    ``preconfigured`` (v0.7.7 Touch 3): set of source identifiers from
    ``kismet_site.conf``. When an adapter's name OR its computed form
    value matches, the row is marked ``preconfigured=True`` and the
    template pre-checks its checkbox so a re-run of the wizard honours
    bootstrap-kismet's prior selection. Any preconfigured identifier
    NOT matched by current detection (adapter currently unplugged) is
    appended as a separate row with ``disconnected=True`` so the
    operator can decide whether to keep it.
    """
    preconfigured = preconfigured or set()
    rows: list[dict] = []
    seen_names: set[str] = set()
    seen_values: set[str] = set()
    for adapter in enumerate_capture_adapters():
        kismet_name = _kismet_name_for_adapter(adapter, sources_list)
        bus = adapter.get("bus")
        removable = adapter.get("removable")
        bus_label = "Internal" if removable == "fixed" else (bus.upper() if bus else None)
        value = kismet_name or adapter["name"]
        is_preconfigured = (
            adapter["name"] in preconfigured or value in preconfigured
        )
        rows.append(
            {
                "name": adapter["name"],
                "kind": adapter["kind"],
                "mac": adapter["mac"],
                "kismet_name": kismet_name,
                "value": value,
                "bus": bus,
                "bus_label": bus_label,
                "driver": adapter.get("driver"),
                "vendor": adapter.get("vendor"),
                "product": adapter.get("product"),
                "usb_id": adapter.get("usb_id"),
                "preconfigured": is_preconfigured,
                "disconnected": False,
            }
        )
        seen_names.add(adapter["name"])
        seen_values.add(value)
    # Disconnected: source= identifiers in kismet_site.conf that current
    # detection didn't find (adapter unplugged, USB removed since the
    # last apply). Surfaced separately so the operator can decide to
    # keep or drop them — the prefill pre-checks them so the default
    # behavior preserves the existing config.
    for name in sorted(preconfigured - seen_names - seen_values):
        rows.append(
            {
                "name": name,
                "kind": "unknown",
                "mac": None,
                "kismet_name": None,
                "value": name,
                "bus": None,
                "bus_label": None,
                "driver": None,
                "vendor": None,
                "product": None,
                "usb_id": None,
                "preconfigured": True,
                "disconnected": True,
            }
        )
    return rows


async def kismet_sources_get(request: Request) -> HTMLResponse:
    session = _session(request)
    sources_list = session.answers.get("kismet_probe_sources")
    preconfigured = _read_kismet_site_conf_sources()
    adapter_rows = _build_adapter_rows(sources_list, preconfigured=preconfigured)
    kismet_panel_labels = (
        [_source_label(s) for s in sources_list if s.get("name")]
        if sources_list
        else []
    )
    return _render(
        request,
        "kismet_sources.html",
        step_index=4,
        probed=(sources_list is not None),
        adapter_rows=adapter_rows,
        kismet_panel_labels=kismet_panel_labels,
        kismet_sources=session.answers.get("kismet_sources", []),
        error=None,
    )


async def kismet_sources_post(request: Request) -> HTMLResponse:
    state = request.app.state
    session = _session(request)
    form = await request.form()
    # Cancel button (rendered on the no-adapters dead-end) short-circuits
    # to /cancel instead of re-rendering the same error page.
    if form.get("action") == "cancel":
        return _redirect(request, "/cancel")

    checkbox_selected = [
        s.strip() for s in form.getlist("kismet_sources") if s and s.strip()
    ]
    selected = list(checkbox_selected)
    # Free-text fallback for hosts where OS enumeration found nothing
    # (Windows dev, remote operators driving the wizard against a Pi
    # whose sysfs the browser can't reach, etc.).
    manual = (form.get("manual_source") or "").strip()
    if manual:
        selected.append(manual)

    sources_list = session.answers.get("kismet_probe_sources")
    if not selected:
        # v0.7.6: re-run preserve. The operator may have an existing
        # lynceus.yaml at state.target_path with a populated
        # kismet_sources: list (typical --reconfigure flow). Loading the
        # template doesn't pre-check those boxes today (see UI scope
        # note on the touchup arc), so the operator clicks Next on an
        # empty form intending "keep what I had." Honor that here: read
        # the on-disk config, and if it has a non-empty kismet_sources
        # list, populate session.answers with it and advance. Otherwise
        # fall through to the standard error.
        existing = _existing_kismet_sources(state.target_path)
        if existing:
            session.answers["kismet_sources"] = existing
            return _redirect(request, "/step/5")
        adapter_rows = _build_adapter_rows(sources_list)
        kismet_panel_labels = (
            [_source_label(s) for s in sources_list if s.get("name")]
            if sources_list
            else []
        )
        return _render(
            request,
            "kismet_sources.html",
            step_index=4,
            probed=(sources_list is not None),
            adapter_rows=adapter_rows,
            kismet_panel_labels=kismet_panel_labels,
            kismet_sources=session.answers.get("kismet_sources", []),
            error="Pick at least one capture source (or enter an interface name).",
        )

    # Touch 3: warn (don't block) when a CHECKBOX selection names a source
    # Kismet isn't capturing from — the silent-drop footgun the Parrot
    # operator hit. manual_source is operator-asserted free text and stays
    # exempt; advanced/not-yet-plugged-in cases stay valid via the
    # "Continue anyway" acknowledgement (confirm_sources, set on the
    # warning re-render below). Skipped entirely when we have no reference
    # set (probe failed/skipped AND no kismet_site.conf) so we never
    # false-warn on a host where Kismet's sources are simply unknown.
    if not form.get("confirm_sources"):
        known = _known_kismet_source_identifiers(sources_list)
        unmatched = [s for s in checkbox_selected if s not in known]
        if known and unmatched:
            preconfigured = _read_kismet_site_conf_sources()
            adapter_rows = _build_adapter_rows(
                sources_list, preconfigured=preconfigured
            )
            kismet_panel_labels = (
                [_source_label(s) for s in sources_list if s.get("name")]
                if sources_list
                else []
            )
            return _render(
                request,
                "kismet_sources.html",
                step_index=4,
                probed=(sources_list is not None),
                adapter_rows=adapter_rows,
                kismet_panel_labels=kismet_panel_labels,
                # Re-check the operator's actual submission, NOT preconfigured,
                # so a box they deliberately unchecked (e.g. the real hci0)
                # stays unchecked on the warning re-render.
                kismet_sources=checkbox_selected,
                selection_active=True,
                unmatched_sources=sorted(unmatched),
                error=None,
            )

    session.answers["kismet_sources"] = selected
    return _redirect(request, "/step/5")


def _existing_kismet_sources(target_path) -> list[str] | None:
    """Return the kismet_sources list from an existing lynceus.yaml at
    ``target_path``, or None if the file is missing, unreadable, or
    has no usable list. Used by the step 4 POST handler to honor a
    re-run operator's "preserve existing selection" gesture (an empty
    form submission on a wizard run that started from a populated
    config).

    Defensive — a malformed YAML or a Config validation failure on
    the existing file must not crash the wizard; the operator can
    still recover by ticking checkboxes manually."""
    from pathlib import Path
    from lynceus.config import load_config
    try:
        p = Path(target_path)
        if not p.exists():
            return None
        cfg = load_config(str(p))
    except Exception:
        return None
    existing = cfg.kismet_sources or []
    if not existing:
        return None
    return list(existing)


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
