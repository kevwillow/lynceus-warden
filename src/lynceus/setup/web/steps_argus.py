"""Legacy /step/14 redirect (v0.7.7 Touch 5).

Step 14 was the pre-v0.7.7 split "Argus watchlist" step, which merged
into step 13 ("Argus configuration") at v0.7.7. The route stays
mounted so bookmarks and browser back-buttons from prior sessions
don't dead-end: both GET and POST now redirect to /step/13 (with the
setup token carried forward).

Step 14 is the current number because the heartbeat step (packet P2)
shifted every subsequent step up by one.

The pre-merge body lived here through v0.7.6 Tier 4; the argus
fields are now captured in the unified rules_post handler in
``steps_severity_rules.py``. The apply pipeline still receives the
same ``ArgusChoice`` dataclass — only the UI consolidation changed.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

if TYPE_CHECKING:
    from fastapi import FastAPI


def _redirect(request: Request) -> RedirectResponse:
    token = request.app.state.setup_token
    return RedirectResponse(f"/step/13?token={token}", status_code=303)


async def argus_get(request: Request) -> RedirectResponse:
    return _redirect(request)


async def argus_post(request: Request) -> RedirectResponse:
    return _redirect(request)


def register_argus_step(app: FastAPI) -> None:
    """Mount the legacy /step/14 redirects onto the wizard app."""
    app.add_api_route("/step/14", argus_get, methods=["GET"], response_class=HTMLResponse)
    app.add_api_route("/step/14", argus_post, methods=["POST"], response_class=HTMLResponse)
