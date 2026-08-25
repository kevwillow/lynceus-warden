"""CaseFile to HTML.

⛔ This module has no data access of any kind, and a test asserts so by
reading its own source. That is what makes ``query.py`` a real choke
point rather than a convention: a renderer that could go and fetch one
more field would be able to disclose what the query deliberately
excluded, and no amount of care in the template would stop it.

The document is opened from a downloads folder, possibly offline,
possibly by a lawyer whose browser blocks everything. So it is one file
with inline styles, no scripts and no external references at all.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import jinja2

TEMPLATES_DIR = Path(__file__).parent / "templates"
TEMPLATE_NAME = "case_file.html"


def _format_ts(value) -> str:
    """A UTC timestamp, always with its zone spelled out.

    A bare local time in a document that may cross jurisdictions is an
    ambiguity a reader cannot resolve from the artifact itself.
    """
    if value in (None, ""):
        return "unknown"
    try:
        moment = datetime.fromtimestamp(int(value), tz=UTC)
    except (ValueError, OSError, OverflowError, TypeError):
        return "unknown"
    return moment.strftime("%Y-%m-%d %H:%M:%S UTC")


def _format_date(value) -> str:
    if value in (None, ""):
        return "unknown"
    try:
        moment = datetime.fromtimestamp(int(value), tz=UTC)
    except (ValueError, OSError, OverflowError, TypeError):
        return "unknown"
    return moment.strftime("%Y-%m-%d")


def _environment() -> jinja2.Environment:
    env = jinja2.Environment(
        loader=jinja2.FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["ts"] = _format_ts
    env.filters["date"] = _format_date
    return env


def render_html(case_file) -> str:
    """Render the case file as one self-contained HTML document."""
    template = _environment().get_template(TEMPLATE_NAME)
    return template.render(
        case=case_file,
        device=case_file.device,
        window=case_file.window,
        parameters=case_file.parameters,
        limits=case_file.limits,
        excluded=case_file.excluded_counts,
    )
