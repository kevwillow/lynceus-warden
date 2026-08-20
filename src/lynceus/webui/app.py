"""Lynceus read-only web UI. FastAPI app factory."""

from __future__ import annotations

import csv
import datetime as _dt
import importlib.metadata
import io
import json
import logging
import math
import sqlite3
import time
from pathlib import Path
from typing import Annotated
from typing import get_args as _typing_get_args
from urllib.parse import urlparse

from fastapi import FastAPI, Form, HTTPException, Query, Request
from fastapi import Path as PathParam
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError

from lynceus import __version__, kismet, paths
from lynceus import allowlist as allowlist_mod
from lynceus import rules as rules_mod
from lynceus.allowlist import (
    AllowlistEntry,
    ImpossibleUiEntry,
    add_ui_entry,
    bulk_remove_ui_entries,
    derive_ui_path,
    find_impossible_ui_entries,
    load_allowlist_with_source,
    remove_ui_entry,
)
from lynceus.ble_bridge_checks import bridge_source_name, collect_bridge_warnings
from lynceus.config import Config
from lynceus.db import (
    DEVICES_DEFAULT_DIR,
    DEVICES_DEFAULT_SORT,
    DEVICES_SORT_EXPRESSIONS,
    Database,
    RuleStats,
    WatchfulRecurrence,
)
from lynceus.patterns import mac_in_mac_range
from lynceus.redact import redact_ntfy_topic
from lynceus.webui.clock import (
    CLOCK_BEHIND_TOLERANCE_SECONDS,
    clock_behind_recorded_history,
    refuse_if_clock_behind,
)
from lynceus.webui.csp import CSPMiddleware
from lynceus.webui.csrf import CSRFMiddleware, get_csrf_token
from lynceus.webui.liveness import (
    allowlist_answerable_for,
    configured_remap_axes,
    effective_severity,
    has_configured_remap,
    is_pattern_type_live,
    is_pattern_type_snoozed,
    is_row_suppressed_by_overrides,
    load_overrides,
    oui_prefix_never_matches,
    override_suppression_axes,
    runtime_suppressions,
    serving_rule_types,
    severity_remap,
    suppression_axes_of,
    watchlist_liveness,
)
from lynceus.webui.pagination import build_pagination, parse_pagination

# Snooze duration vocabulary, shared between the per-alert /snooze
# surface (alert_detail.html) and the watchful /watch surface
# (alerts_list.html). Keys are operator-readable labels posted by the
# form; values are seconds, with ``None`` denoting the "forever"
# (NULL expires_at, semantically a permanent allowlist) sentinel. The
# ``1h`` bucket is offered on per-alert snooze (quick-dismiss-while-
# investigating) and dormant on the watchful surface — its template
# enumerates only forever/24h/7d/30d. See
# ``test_watch_form_renders_exactly_four_options`` for the pin on
# that visible-surface invariant.
_SNOOZE_DURATIONS: dict[str, int | None] = {
    "1h": 3600,
    "24h": 86400,
    "7d": 7 * 86400,
    "30d": 30 * 86400,
    "forever": None,
}

# Default duration for the per-alert /alerts/{id}/snooze form when
# the operator submits without selecting (preserves backward compat
# with the pre-B1 fixed-24h posture).
_SNOOZE_DEFAULT_KEY: str = "24h"

logger = logging.getLogger(__name__)

# Co-observation explorer, design v3 Decision 4 as amended in v3.1. A candidate
# is filed under "high observation coverage" when it has been logged enough to
# judge AND only a small share of its own runs coincided with the anchor -- the
# always-there gadget that co-occurs with everything. Both are properties of the
# candidate's own observation record, countable from rows, and neither is a
# claim about the relationship.
_CO_COVERAGE_MIN_RUNS = 20
_CO_COVERAGE_SHARE = 0.25
# W presets in seconds. A relationship that dissolves as W tightens is
# information the operator should have, so the panel offers the ladder rather
# than a single configured value.
_CO_W_PRESETS = (60, 300, 900)
# Drill-down cap. One observation run can hold many sighting pairs (every
# anchor sighting against every candidate sighting inside W), so this list is
# n*m and grows far faster than the run counts above it. Capped, and the cap is
# always reported -- silent truncation here would contradict the main table,
# which states its own truncation outright.
_CO_PAIRS_LIMIT = 100

PACKAGE = "lynceus.webui"

KISMET_STATUS_CACHE_TTL = 30

# Where the corresponding source of this program can be obtained, as AGPL-3.0
# §13 requires for anyone who interacts with it over a network. It is the
# upstream repository, which is the honest answer for an unmodified install.
# ⚠️ If you MODIFY Lynceus and let anyone else reach your instance, §13 makes
# YOUR modified source the thing that has to be offered here. Point this at
# wherever you publish it.
SOURCE_URL = "https://github.com/kevwillow/lynceus-warden"


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


def _parse_probing_str(value: str | None) -> bool | None:
    """Parse the /devices probing tri-state: yes/no/None(any).

    Distinct token vocabulary from _parse_bool_str (true/false) because
    the probing presets use ?probing=yes -- keeping it separate avoids
    overloading the randomized control's wording.
    """
    if value is None:
        return None
    if value == "yes":
        return True
    if value == "no":
        return False
    raise HTTPException(status_code=400, detail="invalid probing: expected 'yes' or 'no'")


# Authoritative set of rule_type literals for the /alerts filter
# dropdown. Pulled from rules.RuleType at module load so a new
# rule_type added to that Literal surfaces here automatically --
# no manual edit required.
_ALERTS_RULE_TYPES: tuple[str, ...] = tuple(_typing_get_args(rules_mod.RuleType))

# Allowed per_page set + default for the /alerts page. Shared
# convention for the /allowlist page below; both use the same
# PaginationParams helper. The values match the unified
# webui-pagination spec (rc5).
_ALERTS_PER_PAGE_ALLOWED: tuple[int, ...] = (25, 50, 100, 200)
_ALERTS_PER_PAGE_DEFAULT: int = 50

# Triage-note filter dropdown on /alerts. Pairs with the 📝 indicator
# on each row added in the per-alert notes prompt -- closes the
# triage-workflow loop ("notes -> indicator -> filter by triage
# state"). "all" is the default and renders as the empty WHERE
# (every alert). Invalid values silently fall back to "all" via the
# handler's clamp, matching the rule_type / window / severity
# precedent.
_ALERTS_HAS_NOTE_VALUES: tuple[str, ...] = ("all", "with_note", "without_note")

# Action-state filter dropdown on /alerts. "Action" is any one of:
# per-alert snooze (active mac/oui entry in allowlist_ui.yaml),
# permanent allowlist (active mac/oui entry in allowlist.yaml), or
# watchful tracking (an active mac-keyed row in
# watchful_recurrence). Excludes rule_type_snoozes (migration 017):
# that surface is system-wide, not per-alert engagement. Excludes
# the triage-note signal: notes have their own has_note filter, and
# composing the two is the workflow ("actioned but unnoted").
# Invalid values silently fall back to "all" via the handler's
# clamp, matching rule_type / window / has_note precedent.
_ALERTS_HAS_ACTION_VALUES: tuple[str, ...] = ("all", "with_action", "without_action")

# Relative window dropdown for /alerts. Resolved to an absolute
# since_ts at request time so URLs stay shareable ("recent" means
# the same recency to any operator opening the link, anchored to
# their open-time clock). "all" means no window constraint.
_ALERTS_WINDOW_SECONDS: dict[str, int | None] = {
    "1h": 3600,
    "24h": 86400,
    "7d": 7 * 86400,
    "30d": 30 * 86400,
    "all": None,
}

# Relative window dropdown for /rules. Same five buckets as
# /alerts so an operator's muscle memory carries over, but with a
# default of "7d" rather than "" (any time): operators visiting
# /rules want a recency-bounded "is this rule worth keeping?"
# read; defaulting to all-time would dilute "last fired" against
# the lifetime of the deployment. The "all" bucket is reachable
# from the dropdown for explicit lifetime views.
_RULES_WINDOW_SECONDS: dict[str, int | None] = _ALERTS_WINDOW_SECONDS
_RULES_DEFAULT_WINDOW: str = "7d"

# /rules sort options. ``default`` preserves rules.yaml order
# (no-op vs pre-rc5 — important for "/rules with no query params
# behaves exactly as today" invariant). ``count_desc`` /
# ``count_asc`` re-order by fire count over the resolved window;
# never-fired rules (count=0) tie-break by name so the secondary
# ordering is stable across renders.
_RULES_SORT_OPTIONS: tuple[str, ...] = ("default", "count_desc", "count_asc")
_RULES_DEFAULT_SORT: str = "default"

# /rules status filter. Adds a third dropdown alongside since + sort
# so the operator can narrow to "what's currently silenced?" without
# scanning the full list. "all" is the default; "snoozed" filters
# the iteration to rules whose rule_type carries an active snooze;
# "active" is the complement. Invalid values silently fall back to
# "all" via the same pattern as since / sort — a stale bookmark
# with ``status=foo`` lands on the unfiltered page rather than 400.
_RULES_STATUS_OPTIONS: tuple[str, ...] = ("all", "snoozed", "active")
_RULES_DEFAULT_STATUS: str = "all"

# Wirelisted snooze duration set for the rule_type-snooze dropdown
# on /rules. Five buckets paralleling the alerts-window dropdown
# values so an operator's muscle memory carries over. Values are
# duration-in-seconds; the POST handler enforces strict membership
# in this set (an attacker-supplied duration_seconds outside the
# whitelist gets a 400). The label set is co-located with the values
# so the template renders the operator-readable label while the
# form posts the integer seconds.
_RULE_TYPE_SNOOZE_DURATIONS: tuple[tuple[int, str], ...] = (
    (3600, "1 hour"),
    (4 * 3600, "4 hours"),
    (24 * 3600, "24 hours"),
    (7 * 86400, "7 days"),
    (30 * 86400, "30 days"),
)
_RULE_TYPE_SNOOZE_DURATION_SECONDS: frozenset[int] = frozenset(
    seconds for seconds, _label in _RULE_TYPE_SNOOZE_DURATIONS
)

# Authoritative set of rule_type literals admitted by the POST
# snooze / unsnooze routes. Re-derived from rules.RuleType via the
# same get_args path as _ALERTS_RULE_TYPES so a new rule_type added
# to that Literal flows here automatically — no manual edit.
_RULE_TYPE_SNOOZE_ALLOWED: frozenset[str] = frozenset(
    _typing_get_args(rules_mod.RuleType)
)


def _resolve_window_to_since_ts(
    window: str | None,
    *,
    now_ts: int,
    options: dict[str, int | None],
) -> int | None:
    """Resolve a window-dropdown value to a ``since_ts`` lower bound.

    Returns ``None`` when ``window`` is the all-time bucket
    (``"all"``) or unset; otherwise returns ``now_ts - seconds``
    where ``seconds`` is the corresponding value in ``options``.
    Caller is responsible for upstream validation of ``window``
    against ``options.keys()`` — the helper does no validation
    itself so each caller can choose its own fallback policy
    (silent rewrite to default, 400, etc).
    """
    if window is None or window == "":
        return None
    seconds = options.get(window)
    if seconds is None:
        return None
    return now_ts - seconds

# /allowlist pagination shares the same per_page set / default as
# /alerts. Allowlists are typically smaller (the prompt notes the
# rc5 management surface assumed <500 entries), but the unified
# helper means the two pages render the same footer copy.
_ALLOWLIST_PER_PAGE_ALLOWED: tuple[int, ...] = (25, 50, 100, 200)
_ALLOWLIST_PER_PAGE_DEFAULT: int = 50

# /watchlist pagination -- shares the same per_page set + default
# as /alerts and /allowlist so an operator's muscle memory carries
# over. The 22k+ row scale post-Argus-import is the genuine driver
# (default 50 keeps the first paint cheap on a fresh visit).
_WATCHLIST_PER_PAGE_ALLOWED: tuple[int, ...] = (25, 50, 100, 200)
_WATCHLIST_PER_PAGE_DEFAULT: int = 50

# /devices pagination. Wider per_page set than the other list pages --
# the v0.7.8 cap bump deliberately exposed 250 / 500 (and 10) in the
# /devices dropdown for sorting a large wardrive capture. Matching the
# allowed set to the dropdown's existing values keeps every selectable
# option valid; B-5 only changes out-of-range handling (clamp, not 400).
_DEVICES_PER_PAGE_ALLOWED: tuple[int, ...] = (10, 25, 50, 100, 200, 250, 500)
_DEVICES_PER_PAGE_DEFAULT: int = 50

# /devices server-side column sort. The allowed sort keys are derived
# from the DB-layer whitelist (DEVICES_SORT_EXPRESSIONS) so the route's
# silent fallback and the template's active-column affordance stay in
# lockstep with the ORDER BY mapping -- a key added there flows here
# with no second edit. ``dir`` is asc|desc. Both fall back silently on
# bad input, matching the /rules ?sort= idiom: a stale bookmark renders
# the default ordering rather than 400/500.
_DEVICES_SORT_OPTIONS: tuple[str, ...] = tuple(DEVICES_SORT_EXPRESSIONS)
_DEVICES_DIR_OPTIONS: tuple[str, ...] = ("asc", "desc")

# /probes (aggregated probe-SSID view) shares the devices page-size
# vocabulary AND default (50) -- both list the same underlying rows, just
# grouped. 25 was the lowest default of any list page, an outlier that paged
# the probes tab out sooner than the rest; reveals stay collapsed by default,
# so a larger page is not a privacy regression. Default only -- the dropdown
# and ?page_size still offer the full allowed set, and the choice is not
# persisted across visits.
_PROBES_PER_PAGE_ALLOWED: tuple[int, ...] = (10, 25, 50, 100, 200, 250, 500)
_PROBES_PER_PAGE_DEFAULT: int = 50
# The two groupings the Probes tab offers; "device" (which networks each
# device probed) is the default, "ssid" inverts to (which devices probed
# each network). Anything else normalizes back to the default.
_PROBES_GROUPINGS: tuple[str, ...] = ("device", "ssid")
_PROBES_GROUP_DEFAULT: str = "device"

# Pattern_type filter options for /watchlist. Migration 013 expanded
# the v0.3 set to admit ble_manufacturer_id / drone_id_prefix, and
# mig-020 added ble_local_name; the dropdown enumerates every type an
# Argus import or yaml seed can produce. (ssid_pattern from mig-019
# is intentionally absent here — it's matched alongside ssid under
# the same watchlist_ssid rule_type and treated as one operator-
# facing surface; tracking the gap is out of scope for this change.)
# ⛔ Not a copy. This is `Database._WATCHLIST_PATTERN_TYPES` re-exported under
# the name the templates and route handlers already use.
#
# 🪤 It WAS a copy, frozen at migration 020, and the two lists drifted apart.
# The consequence here was different from db.py's under-count and just as quiet:
# `:3999` and `:4098` normalise an unrecognised `?pattern_type=` to None, which
# DROPS the filter rather than rejecting it -- so /watchlist and /watchlist.csv
# answered a filtered request with every row and looked like they had worked.
_WATCHLIST_PATTERN_TYPES: tuple[str, ...] = Database._WATCHLIST_PATTERN_TYPES

# Sentinel for the "(uncategorized)" device_category dropdown option
# -- mirrors Database._WATCHLIST_UNCATEGORIZED_SENTINEL. Surfacing
# it as a constant here keeps the template / route / DB layer in
# lockstep.
_WATCHLIST_UNCATEGORIZED_SENTINEL: str = "__none__"


def _parse_date_or_datetime_to_ts(
    value: str | None, *, end_of_day: bool, name: str
) -> int | None:
    """Parse a since/until URL param to an epoch-seconds bound.

    Accepts two shapes posted by the /alerts filter bar:

    * ``YYYY-MM-DD`` — date-only, promoted to UTC midnight at the
      lower bound or ``23:59:59`` at the upper bound. Preserves the
      pre-rc6 behavior so bookmarks with date-only since/until keep
      filtering the same row set.
    * ``YYYY-MM-DDTHH:MM`` / ``YYYY-MM-DDTHH:MM:SS`` — full ISO 8601
      datetime as submitted by the ``<input type="datetime-local">``
      picker. Parsed verbatim as UTC; ``end_of_day`` is ignored —
      the operator-supplied minute IS the boundary. This is the
      sub-day granularity an operator needs to express ranges like
      "Tuesday 14:00 to Wednesday 09:00."

    Malformed input silently returns ``None`` (no clause applied),
    matching the rule_type / window / has_note clamp posture on
    /alerts so a stale bookmark or fat-fingered picker submission
    lands on the unfiltered page rather than 400. The ``name``
    parameter is retained for call-site readability.
    """
    if not value:
        return None
    if "T" in value or " " in value:
        try:
            dt = _dt.datetime.fromisoformat(value)
        except (ValueError, TypeError):
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_dt.UTC)
        return int(dt.timestamp())
    try:
        d = _dt.date.fromisoformat(value)
    except (ValueError, TypeError):
        return None
    base = _dt.datetime.combine(d, _dt.time.min, tzinfo=_dt.UTC)
    if end_of_day:
        base = base.replace(hour=23, minute=59, second=59)
    return int(base.timestamp())


# Mirror of allowlist.AllowlistPatternType, exposed as a tuple so
# the /allowlist filter validator and the add-form dropdown can
# iterate in display order without re-deriving from typing.get_args.
ALLOWLIST_PATTERN_TYPES: tuple[str, ...] = (
    "mac",
    "oui",
    "ssid",
    "mac_range",
    "ble_uuid",
    "ble_manufacturer_id",
    "drone_id_prefix",
    "ble_local_name",
)


def _validate_allowlist_filters(*, source: str, status: str, type_: str) -> None:
    if source not in ("all", "primary", "ui"):
        raise HTTPException(status_code=400, detail=f"invalid source: {source!r}")
    if status not in ("all", "active", "snoozed", "expired"):
        raise HTTPException(status_code=400, detail=f"invalid status: {status!r}")
    if type_ != "all" and type_ not in ALLOWLIST_PATTERN_TYPES:
        raise HTTPException(status_code=400, detail=f"invalid type: {type_!r}")


def _entry_status_label(entry, now_ts: int) -> str:
    if entry.expires_at is None:
        return "active"
    if entry.expires_at > now_ts:
        return "snoozed"
    return "expired"


def _filter_allowlist_entries(
    tagged: list,
    *,
    q: str | None,
    source: str,
    status: str,
    type_: str,
    now_ts: int,
) -> list[dict]:
    """Apply the q/source/status/type filters and project to template rows.

    Returns a list of dicts (one per surviving entry) carrying every
    field the template renders. ``composite_key`` is populated only
    for UI entries — the template uses its truthiness as the
    "render a checkbox" flag, since primary-source entries are
    not bulk-removable.
    """
    q_lower = (q or "").strip().lower()
    rows: list[dict] = []
    for entry, src in tagged:
        if source != "all" and src != source:
            continue
        if type_ != "all" and entry.pattern_type != type_:
            continue
        status_label = _entry_status_label(entry, now_ts)
        if status != "all" and status_label != status:
            continue
        if q_lower:
            haystack = f"{entry.pattern} {entry.note or ''}".lower()
            if q_lower not in haystack:
                continue
        rows.append(
            {
                "pattern": entry.pattern,
                "pattern_type": entry.pattern_type,
                "note": entry.note or "",
                "expires_at": entry.expires_at,
                "added_at": entry.added_at,
                "source": src,
                "status": status_label,
                "composite_key": (
                    f"{entry.pattern_type}:{entry.pattern}" if src == "ui" else None
                ),
            }
        )
    return rows


def _parse_form_expires_at(value: str | None) -> int | None:
    """Parse the add-form ``expires_at`` field to a UTC epoch int.

    Empty / whitespace → None (permanent entry). HTML datetime-local
    inputs send ``YYYY-MM-DDTHH:MM`` with no timezone — interpreted
    as UTC. Trailing ``Z`` (full ISO-8601) is accepted. Anything
    else raises ValueError; the caller surfaces it inline on the
    add-form re-render.
    """
    if value is None or not value.strip():
        return None
    s = value.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = _dt.datetime.fromisoformat(s)
    except ValueError as exc:
        raise ValueError(
            f"invalid expires_at {value!r}: expected ISO-8601 / datetime-local"
        ) from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.UTC)
    return int(dt.timestamp())


def _first_validation_error(exc: ValidationError) -> str:
    """Extract the first error message from a Pydantic ValidationError.

    The add-form surfaces a single sentence so the operator can see
    the cause without scrolling through pydantic's structured dump.
    Falls back to ``str(exc)`` if the errors list is unexpectedly
    empty.
    """
    errs = exc.errors()
    if not errs:
        return str(exc)
    msg = errs[0].get("msg", "invalid input")
    loc = errs[0].get("loc") or ()
    if loc:
        return f"{loc[-1]}: {msg}"
    return msg


def _normalize_optional_note(note: str | None) -> str | None:
    if note is None or note == "":
        return None
    if len(note) > 500:
        raise HTTPException(status_code=400, detail="note must be <= 500 chars")
    return note


#: Every path parameter that becomes a SQLite row id.
#:
#: ⛔ **`int` alone is not a row id, and the gap is reachable.** FastAPI's `int`
#: converter is an arbitrary-precision Python int with no upper bound; SQLite's
#: INTEGER is signed 64-bit. So `GET /alerts/9223372036854775808` reached the
#: query layer and raised `OverflowError: Python int too large to convert to
#: SQLite INTEGER` out of the route. Measured on **all 15** routes carrying one
#: of these params -- `2**63` returned **500** where `2**63 - 1` correctly
#: returned 404.
#:
#: ⚠️ **Graded, not inflated.** The body is Starlette's plain "Internal Server
#: Error" and leaks nothing; the daemon keeps serving (the next request 404s
#: normally); nothing is written before the raise. It is a wrong status code on
#: hostile input, not a security or availability defect. It is fixed here
#: because the class is 15 surfaces wide and the fix is one line each.
#:
#: ⛔ **`le` only, deliberately no `ge`.** Zero and negative ids currently reach
#: the routes' own preconditions and return **400** with a message about the
#: entry; adding `ge=1` would silently convert those to 422 and change
#: behaviour three existing tests pin. Bounding the end that actually breaks is
#: the whole change.
#:
#: ⛔ Derived, not transcribed: `test_every_int_path_param_is_bounded` walks the
#: AST for `<name>: int` in a route signature and fails on the 16th one, because
#: this project has re-committed a first-match-only fix three PRs later before.
SQLITE_MAX_ROWID = 2**63 - 1
RowId = Annotated[int, PathParam(le=SQLITE_MAX_ROWID)]


def unix_to_iso(ts) -> str:
    """Format a unix epoch int as ISO 8601 UTC with 'Z' suffix.

    None/empty → "" so templates can render the value unconditionally.
    """
    if ts is None or ts == "":
        return ""
    dt = _dt.datetime.fromtimestamp(int(ts), tz=_dt.UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


#: How far AHEAD of this clock a stored timestamp may sit and still count as
#: "now".
#:
#: ⭐ **It is the poller's own clamp, and that is measured, not a matching
#: taste.** ``poller.record_observation`` takes the capture source's
#: ``last_seen`` — Kismet's clock, a different machine's — and only rewrites it
#: when it exceeds ``now_ts + CLOCK_JUMP_TOLERANCE_SECONDS``. So anything inside
#: that band was **deliberately stored as "close enough to now" by the writer**,
#: and a display that flagged it would be this UI disagreeing with the daemon
#: about what counts as a clock problem. That is the exact failure
#: ``CLOCK_BEHIND_TOLERANCE_SECONDS`` documents itself as existing to prevent,
#: and the two are already pinned equal by a test — so this reuses that constant
#: rather than inventing a third number.
#:
#: ⚠️ **Asymmetric on purpose.** The PAST side keeps its own 60-second "just
#: now" bucket, untouched: that is a display convention, not a skew allowance,
#: and widening it would silently rewrite 21 existing call sites.
FUTURE_SKEW_SECONDS = CLOCK_BEHIND_TOLERANCE_SECONDS

#: The past-side "just now" bucket. Unchanged from before this module gained a
#: future branch; see the asymmetry note above.
JUST_NOW_SECONDS = 60


def age_since(reference_ts, *, now_ts: int) -> int | None:
    """Whole seconds since ``reference_ts``, or ``None`` when it is AHEAD of this
    clock by more than ordinary skew.

    ⛔ **Not ``max(0, now - ref)``, and that clamp was a live defect on three
    surfaces.** Clamping a negative delta to zero turns "this timestamp is in
    the future" into "this happened just now", which every downstream staleness
    test then reads as FRESH. Measured, watchlist imported 365 days ago with an
    Argus export dated 30 days ahead:

        /settings card   status=fresh   age_days=0     <- the clamp
        home summary     is_stale=False                <- the clamp
        /healthz.json    stale=True     days=365       <- keyed on a different ts

    Two surfaces called it fresh and one called it stale, for the same watchlist
    at the same instant.

    ⚠️ **This needs no local clock fault to reach.** The watchlist's reference is
    ``exported_at``, which carries the Argus host's clock -- a *different
    machine's* -- so a future-dated export is the ordinary cross-host case, not
    an exotic one.

    ``None`` rather than a negative number, because "how old is this" has no
    answer when the thing is stamped in the future, and a negative age silently
    satisfies every ``age > threshold`` test in the codebase.
    """
    if reference_ts is None:
        return None
    delta = int(now_ts) - int(reference_ts)
    if delta < -FUTURE_SKEW_SECONDS:
        return None
    return max(0, delta)


def stored_int(value) -> int | None:
    """Parse a value read out of the database, or ``None`` if it cannot be read.

    ⛔ **A bare ``int()`` on a stored column crashes the page that reads it.**
    Measured on a database carrying ONE ``import_runs.imported_at`` of
    ``"not-an-int"``:

        route            before        after
        /                HTTP 500      200, watchlist "unknown"
        /settings        HTTP 500      200
        /healthz.json    503           503 (isolated by #161, reported not fatal)

    The home page is the operator's primary surface and, on a default install
    with the heartbeat off, their liveness signal. One damaged row took it out
    entirely -- and #161's per-check isolation covered `/healthz.json` only,
    which is containment of one surface, not a fix of the mechanism.

    ⚠️ ``None`` here means "could not be read", which the callers already have a
    state for: `status: "unknown"` / `staleness_known: False`. It deliberately
    does NOT mean zero -- an unreadable timestamp reported as the epoch would
    render as "imported in 1970", a confident wrong answer.
    """
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def age_days_since(reference_ts, *, now_ts: int) -> int | None:
    """``age_since`` in whole days. ``None`` propagates -- see there."""
    seconds = age_since(reference_ts, now_ts=now_ts)
    return None if seconds is None else seconds // 86400


def unix_to_utc_human(ts) -> str:
    """Format a unix epoch int as 'YYYY-MM-DD HH:MM UTC' for human display."""
    if ts is None or ts == "":
        return ""
    dt = _dt.datetime.fromtimestamp(int(ts), tz=_dt.UTC)
    return dt.strftime("%Y-%m-%d %H:%M UTC")


def relative_time(ts, *, now_ts: int | None = None) -> str:
    """Format a unix epoch int as a human-readable relative time.

    Buckets: within 60s either way → "just now"; <60min → "{N}m ago";
    <24h → "{N}h ago"; else → "{N}d ago". None / empty → "—" (the
    column placeholder).

    ⛔ **A timestamp genuinely AHEAD of this clock renders as an absolute
    instant, not as "just now".** It used to collapse to "just now" at any
    distance, justified as *"defensive against clock skew"*. Measured, that
    made two different claims false:

        /rules,   a rule_type snooze with 6h left  "snoozed (until just now)"
        /devices, a device silence with 6h left    "silenced (until just now)"

    An ``expires_at`` is in the future for **every** suppression still in
    force, so the badge said the suppression was over precisely while it was
    working — and suppression is the direction that hides a follower. The same
    collapse let a poll tick stamped ahead of a behind clock read as a live
    daemon (see ``poll_tick_liveness``).

    ⚠️ The skew defence is real and is KEPT, bounded: ``sightings.ts`` carries
    Kismet's clock, i.e. a different machine's, so a value a few seconds ahead
    is ordinary. Sixty seconds of it is skew; six hours of it is not, and
    calling six hours "just now" is not defensive, it is wrong.

    ⭐ Absolute rather than "in 6h", for two reasons: the templates read
    ``snoozed (until {{ ... }})``, where "until in 6h" is not English; and the
    client-side sibling ``lynceus.js:formatStamp`` already made exactly this
    call for exactly this case ("Future timestamps: render as fully-qualified
    absolute (don't say 'in 3 hours')"). Two formatters disagreeing about the
    same question is how a UI ends up asserting two things at once.

    ``now_ts`` is taken from the template context when called as a
    filter via ``{{ ts | relative_time(now_ts) }}``; falls back to
    ``int(time.time())`` only when invoked without a now_ts
    argument (tests, ad-hoc callers).
    """
    if ts is None or ts == "":
        return "—"
    if now_ts is None:
        now_ts = int(time.time())
    delta = int(now_ts) - int(ts)
    if delta < 0:
        if -delta <= FUTURE_SKEW_SECONDS:
            return "just now"
        return unix_to_utc_human(ts)
    if delta < JUST_NOW_SECONDS:
        return "just now"
    if delta < 3600:
        return f"{delta // 60}m ago"
    if delta < 86400:
        return f"{delta // 3600}h ago"
    return f"{delta // 86400}d ago"


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


def _probe_ssids_list(raw: str | None) -> list[str]:
    """Decode the devices.probe_ssids JSON-string column into a list.

    Storage (merge_device_probe_ssids) writes ``None`` for empty and a
    json.dumps'd list otherwise. The filter is safe-by-default: any
    malformed payload or unexpected shape renders as an empty list,
    which the template treats as "no probes seen"."""
    if not raw:
        return []
    try:
        decoded = json.loads(raw)
    except (json.JSONDecodeError, TypeError, ValueError):
        return []
    if not isinstance(decoded, list):
        return []
    return [s for s in decoded if isinstance(s, str)]


def _device_label(device: dict | None) -> str:
    """Best-available human label for a device.

    Priority: ble_name (Kismet-extracted advertised BLE name, e.g. "Sony
    WH-1000XM4") → friendly_name (alerts-join enrichment) → oui_vendor
    (Kismet manuf) → "—". Forward-compatible: a dict missing any of the
    earlier keys falls through naturally."""
    if not device:
        return "—"
    ble = device.get("ble_name")
    if ble and ble.strip():
        return ble.strip()
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
    # Home page is a valid acknowledge surface: the recent-unacknowledged
    # alerts card on / posts to the same /alerts/<id>/ack endpoint, and
    # an operator who clicks Acknowledge from / should land back on /
    # rather than being teleported to /alerts (v0.7.9 Touch 3).
    if path == "" or path == "/":
        return "/"
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

    The freshness signal that previously lived here as
    ``last_imported_ts`` (a per-row proxy via ``MAX(updated_at)
    FROM watchlist_metadata``) moved to the dedicated
    ``_watchlist_freshness_card`` helper, which reads the canonical
    per-import metadata from the ``import_runs`` table (migration
    012). The proxy was misleading: re-importing the same stale CSV
    flipped it to "now" while the underlying data was still months
    old. The dedicated helper renders both Argus-side
    ``exported_at`` and local-clock ``imported_at`` so operators
    can spot that case.
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
    return {
        "total": int(total),
        "argus": int(argus),
        "yaml": int(yaml_seeded),
        "bundled": int(bundled),
    }


def _watchlist_freshness_card(db: Database, warn_days: int, *, now_ts: int) -> dict:
    """Compute the /settings 'Watchlist freshness' card payload.

    Mirrors the data shape ``log_watchlist_staleness`` reads at
    poller startup — the two surfaces are deliberately kept in
    lockstep so an operator who sees a WARNING in journalctl can
    open /settings and see the same numbers without reconciling.

    Returns a dict with stable keys regardless of state (no
    imports, fresh, stale) so the template doesn't need branching
    on presence:

    - ``has_import``: True iff ``import_runs`` carries at least one
      row. When False, every other field below is None / 0 and the
      template renders a "no Argus import metadata recorded" line.
    - ``status``: ``"fresh"`` | ``"stale"`` | ``"unknown"``. Drives
      the badge color. ``"unknown"`` in TWO cases, distinguished by
      ``has_import``: no import recorded at all (``has_import``
      False), or an import whose reference timestamp is ahead of
      this clock so its age is not established (``has_import`` True,
      ``age_days`` None). ⚠️ This sentence previously said "only
      when ``has_import`` is False" and stopped being true when the
      second case was added.
    - ``imported_at`` / ``exported_at``: int UTC seconds, or None.
      Rendered via the existing ``unix_to_utc_human`` Jinja filter.
    - ``age_days``: int days computed against ``exported_at`` when
      present, else ``imported_at``; **None** when that reference is
      ahead of this clock, because "how old is this" has no answer
      for a future timestamp. Identical fallback rule AND identical
      unknown rule as the log line — both surfaces must agree, and
      ``tests/test_watchlist_age_lockstep.py`` now checks that they
      do rather than leaving it as an instruction to future authors.
    - ``source``: free-form string from ``import_runs.source``
      (absolute path or ``owner/repo@ref``); rendered verbatim
      with no decoration so a forensic copy-paste from /settings
      drops cleanly into a shell.
    - ``record_count``: canonical Argus-side row count from the
      ``# meta:`` line, distinct from the surviving-after-filters
      count in the importer's stdout.
    - ``pattern_type_counts``: ``{mac, oui, ssid, ble_uuid,
      mac_range, ble_manufacturer_id, drone_id_prefix}`` → int.
      Every type present even when zero so the template renders
      a stable layout. Keys mirror ``Database._WATCHLIST_PATTERN_TYPES``;
      adding a new pattern_type there requires extending the
      ``settings.html`` breakdown line too — drift between the
      two surfaces silently drops the new type from the operator
      view (rc5 pre-smoke regression).
    - ``warn_days``: echoed back from config for the "Fresh
      (within N days)" / "Stale (older than N days)" labels.
    """
    pattern_type_counts = db.watchlist_pattern_type_counts()
    latest = db.get_latest_import_run()
    if latest is None:
        return {
            "has_import": False,
            "status": "unknown",
            "imported_at": None,
            "exported_at": None,
            "age_days": None,
            "source": None,
            "record_count": None,
            "pattern_type_counts": pattern_type_counts,
            "warn_days": warn_days,
        }
    imported_at = stored_int(latest["imported_at"])
    exported_at = stored_int(latest["exported_at"])
    # ⚠️ `is not None`, not `or`: an export stamped at epoch 0 is falsy, and the
    # `or` silently fell through to the import time instead -- the same shape as
    # the heartbeat bug where a delivery at epoch 0 read as never delivered.
    reference_ts = exported_at if exported_at is not None else imported_at
    # ⛔ `age_days` is None when the reference is stamped AHEAD of this clock,
    # and the status is then "unknown" rather than "fresh". The old
    # `max(0, ...)` read a future export as "imported today", which is the most
    # reassuring answer available and the one nothing had established.
    # It is None for an UNREADABLE reference too, for the same reason.
    age_days = (
        None if reference_ts is None else age_days_since(reference_ts, now_ts=now_ts)
    )
    return {
        "has_import": True,
        "status": (
            "unknown"
            if age_days is None
            else "stale"
            if age_days > warn_days
            else "fresh"
        ),
        "imported_at": imported_at,
        "exported_at": exported_at,
        "age_days": age_days,
        "source": latest["source"],
        "record_count": stored_int(latest["record_count"]),
        "pattern_type_counts": pattern_type_counts,
        "warn_days": warn_days,
    }


def _watchlist_freshness_summary(
    db: Database, warn_days: int, *, now_ts: int
) -> dict:
    """Compact watchlist-freshness payload for the home page card.

    Returns a stable-shape dict regardless of state so the template
    doesn't have to guard on presence:

    - ``has_import``: True iff at least one row exists in ``import_runs``.
    - ``record_count``: int from the Argus ``# meta:`` line, or None.
    - ``exported_at``: int UTC seconds the snapshot was exported, or
      None when the source CSV had no parseable ``exported_at``.
    - ``is_stale``: True when the age (against exported_at when set,
      else imported_at) exceeds ``warn_days``; never True when
      ``has_import`` is False.

    Gracefully handles the legacy pre-migration-012 install case:
    operators upgrading from before the ``import_runs`` table landed
    will not have the table on first daemon start (only after
    migrations rerun). A bare ``OperationalError`` here would 500 the
    home page; degrade to the "no watchlist loaded" state instead so
    the rest of the page still renders.
    """
    empty = {
        "has_import": False,
        "record_count": None,
        "exported_at": None,
        "is_stale": False,
    }
    try:
        latest = db.get_latest_import_run()
    except sqlite3.OperationalError:
        return empty
    if latest is None:
        return empty
    imported_at = stored_int(latest["imported_at"])
    exported_at = stored_int(latest["exported_at"])
    reference_ts = exported_at if exported_at is not None else imported_at
    age_days = (
        None if reference_ts is None else age_days_since(reference_ts, now_ts=now_ts)
    )
    return {
        "has_import": True,
        # ⛔ None, not False, when the reference is ahead of this clock OR could
        # not be read: the verdict is not established, and False is the
        # reassuring guess.
        "staleness_known": age_days is not None,
        "record_count": stored_int(latest["record_count"]),
        "exported_at": exported_at,
        "is_stale": None if age_days is None else age_days > warn_days,
    }


def _build_settings_context(
    config: Config,
    db: Database,
    kismet_status: dict,
    loaded_config_path: str | Path | None = None,
) -> dict:
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

    # ⛔ The CONFIGURED path, falling back to the default only when nothing is
    # configured. This read `paths.default_overrides_path("user")`
    # unconditionally, so an operator who set `severity_overrides_path`
    # elsewhere was shown the existence of a file nothing reads — measured:
    # config pointing at a loaded temp file, card printing the user default and
    # "missing". The next step it invites is to create a file at that path,
    # where nothing will ever look at it.
    #
    # ⚠️ `configured` travels to the template so the page can say WHICH of the
    # two it is showing. A path with no provenance is how this defect stayed
    # invisible.
    configured_overrides = getattr(config, "severity_overrides_path", None)
    overrides_path = (
        Path(configured_overrides)
        if configured_overrides
        else paths.default_overrides_path("user")
    )
    config_path_default = paths.default_config_path("user")
    # ⚠️ `"user"` for both, and that scope is an assumption, not a reading. A
    # system-scope install logs to /var/log/lynceus and keeps its config under
    # /etc; nothing here knows which it is. The config half is answerable --
    # the loaded path is passed to `create_app` -- so it is answered; the log
    # half is not, and the page now labels it as the default rather than as
    # this daemon's.
    log_dir_default = paths.default_log_dir("user")

    try:
        lynceus_version = importlib.metadata.version("lynceus")
    except importlib.metadata.PackageNotFoundError:
        lynceus_version = __version__

    # Readiness is evaluated even when the bridge is off, so the panel can
    # answer "what would happen if I turned this on" as well as "why is this
    # on but quiet". Rule types are known here (unlike in the wizard), so the
    # alert-storm gate can be checked too — but only if the ruleset actually
    # loads. When it does not we cannot evaluate that gate, and the panel says
    # so rather than rendering a clean result that means "not checked".
    # ⛔ `None` means WE DO NOT KNOW the rule state; `[]` means we looked and
    # found no enabled rules. They are different claims and collapsing them
    # makes the readiness check guess. With no `rules_path` there is no ruleset
    # to read, and when one exists but will not parse we know less still -- in
    # both cases a "nothing consumes the decoded class" warning would be
    # asserting something this function never established. An empty LIST, by
    # contrast, is a real and reportable finding: rules loaded, none enabled.
    enabled_rule_types: list[str] | None = None
    rules_unreadable = False
    if config.rules_path:
        try:
            enabled_rule_types = [
                r.rule_type
                for r in rules_mod.load_ruleset(config.rules_path).rules
                if r.enabled
            ]
        except Exception:
            rules_unreadable = True
            enabled_rule_types = None

    try:
        ble_class_counts = db.count_devices_by_ble_device_class()
    except sqlite3.Error:
        ble_class_counts = {}

    # Surfaced beside the other health facts, because an operator whose snooze
    # was just refused needs somewhere that explains why -- and one whose clock
    # is wrong should not have to be refused first to find out.
    # ⚠️ One clock read for everything below that compares against "now".
    # Three separate `int(time.time())` calls in one page render can straddle a
    # second boundary and make two cards disagree about the same instant.
    settings_now_ts = int(time.time())
    heartbeat_last_delivered = db.latest_delivered_heartbeat_ts()
    clock_state = clock_behind_recorded_history(db, settings_now_ts)
    settings_overrides = load_overrides(config)
    suppressions = suppression_axes_of(settings_overrides)
    # ⭐ Named beside the silence list, and for the same reason: this page tells
    # the operator what their overrides file is doing. It listed the selectors
    # that SILENCE and said nothing about the three that REMAP, so a severity
    # the runtime rewrites had no page anywhere admitting it.
    configured_remaps = configured_remap_axes(settings_overrides)

    # ⭐ Liveness is graded against the card's OWN counts, not a second query.
    # The note says "3 of these cannot fire" directly beneath the breakdown
    # line; two reads with a write possible between them would let the note
    # and the numbers above it disagree, which is a worse failure than the
    # silence this replaces -- an operator would go looking for a row that is
    # not there.
    freshness_card = _watchlist_freshness_card(
        db,
        config.watchlist_staleness_warn_days,
        now_ts=int(time.time()),
    )
    liveness = watchlist_liveness(
        config,
        freshness_card["pattern_type_counts"],
        db=db,
        now_ts=int(time.time()),
    )

    return {
        "capture": {
            "probe_ssids": bool(config.capture.probe_ssids),
            "ble_friendly_names": bool(config.capture.ble_friendly_names),
        },
        "ble_bridge": {
            "enabled": bool(config.ble_bridge.enabled),
            "adapter": config.ble_bridge.adapter,
            "source_name": bridge_source_name(config.ble_bridge.adapter),
            "warnings": collect_bridge_warnings(
                adapter=config.ble_bridge.adapter,
                kismet_sources=config.kismet_sources,
                enabled_rule_types=enabled_rule_types,
            ),
            "class_counts": ble_class_counts,
            "decoded_total": sum(ble_class_counts.values()),
            "rules_unreadable": rules_unreadable,
            # ⛔ THREE-valued, and it has to be. `None` means we could not
            # determine the rule state (no rules_path, or a ruleset that will
            # not parse) -- the panel must not answer ON or OFF there, because
            # both would be claims this function never established. Derived
            # from the LOADED ruleset and never from `config.ble_bridge.enabled`
            # or from an assumption about the shipped default: the operator may
            # have turned the rule off, and a panel that cannot represent that
            # is the same defect this line was added to report.
            "find_my_rule_enabled": (
                None
                if enabled_rule_types is None
                else "ble_device_class" in enabled_rule_types
            ),
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
            # ⭐ Alerts written but never successfully delivered (migration
            # 024). Reachability alone is a LIVENESS probe -- it says the
            # broker answered just now, not that anything ever arrived. A
            # wrong topic or a stale auth token passes reachability and drops
            # every notification, and the operator's only symptom is silence,
            # which is indistinguishable from "nothing is out there". This
            # number is the difference between those two.
            "undelivered": db.count_undelivered_alerts(),
        },
        # The dead-man's switch (migration 025). Reported here rather than on
        # the home page because the question it answers -- "is my proof-of-life
        # actually arriving?" -- is a configuration question. An enabled
        # heartbeat that has never been delivered is the worst state to be in
        # and not know about: the operator believes silence would be
        # interrupted, and it would not.
        "heartbeat": {
            "enabled": config.heartbeat_enabled,
            "interval_hours": config.heartbeat_interval_hours,
            "last_delivered_at": heartbeat_last_delivered,
            "undelivered": db.count_undelivered_heartbeats(),
            # ⛔ "delivered at least once, ever" is what this card used to
            # answer. A switch 400 intervals overdue rendered green.
            **heartbeat_liveness(
                heartbeat_last_delivered, config, now_ts=settings_now_ts
            ),
        },
        "watchlist_stats": _watchlist_origin_breakdown(db),
        "watchlist_freshness": freshness_card,
        "watchlist_liveness": liveness,
        "clock_state": clock_state,
        # The same instant every card on this page compares against.
        "now_ts": settings_now_ts,
        "runtime_suppressions": suppressions,
        "configured_remaps": configured_remaps,
        "severity_overrides": {
            "path": str(overrides_path),
            "exists": overrides_path.exists(),
            "configured": bool(configured_overrides),
            # ⚠️ Existing is not the same as being READ. An unparseable file
            # leaves the runtime layer disabled — `load_runtime_severity_overrides`
            # logs and returns None, and the poller then applies nothing — while
            # the card said "exists" and stopped there.
            "loaded": settings_overrides is not None,
        },
        "system": {
            "lynceus_version": lynceus_version,
            "db_path": str(db_path),
            "db_size_human": db_size_human,
            "db_mtime": db_mtime,
            # The file this process actually loaded, or None when the caller
            # did not say. Never the default dressed up as the active one.
            "config_path": str(loaded_config_path) if loaded_config_path else None,
            "config_path_default": str(config_path_default),
            "log_dir_default": str(log_dir_default),
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


def _match_mac_in_entries(
    entries: list[AllowlistEntry],
    mac: str,
    now_ts: int,
) -> AllowlistEntry | None:
    """Return the first entry whose pattern matches the MAC, respecting expiry.

    Webui-side counterpart to ``Allowlist.is_allowed`` for the alert-detail
    lookup. Matches ``mac``, ``oui``, and ``mac_range`` pattern types:
    alerts do not carry live SSID / BLE / drone-id context, so the
    remaining allowlist types cannot be evaluated against an alert
    without re-fetching the device's last-known fields — and the
    operator-intent of those types is "this network / this radio",
    not "this device", so silently mis-attributing a suppression that
    way would be worse than not matching at all. Expired entries are
    skipped, mirroring poll-time semantics.
    """
    matches = _match_all_mac_in_entries(entries, mac, now_ts)
    return matches[0] if matches else None


def _match_all_mac_in_entries(
    entries: list[AllowlistEntry],
    mac: str,
    now_ts: int,
) -> list[AllowlistEntry]:
    """EVERY active entry covering this MAC, not the first.

    ⛔ A MAC can be covered by an exact `mac` entry AND an `oui` entry AND a
    `mac_range` entry at once. Naming one and telling the operator to remove it
    offers a next step that does not restore alerting — the identical defect
    ``override_suppression_axes`` was changed to fix in #116, found here by a
    cold read of the composed subsystem.

    ⚠️ ``_match_mac_in_entries`` keeps returning the first, because its callers
    (the alert-detail "actioned" badge) ask a yes/no question and the first
    match answers it. Only the surfaces that offer a REMEDIATION need all of
    them.
    """
    out: list[AllowlistEntry] = []
    for entry in entries:
        if entry.expires_at is not None and entry.expires_at <= now_ts:
            continue
        if entry.pattern_type == "mac" and entry.pattern == mac:
            out.append(entry)
        elif entry.pattern_type == "oui" and mac.startswith(entry.pattern + ":"):
            out.append(entry)
        elif entry.pattern_type == "mac_range" and mac_in_mac_range(mac, entry.pattern):
            out.append(entry)
    return out


def _entry_can_alert(
    entry: dict,
    row: dict,
    liveness: dict,
    suppressions: dict,
    allowlist_entries: list,
    now_ts: int,
) -> bool | None:
    """Can this watchlist row produce an alert today? ``None`` = cannot tell.

    Order matters and is the whole point:

    1. **Definite blockers first.** A rule_type snooze, a severity-override
       suppression, a reserved OUI prefix and an allowlist match are each
       established WITHOUT reading the ruleset, so any of them is a plain
       ``False`` no matter what the ruleset verdict is.
    2. **Then the ruleset verdict.** If it could not be read, the answer is
       ``None`` -- not ``True`` (which the page rendered as "this entry
       alerts", a promise nothing had checked) and not ``False`` (whose wording
       points at "the reason given elsewhere on this page", and there is none).
    3. Otherwise the type is delegated or it is not, and that is the answer.

    ⚠️ Callers must test ``is None`` / ``is False`` explicitly. ``if not
    entry_can_alert`` reads ``None`` as "cannot alert", which is the branch
    whose text asserts a blocker exists.
    """
    if is_pattern_type_snoozed(entry["pattern_type"], liveness):
        return False
    if override_suppression_axes(
        row.get("vendor"), row.get("device_category"), suppressions
    ):
        return False
    if oui_prefix_never_matches(row.get("pattern_type"), row.get("pattern")):
        return False
    if (
        allowlist_answerable_for(row.get("pattern_type") or "")
        and row.get("pattern")
        and _match_all_mac_in_entries(allowlist_entries, row["pattern"], now_ts)
    ):
        return False
    if not liveness.get("known"):
        return None
    return is_pattern_type_live(entry["pattern_type"], liveness)


def _merged_allowlist_entries(config: Config) -> list:
    """Primary + UI allowlist entries, in the order ``is_allowed`` sees them.

    ⚠️ Loads YAML, so callers gate on actually needing it — the same posture
    ``_load_actioned_patterns`` documents for the /alerts filter. Missing or
    unconfigured files return an empty list rather than raising: a page must
    not 500 because the operator has not created an allowlist yet.
    """
    if not config.allowlist_path:
        return []
    primary_path = Path(config.allowlist_path)
    try:
        primary_entries = list(allowlist_mod._load_primary(primary_path).entries)
    except FileNotFoundError:
        primary_entries = []
    return primary_entries + list(
        allowlist_mod._load_ui_entries(derive_ui_path(primary_path))
    )


def _allowlisted_row_ids(config: Config, rows, now_ts: int) -> set[int]:
    """Ids of the `mac` watchlist rows an active HARD allowlist entry silences.

    ⛔ `mac` rows only — for anything that can match many devices there is no
    single answer, and inventing one would be a new instance of the defect this
    subsystem keeps finding. ``liveness.allowlist_answerable_for`` is the
    predicate, so the rule lives in one place.

    ⚠️ ``_match_mac_in_entries`` matches exactly ``mac`` / ``oui`` /
    ``mac_range`` — which is ``allowlist.HARD_ALLOWLIST_PATTERN_TYPES``, the set
    that may silence an explicit watchlist hit. A SOFT entry must NOT mark a
    row: since #82 a device-chosen value cannot suppress a watchlist hit, so
    marking it would report a silence that does not happen. Pinned by
    ``test_a_soft_allowlist_entry_does_not_mark_the_row``.
    """
    mac_rows = [
        r for r in rows if allowlist_answerable_for(r.pattern_type) and r.pattern
    ]
    if not mac_rows:
        return set()
    entries = _merged_allowlist_entries(config)
    if not entries:
        return set()
    return {
        r.id
        for r in mac_rows
        if _match_mac_in_entries(entries, r.pattern, now_ts) is not None
    }


def _load_actioned_patterns(
    config: Config,
    now_ts: int,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """Active mac + oui + mac_range allowlist patterns, merged across both files.

    Returns ``(macs, oui_prefixes, mac_ranges)``. All three lists are
    post-expiry -- snooze entries past their ``expires_at`` are
    skipped, mirroring ``Allowlist.is_allowed`` and
    ``_match_mac_in_entries``. ``pattern_type`` in {``mac``, ``oui``,
    ``mac_range``} contributes: alerts do not carry live SSID / BLE /
    drone-id context, so the remaining types cannot be matched from
    ``alert.mac`` alone, and the alert-detail page's
    ``_match_mac_in_entries`` documents the same scope. The /alerts
    has_action filter consumes the third tuple via the SQL
    ``mac_in_mac_range`` function registered on every Database
    connection, so the SQL side and the alert-detail "actioned" badge
    agree on which alerts a mac_range allowlist entry suppresses.

    Called only when has_action is engaged on the /alerts route --
    the default page request stays YAML-cost-free. Missing
    ``allowlist_path`` or missing primary file returns empty tuples
    (the alert-detail page handles those configurations the same way).
    """
    if not config.allowlist_path:
        return (), (), ()
    primary_path = Path(config.allowlist_path)
    try:
        primary_entries = allowlist_mod._load_primary(primary_path).entries
    except FileNotFoundError:
        primary_entries = []
    ui_entries = allowlist_mod._load_ui_entries(derive_ui_path(primary_path))
    macs: list[str] = []
    ouis: list[str] = []
    mac_ranges: list[str] = []
    for entry in list(primary_entries) + list(ui_entries):
        if entry.expires_at is not None and entry.expires_at <= now_ts:
            continue
        if entry.pattern_type == "mac":
            macs.append(entry.pattern)
        elif entry.pattern_type == "oui":
            ouis.append(entry.pattern)
        elif entry.pattern_type == "mac_range":
            mac_ranges.append(entry.pattern)
    return tuple(macs), tuple(ouis), tuple(mac_ranges)


def _resolve_allowlist_match(
    config: Config,
    alert_mac: str | None,
    now_ts: int,
) -> tuple[AllowlistEntry | None, bool, bool, str | None]:
    """Look up the alert's MAC across both allowlist files.

    Returns ``(match, removable, configured, source)``:

    - ``match``: the matched ``AllowlistEntry``, or ``None``.
    - ``removable``: True only when the match came from the daemon-managed
      UI sibling AND is an exact ``mac`` entry, which is the only shape the
      remove endpoints can address. Primary-file entries are
      operator-curated; the daemon never writes to the primary file, so the
      UI cannot remove them. The triage section renders status without a
      button in those cases, with a hint naming what to do instead.

      ⛔ The "exact mac" half was missing and the button lied. ``/allowlist``
      offers an add form with a ``pattern_type`` dropdown, so an operator can
      put an ``oui`` or ``mac_range`` entry in the UI file; it then covers this
      device (the matcher honours all three shapes) and ``removable`` said
      True, while both remove endpoints delete ``(mac, "mac")`` and find
      nothing. Measured at cca7c5c: an ``oui`` UI entry, "Remove from
      allowlist" clicked, **303 back to the page, the file byte-identical, the
      device still silenced** -- a success redirect over a write that never
      happened, which is this project's signature defect.

      ⚠️ Deliberately NOT fixed by making the button remove whatever matched.
      An ``oui`` entry silences a whole prefix; lifting it from a per-device
      button would un-silence every other device it covers, without saying so.
      The offer is narrowed and the covering entry is named instead, with
      ``/allowlist``, which removes UI entries by composite key, as the remedy.

    - ``source``: ``"primary"``, ``"ui"``, or ``None`` when there is no match.
      The template needs the two non-removable cases to read differently:
      a primary-file entry is edited by hand, a non-mac UI entry is removed on
      ``/allowlist``.
    - ``configured``: True when ``config.allowlist_path`` is set. When
      False, the triage section is hidden entirely, parity with the
      /allowlist read-only view.

    Both files are read per request — same convention as the /allowlist
    read-only view. No caching: edits land instantly without invalidation.
    """
    if not config.allowlist_path or alert_mac is None:
        return None, False, bool(config.allowlist_path), None
    primary_path = Path(config.allowlist_path)
    try:
        primary_entries = allowlist_mod._load_primary(primary_path).entries
    except FileNotFoundError:
        primary_entries = []
    ui_entries = allowlist_mod._load_ui_entries(derive_ui_path(primary_path))
    primary_match = _match_mac_in_entries(primary_entries, alert_mac, now_ts)
    if primary_match is not None:
        return primary_match, False, True, "primary"
    ui_match = _match_mac_in_entries(ui_entries, alert_mac, now_ts)
    if ui_match is not None:
        return ui_match, ui_match.pattern_type == "mac", True, "ui"
    return None, False, True, None


def _resolve_silence_states(
    config: Config,
    macs: list[str],
    now_ts: int,
) -> dict[str, AllowlistEntry]:
    """Map each MAC to its active allowlist/snooze entry, for the device list.

    The device-list badge needs the same silence state the device-detail
    page resolves via ``_resolve_allowlist_match``, but for a whole page
    of rows at once. Calling that per device would re-read both YAML
    files once per row; this hoists the two file reads out of the loop
    and matches each MAC against the in-memory entries with the same
    ``_match_mac_in_entries`` matcher, so the list badge agrees with the
    detail page's silence section (mac / oui / mac_range patterns, expiry
    respected). Primary entries are checked before UI entries, mirroring
    ``_resolve_allowlist_match``'s precedence. MACs with no active match
    are absent from the returned dict.
    """
    if not config.allowlist_path:
        return {}
    primary_path = Path(config.allowlist_path)
    try:
        primary_entries = allowlist_mod._load_primary(primary_path).entries
    except FileNotFoundError:
        primary_entries = []
    ui_entries = allowlist_mod._load_ui_entries(derive_ui_path(primary_path))
    all_entries = list(primary_entries) + list(ui_entries)
    states: dict[str, AllowlistEntry] = {}
    for mac in macs:
        match = _match_mac_in_entries(all_entries, mac, now_ts)
        if match is not None:
            states[mac] = match
    return states


# --- /healthz.json per-check helpers ---------------------------------------
#
# Each helper returns a small dict with a stable shape. The shape is the
# project's public contract with monitoring tools (Prometheus blackbox,
# Nagios, uptime bots) — existing keys MUST NEVER disappear in future
# releases; future releases add keys only. Tests in
# tests/test_healthz_json.py pin the key set.
#
# All helpers are read-only and derive from existing data sources only.
# No new tables, no daemon-side heartbeat infrastructure: ``last_poll_at``
# already exists in the ``poller_state`` table (written every poll tick),
# ``last_observation_at`` derives from ``MAX(sightings.ts)`` (index-backed
# via ``idx_sightings_ts``), and the watchlist + alerts checks reuse the
# helpers that back the /settings and / pages today.


def _read_last_tick_stats(db: Database) -> dict | None:
    """Return the most-recent poll tick's per-bucket counters, or ``None``
    when the daemon has not completed a tick yet (fresh install, or the
    daemon never started).

    Five poller_state keys are written every tick by ``poll_once``:
    ``last_tick_completed_at`` (epoch int), ``last_tick_admitted``, and
    three ``last_tick_dropped_*`` counters. We use the presence of
    ``last_tick_completed_at`` as the never-polled sentinel — the
    counters could legitimately all be zero (empty Kismet response on a
    quiet stretch), so the timestamp is the load-bearing signal.

    Internal keys (``dropped_source_allowlist`` / ``min_rssi`` /
    ``unparseable``) stay machine-readable; the home page card and
    /healthz HTML translate them to operator copy at the rendering
    layer."""
    completed_raw = db.get_state("last_tick_completed_at")
    if completed_raw is None:
        return None
    stamp_readable = True
    try:
        completed_at: int | None = int(completed_raw)
    except (TypeError, ValueError):
        # ⛔ Present but unreadable is NOT "never polled", and returning None
        # here said it was. Measured: a stored `last_tick_completed_at` of
        # "not-an-int" produced `staleness_known: True, is_stale: False` -- a
        # daemon dead for a year reported as a fresh install waiting for its
        # first poll, with `admitted: 0` beside it while the real counters
        # (42 admitted, 7 dropped) sat readable in the database.
        completed_at = None
        stamp_readable = False

    counters_known = True

    def _read_int(key: str) -> int:
        nonlocal counters_known
        raw = db.get_state(key)
        if raw is None:
            # Absent is a real zero: poll_once writes all five together, so a
            # missing counter means no tick has written it yet.
            return 0
        try:
            return int(raw)
        except (TypeError, ValueError):
            # ⛔ Present-but-unreadable again. The number returned is a
            # placeholder to keep the published shape and the templates'
            # arithmetic intact; `counters_known` is what says it is not a
            # measurement. Never render the number without checking the flag.
            counters_known = False
            return 0

    dropped_source_allowlist = _read_int("last_tick_dropped_source_allowlist")
    dropped_min_rssi = _read_int("last_tick_dropped_min_rssi")
    dropped_unparseable = _read_int("last_tick_dropped_unparseable")
    admitted = _read_int("last_tick_admitted")
    return {
        "completed_at": completed_at,
        "stamp_readable": stamp_readable,
        "counters_known": counters_known,
        "admitted": admitted,
        "dropped_source_allowlist": dropped_source_allowlist,
        "dropped_min_rssi": dropped_min_rssi,
        "dropped_unparseable": dropped_unparseable,
        "dropped_total": (
            dropped_source_allowlist + dropped_min_rssi + dropped_unparseable
        ),
    }


def clock_stamped_freshness(
    stamp: int | None,
    *,
    now_ts: int,
    stale_after_seconds: int,
    stamp_known: bool = True,
) -> dict:
    """Three-state freshness for a timestamp THIS host wrote: `{"staleness_known",
    "is_stale", "ahead_by_seconds"}`.

    ⛔ **The third state exists because a stamp AHEAD of this clock says nothing
    about whether the writer is alive, and the two-state version said it was.**
    A test of the form `now_ts - stamp > threshold` is False for every negative
    delta, so a stamp from the future scored healthy -- which reported a daemon
    dead for a year as fine. Neither "stale" nor "fresh" is asserted there,
    because neither is established: the clock may be behind now, or that stamp
    may have been written by a fast clock.

    ⭐ **One predicate, several surfaces, deliberately.** `/healthz` (HTML) once
    carried its own copy of the poll-tick arithmetic, `_check_poller` a second
    and the home page an implicit third -- which is how two surfaces came to
    disagree about whether the daemon was alive. The heartbeat card then turned
    out to have NO copy at all, which is the same bug arrived at from the other
    end. Callers differ only in `stale_after_seconds`.

    ⚠️ `stamp is None` is reported known-and-fresh, not unknown: "nothing has
    been written yet" is a state the callers' own surfaces already render
    ("waiting for first poll", "none delivered yet"), and flagging a fresh
    install would be a startup-window false positive.
    """
    if not stamp_known:
        # A stamp we could not read supports no verdict at all -- the same
        # answer as an ahead-of-clock stamp, for the same reason, and
        # deliberately NOT the never-written answer below.
        return {"staleness_known": False, "is_stale": None, "ahead_by_seconds": 0}
    if stamp is None:
        return {"staleness_known": True, "is_stale": False, "ahead_by_seconds": 0}
    ahead_by = int(stamp) - int(now_ts)
    if ahead_by > FUTURE_SKEW_SECONDS:
        return {
            "staleness_known": False,
            "is_stale": None,
            "ahead_by_seconds": ahead_by,
        }
    return {
        "staleness_known": True,
        "is_stale": (int(now_ts) - int(stamp)) > stale_after_seconds,
        "ahead_by_seconds": 0,
    }


def poll_tick_liveness(tick: dict | None, config: Config, *, now_ts: int) -> dict:
    """Is the daemon polling? ``{"staleness_known", "is_stale", "ahead_by_seconds"}``.

    ⛔ **The third state exists because a tick stamped AHEAD of this clock says
    nothing about whether the daemon is alive, and used to say it is.** The old
    test was ``now_ts - completed_at > 2 * interval``, which is False for every
    negative delta, so a tick from the future scored healthy — and the home page
    rendered it "just now" through the same collapse. Measured through the real
    surfaces (`internal/session2-harnesses/poller_liveness_probe.py`):

        CONTROL  dead 365d, clock correct     home "365d ago"   is_stale True
                 dead 365d, clock behind 400d home "just now"   is_stale False
                 dead   2d, clock behind   3d home "just now"   is_stale False

    An RTC-less Pi that boots before NTP is exactly that state, and it is this
    project's target hardware. The heartbeat is off by default, so the home
    page's relative time is the operator's only liveness signal — and the
    product's promise is that silence means nothing is out there.

    ⚠️ Neither "stale" nor "fresh" is asserted in that case, because neither is
    established: the clock may be behind now, or that tick may have been stamped
    by a fast clock. Reported the way this codebase already reports an
    undecidable liveness verdict (``watchlist_liveness``'s ``known`` flag,
    ``/healthz.json``'s ``liveness_known``) — a ``*_known`` flag beside a
    ``None``, never a False that reads as a clean bill.

    ⚠️ Never-polled keeps its documented answer (``is_stale`` False, known):
    there is no tick to be stale, and the home page carries the "waiting for
    first poll" signal. Flagging a fresh install would be a startup-window false
    positive.
    """
    return clock_stamped_freshness(
        None if tick is None else tick["completed_at"],
        now_ts=now_ts,
        stale_after_seconds=max(1, config.poll_interval_seconds) * 2,
        stamp_known=True if tick is None else tick.get("stamp_readable", True),
    )


def heartbeat_liveness(
    last_delivered_at: int | None, config: Config, *, now_ts: int
) -> dict:
    """Is the DEAD-MAN'S SWITCH still firing? Same three states as the poll tick.

    ⛔ **`/settings` reported a heartbeat that had not arrived in over a year as
    a green "on", and nothing anywhere else checked either.** The card's own
    text says the heartbeat is what distinguishes *"nothing is out there"* from
    *"the daemon died"* -- and it answered **"delivered at least once, ever"**.
    Measured on the tree before this
    (`internal/session2-harnesses/heartbeat_surface_probe.py`):

        CONTROL delivered 0d ago,   clock correct        [on]  last delivered just now
                delivered 400d ago, clock correct        [on]  last delivered 400d ago
                delivered 400d ago, clock behind 500d    [on]  last delivered 2025-07-14 UTC

    Every row green, for a switch 400 times overdue on a 24-hour interval.
    ⚠️ `undelivered` does not cover it: that counts heartbeats **composed but
    not delivered**, and a daemon that has stopped composes nothing -- so the
    count is 0 and the card falls through to the healthy branch. The failure the
    operator most needs to see is the one that leaves every counter at zero.

    ⚠️ Two intervals, not one, matching the poll tick for the same reason: a
    single missed beat is a transient delivery failure, which `undelivered`
    already reports separately. Two means the switch has stopped.
    """
    return clock_stamped_freshness(
        last_delivered_at,
        now_ts=now_ts,
        stale_after_seconds=max(1, config.heartbeat_interval_hours) * 3600 * 2,
    )


#: What an anonymous caller is told when the database check fails. Deliberately
#: says nothing about *why* -- see ``_check_db``. Kept non-empty because the
#: published shape contract promises a non-empty string on error.
_DB_ERROR_PUBLIC_DETAIL = "database unavailable; see server log"

#: What an anonymous caller is told when a health check raises. Same reasoning
#: as ``_DB_ERROR_PUBLIC_DETAIL``: ``/healthz.json`` is unauthenticated, so the
#: exception text never reaches the response -- it goes to the server log.
_CHECK_ERROR_PUBLIC_DETAIL = "check failed; see server log"


def _safe_check(name: str, fn):
    """Run one health check, converting an unexpected raise into an ERROR entry.

    ⛔ Without this, ONE corrupt row takes the whole endpoint down and the
    checks that were fine go down with it. Measured on a database carrying a
    single unparseable ``import_runs.imported_at``:

        clean db            -> HTTP 200, checks = db, poller, watchlist,
                               ruleset, clock, alerts
        one corrupt row     -> HTTP 500, body "Internal Server Error", NO JSON

    `_check_watchlist` does ``int(latest["imported_at"])`` with no guard, so the
    `ValueError` escaped the handler. The operator polling `/healthz.json` to
    find out whether the daemon is alive learned nothing at all -- not even that
    the database, the poller and the clock were healthy, which they were.

    ⚠️ This reports the failure, it does not hide it: a raising check scores
    ``status: "error"``, so the endpoint still returns 503 and a monitor still
    pages. What changes is that the other five checks survive to be read.

    ⚠️ Deliberately NOT narrowed to `ValueError`. The point is that one check
    cannot take down the report; narrowing it to the exception we happened to
    measure would leave the next one to rediscover this.
    """
    try:
        return fn()
    except Exception:
        logger.exception("health check %r raised; reporting it as an error", name)
        return {"status": "error", "detail": _CHECK_ERROR_PUBLIC_DETAIL}


def _check_db(db: Database) -> dict:
    """Return ``{"status": "ok", "detail": None}`` on a healthy connection,
    or ``{"status": "error", "detail": <generic>}`` when the connection is
    dead. The minimal ``SELECT 1`` round-trip is the fastest way to confirm
    the SQLite file is open + the connection alive without paying for any
    COUNT scans.

    ⛔ The detail is deliberately NOT the driver's message. This dict is
    returned verbatim in the ``/healthz.json`` 503, and that route has no
    authentication -- loopback binding is the only control, and
    ``ui_allow_remote: true`` removes it. SQLite error text routinely names
    the database file path, and says more on a disk or schema failure, so
    the previous ``str(exc)`` handed an unauthenticated caller a free read
    of local filesystem layout.

    The operator loses nothing: the real exception is logged at ERROR with a
    traceback, which is where someone running the daemon would look anyway.
    Pinned by ``tests/test_healthz_error_disclosure.py``, including a test
    that the logging still happens -- generalising the response must not
    become discarding the diagnosis.
    """
    try:
        db._conn.execute("SELECT 1").fetchone()
    except Exception:
        logger.exception("/healthz.json database check failed")
        return {"status": "error", "detail": _DB_ERROR_PUBLIC_DETAIL}
    return {"status": "ok", "detail": None}


def _check_poller(db: Database, config: Config, *, now_ts: int) -> dict:
    """Two daemon-liveness signals, both index-backed single-row lookups:

    - ``last_poll_at`` — from ``poller_state.last_poll_ts`` (written by the
      daemon every poll tick, regardless of whether Kismet returned any
      devices). Proxies "daemon process alive".
    - ``last_observation_at`` — ``MAX(sightings.ts)``. Proxies "Kismet is
      returning device data".

    Monitoring tools apply their own thresholds (the prompt's stability
    commitment is to the keys, not to interpretation).

    ``poll_tick`` extends the section with the five last-tick counters
    written by ``poll_once`` (admitted + three drop reasons + completed
    timestamp). ``is_stale`` is True when the most-recent tick completed
    more than 2x the configured poll_interval_seconds ago — a daemon
    that should have polled but didn't. Never-polled state reports
    is_stale=False (the home-page card carries the "waiting for first
    poll" signal; flagging stale on fresh installs would just produce
    a startup-window false positive).

    ⛔ ``is_stale`` is ``None`` — never ``False`` — when ``staleness_known``
    is False, i.e. the tick is stamped ahead of this clock and the verdict is
    undecidable. It used to be ``False`` there, which reported a daemon dead
    for a year as healthy. Both keys come from ``poll_tick_liveness``, shared
    with the home page and the HTML health page so the three cannot diverge.
    ``ahead_by_seconds`` is 0 unless that applies. Overall status is NOT flipped —
    matches the _check_watchlist ``stale`` convention; monitoring tools
    that want to page on stale poll-ticks read the boolean directly."""
    last_poll_at = db.latest_poll_ts()
    row = db._conn.execute("SELECT MAX(ts) FROM sightings").fetchone()
    last_observation_at = row[0] if row and row[0] is not None else None

    def _delta(value: int | None) -> int | None:
        # ⛔ `age_since`, not a bare subtraction. A stamp ahead of this clock
        # produced a NEGATIVE "seconds since", and every consumer test is of the
        # form `seconds_since_poll > threshold`, which a negative silently
        # satisfies -- so a daemon dead for a year read as fine to anything
        # alerting on these two fields. Measured: -34,560,000 against a control
        # of +34,560,000.
        return age_since(value, now_ts=now_ts)

    tick = _read_last_tick_stats(db)
    liveness = poll_tick_liveness(tick, config, now_ts=now_ts)
    if tick is not None:
        poll_tick = {
            "completed_at": tick["completed_at"],
            # ⚠️ `counters_known` is False when a stored counter was present but
            # unreadable. The numbers below stay ints so the published shape and
            # every consumer's arithmetic keep working, but a consumer that
            # reports them without checking this flag is reporting "0 dropped"
            # for "could not tell".
            "counters_known": tick["counters_known"],
            "admitted": tick["admitted"],
            "dropped_source_allowlist": tick["dropped_source_allowlist"],
            "dropped_min_rssi": tick["dropped_min_rssi"],
            "dropped_unparseable": tick["dropped_unparseable"],
            **liveness,
        }
    else:
        poll_tick = {
            "completed_at": None,
            # Never polled: these zeros ARE established -- nothing has run.
            "counters_known": True,
            "admitted": 0,
            "dropped_source_allowlist": 0,
            "dropped_min_rssi": 0,
            "dropped_unparseable": 0,
            **liveness,
        }

    return {
        "status": "ok",
        "last_poll_at": unix_to_iso(last_poll_at) or None,
        "seconds_since_poll": _delta(last_poll_at),
        "last_observation_at": (
            unix_to_iso(last_observation_at) or None
            if last_observation_at is not None
            else None
        ),
        "seconds_since_observation": _delta(last_observation_at),
        "poll_tick": poll_tick,
    }


def _check_watchlist(db: Database, config: Config, *, now_ts: int) -> dict:
    """Reuses ``db.watchlist_pattern_type_counts()`` (already powers
    /settings) for the per-type counts. ``total_rows`` is the sum so a
    consumer reading only the top-level number does not need to add
    them. The staleness boolean compares ``days_since_import`` against
    ``config.watchlist_staleness_warn_days`` — the same threshold the
    startup log line and the /settings card use."""
    by_pattern_type = db.watchlist_pattern_type_counts()
    total_rows = sum(by_pattern_type.values())
    latest = db.get_latest_import_run()
    if latest is not None and latest.get("imported_at") is not None:
        imported_at = stored_int(latest["imported_at"])
        last_imported_at_iso: str | None = unix_to_iso(imported_at) or None
        days_since_import: int | None = age_days_since(imported_at, now_ts=now_ts)
    else:
        last_imported_at_iso = None
        days_since_import = None
    # ⛔ Three-valued, matching every other liveness verdict in this file. The
    # old `bool(...)` collapsed BOTH "no import at all" and "the import is
    # stamped in the future" to False, i.e. to "not stale" -- a clean bill from
    # two states that establish nothing.
    staleness_known = latest is None or days_since_import is not None
    stale: bool | None = (
        None
        if days_since_import is None and latest is not None
        else bool(
            days_since_import is not None
            and days_since_import > config.watchlist_staleness_warn_days
        )
    )
    # ⭐ "Your watchlist has 12 entries" is a lie if seven of them cannot fire.
    # An entry whose pattern_type has no enabled delegating rule is stored,
    # counted and reported exactly like a working one -- so a monitoring tool
    # polling total_rows reads a healthy number over a watchlist that watches
    # nothing. Additive keys only; total_rows and by_pattern_type keep their
    # existing meaning, because a consumer alerting on them must not have the
    # numbers change under it.
    liveness = watchlist_liveness(config, by_pattern_type, db=db, now_ts=now_ts)
    suppressions = runtime_suppressions(config)
    return {
        "status": "ok",
        "total_rows": int(total_rows),
        "by_pattern_type": {k: int(v) for k, v in by_pattern_type.items()},
        "last_imported_at": last_imported_at_iso,
        "days_since_import": days_since_import,
        "stale": stale,
        "staleness_known": staleness_known,
        # ⛔ null, not 0, when liveness is unknown. A number here is a claim,
        # and `live_rows: <total>` beside `liveness_known: false` was a claim
        # nothing had established -- a consumer graphing live_rows without
        # gating on the boolean read a clean bill off an unreadable rules file.
        # JSON null forces the consumer to handle the state instead of
        # silently averaging a fabricated zero or total into a dashboard.
        "liveness_known": bool(liveness["known"]),
        "live_rows": (
            int(liveness["live_count"]) if liveness["live_count"] is not None else None
        ),
        "inert_rows": (
            int(liveness["inert_count"]) if liveness["inert_count"] is not None else None
        ),
        "snoozed_rows": (
            int(liveness["suppressed_count"])
            if liveness["suppressed_count"] is not None
            else None
        ),
        # ⚠️ inert and snoozed are INDEPENDENT FLAGS, not a partition: a type
        # that is both has its rows counted in `inert_rows` AND in
        # `snoozed_rows`. Exported as a number because the payload previously
        # left a consumer to discover the overlap by intersecting the two type
        # lists -- and the sum EQUALS total on a normal install and on a
        # snoozed live type, so a dashboard that assumes a partition validates
        # and only breaks later. The invariant this makes checkable is
        #     live_rows + inert_rows + snoozed_rows - double_counted_rows == total_rows
        # `null` when liveness is unknown, matching the three counts above:
        # a number here would be a claim nothing established.
        # ⛔ `snoozes_known` as well as `known`. The overlap is the INTERSECTION
        # of the inert set with the snoozed set, so it is unknown if EITHER
        # side is. Reporting 0 while `snoozed_rows` is null would be this
        # entry's own defect one field along: a scalar saying "unknown" beside
        # a number asserting "none".
        "double_counted_rows": (
            sum(
                int(by_pattern_type.get(pattern_type, 0))
                for pattern_type in liveness["both_types"]
            )
            if liveness["known"] and liveness.get("snoozes_known", True)
            else None
        ),
        # Whether the rule_type snooze table could be read at all. Separate
        # from `liveness_known`, which is about the RULESET: an unreadable
        # snooze table and an unreadable rules file have different fixes.
        "snoozes_known": bool(liveness.get("snoozes_known", True)),
        "both_inert_and_snoozed_pattern_types": list(liveness["both_types"]),
        "inert_pattern_types": list(liveness["inert_types"]),
        "snoozed_pattern_types": list(liveness["suppressed_types"]),
        # ⚠️ The THIRD silencing cause, and the only per-ROW one. Reported as
        # the configured lists, never as a row count: counting would scan the
        # whole watchlist (17k+ rows on an Argus install) on every poll of this
        # endpoint, with no indexed vendor filter to do it cheaply. A monitoring
        # tool can still alert on "any suppression is configured", which is the
        # question worth asking here; /watchlist answers WHICH rows.
        "override_suppressed_vendors": list(suppressions["vendors"]),
        "override_suppressed_categories": list(suppressions["categories"]),
    }


def _check_clock(db: Database, *, now_ts: int) -> dict:
    """Does this process's clock read earlier than events already recorded?

    ⭐ ``status`` stays ``"ok"`` even when the clock is behind, matching the
    ruleset check's contract: only the DB check drives the top-level status, so
    a monitoring tool alerting on ``status`` does not start paging because a
    host drifted. The condition is reported in its own boolean instead --
    ``behind: true`` is the thing to alert on, and it is unambiguous.
    """
    state = clock_behind_recorded_history(db, now_ts)
    return {
        "status": "ok",
        "behind": bool(state["behind"]),
        "behind_by_seconds": int(state["behind_by"]),
        "newest_recorded_at": (
            unix_to_iso(state["newest_ts"]) if state["newest_ts"] is not None else None
        ),
        "blocks_duration_writes": bool(state["behind"]),
    }


def _check_heartbeat(db: Database, config: Config, *, now_ts: int) -> dict:
    """Is the dead-man's switch still firing? The MACHINE-readable half.

    ⛔ **This endpoint said nothing at all about the heartbeat until now** — six
    checks, the word appeared nowhere, and ``status: "ok"`` was returned beside a
    switch 400 intervals overdue. That was not a false claim (silence is not a
    lie), which is why it stayed a decision rather than a bug; it is added
    deliberately, because ``poller.poll_tick`` and the heartbeat fail
    **independently**: the daemon can be polling perfectly while ntfy is broken,
    and a tool watching ``poll_tick.is_stale`` has no way to see the second.

    Shares ``heartbeat_liveness`` with ``/settings``, so the page and the JSON
    cannot drift — the same reason ``poll_tick`` shares its predicate with the
    home page and the HTML health page.

    ⭐ ``status`` stays ``"ok"`` regardless, matching the clock and ruleset
    checks: only the DB check drives top-level status, so a stopped heartbeat
    does not start paging whoever alerts on ``status``. The condition is in its
    own fields, which are unambiguous.

    ⚠️ ``is_stale`` is ``None`` — never a reassuring ``False`` — in the two cases
    where no verdict is established:

        heartbeat disabled      there is no switch to be stale, and "not stale"
                                would read as "the dead-man's switch is fine"
                                about an install that does not have one
        delivery stamped ahead  the clock disagrees; see clock_stamped_freshness

    ``undelivered`` counts heartbeats COMPOSED but not delivered — a channel
    failure whose fix (topic/auth) differs from a stopped daemon's. ⛔ Reported
    beside the staleness verdict rather than folded into it, because a daemon
    that has stopped composes nothing and leaves that counter at zero.
    """
    enabled = bool(config.heartbeat_enabled)
    last_delivered = db.latest_delivered_heartbeat_ts()
    if not enabled or last_delivered is None:
        # ⛔ THREE states collapse here, and none of them is "fresh".
        #
        # `clock_stamped_freshness(None, ...)` deliberately answers
        # known-and-not-stale for a missing stamp, because for the POLL TICK
        # that is a fresh install and its surface says "waiting for first
        # poll". It is the wrong answer here: a heartbeat that is ENABLED and
        # has never once been delivered is the "armed, unproven" state, which
        # /settings deliberately stopped rendering green — the page cannot tell
        # "enabled five minutes ago" from "enabled months ago and never fired",
        # and neither can this.
        #
        # ⚠️ Reporting `is_stale: false` here would have made this endpoint
        # disagree with the page it was added to complement, on the exact state
        # the page warns about. Caught by driving every state rather than the
        # headline one.
        liveness = {"staleness_known": False, "is_stale": None, "ahead_by_seconds": 0}
    else:
        liveness = heartbeat_liveness(last_delivered, config, now_ts=now_ts)
    return {
        "status": "ok",
        "enabled": enabled,
        "interval_hours": int(config.heartbeat_interval_hours),
        "last_delivered_at": (
            unix_to_iso(last_delivered) if last_delivered is not None else None
        ),
        # Shares `age_since`, so a delivery stamped ahead of this clock reports
        # None rather than a negative that every `> threshold` silently passes.
        "seconds_since_delivery": age_since(last_delivered, now_ts=now_ts),
        "undelivered": int(db.count_undelivered_heartbeats()),
        "is_stale": liveness["is_stale"],
        "staleness_known": liveness["staleness_known"],
    }


def _check_ruleset(config: Config) -> dict:
    """Loads ``rules.yaml`` on each call (cheap — the file is small and
    operators rarely poll /healthz.json at sub-second cadence). When the
    loader raises (missing file, parse error, validation error), the
    check stays ``status: ok`` per the prompt's contract — only the DB
    check controls top-level status.

    ⛔ **``rules_loaded`` exists because the documented discriminator did not
    discriminate.** This docstring used to say that "a non-zero
    ``rules_path_configured`` paired with zero ``active_rules`` is the canonical
    'wired but broken' pattern". Measured, that is false: a legitimately EMPTY
    rules file produces byte-identical output to an unparseable one —

        valid file, 1 rule   {'active_rules': 1, 'rules_path_configured': True}
        rules: []            {'active_rules': 0, 'rules_path_configured': True}
        unparseable yaml     {'active_rules': 0, 'rules_path_configured': True}

    — so a consumer following the instruction pages on an empty ruleset and
    stays silent about a corrupt one. ⚠️ In this product a ruleset that failed
    to load means **no alert can fire at all**, which is the silence-means-safe
    direction.

    ⭐ The information already existed: the home page computes
    ``rules_state`` as ``"unset" | "ok" | "unreadable"`` from the same load. The
    HUMAN surface distinguished the two states and the MACHINE surface did not.
    ``rules_loaded`` publishes it, matching the ``*_known`` convention this file
    already uses for ``liveness_known`` / ``snoozes_known`` / ``staleness_known``:
    a flag beside the number saying whether the number means anything.

    ``rules_loaded`` is False when the path is unset (nothing to load) or when
    the load raised; True when the file parsed, including when it parsed to zero
    rules.
    """
    if not config.rules_path:
        return {
            "status": "ok",
            "active_rules": 0,
            "rules_path_configured": False,
            "rules_loaded": False,
        }
    loaded = True
    try:
        ruleset = rules_mod.load_ruleset(config.rules_path)
        active = sum(1 for r in ruleset.rules if r.enabled)
    except Exception as exc:  # noqa: BLE001 — broken-but-configured is observable
        logger.warning(
            "/healthz.json: rules_path=%r failed to load (%s); "
            "reporting active_rules=0 with rules_loaded=false",
            config.rules_path,
            exc,
        )
        active = 0
        loaded = False
    return {
        "status": "ok",
        "active_rules": int(active),
        "rules_path_configured": True,
        "rules_loaded": loaded,
    }


def _check_alerts(db: Database, *, now_ts: int) -> dict:
    """``total`` is a full scan of ``alerts`` (small table; the row count
    is bounded by operator-driven alert traffic, not by sightings).
    ``last_hour`` uses ``idx_alerts_ts`` for an index-backed range
    count."""
    total_row = db._conn.execute("SELECT COUNT(*) FROM alerts").fetchone()
    last_hour_row = db._conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE ts >= ?",
        (now_ts - 3600,),
    ).fetchone()
    return {
        "status": "ok",
        "total": int(total_row[0]),
        "last_hour": int(last_hour_row[0]),
    }


def create_app(
    config: Config, db: Database, *, config_path: str | Path | None = None
) -> FastAPI:
    """App factory. Takes a live Config and Database. Used by both the production
    server entry point and the test client. Does NOT open the DB itself — that's the
    caller's responsibility, so tests can inject an in-memory or tmp_path DB.

    ``config_path`` is the file this ``Config`` was loaded FROM. ``/settings``
    showed ``paths.default_config_path("user")`` under the heading "Read-only
    view of the active configuration", which is a convention rather than a fact
    about this process: a system-scope install, or any `lynceus-ui --config
    <elsewhere>`, saw a path it had not loaded and could edit it all day. The
    entry point requires ``--config``, so in production this is always known;
    when it is not, the page says the location is the default rather than
    calling it the active one.
    """

    app = FastAPI(
        title="lynceus",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    app.state.db = db
    app.state.config = config
    # The path `config` was read from, or None. Read at render time from
    # app.state for the same reason the file-name globals below are callables.
    app.state.config_path = str(config_path) if config_path else None
    app.state.templates = Jinja2Templates(directory=str(_resolve_templates_dir()))
    app.state.templates.env.globals["csrf_token"] = lambda request: get_csrf_token(request)
    # AGPL-3.0 §13: anyone interacting with this over a network must be able to
    # obtain the corresponding source of the version they are talking to. These
    # are env globals rather than per-route context deliberately — the site
    # header's {{ version }} comes from each route's context dict, so a route
    # that forgets the key renders an empty string. That is a cosmetic bug for a
    # version number and a licence-compliance one for the source offer, so the
    # footer must not be able to fail the same way.
    app.state.templates.env.globals["lynceus_version"] = __version__
    app.state.templates.env.globals["lynceus_source_url"] = SOURCE_URL
    app.state.templates.env.globals["lynceus_license"] = "AGPL-3.0-or-later"
    # ⛔ The FILE the daemon actually loads, for every surface that names one.
    #
    # `rules_path` and `allowlist_path` are free-form config: an operator can
    # point them at any filename, and `derive_ui_path` carries the stem AND the
    # extension across, so the UI sibling of `site-devices.yml` is
    # `site-devices_ui.yml`. Twelve renderings across five pages hard-coded
    # `rules.yaml` / `allowlist.yaml` / `allowlist_ui.yaml` instead, including
    # four REMEDIES -- "edit that file directly to remove", "Edit rules.yaml on
    # disk and restart". Measured at cca7c5c against
    # `allowlist_path=site-devices.yml` + `rules_path=site-rules.yml`: every one
    # of those sentences named a file that does not exist on that install, and
    # `/allowlist` printed the true path in its empty state while naming the
    # wrong one in its counts, on the same page.
    #
    # ⚠️ Callables, not values, and env globals rather than per-route context,
    # for the two reasons already written into the block below: a route that
    # forgets a context key renders an EMPTY string -- which for a remedy is
    # worse than a wrong filename -- and reading `app.state.config` at render
    # time cannot go stale if the config object is ever replaced.
    #
    # `None` when the path is unset. Two sites can render with it unset
    # (`/rules`' footer, and the OUI never-matches note on a watchlist entry);
    # both branch on it explicitly, because "no rules file is configured" is a
    # different sentence, not a blank.
    def _rules_file() -> str | None:
        return app.state.config.rules_path or None

    def _allowlist_file() -> str | None:
        return app.state.config.allowlist_path or None

    def _allowlist_ui_file() -> str | None:
        primary = app.state.config.allowlist_path
        return str(derive_ui_path(Path(primary))) if primary else None

    def _config_file() -> str | None:
        """The lynceus.yaml this process loaded, or None when it was not told.

        ⛔ Added because a cold read of the fix caught it applying in one
        direction only: the /settings "config path" ROW was corrected to name
        the loaded file, and three REMEDIES went on saying "set X in
        `lynceus.yaml`" -- which for `lynceus-ui --config /etc/lynceus/site.yml`
        names a file the process never reads. Exactly the class this change set
        exists to remove, reintroduced by two sentences it added itself.
        """
        return app.state.config_path or None

    app.state.templates.env.globals["config_file"] = _config_file
    app.state.templates.env.globals["rules_file"] = _rules_file
    app.state.templates.env.globals["allowlist_file"] = _allowlist_file
    app.state.templates.env.globals["allowlist_ui_file"] = _allowlist_ui_file
    app.state.templates.env.filters["unix_to_iso"] = unix_to_iso
    app.state.templates.env.filters["unix_to_utc_human"] = unix_to_utc_human
    app.state.templates.env.filters["device_label"] = _device_label
    app.state.templates.env.filters["probe_ssids_list"] = _probe_ssids_list
    app.state.templates.env.filters["relative_time"] = relative_time

    app.mount(
        "/static",
        StaticFiles(directory=str(_resolve_static_dir())),
        name="static",
    )

    cookie_secure = bool(config.ui_allow_remote)
    app.add_middleware(CSRFMiddleware, cookie_secure=cookie_secure)
    # ⭐ Added AFTER CSRFMiddleware, which means it runs OUTSIDE it: Starlette
    # applies middleware in reverse registration order, so the CSP wrapper sees
    # every response including the 403 CSRFMiddleware itself returns. Register
    # it first and a rejected request would come back with no policy at all.
    # Pinned by test_csp_header_is_present_even_on_a_csrf_rejection.
    app.add_middleware(CSPMiddleware)

    @app.exception_handler(HTTPException)
    async def _http_exception_handler(request: Request, exc: HTTPException):
        """Render HTTPException as a browser-friendly HTML page.

        Pre-fix UX: a hand-edited URL with an invalid filter value
        landed the operator on a raw JSON {"detail": "..."} page with
        no recovery path. Now they get a same-themed error page with
        a back link. Programmatic callers that explicitly request JSON
        (Accept header excluding text/html) still get the original
        FastAPI JSON shape so we don't break HTML-API parity.

        The /devices/{mac:path} route renders not_found.html via
        TemplateResponse directly (no raise), so this handler does
        NOT intercept it -- existing 404 UX is preserved."""
        accept = (request.headers.get("accept") or "").lower()
        wants_html = "text/html" in accept or accept in ("", "*/*")
        if not wants_html:
            return JSONResponse(
                status_code=exc.status_code,
                content={"detail": exc.detail},
                headers=getattr(exc, "headers", None) or None,
            )
        back_href = _safe_redirect_target(request, "/")
        return app.state.templates.TemplateResponse(
            request=request,
            name="error.html",
            status_code=exc.status_code,
            context={
                "version": __version__,
                "active": "",
                "status_code": exc.status_code,
                "detail": exc.detail,
                "back_href": back_href,
            },
        )

    @app.get("/healthz", response_class=HTMLResponse)
    async def healthz(request: Request):
        health = db.healthcheck()
        now_ts = int(time.time())
        tick = _read_last_tick_stats(db)
        # ⚠️ This handler used to carry its own copy of the staleness test --
        # a third one, beside `_check_poller`'s and the home page's implicit
        # "relative_time says it is recent". Three copies of one predicate is
        # how two surfaces end up disagreeing about whether the daemon is
        # alive; there is one now.
        tick_liveness = poll_tick_liveness(tick, config, now_ts=now_ts)
        return app.state.templates.TemplateResponse(
            request=request,
            name="healthz.html",
            context={
                "health": health,
                "version": __version__,
                "last_tick": tick,
                "tick_liveness": tick_liveness,
                "now_ts": now_ts,
            },
        )

    @app.get("/healthz.json")
    async def healthz_json() -> JSONResponse:
        """Machine-readable health endpoint for monitoring integration.

        Returns HTTP 200 + ``status: "ok"`` when the DB is reachable;
        HTTP 503 + ``status: "error"`` when it is not. Per-check sub-
        sections under ``checks`` are stable: existing keys never
        disappear in future releases (additions only). See
        ``_check_db`` / ``_check_poller`` / ``_check_watchlist`` /
        ``_check_ruleset`` / ``_check_alerts`` for the per-check shape
        contracts.

        Read-only and unauthenticated by design — /healthz.json is the
        standard monitoring-facing surface. Sibling to the existing
        HTML /healthz page; both are kept so the nav link, smoke
        runbook, and quickstart UI-readiness probe stay unchanged.
        """
        db_check = _check_db(db)
        if db_check["status"] == "error":
            return JSONResponse(
                status_code=503,
                content={
                    "status": "error",
                    "version": __version__,
                    "checks": {"db": db_check},
                },
            )
        now_ts = int(time.time())
        # ⛔ Each check is isolated: one raising check must not delete the
        # other five from the report. See ``_safe_check``.
        checks = {
            "db": db_check,
            "poller": _safe_check(
                "poller", lambda: _check_poller(db, config, now_ts=now_ts)
            ),
            "watchlist": _safe_check(
                "watchlist", lambda: _check_watchlist(db, config, now_ts=now_ts)
            ),
            "ruleset": _safe_check("ruleset", lambda: _check_ruleset(config)),
            "clock": _safe_check("clock", lambda: _check_clock(db, now_ts=now_ts)),
            "heartbeat": _safe_check(
                "heartbeat", lambda: _check_heartbeat(db, config, now_ts=now_ts)
            ),
            "alerts": _safe_check("alerts", lambda: _check_alerts(db, now_ts=now_ts)),
        }
        overall = (
            "ok" if all(c["status"] == "ok" for c in checks.values()) else "error"
        )
        return JSONResponse(
            status_code=200 if overall == "ok" else 503,
            content={
                "status": overall,
                "version": __version__,
                "checks": checks,
            },
        )

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request):
        now = time.time()
        now_int = int(now)
        kismet_status = _get_kismet_status(app, now)
        recent_alerts = db.list_alerts(limit=10, acknowledged=False)
        _enrich_alerts_with_devices(db, recent_alerts)
        health = db.healthcheck()
        device_seen = db.device_seen_counts(now_ts=now_int)
        sev_30d = db.alert_severity_counts(since_ts=now_int - 30 * 86400)
        watchlist_freshness = _watchlist_freshness_summary(
            db,
            app.state.config.watchlist_staleness_warn_days,
            now_ts=now_int,
        )

        # The rules tile needs a count of enabled rules, which means reading the
        # ruleset file. Same try/except shape as the /healthz panel above: a
        # rules file that does not parse must not take the home page down with
        # it.
        #
        # ⚠️ Three outcomes, not two, and collapsing any pair of them misleads:
        #   int   -> that many enabled rules
        #   None + rules_state "unset"      -> no rules_path configured. Normal
        #                                      on a fresh install; NOT alarming.
        #   None + rules_state "unreadable" -> a path is set and it did not
        #                                      load. That IS alarming, because
        #                                      the operator believes rules are
        #                                      running and none are.
        # Rendering "unset" as "unreadable" cries wolf on every default config;
        # rendering "unreadable" as 0 hides a broken detection pipeline.
        enabled_rules: int | None = None
        rules_state = "unset"
        if app.state.config.rules_path:
            try:
                enabled_rules = sum(
                    1
                    for r in rules_mod.load_ruleset(app.state.config.rules_path).rules
                    if r.enabled
                )
                rules_state = "ok"
            except Exception:
                enabled_rules = None
                rules_state = "unreadable"

        tiles = {
            "unacked": health.get("unacked_alert_count", 0),
            "high_30d": sev_30d.get("high", 0),
            "devices": health.get("device_count", 0),
            "devices_24h": device_seen.get("day", 0),
            "watchful": db.count_watchful_recurrence(),
            "probe_devices": db.count_probe_devices(),
            "watchlist_records": watchlist_freshness.get("record_count") or 0,
            "rules": enabled_rules,
            "rules_state": rules_state,
        }
        # Hoisted: the context needs the tick twice, once as the counters and
        # once to decide whether its timestamp can be read as liveness at all.
        last_tick = _read_last_tick_stats(db)
        return app.state.templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "version": __version__,
                "active": "home",
                # ⚠️ These four are the hoisted locals, NOT fresh calls. The
                # tiles above need the same figures, and re-querying here would
                # double this page's query count for identical answers.
                "health": health,
                "sev_30d": sev_30d,
                "device_seen": device_seen,
                "watchlist_freshness": watchlist_freshness,
                "sev_24h": db.alert_severity_counts(since_ts=now_int - 86400),
                "sev_7d": db.alert_severity_counts(since_ts=now_int - 7 * 86400),
                "per_day_sev": db.alerts_per_day_by_severity(days=30, now_ts=now_int),
                "recent_alerts": recent_alerts,
                "recent_devices": db.list_devices(limit=25),
                "last_poll": db.latest_poll_ts(),
                "last_tick": last_tick,
                "tick_liveness": poll_tick_liveness(
                    last_tick, config, now_ts=now_int
                ),
                "tiles": tiles,
                "now_ts": now_int,
                "kismet_status": kismet_status,
            },
        )

    @app.get("/alerts", response_class=HTMLResponse)
    def alerts_list(
        request: Request,
        severity: str | None = Query(default=None),
        acknowledged: str | None = Query(default=None),
        page: str | None = Query(default=None),
        page_size: str | None = Query(default=None),
        since: str | None = Query(default=None),
        until: str | None = Query(default=None),
        search: str | None = Query(default=None),
        rule_type: str | None = Query(default=None),
        q: str | None = Query(default=None),
        window: str | None = Query(default=None),
        has_note: str | None = Query(default=None),
        has_action: str | None = Query(default=None),
    ):
        # severity / acknowledged / since / until / search are the
        # pre-rc5 filters and stay byte-identical -- bookmarked URLs
        # keep working. rule_type / q / window are new in rc5
        # alongside the unified-pagination upgrade.
        if severity is not None and severity not in ("low", "med", "high"):
            raise HTTPException(status_code=400, detail="invalid severity")
        ack_bool = _parse_bool_str(acknowledged, "acknowledged")
        if search is not None and len(search) > 100:
            raise HTTPException(status_code=400, detail="search must be <= 100 chars")
        if q is not None and len(q) > 100:
            raise HTTPException(status_code=400, detail="q must be <= 100 chars")
        since_ts = _parse_date_or_datetime_to_ts(since, end_of_day=False, name="since")
        until_ts = _parse_date_or_datetime_to_ts(until, end_of_day=True, name="until")
        search_clean = search if search else None
        q_clean = q if q else None

        # rule_type: invalid value silently falls back to "all" (the
        # operator probably hit a stale URL after a rules.RuleType
        # extension). Treats "" and "all" identically.
        if rule_type is not None and rule_type not in _ALERTS_RULE_TYPES:
            rule_type = None
        rule_type_for_db = rule_type or None

        # window: invalid value silently falls back to "all". Treats
        # "" identically. Resolved server-side to anchor "what does
        # this URL show" to the operator's open-time clock.
        if window is not None and window not in _ALERTS_WINDOW_SECONDS:
            window = None
        window_seconds = _ALERTS_WINDOW_SECONDS.get(window) if window else None
        now_ts = int(time.time())
        window_since_ts = (now_ts - window_seconds) if window_seconds else None

        # has_note: clamp invalid / "all" to the no-op None which the
        # DB-layer filter helper interprets as "no clause." A stale
        # bookmark with has_note=foo lands on the unfiltered page,
        # not 400 -- same clamp posture as rule_type / window.
        if has_note is not None and has_note not in _ALERTS_HAS_NOTE_VALUES:
            has_note = None
        has_note_for_db = has_note if has_note in ("with_note", "without_note") else None

        # has_action: same clamp posture. The YAML-side signals
        # (snooze + permanent allowlist) are loaded lazily ONLY when
        # has_action is engaged -- the default /alerts request stays
        # YAML-cost-free. Watchful is a SQL EXISTS subquery handled
        # by the db layer.
        if has_action is not None and has_action not in _ALERTS_HAS_ACTION_VALUES:
            has_action = None
        has_action_for_db = (
            has_action if has_action in ("with_action", "without_action") else None
        )
        if has_action_for_db is not None:
            (
                actioned_macs,
                actioned_oui_prefixes,
                actioned_mac_ranges,
            ) = _load_actioned_patterns(app.state.config, now_ts)
        else:
            actioned_macs, actioned_oui_prefixes, actioned_mac_ranges = (), (), ()

        # If both absolute since and relative window are provided,
        # combine them by taking the tighter lower bound. The DB
        # gets a single since_ts -- both intent paths roll into the
        # same a.ts >= ? predicate.
        effective_since_ts = since_ts
        if window_since_ts is not None:
            if effective_since_ts is None:
                effective_since_ts = window_since_ts
            else:
                effective_since_ts = max(effective_since_ts, window_since_ts)

        # Parse + clamp pagination via the shared helper. Invalid
        # per_page -> default; invalid page -> 1 (final clamp
        # against total_pages happens once we know the total).
        requested_page, per_page = parse_pagination(
            page,
            page_size,
            allowed_per_page=_ALERTS_PER_PAGE_ALLOWED,
            default_per_page=_ALERTS_PER_PAGE_DEFAULT,
        )

        total_count = db.count_alerts(
            severity=severity,
            acknowledged=ack_bool,
            since_ts=effective_since_ts,
            until_ts=until_ts,
            search=search_clean,
            rule_type=rule_type_for_db,
            q=q_clean,
            has_note=has_note_for_db,
            has_action=has_action_for_db,
            actioned_macs=actioned_macs,
            actioned_oui_prefixes=actioned_oui_prefixes,
            actioned_mac_ranges=actioned_mac_ranges,
        )

        pagination = build_pagination(requested_page, per_page, total_count)

        alerts = db.list_alerts_with_match(
            {
                "limit": pagination.per_page,
                "offset": pagination.offset,
                "severity": severity,
                "acknowledged": ack_bool,
                "since_ts": effective_since_ts,
                "until_ts": until_ts,
                "search": search_clean,
                "rule_type": rule_type_for_db,
                "q": q_clean,
                "has_note": has_note_for_db,
                "has_action": has_action_for_db,
                "actioned_macs": actioned_macs,
                "actioned_oui_prefixes": actioned_oui_prefixes,
                "actioned_mac_ranges": actioned_mac_ranges,
            }
        )
        _enrich_alerts_with_devices(db, alerts)
        filters_active = bool(
            severity
            or ack_bool is not None
            or since
            or until
            or (search and search != "")
            or rule_type
            or (q and q != "")
            or window
            or has_note_for_db
            or has_action_for_db
        )
        return app.state.templates.TemplateResponse(
            request=request,
            name="alerts_list.html",
            context={
                "version": __version__,
                "active": "alerts",
                "alerts": alerts,
                "total_count": total_count,
                "page": pagination.page,
                "page_size": pagination.per_page,
                "total_pages": pagination.total_pages,
                "pagination": pagination,
                "severity": severity,
                "acknowledged": ack_bool,
                "since": since or "",
                "until": until or "",
                "search": search or "",
                "rule_type": rule_type or "",
                "q": q or "",
                "window": window or "",
                # The instant this page was rendered. Carried into the
                # ack-all form so a bulk write acts on what was SHOWN,
                # not on whatever the relative window matches later.
                "rendered_at": now_ts,
                "has_note": has_note or "all",
                "has_action": has_action or "all",
                "rule_types": _ALERTS_RULE_TYPES,
                "per_page_options": _ALERTS_PER_PAGE_ALLOWED,
                "window_options": tuple(_ALERTS_WINDOW_SECONDS.keys()),
                "has_note_options": _ALERTS_HAS_NOTE_VALUES,
                "has_action_options": _ALERTS_HAS_ACTION_VALUES,
                "filters_active": filters_active,
            },
        )

    @app.get("/alerts.csv")
    def alerts_csv_export(
        request: Request,
        severity: str | None = Query(default=None),
        acknowledged: str | None = Query(default=None),
        since: str | None = Query(default=None),
        until: str | None = Query(default=None),
        search: str | None = Query(default=None),
        rule_type: str | None = Query(default=None),
        q: str | None = Query(default=None),
        window: str | None = Query(default=None),
        has_note: str | None = Query(default=None),
        has_action: str | None = Query(default=None),
    ):
        # Streaming CSV export of the currently-filtered /alerts result
        # set. Filter parsing intentionally mirrors the alerts_list
        # handler byte-for-byte (clamp posture + invalid-value
        # silent-fallback) so the same query string the operator
        # sees on the list page produces an identically-filtered
        # download. Pagination is bypassed -- the export covers
        # every matching row, not just the visible page.
        #
        # action_taken column is computed per row from the
        # actioned_macs / actioned_oui_prefixes / active watchful set;
        # the allowlist YAML files are loaded unconditionally here
        # (the operator opted into the YAML cost by clicking the
        # download link), unlike the list route which only loads
        # them when has_action is engaged.
        if severity is not None and severity not in ("low", "med", "high"):
            raise HTTPException(status_code=400, detail="invalid severity")
        ack_bool = _parse_bool_str(acknowledged, "acknowledged")
        if search is not None and len(search) > 100:
            raise HTTPException(status_code=400, detail="search must be <= 100 chars")
        if q is not None and len(q) > 100:
            raise HTTPException(status_code=400, detail="q must be <= 100 chars")
        since_ts = _parse_date_or_datetime_to_ts(since, end_of_day=False, name="since")
        until_ts = _parse_date_or_datetime_to_ts(until, end_of_day=True, name="until")
        search_clean = search if search else None
        q_clean = q if q else None
        if rule_type is not None and rule_type not in _ALERTS_RULE_TYPES:
            rule_type = None
        rule_type_for_db = rule_type or None
        if window is not None and window not in _ALERTS_WINDOW_SECONDS:
            window = None
        window_seconds = _ALERTS_WINDOW_SECONDS.get(window) if window else None
        now_ts = int(time.time())
        window_since_ts = (now_ts - window_seconds) if window_seconds else None
        if has_note is not None and has_note not in _ALERTS_HAS_NOTE_VALUES:
            has_note = None
        has_note_for_db = has_note if has_note in ("with_note", "without_note") else None
        if has_action is not None and has_action not in _ALERTS_HAS_ACTION_VALUES:
            has_action = None
        has_action_for_db = (
            has_action if has_action in ("with_action", "without_action") else None
        )
        effective_since_ts = since_ts
        if window_since_ts is not None:
            if effective_since_ts is None:
                effective_since_ts = window_since_ts
            else:
                effective_since_ts = max(effective_since_ts, window_since_ts)

        (
            actioned_macs,
            actioned_oui_prefixes,
            actioned_mac_ranges,
        ) = _load_actioned_patterns(app.state.config, now_ts)
        actioned_macs_set = frozenset(actioned_macs)
        watchful_macs = db.active_watchful_macs()

        filters = {
            "severity": severity,
            "acknowledged": ack_bool,
            "since_ts": effective_since_ts,
            "until_ts": until_ts,
            "search": search_clean,
            "rule_type": rule_type_for_db,
            "q": q_clean,
            "has_note": has_note_for_db,
            "has_action": has_action_for_db,
            "actioned_macs": actioned_macs,
            "actioned_oui_prefixes": actioned_oui_prefixes,
            "actioned_mac_ranges": actioned_mac_ranges,
        }

        header = [
            "id",
            "ts_iso_utc",
            "ts_unix",
            "severity",
            "rule_name",
            "rule_type",
            "mac",
            "message",
            "acknowledged",
            "note",
            "note_updated_at_iso_utc",
            "matched_watchlist_id",
            "matched_pattern",
            "matched_pattern_type",
            "matched_vendor",
            "matched_confidence",
            "matched_device_category",
            "matched_argus_record_id",
            "device_type",
            "oui_vendor",
            "action_taken",
        ]

        def _mac_is_actioned(mac: str | None) -> bool:
            if not mac:
                return False
            if mac in actioned_macs_set:
                return True
            if mac in watchful_macs:
                return True
            for oui in actioned_oui_prefixes:
                if mac.startswith(f"{oui}:"):
                    return True
            for pattern in actioned_mac_ranges:
                if mac_in_mac_range(mac, pattern):
                    return True
            return False

        def _iso_utc(ts) -> str:
            if ts is None:
                return ""
            return _dt.datetime.fromtimestamp(int(ts), tz=_dt.UTC).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )

        def _row_generator():
            buf = io.StringIO()
            writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
            writer.writerow(header)
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate(0)
            for alert in db.iter_alerts_with_match(filters):
                mac = alert.get("mac")
                # Device join per row -- get_device is a single primary-
                # key lookup, so this stays cheap even at high row counts.
                device = None
                if mac:
                    try:
                        device = db.get_device(mac)
                    except Exception:
                        device = None
                wl = alert.get("watchlist") or {}
                meta = alert.get("watchlist_metadata") or {}
                writer.writerow(
                    [
                        alert["id"],
                        _iso_utc(alert.get("ts")),
                        alert.get("ts") if alert.get("ts") is not None else "",
                        alert.get("severity") or "",
                        alert.get("rule_name") or "",
                        alert.get("rule_type") or "",
                        mac or "",
                        alert.get("message") or "",
                        "true" if alert.get("acknowledged") else "false",
                        alert.get("note") or "",
                        _iso_utc(alert.get("note_updated_at")),
                        alert.get("matched_watchlist_id") or "",
                        wl.get("pattern") or "",
                        wl.get("pattern_type") or "",
                        meta.get("vendor") or "",
                        meta.get("confidence") if meta.get("confidence") is not None else "",
                        meta.get("device_category") or "",
                        meta.get("argus_record_id") or "",
                        (device or {}).get("device_type") or "",
                        (device or {}).get("oui_vendor") or "",
                        "true" if _mac_is_actioned(mac) else "false",
                    ]
                )
                yield buf.getvalue()
                buf.seek(0)
                buf.truncate(0)

        ts_now = _dt.datetime.fromtimestamp(now_ts, tz=_dt.UTC).strftime(
            "%Y%m%dT%H%M%SZ"
        )
        filename = f"alerts-{ts_now}.csv"
        return StreamingResponse(
            _row_generator(),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.get("/alerts/{alert_id}", response_class=HTMLResponse)
    def alert_detail(
        request: Request,
        alert_id: RowId,
        success: str | None = Query(default=None),
    ):
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
        now_ts = int(time.time())
        (
            allowlist_match,
            allowlist_match_removable,
            allowlist_configured,
            allowlist_match_source,
        ) = _resolve_allowlist_match(app.state.config, alert.get("mac"), now_ts)
        snooze_hours_remaining: int | None = None
        if (
            allowlist_match is not None
            and allowlist_match.expires_at is not None
        ):
            # Round up so a partial hour shows >= 1 — operators reading
            # "0 hours remaining" while a snooze is still active would be
            # actively misleading. Past-expiry entries never reach here
            # because ``_match_mac_in_entries`` filters them out first.
            seconds_left = max(0, allowlist_match.expires_at - now_ts)
            snooze_hours_remaining = max(1, (seconds_left + 3599) // 3600)
        # Whitelist the success-flash tokens that the detail page
        # recognizes. Unknown / spoofed values from a hand-crafted
        # URL render as no toast at all rather than echoing arbitrary
        # query-string content into the page.
        note_flash: str | None = None
        if success in ("note_saved", "note_cleared"):
            note_flash = success
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
                "allowlist_match": allowlist_match,
                "allowlist_match_removable": allowlist_match_removable,
                "allowlist_match_source": allowlist_match_source,
                "allowlist_configured": allowlist_configured,
                "snooze_hours_remaining": snooze_hours_remaining,
                "snooze_duration_options": list(_SNOOZE_DURATIONS.keys()),
                "snooze_default_duration": _SNOOZE_DEFAULT_KEY,
                "note_flash": note_flash,
                "note_max_chars": db._ALERT_NOTE_MAX_CHARS,
                "now_ts": now_ts,
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
            # ⛔ The SAME bound `RowId` puts on path params, reached through a
            # FORM instead. `RowId` is a `Path(...)` annotation and cannot apply
            # here, so the check is explicit -- and its absence was NOT
            # hypothetical: `alert_ids=2**63` returned 500 out of
            # `db.bulk_acknowledge_alerts` while `2**63 - 1` returned 200.
            if aid > SQLITE_MAX_ROWID:
                raise HTTPException(
                    status_code=400, detail="alert_id is out of range"
                )
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
        rule_type: str | None = Form(default=None),
        q: str | None = Form(default=None),
        window: str | None = Form(default=None),
        has_note: str | None = Form(default=None),
        has_action: str | None = Form(default=None),
        note: str | None = Form(default=None),
        rendered_at: str | None = Form(default=None),
    ):
        # The filter set MUST mirror /alerts GET exactly. If a filter
        # is on the page but missing here, "ack all matching" acks
        # alerts the operator can't see -- the worst class of bug
        # for an operation that writes silently in bulk.
        sev = severity if severity else None
        if sev is not None and sev not in ("low", "med", "high"):
            raise HTTPException(status_code=400, detail="invalid severity")
        ack_bool = _parse_bool_str(acknowledged if acknowledged else None, "acknowledged")
        if search is not None and len(search) > 100:
            raise HTTPException(status_code=400, detail="search must be <= 100 chars")
        if q is not None and len(q) > 100:
            raise HTTPException(status_code=400, detail="q must be <= 100 chars")
        since_ts = _parse_date_or_datetime_to_ts(since, end_of_day=False, name="since")
        until_ts = _parse_date_or_datetime_to_ts(until, end_of_day=True, name="until")
        search_clean = search if search else None
        q_clean = q if q else None
        note = _normalize_optional_note(note)

        # ⛔ Bound the write to what the operator was actually SHOWN.
        #
        # This route recomputes a RELATIVE window (`window=24h` -> `now - 24h`)
        # at POST time, so an alert arriving between the page rendering and the
        # operator clicking falls inside it and is acknowledged unseen. Measured
        # with NO clock jump at all: three alerts on the page, a fourth
        # HIGH-severity alert arrives, the operator clicks "acknowledge all 3
        # matching" -- and the fourth is acknowledged too. It then drops out of
        # the default unacknowledged views, and there is no bulk undo.
        #
        # ⭐ This function's own comments call an unmirrored filter "the worst
        # class of bug for a bulk-write surface", and every filter IS carefully
        # mirrored. The time window is the one filter that MOVES ON ITS OWN, so
        # mirroring the parameter was never enough: the GET's instant has to be
        # carried across too.
        #
        # ⚠️ A clock STEP between GET and POST is the same bug with a rarer
        # trigger. This closes both.
        effective_until_ts = until_ts
        if rendered_at is not None:
            try:
                rendered_ts: int | None = int(rendered_at)
            except (TypeError, ValueError):
                rendered_ts = None
            # ⛔ Upper bound as well as the existing `> 0`. This value is
            # hand-parsed from a form string and bound straight into
            # `db.count_alerts(until_ts=...)`, so an unbounded int 500s the
            # route. `> 0` alone passed a 19-digit number happily. Treated as
            # unset rather than rejected, matching how this parse already
            # handles every other unusable value.
            if rendered_ts is not None and 0 < rendered_ts <= SQLITE_MAX_ROWID:
                effective_until_ts = (
                    rendered_ts if until_ts is None else min(until_ts, rendered_ts)
                )

        if rule_type is not None and rule_type not in _ALERTS_RULE_TYPES:
            rule_type = None
        rule_type_for_db = rule_type or None

        if window is not None and window not in _ALERTS_WINDOW_SECONDS:
            window = None
        window_seconds = _ALERTS_WINDOW_SECONDS.get(window) if window else None
        now_ts = int(time.time())
        window_since_ts = (now_ts - window_seconds) if window_seconds else None

        # has_note: silently clamp invalid to the no-op. MUST mirror
        # the GET clamp exactly or ack-all-visible could write
        # against a different filter set than the operator sees.
        if has_note is not None and has_note not in _ALERTS_HAS_NOTE_VALUES:
            has_note = None
        has_note_for_db = has_note if has_note in ("with_note", "without_note") else None

        # has_action: same clamp + lazy-load posture as the GET
        # handler. The two MUST stay in lockstep -- ack-all-visible
        # writing under a different filter set than the visible page
        # is the worst class of bug for a bulk-write surface.
        if has_action is not None and has_action not in _ALERTS_HAS_ACTION_VALUES:
            has_action = None
        has_action_for_db = (
            has_action if has_action in ("with_action", "without_action") else None
        )
        if has_action_for_db is not None:
            (
                actioned_macs,
                actioned_oui_prefixes,
                actioned_mac_ranges,
            ) = _load_actioned_patterns(app.state.config, now_ts)
        else:
            actioned_macs, actioned_oui_prefixes, actioned_mac_ranges = (), (), ()

        effective_since_ts = since_ts
        if window_since_ts is not None:
            if effective_since_ts is None:
                effective_since_ts = window_since_ts
            else:
                effective_since_ts = max(effective_since_ts, window_since_ts)

        # Overflow guard runs BEFORE any write so a too-broad filter cannot
        # silently ack thousands of records. count_alerts() is read-only.
        total = db.count_alerts(
            severity=sev,
            acknowledged=ack_bool,
            since_ts=effective_since_ts,
            until_ts=effective_until_ts,
            search=search_clean,
            rule_type=rule_type_for_db,
            q=q_clean,
            has_note=has_note_for_db,
            has_action=has_action_for_db,
            actioned_macs=actioned_macs,
            actioned_oui_prefixes=actioned_oui_prefixes,
            actioned_mac_ranges=actioned_mac_ranges,
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
            since_ts=effective_since_ts,
            until_ts=effective_until_ts,
            search=search_clean,
            rule_type=rule_type_for_db,
            q=q_clean,
            has_note=has_note_for_db,
            has_action=has_action_for_db,
            actioned_macs=actioned_macs,
            actioned_oui_prefixes=actioned_oui_prefixes,
            actioned_mac_ranges=actioned_mac_ranges,
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

    def _alerts_row_swap(request: Request, alert_id: int):
        """htmx in-place row swap for the /alerts LIST page.

        When a /alerts list row form posts (it sends the X-Lyn-Alerts-Row
        header via hx-headers), re-render just that one alert row in its new
        state for an outerHTML swap over #alert-row-<id> -- no full reload, so
        scroll position and the rest of the table are preserved. Returns None
        when this is not a /alerts-list htmx request, so the caller falls back
        to its normal response.

        This is deliberately distinct from the home-page recent-alerts card,
        which posts to the same ack route but wants the row REMOVED (the empty
        200 body in ack_alert below); that card sends no X-Lyn-Alerts-Row
        header, so it never reaches this branch. The row is RE-RENDERED rather
        than removed because /alerts is a mixed acked+unacked list -- an acked
        row stays visible (flipped to its unack state), it does not disappear.
        The alert is loaded + enriched exactly as the list route does
        (get_alert_with_match + _enrich_alerts_with_devices) so the swapped row
        is identical to a freshly rendered list row.
        """
        if not request.headers.get("x-lyn-alerts-row"):
            return None
        alert = db.get_alert_with_match(alert_id)
        if alert is None:
            return None
        _enrich_alerts_with_devices(db, [alert])
        return app.state.templates.TemplateResponse(
            request=request,
            name="_alert_row.html",
            context={"a": alert},
        )

    @app.post("/alerts/{alert_id}/ack")
    def ack_alert(
        request: Request,
        alert_id: RowId,
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
        row = _alerts_row_swap(request, alert_id)
        if row is not None:
            # /alerts list: re-render the now-acked row in place (mixed list).
            return row
        if request.headers.get("hx-request"):
            # Home-page recent-alerts card: an htmx ack swaps this empty body as
            # outerHTML into the row target, removing only that one row — no
            # full reload, so no scroll reset and no live-poll reorder. Must
            # be 200, not 204: htmx skips the swap on a 204 No Content.
            return HTMLResponse("", status_code=200)
        target = _safe_redirect_target(request, default="/alerts")
        return RedirectResponse(target, status_code=303)

    @app.post("/alerts/{alert_id}/unack")
    def unack_alert(
        request: Request,
        alert_id: RowId,
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
        row = _alerts_row_swap(request, alert_id)
        if row is not None:
            # /alerts list: re-render the now-unacked row in place. (No
            # home-page idiom for unack -- the recent-alerts card only acks.)
            return row
        target = _safe_redirect_target(request, default="/alerts")
        return RedirectResponse(target, status_code=303)

    def _load_alert_for_triage(alert_id: int, request: Request):
        """Shared validation for the three triage routes.

        Returns the alert dict on success, or a Response (404 / 400) the
        caller should return directly. Common-validation duplication
        elsewhere in this module is avoided here because the gates
        differ slightly per route — but the three triage routes share
        a structurally identical set, so factoring saves three copies.
        """
        if alert_id < 1:
            raise HTTPException(status_code=400, detail="alert_id must be positive")
        alert = db.get_alert(alert_id)
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
        if not alert.get("mac"):
            raise HTTPException(
                status_code=400,
                detail="alert has no MAC; cannot apply MAC-keyed allowlist action",
            )
        if not app.state.config.allowlist_path:
            raise HTTPException(
                status_code=400,
                detail="allowlist_path is not configured; nothing to write to",
            )
        return alert

    def _write_ui_allowlist(
        mac: str,
        *,
        snooze_duration_key: str | None,
        now_ts: int,
    ) -> None:
        """Construct + persist the UI-managed allowlist entry for ``mac``.

        ``snooze_duration_key`` is ``None`` for the permanent
        /allowlist path, or one of ``_SNOOZE_DURATIONS`` keys for the
        /snooze path. ``"forever"`` writes a NULL expires_at (yaml
        end-state identical to permanent) but records distinct
        provenance in the note prefix so operators reading
        allowlist_ui.yaml can tell which surface produced the entry.
        Caller is responsible for upstream validation of the key
        against ``_SNOOZE_DURATIONS``.

        ``mac`` is the raw MAC; ``AllowlistEntry`` normalizes it to the
        canonical stored form. Shared by the per-alert triage routes
        (``allowlist_alert_post`` / ``snooze_alert_post``) and the
        device-detail silence routes -- same suppression mechanism,
        keyed by a MAC either way.
        """
        iso = unix_to_iso(now_ts)
        if snooze_duration_key is None:
            note = f"added via webui at {iso}"
            expires_at: int | None = None
        else:
            seconds = _SNOOZE_DURATIONS[snooze_duration_key]
            note = f"snoozed {snooze_duration_key} via webui at {iso}"
            expires_at = None if seconds is None else now_ts + seconds
        entry = AllowlistEntry(
            pattern=mac,
            pattern_type="mac",
            note=note,
            added_at=now_ts,
            expires_at=expires_at,
        )
        ui_path = derive_ui_path(Path(app.state.config.allowlist_path))
        add_ui_entry(ui_path, entry)

    @app.post("/alerts/{alert_id}/allowlist")
    def allowlist_alert_post(request: Request, alert_id: RowId):
        result = _load_alert_for_triage(alert_id, request)
        if not isinstance(result, dict):
            return result
        _write_ui_allowlist(
            result["mac"], snooze_duration_key=None, now_ts=int(time.time())
        )
        return RedirectResponse(f"/alerts/{alert_id}", status_code=303)

    @app.post("/alerts/{alert_id}/snooze")
    def snooze_alert_post(
        request: Request,
        alert_id: RowId,
        snooze_duration: str = Form(default=_SNOOZE_DEFAULT_KEY),
    ):
        if snooze_duration not in _SNOOZE_DURATIONS:
            raise HTTPException(
                status_code=400,
                detail=(
                    "snooze_duration must be one of: "
                    + ", ".join(_SNOOZE_DURATIONS)
                ),
            )
        result = _load_alert_for_triage(alert_id, request)
        if not isinstance(result, dict):
            return result
        # ⛔ A duration is only meaningful if the clock stamping it is: a
        # deadline written by a clock that reads behind recorded history is
        # already in the past, so the suppression never takes effect. Refused
        # rather than stored -- see webui/clock.py for the measurement and for
        # why this cannot be repaired after the fact.
        #
        # ⚠️ Placed AFTER this handler's own input validation, deliberately. A
        # bad duration or an unknown rule_type must be reported as what it is;
        # answering a malformed request with "your clock is wrong" tells the
        # caller nothing about the mistake they actually made.
        clock_refusal = refuse_if_clock_behind(
            db, int(time.time()), _SNOOZE_DURATIONS[snooze_duration]
        )
        if clock_refusal:
            raise HTTPException(status_code=400, detail=clock_refusal)

        _write_ui_allowlist(
            result["mac"],
            snooze_duration_key=snooze_duration,
            now_ts=int(time.time()),
        )
        return RedirectResponse(f"/alerts/{alert_id}", status_code=303)

    @app.post("/alerts/{alert_id}/allowlist/remove")
    def remove_allowlist_alert_post(request: Request, alert_id: RowId):
        result = _load_alert_for_triage(alert_id, request)
        if not isinstance(result, dict):
            return result
        ui_path = derive_ui_path(Path(app.state.config.allowlist_path))
        # Idempotent: return value discarded. Operators clicking Cancel
        # twice (or removing an entry that's actually in the primary
        # operator file) get the same 303 back to /alerts/<id>. The
        # template re-renders against the current state and shows the
        # truth, which is more useful than a stale error message.
        #
        # ⚠️ Through an AllowlistEntry, per `remove_ui_entry`'s documented
        # contract: it compares the pattern AS STORED, so a raw `alerts.mac`
        # could miss a normalised stored entry and no-op. The device-side
        # route has always done this; this one passed the raw column.
        entry = AllowlistEntry(pattern=result["mac"], pattern_type="mac")
        remove_ui_entry(ui_path, entry.pattern, "mac")
        return RedirectResponse(f"/alerts/{alert_id}", status_code=303)

    @app.post("/alerts/{alert_id}/note")
    def update_alert_note_post(
        request: Request,
        alert_id: RowId,
        note_text: str = Form(default=""),
    ):
        # Persistent per-alert triage note. Distinct from the
        # alert_actions per-event note posted by ack/unack: this is
        # one current conclusion ("FP -- known device"), replace-on-
        # update; the action history continues to record ack events
        # alongside. CSRF is enforced upstream by CSRFMiddleware.
        if alert_id < 1:
            raise HTTPException(status_code=400, detail="alert_id must be positive")
        try:
            ok = db.update_alert_note(alert_id, note_text, now_ts=int(time.time()))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
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
        # Distinguish cleared vs saved via a ?success= flag so the
        # detail template can show the appropriate one-time toast.
        # Stripped-empty input clears the note (DB column NULL).
        success = "note_cleared" if not note_text.strip() else "note_saved"
        return RedirectResponse(
            f"/alerts/{alert_id}?success={success}", status_code=303
        )

    # ------------------------------------------------------------------
    # Watchful snooze operator actions (Phase 2a backend)
    #
    # Six POST surfaces wire to db.py's Phase 2 helpers:
    #
    #   /alerts/{id}/watch          -- triage entry-point: create a
    #                                  watchful row from an alert
    #   /watchful/{id}/dismiss      -- archive (idempotent)
    #   /watchful/{id}/promote      -- archive + allowlist entry (atomic)
    #   /watchful/{id}/reset        -- walk back from escalated
    #   /watchful/{id}/investigate  -- flag + note, no archive
    #   /watchful/{id}/confirm-safe -- archive with safe annotation
    #
    # All six are CSRF-protected via the global CSRFMiddleware (the
    # `_csrf` form field), return 303 on success (operator forms, not
    # JSON APIs), and use HTTPException 400 for state-precondition
    # violations (matches the existing "alert has no MAC" precedent).
    # Phase 2b lands the UI -- no /watchful page or buttons yet.
    # ------------------------------------------------------------------

    WATCHFUL_NOTE_MAX_CHARS = 4096

    def _normalize_watchful_note(note: str | None) -> str | None:
        if note is None:
            return None
        note = note.strip()
        if not note:
            return None
        if len(note) > WATCHFUL_NOTE_MAX_CHARS:
            raise HTTPException(
                status_code=400,
                detail=f"note must be <= {WATCHFUL_NOTE_MAX_CHARS} chars",
            )
        return note

    def _load_watchful_for_action(entry_id: int, request: Request):
        """Shared 400/404 gate for the five /watchful action routes.

        Returns the entry on success, or a 404 TemplateResponse the
        caller should return directly. Matches the
        ``_load_alert_for_triage`` shape used by the /alerts triage
        family.
        """
        if entry_id < 1:
            raise HTTPException(
                status_code=400, detail="entry_id must be positive"
            )
        entry = db.get_watchful_recurrence(entry_id)
        if entry is None:
            return app.state.templates.TemplateResponse(
                request=request,
                name="not_found.html",
                context={
                    "version": __version__,
                    "active": "alerts",
                    "message": f"Watchful entry {entry_id} not found.",
                },
                status_code=404,
            )
        return entry

    @app.post("/alerts/{alert_id}/watch")
    def watch_alert_post(
        request: Request,
        alert_id: RowId,
        snooze_duration: str = Form(default="forever"),
    ):
        """Triage an alert into the watchful tracking surface.

        Creates a ``watchful_recurrence`` row from the alert's MAC
        and matched watchlist id. The Phase 2b UI will render the
        button on /alerts; the route exists now so the backend is
        complete and ready to wire.
        """
        if alert_id < 1:
            raise HTTPException(
                status_code=400, detail="alert_id must be positive"
            )
        if snooze_duration not in _SNOOZE_DURATIONS:
            raise HTTPException(
                status_code=400,
                detail=(
                    "snooze_duration must be one of: "
                    + ", ".join(_SNOOZE_DURATIONS)
                ),
            )
        seconds = _SNOOZE_DURATIONS[snooze_duration]
        # ⛔ A duration is only meaningful if the clock stamping it is: a
        # deadline written by a clock that reads behind recorded history is
        # already in the past, so the suppression never takes effect. Refused
        # rather than stored -- see webui/clock.py for the measurement and for
        # why this cannot be repaired after the fact.
        #
        # ⚠️ Placed AFTER this handler's own input validation, deliberately. A
        # bad duration or an unknown rule_type must be reported as what it is;
        # answering a malformed request with "your clock is wrong" tells the
        # caller nothing about the mistake they actually made.
        clock_refusal = refuse_if_clock_behind(db, int(time.time()), seconds)
        if clock_refusal:
            raise HTTPException(status_code=400, detail=clock_refusal)

        try:
            new_id = db.create_watchful_from_alert(
                alert_id,
                snooze_duration_seconds=seconds,
                now_ts=int(time.time()),
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        if new_id is None:
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
        row = _alerts_row_swap(request, alert_id)
        if row is not None:
            # /alerts list: re-render the row in place after watching so the
            # action stays put without a full reload (the row's displayed
            # columns are unchanged, but this avoids the scroll reset).
            return row
        target = _safe_redirect_target(request, default="/alerts")
        return RedirectResponse(target, status_code=303)

    @app.post("/watchful/{entry_id}/dismiss")
    def watchful_dismiss_post(request: Request, entry_id: RowId):
        result = _load_watchful_for_action(entry_id, request)
        if not isinstance(result, WatchfulRecurrence):
            return result
        # Idempotent: dismiss on an already-archived entry succeeds
        # with no DB change. Matches the /alerts/{id}/allowlist/remove
        # idempotence pattern; the redirect still fires.
        db.dismiss_watchful_recurrence(entry_id, now_ts=int(time.time()))
        return RedirectResponse("/watchful?success=dismissed", status_code=303)

    @app.post("/watchful/{entry_id}/promote")
    def watchful_promote_post(
        request: Request,
        entry_id: RowId,
        note: str | None = Form(default=None),
    ):
        result = _load_watchful_for_action(entry_id, request)
        if not isinstance(result, WatchfulRecurrence):
            return result
        if not app.state.config.allowlist_path:
            raise HTTPException(
                status_code=400,
                detail="allowlist_path is not configured; nothing to write to",
            )
        operator_note = _normalize_watchful_note(note)
        now_ts = int(time.time())
        iso = unix_to_iso(now_ts)
        # Provenance prefix matches the /alerts/{id}/allowlist convention
        # so an operator reading allowlist_ui.yaml directly sees a
        # consistent "added via webui at ..." marker, with the optional
        # operator note appended.
        provenance = f"promoted from watchful entry {entry_id} via webui at {iso}"
        full_note = (
            f"{provenance} -- {operator_note}" if operator_note else provenance
        )
        ui_path = derive_ui_path(Path(app.state.config.allowlist_path))
        try:
            db.promote_watchful_to_allowlist(
                entry_id,
                allowlist_path=ui_path,
                pattern=result.mac,
                pattern_type="mac",
                note=full_note,
                expires_at=None,
                now_ts=now_ts,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except RuntimeError as exc:
            # Concurrent-archive race; rare. 409 would be ideal but the
            # codebase has no 409 precedent, so 400 with a descriptive
            # detail follows the existing "stateful precondition" shape.
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return RedirectResponse("/watchful?success=promoted", status_code=303)

    @app.post("/watchful/{entry_id}/reset")
    def watchful_reset_post(request: Request, entry_id: RowId):
        result = _load_watchful_for_action(entry_id, request)
        if not isinstance(result, WatchfulRecurrence):
            return result

        # ⛔ Finding 51's route half. This is the sixth clock-stamped write and
        # the only one that is not a snooze: `reset_watchful_recurrence` writes
        # `last_seen_at`, the SOLE lifecycle clock for an unactioned entry, and
        # `auto_archive_watchful_recurrence` archives anything that column says
        # is 90 days quiet. So a reset written against a behind clock buys less
        # continued tracking than the operator asked for, and an entry already
        # near the limit is archived outright -- the exact opposite of what the
        # button means, and the FAIL-CLOSED direction: what gets dropped is the
        # tracking of a possible follower.
        #
        # ⚠️ Deliberately passes no `duration_seconds`. The loss is
        # `min(entry_staleness, behind_by)` -- a property of the ROW, which no
        # duration argument can express. Measured in `refuse_if_clock_behind`'s
        # docstring; session 1's `MAX(last_seen_at, ?)` clamp bounds the damage
        # but does not restore the intent, so both are wanted.
        #
        # ⚠️ Placed AFTER `_load_watchful_for_action`, matching the five snooze
        # routes: a bad or unknown entry must be reported as what it is. The
        # not-escalated precondition stays in `db.py` where the other routes'
        # state preconditions also live.
        clock_refusal = refuse_if_clock_behind(
            db, int(time.time()), action="watchful_reset"
        )
        if clock_refusal:
            raise HTTPException(status_code=400, detail=clock_refusal)

        try:
            db.reset_watchful_recurrence(entry_id, now_ts=int(time.time()))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return RedirectResponse("/watchful?success=reset", status_code=303)

    @app.post("/watchful/{entry_id}/investigate")
    def watchful_investigate_post(
        request: Request,
        entry_id: RowId,
        note: str | None = Form(default=None),
    ):
        result = _load_watchful_for_action(entry_id, request)
        if not isinstance(result, WatchfulRecurrence):
            return result
        operator_note = _normalize_watchful_note(note)
        try:
            db.flag_watchful_for_investigation(
                entry_id, operator_note, now_ts=int(time.time())
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return RedirectResponse("/watchful?success=flagged", status_code=303)

    @app.post("/watchful/{entry_id}/confirm-safe")
    def watchful_confirm_safe_post(
        request: Request,
        entry_id: RowId,
        note: str | None = Form(default=None),
    ):
        result = _load_watchful_for_action(entry_id, request)
        if not isinstance(result, WatchfulRecurrence):
            return result
        operator_note = _normalize_watchful_note(note)
        try:
            db.mark_watchful_confirmed_safe(
                entry_id, operator_note, now_ts=int(time.time())
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return RedirectResponse("/watchful?success=confirmed_safe", status_code=303)

    # ------------------------------------------------------------------
    # /watchful read views (Phase 2b)
    #
    # GET /watchful           -- operator triage list with filter +
    #                            pagination + per-row action buttons
    # GET /watchful/{id}      -- per-entry detail mirroring the
    #                            /alerts/{id} shape: full row state +
    #                            action buttons + cross-links to the
    #                            source alert and matched watchlist row
    #
    # All action POSTs from Phase 2a land back here via the
    # ?success=<token> banner convention established on /rules.
    # ------------------------------------------------------------------

    WATCHFUL_PER_PAGE_ALLOWED: tuple[int, ...] = (25, 50, 100, 200)
    WATCHFUL_PER_PAGE_DEFAULT: int = 50
    WATCHFUL_STATUS_OPTIONS: tuple[str, ...] = ("active", "archived", "all")
    WATCHFUL_STATE_OPTIONS: tuple[str, ...] = ("all", "tracking", "escalated")
    WATCHFUL_DEFAULT_STATUS: str = "active"
    WATCHFUL_DEFAULT_STATE: str = "all"
    WATCHFUL_DIGEST_WEEKS: int = 8
    _WATCHFUL_SUCCESS_FLASHES: dict[str, str] = {
        "dismissed": "Entry dismissed.",
        "promoted": "Entry promoted to the permanent allowlist.",
        "reset": "Escalation reset; tracking continues.",
        "flagged": "Entry flagged for investigation.",
        "confirmed_safe": "Entry confirmed as not suspicious and closed.",
        "watched": "Watchful tracking started for the alert.",
    }

    def _entry_state(entry: WatchfulRecurrence) -> str:
        """Three-state label derived from the timestamp columns (per
        migration 018's timestamp-derived lifecycle convention)."""
        if entry.archived_at is not None:
            return "archived"
        if entry.escalated_at is not None:
            return "escalated"
        return "tracking"

    def _escalation_delivery(entry: WatchfulRecurrence) -> str | None:
        """What does the recorded escalation's alert lookup establish?

        Returns None for an entry that has not escalated, else one of:

          "delivered"    the escalation alert exists and the notifier reported
                         success
          "undelivered"  the alert row exists and has never been delivered --
                         the send failed; poller retries are driven by seeing
                         the device again
          "suppressed"   NO alert row exists. The `watchful_recurrence`
                         rule_type snooze was active at the threshold crossing,
                         so the poller consumed the escalation deliberately and
                         the operator was never told
          "unknown"      the alert lookup failed, so delivery state could not
                         be determined

        End-recipient delivery is not observable here; ``notified_at`` records
        that the notifier reported success.

        ⭐ "suppressed" is decidable rather than inferred: alerts are never
        pruned (no DELETE FROM alerts anywhere, no retention knob), so a missing
        row means it was never written.

        ⚠️ One indexed lookup per rendered row, bounded by the page size, not by
        the table -- the full-table scan #111 refused is a different shape.
        """
        if entry.escalated_at is None:
            return None
        try:
            alert = db.get_recent_alert_for_rule_and_mac(
                "watchful_recurrence", entry.mac, int(entry.escalated_at),
            )
        except Exception:
            # This is diagnostic state. A failed lookup must not cost the page.
            return "unknown"
        if alert is None:
            return "suppressed"
        if alert["notified_at"] is None:
            return "undelivered"
        return "delivered"

    def _is_unsighted_reset_generation(entry: WatchfulRecurrence) -> bool:
        """This row is a reset generation in which no counted sighting has
        happened yet.

        Three writers set that column and only one of them is an
        observation: a counted sighting
        (``record_watchful_sighting``), the operator's reset
        (``reset_watchful_recurrence``, which sets
        ``last_seen_at = now_ts`` and ``sighting_count = 1``), and a
        clock-repair clamp
        (``repair_future_dated_watchful_last_seen``). Rendering all
        three as "last seen" told the operator a device had just been
        seen when what had just happened was their own button press --
        and the same column is the list's ``ORDER BY`` and the column
        the ``?window=`` filter clamps, so the click also moved the row
        to the top of the triage view and into "last 1h".

        The reset is derivable from the row: it forces
        ``sighting_count`` to 1, so ``reset_count > 0 and
        sighting_count == 1`` means this is a reset generation in
        which no counted sighting has landed yet. A never-reset row
        also has ``sighting_count == 1``, which is why this is a
        conjunction and not either half.

        ⛔ Deliberately NOT extended to the clock-repair clamp: that
        write leaves the row byte-identical to one whose device was
        seen at the repair instant, so no predicate here can see it.
        It is named in the page copy instead. A marker implying
        "everything unmarked is a sighting" would be the same false
        claim one layer along.

        ⚠️ The db-layer overwrite is correct and must stay:
        ``last_seen_at`` is also the 90-day auto-archive clock, so a
        reset that left it alone would archive an entry the operator
        had just chosen to keep watching.
        """
        return entry.reset_count > 0 and entry.sighting_count == 1

    def _build_weekly_digest(now_ts: int, n_weeks: int) -> list[dict]:
        """Group recent escalations by ISO week, most recent first.

        Returns a list of ``{week_label, count, macs}`` dicts covering
        the last ``n_weeks`` ISO weeks. Weeks with zero escalations
        are omitted (the empty-state copy in the template handles
        "no recent escalations at all"). Sourced from a single
        ``list_recent_watchful_escalations`` call so the grouping
        happens in Python on a small bounded result set.

        ISO week is the chosen grouping convention (locked decision
        was silent; ISO is the established standard and Python's
        ``isocalendar()`` returns it directly). Week labels use the
        ``YYYY-Www`` shape.
        """
        window_seconds = n_weeks * 7 * 86400
        since_ts = now_ts - window_seconds
        rows = db.list_recent_watchful_escalations(since_ts=since_ts)
        buckets: dict[tuple[int, int], list[str]] = {}
        for row in rows:
            assert row.escalated_at is not None
            iso_year, iso_week, _weekday = _dt.datetime.fromtimestamp(
                row.escalated_at, tz=_dt.UTC,
            ).isocalendar()
            buckets.setdefault((iso_year, iso_week), []).append(row.mac)
        digest: list[dict] = []
        for iso_year, iso_week in sorted(buckets.keys(), reverse=True):
            macs = buckets[(iso_year, iso_week)]
            digest.append({
                "week_label": f"{iso_year}-W{iso_week:02d}",
                "count": len(macs),
                "macs": macs,
            })
        return digest

    @app.get("/watchful", response_class=HTMLResponse)
    def watchful_list(
        request: Request,
        status: str | None = Query(default=None),
        state: str | None = Query(default=None),
        window: str | None = Query(default=None),
        q: str | None = Query(default=None),
        page: str | None = Query(default=None),
        page_size: str | None = Query(default=None),
        success: str | None = Query(default=None),
    ):
        # Silent fallback on unknown filter values -- matches the
        # /alerts and /rules clamp posture so a stale bookmark lands
        # on the unfiltered page, not 400.
        if status is None or status not in WATCHFUL_STATUS_OPTIONS:
            status = WATCHFUL_DEFAULT_STATUS
        if state is None or state not in WATCHFUL_STATE_OPTIONS:
            state = WATCHFUL_DEFAULT_STATE
        if window is not None and window not in _ALERTS_WINDOW_SECONDS:
            window = None
        if q is not None and len(q) > 100:
            raise HTTPException(status_code=400, detail="q must be <= 100 chars")
        q_clean = (q or "").strip() or None

        now_ts = int(time.time())
        window_seconds = _ALERTS_WINDOW_SECONDS.get(window) if window else None
        since_ts = (now_ts - window_seconds) if window_seconds else None

        # state only narrows when status=active. If the operator picks
        # state=escalated on status=archived we still apply both -- the
        # combination has a coherent meaning ("entries that escalated
        # then got archived") even if it's not the common case.

        requested_page, per_page = parse_pagination(
            page,
            page_size,
            allowed_per_page=WATCHFUL_PER_PAGE_ALLOWED,
            default_per_page=WATCHFUL_PER_PAGE_DEFAULT,
        )
        total = db.count_watchful_recurrence(
            status=status, state=state, since_ts=since_ts, q=q_clean,
        )
        pagination = build_pagination(requested_page, per_page, total)
        entries = db.list_watchful_recurrence(
            status=status,
            state=state,
            since_ts=since_ts,
            q=q_clean,
            limit=pagination.per_page,
            offset=pagination.offset,
        )

        # Decorate each entry with its three-state label so the
        # template doesn't have to recompute the same NULL-checks for
        # the action-button visibility test.
        decorated = [
            {
                "entry": e,
                "state_label": _entry_state(e),
                "escalation_delivery": _escalation_delivery(e),
                "is_unsighted_reset_generation": _is_unsighted_reset_generation(e),
            }
            for e in entries
        ]

        digest = _build_weekly_digest(now_ts, WATCHFUL_DIGEST_WEEKS)

        flash = _WATCHFUL_SUCCESS_FLASHES.get(success or "")

        filters_active = bool(
            status != WATCHFUL_DEFAULT_STATUS
            or state != WATCHFUL_DEFAULT_STATE
            or window
            or q_clean
        )

        return app.state.templates.TemplateResponse(
            request=request,
            name="watchful_list.html",
            context={
                "version": __version__,
                "active": "watchful",
                "decorated": decorated,
                "pagination": pagination,
                "status": status,
                "state": state,
                "window": window or "",
                "q": q or "",
                "status_options": WATCHFUL_STATUS_OPTIONS,
                "state_options": WATCHFUL_STATE_OPTIONS,
                "window_options": tuple(_ALERTS_WINDOW_SECONDS.keys()),
                "per_page_options": WATCHFUL_PER_PAGE_ALLOWED,
                "now_ts": now_ts,
                "digest": digest,
                "digest_weeks": WATCHFUL_DIGEST_WEEKS,
                "flash": flash,
                "filters_active": filters_active,
                "watch_snooze_durations": list(_SNOOZE_DURATIONS.keys()),
            },
        )

    @app.get("/watchful/{entry_id}", response_class=HTMLResponse)
    def watchful_detail(
        request: Request,
        entry_id: RowId,
        success: str | None = Query(default=None),
    ):
        if entry_id < 1:
            raise HTTPException(status_code=400, detail="entry_id must be positive")
        entry = db.get_watchful_recurrence(entry_id)
        if entry is None:
            return app.state.templates.TemplateResponse(
                request=request,
                name="not_found.html",
                context={
                    "version": __version__,
                    "active": "watchful",
                    "message": f"Watchful entry {entry_id} not found.",
                },
                status_code=404,
            )
        flash = _WATCHFUL_SUCCESS_FLASHES.get(success or "")
        return app.state.templates.TemplateResponse(
            request=request,
            name="watchful_detail.html",
            context={
                "version": __version__,
                "active": "watchful",
                "entry": entry,
                "state_label": _entry_state(entry),
                "escalation_delivery": _escalation_delivery(entry),
                "is_unsighted_reset_generation": _is_unsighted_reset_generation(entry),
                "now_ts": int(time.time()),
                "flash": flash,
            },
        )

    @app.get("/devices", response_class=HTMLResponse)
    def devices_list(
        request: Request,
        device_type: str | None = Query(default=None),
        randomized: str | None = Query(default=None),
        probing: str | None = Query(default=None),
        q: str | None = Query(default=None),
        page: str | None = Query(default=None),
        page_size: str | None = Query(default=None),
        sort: str | None = Query(default=None),
        direction: str | None = Query(default=None, alias="dir"),
    ):
        # The filter form's "any" <option value=""> emits an empty
        # string, which would slip past the `is not None` guards and
        # 400. Normalize empty-string -> None at route entry so the
        # default form submission renders the unfiltered list. Bogus
        # values (e.g. device_type=cellular) still 400 -- the diagnostic
        # arc kept that posture intentional, matching the existing
        # ValueError raised by db.list_devices on unknown literals.
        # "bluetooth" is a query-only alias the db layer expands to the
        # two BT subtypes; it is accepted here but never stored.
        if device_type == "":
            device_type = None
        if randomized == "":
            randomized = None
        if probing == "":
            probing = None
        if device_type is not None and device_type not in (
            "wifi", "ble", "bt_classic", "remote_id", "bluetooth"
        ):
            raise HTTPException(status_code=400, detail="invalid device_type")
        rand_bool = _parse_bool_str(randomized, "randomized")
        probing_bool = _parse_probing_str(probing)
        # Free-text search mirrors the /watchful q filter: same param
        # name, same 100-char cap, same strip-to-None normalization so
        # an empty / whitespace box renders the unfiltered list. The
        # devices search widens the matched columns (mac/name/vendor/
        # ssid) since the devices table surfaces more identity than the
        # mac-only watchful_recurrence rows.
        if q is not None and len(q) > 100:
            raise HTTPException(status_code=400, detail="q must be <= 100 chars")
        q_clean = (q or "").strip() or None
        # Server-side column sort (matches the /rules ?sort= idiom): an
        # unknown sort key or direction silently falls back to the
        # default ordering instead of 400, so a stale bookmark or a
        # hand-typed param lands on a coherent page. The DB layer
        # whitelists again (defense in depth), but normalizing here
        # keeps the value passed to the template's active-column
        # affordance honest.
        if sort is None or sort == "" or sort not in _DEVICES_SORT_OPTIONS:
            sort = DEVICES_DEFAULT_SORT
        if direction not in _DEVICES_DIR_OPTIONS:
            direction = DEVICES_DEFAULT_DIR
        # Pagination uses the shared two-phase helper (parse -> clamp)
        # like every other list page: an out-of-range page or page_size
        # clamps silently instead of 400 (B-5). Invalid per_page falls
        # back to the default; the page is clamped to [1, total_pages]
        # once the total is known.
        requested_page, per_page = parse_pagination(
            page,
            page_size,
            allowed_per_page=_DEVICES_PER_PAGE_ALLOWED,
            default_per_page=_DEVICES_PER_PAGE_DEFAULT,
        )
        total_count = db.count_devices(
            device_type=device_type, randomized=rand_bool, probing=probing_bool,
            q=q_clean,
        )
        pagination = build_pagination(requested_page, per_page, total_count)
        devices = db.list_devices(
            limit=pagination.per_page,
            offset=pagination.offset,
            device_type=device_type,
            randomized=rand_bool,
            probing=probing_bool,
            q=q_clean,
            sort=sort,
            direction=direction,
        )
        # Silence state lives in the allowlist files, not the devices
        # table, so list_devices can't surface it. Resolve it for the
        # page's MACs in one pass (both files read once) so each row can
        # render the same silenced/snoozed badge the detail page shows.
        now_ts = int(time.time())
        silence_by_mac = _resolve_silence_states(
            app.state.config, [d["mac"] for d in devices], now_ts
        )
        filters_active = (
            bool(device_type)
            or rand_bool is not None
            or probing_bool is not None
            or q_clean is not None
        )
        # The probing filter only ever has data when probe-SSID capture
        # is enabled (off by default). The webui can read the flag, so
        # surface an honest note near the control rather than letting the
        # operator wonder why ?probing=yes is always empty.
        probe_capture_enabled = bool(app.state.config.capture.probe_ssids)
        return app.state.templates.TemplateResponse(
            request=request,
            name="devices_list.html",
            context={
                "version": __version__,
                "active": "devices",
                "devices": devices,
                "total_count": total_count,
                "page": pagination.page,
                "page_size": pagination.per_page,
                "total_pages": pagination.total_pages,
                "sort": sort,
                "dir": direction,
                "device_type": device_type,
                "randomized": rand_bool,
                "probing": probing_bool,
                "q": q or "",
                "probe_capture_enabled": probe_capture_enabled,
                "filters_active": filters_active,
                "silence_by_mac": silence_by_mac,
                "now_ts": now_ts,
            },
        )

    @app.get("/probes", response_class=HTMLResponse)
    def probes_list(
        request: Request,
        group: str | None = Query(default=None),
        q: str | None = Query(default=None),
        page: str | None = Query(default=None),
        page_size: str | None = Query(default=None),
    ):
        # Aggregated probe-SSID view -- the per-device "Probes" column's
        # sibling, and the most PII-sensitive surface in the app. SSIDs
        # are rendered COLLAPSED-BY-DEFAULT in the template (native
        # <details>, no `open`); the operator opts into exposure. This
        # route only reads/aggregates devices.probe_ssids -- no capture,
        # no mutation.
        #
        # Two groupings, selected by ?group=: "device" (default -- which
        # networks each device probed, SSIDs already on the row) and
        # "ssid" (which devices probed each network, unnested with
        # json_each in the db layer). An unknown/empty group normalizes to
        # the default, matching the silent-clamp posture of the other list
        # pages rather than 400-ing a stale bookmark.
        if group not in _PROBES_GROUPINGS:
            group = _PROBES_GROUP_DEFAULT
        # Free-text search mirrors /devices + /watchful exactly: same
        # param, 100-char cap, strip-to-None so an empty box renders the
        # unfiltered view. In "device" grouping q matches device identity
        # or any probe SSID; in "ssid" grouping it matches the SSID name.
        if q is not None and len(q) > 100:
            raise HTTPException(status_code=400, detail="q must be <= 100 chars")
        q_clean = (q or "").strip() or None
        requested_page, per_page = parse_pagination(
            page,
            page_size,
            allowed_per_page=_PROBES_PER_PAGE_ALLOWED,
            default_per_page=_PROBES_PER_PAGE_DEFAULT,
        )

        device_rows: list[dict] = []
        ssid_groups: list[dict] = []
        if group == "ssid":
            total_count = db.count_probe_ssids(q=q_clean)
            pagination = build_pagination(requested_page, per_page, total_count)
            ssid_rows = db.list_probe_ssids(
                limit=pagination.per_page, offset=pagination.offset, q=q_clean,
            )
            # One bounded follow-up query for just this page's SSIDs --
            # not an N+1 and not a full-probe load. Each group's device
            # list is capped (db.PROBE_SSID_DEVICES_CAP); the true count
            # comes from the GROUP BY above so the template can show a
            # "+N more" note when the reveal is truncated.
            page_ssids = [r["ssid"] for r in ssid_rows]
            devices_by_ssid = db.list_devices_for_probe_ssids(page_ssids)
            ssid_groups = [
                {
                    "ssid": r["ssid"],
                    "device_count": r["device_count"],
                    "devices": devices_by_ssid.get(r["ssid"], []),
                    "shown": len(devices_by_ssid.get(r["ssid"], [])),
                }
                for r in ssid_rows
            ]
        else:
            total_count = db.count_probe_devices(q=q_clean)
            pagination = build_pagination(requested_page, per_page, total_count)
            device_rows = db.list_probe_devices(
                limit=pagination.per_page, offset=pagination.offset, q=q_clean,
            )

        # Capture defaults off, so the tab is usually empty. Surface the
        # same honest note the /devices probing filter shows rather than
        # letting the operator wonder why the page is blank.
        probe_capture_enabled = bool(app.state.config.capture.probe_ssids)
        return app.state.templates.TemplateResponse(
            request=request,
            name="probes_list.html",
            context={
                "version": __version__,
                "active": "probes",
                "group": group,
                "device_rows": device_rows,
                "ssid_groups": ssid_groups,
                "per_ssid_cap": db.PROBE_SSID_DEVICES_CAP,
                "total_count": total_count,
                "page": pagination.page,
                "page_size": pagination.per_page,
                "total_pages": pagination.total_pages,
                "per_page_options": _PROBES_PER_PAGE_ALLOWED,
                "q": q or "",
                "filters_active": q_clean is not None,
                "probe_capture_enabled": probe_capture_enabled,
            },
        )

    # Watchful "watch this device" duration vocabulary. Mirrors the
    # /alerts watch surface (alerts_list.html): forever/24h/7d/30d, no
    # 1h bucket -- watchful is a recurrence tracker, not a quick-dismiss.
    _DEVICE_WATCH_DURATIONS = ("24h", "7d", "30d", "forever")
    _DEVICE_WATCH_DEFAULT = "30d"

    def _device_actions_context(mac: str, now_ts: int) -> dict:
        """Build the device-detail action-panel context for ``mac``.

        Shared by the GET page render and every device action POST so
        the htmx partial re-render reflects post-action state through
        exactly the same query path. ``mac`` is the normalized MAC.
        Reuses ``_resolve_allowlist_match`` (the per-alert triage
        surface's own state resolver) so the "silence" section behaves
        identically to the alert-detail allowlist section.
        """
        (
            allowlist_match,
            allowlist_match_removable,
            allowlist_configured,
            allowlist_match_source,
        ) = _resolve_allowlist_match(app.state.config, mac, now_ts)
        snooze_hours_remaining: int | None = None
        if allowlist_match is not None and allowlist_match.expires_at is not None:
            seconds_left = max(0, allowlist_match.expires_at - now_ts)
            snooze_hours_remaining = max(1, (seconds_left + 3599) // 3600)
        return {
            "mac": mac,
            "watchlist_match": db.get_watchlist_entry_by_pattern(mac, "mac"),
            "active_watchful": db.get_active_watchful_recurrence_by_mac(mac),
            "watch_source_alert_id": db.get_most_recent_alert_id_for_mac(mac),
            "allowlist_match": allowlist_match,
            "allowlist_match_removable": allowlist_match_removable,
            "allowlist_match_source": allowlist_match_source,
            "allowlist_configured": allowlist_configured,
            "snooze_hours_remaining": snooze_hours_remaining,
            "severities": db._ALERT_SEVERITIES,
            "severity_default": "med",
            "snooze_duration_options": list(_SNOOZE_DURATIONS.keys()),
            "snooze_default_duration": _SNOOZE_DEFAULT_KEY,
            "watch_duration_options": _DEVICE_WATCH_DURATIONS,
            "watch_default_duration": _DEVICE_WATCH_DEFAULT,
            "now_ts": now_ts,
        }

    def _device_actions_response(request: Request, mac: str):
        """Return the panel partial (htmx) or a 303 back to the device page.

        Mirrors the ack-flow pattern: an HX-Request gets the re-rendered
        ``_device_actions.html`` swapped in place (200, not 204 -- htmx
        skips the swap on 204); a no-JS form submit gets a 303 redirect
        to /devices/<mac> (PRG), where the full-page re-render shows the
        same updated state.
        """
        if request.headers.get("hx-request"):
            return app.state.templates.TemplateResponse(
                request=request,
                name="_device_actions.html",
                context=_device_actions_context(mac, int(time.time())),
            )
        return RedirectResponse(f"/devices/{mac}", status_code=303)

    # ⭐ MUST stay registered BEFORE GET /devices/{mac:path}. That route's
    # ``:path`` converter matches slashes, so it would otherwise win this URL
    # with mac="<mac>/co-observations" and render the device page with a 200 --
    # a silent failure with no error anywhere. Pinned by
    # test_co_observations_route_is_not_swallowed_by_the_device_catch_all.
    @app.get("/devices/{mac:path}/co-observations", response_class=HTMLResponse)
    def device_co_observations(
        request: Request,
        mac: str,
        w: int | None = Query(None),
        detail: str | None = Query(None),
        loc: str | None = Query(None),
    ):
        """Which other devices keep turning up at the same time as this one.

        Read-only, and it makes no statistical claim: sensor uptime is not
        recorded, so absence of data cannot be told apart from absence of a
        device. Counts only, no score and no ranking of suspicion.
        """
        cfg = config.co_observation
        try:
            normalized = kismet.normalize_mac(mac)
        except ValueError:
            # %r, not %s: this is raw un-normalised request input, and a bare
            # %s would let a newline forge extra lines in the audit log.
            logger.info("co-observation request with a malformed mac: %r", mac)
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

        def _absent():
            """The single response used for BOTH 'capability off' and 'no such
            device', so the toggle cannot be used as a probe oracle that
            confirms which MACs the operator has seen.

            ``no-store`` because this response is a statement about WHICH MACs
            the operator has seen -- the same fact the shared response above
            exists to withhold. A cache that retained it would answer the
            question later, to someone who never asked this server. In practice
            every response also carries a CSRF ``Set-Cookie``, which stops
            shared caches storing it, but that is incidental protection from an
            unrelated mechanism: it would vanish the day CSRF cookies moved or
            became conditional, silently, and nothing would notice.
            """
            return app.state.templates.TemplateResponse(
                request=request,
                name="not_found.html",
                context={
                    "version": __version__,
                    "active": "devices",
                    "message": f"Device {normalized} not found.",
                },
                status_code=404,
                headers={"Cache-Control": "no-store"},
            )

        # ⭐ Parameter validation runs BEFORE the capability check, and the
        # order is load-bearing. Validating after it made ?w=-1 answer 400
        # while enabled and 404 while disabled, so one bad parameter revealed
        # the toggle's state -- the toggle becoming the very oracle Decision 6
        # forbids. The oracle closes only if EVERY path agrees, not the happy
        # one. Pinned by
        # test_disabled_is_indistinguishable_even_for_an_invalid_request.
        proximity = cfg.proximity_seconds if w is None else w
        if not (0 <= proximity <= 86400):
            # Logged on both sides of the capability check, like every other
            # branch, so the trail is complete without becoming an oracle: the
            # RESPONSE is unchanged and still identical whether the capability
            # is on or off. Only the server-side record differs.
            logger.info(
                "co-observation request with an out-of-range window: mac=%s w=%r",
                normalized,
                w,
            )
            return app.state.templates.TemplateResponse(
                request=request,
                name="not_found.html",
                context={
                    "version": __version__,
                    "active": "devices",
                    "message": "Proximity window must be between 0 and 86400 seconds.",
                },
                status_code=400,
            )

        if not cfg.enabled:
            logger.info(
                "co-observation panel requested while the capability is disabled: mac=%s",
                normalized,
            )
            return _absent()

        if db.get_device_with_sightings(normalized) is None:
            # ⭐ A miss is logged too, and the placement is the whole point.
            # This line used to be absent, so a MAC that is not in the database
            # left no trace anywhere. Enumeration is overwhelmingly misses --
            # an attacker guesses MACs -- so the audit log, which Decision 6
            # chose INSTEAD of rate limiting precisely to make enumeration
            # visible, recorded only the hits and hid the scan that found them.
            # Pinned by test_co_observations_audit_logs_the_misses_not_only_the_hits.
            logger.info(
                "co-observation query for an unknown device: mac=%s",
                normalized,
            )
            return _absent()

        now_ts = int(time.time())
        since_ts = now_ts - cfg.window_days * 86_400
        # Decision 6: every query is audit-logged, so enumeration leaves a
        # trail even though the panel itself only reads.
        #
        # ⭐ The line stays BEFORE the query, deliberately. It records an
        # ATTEMPT, and for an enumeration control that is the load-bearing
        # event: moving it after the query would mean a scan that provokes
        # failures leaves no trail at all, handing an attacker a way to erase
        # themselves from the one control Decision 6 kept after rejecting rate
        # limiting. Red team 2026-08-06 finding 1 was this same mistake in the
        # other direction -- the line sat one branch too late and recorded only
        # the hits.
        #
        # What WAS wrong is that it read as a completed access: on a failure the
        # log still said "co-observation query: mac=..." and nothing
        # contradicted it. An investigator reading this log after a stolen
        # session could not tell a served page from a query that blew up. So
        # the attempt is now named as an attempt, and the outcome is recorded
        # separately.
        logger.info(
            "co-observation query ATTEMPT: mac=%s window_days=%d proximity_seconds=%d",
            normalized,
            cfg.window_days,
            proximity,
        )
        try:
            result = db.list_co_observations(
                normalized,
                now_ts=now_ts,
                since_ts=since_ts,
                proximity_seconds=proximity,
                gap_seconds=cfg.gap_seconds,
                limit=cfg.max_candidates,
            )
        except Exception:
            # Re-raised unchanged: this handler exists to make the audit trail
            # honest, not to swallow the error or to change what the operator
            # sees. Without it the ATTEMPT line above would be the last word
            # and would read as a success.
            logger.warning(
                "co-observation query FAILED: mac=%s (no results were returned)",
                normalized,
            )
            raise

        # ⭐ One batched call for every candidate, NOT one per candidate inside
        # the loop below. The per-candidate form ran a correlated subquery that
        # expanded the whole devices table each time -- measured dead-linear in
        # corpus size -- so a full page re-scanned the entire capture up to
        # max_candidates (25) times over. Same numbers, one scan.
        # Pinned by test_shared_probe_ssids_corpus_scan_is_not_multiplied_by_candidate_count
        # and, at this layer, by test_co_observations_page_batches_the_probe_ssid_lookup.
        shared_ssids_by_mac = db.shared_probe_ssids_many(
            normalized, [row["mac"] for row in result["candidates"]]
        )

        candidates = []
        for row in result["candidates"]:
            total = row["candidate_total_runs"]
            # Decision 4 as amended in v3.1. NOT a fraction of the location:
            # it is the share of this candidate's OWN logged runs that were
            # shared. A device logged in 500 runs of which 3 coincide reads
            # 0.6% and is demoted on sight.
            shared_share = (row["shared_candidate_runs"] / total) if total else None
            candidates.append(
                {
                    **row,
                    "anchor_total_runs": result["anchor_runs_by_location"].get(
                        row["location_id"], 0
                    ),
                    "shared_share": shared_share,
                    # ⭐ Three outcomes, not two. The rule used to be a single
                    # AND -- enough runs AND a low share -- so the run-count
                    # gate produced a cliff that ran the wrong way: a device
                    # sharing 1 of its own 19 runs (5.3%) could never be
                    # demoted and was shown as a primary candidate, while one
                    # sharing 5 of 20 (25%), a five times stronger overlap, was
                    # demoted as explained away. Unclassifiable rendered
                    # identically to "not explained away", which on this panel
                    # is the difference between "we cannot say" and "this one
                    # stands out". Pinned by
                    # test_co_observations_does_not_promote_a_weaker_association
                    # _over_a_stronger_one.
                    "mostly_elsewhere": (
                        shared_share is not None and shared_share <= _CO_COVERAGE_SHARE
                    ),
                    "high_coverage": (
                        shared_share is not None
                        and total >= _CO_COVERAGE_MIN_RUNS
                        and shared_share <= _CO_COVERAGE_SHARE
                    ),
                    "too_few_runs_to_classify": (
                        shared_share is not None
                        and total < _CO_COVERAGE_MIN_RUNS
                        and shared_share <= _CO_COVERAGE_SHARE
                    ),
                    "shared_ssids": shared_ssids_by_mac.get(row["mac"], []),
                }
            )

        # Drill-down: the real sighting rows behind one candidate's count, so
        # the number is auditable rather than taken on trust. Only reachable
        # for a candidate that is actually on this page.
        pairs = []
        detail_mac = None
        detail_row = None
        if detail and loc:
            try:
                detail_mac = kismet.normalize_mac(detail)
            except ValueError:
                detail_mac = None
            detail_row = next(
                (
                    c
                    for c in candidates
                    if c["mac"] == detail_mac and c["location_id"] == loc
                ),
                None,
            )
            if detail_mac and detail_row is not None:
                pairs = db.list_co_observation_pairs(
                    normalized,
                    detail_mac,
                    location_id=loc,
                    now_ts=now_ts,
                    since_ts=since_ts,
                    proximity_seconds=proximity,
                    limit=_CO_PAIRS_LIMIT,
                )
                # The drill-down is the most sensitive read here -- it returns
                # the exact times two devices were logged together -- and it
                # used to be covered only by the generic query line above, so
                # the log could not tell a browse from a targeted
                # cross-reference, nor name the second device.
                # %r on the location for the same reason as the malformed-MAC
                # line above: it originates outside this code, and a bare %s
                # would let a newline in it forge audit lines. It is narrower
                # here -- loc has to match a location_id already in the
                # database to reach this branch -- but an audit log is exactly
                # the wrong place to rely on that.
                logger.info(
                    "co-observation drill-down: mac=%s candidate=%s location=%r pairs=%d",
                    normalized,
                    detail_mac,
                    loc,
                    len(pairs),
                )
            else:
                detail_mac = None

        return app.state.templates.TemplateResponse(
            request=request,
            name="co_observations.html",
            context={
                "version": __version__,
                "active": "devices",
                "mac": normalized,
                "detail_mac": detail_mac,
                "detail_loc": loc,
                "pairs": pairs,
                "detail_row": detail_row,
                "pairs_truncated": len(pairs) >= _CO_PAIRS_LIMIT,
                "pairs_limit": _CO_PAIRS_LIMIT,
                "candidates": [c for c in candidates if not c["mostly_elsewhere"]],
                "high_coverage": [c for c in candidates if c["high_coverage"]],
                "too_few_runs": [c for c in candidates if c["too_few_runs_to_classify"]],
                "coverage_min_runs": _CO_COVERAGE_MIN_RUNS,
                "total_candidates": result["total_candidates"],
                "shown": len(candidates),
                "proximity_seconds": proximity,
                "gap_seconds": cfg.gap_seconds,
                "window_days": cfg.window_days,
                "since_ts": since_ts,
                "now_ts": now_ts,
                "w_presets": _CO_W_PRESETS,
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
        context = {
            "version": __version__,
            "active": "devices",
            "device": result["device"],
            "sightings": result["sightings"],
            # Gated so the link cannot advertise a route that would 404, and
            # cannot hint that the capability exists at all.
            "co_observation_enabled": config.co_observation.enabled,
            # None while retention is off, which is the default. Present only so
            # the page can state that older rows were deleted, rather than let
            # "showing N of M" imply the rest are still retrievable.
            "sightings_retention_days": config.sightings_retention_days,
        }
        context.update(_device_actions_context(normalized, int(time.time())))
        return app.state.templates.TemplateResponse(
            request=request,
            name="device_detail.html",
            context=context,
        )

    @app.post("/devices/{mac:path}/watchlist")
    def device_add_watchlist_post(
        request: Request,
        mac: str,
        severity: str = Form(...),
    ):
        """Operator action: add this MAC to the watchlist with a severity.

        The sanctioned web write surface for the watchlist (db.add_watchlist,
        idempotent on the (pattern, mac) pair). Severity is constrained to
        the real model values; a re-add never downgrades an existing row.
        """
        try:
            normalized = kismet.normalize_mac(mac)
        except ValueError as exc:
            raise HTTPException(
                status_code=400, detail=f"malformed MAC: {mac!r}"
            ) from exc
        if severity not in db._ALERT_SEVERITIES:
            raise HTTPException(
                status_code=400,
                detail=f"severity must be one of {db._ALERT_SEVERITIES}",
            )
        iso = unix_to_iso(int(time.time()))
        db.add_watchlist(
            pattern=normalized,
            pattern_type="mac",
            severity=severity,
            description=f"added via webui at {iso}",
        )
        return _device_actions_response(request, normalized)

    @app.post("/devices/{mac:path}/watch")
    def device_watch_post(
        request: Request,
        mac: str,
        snooze_duration: str = Form(default=_DEVICE_WATCH_DEFAULT),
    ):
        """Operator action: track this device on the watchful surface.

        Watchful tracking is alert-derived (create_watchful_from_alert),
        so the device's most-recent alert becomes the source row. The
        panel only renders the button when an alert exists; a stale post
        with no alert is rejected (400). An existing active watchful entry
        for the MAC is idempotent -- swallow the one-active-per-MAC
        ValueError and re-render, which shows the existing entry.
        """
        try:
            normalized = kismet.normalize_mac(mac)
        except ValueError as exc:
            raise HTTPException(
                status_code=400, detail=f"malformed MAC: {mac!r}"
            ) from exc
        if snooze_duration not in _SNOOZE_DURATIONS:
            raise HTTPException(
                status_code=400,
                detail="snooze_duration must be one of: "
                + ", ".join(_SNOOZE_DURATIONS),
            )
        source_alert_id = db.get_most_recent_alert_id_for_mac(normalized)
        if source_alert_id is None:
            raise HTTPException(
                status_code=400,
                detail="no alert for this MAC; watchful tracking starts from an alert",
            )
        seconds = _SNOOZE_DURATIONS[snooze_duration]
        # ⛔ A duration is only meaningful if the clock stamping it is: a
        # deadline written by a clock that reads behind recorded history is
        # already in the past, so the suppression never takes effect. Refused
        # rather than stored -- see webui/clock.py for the measurement and for
        # why this cannot be repaired after the fact.
        #
        # ⚠️ Placed AFTER this handler's own input validation, deliberately. A
        # bad duration or an unknown rule_type must be reported as what it is;
        # answering a malformed request with "your clock is wrong" tells the
        # caller nothing about the mistake they actually made.
        clock_refusal = refuse_if_clock_behind(db, int(time.time()), seconds)
        if clock_refusal:
            raise HTTPException(status_code=400, detail=clock_refusal)

        try:
            db.create_watchful_from_alert(
                source_alert_id,
                snooze_duration_seconds=seconds,
                now_ts=int(time.time()),
            )
        except ValueError:
            pass
        return _device_actions_response(request, normalized)

    @app.post("/devices/{mac:path}/allowlist")
    def device_allowlist_post(request: Request, mac: str):
        """Operator action: silence future alerts for this MAC (permanent).

        Reuses the per-alert allowlist suppression mechanism
        (_write_ui_allowlist -> add_ui_entry), keyed by the MAC the
        device page already holds.
        """
        try:
            normalized = kismet.normalize_mac(mac)
        except ValueError as exc:
            raise HTTPException(
                status_code=400, detail=f"malformed MAC: {mac!r}"
            ) from exc
        if not app.state.config.allowlist_path:
            raise HTTPException(
                status_code=400,
                detail="allowlist_path is not configured; nothing to write to",
            )
        _write_ui_allowlist(
            normalized, snooze_duration_key=None, now_ts=int(time.time())
        )
        return _device_actions_response(request, normalized)

    @app.post("/devices/{mac:path}/snooze")
    def device_snooze_post(
        request: Request,
        mac: str,
        snooze_duration: str = Form(default=_SNOOZE_DEFAULT_KEY),
    ):
        """Operator action: silence future alerts for this MAC for a window."""
        try:
            normalized = kismet.normalize_mac(mac)
        except ValueError as exc:
            raise HTTPException(
                status_code=400, detail=f"malformed MAC: {mac!r}"
            ) from exc
        if snooze_duration not in _SNOOZE_DURATIONS:
            raise HTTPException(
                status_code=400,
                detail="snooze_duration must be one of: "
                + ", ".join(_SNOOZE_DURATIONS),
            )
        if not app.state.config.allowlist_path:
            raise HTTPException(
                status_code=400,
                detail="allowlist_path is not configured; nothing to write to",
            )
        # ⛔ A duration is only meaningful if the clock stamping it is: a
        # deadline written by a clock that reads behind recorded history is
        # already in the past, so the suppression never takes effect. Refused
        # rather than stored -- see webui/clock.py for the measurement and for
        # why this cannot be repaired after the fact.
        #
        # ⚠️ Placed AFTER this handler's own input validation, deliberately. A
        # bad duration or an unknown rule_type must be reported as what it is;
        # answering a malformed request with "your clock is wrong" tells the
        # caller nothing about the mistake they actually made.
        clock_refusal = refuse_if_clock_behind(
            db, int(time.time()), _SNOOZE_DURATIONS[snooze_duration]
        )
        if clock_refusal:
            raise HTTPException(status_code=400, detail=clock_refusal)

        _write_ui_allowlist(
            normalized, snooze_duration_key=snooze_duration, now_ts=int(time.time())
        )
        return _device_actions_response(request, normalized)

    @app.post("/devices/{mac:path}/allowlist/remove")
    def device_allowlist_remove_post(request: Request, mac: str):
        """Operator action: lift a UI-managed allowlist/snooze for this MAC.

        Idempotent (mirrors remove_allowlist_alert_post). Constructs an
        AllowlistEntry to get the canonical stored pattern per
        remove_ui_entry's documented contract -- a raw MAC could miss a
        normalized stored entry.
        """
        try:
            normalized = kismet.normalize_mac(mac)
        except ValueError as exc:
            raise HTTPException(
                status_code=400, detail=f"malformed MAC: {mac!r}"
            ) from exc
        if not app.state.config.allowlist_path:
            raise HTTPException(
                status_code=400,
                detail="allowlist_path is not configured; nothing to write to",
            )
        ui_path = derive_ui_path(Path(app.state.config.allowlist_path))
        entry = AllowlistEntry(pattern=normalized, pattern_type="mac")
        remove_ui_entry(ui_path, entry.pattern, "mac")
        return _device_actions_response(request, normalized)

    @app.get("/rules", response_class=HTMLResponse)
    def rules_list(
        request: Request,
        since: str | None = Query(default=None),
        sort: str | None = Query(default=None),
        status: str | None = Query(default=None),
        success: str | None = Query(default=None),
        rule_type: str | None = Query(default=None),
    ):
        # since (window dropdown) and sort are both rc5 additions.
        # status is the rc6 rule_type-snooze filter (all / snoozed /
        # active). Invalid values silently fall back to defaults — the
        # operator probably hit a stale URL after a constant rename;
        # refusing to render the page is hostile when the underlying
        # data (rules.yaml) is independent of the query params. The
        # "no query params" URL behaves exactly as pre-rc6: since=7d,
        # sort=default, status=all, no flash banner — every column
        # renders unchanged.
        if since is None or since == "" or since not in _RULES_WINDOW_SECONDS:
            since = _RULES_DEFAULT_WINDOW
        if sort is None or sort == "" or sort not in _RULES_SORT_OPTIONS:
            sort = _RULES_DEFAULT_SORT
        if status is None or status == "" or status not in _RULES_STATUS_OPTIONS:
            status = _RULES_DEFAULT_STATUS

        now_ts = int(time.time())
        since_ts = _resolve_window_to_since_ts(
            since, now_ts=now_ts, options=_RULES_WINDOW_SECONDS
        )

        # Live aggregate on every render — no caching. At current
        # scale the COUNT/MAX over an indexed-ts predicate is
        # sub-100ms; caching would buy nothing material and would
        # introduce invalidation complexity at alert-write time.
        rule_stats = db.count_alerts_grouped_by_rule_name(since_ts=since_ts)
        # Type-axis sibling of the per-rule_name aggregate above,
        # backing the "fires by rule_type" summary section at the top
        # of the page. Same time window drives both — flipping the
        # since dropdown updates both views in one round-trip.
        rule_type_stats = db.count_alerts_grouped_by_rule_type(since_ts=since_ts)

        # Active rule_type snoozes for the per-row badge / unsnooze
        # button render. Projected to ``{rule_type: RuleTypeSnooze}``
        # so the template can do an O(1) dict lookup per row instead
        # of scanning the list. Expired-but-not-yet-cleaned rows are
        # filtered at the DB layer (``expires_at > now_ts``) so the
        # template never sees them.
        active_snoozes = db.list_active_rule_type_snoozes(now_ts)
        snoozes_by_type: dict[str, object] = {s.rule_type: s for s in active_snoozes}

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

        # Build the iteration list with stats + snooze attached. Rules
        # that never fired in the window get RuleStats(0, None) —
        # caller default rather than absent-key so the template never
        # branches on dict membership. ``snooze`` is None when the
        # rule's rule_type has no active snooze; the template
        # branches on truthiness to pick badge vs. snooze-form render.
        rules_with_stats: list[dict] = []
        if ruleset is not None:
            for rule in ruleset.rules:
                stats = rule_stats.get(
                    rule.name, RuleStats(count=0, last_fired_ts=None)
                )
                snooze = snoozes_by_type.get(rule.rule_type)
                if status == "snoozed" and snooze is None:
                    continue
                if status == "active" and snooze is not None:
                    continue
                rules_with_stats.append(
                    {"rule": rule, "stats": stats, "snooze": snooze}
                )

            if sort == "count_desc":
                rules_with_stats.sort(
                    key=lambda r: (-r["stats"].count, r["rule"].name)
                )
            elif sort == "count_asc":
                rules_with_stats.sort(
                    key=lambda r: (r["stats"].count, r["rule"].name)
                )

        # Per-rule_type breakdown for the summary section at the top
        # of the page. Iteration scope = unique rule_types present
        # in the loaded ruleset (matches per-rule_name behavior: a
        # rule_type with fires in the window but no rule in
        # rules.yaml does not appear, since the operator's
        # rules.yaml view is the authoritative scope). Missing keys
        # default to RuleStats(0, None) so types with zero fires in
        # the window still render with their snooze affordances —
        # the section is independent of the per-rule_name status
        # filter for that reason: hiding snoozed types from the
        # type-level view would defeat its purpose.
        rule_types_with_stats: list[dict] = []
        if ruleset is not None:
            seen_rule_types: list[str] = []
            for rule in ruleset.rules:
                if rule.rule_type not in seen_rule_types:
                    seen_rule_types.append(rule.rule_type)
            for rt in seen_rule_types:
                stats = rule_type_stats.get(
                    rt, RuleStats(count=0, last_fired_ts=None)
                )
                snooze = snoozes_by_type.get(rt)
                rule_types_with_stats.append(
                    {"rule_type": rt, "stats": stats, "snooze": snooze}
                )
            rule_types_with_stats.sort(
                key=lambda r: (-r["stats"].count, r["rule_type"])
            )

        # ⛔ Active snoozes with NO rule of that type in the loaded ruleset.
        # The scope decision above is deliberate and stays -- but its
        # consequence was that such a snooze had no control ANYWHERE, while
        # /watchlist and /settings both told the operator to "lift it on the
        # rules page". Measured at cca7c5c: with `watchlist_ssid` snoozed and
        # no rule of that type loaded, /rules rendered zero unsnooze forms on
        # the default view, on `?status=snoozed`, on `?status=all`, and on
        # `?rule_type=watchlist_ssid`. The snooze stays in force in the poller
        # gate, so re-adding the rule later leaves it silently suppressed.
        #
        # ⭐ Reachable through the UI's own instructions: snooze a type here,
        # then "Edit <rules file> on disk and restart" as the footer says.
        #
        # ⚠️ The unsnooze endpoint already accepts these -- it validates
        # against the RuleType Literal, not against the loaded ruleset -- so
        # the button offered here is one that works, which is the only kind
        # worth adding.
        loaded_rule_types = (
            {rule.rule_type for rule in ruleset.rules} if ruleset is not None else set()
        )
        orphaned_snoozes = [
            {"rule_type": rt, "snooze": snoozes_by_type[rt]}
            for rt in sorted(snoozes_by_type)
            if rt not in loaded_rule_types
        ]

        # Resolve the window label for the dynamic "Fires (last X)"
        # column header. "all" gets the human label "all time"; the
        # other four buckets render their raw key ("1h" / "24h" /
        # "7d" / "30d") since those already read as recency.
        window_label = "all time" if since == "all" else since

        # Success flash banner: surfaced from the snooze / unsnooze
        # POST redirects (?success=snooze_added / snooze_removed +
        # rule_type=<rule_type>). Sanitized against the allowed set
        # so a stale URL doesn't render an arbitrary string. Empty
        # / unknown values silently drop the banner.
        flash = None
        if success == "snooze_added" and rule_type in _RULE_TYPE_SNOOZE_ALLOWED:
            flash = f"Snooze added for rule_type {rule_type}."
        elif success == "snooze_removed" and rule_type in _RULE_TYPE_SNOOZE_ALLOWED:
            flash = f"Snooze removed for rule_type {rule_type}."

        return app.state.templates.TemplateResponse(
            request=request,
            name="rules_list.html",
            context={
                "version": __version__,
                "active": "rules",
                "ruleset": ruleset,
                "notice": notice,
                "orphaned_snoozes": orphaned_snoozes,
                "rules_with_stats": rules_with_stats,
                "rule_types_with_stats": rule_types_with_stats,
                "since": since,
                "sort": sort,
                "status": status,
                "window_options": tuple(_RULES_WINDOW_SECONDS.keys()),
                "sort_options": _RULES_SORT_OPTIONS,
                "status_options": _RULES_STATUS_OPTIONS,
                "window_label": window_label,
                "now_ts": now_ts,
                "snooze_durations": _RULE_TYPE_SNOOZE_DURATIONS,
                "flash": flash,
            },
        )

    @app.post("/rules/{rule_type}/snooze")
    def snooze_rule_type_post(
        request: Request,
        rule_type: str,
        duration_seconds: int = Form(...),
        note: str | None = Form(default=None),
    ):
        # rule_type validated against the literal set so an attacker-
        # crafted URL can't insert arbitrary PK rows. duration_seconds
        # must come from the whitelisted dropdown; custom durations
        # are intentionally out of scope (mirrors the per-alert
        # snooze's fixed-duration posture, though with a richer
        # dropdown). CSRF is enforced upstream by CSRFMiddleware —
        # the handler runs only if the token already validated.
        if rule_type not in _RULE_TYPE_SNOOZE_ALLOWED:
            raise HTTPException(status_code=400, detail=f"unknown rule_type: {rule_type!r}")
        if duration_seconds not in _RULE_TYPE_SNOOZE_DURATION_SECONDS:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"invalid duration_seconds {duration_seconds}: "
                    f"expected one of {sorted(_RULE_TYPE_SNOOZE_DURATION_SECONDS)}"
                ),
            )
        normalized_note = _normalize_optional_note(note)
        now_ts = int(time.time())
        # ⛔ A duration is only meaningful if the clock stamping it is: a
        # deadline written by a clock that reads behind recorded history is
        # already in the past, so the suppression never takes effect. Refused
        # rather than stored -- see webui/clock.py for the measurement and for
        # why this cannot be repaired after the fact.
        #
        # ⚠️ Placed AFTER this handler's own input validation, deliberately. A
        # bad duration or an unknown rule_type must be reported as what it is;
        # answering a malformed request with "your clock is wrong" tells the
        # caller nothing about the mistake they actually made.
        clock_refusal = refuse_if_clock_behind(db, now_ts, duration_seconds)
        if clock_refusal:
            raise HTTPException(status_code=400, detail=clock_refusal)

        expires_at = now_ts + duration_seconds
        db.add_rule_type_snooze(
            rule_type=rule_type,
            expires_at=expires_at,
            added_at=now_ts,
            note=normalized_note,
        )
        return RedirectResponse(
            f"/rules?success=snooze_added&rule_type={rule_type}",
            status_code=303,
        )

    @app.post("/rules/{rule_type}/unsnooze")
    def unsnooze_rule_type_post(request: Request, rule_type: str):
        # Idempotent: double-clicking unsnooze returns the same 303
        # whether or not a row existed. The template re-renders
        # against the current state — that's more useful than a
        # stale error message. CSRF enforced upstream.
        if rule_type not in _RULE_TYPE_SNOOZE_ALLOWED:
            raise HTTPException(status_code=400, detail=f"unknown rule_type: {rule_type!r}")
        db.remove_rule_type_snooze(rule_type)
        return RedirectResponse(
            f"/rules?success=snooze_removed&rule_type={rule_type}",
            status_code=303,
        )

    @app.get("/watchlist", response_class=HTMLResponse)
    def watchlist_list(
        request: Request,
        q: str | None = Query(default=None),
        pattern_type: str | None = Query(default=None),
        severity: str | None = Query(default=None),
        device_category: str | None = Query(default=None),
        page: str | None = Query(default=None),
        page_size: str | None = Query(default=None),
    ):
        render_now_ts = int(time.time())
        # Backward compat: /watchlist with no query params behaves
        # exactly as pre-rc5 (first 50 rows, severity-by-importance
        # then pattern alphabetical). Invalid filter values silently
        # fall back to "all" -- a stale bookmark with a typo like
        # severity=foo lands on the unfiltered page rather than 400.
        if q is not None and len(q) > 100:
            raise HTTPException(status_code=400, detail="q must be <= 100 chars")
        q_clean = q if q else None

        # Lenient, but NOT silent. An unknown pattern_type used to be reset to
        # None, which DROPPED the filter and answered the request with every
        # row -- the operator asked for one type and got the whole watchlist
        # with nothing saying so. Staying lenient keeps stale bookmarks and
        # hand-edited URLs working (a 400 would break them); surfacing it is
        # what stops the page lying about what it is showing.
        dropped_filters: list[str] = []
        if pattern_type is not None and pattern_type not in _WATCHLIST_PATTERN_TYPES:
            dropped_filters.append(f"pattern type {pattern_type!r}")
            pattern_type = None
        pt_clean = pattern_type or None

        if severity is not None and severity not in ("low", "med", "high"):
            severity = None
        sev_clean = severity or None

        device_category_options = db.distinct_watchlist_device_categories()
        # device_category accepts the "uncategorized" sentinel
        # explicitly; any other value must appear in the live DISTINCT
        # set, else silently fall back to "all".
        if device_category is not None and device_category != "":
            if device_category not in (
                _WATCHLIST_UNCATEGORIZED_SENTINEL,
                *device_category_options,
            ):
                device_category = None
        dc_clean = device_category or None

        requested_page, per_page = parse_pagination(
            page,
            page_size,
            allowed_per_page=_WATCHLIST_PER_PAGE_ALLOWED,
            default_per_page=_WATCHLIST_PER_PAGE_DEFAULT,
        )

        rows, total = db.list_watchlist_filtered(
            q=q_clean,
            pattern_type=pt_clean,
            severity=sev_clean,
            device_category=dc_clean,
            page=requested_page,
            per_page=per_page,
        )
        pagination = build_pagination(requested_page, per_page, total)

        # If the requested page exceeded total_pages, re-fetch at the
        # clamped page so the rendered rows match the footer. The
        # alternative -- returning the over-the-edge empty page -- is
        # worse UX for a stale bookmark.
        if pagination.page != requested_page:
            rows, _ = db.list_watchlist_filtered(
                q=q_clean,
                pattern_type=pt_clean,
                severity=sev_clean,
                device_category=dc_clean,
                page=pagination.page,
                per_page=per_page,
            )

        filters_active = bool(
            q_clean
            or pt_clean
            or sev_clean
            or dc_clean
        )

        # ⭐ Graded over the WHOLE watchlist, not this page of it. A per-page
        # count would tell an operator on page 2 that nothing is wrong while
        # page 1 was entirely inert. The per-row marker below is what makes it
        # actionable; this is the headline that gets them to look.
        liveness = watchlist_liveness(
            app.state.config,
            db.watchlist_pattern_type_counts(),
            db=db,
            now_ts=render_now_ts,
        )
        # ⚠️ Loaded ONCE and shared: the suppression axes and the severity remap
        # read the same file, and two loads per render could disagree if the
        # operator saved the file between them.
        overrides = load_overrides(app.state.config)
        row_suppressions = suppression_axes_of(overrides)

        return app.state.templates.TemplateResponse(
            request=request,
            name="watchlist_list.html",
            context={
                "version": __version__,
                "active": "watchlist",
                "entries": rows,
                "pagination": pagination,
                "q": q or "",
                "pattern_type": pattern_type or "",
                "severity": severity or "",
                "device_category": device_category or "",
                "pattern_type_options": _WATCHLIST_PATTERN_TYPES,
                "dropped_filters": dropped_filters,
                "device_category_options": device_category_options,
                "uncategorized_sentinel": _WATCHLIST_UNCATEGORIZED_SENTINEL,
                "per_page_options": _WATCHLIST_PER_PAGE_ALLOWED,
                "filters_active": filters_active,
                "liveness": liveness,
                # ⭐ Marked per ROW, not per type: a severity override silences
                # an individual entry by its vendor/category, so the type-level
                # verdict cannot express it. Free here -- the rows are already
                # loaded with the metadata the override matches on.
                "suppressed_ids": {
                    r.id for r in rows
                    if is_row_suppressed_by_overrides(
                        r.vendor, r.device_category, row_suppressions
                    )
                },
                "never_match_ids": {
                    r.id for r in rows
                    if oui_prefix_never_matches(r.pattern_type, r.pattern)
                },
                # ⭐ The FIFTH silencing mechanism, reported for the rows where
                # it has a single answer. `liveness.allowlist_answerable_for`
                # carries the reasoning and the measurement; the loader is
                # called once per request and only when a `mac` row is actually
                # on the page, so a watchlist with none stays YAML-cost-free.
                "allowlisted_ids": _allowlisted_row_ids(
                    app.state.config, rows, render_now_ts
                ),
                # ⭐ Finding 42. The severity column is the triage surface, and
                # it was rendering the value the importer baked in rather than
                # the one the runtime layer will actually send. Free here --
                # vendor, category and argus_record_id are already loaded, and
                # the overrides file is already read for the suppression marks.
                "severity_remaps": {
                    r.id: remap
                    for r in rows
                    if (
                        remap := severity_remap(
                            r.severity,
                            r.vendor,
                            r.device_category,
                            r.argus_record_id,
                            row_suppressions,
                            overrides,
                        )
                    )
                },
                # ⚠️ Shown only when the operator is FILTERING by severity and a
                # remap is configured. The filter is SQL over the stored column
                # and cannot be made remap-aware without scanning the whole
                # table, so the honest move is to say which value it matched
                # rather than to quietly answer a different question.
                "severity_filter_is_stored_only": bool(
                    sev_clean and has_configured_remap(overrides)
                ),
                "inert_pattern_types": liveness["inert_types"],
                "snoozed_pattern_types": liveness["suppressed_types"],
            },
        )

    @app.get("/watchlist.csv")
    def watchlist_csv_export(
        request: Request,
        q: str | None = Query(default=None),
        pattern_type: str | None = Query(default=None),
        severity: str | None = Query(default=None),
        device_category: str | None = Query(default=None),
    ):
        render_now_ts = int(time.time())
        # Streaming CSV export of the currently-filtered /watchlist
        # result set. Filter parsing mirrors the watchlist_list handler
        # byte-for-byte: same clamp posture, same silent-fallback for
        # invalid values, same device_category sentinel handling.
        # Pagination is bypassed; the export covers every matching row.
        # Column projection is wider than the list page -- the full
        # watchlist_metadata join surfaces (source_url, source_excerpt,
        # fcc_id, geographic_scope, first_seen, last_verified, notes)
        # for offline Argus-provenance triage.
        if q is not None and len(q) > 100:
            raise HTTPException(status_code=400, detail="q must be <= 100 chars")
        q_clean = q if q else None

        # Lenient, but NOT silent. An unknown pattern_type used to be reset to
        # None, which DROPPED the filter and answered the request with every
        # row -- the operator asked for one type and got the whole watchlist
        # with nothing saying so. Staying lenient keeps stale bookmarks and
        # hand-edited URLs working (a 400 would break them); surfacing it is
        # what stops the page lying about what it is showing.
        dropped_filters: list[str] = []
        if pattern_type is not None and pattern_type not in _WATCHLIST_PATTERN_TYPES:
            dropped_filters.append(f"pattern type {pattern_type!r}")
            pattern_type = None
        pt_clean = pattern_type or None
        if dropped_filters:
            # No page to carry a notice on, so the export must not be silent
            # either: a CSV that quietly contains every row is worse than the
            # HTML page, because it gets archived and cited later.
            logger.warning(
                "/watchlist.csv ignoring unrecognised filter(s): %s -- exporting "
                "ALL matching rows",
                ", ".join(dropped_filters),
            )

        if severity is not None and severity not in ("low", "med", "high"):
            severity = None
        sev_clean = severity or None

        device_category_options = db.distinct_watchlist_device_categories()
        if device_category is not None and device_category != "":
            if device_category not in (
                _WATCHLIST_UNCATEGORIZED_SENTINEL,
                *device_category_options,
            ):
                device_category = None
        dc_clean = device_category or None

        header = [
            "id",
            "pattern",
            "pattern_type",
            "severity",
            "description",
            "mac_range_prefix",
            "mac_range_prefix_length",
            "argus_record_id",
            "device_category",
            "confidence",
            "vendor",
            "source",
            "source_url",
            "source_excerpt",
            "fcc_id",
            "geographic_scope",
            "first_seen_iso_utc",
            "first_seen_unix",
            "last_verified_iso_utc",
            "last_verified_unix",
            "notes",
            # ⭐ APPENDED, never inserted. This export is for offline triage, so
            # a consumer reading columns positionally must keep working; a new
            # column at the end is additive, one in the middle is a silent
            # data-corruption bug in somebody's spreadsheet.
            #
            # It answers the same question the pages now answer: an operator
            # exporting their watchlist to review it was getting the identical
            # silent lie the UI no longer tells.
            # Values: yes / no / snoozed / unknown. TYPE-level only.
            "can_fire",
            # ⭐ Its own column, not a fifth `can_fire` value: this cause is
            # per-ROW and INDEPENDENT of the type-level verdict, so a row can
            # carry both and one enum cannot say so. Values: yes / no.
            "override_suppressed",
            # ⭐ Its own column for the same reason `override_suppressed` has
            # one, and `_can_fire`'s docstring had already written the rule down
            # while the enum went on breaking it: a row can be inert AND
            # snoozed, `can_fire` reports whichever check ran first, and an
            # operator told `no` fixes rules.yaml and still hears nothing.
            # Values: yes / no / unknown.
            #
            # ⚠️ `can_fire == "snoozed"` still implies `type_snoozed == "yes"`.
            # That redundancy is deliberate: changing `can_fire`'s value set
            # would break consumers to fix a hole an additive column closes.
            "type_snoozed",
            # ⭐ Finding 42, and APPENDED for the same reason as the two above.
            # `severity` is what the importer baked in; this is what the runtime
            # layer will actually send. They differ whenever a remap axis
            # matches the row -- and this export exists for offline triage,
            # which is sorting by severity.
            #
            # ⚠️ EMPTY for a suppressed row, not the remapped value. A
            # suppressed row produces no alert, so it has no severity to
            # receive; `override_suppressed=yes` is the column that says why.
            # Writing a severity there would invite exactly the misreading this
            # column exists to fix.
            "effective_severity",
            # ⭐ The fifth silencing mechanism, for the rows where it has one
            # answer. Values: yes / no / n/a.
            #
            # ⛔ `n/a` is "not evaluated for this row shape", and it is neither
            # a hedge nor a `no`. A row that can match many devices (oui,
            # mac_range, ssid, ...) may have none, some or all of them
            # allowlisted, and nothing here checks which -- so any yes/no would
            # be a claim about a set nobody enumerated.
            #
            # 🪤 An earlier version of this comment asserted such a row HAS
            # "some allowlisted and some not". That is a mixture the code never
            # established either; a cold read caught it. The honest statement is
            # about what was not evaluated, not about what the set contains.
            "allowlist_suppressed",
        ]

        def _iso_utc(ts) -> str:
            if ts is None:
                return ""
            return _dt.datetime.fromtimestamp(int(ts), tz=_dt.UTC).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )

        # Computed ONCE, outside the generator: this route streams, and a
        # per-row lookup would re-parse rules.yaml for every exported entry.
        csv_liveness = watchlist_liveness(
            app.state.config,
            db.watchlist_pattern_type_counts(),
            db=db,
            now_ts=render_now_ts,
        )
        csv_overrides = load_overrides(app.state.config)
        csv_suppressions = suppression_axes_of(csv_overrides)
        # Loaded ONCE for the whole export rather than per row: this route
        # streams, and a per-row load would re-parse the allowlist YAML for
        # every one of a 17k-row watchlist.
        csv_allowlist = _merged_allowlist_entries(app.state.config)
        csv_now = render_now_ts

        def _allowlist_suppressed(pattern_type: str, pattern: str) -> str:
            if not allowlist_answerable_for(pattern_type) or not pattern:
                return "n/a"
            return "yes" if _match_mac_in_entries(csv_allowlist, pattern, csv_now) else "no"

        def _can_fire(pattern_type: str) -> str:
            """The TYPE-level verdict: no = fix rules.yaml, snoozed = lift it
            on /rules, unknown = the question could not be answered, yes = a
            rule consults this type.

            ⛔ Deliberately does NOT fold in the per-row override cause. A
            single enum cannot carry two INDEPENDENT causes: an entry can be
            inert AND override-suppressed, and whichever check ran first would
            hide the other -- so an operator told "no" would fix rules.yaml and
            still hear nothing. `override_suppressed` is its own column for
            exactly that reason.

            🪤 An earlier version of this column DID answer from the type-level
            verdict alone and reported `yes` for an override-silenced row; the
            first fix then made `override` a fifth enum value, which traded one
            wrong answer for a different one. A cold read caught the second.
            """
            if not csv_liveness["known"]:
                return "unknown"
            if pattern_type in csv_liveness["inert_types"]:
                return "no"
            if pattern_type in csv_liveness["suppressed_types"]:
                return "snoozed"
            return "yes"

        def _type_snoozed(pattern_type: str) -> str:
            """The snooze flag, INDEPENDENT of the verdict above.

            ⛔ `_can_fire` answers `no` for a type that is inert AND snoozed,
            because inert is checked first — so the snooze disappeared from the
            export entirely and an operator acting on `no` would edit
            `rules.yaml` and still hear nothing. That is exactly the failure
            `_can_fire`'s own docstring describes for the override cause; the
            same fix applies here.
            """
            if not csv_liveness["known"]:
                return "unknown"
            return "yes" if pattern_type in csv_liveness["suppressed_types"] else "no"

        def _row_generator():
            buf = io.StringIO()
            writer = csv.writer(buf, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")
            writer.writerow(header)
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate(0)
            for row in db.iter_watchlist_filtered(
                q=q_clean,
                pattern_type=pt_clean,
                severity=sev_clean,
                device_category=dc_clean,
            ):
                writer.writerow(
                    [
                        row["id"],
                        row.get("pattern") or "",
                        row.get("pattern_type") or "",
                        row.get("severity") or "",
                        row.get("description") or "",
                        row.get("mac_range_prefix") or "",
                        row.get("mac_range_prefix_length")
                        if row.get("mac_range_prefix_length") is not None
                        else "",
                        row.get("argus_record_id") or "",
                        row.get("device_category") or "",
                        row.get("confidence") if row.get("confidence") is not None else "",
                        row.get("vendor") or "",
                        row.get("source") or "",
                        row.get("source_url") or "",
                        row.get("source_excerpt") or "",
                        row.get("fcc_id") or "",
                        row.get("geographic_scope") or "",
                        _iso_utc(row.get("first_seen")),
                        row.get("first_seen") if row.get("first_seen") is not None else "",
                        _iso_utc(row.get("last_verified")),
                        row.get("last_verified") if row.get("last_verified") is not None else "",
                        row.get("notes") or "",
                        _can_fire(row.get("pattern_type") or ""),
                        "yes"
                        if is_row_suppressed_by_overrides(
                            row.get("vendor"),
                            row.get("device_category"),
                            csv_suppressions,
                        )
                        else "no",
                        _type_snoozed(row.get("pattern_type") or ""),
                        effective_severity(
                            row.get("severity") or "",
                            row.get("vendor"),
                            row.get("device_category"),
                            row.get("argus_record_id"),
                            csv_suppressions,
                            csv_overrides,
                        )
                        or "",
                        _allowlist_suppressed(
                            row.get("pattern_type") or "", row.get("pattern") or ""
                        ),
                    ]
                )
                yield buf.getvalue()
                buf.seek(0)
                buf.truncate(0)

        ts_now = _dt.datetime.fromtimestamp(render_now_ts, tz=_dt.UTC).strftime(
            "%Y%m%dT%H%M%SZ"
        )
        filename = f"watchlist-{ts_now}.csv"
        return StreamingResponse(
            _row_generator(),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.get("/watchlist/{watchlist_id}", response_class=HTMLResponse)
    def watchlist_detail(request: Request, watchlist_id: RowId):
        render_now_ts = int(time.time())
        # ⛔ ONE clock read per render, threaded into every consumer.
        # Two independent reads let the SAME row be classified twice from
        # two instants. Measured here: with an allowlist entry expiring
        # between them the page rendered `entry_can_alert=False` beside
        # `allowlist_entries=[]` -- "cannot alert because it is
        # allowlisted", with nothing shown suppressing it. Neither
        # consistent state produces that pair.
        if watchlist_id < 1:
            raise HTTPException(status_code=400, detail="watchlist_id must be positive")
        row = db.get_watchlist_with_metadata(watchlist_id)
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
        # The detail page is where an operator lands from an alert-less hunt
        # ("I added this, why have I heard nothing?"), so it carries the fuller
        # explanation rather than the list page's one-word badge.
        liveness = watchlist_liveness(
            app.state.config,
            db.watchlist_pattern_type_counts(),
            db=db,
            now_ts=render_now_ts,
        )
        # Read once; the suppression axes and the severity remap are two
        # questions about the same file.
        overrides = load_overrides(app.state.config)
        suppressions = suppression_axes_of(overrides)
        return app.state.templates.TemplateResponse(
            request=request,
            name="watchlist_detail.html",
            context={
                "version": __version__,
                "active": "watchlist",
                "entry": entry,
                "has_metadata": has_metadata,
                "metadata": metadata,
                "liveness": liveness,
                "entry_is_live": is_pattern_type_live(entry["pattern_type"], liveness),
                "entry_is_snoozed": is_pattern_type_snoozed(
                    entry["pattern_type"], liveness
                ),
                # The rule_type an operator actually has a button for on
                # /rules -- not the pattern_type, which is a different name.
                "entry_rule_types": serving_rule_types(entry["pattern_type"]),
                # ⭐ Finding 42, with the axis and the key named: this page is
                # where an operator lands asking why an alert did not look the
                # way they expected, so it carries the cause rather than the
                # list page's marker.
                "severity_remap": severity_remap(
                    entry["severity"],
                    row.get("vendor"),
                    row.get("device_category"),
                    row.get("argus_record_id"),
                    suppressions,
                    overrides,
                ),
                "override_suppression_axes": override_suppression_axes(
                    row.get("vendor"),
                    row.get("device_category"),
                    suppressions,
                ),
                # ⚠️ Whether ANY cause on this page stops the row alerting at
                # all. The remap block used to say "an alert will actually
                # carry X" beside "this entry cannot currently fire" — two
                # sentences about one row, one of which had to be false. The
                # remap is still worth showing (it decides the severity the
                # moment the other blocker is lifted); it just cannot be
                # phrased as something that happens today.
                #
                # ⛔ THREE-VALUED, and the third value is not decoration.
                # `is_pattern_type_live` returns True when the ruleset verdict
                # is UNKNOWN — deliberately, so an unreadable rules file cannot
                # mark every row inert. That benefit of the doubt then arrived
                # here as a `True` and the page turned it into a present-tense
                # promise: with a rules file that would not parse, /watchlist/1
                # said "This entry alerts at a different severity" and named
                # what an alert "will actually carry", while /settings one
                # click away correctly said the verdict could not be read.
                # Measured at cca7c5c.
                #
                # ⚠️ Collapsing it to False would be the opposite lie: the
                # else-branch says the row "produces none today, for the reason
                # given elsewhere on this page", and under an unknown verdict
                # there IS no reason elsewhere on the page. Unknown reads as
                # unknown — the rule this module already follows for the
                # inert/live verdict itself.
                #
                # ⭐ A DEFINITE blocker still wins outright. A snooze, an
                # override suppression, a reserved OUI or an allowlist match
                # are all established without reading the ruleset, so a row
                # carrying one is a plain False even when the verdict is
                # unknown — which is what keeps `entry_can_alert is False`
                # meaning "something on this page is suppressing it" for
                # test_webui_one_clock_read.
                "entry_can_alert": _entry_can_alert(
                    entry,
                    row,
                    liveness,
                    suppressions,
                    _merged_allowlist_entries(app.state.config),
                    render_now_ts,
                ),
                "oui_never_matches_reason": oui_prefix_never_matches(
                    row.get("pattern_type"), row.get("pattern")
                ),
                # ⭐ EVERY covering entry, not the first. A MAC can be covered
                # by an exact entry and an `oui` entry at once, and removing the
                # one named would leave the other suppressing it -- the same
                # defect #116 fixed for the override axes, in a new place.
                "allowlist_entries": (
                    _match_all_mac_in_entries(
                        _merged_allowlist_entries(app.state.config),
                        row["pattern"],
                        render_now_ts,
                    )
                    if allowlist_answerable_for(row.get("pattern_type") or "")
                    and row.get("pattern")
                    else []
                ),
            },
        )

    @app.get("/settings", response_class=HTMLResponse)
    def settings_view(request: Request):
        now = time.time()
        kismet_status = _get_kismet_status(app, now)
        ctx = _build_settings_context(
            app.state.config, db, kismet_status, app.state.config_path
        )
        return app.state.templates.TemplateResponse(
            request=request,
            name="settings.html",
            context={
                "version": __version__,
                "active": "settings",
                **ctx,
            },
        )

    def _render_allowlist(
        request: Request,
        *,
        q: str | None,
        source: str,
        status: str,
        type_: str,
        page: str | None = None,
        page_size: str | None = None,
        success: str | None = None,
        count: int | None = None,
        add_form: dict | None = None,
        add_error: str | None = None,
        http_status: int = 200,
    ) -> HTMLResponse:
        """Shared renderer for /allowlist and the add-form error path.

        Loads the merged primary+UI allowlist, applies filters
        server-side, then slices into a paginated window via the
        shared PaginationParams helper. The add-form error path
        re-renders the same page with ``add_form`` / ``add_error``
        populated so the operator's input survives the round-trip
        — filters are reset on the error render so the operator can
        see the full current state alongside their rejected input.
        """
        allowlist_path = app.state.config.allowlist_path
        notice: str | None = None
        filtered_rows: list[dict] = []
        primary_count = 0
        ui_count = 0
        configured = bool(allowlist_path)
        clock_disagreements: list[ImpossibleUiEntry] = []
        if not configured:
            notice = "No allowlist_path configured. Set allowlist_path in lynceus.yaml."
        else:
            try:
                tagged = load_allowlist_with_source(allowlist_path)
            except FileNotFoundError:
                notice = f"Allowlist file not found at {allowlist_path}."
                tagged = []
            primary_count = sum(1 for _, src in tagged if src == "primary")
            ui_count = sum(1 for _, src in tagged if src == "ui")
            # ⛔ ONE clock read, threaded into both consumers below. It used
            # to be two independent `int(time.time())` calls, and a render
            # straddling a second boundary gave the SAME ROW opposite verdicts:
            # the table labelled it `snoozed` (live) while the banner called it
            # an expired suppression that disagrees. Reproduced deterministically
            # by returning `T - epsilon` then `T + epsilon`. That is the Finding
            # 45 class -- two surfaces naming contradictory causes for one row --
            # and the cause here is simply reading the clock twice.
            render_now_ts = int(time.time())
            filtered_rows = _filter_allowlist_entries(
                tagged,
                q=q,
                source=source,
                status=status,
                type_=type_,
                now_ts=render_now_ts,
            )
            # ⛔ Reported on the UNFILTERED file, deliberately. The evidence is
            # an ORDERING fact between two entries, so a filter that hides
            # either half would silently change the verdict -- an operator
            # searching for one MAC would be told their clock was fine.
            #
            # ⚠️ Read from disk rather than derived from `tagged`:
            # `load_allowlist_with_source` merges primary and UI entries, and
            # the discriminator is only valid within the UI file's own append
            # order. A merged list is not that order.
            clock_disagreements = find_impossible_ui_entries(
                derive_ui_path(Path(allowlist_path)), render_now_ts
            )

        # Pagination is applied in Python on the already-filtered list
        # rather than via SQL because the allowlist sits in YAML on
        # disk, not a DB table. The same PaginationParams helper used
        # by /alerts handles the math identically.
        requested_page, per_page = parse_pagination(
            page,
            page_size,
            allowed_per_page=_ALLOWLIST_PER_PAGE_ALLOWED,
            default_per_page=_ALLOWLIST_PER_PAGE_DEFAULT,
        )
        total = len(filtered_rows)
        pagination = build_pagination(requested_page, per_page, total)
        page_rows = filtered_rows[pagination.offset : pagination.offset + pagination.per_page]

        filters_active = bool(
            (q and q.strip())
            or source != "all"
            or status != "all"
            or type_ != "all"
        )
        return app.state.templates.TemplateResponse(
            request=request,
            name="allowlist_list.html",
            status_code=http_status,
            context={
                "version": __version__,
                "active": "allowlist",
                "notice": notice,
                "configured": configured,
                # allowlist_path is threaded through so the empty-state
                # instructions can show the operator exactly which file
                # they're editing. ``None`` when allowlist_path is unset
                # (legacy installs pre-Tier 1 scaffold); the template's
                # configured-branch guard prevents the value from
                # rendering in that case.
                "allowlist_path": allowlist_path,
                "entries": page_rows,
                "clock_disagreements": clock_disagreements,
                "primary_count": primary_count,
                "ui_count": ui_count,
                "filters": {
                    "q": q or "",
                    "source": source,
                    "status": status,
                    "type": type_,
                },
                "filters_active": filters_active,
                "supported_pattern_types": ALLOWLIST_PATTERN_TYPES,
                "success": success,
                "success_count": count,
                "add_form": add_form or {},
                "add_error": add_error,
                "pagination": pagination,
                "per_page_options": _ALLOWLIST_PER_PAGE_ALLOWED,
            },
        )

    @app.get("/allowlist", response_class=HTMLResponse)
    def allowlist_view(
        request: Request,
        q: str | None = Query(default=None),
        source: str = Query(default="all"),
        status: str = Query(default="all"),
        type: str = Query(default="all"),
        page: str | None = Query(default=None),
        page_size: str | None = Query(default=None),
        success: str | None = Query(default=None),
        count: int | None = Query(default=None),
    ):
        _validate_allowlist_filters(source=source, status=status, type_=type)
        return _render_allowlist(
            request,
            q=q,
            source=source,
            status=status,
            type_=type,
            page=page,
            page_size=page_size,
            success=success,
            count=count,
        )

    @app.post("/allowlist/add")
    def allowlist_add(
        request: Request,
        pattern: str = Form(default=""),
        pattern_type: str = Form(default=""),
        note: str | None = Form(default=None),
        expires_at: str | None = Form(default=None),
    ):
        if not app.state.config.allowlist_path:
            raise HTTPException(
                status_code=400,
                detail="allowlist_path is not configured; nothing to write to",
            )
        echo = {
            "pattern": pattern,
            "pattern_type": pattern_type,
            "note": note or "",
            "expires_at": expires_at or "",
        }
        pattern_stripped = pattern.strip()
        if not pattern_stripped:
            return _render_allowlist(
                request,
                q=None, source="all", status="all", type_="all",
                add_form=echo,
                add_error="pattern is required.",
                http_status=400,
            )
        if pattern_type not in ALLOWLIST_PATTERN_TYPES:
            return _render_allowlist(
                request,
                q=None, source="all", status="all", type_="all",
                add_form=echo,
                add_error=f"invalid pattern_type: {pattern_type!r}.",
                http_status=400,
            )
        try:
            expires_int = _parse_form_expires_at(expires_at)
        except ValueError as exc:
            return _render_allowlist(
                request,
                q=None, source="all", status="all", type_="all",
                add_form=echo,
                add_error=str(exc),
                http_status=400,
            )
        note_clean = (note or "").strip() or None
        if note_clean is not None and len(note_clean) > 500:
            return _render_allowlist(
                request,
                q=None, source="all", status="all", type_="all",
                add_form=echo,
                add_error="note must be 500 characters or fewer.",
                http_status=400,
            )
        try:
            entry = AllowlistEntry(
                pattern=pattern_stripped,
                pattern_type=pattern_type,
                note=note_clean,
                expires_at=expires_int,
                added_at=int(time.time()),
            )
        except ValidationError as exc:
            return _render_allowlist(
                request,
                q=None, source="all", status="all", type_="all",
                add_form=echo,
                add_error=_first_validation_error(exc),
                http_status=400,
            )
        ui_path = derive_ui_path(Path(app.state.config.allowlist_path))
        add_ui_entry(ui_path, entry)
        actor = request.client.host if request.client else "unknown"
        logger.info(
            "allowlist UI add: actor=%s pattern_type=%s pattern=%s expires_at=%s",
            actor, entry.pattern_type, entry.pattern, entry.expires_at,
        )
        return RedirectResponse("/allowlist?success=add", status_code=303)

    @app.post("/allowlist/bulk_remove")
    def allowlist_bulk_remove(
        request: Request,
        entry_keys: list[str] | None = Form(default=None),
        q: str | None = Form(default=None),
        source: str = Form(default="all"),
        status: str = Form(default="all"),
        type: str = Form(default="all"),
    ):
        if not app.state.config.allowlist_path:
            raise HTTPException(
                status_code=400,
                detail="allowlist_path is not configured; nothing to write to",
            )
        if not entry_keys:
            raise HTTPException(
                status_code=400,
                detail="no entries selected for bulk remove",
            )
        keys: list[tuple[str, str]] = []
        for ek in entry_keys:
            ptype, sep, pat = ek.partition(":")
            if not sep or not ptype or not pat:
                raise HTTPException(
                    status_code=400,
                    detail=f"malformed entry_key: {ek!r}",
                )
            keys.append((pat, ptype))
        try:
            tagged = load_allowlist_with_source(app.state.config.allowlist_path)
        except FileNotFoundError:
            raise HTTPException(
                status_code=400,
                detail="allowlist primary file not found",
            ) from None
        primary_pairs = {(e.pattern, e.pattern_type) for e, src in tagged if src == "primary"}
        primary_collisions = [k for k in keys if k in primary_pairs]
        if primary_collisions:
            # No partial removes. Either every selection is UI-removable
            # or the whole batch fails — otherwise an operator who
            # crafted a hostile form (or hit a stale row that moved into
            # the primary file mid-session) would silently delete the UI
            # rows and only learn about the primary refusal in the error
            # message, by which point the UI rows are gone.
            raise HTTPException(
                status_code=400,
                detail=(
                    f"refusing to bulk-remove {len(primary_collisions)} "
                    "operator-managed (primary-file) entries via the UI; "
                    "edit allowlist.yaml directly to remove those rows."
                ),
            )
        ui_path = derive_ui_path(Path(app.state.config.allowlist_path))
        removed = bulk_remove_ui_entries(ui_path, keys)
        actor = request.client.host if request.client else "unknown"
        logger.info(
            "allowlist UI bulk_remove: actor=%s removed=%d requested=%d",
            actor, removed, len(keys),
        )
        params: dict[str, str] = {}
        if q and q.strip():
            params["q"] = q
        if source != "all":
            params["source"] = source
        if status != "all":
            params["status"] = status
        if type != "all":
            params["type"] = type
        params["success"] = "bulk_remove"
        params["count"] = str(removed)
        from urllib.parse import urlencode as _urlencode
        return RedirectResponse(
            f"/allowlist?{_urlencode(params)}",
            status_code=303,
        )

    return app
