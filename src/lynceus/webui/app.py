"""Lynceus read-only web UI. FastAPI app factory."""

from __future__ import annotations

import datetime as _dt
import importlib.metadata
import json
import logging
import math
import time
from math import ceil
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError

from lynceus import __version__, kismet, paths
from typing import get_args as _typing_get_args

from lynceus import allowlist as allowlist_mod
from lynceus import rules as rules_mod
from lynceus.allowlist import (
    AllowlistEntry,
    add_ui_entry,
    bulk_remove_ui_entries,
    derive_ui_path,
    load_allowlist_with_source,
    remove_ui_entry,
)
from lynceus.config import Config
from lynceus.db import Database, RuleStats, WatchfulRecurrence
from lynceus.redact import redact_ntfy_topic
from lynceus.webui.csrf import CSRFMiddleware, get_csrf_token
from lynceus.webui.pagination import build_pagination, parse_pagination

# Fixed snooze duration. Custom durations are intentionally out of scope —
# operators wanting a non-24h window edit allowlist.yaml directly.
SNOOZE_DEFAULT_SECONDS = 86400

logger = logging.getLogger(__name__)

PACKAGE = "lynceus.webui"

KISMET_STATUS_CACHE_TTL = 30


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


def _total_pages(total_count: int, page_size: int) -> int:
    if total_count <= 0:
        return 1
    return max(1, ceil(total_count / page_size))


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

# Pattern_type filter options for /watchlist. All 7 currently-
# supported types -- migration 013 expanded the v0.3 set to admit
# ble_manufacturer_id and drone_id_prefix, so the dropdown enumerates
# every type an Argus import or yaml seed can produce.
_WATCHLIST_PATTERN_TYPES: tuple[str, ...] = (
    "mac",
    "oui",
    "ssid",
    "ble_uuid",
    "mac_range",
    "ble_manufacturer_id",
    "drone_id_prefix",
)

# Sentinel for the "(uncategorized)" device_category dropdown option
# -- mirrors Database._WATCHLIST_UNCATEGORIZED_SENTINEL. Surfacing
# it as a constant here keeps the template / route / DB layer in
# lockstep.
_WATCHLIST_UNCATEGORIZED_SENTINEL: str = "__none__"


def _parse_date_to_ts(value: str, *, end_of_day: bool, name: str) -> int:
    try:
        d = _dt.date.fromisoformat(value)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=400, detail=f"invalid {name}: {value!r}") from exc
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


def unix_to_iso(ts) -> str:
    """Format a unix epoch int as ISO 8601 UTC with 'Z' suffix.

    None/empty → "" so templates can render the value unconditionally.
    """
    if ts is None or ts == "":
        return ""
    dt = _dt.datetime.fromtimestamp(int(ts), tz=_dt.UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def unix_to_utc_human(ts) -> str:
    """Format a unix epoch int as 'YYYY-MM-DD HH:MM UTC' for human display."""
    if ts is None or ts == "":
        return ""
    dt = _dt.datetime.fromtimestamp(int(ts), tz=_dt.UTC)
    return dt.strftime("%Y-%m-%d %H:%M UTC")


def relative_time(ts, *, now_ts: int | None = None) -> str:
    """Format a unix epoch int as a human-readable relative time.

    Buckets: <60s → "just now"; <60min → "{N}m ago"; <24h →
    "{N}h ago"; else → "{N}d ago". Future timestamps (ts > now_ts)
    collapse to "just now" rather than negative output — defensive
    against clock skew on the operator's machine vs the DB's
    timestamps. None / empty → "—" (the column placeholder).

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
    if delta < 60:
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


def _device_label(device: dict | None) -> str:
    """Best-available human label for a device.

    Priority: friendly_name (BLE/BT advertised name, v0.3+) → oui_vendor
    (Kismet manuf, v0.2) → "—". Forward-compatible: a v0.2 dict without
    the friendly_name key falls through to oui_vendor naturally."""
    if not device:
        return "—"
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
      the badge color. ``"unknown"`` only when ``has_import`` is
      False.
    - ``imported_at`` / ``exported_at``: int UTC seconds, or None.
      Rendered via the existing ``unix_to_utc_human`` Jinja filter.
    - ``age_days``: int days computed against ``exported_at`` when
      present, else ``imported_at``. Identical fallback rule to the
      log line — both surfaces must agree.
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
    reference_ts = latest["exported_at"] or latest["imported_at"]
    age_days = max(0, (now_ts - int(reference_ts)) // 86400)
    return {
        "has_import": True,
        "status": "stale" if age_days > warn_days else "fresh",
        "imported_at": int(latest["imported_at"]),
        "exported_at": (
            int(latest["exported_at"]) if latest["exported_at"] is not None else None
        ),
        "age_days": age_days,
        "source": latest["source"],
        "record_count": (
            int(latest["record_count"]) if latest["record_count"] is not None else None
        ),
        "pattern_type_counts": pattern_type_counts,
        "warn_days": warn_days,
    }


def _build_settings_context(config: Config, db: Database, kismet_status: dict) -> dict:
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

    overrides_path = paths.default_overrides_path("user")
    config_path_default = paths.default_config_path("user")
    log_dir_default = paths.default_log_dir("user")

    try:
        lynceus_version = importlib.metadata.version("lynceus")
    except importlib.metadata.PackageNotFoundError:
        lynceus_version = __version__

    return {
        "capture": {
            "probe_ssids": bool(config.capture.probe_ssids),
            "ble_friendly_names": bool(config.capture.ble_friendly_names),
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
        },
        "watchlist_stats": _watchlist_origin_breakdown(db),
        "watchlist_freshness": _watchlist_freshness_card(
            db,
            config.watchlist_staleness_warn_days,
            now_ts=int(time.time()),
        ),
        "severity_overrides": {
            "path": str(overrides_path),
            "exists": overrides_path.exists(),
        },
        "system": {
            "lynceus_version": lynceus_version,
            "db_path": str(db_path),
            "db_size_human": db_size_human,
            "db_mtime": db_mtime,
            "config_path": str(config_path_default),
            "log_dir": str(log_dir_default),
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
    lookup. Only MAC and OUI matches are considered: alerts do not carry
    live SSID context, so an ``ssid``-type allowlist entry could not be
    correctly evaluated against an alert without re-fetching the device's
    last-known SSID — and the operator-intent of an SSID allowlist is
    "this network", not "this device", so silently mis-attributing a
    suppression that way would be worse than not matching at all.
    Expired entries are skipped, mirroring poll-time semantics.
    """
    for entry in entries:
        if entry.expires_at is not None and entry.expires_at <= now_ts:
            continue
        if entry.pattern_type == "mac" and entry.pattern == mac:
            return entry
        if entry.pattern_type == "oui" and mac.startswith(entry.pattern + ":"):
            return entry
    return None


def _resolve_allowlist_match(
    config: Config,
    alert_mac: str | None,
    now_ts: int,
) -> tuple[AllowlistEntry | None, bool, bool]:
    """Look up the alert's MAC across both allowlist files.

    Returns ``(match, removable, configured)``:

    - ``match``: the matched ``AllowlistEntry``, or ``None``.
    - ``removable``: True only when the match came from the daemon-managed
      UI sibling. Primary-file entries are operator-curated; the daemon
      never writes to ``allowlist.yaml``, so the UI cannot remove them.
      The triage section renders status without a button in that case
      with a hint to edit the primary file directly.
    - ``configured``: True when ``config.allowlist_path`` is set. When
      False, the triage section is hidden entirely, parity with the
      /allowlist read-only view.

    Both files are read per request — same convention as the /allowlist
    read-only view. No caching: edits land instantly without invalidation.
    """
    if not config.allowlist_path or alert_mac is None:
        return None, False, bool(config.allowlist_path)
    primary_path = Path(config.allowlist_path)
    try:
        primary_entries = allowlist_mod._load_primary(primary_path).entries
    except FileNotFoundError:
        primary_entries = []
    ui_entries = allowlist_mod._load_ui_entries(derive_ui_path(primary_path))
    primary_match = _match_mac_in_entries(primary_entries, alert_mac, now_ts)
    if primary_match is not None:
        return primary_match, False, True
    ui_match = _match_mac_in_entries(ui_entries, alert_mac, now_ts)
    if ui_match is not None:
        return ui_match, True, True
    return None, False, True


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


def _check_db(db: Database) -> dict:
    """Return ``{"status": "ok", "detail": None}`` on a healthy connection,
    or ``{"status": "error", "detail": "<exception>"}`` when the connection
    is dead. The minimal ``SELECT 1`` round-trip is the fastest way to
    confirm the SQLite file is open + the connection alive without paying
    for any COUNT scans."""
    try:
        db._conn.execute("SELECT 1").fetchone()
    except Exception as exc:  # noqa: BLE001 — surface the actual driver error
        return {"status": "error", "detail": str(exc)}
    return {"status": "ok", "detail": None}


def _check_poller(db: Database, *, now_ts: int) -> dict:
    """Two daemon-liveness signals, both index-backed single-row lookups:

    - ``last_poll_at`` — from ``poller_state.last_poll_ts`` (written by the
      daemon every poll tick, regardless of whether Kismet returned any
      devices). Proxies "daemon process alive".
    - ``last_observation_at`` — ``MAX(sightings.ts)``. Proxies "Kismet is
      returning device data".

    Monitoring tools apply their own thresholds (the prompt's stability
    commitment is to the keys, not to interpretation)."""
    last_poll_at = db.latest_poll_ts()
    row = db._conn.execute("SELECT MAX(ts) FROM sightings").fetchone()
    last_observation_at = row[0] if row and row[0] is not None else None

    def _delta(value: int | None) -> int | None:
        return (now_ts - int(value)) if value is not None else None

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
        imported_at = int(latest["imported_at"])
        last_imported_at_iso: str | None = unix_to_iso(imported_at) or None
        days_since_import: int | None = max(0, (now_ts - imported_at) // 86400)
    else:
        last_imported_at_iso = None
        days_since_import = None
    stale = bool(
        days_since_import is not None
        and days_since_import > config.watchlist_staleness_warn_days
    )
    return {
        "status": "ok",
        "total_rows": int(total_rows),
        "by_pattern_type": {k: int(v) for k, v in by_pattern_type.items()},
        "last_imported_at": last_imported_at_iso,
        "days_since_import": days_since_import,
        "stale": stale,
    }


def _check_ruleset(config: Config) -> dict:
    """Loads ``rules.yaml`` on each call (cheap — the file is small and
    operators rarely poll /healthz.json at sub-second cadence). When the
    loader raises (missing file, parse error, validation error), the
    check stays ``status: ok`` per the prompt's contract — only the DB
    check controls top-level status. ``active_rules`` falls to 0 so the
    monitoring tool can see the file is broken via a separate signal
    (a non-zero ``rules_path_configured`` paired with zero
    ``active_rules`` is the canonical "wired but broken" pattern)."""
    if not config.rules_path:
        return {
            "status": "ok",
            "active_rules": 0,
            "rules_path_configured": False,
        }
    try:
        ruleset = rules_mod.load_ruleset(config.rules_path)
        active = sum(1 for r in ruleset.rules if r.enabled)
    except Exception as exc:  # noqa: BLE001 — broken-but-configured is observable
        logger.warning(
            "/healthz.json: rules_path=%r failed to load (%s); "
            "reporting active_rules=0",
            config.rules_path,
            exc,
        )
        active = 0
    return {
        "status": "ok",
        "active_rules": int(active),
        "rules_path_configured": True,
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


def create_app(config: Config, db: Database) -> FastAPI:
    """App factory. Takes a live Config and Database. Used by both the production
    server entry point and the test client. Does NOT open the DB itself — that's the
    caller's responsibility, so tests can inject an in-memory or tmp_path DB."""

    app = FastAPI(
        title="lynceus",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    app.state.db = db
    app.state.config = config
    app.state.templates = Jinja2Templates(directory=str(_resolve_templates_dir()))
    app.state.templates.env.globals["csrf_token"] = lambda request: get_csrf_token(request)
    app.state.templates.env.filters["unix_to_iso"] = unix_to_iso
    app.state.templates.env.filters["unix_to_utc_human"] = unix_to_utc_human
    app.state.templates.env.filters["device_label"] = _device_label
    app.state.templates.env.filters["relative_time"] = relative_time

    app.mount(
        "/static",
        StaticFiles(directory=str(_resolve_static_dir())),
        name="static",
    )

    cookie_secure = bool(config.ui_allow_remote)
    app.add_middleware(CSRFMiddleware, cookie_secure=cookie_secure)

    @app.get("/healthz", response_class=HTMLResponse)
    async def healthz(request: Request):
        health = db.healthcheck()
        return app.state.templates.TemplateResponse(
            request=request,
            name="healthz.html",
            context={"health": health, "version": __version__},
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
        checks = {
            "db": db_check,
            "poller": _check_poller(db, now_ts=now_ts),
            "watchlist": _check_watchlist(db, config, now_ts=now_ts),
            "ruleset": _check_ruleset(config),
            "alerts": _check_alerts(db, now_ts=now_ts),
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
        return app.state.templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "version": __version__,
                "active": "home",
                "health": db.healthcheck(),
                "sev_24h": db.alert_severity_counts(since_ts=now_int - 86400),
                "sev_7d": db.alert_severity_counts(since_ts=now_int - 7 * 86400),
                "sev_30d": db.alert_severity_counts(since_ts=now_int - 30 * 86400),
                "per_day": db.alerts_per_day(days=30, now_ts=now_int),
                "recent_alerts": recent_alerts,
                "recent_devices": db.list_devices(limit=10),
                "device_seen": db.device_seen_counts(now_ts=now_int),
                "last_poll": db.latest_poll_ts(),
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
        since_ts = (
            _parse_date_to_ts(since, end_of_day=False, name="since") if since else None
        )
        until_ts = (
            _parse_date_to_ts(until, end_of_day=True, name="until") if until else None
        )
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
                "has_note": has_note or "all",
                "rule_types": _ALERTS_RULE_TYPES,
                "per_page_options": _ALERTS_PER_PAGE_ALLOWED,
                "window_options": tuple(_ALERTS_WINDOW_SECONDS.keys()),
                "has_note_options": _ALERTS_HAS_NOTE_VALUES,
                "filters_active": filters_active,
            },
        )

    @app.get("/alerts/{alert_id}", response_class=HTMLResponse)
    def alert_detail(
        request: Request,
        alert_id: int,
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
        allowlist_match, allowlist_match_removable, allowlist_configured = (
            _resolve_allowlist_match(app.state.config, alert.get("mac"), now_ts)
        )
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
                "allowlist_configured": allowlist_configured,
                "snooze_hours_remaining": snooze_hours_remaining,
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
        note: str | None = Form(default=None),
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
        since_ts = _parse_date_to_ts(since, end_of_day=False, name="since") if since else None
        until_ts = _parse_date_to_ts(until, end_of_day=True, name="until") if until else None
        search_clean = search if search else None
        q_clean = q if q else None
        note = _normalize_optional_note(note)

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
            until_ts=until_ts,
            search=search_clean,
            rule_type=rule_type_for_db,
            q=q_clean,
            has_note=has_note_for_db,
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
            until_ts=until_ts,
            search=search_clean,
            rule_type=rule_type_for_db,
            q=q_clean,
            has_note=has_note_for_db,
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

    @app.post("/alerts/{alert_id}/ack")
    def ack_alert(
        request: Request,
        alert_id: int,
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
        target = _safe_redirect_target(request, default="/alerts")
        return RedirectResponse(target, status_code=303)

    @app.post("/alerts/{alert_id}/unack")
    def unack_alert(
        request: Request,
        alert_id: int,
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

    def _write_ui_allowlist(alert: dict, *, snooze: bool, now_ts: int) -> None:
        """Construct + persist the UI-managed entry for ``alert``.

        Permanent and snooze share the same code path because the only
        difference is ``expires_at`` and the note prefix. Centralizing
        keeps the note format consistent — operators reading
        allowlist_ui.yaml directly should see the same provenance
        string for every webui-originated entry.
        """
        iso = unix_to_iso(now_ts)
        if snooze:
            note = f"snoozed 24h via webui at {iso}"
            expires_at: int | None = now_ts + SNOOZE_DEFAULT_SECONDS
        else:
            note = f"added via webui at {iso}"
            expires_at = None
        entry = AllowlistEntry(
            pattern=alert["mac"],
            pattern_type="mac",
            note=note,
            added_at=now_ts,
            expires_at=expires_at,
        )
        ui_path = derive_ui_path(Path(app.state.config.allowlist_path))
        add_ui_entry(ui_path, entry)

    @app.post("/alerts/{alert_id}/allowlist")
    def allowlist_alert_post(request: Request, alert_id: int):
        result = _load_alert_for_triage(alert_id, request)
        if not isinstance(result, dict):
            return result
        _write_ui_allowlist(result, snooze=False, now_ts=int(time.time()))
        return RedirectResponse(f"/alerts/{alert_id}", status_code=303)

    @app.post("/alerts/{alert_id}/snooze")
    def snooze_alert_post(request: Request, alert_id: int):
        result = _load_alert_for_triage(alert_id, request)
        if not isinstance(result, dict):
            return result
        _write_ui_allowlist(result, snooze=True, now_ts=int(time.time()))
        return RedirectResponse(f"/alerts/{alert_id}", status_code=303)

    @app.post("/alerts/{alert_id}/allowlist/remove")
    def remove_allowlist_alert_post(request: Request, alert_id: int):
        result = _load_alert_for_triage(alert_id, request)
        if not isinstance(result, dict):
            return result
        ui_path = derive_ui_path(Path(app.state.config.allowlist_path))
        # Idempotent: return value discarded. Operators clicking Cancel
        # twice (or removing an entry that's actually in the primary
        # operator file) get the same 303 back to /alerts/<id>. The
        # template re-renders against the current state and shows the
        # truth, which is more useful than a stale error message.
        remove_ui_entry(ui_path, result["mac"], "mac")
        return RedirectResponse(f"/alerts/{alert_id}", status_code=303)

    @app.post("/alerts/{alert_id}/note")
    def update_alert_note_post(
        request: Request,
        alert_id: int,
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

    # Snooze duration vocabulary for /alerts/{id}/watch. Mirrors the
    # operator's mental model ("forever / 24h / 7d / 30d") rather than
    # taking raw seconds via the form, so a typo can't accidentally
    # produce a wildly off snooze window.
    WATCH_SNOOZE_DURATIONS: dict[str, int | None] = {
        "forever": None,
        "24h": 86400,
        "7d": 7 * 86400,
        "30d": 30 * 86400,
    }

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
        alert_id: int,
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
        if snooze_duration not in WATCH_SNOOZE_DURATIONS:
            raise HTTPException(
                status_code=400,
                detail=(
                    "snooze_duration must be one of: "
                    + ", ".join(WATCH_SNOOZE_DURATIONS)
                ),
            )
        seconds = WATCH_SNOOZE_DURATIONS[snooze_duration]
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
        target = _safe_redirect_target(request, default="/alerts")
        return RedirectResponse(target, status_code=303)

    @app.post("/watchful/{entry_id}/dismiss")
    def watchful_dismiss_post(request: Request, entry_id: int):
        result = _load_watchful_for_action(entry_id, request)
        if not isinstance(result, WatchfulRecurrence):
            return result
        # Idempotent: dismiss on an already-archived entry succeeds
        # with no DB change. Matches the /alerts/{id}/allowlist/remove
        # idempotence pattern; the redirect still fires.
        db.dismiss_watchful_recurrence(entry_id, now_ts=int(time.time()))
        return RedirectResponse("/alerts", status_code=303)

    @app.post("/watchful/{entry_id}/promote")
    def watchful_promote_post(
        request: Request,
        entry_id: int,
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
        return RedirectResponse("/alerts", status_code=303)

    @app.post("/watchful/{entry_id}/reset")
    def watchful_reset_post(request: Request, entry_id: int):
        result = _load_watchful_for_action(entry_id, request)
        if not isinstance(result, WatchfulRecurrence):
            return result
        try:
            db.reset_watchful_recurrence(entry_id, now_ts=int(time.time()))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return RedirectResponse("/alerts", status_code=303)

    @app.post("/watchful/{entry_id}/investigate")
    def watchful_investigate_post(
        request: Request,
        entry_id: int,
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
        return RedirectResponse("/alerts", status_code=303)

    @app.post("/watchful/{entry_id}/confirm-safe")
    def watchful_confirm_safe_post(
        request: Request,
        entry_id: int,
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
        return RedirectResponse("/alerts", status_code=303)

    @app.get("/devices", response_class=HTMLResponse)
    def devices_list(
        request: Request,
        device_type: str | None = Query(default=None),
        randomized: str | None = Query(default=None),
        page: int = Query(default=1),
        page_size: int = Query(default=50),
    ):
        if device_type is not None and device_type not in (
            "wifi", "ble", "bt_classic", "remote_id"
        ):
            raise HTTPException(status_code=400, detail="invalid device_type")
        rand_bool = _parse_bool_str(randomized, "randomized")
        if page < 1:
            raise HTTPException(status_code=400, detail="page must be >= 1")
        if page_size < 10 or page_size > 200:
            raise HTTPException(status_code=400, detail="page_size must be in [10, 200]")

        offset = (page - 1) * page_size
        total_count = db.count_devices(device_type=device_type, randomized=rand_bool)
        devices = db.list_devices(
            limit=page_size,
            offset=offset,
            device_type=device_type,
            randomized=rand_bool,
        )
        return app.state.templates.TemplateResponse(
            request=request,
            name="devices_list.html",
            context={
                "version": __version__,
                "active": "devices",
                "devices": devices,
                "total_count": total_count,
                "page": page,
                "page_size": page_size,
                "total_pages": _total_pages(total_count, page_size),
                "device_type": device_type,
                "randomized": rand_bool,
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
        return app.state.templates.TemplateResponse(
            request=request,
            name="device_detail.html",
            context={
                "version": __version__,
                "active": "devices",
                "device": result["device"],
                "sightings": result["sightings"],
            },
        )

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
                "rules_with_stats": rules_with_stats,
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
        # Backward compat: /watchlist with no query params behaves
        # exactly as pre-rc5 (first 50 rows, severity-by-importance
        # then pattern alphabetical). Invalid filter values silently
        # fall back to "all" -- a stale bookmark with a typo like
        # severity=foo lands on the unfiltered page rather than 400.
        if q is not None and len(q) > 100:
            raise HTTPException(status_code=400, detail="q must be <= 100 chars")
        q_clean = q if q else None

        if pattern_type is not None and pattern_type not in _WATCHLIST_PATTERN_TYPES:
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
                "device_category_options": device_category_options,
                "uncategorized_sentinel": _WATCHLIST_UNCATEGORIZED_SENTINEL,
                "per_page_options": _WATCHLIST_PER_PAGE_ALLOWED,
                "filters_active": filters_active,
            },
        )

    @app.get("/watchlist/{watchlist_id}", response_class=HTMLResponse)
    def watchlist_detail(request: Request, watchlist_id: int):
        if watchlist_id < 1:
            raise HTTPException(status_code=400, detail="watchlist_id must be positive")
        rows = db.list_watchlist_with_metadata()
        row = next((r for r in rows if r["id"] == watchlist_id), None)
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
        return app.state.templates.TemplateResponse(
            request=request,
            name="watchlist_detail.html",
            context={
                "version": __version__,
                "active": "watchlist",
                "entry": entry,
                "has_metadata": has_metadata,
                "metadata": metadata,
            },
        )

    @app.get("/settings", response_class=HTMLResponse)
    def settings_view(request: Request):
        now = time.time()
        kismet_status = _get_kismet_status(app, now)
        ctx = _build_settings_context(app.state.config, db, kismet_status)
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
            filtered_rows = _filter_allowlist_entries(
                tagged,
                q=q,
                source=source,
                status=status,
                type_=type_,
                now_ts=int(time.time()),
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
                "entries": page_rows,
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
