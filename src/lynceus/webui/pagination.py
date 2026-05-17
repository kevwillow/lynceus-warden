"""Unified offset-pagination math for the web UI.

Two-phase API. Phase 1 (parse_pagination) clamps the raw query
parameters: invalid per_page falls back to the page's default;
the requested page is captured but not yet clamped because total
is unknown. Phase 2 (build_pagination) runs after the handler has
the total row count from the DB; it clamps page to the valid
range and packages everything into a PaginationParams the
template renders directly.

Splitting these two phases keeps the math testable in isolation
from any specific filter shape -- the helper has no knowledge of
``alerts``, ``allowlist``, or any DB call. Routes import it,
parse params, run their own COUNT(*) (sharing a filter-builder
with their page query for COUNT-consistency), then build the
PaginationParams.

Out-of-range behavior is "clamp silently" rather than "raise
4xx" by design: a stale bookmark like ?page=999 should land on
the last valid page, not 404; ?per_page=37 should fall back to
the default rather than 400. Operator UX trumps strict input
validation here.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import ceil


@dataclass(frozen=True)
class PaginationParams:
    """Resolved pagination state for a single page render.

    ``page`` is 1-indexed and clamped to [1, total_pages].
    ``per_page`` is the validated rows-per-page (one of the
    page's allowed values). ``total`` is the total matching row
    count under the current filter set -- not the unfiltered
    table size.
    """

    page: int
    per_page: int
    total: int

    @property
    def total_pages(self) -> int:
        if self.total <= 0:
            return 1
        return max(1, ceil(self.total / self.per_page))

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.per_page

    @property
    def has_prev(self) -> bool:
        return self.page > 1

    @property
    def has_next(self) -> bool:
        return self.page < self.total_pages


def parse_pagination(
    raw_page,
    raw_per_page,
    *,
    allowed_per_page: tuple[int, ...],
    default_per_page: int,
) -> tuple[int, int]:
    """Parse raw page + per_page from query params.

    Returns ``(requested_page, validated_per_page)``. The page is
    coerced to int and floored at 1; final clamping against
    total_pages is deferred to ``build_pagination`` because the
    total isn't known yet at parse time. per_page falls back to
    ``default_per_page`` for any value outside ``allowed_per_page``
    -- the prompt's "ignore invalid, fall back to default" rule.
    Non-integer or negative inputs are treated as missing.
    """

    if default_per_page not in allowed_per_page:
        raise ValueError(
            f"default_per_page={default_per_page} is not in allowed_per_page="
            f"{allowed_per_page}"
        )

    try:
        page = int(raw_page) if raw_page is not None else 1
    except (TypeError, ValueError):
        page = 1
    if page < 1:
        page = 1

    try:
        per_page = int(raw_per_page) if raw_per_page is not None else default_per_page
    except (TypeError, ValueError):
        per_page = default_per_page
    if per_page not in allowed_per_page:
        per_page = default_per_page

    return page, per_page


def build_pagination(
    requested_page: int, per_page: int, total: int
) -> PaginationParams:
    """Apply final clamping once the total row count is known.

    Clamps ``requested_page`` to [1, total_pages]. total == 0
    renders as "page 1 of 1" with no rows -- callers handle the
    empty-state rendering; the pagination footer is still
    coherent.
    """

    if total <= 0:
        return PaginationParams(page=1, per_page=per_page, total=0)
    total_pages = max(1, ceil(total / per_page))
    page = max(1, min(requested_page, total_pages))
    return PaginationParams(page=page, per_page=per_page, total=total)
