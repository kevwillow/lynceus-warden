"""Unit tests for the offset-pagination helper.

Pure-math coverage. No DB, no route, no template -- just the
clamping rules and the dataclass properties. Tests live in their
own file because the helper is shared by multiple routes and
deserves a single source of truth for its semantics; route-level
state-preservation lives in the route's own test file.
"""

import pytest

from lynceus.webui.pagination import (
    PaginationParams,
    build_pagination,
    parse_pagination,
)


_ALLOWED = (25, 50, 100, 200)
_DEFAULT = 50


# --- parse_pagination --------------------------------------------------------


def test_parse_pagination_happy_path():
    page, per_page = parse_pagination("3", "100", allowed_per_page=_ALLOWED, default_per_page=_DEFAULT)
    assert page == 3
    assert per_page == 100


def test_parse_pagination_defaults_when_missing():
    page, per_page = parse_pagination(None, None, allowed_per_page=_ALLOWED, default_per_page=_DEFAULT)
    assert page == 1
    assert per_page == _DEFAULT


def test_parse_pagination_invalid_per_page_falls_back_to_default():
    # Per-prompt: per_page=37 (non-allowed value) -> default.
    _, per_page = parse_pagination("1", "37", allowed_per_page=_ALLOWED, default_per_page=_DEFAULT)
    assert per_page == _DEFAULT


def test_parse_pagination_out_of_range_per_page_falls_back():
    # Per-prompt: per_page=999 -> default.
    _, per_page = parse_pagination("1", "999", allowed_per_page=_ALLOWED, default_per_page=_DEFAULT)
    assert per_page == _DEFAULT


def test_parse_pagination_non_integer_per_page_falls_back():
    _, per_page = parse_pagination("1", "abc", allowed_per_page=_ALLOWED, default_per_page=_DEFAULT)
    assert per_page == _DEFAULT


def test_parse_pagination_negative_page_clamps_to_one():
    page, _ = parse_pagination("-1", "50", allowed_per_page=_ALLOWED, default_per_page=_DEFAULT)
    assert page == 1


def test_parse_pagination_zero_page_clamps_to_one():
    page, _ = parse_pagination("0", "50", allowed_per_page=_ALLOWED, default_per_page=_DEFAULT)
    assert page == 1


def test_parse_pagination_non_integer_page_defaults_to_one():
    page, _ = parse_pagination("not-a-number", "50", allowed_per_page=_ALLOWED, default_per_page=_DEFAULT)
    assert page == 1


def test_parse_pagination_rejects_default_outside_allowed_set():
    with pytest.raises(ValueError):
        parse_pagination("1", "50", allowed_per_page=(25, 100), default_per_page=50)


# --- build_pagination --------------------------------------------------------


def test_build_pagination_typical_case():
    p = build_pagination(requested_page=2, per_page=25, total=100)
    assert p.page == 2
    assert p.per_page == 25
    assert p.total == 100
    assert p.total_pages == 4
    assert p.offset == 25
    assert p.has_prev is True
    assert p.has_next is True


def test_build_pagination_clamps_page_above_total():
    # Per-prompt: page=999 with only 5 pages -> last valid page.
    p = build_pagination(requested_page=999, per_page=25, total=100)
    assert p.page == 4
    assert p.has_next is False


def test_build_pagination_zero_total_renders_empty_page_1_of_1():
    p = build_pagination(requested_page=1, per_page=25, total=0)
    assert p.page == 1
    assert p.total == 0
    assert p.total_pages == 1
    assert p.offset == 0
    assert p.has_prev is False
    assert p.has_next is False


def test_build_pagination_first_page():
    p = build_pagination(requested_page=1, per_page=25, total=100)
    assert p.page == 1
    assert p.has_prev is False
    assert p.has_next is True
    assert p.offset == 0


def test_build_pagination_last_page():
    p = build_pagination(requested_page=4, per_page=25, total=100)
    assert p.page == 4
    assert p.total_pages == 4
    assert p.has_prev is True
    assert p.has_next is False
    assert p.offset == 75


def test_build_pagination_single_page_for_small_total():
    p = build_pagination(requested_page=1, per_page=50, total=10)
    assert p.total_pages == 1
    assert p.has_prev is False
    assert p.has_next is False


def test_build_pagination_partial_last_page():
    # 17 rows, per_page=5 -> 4 pages; last page has 2 rows.
    p = build_pagination(requested_page=4, per_page=5, total=17)
    assert p.total_pages == 4
    assert p.offset == 15


def test_build_pagination_negative_requested_page_clamps_to_one():
    p = build_pagination(requested_page=-3, per_page=25, total=100)
    assert p.page == 1


def test_pagination_params_is_frozen():
    p = PaginationParams(page=1, per_page=25, total=10)
    with pytest.raises(AttributeError):
        p.page = 2  # type: ignore[misc]
