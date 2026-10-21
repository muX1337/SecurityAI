"""Tests for filters.py: registry, individual filters, chaining."""
from __future__ import annotations

import pytest
from sqli_ai.filters import (
    FILTERS,
    apply_filters,
    block_keyword_select,
    block_keyword_union,
    escape_single_quotes,
    get_filter,
    numeric_cast,
)


class TestRegistry:
    def test_registry_has_at_least_nine_filters(self):
        assert len(FILTERS) >= 9

    def test_expected_filter_names_registered(self):
        expected = {
            "escape_single_quotes",
            "escape_double_quotes",
            "block_keyword_union",
            "block_keyword_select",
            "block_keyword_and_or",
            "block_comment_dash",
            "block_comment_hash",
            "numeric_cast",
            "lowercase_input",
        }
        assert expected <= set(FILTERS)

    def test_get_filter_returns_callable(self):
        fn = get_filter("escape_single_quotes")
        assert callable(fn)

    def test_get_filter_unknown_raises(self):
        with pytest.raises(KeyError) as exc_info:
            get_filter("does_not_exist")
        assert "does_not_exist" in str(exc_info.value)


class TestEscapeQuotes:
    def test_escape_single_quotes_doubles(self):
        assert escape_single_quotes("a'b") == "a''b"

    def test_escape_single_quotes_multiple(self):
        assert escape_single_quotes("' OR '1'='1") == "'' OR ''1''=''1"

    def test_escape_single_quotes_no_change(self):
        assert escape_single_quotes("admin") == "admin"

    def test_escape_single_quotes_empty(self):
        assert escape_single_quotes("") == ""


class TestBlockKeywordUnion:
    def test_blocks_uppercase_union(self):
        assert block_keyword_union("1 UNION SELECT password") == ""

    def test_blocks_lowercase_union(self):
        assert block_keyword_union("1 union select password") == ""

    def test_blocks_mixed_case_union(self):
        assert block_keyword_union("1 UnIoN select password") == ""

    def test_passes_without_union(self):
        assert block_keyword_union("admin") == "admin"

    def test_does_not_block_substring(self):
        # "reunion" contains "union" but is not the keyword.
        assert block_keyword_union("reunion") == "reunion"


class TestBlockKeywordSelect:
    def test_blocks_select(self):
        assert block_keyword_select("UNION SELECT * FROM t") == ""

    def test_blocks_lowercase_select(self):
        assert block_keyword_select("1 select 2") == ""

    def test_passes_without_select(self):
        assert block_keyword_select("admin'--") == "admin'--"


class TestNumericCast:
    def test_casts_integer_string(self):
        assert numeric_cast("42") == "42"

    def test_casts_negative_integer(self):
        assert numeric_cast("-1") == "-1"

    def test_non_numeric_becomes_zero(self):
        assert numeric_cast("abc") == "0"

    def test_float_truncated_to_int(self):
        # int("1.5") raises ValueError -> returns "0"
        assert numeric_cast("1.5") == "0"

    def test_empty_becomes_zero(self):
        assert numeric_cast("") == "0"


class TestApplyFilters:
    def test_empty_filter_list_passes_through(self):
        assert apply_filters("payload", []) == "payload"

    def test_single_filter_applied(self):
        out = apply_filters("a'b", ["escape_single_quotes"])
        assert out == "a''b"

    def test_chain_applied_in_order(self):
        out = apply_filters(
            "Admin",
            ["lowercase_input"],
        )
        assert out == "admin"

    def test_chain_blocks_return_empty(self):
        # Union blocked before escape ever runs.
        out = apply_filters(
            "1 UNION SELECT x",
            ["block_keyword_union", "escape_single_quotes"],
        )
        assert out == ""

    def test_chain_short_circuits_on_block(self):
        # If the first filter blocks, the second is not reached.
        out = apply_filters(
            "1 UNION SELECT x",
            ["block_keyword_union", "lowercase_input"],
        )
        assert out == ""

    def test_chain_escape_then_block_union(self):
        # Escape quotes first, then union is still present and blocked.
        out = apply_filters(
            "1' UNION SELECT x",
            ["escape_single_quotes", "block_keyword_union"],
        )
        assert out == ""

    def test_unknown_filter_raises(self):
        with pytest.raises(KeyError):
            apply_filters("payload", ["nope"])
