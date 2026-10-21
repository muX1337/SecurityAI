"""Tests for filters.py: registry, individual filters, chaining."""
from __future__ import annotations

import pytest
from cmdi_ai.filters import (
    FILTERS,
    alphanumeric_only,
    apply_filters,
    block_ampersand,
    block_backtick,
    block_dollar,
    block_keywords,
    block_pipe,
    block_redirect,
    block_semicolon,
    get_filter,
)


class TestRegistry:
    def test_registry_has_at_least_eight_filters(self):
        assert len(FILTERS) >= 8

    def test_expected_filter_names_registered(self):
        expected = {
            "block_semicolon",
            "block_pipe",
            "block_ampersand",
            "block_backtick",
            "block_dollar",
            "block_redirect",
            "block_keywords",
            "alphanumeric_only",
        }
        assert expected <= set(FILTERS)

    def test_get_filter_returns_callable(self):
        fn = get_filter("block_semicolon")
        assert callable(fn)

    def test_get_filter_unknown_raises(self):
        with pytest.raises(KeyError) as exc_info:
            get_filter("does_not_exist")
        assert "does_not_exist" in str(exc_info.value)


class TestBlockSemicolon:
    def test_blocks_semicolon(self):
        assert block_semicolon(";whoami") == ""

    def test_blocks_multiple_semicolons(self):
        assert block_semicolon("a; b; c") == ""

    def test_passes_without_semicolon(self):
        assert block_semicolon("|whoami") == "|whoami"

    def test_empty(self):
        assert block_semicolon("") == ""


class TestBlockPipe:
    def test_blocks_pipe(self):
        assert block_pipe("|whoami") == ""

    def test_blocks_double_pipe(self):
        assert block_pipe("|| whoami") == ""

    def test_passes_without_pipe(self):
        assert block_pipe(";whoami") == ";whoami"


class TestBlockAmpersand:
    def test_blocks_ampersand(self):
        assert block_ampersand("&whoami") == ""

    def test_blocks_double_ampersand(self):
        assert block_ampersand("&&whoami") == ""

    def test_passes_without_ampersand(self):
        assert block_ampersand(";whoami") == ";whoami"


class TestBlockBacktick:
    def test_blocks_backtick(self):
        assert block_backtick("`whoami`") == ""

    def test_passes_without_backtick(self):
        assert block_backtick("$(whoami)") == "$(whoami)"


class TestBlockDollar:
    def test_blocks_dollar(self):
        assert block_dollar("$(whoami)") == ""

    def test_blocks_dollar_var(self):
        assert block_dollar("$HOME") == ""

    def test_passes_without_dollar(self):
        assert block_dollar(";whoami") == ";whoami"


class TestBlockRedirect:
    def test_blocks_gt(self):
        assert block_redirect("echo x > file") == ""

    def test_blocks_lt(self):
        assert block_redirect("cat < file") == ""

    def test_passes_without_redirect(self):
        assert block_redirect(";whoami") == ";whoami"


class TestBlockKeywords:
    def test_blocks_whoami(self):
        assert block_keywords(";whoami") == ""

    def test_blocks_cat(self):
        assert block_keywords(";cat /etc/passwd") == ""

    def test_blocks_mixed_case(self):
        assert block_keywords(";WHOAMI") == ""

    def test_passes_echo(self):
        # echo is not in the blocklist
        assert block_keywords(";echo test") == ";echo test"

    def test_passes_without_keywords(self):
        assert block_keywords(";ls") == ""  # ls IS in the blocklist
        assert block_keywords(";foo") == ";foo"  # foo is not


class TestAlphanumericOnly:
    def test_strips_special_chars(self):
        assert alphanumeric_only(";whoami") == "whoami"

    def test_keeps_dot(self):
        assert alphanumeric_only("test.input") == "test.input"

    def test_strips_pipe_amp(self):
        assert alphanumeric_only("|&;") == ""

    def test_plain_text_unchanged(self):
        assert alphanumeric_only("whoami") == "whoami"


class TestApplyFilters:
    def test_empty_filter_list_passes_through(self):
        assert apply_filters("payload", []) == "payload"

    def test_single_filter_applied(self):
        out = apply_filters(";whoami", ["block_semicolon"])
        assert out == ""

    def test_chain_applied_in_order(self):
        out = apply_filters(
            ";whoami",
            ["block_semicolon"],
        )
        assert out == ""

    def test_chain_blocks_return_empty(self):
        out = apply_filters(
            "1 | whoami",
            ["block_pipe", "block_semicolon"],
        )
        assert out == ""

    def test_chain_short_circuits_on_block(self):
        out = apply_filters(
            "; | whoami",
            ["block_semicolon", "block_pipe"],
        )
        assert out == ""

    def test_unknown_filter_raises(self):
        with pytest.raises(KeyError):
            apply_filters("payload", ["nope"])
