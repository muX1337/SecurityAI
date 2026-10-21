"""Tests for filters.py: registry, individual filters, chaining."""
from __future__ import annotations

import pytest
from pathtraversal_ai.filters import (
    FILTERS,
    apply_filters,
    basename_only,
    block_absolute,
    block_null_byte,
    double_decode,
    get_filter,
    prefix_append,
    strip_dotdot,
    strip_dotdot_recursive,
    url_decode,
)


class TestRegistry:
    def test_registry_has_at_least_eight_filters(self):
        assert len(FILTERS) >= 8

    def test_expected_filter_names_registered(self):
        expected = {
            "strip_dotdot",
            "strip_dotdot_recursive",
            "basename_only",
            "block_absolute",
            "block_null_byte",
            "url_decode",
            "double_decode",
            "prefix_append",
        }
        assert expected <= set(FILTERS)

    def test_get_filter_returns_callable(self):
        fn = get_filter("strip_dotdot")
        assert callable(fn)

    def test_get_filter_unknown_raises(self):
        with pytest.raises(KeyError) as exc_info:
            get_filter("does_not_exist")
        assert "does_not_exist" in str(exc_info.value)


class TestStripDotdot:
    def test_strips_single_pass(self):
        assert strip_dotdot("../../etc/passwd") == "etc/passwd"

    def test_strips_once_not_recursive(self):
        # Non-recursive: '....//' -> '../' survives one pass (this is the
        # classic strip_dotdot bypass: a single non-recursive removal leaves
        # a working '../' behind).
        assert strip_dotdot("....//etc/passwd") == "../etc/passwd"

    def test_no_change_when_absent(self):
        assert strip_dotdot("etc/passwd") == "etc/passwd"

    def test_empty(self):
        assert strip_dotdot("") == ""


class TestStripDotdotRecursive:
    def test_recursive_collapses_all(self):
        assert strip_dotdot_recursive("../../etc/passwd") == "etc/passwd"

    def test_recursive_handles_smuggled(self):
        # '....//' -> '../' after first pass, then '' after second pass.
        assert strip_dotdot_recursive("....//etc/passwd") == "etc/passwd"

    def test_recursive_handles_double_smuggled(self):
        assert strip_dotdot_recursive("....//....//etc/passwd") == "etc/passwd"

    def test_no_change_when_absent(self):
        assert strip_dotdot_recursive("etc/passwd") == "etc/passwd"


class TestBasenameOnly:
    def test_strips_directories(self):
        assert basename_only("../../../etc/passwd") == "passwd"

    def test_keeps_single_filename(self):
        assert basename_only("safe_file.txt") == "safe_file.txt"

    def test_handles_windows_backslash(self):
        assert basename_only("..\\..\\Windows\\win.ini") == "win.ini"

    def test_handles_mixed_separators(self):
        assert basename_only("..\\..\\Windows/win.ini") == "win.ini"

    def test_root_slash(self):
        assert basename_only("/etc/passwd") == "passwd"


class TestBlockAbsolute:
    def test_blocks_leading_slash(self):
        assert block_absolute("/etc/passwd") == ""

    def test_blocks_windows_drive(self):
        assert block_absolute("C:\\Windows\\win.ini") == ""

    def test_blocks_windows_forward_slash(self):
        assert block_absolute("C:/Windows/win.ini") == ""

    def test_passes_relative(self):
        assert block_absolute("../../etc/passwd") == "../../etc/passwd"

    def test_passes_filename(self):
        assert block_absolute("safe_file.txt") == "safe_file.txt"


class TestBlockNullByte:
    def test_blocks_encoded_null(self):
        assert block_null_byte("../../etc/passwd%00") == ""

    def test_blocks_literal_null(self):
        assert block_null_byte("file\x00.txt") == ""

    def test_passes_without_null(self):
        assert block_null_byte("etc/passwd") == "etc/passwd"


class TestUrlDecode:
    def test_decodes_once(self):
        assert url_decode("..%2f..%2fetc%2fpasswd") == "../../etc/passwd"

    def test_decodes_hex_e(self):
        assert url_decode("%2e%2e%2fetc%2fpasswd") == "../etc/passwd"

    def test_no_change_when_not_encoded(self):
        assert url_decode("etc/passwd") == "etc/passwd"


class TestDoubleDecode:
    def test_double_decoded_passes_through(self):
        assert double_decode("..%252fetc%252fpasswd") == "../etc/passwd"

    def test_single_encoded_also_resolves(self):
        assert double_decode("..%2fetc%2fpasswd") == "../etc/passwd"


class TestPrefixAppend:
    def test_pass_through(self):
        assert prefix_append("../../etc/passwd") == "../../etc/passwd"

    def test_empty(self):
        assert prefix_append("") == ""


class TestApplyFilters:
    def test_empty_filter_list_passes_through(self):
        assert apply_filters("payload", []) == "payload"

    def test_single_filter_applied(self):
        out = apply_filters("../../etc/passwd", ["strip_dotdot"])
        assert out == "etc/passwd"

    def test_chain_blocks_return_empty(self):
        out = apply_filters(
            "/etc/passwd",
            ["block_absolute", "strip_dotdot"],
        )
        assert out == ""

    def test_chain_short_circuits_on_block(self):
        out = apply_filters(
            "/etc/passwd",
            ["block_absolute", "url_decode"],
        )
        assert out == ""

    def test_url_decode_then_strip_dotdot(self):
        out = apply_filters(
            "..%2f..%2fetc%2fpasswd",
            ["url_decode", "strip_dotdot"],
        )
        assert out == "etc/passwd"

    def test_unknown_filter_raises(self):
        with pytest.raises(KeyError):
            apply_filters("payload", ["nope"])
