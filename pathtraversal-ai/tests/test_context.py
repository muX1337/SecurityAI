"""Tests for context.py: LOCATIONS, ContextSpec validation, rendering, reflection."""
from __future__ import annotations

import pytest
from pathtraversal_ai.context import (
    LOCATIONS,
    ContextSpec,
    render_description,
    simulate_reflection,
)
from pydantic import ValidationError


class TestLocations:
    def test_locations_contains_file_include(self):
        assert "file_include" in LOCATIONS

    def test_locations_contains_all_expected(self):
        assert set(LOCATIONS) == {
            "file_include",
            "file_read",
            "download_param",
            "template_path",
        }

    def test_locations_is_tuple(self):
        assert isinstance(LOCATIONS, tuple)
        for loc in LOCATIONS:
            assert isinstance(loc, str)


class TestContextSpecValidation:
    def test_minimal_valid_spec(self):
        ctx = ContextSpec(id="t1", location="file_include")
        assert ctx.id == "t1"
        assert ctx.location == "file_include"
        assert ctx.filters == []
        assert ctx.base_dir == "/var/www/files"
        assert ctx.description is None

    def test_spec_accepts_all_locations(self):
        for loc in LOCATIONS:
            ctx = ContextSpec(id=f"t-{loc}", location=loc)
            assert ctx.location == loc

    def test_spec_with_filters(self):
        ctx = ContextSpec(
            id="t2",
            location="file_read",
            filters=["strip_dotdot", "block_absolute"],
        )
        assert ctx.filters == ["strip_dotdot", "block_absolute"]

    def test_spec_custom_base_dir(self):
        ctx = ContextSpec(id="t3", location="file_read", base_dir="/app/templates")
        assert ctx.base_dir == "/app/templates"

    def test_unknown_location_raises(self):
        with pytest.raises((ValidationError, ValueError)) as exc_info:
            ContextSpec(id="bad", location="not_a_real_location")
        assert "not_a_real_location" in str(exc_info.value)

    def test_unknown_filter_raises(self):
        with pytest.raises((ValidationError, ValueError)) as exc_info:
            ContextSpec(id="bad", location="file_include", filters=["nope_filter"])
        assert "nope_filter" in str(exc_info.value)

    def test_unknown_filter_reports_in_list(self):
        with pytest.raises((ValidationError, ValueError)) as exc_info:
            ContextSpec(
                id="bad",
                location="file_include",
                filters=["strip_dotdot", "ghost"],
            )
        msg = str(exc_info.value)
        assert "ghost" in msg
        # the known filter should NOT be flagged as unknown
        assert "strip_dotdot" not in msg.replace("strip_dotdot", "")


class TestRenderDescription:
    def test_file_include_mentions_include(self):
        ctx = ContextSpec(id="s1", location="file_include")
        desc = render_description(ctx)
        assert "include" in desc.lower() or "require" in desc.lower()

    def test_file_read_mentions_read(self):
        ctx = ContextSpec(id="s2", location="file_read")
        desc = render_description(ctx)
        assert "read" in desc.lower() or "file_get_contents" in desc.lower()

    def test_custom_description_takes_precedence(self):
        ctx = ContextSpec(
            id="s3",
            location="template_path",
            description="Custom override text.",
        )
        assert render_description(ctx) == "Custom override text."

    def test_description_includes_filter_prose(self):
        ctx = ContextSpec(
            id="s4",
            location="file_include",
            filters=["strip_dotdot"],
        )
        desc = render_description(ctx)
        assert "../" in desc or "stripped" in desc.lower()

    def test_description_includes_basename_prose(self):
        ctx = ContextSpec(
            id="s5",
            location="file_read",
            filters=["basename_only"],
        )
        desc = render_description(ctx)
        assert "basename" in desc.lower() or "directory" in desc.lower()


class TestSimulateReflection:
    def test_no_filters_passes_through(self):
        ctx = ContextSpec(id="r1", location="file_include")
        assert simulate_reflection(ctx, "../../../etc/passwd") == "../../../etc/passwd"

    def test_strip_dotdot_removes_once(self):
        ctx = ContextSpec(
            id="r2", location="file_include", filters=["strip_dotdot"]
        )
        out = simulate_reflection(ctx, "../../etc/passwd")
        assert out == "etc/passwd"

    def test_basename_strips_dirs(self):
        ctx = ContextSpec(
            id="r3", location="file_read", filters=["basename_only"]
        )
        assert simulate_reflection(ctx, "../../../etc/passwd") == "passwd"

    def test_block_absolute_blocks_root(self):
        ctx = ContextSpec(
            id="r4", location="file_read", filters=["block_absolute"]
        )
        assert simulate_reflection(ctx, "/etc/passwd") == ""

    def test_block_absolute_blocks_windows_drive(self):
        ctx = ContextSpec(
            id="r5", location="template_path", filters=["block_absolute"]
        )
        assert simulate_reflection(ctx, "C:\\Windows\\win.ini") == ""

    def test_url_decode(self):
        ctx = ContextSpec(
            id="r6", location="file_include", filters=["url_decode"]
        )
        assert simulate_reflection(ctx, "..%2f..%2fetc%2fpasswd") == "../../etc/passwd"
