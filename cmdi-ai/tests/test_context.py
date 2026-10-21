"""Tests for context.py: LOCATIONS, ContextSpec validation, rendering, reflection."""
from __future__ import annotations

import pytest
from cmdi_ai.context import (
    LOCATIONS,
    ContextSpec,
    render_description,
    simulate_reflection,
)
from pydantic import ValidationError


class TestLocations:
    def test_locations_contains_shell_arg(self):
        assert "shell_arg" in LOCATIONS

    def test_locations_contains_all_expected(self):
        # The four command injection injection points.
        assert set(LOCATIONS) == {
            "shell_arg",
            "shell_command",
            "filename_arg",
            "variable_value",
        }

    def test_locations_is_tuple(self):
        assert isinstance(LOCATIONS, tuple)
        for loc in LOCATIONS:
            assert isinstance(loc, str)


class TestContextSpecValidation:
    def test_minimal_valid_spec(self):
        ctx = ContextSpec(id="t1", location="shell_arg")
        assert ctx.id == "t1"
        assert ctx.location == "shell_arg"
        assert ctx.filters == []
        assert ctx.shell == "bash"
        assert ctx.description is None

    def test_spec_accepts_all_locations(self):
        for loc in LOCATIONS:
            ctx = ContextSpec(id=f"t-{loc}", location=loc)
            assert ctx.location == loc

    def test_spec_with_filters(self):
        ctx = ContextSpec(
            id="t2",
            location="shell_arg",
            filters=["block_semicolon", "block_pipe"],
        )
        assert ctx.filters == ["block_semicolon", "block_pipe"]

    def test_spec_custom_shell(self):
        ctx = ContextSpec(id="t3", location="shell_arg", shell="cmd.exe")
        assert ctx.shell == "cmd.exe"

    def test_unknown_location_raises(self):
        with pytest.raises((ValidationError, ValueError)) as exc_info:
            ContextSpec(id="bad", location="not_a_real_location")
        assert "not_a_real_location" in str(exc_info.value)

    def test_unknown_filter_raises(self):
        with pytest.raises((ValidationError, ValueError)) as exc_info:
            ContextSpec(id="bad", location="shell_arg", filters=["nope_filter"])
        assert "nope_filter" in str(exc_info.value)

    def test_unknown_filter_reports_in_list(self):
        with pytest.raises((ValidationError, ValueError)) as exc_info:
            ContextSpec(
                id="bad",
                location="shell_arg",
                filters=["block_semicolon", "ghost"],
            )
        msg = str(exc_info.value)
        assert "ghost" in msg
        # the known filter should NOT be flagged as unknown
        assert "escape_single_quotes" not in msg


class TestRenderDescription:
    def test_shell_arg_mentions_argument_or_command(self):
        ctx = ContextSpec(id="s1", location="shell_arg")
        desc = render_description(ctx)
        assert "argument" in desc.lower() or "command" in desc.lower()

    def test_includes_shell(self):
        ctx = ContextSpec(id="s2", location="shell_arg", shell="zsh")
        desc = render_description(ctx)
        assert "zsh" in desc

    def test_custom_description_takes_precedence(self):
        ctx = ContextSpec(
            id="s3",
            location="shell_command",
            description="Custom override text.",
        )
        assert render_description(ctx) == "Custom override text."

    def test_description_includes_filter_prose(self):
        ctx = ContextSpec(
            id="s4",
            location="shell_arg",
            filters=["block_semicolon"],
        )
        desc = render_description(ctx)
        assert "semicolon" in desc.lower() or "blocked" in desc.lower()

    def test_shell_command_description(self):
        ctx = ContextSpec(id="s5", location="shell_command")
        desc = render_description(ctx)
        assert "directly" in desc.lower() or "command" in desc.lower()


class TestSimulateReflection:
    def test_no_filters_passes_through(self):
        ctx = ContextSpec(id="r1", location="shell_arg")
        assert simulate_reflection(ctx, ";whoami") == ";whoami"

    def test_block_semicolon_blocks(self):
        ctx = ContextSpec(
            id="r2", location="shell_arg", filters=["block_semicolon"]
        )
        assert simulate_reflection(ctx, ";whoami") == ""

    def test_block_pipe_passes_safe_payload(self):
        ctx = ContextSpec(
            id="r3", location="shell_arg", filters=["block_pipe"]
        )
        out = simulate_reflection(ctx, ";whoami")
        assert out == ";whoami"

    def test_block_pipe_blocks_pipe(self):
        ctx = ContextSpec(
            id="r4", location="shell_arg", filters=["block_pipe"]
        )
        assert simulate_reflection(ctx, "|whoami") == ""

    def test_alphanumeric_only_strips(self):
        ctx = ContextSpec(id="r5", location="shell_arg", filters=["alphanumeric_only"])
        assert simulate_reflection(ctx, ";whoami") == "whoami"
        assert simulate_reflection(ctx, "test.input") == "test.input"
