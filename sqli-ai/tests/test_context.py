"""Tests for context.py: LOCATIONS, ContextSpec validation, rendering, reflection."""
from __future__ import annotations

import pytest
from pydantic import ValidationError
from sqli_ai.context import (
    LOCATIONS,
    ContextSpec,
    render_description,
    simulate_reflection,
)


class TestLocations:
    def test_locations_contains_string_literal(self):
        assert "string_literal" in LOCATIONS

    def test_locations_contains_all_expected(self):
        # The five SQL injection injection points.
        assert set(LOCATIONS) == {
            "string_literal",
            "numeric",
            "order_by",
            "column_name",
            "insert_values",
        }

    def test_locations_is_tuple(self):
        assert isinstance(LOCATIONS, tuple)
        for loc in LOCATIONS:
            assert isinstance(loc, str)


class TestContextSpecValidation:
    def test_minimal_valid_spec(self):
        ctx = ContextSpec(id="t1", location="string_literal")
        assert ctx.id == "t1"
        assert ctx.location == "string_literal"
        assert ctx.filters == []
        assert ctx.dialect == "sqlite"
        assert ctx.description is None

    def test_spec_accepts_all_locations(self):
        for loc in LOCATIONS:
            ctx = ContextSpec(id=f"t-{loc}", location=loc)
            assert ctx.location == loc

    def test_spec_with_filters(self):
        ctx = ContextSpec(
            id="t2",
            location="numeric",
            filters=["block_keyword_union", "block_keyword_select"],
        )
        assert ctx.filters == ["block_keyword_union", "block_keyword_select"]

    def test_spec_custom_dialect(self):
        ctx = ContextSpec(id="t3", location="string_literal", dialect="mysql")
        assert ctx.dialect == "mysql"

    def test_unknown_location_raises(self):
        with pytest.raises((ValidationError, ValueError)) as exc_info:
            ContextSpec(id="bad", location="not_a_real_location")
        assert "not_a_real_location" in str(exc_info.value)

    def test_unknown_filter_raises(self):
        with pytest.raises((ValidationError, ValueError)) as exc_info:
            ContextSpec(id="bad", location="string_literal", filters=["nope_filter"])
        assert "nope_filter" in str(exc_info.value)

    def test_unknown_filter_reports_in_list(self):
        with pytest.raises((ValidationError, ValueError)) as exc_info:
            ContextSpec(
                id="bad",
                location="string_literal",
                filters=["escape_single_quotes", "ghost"],
            )
        msg = str(exc_info.value)
        assert "ghost" in msg
        # the known filter should NOT be flagged as unknown
        assert "escape_single_quotes" not in msg.replace("escape_single_quotes", "")


class TestRenderDescription:
    def test_string_literal_mentions_where_or_string_literal(self):
        ctx = ContextSpec(id="s1", location="string_literal")
        desc = render_description(ctx)
        assert "WHERE" in desc or "string literal" in desc

    def test_includes_dialect(self):
        ctx = ContextSpec(id="s2", location="numeric", dialect="postgres")
        desc = render_description(ctx)
        assert "postgres" in desc

    def test_custom_description_takes_precedence(self):
        ctx = ContextSpec(
            id="s3",
            location="order_by",
            description="Custom override text.",
        )
        assert render_description(ctx) == "Custom override text."

    def test_description_includes_filter_prose(self):
        ctx = ContextSpec(
            id="s4",
            location="string_literal",
            filters=["escape_single_quotes"],
        )
        desc = render_description(ctx)
        assert "escaped" in desc.lower() or "quote" in desc.lower()

    def test_numeric_description(self):
        ctx = ContextSpec(id="s5", location="numeric")
        desc = render_description(ctx)
        assert "numeric" in desc.lower()


class TestSimulateReflection:
    def test_no_filters_passes_through(self):
        ctx = ContextSpec(id="r1", location="string_literal")
        assert simulate_reflection(ctx, "admin' OR '1'='1") == "admin' OR '1'='1"

    def test_escape_quotes_doubles(self):
        ctx = ContextSpec(
            id="r2", location="string_literal", filters=["escape_single_quotes"]
        )
        out = simulate_reflection(ctx, "admin'--")
        assert out == "admin''--"

    def test_block_union_blocks_payload(self):
        ctx = ContextSpec(
            id="r3", location="string_literal", filters=["block_keyword_union"]
        )
        assert simulate_reflection(ctx, "1 UNION SELECT * FROM users") == ""

    def test_block_union_passes_safe_payload(self):
        ctx = ContextSpec(
            id="r4", location="string_literal", filters=["block_keyword_union"]
        )
        out = simulate_reflection(ctx, "admin")
        assert out == "admin"

    def test_numeric_cast(self):
        ctx = ContextSpec(id="r5", location="numeric", filters=["numeric_cast"])
        assert simulate_reflection(ctx, "42") == "42"
        assert simulate_reflection(ctx, "abc") == "0"
