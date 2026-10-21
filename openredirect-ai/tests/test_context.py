import pytest
from openredirect_ai.context import (
    LOCATIONS,
    ContextSpec,
    render_description,
    simulate_reflection,
)


def test_locations_contains_redirect_param():
    assert "redirect_param" in LOCATIONS
    assert "location_header" in LOCATIONS
    assert "return_url" in LOCATIONS
    assert "next_param" in LOCATIONS


def test_context_spec_builds_with_minimal_fields():
    ctx = ContextSpec(id="redirect-param-plain", location="redirect_param")
    assert ctx.filters == []
    assert ctx.app_domain == "app.com"


def test_context_spec_rejects_unknown_location():
    with pytest.raises(Exception):
        ContextSpec(id="x", location="bogus_location")


def test_context_spec_rejects_unknown_filter():
    with pytest.raises(Exception):
        ContextSpec(id="x", location="redirect_param", filters=["bogus_filter"])


def test_render_description_redirect_param_with_filters():
    ctx = ContextSpec(
        id="redirect-param-block-absolute",
        location="redirect_param",
        filters=["block_absolute_url", "block_protocol_relative"],
    )
    desc = render_description(ctx)
    assert "redirect" in desc.lower() or "query" in desc.lower()
    assert "absolute" in desc.lower()
    assert "protocol-relative" in desc.lower() or "//" in desc


def test_render_description_no_filters_mentions_no_validation():
    ctx = ContextSpec(id="x", location="redirect_param")
    desc = render_description(ctx)
    assert "no url validation" in desc.lower()


def test_simulate_reflection_no_filters_returns_payload():
    ctx = ContextSpec(id="x", location="redirect_param")
    result = simulate_reflection(ctx, "https://evil.com/path")
    assert result == "https://evil.com/path"


def test_simulate_reflection_block_absolute_url():
    ctx = ContextSpec(id="x", location="redirect_param", filters=["block_absolute_url"])
    result = simulate_reflection(ctx, "https://evil.com/path")
    assert result == ""  # blocked


def test_simulate_reflection_block_absolute_passes_protocol_relative():
    ctx = ContextSpec(id="x", location="redirect_param", filters=["block_absolute_url"])
    result = simulate_reflection(ctx, "//evil.com/")
    assert result == "//evil.com/"  # survives
