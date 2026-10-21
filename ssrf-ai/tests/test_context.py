import pytest
from ssrf_ai.context import (
    LOCATIONS,
    ContextSpec,
    render_description,
    simulate_reflection,
)


def test_locations_contains_query_param():
    assert "query_param" in LOCATIONS

def test_context_spec_builds_with_minimal_fields():
    ctx = ContextSpec(id="ssrf-query-plain", location="query_param")
    assert ctx.filters == []
    assert ctx.scheme_allowlist is None
    assert ctx.allows_redirects is True

def test_context_spec_rejects_unknown_location():
    with pytest.raises(Exception):
        ContextSpec(id="x", location="bogus_location")

def test_context_spec_rejects_unknown_filter():
    with pytest.raises(Exception):
        ContextSpec(id="x", location="query_param", filters=["bogus_filter"])

def test_render_description_query_param_with_filters():
    ctx = ContextSpec(
        id="ssrf-query-block-private-ip",
        location="query_param",
        filters=["block_private_ip", "block_localhost_aliases"],
    )
    desc = render_description(ctx)
    assert "query parameter" in desc.lower() or "query param" in desc.lower()
    assert "private" in desc.lower() or "internal" in desc.lower()
    assert "localhost" in desc.lower()

def test_render_description_scheme_allowlist():
    ctx = ContextSpec(
        id="x",
        location="query_param",
        scheme_allowlist=["http", "https"],
    )
    desc = render_description(ctx)
    assert "http" in desc.lower()

def test_simulate_reflection_no_filters_returns_payload():
    ctx = ContextSpec(id="x", location="query_param")
    result = simulate_reflection(ctx, "http://example.com/path")
    assert result == "http://example.com/path"

def test_simulate_reflection_block_private_ip():
    ctx = ContextSpec(id="x", location="query_param", filters=["block_private_ip"])
    result = simulate_reflection(ctx, "http://127.0.0.1/secret")
    assert result == ""  # blocked

def test_simulate_reflection_passes_public_ip():
    ctx = ContextSpec(id="x", location="query_param", filters=["block_private_ip"])
    result = simulate_reflection(ctx, "http://8.8.8.8/")
    assert result == "http://8.8.8.8/"
