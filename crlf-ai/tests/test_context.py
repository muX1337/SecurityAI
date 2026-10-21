import pytest
from crlf_ai.context import (
    LOCATIONS,
    ContextSpec,
    location_header_name,
    render_description,
    simulate_reflection,
)


def test_locations_contains_response_header():
    assert "response_header" in LOCATIONS
    assert "set_cookie" in LOCATIONS
    assert "location_header" in LOCATIONS
    assert "response_body" in LOCATIONS


def test_context_spec_builds_with_minimal_fields():
    ctx = ContextSpec(id="crlf-resp-header-plain", location="response_header")
    assert ctx.filters == []
    assert ctx.description is None


def test_context_spec_rejects_unknown_location():
    with pytest.raises(Exception):
        ContextSpec(id="x", location="bogus_location")


def test_context_spec_rejects_unknown_filter():
    with pytest.raises(Exception):
        ContextSpec(id="x", location="response_header", filters=["bogus_filter"])


def test_render_description_plain_context():
    ctx = ContextSpec(id="x", location="response_header")
    desc = render_description(ctx)
    assert "response header" in desc.lower()
    assert "no input filtering" in desc.lower()


def test_render_description_set_cookie_with_filters():
    ctx = ContextSpec(
        id="crlf-set-cookie-block-crlf",
        location="set_cookie",
        filters=["block_crlf"],
    )
    desc = render_description(ctx)
    assert "set-cookie" in desc.lower()
    assert "crlf" in desc.lower() or "carriage" in desc.lower()


def test_render_description_uses_explicit_description_when_set():
    ctx = ContextSpec(id="x", location="response_header", description="Custom prose.")
    assert render_description(ctx) == "Custom prose."


def test_location_header_name_for_each_location():
    assert location_header_name(ContextSpec(id="x", location="response_header")) == "X-Custom"
    assert location_header_name(ContextSpec(id="x", location="set_cookie")) == "Set-Cookie"
    assert location_header_name(ContextSpec(id="x", location="location_header")) == "Location"
    assert location_header_name(ContextSpec(id="x", location="response_body")) == "X-Custom"


def test_simulate_reflection_no_filters_returns_payload():
    ctx = ContextSpec(id="x", location="response_header")
    assert simulate_reflection(ctx, "benign_value") == "benign_value"


def test_simulate_reflection_block_crlf_rejects_pair():
    ctx = ContextSpec(id="x", location="response_header", filters=["block_crlf"])
    assert simulate_reflection(ctx, "x\r\ny") == ""


def test_simulate_reflection_url_decode_decodes_first():
    ctx = ContextSpec(id="x", location="response_header", filters=["url_decode"])
    # %0d decodes to a CR byte
    assert simulate_reflection(ctx, "a%0db") == "a\rb"
