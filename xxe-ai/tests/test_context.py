import pytest
from xxe_ai.context import (
    LOCATIONS,
    ContextSpec,
    render_description,
    simulate_reflection,
)


def test_locations_contains_xml_body():
    assert "xml_body" in LOCATIONS

def test_context_spec_builds_with_minimal_fields():
    ctx = ContextSpec(id="xxe-body-plain", location="xml_body")
    assert ctx.filters == []
    assert ctx.description is None

def test_context_spec_rejects_unknown_location():
    with pytest.raises(Exception):
        ContextSpec(id="x", location="bogus_location")

def test_context_spec_rejects_unknown_filter():
    with pytest.raises(Exception):
        ContextSpec(id="x", location="xml_body", filters=["bogus_filter"])

def test_render_description_xml_body_with_filters():
    ctx = ContextSpec(
        id="xxe-body-block-file",
        location="xml_body",
        filters=["block_file_protocol", "block_doctype"],
    )
    desc = render_description(ctx)
    assert "xml" in desc.lower()
    assert "file://" in desc.lower()
    assert "doctype" in desc.lower()

def test_render_description_no_filters_mentions_dtd():
    ctx = ContextSpec(id="x", location="xml_body", filters=[])
    desc = render_description(ctx)
    assert "no xml input filtering" in desc.lower() or "dtd" in desc.lower()

def test_simulate_reflection_no_filters_returns_payload():
    ctx = ContextSpec(id="x", location="xml_body")
    payload = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
    result = simulate_reflection(ctx, payload)
    assert result == payload

def test_simulate_reflection_block_doctype():
    ctx = ContextSpec(id="x", location="xml_body", filters=["block_doctype"])
    payload = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
    result = simulate_reflection(ctx, payload)
    assert result == ""  # blocked

def test_simulate_reflection_block_file_protocol():
    ctx = ContextSpec(id="x", location="xml_body", filters=["block_file_protocol"])
    payload = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
    result = simulate_reflection(ctx, payload)
    assert result == ""  # blocked

def test_simulate_reflection_passes_http_payload_with_file_block():
    ctx = ContextSpec(id="x", location="xml_body", filters=["block_file_protocol"])
    payload = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/">]><foo>&xxe;</foo>'
    result = simulate_reflection(ctx, payload)
    assert result == payload  # not blocked

def test_all_locations_present():
    for loc in ("xml_body", "xml_attribute", "xml_cdata", "soap_body", "svg_upload"):
        assert loc in LOCATIONS
