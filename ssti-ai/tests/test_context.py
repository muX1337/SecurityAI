import pytest
from ssti_ai.context import (
    LOCATIONS,
    ContextSpec,
    engine_delimiters,
    render_description,
    simulate_reflection,
)


def test_locations_contains_jinja2_body():
    assert "jinja2_body" in LOCATIONS

def test_all_five_engines_present():
    for loc in ("jinja2_body", "twig_body", "freemarker_body", "velocity_body", "mako_body"):
        assert loc in LOCATIONS

def test_context_spec_builds_with_minimal_fields():
    ctx = ContextSpec(id="ssti-jinja2-plain", location="jinja2_body")
    assert ctx.filters == []
    assert ctx.description is None

def test_context_spec_rejects_unknown_location():
    with pytest.raises(Exception):
        ContextSpec(id="x", location="bogus_location")

def test_context_spec_rejects_unknown_filter():
    with pytest.raises(Exception):
        ContextSpec(id="x", location="jinja2_body", filters=["bogus_filter"])

def test_render_description_jinja2_with_filters():
    ctx = ContextSpec(
        id="ssti-jinja2-block-curly",
        location="jinja2_body",
        filters=["block_curly_braces", "block_keyword_config"],
    )
    desc = render_description(ctx)
    assert "jinja2" in desc.lower()
    assert "template" in desc.lower()
    assert "{{" in desc or "curly" in desc.lower()
    assert "config" in desc.lower()

def test_render_description_mentions_no_filtering_when_empty():
    ctx = ContextSpec(id="x", location="jinja2_body", filters=[])
    desc = render_description(ctx)
    assert "no input filtering" in desc.lower()

def test_simulate_reflection_no_filters_returns_payload():
    ctx = ContextSpec(id="x", location="jinja2_body")
    result = simulate_reflection(ctx, "{{7*7}}")
    assert result == "{{7*7}}"

def test_simulate_reflection_block_curly_braces():
    ctx = ContextSpec(id="x", location="jinja2_body", filters=["block_curly_braces"])
    result = simulate_reflection(ctx, "{{7*7}}")
    assert result == ""  # blocked

def test_simulate_reflection_block_keyword_config():
    ctx = ContextSpec(id="x", location="jinja2_body", filters=["block_keyword_config"])
    assert simulate_reflection(ctx, "{{config}}") == ""
    assert simulate_reflection(ctx, "{{7*7}}") == "{{7*7}}"

def test_engine_delimiters_jinja2():
    d = engine_delimiters("jinja2_body")
    assert "{{" in d and "}}" in d

def test_engine_delimiters_freemarker_has_dollar():
    d = engine_delimiters("freemarker_body")
    assert "${" in d
