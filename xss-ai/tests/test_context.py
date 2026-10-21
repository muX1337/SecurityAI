import pytest
from xss_ai.context import (
    LOCATIONS,
    ContextSpec,
    render_description,
    simulate_reflection,
)


def test_locations_contains_html_body():
    assert "html_body" in LOCATIONS

def test_context_spec_requires_core_fields():
    with pytest.raises(Exception):
        ContextSpec()  # missing required fields

def test_context_spec_builds_with_minimal_fields():
    ctx = ContextSpec(
        id="html-body-plain",
        location="html_body",
    )
    assert ctx.reflection == "reflected"  # default
    assert ctx.filters == []
    assert ctx.encoding == []

def test_render_description_html_body_with_filters():
    ctx = ContextSpec(
        id="html-body-strip-ltgt-block-script",
        location="html_body",
        filters=["strip_angle_brackets", "block_keyword_script"],
    )
    desc = render_description(ctx)
    assert "HTML body" in desc
    assert "<" in desc or "angle brackets" in desc.lower()
    assert "script" in desc.lower()

def test_render_description_attr_dq():
    ctx = ContextSpec(
        id="attr-dq-escape-dq",
        location="attr_dq",
        filters=["escape_double_quotes_html"],
    )
    desc = render_description(ctx)
    assert "attribute" in desc.lower() or "attr" in desc.lower()
    assert "double quot" in desc.lower()


def test_simulate_reflection_no_filters_returns_input():
    ctx = ContextSpec(id="c", location="html_body")
    assert simulate_reflection(ctx, "<svg>") == "<svg>"


def test_simulate_reflection_applies_filter():
    ctx = ContextSpec(id="c", location="html_body", filters=["strip_angle_brackets"])
    assert simulate_reflection(ctx, "<script>") == "script"


def test_simulate_reflection_encode_then_filter():
    ctx = ContextSpec(id="c", location="url_param", encoding=["url_decode"],
                      filters=["block_keyword_script"])
    # url_decode first: %3Cscript%3E -> <script>, then block_keyword_script -> ""
    assert simulate_reflection(ctx, "%3Cscript%3E") == ""
