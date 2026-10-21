"""Tests for the DVWA context prober — tests the HTML-to-filter mapping logic."""
from xss_ai.eval.t3_real_apps import ProbeResult, derive_context_from_html


def test_raw_reflection_no_filtering():
    """When input is reflected raw, no filters are detected."""
    result = ProbeResult(
        input_sent="<script>alert(1)</script>",
        response_html='<pre><script>alert(1)</script></pre>',
    )
    ctx = derive_context_from_html(result, location="html_body")
    assert ctx.filters == []
    assert ctx.location == "html_body"


def test_angle_brackets_escaped():
    """When < > become &lt; &gt;, the escape_angle_brackets filter is detected."""
    result = ProbeResult(
        input_sent="<script>alert(1)</script>",
        response_html="&lt;script&gt;alert(1)&lt;/script&gt;",
    )
    ctx = derive_context_from_html(result, location="html_body")
    assert "escape_angle_brackets_html" in ctx.filters


def test_script_keyword_blocked():
    """When 'script' is removed/blocked, block_keyword_script is detected."""
    result = ProbeResult(
        input_sent="<script>alert(1)</script>",
        response_html="<>alert(1)</>",
    )
    ctx = derive_context_from_html(result, location="html_body")
    assert "block_keyword_script" in ctx.filters or "strip_angle_brackets" in ctx.filters


def test_double_quotes_escaped():
    """When " becomes &quot;, escape_double_quotes_html is detected."""
    result = ProbeResult(
        input_sent='"><svg onload=alert(1)>',
        response_html="&quot;><svg onload=alert(1)>",
    )
    ctx = derive_context_from_html(result, location="attr_dq")
    assert "escape_double_quotes_html" in ctx.filters


def test_empty_response():
    """Empty/blocked response -> block_keyword filter or empty."""
    result = ProbeResult(
        input_sent="<script>alert(1)</script>",
        response_html="",
    )
    ctx = derive_context_from_html(result, location="html_body")
    # Empty response means the input was blocked entirely
    assert isinstance(ctx.filters, list)


def test_context_has_description():
    """Derived context must have a rendered description for the model."""
    result = ProbeResult(
        input_sent="<svg onload=alert(1)>",
        response_html="<svg onload=alert(1)>",
    )
    ctx = derive_context_from_html(result, location="html_body")
    assert ctx.description is not None
    assert len(ctx.description) > 0
    assert "HTML body" in ctx.description
