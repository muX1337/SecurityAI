import pytest
from xss_ai.context import ContextSpec
from xss_ai.eval.batched_oracle import BatchedOracle


@pytest.mark.browser
def test_batched_oracle_fires_on_script():
    ctx = ContextSpec(id="c", location="html_body")
    ctx.description = "d"
    with BatchedOracle() as oracle:
        assert oracle.check_fires(ctx, "<script>alert(1)</script>") is True

@pytest.mark.browser
def test_batched_oracle_does_not_fire_on_plain_text():
    ctx = ContextSpec(id="c", location="html_body")
    ctx.description = "d"
    with BatchedOracle() as oracle:
        assert oracle.check_fires(ctx, "hello world") is False

@pytest.mark.browser
def test_batched_oracle_fires_on_svg_onload():
    ctx = ContextSpec(id="c", location="html_body")
    ctx.description = "d"
    with BatchedOracle() as oracle:
        assert oracle.check_fires(ctx, "<svg onload=alert(1)>") is True

@pytest.mark.browser
def test_batched_oracle_handles_filtered_payload():
    ctx = ContextSpec(id="c", location="html_body", filters=["block_keyword_script"])
    ctx.description = "d"
    with BatchedOracle() as oracle:
        # block_keyword_script returns "" -> no reflection -> False
        assert oracle.check_fires(ctx, "<script>alert(1)</script>") is False

@pytest.mark.browser
def test_batched_oracle_multiple_checks_same_session():
    """The whole point: multiple checks reuse one browser."""
    ctx = ContextSpec(id="c", location="html_body")
    ctx.description = "d"
    with BatchedOracle() as oracle:
        assert oracle.check_fires(ctx, "<script>alert(1)</script>") is True
        assert oracle.check_fires(ctx, "not a payload") is False
        assert oracle.check_fires(ctx, "<svg onload=alert(1)>") is True
        assert oracle.check_fires(ctx, "<img src=x onerror=alert(1)>") is True
