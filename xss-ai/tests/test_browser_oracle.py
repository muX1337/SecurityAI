import pytest
from xss_ai.browser_oracle import check_fires, render_page_html
from xss_ai.context import ContextSpec


def test_render_html_body():
    ctx = ContextSpec(id="c", location="html_body")
    html = render_page_html(ctx, "<script>alert(1)</script>")
    assert "<script>alert(1)</script>" in html
    assert "alert(1)" in html

def test_render_attr_dq():
    ctx = ContextSpec(id="c", location="attr_dq")
    html = render_page_html(ctx, 'x">Y')
    assert 'value="x">Y' in html or 'value="x&quot;>Y' not in html  # raw embed

def test_render_js_string_sq():
    ctx = ContextSpec(id="c", location="js_string_sq")
    html = render_page_html(ctx, "PAYLOAD")
    assert "'PAYLOAD'" in html

# Live browser test — requires chromium installed. Marked slow.
@pytest.mark.browser
def test_check_fires_real_script():
    ctx = ContextSpec(id="c", location="html_body")
    # Raw payload, no filter -> fires.
    assert check_fires(ctx, "<script>alert(1)</script>") is True

@pytest.mark.browser
def test_check_fires_filtered_out():
    ctx = ContextSpec(id="c", location="html_body", filters=["block_keyword_script"])
    # script blocked -> server returns "" -> does not fire.
    assert check_fires(ctx, "<script>alert(1)</script>") is False

@pytest.mark.browser
def test_check_fires_svg_onload():
    ctx = ContextSpec(id="c", location="html_body")
    assert check_fires(ctx, "<svg onload=alert(1)>") is True

@pytest.mark.browser
def test_mine_pairs_returns_only_firing():
    from xss_ai.browser_oracle import mine_pairs
    from xss_ai.pair_schema import Pair
    ctx = ContextSpec(id="html-body-plain", location="html_body")
    ctx.description = "d"
    # Mix of firing and non-firing payloads
    payloads = [
        "<script>alert(1)</script>",      # fires
        "hello world",                      # does not fire
        "<svg onload=alert(1)>",           # fires
        "not a payload",                    # does not fire
    ]
    mined = mine_pairs([ctx], payloads, per_context_cap=10)
    assert len(mined) == 2
    for pair in mined:
        assert isinstance(pair, Pair)
        assert pair.provenance["source"] == "browser_oracle"
        assert pair.provenance["verified_by"] == "playwright"


def test_expand_verified_creates_pairs_for_surviving_contexts():
    """A verified payload expands into a pair for every context where it survives
    the reflection pipeline + can_fire."""
    from xss_ai.browser_oracle import expand_verified
    from xss_ai.context import ContextSpec, render_description

    # ">" prefix breaks out of attr_dq; no 'script' so block_keyword_script is survived too.
    payload = '"><svg onload=alert(1)>'
    contexts = [
        ContextSpec(id="html-body-plain", location="html_body"),
        ContextSpec(id="html-body-block-script", location="html_body",
                    filters=["block_keyword_script"]),
        ContextSpec(id="attr-dq-plain", location="attr_dq"),
    ]
    for c in contexts:
        c.description = render_description(c)

    pairs = expand_verified([payload], contexts)
    # "><svg onload=alert(1)> has no 'script', so it survives block_keyword_script too,
    # and it breaks out of the double-quoted attribute, so it survives attr_dq.
    ctx_ids = {p.context.id for p in pairs}
    assert "html-body-plain" in ctx_ids
    assert "attr-dq-plain" in ctx_ids
    for p in pairs:
        assert p.provenance["source"] == "browser_oracle"
        assert p.provenance["verified_by"] == "playwright"


def test_expand_verified_drops_payloads_killed_by_filter():
    """If a filter kills a verified payload for a context, no pair is made."""
    from xss_ai.browser_oracle import expand_verified
    from xss_ai.context import ContextSpec, render_description

    payload = "<script>alert(1)</script>"
    contexts = [
        ContextSpec(id="html-body-plain", location="html_body"),
        ContextSpec(id="html-body-block-script", location="html_body",
                    filters=["block_keyword_script"]),  # kills <script>
    ]
    for c in contexts:
        c.description = render_description(c)

    pairs = expand_verified([payload], contexts)
    ctx_ids = {p.context.id for p in pairs}
    assert "html-body-plain" in ctx_ids
    assert "html-body-block-script" not in ctx_ids  # killed by filter


def test_expand_verified_empty_payloads_returns_empty():
    from xss_ai.browser_oracle import expand_verified
    from xss_ai.context import ContextSpec
    ctx = ContextSpec(id="c", location="html_body")
    ctx.description = "d"
    assert expand_verified([], [ctx]) == []


@pytest.mark.browser
def test_test_payloads_once_returns_only_firing():
    from xss_ai.browser_oracle import test_payloads_once
    from xss_ai.context import ContextSpec
    ctx = ContextSpec(id="html-body-plain", location="html_body")
    ctx.description = "d"
    payloads = [
        "<script>alert(1)</script>",   # fires
        "hello world",                   # does not fire
        "<svg onload=alert(1)>",        # fires
    ]
    firing = test_payloads_once(payloads, ctx)
    assert len(firing) == 2
    assert "<script>alert(1)</script>" in firing
    assert "<svg onload=alert(1)>" in firing
