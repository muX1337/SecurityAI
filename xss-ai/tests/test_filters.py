import pytest
from xss_ai.filters import (
    FILTERS,
    apply_filters,
    block_event_handlers,
    block_keyword_script,
    escape_double_quotes_html,
    get_filter,
    register,
    strip_angle_brackets,
    url_decode,
)


def test_registry_has_at_least_15_filters():
    assert len(FILTERS) >= 15

def test_strip_angle_brackets():
    assert strip_angle_brackets("<script>alert(1)</script>") == "scriptalert(1)/script"

def test_escape_double_quotes_html():
    assert escape_double_quotes_html('a"b') == "a&quot;b"

def test_block_keyword_script_blocks():
    assert block_keyword_script("<script>x</script>") == ""

def test_block_keyword_script_passes_non_script():
    assert block_keyword_script("<svg onload=alert(1)>") == "<svg onload=alert(1)>"

def test_url_decode():
    assert url_decode("%3Cscript%3E") == "<script>"

def test_block_event_handlers_removes_onload():
    out = block_event_handlers('<svg onload=alert(1)>')
    assert "onload" not in out

def test_get_filter_unknown_raises():
    with pytest.raises(KeyError):
        get_filter("does_not_exist")

def test_apply_filters_chains_in_order():
    # strip < > first, then check script still present after stripping
    out = apply_filters("<script>", ["strip_angle_brackets", "block_keyword_script"])
    assert out == ""  # "script" survives strip, then block_keyword_script kills it

def test_apply_filters_empty_list_returns_input():
    assert apply_filters("hello", []) == "hello"

def test_register_custom_filter():
    @register("my_reverse")
    def rev(s):
        return s[::-1]
    assert get_filter("my_reverse")("abc") == "cba"
