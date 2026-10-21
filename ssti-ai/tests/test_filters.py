import pytest
from ssti_ai.filters import (
    FILTERS,
    apply_filters,
    block_class_keyword,
    block_curly_braces,
    block_dollar_braces,
    block_import,
    block_keyword_config,
    block_os_keyword,
    block_percent_braces,
    block_subclasses,
    get_filter,
    register,
)


def test_registry_has_at_least_8_filters():
    assert len(FILTERS) >= 8

def test_block_curly_braces_blocks_open():
    assert block_curly_braces("{{7*7}}") == ""

def test_block_curly_braces_blocks_close():
    assert block_curly_braces("foo}}") == ""

def test_block_curly_braces_passes_clean():
    assert block_curly_braces("${7*7}") == "${7*7}"

def test_block_percent_braces_blocks_open():
    assert block_percent_braces("{% if x %}") == ""

def test_block_percent_braces_passes_clean():
    assert block_percent_braces("{{7*7}}") == "{{7*7}}"

def test_block_dollar_braces_blocks_dollar():
    assert block_dollar_braces("${7*7}") == ""

def test_block_dollar_braces_blocks_any_brace():
    # closing brace alone is blocked (catches FreeMarker interpolation)
    assert block_dollar_braces("foo}") == ""

def test_block_keyword_config_blocks_config():
    assert block_keyword_config("{{config}}") == ""

def test_block_keyword_config_blocks_self():
    assert block_keyword_config("{{self}}") == ""

def test_block_keyword_config_blocks_request():
    assert block_keyword_config("{{request}}") == ""

def test_block_keyword_config_passes_clean():
    assert block_keyword_config("{{7*7}}") == "{{7*7}}"

def test_block_class_keyword_blocks_dunder():
    assert block_class_keyword("{{''.__class__}}") == ""

def test_block_class_keyword_passes_clean():
    assert block_class_keyword("{{7*7}}") == "{{7*7}}"

def test_block_subclasses_blocks():
    assert block_subclasses("{{''.__subclasses__()}}") == ""

def test_block_import_blocks_keyword():
    assert block_import("{%import os%}") == ""

def test_block_import_passes_clean():
    assert block_import("{{7*7}}") == "{{7*7}}"

def test_block_os_keyword_blocks_os():
    assert block_os_keyword("os.popen('id')") == ""

def test_block_os_keyword_blocks_popen():
    assert block_os_keyword("{{x.popen('id')}}") == ""

def test_block_os_keyword_blocks_system():
    assert block_os_keyword("system('id')") == ""

def test_block_os_keyword_passes_clean():
    assert block_os_keyword("{{7*7}}") == "{{7*7}}"

def test_apply_filters_chains_in_order():
    out = apply_filters("{{config}}", ["block_keyword_config", "block_curly_braces"])
    assert out == ""

def test_apply_filters_empty_list_returns_input():
    assert apply_filters("{{7*7}}", []) == "{{7*7}}"

def test_get_filter_unknown_raises():
    with pytest.raises(KeyError):
        get_filter("does_not_exist")

def test_register_custom_filter():
    @register("my_test_filter")
    def rev(s):
        return s[::-1]
    assert get_filter("my_test_filter")("abc") == "cba"
