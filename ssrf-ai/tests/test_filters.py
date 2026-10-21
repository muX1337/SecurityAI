import pytest
from ssrf_ai.filters import (
    FILTERS,
    apply_filters,
    block_localhost_aliases,
    block_metadata_ip,
    block_private_ip,
    get_filter,
    register,
    scheme_http_only,
)


def test_registry_has_at_least_7_filters():
    assert len(FILTERS) >= 7

def test_block_private_ip_blocks_127():
    assert block_private_ip("http://127.0.0.1/secret") == ""

def test_block_private_ip_blocks_10():
    assert block_private_ip("http://10.0.0.1/internal") == ""

def test_block_private_ip_blocks_192_168():
    assert block_private_ip("http://192.168.1.1/admin") == ""

def test_block_private_ip_passes_public():
    assert block_private_ip("http://8.8.8.8/dns") == "http://8.8.8.8/dns"

def test_block_private_ip_passes_hostname():
    assert block_private_ip("http://example.com/") == "http://example.com/"

def test_block_localhost_aliases_blocks_localhost():
    assert block_localhost_aliases("http://localhost:8080/") == ""

def test_block_localhost_aliases_blocks_decimal():
    assert block_localhost_aliases("http://2130706433/") == ""

def test_block_localhost_aliases_passes_public():
    assert block_localhost_aliases("http://example.com/") == "http://example.com/"

def test_scheme_http_only_blocks_file():
    assert scheme_http_only("file:///etc/passwd") == ""

def test_scheme_http_only_blocks_gopher():
    assert scheme_http_only("gopher://127.0.0.1/") == ""

def test_scheme_http_only_passes_http():
    assert scheme_http_only("http://example.com/") == "http://example.com/"

def test_block_metadata_ip_blocks_aws():
    assert block_metadata_ip("http://169.254.169.254/latest/meta-data/") == ""

def test_apply_filters_chains_in_order():
    out = apply_filters("http://127.0.0.1/", ["block_private_ip", "scheme_http_only"])
    assert out == ""

def test_apply_filters_empty_list_returns_input():
    assert apply_filters("http://example.com/", []) == "http://example.com/"

def test_get_filter_unknown_raises():
    with pytest.raises(KeyError):
        get_filter("does_not_exist")

def test_register_custom_filter():
    @register("my_test_filter")
    def rev(s):
        return s[::-1]
    assert get_filter("my_test_filter")("abc") == "cba"
