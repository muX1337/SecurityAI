import pytest
from openredirect_ai.filters import (
    FILTERS,
    allowlist_paths,
    apply_filters,
    block_absolute_url,
    block_at_symbol,
    block_backslash,
    block_dotdot,
    block_protocol_relative,
    get_filter,
    register,
    require_same_domain,
    url_decode,
)


def test_registry_has_at_least_8_filters():
    assert len(FILTERS) >= 8


def test_block_absolute_url_blocks_https():
    assert block_absolute_url("https://evil.com/") == ""


def test_block_absolute_url_blocks_http():
    assert block_absolute_url("http://evil.com/") == ""


def test_block_absolute_url_passes_protocol_relative():
    assert block_absolute_url("//evil.com/") == "//evil.com/"


def test_block_absolute_url_passes_scheme_no_slash():
    assert block_absolute_url("https:evil.com/") == "https:evil.com/"


def test_require_same_domain_blocks_external_absolute():
    assert require_same_domain("https://evil.com/") == ""


def test_require_same_domain_blocks_protocol_relative():
    assert require_same_domain("//evil.com/") == ""


def test_require_same_domain_passes_relative_path():
    assert require_same_domain("/home") == "/home"


def test_require_same_domain_passes_same_host():
    assert require_same_domain("https://app.com/path") == "https://app.com/path"


def test_require_same_domain_blocks_app_at_evil():
    # host is evil.com (after @) -> external
    assert require_same_domain("https://app.com@evil.com/") == ""


def test_block_protocol_relative_blocks_double_slash():
    assert block_protocol_relative("//evil.com/") == ""


def test_block_protocol_relative_passes_absolute():
    assert block_protocol_relative("https://evil.com/") == "https://evil.com/"


def test_block_at_symbol_blocks_userinfo():
    assert block_at_symbol("https://app.com@evil.com/") == ""


def test_block_at_symbol_passes_no_at():
    assert block_at_symbol("https://evil.com/") == "https://evil.com/"


def test_block_backslash_blocks():
    assert block_backslash("http:\\\\evil.com\\") == ""


def test_block_backslash_passes_no_backslash():
    assert block_backslash("https://evil.com/") == "https://evil.com/"


def test_url_decode_decodes():
    assert url_decode("%2F%2Fevil.com%2F") == "//evil.com/"


def test_url_decode_no_encoded_chars():
    assert url_decode("https://evil.com/") == "https://evil.com/"


def test_block_dotdot_blocks():
    assert block_dotdot("../etc/passwd") == ""


def test_block_dotdot_passes_no_dotdot():
    assert block_dotdot("https://evil.com/") == "https://evil.com/"


def test_allowlist_paths_blocks_external_absolute():
    assert allowlist_paths("https://evil.com/") == ""


def test_allowlist_paths_blocks_protocol_relative():
    assert allowlist_paths("//evil.com/") == ""


def test_allowlist_paths_passes_relative():
    assert allowlist_paths("/home") == "/home"


def test_apply_filters_chains_in_order():
    # url_decode first decodes %2F%2F -> //, then block_protocol_relative blocks it
    out = apply_filters("%2F%2Fevil.com%2F", ["url_decode", "block_protocol_relative"])
    assert out == ""


def test_apply_filters_empty_list_returns_input():
    assert apply_filters("https://evil.com/", []) == "https://evil.com/"


def test_apply_filters_short_circuits_on_empty():
    out = apply_filters("https://evil.com/", ["block_absolute_url", "block_at_symbol"])
    assert out == ""


def test_get_filter_unknown_raises():
    with pytest.raises(KeyError):
        get_filter("does_not_exist")


def test_register_custom_filter():
    @register("my_test_filter")
    def rev(s, app_domain="app.com"):
        return s[::-1]
    assert get_filter("my_test_filter")("abc") == "cba"
