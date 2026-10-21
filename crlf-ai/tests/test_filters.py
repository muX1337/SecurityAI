import pytest
from crlf_ai.filters import (
    FILTERS,
    apply_filters,
    block_cr_only,
    block_crlf,
    block_header_keywords,
    block_lf_only,
    block_percent_0a,
    block_percent_0d,
    double_decode,
    get_filter,
    register,
    url_decode,
)


def test_registry_has_all_eight_filters():
    expected = {
        "url_decode", "double_decode",
        "block_crlf", "block_cr_only", "block_lf_only",
        "block_percent_0d", "block_percent_0a", "block_header_keywords",
    }
    assert expected.issubset(set(FILTERS))


def test_url_decode_decodes_once():
    assert url_decode("%0d%0a") == "\r\n"


def test_double_decode_unwraps_double_encoding():
    # %25 -> %, %30 -> 0 -> on second decode %0d -> CR
    assert double_decode("%250d%250a") == "\r\n"


def test_block_crlf_rejects_pair():
    assert block_crlf("a\r\nb") == ""
    # standalone CR/LF are NOT the pair -> pass through
    assert block_crlf("a\rb") == "a\rb"


def test_block_cr_only_rejects_any_cr():
    assert block_cr_only("a\rb") == ""
    assert block_cr_only("no control") == "no control"


def test_block_lf_only_rejects_any_lf():
    assert block_lf_only("a\nb") == ""
    assert block_lf_only("no control") == "no control"


def test_block_percent_0d_case_insensitive():
    assert block_percent_0d("foo%0dbar") == ""
    assert block_percent_0d("foo%0Dbar") == ""
    assert block_percent_0d("no token") == "no token"


def test_block_percent_0a_case_insensitive():
    assert block_percent_0a("foo%0abar") == ""
    assert block_percent_0a("foo%0Abar") == ""
    assert block_percent_0a("no token") == "no token"


def test_block_header_keywords_set_cookie():
    assert block_header_keywords("Set-Cookie: evil=1") == ""


def test_block_header_keywords_location():
    assert block_header_keywords("Location: https://evil.com") == ""


def test_block_header_keywords_content_type():
    assert block_header_keywords("Content-Type: text/html") == ""


def test_apply_filters_empty_list_returns_input():
    assert apply_filters("plain", []) == "plain"


def test_apply_filters_decode_runs_before_block():
    # url_decode turns %0d%0a into \r\n, then block_crlf catches it
    out = apply_filters("%0d%0a", ["block_crlf", "url_decode"])
    assert out == ""


def test_apply_filters_block_only_passes_when_no_match():
    out = apply_filters("clean payload", ["block_crlf"])
    assert out == "clean payload"


def test_apply_filters_short_circuits_on_first_block():
    # Both filters would reject, but order in list is preserved for block filters.
    out = apply_filters("a\r\nb", ["block_crlf", "block_cr_only"])
    assert out == ""


def test_get_filter_unknown_raises():
    with pytest.raises(KeyError):
        get_filter("does_not_exist")


def test_register_custom_filter():
    @register("my_test_filter")
    def rev(s):
        return s[::-1]
    assert get_filter("my_test_filter")("abc") == "cba"
