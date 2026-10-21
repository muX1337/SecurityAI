"""Tests for can_fire.py: SQL keyword/quote/comment heuristic."""
from __future__ import annotations

import pytest
from sqli_ai.can_fire import can_fire


@pytest.mark.parametrize(
    "payload,location,expected",
    [
        # Classic tautologies with keywords/quotes -> fire.
        ("' OR 1=1 --", "string_literal", True),
        ("' OR '1'='1", "string_literal", True),
        ("admin'--", "string_literal", True),
        ("' UNION SELECT 1,2,3 --", "string_literal", True),
        ("1 UNION SELECT NULL,NULL,NULL --", "numeric", True),
        ("1 OR 1=1", "numeric", True),
        ("1 OR 1=1 --", "numeric", True),
        ("1; DROP TABLE users --", "numeric", True),
        # Comment markers without keyword still look suspicious.
        ("foo'--", "string_literal", True),
        ("foo#", "string_literal", True),
        # Numeric payloads fire ONLY in numeric context.
        ("42", "numeric", True),
        ("42", "string_literal", False),
        ("123", "numeric", True),
        # Plain benign text never fires.
        ("hello", "string_literal", False),
        ("hello", "numeric", False),
        ("test_input", "string_literal", False),
        # Empty / whitespace never fires.
        ("", "string_literal", False),
        ("   ", "numeric", False),
    ],
)
def test_can_fire_parametrized(payload, location, expected):
    assert can_fire(payload, location) is expected


class TestCanFireKeywords:
    def test_union_keyword_fires(self):
        assert can_fire("' UNION SELECT 1,2,3 --", "string_literal")

    def test_sleep_keyword_fires(self):
        assert can_fire("' AND SLEEP(5) --", "string_literal")

    def test_benchmark_keyword_fires(self):
        assert can_fire("' AND BENCHMARK(5000000,MD5(1)) --", "string_literal")

    def test_extractvalue_keyword_fires(self):
        assert can_fire(
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()))) --",
            "string_literal",
        )

    def test_case_insensitive_keyword(self):
        assert can_fire("' UnIoN SeLeCt 1,2,3 --", "string_literal")

    def test_substring_keyword_fires(self):
        assert can_fire("' AND SUBSTRING(database(),1,1)='s' --", "string_literal")


class TestCanFireNumericOnly:
    def test_numeric_fires_in_numeric_context(self):
        assert can_fire("999", "numeric") is True

    def test_numeric_does_not_fire_in_string_context(self):
        # "999" has no keyword/quote/comment, and it's not in a numeric context.
        assert can_fire("999", "string_literal") is False

    def test_non_numeric_in_numeric_context_does_not_fire(self):
        # No keyword/quote AND not parseable as int.
        assert can_fire("abc", "numeric") is False


class TestCanFireEdgeCases:
    def test_empty(self):
        assert can_fire("", "string_literal") is False

    def test_whitespace_only(self):
        assert can_fire("   ", "numeric") is False

    def test_quote_alone_fires(self):
        assert can_fire("'", "string_literal") is True

    def test_double_dash_alone_fires(self):
        assert can_fire("--", "string_literal") is True

    def test_block_comment_marker_fires(self):
        assert can_fire("/**/", "string_literal") is True
