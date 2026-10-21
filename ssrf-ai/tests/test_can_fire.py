import pytest
from ssrf_ai.can_fire import can_fire

CASES = [
    ("http://127.0.0.1/", "query_param", True),
    ("http://example.com/", "query_param", True),
    ("http://2130706433/", "query_param", True),
    ("file:///etc/passwd", "query_param", True),
    ("gopher://127.0.0.1:6379/_INFO", "query_param", True),
    ("http://169.254.169.254/latest/meta-data/", "query_param", True),
    ("", "query_param", False),
    ("not a url", "query_param", False),
    ("   ", "query_param", False),
    ("127.0.0.1", "query_param", False),
    ("example.com", "query_param", False),
]


@pytest.mark.parametrize("payload,location,expected", CASES)
def test_can_fire(payload, location, expected):
    assert can_fire(payload, location) is expected
