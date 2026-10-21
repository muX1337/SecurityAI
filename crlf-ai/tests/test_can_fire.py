import pytest
from crlf_ai.can_fire import can_fire

CASES = [
    # URL-encoded CRLF + injection marker -> fires
    ("%0d%0aSet-Cookie: evil=1", "response_header", True),
    ("%0D%0ASet-Cookie: csrf=bypassed", "response_header", True),
    ("%0d%0aLocation: https://evil.com", "location_header", True),
    ("%0d%0aContent-Length: 0", "response_header", True),
    ("%0d%0aContent-Type: text/html", "response_header", True),
    # Double-encoded bypass
    ("%250d%250aSet-Cookie: evil=1", "response_header", True),
    # Unicode overlong UTF-8 of newline
    ("%E5%98%8A%E5%98%8DSet-Cookie: evil=1", "response_header", True),
    # Response splitting into body
    ("%0d%0a%0d%0a<html>injected</html>", "response_body", True),
    ("%0d%0a%0d%0a<script>alert(1)</script>", "response_body", True),
    # Raw literal CRLF bytes + marker
    ("\r\nSet-Cookie: evil=1", "response_header", True),
    ("\nSet-Cookie: evil=1", "response_header", True),
    # Benign / negatives
    ("test_input", "response_header", False),
    ("hello_world", "response_header", False),
    ("normal_value", "set_cookie", False),
    ("", "response_header", False),
    ("   ", "response_header", False),
    # A bare CRLF with no injection marker does NOT fire
    ("%0d%0a", "response_header", False),
    # Marker without a newline does not fire
    ("Set-Cookie: evil=1", "response_header", False),
]


@pytest.mark.parametrize("payload,location,expected", CASES)
def test_can_fire(payload, location, expected):
    assert can_fire(payload, location) is expected


def test_can_fire_returns_bool():
    assert isinstance(can_fire("%0d%0aSet-Cookie: evil=1", "response_header"), bool)
