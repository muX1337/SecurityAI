import pytest
from openredirect_ai.can_fire import can_fire

CASES = [
    # Absolute external URLs -> True
    ("https://evil.com/", "redirect_param", True),
    ("http://evil.com/", "redirect_param", True),
    ("https://app.com@evil.com/", "redirect_param", True),
    ("https://attacker.com/", "redirect_param", True),
    # Protocol-relative -> True
    ("//evil.com/", "redirect_param", True),
    ("//attacker.com/steal", "redirect_param", True),
    ("//app.com@evil.com/", "redirect_param", True),
    # Internal / same-domain absolute -> False
    ("https://app.com/path", "redirect_param", False),
    ("http://localhost/", "redirect_param", False),
    ("https://127.0.0.1/", "redirect_param", False),
    # Not URLs -> False
    ("", "redirect_param", False),
    ("   ", "redirect_param", False),
    ("test_input", "redirect_param", False),
    ("hello", "redirect_param", False),
    ("/home", "redirect_param", False),
    # Scheme without // (e.g. https:evil.com) -> no netloc -> False
    ("https:evil.com", "redirect_param", False),
]


@pytest.mark.parametrize("payload,location,expected", CASES)
def test_can_fire(payload, location, expected):
    assert can_fire(payload, location) is expected
