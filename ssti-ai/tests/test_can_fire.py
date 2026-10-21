import pytest
from ssti_ai.can_fire import can_fire

CASES = [
    # Jinja2/Twig expressions
    ("{{7*7}}", "jinja2_body", True),
    ("{{config}}", "jinja2_body", True),
    ("{%import os%}", "jinja2_body", True),
    ("{{7*7}}", "twig_body", True),
    # FreeMarker/Mako dollar-brace
    ("${7*7}", "freemarker_body", True),
    ("${7*7}", "mako_body", True),
    # Velocity
    ("$ex.waitFor()", "velocity_body", True),
    # Generic cross-engine syntax
    ("<%= 7*7 %>", "jinja2_body", True),
    ("#{7*7}", "jinja2_body", True),
    ("*{7*7}", "jinja2_body", True),
    # Benign / negatives
    ("", "jinja2_body", False),
    ("   ", "jinja2_body", False),
    ("hello world", "jinja2_body", False),
    ("test_input", "jinja2_body", False),
    # Wrong-delimiter payload that no engine marker matches (plain text)
    ("just some text", "jinja2_body", False),
]


@pytest.mark.parametrize("payload,location,expected", CASES)
def test_can_fire(payload, location, expected):
    assert can_fire(payload, location) is expected
