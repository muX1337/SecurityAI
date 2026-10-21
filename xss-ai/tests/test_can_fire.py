import pytest
from xss_ai.can_fire import AUTO_FIRING_HANDLERS, can_fire

# (payload_after_filter, location, expected_can_fire)
CASES = [
    # HTML body: classic auto-firing patterns
    ("<script>alert(1)</script>", "html_body", True),
    ("<svg onload=alert(1)>", "html_body", True),
    ("<img src=x onerror=alert(1)>", "html_body", True),
    ("<body onload=alert(1)>", "html_body", True),
    # event handler that needs interaction -> now correctly REJECTED
    ("<aside id=x tabindex=1 onfocusin=alert(1)></aside>", "html_body", False),
    ("<option onbeforeactivate=alert(1)>", "html_body", False),
    ("<div onmouseover=alert(1)>x</div>", "html_body", False),
    # onfocus WITHOUT autofocus/tabindex -> rejected
    ("<input onfocus=alert(1)>", "html_body", False),
    # onfocus WITH autofocus -> accepted
    ("<input onfocus=alert(1) autofocus>", "html_body", True),
    # ontoggle on details with open -> accepted
    ("<details open ontoggle=alert(1)>", "html_body", True),
    # ontoggle without open -> rejected (won't fire)
    ("<details ontoggle=alert(1)>", "html_body", False),
    # stripped of brackets -> no tag -> cannot fire
    ("scriptalert(1)/script", "html_body", False),
    # event handler survived but no sink -> cannot fire
    ("<svg onload=x>", "html_body", False),
    # empty
    ("", "html_body", False),

    # Double-quoted attribute: must break out (">) then carry an auto-firing handler+sink
    ('"><svg onload=alert(1)>', "attr_dq", True),
    ('"><script>alert(1)</script>', "attr_dq", True),
    # breakout but only interaction handler -> rejected
    ('"><div onmouseover=alert(1)>', "attr_dq", False),
    # quote escaped, no breakout
    ('x&quot;&gt;', "attr_dq", False),

    # Single-quoted attribute
    ("'><svg onload=alert(1)>", "attr_sq", True),

    # JS single-quoted string: must break out (';) then call a sink
    ("';alert(1);//", "js_string_sq", True),
    # still inside the string
    ("hello world", "js_string_sq", False),
]


@pytest.mark.parametrize("payload,location,expected", CASES)
def test_can_fire(payload, location, expected):
    assert can_fire(payload, location) is expected


def test_auto_firing_handlers_includes_core_set():
    for h in ("onload", "onerror"):
        assert h in AUTO_FIRING_HANDLERS


def test_interaction_handlers_not_in_auto_firing_set():
    for h in ("onmouseover", "onfocusin", "onclick", "ondragleave", "onbeforeactivate"):
        assert h not in AUTO_FIRING_HANDLERS
