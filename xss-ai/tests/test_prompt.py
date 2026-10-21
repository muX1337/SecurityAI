from xss_ai.prompt import (
    PROMPT_SEPARATOR,
    extract_payload,
    format_example,
    format_prompt,
)


def test_format_prompt_wraps_description():
    desc = "Input is reflected into the HTML body (element content)."
    result = format_prompt(desc)
    assert "### Context:" in result
    assert desc in result
    assert "### Payload:" in result
    assert result.endswith("### Payload:\n")

def test_format_example_concatenates_prompt_and_payload():
    desc = "Input is reflected into the HTML body."
    payload = "<svg onload=alert(1)>"
    result = format_example(desc, payload)
    assert payload in result
    assert "### Context:" in result
    assert "### Payload:" in result
    # payload comes after the separator
    assert result.index(payload) > result.index("### Payload:")

def test_extract_payload_strips_prompt():
    text = "### Context:\nSome description.\n\n### Payload:\n<svg onload=alert(1)>"
    payload = extract_payload(text)
    assert payload == "<svg onload=alert(1)>"

def test_extract_payload_handles_extra_text():
    text = "garbage before### Context:\nDesc.\n\n### Payload:\n<img src=x onerror=alert(1)>\nmore stuff"
    payload = extract_payload(text)
    assert payload == "<img src=x onerror=alert(1)>"

def test_extract_payload_returns_none_if_no_separator():
    payload = extract_payload("no payload marker here")
    assert payload is None

def test_prompt_separator_is_string():
    assert isinstance(PROMPT_SEPARATOR, str)
    assert "### Payload:" in PROMPT_SEPARATOR
