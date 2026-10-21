from xss_ai.generate import GENERATION_DEFAULTS, parse_generation_output


def test_parse_generation_output_extracts_payload():
    raw = "### Context:\nDesc.\n\n### Payload:\n<svg onload=alert(1)>\n<some trailing>"
    payload = parse_generation_output(raw)
    assert payload == "<svg onload=alert(1)>"

def test_parse_generation_output_returns_none_on_failure():
    assert parse_generation_output("no marker here") is None

def test_generation_defaults_has_sensible_values():
    assert "greedy" in GENERATION_DEFAULTS["strategies"]
    assert "sampling" in GENERATION_DEFAULTS["strategies"]
    assert GENERATION_DEFAULTS["max_new_tokens"] > 0
    assert GENERATION_DEFAULTS["max_new_tokens"] <= 256  # payloads are short

def test_generation_defaults_sampling_params():
    assert 0 < GENERATION_DEFAULTS["temperature"] <= 1.0
    assert 0 < GENERATION_DEFAULTS["top_p"] <= 1.0
