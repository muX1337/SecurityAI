from xss_ai.eval.metrics import diversity_score, refusal_rate, valid_syntax_rate


def test_valid_syntax_rate_all_valid():
    payloads = [
        "<script>alert(1)</script>",
        "<svg onload=alert(1)>",
        "<img src=x onerror=alert(1)>",
    ]
    assert valid_syntax_rate(payloads) == 1.0

def test_valid_syntax_rate_mixed():
    payloads = [
        "<script>alert(1)</script>",  # valid
        "hello world",                  # invalid
        "<svg onload=alert(1)>",       # valid
        "not a payload",                # invalid
    ]
    assert valid_syntax_rate(payloads) == 0.5

def test_valid_syntax_rate_empty():
    assert valid_syntax_rate([]) == 0.0

def test_valid_syntax_javascript_uri():
    payloads = ["javascript:alert(1)"]
    assert valid_syntax_rate(payloads) == 1.0

def test_valid_syntax_quote_breakout():
    payloads = ['"><script>alert(1)</script>']
    assert valid_syntax_rate(payloads) == 1.0

def test_refusal_rate_zero():
    payloads = ["<script>alert(1)</script>", "<svg onload=alert(1)>"]
    assert refusal_rate(payloads) == 0.0

def test_refusal_rate_detects_common_phrases():
    payloads = [
        "I cannot help with that.",
        "I'm sorry, but I can't generate XSS payloads.",
        "I can't assist with this request.",
    ]
    assert refusal_rate(payloads) == 1.0

def test_refusal_rate_mixed():
    payloads = [
        "<script>alert(1)</script>",
        "I cannot help with that.",
    ]
    assert refusal_rate(payloads) == 0.5

def test_diversity_score_all_same():
    """When all samples produce the same payload, diversity = 0."""
    payloads = ["<svg onload=alert(1)>"] * 10
    assert diversity_score(payloads) == 0.0

def test_diversity_score_all_unique():
    payloads = [f"<svg onload=alert({i})>" for i in range(10)]
    assert diversity_score(payloads) == 1.0

def test_diversity_score_partial():
    payloads = ["<svg onload=alert(1)>"] * 5 + [f"<img onerror=alert({i})>" for i in range(5)]
    score = diversity_score(payloads)
    assert 0.0 < score < 1.0

def test_diversity_score_empty():
    assert diversity_score([]) == 0.0
