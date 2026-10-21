from ssti_ai.corpus_loader import (
    BUILTIN_PAYLOADS,
    load_payloads_from_dir,
    normalize_payload,
)


def test_normalize_payload_strips_whitespace():
    assert normalize_payload("  {{7*7}}  \n") == "{{7*7}}"

def test_normalize_payload_drops_empty():
    assert normalize_payload("   \n\t") == ""

def test_normalize_payload_drops_comments():
    assert normalize_payload("# this is a comment") == ""

def test_load_payloads_from_dir(tmp_path):
    d = tmp_path / "corpus"
    d.mkdir()
    (d / "a.txt").write_text("{{7*7}}\n{{config}}\n")
    (d / "b.txt").write_text("${7*7}")
    payloads = load_payloads_from_dir(d)
    assert len(payloads) == 3
    assert "{{7*7}}" in payloads

def test_load_payloads_dedups(tmp_path):
    d = tmp_path / "corpus"
    d.mkdir()
    (d / "a.txt").write_text("{{7*7}}\n{{7*7}}")
    payloads = load_payloads_from_dir(d)
    assert len(payloads) == 1

def test_builtin_payloads_has_at_least_40():
    assert len(BUILTIN_PAYLOADS) >= 40

def test_builtin_payloads_contains_math_probe():
    assert "{{7*7}}" in BUILTIN_PAYLOADS

def test_builtin_payloads_contains_config_probe():
    assert "{{config}}" in BUILTIN_PAYLOADS

def test_builtin_payloads_contains_freemarker():
    assert any("${" in p for p in BUILTIN_PAYLOADS)

def test_builtin_payloads_contains_benign():
    assert "hello world" in BUILTIN_PAYLOADS
    assert "test_input" in BUILTIN_PAYLOADS
