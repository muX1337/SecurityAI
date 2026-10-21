from ssrf_ai.corpus_loader import load_payloads_from_dir, normalize_payload


def test_normalize_payload_strips_whitespace():
    assert normalize_payload("  http://127.0.0.1/  \n") == "http://127.0.0.1/"

def test_normalize_payload_drops_empty():
    assert normalize_payload("   \n\t") == ""

def test_normalize_payload_drops_comments():
    assert normalize_payload("# this is a comment") == ""

def test_load_payloads_from_dir(tmp_path):
    d = tmp_path / "corpus"
    d.mkdir()
    (d / "a.txt").write_text("http://127.0.0.1/\nhttp://2130706433/\n")
    (d / "b.txt").write_text("file:///etc/passwd")
    payloads = load_payloads_from_dir(d)
    assert len(payloads) == 3
    assert "http://127.0.0.1/" in payloads

def test_load_payloads_dedups(tmp_path):
    d = tmp_path / "corpus"
    d.mkdir()
    (d / "a.txt").write_text("http://127.0.0.1/\nhttp://127.0.0.1/")
    payloads = load_payloads_from_dir(d)
    assert len(payloads) == 1
