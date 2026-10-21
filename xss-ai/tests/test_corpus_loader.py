from xss_ai.corpus_loader import load_payloads_from_dir, normalize_payload


def test_normalize_payload_strips_whitespace():
    assert normalize_payload("  <script>alert(1)</script>  \n") == "<script>alert(1)</script>"

def test_normalize_payload_drops_empty():
    assert normalize_payload("   \n\t") == ""

def test_normalize_payload_drops_comments():
    # lines that are pure comments after strip should be dropped
    assert normalize_payload("# this is a comment") == ""

def test_load_payloads_from_dir(tmp_path):
    d = tmp_path / "corpus"
    d.mkdir()
    (d / "a.txt").write_text("<script>alert(1)</script>\n<img src=x onerror=alert(1)>\n")
    (d / "b.txt").write_text("<svg onload=alert(1)>")
    payloads = load_payloads_from_dir(d)
    assert len(payloads) == 3
    assert "<script>alert(1)</script>" in payloads

def test_load_payloads_dedups(tmp_path):
    d = tmp_path / "corpus"
    d.mkdir()
    (d / "a.txt").write_text("<script>alert(1)</script>\n<script>alert(1)</script>")
    payloads = load_payloads_from_dir(d)
    assert len(payloads) == 1
