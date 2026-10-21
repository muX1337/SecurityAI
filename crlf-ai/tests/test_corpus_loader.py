from crlf_ai.corpus_loader import (
    BUILTIN_PAYLOADS,
    load_all_corpora,
    load_payloads_from_dir,
    load_payloads_from_file,
    normalize_payload,
)


def test_normalize_payload_strips_whitespace():
    assert normalize_payload("  %0d%0aSet-Cookie: evil=1  \n") == "%0d%0aSet-Cookie: evil=1"


def test_normalize_payload_drops_empty():
    assert normalize_payload("   \n\t") == ""


def test_normalize_payload_drops_comments():
    assert normalize_payload("# this is a comment") == ""


def test_normalize_payload_strips_leading_trailing_whitespace():
    # Leading/trailing whitespace (including CRLF bytes) is stripped.
    assert normalize_payload("  \r\n%0d%0aSet-Cookie: evil=1\r\n  ") == "%0d%0aSet-Cookie: evil=1"


def test_normalize_payload_preserves_interior_control_bytes():
    # Interior \r\n bytes are the payload itself and must survive.
    assert normalize_payload("a\r\nb\r\nSet-Cookie: evil=1") == "a\r\nb\r\nSet-Cookie: evil=1"


def test_load_payloads_from_file(tmp_path):
    f = tmp_path / "payloads.txt"
    f.write_text("%0d%0aSet-Cookie: evil=1\n# comment\n\n%0d%0aLocation: https://evil.com\n")
    payloads = load_payloads_from_file(f)
    assert payloads == ["%0d%0aSet-Cookie: evil=1", "%0d%0aLocation: https://evil.com"]


def test_load_payloads_from_dir(tmp_path):
    d = tmp_path / "corpus"
    d.mkdir()
    (d / "a.txt").write_text("%0d%0aSet-Cookie: evil=1\n%0d%0aContent-Length: 0\n")
    (d / "b.txt").write_text("%0d%0aLocation: https://evil.com")
    payloads = load_payloads_from_dir(d)
    assert len(payloads) == 3
    assert "%0d%0aSet-Cookie: evil=1" in payloads


def test_load_payloads_from_dir_dedups(tmp_path):
    d = tmp_path / "corpus"
    d.mkdir()
    (d / "a.txt").write_text("%0d%0aSet-Cookie: evil=1\n%0d%0aSet-Cookie: evil=1")
    payloads = load_payloads_from_dir(d)
    assert len(payloads) == 1


def test_load_payloads_from_dir_missing_returns_empty(tmp_path):
    assert load_payloads_from_dir(tmp_path / "does_not_exist") == []


def test_builtin_payloads_contains_encoded_crlf_set_cookie():
    assert any("%0d%0aSet-Cookie:" in p for p in BUILTIN_PAYLOADS)


def test_builtin_payloads_contains_benign_negatives():
    assert "test_input" in BUILTIN_PAYLOADS
    assert "hello_world" in BUILTIN_PAYLOADS
    assert "normal_value" in BUILTIN_PAYLOADS


def test_load_all_corpora_includes_builtins(tmp_path):
    # raw dir without SecLists / PayloadsAllTheThings subdirs -> just builtins.
    payloads = load_all_corpora(tmp_path)
    assert len(payloads) > 0
    assert any("Set-Cookie" in p for p in payloads)


def test_load_all_corpora_dedups(tmp_path):
    payloads = load_all_corpora(tmp_path)
    assert len(payloads) == len(set(payloads))


def test_load_all_corpora_reads_external_subdirs(tmp_path):
    raw = tmp_path / "raw"
    sec = raw / "SecLists"
    sec.mkdir(parents=True)
    (sec / "extra.txt").write_text("UNIQUE_EXTERNAL_PAYLOAD_%0d%0aSet-Cookie: x=1\n")
    payloads = load_all_corpora(raw)
    assert "UNIQUE_EXTERNAL_PAYLOAD_%0d%0aSet-Cookie: x=1" in payloads
