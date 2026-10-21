from openredirect_ai.corpus_loader import (
    BUILTIN_PAYLOADS,
    load_payloads_from_dir,
    normalize_payload,
)


def test_normalize_payload_strips_whitespace():
    assert normalize_payload("  https://evil.com/  \n") == "https://evil.com/"


def test_normalize_payload_drops_empty():
    assert normalize_payload("   \n\t") == ""


def test_normalize_payload_drops_comments():
    assert normalize_payload("# this is a comment") == ""


def test_builtin_payloads_has_at_least_40():
    assert len(BUILTIN_PAYLOADS) >= 40


def test_builtin_contains_canonical_evil():
    assert "https://evil.com/" in BUILTIN_PAYLOADS
    assert "//evil.com/" in BUILTIN_PAYLOADS


def test_load_payloads_from_dir(tmp_path):
    d = tmp_path / "corpus"
    d.mkdir()
    (d / "a.txt").write_text("//evil.com/\nhttps://attacker.com/\n")
    (d / "b.txt").write_text("https://app.com@evil.com/")
    payloads = load_payloads_from_dir(d)
    assert len(payloads) == 3
    assert "//evil.com/" in payloads


def test_load_payloads_dedups(tmp_path):
    d = tmp_path / "corpus"
    d.mkdir()
    (d / "a.txt").write_text("//evil.com/\n//evil.com/")
    payloads = load_payloads_from_dir(d)
    assert len(payloads) == 1
