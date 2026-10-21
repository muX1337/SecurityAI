"""Tests for corpus_loader.py: normalize, load_from_file/dir, BUILTIN_PAYLOADS."""
from __future__ import annotations

from sqli_ai.corpus_loader import (
    BUILTIN_PAYLOADS,
    load_all_corpora,
    load_payloads_from_dir,
    load_payloads_from_file,
    normalize_payload,
)


class TestNormalizePayload:
    def test_strips_whitespace(self):
        assert normalize_payload("  ' OR 1=1 --  \n") == "' OR 1=1 --"

    def test_drops_empty(self):
        assert normalize_payload("   \n\t") == ""

    def test_drops_blank(self):
        assert normalize_payload("") == ""

    def test_drops_comments(self):
        assert normalize_payload("# this is a comment") == ""

    def test_drops_indented_comment(self):
        assert normalize_payload("   # leading-hash comment") == ""

    def test_keeps_hash_inside_payload(self):
        # A payload that legitimately contains a hash (mid-string) is kept;
        # only lines STARTING with # after stripping are dropped.
        assert normalize_payload("' OR 1=1 #") == "' OR 1=1 #"

    def test_keeps_plain_payload(self):
        assert normalize_payload("admin") == "admin"


class TestLoadPayloadsFromFile:
    def test_loads_lines(self, tmp_path):
        f = tmp_path / "p.txt"
        f.write_text("' OR 1=1 --\nadmin'--\nhello\n")
        out = load_payloads_from_file(f)
        assert out == ["' OR 1=1 --", "admin'--", "hello"]

    def test_skips_blank_and_comments(self, tmp_path):
        f = tmp_path / "p.txt"
        f.write_text("# header\n' OR 1=1 --\n\n  \nadmin\n# trailing\n")
        out = load_payloads_from_file(f)
        assert out == ["' OR 1=1 --", "admin"]

    def test_strips_each_line(self, tmp_path):
        f = tmp_path / "p.txt"
        f.write_text("  admin  \n\tguest\t\n")
        out = load_payloads_from_file(f)
        assert out == ["admin", "guest"]


class TestLoadPayloadsFromDir:
    def test_loads_multiple_files(self, tmp_path):
        d = tmp_path / "corpus"
        d.mkdir()
        (d / "a.txt").write_text("' OR 1=1 --\n1 UNION SELECT 1,2,3 --\n")
        (d / "b.txt").write_text("admin'--")
        out = load_payloads_from_dir(d)
        assert set(out) == {"' OR 1=1 --", "1 UNION SELECT 1,2,3 --", "admin'--"}

    def test_dedups_across_files(self, tmp_path):
        d = tmp_path / "corpus"
        d.mkdir()
        (d / "a.txt").write_text("' OR 1=1 --\n' OR 1=1 --")
        (d / "b.txt").write_text("' OR 1=1 --")
        out = load_payloads_from_dir(d)
        assert out == ["' OR 1=1 --"]

    def test_empty_dir(self, tmp_path):
        d = tmp_path / "corpus"
        d.mkdir()
        assert load_payloads_from_dir(d) == []

    def test_missing_dir_returns_empty(self, tmp_path):
        d = tmp_path / "nope"
        assert load_payloads_from_dir(d) == []

    def test_recursive(self, tmp_path):
        sub = tmp_path / "corpus" / "sub"
        sub.mkdir(parents=True)
        (sub / "deep.txt").write_text("' UNION SELECT 1,2,3 --")
        out = load_payloads_from_dir(tmp_path / "corpus")
        assert "' UNION SELECT 1,2,3 --" in out


class TestBuiltinPayloads:
    def test_has_at_least_thirty(self):
        assert len(BUILTIN_PAYLOADS) >= 30

    def test_contains_classic_tautology(self):
        assert "' OR '1'='1" in BUILTIN_PAYLOADS

    def test_contains_numeric_payload(self):
        assert "1 OR 1=1" in BUILTIN_PAYLOADS

    def test_contains_plain_safe_strings(self):
        assert "hello" in BUILTIN_PAYLOADS
        assert "123" in BUILTIN_PAYLOADS
        assert "test_input" in BUILTIN_PAYLOADS

    def test_all_nonempty(self):
        for p in BUILTIN_PAYLOADS:
            assert p.strip() != ""


class TestLoadAllCorpora:
    def test_falls_back_to_builtins_when_no_raw(self, tmp_path):
        out = load_all_corpora(tmp_path / "raw")
        # Built-ins always available even with no external corpora.
        assert len(out) == len(set(BUILTIN_PAYLOADS))  # deduped
        assert "' OR '1'='1" in out

    def test_external_plus_builtins_deduped(self, tmp_path):
        raw = tmp_path / "raw" / "SecLists"
        raw.mkdir(parents=True)
        (raw / "sqli.txt").write_text("' OR '1'='1\n1 UNION SELECT 1,2,3 --")
        out = load_all_corpora(tmp_path / "raw")
        # The external payload duplicates a builtin, so no extra entry for it.
        assert out.count("' OR '1'='1") == 1
        assert "1 UNION SELECT 1,2,3 --" in out
        # All builtins still present.
        for p in BUILTIN_PAYLOADS:
            assert p in out

    def test_external_payloads_come_first(self, tmp_path):
        raw = tmp_path / "raw" / "PayloadsAllTheThings"
        raw.mkdir(parents=True)
        (raw / "extra.txt").write_text("ZZZ_UNIQUE_EXTERNAL_PAYLOAD")
        out = load_all_corpora(tmp_path / "raw")
        # External corpora are loaded before builtins.
        assert out[0] == "ZZZ_UNIQUE_EXTERNAL_PAYLOAD"
