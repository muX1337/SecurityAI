"""Tests for corpus_loader.py: normalize, load_from_file/dir, BUILTIN_PAYLOADS."""
from __future__ import annotations

from pathtraversal_ai.corpus_loader import (
    BUILTIN_PAYLOADS,
    load_all_corpora,
    load_payloads_from_dir,
    load_payloads_from_file,
    normalize_payload,
)


class TestNormalizePayload:
    def test_strips_whitespace(self):
        assert normalize_payload("  ../../../etc/passwd  \n") == "../../../etc/passwd"

    def test_drops_empty(self):
        assert normalize_payload("   \n\t") == ""

    def test_drops_blank(self):
        assert normalize_payload("") == ""

    def test_drops_comments(self):
        assert normalize_payload("# this is a comment") == ""

    def test_drops_indented_comment(self):
        assert normalize_payload("   # leading-hash comment") == ""

    def test_keeps_hash_inside_payload(self):
        # A payload that legitimately contains a hash (mid-string) is kept.
        assert normalize_payload("../etc/passwd#frag") == "../etc/passwd#frag"

    def test_keeps_plain_payload(self):
        assert normalize_payload("../../../etc/passwd") == "../../../etc/passwd"


class TestLoadPayloadsFromFile:
    def test_loads_lines(self, tmp_path):
        f = tmp_path / "p.txt"
        f.write_text("../../../etc/passwd\n/etc/shadow\nsafe_file.txt\n")
        out = load_payloads_from_file(f)
        assert out == ["../../../etc/passwd", "/etc/shadow", "safe_file.txt"]

    def test_skips_blank_and_comments(self, tmp_path):
        f = tmp_path / "p.txt"
        f.write_text("# header\n../../../etc/passwd\n\n  \nsafe_file.txt\n# trailing\n")
        out = load_payloads_from_file(f)
        assert out == ["../../../etc/passwd", "safe_file.txt"]

    def test_strips_each_line(self, tmp_path):
        f = tmp_path / "p.txt"
        f.write_text("  ../../etc/passwd  \n\t/etc/shadow\t\n")
        out = load_payloads_from_file(f)
        assert out == ["../../etc/passwd", "/etc/shadow"]


class TestLoadPayloadsFromDir:
    def test_loads_multiple_files(self, tmp_path):
        d = tmp_path / "corpus"
        d.mkdir()
        (d / "a.txt").write_text("../../../etc/passwd\n/etc/shadow\n")
        (d / "b.txt").write_text("/proc/self/environ")
        out = load_payloads_from_dir(d)
        assert set(out) == {"../../../etc/passwd", "/etc/shadow", "/proc/self/environ"}

    def test_dedups_across_files(self, tmp_path):
        d = tmp_path / "corpus"
        d.mkdir()
        (d / "a.txt").write_text("../../../etc/passwd\n../../../etc/passwd")
        (d / "b.txt").write_text("../../../etc/passwd")
        out = load_payloads_from_dir(d)
        assert out == ["../../../etc/passwd"]

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
        (sub / "deep.txt").write_text("/proc/version")
        out = load_payloads_from_dir(tmp_path / "corpus")
        assert "/proc/version" in out


class TestBuiltinPayloads:
    def test_has_at_least_fifty(self):
        assert len(BUILTIN_PAYLOADS) >= 50

    def test_contains_classic_traversal(self):
        assert "../../../etc/passwd" in BUILTIN_PAYLOADS

    def test_contains_php_wrapper(self):
        assert "php://filter/convert.base64-encode/resource=index.php" in BUILTIN_PAYLOADS

    def test_contains_windows_target(self):
        assert "C:\\Windows\\win.ini" in BUILTIN_PAYLOADS

    def test_contains_null_byte(self):
        assert "/etc/passwd%00" in BUILTIN_PAYLOADS

    def test_contains_plain_safe_filenames(self):
        assert "safe_file.txt" in BUILTIN_PAYLOADS

    def test_all_nonempty(self):
        for p in BUILTIN_PAYLOADS:
            assert p.strip() != ""


class TestLoadAllCorpora:
    def test_falls_back_to_builtins_when_no_raw(self, tmp_path):
        out = load_all_corpora(tmp_path / "raw")
        assert len(out) == len(set(BUILTIN_PAYLOADS))  # deduped
        assert "../../../etc/passwd" in out

    def test_external_plus_builtins_deduped(self, tmp_path):
        raw = tmp_path / "raw" / "SecLists"
        raw.mkdir(parents=True)
        (raw / "trav.txt").write_text("../../../etc/passwd\n/proc/self/environ")
        out = load_all_corpora(tmp_path / "raw")
        assert out.count("../../../etc/passwd") == 1
        assert "/proc/self/environ" in out
        for p in BUILTIN_PAYLOADS:
            assert p in out

    def test_external_payloads_come_first(self, tmp_path):
        raw = tmp_path / "raw" / "PayloadsAllTheThings"
        raw.mkdir(parents=True)
        (raw / "extra.txt").write_text("ZZZ_UNIQUE_EXTERNAL_PAYLOAD")
        out = load_all_corpora(tmp_path / "raw")
        assert out[0] == "ZZZ_UNIQUE_EXTERNAL_PAYLOAD"
