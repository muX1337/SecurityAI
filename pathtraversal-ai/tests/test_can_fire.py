"""Tests for can_fire.py: path traversal heuristic."""
from __future__ import annotations

import pytest
from pathtraversal_ai.can_fire import can_fire


@pytest.mark.parametrize(
    "payload,location,expected",
    [
        # Classic traversal -> fire.
        ("../../../etc/passwd", "file_read", True),
        ("../../../../etc/passwd", "file_include", True),
        # Absolute Unix -> fire.
        ("/etc/passwd", "file_read", True),
        ("/etc/shadow", "file_include", True),
        ("/proc/self/environ", "file_read", True),
        # Windows drive -> fire.
        ("C:\\Windows\\win.ini", "file_read", True),
        # PHP wrappers -> fire.
        ("php://filter/convert.base64-encode/resource=index.php", "file_include", True),
        ("file:///etc/passwd", "file_read", True),
        ("data://text/plain;base64,SGVsbG8=", "file_include", True),
        # Encoded traversal -> fire.
        ("..%2f..%2fetc%2fpasswd", "file_read", True),
        ("%2e%2e%2fetc%2fpasswd", "file_read", True),
        ("..%252f..%252fetc%252fpasswd", "file_read", True),
        # Null byte suffix -> fire.
        ("/etc/passwd%00", "file_include", True),
        # Smuggled sequences -> fire.
        ("....//....//etc/passwd", "file_read", True),
        # Plain benign filenames -> never fire.
        ("safe_file.txt", "file_read", False),
        ("index.php", "file_include", False),
        ("readme.txt", "template_path", False),
        # Empty / whitespace -> never fire.
        ("", "file_read", False),
        ("   ", "file_include", False),
    ],
)
def test_can_fire_parametrized(payload, location, expected):
    assert can_fire(payload, location) is expected


class TestCanFireKeywords:
    def test_traversal_fires(self):
        assert can_fire("../../etc/passwd", "file_read")

    def test_absolute_proc_fires(self):
        assert can_fire("/proc/self/cmdline", "file_read")

    def test_var_log_fires(self):
        assert can_fire("/var/log/auth.log", "file_read")

    def test_windows_backslash_fires(self):
        assert can_fire("..\\..\\Windows\\win.ini", "file_read")

    def test_php_filter_fires(self):
        assert can_fire("php://filter/read=string.rot13/resource=index.php", "file_include")

    def test_file_scheme_fires(self):
        assert can_fire("file:///C:/Windows/win.ini", "file_read")


class TestCanFireEdgeCases:
    def test_empty(self):
        assert can_fire("", "file_read") is False

    def test_whitespace_only(self):
        assert can_fire("   ", "file_include") is False

    def test_dot_slash_relative(self):
        assert can_fire("./secret.txt", "file_read") is True

    def test_benign_word(self):
        assert can_fire("hello", "file_read") is False

    def test_benign_number(self):
        assert can_fire("123", "file_include") is False
