"""Tests for can_fire.py: shell metacharacter / keyword heuristic."""
from __future__ import annotations

import pytest
from cmdi_ai.can_fire import can_fire


@pytest.mark.parametrize(
    "payload,location,expected",
    [
        # Classic command separators -> fire.
        (";whoami", "shell_arg", True),
        ("|whoami", "shell_arg", True),
        ("&&whoami", "shell_arg", True),
        ("&whoami", "shell_arg", True),
        ("`whoami`", "shell_arg", True),
        ("$(whoami)", "shell_arg", True),
        ("|| whoami", "shell_arg", True),
        # Encoded newline -> fire.
        ("%0awhoami", "shell_arg", True),
        ("%0dwhoami", "shell_arg", True),
        # Redirect chars -> fire (they are metacharacters).
        ("echo > file", "shell_arg", True),
        # Plain command keywords fire ONLY in shell_command context.
        ("whoami", "shell_command", True),
        ("whoami", "shell_arg", False),
        ("id", "shell_command", True),
        ("id", "shell_arg", False),
        # Plain benign text never fires.
        ("localhost", "shell_arg", False),
        ("localhost", "shell_command", False),
        ("hello", "shell_arg", False),
        ("test_input", "shell_arg", False),
        # Empty / whitespace never fires.
        ("", "shell_arg", False),
        ("   ", "shell_command", False),
    ],
)
def test_can_fire_parametrized(payload, location, expected):
    assert can_fire(payload, location) is expected


class TestCanFireMetacharacters:
    def test_semicolon_fires(self):
        assert can_fire(";whoami", "shell_arg") is True

    def test_pipe_fires(self):
        assert can_fire("|whoami", "shell_arg") is True

    def test_ampersand_fires(self):
        assert can_fire("&whoami", "shell_arg") is True

    def test_double_ampersand_fires(self):
        assert can_fire("&&whoami", "shell_arg") is True

    def test_backtick_fires(self):
        assert can_fire("`whoami`", "shell_arg") is True

    def test_dollar_paren_fires(self):
        assert can_fire("$(whoami)", "shell_arg") is True


class TestCanFireKeywords:
    def test_keyword_fires_in_shell_command(self):
        assert can_fire("whoami", "shell_command") is True

    def test_keyword_does_not_fire_in_shell_arg(self):
        # "whoami" alone (no metachar) is just a benign string when passed as an arg.
        assert can_fire("whoami", "shell_arg") is False

    def test_cat_keyword_fires_in_shell_command(self):
        assert can_fire("cat /etc/passwd", "shell_command") is True


class TestCanFireEdgeCases:
    def test_empty(self):
        assert can_fire("", "shell_arg") is False

    def test_whitespace_only(self):
        assert can_fire("   ", "shell_arg") is False

    def test_encoded_newline_fires(self):
        assert can_fire("%0awhoami", "shell_arg") is True

    def test_redirect_fires(self):
        assert can_fire("echo>x", "shell_arg") is True
