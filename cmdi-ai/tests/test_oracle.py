"""Tests for the subprocess-backed CMDi oracle (oracle/check_fires.py)."""
from __future__ import annotations

from cmdi_ai.context import ContextSpec
from cmdi_ai.oracle.check_fires import OracleSession, check_fires


class TestOracleSessionBasics:
    def test_fires_on_semicolon(self):
        # ";whoami" chains a command after the base -> marker created.
        ctx = ContextSpec(id="x", location="shell_arg", filters=[])
        with OracleSession() as session:
            assert session.check_fires(ctx, ";whoami") is True

    def test_fires_on_pipe(self):
        ctx = ContextSpec(id="x", location="shell_arg", filters=[])
        with OracleSession() as session:
            assert session.check_fires(ctx, "|whoami") is True

    def test_fires_on_ampersand(self):
        ctx = ContextSpec(id="x", location="shell_arg", filters=[])
        with OracleSession() as session:
            assert session.check_fires(ctx, "&whoami") is True

    def test_fires_on_double_ampersand(self):
        ctx = ContextSpec(id="x", location="shell_arg", filters=[])
        with OracleSession() as session:
            assert session.check_fires(ctx, "&&whoami") is True

    def test_fires_on_backtick(self):
        ctx = ContextSpec(id="x", location="shell_arg", filters=[])
        with OracleSession() as session:
            assert session.check_fires(ctx, "`whoami`") is True

    def test_fires_on_dollar_substitution(self):
        ctx = ContextSpec(id="x", location="shell_arg", filters=[])
        with OracleSession() as session:
            assert session.check_fires(ctx, "$(whoami)") is True

    def test_fires_on_or_separator(self):
        ctx = ContextSpec(id="x", location="shell_arg", filters=[])
        with OracleSession() as session:
            assert session.check_fires(ctx, "|| whoami") is True

    def test_does_not_fire_on_plain_text(self):
        ctx = ContextSpec(id="x", location="shell_arg", filters=[])
        with OracleSession() as session:
            assert session.check_fires(ctx, "localhost") is False

    def test_does_not_fire_on_empty(self):
        ctx = ContextSpec(id="x", location="shell_arg", filters=[])
        with OracleSession() as session:
            assert session.check_fires(ctx, "") is False


class TestOracleFilters:
    def test_blocked_by_block_semicolon(self):
        ctx = ContextSpec(
            id="x", location="shell_arg", filters=["block_semicolon"]
        )
        with OracleSession() as session:
            assert session.check_fires(ctx, ";whoami") is False

    def test_blocked_by_block_pipe(self):
        ctx = ContextSpec(
            id="x", location="shell_arg", filters=["block_pipe"]
        )
        with OracleSession() as session:
            assert session.check_fires(ctx, "|whoami") is False

    def test_blocked_by_block_ampersand(self):
        ctx = ContextSpec(
            id="x", location="shell_arg", filters=["block_ampersand"]
        )
        with OracleSession() as session:
            assert session.check_fires(ctx, "&whoami") is False

    def test_blocked_by_block_backtick(self):
        ctx = ContextSpec(
            id="x", location="shell_arg", filters=["block_backtick"]
        )
        with OracleSession() as session:
            assert session.check_fires(ctx, "`whoami`") is False

    def test_blocked_by_block_dollar(self):
        ctx = ContextSpec(
            id="x", location="shell_arg", filters=["block_dollar"]
        )
        with OracleSession() as session:
            assert session.check_fires(ctx, "$(whoami)") is False

    def test_blocked_by_alphanumeric_only(self):
        # Strips the semicolon, leaving "whoami" — no injection vector remains.
        ctx = ContextSpec(
            id="x", location="shell_arg", filters=["alphanumeric_only"]
        )
        with OracleSession() as session:
            assert session.check_fires(ctx, ";whoami") is False

    def test_block_semicolon_allows_pipe(self):
        ctx = ContextSpec(
            id="x", location="shell_arg", filters=["block_semicolon"]
        )
        with OracleSession() as session:
            # Pipe is not blocked -> fires.
            assert session.check_fires(ctx, "|whoami") is True

    def test_benign_payload_skipped_by_can_fire(self):
        # can_fire rejects benign text before any subprocess runs.
        ctx = ContextSpec(id="x", location="shell_arg", filters=[])
        with OracleSession() as session:
            assert session.check_fires(ctx, "totally harmless") is False


class TestOracleLocations:
    def test_shell_command_fires_on_direct_command(self):
        # In shell_command, the input IS the command.
        ctx = ContextSpec(id="c", location="shell_command", filters=[])
        with OracleSession() as session:
            assert session.check_fires(ctx, "whoami") is True

    def test_shell_command_fires_on_separator(self):
        ctx = ContextSpec(id="c", location="shell_command", filters=[])
        with OracleSession() as session:
            assert session.check_fires(ctx, ";id") is True

    def test_filename_arg_fires_on_semicolon(self):
        ctx = ContextSpec(id="f", location="filename_arg", filters=[])
        with OracleSession() as session:
            assert session.check_fires(ctx, ";whoami") is True

    def test_variable_value_fires_on_semicolon(self):
        ctx = ContextSpec(id="v", location="variable_value", filters=[])
        with OracleSession() as session:
            assert session.check_fires(ctx, ";whoami") is True

    def test_variable_value_fires_on_dollar(self):
        ctx = ContextSpec(id="v", location="variable_value", filters=[])
        with OracleSession() as session:
            assert session.check_fires(ctx, "$(whoami)") is True


class TestStandaloneCheckFires:
    def test_standalone_fires_on_semicolon(self):
        ctx = ContextSpec(id="x", location="shell_arg", filters=[])
        # The standalone form opens its own temp-dir session.
        assert check_fires(ctx, ";whoami") is True

    def test_standalone_does_not_fire_on_plain_text(self):
        ctx = ContextSpec(id="x", location="shell_arg", filters=[])
        assert check_fires(ctx, "hello") is False

    def test_standalone_returns_bool(self):
        ctx = ContextSpec(id="x", location="shell_arg", filters=[])
        assert isinstance(check_fires(ctx, ";whoami"), bool)
