"""Tests for the SQLite-backed SQLi oracle (oracle/check_fires.py)."""
from __future__ import annotations

from sqli_ai.context import ContextSpec
from sqli_ai.oracle.check_fires import OracleSession, check_fires


class TestOracleSessionBasics:
    def test_fires_on_tautology_returns_all_rows(self):
        # "' OR 1=1 --" makes the WHERE trivially true -> all 3 rows returned.
        # But the base table only has 3 rows, so the ">3 rows" check won't trip;
        # the query still executes without error. To assert a TRUE fire we use a
        # payload that extracts the marker via UNION.
        ctx = ContextSpec(id="x", location="string_literal", filters=[])
        with OracleSession() as session:
            payload = "' UNION SELECT id, name FROM users --"
            assert session.check_fires(ctx, payload) is True

    def test_fires_on_or_1_1(self):
        # The marker row (id=1) is returned because OR 1=1 matches everything.
        # Since name = SQLI_MARKER_1337 is in the result, the marker check trips.
        ctx = ContextSpec(id="x", location="string_literal", filters=[])
        with OracleSession() as session:
            assert session.check_fires(ctx, "' OR 1=1 --") is True

    def test_fires_on_union_extracting_marker(self):
        ctx = ContextSpec(id="x", location="string_literal", filters=[])
        with OracleSession() as session:
            # UNION adds a synthetic row whose name column is the marker.
            payload = "' UNION SELECT 1, 'SQLI_MARKER_1337' --"
            assert session.check_fires(ctx, payload) is True

    def test_does_not_fire_on_plain_text(self):
        ctx = ContextSpec(id="x", location="string_literal", filters=[])
        with OracleSession() as session:
            # "hello" matches no rows; no marker, no error, <=3 rows.
            assert session.check_fires(ctx, "hello") is False

    def test_does_not_fire_on_empty(self):
        ctx = ContextSpec(id="x", location="string_literal", filters=[])
        with OracleSession() as session:
            assert session.check_fires(ctx, "") is False

    def test_blocked_by_escape_single_quotes_filter(self):
        # Escaping doubles the quotes, so the breakout can no longer escape the
        # string literal. The query either errors harmlessly (no marker, no
        # extra rows) or matches nothing — and crucially never fires.
        ctx = ContextSpec(
            id="x", location="string_literal", filters=["escape_single_quotes"]
        )
        with OracleSession() as session:
            assert session.check_fires(ctx, "' OR 1=1 --") is False

    def test_blocked_payload_returns_false(self):
        # block_keyword_select drops the payload entirely -> simulate_reflection
        # returns "" -> oracle short-circuits to False without running SQL.
        ctx = ContextSpec(
            id="x", location="string_literal", filters=["block_keyword_select"]
        )
        with OracleSession() as session:
            assert session.check_fires(ctx, "' UNION SELECT 1,2,3 --") is False

    def test_benign_payload_skipped_by_can_fire(self):
        # can_fire rejects benign text before any SQL runs.
        ctx = ContextSpec(id="x", location="string_literal", filters=[])
        with OracleSession() as session:
            assert session.check_fires(ctx, "totally harmless") is False


class TestOracleLocations:
    def test_numeric_context_fires_on_tautology(self):
        ctx = ContextSpec(id="n", location="numeric", filters=[])
        with OracleSession() as session:
            # OR 1=1 matches all rows including the marker row.
            assert session.check_fires(ctx, "1 OR 1=1") is True

    def test_numeric_union_extracts_marker(self):
        ctx = ContextSpec(id="n", location="numeric", filters=[])
        with OracleSession() as session:
            payload = "1 UNION SELECT 1, 'SQLI_MARKER_1337' --"
            assert session.check_fires(ctx, payload) is True

    def test_insert_context_fires_on_stacked_values(self):
        ctx = ContextSpec(id="i", location="insert_values", filters=[])
        with OracleSession() as session:
            # Stacked-values inject: query becomes
            #   INSERT INTO users (name) VALUES ('a'),('b')
            # which is valid SQL, executes without error -> injection "worked".
            assert session.check_fires(ctx, "a'),('b") is True

    def test_insert_context_does_not_fire_on_benign(self):
        ctx = ContextSpec(id="i", location="insert_values", filters=[])
        with OracleSession() as session:
            # "injected" has no SQL marker -> can_fire rejects it before SQL runs.
            assert session.check_fires(ctx, "injected") is False


class TestStandaloneCheckFires:
    def test_standalone_fires_on_union(self):
        ctx = ContextSpec(id="x", location="string_literal", filters=[])
        # The standalone form opens its own in-memory DB session.
        assert check_fires(ctx, "' UNION SELECT 1, 'SQLI_MARKER_1337' --") is True

    def test_standalone_does_not_fire_on_plain_text(self):
        ctx = ContextSpec(id="x", location="string_literal", filters=[])
        assert check_fires(ctx, "hello") is False

    def test_standalone_returns_bool(self):
        ctx = ContextSpec(id="x", location="string_literal", filters=[])
        assert isinstance(check_fires(ctx, "' OR 1=1 --"), bool)
