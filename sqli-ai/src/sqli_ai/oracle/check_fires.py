"""SQLi oracle: check_fires(ctx, payload) -> bool.

Uses an in-memory SQLite database. Applies filters to the payload,
injects into a vulnerable query, executes, and checks for success.
"""
from __future__ import annotations

import sqlite3
from typing import Self

from ..can_fire import can_fire
from ..context import ContextSpec, simulate_reflection

# Marker data we insert into the test DB. If the oracle sees this in
# the query result, the injection extracted data successfully.
_MARKER = "SQLI_MARKER_1337"


def _build_query(ctx: ContextSpec, filtered_payload: str) -> str:
    """Build a vulnerable SQL query with the payload injected."""
    if ctx.location == "string_literal":
        return f"SELECT id, name FROM users WHERE name = '{filtered_payload}'"
    elif ctx.location == "numeric":
        return f"SELECT id, name FROM users WHERE id = {filtered_payload}"
    elif ctx.location == "order_by":
        return f"SELECT id, name FROM users ORDER BY {filtered_payload}"
    elif ctx.location == "column_name":
        return f"SELECT {filtered_payload} FROM users"
    elif ctx.location == "insert_values":
        return f"INSERT INTO users (name) VALUES ('{filtered_payload}')"
    else:
        return f"SELECT '{filtered_payload}'"


def _setup_db() -> sqlite3.Connection:
    """Create an in-memory DB with test data."""
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)")
    conn.execute("INSERT INTO users (id, name) VALUES (1, ?)", (_MARKER,))
    conn.execute("INSERT INTO users (id, name) VALUES (2, 'admin')")
    conn.execute("INSERT INTO users (id, name) VALUES (3, 'guest')")
    conn.commit()
    return conn


class OracleSession:
    """Keeps a DB connection for batch checks."""

    def __init__(self):
        self._conn: sqlite3.Connection | None = None

    def __enter__(self) -> Self:
        self._conn = _setup_db()
        return self

    def __exit__(self, *args):
        if self._conn:
            self._conn.close()
            self._conn = None
        return False

    def check_fires(self, ctx: ContextSpec, payload: str) -> bool:
        """Return True if the payload causes data extraction or SQL error."""
        if not can_fire(payload, ctx.location):
            return False

        filtered = simulate_reflection(ctx, payload)
        if not filtered:
            return False  # blocked by filters

        query = _build_query(ctx, filtered)

        try:
            cursor = self._conn.execute(query)
            results = cursor.fetchall()

            # Check if marker data was extracted (UNION-based)
            for row in results:
                for val in row:
                    if val and _MARKER in str(val):
                        return True

            # Check if we got more rows than expected (UNION expanded results)
            # (base table has 3 rows; more means UNION expanded the result set)
            if ctx.location in ("string_literal", "numeric") and len(results) > 3:
                return True

            # INSERT context: if no error, injection worked
            return ctx.location == "insert_values"

        except sqlite3.Error as exc:
            # Only a genuine data leak through the error message counts
            # (true error-based injection). A bare syntax error — e.g. a
            # MySQL-style '#' comment under SQLite — extracts nothing.
            return _MARKER in str(exc)


def check_fires(ctx: ContextSpec, payload: str) -> bool:
    """Standalone check_fires."""
    with OracleSession() as session:
        return session.check_fires(ctx, payload)
