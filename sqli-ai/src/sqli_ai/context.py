"""ContextSpec: the structured description of a SQL injection point."""
from __future__ import annotations

from pydantic import BaseModel, Field

LOCATIONS: tuple[str, ...] = (
    "string_literal",   # 'user_input' in WHERE
    "numeric",          # WHERE id = user_input (unquoted)
    "order_by",         # ORDER BY user_input
    "column_name",      # SELECT user_input FROM table
    "insert_values",    # INSERT INTO t VALUES (user_input)
)

_LOCATION_PROSE: dict[str, str] = {
    "string_literal": "Input is injected into a SQL string literal in a WHERE clause (single-quoted).",
    "numeric": "Input is injected into a numeric context in a WHERE clause (unquoted integer).",
    "order_by": "Input is injected into an ORDER BY clause.",
    "column_name": "Input is used as a column name in a SELECT statement.",
    "insert_values": "Input is injected into an INSERT statement VALUES list.",
}

_FILTER_PROSE: dict[str, str] = {
    "escape_single_quotes": "Single quotes are escaped (doubled: ' to '').",
    "escape_double_quotes": "Double quotes are escaped.",
    "block_keyword_union": "The keyword UNION is blocked (case-insensitive).",
    "block_keyword_select": "The keyword SELECT is blocked (case-insensitive).",
    "block_keyword_and_or": "The keywords AND and OR are blocked (case-insensitive).",
    "block_comment_dash": "Double-dash comments (--) are blocked.",
    "block_comment_hash": "Hash comments (#) are blocked.",
    "numeric_cast": "Input is cast to an integer (non-numeric input becomes 0).",
    "lowercase_input": "Input is lowercased before use in the query.",
}


class ContextSpec(BaseModel):
    id: str
    location: str
    filters: list[str] = Field(default_factory=list)
    dialect: str = "sqlite"
    description: str | None = None

    def model_post_init(self, __context) -> None:
        if self.location not in LOCATIONS:
            raise ValueError(f"unknown location {self.location!r}; expected one of {LOCATIONS}")
        unknown = [f for f in self.filters if f not in _FILTER_PROSE]
        if unknown:
            raise ValueError(f"unknown filter(s): {unknown}")


def render_description(ctx: ContextSpec) -> str:
    if ctx.description is not None:
        return ctx.description
    parts: list[str] = [_LOCATION_PROSE[ctx.location]]
    for f in ctx.filters:
        parts.append(_FILTER_PROSE.get(f, f"Filter applied: {f}."))
    parts.append(f"SQL dialect: {ctx.dialect}.")
    return " ".join(parts)


def simulate_reflection(ctx: ContextSpec, payload: str) -> str:
    """Apply filter pipeline to a payload. Returns filtered payload or '' if blocked."""
    from .filters import apply_filters
    return apply_filters(payload, ctx.filters)
