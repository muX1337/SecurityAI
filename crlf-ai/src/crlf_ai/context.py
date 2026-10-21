"""ContextSpec: the structured description of a CRLF / HTTP response injection point."""
from __future__ import annotations

from pydantic import BaseModel, Field

LOCATIONS: tuple[str, ...] = (
    "response_header",
    "set_cookie",
    "location_header",
    "response_body",
)

_LOCATION_PROSE: dict[str, str] = {
    "response_header": "User input is reflected into a custom HTTP response header value.",
    "set_cookie": "User input is placed into the value of a Set-Cookie response header.",
    "location_header": "User input is placed into the value of a Location redirect response header.",
    "response_body": "User input is reflected into the HTTP response body after the headers.",
}

# Name of the header each location injects the payload into in the simulated
# response. response_body uses a pseudo "X-Custom" header slot too so the same
# reflection simulation applies uniformly; the body cases fire via a doubled
# CRLF that terminates the header block and injects body content.
_LOCATION_HEADER: dict[str, str] = {
    "response_header": "X-Custom",
    "set_cookie": "Set-Cookie",
    "location_header": "Location",
    "response_body": "X-Custom",
}

_FILTER_PROSE: dict[str, str] = {
    "block_crlf": "Literal CRLF sequences (carriage return + linefeed, \\r\\n) are blocked.",
    "block_cr_only": "Carriage return characters (\\r) are blocked.",
    "block_lf_only": "Linefeed characters (\\n) are blocked.",
    "block_percent_0d": "The URL-encoded carriage return sequence %0d (case-insensitive) is blocked.",
    "block_percent_0a": "The URL-encoded linefeed sequence %0a (case-insensitive) is blocked.",
    "url_decode": "Input is URL-decoded once before reflection and before any block filters run.",
    "double_decode": "Input is URL-decoded twice before reflection and before any block filters run.",
    "block_header_keywords": "Header-injection keywords (Set-Cookie, Location, Content-Type) are blocked.",
}


class ContextSpec(BaseModel):
    id: str
    location: str
    filters: list[str] = Field(default_factory=list)
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

    if not ctx.filters:
        parts.append("No input filtering is applied.")
    else:
        for f in ctx.filters:
            parts.append(_FILTER_PROSE.get(f, f"Filter applied: {f}."))

    return " ".join(parts)


def location_header_name(ctx: ContextSpec) -> str:
    """Return the simulated response header name the payload is injected into."""
    return _LOCATION_HEADER[ctx.location]


def simulate_reflection(ctx: ContextSpec, payload: str) -> str:
    """Apply the context's filters to the payload.

    Returns "" if a block filter rejects the payload, otherwise the (possibly
    decoded) reflected string. Filter ordering: decode filters (url_decode /
    double_decode) run FIRST, then block filters examine the decoded result.
    This models a server that decodes input before sanitizing it — the classic
    CRLF bypass is double-encoding so that a single decode still leaves an
    encoded sequence the block filter misses.
    """
    from .filters import apply_filters
    return apply_filters(payload, ctx.filters)
