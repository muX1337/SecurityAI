"""ContextSpec: the structured description of an open redirect injection point."""
from __future__ import annotations

from pydantic import BaseModel, Field

LOCATIONS: tuple[str, ...] = (
    "redirect_param",
    "location_header",
    "return_url",
    "next_param",
)

_LOCATION_PROSE: dict[str, str] = {
    "redirect_param": "The URL is taken from a query parameter for redirect (e.g. ?redirect=INPUT).",
    "location_header": "The URL is set as a Location header value for a redirect.",
    "return_url": "The URL is used as a post-login return destination.",
    "next_param": "The URL is taken from a \"next\" navigation query parameter.",
}

_FILTER_PROSE: dict[str, str] = {
    "block_absolute_url": "Absolute URLs starting with http:// or https:// are blocked.",
    "require_same_domain": "Only same-domain redirects are allowed.",
    "block_protocol_relative": "Protocol-relative URLs (starting with //) are blocked.",
    "block_at_symbol": "URLs containing the @ symbol are blocked.",
    "block_backslash": "URLs containing backslashes (\\) are blocked.",
    "url_decode": "Input is URL-decoded before checking.",
    "block_dotdot": "URLs containing ../ sequences are blocked.",
    "allowlist_paths": "Only specific path prefixes are allowed (rejects external hosts).",
}

# App domain used as the "trusted" origin across the taxonomy.
APP_DOMAIN = "app.com"


class ContextSpec(BaseModel):
    id: str
    location: str
    filters: list[str] = Field(default_factory=list)
    app_domain: str = APP_DOMAIN
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

    if not ctx.filters:
        parts.append("No URL validation is performed.")

    return " ".join(parts)


def simulate_reflection(ctx: ContextSpec, payload: str) -> str:
    from .filters import apply_filters
    return apply_filters(payload, ctx.filters, ctx.app_domain)
