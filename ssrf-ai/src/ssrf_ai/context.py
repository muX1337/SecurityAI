"""ContextSpec: the structured description of an SSRF injection point."""
from __future__ import annotations

from pydantic import BaseModel, Field

LOCATIONS: tuple[str, ...] = (
    "query_param",
    "post_body",
    "json_field",
    "redirect_header",
    "xml_body",
)

_LOCATION_PROSE: dict[str, str] = {
    "query_param": "Server fetches a URL from a query parameter in the request.",
    "post_body": "Server fetches a URL from a POST form body field.",
    "json_field": "Server fetches a URL from a JSON field in the request body.",
    "redirect_header": "Server fetches a URL from a redirect Location header.",
    "xml_body": "Server fetches a URL from an XML element in the request body.",
}

_FILTER_PROSE: dict[str, str] = {
    "block_private_ip": "Private IP ranges (10/8, 172.16/12, 192.168/16, 127/8, 169.254/16) are blocked.",
    "block_localhost_aliases": "Localhost aliases (localhost, 0.0.0.0, [::], 2130706433, 0x7f000001) are blocked.",
    "block_metadata_ip": "Cloud metadata endpoint (169.254.169.254) is blocked.",
    "scheme_http_only": "Only http and https schemes are allowed. Other schemes (file://, gopher://, dict://, ftp://) are blocked.",
    "block_redirects": "HTTP redirects are NOT followed.",
    "url_syntax_validate": "URL syntax is validated: URLs with newlines, CRLF, embedded credentials, or backslashes are rejected.",
    "dns_resolve_check": "DNS is resolved and checked: if the resolved IP is private, the request is blocked.",
}


class ContextSpec(BaseModel):
    id: str
    location: str
    filters: list[str] = Field(default_factory=list)
    scheme_allowlist: list[str] | None = None
    allows_redirects: bool = True
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

    if ctx.scheme_allowlist:
        schemes = ", ".join(ctx.scheme_allowlist)
        parts.append(f"Allowed schemes: {schemes}.")
    else:
        parts.append("All URL schemes are allowed.")

    if ctx.allows_redirects:
        parts.append("HTTP redirects are followed.")
    else:
        parts.append("HTTP redirects are NOT followed.")

    return " ".join(parts)


def simulate_reflection(ctx: ContextSpec, payload: str) -> str:
    from .filters import apply_filters
    return apply_filters(payload, ctx.filters)
