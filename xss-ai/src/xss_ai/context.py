"""ContextSpec: the structured description of an XSS injection point."""
from __future__ import annotations

import html as html_module
import urllib.parse

from pydantic import BaseModel, Field

# The injection locations supported in v1.
LOCATIONS: tuple[str, ...] = (
    "html_body",      # reflected into element content
    "attr_dq",        # reflected into a double-quoted attribute value
    "attr_sq",        # reflected into a single-quoted attribute value
    "js_string_sq",   # reflected into a JS single-quoted string literal
    "js_string_dq",   # reflected into a JS double-quoted string literal
    "url_param",      # reflected into a URL (e.g. href parameter)
    "html_comment",   # reflected inside <!-- ... -->
)

_LOCATION_PROSE: dict[str, str] = {
    "html_body": "Input is reflected into the HTML body (element content).",
    "attr_dq": "Input is reflected into a double-quoted HTML attribute value.",
    "attr_sq": "Input is reflected into a single-quoted HTML attribute value.",
    "js_string_sq": "Input is reflected into a single-quoted JavaScript string literal.",
    "js_string_dq": "Input is reflected into a double-quoted JavaScript string literal.",
    "url_param": "Input is reflected into a URL (href parameter).",
    "html_comment": "Input is reflected inside an HTML comment.",
}

_FILTER_PROSE: dict[str, str] = {
    "strip_angle_brackets": "The server strips the characters < and >.",
    "strip_open_angle": "The server strips the < character.",
    "escape_double_quotes_html": 'Double quotes are HTML-encoded to &quot;.',
    "escape_single_quotes_html": "Single quotes are HTML-encoded to &#39;.",
    "escape_angle_brackets_html": "Angle brackets are HTML-encoded (&lt; &gt;).",
    "block_keyword_script": 'The substring "script" is blocked (case-insensitive).',
    "block_keyword_alert": 'The substring "alert" is blocked (case-insensitive).',
    "block_keyword_javascript": 'The substring "javascript:" is blocked (case-insensitive).',
    "block_event_handlers": "Event handler attributes (on*=) are stripped.",
    "url_decode": "The server URL-decodes the input before reflection.",
    "html_entity_decode": "The server HTML-entity-decodes the input before reflection.",
    "strip_parentheses": "The characters ( and ) are stripped.",
    "lowercase": "The input is lowercased before reflection.",
    "strip_backslashes": "Backslashes are stripped.",
    "block_keyword_on_prefix": "Tokens starting with 'on' followed by '=' are blocked.",
}

_ENCODING_PROSE: dict[str, str] = {
    "url_decode": "Input is URL-decoded before reflection.",
    "html_entity_decode": "Input is HTML-entity-decoded before reflection.",
}


class ContextSpec(BaseModel):
    """One injection context the model must produce payloads for."""

    id: str
    location: str
    reflection: str = "reflected"
    encoding: list[str] = Field(default_factory=list)
    filters: list[str] = Field(default_factory=list)
    allowed_chars: str | None = None
    description: str | None = None  # if None, rendered on demand

    def model_post_init(self, __context) -> None:
        if self.location not in LOCATIONS:
            raise ValueError(f"unknown location {self.location!r}; expected one of {LOCATIONS}")
        unknown = [f for f in self.filters if f not in _FILTER_PROSE]
        if unknown:
            raise ValueError(f"unknown filter(s): {unknown}")


def render_description(ctx: ContextSpec) -> str:
    """Render a ContextSpec into the natural-language prompt the model sees."""
    if ctx.description is not None:
        return ctx.description

    parts: list[str] = [_LOCATION_PROSE[ctx.location]]

    # Encoding transforms (applied first, server-side)
    for enc in ctx.encoding:
        parts.append(_ENCODING_PROSE.get(enc, f"Input is {enc} before reflection."))

    # Filters
    for f in ctx.filters:
        parts.append(_FILTER_PROSE.get(f, f"Filter applied: {f}."))

    if ctx.allowed_chars:
        parts.append(f"Allowed characters: {ctx.allowed_chars}")

    return " ".join(parts)


_ENCODINGS = {
    "url_decode": urllib.parse.unquote,
    "html_entity_decode": html_module.unescape,
}


def simulate_reflection(ctx: ContextSpec, payload: str) -> str:
    """Apply the server-side pipeline (encoding, then filters) to a raw payload.

    Single source of truth for how a victim server transforms attacker input
    before reflection. Both the filter harness (pair generation) and the browser
    oracle (ground-truth validation) MUST use this so they agree on what
    'reflection' means.
    """
    from .filters import apply_filters  # local import to avoid circular at module load
    encoded = payload
    for enc in ctx.encoding:
        fn = _ENCODINGS.get(enc)
        if fn:
            encoded = fn(encoded)
    return apply_filters(encoded, ctx.filters)
