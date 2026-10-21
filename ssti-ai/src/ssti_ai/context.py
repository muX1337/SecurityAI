"""ContextSpec: the structured description of an SSTI injection point."""
from __future__ import annotations

from pydantic import BaseModel, Field

# Locations: template engines + injection point within the template.
LOCATIONS: tuple[str, ...] = (
    "jinja2_body",
    "twig_body",
    "freemarker_body",
    "velocity_body",
    "mako_body",
)

_LOCATION_PROSE: dict[str, str] = {
    "jinja2_body": "User input is rendered inside a Jinja2 template body (Flask).",
    "twig_body": "User input is rendered inside a Twig template body (PHP/Symfony).",
    "freemarker_body": "User input is rendered inside a FreeMarker template body (Java).",
    "velocity_body": "User input is rendered inside a Velocity template body (Java).",
    "mako_body": "User input is rendered inside a Mako template body (Python).",
}

# The canonical delimiters each engine evaluates. Used by the oracle to know
# which expression syntax would be interpreted if it reaches the renderer.
_ENGINE_DELIMITERS: dict[str, tuple[str, ...]] = {
    "jinja2_body": ("{{", "}}", "{%", "%}"),
    "twig_body": ("{{", "}}", "{%", "%}"),
    "freemarker_body": ("${", "}", "<#", "</#"),
    "velocity_body": ("$"),
    "mako_body": ("${", "}"),
}

# Filters: server-side input sanitization applied before rendering.
_FILTER_PROSE: dict[str, str] = {
    "block_curly_braces": "The substring '{{' and '}}' is blocked.",
    "block_percent_braces": "The substring '{%' and '%}' is blocked.",
    "block_dollar_braces": "The substring '${' and '}' is blocked.",
    "block_keyword_config": "The keywords 'config', 'self', and 'request' are blocked.",
    "block_class_keyword": "The substring '__class__' is blocked.",
    "block_subclasses": "The substring '__subclasses__' is blocked.",
    "block_import": "The keyword 'import' is blocked.",
    "block_os_keyword": "The keywords 'os', 'popen', and 'system' are blocked.",
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


def engine_delimiters(location: str) -> tuple[str, ...]:
    """Return the expression delimiters the engine at `location` evaluates."""
    return _ENGINE_DELIMITERS.get(location, ())


def render_description(ctx: ContextSpec) -> str:
    if ctx.description is not None:
        return ctx.description

    parts: list[str] = [_LOCATION_PROSE[ctx.location]]

    for f in ctx.filters:
        parts.append(_FILTER_PROSE.get(f, f"Filter applied: {f}."))

    if not ctx.filters:
        parts.append("No input filtering is applied.")

    return " ".join(parts)


def simulate_reflection(ctx: ContextSpec, payload: str) -> str:
    """Apply the context's filters to the payload; '' means blocked."""
    from .filters import apply_filters
    return apply_filters(payload, ctx.filters)
