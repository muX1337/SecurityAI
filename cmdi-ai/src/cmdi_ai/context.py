"""ContextSpec: the structured description of a command injection point."""
from __future__ import annotations

from pydantic import BaseModel, Field

LOCATIONS: tuple[str, ...] = (
    "shell_arg",        # input is an argument to a shell command (ping INPUT)
    "shell_command",    # input IS the command (system(INPUT))
    "filename_arg",     # input is a filename argument (cat INPUT)
    "variable_value",   # input is set as an env var then used in a command
)

_LOCATION_PROSE: dict[str, str] = {
    "shell_arg": "Input is passed as an argument to a shell command (e.g. ping INPUT).",
    "shell_command": "Input is executed directly as a shell command (e.g. system(INPUT)).",
    "filename_arg": "Input is used as a filename argument to a command (e.g. cat INPUT).",
    "variable_value": "Input is assigned to an environment variable then expanded in a command.",
}

_FILTER_PROSE: dict[str, str] = {
    "block_semicolon": "The semicolon character (;) is blocked, preventing command chaining.",
    "block_pipe": "The pipe character (|) is blocked, preventing command piping.",
    "block_ampersand": "The ampersand character (&) is blocked, preventing background execution and AND-chaining.",
    "block_backtick": "The backtick character (`) is blocked, preventing command substitution.",
    "block_dollar": "The dollar character ($) is blocked, preventing variable expansion and $() substitution.",
    "block_redirect": "I/O redirection characters (> and <) are blocked.",
    "block_keywords": "Common command names (cat, ls, whoami, id, curl, wget, nc, bash, sh) are blocked.",
    "alphanumeric_only": "Input is stripped to alphanumeric characters and dots only ([a-zA-Z0-9.]).",
}


class ContextSpec(BaseModel):
    id: str
    location: str
    filters: list[str] = Field(default_factory=list)
    shell: str = "bash"
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
    parts.append(f"Shell: {ctx.shell}.")
    return " ".join(parts)


def simulate_reflection(ctx: ContextSpec, payload: str) -> str:
    """Apply filter pipeline to a payload. Returns filtered payload or '' if blocked."""
    from .filters import apply_filters
    return apply_filters(payload, ctx.filters)
