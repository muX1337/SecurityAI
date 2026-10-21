"""ContextSpec: the structured description of a path traversal / LFI injection point."""
from __future__ import annotations

from pydantic import BaseModel, Field

LOCATIONS: tuple[str, ...] = (
    "file_include",    # path passed to include/require (PHP-style)
    "file_read",       # path passed to fopen/file_get_contents/readFile
    "download_param",  # path in a download endpoint (?file=INPUT)
    "template_path",   # path in a template loader
)

_LOCATION_PROSE: dict[str, str] = {
    "file_include": "The input is passed to a server-side include/require call (e.g. PHP include INPUT).",
    "file_read": "The input is passed to a file-read function such as file_get_contents, fopen, or readFile (e.g. file_get_contents(INPUT)).",
    "download_param": "The input is a filename in a download endpoint query parameter (e.g. ?file=INPUT).",
    "template_path": "The input is used as a template path in a template loader (e.g. render(INPUT)).",
}

_FILTER_PROSE: dict[str, str] = {
    "strip_dotdot": "The string '../' is stripped from the input (a single non-recursive removal).",
    "strip_dotdot_recursive": "The string '../' is removed repeatedly until no occurrences remain (recursive collapse).",
    "basename_only": "basename() is applied, stripping all directory components so only the final filename remains.",
    "block_absolute": "Absolute paths (starting with '/' or a Windows drive letter like 'C:\\') are blocked.",
    "block_null_byte": "Null bytes and their URL-encoding (%00) are blocked.",
    "url_decode": "The input is URL-decoded once before any other filtering.",
    "double_decode": "The input is URL-decoded twice (to catch double-encoding bypasses).",
    "prefix_append": "A base directory is prepended to the input before the file is opened.",
}


class ContextSpec(BaseModel):
    id: str
    location: str
    filters: list[str] = Field(default_factory=list)
    base_dir: str = "/var/www/files"
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
    return " ".join(parts)


def simulate_reflection(ctx: ContextSpec, payload: str) -> str:
    """Apply filter pipeline to a payload. Returns filtered payload or '' if blocked."""
    from .filters import apply_filters
    return apply_filters(payload, ctx.filters)
