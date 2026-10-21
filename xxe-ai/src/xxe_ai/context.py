"""ContextSpec: the structured description of an XXE injection point."""
from __future__ import annotations

from pydantic import BaseModel, Field

LOCATIONS: tuple[str, ...] = (
    "xml_body",
    "xml_attribute",
    "xml_cdata",
    "soap_body",
    "svg_upload",
)

_LOCATION_PROSE: dict[str, str] = {
    "xml_body": "Input is placed inside an XML element body in the request.",
    "xml_attribute": "Input is placed inside an XML attribute value in the request.",
    "xml_cdata": "Input is placed inside a CDATA section in the XML request.",
    "soap_body": "Input is placed inside a SOAP request body.",
    "svg_upload": "Input is the content of an uploaded SVG file, parsed as XML.",
}

_FILTER_PROSE: dict[str, str] = {
    "block_doctype": "DOCTYPE declarations (<!DOCTYPE) are blocked.",
    "block_entity": "Entity declarations (<!ENTITY) are blocked.",
    "block_external_entity": "External entities using the SYSTEM keyword are blocked.",
    "block_parameter_entity": "Parameter entities (%) are blocked.",
    "block_file_protocol": "The file:// protocol in entity URLs is blocked.",
    "block_http_protocol": "The http:// protocol in entity URLs is blocked.",
    "strip_comments": "XML comments (<!-- -->) are stripped before parsing.",
    "disable_dtd": "DTD processing is disabled entirely; no entities are resolved.",
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

    for f in ctx.filters:
        parts.append(_FILTER_PROSE.get(f, f"Filter applied: {f}."))

    if not ctx.filters:
        parts.append("No XML input filtering is applied; DTD and entities are processed.")

    return " ".join(parts)


def simulate_reflection(ctx: ContextSpec, payload: str) -> str:
    from .filters import apply_filters
    return apply_filters(payload, ctx.filters)
