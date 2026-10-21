"""XXE payload filter registry: each filter models ONE server-side XML input check.

Each filter takes a raw payload string and returns the filtered version, or "" if
the payload is blocked entirely. Filters chain in order: if any returns "", the
payload is rejected.
"""
from __future__ import annotations

import re
from collections.abc import Callable

FILTERS: dict[str, Callable[[str], str]] = {}


def register(name: str) -> Callable[[Callable[[str], str]], Callable[[str], str]]:
    def deco(fn: Callable[[str], str]) -> Callable[[str], str]:
        FILTERS[name] = fn
        return fn
    return deco


def get_filter(name: str) -> Callable[[str], str]:
    if name not in FILTERS:
        raise KeyError(f"unknown filter {name!r}; registered: {sorted(FILTERS)}")
    return FILTERS[name]


def apply_filters(payload: str, filter_names: list[str]) -> str:
    out = payload
    for name in filter_names:
        out = get_filter(name)(out)
        if out == "":
            return ""
    return out


_DOCTYPE_RE = re.compile(r"<!DOCTYPE", re.IGNORECASE)
_ENTITY_RE = re.compile(r"<!ENTITY", re.IGNORECASE)
_SYSTEM_RE = re.compile(r"\bSYSTEM\b", re.IGNORECASE)
_PUBLIC_RE = re.compile(r"\bPUBLIC\b", re.IGNORECASE)
_PARAM_ENTITY_RE = re.compile(r"<!ENTITY\s*%")
_FILE_PROTO_RE = re.compile(r"file://", re.IGNORECASE)
_HTTP_PROTO_RE = re.compile(r"https?://", re.IGNORECASE)
_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)


@register("block_doctype")
def block_doctype(payload: str) -> str:
    """Block payloads containing a DOCTYPE declaration."""
    if _DOCTYPE_RE.search(payload):
        return ""
    return payload


@register("block_entity")
def block_entity(payload: str) -> str:
    """Block payloads containing an ENTITY declaration."""
    if _ENTITY_RE.search(payload):
        return ""
    return payload


@register("block_external_entity")
def block_external_entity(payload: str) -> str:
    """Block external entities (SYSTEM/PUBLIC keyword). Internal entities pass."""
    if _ENTITY_RE.search(payload) and (_SYSTEM_RE.search(payload) or _PUBLIC_RE.search(payload)):
        return ""
    return payload


@register("block_parameter_entity")
def block_parameter_entity(payload: str) -> str:
    """Block parameter entities (those using % syntax)."""
    if _PARAM_ENTITY_RE.search(payload):
        return ""
    # Also catch bare % references that form parameter entity usage in DTD
    if "% " in payload or "%\n" in payload:
        return ""
    return payload


@register("block_file_protocol")
def block_file_protocol(payload: str) -> str:
    """Block entities referencing the file:// protocol."""
    if _FILE_PROTO_RE.search(payload):
        return ""
    return payload


@register("block_http_protocol")
def block_http_protocol(payload: str) -> str:
    """Block entities referencing http:// or https:// protocols."""
    if _HTTP_PROTO_RE.search(payload):
        return ""
    return payload


@register("strip_comments")
def strip_comments(payload: str) -> str:
    """Remove XML comments before parsing."""
    return _COMMENT_RE.sub("", payload)


@register("disable_dtd")
def disable_dtd(payload: str) -> str:
    """DTD processing disabled: any DOCTYPE declaration makes the whole payload invalid."""
    if _DOCTYPE_RE.search(payload):
        return ""
    return payload
