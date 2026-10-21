"""SSTI input filter registry: each filter models ONE server-side sanitization check.

Each filter takes a payload string and returns the (possibly modified) string,
or "" if the payload is blocked/rejected. Filters are chained in order by
apply_filters(); a "" at any stage short-circuits.
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


@register("block_curly_braces")
def block_curly_braces(payload: str) -> str:
    """Block '{{' and '}}' (Jinja2/Twig expression delimiters)."""
    if "{{" in payload or "}}" in payload:
        return ""
    return payload


@register("block_percent_braces")
def block_percent_braces(payload: str) -> str:
    """Block '{%' and '%}' (Jinja2/Twig statement delimiters)."""
    if "{%" in payload or "%}" in payload:
        return ""
    return payload


@register("block_dollar_braces")
def block_dollar_braces(payload: str) -> str:
    """Block '${' and '}' (FreeMarker/Mako interpolation)."""
    if "${" in payload or "}" in payload:
        return ""
    return payload


@register("block_keyword_config")
def block_keyword_config(payload: str) -> str:
    """Block 'config', 'self', and 'request' keywords (case-sensitive)."""
    lower = payload
    for kw in ("config", "self", "request"):
        if re.search(r"\b" + re.escape(kw) + r"\b", lower):
            return ""
    return payload


@register("block_class_keyword")
def block_class_keyword(payload: str) -> str:
    """Block the '__class__' attribute access."""
    if "__class__" in payload:
        return ""
    return payload


@register("block_subclasses")
def block_subclasses(payload: str) -> str:
    """Block the '__subclasses__' attribute access."""
    if "__subclasses__" in payload:
        return ""
    return payload


@register("block_import")
def block_import(payload: str) -> str:
    """Block the 'import' keyword."""
    if re.search(r"\bimport\b", payload):
        return ""
    return payload


@register("block_os_keyword")
def block_os_keyword(payload: str) -> str:
    """Block 'os', 'popen', and 'system' keywords."""
    for kw in ("os", "popen", "system"):
        if re.search(r"\b" + re.escape(kw) + r"\b", payload):
            return ""
    return payload
