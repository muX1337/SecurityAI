"""Command injection filter registry."""
from __future__ import annotations

import re
from collections.abc import Callable

FILTERS: dict[str, Callable[[str], str]] = {}

def register(name: str):
    def deco(fn):
        FILTERS[name] = fn
        return fn
    return deco

def get_filter(name: str):
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

@register("block_semicolon")
def block_semicolon(s: str) -> str:
    return "" if ";" in s else s

@register("block_pipe")
def block_pipe(s: str) -> str:
    return "" if "|" in s else s

@register("block_ampersand")
def block_ampersand(s: str) -> str:
    return "" if "&" in s else s

@register("block_backtick")
def block_backtick(s: str) -> str:
    return "" if "`" in s else s

@register("block_dollar")
def block_dollar(s: str) -> str:
    return "" if "$" in s else s

@register("block_redirect")
def block_redirect(s: str) -> str:
    return "" if (">" in s or "<" in s) else s

@register("block_keywords")
def block_keywords(s: str) -> str:
    # Block common command names appearing as whole words (case-insensitive).
    return "" if re.search(r"\b(cat|ls|whoami|id|curl|wget|nc|bash|sh)\b", s, re.IGNORECASE) else s

@register("alphanumeric_only")
def alphanumeric_only(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9.]", "", s)
