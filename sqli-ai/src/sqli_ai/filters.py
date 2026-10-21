"""SQL injection filter registry."""
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

@register("escape_single_quotes")
def escape_single_quotes(s: str) -> str:
    return s.replace("'", "''")

@register("escape_double_quotes")
def escape_double_quotes(s: str) -> str:
    return s.replace('"', '\\"')

@register("block_keyword_union")
def block_keyword_union(s: str) -> str:
    return "" if re.search(r"\bunion\b", s, re.IGNORECASE) else s

@register("block_keyword_select")
def block_keyword_select(s: str) -> str:
    return "" if re.search(r"\bselect\b", s, re.IGNORECASE) else s

@register("block_keyword_and_or")
def block_keyword_and_or(s: str) -> str:
    return "" if re.search(r"\b(and|or)\b", s, re.IGNORECASE) else s

@register("block_comment_dash")
def block_comment_dash(s: str) -> str:
    return "" if "--" in s else s

@register("block_comment_hash")
def block_comment_hash(s: str) -> str:
    return "" if "#" in s else s

@register("numeric_cast")
def numeric_cast(s: str) -> str:
    try:
        return str(int(s))
    except (ValueError, TypeError):
        return "0"

@register("lowercase_input")
def lowercase(s: str) -> str:
    return s.lower()
