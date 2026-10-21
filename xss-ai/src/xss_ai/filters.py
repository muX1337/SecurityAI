"""Filter registry: each filter models ONE server-side input transformation.

A filter takes the raw payload string (what the attacker sends) and returns
the string as it would appear after the server's transformation. Filters
that "block" a keyword return "" when the keyword is present (server rejects).
"""
from __future__ import annotations

import html as html_module
import re
import urllib.parse
from collections.abc import Callable

# name -> function(str) -> str
FILTERS: dict[str, Callable[[str], str]] = {}


def register(name: str) -> Callable[[Callable[[str], str]], Callable[[str], str]]:
    """Decorator: register a filter function under `name`."""
    def deco(fn: Callable[[str], str]) -> Callable[[str], str]:
        FILTERS[name] = fn
        return fn
    return deco


def get_filter(name: str) -> Callable[[str], str]:
    if name not in FILTERS:
        raise KeyError(f"unknown filter {name!r}; registered: {sorted(FILTERS)}")
    return FILTERS[name]


def apply_filters(payload: str, filter_names: list[str]) -> str:
    """Apply filters in order. A blocking filter that returns '' short-circuits."""
    out = payload
    for name in filter_names:
        out = get_filter(name)(out)
        if out == "":
            return ""  # blocked
    return out


# --------------------------------------------------------------------------
# Concrete filters
# --------------------------------------------------------------------------

@register("strip_angle_brackets")
def strip_angle_brackets(s: str) -> str:
    return re.sub(r"[<>]", "", s)

@register("strip_open_angle")
def strip_open_angle(s: str) -> str:
    return s.replace("<", "")

@register("escape_double_quotes_html")
def escape_double_quotes_html(s: str) -> str:
    return s.replace('"', "&quot;")

@register("escape_single_quotes_html")
def escape_single_quotes_html(s: str) -> str:
    return s.replace("'", "&#39;")

@register("escape_angle_brackets_html")
def escape_angle_brackets_html(s: str) -> str:
    return s.replace("<", "&lt;").replace(">", "&gt;")

@register("block_keyword_script")
def block_keyword_script(s: str) -> str:
    return "" if re.search(r"script", s, re.IGNORECASE) else s

@register("block_keyword_alert")
def block_keyword_alert(s: str) -> str:
    return "" if re.search(r"alert", s, re.IGNORECASE) else s

@register("block_keyword_javascript")
def block_keyword_javascript(s: str) -> str:
    return "" if re.search(r"javascript:", s, re.IGNORECASE) else s

@register("block_event_handlers")
def block_event_handlers(s: str) -> str:
    # Remove onXXX= event handler attributes.
    return re.sub(r"\bon\w+\s*=", "", s, flags=re.IGNORECASE)

@register("block_keyword_on_prefix")
def block_keyword_on_prefix(s: str) -> str:
    return "" if re.search(r"\bon\w+\s*=", s, re.IGNORECASE) else s

@register("url_decode")
def url_decode(s: str) -> str:
    return urllib.parse.unquote(s)

@register("html_entity_decode")
def html_entity_decode(s: str) -> str:
    return html_module.unescape(s)

@register("strip_parentheses")
def strip_parentheses(s: str) -> str:
    return s.replace("(", "").replace(")", "")

@register("lowercase")
def lowercase(s: str) -> str:
    return s.lower()

@register("strip_backslashes")
def strip_backslashes(s: str) -> str:
    return s.replace("\\", "")
