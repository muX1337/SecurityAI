"""Path traversal / LFI filter registry: each filter models ONE server-side path check."""
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


@register("strip_dotdot")
def strip_dotdot(s: str) -> str:
    """Remove '../' once (non-recursive single pass)."""
    return s.replace("../", "")


@register("strip_dotdot_recursive")
def strip_dotdot_recursive(s: str) -> str:
    """Remove '../' repeatedly until none remain (recursive collapse)."""
    prev = None
    while prev != s:
        prev = s
        s = s.replace("../", "")
    return s


@register("basename_only")
def basename_only(s: str) -> str:
    """Apply basename(): keep only the final path component.

    Strips directory components on both '/' and '\\' separators. An empty
    result (e.g. input was just slashes) maps to "" which blocks the payload.
    """
    s = s.replace("\\", "/")
    if "/" in s:
        s = s.rsplit("/", 1)[-1]
    return s


@register("block_absolute")
def block_absolute(s: str) -> str:
    """Block absolute paths starting with '/' or a Windows drive letter (e.g. C:\\)."""
    if s.startswith("/"):
        return ""
    if re.match(r"^[a-zA-Z]:[\\/]", s):
        return ""
    return s


@register("block_null_byte")
def block_null_byte(s: str) -> str:
    """Block payloads containing a null byte (literal or %00 encoded)."""
    if "\x00" in s or "%00" in s.lower():
        return ""
    return s


@register("url_decode")
def url_decode(s: str) -> str:
    """URL-decode the input once."""
    from urllib.parse import unquote
    return unquote(s)


@register("double_decode")
def double_decode(s: str) -> str:
    """URL-decode the input twice (catches double-encoding bypasses)."""
    from urllib.parse import unquote
    return unquote(unquote(s))


@register("prefix_append")
def prefix_append(s: str) -> str:
    """Flag filter: a base directory will be prepended at file-open time.

    The filter itself is a pass-through here; the actual prefix logic lives in
    the oracle (which concatenates base_dir + '/' + payload before resolving).
    Returning the payload unchanged lets the oracle observe the raw payload so
    it can build the vulnerable path correctly.
    """
    return s
